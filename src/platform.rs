//! Operating-system specific pieces: ICMP, ARP, routes, adapters, name lookup, and opening tools.
//! Windows uses the IP Helper API; macOS and Linux use libc, the system tools and (Linux) /proc.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;

pub use imp::*;

/// Where the settings file lives: %APPDATA%\NetScan on Windows, ~/Library/Application Support/NetScan on macOS,
/// $XDG_CONFIG_HOME/NetScan (usually ~/.config/NetScan) on Linux.
pub fn settings_file() -> Option<PathBuf> {
    #[cfg(windows)]
    let base = PathBuf::from(std::env::var_os("APPDATA")?);
    #[cfg(target_os = "macos")]
    let base = PathBuf::from(std::env::var_os("HOME")?).join("Library").join("Application Support");
    #[cfg(not(any(windows, target_os = "macos")))]
    let base = match std::env::var_os("XDG_CONFIG_HOME").filter(|d| !d.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(std::env::var_os("HOME")?).join(".config"),
    };
    Some(base.join("NetScan").join("settings.txt"))
}

/// Tag of the newest GitHub release, via the curl that ships with Windows 10+, macOS and most Linux desktops (no TLS stack in the app).
pub fn latest_release(repo: &str) -> Result<String, String> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let mut cmd = std::process::Command::new("curl");
    cmd.args(["-sS", "--max-time", "10", "-H", "Accept: application/vnd.github+json", "-H", "User-Agent: NetScan", "-w", "\n%{http_code}", &url]);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000; // no console flashing up behind the GUI
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let out = cmd.output().map_err(|_| "curl nicht gefunden".to_string())?;
    let text = String::from_utf8_lossy(&out.stdout);
    let (body, code) = text.rsplit_once('\n').unwrap_or(("", &text));
    match code.trim() {
        "200" => json_string(body, "tag_name").ok_or_else(|| "unerwartete Antwort von GitHub".to_string()),
        // GitHub also answers 404 while the repository is private
        "404" => Err("keine öffentliche Version gefunden".to_string()),
        "" | "000" => Err("GitHub nicht erreichbar – keine Internetverbindung?".to_string()),
        code => Err(format!("GitHub antwortet mit HTTP {code}")),
    }
}

/// The string value of `key` in a flat JSON object; enough for one field of a known API answer.
fn json_string(body: &str, key: &str) -> Option<String> {
    let rest = &body[body.find(&format!("\"{key}\""))? + key.len() + 2..];
    let rest = rest.trim_start().strip_prefix(':')?.trim_start().strip_prefix('"')?;
    Some(rest[..rest.find('"')?].to_string())
}

#[cfg(windows)]
mod imp {
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::net::Ipv4Addr;
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    use std::sync::Once;

    pub const PING_WORKERS: usize = 512;

    /// Windows has no per-process limit on open sockets worth worrying about.
    pub fn open_file_limit() -> usize {
        usize::MAX
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        fn IcmpCreateFile() -> *mut c_void;
        fn IcmpCloseHandle(handle: *mut c_void) -> i32;
        fn IcmpSendEcho(
            handle: *mut c_void, dest: u32, data: *const c_void, data_len: u16,
            options: *const c_void, reply: *mut c_void, reply_len: u32, timeout_ms: u32,
        ) -> u32;
        fn GetIpNetTable(table: *mut c_void, size: *mut u32, sort: i32) -> u32;
        fn GetBestRoute(dest: u32, src: u32, row: *mut c_void) -> u32;
        fn GetIpAddrTable(table: *mut c_void, size: *mut u32, sort: i32) -> u32;
    }

    #[link(name = "ws2_32")]
    extern "system" {
        fn WSAStartup(version: u16, data: *mut c_void) -> i32;
        fn GetNameInfoW(
            addr: *const c_void, addr_len: i32, host: *mut u16, host_len: u32,
            service: *mut u16, service_len: u32, flags: i32,
        ) -> i32;
    }

    /// ICMP echo via the Windows ICMP API (works without admin rights). Returns (round-trip ms, reply TTL).
    pub fn ping(ip: Ipv4Addr, timeout_ms: u32) -> Option<(u32, u8)> {
        let payload = *b"netscan-probe";
        let mut reply = [0u64; 32]; // 256 bytes, 8-byte aligned for ICMP_ECHO_REPLY + payload
        unsafe {
            let handle = IcmpCreateFile();
            if handle as isize == -1 {
                return None;
            }
            let replies = IcmpSendEcho(
                handle, u32::from_ne_bytes(ip.octets()), payload.as_ptr().cast(), payload.len() as u16,
                std::ptr::null(), reply.as_mut_ptr().cast(), std::mem::size_of_val(&reply) as u32, timeout_ms,
            );
            IcmpCloseHandle(handle);
            // ICMP_ECHO_REPLY: Address, Status, RoundTripTime (u32 each; Status 0 = success), DataSize, Reserved,
            // Data pointer at 16, then IP_OPTION_INFORMATION at 24 whose first byte is the TTL
            let words = reply.as_ptr().cast::<u32>();
            let ttl = *reply.as_ptr().cast::<u8>().add(24);
            (replies > 0 && *words.add(1) == 0).then(|| (*words.add(2), ttl))
        }
    }

    /// IP → MAC from the Windows ARP cache (dynamic and static entries only).
    pub fn arp_table() -> HashMap<Ipv4Addr, String> {
        // shortcut: a host that left the network in the last minutes can still be cached as alive
        let mut size = 0u32;
        unsafe { GetIpNetTable(std::ptr::null_mut(), &mut size, 0) };
        let mut buf = vec![0u32; size as usize / 4 + 1];
        if unsafe { GetIpNetTable(buf.as_mut_ptr().cast(), &mut size, 0) } != 0 {
            return HashMap::new();
        }
        // MIB_IPNETTABLE: entry count, then MIB_IPNETROW = index, mac_len, mac[8], addr, type (6 × u32)
        let count = buf[0] as usize;
        buf[1..]
            .chunks_exact(6)
            .take(count)
            .filter(|row| row[1] == 6 && matches!(row[5], 3 | 4))
            .filter_map(|row| {
                let mac: Vec<u8> = row[2].to_ne_bytes().into_iter().chain(row[3].to_ne_bytes()).take(6).collect();
                let multicast = mac[0] & 1 == 1; // also covers broadcast ff-ff-…
                (!multicast && mac.iter().any(|b| *b != 0)).then(|| {
                    let text = mac.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join("-");
                    (Ipv4Addr::from(row[4].to_ne_bytes()), text)
                })
            })
            .collect()
    }

    /// Next hop towards the internet = the default gateway of the active adapter.
    pub fn gateway() -> Option<Ipv4Addr> {
        let mut row = [0u32; 14]; // MIB_IPFORWARDROW; the next hop is its 4th field
        let rc = unsafe { GetBestRoute(u32::from_ne_bytes([8, 8, 8, 8]), 0, row.as_mut_ptr().cast()) };
        (rc == 0 && row[3] != 0).then(|| Ipv4Addr::from(row[3].to_ne_bytes()))
    }

    /// (own address, prefix length) of every connected IPv4 adapter, without loopback and link-local.
    pub fn local_networks() -> Vec<(Ipv4Addr, u32)> {
        let mut size = 0u32;
        unsafe { GetIpAddrTable(std::ptr::null_mut(), &mut size, 0) };
        let mut buf = vec![0u32; size as usize / 4 + 1];
        if unsafe { GetIpAddrTable(buf.as_mut_ptr().cast(), &mut size, 1) } != 0 {
            return Vec::new();
        }
        // MIB_IPADDRTABLE: entry count, then MIB_IPADDRROW = addr, index, mask, bcast, reasm, (unused u16, type u16)
        const DISCONNECTED: u32 = 0x08;
        const DELETED: u32 = 0x40;
        let count = buf[0] as usize;
        buf[1..]
            .chunks_exact(6)
            .take(count)
            .filter(|row| (row[5] >> 16) & (DISCONNECTED | DELETED) == 0)
            .map(|row| (Ipv4Addr::from(row[0].to_ne_bytes()), u32::from_be_bytes(row[2].to_ne_bytes()).count_ones()))
            .filter(|(ip, _)| !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified())
            .collect()
    }

    /// Reverse lookup through the Windows resolver (DNS, LLMNR, NetBIOS).
    pub fn hostname(ip: Ipv4Addr) -> Option<String> {
        static WINSOCK: Once = Once::new();
        WINSOCK.call_once(|| unsafe {
            let mut wsa_data = [0u8; 512]; // WSADATA, contents unused
            WSAStartup(0x0202, wsa_data.as_mut_ptr().cast());
        });
        // sockaddr_in: family AF_INET (2), port, address, 8 bytes padding
        let mut sockaddr = [0u8; 16];
        sockaddr[..2].copy_from_slice(&2u16.to_ne_bytes());
        sockaddr[4..8].copy_from_slice(&ip.octets());
        let mut name = [0u16; 1025]; // NI_MAXHOST
        const NI_NAMEREQD: i32 = 0x04; // fail instead of returning the numeric address
        let rc = unsafe {
            GetNameInfoW(sockaddr.as_ptr().cast(), 16, name.as_mut_ptr(), name.len() as u32, std::ptr::null_mut(), 0, NI_NAMEREQD)
        };
        let len = name.iter().position(|c| *c == 0).unwrap_or(name.len());
        (rc == 0 && len > 0).then(|| String::from_utf16_lossy(&name[..len]))
    }

    /// URLs, UNC paths and files go to their default program.
    pub fn open(target: &str) {
        let _ = Command::new("explorer").arg(target).spawn();
    }

    /// File share address: `\\ip` or `\\ip\name`.
    pub fn share(ip: Ipv4Addr, name: &str) -> String {
        if name.is_empty() { format!(r"\\{ip}") } else { format!(r"\\{ip}\{name}") }
    }

    pub fn remote_desktop(ip: Ipv4Addr) {
        let _ = Command::new("mstsc").arg(format!("/v:{ip}")).spawn();
    }

    /// Runs a command line tool in its own console window that stays open afterwards.
    fn console(args: &[&str]) {
        const CREATE_NEW_CONSOLE: u32 = 0x10;
        let _ = Command::new("cmd").arg("/k").args(args).creation_flags(CREATE_NEW_CONSOLE).spawn();
    }

    pub fn ssh(ip: Ipv4Addr) {
        console(&["ssh", &ip.to_string()]);
    }

    pub fn ping_forever(ip: Ipv4Addr) {
        console(&["ping", "-t", &ip.to_string()]);
    }

    pub fn traceroute(ip: Ipv4Addr) {
        console(&["tracert", "-d", &ip.to_string()]);
    }

    /// Runs the official install line in a visible window; it stops the installed NetScan and starts the new one.
    pub fn self_update(repo: &str) {
        let line = format!("irm https://raw.githubusercontent.com/{repo}/main/install.ps1 | iex");
        console(&["powershell", "-NoProfile", "-Command", &line]);
    }
}

#[cfg(unix)]
mod imp {
    use std::collections::HashMap;
    use std::ffi::{c_char, c_int, c_void, CStr};
    use std::net::Ipv4Addr;
    use std::process::Command;

    /// Each ping is a `ping` process: fewer at once than the Windows API calls.
    pub const PING_WORKERS: usize = 128;

    #[cfg(target_os = "macos")]
    #[repr(C)]
    struct SockaddrIn {
        len: u8,
        family: u8,
        port: u16,
        addr: [u8; 4],
        zero: [u8; 8],
    }

    /// Linux has no length byte; the family is a 16-bit field.
    #[cfg(not(target_os = "macos"))]
    #[repr(C)]
    struct SockaddrIn {
        family: u16,
        port: u16,
        addr: [u8; 4],
        zero: [u8; 8],
    }

    #[repr(C)]
    struct Ifaddrs {
        next: *mut Ifaddrs,
        name: *mut c_char,
        flags: u32,
        addr: *mut SockaddrIn,
        netmask: *mut SockaddrIn,
        dstaddr: *mut c_void,
        data: *mut c_void,
    }

    #[repr(C)]
    struct Rlimit {
        cur: u64,
        max: u64,
    }

    extern "C" {
        fn getrlimit(resource: c_int, rl: *mut Rlimit) -> c_int;
        fn setrlimit(resource: c_int, rl: *const Rlimit) -> c_int;
        fn getifaddrs(list: *mut *mut Ifaddrs) -> c_int;
        fn freeifaddrs(list: *mut Ifaddrs);
        fn getnameinfo(
            sa: *const SockaddrIn, salen: u32, host: *mut c_char, hostlen: u32, serv: *mut c_char, servlen: u32, flags: c_int,
        ) -> c_int;
    }

    #[cfg(target_os = "macos")]
    const AF_INET: u8 = 2;
    #[cfg(not(target_os = "macos"))]
    const AF_INET: u16 = 2;

    /// Raises the open-file limit to the hard limit and returns it. Linux starts GUI apps with 1024 open
    /// files, macOS with 256; a scan needs thousands of sockets at once.
    pub fn open_file_limit() -> usize {
        #[cfg(target_os = "macos")]
        const RLIMIT_NOFILE: c_int = 8;
        #[cfg(not(target_os = "macos"))]
        const RLIMIT_NOFILE: c_int = 7;
        // the kernels refuse more than OPEN_MAX (macOS) or nr_open (Linux, 2^20 by default)
        #[cfg(target_os = "macos")]
        const CEILING: u64 = 10240;
        #[cfg(not(target_os = "macos"))]
        const CEILING: u64 = 1 << 20;
        let mut rl = Rlimit { cur: 0, max: 0 };
        if unsafe { getrlimit(RLIMIT_NOFILE, &mut rl) } != 0 {
            return 256;
        }
        let want = rl.max.min(CEILING);
        if rl.cur < want && unsafe { setrlimit(RLIMIT_NOFILE, &Rlimit { cur: want, max: rl.max }) } == 0 {
            rl.cur = want;
        }
        rl.cur.try_into().unwrap_or(usize::MAX)
    }

    fn run(program: &str, args: &[&str]) -> String {
        Command::new(program).args(args).output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default()
    }

    #[cfg(target_os = "macos")]
    pub fn ping(ip: Ipv4Addr, timeout_ms: u32) -> Option<(u32, u8)> {
        // -W waits in milliseconds on macOS; -n skips the reverse lookup
        super::parse_ping(&run("/sbin/ping", &["-n", "-c", "1", "-W", &timeout_ms.to_string(), &ip.to_string()]))
    }

    /// iputils and busybox ping; unprivileged ICMP is allowed on current distributions.
    #[cfg(not(target_os = "macos"))]
    pub fn ping(ip: Ipv4Addr, timeout_ms: u32) -> Option<(u32, u8)> {
        // shortcut: -W takes whole seconds (busybox, older iputils), so a silent host costs 1 s instead of 0.8 s
        let secs = timeout_ms.div_ceil(1000).max(1).to_string();
        super::parse_ping(&run("ping", &["-n", "-c", "1", "-W", &secs, &ip.to_string()]))
    }

    #[cfg(target_os = "macos")]
    pub fn arp_table() -> HashMap<Ipv4Addr, String> {
        super::parse_arp(&run("/usr/sbin/arp", &["-an"]))
    }

    #[cfg(not(target_os = "macos"))]
    pub fn arp_table() -> HashMap<Ipv4Addr, String> {
        super::parse_proc_arp(&std::fs::read_to_string("/proc/net/arp").unwrap_or_default())
    }

    #[cfg(target_os = "macos")]
    pub fn gateway() -> Option<Ipv4Addr> {
        super::parse_route_gateway(&run("/sbin/route", &["-n", "get", "default"]))
    }

    #[cfg(not(target_os = "macos"))]
    pub fn gateway() -> Option<Ipv4Addr> {
        super::parse_proc_route(&std::fs::read_to_string("/proc/net/route").unwrap_or_default())
    }

    pub fn local_networks() -> Vec<(Ipv4Addr, u32)> {
        const IFF_UP: u32 = 0x1;
        const IFF_RUNNING: u32 = 0x40;
        let mut list = std::ptr::null_mut();
        if unsafe { getifaddrs(&mut list) } != 0 {
            return Vec::new();
        }
        let mut nets = Vec::new();
        let mut cur = list;
        while let Some(ifa) = unsafe { cur.as_ref() } {
            cur = ifa.next;
            let (Some(addr), Some(mask)) = (unsafe { ifa.addr.as_ref() }, unsafe { ifa.netmask.as_ref() }) else { continue };
            if addr.family != AF_INET || ifa.flags & (IFF_UP | IFF_RUNNING) != IFF_UP | IFF_RUNNING {
                continue;
            }
            let ip = Ipv4Addr::from(addr.addr);
            if !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified() {
                nets.push((ip, u32::from_be_bytes(mask.addr).count_ones()));
            }
        }
        unsafe { freeifaddrs(list) };
        nets
    }

    /// Reverse lookup through the system resolver (DNS and mDNS).
    pub fn hostname(ip: Ipv4Addr) -> Option<String> {
        #[cfg(target_os = "macos")]
        const NI_NAMEREQD: c_int = 0x04;
        #[cfg(not(target_os = "macos"))]
        const NI_NAMEREQD: c_int = 0x08;
        #[cfg(target_os = "macos")]
        let sa = SockaddrIn { len: 16, family: AF_INET, port: 0, addr: ip.octets(), zero: [0; 8] };
        #[cfg(not(target_os = "macos"))]
        let sa = SockaddrIn { family: AF_INET, port: 0, addr: ip.octets(), zero: [0; 8] };
        let mut name = [0 as c_char; 1025];
        let rc = unsafe { getnameinfo(&sa, 16, name.as_mut_ptr(), name.len() as u32, std::ptr::null_mut(), 0, NI_NAMEREQD) };
        (rc == 0).then(|| unsafe { CStr::from_ptr(name.as_ptr()) }.to_string_lossy().into_owned()).filter(|n| !n.is_empty())
    }

    pub fn open(target: &str) {
        #[cfg(target_os = "macos")]
        let _ = Command::new("open").arg(target).spawn();
        #[cfg(not(target_os = "macos"))]
        let _ = Command::new("xdg-open").arg(target).spawn();
    }

    /// Starts the first of these commands that is installed.
    #[cfg(not(target_os = "macos"))]
    fn spawn_first(commands: &[Vec<String>]) -> bool {
        commands.iter().any(|c| Command::new(&c[0]).args(&c[1..]).spawn().is_ok())
    }

    /// File share address: `smb://ip` or `smb://ip/name`.
    pub fn share(ip: Ipv4Addr, name: &str) -> String {
        if name.is_empty() { format!("smb://{ip}") } else { format!("smb://{ip}/{name}") }
    }

    /// Microsoft's "Windows App" (formerly Remote Desktop) handles rdp:// links.
    #[cfg(target_os = "macos")]
    pub fn remote_desktop(ip: Ipv4Addr) {
        open(&format!("rdp://full%20address=s:{ip}"));
    }

    /// Remmina or FreeRDP, whichever is installed.
    #[cfg(not(target_os = "macos"))]
    pub fn remote_desktop(ip: Ipv4Addr) {
        let cmd = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let v = format!("/v:{ip}");
        if !spawn_first(&[cmd(&["remmina", "-c", &format!("rdp://{ip}")]), cmd(&["xfreerdp3", &v]), cmd(&["xfreerdp", &v])]) {
            open(&format!("rdp://{ip}"));
        }
    }

    /// Runs a command in the first terminal emulator found; the window stays open until Enter.
    #[cfg(not(target_os = "macos"))]
    fn console(args: &[&str]) {
        let line = format!("{}; echo; printf 'Enter schliesst das Fenster '; read _", args.join(" "));
        let terminals: [&[&str]; 7] = [
            &["gnome-terminal", "--"],
            &["ptyxis", "--"],
            &["kgx", "--"],
            &["konsole", "-e"],
            &["xfce4-terminal", "-x"],
            &["x-terminal-emulator", "-e"],
            &["xterm", "-e"],
        ];
        let commands: Vec<Vec<String>> = terminals
            .iter()
            .map(|t| t.iter().copied().chain(["sh", "-c", line.as_str()]).map(String::from).collect())
            .collect();
        spawn_first(&commands);
    }

    /// Runs a command in a new Terminal window; the arguments are IPs and fixed words, nothing to escape.
    #[cfg(target_os = "macos")]
    fn console(args: &[&str]) {
        let script = format!("tell application \"Terminal\"\ndo script \"{}\"\nactivate\nend tell", args.join(" "));
        let _ = Command::new("osascript").args(["-e", &script]).spawn();
    }

    pub fn ssh(ip: Ipv4Addr) {
        console(&["ssh", &ip.to_string()]);
    }

    pub fn ping_forever(ip: Ipv4Addr) {
        console(&["ping", &ip.to_string()]);
    }

    pub fn traceroute(ip: Ipv4Addr) {
        #[cfg(target_os = "macos")]
        console(&["traceroute", "-n", &ip.to_string()]);
        // tracepath comes with iputils on every distribution, traceroute often isn't installed
        #[cfg(not(target_os = "macos"))]
        console(&["tracepath", "-n", &ip.to_string()]);
    }

    /// Runs the official install line in a terminal; it stops the running NetScan and starts the new one.
    pub fn self_update(repo: &str) {
        console(&[&format!("curl -fsSL https://raw.githubusercontent.com/{repo}/main/install.sh | sh")]);
    }
}

// the parsers serve macOS and Linux; they are tested on every platform
#[cfg_attr(windows, allow(dead_code))]
/// `64 bytes from 10.0.0.1: icmp_seq=0 ttl=64 time=2.645 ms` → (3, 64).
pub fn parse_ping(output: &str) -> Option<(u32, u8)> {
    let line = output.lines().find(|l| l.contains(" bytes from "))?;
    let field = |key: &str| line.split_whitespace().find_map(|w| w.strip_prefix(key));
    let ttl = field("ttl=")?.parse().ok()?;
    let ms: f32 = field("time=")?.parse().ok()?;
    Some((ms.round() as u32, ttl))
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
/// `? (10.0.0.1) at 0:11:22:a:b:c on en0 ifscope [ethernet]` → 10.0.0.1 → "00-11-22-0A-0B-0C".
pub fn parse_arp(output: &str) -> HashMap<Ipv4Addr, String> {
    output
        .lines()
        .filter_map(|line| {
            let ip = line.split_once('(')?.1.split_once(')')?.0.parse().ok()?;
            Some((ip, unicast_mac(line.split_once(" at ")?.1.split_whitespace().next()?)?))
        })
        .collect()
}

/// `0:11:22:a:b:c` → "00-11-22-0A-0B-0C"; broadcast, multicast and all-zero addresses → None.
#[cfg_attr(windows, allow(dead_code))]
fn unicast_mac(mac: &str) -> Option<String> {
    let bytes: Vec<u8> = mac.split(':').filter_map(|h| u8::from_str_radix(h, 16).ok()).collect();
    let usable = bytes.len() == 6 && bytes[0] & 1 == 0 && bytes.iter().any(|b| *b != 0);
    usable.then(|| bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join("-"))
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// Linux `/proc/net/arp`: `10.0.0.1  0x1  0x2  00:11:22:0a:0b:0c  *  eth0`; flags 0x0 is an unanswered entry.
pub fn parse_proc_arp(table: &str) -> HashMap<Ipv4Addr, String> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 4 || f[2] == "0x0" {
                return None;
            }
            Some((f[0].parse().ok()?, unicast_mac(f[3])?))
        })
        .collect()
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// Linux `/proc/net/route`: the default route (destination 0) with the lowest metric. The kernel prints
/// addresses as the raw 32-bit value, so `to_ne_bytes` gives the bytes back in network order.
pub fn parse_proc_route(table: &str) -> Option<Ipv4Addr> {
    const RTF_GATEWAY: u32 = 0x2;
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let hex = |i: usize| f.get(i).and_then(|v| u32::from_str_radix(v, 16).ok());
            if hex(1)? != 0 || hex(3)? & RTF_GATEWAY == 0 {
                return None;
            }
            Some((f.get(6)?.parse::<u32>().ok()?, Ipv4Addr::from(hex(2)?.to_ne_bytes())))
        })
        .min_by_key(|(metric, _)| *metric)
        .map(|(_, ip)| ip)
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
/// The `gateway: 10.0.0.1` line of `route -n get default`.
pub fn parse_route_gateway(output: &str) -> Option<Ipv4Addr> {
    output.lines().find_map(|l| l.trim().strip_prefix("gateway:")?.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_release_tag() {
        let body = r#"{"url":"x","tag_name" : "v0.3.1","name":"NetScan 0.3.1"}"#;
        assert_eq!(json_string(body, "tag_name").as_deref(), Some("v0.3.1"));
        assert_eq!(json_string(body, "missing"), None);
    }

    #[test]
    fn parses_macos_tool_output() {
        let ping = "PING 10.0.0.1 (10.0.0.1): 56 data bytes\n64 bytes from 10.0.0.1: icmp_seq=0 ttl=64 time=2.645 ms\n";
        assert_eq!(parse_ping(ping), Some((3, 64)));
        assert_eq!(parse_ping("Request timeout for icmp_seq 0"), None);

        let arp = "? (10.0.0.1) at 0:11:22:a:b:c on en0 ifscope [ethernet]\n\
                   ? (10.0.0.9) at (incomplete) on en0 ifscope [ethernet]\n\
                   ? (10.0.0.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n";
        let table = parse_arp(arp);
        assert_eq!(table.len(), 1);
        assert_eq!(table[&Ipv4Addr::new(10, 0, 0, 1)], "00-11-22-0A-0B-0C");

        let route = "   route to: default\ndestination: default\n    gateway: 192.168.1.1\n  interface: en0\n";
        assert_eq!(parse_route_gateway(route), Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn parses_linux_tables() {
        let ping = "PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.\n64 bytes from 10.0.0.1: icmp_seq=1 ttl=63 time=1.42 ms\n";
        assert_eq!(parse_ping(ping), Some((1, 63)));

        let arp = "IP address       HW type     Flags       HW address            Mask     Device\n\
                   10.0.0.1         0x1         0x2         00:11:22:0a:0b:0c     *        eth0\n\
                   10.0.0.9         0x1         0x0         00:00:00:00:00:00     *        eth0\n";
        let table = parse_proc_arp(arp);
        assert_eq!(table.len(), 1);
        assert_eq!(table[&Ipv4Addr::new(10, 0, 0, 1)], "00-11-22-0A-0B-0C");

        // VPN default route with a higher metric next to the LAN one; the subnet route has no gateway
        let route = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                     tun0\t00000000\t0100080A\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
                     eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
                     eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
        let lan = Ipv4Addr::from(0x0101_A8C0u32.to_ne_bytes());
        assert_eq!(parse_proc_route(route), Some(lan));
        if cfg!(target_endian = "little") {
            assert_eq!(lan, Ipv4Addr::new(192, 168, 1, 1));
        }
    }
}
