//! Host discovery (ICMP, ARP table, TCP) and TCP port scanning, all blocking calls fanned out over threads.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};

use crate::fingerprint;
pub use crate::platform::{arp_table, gateway, hostname, local_networks, ping};
use crate::platform::PING_WORKERS;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

/// Ports tried on hosts that ignore ping (e.g. Windows firewall), so routed subnets work too.
const PROBE_PORTS: &[u16] = &[445, 80, 443, 22, 3389, 135, 139, 8080];
/// Checked on every live host during the IP scan: enough to tell device types and server roles apart
/// (DNS, Kerberos/LDAP = domain controller, SQL, WinRM, ESXi, Proxmox, Synology, iPhone lockdown).
pub const SERVICE_PORTS: &[u16] = &[
    21, 22, 23, 53, 80, 88, 135, 139, 389, 443, 445, 515, 548, 554, 631, 902, 1433, 3306, 3389, 5000, 5432, 5900, 5985,
    5357, 8006, 8080, 9100, 62078,
];
const PING_TIMEOUT_MS: u32 = 800;
const PROBE_TIMEOUT_MS: u64 = 400;
/// Wi-Fi laptops in power save answer TCP slower than ping; still finishes inside NAME_DEADLINE.
const SERVICE_TIMEOUT_MS: u64 = 1000;
/// Names that resolve come back in < 1 s; failing lookups hang 5-10 s in the NetBIOS fallback.
const NAME_DEADLINE: Duration = Duration::from_millis(1500);
/// UPnP answers arrive within the MX window (1 s); the rest of the scan runs meanwhile.
const SSDP_LISTEN: Duration = Duration::from_millis(2500);
const STACK: usize = 256 * 1024; // thousands of mostly-waiting threads; keep the reservation small

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Kind {
    Router,
    ThisPc,
    WindowsServer,
    WindowsClient,
    LinuxServer,
    Nas,
    Hypervisor,
    Network,
    Printer,
    Apple,
    Mobile,
    Media,
    Unknown,
}

impl Kind {
    pub const ALL: [Kind; 13] = [
        Kind::Router, Kind::ThisPc, Kind::WindowsServer, Kind::WindowsClient, Kind::LinuxServer, Kind::Nas, Kind::Hypervisor,
        Kind::Network, Kind::Printer, Kind::Apple, Kind::Mobile, Kind::Media, Kind::Unknown,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Kind::Router => "Router / Gateway",
            Kind::ThisPc => "Dieser PC",
            Kind::WindowsServer => "Windows-Server",
            Kind::WindowsClient => "Windows-Client",
            Kind::LinuxServer => "Linux-/Unix-Server",
            Kind::Nas => "NAS / Speicher",
            Kind::Hypervisor => "Virtualisierungs-Host",
            Kind::Network => "Netzwerkgerät",
            Kind::Printer => "Drucker / Scanner",
            Kind::Apple => "Apple / macOS",
            Kind::Mobile => "Smartphone / Tablet",
            Kind::Media => "Multimedia / IoT",
            Kind::Unknown => "Unbekannt",
        }
    }

    /// Symbol for the network map (egui's built-in emoji font).
    pub fn icon(self) -> &'static str {
        match self {
            Kind::Router => "📶",
            Kind::ThisPc => "💻",
            Kind::WindowsServer => "🗄",
            Kind::WindowsClient => "🖥",
            Kind::LinuxServer => "🐧",
            Kind::Nas => "💾",
            Kind::Hypervisor => "☁",
            Kind::Network => "🔀",
            Kind::Printer => "🖨",
            Kind::Apple => "🍏",
            Kind::Mobile => "📱",
            Kind::Media => "📺",
            Kind::Unknown => "❔",
        }
    }

    /// Shared by the window and the Excel report so both use the same colors.
    pub fn rgb(self) -> [u8; 3] {
        match self {
            Kind::Router => [139, 92, 246],
            Kind::ThisPc => [34, 197, 94],
            Kind::WindowsServer => [29, 78, 216],
            Kind::WindowsClient => [96, 165, 250],
            Kind::LinuxServer => [13, 148, 136],
            Kind::Nas => [234, 88, 12],
            Kind::Hypervisor => [217, 70, 239],
            Kind::Network => [6, 182, 212],
            Kind::Printer => [245, 158, 11],
            Kind::Apple => [71, 85, 105],
            Kind::Mobile => [244, 63, 94],
            Kind::Media => [132, 204, 22],
            Kind::Unknown => [148, 163, 184],
        }
    }
}

pub struct Host {
    pub ip: Ipv4Addr,
    pub rtt_ms: Option<u32>,
    pub ttl: Option<u8>,
    pub mac: Option<String>,
    pub name: Option<String>,
    pub services: Vec<u16>,
    pub kind: Kind,
    pub os: Option<String>,
    /// "SMB", "WinRM", "SSH", "mDNS", … or "TTL" when the OS is only guessed from the hop count.
    pub os_source: Option<&'static str>,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub domain: Option<String>,
    /// Evidence lines ("SSH: …", "SNMP: …") shown in tooltips and the report.
    pub details: Vec<String>,
}

/// Shared between the scan thread and the window: what is running, how far, and the stop request.
#[derive(Default)]
pub struct Progress {
    done: AtomicUsize,
    total: AtomicUsize,
    stage: Mutex<&'static str>,
    cancel: AtomicBool,
}

impl Progress {
    fn start(&self, stage: &'static str, total: usize) {
        *self.stage.lock().unwrap() = stage;
        self.total.store(total, Ordering::Relaxed);
        self.done.store(0, Ordering::Relaxed);
    }

    /// (stage, done, total)
    pub fn snapshot(&self) -> (&'static str, usize, usize) {
        (*self.stage.lock().unwrap(), self.done.load(Ordering::Relaxed), self.total.load(Ordering::Relaxed))
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    pub fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
}

/// Wake-on-LAN magic packet: 6 × 0xFF, then the MAC 16 times.
pub fn magic_packet(mac: &str) -> Option<Vec<u8>> {
    let bytes: Vec<u8> = mac.split(['-', ':']).filter_map(|h| u8::from_str_radix(h, 16).ok()).collect();
    (bytes.len() == 6).then(|| [0xFF; 6].into_iter().chain(bytes.iter().copied().cycle().take(96)).collect())
}

pub fn wake_on_lan(mac: &str, ip: Ipv4Addr) -> std::io::Result<()> {
    let packet = magic_packet(mac).ok_or_else(|| std::io::Error::other("ungültige MAC-Adresse"))?;
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_broadcast(true)?;
    // shortcut: directed broadcast assumes a /24; the global broadcast covers the local segment anyway
    let o = ip.octets();
    socket.send_to(&packet, (Ipv4Addr::new(o[0], o[1], o[2], 255), 9))?;
    socket.send_to(&packet, (Ipv4Addr::BROADCAST, 9))?;
    Ok(())
}

/// Compared with an earlier scan of the same range: addresses that are new, and hosts no longer answering.
pub fn changes(old: Vec<Host>, new: &[Host]) -> (HashSet<Ipv4Addr>, Vec<Host>) {
    let before: HashSet<Ipv4Addr> = old.iter().map(|h| h.ip).collect();
    let added = new.iter().map(|h| h.ip).filter(|ip| !before.contains(ip)).collect();
    let gone = old.into_iter().filter(|h| !new.iter().any(|n| n.ip == h.ip)).collect();
    (added, gone)
}

pub fn tcp_open(ip: Ipv4Addr, port: u16, timeout_ms: u64) -> bool {
    TcpStream::connect_timeout(&SocketAddr::from((ip, port)), Duration::from_millis(timeout_ms)).is_ok()
}

/// Every worker holds a socket or a `ping` process with its pipes. Past the open-file limit connects fail
/// silently and, on Linux, the window loses the descriptors it needs for Wayland/X11 buffers and dies.
fn max_workers() -> usize {
    static MAX: OnceLock<usize> = OnceLock::new();
    // ponytail: /8 leaves room for two pools at once (ping processes use ~6 descriptors) plus the window
    *MAX.get_or_init(|| (crate::platform::open_file_limit() / 8).max(16))
}

/// Runs `f` over `items` on up to `workers` threads, results in input order. Counts into `progress`;
/// after a stop request the remaining items get `R::default()` without running `f`.
pub fn par_map<T: Sync, R: Send + Default>(items: &[T], workers: usize, progress: &Progress, f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let next = AtomicUsize::new(0);
    let results: Vec<Mutex<Option<R>>> = items.iter().map(|_| Mutex::new(None)).collect();
    thread::scope(|s| {
        for _ in 0..workers.min(max_workers()).min(items.len()) {
            thread::Builder::new()
                .stack_size(STACK)
                .spawn_scoped(s, || loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(i) else { break };
                    let r = if progress.cancelled() { R::default() } else { f(item) };
                    *results[i].lock().unwrap() = Some(r);
                    progress.done.fetch_add(1, Ordering::Relaxed);
                })
                .expect("Thread konnte nicht gestartet werden");
        }
    });
    results.into_iter().map(|r| r.into_inner().unwrap().expect("jedes Element verarbeitet")).collect()
}

/// Looks up all names in parallel and returns what arrived before the deadline; stragglers finish in the background.
pub fn hostnames(ips: &[Ipv4Addr]) -> Vec<Option<String>> {
    let (tx, rx) = mpsc::channel();
    for (i, ip) in ips.iter().copied().enumerate() {
        let tx = tx.clone();
        // one thread per live host: fine for LANs, a /16 full of hosts would spawn thousands
        let _ = thread::Builder::new().stack_size(STACK).spawn(move || tx.send((i, hostname(ip))));
    }
    drop(tx);
    let mut names = vec![None; ips.len()];
    let deadline = Instant::now() + NAME_DEADLINE;
    while let Ok((i, name)) = rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        names[i] = name;
    }
    names
}

pub fn discover(ips: &[Ipv4Addr], progress: &Progress) -> Vec<Host> {
    thread::scope(|outer| {
        // UPnP devices answer one multicast search; listen for them while the rest of the scan runs
        let upnp = outer.spawn(|| fingerprint::ssdp(SSDP_LISTEN));

        // Ping alone first: it also triggers ARP for the whole subnet. Running ARP/TCP at the same time
        // makes Windows drop the echo while the neighbor is unresolved (IP_REQ_TIMED_OUT within ~100 ms).
        progress.start("Ping", ips.len());
        let mut echoes = par_map(ips, PING_WORKERS, progress, |ip| ping(*ip, PING_TIMEOUT_MS));

        // Second round with ARP resolved: a second chance for the silent ones, and a true round-trip time
        // for the rest (the first echo also waited for ARP). Meanwhile TCP for hosts that drop ICMP.
        let silent: Vec<Ipv4Addr> = ips.iter().zip(&echoes).filter(|(_, r)| r.is_none()).map(|(ip, _)| *ip).collect();
        let probes: Vec<(Ipv4Addr, u16)> = silent.iter().flat_map(|ip| PROBE_PORTS.iter().map(move |p| (*ip, *p))).collect();
        progress.start("Nachprüfung", ips.len() + probes.len());
        let (retries, tcp_alive) = thread::scope(|s| {
            let tcp = s.spawn(|| {
                par_map(&probes, 1024, progress, |(ip, port)| tcp_open(*ip, *port, PROBE_TIMEOUT_MS).then_some(*ip))
                    .into_iter()
                    .flatten()
                    .collect::<HashSet<_>>()
            });
            (par_map(ips, PING_WORKERS, progress, |ip| ping(*ip, PING_TIMEOUT_MS)), tcp.join().unwrap())
        });
        for (echo, retry) in echoes.iter_mut().zip(retries) {
            *echo = match (*echo, retry) {
                (Some(a), Some(b)) => Some(if b.0 < a.0 { b } else { a }),
                (a, b) => a.or(b),
            };
        }

        // Local hosts that drop ping and TCP still had to answer ARP
        let mut arp = arp_table();
        let alive: Vec<(Ipv4Addr, Option<(u32, u8)>, Option<String>)> = ips
            .iter()
            .zip(echoes)
            .map(|(ip, echo)| (*ip, echo, arp.remove(ip)))
            .filter(|(ip, echo, mac)| echo.is_some() || mac.is_some() || tcp_alive.contains(ip))
            .collect();
        let addrs: Vec<Ipv4Addr> = alive.iter().map(|(ip, ..)| *ip).collect();

        // Names run alongside the service check and the identification that builds on it
        let checks: Vec<(Ipv4Addr, u16)> = addrs.iter().flat_map(|ip| SERVICE_PORTS.iter().map(move |p| (*ip, *p))).collect();
        progress.start("Dienste & Namen", checks.len());
        let (names, services, evidence) = thread::scope(|s| {
            let names = s.spawn(|| hostnames(&addrs));
            let open = scan_ports_inner(&checks, SERVICE_TIMEOUT_MS, progress);
            let services: Vec<Vec<u16>> =
                addrs.iter().map(|ip| open.iter().filter(|(o, _)| o == ip).map(|(_, p)| *p).collect()).collect();
            progress.start("Erkennung", addrs.len());
            let indices: Vec<usize> = (0..addrs.len()).collect();
            let evidence = par_map(&indices, 128, progress, |i| fingerprint::probe(addrs[*i], &services[*i]));
            (names.join().unwrap(), services, evidence)
        });

        let mut upnp = upnp.join().unwrap_or_default();
        let (gateway, own) = (gateway(), crate::parse::local_ip());
        alive
            .into_iter()
            .zip(names)
            .zip(services)
            .zip(evidence)
            .map(|((((ip, echo, mac), name), services), mut ev)| {
                ev.upnp = upnp.remove(&ip);
                let ttl = echo.map(|(_, ttl)| ttl);
                let id = fingerprint::identify(ip, ttl, &services, mac.as_deref(), &ev, gateway, own);
                Host {
                    ip,
                    rtt_ms: echo.map(|(rtt, _)| rtt),
                    ttl,
                    mac,
                    // reverse DNS first, then the name the host reports over SMB/WinRM, then its mDNS name
                    name: name.or(id.computer).or(id.mdns_name),
                    services,
                    kind: id.kind,
                    os: id.os,
                    os_source: id.os_source,
                    vendor: id.vendor,
                    model: id.model,
                    domain: id.domain,
                    details: id.details,
                }
            })
            .collect()
    })
}

impl Host {
    /// The OS comes only from the TTL start value, not from anything the host said.
    pub fn os_guessed(&self) -> bool {
        self.os_source == Some("TTL")
    }
}

/// What each open port says about itself: banner, web server and title, or the Windows build.
pub fn port_details(open: &[(Ipv4Addr, u16)], progress: &Progress) -> Vec<Option<String>> {
    progress.start("Dienstversionen", open.len());
    par_map(open, 256, progress, |(ip, port)| fingerprint::port_info(*ip, *port))
}

/// Every host × port combination in parallel; returns the open ones in host/port order.
pub fn scan_ports(hosts: &[Ipv4Addr], ports: &[u16], timeout_ms: u64, progress: &Progress) -> Vec<(Ipv4Addr, u16)> {
    let pairs: Vec<(Ipv4Addr, u16)> = hosts.iter().flat_map(|h| ports.iter().map(move |p| (*h, *p))).collect();
    progress.start("Ports", pairs.len());
    scan_ports_inner(&pairs, timeout_ms, progress)
}

fn scan_ports_inner(pairs: &[(Ipv4Addr, u16)], timeout_ms: u64, progress: &Progress) -> Vec<(Ipv4Addr, u16)> {
    let open = par_map(pairs, 2000, progress, |(ip, port)| tcp_open(*ip, *port, timeout_ms));
    pairs.iter().zip(open).filter_map(|(pair, ok)| ok.then_some(*pair)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn ping_localhost() {
        assert!(ping(Ipv4Addr::LOCALHOST, 1000).is_some());
    }

    #[test]
    fn resolves_localhost_name() {
        assert!(hostname(Ipv4Addr::LOCALHOST).is_some());
        assert!(hostnames(&[Ipv4Addr::LOCALHOST])[0].is_some());
    }

    #[test]
    fn arp_table_has_no_broadcast_or_empty_macs() {
        for mac in arp_table().values() {
            assert!(mac.len() == 17 && mac != "00-00-00-00-00-00" && !mac.starts_with("FF"), "{mac}");
        }
    }

    #[test]
    fn finds_listening_port() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let closed = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port(); // released again
        let progress = Progress::default();
        let open = scan_ports(&[Ipv4Addr::LOCALHOST], &[port, closed], 500, &progress);
        assert_eq!(open, vec![(Ipv4Addr::LOCALHOST, port)]);
        assert_eq!(progress.snapshot(), ("Ports", 2, 2));
    }

    #[test]
    fn wake_packet_and_scan_changes() {
        let p = magic_packet("00-11-22-AA-bb-CC").unwrap();
        assert_eq!((p.len(), &p[..7], &p[96..]), (102, &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00][..], &[0x00, 0x11, 0x22, 0xAA, 0xBB, 0xCC][..]));
        assert_eq!(magic_packet("kaputt"), None);

        let host = |last: u8| Host {
            ip: Ipv4Addr::new(10, 0, 0, last), rtt_ms: None, ttl: None, mac: None, name: None, services: vec![],
            kind: Kind::Unknown, os: None, os_source: None, vendor: None, model: None, domain: None, details: vec![],
        };
        let (added, gone) = changes(vec![host(1), host(2)], &[host(2), host(3)]);
        assert_eq!(added, HashSet::from([Ipv4Addr::new(10, 0, 0, 3)]));
        assert_eq!(gone.iter().map(|h| h.ip).collect::<Vec<_>>(), [Ipv4Addr::new(10, 0, 0, 1)]);
    }

    #[test]
    fn local_networks_are_real_adapters() {
        for (ip, prefix) in local_networks() {
            assert!(!ip.is_loopback() && (1..=32).contains(&prefix), "{ip}/{prefix}");
        }
    }

    #[test]
    fn par_map_keeps_order_and_honours_stop() {
        let input: Vec<u32> = (0..1000).collect();
        let progress = Progress::default();
        assert_eq!(par_map(&input, 37, &progress, |x| x * 2), input.iter().map(|x| x * 2).collect::<Vec<_>>());
        progress.cancel();
        assert!(par_map(&input, 37, &progress, |x| x * 2).iter().all(|x| *x == 0));
    }

    /// Manual check against the real network: cargo test live_scan -- --ignored --nocapture
    #[test]
    #[ignore = "scans the local network"]
    fn live_scan() {
        let range = crate::parse::default_range(&local_networks(), crate::parse::local_ip());
        let ips = crate::parse::parse_hosts(&range).unwrap();
        let started = Instant::now();
        let hosts = discover(&ips, &Progress::default());
        for h in &hosts {
            println!(
                "{:<16} {:<24} {:<22} {:<44} {:<28} {}",
                h.ip.to_string(),
                h.name.as_deref().unwrap_or("-"),
                h.kind.label(),
                format!("{} [{}]", h.os.as_deref().unwrap_or("-"), h.os_source.unwrap_or("-")),
                format!("{} {}", h.vendor.as_deref().unwrap_or(""), h.model.as_deref().unwrap_or("")),
                h.details.join(" | ")
            );
        }
        println!("{} Hosts in {:.1} s", hosts.len(), started.elapsed().as_secs_f32());
    }
}
