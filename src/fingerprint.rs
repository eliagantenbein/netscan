//! Device identification without admin rights: TTL, service banners, SMB/WinRM NTLM, SNMP, mDNS and UPnP.
//! Everything here only reads what a device tells any client that asks; nothing logs in.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::thread::{self, ScopedJoinHandle};
use std::time::{Duration, Instant};

use crate::oui;
use crate::scan::{par_map, Kind, Progress};

const TIMEOUT: Duration = Duration::from_millis(1200);
const SNMP_TIMEOUT: Duration = Duration::from_millis(900);

#[derive(Default, Clone, Debug)]
pub struct Http {
    pub server: Option<String>,
    pub title: Option<String>,
}

#[derive(Default, Clone, Debug)]
pub struct Smb {
    pub major: u8,
    pub minor: u8,
    pub build: u16,
    pub computer: Option<String>,
    pub domain: Option<String>,
    pub dns_domain: Option<String>,
}

#[derive(Default, Clone, Debug)]
pub struct Mdns {
    pub name: Option<String>,
    /// Apple model identifier from the `_device-info` record, e.g. "MacBookPro18,3".
    pub model: Option<String>,
}

#[derive(Default, Clone, Debug)]
pub struct Upnp {
    pub server: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub friendly: Option<String>,
}

/// What one host revealed about itself.
#[derive(Default, Clone, Debug)]
pub struct Evidence {
    pub ssh: Option<String>,
    pub ftp: Option<String>,
    pub http: Option<Http>,
    pub smb: Option<Smb>,
    /// The same NTLM details, read over WinRM when SMB is closed (typical for servers behind a firewall).
    pub winrm: Option<Smb>,
    pub snmp: Option<String>,
    pub mdns: Option<Mdns>,
    pub upnp: Option<Upnp>,
}

pub struct Identity {
    pub kind: Kind,
    pub os: Option<String>,
    /// Where the OS came from: "SMB", "WinRM", "SSH", … or "TTL" for a mere guess.
    pub os_source: Option<&'static str>,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub domain: Option<String>,
    pub computer: Option<String>,
    pub mdns_name: Option<String>,
    pub details: Vec<String>,
}

// ---------------------------------------------------------------- probes

fn connect(ip: Ipv4Addr, port: u16) -> Option<TcpStream> {
    let stream = TcpStream::connect_timeout(&SocketAddr::from((ip, port)), TIMEOUT).ok()?;
    stream.set_read_timeout(Some(TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(TIMEOUT)).ok()?;
    Some(stream)
}

fn clean(s: &str) -> String {
    let text: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).take(200).collect();
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn non_empty(s: String) -> Option<String> {
    (!s.is_empty()).then_some(s)
}

/// First line a server sends on connect (SSH, FTP).
pub fn banner(ip: Ipv4Addr, port: u16) -> Option<String> {
    let mut stream = connect(ip, port)?;
    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf).ok()?;
    non_empty(clean(String::from_utf8_lossy(&buf[..n]).lines().next()?))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Text between `<name ...>` and `</name>`, case-insensitive.
pub fn tag(text: &str, name: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let open = lower.find(&format!("<{name}"))?;
    let start = open + lower[open..].find('>')? + 1;
    let end = start + lower[start..].find(&format!("</{name}"))?;
    non_empty(clean(&text[start..end].replace("&amp;", "&")))
}

fn header(text: &str, name: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then(|| clean(value)).and_then(non_empty)
    })
}

fn http_get(ip: Ipv4Addr, port: u16, path: &str) -> Option<String> {
    let mut stream = connect(ip, port)?;
    write!(stream, "GET {path} HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetScan\r\nConnection: close\r\n\r\n").ok()?;
    let mut buf = Vec::new();
    let _ = (&stream).take(64 * 1024).read_to_end(&mut buf); // a read timeout still leaves what arrived
    (!buf.is_empty()).then(|| String::from_utf8_lossy(&buf).into_owned())
}

pub fn http(ip: Ipv4Addr, port: u16) -> Option<Http> {
    let text = http_get(ip, port, "/")?;
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    Some(Http { server: header(head, "server"), title: tag(body, "title") })
}

/// SPNEGO NegTokenInit wrapping a 40-byte NTLMSSP NEGOTIATE (all DER lengths are fixed).
const SPNEGO_PREFIX: [u8; 34] = [
    0x60, 0x48, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x3e, 0x30, 0x3c, 0xa0, 0x0e, 0x30, 0x0c, 0x06, 0x0a,
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0xa2, 0x2a, 0x04, 0x28,
];

fn smb2_send(stream: &mut TcpStream, command: u16, message_id: u64, body: &[u8]) -> Option<()> {
    let mut msg = vec![0u8; 4]; // NetBIOS session header, length filled in below
    msg.extend(b"\xFESMB");
    msg.extend(64u16.to_le_bytes()); // header size
    msg.extend([0u8; 6]); // credit charge, status
    msg.extend(command.to_le_bytes());
    msg.extend(1u16.to_le_bytes()); // credits requested
    msg.extend([0u8; 8]); // flags, next command
    msg.extend(message_id.to_le_bytes());
    msg.extend([0u8; 32]); // reserved, tree id, session id, signature
    msg.extend(body);
    let len = (msg.len() - 4) as u32;
    msg[1..4].copy_from_slice(&len.to_be_bytes()[1..]);
    stream.write_all(&msg).ok()
}

fn netbios_read(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).ok()?;
    let len = u32::from_be_bytes([0, head[1], head[2], head[3]]) as usize;
    if len > 1 << 20 {
        return None;
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).ok()?;
    Some(buf)
}

/// 40-byte NTLMSSP NEGOTIATE asking for the server's version and target info.
fn ntlm_negotiate() -> Vec<u8> {
    let mut m = b"NTLMSSP\0".to_vec();
    m.extend(1u32.to_le_bytes()); // NEGOTIATE message
    m.extend(0xE208_8297u32.to_le_bytes()); // unicode, NTLM, target info, version, 128/56 bit …
    m.extend([0u8; 24]); // empty domain/workstation fields, version
    m
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            out.push(if i <= chunk.len() { B64[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    out
}

fn unbase64(text: &str) -> Vec<u8> {
    let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0);
    for v in text.bytes().filter_map(|c| B64.iter().position(|b| *b == c)) {
        acc = (acc << 6 | v as u32) & 0xFFFF;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

/// WinRM (HTTP 5985) answers an NTLM negotiate with the same challenge as SMB: version, name, domain.
pub fn winrm(ip: Ipv4Addr) -> Option<Smb> {
    let mut stream = connect(ip, 5985)?;
    let token = base64(&ntlm_negotiate());
    write!(stream, "POST /wsman HTTP/1.1\r\nHost: {ip}:5985\r\nAuthorization: Negotiate {token}\r\nContent-Length: 0\r\n\r\n").ok()?;
    let mut buf = [0u8; 8192];
    let mut len = 0;
    // the 401 head is all we need; don't wait for the server to close a kept-alive connection
    while let Ok(n @ 1..) = stream.read(&mut buf[len..]) {
        len += n;
        if find(&buf[..len], b"\r\n\r\n").is_some() || len == buf.len() {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf[..len]);
    let token = head.lines().find_map(|l| {
        let (key, value) = l.split_once(':')?;
        key.trim().eq_ignore_ascii_case("www-authenticate").then(|| value.trim().strip_prefix("Negotiate ").map(str::to_string))?
    })?;
    let raw = unbase64(token.trim());
    parse_challenge(&raw[find(&raw, b"NTLMSSP\0\x02\0\0\0")?..])
}

fn dns_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut q = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]; // id 0, flags 0, one question
    for label in name.split('.').filter(|l| !l.is_empty()) {
        let bytes = &label.as_bytes()[..label.len().min(63)];
        q.push(bytes.len() as u8);
        q.extend(bytes);
    }
    q.push(0);
    q.extend(qtype.to_be_bytes());
    q.extend(1u16.to_be_bytes()); // class IN
    q
}

/// A possibly compressed DNS name at `pos`, and the position right after it.
fn dns_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let (mut labels, mut end, mut jumps) = (Vec::new(), None, 0);
    loop {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            end.get_or_insert(pos + 2);
            jumps += 1;
            if jumps > 16 {
                return None;
            }
            pos = (len & 0x3F) << 8 | *msg.get(pos + 1)? as usize;
            continue;
        }
        labels.push(String::from_utf8_lossy(msg.get(pos + 1..pos + 1 + len)?).into_owned());
        pos += 1 + len;
    }
    Some((labels.join("."), end.unwrap_or(pos)))
}

/// Every resource record of a DNS reply as (type, rdata offset, rdata length).
fn dns_records(msg: &[u8]) -> Vec<(u16, usize, usize)> {
    let count = |o: usize| msg.get(o..o + 2).map_or(0, |b| u16::from_be_bytes([b[0], b[1]]) as usize);
    let mut pos = 12;
    for _ in 0..count(4) {
        let Some((_, p)) = dns_name(msg, pos) else { return Vec::new() };
        pos = p + 4;
    }
    let mut out = Vec::new();
    for _ in 0..count(6) + count(8) + count(10) {
        let Some((_, p)) = dns_name(msg, pos) else { break };
        let Some(h) = msg.get(p..p + 10) else { break };
        let len = u16::from_be_bytes([h[8], h[9]]) as usize;
        out.push((u16::from_be_bytes([h[0], h[1]]), p + 10, len));
        pos = p + 10 + len;
    }
    out
}

/// `model=` from any TXT record in the reply.
fn txt_model(msg: &[u8]) -> Option<String> {
    dns_records(msg).into_iter().filter(|r| r.0 == 16).find_map(|(_, at, len)| {
        let mut data = msg.get(at..at + len)?;
        while let Some((&n, rest)) = data.split_first() {
            let entry = rest.get(..n as usize)?;
            if let Some(model) = entry.strip_prefix(b"model=") {
                return non_empty(String::from_utf8_lossy(model).into_owned());
            }
            data = &rest[n as usize..];
        }
        None
    })
}

/// Asks the host's own mDNS responder directly (legacy unicast): Macs, iPhones, printers and many IoT devices answer.
pub fn mdns(ip: Ipv4Addr) -> Option<Mdns> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(SNMP_TIMEOUT)).ok()?;
    let ask = |name: &str, qtype: u16| -> Option<Vec<u8>> {
        socket.send_to(&dns_query(name, qtype), (ip, 5353)).ok()?;
        let mut buf = [0u8; 4096];
        let (n, from) = socket.recv_from(&mut buf).ok()?;
        (from.ip() == IpAddr::V4(ip)).then(|| buf[..n].to_vec())
    };
    let o = ip.octets();
    let reply = ask(&format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]), 12)?;
    let name = dns_records(&reply).into_iter().find(|r| r.0 == 12).and_then(|(_, at, _)| dns_name(&reply, at)).map(|(n, _)| n);
    // the device-info TXT usually rides along as additional record; otherwise ask for it by instance name
    let model = ask("_device-info._tcp.local", 12).and_then(|r| {
        txt_model(&r).or_else(|| {
            let (_, at, _) = dns_records(&r).into_iter().find(|x| x.0 == 12)?;
            txt_model(&ask(&dns_name(&r, at)?.0, 16)?)
        })
    });
    Some(Mdns { name: name.filter(|n| !n.is_empty()), model })
}

/// SMB2 negotiate + anonymous session setup: the NTLM challenge carries OS version, name and domain.
pub fn smb(ip: Ipv4Addr) -> Option<Smb> {
    let mut stream = connect(ip, 445)?;
    let mut negotiate = Vec::new();
    negotiate.extend(36u16.to_le_bytes()); // structure size
    negotiate.extend(2u16.to_le_bytes()); // dialect count
    negotiate.extend(1u16.to_le_bytes()); // signing enabled
    negotiate.extend([0u8; 6]); // reserved, capabilities
    negotiate.extend(*b"NetScanClientId!"); // client guid
    negotiate.extend([0u8; 8]); // start time
    negotiate.extend(0x0202u16.to_le_bytes());
    negotiate.extend(0x0210u16.to_le_bytes());
    smb2_send(&mut stream, 0, 0, &negotiate)?;
    netbios_read(&mut stream)?;

    let mut token = SPNEGO_PREFIX.to_vec();
    token.extend(ntlm_negotiate());
    let mut setup = Vec::new();
    setup.extend(25u16.to_le_bytes()); // structure size
    setup.extend([0u8, 1]); // flags, signing enabled
    setup.extend([0u8; 8]); // capabilities, channel
    setup.extend(88u16.to_le_bytes()); // security buffer offset = 64 header + 24 body
    setup.extend((token.len() as u16).to_le_bytes());
    setup.extend([0u8; 8]); // previous session
    setup.extend(token);
    smb2_send(&mut stream, 1, 1, &setup)?;
    let reply = netbios_read(&mut stream)?;
    parse_challenge(&reply[find(&reply, b"NTLMSSP\0\x02\0\0\0")?..])
}

fn parse_challenge(b: &[u8]) -> Option<Smb> {
    let u16_at = |o: usize| Some(u16::from_le_bytes([*b.get(o)?, *b.get(o + 1)?]));
    let u32_at = |o: usize| Some(u32::from_le_bytes([*b.get(o)?, *b.get(o + 1)?, *b.get(o + 2)?, *b.get(o + 3)?]));
    let flags = u32_at(20)?;
    let mut smb = Smb::default();
    if flags & 0x0200_0000 != 0 {
        // NTLMSSP_NEGOTIATE_VERSION: major, minor, build
        smb.major = *b.get(48)?;
        smb.minor = *b.get(49)?;
        smb.build = u16_at(50)?;
    }
    let (len, offset) = (u16_at(40)? as usize, u32_at(44)? as usize);
    let info = b.get(offset..offset + len).unwrap_or(&[]);
    let mut i = 0;
    while i + 4 <= info.len() {
        let id = u16::from_le_bytes([info[i], info[i + 1]]);
        let n = u16::from_le_bytes([info[i + 2], info[i + 3]]) as usize;
        let Some(raw) = info.get(i + 4..i + 4 + n) else { break };
        let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let value = non_empty(String::from_utf16_lossy(&units));
        match id {
            0 => break,
            1 => smb.computer = smb.computer.take().or(value),
            2 => smb.domain = value,
            3 => smb.computer = value.or(smb.computer.take()), // DNS name beats NetBIOS name
            4 => smb.dns_domain = value,
            _ => {}
        }
        i += 4 + n;
    }
    Some(smb)
}

/// SNMPv1 GET sysDescr.0 with community "public".
const SNMP_GET_SYSDESCR: [u8; 43] = [
    0x30, 0x29, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0, 0x1c, 0x02, 0x04, 0x4e, 0x53, 0x43,
    0x4e, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01,
    0x00, 0x05, 0x00,
];
const SYSDESCR_OID: [u8; 10] = [0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];

pub fn snmp_sysdescr(ip: Ipv4Addr) -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(SNMP_TIMEOUT)).ok()?;
    socket.send_to(&SNMP_GET_SYSDESCR, (ip, 161)).ok()?;
    let mut buf = [0u8; 1500];
    let (n, from) = socket.recv_from(&mut buf).ok()?;
    (from.ip() == IpAddr::V4(ip)).then(|| parse_snmp(&buf[..n])).flatten()
}

fn parse_snmp(r: &[u8]) -> Option<String> {
    let at = find(r, &SYSDESCR_OID)? + SYSDESCR_OID.len();
    if *r.get(at)? != 0x04 {
        return None; // NULL / noSuchObject instead of an OCTET STRING
    }
    let (len, start) = match *r.get(at + 1)? {
        l if l < 0x80 => (l as usize, at + 2),
        0x81 => (*r.get(at + 2)? as usize, at + 3),
        0x82 => (u16::from_be_bytes([*r.get(at + 2)?, *r.get(at + 3)?]) as usize, at + 4),
        _ => return None,
    };
    non_empty(clean(&String::from_utf8_lossy(r.get(start..start + len)?)))
}

/// All checks that fit the open ports, in parallel.
pub fn probe(ip: Ipv4Addr, services: &[u16]) -> Evidence {
    let has = |p: u16| services.contains(&p);
    fn join<T>(handle: Option<ScopedJoinHandle<'_, Option<T>>>) -> Option<T> {
        handle.and_then(|h| h.join().ok().flatten())
    }
    thread::scope(|s| {
        let ssh = has(22).then(|| s.spawn(|| banner(ip, 22)));
        let ftp = has(21).then(|| s.spawn(|| banner(ip, 21)));
        let web = [80, 8080, 5000].into_iter().find(|p| has(*p)).map(|p| s.spawn(move || http(ip, p)));
        let smb_info = has(445).then(|| s.spawn(|| smb(ip)));
        let winrm_info = has(5985).then(|| s.spawn(|| winrm(ip)));
        let mdns_info = s.spawn(|| mdns(ip));
        let snmp = snmp_sysdescr(ip);
        Evidence {
            ssh: join(ssh),
            ftp: join(ftp),
            http: join(web),
            smb: join(smb_info),
            winrm: join(winrm_info),
            snmp,
            mdns: mdns_info.join().ok().flatten(),
            upnp: None,
        }
    })
}

/// One open port's self-description for the port list.
pub fn port_info(ip: Ipv4Addr, port: u16) -> Option<String> {
    let windows = |s: Smb| {
        if s.build == 0 {
            return "Samba".to_string();
        }
        let name = s.computer.map_or(String::new(), |c| format!(" · {c}"));
        format!("Windows {}.{} Build {}{name}", s.major, s.minor, s.build)
    };
    match port {
        21 | 22 | 25 | 110 | 143 | 587 => banner(ip, port),
        445 => smb(ip).map(windows),
        5985 => winrm(ip).map(windows),
        80 | 81 | 3000 | 5000 | 8000 | 8008 | 8080 | 8081 | 8888 | 9000 | 9090 => http(ip, port).and_then(|h| {
            let parts: Vec<String> = [h.server, h.title].into_iter().flatten().collect();
            non_empty(parts.join(" – "))
        }),
        _ => None,
    }
}

/// UPnP devices answer a multicast search with a description URL; read manufacturer and model from it.
pub fn ssdp(listen: Duration) -> HashMap<Ipv4Addr, Upnp> {
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else { return HashMap::new() };
    let _ = socket.set_multicast_ttl_v4(2);
    let search = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n";
    for _ in 0..2 {
        let _ = socket.send_to(search.as_bytes(), "239.255.255.250:1900");
    }
    let mut seen: HashMap<Ipv4Addr, (Option<String>, Option<String>)> = HashMap::new(); // server, location
    let end = Instant::now() + listen;
    let mut buf = [0u8; 2048];
    loop {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() || socket.set_read_timeout(Some(left)).is_err() {
            break;
        }
        let Ok((n, SocketAddr::V4(from))) = socket.recv_from(&mut buf) else { break };
        let text = String::from_utf8_lossy(&buf[..n]);
        let entry = seen.entry(*from.ip()).or_default();
        entry.0 = entry.0.take().or_else(|| header(&text, "server"));
        entry.1 = entry.1.take().or_else(|| header(&text, "location"));
    }
    let hosts: Vec<(Ipv4Addr, (Option<String>, Option<String>))> = seen.into_iter().collect();
    let described = par_map(&hosts, 64, &Progress::default(), |(_, (server, location))| {
        let mut upnp = location.as_deref().and_then(description).unwrap_or_default();
        upnp.server = server.clone();
        upnp
    });
    hosts.into_iter().map(|(ip, _)| ip).zip(described).collect()
}

/// Fetches a UPnP device description from an `http://host:port/path` URL.
fn description(url: &str) -> Option<Upnp> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = rest.split_once('/').map_or((rest, "/".to_string()), |(a, p)| (a, format!("/{p}")));
    let (host, port) = authority.split_once(':').map_or((authority, Some(80)), |(h, p)| (h, p.parse().ok()));
    let xml = http_get(host.parse().ok()?, port?, &path)?;
    let model = match (tag(&xml, "modelName"), tag(&xml, "modelNumber")) {
        (Some(name), Some(number)) if !name.contains(&number) => Some(format!("{name} {number}")),
        (name, number) => name.or(number),
    };
    Some(Upnp { server: None, manufacturer: tag(&xml, "manufacturer"), model, friendly: tag(&xml, "friendlyName") })
}

// ---------------------------------------------------------------- interpretation

/// Product name for an NTLM version. Client and server share builds (26100 = Windows 11 24H2 and Server 2025),
/// so the caller decides the edition from what the host runs.
pub fn windows_name(major: u8, minor: u8, build: u16, server: bool) -> String {
    let pick = |server_name: &'static str, client_name: &'static str| if server { server_name } else { client_name };
    let name = match (major, minor) {
        (10, 0) if server_only_build(major, build) => "Windows Server 2022",
        (10, 0) if server => match build {
            26100.. => "Windows Server 2025",
            17763 => "Windows Server 2019",
            14393 => "Windows Server 2016",
            _ => "Windows Server",
        },
        (10, 0) => match build {
            28000.. => "Windows 11 26H1",
            26200 => "Windows 11 25H2",
            26100 => "Windows 11 24H2",
            22631 => "Windows 11 23H2",
            22621 => "Windows 11 22H2",
            22000 => "Windows 11 21H2",
            22001.. => "Windows 11",
            19045 => "Windows 10 22H2",
            19044 => "Windows 10 21H2",
            17763 => "Windows 10 1809",
            14393 => "Windows 10 1607",
            _ => "Windows 10",
        },
        (6, 3) => pick("Windows Server 2012 R2", "Windows 8.1"),
        (6, 2) => pick("Windows Server 2012", "Windows 8"),
        (6, 1) => pick("Windows Server 2008 R2", "Windows 7"),
        (6, 0) => pick("Windows Server 2008", "Windows Vista"),
        (5, _) => pick("Windows Server 2003", "Windows XP"),
        _ => "Windows",
    };
    name.to_string()
}

/// Builds that only exist as a server release.
fn server_only_build(major: u8, build: u16) -> bool {
    major == 10 && build == 20348
}

/// (product, OS) for an Apple model identifier; the most specific prefix comes first.
fn apple_model(id: &str) -> Option<(&'static str, &'static str)> {
    const MODELS: &[(&str, &str, &str)] = &[
        ("MacBookPro", "MacBook Pro", "macOS"), ("MacBookAir", "MacBook Air", "macOS"), ("MacBook", "MacBook", "macOS"),
        ("Macmini", "Mac mini", "macOS"), ("MacPro", "Mac Pro", "macOS"), ("iMac", "iMac", "macOS"), ("Mac", "Mac", "macOS"),
        ("iPhone", "iPhone", "iOS"), ("iPad", "iPad", "iPadOS"), ("AppleTV", "Apple TV", "tvOS"),
        ("AudioAccessory", "HomePod", "audioOS"), ("Watch", "Apple Watch", "watchOS"),
    ];
    MODELS.iter().find(|(prefix, ..)| id.starts_with(prefix)).map(|(_, product, os)| (*product, *os))
}

fn ssh_os(banner: &str) -> Option<String> {
    let b = banner.to_lowercase();
    let os = [
        ("ubuntu", "Ubuntu Linux"),
        ("debian", "Debian Linux"),
        ("raspbian", "Raspberry Pi OS"),
        ("freebsd", "FreeBSD"),
        ("for_windows", "Windows"),
        ("dropbear", "Embedded Linux (Dropbear)"),
        ("cisco", "Cisco IOS"),
        ("rosssh", "MikroTik RouterOS"),
        ("openssh", "Linux / Unix"),
    ];
    os.iter().find(|(needle, _)| b.contains(needle)).map(|(_, name)| (*name).to_string())
}

fn snmp_os(descr: &str) -> Option<String> {
    let d = descr.to_lowercase();
    if d.starts_with("linux") {
        let kernel = descr.split_whitespace().nth(2).unwrap_or("");
        return Some(format!("Linux {kernel}").trim().to_string());
    }
    if d.contains("windows") {
        let build = d.split("build ").nth(1).and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next()?.parse::<u16>().ok());
        return Some(match build {
            Some(b) if b >= 10240 => windows_name(10, 0, b, d.contains("server")),
            _ => "Windows".into(),
        });
    }
    let os = [
        ("cisco ios", "Cisco IOS"),
        ("routeros", "MikroTik RouterOS"),
        ("fortigate", "FortiOS"),
        ("junos", "Junos"),
        ("vmware esxi", "VMware ESXi"),
        ("freebsd", "FreeBSD"),
        ("darwin", "macOS"),
    ];
    os.iter().find(|(needle, _)| d.contains(needle)).map(|(_, name)| (*name).to_string())
}

fn http_os(server: &str) -> Option<String> {
    let s = server.to_lowercase();
    if let Some(version) = s.split("microsoft-iis/").nth(1) {
        return Some(format!("Windows Server (IIS {})", version.split_whitespace().next().unwrap_or("")));
    }
    let os = [
        ("microsoft-httpapi", "Windows"),
        ("(win64)", "Windows"),
        ("(win32)", "Windows"),
        ("(ubuntu)", "Ubuntu Linux"),
        ("(debian)", "Debian Linux"),
        ("(centos)", "CentOS Linux"),
        ("(red hat)", "Red Hat Linux"),
        ("(rocky", "Rocky Linux"),
        ("(almalinux)", "AlmaLinux"),
    ];
    os.iter().find(|(needle, _)| s.contains(needle)).map(|(_, name)| (*name).to_string())
}

fn detect_os(ttl: Option<u8>, services: &[u16], ev: &Evidence, server: bool) -> Option<(String, &'static str)> {
    let ntlm = ev.smb.as_ref().map(|s| (s, "SMB")).or(ev.winrm.as_ref().map(|s| (s, "WinRM")));
    if let Some((s, source)) = ntlm {
        // Windows always reports its build; Samba sends no version or build 0
        let os = if s.build > 0 { windows_name(s.major, s.minor, s.build, server) } else { "Linux / Unix (Samba)".into() };
        return Some((os, source));
    }
    let from_upnp = |s: &str| {
        let s = s.to_lowercase();
        if s.contains("windows") {
            Some("Windows".to_string())
        } else if s.contains("darwin") || s.contains("mac os") {
            Some("macOS".to_string())
        } else if s.contains("linux") {
            Some("Linux".to_string())
        } else {
            None
        }
    };
    let from = |source: &'static str| move |os: String| (os, source);
    ev.mdns
        .as_ref()
        .and_then(|m| apple_model(m.model.as_deref()?))
        .map(|(_, os)| (os.to_string(), "mDNS"))
        .or_else(|| ev.ssh.as_deref().and_then(ssh_os).map(from("SSH")))
        .or_else(|| ev.snmp.as_deref().and_then(snmp_os).map(from("SNMP")))
        .or_else(|| ev.http.as_ref()?.server.as_deref().and_then(http_os).map(from("Web")))
        .or_else(|| ev.upnp.as_ref()?.server.as_deref().and_then(from_upnp).map(from("UPnP")))
        .or_else(|| services.contains(&62078).then(|| ("iOS / iPadOS".to_string(), "Dienste")))
        .or_else(|| {
            // only the hop-count start value: 64 Linux/macOS/iOS/Android, 128 Windows, 255 network gear
            ttl.map(|t| match t {
                0..=64 => ("Unix-basiert".to_string(), "TTL"),
                65..=128 => ("Windows".to_string(), "TTL"),
                _ => ("Netzwerkgerät".to_string(), "TTL"),
            })
        })
}

const BRANDS: &[(&str, &str)] = &[
    ("synology", "Synology"), ("diskstation", "Synology"), ("qnap", "QNAP"), ("ubiquiti", "Ubiquiti"), ("unifi", "Ubiquiti"),
    ("mikrotik", "MikroTik"), ("routeros", "MikroTik"), ("cisco", "Cisco"), ("meraki", "Cisco Meraki"), ("fortinet", "Fortinet"),
    ("fortigate", "Fortinet"), ("juniper", "Juniper"), ("aruba", "HPE Aruba"), ("procurve", "HPE"), ("zyxel", "Zyxel"),
    ("lancom", "LANCOM"), ("netgear", "Netgear"), ("tp-link", "TP-Link"), ("draytek", "DrayTek"), ("sophos", "Sophos"),
    ("fritz!box", "AVM"), ("brother", "Brother"), ("ricoh", "Ricoh"), ("kyocera", "Kyocera"), ("xerox", "Xerox"),
    ("lexmark", "Lexmark"), ("konica", "Konica Minolta"), ("canon", "Canon"), ("epson", "Epson"), ("laserjet", "HP"),
    ("officejet", "HP"), ("jetdirect", "HP"), ("hewlett", "HP"), ("hp ethernet", "HP"), ("hp http server", "HP"), ("sonos", "Sonos"), ("vmware", "VMware"),
    ("proxmox", "Proxmox"), ("raspberry", "Raspberry Pi"), ("samsung", "Samsung"), ("philips", "Philips"),
    ("hikvision", "Hikvision"), ("apple", "Apple"), ("macbook", "Apple"), ("iphone", "Apple"), ("ipad", "Apple"),
    ("homepod", "Apple"), ("microsoft", "Microsoft"),
];
const PRINTER_WORDS: &[&str] = &[
    "printer", "laserjet", "jetdirect", "officejet", "deskjet", "mfp", "imagerunner", "workcentre", "bizhub", "ecosys", "brother",
    "ricoh", "kyocera", "xerox", "lexmark",
];
const NAS_WORDS: &[&str] = &["synology", "diskstation", "qnap", "readynas", "truenas", "freenas"];
const VIRTUAL_HOST_WORDS: &[&str] = &["vmware esxi", "proxmox"];
const NETWORK_WORDS: &[&str] = &[
    "cisco", "ubiquiti", "unifi", "mikrotik", "routeros", "fortinet", "fortigate", "fortios", "juniper", "junos", "aruba",
    "procurve", "zyxel", "lancom", "draytek", "meraki", "sophos", "edgeos", "airos", "switch", "access point", "firewall",
];
const MEDIA_WORDS: &[&str] = &[
    "sonos", "chromecast", "roku", "apple tv", "homepod", "webos", "bravia", "smart tv", "fire tv", "denon", "philips hue", "shelly",
    "tasmota", "esphome",
];
const VM_VENDORS: &[&str] = &["vmware", "hyper-v", "qemu", "virtualbox"];

fn any(text: &str, words: &[&str]) -> bool {
    words.iter().any(|w| text.contains(w))
}

pub fn identify(
    ip: Ipv4Addr,
    ttl: Option<u8>,
    services: &[u16],
    mac: Option<&str>,
    ev: &Evidence,
    gateway: Option<Ipv4Addr>,
    own: Option<Ipv4Addr>,
) -> Identity {
    let has = |p: u16| services.contains(&p);
    let mut details = Vec::new();
    // without a domain, Windows reports its own computer name as the domain
    let domain = ev.smb.as_ref().and_then(|s| {
        let computer = s.computer.as_deref().unwrap_or("").to_lowercase();
        let differs = |d: &&String| computer.is_empty() || d.to_lowercase() != computer && !d.to_lowercase().starts_with(&format!("{computer}."));
        s.dns_domain.as_ref().filter(differs).or(s.domain.as_ref().filter(differs)).cloned()
    });
    let ntlm = ev.smb.as_ref().or(ev.winrm.as_ref());
    let domain_controller = has(88) && has(389);
    let iis = ev.http.as_ref().and_then(|h| h.server.as_deref()).is_some_and(|s| s.to_lowercase().contains("microsoft-iis"));
    // Client and server editions share builds; decide from what usually only servers run.
    // WSD (5357) is open on clients with network discovery, which servers leave off.
    let reasons: Vec<&str> = [
        (domain_controller, "Domänencontroller"),
        (has(53), "DNS-Server"),
        (has(1433), "SQL Server"),
        (iis, "IIS"),
        ((has(5985) || ev.winrm.is_some()) && !has(5357), "WinRM ohne Netzwerkerkennung"),
    ]
    .into_iter()
    .filter_map(|(hit, why)| hit.then_some(why))
    .collect();
    let server = ntlm.is_some_and(|s| server_only_build(s.major, s.build)) || !reasons.is_empty();
    for (s, via) in [(&ev.smb, "SMB"), (&ev.winrm, "WinRM")].into_iter().filter_map(|(s, via)| Some((s.as_ref()?, via))) {
        let shown = domain.as_ref().map_or(String::new(), |d| format!(", Domäne {d}"));
        let what = if s.build > 0 { format!("Windows {}.{} Build {}", s.major, s.minor, s.build) } else { "Samba".into() };
        details.push(format!("{via}: {what}{shown}"));
    }
    if let Some(s) = ntlm.filter(|s| s.build > 0 && !server_only_build(s.major, s.build)) {
        let edition = if server { format!("Server ({})", reasons.join(", ")) } else { "Client (keine Server-Dienste)".into() };
        details.push(format!("Edition: {edition} – Build {} gibt es für beide", s.build));
    }
    if let Some(m) = &ev.mdns {
        let model = m.model.as_deref().map(|id| apple_model(id).map_or(id.to_string(), |(p, _)| format!("{p} ({id})")));
        let parts: Vec<String> = [m.name.clone(), model].into_iter().flatten().collect();
        if !parts.is_empty() {
            details.push(format!("mDNS: {}", parts.join(" · ")));
        }
    }

    if let Some(b) = &ev.ssh {
        details.push(format!("SSH: {b}"));
    }
    if let Some(b) = &ev.ftp {
        details.push(format!("FTP: {b}"));
    }
    if let Some(h) = &ev.http {
        let parts: Vec<&str> = [h.server.as_deref(), h.title.as_deref()].into_iter().flatten().collect();
        if !parts.is_empty() {
            details.push(format!("Web: {}", parts.join(" – ")));
        }
    }
    if let Some(s) = &ev.snmp {
        details.push(format!("SNMP: {s}"));
    }
    if let Some(u) = &ev.upnp {
        let parts: Vec<&str> =
            [u.friendly.as_deref(), u.manufacturer.as_deref(), u.model.as_deref(), u.server.as_deref()].into_iter().flatten().collect();
        if !parts.is_empty() {
            details.push(format!("UPnP: {}", parts.join(" · ")));
        }
    }
    let said = details.join(" ").to_lowercase(); // everything the device told us about itself

    let mac_vendor = mac.and_then(oui::vendor);
    let random_mac = mac_vendor.as_deref() == Some(oui::RANDOM);
    let vendor = mac_vendor
        .clone()
        .filter(|_| !random_mac)
        .or_else(|| ev.upnp.as_ref()?.manufacturer.clone())
        .or_else(|| BRANDS.iter().find(|(needle, _)| said.contains(needle)).map(|(_, name)| (*name).to_string()))
        // the lockdown service (62078) only runs on iPhones and iPads, which usually hide behind a random MAC
        .or_else(|| has(62078).then(|| "Apple".to_string()))
        .or(mac_vendor);
    let apple = ev.mdns.as_ref().and_then(|m| m.model.as_deref()).and_then(|id| Some((apple_model(id)?.0, id)));
    let vendor = vendor.or_else(|| apple.map(|_| "Apple".to_string()));
    let model = apple
        .map(|(product, id)| format!("{product} ({id})"))
        .or_else(|| ev.upnp.as_ref().and_then(|u| u.model.clone().or_else(|| u.friendly.clone())))
        .or_else(|| ev.snmp.as_ref().filter(|d| snmp_os(d).is_none()).map(|d| d.split([',', ';']).next().unwrap_or(d).to_string()))
        .or_else(|| ev.http.as_ref()?.title.clone())
        .map(|m| strip_vendor(m, vendor.as_deref()));
    let (os, os_source) = detect_os(ttl, services, ev, server).unzip();

    let vm = vendor.as_deref().is_some_and(|v| any(&v.to_lowercase(), VM_VENDORS));
    if domain_controller {
        details.push("Rolle: Domänencontroller (Kerberos + LDAP)".into());
    }
    if has(1433) {
        details.push("Rolle: SQL Server".into());
    }
    if vm {
        details.push("Virtuelle Maschine".into());
    }
    if let Some(t) = ttl {
        details.push(format!("TTL: {t}"));
    }

    let os_lower = os.as_deref().unwrap_or("").to_lowercase();
    let text = format!("{said} {os_lower} {}", vendor.as_deref().unwrap_or("").to_lowercase());
    let windows = os_lower.starts_with("windows");
    // with a build the edition is known; a TTL guess falls back to typical server ports
    let server_hints = match ntlm {
        Some(_) => server,
        None => domain_controller || [53, 389, 1433, 5985, 80, 443].iter().any(|p| has(*p)) || vm,
    };
    let kind = if Some(ip) == own {
        Kind::ThisPc
    } else if Some(ip) == gateway {
        Kind::Router
    } else if any(&text, NAS_WORDS) {
        Kind::Nas // before the printer ports: NAS boxes share USB printers over IPP/LPD
    } else if has(9100) || has(631) || has(515) || any(&text, PRINTER_WORDS) {
        Kind::Printer
    } else if has(902) || has(8006) || any(&text, VIRTUAL_HOST_WORDS) {
        Kind::Hypervisor
    } else if any(&said, NETWORK_WORDS) || ttl.is_some_and(|t| t > 128) {
        Kind::Network
    } else if windows && server_hints {
        Kind::WindowsServer
    } else if windows {
        Kind::WindowsClient
    } else if has(62078) || said.contains("iphone") || said.contains("android") || (random_mac && services.is_empty()) {
        Kind::Mobile
    } else if any(&text, MEDIA_WORDS) {
        Kind::Media
    } else if os_lower.contains("macos") || os_lower.starts_with("ios") || text.contains("apple") {
        Kind::Apple
    } else if !os_lower.is_empty() && [22, 21, 80, 443, 8080, 3306, 5432, 2049].iter().any(|p| has(*p)) {
        Kind::LinuxServer
    } else {
        Kind::Unknown
    };

    // for appliances a TTL guess ("Unix-based") is noise: the device type already says more
    let appliance = matches!(kind, Kind::Router | Kind::Network | Kind::Printer | Kind::Media | Kind::Mobile);
    let (os, os_source) = if appliance && os_source == Some("TTL") { (None, None) } else { (os, os_source) };
    let smb = ev.smb.as_ref();
    Identity {
        kind,
        os,
        os_source,
        vendor,
        model,
        domain,
        computer: smb.or(ev.winrm.as_ref()).and_then(|s| s.computer.clone()),
        mdns_name: ev.mdns.as_ref().and_then(|m| m.name.clone()),
        details,
    }
}

/// "HP" + "HP ETHERNET …" shows as "HP ETHERNET …", not "HP HP ETHERNET …".
fn strip_vendor(model: String, vendor: Option<&str>) -> String {
    let Some(v) = vendor.and_then(|v| v.split([',', ' ']).next()).filter(|v| !v.is_empty()) else { return model };
    match model.get(..v.len()) {
        Some(head) if head.eq_ignore_ascii_case(v) && model.len() > v.len() => model[v.len()..].trim_start().to_string(),
        _ => model,
    }
}

/// Coarse OS family for the report chart.
pub fn os_family(os: Option<&str>) -> (&'static str, [u8; 3]) {
    let os = os.unwrap_or("").to_lowercase();
    if os.starts_with("windows") {
        ("Windows", [37, 99, 235])
    } else if os.contains("macos") || os.starts_with("ios") {
        ("Apple macOS / iOS", [71, 85, 105])
    } else if ["linux", "unix", "bsd", "samba"].iter().any(|w| os.contains(w)) {
        ("Linux / Unix", [13, 148, 136])
    } else if !os.is_empty() {
        ("Netzwerk-Betriebssystem", [6, 182, 212])
    } else {
        ("Unbekannt", [148, 163, 184])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn reads_ntlm_challenge() {
        let mut info = Vec::new();
        for (id, value) in [(2u16, "EXAMPLE"), (1, "SRV01"), (4, "example.local"), (3, "srv01.example.local")] {
            let v = utf16(value);
            info.extend(id.to_le_bytes());
            info.extend((v.len() as u16).to_le_bytes());
            info.extend(v);
        }
        info.extend([0u8; 4]);
        let mut msg = b"NTLMSSP\0\x02\0\0\0".to_vec();
        msg.extend([0u8; 8]); // target name fields
        msg.extend(0x0200_0000u32.to_le_bytes()); // flags: version present
        msg.extend([0u8; 16]); // challenge, reserved
        msg.extend((info.len() as u16).to_le_bytes());
        msg.extend((info.len() as u16).to_le_bytes());
        msg.extend(56u32.to_le_bytes()); // target info offset
        msg.extend([10, 0]);
        msg.extend(20348u16.to_le_bytes());
        msg.extend([0, 0, 0, 15]);
        msg.extend(info);
        let smb = parse_challenge(&msg).unwrap();
        assert_eq!((smb.major, smb.minor, smb.build), (10, 0, 20348));
        assert_eq!(smb.computer.as_deref(), Some("srv01.example.local"));
        assert_eq!(smb.dns_domain.as_deref(), Some("example.local"));
        assert_eq!(windows_name(10, 0, 20348, false), "Windows Server 2022");
    }

    #[test]
    fn reads_snmp_sysdescr() {
        let mut reply = SNMP_GET_SYSDESCR[..41].to_vec(); // up to and including the OID
        let text = b"HP ETHERNET MULTI-ENVIRONMENT,JETDIRECT";
        reply.push(0x04);
        reply.push(text.len() as u8);
        reply.extend(text);
        assert_eq!(parse_snmp(&reply).as_deref(), Some("HP ETHERNET MULTI-ENVIRONMENT,JETDIRECT"));
        let null = SNMP_GET_SYSDESCR.to_vec(); // value NULL = no answer
        assert_eq!(parse_snmp(&null), None);
        assert_eq!(SNMP_GET_SYSDESCR[1] as usize, SNMP_GET_SYSDESCR.len() - 2, "outer BER length");
    }

    #[test]
    fn names_windows_editions_cleanly() {
        assert_eq!(windows_name(10, 0, 26100, false), "Windows 11 24H2");
        assert_eq!(windows_name(10, 0, 26100, true), "Windows Server 2025");
        assert_eq!(windows_name(10, 0, 17763, true), "Windows Server 2019");
        assert_eq!(windows_name(10, 0, 19045, false), "Windows 10 22H2");
        assert_eq!(windows_name(6, 3, 9600, true), "Windows Server 2012 R2");

        let smb = |build| Evidence { smb: Some(Smb { major: 10, minor: 0, build, ..Smb::default() }), ..Evidence::default() };
        let client = id(128, &[135, 445, 5357], smb(26100), None);
        assert_eq!((client.os.as_deref(), client.os_source), (Some("Windows 11 24H2"), Some("SMB")));
        let server = id(128, &[135, 445, 5985], smb(26100), None);
        assert_eq!((server.kind, server.os.as_deref()), (Kind::WindowsServer, Some("Windows Server 2025")));
        assert!(server.details.iter().any(|d| d.contains("WinRM")), "{:?}", server.details);
        let guess = id(128, &[], Evidence::default(), None);
        assert_eq!((guess.os.as_deref(), guess.os_source), (Some("Windows"), Some("TTL")));
    }

    #[test]
    fn base64_and_mdns_records() {
        assert_eq!(base64(b"Man"), "TWFu");
        assert_eq!(base64(b"Ma"), "TWE=");
        assert_eq!(unbase64(&base64(&ntlm_negotiate())), ntlm_negotiate());

        // reply: header, question, a PTR answer pointing back into the question, a TXT additional record
        let mut msg = vec![0, 0, 0x84, 0, 0, 1, 0, 1, 0, 0, 0, 1];
        msg.extend(&dns_query("_device-info._tcp.local", 12)[12..]);
        let target = [&[4u8][..], b"Mac1", &[0xC0, 12]].concat();
        msg.extend([0xC0, 12, 0, 12, 0, 1, 0, 0, 0, 10]);
        msg.extend((target.len() as u16).to_be_bytes());
        msg.extend(&target);
        let txt = [&[20u8][..], b"model=MacBookPro18,3"].concat();
        msg.extend([0xC0, 12, 0, 16, 0, 1, 0, 0, 0, 10]);
        msg.extend((txt.len() as u16).to_be_bytes());
        msg.extend(&txt);
        let (_, at, _) = dns_records(&msg)[0];
        assert_eq!(dns_name(&msg, at).unwrap().0, "Mac1._device-info._tcp.local");
        assert_eq!(txt_model(&msg).as_deref(), Some("MacBookPro18,3"));
        assert_eq!(apple_model("iPhone15,2"), Some(("iPhone", "iOS")));

        let mdns = Mdns { name: Some("Mac1.local".into()), model: Some("MacBookPro18,3".into()) };
        let mac = id(64, &[], Evidence { mdns: Some(mdns), ..Evidence::default() }, None);
        assert_eq!((mac.kind, mac.os.as_deref()), (Kind::Apple, Some("macOS")));
        assert_eq!((mac.model.as_deref(), mac.vendor.as_deref()), (Some("MacBook Pro (MacBookPro18,3)"), Some("Apple")));
    }

    #[test]
    fn reads_tags_and_headers() {
        assert_eq!(tag("<html><TITLE> Synology&amp;Co </TITLE>", "title").as_deref(), Some("Synology&Co"));
        assert_eq!(header("HTTP/1.1 200 OK\r\nServer: nginx\r\n", "server").as_deref(), Some("nginx"));
    }

    fn id(ttl: u8, services: &[u16], ev: Evidence, mac: Option<&str>) -> Identity {
        identify(Ipv4Addr::new(10, 0, 0, 9), Some(ttl), services, mac, &ev, Some(Ipv4Addr::new(10, 0, 0, 1)), None)
    }

    #[test]
    fn hides_workgroup_domain_and_repeated_vendor() {
        let smb = |computer: &str, domain: &str| Evidence {
            smb: Some(Smb { major: 10, minor: 0, build: 26100, computer: Some(computer.into()), domain: Some(domain.into()), dns_domain: Some(domain.into()), ..Smb::default() }),
            ..Evidence::default()
        };
        assert_eq!(id(128, &[445], smb("LAPTOP-01", "LAPTOP-01"), None).domain, None);
        assert_eq!(id(128, &[445], smb("pc1.example.local", "example.local"), None).domain.as_deref(), Some("example.local"));
        assert_eq!(strip_vendor("HP ETHERNET MULTI-ENVIRONMENT".into(), Some("HP")), "ETHERNET MULTI-ENVIRONMENT");
        assert_eq!(strip_vendor("NC-04h".into(), Some("Brother")), "NC-04h");
        assert_eq!(strip_vendor("Sonos".into(), Some("Sonos, Inc.")), "Sonos");
    }

    #[test]
    fn classifies_devices() {
        let smb = |build| Evidence { smb: Some(Smb { major: 10, minor: 0, build, ..Smb::default() }), ..Evidence::default() };
        let dc = id(128, &[53, 88, 135, 389, 445], smb(26100), None);
        assert_eq!(dc.kind, Kind::WindowsServer);
        assert!(dc.details.iter().any(|d| d.contains("Domänencontroller")));
        assert_eq!(id(128, &[135, 445], smb(26100), None).kind, Kind::WindowsClient);
        assert_eq!(id(128, &[135, 445], smb(20348), None).kind, Kind::WindowsServer);

        let ubuntu = id(64, &[22, 80], Evidence { ssh: Some("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6".into()), ..Evidence::default() }, None);
        assert_eq!((ubuntu.kind, ubuntu.os.as_deref()), (Kind::LinuxServer, Some("Ubuntu Linux")));

        let printer = id(255, &[80, 9100], Evidence { snmp: Some("HP ETHERNET MULTI-ENVIRONMENT".into()), ..Evidence::default() }, None);
        assert_eq!((printer.kind, printer.vendor.as_deref()), (Kind::Printer, Some("HP")));
        assert_eq!(printer.os, None, "no TTL guess for appliances");
        // QNAP and Synology share printers over IPP/LPD, so the printer ports alone don't make a printer
        let qnap = id(64, &[80, 443, 445, 631], Evidence { http: Some(Http { title: Some("QTS".into()), ..Http::default() }), ..Evidence::default() }, Some("24-5E-BE-00-00-01"));
        assert_eq!((qnap.kind, qnap.vendor.as_deref()), (Kind::Nas, Some("QNAP Systems, Inc.")));

        assert_eq!(id(255, &[22], Evidence::default(), None).kind, Kind::Network);
        assert_eq!(id(64, &[], Evidence::default(), Some("DA-11-22-33-44-55")).kind, Kind::Mobile);
        let iphone = id(64, &[62078], Evidence::default(), Some("DA-11-22-33-44-55"));
        assert_eq!((iphone.kind, iphone.vendor.as_deref()), (Kind::Mobile, Some("Apple")));
        let vm = id(128, &[3389], Evidence::default(), Some("00-15-5D-01-02-03"));
        assert_eq!(vm.kind, Kind::WindowsServer, "Hyper-V guest with RDP");
        assert_eq!(id(64, &[], Evidence::default(), None).kind, Kind::Unknown);
    }
}
