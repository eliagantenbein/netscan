//! Parsing of user input: address ranges and port lists.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};

const MAX_HOSTS: u32 = 65_536;

/// Common TCP ports with service names: default port list and name lookup.
pub const TOP_PORTS: &[(u16, &str)] = &[
    (21, "ftp"), (22, "ssh"), (23, "telnet"), (25, "smtp"), (53, "dns"),
    (80, "http"), (81, "http-alt"), (88, "kerberos"), (110, "pop3"), (111, "rpcbind"),
    (135, "msrpc"), (139, "netbios"), (143, "imap"), (389, "ldap"), (443, "https"),
    (445, "smb"), (465, "smtps"), (515, "lpd"), (548, "afp"), (554, "rtsp"),
    (587, "submission"), (631, "ipp"), (636, "ldaps"), (873, "rsync"), (902, "vmware"),
    (993, "imaps"), (995, "pop3s"), (1080, "socks"), (1433, "mssql"), (1521, "oracle"),
    (1723, "pptp"), (1883, "mqtt"), (2049, "nfs"), (3000, "http-dev"), (3128, "squid"),
    (3268, "ldap-gc"), (3306, "mysql"), (3389, "rdp"), (4443, "https-alt"), (5000, "upnp/http"),
    (5060, "sip"), (5357, "wsd"), (5432, "postgres"), (5900, "vnc"), (5985, "winrm"),
    (5986, "winrm-https"), (6379, "redis"), (6443, "kubernetes"), (8000, "http-alt"), (8006, "proxmox"),
    (8008, "http-alt"), (8080, "http-proxy"), (8081, "http-alt"), (8443, "https-alt"), (8888, "http-alt"),
    (9000, "http-alt"), (9090, "http-alt"), (9100, "jetdirect"), (9200, "elasticsearch"), (9443, "https-alt"),
    (10000, "webmin"), (27017, "mongodb"),
];

pub fn service_name(port: u16) -> &'static str {
    TOP_PORTS.iter().find(|(p, _)| *p == port).map_or("", |(_, n)| n)
}

/// What a technician calls the service: "Remotedesktop (RDP)" instead of "rdp".
pub fn describe(port: u16) -> String {
    let text = match port {
        21 => "Dateiübertragung (FTP)",
        22 => "Fernzugriff (SSH)",
        23 => "Telnet",
        25 | 465 | 587 => "Mailversand (SMTP)",
        53 => "Namensauflösung (DNS)",
        80 | 81 | 8000 | 8008 | 8080 | 8081 | 8888 | 9000 | 9090 => "Web (HTTP)",
        88 => "Kerberos (Anmeldung)",
        110 | 995 => "Mailabruf (POP3)",
        135 => "Windows RPC",
        139 => "NetBIOS-Freigaben",
        143 | 993 => "Mailabruf (IMAP)",
        389 | 3268 => "Verzeichnis (LDAP)",
        443 | 4443 | 8443 | 9443 => "Web verschlüsselt (HTTPS)",
        445 => "Windows-Freigaben (SMB)",
        515 | 631 | 9100 => "Drucken",
        548 => "Apple-Freigaben (AFP)",
        554 => "Videostream (RTSP)",
        636 => "Verzeichnis verschlüsselt (LDAPS)",
        902 => "VMware ESXi",
        1433 => "Microsoft SQL Server",
        1521 => "Oracle-Datenbank",
        2049 => "NFS-Freigaben",
        3306 => "MySQL / MariaDB",
        3389 => "Remotedesktop (RDP)",
        5357 => "Netzwerkerkennung (WSD)",
        5432 => "PostgreSQL",
        5900 => "Bildschirmfreigabe (VNC)",
        5985 => "Windows-Fernverwaltung (WinRM)",
        5986 => "WinRM verschlüsselt",
        6379 => "Redis",
        8006 => "Proxmox VE",
        10000 => "Webmin",
        27017 => "MongoDB",
        62078 => "Apple-Gerätedienst (iPhone/iPad)",
        _ => return match service_name(port) {
            "" => format!("Port {port}"),
            name => name.to_uppercase(),
        },
    };
    text.to_string()
}

/// A short warning for services that are risky when reachable: unencrypted or often without password.
pub fn port_note(port: u16) -> Option<&'static str> {
    match port {
        21 => Some("unverschlüsselt – Passwörter im Klartext"),
        23 => Some("unverschlüsselt – durch SSH ersetzen"),
        5900 => Some("oft schwach oder ohne Passwort"),
        6379 | 27017 | 9200 => Some("oft ohne Anmeldung erreichbar"),
        139 => Some("veraltetes NetBIOS/SMBv1 möglich"),
        _ => None,
    }
}

/// "SSH · HTTP · 9999" for display in tables and the report.
pub fn services_text(ports: &[u16]) -> String {
    let names: Vec<String> = ports
        .iter()
        .map(|p| match service_name(*p) {
            "" => p.to_string(),
            name => name.to_uppercase(),
        })
        .collect();
    names.join(" · ")
}

/// This machine's primary IPv4 address.
pub fn local_ip() -> Option<Ipv4Addr> {
    // connect() on UDP only picks the outgoing interface, no packet is sent
    let local = UdpSocket::bind("0.0.0.0:0").and_then(|s| {
        s.connect("8.8.8.8:80")?;
        s.local_addr()
    });
    match local {
        Ok(SocketAddr::V4(a)) => Some(*a.ip()),
        _ => None,
    }
}

/// `ip`'s network in CIDR notation: (192.168.1.23, 24) → "192.168.1.0/24".
pub fn network(ip: Ipv4Addr, prefix: u32) -> String {
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix.min(32)) };
    format!("{}/{prefix}", Ipv4Addr::from(u32::from(ip) & mask))
}

/// Start range: the primary adapter's real network, or its /24 when the net is too big to sweep quickly.
pub fn default_range(nets: &[(Ipv4Addr, u32)], primary: Option<Ipv4Addr>) -> String {
    let net = nets.iter().find(|(ip, _)| Some(*ip) == primary).or(nets.first()).copied();
    match net.or(primary.map(|ip| (ip, 24))) {
        Some((ip, prefix)) => network(ip, if prefix < 22 { 24 } else { prefix }),
        None => "192.168.1.0/24".into(),
    }
}

/// Accepts `192.168.1.0/24`, `192.168.1.10-50`, `10.0.0.1-10.0.1.255`, a single IP or a hostname.
pub fn parse_hosts(input: &str) -> Result<Vec<Ipv4Addr>, String> {
    let s = input.trim();
    if s.is_empty() {
        // getaddrinfo("") would quietly resolve to this machine
        return Err("Kein Ziel angegeben".into());
    }
    let ip = |x: &str| x.trim().parse::<Ipv4Addr>().map_err(|_| format!("Ungültige IP-Adresse: {x}"));

    let (start, end) = if let Some((addr, bits)) = s.split_once('/') {
        let net = u32::from(ip(addr)?);
        let bits: u32 = bits.trim().parse().ok().filter(|b| *b <= 32).ok_or(format!("Ungültige Maske: /{bits}"))?;
        let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
        let (first, last) = (net & mask, net | !mask);
        // /31 and /32 have no network/broadcast address to skip
        if bits >= 31 { (first, last) } else { (first + 1, last - 1) }
    } else if let Some((a, b)) = s.split_once('-').filter(|(a, _)| a.trim().parse::<Ipv4Addr>().is_ok()) {
        let a = u32::from(ip(a)?);
        let b = match b.trim().parse::<Ipv4Addr>() {
            Ok(full) => u32::from(full),
            Err(_) => {
                let last: u8 = b.trim().parse().map_err(|_| format!("Ungültiges Bereichsende: {b}"))?;
                (a & 0xFFFF_FF00) | u32::from(last)
            }
        };
        (a, b)
    } else {
        let one = u32::from(ip(s).or_else(|_| resolve(s))?);
        (one, one)
    };

    if end < start {
        return Err("Bereichsende liegt vor dem Anfang".into());
    }
    if end - start >= MAX_HOSTS {
        return Err(format!("Bereich zu gross (max. {MAX_HOSTS} Adressen, also /16)"));
    }
    Ok((start..=end).map(Ipv4Addr::from).collect())
}

fn resolve(name: &str) -> Result<Ipv4Addr, String> {
    (name, 0)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.find_map(|a| match a.ip() { IpAddr::V4(v) => Some(v), _ => None }))
        .ok_or(format!("Ziel nicht gefunden: {name}"))
}

/// Accepts empty/`top` (common ports), `all`, `1-1024`, `22,80,443` or mixes like `1-100,8080`.
pub fn parse_ports(input: &str) -> Result<Vec<u16>, String> {
    let s = input.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("top") {
        return Ok(TOP_PORTS.iter().map(|(p, _)| *p).collect());
    }
    if s.eq_ignore_ascii_case("all") {
        return Ok((1..=65535).collect());
    }
    let port = |x: &str| x.trim().parse::<u16>().ok().filter(|p| *p > 0).ok_or(format!("Ungültiger Port: {x}"));
    let mut out = Vec::new();
    for part in s.split(',') {
        let (a, b) = part.split_once('-').unwrap_or((part, part));
        let (a, b) = (port(a)?, port(b)?);
        if b < a {
            return Err(format!("Ungültiger Portbereich: {part}"));
        }
        out.extend(a..=b);
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn cidr_skips_network_and_broadcast() {
        let h = parse_hosts("192.168.1.77/24").unwrap();
        assert_eq!((h.len(), h[0], h[253]), (254, ip("192.168.1.1"), ip("192.168.1.254")));
        assert_eq!(parse_hosts("10.0.0.5/32").unwrap(), vec![ip("10.0.0.5")]);
        assert_eq!(parse_hosts("10.0.0.4/31").unwrap().len(), 2);
    }

    #[test]
    fn ranges_and_single() {
        assert_eq!(parse_hosts("10.0.0.10-12").unwrap(), vec![ip("10.0.0.10"), ip("10.0.0.11"), ip("10.0.0.12")]);
        assert_eq!(parse_hosts("10.0.0.255-10.0.1.1").unwrap().len(), 3);
        assert_eq!(parse_hosts(" 8.8.8.8 ").unwrap(), vec![ip("8.8.8.8")]);
        assert_eq!(parse_hosts("localhost").unwrap(), vec![ip("127.0.0.1")]);
    }

    #[test]
    fn rejects_bad_input() {
        for bad in ["", "10.0.0.20-10", "10.0.0.0/33", "10.0.0.0/8", "300.1.1.1", "10.0.0.1-999"] {
            assert!(parse_hosts(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn ports() {
        assert_eq!(parse_ports("443, 22,20-22").unwrap(), vec![20, 21, 22, 443]);
        assert_eq!(parse_ports("").unwrap().len(), TOP_PORTS.len());
        assert_eq!(parse_ports("all").unwrap().len(), 65535);
        for bad in ["0", "70000", "80-79", "http"] {
            assert!(parse_ports(bad).is_err(), "{bad}");
        }
        assert_eq!(service_name(3389), "rdp");
    }

    #[test]
    fn default_range_uses_real_mask_but_caps_big_nets() {
        assert_eq!(network(ip("10.1.2.3"), 23), "10.1.2.0/23");
        let nets = [(ip("172.16.5.9"), 16), (ip("192.168.100.23"), 22)];
        assert_eq!(default_range(&nets, Some(ip("192.168.100.23"))), "192.168.100.0/22");
        assert_eq!(default_range(&nets, Some(ip("172.16.5.9"))), "172.16.5.0/24");
        assert_eq!(default_range(&[], Some(ip("10.0.0.7"))), "10.0.0.0/24");
        assert_eq!(default_range(&[], None), "192.168.1.0/24");
    }
}
