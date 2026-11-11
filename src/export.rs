//! Excel report: overview with KPI cards and charts, plus filterable host and port tables.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::path::Path;

use rust_xlsxwriter::{
    Chart, ChartDataLabel, ChartFormat, ChartLegendPosition, ChartPoint, ChartSolidFill, ChartType, Color,
    ConditionalFormatDataBar, Format, FormatAlign, FormatBorder, Table, TableColumn, TableStyle, Workbook,
    Worksheet, XlsxError,
};

use crate::scan::Kind;
use crate::{fingerprint, parse, IpScan, PortScan};

const NAVY: u32 = 0x1E293B;
const MUTED: u32 = 0x64748B;
const ACCENT: u32 = 0x2563EB;
const CARD: u32 = 0xF1F5F9;
const LINE: u32 = 0xCBD5E1;
const OVERVIEW: &str = "Übersicht";
const TOP_SERVICES: usize = 12;

pub fn write(path: &Path, ip: Option<&IpScan>, port: Option<&PortScan>) -> Result<(), XlsxError> {
    let mut workbook = Workbook::new();
    overview(workbook.add_worksheet(), ip, port)?;
    if let Some(ip) = ip {
        hosts_sheet(workbook.add_worksheet(), ip)?;
    }
    if let Some(port) = port {
        ports_sheet(workbook.add_worksheet(), port)?;
    }
    workbook.save(path)
}

fn rgb(kind: Kind) -> Color {
    let [r, g, b] = kind.rgb();
    Color::RGB(u32::from(r) << 16 | u32::from(g) << 8 | u32::from(b))
}

fn title(ws: &mut Worksheet, text: &str, subtitle: &str) -> Result<(), XlsxError> {
    ws.set_screen_gridlines(false);
    ws.set_column_width(0, 2)?;
    ws.set_row_height(1, 34)?;
    ws.write_string_with_format(1, 1, text, &Format::new().set_font_size(22).set_bold().set_font_color(NAVY))?;
    ws.write_string_with_format(2, 1, subtitle, &Format::new().set_font_color(MUTED))?;
    Ok(())
}

fn section(ws: &mut Worksheet, row: u32, text: &str) -> Result<(), XlsxError> {
    let format = Format::new().set_font_size(13).set_bold().set_font_color(NAVY).set_border_bottom(FormatBorder::Thin).set_border_bottom_color(LINE);
    ws.set_row_height(row, 22)?;
    for col in 1..=10 {
        ws.write_blank(row, col, &format)?;
    }
    ws.write_string_with_format(row, 1, text, &format)?;
    Ok(())
}

fn table(header: &[&str], style: TableStyle) -> Table {
    let columns: Vec<TableColumn> = header.iter().map(|h| TableColumn::new().set_header(*h)).collect();
    Table::new().set_columns(&columns).set_style(style)
}

fn overview(ws: &mut Worksheet, ip: Option<&IpScan>, port: Option<&PortScan>) -> Result<(), XlsxError> {
    ws.set_name(OVERVIEW)?;
    // one column per KPI card and per table column: Excel tables must not contain merged cells
    for col in 1..=10 {
        ws.set_column_width(col, 22)?;
    }
    let (what, at, secs) = match (ip, port) {
        (Some(s), _) => (format!("Bereich {}", s.range), s.at, s.secs),
        (None, Some(p)) => (format!("Ziel {}", p.target), p.at, p.secs),
        (None, None) => return Ok(()),
    };
    title(ws, "NetScan – Netzwerkbericht", &format!("{what} · Scan vom {} · Dauer {:.1} s", at.format("%d.%m.%Y %H:%M"), secs))?;

    // KPI cards: label row 4, value row 5
    let mut kpis: Vec<(&str, f64, &str)> = Vec::new();
    if let Some(s) = ip {
        let pings: Vec<u32> = s.hosts.iter().filter_map(|h| h.rtt_ms).collect();
        kpis.push(("GESCANNTE ADRESSEN", s.scanned.len() as f64, "0"));
        kpis.push(("AKTIVE GERÄTE", s.hosts.len() as f64, "0"));
        kpis.push(("ERKANNTE DIENSTE", s.hosts.iter().map(|h| h.services.len()).sum::<usize>() as f64, "0"));
        if !pings.is_empty() {
            kpis.push(("Ø PING", pings.iter().sum::<u32>() as f64 / pings.len() as f64, "0.0 \"ms\""));
        }
    }
    if let Some(p) = port {
        kpis.push(("OFFENE PORTS", p.open.len() as f64, "0"));
        if ip.is_none() {
            kpis.push(("GEPRÜFTE HOSTS", p.hosts.len() as f64, "0"));
            kpis.push(("PORTS JE HOST", p.port_count as f64, "0"));
        }
    }
    let label = Format::new().set_font_size(9).set_bold().set_font_color(MUTED).set_background_color(CARD).set_align(FormatAlign::Left).set_indent(1);
    ws.set_row_height(4, 20)?;
    ws.set_row_height(5, 40)?;
    for (i, (text, value, num)) in kpis.iter().take(5).enumerate() {
        let col = 1 + i as u16;
        let value_format = Format::new()
            .set_font_size(24)
            .set_bold()
            .set_font_color(ACCENT)
            .set_background_color(CARD)
            .set_align(FormatAlign::Left)
            .set_align(FormatAlign::VerticalCenter)
            .set_indent(1)
            .set_num_format(*num);
        ws.write_string_with_format(4, col, *text, &label)?;
        ws.write_number_with_format(5, col, *value, &value_format)?;
    }

    let mut row = 8;
    if let Some(s) = ip {
        let kinds: Vec<(String, usize, Option<Color>)> = Kind::ALL
            .iter()
            .map(|k| (k.label().to_string(), s.hosts.iter().filter(|h| h.kind == *k).count(), Some(rgb(*k))))
            .filter(|(_, n, _)| *n > 0)
            .collect();
        row = count_section(ws, row, "Geräte nach Typ", "Gerätetyp", &kinds, true)?;

        let mut families: Vec<(String, usize, Option<Color>)> = Vec::new();
        for h in &s.hosts {
            let (family, [r, g, b]) = fingerprint::os_family(h.os.as_deref());
            match families.iter_mut().find(|(f, ..)| f == family) {
                Some(entry) => entry.1 += 1,
                None => families.push((family.to_string(), 1, Some(Color::RGB(u32::from(r) << 16 | u32::from(g) << 8 | u32::from(b))))),
            }
        }
        families.sort_by(|a, b| b.1.cmp(&a.1));
        row = count_section(ws, row, "Betriebssysteme", "Betriebssystem", &families, true)?;
    }

    // Distinct hosts per open port, from both scans
    let mut pairs: BTreeSet<(Ipv4Addr, u16)> = BTreeSet::new();
    if let Some(s) = ip {
        pairs.extend(s.hosts.iter().flat_map(|h| h.services.iter().map(move |p| (h.ip, *p))));
    }
    if let Some(p) = port {
        pairs.extend(p.open.iter().copied());
    }
    let mut per_port: BTreeMap<u16, usize> = BTreeMap::new();
    for (_, p) in &pairs {
        *per_port.entry(*p).or_default() += 1;
    }
    let mut services: Vec<(u16, usize)> = per_port.into_iter().collect();
    services.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    services.truncate(TOP_SERVICES);
    let services: Vec<(String, usize, Option<Color>)> = services
        .into_iter()
        .map(|(p, n)| {
            let name = parse::service_name(p);
            (if name.is_empty() { format!("Port {p}") } else { format!("{} ({p})", name.to_uppercase()) }, n, None)
        })
        .collect();
    count_section(ws, row, "Häufigste Dienste", "Dienst (Port)", &services, false)?;
    Ok(())
}

/// Section title, a two-column table (label, count) and a chart next to it. Returns the next free row.
fn count_section(
    ws: &mut Worksheet,
    row: u32,
    title: &str,
    header: &str,
    rows: &[(String, usize, Option<Color>)],
    doughnut: bool,
) -> Result<u32, XlsxError> {
    if rows.is_empty() {
        return Ok(row);
    }
    section(ws, row, title)?;
    let first = row + 2;
    let last = first + rows.len() as u32;
    ws.add_table(first, 1, last, 2, &table(&[header, "Anzahl"], TableStyle::Light1))?;
    for (i, (label, n, color)) in rows.iter().enumerate() {
        let r = first + 1 + i as u32;
        let format = color.map_or(Format::new(), |c| Format::new().set_bold().set_font_color(c));
        ws.write_string_with_format(r, 1, label, &format)?;
        ws.write_number(r, 2, *n as f64)?;
    }
    let mut chart = Chart::new(if doughnut { ChartType::Doughnut } else { ChartType::Bar });
    {
        let series = chart
            .add_series()
            .set_categories((OVERVIEW, first + 1, 1, last, 1))
            .set_values((OVERVIEW, first + 1, 2, last, 2))
            .set_data_label(ChartDataLabel::new().show_value());
        if rows.iter().all(|(.., c)| c.is_some()) {
            let points: Vec<ChartPoint> = rows
                .iter()
                .filter_map(|(.., c)| *c)
                .map(|c| ChartPoint::new().set_format(ChartFormat::new().set_solid_fill(ChartSolidFill::new().set_color(c))))
                .collect();
            series.set_points(&points);
        } else {
            series.set_format(ChartFormat::new().set_solid_fill(ChartSolidFill::new().set_color(ACCENT))).set_gap(60);
        }
    }
    chart.title().set_name(title);
    if doughnut {
        chart.legend().set_position(ChartLegendPosition::Right);
        chart.set_hole_size(55);
    } else {
        chart.legend().set_hidden();
        chart.y_axis().set_reverse(); // largest on top
    }
    chart.set_width(560).set_height(300);
    ws.insert_chart(row + 2, 4, &chart)?;
    Ok(row + 2 + (rows.len() as u32 + 2).max(17))
}

fn hosts_sheet(ws: &mut Worksheet, s: &IpScan) -> Result<(), XlsxError> {
    ws.set_name("Geräte")?;
    title(ws, "Geräte", &format!("{} von {} Adressen aktiv · Bereich {}", s.hosts.len(), s.scanned.len(), s.range))?;
    if s.hosts.is_empty() {
        ws.write_string(4, 1, "Keine aktiven Geräte gefunden.")?;
        return Ok(());
    }
    let header = [
        "IP-Adresse", "Hostname", "Gerätetyp", "Betriebssystem", "Hersteller", "Modell", "Domäne", "Ping (ms)", "TTL",
        "MAC-Adresse", "Dienste", "Erkannt über", "Details",
    ];
    let widths = [16.0, 26.0, 22.0, 32.0, 24.0, 30.0, 16.0, 10.0, 7.0, 19.0, 40.0, 12.0, 90.0];
    let first = 4u32;
    let last = first + s.hosts.len() as u32;
    ws.add_table(first, 1, last, header.len() as u16, &table(&header, TableStyle::Medium2))?;
    for (i, w) in widths.iter().enumerate() {
        ws.set_column_width(1 + i as u16, *w)?;
    }
    let mono = Format::new().set_font_name("Consolas");
    let number = Format::new().set_num_format("0").set_align(FormatAlign::Right);
    let guess = Format::new().set_italic().set_font_color(MUTED);
    for (i, h) in s.hosts.iter().enumerate() {
        let r = first + 1 + i as u32;
        ws.write_string_with_format(r, 1, h.ip.to_string(), &mono)?;
        ws.write_string(r, 2, h.name.as_deref().unwrap_or(""))?;
        ws.write_string_with_format(r, 3, h.kind.label(), &Format::new().set_bold().set_font_color(rgb(h.kind)))?;
        let os = h.os.as_deref().unwrap_or("");
        if h.os_guessed() {
            ws.write_string_with_format(r, 4, format!("≈ {os}"), &guess)?;
        } else {
            ws.write_string(r, 4, os)?;
        }
        ws.write_string(r, 5, h.vendor.as_deref().unwrap_or(""))?;
        ws.write_string(r, 6, h.model.as_deref().unwrap_or(""))?;
        ws.write_string(r, 7, h.domain.as_deref().unwrap_or(""))?;
        if let Some(ms) = h.rtt_ms {
            ws.write_number_with_format(r, 8, f64::from(ms), &number)?;
        }
        if let Some(ttl) = h.ttl {
            ws.write_number_with_format(r, 9, f64::from(ttl), &number)?;
        }
        ws.write_string_with_format(r, 10, h.mac.as_deref().unwrap_or(""), &mono)?;
        ws.write_string(r, 11, parse::services_text(&h.services))?;
        ws.write_string(r, 12, if h.rtt_ms.is_some() { "Ping" } else { "ARP / TCP" })?;
        ws.write_string(r, 13, h.details.join(" | "))?;
    }
    ws.add_conditional_format(first + 1, 8, last, 8, &ConditionalFormatDataBar::new())?;
    ws.set_freeze_panes(first + 1, 2)?;
    Ok(())
}

fn ports_sheet(ws: &mut Worksheet, p: &PortScan) -> Result<(), XlsxError> {
    ws.set_name("Ports")?;
    title(ws, "Offene Ports", &format!("Ziel {} · {} Ports je Host · {} Host(s) geprüft", p.target, p.port_count, p.hosts.len()))?;
    if p.open.is_empty() {
        ws.write_string(4, 1, "Keine offenen Ports gefunden.")?;
        return Ok(());
    }
    let header = ["IP-Adresse", "Hostname", "Port", "Dienst", "Version / Antwort"];
    let first = 4u32;
    let last = first + p.open.len() as u32;
    ws.add_table(first, 1, last, header.len() as u16, &table(&header, TableStyle::Medium2))?;
    for (i, w) in [16.0, 30.0, 10.0, 26.0, 60.0].iter().enumerate() {
        ws.set_column_width(1 + i as u16, *w)?;
    }
    let mono = Format::new().set_font_name("Consolas");
    for (i, (ip, port)) in p.open.iter().enumerate() {
        let r = first + 1 + i as u32;
        let name = p.hosts.iter().find(|(h, _)| h == ip).and_then(|(_, n)| n.as_deref()).unwrap_or("");
        ws.write_string_with_format(r, 1, ip.to_string(), &mono)?;
        ws.write_string(r, 2, name)?;
        ws.write_number(r, 3, f64::from(*port))?;
        ws.write_string(r, 4, parse::describe(*port))?;
        ws.write_string(r, 5, p.info.get(i).cloned().flatten().unwrap_or_default())?;
    }
    ws.set_freeze_panes(first + 1, 0)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::Host;

    fn host(last: u8, rtt: Option<u32>, services: &[u16], kind: Kind) -> Host {
        Host {
            ip: Ipv4Addr::new(10, 0, 0, last),
            rtt_ms: rtt,
            mac: Some(format!("00-11-22-33-44-{last:02X}")),
            name: (last % 2 == 0).then(|| format!("host-{last}")),
            services: services.to_vec(),
            kind,
            ttl: rtt.map(|_| 64),
            os: Some(if last == 30 { "Unix-basiert".into() } else { "Windows 11 24H2".into() }),
            os_source: Some(if last == 30 { "TTL" } else { "SMB" }),
            vendor: Some("Ubiquiti".into()),
            model: (last == 20).then(|| "LaserJet M404".into()),
            domain: Some("example.local".into()),
            details: vec!["SMB: Windows 10.0 Build 26100, Domäne example.local".into(), "TTL: 128".into()],
        }
    }

    #[test]
    fn writes_full_report() {
        let ip = IpScan {
            range: "10.0.0.0/24".into(),
            scanned: (1..=254).map(|i| Ipv4Addr::new(10, 0, 0, i)).collect(),
            hosts: vec![
                host(1, Some(1), &[22, 80], Kind::Router),
                host(10, Some(0), &[135, 445, 3389], Kind::WindowsServer),
                host(11, Some(3), &[135, 445], Kind::WindowsClient),
                host(20, None, &[80, 9100], Kind::Printer),
                host(30, Some(12), &[], Kind::Unknown),
            ],
            gateway: Some(Ipv4Addr::new(10, 0, 0, 1)),
            secs: 3.1,
            at: chrono::Local::now(),
        };
        let port = PortScan {
            target: "10.0.0.10".into(),
            port_count: 62,
            hosts: vec![(Ipv4Addr::new(10, 0, 0, 10), Some("host-10".into()))],
            open: vec![(Ipv4Addr::new(10, 0, 0, 10), 445), (Ipv4Addr::new(10, 0, 0, 10), 3389)],
            info: vec![Some("Windows 10.0 Build 26100 · SRV01".into()), None],
            secs: 0.6,
            at: chrono::Local::now(),
        };
        let dir = std::env::temp_dir();
        write(&dir.join("netscan-test-report.xlsx"), Some(&ip), Some(&port)).unwrap();
        assert!(std::fs::metadata(dir.join("netscan-test-report.xlsx")).unwrap().len() > 5_000);
        // edge cases: only one kind of scan, and a scan without results
        write(&dir.join("netscan-test-ports.xlsx"), None, Some(&port)).unwrap();
        let empty = IpScan { hosts: vec![], ..ip };
        write(&dir.join("netscan-test-empty.xlsx"), Some(&empty), None).unwrap();
    }
}
