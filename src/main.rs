#![cfg_attr(windows, windows_subsystem = "windows")] // no console window behind the GUI

mod export;
mod fingerprint;
mod map;
mod oui;
mod parse;
mod platform;
mod scan;

use std::cmp::Ordering;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use chrono::{DateTime, Local};
use eframe::egui::{self, Color32, RichText, TextEdit, Ui};
use egui_extras::{Column, TableBuilder};
use scan::{Host, Kind, Progress};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const REPO_URL: &str = env!("CARGO_PKG_REPOSITORY");
const RECENT_MAX: usize = 6;
const PORT_TIMEOUT_MS: u64 = 500;
const ROW_HEIGHT: f32 = 24.0;
pub const NEW_COLOR: Color32 = Color32::from_rgb(46, 160, 67);
pub const WARN_COLOR: Color32 = Color32::from_rgb(217, 119, 6);

/// Ready-made port lists for the port scan.
const PORT_PRESETS: &[(&str, &str)] = &[
    ("Top 62 (Standard)", ""),
    ("Web-Oberflächen", "80,81,443,3000,4443,5000,8000,8006,8008,8080,8081,8443,8888,9000,9090,9443,10000"),
    ("Windows & Active Directory", "53,88,135,139,389,445,464,636,3268,3269,3389,5985,5986,9389"),
    ("Fernzugriff", "22,23,3389,5900,5938,5985,5986"),
    ("Datenbanken", "1433,1521,3306,5432,6379,9200,27017"),
    ("Drucker", "515,631,9100"),
    ("1–1024", "1-1024"),
    ("Alle 65 535", "all"),
];

pub struct IpScan {
    pub range: String,
    pub scanned: Vec<Ipv4Addr>,
    pub hosts: Vec<Host>,
    pub gateway: Option<Ipv4Addr>,
    pub secs: f32,
    pub at: DateTime<Local>,
}

pub struct PortScan {
    pub target: String,
    pub port_count: usize,
    pub hosts: Vec<(Ipv4Addr, Option<String>)>,
    pub open: Vec<(Ipv4Addr, u16)>,
    /// Banner, web title or Windows build per entry of `open`.
    pub info: Vec<Option<String>>,
    pub secs: f32,
    pub at: DateTime<Local>,
}

enum Finished {
    Ip(IpScan),
    Port(PortScan),
}

enum Update {
    Checking(JoinHandle<Result<String, String>>),
    Done(Result<String, String>),
}

struct Job {
    progress: Arc<Progress>,
    handle: JoinHandle<Finished>,
}

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Hosts,
    Map,
    Ports,
}

/// A click in a table or on the map that changes app state; applied after drawing, outside the borrows.
pub enum Action {
    ScanPorts(Ipv4Addr, &'static str),
    Select(Ipv4Addr),
    Notice(String, bool), // text, is_error
}

/// A column of the host table; the user picks which ones are shown.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Col {
    Ip,
    Name,
    Kind,
    Os,
    OsSource,
    Vendor,
    Model,
    Ping,
    Ttl,
    Mac,
    Services,
    Domain,
}

impl Col {
    const ALL: [Col; 12] = [
        Col::Ip, Col::Name, Col::Kind, Col::Os, Col::OsSource, Col::Vendor, Col::Model, Col::Ping, Col::Ttl, Col::Mac,
        Col::Services, Col::Domain,
    ];
    const DEFAULT: [Col; 9] = [Col::Ip, Col::Name, Col::Kind, Col::Os, Col::Vendor, Col::Model, Col::Ping, Col::Mac, Col::Services];

    fn label(self) -> &'static str {
        match self {
            Col::Ip => "IP-Adresse",
            Col::Name => "Hostname",
            Col::Kind => "Gerätetyp",
            Col::Os => "Betriebssystem",
            Col::OsSource => "OS-Quelle",
            Col::Vendor => "Hersteller",
            Col::Model => "Modell",
            Col::Ping => "Ping",
            Col::Ttl => "TTL",
            Col::Mac => "MAC-Adresse",
            Col::Services => "Dienste",
            Col::Domain => "Domäne",
        }
    }

    fn width(self) -> f32 {
        match self {
            Col::Ip => 128.0,
            Col::Name => 170.0,
            Col::Kind => 165.0,
            Col::Os => 180.0,
            Col::OsSource => 110.0,
            Col::Vendor => 150.0,
            Col::Model => 190.0,
            Col::Ping => 62.0,
            Col::Ttl => 48.0,
            Col::Mac => 140.0,
            Col::Services => 200.0,
            Col::Domain => 130.0,
        }
    }

    fn from_key(key: &str) -> Option<Col> {
        Col::ALL.into_iter().find(|c| format!("{c:?}") == key.trim())
    }

    /// Plain text for filter, clipboard and CSV.
    fn text(self, h: &Host) -> String {
        let opt = |v: &Option<String>| v.clone().unwrap_or_default();
        match self {
            Col::Ip => h.ip.to_string(),
            Col::Name => opt(&h.name),
            Col::Kind => h.kind.label().to_string(),
            Col::Os => opt(&h.os),
            Col::OsSource => match h.os_source {
                Some("TTL") => "TTL (geschätzt)".to_string(),
                source => source.unwrap_or_default().to_string(),
            },
            Col::Vendor => opt(&h.vendor),
            Col::Model => opt(&h.model),
            Col::Ping => ping_text(h.rtt_ms),
            Col::Ttl => h.ttl.map_or(String::new(), |t| t.to_string()),
            Col::Mac => opt(&h.mac),
            Col::Services => parse::services_text(&h.services),
            Col::Domain => opt(&h.domain),
        }
    }

    /// Ascending order; empty values last.
    fn cmp(self, a: &Host, b: &Host) -> Ordering {
        match self {
            Col::Ip => a.ip.cmp(&b.ip),
            Col::Kind => a.kind.cmp(&b.kind),
            Col::Ping => a.rtt_ms.unwrap_or(u32::MAX).cmp(&b.rtt_ms.unwrap_or(u32::MAX)),
            Col::Ttl => a.ttl.unwrap_or(u8::MAX).cmp(&b.ttl.unwrap_or(u8::MAX)),
            Col::Services => b.services.len().cmp(&a.services.len()),
            _ => {
                let (x, y) = (self.text(a).to_lowercase(), self.text(b).to_lowercase());
                (x.is_empty(), x).cmp(&(y.is_empty(), y))
            }
        }
    }
}

struct App {
    tab: Tab,
    range: String,
    target: String,
    ports: String,
    filter: String,
    focus_filter: bool,
    only_new: bool,
    /// Shown host columns, always in `Col::ALL` order.
    columns: Vec<Col>,
    sort: (Col, bool),
    ip: Option<IpScan>,
    port: Option<PortScan>,
    selected: Option<Ipv4Addr>,
    /// Against the previous complete scan of the same range.
    new_ips: HashSet<Ipv4Addr>,
    gone: Vec<Host>,
    job: Option<Job>,
    message: Option<(String, bool)>, // text, is_error
    autostart: bool,
    /// Ranges scanned lately, newest first; a technician moves between the same few customer networks.
    recent: Vec<String>,
    about: bool,
    update: Option<Update>,
}

// eframe sets the Dock icon from this image at runtime, so macOS gets the version with Apple's margin
#[cfg(target_os = "macos")]
const ICON: &[u8] = include_bytes!("../assets/icon-mac.png");
#[cfg(not(target_os = "macos"))]
const ICON: &[u8] = include_bytes!("../assets/icon.png");

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("NetScan")
            .with_inner_size([1180.0, 720.0])
            .with_min_inner_size([860.0, 520.0])
            .with_icon(eframe::icon_data::from_png_bytes(ICON).expect("the icon in assets/ is a valid PNG")),
        ..Default::default()
    };
    eframe::run_native(
        "NetScan",
        options,
        Box::new(|cc| {
            cc.egui_ctx.global_style_mut(|style| {
                style.spacing.item_spacing = egui::vec2(8.0, 6.0);
                style.spacing.button_padding = egui::vec2(10.0, 5.0);
            });
            Ok(Box::new(App::new(std::env::args().skip(1).collect())))
        }),
    )
}

impl App {
    /// Command line: `netscan [bereich] [--ports] [--karte]` – with a range the scan starts right away.
    fn new(args: Vec<String>) -> Self {
        let target = args.iter().find(|a| !a.starts_with("--")).cloned();
        let tab = if args.iter().any(|a| a == "--ports") {
            Tab::Ports
        } else if args.iter().any(|a| a == "--karte") {
            Tab::Map
        } else {
            Tab::Hosts
        };
        let mut app = App {
            tab,
            range: parse::default_range(&scan::local_networks(), parse::local_ip()),
            target: String::new(),
            ports: String::new(),
            filter: String::new(),
            focus_filter: false,
            only_new: false,
            columns: Col::DEFAULT.to_vec(),
            sort: (Col::Ip, true),
            ip: None,
            port: None,
            selected: None,
            new_ips: HashSet::new(),
            gone: Vec::new(),
            job: None,
            message: None,
            autostart: target.is_some(),
            recent: Vec::new(),
            about: false,
            update: None,
        };
        if let Some(text) = platform::settings_file().and_then(|p| std::fs::read_to_string(p).ok()) {
            app.apply_settings(&text);
        }
        if let Some(t) = target {
            if tab == Tab::Ports { app.target = t } else { app.range = t }
        }
        app
    }

    fn apply_settings(&mut self, text: &str) {
        for (key, value) in text.lines().filter_map(|l| l.split_once('=')) {
            match key.trim() {
                "columns" => {
                    let cols: Vec<Col> = value.split(',').filter_map(Col::from_key).collect();
                    if !cols.is_empty() {
                        self.columns = Col::ALL.into_iter().filter(|c| cols.contains(c)).collect();
                    }
                }
                "ports" => self.ports = value.trim().to_string(),
                "recent" => self.recent = value.split('|').map(str::trim).filter(|r| !r.is_empty()).take(RECENT_MAX).map(String::from).collect(),
                _ => {}
            }
        }
    }

    fn settings_text(&self) -> String {
        let cols: Vec<String> = self.columns.iter().map(|c| format!("{c:?}")).collect();
        format!("columns={}\nports={}\nrecent={}\n", cols.join(","), self.ports, self.recent.join("|"))
    }

    fn save_settings(&self) {
        // losing the preferences is harmless, so a failed write is not reported
        if let Some(path) = platform::settings_file() {
            let _ = path.parent().map(std::fs::create_dir_all);
            let _ = std::fs::write(path, self.settings_text());
        }
    }

    fn spawn(&mut self, ctx: &egui::Context, work: impl FnOnce(&Progress) -> Finished + Send + 'static) {
        let progress = Arc::new(Progress::default());
        let (p, ctx) = (progress.clone(), ctx.clone());
        let handle = thread::spawn(move || {
            let result = work(&p);
            ctx.request_repaint();
            result
        });
        self.job = Some(Job { progress, handle });
        self.message = None;
    }

    fn start_ip(&mut self, ctx: &egui::Context) {
        let ips = match parse::parse_hosts(&self.range) {
            Ok(ips) => ips,
            Err(e) => return self.message = Some((e, true)),
        };
        let range = self.range.trim().to_string();
        self.recent.retain(|r| *r != range);
        self.recent.insert(0, range.clone());
        self.recent.truncate(RECENT_MAX);
        self.save_settings();
        self.spawn(ctx, move |p| {
            let started = Instant::now();
            let hosts = scan::discover(&ips, p);
            Finished::Ip(IpScan {
                range,
                gateway: scan::gateway(),
                hosts,
                scanned: ips,
                secs: started.elapsed().as_secs_f32(),
                at: Local::now(),
            })
        });
    }

    fn start_ports(&mut self, ctx: &egui::Context) {
        let parsed = parse::parse_hosts(&self.target).and_then(|ips| Ok((ips, parse::parse_ports(&self.ports)?)));
        let (ips, ports) = match parsed {
            Ok(v) => v,
            Err(e) => return self.message = Some((e, true)),
        };
        self.save_settings();
        let target = self.target.trim().to_string();
        self.spawn(ctx, move |p| {
            let started = Instant::now();
            // A single target is scanned even if it ignores ping; for ranges, only the hosts that are up
            let (hosts, open) = if let [ip] = ips[..] {
                thread::scope(|s| {
                    let name = s.spawn(|| scan::hostnames(&[ip]).pop().flatten());
                    let open = scan::scan_ports(&[ip], &ports, PORT_TIMEOUT_MS, p);
                    (vec![(ip, name.join().unwrap())], open)
                })
            } else {
                let hosts: Vec<(Ipv4Addr, Option<String>)> = scan::discover(&ips, p).into_iter().map(|h| (h.ip, h.name)).collect();
                let addrs: Vec<Ipv4Addr> = hosts.iter().map(|(ip, _)| *ip).collect();
                let open = scan::scan_ports(&addrs, &ports, PORT_TIMEOUT_MS, p);
                (hosts, open)
            };
            let info = scan::port_details(&open, p);
            Finished::Port(PortScan {
                target,
                port_count: ports.len(),
                hosts,
                open,
                info,
                secs: started.elapsed().as_secs_f32(),
                at: Local::now(),
            })
        });
    }

    fn poll(&mut self, ctx: &egui::Context) {
        let Some(job) = &self.job else { return };
        if !job.handle.is_finished() {
            ctx.request_repaint_after(Duration::from_millis(100));
            return;
        }
        let job = self.job.take().expect("checked above");
        let stopped = job.progress.cancelled();
        match job.handle.join() {
            Ok(Finished::Ip(r)) => {
                // a stopped scan would report every host it never reached as gone
                (self.new_ips, self.gone) = match self.ip.take() {
                    Some(old) if old.range == r.range && !stopped => scan::changes(old.hosts, &r.hosts),
                    _ => (HashSet::new(), Vec::new()),
                };
                self.only_new &= !self.new_ips.is_empty();
                self.selected = self.selected.filter(|ip| r.hosts.iter().any(|h| h.ip == *ip));
                self.ip = Some(r);
            }
            Ok(Finished::Port(r)) => self.port = Some(r),
            Err(_) => return self.message = Some(("Scan unerwartet abgebrochen".into(), true)),
        }
        self.message = stopped.then(|| ("Scan gestoppt – Ergebnis unvollständig".to_string(), true));
    }

    fn scan_now(&mut self, ctx: &egui::Context) {
        if self.job.is_some() {
            return;
        }
        if self.tab == Tab::Ports {
            self.start_ports(ctx);
        } else {
            self.start_ip(ctx);
        }
    }

    fn can_export(&self) -> bool {
        self.job.is_none() && (self.ip.is_some() || self.port.is_some())
    }

    fn selected_host(&self) -> Option<&Host> {
        let ip = self.selected?;
        self.ip.as_ref()?.hosts.iter().find(|h| h.ip == ip)
    }

    /// The hosts the table shows right now: filter and "only new" applied, sorted.
    fn visible_hosts(&self) -> Vec<&Host> {
        let Some(scan) = &self.ip else { return Vec::new() };
        let needle = self.filter.trim().to_lowercase();
        let mut rows: Vec<&Host> = scan
            .hosts
            .iter()
            .filter(|h| !self.only_new || self.new_ips.contains(&h.ip))
            .filter(|h| needle.is_empty() || row_text(h).to_lowercase().contains(&needle))
            .collect();
        let (col, ascending) = self.sort;
        rows.sort_by(|a, b| {
            let order = col.cmp(a, b);
            if ascending { order.then(a.ip.cmp(&b.ip)) } else { order.reverse().then(a.ip.cmp(&b.ip)) }
        });
        rows
    }

    /// Header plus rows of what the current tab shows, for CSV and the clipboard.
    fn table_rows(&self) -> Vec<Vec<String>> {
        if let (Tab::Ports, Some(p)) = (self.tab, &self.port) {
            let mut rows = vec![["IP-Adresse", "Hostname", "Port", "Dienst", "Version / Antwort", "Hinweis"].map(String::from).to_vec()];
            for (i, (ip, port)) in p.open.iter().enumerate() {
                let name = p.hosts.iter().find(|(h, _)| h == ip).and_then(|(_, n)| n.clone()).unwrap_or_default();
                let info = p.info.get(i).cloned().flatten().unwrap_or_default();
                let note = parse::port_note(*port).unwrap_or_default().to_string();
                rows.push(vec![ip.to_string(), name, port.to_string(), parse::describe(*port), info, note]);
            }
            return rows;
        }
        let mut rows = vec![self.columns.iter().map(|c| c.label().to_string()).collect()];
        rows.extend(self.visible_hosts().iter().map(|h| self.columns.iter().map(|c| c.text(h)).collect()));
        rows
    }

    /// F5 scan, Esc stop or deselect, Ctrl+F filter, Ctrl+E export, Ctrl+C copy the selected host, F1 info.
    fn shortcuts(&mut self, ctx: &egui::Context) {
        let typing = ctx.memory(|m| m.focused().is_some());
        let (f1, f5, esc, find, export, copy) = ctx.input(|i| {
            let ctrl = i.modifiers.command;
            (
                i.key_pressed(egui::Key::F1),
                i.key_pressed(egui::Key::F5),
                i.key_pressed(egui::Key::Escape),
                ctrl && i.key_pressed(egui::Key::F),
                ctrl && i.key_pressed(egui::Key::E),
                i.events.iter().any(|e| matches!(e, egui::Event::Copy)),
            )
        });
        if f1 {
            self.about = !self.about;
        }
        if f5 {
            self.scan_now(ctx);
        }
        if esc {
            match &self.job {
                Some(job) => job.progress.cancel(),
                None if self.about => self.about = false,
                None => self.selected = None,
            }
        }
        if find {
            self.tab = Tab::Hosts;
            self.focus_filter = true;
        }
        if export && self.can_export() {
            self.export_excel();
        }
        if copy && !typing {
            if let Some(h) = self.selected_host() {
                let text = tsv_row(&self.columns.iter().map(|c| c.text(h)).collect::<Vec<_>>());
                ctx.copy_text(text);
                self.message = Some(("Zeile in die Zwischenablage kopiert".into(), false));
            }
        }
    }

    fn save_dialog(title: &str, ext: &str, filter: &str) -> Option<std::path::PathBuf> {
        rfd::FileDialog::new()
            .set_title(title)
            .set_file_name(format!("NetScan_{}.{ext}", Local::now().format("%Y-%m-%d_%H%M")))
            .add_filter(filter, &[ext])
            .save_file()
    }

    fn export_excel(&mut self) {
        let Some(path) = Self::save_dialog("Excel-Bericht speichern", "xlsx", "Excel-Arbeitsmappe") else { return };
        self.message = Some(match export::write(&path, self.ip.as_ref(), self.port.as_ref()) {
            Ok(()) => {
                platform::open(&path.to_string_lossy());
                (format!("Bericht gespeichert: {}", path.display()), false)
            }
            Err(e) => (format!("Export fehlgeschlagen: {e}"), true),
        });
    }

    fn export_csv(&mut self) {
        let Some(path) = Self::save_dialog("CSV speichern", "csv", "CSV (Semikolon, für Excel)") else { return };
        let rows = self.table_rows();
        self.message = Some(match std::fs::write(&path, csv(&rows)) {
            Ok(()) => (format!("{} Zeilen gespeichert: {}", rows.len() - 1, path.display()), false),
            Err(e) => (format!("CSV-Export fehlgeschlagen: {e}"), true),
        });
    }

    fn toolbar(&mut self, ui: &mut Ui) {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("NetScan").size(20.0).strong());
            if ui.add(egui::Label::new(RichText::new(format!("v{VERSION}")).weak()).sense(egui::Sense::click())).on_hover_text("Version, Updates, Tastenkürzel (F1)").clicked() {
                self.about = true;
            }
            ui.add_space(14.0);
            ui.selectable_value(&mut self.tab, Tab::Hosts, RichText::new("Hosts").size(15.0));
            ui.selectable_value(&mut self.tab, Tab::Map, RichText::new("Netzwerkkarte").size(15.0));
            ui.selectable_value(&mut self.tab, Tab::Ports, RichText::new("Ports").size(15.0));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let enabled = self.can_export();
                ui.add_enabled_ui(enabled, |ui| {
                    ui.menu_button("Export ▾", |ui| {
                        if ui.button("Excel-Bericht (.xlsx)   Ctrl+E").on_hover_text("Übersicht, Diagramme und alle Tabellen").clicked() {
                            ui.close();
                            self.export_excel();
                        }
                        let what = if self.tab == Tab::Ports { "offene Ports" } else { "sichtbare Zeilen und Spalten" };
                        if ui.button("CSV (.csv)").on_hover_text(format!("Semikolon-getrennt für Excel – {what}")).clicked() {
                            ui.close();
                            self.export_csv();
                        }
                    })
                })
                .response
                .on_disabled_hover_text("Zuerst scannen");
                if ui.button("Info").on_hover_text("Version, Updates, Tastenkürzel (F1)").clicked() {
                    self.about = !self.about;
                }
            });
        });
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
            let submitted = if self.tab == Tab::Ports {
                ui.label("Ziel");
                let a = ui.add(TextEdit::singleline(&mut self.target).hint_text("IP, Name oder Bereich").desired_width(200.0));
                ui.label("Ports");
                let b = ui.add(TextEdit::singleline(&mut self.ports).hint_text("leer = Top 62 · 1-1024 · 22,80 · all").desired_width(230.0));
                ui.menu_button("Vorlagen ▾", |ui| {
                    for (label, ports) in PORT_PRESETS {
                        if ui.button(*label).on_hover_text(if ports.is_empty() { "Die 62 häufigsten Ports" } else { ports }).clicked() {
                            self.ports = ports.to_string();
                            ui.close();
                        }
                    }
                });
                enter && (a.lost_focus() || b.lost_focus())
            } else {
                ui.label("Bereich");
                let a = ui.add(TextEdit::singleline(&mut self.range).hint_text("192.168.1.0/24 · 10.0.0.1-50").desired_width(220.0));
                ui.menu_button("▾", |ui| {
                    ui.label(RichText::new("Netze dieses Computers").weak());
                    let nets = scan::local_networks();
                    if nets.is_empty() {
                        ui.label("Kein verbundener Adapter gefunden");
                    }
                    for (ip, prefix) in nets {
                        let net = parse::network(ip, prefix);
                        if ui.button(format!("{net}   (eigene IP {ip})")).clicked() {
                            self.range = net;
                            ui.close();
                        }
                    }
                    if !self.recent.is_empty() {
                        ui.separator();
                        ui.label(RichText::new("Zuletzt gescannt").weak());
                        for r in self.recent.clone() {
                            if ui.button(&r).clicked() {
                                self.range = r;
                                ui.close();
                            }
                        }
                    }
                })
                .response
                .on_hover_text("Netz eines Adapters oder einen zuletzt gescannten Bereich übernehmen");
                enter && a.lost_focus()
            };
            if let Some(job) = &self.job {
                if ui.button("Stopp").on_hover_text("Esc").clicked() {
                    job.progress.cancel();
                }
                let (stage, done, total) = job.progress.snapshot();
                let fraction = if total == 0 { 0.0 } else { done as f32 / total as f32 };
                ui.add(egui::ProgressBar::new(fraction).desired_width(300.0).animate(true).text(format!("{stage}  {done} / {total}")));
            } else {
                let label = if self.tab == Tab::Ports { "Ports scannen" } else { "Netz scannen" };
                if ui.add(egui::Button::new(RichText::new(label).strong())).on_hover_text("Enter oder F5").clicked() || submitted {
                    self.scan_now(ui.ctx());
                }
            }
        });
        ui.add_space(6.0);
    }

    fn status_bar(&self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            if let Some((text, error)) = &self.message {
                let color = if *error { ui.visuals().error_fg_color } else { ui.visuals().strong_text_color() };
                ui.colored_label(color, text);
            } else if self.job.is_some() {
                ui.label("Scan läuft …");
            } else if let (Tab::Ports, Some(p)) = (self.tab, &self.port) {
                ui.label(format!(
                    "{} offene Ports auf {} Host(s) · {} Ports je Host geprüft · {:.1} s · {}",
                    p.open.len(), p.hosts.len(), p.port_count, p.secs, p.at.format("%d.%m.%Y %H:%M")
                ));
            } else if let Some(s) = &self.ip {
                let gateway = s.gateway.map_or("–".to_string(), |g| g.to_string());
                ui.label(format!(
                    "{} von {} Adressen aktiv · {:.1} s · Gateway {gateway} · {}",
                    s.hosts.len(), s.scanned.len(), s.secs, s.at.format("%d.%m.%Y %H:%M")
                ));
                if !self.new_ips.is_empty() {
                    ui.colored_label(NEW_COLOR, format!("· {} neu seit letztem Scan", self.new_ips.len()));
                }
                if !self.gone.is_empty() {
                    ui.colored_label(ui.visuals().warn_fg_color, format!("· {} nicht mehr erreichbar", self.gone.len()))
                        .on_hover_ui(|ui| {
                            for h in &self.gone {
                                ui.label(format!("{}  {}  {}", h.ip, h.name.as_deref().unwrap_or(""), h.mac.as_deref().unwrap_or("")));
                            }
                        });
                }
            } else {
                ui.label("Bereit");
            }
        });
    }

    fn column_menu(&mut self, ui: &mut Ui) {
        ui.menu_button("Spalten ▾", |ui| {
            let mut changed = false;
            for col in Col::ALL {
                let mut on = self.columns.contains(&col);
                // the IP identifies the row and stays
                if ui.add_enabled(col != Col::Ip, egui::Checkbox::new(&mut on, col.label())).changed() {
                    changed = true;
                    self.columns = Col::ALL.into_iter().filter(|c| if *c == col { on } else { self.columns.contains(c) }).collect();
                }
            }
            ui.separator();
            if ui.button("Standard wiederherstellen").clicked() {
                self.columns = Col::DEFAULT.to_vec();
                changed = true;
            }
            if changed {
                if !self.columns.contains(&self.sort.0) {
                    self.sort = (Col::Ip, true);
                }
                self.save_settings();
            }
        })
        .response
        .on_hover_text("Welche Spalten die Tabelle zeigt – wird gespeichert");
    }

    fn hosts_view(&mut self, ui: &mut Ui) -> Option<Action> {
        let Some(total) = self.ip.as_ref().map(|s| s.hosts.len()) else {
            empty_state(ui, "Noch kein Scan", "Bereich prüfen und «Netz scannen» klicken – oder Enter drücken.");
            return None;
        };
        if total == 0 {
            empty_state(ui, "Keine aktiven Hosts", "Kein Gerät hat geantwortet. Stimmt der Bereich? Über «▾» neben dem Bereich lassen sich die Netze dieses Computers übernehmen.");
            return None;
        }
        let mut action = None;
        let shown = self.visible_hosts().len();
        ui.horizontal(|ui| {
            ui.label("Filter");
            let field = ui.add(TextEdit::singleline(&mut self.filter).hint_text("IP, Name, MAC, Typ oder Dienst  (Ctrl+F)").desired_width(300.0));
            if std::mem::take(&mut self.focus_filter) {
                field.request_focus();
            }
            if !self.filter.is_empty() && ui.small_button("✕").on_hover_text("Filter leeren").clicked() {
                self.filter.clear();
            }
            if !self.new_ips.is_empty() {
                ui.toggle_value(&mut self.only_new, format!("Nur neue ({})", self.new_ips.len()));
            }
            ui.label(RichText::new(format!("{shown} von {total} Hosts")).weak())
                .on_hover_text("Klick: Details · Doppelklick: Ports scannen · Rechtsklick: Aktionen");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                self.column_menu(ui);
                if ui.button("Tabelle kopieren").on_hover_text("Sichtbare Zeilen und Spalten – einfügbar in Excel oder ein Ticket").clicked() {
                    let rows = self.table_rows();
                    ui.ctx().copy_text(rows.iter().map(|r| tsv_row(r)).collect::<Vec<_>>().join("\n"));
                    action = Some(Action::Notice(format!("{} Zeilen kopiert", rows.len() - 1), false));
                }
            });
        });

        let rows = self.visible_hosts();
        let cols = &self.columns;
        let mut sort = self.sort;
        let mut table = TableBuilder::new(ui)
            .id_salt(format!("{cols:?}")) // fresh column widths when the column set changes
            .striped(true)
            .resizable(true)
            .sense(egui::Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center));
        for (i, col) in cols.iter().enumerate() {
            table = table.column(if i + 1 == cols.len() {
                Column::remainder().at_least(60.0).clip(true)
            } else {
                Column::initial(col.width()).at_least(40.0).clip(true)
            });
        }
        table
            .header(ROW_HEIGHT, |mut header| {
                for col in cols {
                    header.col(|ui| sort_header(ui, *col, &mut sort));
                }
            })
            .body(|body| {
                body.rows(ROW_HEIGHT, rows.len(), |mut row| {
                    let h = rows[row.index()];
                    row.set_selected(self.selected == Some(h.ip));
                    for col in cols {
                        row.col(|ui| cell(ui, *col, h, self.new_ips.contains(&h.ip)));
                    }
                    let response = row.response();
                    if response.double_clicked() {
                        action = Some(Action::ScanPorts(h.ip, ""));
                    } else if response.clicked() || response.secondary_clicked() && self.selected != Some(h.ip) {
                        action = Some(Action::Select(h.ip));
                    }
                    response.context_menu(|ui| {
                        if let Some(a) = host_menu(ui, h) {
                            action = Some(a);
                        }
                    });
                });
            });
        self.sort = sort;
        action
    }

    fn ports_view(&mut self, ui: &mut Ui) -> Option<Action> {
        let Some(scan) = &self.port else {
            empty_state(ui, "Noch kein Port-Scan", "Ziel eingeben – oder im Tab «Hosts» doppelt auf einen Host klicken.");
            return None;
        };
        let mut action = None;
        let notes = scan.open.iter().filter(|(_, p)| parse::port_note(*p).is_some()).count();
        let with_open: HashSet<Ipv4Addr> = scan.open.iter().map(|(ip, _)| *ip).collect();
        ui.horizontal(|ui| {
            stat(ui, &scan.hosts.len().to_string(), "Hosts geprüft", None);
            stat(ui, &with_open.len().to_string(), "mit offenen Ports", None);
            stat(ui, &scan.open.len().to_string(), "offene Ports", None);
            if notes > 0 {
                stat(ui, &notes.to_string(), "mit Hinweis", Some(WARN_COLOR));
            }
            ui.label(RichText::new(format!("{} Ports je Host · {:.1} s · {}", scan.port_count, scan.secs, scan.at.format("%d.%m.%Y %H:%M"))).weak());
        });
        ui.add_space(6.0);
        if scan.hosts.is_empty() {
            empty_state(ui, "Kein Host erreichbar", "Im Bereich hat kein Gerät geantwortet. Eine einzelne IP wird auch ohne Ping-Antwort gescannt.");
            return None;
        }
        if scan.open.is_empty() {
            empty_state(ui, "Keine offenen Ports", &format!("{} Ports auf {} Host(s) geprüft.", scan.port_count, scan.hosts.len()));
            return None;
        }
        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            for (ip, name) in scan.hosts.iter().filter(|(ip, _)| with_open.contains(ip)) {
                let ports: Vec<(u16, Option<&String>)> = scan
                    .open
                    .iter()
                    .zip(&scan.info)
                    .filter(|((h, _), _)| h == ip)
                    .map(|((_, p), info)| (*p, info.as_ref()))
                    .collect();
                egui::Frame::group(ui.style()).inner_margin(10.0).corner_radius(8.0).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(ip.to_string()).monospace().strong().size(15.0));
                        if let Some(n) = name {
                            ui.label(RichText::new(n).strong().size(15.0));
                        }
                        ui.label(RichText::new(format!("{} offen", ports.len())).weak());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if scan.port_count < 65535 && ui.button("Alle Ports scannen").clicked() {
                                action = Some(Action::ScanPorts(*ip, "all"));
                            }
                            if ui.button("Kopieren").on_hover_text("Host mit allen offenen Ports").clicked() {
                                let lines: Vec<String> = ports
                                    .iter()
                                    .map(|(p, info)| tsv_row(&[format!("{ip}:{p}"), parse::describe(*p), info.cloned().unwrap_or_default()]))
                                    .collect();
                                ui.ctx().copy_text(lines.join("\n"));
                                action = Some(Action::Notice(format!("{ip} mit {} Ports kopiert", ports.len()), false));
                            }
                        });
                    });
                    ui.add_space(2.0);
                    egui::Grid::new(("ports", ip)).num_columns(5).striped(true).spacing([16.0, 6.0]).show(ui, |ui| {
                        for (port, info) in &ports {
                            ui.label(RichText::new(format!("{port}/tcp")).monospace().strong());
                            ui.label(parse::describe(*port));
                            let text = info.map_or(String::new(), |s| shorten(s, 70));
                            let shown = ui.label(RichText::new(text).weak());
                            if let Some(full) = info.filter(|s| s.chars().count() > 70) {
                                shown.on_hover_text(full.as_str());
                            }
                            match parse::port_note(*port) {
                                Some(note) => ui.colored_label(WARN_COLOR, format!("⚠ {note}")),
                                None => ui.label(""),
                            };
                            match port_action(*port) {
                                Some(action) if ui.button(action).clicked() => open_port(*ip, *port),
                                Some(_) => {}
                                None => {
                                    ui.label("");
                                }
                            }
                            ui.end_row();
                        }
                    });
                });
                ui.add_space(6.0);
            }
            let closed: Vec<String> = scan.hosts.iter().filter(|(ip, _)| !with_open.contains(ip)).map(|(ip, _)| ip.to_string()).collect();
            if !closed.is_empty() {
                ui.collapsing(format!("{} Host(s) ohne offene Ports", closed.len()), |ui| {
                    ui.label(RichText::new(closed.join(" · ")).monospace().weak());
                });
            }
        });
        action
    }
}

impl App {
    fn about_window(&mut self, ctx: &egui::Context) {
        let mut open = self.about;
        egui::Window::new("Über NetScan")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_width(420.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("NetScan").size(22.0).strong());
                    ui.label(RichText::new(format!("Version {VERSION}")).size(15.0));
                });
                ui.label("IP- und Port-Scanner für ICT-Techniker · Windows und macOS");
                ui.add_space(8.0);
                ui.horizontal(|ui| match &self.update {
                    None => {
                        if ui.button("Nach Updates suchen").clicked() {
                            let repo = REPO_URL.trim_start_matches("https://github.com/").to_string();
                            self.update = Some(Update::Checking(thread::spawn(move || platform::latest_release(&repo))));
                        }
                    }
                    Some(Update::Checking(_)) => {
                        ui.spinner();
                        ui.label("Prüfe GitHub …");
                    }
                    Some(Update::Done(result)) => {
                        match result {
                            Ok(tag) if is_newer(tag, VERSION) => {
                                ui.colored_label(NEW_COLOR, format!("Version {} ist verfügbar", tag.trim_start_matches('v')));
                                if ui.button("Herunterladen").clicked() {
                                    platform::open(&format!("{REPO_URL}/releases/latest"));
                                }
                            }
                            Ok(_) => {
                                ui.label("Du hast die neuste Version.");
                            }
                            Err(e) => {
                                ui.colored_label(ui.visuals().warn_fg_color, format!("Prüfung nicht möglich: {e}"));
                            }
                        }
                        if ui.small_button("↻").on_hover_text("Nochmals prüfen").clicked() {
                            self.update = None;
                        }
                    }
                });
                ui.add_space(8.0);
                ui.hyperlink_to("Projekt auf GitHub", REPO_URL);
                ui.hyperlink_to("Alle Versionen und Downloads", format!("{REPO_URL}/releases"));
                ui.hyperlink_to("Fehler melden oder Wunsch äussern", format!("{REPO_URL}/issues"));
                ui.add_space(8.0);
                ui.strong("Tastenkürzel");
                egui::Grid::new("keys").num_columns(2).spacing([16.0, 3.0]).show(ui, |ui| {
                    for (key, what) in [
                        ("Enter / F5", "Scan starten"),
                        ("Esc", "Scan stoppen, Fenster oder Details schliessen"),
                        ("Ctrl+F", "Filter"),
                        ("Ctrl+E", "Excel-Bericht"),
                        ("Ctrl+C", "ausgewählten Host kopieren"),
                        ("Doppelklick", "Ports des Hosts scannen"),
                        ("Rechtsklick", "Aktionen: RDP, Freigaben, Ping …"),
                        ("F1", "dieses Fenster"),
                    ] {
                        ui.label(RichText::new(key).monospace());
                        ui.label(what);
                        ui.end_row();
                    }
                });
                if let Some(path) = platform::settings_file() {
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Einstellungen:").weak());
                        if ui.link("Ordner öffnen").on_hover_text(path.display().to_string()).clicked() {
                            if let Some(dir) = path.parent() {
                                let _ = std::fs::create_dir_all(dir);
                                platform::open(&dir.to_string_lossy());
                            }
                        }
                    });
                }
                ui.add_space(4.0);
                ui.label(RichText::new("MIT-Lizenz · © 2026 Elia Gantenbein").weak());
            });
        self.about = open;
    }
}

/// "v0.10.1" is newer than "0.9.3": compared number by number, a leading v ignored.
fn is_newer(latest: &str, current: &str) -> bool {
    let parts = |v: &str| v.trim().trim_start_matches('v').split('.').map(|p| p.parse::<u32>().unwrap_or(0)).collect::<Vec<_>>();
    parts(latest) > parts(current)
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        if std::mem::take(&mut self.autostart) {
            self.scan_now(ui.ctx());
        }
        self.poll(ui.ctx());
        self.shortcuts(ui.ctx());
        if self.tab == Tab::Ports && self.target.trim().is_empty() {
            // the host picked in the table or on the map is the obvious port-scan target
            if let Some(ip) = self.selected {
                self.target = ip.to_string();
            }
        }
        if let Some(Update::Checking(handle)) = &self.update {
            if handle.is_finished() {
                if let Some(Update::Checking(handle)) = self.update.take() {
                    self.update = Some(Update::Done(handle.join().unwrap_or_else(|_| Err("Prüfung abgebrochen".into()))));
                }
            } else {
                ui.ctx().request_repaint_after(Duration::from_millis(200));
            }
        }
        self.about_window(ui.ctx());
        egui::Panel::top("toolbar").show(ui, |ui| self.toolbar(ui));
        egui::Panel::bottom("status").show(ui, |ui| self.status_bar(ui));
        let mut action = None;
        if self.tab != Tab::Ports {
            if let Some(h) = self.selected_host() {
                let is_new = self.new_ips.contains(&h.ip);
                egui::Panel::right("details").resizable(true).default_size(340.0).min_size(260.0).show(ui, |ui| {
                    action = detail_panel(ui, h, is_new);
                });
            }
        }
        egui::CentralPanel::default().show(ui, |ui| {
            let a = match self.tab {
                Tab::Hosts => self.hosts_view(ui),
                Tab::Map => map::show(ui, self.ip.as_ref(), self.selected),
                Tab::Ports => self.ports_view(ui),
            };
            action = a.or(action.take());
        });
        match action {
            Some(Action::ScanPorts(ip, ports)) if self.job.is_none() => {
                self.target = ip.to_string();
                self.ports = ports.to_string();
                self.tab = Tab::Ports;
                self.start_ports(ui.ctx());
            }
            // clicking the selected host again closes the details
            Some(Action::Select(ip)) => self.selected = (self.selected != Some(ip)).then_some(ip),
            Some(Action::Notice(text, error)) => self.message = Some((text, error)),
            _ => {}
        }
    }
}

/// Semicolon-separated with BOM: Excel in German-speaking locales opens it with umlauts and columns intact.
fn csv(rows: &[Vec<String>]) -> String {
    let field = |f: &str| {
        let f = defuse(f);
        if f.contains([';', '"', '\n', '\r']) { format!("\"{}\"", f.replace('"', "\"\"")) } else { f }
    };
    let mut out = String::from('\u{FEFF}');
    for row in rows {
        out.push_str(&row.iter().map(|f| field(f)).collect::<Vec<_>>().join(";"));
        out.push_str("\r\n");
    }
    out
}

/// A leading = + - @ would run as a formula in Excel; device names, banners and web titles are untrusted.
fn defuse(f: &str) -> String {
    if f.starts_with(['=', '+', '-', '@']) { format!("'{f}") } else { f.to_string() }
}

/// One tab-separated line for the clipboard, safe to paste into Excel.
fn tsv_row<S: AsRef<str>>(cells: &[S]) -> String {
    cells.iter().map(|c| defuse(&c.as_ref().replace(['\t', '\r', '\n'], " "))).collect::<Vec<_>>().join("\t")
}

fn shorten(text: &str, max: usize) -> String {
    if text.chars().count() <= max { text.to_string() } else { format!("{}…", text.chars().take(max - 1).collect::<String>()) }
}

fn stat(ui: &mut Ui, value: &str, label: &str, color: Option<Color32>) {
    egui::Frame::group(ui.style()).inner_margin(egui::Margin::symmetric(12, 6)).corner_radius(8.0).show(ui, |ui| {
        ui.horizontal(|ui| {
            let value = RichText::new(value).size(18.0).strong();
            ui.label(match color {
                Some(c) => value.color(c),
                None => value,
            });
            ui.label(RichText::new(label).weak());
        });
    });
}

fn cell(ui: &mut Ui, col: Col, h: &Host, is_new: bool) {
    match col {
        Col::Ip => {
            ui.label(RichText::new(h.ip.to_string()).monospace());
            if is_new {
                ui.label(RichText::new("NEU").small().strong().color(NEW_COLOR)).on_hover_text("Beim letzten Scan noch nicht da");
            }
        }
        Col::Kind => kind_chip(ui, h.kind),
        Col::Os if h.os_guessed() => {
            ui.label(RichText::new(format!("≈ {}", h.os.as_deref().unwrap_or(""))).weak())
                .on_hover_text("Nur aus der TTL geschätzt – das Gerät hat nichts über sich verraten");
        }
        Col::Mac => {
            ui.label(RichText::new(h.mac.as_deref().unwrap_or("–")).monospace());
        }
        _ => {
            ui.label(col.text(h));
        }
    }
}

pub fn kind_color(kind: Kind) -> Color32 {
    let [r, g, b] = kind.rgb();
    Color32::from_rgb(r, g, b)
}

fn kind_chip(ui: &mut Ui, kind: Kind) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 5.0, kind_color(kind));
    ui.label(kind.label());
}

pub fn ping_text(rtt: Option<u32>) -> String {
    match rtt {
        Some(0) => "<1 ms".into(),
        Some(ms) => format!("{ms} ms"),
        None => "–".into(),
    }
}

/// Every column, tab-separated: for the filter and "copy whole row".
fn row_text(h: &Host) -> String {
    Col::ALL.iter().map(|c| c.text(h)).collect::<Vec<_>>().join("\t")
}

fn sort_header(ui: &mut Ui, col: Col, sort: &mut (Col, bool)) {
    let active = sort.0 == col;
    let text = if active { format!("{} {}", col.label(), if sort.1 { "▲" } else { "▼" }) } else { col.label().to_string() };
    if ui.add(egui::Button::new(RichText::new(text).strong()).frame(false)).clicked() {
        *sort = (col, !active || !sort.1);
    }
}

/// Context menu for a host, shared by the table and the map.
pub fn host_menu(ui: &mut Ui, h: &Host) -> Option<Action> {
    ui.label(RichText::new(h.name.as_deref().unwrap_or(&h.ip.to_string())).strong());
    let (action, clicked) = host_actions(ui, h);
    if clicked {
        ui.close();
    }
    action
}

/// Click, hover card and context menu for a host drawn on the map.
pub fn host_interact(response: egui::Response, h: &Host, action: &mut Option<Action>) {
    if response.clicked() {
        *action = Some(Action::Select(h.ip));
    }
    response.on_hover_ui(|ui| host_tooltip(ui, h)).context_menu(|ui| {
        if let Some(a) = host_menu(ui, h) {
            *action = Some(a);
        }
    });
}

/// The technician's toolbox for one host; returns the app-level action and whether anything was clicked.
fn host_actions(ui: &mut Ui, h: &Host) -> (Option<Action>, bool) {
    let has = |p: u16| h.services.contains(&p);
    let mut action = None;
    let mut clicked = false;
    let mut item = |ui: &mut Ui, enabled: bool, label: &str, hint: &str| {
        let hit = ui.add_enabled(enabled, egui::Button::new(label)).on_disabled_hover_text(hint).clicked();
        clicked |= hit;
        hit
    };

    if item(ui, true, "Ports scannen (Top 62)", "") {
        action = Some(Action::ScanPorts(h.ip, ""));
    }
    if item(ui, true, "Alle Ports scannen", "") {
        action = Some(Action::ScanPorts(h.ip, "all"));
    }
    ui.separator();
    let web = [80, 8080, 8000, 8081, 5000].into_iter().find(|p| has(*p));
    let secure = [443, 8443, 4443, 9443, 8006].into_iter().find(|p| has(*p));
    if item(ui, web.is_some(), "Web-Oberfläche (HTTP)", "Kein HTTP-Port gefunden") {
        open_port(h.ip, web.unwrap_or(80));
    }
    if item(ui, secure.is_some(), "Web-Oberfläche (HTTPS)", "Kein HTTPS-Port gefunden") {
        open_port(h.ip, secure.unwrap_or(443));
    }
    if item(ui, has(3389), "Remotedesktop (RDP)", "Port 3389 ist zu") {
        open_port(h.ip, 3389);
    }
    if item(ui, has(22), "SSH-Sitzung", "Port 22 ist zu") {
        open_port(h.ip, 22);
    }
    if item(ui, has(5900), "Bildschirmfreigabe (VNC)", "Port 5900 ist zu") {
        open_port(h.ip, 5900);
    }
    if item(ui, has(445), "Freigaben öffnen", "Port 445 ist zu") {
        open_port(h.ip, 445);
    }
    if item(ui, has(445), "Admin-Freigabe C$", "Port 445 ist zu") {
        platform::open(&platform::share(h.ip, "C$"));
    }
    ui.separator();
    if item(ui, true, "Dauerping", "") {
        platform::ping_forever(h.ip);
    }
    if item(ui, true, "Traceroute", "") {
        platform::traceroute(h.ip);
    }
    if item(ui, h.mac.is_some(), "Wake-on-LAN senden", "MAC-Adresse unbekannt") {
        let mac = h.mac.as_deref().unwrap_or("");
        action = Some(match scan::wake_on_lan(mac, h.ip) {
            Ok(()) => Action::Notice(format!("Wake-on-LAN an {mac} gesendet"), false),
            Err(e) => Action::Notice(format!("Wake-on-LAN fehlgeschlagen: {e}"), true),
        });
    }
    ui.separator();
    ui.menu_button("Kopieren", |ui| {
        let values = [
            ("IP-Adresse", Some(h.ip.to_string())),
            ("Hostname", h.name.clone()),
            ("MAC-Adresse", h.mac.clone()),
            ("Ganze Zeile", Some(row_text(h))),
        ];
        for (label, value) in values {
            if ui.add_enabled(value.is_some(), egui::Button::new(label)).clicked() {
                ui.ctx().copy_text(value.unwrap_or_default());
                action = Some(Action::Notice(format!("{label} kopiert"), false));
                clicked = true;
                ui.close();
            }
        }
    });
    (action, clicked)
}

/// Right-hand panel with everything known about the selected host.
fn detail_panel(ui: &mut Ui, h: &Host, is_new: bool) -> Option<Action> {
    let mut action = None;
    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.heading(h.name.as_deref().unwrap_or(&h.ip.to_string()));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("✕").on_hover_text("Schliessen (Esc)").clicked() {
                    action = Some(Action::Select(h.ip));
                }
            });
        });
        ui.horizontal(|ui| {
            kind_chip(ui, h.kind);
            if is_new {
                ui.label(RichText::new("NEU seit letztem Scan").small().strong().color(NEW_COLOR));
            }
        });
        ui.add_space(4.0);
        let os = h.os.clone().map(|os| match h.os_source {
            Some("TTL") => format!("≈ {os} (nur TTL)"),
            Some(source) => format!("{os}  · via {source}"),
            None => os,
        });
        let lines = [
            ("IP-Adresse", Some(h.ip.to_string())),
            ("Hostname", h.name.clone()),
            ("Betriebssystem", os),
            ("Hersteller", h.vendor.clone()),
            ("Modell", h.model.clone()),
            ("Domäne", h.domain.clone()),
            ("MAC-Adresse", h.mac.clone()),
            ("Ping", Some(ping_text(h.rtt_ms))),
            ("TTL", h.ttl.map(|t| t.to_string())),
        ];
        egui::Grid::new(("detail", h.ip)).num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
            for (label, value) in lines {
                if let Some(value) = value {
                    ui.label(RichText::new(label).weak());
                    // click copies: faster than selecting text with the mouse
                    if ui.add(egui::Label::new(&value).sense(egui::Sense::click())).on_hover_text("Klicken zum Kopieren").clicked() {
                        ui.ctx().copy_text(value);
                        action = Some(Action::Notice(format!("{label} kopiert"), false));
                    }
                    ui.end_row();
                }
            }
        });

        ui.add_space(8.0);
        ui.strong("Offene Ports");
        if h.services.is_empty() {
            ui.label(RichText::new("Keine bekannten Dienste gefunden – «Alle Ports scannen» prüft alle 65 535.").weak());
        }
        ui.horizontal_wrapped(|ui| {
            for &port in &h.services {
                let action = port_action(port);
                let hover = action.map_or(parse::describe(port), |a| format!("{} – {a}", parse::describe(port)));
                let button = ui.add_enabled(action.is_some(), egui::Button::new(format!("{port} {}", parse::service_name(port))));
                if button.on_hover_text(&hover).on_disabled_hover_text(&hover).clicked() {
                    open_port(h.ip, port);
                }
            }
        });

        if !h.details.is_empty() {
            ui.add_space(8.0);
            ui.strong("Erkennung");
            for line in &h.details {
                ui.label(RichText::new(line).small());
            }
        }

        ui.add_space(8.0);
        ui.strong("Aktionen");
        let (a, _) = host_actions(ui, h);
        action = a.or(action.take());
    });
    action
}

/// What opening this port does, for buttons and tooltips.
fn port_action(port: u16) -> Option<&'static str> {
    Some(match port {
        22 => "SSH-Sitzung",
        3389 => "Remotedesktop",
        139 | 445 => "Freigaben öffnen",
        548 => "Apple-Freigabe öffnen",
        5900 => "VNC öffnen",
        21 => "FTP öffnen",
        // these speak their own protocol; a browser would only show an error
        23 | 25 | 53 | 88 | 110 | 135 | 143 | 389 | 465 | 515 | 554 | 587 | 636 | 902 | 993 | 995 | 1433 | 1521 | 2049
        | 3268 | 3306 | 5357 | 5432 | 5985 | 5986 | 6379 | 9100 | 27017 | 62078 => return None,
        _ => "Im Browser öffnen",
    })
}

fn open_port(ip: Ipv4Addr, port: u16) {
    match port {
        22 => platform::ssh(ip),
        3389 => platform::remote_desktop(ip),
        139 | 445 => platform::open(&platform::share(ip, "")),
        548 => platform::open(&format!("afp://{ip}")),
        5900 => platform::open(&format!("vnc://{ip}")),
        21 => platform::open(&format!("ftp://{ip}")),
        80 => platform::open(&format!("http://{ip}")),
        443 => platform::open(&format!("https://{ip}")),
        p if p == 8006 || matches!(parse::service_name(p), "https" | "https-alt" | "winrm-https") => {
            platform::open(&format!("https://{ip}:{p}"))
        }
        p => platform::open(&format!("http://{ip}:{p}")),
    }
}

/// Hover card for a host, shared by the map views.
pub fn host_tooltip(ui: &mut Ui, h: &Host) {
    ui.set_max_width(460.0);
    ui.strong(match &h.name {
        Some(name) => format!("{name}  ({})", h.ip),
        None => h.ip.to_string(),
    });
    ui.horizontal(|ui| kind_chip(ui, h.kind));
    let os = h.os.clone().map(|os| if h.os_guessed() { format!("≈ {os} (nur TTL)") } else { os });
    let lines = [
        ("Betriebssystem", os),
        ("Hersteller", h.vendor.clone()),
        ("Modell", h.model.clone()),
        ("Domäne", h.domain.clone()),
        ("Ping", Some(ping_text(h.rtt_ms))),
        ("MAC", h.mac.clone()),
        ("Dienste", Some(parse::services_text(&h.services)).filter(|s| !s.is_empty())),
    ];
    egui::Grid::new(("tip", h.ip)).num_columns(2).spacing([10.0, 2.0]).show(ui, |ui| {
        for (label, value) in lines {
            if let Some(value) = value {
                ui.label(RichText::new(label).weak());
                ui.label(value);
                ui.end_row();
            }
        }
    });
    ui.label(RichText::new("Klick: Details · Rechtsklick: Aktionen").weak().small());
}

pub fn empty_state(ui: &mut Ui, title: &str, hint: &str) {
    ui.vertical_centered(|ui| {
        ui.add_space(ui.available_height() / 3.0);
        ui.heading(title);
        ui.label(RichText::new(hint).weak());
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_is_excel_safe() {
        let rows = vec![
            vec!["IP".to_string(), "Name".to_string()],
            vec!["10.0.0.1".to_string(), "a;b \"x\"".to_string()],
            vec!["10.0.0.2".to_string(), "=HYPERLINK(1)".to_string()],
        ];
        assert_eq!(csv(&rows), "\u{FEFF}IP;Name\r\n10.0.0.1;\"a;b \"\"x\"\"\"\r\n10.0.0.2;'=HYPERLINK(1)\r\n");
        // clipboard: a banner must neither run as a formula nor break the row
        assert_eq!(tsv_row(&["10.0.0.2", "=cmd|x\tA\r\nB", "@SUM(1)"]), "10.0.0.2\t'=cmd|x A  B\t'@SUM(1)");
    }

    #[test]
    fn settings_round_trip_and_ignore_junk() {
        let mut app = App::new(vec![]);
        app.apply_settings("columns=Mac, Ip,Kaputt\nports=22,80\nunbekannt=1\n");
        assert_eq!(app.columns, vec![Col::Ip, Col::Mac], "kept in table order, unknown names dropped");
        assert_eq!(app.ports, "22,80");
        let mut other = App::new(vec![]);
        other.apply_settings(&app.settings_text());
        assert_eq!((&other.columns, &other.ports), (&app.columns, &app.ports));
        other.apply_settings("columns=");
        assert!(!other.columns.is_empty(), "an empty list keeps the current columns");
        app.recent = vec!["10.0.0.0/24".into(), "192.168.1.1-50".into()];
        other.apply_settings(&app.settings_text());
        assert_eq!(other.recent, app.recent);
    }

    #[test]
    fn compares_versions_by_number() {
        assert!(is_newer("v0.10.0", "0.9.3"));
        assert!(is_newer("1.0.0", "0.2.0"));
        assert!(!is_newer("v0.2.0", "0.2.0"));
        assert!(!is_newer("0.1.9", "0.2.0"));
    }
}
