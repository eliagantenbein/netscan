//! Graphical views of an IP scan: a topology (internet → gateway → device groups) and an address grid.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use eframe::egui::{self, vec2, Align2, Color32, FontId, Rect, RichText, Sense, Shape, Stroke, Ui};

use crate::scan::{Host, Kind};
use crate::{empty_state, host_interact, kind_color, Action, IpScan};

const GRID_COLS: u32 = 16;
const GRID_MAX_CELLS: u32 = 1024;
const TILE: egui::Vec2 = vec2(156.0, 50.0);
const CARD_MIN_WIDTH: f32 = 330.0;
/// Room on the left for the bus line that links the rows.
const GUTTER: f32 = 16.0;
const ROW_GAP: f32 = 22.0;

pub fn show(ui: &mut Ui, scan: Option<&IpScan>, selected: Option<Ipv4Addr>) -> Option<Action> {
    let Some(scan) = scan else {
        empty_state(ui, "Noch keine Karte", "Zuerst ein Netz scannen – die Karte entsteht aus dem IP-Scan.");
        return None;
    };
    let mode_id = egui::Id::unique("map_mode_grid");
    let mut grid = ui.data_mut(|d| d.get_persisted::<bool>(mode_id)).unwrap_or(false);
    ui.horizontal(|ui| {
        ui.selectable_value(&mut grid, false, "Topologie");
        ui.selectable_value(&mut grid, true, "Adressraster");
        ui.label(RichText::new("Klick: Details · Rechtsklick: Aktionen").weak());
    });
    ui.data_mut(|d| d.insert_persisted(mode_id, grid));
    ui.add_space(4.0);

    let mut action = None;
    egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
        if grid {
            ui.columns(2, |cols| {
                legend(&mut cols[0], scan);
                action = address_grid(&mut cols[1], scan);
            });
        } else {
            action = topology(ui, scan, selected);
        }
    });
    action
}

/// Groups in the order a technician reads a network: infrastructure first, then users, then the rest.
const GROUP_ORDER: [Kind; 12] = [
    Kind::Network, Kind::WindowsServer, Kind::LinuxServer, Kind::Hypervisor, Kind::Nas, Kind::ThisPc, Kind::WindowsClient,
    Kind::Apple, Kind::Mobile, Kind::Printer, Kind::Media, Kind::Unknown,
];

fn topology(ui: &mut Ui, scan: &IpScan, selected: Option<Ipv4Addr>) -> Option<Action> {
    let mut action = None;
    let visuals = ui.visuals().clone();
    // lines go below everything drawn afterwards: reserve their slot now, fill it at the end
    let lines_slot = ui.painter().add(Shape::Noop);
    let width = ui.available_width();

    // internet and gateway
    let (head, _) = ui.allocate_exact_size(vec2(width, 150.0), Sense::hover());
    let internet = Rect::from_center_size(egui::pos2(head.center().x, head.top() + 22.0), vec2(150.0, 34.0));
    ui.painter().rect_filled(internet, 17.0, visuals.faint_bg_color);
    ui.painter().rect_stroke(internet, 17.0, Stroke::new(1.0, visuals.weak_text_color()), egui::StrokeKind::Inside);
    ui.painter().text(internet.center(), Align2::CENTER_CENTER, "🌐  Internet", FontId::proportional(15.0), visuals.strong_text_color());

    let gateway = scan.gateway.and_then(|g| scan.hosts.iter().find(|h| h.ip == g));
    let router = Rect::from_center_size(egui::pos2(head.center().x, head.top() + 104.0), vec2(220.0, 58.0));
    match gateway {
        Some(g) => {
            let response = tile(ui, router, g, selected == Some(g.ip), true);
            host_interact(response, g, &mut action);
        }
        None => {
            ui.painter().rect_filled(router, 10.0, visuals.faint_bg_color);
            let label = scan.gateway.map_or("Gateway unbekannt".to_string(), |g| format!("📶  Gateway {g}"));
            ui.painter().text(router.center(), Align2::CENTER_CENTER, label, FontId::proportional(14.0), visuals.text_color());
        }
    }
    let mut lines = vec![Shape::line_segment([internet.center_bottom(), router.center_top()], Stroke::new(2.0, visuals.weak_text_color()))];

    // one card per device type in a grid; an orthogonal bus links the gateway to every card
    let groups: Vec<(Kind, Vec<&Host>)> = GROUP_ORDER
        .into_iter()
        .map(|k| (k, scan.hosts.iter().filter(|h| h.kind == k && Some(h.ip) != scan.gateway).collect::<Vec<_>>()))
        .filter(|(_, hosts)| !hosts.is_empty())
        .collect();
    let trunk_x = head.left() + 6.0;
    let cards_left = head.left() + GUTTER;
    let gap = 14.0;
    let per_row = (((width - GUTTER + gap) / (CARD_MIN_WIDTH + gap)) as usize).clamp(1, 4);
    let card_w = ((width - GUTTER - gap * (per_row - 1) as f32) / per_row as f32).floor();
    let bus = Stroke::new(2.0, visuals.weak_text_color().gamma_multiply(0.6));
    let mut first_bus = None;
    let mut last_bus = 0.0;
    for row in groups.chunks(per_row) {
        ui.add_space(ROW_GAP);
        let top = ui.cursor().top();
        let bus_y = top - ROW_GAP / 2.0;
        first_bus.get_or_insert(bus_y);
        last_bus = bus_y;
        let mut bottom = top;
        let mut right_most = trunk_x;
        for (i, (kind, hosts)) in row.iter().enumerate() {
            let rect = Rect::from_min_size(egui::pos2(cards_left + i as f32 * (card_w + gap), top), vec2(card_w, 0.0));
            // a child that does not move the parent's cursor: the row reserves its height once below
            let builder = egui::UiBuilder::new().max_rect(rect.with_max_y(top + 1e5)).layout(egui::Layout::top_down(egui::Align::Min));
            let mut child = ui.new_child(builder);
            card(&mut child, *kind, hosts, card_w, selected, &mut action);
            let used = child.min_rect();
            bottom = bottom.max(used.bottom());
            right_most = right_most.max(used.center().x);
            lines.push(Shape::line_segment([egui::pos2(used.center().x, bus_y), used.center_top()], Stroke::new(2.0, kind_color(*kind).gamma_multiply(0.8))));
        }
        lines.push(Shape::line_segment([egui::pos2(trunk_x, bus_y), egui::pos2(right_most, bus_y)], bus));
        // reserve the row's height in the scroll area
        ui.allocate_exact_size(vec2(width, bottom - top), Sense::hover());
    }
    if let Some(first) = first_bus {
        // gateway straight down to the first bus, then along the left edge to every row
        lines.push(Shape::line_segment([router.center_bottom(), egui::pos2(router.center().x, first)], bus));
        lines.push(Shape::line_segment([egui::pos2(trunk_x, first), egui::pos2(trunk_x, last_bus)], bus));
    }
    ui.add_space(ROW_GAP);
    ui.painter().set(lines_slot, Shape::Vec(lines));
    action
}

fn card(ui: &mut Ui, kind: Kind, hosts: &[&Host], width: f32, selected: Option<Ipv4Addr>, action: &mut Option<Action>) {
    let color = kind_color(kind);
    let stroke = 1.5;
    let margin = 10.0;
    egui::Frame::new()
        .fill(ui.visuals().panel_fill)
        .stroke(Stroke::new(stroke, color.gamma_multiply(0.7)))
        .corner_radius(12.0)
        .inner_margin(margin)
        .show(ui, |ui| {
            ui.set_width(width - 2.0 * (margin + stroke));
            ui.horizontal(|ui| {
                ui.label(RichText::new(kind.icon()).size(18.0).color(color));
                ui.label(RichText::new(kind.label()).strong().size(15.0));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(hosts.len().to_string()).strong().size(15.0).color(color));
                });
            });
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = vec2(6.0, 6.0);
                for h in hosts {
                    let (rect, _) = ui.allocate_exact_size(TILE, Sense::hover());
                    let response = tile(ui, rect, h, selected == Some(h.ip), false);
                    host_interact(response, h, action);
                }
            });
        });
}

/// One device: accent bar in its type color, symbol, name and address, latency dot.
fn tile(ui: &mut Ui, rect: Rect, h: &Host, selected: bool, big: bool) -> egui::Response {
    let response = ui.interact(rect, ui.scope_id().with(("tile", h.ip)), Sense::click());
    let visuals = ui.visuals();
    let color = kind_color(h.kind);
    let fill = if selected {
        color.gamma_multiply(0.35)
    } else if response.hovered() {
        visuals.widgets.hovered.bg_fill
    } else {
        visuals.faint_bg_color
    };
    let painter = ui.painter();
    painter.rect_filled(rect, 8.0, fill);
    if selected || h.kind == Kind::ThisPc {
        painter.rect_stroke(rect, 8.0, Stroke::new(2.0, color), egui::StrokeKind::Inside);
    }
    painter.rect_filled(Rect::from_min_size(rect.min, vec2(4.0, rect.height())), egui::CornerRadius { nw: 8, sw: 8, ne: 0, se: 0 }, color);

    let icon_size = if big { 24.0 } else { 18.0 };
    painter.text(egui::pos2(rect.left() + 20.0, rect.center().y), Align2::CENTER_CENTER, h.kind.icon(), FontId::proportional(icon_size), color);
    let text_left = rect.left() + if big { 40.0 } else { 34.0 };
    let max_w = rect.right() - text_left - 14.0;
    let name = h.name.as_deref().map(|n| n.split('.').next().unwrap_or(n).to_string());
    let title = name.unwrap_or_else(|| h.ip.to_string());
    let title_font = FontId::proportional(if big { 15.0 } else { 13.0 });
    painter.text(
        egui::pos2(text_left, rect.center().y - 1.0),
        Align2::LEFT_BOTTOM,
        fit(ui, &title, &title_font, max_w),
        title_font,
        visuals.strong_text_color(),
    );
    // named devices show their address underneath; unnamed ones already show it as title
    let sub = if h.name.is_some() { h.ip.to_string() } else { short_os(h) };
    let sub_font = FontId::proportional(11.0);
    painter.text(egui::pos2(text_left, rect.center().y + 2.0), Align2::LEFT_TOP, fit(ui, &sub, &sub_font, max_w), sub_font, visuals.weak_text_color());
    painter.circle_filled(egui::pos2(rect.right() - 8.0, rect.top() + 8.0), 3.5, latency_color(h));
    response
}

fn short_os(h: &Host) -> String {
    match (&h.os, h.os_guessed()) {
        (Some(os), false) => os.clone(),
        (Some(os), true) => format!("≈ {os}"),
        (None, _) => String::new(),
    }
}

/// `text` cut with "…" so it fits `max` points in `font`.
fn fit(ui: &Ui, text: &str, font: &FontId, max: f32) -> String {
    let width = |t: &str| ui.ctx().fonts_mut(|f| f.layout_no_wrap(t.to_string(), font.clone(), Color32::WHITE).size().x);
    if width(text) <= max {
        return text.to_string();
    }
    let mut chars: Vec<char> = text.chars().collect();
    while !chars.is_empty() && width(&format!("{}…", chars.iter().collect::<String>())) > max {
        chars.pop();
    }
    format!("{}…", chars.into_iter().collect::<String>())
}

fn legend(ui: &mut Ui, scan: &IpScan) {
    ui.strong("Gerätetypen");
    ui.add_space(2.0);
    for kind in Kind::ALL {
        let count = scan.hosts.iter().filter(|h| h.kind == kind).count();
        if count == 0 {
            continue;
        }
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(vec2(12.0, 12.0), Sense::hover());
            ui.painter().circle_filled(rect.center(), 6.0, kind_color(kind));
            ui.label(kind.label());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(RichText::new(count.to_string()).strong());
            });
        });
    }
    let silent = scan.hosts.iter().filter(|h| h.rtt_ms.is_none()).count();
    if silent > 0 {
        ui.label(RichText::new(format!("{silent} Geräte antworten nicht auf Ping (über ARP/TCP gefunden)")).weak().small());
    }
}

fn latency_color(h: &Host) -> Color32 {
    match h.rtt_ms {
        Some(ms) if ms <= 10 => Color32::from_rgb(34, 197, 94),
        Some(ms) if ms <= 50 => Color32::from_rgb(132, 204, 22),
        Some(_) => Color32::from_rgb(234, 179, 8),
        None => Color32::from_rgb(59, 130, 246),
    }
}

/// One square per scanned address, aligned so each row starts at a multiple of 16.
fn address_grid(ui: &mut Ui, scan: &IpScan) -> Option<Action> {
    let (Some(first), Some(last)) = (scan.scanned.first(), scan.scanned.last()) else { return None };
    let base = u32::from(*first) & !(GRID_COLS - 1);
    let cells = (u32::from(*last) - base + 1).min(GRID_MAX_CELLS);
    let by_ip: HashMap<Ipv4Addr, &Host> = scan.hosts.iter().map(|h| (h.ip, h)).collect();

    ui.strong("Adressraster");
    ui.label(RichText::new("Grün = Ping < 10 ms · Gelb = langsam · Blau = nur ARP/TCP").weak().small());
    let label_w = 34.0;
    let cell = ((ui.available_width() - label_w) / GRID_COLS as f32).clamp(8.0, 18.0);
    let rows = cells.div_ceil(GRID_COLS);
    let (area, _) = ui.allocate_exact_size(vec2(label_w + cell * GRID_COLS as f32, cell * rows as f32), Sense::hover());
    let painter = ui.painter_at(area);
    let empty = ui.visuals().widgets.inactive.bg_fill;
    let mut action = None;

    for r in 0..rows {
        let y = area.top() + r as f32 * cell;
        let octet = (base + r * GRID_COLS) & 0xFF;
        painter.text(
            egui::pos2(area.left() + label_w - 6.0, y + cell / 2.0),
            Align2::RIGHT_CENTER,
            format!(".{octet}"),
            FontId::monospace(10.0),
            ui.visuals().weak_text_color(),
        );
    }
    for offset in 0..cells {
        let ip = Ipv4Addr::from(base + offset);
        if ip < *first || ip > *last {
            continue;
        }
        let (r, c) = (offset / GRID_COLS, offset % GRID_COLS);
        let min = egui::pos2(area.left() + label_w + c as f32 * cell, area.top() + r as f32 * cell);
        let rect = Rect::from_min_size(min, vec2(cell, cell)).shrink(1.0);
        let host = by_ip.get(&ip).copied();
        let response = ui.interact(rect, ui.scope_id().with(("cell", offset)), Sense::click());
        let mut color = host.map_or(empty, latency_color);
        if response.hovered() {
            color = color.gamma_multiply(1.3);
        }
        painter.rect_filled(rect, 2.0, color);
        match host {
            Some(h) => host_interact(response, h, &mut action),
            None => {
                response.on_hover_text(format!("{ip} – keine Antwort"));
            }
        }
    }
    if u32::from(*last) - base + 1 > GRID_MAX_CELLS {
        ui.label(RichText::new(format!("Raster zeigt die ersten {GRID_MAX_CELLS} Adressen.")).weak().small());
    }
    action
}
