//! Turns the IEEE vendor list (data/oui.csv, optional) into a compact "AABBCC<TAB>Vendor" table.

use std::{env, fs, path::Path};

fn main() {
    println!("cargo:rerun-if-changed=data/oui.csv");
    let out = Path::new(&env::var("OUT_DIR").expect("set by cargo")).join("oui.tsv");
    let tsv = match fs::read_to_string("data/oui.csv") {
        Ok(csv) => convert(&csv),
        Err(_) => {
            println!("cargo:warning=data/oui.csv fehlt - Hersteller nur aus Geraetedaten und der eingebauten Kurzliste");
            String::new()
        }
    };
    fs::write(out, tsv).expect("OUT_DIR is writable");

    // icon for Explorer, start menu and taskbar; the window icon itself comes from assets/icon.png
    #[cfg(windows)]
    {
        println!("cargo:rerun-if-changed=assets/icon.ico");
        winresource::WindowsResource::new().set_icon("assets/icon.ico").compile().expect("Windows-Ressource (Icon) nicht kompiliert");
    }
}

/// IEEE format: Registry,Assignment,Organization Name,Organization Address (quoted where needed).
fn convert(csv: &str) -> String {
    let mut out = String::new();
    for line in csv.lines().skip(1) {
        let fields = split_csv(line);
        if let (Some(prefix), Some(name)) = (fields.get(1), fields.get(2)) {
            if prefix.len() == 6 && prefix.chars().all(|c| c.is_ascii_hexdigit()) && !name.trim().is_empty() {
                out.push_str(&format!("{}\t{}\n", prefix.to_ascii_uppercase(), name.trim()));
            }
        }
    }
    out
}

fn split_csv(line: &str) -> Vec<String> {
    let (mut fields, mut field, mut quoted) = (Vec::new(), String::new(), false);
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(std::mem::take(&mut field)),
            _ => field.push(c),
        }
    }
    fields.push(field);
    fields
}
