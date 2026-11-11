//! MAC address → vendor, from the IEEE list embedded at build time (see build.rs) plus a short built-in list.

use std::collections::HashMap;
use std::sync::OnceLock;

pub const RANDOM: &str = "Zufällige MAC (Datenschutz)";

static IEEE: &str = include_str!(concat!(env!("OUT_DIR"), "/oui.tsv"));

/// Prefixes worth knowing even without the IEEE file: virtual machines and a few common devices.
const BUILTIN: &[(&str, &str)] = &[
    ("005056", "VMware (virtuelle Maschine)"),
    ("000C29", "VMware (virtuelle Maschine)"),
    ("000569", "VMware (virtuelle Maschine)"),
    ("001C14", "VMware (virtuelle Maschine)"),
    ("00155D", "Microsoft Hyper-V (virtuelle Maschine)"),
    ("080027", "VirtualBox (virtuelle Maschine)"),
    ("525400", "QEMU/KVM (virtuelle Maschine)"),
    ("B827EB", "Raspberry Pi"),
    ("DCA632", "Raspberry Pi"),
    ("E45F01", "Raspberry Pi"),
    ("001132", "Synology"),
];

fn table() -> &'static HashMap<&'static str, &'static str> {
    static TABLE: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    TABLE.get_or_init(|| IEEE.lines().filter_map(|l| l.split_once('\t')).collect())
}

/// `mac` as printed by the scanner: "AA-BB-CC-DD-EE-FF".
pub fn vendor(mac: &str) -> Option<String> {
    let bytes: Vec<u8> = mac.split('-').filter_map(|h| u8::from_str_radix(h, 16).ok()).collect();
    if bytes.len() != 6 {
        return None;
    }
    let prefix = format!("{:02X}{:02X}{:02X}", bytes[0], bytes[1], bytes[2]);
    if let Some((_, name)) = BUILTIN.iter().find(|(p, _)| *p == prefix) {
        return Some((*name).to_string());
    }
    // locally administered bit: phones and laptops randomise their MAC per network
    if bytes[0] & 0x02 != 0 {
        return Some(RANDOM.to_string());
    }
    table().get(prefix.as_str()).map(|v| v.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_random_and_unknown() {
        assert_eq!(vendor("00-50-56-AB-CD-EF").as_deref(), Some("VMware (virtuelle Maschine)"));
        assert_eq!(vendor("52-54-00-12-34-56").as_deref(), Some("QEMU/KVM (virtuelle Maschine)"));
        assert_eq!(vendor("DA-11-22-33-44-55").as_deref(), Some(RANDOM));
        assert_eq!(vendor("kaputt"), None);
    }

    /// Release builds must carry the full IEEE list (data/oui.csv is in the repo).
    #[test]
    fn ieee_list_is_built_in() {
        assert!(table().len() > 30_000, "data/oui.csv fehlt oder ist unvollstaendig");
        assert_eq!(vendor("28-6F-B9-00-00-01").as_deref(), Some("Nokia Shanghai Bell Co., Ltd."));
    }
}
