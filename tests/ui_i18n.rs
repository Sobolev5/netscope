//! The embedded dashboard's dictionaries: RU and EN must have the same keys, every
//! `t("…")` call must resolve, and every enum value the backend serializes must have a
//! label in both languages.

use std::collections::BTreeSet;

use netscope::analytics::flows::FlowState;
use netscope::analytics::AlertKind;
use netscope::web::INDEX_HTML;

/// Keys (`name: "`) inside the object literal that starts at `start`.
fn dict_keys(start: &str) -> BTreeSet<String> {
    let from = INDEX_HTML.find(start).unwrap_or_else(|| panic!("{start} not found"));
    let body = &INDEX_HTML[from + start.len()..];
    let end = body.find("\n  },").expect("dictionary end");
    let body = &body[..end];
    let mut keys = BTreeSet::new();
    let bytes = body.as_bytes();
    let mut i = 0;
    let mut in_str = false;
    while i < bytes.len() {
        let c = bytes[i];
        if in_str {
            if c == b'\\' {
                i += 1;
            } else if c == b'"' {
                in_str = false;
            }
        } else if c == b'"' {
            in_str = true;
        } else if c.is_ascii_lowercase() && (i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_')) {
            let s = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            if body[i..].starts_with(": \"") {
                keys.insert(body[s..i].to_string());
            }
            continue;
        }
        i += 1;
    }
    keys
}

fn serde_name<T: serde::Serialize>(v: T) -> String {
    serde_json::to_value(v).unwrap().as_str().unwrap().to_string()
}

#[test]
fn ru_and_en_have_the_same_keys() {
    let ru = dict_keys("  ru: {");
    let en = dict_keys("  en: {");
    assert!(ru.len() > 150, "parsed only {} keys", ru.len());
    let only_ru: Vec<_> = ru.difference(&en).collect();
    let only_en: Vec<_> = en.difference(&ru).collect();
    assert!(only_ru.is_empty() && only_en.is_empty(), "only in ru: {only_ru:?}; only in en: {only_en:?}");
}

#[test]
fn every_literal_translation_key_exists() {
    let en = dict_keys("  en: {");
    let mut missing = BTreeSet::new();
    for (i, _) in INDEX_HTML.match_indices("t(\"") {
        // Only the bare function `t(`, not `get(`, `set(`, `createElement(`...
        let prev = INDEX_HTML[..i].chars().next_back().unwrap_or(' ');
        if prev.is_ascii_alphanumeric() || prev == '_' || prev == '.' {
            continue;
        }
        let rest = &INDEX_HTML[i + 3..];
        let key: String = rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
        // `t("nav_" + k)` style keys are checked by the enum test below.
        if rest[key.len()..].starts_with('"') && !key.is_empty() && !rest[key.len() + 1..].trim_start().starts_with('+') && !en.contains(&key) {
            missing.insert(key);
        }
    }
    assert!(missing.is_empty(), "t() keys without a translation: {missing:?}");
}

#[test]
fn backend_enums_have_labels() {
    let en = dict_keys("  en: {");
    let ru = dict_keys("  ru: {");
    for k in AlertKind::ALL {
        let name = serde_name(k);
        for dict in [&en, &ru] {
            assert!(dict.contains(&format!("kind_{name}")), "kind_{name}");
            // Kinds whose text depends on a detail have one key per variant (checked below).
            if !matches!(name.as_str(), "suspicious_dns" | "suspicious_connection" | "port_scan") {
                assert!(dict.contains(&format!("alert_{name}")), "alert_{name}");
            }
        }
    }
    let variants = [
        "alert_dns_long_name",
        "alert_dns_long_label",
        "alert_dns_entropy",
        "alert_dns_rare_type",
        "alert_unsigned_process_risky",
        "alert_susp_remote_control",
        "alert_susp_smb",
        "alert_susp_mail",
        "alert_susp_unsigned_ip",
        "alert_port_scan_in",
        "alert_port_scan_out",
        "alert_network_change_on",
        "alert_network_change_off",
        "alert_egress_change_on",
        "alert_egress_change_off",
    ];
    for key in variants {
        assert!(en.contains(key) && ru.contains(key), "{key}");
    }
    for c in netscope::analytics::Category::ALL {
        let key = format!("cat_{}", c.name());
        assert!(en.contains(&key) && ru.contains(&key), "{key}");
    }
    for st in [FlowState::Opening, FlowState::Established, FlowState::Closing, FlowState::Closed, FlowState::Active] {
        let name = serde_name(st);
        assert!(en.contains(&format!("st_{name}")) && ru.contains(&format!("st_{name}")), "st_{name}");
    }
    for sig in ["signed", "unsigned", "invalid", "unknown"] {
        assert!(en.contains(&format!("sig_{sig}")), "sig_{sig}");
    }
    for nav in ["overview", "processes", "connections", "hosts", "map", "route", "dns", "sockets", "alerts"] {
        assert!(en.contains(&format!("nav_{nav}")) && ru.contains(&format!("nav_{nav}")), "nav_{nav}");
    }
}

#[test]
fn embedded_script_is_valid_javascript() {
    // Skipped where Node.js is not installed.
    let Ok(v) = std::process::Command::new("node").arg("--version").output() else { return };
    if !v.status.success() {
        return;
    }
    let start = INDEX_HTML.find("<script>\n").expect("inline script") + "<script>\n".len();
    let end = INDEX_HTML[start..].find("</script>").expect("script end") + start;
    let path = std::env::temp_dir().join(format!("netscope-ui-{}.js", std::process::id()));
    std::fs::write(&path, &INDEX_HTML[start..end]).unwrap();
    let out = std::process::Command::new("node").arg("--check").arg(&path).output().unwrap();
    std::fs::remove_file(&path).ok();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}
