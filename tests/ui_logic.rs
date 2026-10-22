//! The dashboard's JavaScript, run with Node.js when it is installed (skipped otherwise):
//! the pure filter and map-layout logic (`tests/js/ui_logic.test.js`), and every view
//! rendered from a real snapshot of the demo traffic (`tests/js/ui_render.test.js`).

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use netscope::web::INDEX_HTML;
use serde_json::{json, Value};

/// `node` when it runs; `None` (and a note in the test output) when it is not installed.
fn node() -> Option<&'static str> {
    match Command::new("node").arg("--version").output() {
        Ok(o) if o.status.success() => Some("node"),
        _ => {
            eprintln!("node not found: skipping the dashboard JavaScript tests");
            None
        }
    }
}

fn run(script: &Path, args: &[&Path]) {
    let out = Command::new("node").arg(script).args(args).output().expect("node runs");
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    println!("{text}");
    assert!(out.status.success(), "{} failed:\n{text}", script.display());
}

fn dir(name: &str) -> PathBuf {
    let d = common::temp_path(name);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The page's own script (the one `<script>` block without attributes).
fn page_script() -> &'static str {
    let start = INDEX_HTML.find("<script>\n").expect("page script") + "<script>\n".len();
    let end = start + INDEX_HTML[start..].find("</script>").expect("script end");
    &INDEX_HTML[start..end]
}

#[test]
fn pure_logic() {
    if node().is_none() {
        return;
    }
    let start = INDEX_HTML.find("// BEGIN PURE").expect("BEGIN PURE marker");
    let end = INDEX_HTML.find("// END PURE").expect("END PURE marker");
    let d = dir("ui-pure");
    let file = d.join("pure.test.js");
    std::fs::write(&file, format!("{}\n{}", &INDEX_HTML[start..end], include_str!("js/ui_logic.test.js"))).unwrap();
    run(&file, &[]);
    std::fs::remove_dir_all(&d).ok();
}

/// Places, providers and programs for the replayed hosts (a pcap replay has neither a
/// geolocation database nor a socket table): two hosts share a city, so the map clusters.
fn decorate(stats: &mut Value) -> String {
    let places = [
        ("DE", "Germany", "Германия", "Frankfurt am Main", 50.11, 8.68, "Hetzner Online GmbH"),
        ("DE", "Germany", "Германия", "Frankfurt am Main", 50.11, 8.68, "Akamai Technologies"),
        ("US", "United States", "США", "Ashburn", 39.04, -77.49, "Amazon.com, Inc."),
        ("NL", "Netherlands", "Нидерланды", "Amsterdam", 52.37, 4.9, "Google LLC"),
    ];
    let programs = [["chrome.exe"].as_slice(), &["svchost.exe", "chrome.exe"], &["updater.exe"], &[]];
    let mut countries: Vec<(String, String, String, usize, u64)> = Vec::new();
    let hosts = stats["hosts"].as_array_mut().unwrap();
    let mut placed = 0;
    for h in hosts.iter_mut().filter(|h| h["scope"] == "external") {
        let (code, name, name_ru, city, lat, lon, org) = places[placed % places.len()];
        h["geo"] = json!({ "country_code": code, "country": name, "country_ru": name_ru, "city": city, "region": null, "lat": lat, "lon": lon, "asn": 64500 + placed, "org": org, "anycast": placed % 3 == 2 });
        h["processes"] = json!(programs[placed % programs.len()]);
        let bytes = h["bytes_in"].as_u64().unwrap() + h["bytes_out"].as_u64().unwrap();
        match countries.iter_mut().find(|c| c.0 == code) {
            Some(c) => {
                c.3 += 1;
                c.4 += bytes;
            }
            None => countries.push((code.into(), name.into(), name_ru.into(), 1, bytes)),
        }
        placed += 1;
    }
    assert!(placed >= 4, "the demo replay has external hosts: {placed}");
    // Connections to those hosts are where the hosts are.
    let geo: std::collections::HashMap<String, Value> = hosts.iter().filter(|h| !h["geo"].is_null()).map(|h| (h["ip"].as_str().unwrap().to_string(), h["geo"].clone())).collect();
    for c in stats["connections"].as_array_mut().unwrap() {
        if let Some(g) = c["remote_ip"].as_str().and_then(|ip| geo.get(ip)) {
            c["geo"] = g.clone();
        }
    }
    stats["netpath"]["countries"] = json!(countries.iter().map(|c| json!({ "code": c.0, "name": c.1, "name_ru": c.2, "hosts": c.3, "bytes": c.4 })).collect::<Vec<_>>());
    stats["netpath"]["geo"] = json!({ "city": true, "asn": true, "dir": "test" });
    // Two programs as the socket table would report them.
    let proc = |pid: u32, name: &str, path: &str, status: Option<&str>, temp: bool| {
        json!({ "pid": pid, "name": name, "path": path, "parent": null, "parent_name": null, "bytes_in": 1000 * pid, "bytes_out": 10 * pid, "packets": 5,
            "connections_total": 3, "connections_active": 1, "first_us": 0, "last_us": stats["now"].as_i64().unwrap() * 1_000_000, "protocols": ["tls", "dns"],
            "top_remotes": ["example.org"], "signature": status.map(|s| json!({ "status": s, "signer": null })), "suspicious_path": temp, "ja4": [] })
    };
    stats["processes"]["processes"] = json!([
        proc(11, "chrome.exe", r"C:\Program Files\Google\Chrome\chrome.exe", Some("signed"), false),
        proc(12, "updater.exe", r"C:\Users\demo\AppData\Local\Temp\updater.exe", Some("unsigned"), true),
    ]);
    "DE".into()
}

#[test]
fn every_view_renders() {
    if node().is_none() {
        return;
    }
    let pcap = common::demo_pcap("ui-render.pcap", 25);
    let shared = common::replay(&pcap);
    std::fs::remove_file(&pcap).ok();
    let (mut stats, dns) = {
        let st = shared.read();
        (serde_json::to_value(st.snapshot(200, 200)).unwrap(), serde_json::to_value(st.dns(None, 500)).unwrap())
    };
    let country = decorate(&mut stats);
    let journal = json!({
        "kind": "connections", "total": 1, "facets": { "process": [["chrome.exe", 1]], "country": [["DE", 1]], "app": [["tls", 1]], "org": [], "dir": [["out", 1]], "reason": [["closed", 1]] },
        "records": [{ "ts": 1, "first_us": 1_000_000, "last_us": 2_000_000, "id": 1, "process": { "pid": 11, "name": "chrome.exe", "path": null }, "l4": "tcp", "app": "tls",
            "local": "192.168.1.50:5000", "remote": "203.0.113.9:443", "remote_ip": "203.0.113.9", "name": "example.org",
            "geo": { "country_code": "DE", "country": "Germany", "city": "Frankfurt am Main", "org": "Hetzner", "asn": 24940 },
            "bytes_in": 10, "bytes_out": 20, "packets_in": 1, "packets_out": 1, "state": "closed", "initiated": "local", "tls": null, "rtt_ms": null, "retrans": 0, "hops": null, "reason": "closed" }],
    });
    let sockets = json!({ "enabled": true, "error": null, "sockets": [
        { "proto": "tcp", "local": "0.0.0.0:445", "remote": null, "state": "LISTEN", "pid": 4, "process": "System", "current": false },
        { "proto": "tcp", "local": "127.0.0.1:8888", "remote": null, "state": "LISTEN", "pid": 11, "process": "netscope.exe", "current": false },
        { "proto": "udp", "local": "192.168.1.50:55123", "remote": null, "state": null, "pid": 11, "process": "chrome.exe", "current": false },
        { "proto": "tcp", "local": "192.168.1.50:5000", "remote": "203.0.113.9:443", "state": "ESTABLISHED", "pid": 11, "process": "chrome.exe", "current": false },
    ]});
    let fixture = json!({ "stats": stats, "dns": dns, "journal": journal, "sockets": sockets, "country": country });
    let d = dir("ui-render");
    let (page, fx, test) = (d.join("page.js"), d.join("fixture.json"), d.join("render.test.js"));
    std::fs::write(&page, page_script()).unwrap();
    std::fs::write(&fx, fixture.to_string()).unwrap();
    std::fs::write(&test, include_str!("js/ui_render.test.js")).unwrap();
    run(&test, &[&page, &fx]);
    std::fs::remove_dir_all(&d).ok();
}
