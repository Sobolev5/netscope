//! HTTP API, WebSocket streaming and graceful shutdown against a real server.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::Message;

use netscope::web;

/// Minimal HTTP/1.1 GET returning (status, body).
async fn get(addr: SocketAddr, path: &str) -> (u16, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, body.to_string())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_websocket_and_shutdown() {
    let path = common::demo_pcap("web.pcap", 15);
    let shared = tokio::task::spawn_blocking({
        let path = path.clone();
        move || common::replay(&path)
    })
    .await
    .unwrap();
    std::fs::remove_file(&path).ok();

    let listener = web::bind("127.0.0.1", 0).await.unwrap();
    let addr = web::local_addr(&listener).unwrap();
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(web::run(listener, shared.clone(), false, async move {
        let _ = stop_rx.await;
    }));

    let (status, html) = get(addr, "/").await;
    assert_eq!(status, 200);
    assert!(html.contains("<title>netscope</title>") && html.contains("/api/ws"));

    let (status, body) = get(addr, "/api/stats").await;
    assert_eq!(status, 200);
    let stats: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(stats["totals"]["packets"].as_u64().unwrap() > 1000);
    assert_eq!(stats["capture"]["status"]["state"], "finished");
    assert!(stats["hosts"].as_array().unwrap().len() <= 50);
    assert!(stats["alert_counts"]["total"].as_u64().unwrap() >= 3);

    let (_, body) = get(addr, "/api/stats?hosts=2&alerts=1").await;
    let small: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(small["hosts"].as_array().unwrap().len(), 2);
    assert_eq!(small["alerts"].as_array().unwrap().len(), 1);

    let (_, body) = get(addr, "/api/alerts").await;
    let alerts: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(alerts["counts"]["total"], stats["alert_counts"]["total"]);

    let (status, body) = get(addr, "/api/health").await;
    assert_eq!(status, 200);
    let health: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!((health["status"].as_str(), health["version"].as_str()), (Some("ok"), Some(env!("CARGO_PKG_VERSION"))));
    assert_eq!(stats["version"], env!("CARGO_PKG_VERSION"));
    let (open, total) = (stats["open_connections"].as_u64().unwrap(), stats["connection_count"].as_u64().unwrap());
    assert!(open > 0 && open < total, "some demo connections close: {open} of {total}");
    // Alerts about a host carry it; alerts about programs/routes carry null, never "".
    for a in stats["alerts"].as_array().unwrap() {
        assert!(a["host"].is_null() || !a["host"].as_str().unwrap().is_empty(), "{a}");
        if a["kind"] == "volume_spike" {
            assert!(a["details"]["rate"].as_str().unwrap().parse::<u64>().is_ok(), "{a}");
            assert!(a["details"]["baseline"].as_str().unwrap().parse::<u64>().is_ok(), "{a}");
        }
    }
    assert!(stats["alerts"].as_array().unwrap().iter().any(|a| a["kind"] == "volume_spike"));

    assert_eq!(get(addr, "/nope").await.0, 404);

    // WebSocket: an immediate snapshot, then the server must close it on shutdown.
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/api/ws")).await.unwrap();
    let first = tokio::time::timeout(Duration::from_secs(5), ws.next()).await.unwrap().unwrap().unwrap();
    let Message::Text(text) = first else { panic!("expected a text frame, got {first:?}") };
    let snap: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert!(snap["series"].as_array().unwrap().len() > 10);

    stop_tx.send(()).unwrap();
    let finished = tokio::time::timeout(Duration::from_secs(5), server).await;
    assert!(finished.is_ok(), "graceful shutdown hung with an open WebSocket");
    finished.unwrap().unwrap().unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(Ok(msg)) = ws.next().await {
            if msg.is_close() {
                break;
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "client never saw the close");
}

#[tokio::test]
async fn bind_errors_are_actionable() {
    let taken = web::bind("127.0.0.1", 0).await.unwrap();
    let port = web::local_addr(&taken).unwrap().port();
    let err = web::bind("127.0.0.1", port).await.unwrap_err().to_string();
    assert!(err.contains("already in use") && err.contains("--port"), "{err}");
    // Without an explicit port the next free one is taken instead of failing.
    let l = web::bind_default("127.0.0.1", None).await.unwrap();
    assert_ne!(web::local_addr(&l).unwrap().port(), port);
    assert!(web::bind_default("127.0.0.1", Some(port)).await.is_err(), "an explicit port is not negotiable");
    let err = web::bind("203.0.113.1", 0).await.unwrap_err().to_string();
    assert!(err.contains("--host") || err.contains("cannot listen"), "{err}");
}

/// Raw GET/POST/DELETE returning (status, headers, body bytes).
async fn request(addr: SocketAddr, method: &str, path: &str) -> (u16, String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await.unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, head, raw[split + 4..].to_vec())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn filters_dns_watch_and_exports() {
    let path = common::demo_pcap("web2.pcap", 15);
    let shared = tokio::task::spawn_blocking({
        let path = path.clone();
        move || common::replay(&path)
    })
    .await
    .unwrap();
    std::fs::remove_file(&path).ok();
    let listener = web::bind("127.0.0.1", 0).await.unwrap();
    let addr = web::local_addr(&listener).unwrap();
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(web::run(listener, shared, false, async move {
        let _ = stop_rx.await;
    }));
    let json = |b: &[u8]| serde_json::from_slice::<serde_json::Value>(b).unwrap();

    // Filters: a valid expression narrows the list, a broken one is a 400 with a position.
    let (st, _, all) = request(addr, "GET", "/api/connections?limit=5000").await;
    assert_eq!(st, 200);
    let total = json(&all)["total"].as_u64().unwrap();
    let (_, _, tls) = request(addr, "GET", "/api/connections?q=app%20%3D%3D%20tls&limit=5000").await;
    let tls = json(&tls);
    let n_tls = tls["total"].as_u64().unwrap();
    assert!(n_tls > 0 && n_tls < total, "{n_tls} of {total}");
    assert!(tls["connections"].as_array().unwrap().iter().all(|c| c["app"] == "tls"));
    let (st, _, err) = request(addr, "GET", "/api/connections?q=bytes%20%3E").await;
    assert_eq!(st, 400);
    let err = json(&err);
    assert!(err["error"]["message"].as_str().unwrap().contains("missing value"), "{err}");
    assert_eq!(err["error"]["position"], 7);
    let (_, _, fields) = request(addr, "GET", "/api/filter/fields").await;
    assert!(json(&fields).as_array().unwrap().iter().any(|f| f["name"] == "process"));

    // DNS journal of the demo traffic: queries joined with answers.
    let (_, _, dns) = request(addr, "GET", "/api/dns?q=github").await;
    let dns = json(&dns);
    let e = &dns["entries"][0];
    assert_eq!((e["name"].as_str(), e["rcode"].as_str()), (Some("github.com"), Some("NOERROR")));
    assert_eq!(e["answers"][0], "140.82.121.4");

    // Route watch: add, list, remove; removing twice is a 404.
    let (st, _, w) = request(addr, "POST", "/api/watch?ip=127.0.0.1&label=self").await;
    assert_eq!(st, 200);
    assert_eq!(json(&w)["targets"][0]["label"], "self");
    assert_eq!(request(addr, "DELETE", "/api/watch?ip=127.0.0.1").await.0, 200);
    let (st, head, body) = request(addr, "DELETE", "/api/watch?ip=127.0.0.1").await;
    assert_eq!(st, 404);
    assert!(head.to_lowercase().contains("content-type: application/json"), "{head}");
    assert_eq!(json(&body)["error"]["code"], "not_found");
    let (st, _, body) = request(addr, "POST", "/api/watch?ip=not-an-ip").await;
    assert_eq!((st, json(&body)["error"]["code"].as_str()), (400, Some("bad_request")));
    // Labels are cut to 64 characters; the 33rd target is refused with code "limit".
    let long = "x".repeat(100);
    let (st, _, w) = request(addr, "POST", &format!("/api/watch?ip=203.0.113.1&label={long}")).await;
    assert_eq!(st, 200);
    assert_eq!(json(&w)["targets"][0]["label"].as_str().unwrap().len(), 64);
    for i in 2..=32 {
        assert_eq!(request(addr, "POST", &format!("/api/watch?ip=203.0.113.{i}")).await.0, 200, "target {i}");
    }
    let (st, _, body) = request(addr, "POST", "/api/watch?ip=203.0.113.99").await;
    let err = json(&body);
    assert_eq!((st, err["error"]["code"].as_str()), (400, Some("limit")));
    assert!(err["error"]["message"].as_str().unwrap().contains("32"), "{err}");
    assert_eq!(request(addr, "POST", "/api/watch?ip=203.0.113.5&label=again").await.0, 200, "re-labelling is not an addition");
    for i in 1..=32 {
        request(addr, "DELETE", &format!("/api/watch?ip=203.0.113.{i}")).await;
    }

    // Everything non-2xx under /api is the JSON envelope, including axum's own rejections.
    for (path, code) in [("/api/nope", "not_found"), ("/api/connections/999999", "not_found"), ("/api/stats?hosts=abc", "bad_request"), ("/api/trace?ip=x", "bad_request")] {
        let (st, head, body) = request(addr, "GET", path).await;
        assert!((400..500).contains(&st), "{path}: {st}");
        assert!(head.to_lowercase().contains("content-type: application/json"), "{path}: {head}");
        let err = json(&body);
        assert_eq!(err["error"]["code"], code, "{path}: {err}");
        assert!(!err["error"]["message"].as_str().unwrap().is_empty(), "{path}");
    }
    let (st, _, body) = request(addr, "DELETE", "/api/stats").await;
    assert_eq!((st, json(&body)["error"]["code"].as_str()), (405, Some("bad_request")));

    // CSV exports are UTF-8 with a BOM and a download file name.
    let (st, head, csv) = request(addr, "GET", "/api/export/connections.csv?q=app%20%3D%3D%20tls").await;
    assert_eq!(st, 200);
    assert!(head.to_lowercase().contains("content-disposition: attachment; filename=\"netscope-connections-"), "{head}");
    let text = String::from_utf8(csv).unwrap();
    assert!(text.starts_with("\u{feff}id,first_seen_utc"));
    assert_eq!(text.lines().count() as u64, n_tls + 1, "header + one row per matching connection");
    // A replayed file has no process attribution: processes.csv is just the header.
    for (p, min_lines) in [("/api/export/hosts.csv", 2), ("/api/export/processes.csv", 1), ("/api/export/dns.csv", 2)] {
        let (st, _, b) = request(addr, "GET", p).await;
        assert_eq!(st, 200, "{p}");
        assert!(String::from_utf8(b).unwrap().lines().count() >= min_lines, "{p}");
    }

    // pcap exports are valid capture files our own reader understands.
    let (st, _, pcap) = request(addr, "GET", "/api/export/connections.pcap?q=name%20~%20example.org").await;
    assert_eq!(st, 200);
    assert_eq!(&pcap[..4], &0xA1B2_C3D4u32.to_le_bytes());
    let tmp = common::temp_path("export.pcap");
    std::fs::write(&tmp, &pcap).unwrap();
    let mut f = netscope::capture::file::PcapFile::open(&tmp).unwrap();
    let mut frames = 0;
    while let netscope::capture::Next::Packet(_) = netscope::capture::PacketSource::next_packet(&mut f).unwrap() {
        frames += 1;
    }
    std::fs::remove_file(&tmp).ok();
    assert!(frames > 3, "{frames} frames");
    let first_id = json(&all)["connections"][0]["id"].as_u64().unwrap();
    assert_eq!(request(addr, "GET", &format!("/api/connections/{first_id}/pcap")).await.0, 200);
    assert_eq!(request(addr, "GET", "/api/connections/999999/pcap").await.0, 404);

    // The map outlines are served locally.
    let (st, head, land) = request(addr, "GET", "/static/land-110m.json").await;
    assert_eq!(st, 200);
    assert!(head.to_lowercase().contains("application/json"));
    assert!(json(&land)["objects"]["land"].is_object());

    stop_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap().unwrap();
}

async fn raw(addr: SocketAddr, head: &str) -> u16 {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(head.as_bytes()).await.unwrap();
    // Only the status line: a refused WebSocket handshake may keep the connection open.
    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    while !out.windows(2).any(|w| w == b"\r\n") {
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await.unwrap().unwrap();
        assert!(n > 0, "connection closed before a status line");
        out.extend_from_slice(&buf[..n]);
    }
    String::from_utf8_lossy(&out).split(' ').nth(1).unwrap().parse().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn other_web_pages_cannot_use_the_api() {
    let path = common::demo_pcap("web3.pcap", 3);
    let shared = tokio::task::spawn_blocking({
        let path = path.clone();
        move || common::replay(&path)
    })
    .await
    .unwrap();
    std::fs::remove_file(&path).ok();
    let listener = web::bind("127.0.0.1", 0).await.unwrap();
    let addr = web::local_addr(&listener).unwrap();
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(web::run(listener, shared, false, async move {
        let _ = stop_rx.await;
    }));
    let get = |extra: &str| format!("GET /api/stats HTTP/1.1\r\n{extra}Connection: close\r\n\r\n");

    assert_eq!(raw(addr, &get("Host: 127.0.0.1:8888\r\n")).await, 200);
    assert_eq!(raw(addr, &get("Host: localhost\r\n")).await, 200);
    assert_eq!(raw(addr, &get("Host: [::1]:8888\r\n")).await, 200);
    // DNS rebinding: attacker.example resolved to 127.0.0.1.
    assert_eq!(raw(addr, &get("Host: attacker.example:8888\r\n")).await, 403);
    // A cross-site <img>/fetch from another page.
    assert_eq!(raw(addr, &get("Host: 127.0.0.1\r\nSec-Fetch-Site: cross-site\r\n")).await, 403);
    assert_eq!(raw(addr, &get("Host: 127.0.0.1\r\nSec-Fetch-Site: same-origin\r\n")).await, 200);
    // WebSocket handshake or POST from another origin.
    let ws = "GET /api/ws HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://evil.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    assert_eq!(raw(addr, ws).await, 403);
    assert_eq!(raw(addr, "POST /api/watch?ip=1.1.1.1 HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: null\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await, 403);
    assert_eq!(raw(addr, "POST /api/watch?ip=1.1.1.1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\nOrigin: http://127.0.0.1:1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await, 200);

    // A huge filter is rejected instead of exhausting the stack.
    let q = "a%20".repeat(1_500); // 1500 terms: past MAX_TOKENS, within the URI limit
    assert_eq!(raw(addr, &format!("GET /api/connections?q={q} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")).await, 400);

    stop_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap().unwrap();
}

/// Starts a server over `shared`; returns its address, the stop switch and the task.
async fn serve(shared: netscope::analytics::SharedState) -> (SocketAddr, oneshot::Sender<()>, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let listener = web::bind("127.0.0.1", 0).await.unwrap();
    let addr = web::local_addr(&listener).unwrap();
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(web::run(listener, shared, false, async move {
        let _ = stop_rx.await;
    }));
    (addr, stop_tx, server)
}

async fn replayed(name: &str, seconds: u32) -> netscope::analytics::SharedState {
    let path = common::demo_pcap(name, seconds);
    let shared = tokio::task::spawn_blocking({
        let path = path.clone();
        move || common::replay(&path)
    })
    .await
    .unwrap();
    std::fs::remove_file(&path).ok();
    shared
}

fn json(b: &[u8]) -> serde_json::Value {
    serde_json::from_slice(b).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(b)))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_api_error_is_a_json_envelope() {
    let shared = replayed("web-errors.pcap", 3).await;
    let (addr, stop_tx, server) = serve(shared).await;
    // (method, path, status, code, message fragment)
    let cases = [
        ("GET", "/api/zzz", 404, "not_found", ""),
        ("GET", "/api/connections/999999", 404, "not_found", "connection"),
        ("GET", "/api/connections/999999/stream", 404, "not_found", "connection"),
        ("GET", "/api/connections/999999/packets/1", 404, "not_found", "packet"),
        ("GET", "/api/connections/999999/pcap", 404, "not_found", "connection"),
        ("GET", "/api/connections/abc", 400, "bad_request", ""),
        ("GET", "/api/connections/1/packets/x", 400, "bad_request", ""),
        ("GET", "/api/connections/-1", 400, "bad_request", ""),
        ("GET", "/api/connections?pid=abc", 400, "bad_request", "pid"),
        ("GET", "/api/connections?limit=-5", 400, "bad_request", "limit"),
        ("GET", "/api/connections?q=bytes%20%3E", 400, "filter", "missing value"),
        ("GET", "/api/export/connections.csv?q=bytes%20%3E", 400, "filter", "missing value"),
        ("GET", "/api/export/connections.pcap?q=bytes%20==", 400, "filter", "missing value"),
        ("GET", "/api/connections?q=nope%20==%201", 400, "filter", "unknown field"),
        ("GET", "/api/stats?hosts=abc", 400, "bad_request", "hosts"),
        ("GET", "/api/stats?alerts=-1", 400, "bad_request", "alerts"),
        ("GET", "/api/dns?limit=x", 400, "bad_request", "limit"),
        ("GET", "/api/sockets?pid=x", 400, "bad_request", "pid"),
        ("GET", "/api/geo", 400, "bad_request", "ip"),
        ("GET", "/api/geo?ip=", 400, "bad_request", "IPv4 or IPv6"),
        ("GET", "/api/geo?ip=1.2.3", 400, "bad_request", "IPv4 or IPv6"),
        ("GET", "/api/geo?ip=example.org", 400, "bad_request", "IPv4 or IPv6"),
        ("GET", "/api/trace", 400, "bad_request", "ip"),
        ("GET", "/api/trace?ip=%20", 400, "bad_request", "IPv4 or IPv6"),
        ("GET", "/api/trace?ip=1.1.1.1&fresh=maybe", 400, "bad_request", "fresh"),
        ("POST", "/api/watch", 400, "bad_request", "ip"),
        ("POST", "/api/watch?ip=1.2.3.4.5", 400, "bad_request", "IPv4 or IPv6"),
        ("DELETE", "/api/watch?ip=x", 400, "bad_request", "IPv4 or IPv6"),
        ("DELETE", "/api/watch?ip=203.0.113.200", 404, "not_found", "watched route"),
        ("POST", "/api/stats", 405, "bad_request", ""),
        ("PUT", "/api/watch?ip=1.1.1.1", 405, "bad_request", ""),
        ("DELETE", "/api/connections", 405, "bad_request", ""),
        ("POST", "/api/export/hosts.csv", 405, "bad_request", ""),
    ];
    for (method, path, status, code, fragment) in cases {
        let (st, head, body) = request(addr, method, path).await;
        assert_eq!(st, status, "{method} {path}: {}", String::from_utf8_lossy(&body));
        let head = head.to_lowercase();
        assert!(head.contains("content-type: application/json"), "{method} {path}: {head}");
        assert!(head.contains("cache-control: no-store"), "{method} {path}: {head}");
        let err = json(&body);
        assert_eq!(err["error"]["code"], code, "{method} {path}: {err}");
        let message = err["error"]["message"].as_str().unwrap_or_else(|| panic!("{method} {path}: {err}"));
        assert!(!message.is_empty() && message.contains(fragment), "{method} {path}: {message:?} should mention {fragment:?}");
        if code == "filter" {
            assert!(err["error"]["position"].is_u64(), "{err}");
        } else {
            assert!(err["error"].get("position").is_none(), "{err}");
        }
    }
    // Oversized limits are clamped, not refused.
    let (st, _, body) = request(addr, "GET", "/api/stats?hosts=99999999&alerts=99999999").await;
    assert_eq!(st, 200);
    let stats = json(&body);
    assert!(stats["hosts"].as_array().unwrap().len() <= 1000 && stats["alerts"].as_array().unwrap().len() <= 1000);
    let (st, _, body) = request(addr, "GET", "/api/connections?limit=99999999").await;
    assert_eq!(st, 200);
    let c = json(&body);
    assert!(c["connections"].as_array().unwrap().len() <= 5000 && c["total"].as_u64().unwrap() > 0);
    let (st, _, body) = request(addr, "GET", "/api/connections?limit=0").await;
    assert_eq!((st, json(&body)["connections"].as_array().unwrap().len()), (200, 0));
    let (st, _, body) = request(addr, "GET", "/api/dns?limit=0&q=").await;
    assert_eq!(st, 200);
    assert_eq!(json(&body)["entries"].as_array().unwrap().len(), 0);
    // Valid lookups: the geo answer is null without databases, never an error.
    let (st, _, body) = request(addr, "GET", "/api/geo?ip=%208.8.8.8%20").await;
    let g = json(&body);
    assert_eq!((st, g["ip"].as_str()), (200, Some("8.8.8.8")), "{g}");
    assert!(g["geo"].is_null() && g["status"].is_null(), "no databases in a replayed state: {g}");
    let (st, _, body) = request(addr, "GET", "/api/geo?ip=%5B::1%5D").await;
    assert_eq!(st, 400, "brackets are not part of an address: {}", String::from_utf8_lossy(&body));
    let (st, _, body) = request(addr, "GET", "/api/geo?ip=::1").await;
    assert_eq!((st, json(&body)["ip"].as_str()), (200, Some("::1")));
    // Successful responses are JSON too, and non-API 404s are plain text.
    for path in ["/api/processes", "/api/sockets", "/api/netpath", "/api/watch", "/api/filter/fields", "/api/health"] {
        let (st, head, _) = request(addr, "GET", path).await;
        assert_eq!(st, 200, "{path}");
        assert!(head.to_lowercase().contains("content-type: application/json"), "{path}: {head}");
    }
    let (st, head, body) = request(addr, "GET", "/nope").await;
    assert_eq!((st, &body[..]), (404, &b"not found"[..]));
    assert!(!head.to_lowercase().contains("application/json"), "{head}");
    let (st, head, css) = request(addr, "GET", "/static/app.css").await;
    assert_eq!(st, 200);
    assert!(head.to_lowercase().contains("content-type: text/css"), "{head}");
    assert!(String::from_utf8(css).unwrap().starts_with("*,::before,::after{box-sizing:border-box"));
    stop_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_and_origin_guard_variants() {
    let shared = replayed("web-guard.pcap", 2).await;
    let (addr, stop_tx, server) = serve(shared).await;
    let get = |extra: &str| format!("GET /api/health HTTP/1.1\r\n{extra}Connection: close\r\n\r\n");
    // Host variants: loopback names in any case and with or without a port, IPv6 with brackets.
    for ok in ["Host: 127.0.0.1\r\n", "Host: LOCALHOST\r\n", "Host: Localhost:1\r\n", "Host: [::1]\r\n", "Host: [::1]:65535\r\n", "Host: [::1]:8888\r\n"] {
        assert_eq!(raw(addr, &get(ok)).await, 200, "{ok:?}");
    }
    for bad in [
        "Host: \r\n",
        "",
        "Host: 127.0.0.2\r\n",
        "Host: [::ffff:127.0.0.1]\r\n",
        "Host: localhost.\r\n",
        "Host: localhost.example\r\n",
        "Host: 127.0.0.1.evil.example\r\n",
        "Host: evil.example:8888\r\n",
        "Host: ::1\r\n",
        "Host: 0.0.0.0\r\n",
    ] {
        assert_eq!(raw(addr, &get(bad)).await, 403, "{bad:?}");
    }
    // Origin variants: scheme and port are ignored, the host must match the Host header exactly.
    for ok in [
        "Host: 127.0.0.1\r\nOrigin: http://127.0.0.1\r\n",
        "Host: 127.0.0.1:8888\r\nOrigin: HTTP://127.0.0.1:9999\r\n",
        "Host: 127.0.0.1\r\nOrigin: https://127.0.0.1/\r\n",
        "Host: [::1]:8888\r\nOrigin: http://[::1]:8888\r\n",
        "Host: localhost\r\nOrigin: http://LOCALHOST:8888\r\n",
        "Host: 127.0.0.1\r\nOrigin: 127.0.0.1\r\n",
        "Host: 127.0.0.1\r\nSec-Fetch-Site: same-site\r\n",
        "Host: 127.0.0.1\r\nSec-Fetch-Site: none\r\n",
    ] {
        assert_eq!(raw(addr, &get(ok)).await, 200, "{ok:?}");
    }
    for bad in [
        "Host: 127.0.0.1\r\nOrigin: http://localhost:8888\r\n",
        "Host: localhost\r\nOrigin: http://127.0.0.1\r\n",
        "Host: 127.0.0.1\r\nOrigin: null\r\n",
        "Host: 127.0.0.1\r\nOrigin: http://127.0.0.1.evil.example\r\n",
        "Host: 127.0.0.1\r\nSec-Fetch-Site: cross-site\r\n",
        "Host: 127.0.0.1\r\nSec-Fetch-Site: cross-site\r\nOrigin: http://127.0.0.1\r\n",
    ] {
        assert_eq!(raw(addr, &get(bad)).await, 403, "{bad:?}");
    }
    // The guard protects the page and the static files as well, not only /api.
    assert_eq!(raw(addr, "GET / HTTP/1.1\r\nHost: attacker.example\r\nConnection: close\r\n\r\n").await, 403);
    assert_eq!(raw(addr, "GET /static/app.css HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: cross-site\r\nConnection: close\r\n\r\n").await, 403);
    assert_eq!(raw(addr, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").await, 200);
    stop_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap().unwrap();
}

/// A capture whose names start like spreadsheet formulas: an HTTP Host header and DNS labels.
fn hostile_pcap(name: &str) -> std::path::PathBuf {
    use netscope::capture::file::PcapWriter;
    use netscope::decode::{dns, linktype};
    use netscope::demo::frames::{tcp_frame_seq, udp_frame, TcpFlags};
    let (me, srv, resolver) = ([10, 0, 0, 2], [93, 184, 215, 14], [10, 0, 0, 1]);
    let path = common::temp_path(name);
    let mut w = PcapWriter::create(&path, linktype::ETHERNET).unwrap();
    let t = common::START_US;
    w.write(t, &tcp_frame_seq(me, srv, 40000, 80, TcpFlags::Syn, 99, b"")).unwrap();
    w.write(t + 10, &tcp_frame_seq(srv, me, 80, 40000, TcpFlags::SynAck, 499, b"")).unwrap();
    w.write(t + 20, &tcp_frame_seq(me, srv, 40000, 80, TcpFlags::Data, 100, b"GET /x HTTP/1.1\r\nHost: =HYPERLINK(\"http://evil.example\")\r\n\r\n")).unwrap();
    w.write(t + 30, &udp_frame(me, resolver, 50000, 53, &dns::build_query(1, "-minus.example", dns::TYPE_A))).unwrap();
    w.write(t + 40, &udp_frame(me, resolver, 50001, 53, &dns::build_query(2, "@at.example", dns::TYPE_A))).unwrap();
    w.write(t + 50, &udp_frame(me, resolver, 50002, 53, &dns::build_query(3, "+plus.example", dns::TYPE_A))).unwrap();
    w.finish().unwrap();
    path
}

/// All frames of a pcap body as (timestamp, wire length, stored length), plus the link type.
fn frames_of(pcap: &[u8], name: &str) -> (i32, Vec<(i64, u32, usize)>) {
    use netscope::capture::{Next, PacketSource};
    let tmp = common::temp_path(name);
    std::fs::write(&tmp, pcap).unwrap();
    let mut f = netscope::capture::file::PcapFile::open(&tmp).unwrap();
    let lt = f.linktype();
    let mut out = Vec::new();
    while let Next::Packet(p) = f.next_packet().unwrap() {
        out.push((p.ts_us, p.wire_len, p.data.len()));
    }
    std::fs::remove_file(&tmp).ok();
    (lt, out)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exports_escape_formulas_and_pcaps_round_trip() {
    // 1. Formula-like names are neutralized in every CSV cell that carries them.
    let path = hostile_pcap("hostile.pcap");
    let shared = tokio::task::spawn_blocking({
        let path = path.clone();
        move || common::replay(&path)
    })
    .await
    .unwrap();
    std::fs::remove_file(&path).ok();
    let (addr, stop_tx, server) = serve(shared).await;
    let (st, _, csv) = request(addr, "GET", "/api/export/connections.csv").await;
    assert_eq!(st, 200);
    let text = String::from_utf8(csv).unwrap();
    assert_eq!(text.lines().count(), 5, "header + 4 connections:\n{text}");
    assert!(text.contains(",\"'=hyperlink(\"\"http://evil.example\"\")\","), "the Host header is quoted and prefixed:\n{text}");
    assert!(!text.contains(",=hyperlink"), "{text}");
    for cell in ["'-minus.example", "'@at.example", "'+plus.example"] {
        assert!(text.contains(&format!(",{cell},")), "{cell} in connections.csv:\n{text}");
    }
    let (_, _, dns) = request(addr, "GET", "/api/export/dns.csv").await;
    let dns = String::from_utf8(dns).unwrap();
    assert_eq!(dns.lines().count(), 4, "{dns}");
    for cell in ["'-minus.example", "'@at.example", "'+plus.example"] {
        assert!(dns.lines().any(|l| l.split(',').nth(1) == Some(cell)), "{cell} in dns.csv:\n{dns}");
    }
    let (_, _, hosts) = request(addr, "GET", "/api/export/hosts.csv").await;
    let hosts = String::from_utf8(hosts).unwrap();
    assert!(hosts.lines().any(|l| l.starts_with("93.184.215.14,\"'=hyperlink(")), "the learned name of the host is escaped too:\n{hosts}");
    // The JSON API carries the raw name; only the CSV is escaped.
    let (_, _, body) = request(addr, "GET", "/api/connections?q=app%20==%20http").await;
    assert_eq!(json(&body)["connections"][0]["name"], "=hyperlink(\"http://evil.example\")");
    stop_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap().unwrap();

    // 2. pcap exports contain exactly the stored frames, with their original times and lengths.
    let path = common::demo_pcap("roundtrip.pcap", 6);
    let (_, original) = frames_of(&std::fs::read(&path).unwrap(), "roundtrip-copy.pcap");
    let shared = tokio::task::spawn_blocking({
        let path = path.clone();
        move || common::replay(&path)
    })
    .await
    .unwrap();
    std::fs::remove_file(&path).ok();
    let (addr, stop_tx, server) = serve(shared).await;
    let (_, _, body) = request(addr, "GET", "/api/connections?limit=5000").await;
    let conns = json(&body);
    let conns = conns["connections"].as_array().unwrap();
    let stored: u64 = conns.iter().map(|c| c["stored_packets"].as_u64().unwrap()).sum();
    assert!(stored > 100 && (stored as usize) < original.len(), "{stored} of {} frames kept: some rings must have dropped packets", original.len());
    let (st, head, pcap) = request(addr, "GET", "/api/export/connections.pcap").await;
    assert_eq!(st, 200);
    assert!(head.to_lowercase().contains("content-type: application/vnd.tcpdump.pcap"), "{head}");
    let (lt, exported) = frames_of(&pcap, "roundtrip-export.pcap");
    assert_eq!(lt, netscope::decode::linktype::ETHERNET);
    assert_eq!(exported.len() as u64, stored, "one frame per stored packet");
    assert!(exported.windows(2).all(|w| w[0].0 <= w[1].0), "time order across connections");
    let mut pool: std::collections::HashMap<(i64, u32), usize> = std::collections::HashMap::new();
    for &(ts, wire, _) in &original {
        *pool.entry((ts, wire)).or_default() += 1;
    }
    for &(ts, wire, cap) in &exported {
        assert_eq!(wire as usize, cap, "demo frames are stored whole");
        let n = pool.get_mut(&(ts, wire)).unwrap_or_else(|| panic!("exported frame ({ts}, {wire}) is not in the original capture"));
        assert!(*n > 0, "frame ({ts}, {wire}) exported more often than captured");
        *n -= 1;
    }
    // A single connection's pcap holds exactly its stored packets, all of them on its ports.
    let c = conns.iter().max_by_key(|c| c["stored_packets"].as_u64().unwrap()).unwrap();
    let (id, lport, rport, n) = (c["id"].as_u64().unwrap(), c["local_port"].as_u64().unwrap() as u16, c["remote_port"].as_u64().unwrap() as u16, c["stored_packets"].as_u64().unwrap());
    let (st, head, one) = request(addr, "GET", &format!("/api/connections/{id}/pcap")).await;
    assert_eq!(st, 200);
    assert!(head.contains(&format!("filename=\"netscope-connection-{id}.pcap\"")), "{head}");
    let tmp = common::temp_path("one.pcap");
    std::fs::write(&tmp, &one).unwrap();
    let mut f = netscope::capture::file::PcapFile::open(&tmp).unwrap();
    let mut count = 0;
    while let netscope::capture::Next::Packet(p) = netscope::capture::PacketSource::next_packet(&mut f).unwrap() {
        let info = netscope::decode::decode(netscope::decode::linktype::ETHERNET, p.data).unwrap();
        let ports = [info.src_port, info.dst_port];
        assert!(ports.contains(&lport) && ports.contains(&rport), "frame of another connection: {ports:?}");
        count += 1;
    }
    std::fs::remove_file(&tmp).ok();
    assert_eq!(count, n);
    // A filter that matches nothing is an empty but valid capture file.
    let (st, _, empty) = request(addr, "GET", "/api/export/connections.pcap?q=name%20==%20nothing.invalid").await;
    assert_eq!((st, empty.len()), (200, 24));
    assert!(frames_of(&empty, "empty.pcap").1.is_empty());

    // 3. Watch details: labels are cut by characters, not bytes; addresses are trimmed.
    let (st, _, w) = request(addr, "POST", &format!("/api/watch?ip=%20203.0.113.7%20&label={}", "%D1%8F".repeat(70))).await;
    assert_eq!(st, 200);
    let w = json(&w);
    let label = w["targets"][0]["label"].as_str().unwrap();
    assert_eq!((label.chars().count(), label.chars().all(|c| c == 'я')), (64, true), "{label}");
    assert_eq!((w["targets"][0]["ip"].as_str(), w["targets"][0]["running"].as_bool(), w["interval_secs"].as_i64()), (Some("203.0.113.7"), Some(false), Some(600)));
    let (_, _, w) = request(addr, "POST", "/api/watch?ip=203.0.113.7").await;
    assert_eq!(json(&w)["targets"][0]["label"].as_str().map(|l| l.chars().count()), Some(64), "re-adding without a label keeps the old one");
    let (_, _, w) = request(addr, "GET", "/api/watch").await;
    let w = json(&w);
    assert_eq!(w["targets"].as_array().unwrap().len(), 1);
    assert!(w["targets"][0]["history"].as_array().unwrap().is_empty() && w["targets"][0]["last"].is_null());
    assert_eq!(request(addr, "DELETE", "/api/watch?ip=%20203.0.113.7").await.0, 200);
    assert_eq!(json(&request(addr, "GET", "/api/watch").await.2)["targets"].as_array().unwrap().len(), 0);
    stop_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn route_traces_are_cached() {
    let shared = replayed("web-trace.pcap", 1).await;
    let (addr, stop_tx, server) = serve(shared).await;
    // Loopback is the only target that needs no network; the result is cached for 5 minutes.
    // (The 429 path, two traces at once, is not tested here: a third loopback target would
    // cost seconds of reverse-DNS waits on the system resolver.)
    let (st, head, first) = request(addr, "GET", "/api/trace?ip=127.0.0.1").await;
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&first));
    assert!(head.to_lowercase().contains("cache-control: no-store"), "{head}");
    let first = json(&first);
    assert_eq!((first["target"].as_str(), first["reached"].as_bool()), (Some("127.0.0.1"), Some(true)), "{first}");
    assert_eq!(first["hops"][0]["ip"], "127.0.0.1");
    assert_eq!(first["hops"][0]["private"], true);
    let (_, _, again) = request(addr, "GET", "/api/trace?ip=%20127.0.0.1%20").await;
    assert_eq!(json(&again), first, "served from the cache: identical, including duration_ms");
    let (_, _, fresh) = request(addr, "GET", "/api/trace?ip=127.0.0.1&fresh=true").await;
    assert_eq!(json(&fresh), first, "a `fresh` trace is not repeated within 15 seconds either");
    stop_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn bind_default_skips_taken_ports_and_falls_back_to_any_free_one() {
    use netscope::web::DEFAULT_PORT;
    use tokio::net::TcpListener;
    // A second loopback address keeps this test away from a real netscope on 8888 and from
    // the other tests' bind_default calls; platforms without 127.0.0.2 skip it.
    let host = "127.0.0.2";
    if TcpListener::bind((host, 0)).await.is_err() {
        return;
    }
    let range = DEFAULT_PORT..=DEFAULT_PORT + 12;
    let mut held = Vec::new();
    for p in range.clone() {
        // A port that cannot be taken is taken by someone else, which is just as good here.
        if let Ok(l) = TcpListener::bind((host, p)).await {
            held.push(l);
        }
    }
    let l = web::bind_default(host, None).await.unwrap();
    let port = web::local_addr(&l).unwrap().port();
    assert!(!range.contains(&port), "with 8888..8900 busy the OS picks the port, got {port}");
    assert_eq!(web::local_addr(&l).unwrap().ip().to_string(), host);
    // An explicit port is never negotiated.
    if let Some(l) = held.first() {
        let busy = l.local_addr().unwrap().port();
        let e = web::bind_default(host, Some(busy)).await.unwrap_err().to_string();
        assert!(e.contains(&busy.to_string()) && e.contains("--port"), "{e}");
    }
    // Freeing one port in the middle makes it the next choice: ports are tried in order.
    let target = DEFAULT_PORT + 7;
    if let Some(i) = held.iter().position(|l| l.local_addr().map(|a| a.port()).ok() == Some(target)) {
        drop(held.swap_remove(i));
        let l2 = web::bind_default(host, None).await.unwrap();
        assert_eq!(web::local_addr(&l2).unwrap().port(), target);
    }
}

// ----- settings page -----

/// POST with a JSON body returning (status, parsed body or Null).
async fn post_json(addr: SocketAddr, path: &str, body: &str) -> (u16, serde_json::Value) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let head = format!("POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    s.write_all(format!("{head}{body}").as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, serde_json::from_str(body).unwrap_or(serde_json::Value::Null))
}

fn empty_state(source: &str) -> netscope::analytics::SharedState {
    use netscope::analytics::{Config, SharedState, State};
    SharedState::new(State::new(Config::default(), std::collections::HashSet::new(), common::file_info(std::path::Path::new(source))))
}

/// A desktop-app-like host: records what the page asked for.
struct TestHost {
    path: std::path::PathBuf,
    log: Option<std::path::PathBuf>,
    autostart: std::sync::Mutex<bool>,
    restarts: std::sync::atomic::AtomicUsize,
}

impl netscope::settings::SettingsHost for TestHost {
    fn log_path(&self) -> Option<std::path::PathBuf> {
        self.log.clone()
    }
    fn autostart(&self) -> Option<bool> {
        Some(*self.autostart.lock().unwrap())
    }
    fn set_autostart(&self, on: bool) -> Result<(), String> {
        *self.autostart.lock().unwrap() = on;
        Ok(())
    }
    fn can_restart(&self) -> bool {
        true
    }
    fn request_restart(&self) -> Result<(), String> {
        self.restarts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    fn settings_path(&self) -> std::path::PathBuf {
        self.path.clone()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn settings_page_round_trip_validation_and_restart() {
    let dir = common::temp_path("settings-dir");
    let _ = std::fs::remove_dir_all(&dir);
    let ini = dir.join("netscope.ini");
    let host = std::sync::Arc::new(TestHost { path: ini.clone(), log: None, autostart: std::sync::Mutex::new(false), restarts: Default::default() });
    let shared = empty_state("replay.pcap");
    // A live journal, so the retention can be changed from the page.
    let journal_dir = dir.join("journal");
    let journal = std::sync::Arc::new(netscope::analytics::Journal::new(&journal_dir, 1));
    shared.write().set_journal(journal.clone());
    let listener = web::bind("127.0.0.1", 0).await.unwrap();
    let addr = web::local_addr(&listener).unwrap();
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let shutdown = async move {
        let _ = stop_rx.await;
    };
    let server = tokio::spawn(web::run_with_host(listener, shared, false, shutdown, Some(host.clone())));

    // No file yet: defaults, plus what the program is actually doing.
    let (st, body) = get(addr, "/api/settings").await;
    assert_eq!(st, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["file"], ini.display().to_string());
    let defaults = serde_json::json!({
        "port": null, "host": "127.0.0.1", "interface": null, "filter": null, "geoip": null,
        "egress_check": true, "promiscuous": true, "verbose": false, "show_window": true, "notifications": "medium",
        "notify_categories": ["security", "novelty", "network", "routes"], "notify_snooze_until": 0, "journal_days": 1
    });
    assert_eq!(v["values"], defaults);
    assert_eq!(v["journal"], serde_json::json!({ "dir": journal_dir.display().to_string(), "days": 1, "enabled": true }));
    assert_eq!(v["api"], serde_json::json!({ "base": format!("http://127.0.0.1:{}", addr.port()), "metrics": "/metrics" }));
    let active = serde_json::json!({ "interface": "replay.pcap", "interface_description": null, "host": "127.0.0.1", "port": addr.port(), "mode": "file" });
    assert_eq!(v["active"], active);
    assert_eq!((v["autostart"].as_bool(), v["can_restart"].as_bool(), v["from_cli"].as_bool()), (Some(false), Some(true), Some(false)));
    assert_eq!(v["geoip"], serde_json::json!({ "enabled": false, "dir": null, "note": null }));
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    assert!(!ini.exists(), "GET does not create the file");

    // Save: the file appears (with its directory), autostart reaches the host.
    let (st, r) = post_json(addr, "/api/settings", r#"{"port": 9000, "host": " 0.0.0.0 ", "interface": " Wi-Fi ", "notifications": "OFF", "notify_categories": ["routes", "security", "routes"], "notify_snooze_until": 1760000000, "autostart": true}"#).await;
    assert_eq!((st, &r), (200, &serde_json::json!({ "saved": true, "restart_required": true })));
    assert!(*host.autostart.lock().unwrap());
    let text = std::fs::read_to_string(&ini).unwrap();
    for line in ["port=9000\r\n", "host=0.0.0.0\r\n", "interface=Wi-Fi\r\n", "notifications=off\r\n", "notify_categories=security,routes\r\n", "notify_snooze_until=1760000000\r\n"] {
        assert!(text.contains(line), "{line:?} in {text:?}");
    }
    let (_, body) = get(addr, "/api/settings").await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let vals = &v["values"];
    assert_eq!((vals["port"].as_u64(), vals["host"].as_str(), vals["interface"].as_str(), vals["notifications"].as_str()), (Some(9000), Some("0.0.0.0"), Some("Wi-Fi"), Some("off")));
    assert_eq!(v["autostart"], true);
    assert_eq!(v["active"]["port"], addr.port(), "the active port is the bound one, not the saved one");

    // Only on-the-fly settings: no restart needed; clearing the port needs one.
    let (st, r) = post_json(addr, "/api/settings", r#"{"show_window": false, "notifications": "high", "autostart": false}"#).await;
    assert_eq!((st, &r), (200, &serde_json::json!({ "saved": true, "restart_required": false })));
    assert!(!*host.autostart.lock().unwrap());
    let (st, r) = post_json(addr, "/api/settings", r#"{"port_auto": true, "interface": ""}"#).await;
    assert_eq!((st, &r), (200, &serde_json::json!({ "saved": true, "restart_required": true })));
    let (_, body) = get(addr, "/api/settings").await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(v["values"]["port"].is_null() && v["values"]["interface"].is_null() && v["values"]["show_window"] == false, "{v}");
    let (st, r) = post_json(addr, "/api/settings", "{}").await;
    assert_eq!((st, &r), (200, &serde_json::json!({ "saved": true, "restart_required": false })));

    // Ending a snooze from the page sends that key alone: everything else stays as saved.
    let (st, _) = post_json(addr, "/api/settings", r#"{"notify_categories": ["security"], "notify_snooze_until": 1760000000}"#).await;
    assert_eq!(st, 200);
    let before = std::fs::read_to_string(&ini).unwrap();
    let (st, r) = post_json(addr, "/api/settings", r#"{"notify_snooze_until": 0}"#).await;
    assert_eq!((st, &r), (200, &serde_json::json!({ "saved": true, "restart_required": false })));
    let after = std::fs::read_to_string(&ini).unwrap();
    assert_eq!(after, before.replace("notify_snooze_until=1760000000", "notify_snooze_until=0"), "only the snooze line changed");
    // An absurd snooze is clamped (it would overflow the tray's clock), not stored.
    let (st, _) = post_json(addr, "/api/settings", r#"{"notify_snooze_until": 9000000000000000000}"#).await;
    assert_eq!(st, 200);
    let (_, body) = get(addr, "/api/settings").await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["values"]["notify_snooze_until"].as_i64(), Some(netscope::settings::MAX_SNOOZE_UNTIL));
    assert_eq!(v["values"]["notify_categories"], serde_json::json!(["security"]));
    let (st, _) = post_json(addr, "/api/settings", r#"{"notify_snooze_until": 0, "notify_categories": ["security", "novelty", "network", "routes"]}"#).await;
    assert_eq!(st, 200);

    // The journal retention: saved to the file and applied to the running journal at once.
    let (st, r) = post_json(addr, "/api/settings", r#"{"journal_days": 3}"#).await;
    assert_eq!((st, &r), (200, &serde_json::json!({ "saved": true, "restart_required": false })));
    assert!(std::fs::read_to_string(&ini).unwrap().contains("journal_days=3\r\n"));
    assert_eq!(journal.retention_days(), 3);
    let (_, body) = get(addr, "/api/settings").await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!((v["values"]["journal_days"].as_u64(), v["journal"]["days"].as_u64(), v["journal"]["enabled"].as_bool()), (Some(3), Some(3), Some(true)));
    let (st, body) = get(addr, "/api/journal/stats").await;
    assert_eq!(st, 200, "{body}");
    let stats: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!((stats["days_kept"].as_u64(), stats["enabled"].as_bool(), stats["pending"].as_u64(), stats["dropped"].as_u64()), (Some(3), Some(true), Some(0), Some(0)));
    assert_eq!((stats["dir"].as_str(), stats["bytes_total"].as_u64(), stats["days"].as_array().map(Vec::len)), (Some(journal_dir.display().to_string().as_str()), Some(0), Some(0)));
    let (st, r) = post_json(addr, "/api/settings", r#"{"journal_days": 0}"#).await;
    assert_eq!(st, 200, "{r}");
    assert!(!journal.enabled());
    let (_, body) = get(addr, "/api/settings").await;
    assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["journal"]["enabled"], false);

    // Validation: 400 naming the field, and the file stays as it was.
    let before = std::fs::read_to_string(&ini).unwrap();
    let bad = [
        (r#"{"port": 0}"#, "port"),
        (r#"{"port": 70000}"#, "port"),
        (r#"{"port": "x"}"#, "port"),
        (r#"{"host": "example.org"}"#, "host"),
        (r#"{"host": "127.0.0.1:80"}"#, "host"),
        (r#"{"notifications": "loud"}"#, "notifications"),
        (r#"{"notify_categories": ["security", "everything"]}"#, "everything"),
        (r#"{"notify_categories": "security"}"#, "notify_categories"),
        (r#"{"verbose": "yes"}"#, "verbose"),
        (r#"{"journal_days": 366}"#, "journal_days"),
        (r#"{"journal_days": -1}"#, "journal_days"),
        ("not json", "settings"),
        ("", "settings"),
    ];
    for (body, field) in bad {
        let (st, r) = post_json(addr, "/api/settings", body).await;
        assert_eq!(st, 400, "{body}: {r}");
        assert_eq!(r["error"]["code"], "bad_request", "{body}");
        assert!(r["error"]["message"].as_str().unwrap().contains(field), "{body}: {r}");
    }
    assert_eq!(std::fs::read_to_string(&ini).unwrap(), before);

    // Interfaces: an array (empty without a capture library).
    let (st, body) = get(addr, "/api/interfaces").await;
    assert_eq!(st, 200);
    let list: serde_json::Value = serde_json::from_str(&body).unwrap();
    for d in list.as_array().expect("an array") {
        assert!(d["name"].is_string() && d["addresses"].is_array() && d["up"].is_boolean() && d["loopback"].is_boolean() && d["default"].is_boolean(), "{d}");
    }
    assert!(list.as_array().unwrap().iter().filter(|d| d["default"] == true).count() <= 1);

    // Restart goes to the host.
    let (st, r) = post_json(addr, "/api/restart", "").await;
    assert_eq!((st, &r), (202, &serde_json::json!({ "restarting": true })));
    assert_eq!(host.restarts.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(request(addr, "GET", "/api/restart").await.0, 405);

    stop_tx.send(()).unwrap();
    server.await.unwrap().unwrap();
    std::fs::remove_dir_all(&dir).ok();
}

/// The plain CLI: no host, so the page reads and writes but cannot restart or autostart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn settings_page_without_a_host() {
    let shared = empty_state("cli.pcap");
    let listener = web::bind("127.0.0.1", 0).await.unwrap();
    let addr = web::local_addr(&listener).unwrap();
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(web::run(listener, shared, false, async move {
        let _ = stop_rx.await;
    }));

    let (st, body) = get(addr, "/api/settings").await;
    assert_eq!(st, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(v["autostart"].is_null() && v["can_restart"] == false && v["from_cli"] == true, "{v}");
    assert!(v["file"].as_str().unwrap().ends_with("netscope.ini"));
    assert!(v["values"]["host"].is_string() && v["active"]["port"] == addr.port());

    let (st, r) = post_json(addr, "/api/restart", "").await;
    assert_eq!(st, 400, "{r}");
    assert_eq!(r["error"]["code"], "bad_request");
    assert!(r["error"]["message"].as_str().unwrap().contains("manually"), "{r}");
    // Rejected before anything is written (this is the user's real settings file).
    let (st, r) = post_json(addr, "/api/settings", r#"{"autostart": true}"#).await;
    assert_eq!(st, 400, "{r}");
    assert!(r["error"]["message"].as_str().unwrap().contains("autostart"), "{r}");

    let (st, body) = get(addr, "/api/interfaces").await;
    assert_eq!(st, 200);
    assert!(serde_json::from_str::<serde_json::Value>(&body).unwrap().is_array());

    // No host, no log file; no journal attached: stats are those of the default directory.
    let (st, body) = get(addr, "/api/logs").await;
    assert_eq!((st, body.as_str()), (200, r#"{"file":null,"lines":[]}"#));
    let (st, body) = get(addr, "/api/journal/stats").await;
    assert_eq!(st, 200, "{body}");
    let stats: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(stats["enabled"], false);
    assert!(stats["dir"].as_str().unwrap().ends_with("journal"), "{stats}");
    assert!(v["journal"]["dir"] == stats["dir"] && v["journal"]["enabled"] == false, "{v}");

    stop_tx.send(()).unwrap();
    server.await.unwrap().unwrap();
}

// ----- journal, metrics, logs -----

/// A replayed capture with a journal: closed connections are journaled during the replay,
/// the rest by the shutdown step; then the files are queried through the API.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn journal_endpoints_after_a_replay_and_a_forced_shutdown() {
    use netscope::analytics::journal::{self, Kind};
    use netscope::analytics::Journal;
    let dir = common::temp_path("journal-replay");
    let _ = std::fs::remove_dir_all(&dir);
    let journal = std::sync::Arc::new(Journal::new(&dir, 2));
    let shared = empty_state("journal.pcap");
    shared.write().set_journal(journal.clone());
    let path = common::demo_pcap("journal.pcap", 15);
    let shared = tokio::task::spawn_blocking({
        let (path, shared) = (path.clone(), shared.clone());
        move || common::replay_into(&path, shared)
    })
    .await
    .unwrap();
    std::fs::remove_file(&path).ok();
    let (flows, closed_in_memory) = {
        let st = shared.read();
        (st.flows().count(), st.flows().filter(|f| f.journaled).count())
    };
    assert!(closed_in_memory > 0 && closed_in_memory < flows, "some demo connections close during the replay: {closed_in_memory} of {flows}");
    let pending_before = journal.pending();
    assert!(pending_before >= closed_in_memory);
    // The program's shutdown step: the open connections, then the writer drains and stops.
    assert_eq!(shared.write().journal_remaining(), flows - closed_in_memory);
    assert_eq!(shared.write().journal_remaining(), 0);
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let writer = journal::spawn_writer(journal.clone(), stop).unwrap();
    tokio::task::spawn_blocking(move || writer.join().unwrap()).await.unwrap();
    assert_eq!(journal.pending(), 0);
    assert_eq!(journal.written(Kind::Connections) as usize, flows, "one record per connection");
    assert!(journal.written(Kind::Dns) > 0 && journal.written(Kind::Alerts) > 0);

    let (addr, stop_tx, server) = serve(shared.clone()).await;

    // JSON: the default window (today and the kept days) holds every connection record.
    let (st, body) = get(addr, "/api/journal?kind=connections").await;
    assert_eq!(st, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!((v["kind"].as_str(), v["total"].as_u64()), (Some("connections"), Some(flows as u64)));
    let records = v["records"].as_array().unwrap();
    assert_eq!(records.len(), flows.min(500));
    let now = netscope::capture::engine::unix_now();
    assert!(v["from"].as_i64().unwrap() <= now - 2 * 86_400 && v["to"].as_i64().unwrap() >= now - 5, "{v}");
    let mut ids: Vec<u64> = records.iter().map(|r| r["id"].as_u64().unwrap()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), records.len(), "no connection twice");
    for r in records {
        assert!(matches!(r["reason"].as_str(), Some("closed" | "shutdown")), "{r}");
        assert!((r["ts"].as_i64().unwrap() - now).abs() < 60, "{r}");
        for key in ["first_us", "last_us", "l4", "app", "local", "remote", "remote_ip", "bytes_in", "bytes_out", "packets_in", "packets_out", "state"] {
            assert!(!r[key].is_null(), "{key} in {r}");
        }
        assert!(r.get("process").is_some() && r.get("geo").is_some() && r.get("tls").is_some(), "{r}");
    }
    if records.len() == flows {
        assert_eq!(records.iter().filter(|r| r["reason"] == "closed").count(), closed_in_memory);
    }
    assert!(records.windows(2).all(|w| w[0]["ts"].as_i64() >= w[1]["ts"].as_i64()), "newest first");
    // Search, paging.
    // (A replayed file has no process table, so the search uses a remote address; the text
    // search covers the whole JSON line, case-insensitively.)
    let ip = records[0]["remote_ip"].as_str().unwrap().to_string();
    let (_, body) = get(addr, &format!("/api/journal?kind=connections&q={}&limit=2", ip.replace("a", "A").replace("e", "E"))).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let total = v["total"].as_u64().unwrap();
    assert!(total > 0 && total < flows as u64, "{ip}: {total}");
    assert_eq!(v["records"].as_array().unwrap().len(), 2.min(total as usize));
    assert!(v["records"].as_array().unwrap().iter().all(|r| r.to_string().contains(&ip)));
    assert!(records.iter().all(|r| r["process"].is_null()), "a replayed file has no process table");
    let (_, body) = get(addr, "/api/journal?kind=connections&q=no-such-thing-anywhere").await;
    assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["total"], 0);
    // DNS records today; alerts carry the capture's own (old) time, so the default window misses them.
    let (_, body) = get(addr, "/api/journal?kind=dns").await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["total"].as_u64(), Some(journal.written(Kind::Dns)));
    let d = &v["records"][0];
    assert!(d["name"].is_string() && d["ts_us"].is_i64() && d["answers"].is_array() && d["used_by"].is_array() && d["ts"].is_i64(), "{d}");
    let (_, body) = get(addr, "/api/journal?kind=alerts").await;
    assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["total"], 0);
    let (_, body) = get(addr, &format!("/api/journal?kind=alerts&from=0&to={}", common::START_US / 1_000_000 + 100)).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["total"].as_u64(), Some(journal.written(Kind::Alerts)));
    let a = &v["records"][0];
    assert!(a["kind"].is_string() && a["severity"].is_string() && a["message"].is_string() && a["details"].is_object(), "{a}");
    assert!((common::START_US / 1_000_000..common::START_US / 1_000_000 + 100).contains(&a["ts"].as_i64().unwrap()), "{a}");

    // Downloads.
    let (st, head, body) = request(addr, "GET", "/api/journal?kind=connections&format=csv&limit=10").await;
    assert_eq!(st, 200);
    assert!(head.contains("text/csv") && head.contains("attachment; filename=\"netscope-connections-"), "{head}");
    let text = String::from_utf8(body).unwrap();
    let lines: Vec<&str> = text.trim_start_matches('\u{feff}').lines().collect();
    assert_eq!(lines.len(), 11, "header plus ten rows");
    assert!(lines[0].starts_with("ts,time_utc,first_us,last_us,id,process.pid,process.name,process.path,l4,app,local,remote,remote_ip,name,geo.country_code,"));
    assert!(lines[0].ends_with(",tls.sni,tls.version,tls.alpn,tls.ja4,rtt_ms,retrans,hops,reason"));
    assert!(lines[1].ends_with(",closed") || lines[1].ends_with(",shutdown"), "{}", lines[1]);
    let (st, head, body) = request(addr, "GET", "/api/journal?kind=dns&format=jsonl&limit=3").await;
    assert_eq!(st, 200);
    assert!(head.contains("application/x-ndjson") && head.contains("filename=\"netscope-dns-") && head.contains(".jsonl\""), "{head}");
    let text = String::from_utf8(body).unwrap();
    assert_eq!(text.lines().count(), 3);
    for l in text.lines() {
        assert!(serde_json::from_str::<serde_json::Value>(l).unwrap()["name"].is_string());
    }

    // Stats: today's file set, nothing queued.
    let (st, body) = get(addr, "/api/journal/stats").await;
    assert_eq!(st, 200, "{body}");
    let s: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!((s["dir"].as_str(), s["days_kept"].as_u64(), s["enabled"].as_bool(), s["pending"].as_u64(), s["dropped"].as_u64()), (Some(dir.display().to_string().as_str()), Some(2), Some(true), Some(0), Some(0)));
    let days = s["days"].as_array().unwrap();
    assert_eq!(days.len(), 2, "today (connections, dns) and the capture's day (alerts): {s}");
    assert_eq!(days[0]["date"], journal::date_string(now.div_euclid(86_400)));
    assert_eq!(days[0]["records"]["connections"].as_u64(), Some(flows as u64));
    assert_eq!(days[0]["records"]["dns"].as_u64(), Some(journal.written(Kind::Dns)));
    assert_eq!(days[1]["records"]["alerts"].as_u64(), Some(journal.written(Kind::Alerts)));
    assert_eq!(s["bytes_total"].as_u64().unwrap(), days.iter().map(|d| d["bytes"].as_u64().unwrap()).sum::<u64>());
    assert!(s["bytes_total"].as_u64().unwrap() > 1000);

    // Errors in the usual envelope.
    for (path, word) in [("/api/journal", "kind"), ("/api/journal?kind=hosts", "kind"), ("/api/journal?kind=dns&format=xml", "format"), ("/api/journal?kind=dns&from=10&to=5", "from"), ("/api/journal?kind=dns&limit=x", "limit")] {
        let (st, body) = get(addr, path).await;
        assert_eq!(st, 400, "{path}: {body}");
        let e: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(e["error"]["message"].as_str().unwrap().contains(word), "{path}: {body}");
    }

    // Metrics after the replay.
    let (st, head, body) = request(addr, "GET", "/metrics").await;
    assert_eq!(st, 200);
    assert!(head.contains("text/plain; version=0.0.4"), "{head}");
    let text = String::from_utf8(body).unwrap();
    assert!(text.contains(&format!("netscope_journal_records_total{{kind=\"connections\"}} {flows}\n")), "{text}");
    assert!(text.contains("netscope_journal_pending 0\n"));
    assert!(text.contains("netscope_up 0\n"), "finished capture");
    assert!(text.contains(&format!("netscope_connections{{state=\"total\"}} {flows}\n")));
    assert!(text.contains("# TYPE netscope_process_bytes_total counter\n"));
    assert!(text.contains("netscope_dns_queries_total ") && text.contains("netscope_alerts_total{severity=\"high\"} "));
    let totals: serde_json::Value = serde_json::from_str(&get(addr, "/api/stats").await.1).unwrap();
    assert!(text.contains(&format!("netscope_bytes_total{{direction=\"in\"}} {}\n", totals["totals"]["bytes_in"])));
    assert!(text.contains(&format!("netscope_packets_total{{direction=\"out\"}} {}\n", totals["totals"]["packets_out"])));

    stop_tx.send(()).unwrap();
    server.await.unwrap().unwrap();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_escape_labels_and_sit_behind_the_guard() {
    use netscope::decode::{decode, linktype};
    use netscope::demo::frames::{tcp_frame, TcpFlags};
    use netscope::procs::{OsSnapshot, OwnerIndex, ProcInfo, SockProto, SocketEntry};
    let shared = empty_state("metrics.pcap");
    {
        let mut st = shared.write();
        let mut procs = std::collections::HashMap::new();
        procs.insert(7, ProcInfo { pid: 7, name: "say \"hi\"\\there.exe".into(), path: None, parent: None });
        let sock = SocketEntry { proto: SockProto::Tcp, local: "10.0.0.2:5000".parse().unwrap(), remote: Some("93.184.215.14:80".parse().unwrap()), state: Some("ESTABLISHED"), pid: 7 };
        st.set_owners(std::sync::Arc::new(OwnerIndex::new(OsSnapshot { sockets: vec![sock], procs, error: None })));
        let f = tcp_frame([10, 0, 0, 2], [93, 184, 215, 14], 5000, 80, TcpFlags::Data, b"hello");
        st.record_frame(common::START_US, f.len() as u32, &f, decode(linktype::ETHERNET, &f).as_ref());
    }
    let (addr, stop_tx, server) = serve(shared).await;
    let (st, body) = get(addr, "/metrics").await;
    assert_eq!(st, 200);
    let line = body.lines().find(|l| l.starts_with("netscope_process_bytes_total{process=\"say \\\"hi\\\"\\\\there.exe\",direction=\"out\"} ")).unwrap_or_else(|| panic!("{body}"));
    assert!(line.rsplit(' ').next().unwrap().parse::<u64>().unwrap() > 50, "{line}");
    assert!(body.contains("netscope_build_info{version=\"") && body.contains("netscope_connections{state=\"active\"} 1\n"), "{body}");
    assert!(body.contains("# HELP netscope_bytes_total ") && body.contains("# TYPE netscope_bytes_total counter\n"));
    // Not under /api, but the same protection against other web pages.
    assert_eq!(raw(addr, "GET /metrics HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n").await, 403);
    assert_eq!(raw(addr, "GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: cross-site\r\nConnection: close\r\n\r\n").await, 403);
    assert_eq!(raw(addr, "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await, 200);
    stop_tx.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logs_endpoint_with_a_host() {
    let dir = common::temp_path("logs-dir");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("netscope.log");
    let host = std::sync::Arc::new(TestHost { path: dir.join("netscope.ini"), log: Some(log.clone()), autostart: std::sync::Mutex::new(false), restarts: Default::default() });
    let shared = empty_state("logs.pcap");
    let listener = web::bind("127.0.0.1", 0).await.unwrap();
    let addr = web::local_addr(&listener).unwrap();
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(web::run_with_host(listener, shared, false, async move { let _ = stop_rx.await; }, Some(host)));

    // The path is known but the file is not there yet.
    let (st, body) = get(addr, "/api/logs").await;
    assert_eq!(st, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!((v["file"].as_str(), v["lines"].as_array().map(Vec::len)), (Some(log.display().to_string().as_str()), Some(0)));

    let text: String = (1..=300).map(|i| format!("2026-10-20T10:00:{:02}Z  INFO line {i}\n", i % 60)).collect();
    std::fs::write(&log, &text).unwrap();
    let (_, body) = get(addr, "/api/logs").await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let lines = v["lines"].as_array().unwrap();
    assert_eq!(lines.len(), 200, "default");
    assert!(lines[0].as_str().unwrap().ends_with("line 101") && lines[199].as_str().unwrap().ends_with("line 300"));
    let (_, body) = get(addr, "/api/logs?lines=5").await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["lines"].as_array().unwrap().iter().map(|l| l.as_str().unwrap().rsplit(' ').next().unwrap()).collect::<Vec<_>>(), ["296", "297", "298", "299", "300"]);
    let (_, body) = get(addr, "/api/logs?lines=99999").await;
    assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["lines"].as_array().unwrap().len(), 300, "capped at 5000, so all of them");
    let (st, body) = get(addr, "/api/logs?lines=x").await;
    assert_eq!(st, 400, "{body}");

    stop_tx.send(()).unwrap();
    server.await.unwrap().unwrap();
    std::fs::remove_dir_all(&dir).ok();
}
