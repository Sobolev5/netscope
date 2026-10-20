//! End to end without privileges: demo frames -> .pcap -> built-in reader -> capture
//! thread -> decoder -> analytics.

mod common;

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use netscope::analytics::{AlertKind, CaptureStatus, Config, NameSource, Severity, SharedState, State};
use netscope::capture::engine::{self, Pacing};
use netscope::demo::DemoSource;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn replayed_capture_produces_names_protocols_and_every_alert_kind() {
    let path = common::demo_pcap("full.pcap", 20);
    let shared = common::replay(&path);
    std::fs::remove_file(&path).ok();

    let st = shared.read();
    assert_eq!(st.capture.status, CaptureStatus::Finished);

    // Names learned from TLS SNI, DNS answers and HTTP Host headers.
    let gh = st.name_of(&ip("140.82.121.4")).expect("github resolved");
    assert_eq!((gh.name.as_str(), gh.source), ("github.com", NameSource::Sni));
    assert_eq!(st.name_of(&ip("142.250.74.46")).unwrap().name, "www.youtube.com");
    assert_eq!(st.name_of(&ip("142.250.74.46")).unwrap().source, NameSource::Dns, "QUIC has no SNI here");
    assert_eq!(st.name_of(&ip("93.184.215.14")).unwrap().name, "example.org");
    assert!(st.name_of(&ip("203.0.113.77")).is_none());

    // Direction: downloads dominate, our own address is never a destination.
    let t = st.totals();
    assert!(t.bytes_in > t.bytes_out * 2, "{t:?}");
    assert!(st.host(&ip("192.168.1.50")).is_none());
    assert!(st.host(&ip("192.168.1.1")).is_some(), "LAN resolver");

    let snap = st.snapshot(100, 100);
    let proto = |n: &str| snap.protocols.iter().find(|p| p.name == n).unwrap().packets;
    for p in ["tls", "quic", "dns", "http", "icmp"] {
        assert!(proto(p) > 0, "no {p} traffic");
    }
    assert_eq!(proto("other"), 0);

    let kinds: HashSet<_> = snap.alerts.iter().map(|a| format!("{:?}", a.kind)).collect();
    for k in [AlertKind::SensitiveHttp, AlertKind::SuspiciousDns, AlertKind::VolumeSpike, AlertKind::CleartextProtocol] {
        assert!(kinds.contains(&format!("{k:?}")), "missing {k:?} in {kinds:?}");
    }
    let creds = snap.alerts.iter().find(|a| a.kind == AlertKind::SensitiveHttp).unwrap();
    assert_eq!(creds.severity, Severity::High);
    assert!(creds.message.contains("http://example.org/login"));

    let spike = snap.hosts.iter().find(|h| h.ip == "203.0.113.77").expect("exfil host listed");
    assert!(spike.flagged && spike.bytes_out > 1 << 20 && spike.name.is_none());
    // Heavy but named hosts are never flagged.
    assert!(snap.hosts.iter().filter(|h| h.name.is_some()).all(|h| !h.flagged));

    // Top hosts are sorted by volume and the busiest is the video stream.
    assert_eq!(snap.hosts[0].name.as_deref(), Some("www.youtube.com"));
    assert!(snap.hosts.windows(2).all(|w| w[0].bytes_in + w[0].bytes_out >= w[1].bytes_in + w[1].bytes_out));
    assert!(snap.dns_top.iter().any(|d| d.name == "github.com"));
    assert!(snap.uptime_secs >= 19);
}

#[test]
fn spike_threshold_is_configurable() {
    let path = common::demo_pcap("threshold.pcap", 15);
    let shared = SharedState::new(State::new(
        Config { spike_min_bytes: 64 << 20, ..Config::default() },
        HashSet::new(),
        common::file_info(&path),
    ));
    let source = netscope::capture::file::PcapFile::open(&path).unwrap();
    engine::spawn(Box::new(source), shared.clone(), Arc::new(AtomicBool::new(false)), Pacing::Fast)
        .unwrap()
        .join()
        .unwrap();
    std::fs::remove_file(&path).ok();
    let st = shared.read();
    assert!(st.alerts(100).iter().all(|a| a.kind != AlertKind::VolumeSpike));
    assert!(st.alert_counts().total > 0, "other detectors still fire");
}

#[test]
fn live_engine_stops_promptly_and_reports_status() {
    let shared = SharedState::new(State::new(Config::default(), HashSet::new(), common::file_info(std::path::Path::new("demo"))));
    let stop = Arc::new(AtomicBool::new(false));
    let handle = engine::spawn(Box::new(DemoSource::new()), shared.clone(), stop.clone(), Pacing::Fast).unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    while shared.read().totals().packets == 0 {
        assert!(Instant::now() < deadline, "no demo packets");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(shared.read().capture.status, CaptureStatus::Running);

    let asked = Instant::now();
    stop.store(true, Ordering::Relaxed);
    handle.join().unwrap();
    assert!(asked.elapsed() < Duration::from_secs(1), "took {:?}", asked.elapsed());
    assert_eq!(shared.read().capture.status, CaptureStatus::Finished);
}

#[test]
fn realtime_replay_caps_idle_gaps_at_one_second() {
    use netscope::capture::file::{PcapFile, PcapWriter};
    use netscope::decode::linktype;
    use netscope::demo::frames::{tcp_frame, udp_frame, TcpFlags};
    let path = common::temp_path("realtime.pcap");
    let mut w = PcapWriter::create(&path, linktype::ETHERNET).unwrap();
    let t = common::START_US;
    let f = udp_frame([10, 0, 0, 2], [1, 1, 1, 1], 5000, 53, b"x");
    w.write(t, &f).unwrap();
    w.write(t + 5_000_000, &f).unwrap(); // a 5 s pause: replayed as 1 s
    w.write(t + 5_100_000, &tcp_frame([10, 0, 0, 2], [1, 1, 1, 1], 5001, 443, TcpFlags::Syn, b"")).unwrap();
    w.write(t + 5_100_000, &f).unwrap(); // same instant: no wait at all
    w.write(t + 5_000_000, &f).unwrap(); // earlier than the previous one: no wait either
    w.finish().unwrap();
    let shared = SharedState::new(State::new(Config::default(), HashSet::new(), common::file_info(&path)));
    let source = PcapFile::open(&path).unwrap();
    let started = Instant::now();
    engine::spawn(Box::new(source), shared.clone(), Arc::new(AtomicBool::new(false)), Pacing::Realtime).unwrap().join().unwrap();
    let took = started.elapsed();
    std::fs::remove_file(&path).ok();
    assert!(took >= Duration::from_millis(1_050) && took < Duration::from_secs(3), "{took:?}");
    let st = shared.read();
    assert_eq!((st.totals().packets, st.capture.status.clone()), (5, CaptureStatus::Finished));
    assert_eq!(st.now() - common::START_US / 1_000_000, 5, "the traffic clock follows the file, not the wall clock");
}

#[test]
fn a_corrupt_record_ends_the_capture_with_a_failed_status() {
    use netscope::capture::file::{PcapFile, PcapWriter};
    use netscope::decode::linktype;
    use netscope::demo::frames::udp_frame;
    let path = common::temp_path("corrupt.pcap");
    let mut w = PcapWriter::create(&path, linktype::ETHERNET).unwrap();
    let f = udp_frame([10, 0, 0, 2], [1, 1, 1, 1], 5000, 53, b"x");
    for i in 0..3 {
        w.write(common::START_US + i, &f).unwrap();
    }
    w.finish().unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    let third = 24 + 2 * (16 + f.len());
    bytes[third + 8..third + 12].copy_from_slice(&(2u32 << 20).to_le_bytes());
    std::fs::write(&path, &bytes).unwrap();
    let shared = SharedState::new(State::new(Config::default(), HashSet::new(), common::file_info(&path)));
    let source = PcapFile::open(&path).unwrap();
    engine::spawn(Box::new(source), shared.clone(), Arc::new(AtomicBool::new(false)), Pacing::Fast).unwrap().join().unwrap();
    std::fs::remove_file(&path).ok();
    let st = shared.read();
    assert_eq!(st.totals().packets, 2, "everything before the corruption is kept");
    let CaptureStatus::Failed(e) = &st.capture.status else { panic!("{:?}", st.capture.status) };
    assert!(e.contains("corrupt record") && e.contains("2097152") && e.contains("corrupt.pcap"), "{e}");
    let json = serde_json::to_value(&st.capture).unwrap();
    assert_eq!(json["status"]["state"], "failed");
    assert_eq!(json["status"]["error"], e.as_str());
}

#[test]
fn persisted_state_survives_a_file_round_trip_and_a_restart() {
    use netscope::analytics::{persist, CaptureInfo, Persisted, WatchEntry};
    let live = || CaptureInfo { mode: "live", source: "eth0".into(), description: None, filter: None, libpcap: None, status: CaptureStatus::Running };
    let path = common::temp_path("state").join("state.json");
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
    assert_eq!(persist::load(&path), Ok(None));

    let mut first = State::new(Config::default(), HashSet::new(), live());
    assert!(first.routes.add(ip("203.0.113.9"), Some("example".into()), 0));
    assert!(first.routes.add(ip("2001:db8::1"), None, 0));
    let p = first.persisted();
    persist::save(&path, &p).unwrap();
    let loaded = persist::load(&path).unwrap().expect("saved");
    assert_eq!(loaded, p);
    assert!(!path.with_extension("json.tmp").exists(), "atomic write leaves no temporary file");

    let mut second = State::new(Config::default(), HashSet::new(), live());
    second.restore(loaded);
    assert_eq!(second.persisted().watch, vec![
        WatchEntry { ip: ip("203.0.113.9"), label: Some("example".into()) },
        WatchEntry { ip: ip("2001:db8::1"), label: None },
    ]);
    assert_eq!(second.routes.take_due(netscope::capture::engine::unix_now()).len(), 2, "restored routes are traced right away");
    // A replayed file never carries processes (no socket owners), so its baseline is empty
    // and nothing from it should ever end up in a state file.
    let pcap = common::demo_pcap("state.pcap", 5);
    let shared = common::replay(&pcap);
    std::fs::remove_file(&pcap).ok();
    let from_file = shared.read().persisted();
    assert!(from_file.novelty.processes.is_empty() && from_file.watch.is_empty());
    assert!(from_file.same_content(&Persisted::default()));
    std::fs::remove_dir_all(path.parent().unwrap()).ok();
}
