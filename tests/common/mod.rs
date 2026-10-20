#![allow(dead_code)]

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use netscope::analytics::{CaptureInfo, CaptureStatus, Config, SharedState, State};
use netscope::capture::engine::{self, Pacing};
use netscope::capture::file::{PcapFile, PcapWriter};
use netscope::decode::linktype;
use netscope::demo;

pub const START_US: i64 = 1_760_000_000_000_000;

pub fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("netscope-it-{}-{name}", std::process::id()))
}

/// Writes the first `seconds` of the demo script to a pcap file.
pub fn demo_pcap(name: &str, seconds: u32) -> PathBuf {
    let path = temp_path(name);
    let mut w = PcapWriter::create(&path, linktype::ETHERNET).unwrap();
    for (ts, frame) in demo::script(seconds, START_US) {
        w.write(ts, &frame).unwrap();
    }
    w.finish().unwrap();
    path
}

pub fn file_info(path: &Path) -> CaptureInfo {
    CaptureInfo {
        mode: "file",
        source: path.display().to_string(),
        description: None,
        filter: None,
        libpcap: None,
        status: CaptureStatus::Starting,
    }
}

/// Replays a pcap through the real engine and waits for it to finish.
pub fn replay(path: &Path) -> SharedState {
    replay_into(path, SharedState::new(State::new(Config::default(), HashSet::new(), file_info(path))))
}

/// Replays a pcap into a prepared state (e.g. one with a journal attached).
pub fn replay_into(path: &Path, shared: SharedState) -> SharedState {
    let source = PcapFile::open(path).unwrap();
    let handle = engine::spawn(Box::new(source), shared.clone(), Arc::new(AtomicBool::new(false)), Pacing::Fast).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !handle.is_finished() {
        assert!(Instant::now() < deadline, "replay did not finish");
        std::thread::sleep(Duration::from_millis(10));
    }
    handle.join().unwrap();
    shared
}
