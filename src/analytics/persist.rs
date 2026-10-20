//! What survives a restart: the watched routes and the novelty baseline, as one JSON file.
//! Without it an installed program would re-learn "normal" on every start and greet old
//! friends as new programs, domains and countries.

use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::SharedState;

/// Bumped when the layout changes incompatibly; other versions are refused, not guessed at.
pub const VERSION: u32 = 1;
/// The state-saver thread writes at most this often.
pub const SAVE_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct Persisted {
    pub version: u32,
    /// Unix seconds.
    pub saved_at: i64,
    #[serde(default)]
    pub watch: Vec<WatchEntry>,
    #[serde(default)]
    pub novelty: NoveltyBaseline,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatchEntry {
    pub ip: IpAddr,
    pub label: Option<String>,
}

/// Everything `Novelty` needs to resume without a learning period. A baseline never
/// expires: what was normal a month ago is still a better reference than nothing, and
/// an entry for a program long uninstalled costs a few bytes.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NoveltyBaseline {
    /// End of the learning period of the first run ever (unix µs); `None` before any flow.
    pub learn_until_us: Option<i64>,
    /// A usable listener table was seen, so the next one is compared, not recorded.
    pub listeners_known: bool,
    pub processes: Vec<String>,
    /// (process, registrable domain or provider)
    pub destinations: Vec<(String, String)>,
    /// (process, country code)
    pub countries: Vec<(String, String)>,
    /// (process, port)
    pub listeners: Vec<(String, u16)>,
}

impl Persisted {
    /// Equal apart from the save time: what decides whether a write is worth it.
    pub fn same_content(&self, other: &Self) -> bool {
        self.watch == other.watch && self.novelty == other.novelty
    }
}

/// `Ok(None)` when there is no file yet; anything unreadable is an error naming the file.
pub fn load(path: &Path) -> Result<Option<Persisted>, String> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let p: Persisted = serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    if p.version != VERSION {
        return Err(format!("{}: state version {} is not supported (this build writes version {VERSION})", path.display(), p.version));
    }
    Ok(Some(p))
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

/// Writes `<path>.tmp` and renames it over `path`, so a crash mid-write leaves the old
/// state intact; the parent directory is created on the way.
pub fn save(path: &Path, p: &Persisted) -> Result<(), String> {
    let ctx = |e: io::Error| format!("{}: {e}", path.display());
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir).map_err(ctx)?;
    }
    let json = serde_json::to_vec(p).map_err(|e| format!("{}: {e}", path.display()))?;
    let tmp = tmp_path(path);
    fs::write(&tmp, json).and_then(|()| fs::rename(&tmp, path)).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        ctx(e)
    })
}

/// Saves `shared` to `path` every `interval` when it changed since `last` (what was loaded,
/// or `None`), and once more when `stop` is set, so the caller decides when the final
/// write happens (after the capture thread is gone) and joins this thread to wait for it.
pub fn spawn_saver(shared: SharedState, path: PathBuf, stop: Arc<AtomicBool>, mut last: Option<Persisted>, interval: Duration) -> io::Result<JoinHandle<()>> {
    thread::Builder::new().name("state-saver".into()).spawn(move || {
        let mut next = Instant::now() + interval;
        loop {
            let stopping = stop.load(Ordering::Relaxed);
            if stopping || Instant::now() >= next {
                let p = shared.read().persisted();
                if !matches!(&last, Some(l) if l.same_content(&p)) {
                    match save(&path, &p) {
                        Ok(()) => {
                            tracing::debug!("state saved: {} watched routes, {} known programs", p.watch.len(), p.novelty.processes.len());
                            last = Some(p);
                        }
                        Err(e) => tracing::warn!("cannot save the state: {e}"),
                    }
                }
                next = Instant::now() + interval;
            }
            if stopping {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("netscope-persist-{}-{name}", std::process::id()))
    }

    fn sample() -> Persisted {
        Persisted {
            version: VERSION,
            saved_at: 1_760_000_000,
            watch: vec![
                WatchEntry { ip: "203.0.113.9".parse().unwrap(), label: Some("example".into()) },
                WatchEntry { ip: "2001:db8::1".parse().unwrap(), label: None },
            ],
            novelty: NoveltyBaseline {
                learn_until_us: Some(1_760_000_060_000_000),
                listeners_known: true,
                processes: vec!["chrome.exe".into()],
                destinations: vec![("chrome.exe".into(), "google.com".into())],
                countries: vec![("chrome.exe".into(), "US".into())],
                listeners: vec![("nginx.exe".into(), 80)],
            },
        }
    }

    #[test]
    fn round_trip_creates_the_directory_and_leaves_no_tmp_file() {
        let dir = temp("rt");
        let path = dir.join("deeper").join("state.json");
        assert_eq!(load(&path), Ok(None), "no file is not an error");
        let p = sample();
        save(&path, &p).unwrap();
        assert!(!tmp_path(&path).exists(), "the temporary file was renamed away");
        assert_eq!(load(&path), Ok(Some(p.clone())));
        // Overwriting works too (rename over an existing file).
        let mut p2 = p.clone();
        p2.watch.pop();
        p2.saved_at += 1;
        save(&path, &p2).unwrap();
        assert_eq!(load(&path).unwrap().unwrap().watch.len(), 1);
        assert!(!p.same_content(&p2) && p.same_content(&Persisted { saved_at: 0, ..p.clone() }));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupt_and_foreign_versions_are_errors_naming_the_file() {
        let path = temp("corrupt.json");
        std::fs::write(&path, b"{ not json").unwrap();
        let e = load(&path).unwrap_err();
        assert!(e.contains("corrupt.json"), "{e}");
        std::fs::write(&path, serde_json::to_vec(&Persisted { version: 99, ..sample() }).unwrap()).unwrap();
        let e = load(&path).unwrap_err();
        assert!(e.contains("version 99") && e.contains("corrupt.json"), "{e}");
        // Missing optional sections default (a file from a smaller older layout still loads).
        std::fs::write(&path, br#"{"version":1,"saved_at":5}"#).unwrap();
        assert_eq!(load(&path), Ok(Some(Persisted { version: 1, saved_at: 5, ..Persisted::default() })));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn save_into_an_impossible_place_fails_cleanly() {
        // A file where the parent directory should be.
        let blocker = temp("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let path = blocker.join("state.json");
        let e = save(&path, &sample()).unwrap_err();
        assert!(e.contains("state.json"), "{e}");
        assert!(!tmp_path(&path).exists());
        std::fs::remove_file(&blocker).ok();
    }

    #[test]
    fn saver_writes_on_change_and_on_stop() {
        use crate::analytics::{CaptureInfo, CaptureStatus, Config, State};
        let path = temp("saver").join("state.json");
        let info = CaptureInfo { mode: "live", source: "t".into(), description: None, filter: None, libpcap: None, status: CaptureStatus::Running };
        let shared = SharedState::new(State::new(Config::default(), Default::default(), info));
        let stop = Arc::new(AtomicBool::new(false));
        // Starting from the loaded value: an unchanged state is never rewritten.
        let last = shared.read().persisted();
        let h = spawn_saver(shared.clone(), path.clone(), stop.clone(), Some(last), Duration::from_millis(50)).unwrap();
        thread::sleep(Duration::from_millis(250));
        assert!(!path.exists(), "nothing changed, nothing written");
        shared.write().routes.add("203.0.113.1".parse().unwrap(), Some("a".into()), 0);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !path.exists() {
            assert!(Instant::now() < deadline, "periodic save did not happen");
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(load(&path).unwrap().unwrap().watch.len(), 1);
        shared.write().routes.add("203.0.113.2".parse().unwrap(), None, 0);
        stop.store(true, Ordering::Relaxed);
        h.join().unwrap();
        assert_eq!(load(&path).unwrap().unwrap().watch.len(), 2, "the final save on stop carries the last change");
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }
}
