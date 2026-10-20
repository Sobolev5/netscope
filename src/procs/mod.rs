//! Which process owns a connection: periodic snapshots of the OS socket table
//! (socket → PID) and process list (PID → name, path, parent).
//!
//! * Windows: `GetExtendedTcpTable` / `GetExtendedUdpTable` + Toolhelp
//! * Linux: `/proc/net/{tcp,tcp6,udp,udp6}` + `/proc/<pid>/fd` socket inodes
//! * macOS: `lsof -nP -i -F`
//!
//! Connections that open and close between two snapshots cannot be attributed;
//! the refresher therefore also runs early when a new unattributed TCP flow shows up.

mod linux;
mod macos;
pub mod signature;
#[cfg(windows)]
mod windows;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::analytics::SharedState;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SockProto {
    Tcp,
    Udp,
}

/// One row of the OS socket table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SocketEntry {
    pub proto: SockProto,
    pub local: SocketAddr,
    /// `None` for listening TCP sockets and for UDP.
    pub remote: Option<SocketAddr>,
    /// TCP state as the OS reports it (`ESTABLISHED`, `LISTEN`, ...).
    pub state: Option<&'static str>,
    pub pid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcInfo {
    pub pid: u32,
    /// Executable name, e.g. `Code.exe`.
    pub name: String,
    /// Full executable path when the OS lets us read it.
    pub path: Option<String>,
    pub parent: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct OsSnapshot {
    pub sockets: Vec<SocketEntry>,
    pub procs: HashMap<u32, ProcInfo>,
    /// Why the snapshot is empty or partial (unsupported OS, missing permissions...).
    pub error: Option<String>,
}

/// Produces snapshots; the OS implementation or the demo generator.
pub trait OwnerSource: Send {
    fn snapshot(&mut self) -> OsSnapshot;
}

/// The running system.
#[derive(Default)]
pub struct OsOwners {
    #[cfg(windows)]
    paths: windows::PathCache,
}

impl OwnerSource for OsOwners {
    fn snapshot(&mut self) -> OsSnapshot {
        #[cfg(windows)]
        {
            windows::snapshot(&mut self.paths)
        }
        #[cfg(target_os = "linux")]
        {
            linux::snapshot()
        }
        #[cfg(target_os = "macos")]
        {
            macos::snapshot()
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            OsSnapshot { error: Some("process attribution is not supported on this OS".into()), ..OsSnapshot::default() }
        }
    }
}

/// Lookup structure built from one snapshot.
#[derive(Debug, Default)]
pub struct OwnerIndex {
    snap: OsSnapshot,
    exact: HashMap<(SockProto, SocketAddr, SocketAddr), u32>,
    bound: HashMap<(SockProto, SocketAddr), u32>,
    by_port: HashMap<(SockProto, u16), u32>,
}

/// Dual-stack sockets report IPv4 peers as `::ffff:a.b.c.d`; compare them as IPv4.
pub(crate) fn unmap(a: SocketAddr) -> SocketAddr {
    match a {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
            None => a,
        },
        v4 => v4,
    }
}

impl OwnerIndex {
    pub fn new(snap: OsSnapshot) -> Self {
        let mut idx = OwnerIndex { snap: OsSnapshot::default(), ..Default::default() };
        for s in &snap.sockets {
            // PID 0 is "System Idle"/unknown (e.g. TIME_WAIT); it owns nothing useful.
            if s.pid == 0 {
                continue;
            }
            let local = unmap(s.local);
            if let Some(r) = s.remote.map(unmap).filter(|r| !r.ip().is_unspecified()) {
                idx.exact.insert((s.proto, local, r), s.pid);
            }
            idx.bound.entry((s.proto, local)).or_insert(s.pid);
            idx.by_port.entry((s.proto, local.port())).or_insert(s.pid);
        }
        idx.snap = snap;
        idx
    }

    /// PID owning the local end of a connection, most specific match first.
    pub fn lookup_pid(&self, proto: SockProto, local: SocketAddr, remote: SocketAddr) -> Option<u32> {
        let (local, remote) = (unmap(local), unmap(remote));
        let any = |ip: IpAddr| match ip {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        self.exact
            .get(&(proto, local, remote))
            .or_else(|| self.bound.get(&(proto, local)))
            .or_else(|| self.bound.get(&(proto, SocketAddr::new(any(local.ip()), local.port()))))
            .or_else(|| self.by_port.get(&(proto, local.port())))
            .copied()
    }

    pub fn lookup(&self, proto: SockProto, local: SocketAddr, remote: SocketAddr) -> Option<ProcInfo> {
        self.lookup_pid(proto, local, remote).map(|pid| self.process_or_placeholder(pid))
    }

    pub fn process(&self, pid: u32) -> Option<&ProcInfo> {
        self.snap.procs.get(&pid)
    }

    pub fn process_or_placeholder(&self, pid: u32) -> ProcInfo {
        self.process(pid).cloned().unwrap_or(ProcInfo { pid, name: format!("pid {pid}"), path: None, parent: None })
    }

    pub fn sockets(&self) -> &[SocketEntry] {
        &self.snap.sockets
    }

    pub fn error(&self) -> Option<&str> {
        self.snap.error.as_deref()
    }
}

const REFRESH_EVERY: Duration = Duration::from_millis(1000);
const REFRESH_MIN_GAP: Duration = Duration::from_millis(150);

/// Keeps `State`'s owner index fresh until `stop` is set.
pub fn spawn_refresher(
    mut source: Box<dyn OwnerSource>,
    shared: SharedState,
    stop: Arc<AtomicBool>,
) -> std::io::Result<JoinHandle<()>> {
    thread::Builder::new().name("owners".into()).spawn(move || {
        let mut last = Instant::now() - REFRESH_EVERY;
        let mut warned = false;
        while !stop.load(Ordering::Relaxed) {
            let due = last.elapsed() >= REFRESH_EVERY;
            let wanted = last.elapsed() >= REFRESH_MIN_GAP && shared.read().wants_owner_refresh();
            if due || wanted {
                let snap = source.snapshot();
                if let (Some(e), false) = (&snap.error, warned) {
                    tracing::warn!("process attribution limited: {e}");
                    warned = true;
                }
                shared.write().set_owners(Arc::new(OwnerIndex::new(snap)));
                last = Instant::now();
            }
            thread::sleep(Duration::from_millis(50));
        }
    })
}

pub fn tcp_state_name(code: u32) -> &'static str {
    match code {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn entry(proto: SockProto, local: &str, remote: Option<&str>, pid: u32) -> SocketEntry {
        SocketEntry { proto, local: sa(local), remote: remote.map(sa), state: None, pid }
    }

    #[test]
    fn lookup_prefers_exact_then_bound_then_wildcard() {
        let mut procs = HashMap::new();
        procs.insert(10, ProcInfo { pid: 10, name: "Code.exe".into(), path: None, parent: Some(1) });
        let snap = OsSnapshot {
            sockets: vec![
                entry(SockProto::Tcp, "10.0.0.2:5000", Some("1.1.1.1:443"), 10),
                entry(SockProto::Tcp, "10.0.0.2:5000", Some("8.8.8.8:443"), 11),
                entry(SockProto::Udp, "0.0.0.0:5353", None, 12),
                entry(SockProto::Udp, "[::]:6000", None, 13),
                entry(SockProto::Tcp, "10.0.0.2:6001", Some("9.9.9.9:80"), 0),
            ],
            procs,
            error: None,
        };
        let idx = OwnerIndex::new(snap);
        assert_eq!(idx.lookup_pid(SockProto::Tcp, sa("10.0.0.2:5000"), sa("8.8.8.8:443")), Some(11));
        assert_eq!(idx.lookup(SockProto::Tcp, sa("10.0.0.2:5000"), sa("1.1.1.1:443")).unwrap().name, "Code.exe");
        assert_eq!(idx.lookup_pid(SockProto::Udp, sa("10.0.0.2:5353"), sa("224.0.0.251:5353")), Some(12), "wildcard bind");
        assert_eq!(idx.lookup_pid(SockProto::Udp, sa("10.0.0.2:6000"), sa("1.2.3.4:1")), Some(13), "v6 wildcard by port");
        assert_eq!(idx.lookup_pid(SockProto::Tcp, sa("10.0.0.2:6001"), sa("9.9.9.9:80")), None, "pid 0 ignored");
        assert_eq!(idx.lookup(SockProto::Tcp, sa("10.0.0.2:5000"), sa("8.8.8.8:443")).unwrap().name, "pid 11");
    }

    #[test]
    fn ipv4_mapped_addresses_match() {
        let snap = OsSnapshot {
            sockets: vec![entry(SockProto::Tcp, "[::ffff:10.0.0.2]:7000", Some("[::ffff:1.2.3.4]:443"), 42)],
            ..OsSnapshot::default()
        };
        let idx = OwnerIndex::new(snap);
        assert_eq!(idx.lookup_pid(SockProto::Tcp, sa("10.0.0.2:7000"), sa("1.2.3.4:443")), Some(42));
    }

    #[test]
    fn state_names() {
        assert_eq!(tcp_state_name(5), "ESTABLISHED");
        assert_eq!(tcp_state_name(99), "UNKNOWN");
    }

    #[test]
    fn os_snapshot_runs() {
        // Smoke test against the real OS: must not panic; on Windows/Linux/macOS our
        // own test process is not required to own sockets, but the process list exists.
        let snap = OsOwners::default().snapshot();
        if cfg!(any(windows, target_os = "linux")) {
            assert!(snap.procs.contains_key(&std::process::id()), "own process missing; error: {:?}", snap.error);
        }
    }
}
