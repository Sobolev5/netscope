//! Thread-safe traffic analytics: the capture thread writes, the web layer reads.

pub mod addr;
pub mod anomaly;
pub mod dnslog;
pub mod filter;
pub mod flows;
pub mod novelty;
pub mod persist;
mod snapshot;
mod state;
pub mod stream;
pub mod views;

use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

pub use anomaly::{Alert, AlertCounts, AlertKind, Severity};
pub use persist::{NoveltyBaseline, Persisted, WatchEntry};
pub use snapshot::{DnsView, HostView, ProtoView, Rates, Snapshot};
pub use state::{CaptureInfo, CaptureStatus, Config, Counter, Host, NameSource, Named, Sample, State, Totals};

/// `Arc<RwLock<State>>` that shrugs off poisoning: a panic in one reader must not
/// take the dashboard down, and the state stays internally consistent per call.
#[derive(Clone)]
pub struct SharedState(Arc<RwLock<State>>);

impl SharedState {
    pub fn new(state: State) -> Self {
        Self(Arc::new(RwLock::new(state)))
    }

    pub fn read(&self) -> RwLockReadGuard<'_, State> {
        self.0.read().unwrap_or_else(|e| e.into_inner())
    }

    pub fn write(&self) -> RwLockWriteGuard<'_, State> {
        self.0.write().unwrap_or_else(|e| e.into_inner())
    }
}
