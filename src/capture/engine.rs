//! The capture thread: pulls packets from a source, decodes them outside the lock and
//! records them into the shared state.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::{Next, PacketSource};
use crate::analytics::{CaptureStatus, SharedState};
use crate::decode::decode;

pub fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// How a finite source (file) is replayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pacing {
    /// As fast as possible.
    Fast,
    /// Sleep to reproduce the original gaps between packets (each capped at 1 s).
    Realtime,
}

/// Runs the capture loop on its own OS thread until the source ends, fails or `stop` is set.
pub fn spawn(
    mut source: Box<dyn PacketSource>,
    state: SharedState,
    stop: Arc<AtomicBool>,
    pacing: Pacing,
) -> std::io::Result<JoinHandle<()>> {
    thread::Builder::new().name("capture".into()).spawn(move || {
        state.write().set_status(CaptureStatus::Running);
        let status = run(source.as_mut(), &state, &stop, pacing);
        if let CaptureStatus::Failed(e) = &status {
            tracing::error!("capture stopped: {e}");
        } else {
            tracing::info!("capture finished");
        }
        state.write().set_status(status);
    })
}

fn run(source: &mut dyn PacketSource, state: &SharedState, stop: &AtomicBool, pacing: Pacing) -> CaptureStatus {
    let linktype = source.linktype();
    let live = source.is_live();
    state.write().linktype = linktype;
    let mut clock: Option<(i64, Instant)> = None;
    let mut packets: u64 = 0;
    loop {
        if stop.load(Ordering::Relaxed) {
            return CaptureStatus::Finished;
        }
        match source.next_packet() {
            Ok(Next::Packet(p)) => {
                if pacing == Pacing::Realtime && !live {
                    let (first_ts, started) = *clock.get_or_insert((p.ts_us, Instant::now()));
                    let due = Duration::from_micros(p.ts_us.saturating_sub(first_ts).max(0) as u64);
                    let wait = due.saturating_sub(started.elapsed()).min(Duration::from_secs(1));
                    if !wait.is_zero() {
                        thread::sleep(wait);
                    }
                    if wait == Duration::from_secs(1) {
                        // Collapse long idle gaps instead of replaying them.
                        clock = Some((p.ts_us, Instant::now()));
                    }
                }
                let info = decode(linktype, p.data);
                state.write().record_frame(p.ts_us, p.wire_len, p.data, info.as_ref());
                packets += 1;
            }
            Ok(Next::Timeout) => {
                if live {
                    state.write().advance(unix_now());
                }
            }
            Ok(Next::End) => {
                state.write().finish();
                tracing::info!("end of capture after {packets} packets");
                return CaptureStatus::Finished;
            }
            Err(e) => return CaptureStatus::Failed(e.to_string()),
        }
    }
}
