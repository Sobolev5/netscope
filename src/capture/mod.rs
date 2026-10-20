//! Packet sources: live interfaces and pcap/pcapng files via runtime-loaded libpcap,
//! classic `.pcap` files via a built-in reader, and the synthetic demo generator.

pub mod engine;
mod error;
mod ffi;
pub mod file;
pub mod live;

pub use error::{install_hint, permission_hint, CaptureError};

/// Latest timestamp accepted from a capture (year 3000): a crafted file with a huge
/// `tv_sec` must neither overflow the microsecond arithmetic nor break the clock.
pub const MAX_TS_US: i64 = 32_503_680_000 * 1_000_000;

/// Unix microseconds from a capture header's seconds and sub-second part, clamped to `0..=MAX_TS_US`.
pub fn timestamp_us(sec: i64, frac_us: i64) -> i64 {
    sec.saturating_mul(1_000_000).saturating_add(frac_us).clamp(0, MAX_TS_US)
}

/// One captured frame, borrowed from the source until the next call.
pub struct Packet<'a> {
    /// Capture timestamp, microseconds since the Unix epoch.
    pub ts_us: i64,
    /// Original length on the wire (may exceed `data.len()` when truncated by snaplen).
    pub wire_len: u32,
    pub data: &'a [u8],
}

pub enum Next<'a> {
    Packet(Packet<'a>),
    /// No packet within the read timeout (live sources only).
    Timeout,
    /// The source is exhausted.
    End,
}

pub trait PacketSource: Send {
    fn next_packet(&mut self) -> Result<Next<'_>, CaptureError>;
    /// pcap link-layer type of every frame this source returns.
    fn linktype(&self) -> i32;
    /// Live sources produce wall-clock timestamps and never end on their own.
    fn is_live(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_never_overflow() {
        assert_eq!(timestamp_us(1_760_000_000, 123_456), 1_760_000_000_123_456);
        assert_eq!(timestamp_us(i64::MAX, 999_999), MAX_TS_US);
        assert_eq!(timestamp_us(u32::MAX as i64, 0), u32::MAX as i64 * 1_000_000, "a classic pcap's largest second fits");
        assert_eq!(timestamp_us(i64::MIN, 0), 0);
        assert_eq!(timestamp_us(-1, 0), 0);
    }
}
