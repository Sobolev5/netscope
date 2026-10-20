//! "Follow stream": the application bytes of a connection in conversation order.
//! TCP payloads are placed by sequence number, so retransmissions and overlaps
//! are dropped and holes (packets not captured or not kept) are reported.

use etherparse::TransportSlice;
use serde::Serialize;

use super::flows::{StoredPacket, L4};
use crate::decode::slice_frame;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Segment {
    /// Sent by the local machine.
    pub outbound: bool,
    pub ts_us: i64,
    /// Packets merged into this segment.
    pub packets: u32,
    /// Bytes missing right before this segment in its direction.
    pub gap_before: u64,
    #[serde(skip)]
    pub data: Vec<u8>,
}

/// Per-direction TCP sequence tracking with 32-bit sequence numbers unwrapped to a
/// 64-bit stream position, so reordering and streams beyond 4 GiB stay correct.
#[derive(Default)]
struct Dir {
    /// Last sequence number seen and its unwrapped position.
    last: Option<(u32, i64)>,
    /// Next expected stream position (`None` until the first byte is placed).
    next: Option<i64>,
}

impl Dir {
    /// Position of `seq`: the nearest one to the previous sequence number (±2 GiB).
    fn unwrap_seq(&mut self, seq: u32) -> i64 {
        match self.last {
            None => {
                self.last = Some((seq, 0));
                0
            }
            Some((prev, pos)) => {
                let p = pos + i64::from(seq.wrapping_sub(prev) as i32);
                if p > pos {
                    self.last = Some((seq, p));
                }
                p
            }
        }
    }

    /// Returns (new bytes, gap before them) for a segment starting at `seq`.
    fn place<'a>(&mut self, seq: u32, syn: bool, payload: &'a [u8]) -> (&'a [u8], u64) {
        // SYN consumes one sequence number before the first data byte.
        let data_seq = if syn { seq.wrapping_add(1) } else { seq };
        let start = self.unwrap_seq(data_seq);
        if payload.is_empty() {
            return (&[], 0);
        }
        let end = start + payload.len() as i64;
        let next = *self.next.get_or_insert(start);
        if end <= next {
            // Retransmission, or data from before the first byte we placed.
            return (&[], 0);
        }
        let (skip, gap) = if start < next { ((next - start) as usize, 0) } else { (0, (start - next) as u64) };
        self.next = Some(end);
        (&payload[skip..], gap)
    }
}

pub fn reassemble(lt: i32, l4: L4, packets: &[&StoredPacket]) -> Vec<Segment> {
    let mut out: Vec<Segment> = Vec::new();
    let (mut tx, mut rx) = (Dir::default(), Dir::default());
    for p in packets {
        let Some(s) = slice_frame(lt, &p.data) else { continue };
        let (data, gap): (Vec<u8>, u64) = match (&s.transport, l4) {
            (Some(TransportSlice::Tcp(t)), L4::Tcp) => {
                let dir = if p.outbound { &mut tx } else { &mut rx };
                let (d, gap) = dir.place(t.sequence_number(), t.syn(), t.payload());
                (d.to_vec(), gap)
            }
            (Some(TransportSlice::Udp(u)), L4::Udp) => (u.payload().to_vec(), 0),
            _ => continue,
        };
        if data.is_empty() {
            continue;
        }
        match out.last_mut() {
            Some(last) if last.outbound == p.outbound && gap == 0 && l4 == L4::Tcp => {
                last.data.extend_from_slice(&data);
                last.packets += 1;
            }
            _ => out.push(Segment { outbound: p.outbound, ts_us: p.ts_us, packets: 1, gap_before: gap, data }),
        }
    }
    out
}

/// Readable rendering: printable ASCII and valid UTF-8 kept, line breaks kept,
/// other bytes shown as `·`.
pub fn render_text(b: &[u8]) -> String {
    let lossy = String::from_utf8_lossy(b);
    lossy
        .chars()
        .map(|c| match c {
            '\n' | '\t' => c,
            '\r' => '\r',
            c if c.is_control() || c == char::REPLACEMENT_CHARACTER => '·',
            c => c,
        })
        .collect::<String>()
        .replace("\r\n", "\n")
        .replace('\r', "\n")
}

/// Share of bytes that render as readable text (0..1).
pub fn printable_ratio(b: &[u8]) -> f64 {
    if b.is_empty() {
        return 1.0;
    }
    let ok = b.iter().filter(|&&c| c == b'\n' || c == b'\r' || c == b'\t' || (0x20..0x7F).contains(&c)).count();
    ok as f64 / b.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::linktype;
    use crate::demo::frames::{tcp_frame_seq, udp_frame, TcpFlags};

    const A: [u8; 4] = [10, 0, 0, 2];
    const B: [u8; 4] = [1, 1, 1, 1];

    fn pkt(n: u64, outbound: bool, frame: Vec<u8>) -> StoredPacket {
        StoredPacket { n, ts_us: n as i64, outbound, wire_len: frame.len() as u32, data: frame.into() }
    }

    #[test]
    fn tcp_conversation_with_retransmission_overlap_and_gap() {
        let p = [
            pkt(1, true, tcp_frame_seq(A, B, 5000, 80, TcpFlags::Syn, 999, b"")),
            pkt(2, true, tcp_frame_seq(A, B, 5000, 80, TcpFlags::Data, 1000, b"GET / HTTP/1.1\r\n")),
            pkt(3, true, tcp_frame_seq(A, B, 5000, 80, TcpFlags::Data, 1000, b"GET / HTTP/1.1\r\n")),
            pkt(4, true, tcp_frame_seq(A, B, 5000, 80, TcpFlags::Data, 1010, b"/1.1\r\nHost: x\r\n\r\n")),
            pkt(5, false, tcp_frame_seq(B, A, 80, 5000, TcpFlags::Data, 7000, b"HTTP/1.1 200 OK\r\n")),
            pkt(6, false, tcp_frame_seq(B, A, 80, 5000, TcpFlags::Data, 7100, b"tail")),
        ];
        let refs: Vec<&StoredPacket> = p.iter().collect();
        let s = reassemble(linktype::ETHERNET, L4::Tcp, &refs);
        assert_eq!(s.len(), 3);
        assert_eq!(s[0].data, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(), "dup dropped, overlap trimmed");
        assert_eq!((s[0].outbound, s[0].packets), (true, 2));
        assert_eq!(s[1].data, b"HTTP/1.1 200 OK\r\n".to_vec());
        assert_eq!((s[2].gap_before, s[2].data.as_slice()), (83, &b"tail"[..]));
    }

    #[test]
    fn reordered_first_segment_does_not_break_the_stream() {
        // Seen order: 2000 "WORLD", 1995 "HELLO" (older), 2005 "-MORE-DATA".
        let p = [
            pkt(1, false, tcp_frame_seq(B, A, 80, 5000, TcpFlags::Data, 2000, b"WORLD")),
            pkt(2, false, tcp_frame_seq(B, A, 80, 5000, TcpFlags::Data, 1995, b"HELLO")),
            pkt(3, false, tcp_frame_seq(B, A, 80, 5000, TcpFlags::Data, 2005, b"-MORE-DATA")),
        ];
        let refs: Vec<&StoredPacket> = p.iter().collect();
        let s = reassemble(linktype::ETHERNET, L4::Tcp, &refs);
        assert_eq!(s.len(), 1);
        assert_eq!((s[0].data.as_slice(), s[0].gap_before), (&b"WORLD-MORE-DATA"[..], 0));
    }

    #[test]
    fn sequence_wrap_and_streams_beyond_4_gib() {
        let mut d = Dir::default();
        let near = u32::MAX - 2;
        assert_eq!(d.place(near, false, b"abcdef"), (&b"abcdef"[..], 0), "crosses 2^32");
        assert_eq!(d.place(3, false, b"gh"), (&b"gh"[..], 0));
        // Then jump 1 GiB forward five times: every jump is a 1 GiB gap of new data,
        // never mistaken for a retransmission after the 32-bit sequence wraps.
        let mut seq = 5u32;
        for _ in 0..5 {
            seq = seq.wrapping_add(1 << 30);
            assert_eq!(d.place(seq, false, b"x"), (&b"x"[..], 1u64 << 30));
            seq = seq.wrapping_add(1);
        }
        assert!(d.next.unwrap() > 5 << 30, "position beyond 4 GiB: {:?}", d.next);
    }

    #[test]
    fn udp_datagrams_stay_separate() {
        let p = [pkt(1, true, udp_frame(A, B, 1, 2, b"ping")), pkt(2, true, udp_frame(A, B, 1, 2, b"ping2"))];
        let refs: Vec<&StoredPacket> = p.iter().collect();
        let s = reassemble(linktype::ETHERNET, L4::Udp, &refs);
        assert_eq!(s.iter().map(|x| x.data.len()).collect::<Vec<_>>(), vec![4, 5]);
    }

    #[test]
    fn text_rendering() {
        assert_eq!(render_text(b"a\r\nb\x00c\xffd"), "a\nb·c·d");
        assert_eq!(render_text("привет".as_bytes()), "привет");
        assert!(printable_ratio(b"hello\r\n") > 0.99);
        assert!(printable_ratio(&[0u8, 1, 2, 200]) < 0.01);
        assert_eq!(render_text(b"old\rmac\tt\x1b[0m"), "old\nmac\tt·[0m", "lone CR is a line break, escape codes are dots");
        assert_eq!(render_text(b""), "");
        assert_eq!(printable_ratio(b""), 1.0);
        assert_eq!(printable_ratio(b"\t\n\r "), 1.0);
        assert_eq!(printable_ratio(&[0x7f, 0x20]), 0.5, "DEL is not printable");
    }

    #[test]
    fn placement_edge_cases() {
        let mut d = Dir::default();
        // A SYN with payload (TCP fast open): the data starts one past the SYN's number.
        assert_eq!(d.place(100, true, b"abc"), (&b"abc"[..], 0));
        assert_eq!(d.next, Some(3));
        assert_eq!(d.place(104, false, b"de"), (&b"de"[..], 0), "contiguous after the SYN");
        // Fully before what was placed: dropped; partially overlapping: trimmed.
        assert_eq!(d.place(101, false, b"xx"), (&[][..], 0));
        assert_eq!(d.place(105, false, b"EFG"), (&b"FG"[..], 0));
        // Empty payloads (pure ACKs) never move the cursor or create gaps.
        assert_eq!(d.place(9000, false, b""), (&[][..], 0));
        assert_eq!(d.next, Some(7));
        // A segment far ahead reports the hole before it.
        assert_eq!(d.place(1_108, false, b"Z"), (&b"Z"[..], 1000));
        // Far behind the current position (a retransmission of old data): dropped.
        assert_eq!(d.place(500, false, b"old"), (&[][..], 0));
        // Unwrapping: a backwards jump keeps the forward anchor.
        let mut u = Dir::default();
        assert_eq!(u.unwrap_seq(10), 0);
        assert_eq!(u.unwrap_seq(5), -5);
        assert_eq!(u.unwrap_seq(20), 10, "anchor stayed at 10, not at 5");
        assert_eq!(u.unwrap_seq(20u32.wrapping_sub(1 << 31)), 10 - (1i64 << 31), "half the space back is still 'behind'");
    }

    #[test]
    fn mixed_and_mutated_packets_never_panic() {
        let p = [
            pkt(1, true, tcp_frame_seq(A, B, 5000, 80, TcpFlags::Syn, 999, b"")),
            pkt(2, true, tcp_frame_seq(A, B, 5000, 80, TcpFlags::Data, 1000, b"GET / HTTP/1.1\r\n")),
            pkt(3, false, udp_frame(B, A, 80, 5000, b"not tcp")),
            pkt(4, false, tcp_frame_seq(B, A, 80, 5000, TcpFlags::Data, 7000, b"HTTP/1.1 200 OK\r\n")),
            pkt(5, false, vec![0u8; 3]),
            pkt(6, false, vec![]),
        ];
        let refs: Vec<&StoredPacket> = p.iter().collect();
        let s = reassemble(linktype::ETHERNET, L4::Tcp, &refs);
        assert_eq!(s.iter().map(|x| x.data.len()).collect::<Vec<_>>(), vec![16, 17], "UDP and junk frames are skipped in a TCP flow");
        let s = reassemble(linktype::ETHERNET, L4::Udp, &refs);
        assert_eq!(s.iter().map(|x| x.data.len()).collect::<Vec<_>>(), vec![7]);
        assert!(reassemble(linktype::ETHERNET, L4::Icmp, &refs).is_empty());
        assert!(reassemble(9999, L4::Tcp, &refs).is_empty(), "unknown link type");
        let mut seed = 0x8badf00d_u64;
        let mut rnd = move || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 33) as usize
        };
        for _ in 0..1500 {
            let mut m: Vec<StoredPacket> = p.to_vec();
            for q in m.iter_mut().filter(|q| !q.data.is_empty()) {
                let mut d = q.data.to_vec();
                for _ in 0..1 + rnd() % 3 {
                    let i = rnd() % d.len();
                    d[i] = rnd() as u8;
                }
                q.data = d.into();
                q.outbound = rnd() % 2 == 0;
            }
            let refs: Vec<&StoredPacket> = m.iter().collect();
            for l4 in [L4::Tcp, L4::Udp] {
                for s in reassemble(linktype::ETHERNET, l4, &refs) {
                    assert!(!s.data.is_empty() && s.packets >= 1);
                    let _ = render_text(&s.data);
                }
            }
        }
    }
}
