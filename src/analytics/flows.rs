//! Connections ("flows"): one per (transport, local socket, remote socket), with TCP
//! state, the owning process and a ring of the latest raw packets for inspection.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;

use serde::Serialize;

use crate::decode::{App, PacketInfo, Proto, TcpMeta, TlsHello, Transport};
use crate::procs::{ProcInfo, SockProto};

/// The first packets of every connection are always kept (handshakes, TLS certificates).
pub const HEAD: usize = 32;
/// Most recent packets kept per connection, after the head.
pub const RING: usize = 200;
/// Bytes kept per packet (covers full-size and most offloaded frames).
pub const SNAP_BYTES: usize = 16 * 1024;
/// All stored packet bytes together; the least recently active rings are dropped beyond it.
pub const BUDGET: usize = 96 << 20;
/// Attribution retries (one per owner refresh) before a flow is considered foreign.
const MAX_TRIES: u8 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum L4 {
    Tcp,
    Udp,
    Icmp,
    Other,
}

impl L4 {
    pub fn sock(self) -> Option<SockProto> {
        match self {
            L4::Tcp => Some(SockProto::Tcp),
            L4::Udp => Some(SockProto::Udp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub l4: L4,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowState {
    /// SYN seen, handshake not finished.
    Opening,
    Established,
    /// One side sent FIN.
    Closing,
    /// Both FINs or a RST.
    Closed,
    /// Connectionless traffic (UDP, ICMP).
    Active,
}

#[derive(Debug, Clone)]
pub struct StoredPacket {
    /// Sequence number of the packet within the flow, starting at 1.
    pub n: u64,
    pub ts_us: i64,
    pub outbound: bool,
    pub wire_len: u32,
    pub data: Box<[u8]>,
}

#[derive(Debug, Clone)]
pub struct Flow {
    pub id: u64,
    pub key: FlowKey,
    pub app: Proto,
    pub name: Option<String>,
    pub first_us: i64,
    pub last_us: i64,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub packets_out: u64,
    pub packets_in: u64,
    pub state: FlowState,
    /// `Some(true)` when our side sent the opening SYN.
    pub initiated_locally: Option<bool>,
    fin_out: bool,
    fin_in: bool,
    pub process: Option<ProcInfo>,
    head: Vec<StoredPacket>,
    ring: VecDeque<StoredPacket>,
    /// Routers between us and the peer, estimated from received TTLs.
    pub hops: Option<u8>,
    /// The client's TLS hello (SNI, ALPN, JA4) if one was captured.
    pub tls: Option<TlsHello>,
    /// TCP handshake round trip: SYN → SYN-ACK (outgoing) or SYN-ACK → ACK (incoming).
    pub rtt_us: Option<u32>,
    /// Data segments that did not advance the sequence (retransmissions; also late out-of-order ones).
    pub retrans_out: u32,
    pub retrans_in: u32,
    /// Segments advertising a zero receive window (a side cannot keep up).
    pub zero_window: u32,
    /// Written to the journal already (a connection is journaled once).
    pub journaled: bool,
    syn_us: Option<i64>,
    synack_us: Option<i64>,
    high_out: Option<u32>,
    high_in: Option<u32>,
    tries: u8,
    next_n: u64,
}

impl Flow {
    pub fn total(&self) -> u64 {
        self.bytes_in + self.bytes_out
    }

    /// Whether more owner refreshes may still find the process.
    pub fn awaiting_owner(&self) -> bool {
        self.process.is_none() && self.tries < MAX_TRIES && self.key.l4.sock().is_some()
    }

    /// Stored packets in order: the head, then the most recent ones.
    pub fn stored(&self) -> impl Iterator<Item = &StoredPacket> {
        self.head.iter().chain(self.ring.iter())
    }

    pub fn stored_count(&self) -> usize {
        self.head.len() + self.ring.len()
    }

    /// Whether the very first packet is still stored (handshakes can be read).
    pub fn has_beginning(&self) -> bool {
        self.head.first().is_some_and(|p| p.n == 1)
    }

    pub fn packet(&self, n: u64) -> Option<&StoredPacket> {
        if let Some(p) = self.head.iter().find(|p| p.n == n) {
            return Some(p);
        }
        // Ring numbers are increasing but not contiguous (frames without bytes are not stored).
        let i = self.ring.binary_search_by_key(&n, |p| p.n).ok()?;
        self.ring.get(i)
    }

    /// Packets seen but no longer stored (between head and ring, or dropped for memory).
    pub fn dropped_packets(&self) -> u64 {
        (self.packets_in + self.packets_out).saturating_sub(self.stored_count() as u64)
    }

    fn stored_bytes(&self) -> usize {
        self.stored().map(|p| p.data.len()).sum()
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ProcStats {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets: u64,
    pub connections: u64,
    pub first_us: i64,
    pub last_us: i64,
}

pub struct FlowTable {
    flows: HashMap<FlowKey, Flow>,
    by_id: HashMap<u64, FlowKey>,
    next_id: u64,
    cap: usize,
    stored: usize,
}

/// A flow that just got its owning process, with the traffic it carried so far.
pub struct Attributed {
    pub id: u64,
    pub process: ProcInfo,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets: u64,
    pub first_us: i64,
    pub last_us: i64,
}

/// What happened to a flow during `observe`, for the caller's bookkeeping.
pub struct Observed {
    pub id: u64,
    pub created: bool,
    pub process: Option<u32>,
    /// The flow got a name (SNI/Host/DNS question) with this packet.
    pub named: bool,
    pub rtt_us: Option<u32>,
    /// This packet closed the connection (both FINs or a RST).
    pub closed: bool,
}

impl FlowTable {
    pub fn new(cap: usize) -> Self {
        Self { flows: HashMap::new(), by_id: HashMap::new(), next_id: 1, cap, stored: 0 }
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Flow> {
        self.flows.values()
    }

    pub fn get(&self, id: u64) -> Option<&Flow> {
        self.by_id.get(&id).and_then(|k| self.flows.get(k))
    }

    pub fn get_mut(&mut self, id: u64) -> Option<&mut Flow> {
        let k = *self.by_id.get(&id)?;
        self.flows.get_mut(&k)
    }

    pub fn stored_bytes(&self) -> usize {
        self.stored
    }

    #[allow(clippy::too_many_arguments)]
    pub fn observe(
        &mut self,
        key: FlowKey,
        ts_us: i64,
        outbound: bool,
        wire_len: u32,
        frame: &[u8],
        info: &PacketInfo,
        lookup: impl FnOnce(&FlowKey) -> Option<ProcInfo>,
    ) -> Observed {
        let created = !self.flows.contains_key(&key);
        if created {
            let id = self.next_id;
            self.next_id += 1;
            self.by_id.insert(id, key);
            let process = lookup(&key);
            self.flows.insert(
                key,
                Flow {
                    id,
                    key,
                    app: info.proto,
                    name: None,
                    first_us: ts_us,
                    last_us: ts_us,
                    bytes_out: 0,
                    bytes_in: 0,
                    packets_out: 0,
                    packets_in: 0,
                    state: if key.l4 == L4::Tcp { FlowState::Established } else { FlowState::Active },
                    initiated_locally: None,
                    fin_out: false,
                    fin_in: false,
                    hops: None,
                    tls: None,
                    rtt_us: None,
                    retrans_out: 0,
                    retrans_in: 0,
                    zero_window: 0,
                    journaled: false,
                    syn_us: None,
                    synack_us: None,
                    high_out: None,
                    high_in: None,
                    tries: u8::from(process.is_none()),
                    process,
                    head: Vec::new(),
                    ring: VecDeque::new(),
                    next_n: 1,
                },
            );
        }
        let f = self.flows.get_mut(&key).expect("inserted above");
        f.last_us = f.last_us.max(ts_us);
        if outbound {
            f.bytes_out += wire_len as u64;
            f.packets_out += 1;
        } else {
            f.bytes_in += wire_len as u64;
            f.packets_in += 1;
        }
        if !outbound {
            f.hops = Some(super::state::estimate_hops(info.ttl));
        }
        if matches!(info.proto, Proto::Http | Proto::Tls | Proto::Dns | Proto::Quic) {
            f.app = info.proto;
        }
        let had_name = f.name.is_some();
        let was_closed = f.state == FlowState::Closed;
        match &info.app {
            App::TlsHello(h) => {
                if let Some(sni) = &h.sni {
                    f.name = Some(sni.clone());
                }
                f.tls = Some((**h).clone());
            }
            App::Http(req) => {
                if let Some(h) = &req.host {
                    f.name = Some(h.clone());
                }
            }
            App::Dns(m) => {
                if let Some(q) = m.questions.first() {
                    f.name = Some(q.name.clone());
                }
            }
            App::None => {}
        }
        if let Transport::Tcp { syn, ack, fin, rst } = info.transport {
            if rst {
                f.state = FlowState::Closed;
            } else if syn {
                if f.initiated_locally.is_none() {
                    // SYN comes from the client; SYN-ACK from the server.
                    f.initiated_locally = Some(if ack { !outbound } else { outbound });
                }
                if f.state != FlowState::Closed {
                    f.state = FlowState::Opening;
                }
            } else if fin {
                if outbound {
                    f.fin_out = true;
                } else {
                    f.fin_in = true;
                }
                f.state = if f.fin_in && f.fin_out { FlowState::Closed } else { FlowState::Closing };
            } else if f.state == FlowState::Opening {
                f.state = FlowState::Established;
            }
            if let Some(m) = info.tcp {
                track_quality(f, ts_us, outbound, (syn, ack, fin, rst), m);
            }
        }

        if !frame.is_empty() {
            let data: Box<[u8]> = frame[..frame.len().min(SNAP_BYTES)].into();
            self.stored += data.len();
            let p = StoredPacket { n: f.next_n, ts_us, outbound, wire_len, data };
            // The head holds packets 1..=HEAD, i.e. the opening of the connection.
            if f.next_n <= HEAD as u64 {
                f.head.push(p);
            } else {
                f.ring.push_back(p);
                if f.ring.len() > RING {
                    if let Some(old) = f.ring.pop_front() {
                        self.stored -= old.data.len();
                    }
                }
            }
        }
        f.next_n += 1;
        Observed {
            id: f.id,
            created,
            process: f.process.as_ref().map(|p| p.pid),
            named: !had_name && f.name.is_some(),
            rtt_us: f.rtt_us,
            closed: !was_closed && f.state == FlowState::Closed,
        }
    }


    /// Tries to attribute flows still missing a process; returns the newly attributed ones.
    pub fn attribute(&mut self, lookup: impl Fn(&FlowKey) -> Option<ProcInfo>) -> Vec<Attributed> {
        let mut found = Vec::new();
        for f in self.flows.values_mut().filter(|f| f.awaiting_owner()) {
            f.tries += 1;
            if let Some(p) = lookup(&f.key) {
                found.push(Attributed {
                    id: f.id,
                    process: p.clone(),
                    bytes_in: f.bytes_in,
                    bytes_out: f.bytes_out,
                    packets: f.packets_in + f.packets_out,
                    first_us: f.first_us,
                    last_us: f.last_us,
                });
                f.process = Some(p);
            }
        }
        found
    }

    /// Whether `evict` has work to do (checked per packet, so limits hold even when
    /// timestamps do not advance, e.g. a capture file with constant times).
    pub fn over_limits(&self) -> bool {
        self.flows.len() > self.cap + self.cap / 10 || self.stored > BUDGET
    }

    /// Keeps the table and the packet store within limits, dropping least recent first.
    /// Returns the connections removed from the table (for the journal).
    pub fn evict(&mut self) -> Vec<Flow> {
        let mut removed = Vec::new();
        if self.flows.len() > self.cap {
            let mut by_age: Vec<(i64, FlowKey)> = self.flows.values().map(|f| (f.last_us, f.key)).collect();
            by_age.sort_unstable_by_key(|x| x.0);
            let remove = self.flows.len() - self.cap * 9 / 10;
            for (_, k) in by_age.into_iter().take(remove) {
                if let Some(f) = self.flows.remove(&k) {
                    self.by_id.remove(&f.id);
                    self.stored -= f.stored_bytes();
                    removed.push(f);
                }
            }
        }
        if self.stored > BUDGET {
            let mut by_age: Vec<(i64, FlowKey)> =
                self.flows.values().filter(|f| f.stored_count() > 0).map(|f| (f.last_us, f.key)).collect();
            by_age.sort_unstable_by_key(|x| x.0);
            for (_, k) in by_age {
                if self.stored <= BUDGET * 8 / 10 {
                    break;
                }
                if let Some(f) = self.flows.get_mut(&k) {
                    self.stored -= f.stored_bytes();
                    f.head.clear();
                    f.ring.clear();
                }
            }
        }
        removed
    }
}

/// Handshake RTT, retransmissions and zero windows for one TCP segment.
fn track_quality(f: &mut Flow, ts: i64, outbound: bool, (syn, ack, fin, rst): (bool, bool, bool, bool), m: TcpMeta) {
    if syn && !ack {
        f.syn_us.get_or_insert(ts);
    }
    if syn && ack && outbound {
        f.synack_us.get_or_insert(ts);
    }
    if f.rtt_us.is_none() {
        let start = if syn && ack && !outbound {
            f.syn_us
        } else if !syn && ack && !outbound && f.initiated_locally == Some(false) {
            f.synack_us
        } else {
            None
        };
        if let Some(s) = start {
            f.rtt_us = Some((ts - s).clamp(0, u32::MAX as i64) as u32);
        }
    }
    // One-byte segments are keep-alives / window probes, not data.
    if m.payload_len > 1 {
        let end = m.seq.wrapping_add(m.payload_len);
        let high = if outbound { &mut f.high_out } else { &mut f.high_in };
        match *high {
            // Ends at or before data already seen (sequence arithmetic, wrap-safe).
            Some(h) if (end.wrapping_sub(h) as i32) <= 0 => {
                if outbound {
                    f.retrans_out += 1;
                } else {
                    f.retrans_in += 1;
                }
            }
            _ => *high = Some(end),
        }
    }
    if m.window == 0 && !syn && !rst && !fin {
        f.zero_window += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::http::HttpRequest;

    fn key(lport: u16) -> FlowKey {
        FlowKey { l4: L4::Tcp, local: format!("10.0.0.2:{lport}").parse().unwrap(), remote: "1.1.1.1:443".parse().unwrap() }
    }

    fn info(transport: Transport, app: App) -> PacketInfo {
        PacketInfo {
            src: "10.0.0.2".parse().unwrap(),
            dst: "1.1.1.1".parse().unwrap(),
            src_port: 5000,
            dst_port: 443,
            transport,
            proto: Proto::Tcp,
            app,
            ttl: 64,
            tcp: None,
        }
    }

    fn proc(pid: u32) -> ProcInfo {
        ProcInfo { pid, name: "Code.exe".into(), path: None, parent: None }
    }

    const SYNACK: Transport = Transport::Tcp { syn: true, ack: true, fin: false, rst: false };
    const FIN: Transport = Transport::Tcp { syn: false, ack: true, fin: true, rst: false };

    #[test]
    fn tcp_lifecycle_and_direction() {
        let mut t = FlowTable::new(100);
        let k = key(5000);
        let o = t.observe(k, 1, true, 60, b"syn", &info(Transport::TCP_SYN, App::None), |_| Some(proc(7)));
        assert!(o.created && o.process == Some(7));
        assert_eq!(t.get(o.id).unwrap().state, FlowState::Opening);
        t.observe(k, 2, false, 60, b"synack", &info(SYNACK, App::None), |_| None);
        t.observe(k, 3, true, 1000, b"data", &info(Transport::TCP_ACK, App::TlsHello(TlsHello::with_sni("github.com"))), |_| None);
        let f = t.get(o.id).unwrap();
        assert_eq!((f.state, f.initiated_locally, f.name.as_deref()), (FlowState::Established, Some(true), Some("github.com")));
        assert_eq!((f.bytes_out, f.bytes_in, f.packets_out, f.packets_in), (1060, 60, 2, 1));
        t.observe(k, 4, true, 60, b"fin", &info(FIN, App::None), |_| None);
        assert_eq!(t.get(o.id).unwrap().state, FlowState::Closing);
        t.observe(k, 5, false, 60, b"fin", &info(FIN, App::None), |_| None);
        assert_eq!(t.get(o.id).unwrap().state, FlowState::Closed);
        assert_eq!(t.get(o.id).unwrap().packet(3).unwrap().data.as_ref(), b"data");
    }

    #[test]
    fn server_side_flow_from_synack_and_http_host() {
        let mut t = FlowTable::new(100);
        let o = t.observe(key(80), 1, true, 60, b"", &info(SYNACK, App::None), |_| None);
        assert_eq!(t.get(o.id).unwrap().initiated_locally, Some(false));
        let req = HttpRequest { method: "GET".into(), path: "/".into(), host: Some("h.test".into()), sensitive: vec![] };
        t.observe(key(80), 2, false, 300, b"", &info(Transport::TCP_ACK, App::Http(req)), |_| None);
        assert_eq!(t.get(o.id).unwrap().name.as_deref(), Some("h.test"));
        assert_eq!(t.get(o.id).unwrap().stored_count(), 0, "empty frames are not stored");
    }

    #[test]
    fn ring_is_bounded_and_packets_addressable() {
        let mut t = FlowTable::new(100);
        let k = key(1);
        for i in 0..(RING + 50) {
            t.observe(k, i as i64, i % 2 == 0, 100, &[i as u8; 10], &info(Transport::TCP_ACK, App::None), |_| None);
        }
        let f = t.flows.get(&k).unwrap();
        assert_eq!(f.stored_count(), HEAD + RING);
        assert_eq!(f.dropped_packets(), (RING + 50 - HEAD - RING) as u64);
        assert!(f.has_beginning(), "the opening packets stay");
        assert_eq!(f.packet(1).unwrap().n, 1);
        assert_eq!(f.packet(HEAD as u64).unwrap().n, HEAD as u64);
        assert!(f.packet(HEAD as u64 + 1).is_none(), "the gap between head and ring");
        assert_eq!(f.packet(51).unwrap().n, 51);
        assert_eq!(f.packet((RING + 50) as u64).unwrap().data[0], (RING + 49) as u8);
        let ns: Vec<u64> = f.stored().map(|p| p.n).collect();
        assert!(ns.windows(2).all(|w| w[0] < w[1]), "stored() is in order");
        assert_eq!(t.stored_bytes(), (HEAD + RING) * 10);
    }

    #[test]
    fn late_attribution_and_retry_limit() {
        let mut t = FlowTable::new(100);
        let o = t.observe(key(1), 1, true, 100, b"", &info(Transport::TCP_ACK, App::None), |_| None);
        assert!(t.attribute(|_| None).is_empty());
        let found = t.attribute(|_| Some(proc(9)));
        assert_eq!(found.len(), 1);
        assert_eq!((found[0].process.pid, found[0].bytes_out, found[0].id), (9, 100, o.id));
        assert_eq!(t.get(o.id).unwrap().process.as_ref().unwrap().pid, 9);

        let o2 = t.observe(key(2), 1, true, 1, b"", &info(Transport::TCP_ACK, App::None), |_| None);
        for _ in 0..MAX_TRIES {
            t.attribute(|_| None);
        }
        assert!(!t.get(o2.id).unwrap().awaiting_owner());
    }

    fn seg(transport: Transport, seq: u32, len: u32, window: u16) -> PacketInfo {
        let mut i = info(transport, App::None);
        i.tcp = Some(TcpMeta { seq, ack: 0, window, payload_len: len });
        i
    }

    #[test]
    fn handshake_rtt_retransmissions_and_zero_window() {
        let mut t = FlowTable::new(10);
        let k = key(7000);
        t.observe(k, 1_000, true, 60, b"", &seg(Transport::TCP_SYN, 99, 0, 64_000), |_| None);
        let o = t.observe(k, 43_000, false, 60, b"", &seg(SYNACK, 5_000, 0, 64_000), |_| None);
        assert_eq!(o.rtt_us, Some(42_000), "outgoing: SYN -> SYN-ACK");
        t.observe(k, 44_000, true, 600, b"", &seg(Transport::TCP_ACK, 100, 500, 64_000), |_| None);
        t.observe(k, 45_000, true, 600, b"", &seg(Transport::TCP_ACK, 100, 500, 64_000), |_| None);
        t.observe(k, 46_000, true, 600, b"", &seg(Transport::TCP_ACK, 600, 500, 64_000), |_| None);
        t.observe(k, 47_000, false, 60, b"", &seg(Transport::TCP_ACK, 5_001, 0, 0), |_| None);
        t.observe(k, 48_000, true, 61, b"", &seg(Transport::TCP_ACK, 1_099, 1, 64_000), |_| None);
        let f = t.get(o.id).unwrap();
        assert_eq!((f.retrans_out, f.retrans_in, f.zero_window), (1, 0, 1), "keep-alive is not a retransmission");
    }

    #[test]
    fn incoming_rtt_and_sequence_wrap() {
        let mut t = FlowTable::new(10);
        let k = key(8080);
        t.observe(k, 0, false, 60, b"", &seg(Transport::TCP_SYN, 1, 0, 1000), |_| None);
        t.observe(k, 100, true, 60, b"", &seg(SYNACK, 9, 0, 1000), |_| None);
        let o = t.observe(k, 3_100, false, 60, b"", &seg(Transport::TCP_ACK, 2, 0, 1000), |_| None);
        assert_eq!(o.rtt_us, Some(3_000), "incoming: SYN-ACK -> ACK");
        // Data across the 2^32 wrap is new data, not a retransmission.
        t.observe(k, 4_000, false, 100, b"", &seg(Transport::TCP_ACK, u32::MAX - 10, 50, 1000), |_| None);
        t.observe(k, 5_000, false, 100, b"", &seg(Transport::TCP_ACK, 39, 50, 1000), |_| None);
        assert_eq!(t.get(o.id).unwrap().retrans_in, 0);
    }

    #[test]
    fn byte_budget_drops_the_oldest_rings_first_and_keeps_the_accounting_exact() {
        let mut t = FlowTable::new(1000);
        let frame = vec![0xAAu8; SNAP_BYTES + 100];
        let per_flow = HEAD + RING;
        let flows = BUDGET / (per_flow * SNAP_BYTES) + 6; // comfortably over the budget
        let mut ts = 0;
        let mut evictions = 0;
        for i in 0..flows as u16 {
            for _ in 0..per_flow {
                ts += 1;
                t.observe(key(i), ts, true, 1, &frame, &info(Transport::TCP_ACK, App::None), |_| None);
                assert!(t.stored_bytes() <= BUDGET + SNAP_BYTES, "one frame over the budget at most before eviction");
                if t.over_limits() {
                    t.evict();
                    evictions += 1;
                    assert!(t.stored_bytes() <= BUDGET * 8 / 10, "{} after eviction", t.stored_bytes());
                }
            }
        }
        assert!(evictions >= 1);
        assert_eq!(t.len(), flows, "eviction for memory keeps the connections, only their bytes go");
        let sum: usize = t.iter().map(Flow::stored_bytes).sum();
        assert_eq!(sum, t.stored_bytes(), "the running total matches the flows");
        let newest = t.flows.get(&key(flows as u16 - 1)).unwrap();
        assert_eq!(newest.stored_count(), per_flow);
        assert!(newest.stored().all(|p| p.data.len() == SNAP_BYTES), "frames are cut to SNAP_BYTES");
        let oldest = t.flows.get(&key(0)).unwrap();
        assert_eq!((oldest.stored_count(), oldest.dropped_packets(), oldest.has_beginning()), (0, per_flow as u64, false));
        assert_eq!((oldest.packets_out, oldest.bytes_out), (per_flow as u64, per_flow as u64), "counters survive the purge");
        // Dropped rings stay dropped; a second evict is a no-op; new packets are stored again.
        let before = t.stored_bytes();
        t.evict();
        assert_eq!(t.stored_bytes(), before);
        t.observe(key(0), ts + 1, false, 1, b"late", &info(Transport::TCP_ACK, App::None), |_| None);
        let oldest = t.flows.get(&key(0)).unwrap();
        assert_eq!((oldest.stored_count(), oldest.packet(per_flow as u64 + 1).map(|p| p.data.len())), (1, Some(4)));
        assert!(!t.over_limits());
        // The count limit has slack of 10% before `over_limits` reports it.
        let mut small = FlowTable::new(10);
        for i in 0..11u16 {
            small.observe(key(i), i as i64, true, 1, b"", &info(Transport::TCP_ACK, App::None), |_| None);
        }
        assert!(!small.over_limits());
        small.observe(key(11), 11, true, 1, b"", &info(Transport::TCP_ACK, App::None), |_| None);
        assert!(small.over_limits());
    }

    #[test]
    fn eviction_by_count_and_budget() {
        let mut t = FlowTable::new(10);
        for i in 0..20u16 {
            t.observe(key(i), i as i64, true, 1, &[0u8; 100], &info(Transport::TCP_ACK, App::None), |_| None);
        }
        t.evict();
        assert!(t.len() <= 10);
        assert!(t.flows.contains_key(&key(19)) && !t.flows.contains_key(&key(0)));
        assert_eq!(t.stored_bytes(), t.len() * 100);
        assert!(t.get(1).is_none(), "id index cleaned up");
    }
}
