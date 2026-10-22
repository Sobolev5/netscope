//! The traffic model: per-remote-host volumes, protocol mix, bandwidth history,
//! IP в†’ name mapping learned from DNS answers / TLS SNI / HTTP Host, and alerts.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use serde::Serialize;

use super::addr::{is_external, is_local_scope};
use super::anomaly::{cleartext_service, details, inspect_dns, AlertKind, AlertLog, NewAlert, Severity};
use super::dnslog::{DnsLog, Requester};
use super::dnslog::DnsEntry;
use super::flows::{Flow, FlowKey, FlowTable, Observed, ProcStats, L4};
use super::journal::{ConnRecord, Journal, JournalRecord, Kind, Stamped};
use super::novelty::{registrable_domain, Novel, Novelty};
use super::views::DnsEntryView;
use super::persist::{self, Persisted, WatchEntry};
use crate::capture::engine::unix_now;
use crate::decode::{linktype, App, PacketInfo, Proto, Transport};
use crate::geo::GeoDb;
use crate::netpath::{Egress, RouteInfo};
use crate::procs::signature::{suspicious_location, SigStatus, Signature};
use crate::procs::{OwnerIndex, ProcInfo, SockProto};
use crate::trace::watch::{RouteEvent, RouteWatch};
use crate::trace::Trace;

#[derive(Debug, Clone)]
pub struct Config {
    /// Bytes a single unrecognized external host must exchange within one second to be a spike.
    pub spike_min_bytes: u64,
    /// ...and how many times its usual per-second volume that must be.
    pub spike_factor: f64,
    /// Remote hosts kept in memory; the least recently seen are evicted beyond this.
    pub max_hosts: usize,
    /// Seconds of bandwidth history.
    pub history_secs: usize,
    /// Identical alerts are suppressed for this long.
    pub alert_suppress_secs: i64,
    pub alert_capacity: usize,
    /// Connections kept in memory (least recently active evicted).
    pub max_flows: usize,
    /// Distinct ports one host must probe within `scan_window_secs` to be a port scan.
    pub scan_ports: usize,
    pub scan_window_secs: i64,
    /// Bytes sent to one external host within `upload_window_secs` that make a "large upload".
    pub upload_min_bytes: u64,
    pub upload_window_secs: i64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            spike_min_bytes: 1 << 20,
            spike_factor: 8.0,
            max_hosts: 4096,
            history_secs: 300,
            alert_suppress_secs: 60,
            alert_capacity: 500,
            max_flows: 4096,
            scan_ports: 15,
            scan_window_secs: 10,
            upload_min_bytes: 200 << 20,
            upload_window_secs: 600,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "error", rename_all = "lowercase")]
pub enum CaptureStatus {
    Starting,
    Running,
    Finished,
    Failed(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct CaptureInfo {
    /// `live`, `file` or `demo`.
    pub mode: &'static str,
    /// Interface name or file path.
    pub source: String,
    pub description: Option<String>,
    pub filter: Option<String>,
    pub libpcap: Option<String>,
    pub status: CaptureStatus,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Totals {
    pub packets: u64,
    pub bytes: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub non_ip_packets: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Sample {
    pub ts: i64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Counter {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NameSource {
    Dns,
    Sni,
    Http,
}

#[derive(Debug, Clone)]
pub struct Named {
    pub name: String,
    pub source: NameSource,
}

#[derive(Debug, Clone)]
pub struct Host {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets: u64,
    pub first_seen: i64,
    pub last_seen: i64,
    /// Bit set of `Proto::index()`.
    pub protos: u16,
    /// Remote ports seen (capped).
    pub ports: BTreeSet<u16>,
    /// Bytes in the current second, closed by `advance`.
    sec_bytes: u64,
    /// Exponentially weighted per-second volume while active.
    pub baseline: f64,
    pub peak_bytes_per_sec: u64,
    pub flagged: bool,
    /// Routers between us and the host, estimated from the TTL of its packets.
    pub hops: Option<u8>,
    /// Best TCP handshake round trip to the host.
    pub rtt_us: Option<u32>,
    /// Our ports this host sent SYNs to lately (inbound port-scan detection).
    probe_in: PortWindow,
    /// Its ports we sent SYNs to lately (outbound port-scan detection).
    probe_out: PortWindow,
    /// Bytes sent to the host since `up_since` (large-upload detection).
    up_bytes: u64,
    up_since: i64,
}

/// Distinct ports seen within a time window.
#[derive(Debug, Clone, Default)]
struct PortWindow {
    ports: BTreeSet<u16>,
    since: i64,
}

impl PortWindow {
    /// Adds `port` at `now`, restarting the window when `window_secs` have passed; returns
    /// the number of distinct ports in the window.
    fn observe(&mut self, port: u16, now: i64, window_secs: i64) -> usize {
        if self.ports.is_empty() || now - self.since > window_secs {
            self.ports.clear();
            self.since = now;
        }
        if self.ports.len() < 1024 {
            self.ports.insert(port);
        }
        self.ports.len()
    }

    fn reset(&mut self) {
        self.ports.clear();
    }
}

impl Host {
    fn new(ts: i64) -> Self {
        Self {
            bytes_in: 0,
            bytes_out: 0,
            packets: 0,
            first_seen: ts,
            last_seen: ts,
            protos: 0,
            ports: BTreeSet::new(),
            sec_bytes: 0,
            baseline: 0.0,
            peak_bytes_per_sec: 0,
            flagged: false,
            hops: None,
            rtt_us: None,
            probe_in: PortWindow::default(),
            probe_out: PortWindow::default(),
            up_bytes: 0,
            up_since: ts,
        }
    }

    pub fn total(&self) -> u64 {
        self.bytes_in + self.bytes_out
    }

    pub fn protocols(&self) -> Vec<Proto> {
        Proto::ALL.into_iter().filter(|p| self.protos & (1 << p.index()) != 0).collect()
    }
}

const MAX_PORTS_PER_HOST: usize = 12;
const MAX_DNS_NAMES: usize = 20_000;

pub struct State {
    pub(super) cfg: Config,
    pub capture: CaptureInfo,
    local: HashSet<IpAddr>,
    /// No local addresses were given (file replay): learn them from client-side packets.
    learn_local: bool,
    /// Current second (unix time), driven by packet timestamps and the live clock.
    pub(super) now: i64,
    pub(super) first_ts: Option<i64>,
    pub(super) totals: Totals,
    pub(super) protocols: [Counter; Proto::ALL.len()],
    pub(super) hosts: HashMap<IpAddr, Host>,
    pub(super) names: HashMap<IpAddr, Named>,
    pub(super) dns_queries: HashMap<String, u64>,
    pub(super) series: VecDeque<Sample>,
    /// Hosts with traffic in the current second.
    active: Vec<IpAddr>,
    pub(super) alerts: AlertLog,
    pub(super) flows: FlowTable,
    /// Latest socket в†’ process index from the OS (or the demo).
    owners: Option<Arc<OwnerIndex>>,
    want_owners: bool,
    /// Traffic per process (PID), including connections already evicted.
    pub(super) proc_stats: HashMap<u32, (ProcInfo, ProcStats)>,
    /// pcap link type of stored frames, needed to dissect them later.
    pub linktype: i32,
    /// Offline geolocation; `None` when disabled.
    pub geo: Option<Arc<GeoDb>>,
    /// Last public egress check (`None` until done or when disabled).
    pub(super) egress: Option<Result<Egress, String>>,
    pub egress_enabled: bool,
    pub(super) dns_log: DnsLog,
    novelty: Novelty,
    /// Code signatures of executables, by path.
    pub(super) signatures: HashMap<String, Signature>,
    /// Hosts whose route is traced periodically.
    pub routes: RouteWatch,
    /// On-disk journal of finished connections, DNS lookups and alerts; `None` = not kept.
    journal: Option<Arc<Journal>>,
    /// Connections seen closed, `(close time µs, id)` in order: journaled by `advance` once
    /// `CLOSE_GRACE_US` has passed, so a late process attribution still lands in the record.
    close_queue: VecDeque<(i64, u64)>,
    /// DNS servers queries were sent to (bounded); a new one after the learning period is news.
    dns_resolvers: HashSet<IpAddr>,
    last_resolver: Option<IpAddr>,
    /// The adapter carrying the default route, as last reported by the network watcher.
    route: Option<RouteInfo>,
    /// The last route there was: a reconnect after a moment without one is compared to it.
    known_route: Option<RouteInfo>,
    /// Wall-clock time of the last default-route change (resolver changes right after it
    /// are part of the same event).
    last_network_change: i64,
    /// The last successful egress check and whether a tunnel adapter carried the route
    /// then (failed checks in between do not reset the comparison).
    last_egress: Option<(Egress, bool)>,
    /// New outbound connections to bare IPs, `(deadline µs, id, attempts)`: judged once a
    /// name had time to show up (SNI, Host) — see `check_unnamed_connections`.
    ip_checks: VecDeque<(i64, u64, u32)>,
}

/// A connection to a bare IP gets this long for a name (SNI/Host) to show up before an
/// unsigned program using it is reported.
const IP_CHECK_GRACE_US: i64 = 3_000_000;
/// A connection whose program's signature is not verified yet is looked at again (every
/// `IP_CHECK_GRACE_US`) this many times: the first check of a new program takes a while.
const IP_CHECK_ATTEMPTS: u32 = 20;
/// Resolver changes are not reported this long after a network change.
const RESOLVER_QUIET_SECS: i64 = 120;
/// Nothing is learned about resolvers during the first minute (baseline).
const RESOLVER_LEARNING_SECS: i64 = 60;
const MAX_RESOLVERS: usize = 64;

/// A closed connection waits this long (traffic clock) before it is journaled.
pub const CLOSE_GRACE_US: i64 = 5_000_000;

impl State {
    pub fn new(cfg: Config, local: HashSet<IpAddr>, capture: CaptureInfo) -> Self {
        let alerts = AlertLog::new(cfg.alert_capacity, cfg.alert_suppress_secs);
        let cfg_flows = cfg.max_flows;
        Self {
            cfg,
            capture,
            learn_local: local.is_empty(),
            local,
            now: 0,
            first_ts: None,
            totals: Totals::default(),
            protocols: [Counter::default(); Proto::ALL.len()],
            hosts: HashMap::new(),
            names: HashMap::new(),
            dns_queries: HashMap::new(),
            series: VecDeque::new(),
            active: Vec::new(),
            flows: FlowTable::new(cfg_flows),
            owners: None,
            want_owners: false,
            proc_stats: HashMap::new(),
            linktype: linktype::ETHERNET,
            geo: None,
            egress: None,
            egress_enabled: false,
            dns_log: DnsLog::new(3000),
            novelty: Novelty::default(),
            signatures: HashMap::new(),
            routes: RouteWatch::default(),
            alerts,
            journal: None,
            close_queue: VecDeque::new(),
            dns_resolvers: HashSet::new(),
            last_resolver: None,
            route: None,
            known_route: None,
            last_network_change: 0,
            last_egress: None,
            ip_checks: VecDeque::new(),
        }
    }

    /// Journals the connections whose close is at least `CLOSE_GRACE_US` old (once each;
    /// one evicted meanwhile was journaled then).
    fn journal_due_closes(&mut self) {
        let now_us = self.now.saturating_mul(1_000_000);
        while let Some(&(closed_us, id)) = self.close_queue.front() {
            if closed_us.saturating_add(CLOSE_GRACE_US) > now_us {
                break;
            }
            self.close_queue.pop_front();
            if self.flows.get(id).is_some_and(|f| !f.journaled && self.journal_flow(f, "closed")) {
                if let Some(f) = self.flows.get_mut(id) {
                    f.journaled = true;
                }
            }
        }
    }

    /// Attaches the journal; records are produced from now on (while its retention is > 0).
    pub fn set_journal(&mut self, journal: Arc<Journal>) {
        self.journal = Some(journal);
    }

    pub fn journal(&self) -> Option<&Arc<Journal>> {
        self.journal.as_ref()
    }

    /// The journal when it is attached and switched on.
    fn journal_on(&self) -> Option<&Journal> {
        self.journal.as_deref().filter(|j| j.enabled())
    }

    /// Writes a connection record; `false` when the journal is off.
    fn journal_flow(&self, f: &Flow, reason: &'static str) -> bool {
        let Some(j) = self.journal_on() else { return false };
        let ts = unix_now();
        let rec = ConnRecord::from_view(ts, self.conn_view(f), reason);
        if let Some(r) = JournalRecord::new(Kind::Connections, ts, &rec) {
            j.push(r);
        }
        true
    }

    /// Writes a DNS record for an entry that is final (answered, failed or evicted).
    fn journal_dns(&self, e: DnsEntry) {
        let Some(j) = self.journal_on() else { return };
        let answers: Vec<IpAddr> = e.answers.iter().filter_map(|a| a.parse().ok()).collect();
        let mut used_by: Vec<String> = Vec::new();
        if !answers.is_empty() {
            for f in self.flows().filter(|f| answers.contains(&f.key.remote.ip())) {
                if let Some(p) = &f.process {
                    if !used_by.contains(&p.name) {
                        used_by.push(p.name.clone());
                    }
                }
            }
            used_by.sort();
        }
        let ts = unix_now();
        let view = DnsEntryView { entry: e, used_by };
        if let Some(r) = JournalRecord::new(Kind::Dns, ts, &Stamped { ts, inner: &view }) {
            j.push(r);
        }
    }

    /// Journals every connection not journaled yet (reason `shutdown`); returns how many.
    /// For the end of the program, once the capture thread is done.
    pub fn journal_remaining(&mut self) -> usize {
        let ids: Vec<u64> = self.flows.iter().filter(|f| !f.journaled).map(|f| f.id).collect();
        let mut n = 0;
        for id in ids {
            if self.flows.get(id).is_some_and(|f| self.journal_flow(f, "shutdown")) {
                n += 1;
            }
            if let Some(f) = self.flows.get_mut(id) {
                f.journaled = true;
            }
        }
        n
    }

    /// Seconds between the first and the current second of the traffic clock.
    pub fn uptime_secs(&self) -> i64 {
        self.first_ts.map_or(0, |t| self.now - t)
    }

    /// Throughput of the last complete second (the newest sample is still filling up).
    pub fn rates(&self) -> super::Rates {
        let complete = if self.series.len() >= 2 { self.series.get(self.series.len() - 2) } else { self.series.back() };
        complete.map_or(super::Rates::default(), |s| super::Rates { bytes_in: s.bytes_in, bytes_out: s.bytes_out, packets: s.packets })
    }

    /// (queries seen, failed answers) of the DNS journal.
    pub fn dns_counts(&self) -> (u64, u64) {
        (self.dns_log.queries, self.dns_log.failures)
    }

    pub fn host_count(&self) -> usize {
        self.hosts.len()
    }

    /// Bytes per country code of the hosts in memory (`??` for unknown), largest first.
    pub fn country_bytes(&self) -> Vec<(String, u64)> {
        let mut by_code: HashMap<String, u64> = HashMap::new();
        if let Some(g) = &self.geo {
            for (ip, h) in &self.hosts {
                if let Some(info) = g.lookup(*ip) {
                    *by_code.entry(info.country_code.unwrap_or_else(|| "??".into())).or_default() += h.total();
                }
            }
        }
        let mut v: Vec<(String, u64)> = by_code.into_iter().collect();
        v.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v
    }

    pub fn set_status(&mut self, status: CaptureStatus) {
        if let CaptureStatus::Failed(e) = &status {
            if self.capture.status != status {
                self.alert_at(unix_now(), NewAlert {
                    severity: Severity::High,
                    kind: AlertKind::CaptureFailed,
                    host: None,
                    name: None,
                    message: format!("Traffic capture stopped: {e}"),
                    details: details([("error", e.clone())]),
                    key: "capture-failed".into(),
                });
            }
        }
        self.capture.status = status;
    }

    pub fn host(&self, ip: &IpAddr) -> Option<&Host> {
        self.hosts.get(ip)
    }

    pub fn name_of(&self, ip: &IpAddr) -> Option<&Named> {
        self.names.get(ip)
    }

    pub fn totals(&self) -> Totals {
        self.totals
    }

    pub fn protocol(&self, p: Proto) -> Counter {
        self.protocols[p.index()]
    }

    /// Current second of the traffic clock.
    pub fn now(&self) -> i64 {
        self.now
    }

    /// Newest first.
    pub fn alerts(&self, limit: usize) -> Vec<super::Alert> {
        self.alerts.recent(limit)
    }

    pub fn alert_counts(&self) -> super::AlertCounts {
        self.alerts.counts()
    }

    /// Moves the clock to `sec`: closes the previous second (spike checks), extends the
    /// bandwidth history and evicts stale hosts. Earlier times are ignored.
    pub fn advance(&mut self, sec: i64) {
        if self.series.is_empty() {
            self.now = sec;
            self.first_ts = Some(sec);
            self.series.push_back(Sample { ts: sec, ..Sample::default() });
            return;
        }
        if sec <= self.now {
            return;
        }
        self.close_second();
        let gap = (sec - self.now).min(self.cfg.history_secs as i64);
        for t in (sec - gap + 1)..=sec {
            self.series.push_back(Sample { ts: t, ..Sample::default() });
        }
        while self.series.len() > self.cfg.history_secs {
            self.series.pop_front();
        }
        self.now = sec;
        self.evict();
        self.journal_due_closes();
        self.check_unnamed_connections();
    }

    /// End of input (capture file finished): closes the last second so its spike checks run.
    pub fn finish(&mut self) {
        self.close_second();
        self.evict();
    }

    /// Records one packet without keeping its bytes. `info` is `None` for non-IP frames.
    pub fn record(&mut self, ts_us: i64, wire_len: u32, info: Option<&PacketInfo>) {
        self.record_frame(ts_us, wire_len, &[], info);
    }

    /// Records one packet; `frame` (possibly empty) is kept for the connection inspector.
    pub fn record_frame(&mut self, ts_us: i64, wire_len: u32, frame: &[u8], info: Option<&PacketInfo>) {
        let sec = ts_us.div_euclid(1_000_000);
        self.advance(sec);
        let len = wire_len as u64;
        if let Some(i) = info.filter(|_| self.learn_local) {
            self.learn_local_address(i);
        }
        let (proto, direction) = match info {
            Some(i) => (i.proto, Some(self.orient(i))),
            // Non-IP frames (ARP, LLDP...) count as inbound "other" traffic.
            None => (Proto::Other, None),
        };
        let outbound = direction.is_some_and(|d| d.1);

        self.totals.packets += 1;
        self.totals.bytes += len;
        let sample = self.series.back_mut().expect("advance created a sample");
        sample.packets += 1;
        if outbound {
            sample.bytes_out += len;
            self.totals.bytes_out += len;
            self.totals.packets_out += 1;
        } else {
            sample.bytes_in += len;
            self.totals.bytes_in += len;
            self.totals.packets_in += 1;
        }
        let c = &mut self.protocols[proto.index()];
        c.packets += 1;
        c.bytes += len;

        let (Some(info), Some((remote, outbound, remote_port))) = (info, direction) else {
            self.totals.non_ip_packets += 1;
            return;
        };

        let now = self.now;
        let host = self.hosts.entry(remote).or_insert_with(|| Host::new(now));
        if outbound {
            host.bytes_out += len;
        } else {
            host.bytes_in += len;
        }
        host.packets += 1;
        host.last_seen = host.last_seen.max(sec);
        host.protos |= 1 << info.proto.index();
        if remote_port != 0 && host.ports.len() < MAX_PORTS_PER_HOST {
            host.ports.insert(remote_port);
        }
        if !outbound {
            host.hops = Some(estimate_hops(info.ttl));
        }
        if host.sec_bytes == 0 {
            self.active.push(remote);
        }
        host.sec_bytes += len;

        let o = self.track_flow(ts_us, wire_len, frame, info, outbound);
        self.watch_probes_and_uploads(sec, len, info, remote, remote_port, outbound, o.id);
        if o.created && outbound && matches!(info.transport, Transport::Tcp { syn: true, ack: false, .. }) && is_external(&remote) {
            self.ip_checks.push_back((ts_us + IP_CHECK_GRACE_US, o.id, 1));
        }
        // A closed connection is journaled by `advance` after a grace period, so the process
        // found by the next socket-table poll is still part of the record.
        if o.closed {
            self.close_queue.push_back((ts_us, o.id));
        }
        if self.flows.over_limits() {
            self.evict();
        }
        if let Some(rtt) = o.rtt_us {
            if let Some(h) = self.hosts.get_mut(&remote) {
                h.rtt_us = Some(h.rtt_us.map_or(rtt, |r| r.min(rtt)));
            }
        }
        if o.process.is_some() && (o.created || o.named) {
            self.check_novelty(o.id);
            self.check_suspicious(o.id);
        }
        let requester = self.flows.get(o.id).and_then(|f| f.process.as_ref()).map(|p| Requester { pid: p.pid, name: p.name.clone() });
        self.inspect(ts_us, info, remote, remote_port, requester);
    }

    fn track_flow(&mut self, ts_us: i64, wire_len: u32, frame: &[u8], info: &PacketInfo, outbound: bool) -> Observed {
        let l4 = match info.transport {
            Transport::Tcp { .. } => L4::Tcp,
            Transport::Udp => L4::Udp,
            Transport::Icmp => L4::Icmp,
            Transport::Other(_) => L4::Other,
        };
        let (local, remote) = if outbound {
            (SocketAddr::new(info.src, info.src_port), SocketAddr::new(info.dst, info.dst_port))
        } else {
            (SocketAddr::new(info.dst, info.dst_port), SocketAddr::new(info.src, info.src_port))
        };
        let key = FlowKey { l4, local, remote };
        // Traffic between other devices (seen in promiscuous mode, LAN multicast) has no
        // local socket here, even if some program listens on the same port.
        let ours = self.learn_local || self.local.contains(&local.ip());
        let owners = self.owners.clone();
        let o = self.flows.observe(key, ts_us, outbound, wire_len, frame, info, |k| {
            let proto = k.l4.sock()?;
            owners.as_ref().filter(|_| ours)?.lookup(proto, k.local, k.remote)
        });
        if o.created && o.process.is_none() && l4.sock().is_some() && ours {
            // Ask for a fresh socket table soon: short connections may close before the next one.
            self.want_owners = true;
        }
        if let Some(info) = self.flows.get(o.id).and_then(|f| f.process.clone()) {
            let s = self.proc_entry(&info, ts_us);
            if outbound {
                s.bytes_out += wire_len as u64;
            } else {
                s.bytes_in += wire_len as u64;
            }
            s.packets += 1;
            s.connections += u64::from(o.created);
            s.last_us = s.last_us.max(ts_us);
        }
        o
    }

    /// Traffic counters of `p`; reset when its PID now belongs to a different program.
    fn proc_entry(&mut self, p: &ProcInfo, first_us: i64) -> &mut ProcStats {
        let e = self.proc_stats.entry(p.pid).or_insert_with(|| (p.clone(), ProcStats { first_us, ..ProcStats::default() }));
        if e.0.name != p.name {
            e.1 = ProcStats { first_us, ..ProcStats::default() };
        }
        e.0 = p.clone();
        &mut e.1
    }

    /// Installs a new socket в†’ process index and attributes waiting connections with it.
    pub fn set_owners(&mut self, idx: Arc<OwnerIndex>) {
        let (local, learn) = (&self.local, self.learn_local);
        let found = self.flows.attribute(|k| {
            if !learn && !local.contains(&k.local.ip()) {
                return None;
            }
            idx.lookup(k.l4.sock()?, k.local, k.remote)
        });
        for a in found {
            let s = self.proc_entry(&a.process, a.first_us);
            s.bytes_in += a.bytes_in;
            s.bytes_out += a.bytes_out;
            s.packets += a.packets;
            s.connections += 1;
            s.first_us = s.first_us.min(a.first_us);
            s.last_us = s.last_us.max(a.last_us);
            self.check_novelty(a.id);
            self.check_suspicious(a.id);
        }
        // Programs that start listening on ports reachable from the network. A failed or
        // empty socket table must not become the baseline: everything would be "new" later.
        if idx.error().is_none() && !idx.sockets().is_empty() {
            let listeners: Vec<(String, SocketAddr)> = idx
                .sockets()
                .iter()
                .filter(|s| s.proto == SockProto::Tcp && s.state == Some("LISTEN"))
                .map(|s| (idx.process_or_placeholder(s.pid).name, s.local))
                .collect();
            for n in self.novelty.observe_listeners(listeners.iter().map(|(p, a)| (p.as_str(), *a))) {
                self.novel_alert(n, unix_now());
            }
        }
        self.owners = Some(idx);
        self.want_owners = false;
    }

    /// Raises "first time" alerts for a connection whose process (and maybe name) is known.
    fn check_novelty(&mut self, flow_id: u64) {
        let Some(f) = self.flows.get(flow_id) else { return };
        let Some(p) = &f.process else { return };
        // netscope's own traffic (web UI, egress check, traces) is not news.
        if p.pid == std::process::id() {
            return;
        }
        let process = p.name.clone();
        let remote = f.key.remote.ip();
        if !is_external(&remote) {
            return;
        }
        let geo = self.geo.as_ref().and_then(|g| g.lookup(remote));
        let destination = f.name.clone().or_else(|| self.names.get(&remote).map(|n| n.name.clone())).or_else(|| geo.as_ref().and_then(|g| g.org.clone()));
        let country = geo.as_ref().and_then(|g| g.country_code.clone());
        let now_us = f.last_us;
        let ts = self.now;
        for n in self.novelty.observe_flow(now_us, &process, destination.as_deref(), country.as_deref()) {
            self.novel_alert(n, ts);
        }
    }

    fn novel_alert(&mut self, n: Novel, ts: i64) {
        let (severity, kind, message, d, key) = match n {
            Novel::Process { process } => (
                Severity::Low,
                AlertKind::NewProcess,
                format!("{process} used the network for the first time"),
                details([("process", process.clone())]),
                format!("new-proc:{process}"),
            ),
            Novel::Destination { process, destination } => (
                Severity::Low,
                AlertKind::NewDestination,
                format!("{process} contacted {destination} for the first time"),
                details([("process", process.clone()), ("destination", destination.clone())]),
                format!("new-dst:{process}:{destination}"),
            ),
            Novel::Country { process, country } => (
                Severity::Medium,
                AlertKind::NewCountry,
                format!("{process} connected to a new country: {country}"),
                details([("process", process.clone()), ("country", country.clone())]),
                format!("new-cc:{process}:{country}"),
            ),
            Novel::Listener { process, addr } => (
                Severity::Medium,
                AlertKind::NewListener,
                format!("{process} started listening on {addr}"),
                details([("process", process.clone()), ("address", addr.to_string()), ("port", addr.port().to_string())]),
                format!("new-listen:{process}:{}", addr.port()),
            ),
        };
        self.alert_at(ts, NewAlert { severity, kind, host: None, name: None, message, details: d, key });
    }

    /// Code signature of a process' executable: pending (`None`) only while a path is
    /// still being verified; processes without a readable path are unknown right away.
    pub fn signature_for(&self, p: &ProcInfo) -> Option<Signature> {
        match &p.path {
            Some(path) => self.signatures.get(path).cloned(),
            None => Some(Signature { status: SigStatus::Unknown, signer: None }),
        }
    }

    /// Executable paths of processes with network activity that were not verified yet.
    pub fn paths_to_verify(&self, limit: usize) -> Vec<String> {
        let mut out: Vec<String> = self
            .proc_stats
            .values()
            .filter(|(p, _)| p.pid != std::process::id())
            .filter_map(|(p, _)| p.path.clone())
            .filter(|path| !self.signatures.contains_key(path))
            .collect();
        out.sort();
        out.dedup();
        out.truncate(limit);
        out
    }

    /// Stores verification results and flags unsigned programs that use the network.
    pub fn set_signatures(&mut self, found: HashMap<String, Signature>) {
        for (path, sig) in found {
            if matches!(sig.status, SigStatus::Unsigned | SigStatus::Invalid) {
                let name = self.proc_stats.values().find(|(p, _)| p.path.as_deref() == Some(path.as_str())).map(|(p, _)| p.name.clone()).unwrap_or_default();
                let risky = suspicious_location(&path);
                let status = if sig.status == SigStatus::Unsigned { "unsigned" } else { "invalid" };
                self.alert_at(unix_now(), NewAlert {
                    severity: if risky { Severity::High } else { Severity::Medium },
                    kind: AlertKind::UnsignedProcess,
                    host: None,
                    name: None,
                    message: format!("{name} ({path}) is {status} and uses the network{}", if risky { " from a temporary/download folder" } else { "" }),
                    details: details([("process", name.clone()), ("path", path.clone()), ("status", status.into()), ("risky_location", risky.to_string())]),
                    key: format!("sig:{path}"),
                });
            }
            self.signatures.insert(path, sig);
        }
    }

    /// Stores a watched route's trace and alerts on path changes or slowdowns.
    pub fn record_route(&mut self, ip: IpAddr, t: Trace) {
        let now = unix_now();
        let name = self.names.get(&ip).map(|n| n.name.clone());
        for e in self.routes.record(ip, t, now) {
            let (severity, kind, message, d, key) = match e {
                RouteEvent::Changed { before, after } => (
                    Severity::Medium,
                    AlertKind::RouteChange,
                    format!("Route to {ip} changed: {} -> {}", before.join(" > "), after.join(" > ")),
                    details([("before", before.join(" > ")), ("after", after.join(" > "))]),
                    format!("route:{ip}:{}", after.join(">")),
                ),
                RouteEvent::Slower { before_ms, after_ms } => (
                    Severity::Low,
                    AlertKind::LatencyIncrease,
                    format!("Route to {ip} got slower: {before_ms:.0} ms -> {after_ms:.0} ms"),
                    details([("before_ms", format!("{before_ms:.0}")), ("after_ms", format!("{after_ms:.0}"))]),
                    format!("slow:{ip}"),
                ),
            };
            self.alert_at(now, NewAlert { severity, kind, host: Some(ip.to_string()), name: name.clone(), message, details: d, key });
        }
    }

    pub fn signature_of(&self, path: &str) -> Option<&Signature> {
        self.signatures.get(path)
    }

    /// What the next start should already know; see [`persist`].
    pub fn persisted(&self) -> Persisted {
        Persisted {
            version: persist::VERSION,
            saved_at: unix_now(),
            watch: self.routes.entries().map(|(ip, label)| WatchEntry { ip, label: label.map(String::from) }).collect(),
            novelty: self.novelty.export(),
        }
    }

    /// Resumes from a previous run: the watched routes are traced again (up to the usual
    /// cap, first entries win) and nothing in the baseline is news. Meant for a fresh
    /// state, before any traffic.
    pub fn restore(&mut self, p: Persisted) {
        let now = unix_now();
        for w in p.watch {
            if !self.routes.add(w.ip, w.label, now) {
                tracing::warn!("saved state has more watched routes than the limit; dropping the rest");
                break;
            }
        }
        self.novelty.import(&p.novelty);
    }

    /// Addresses of this machine (given or learned).
    pub fn local_addresses(&self) -> Vec<IpAddr> {
        let mut v: Vec<IpAddr> = self.local.iter().copied().collect();
        v.sort();
        v
    }

    /// Stores an egress check; a changed public address (after a successful earlier check)
    /// is reported, with a VPN hint from the default route's adapter.
    pub fn set_egress(&mut self, r: Result<Egress, String>) {
        let tunnel = self.route.as_ref().is_some_and(|x| x.tunnel);
        if let (Some((prev, prev_tunnel)), Ok(next)) = (&self.last_egress, &r) {
            if prev.ip != next.ip {
                let label = |e: &Egress| match &e.loc {
                    Some(cc) => format!("{} ({cc})", e.ip),
                    None => e.ip.clone(),
                };
                let vpn = match (*prev_tunnel, tunnel) {
                    (false, true) => "on",
                    (true, false) => "off",
                    _ => "",
                };
                let (before, after) = (label(prev), label(next));
                self.alert_at(unix_now(), NewAlert {
                    severity: Severity::Medium,
                    kind: AlertKind::EgressChange,
                    host: None,
                    name: None,
                    message: match vpn {
                        "on" => format!("VPN is on: the internet exit is now {after} (was {before})"),
                        "off" => format!("VPN is off: the internet exit is {after} again (was {before})"),
                        _ => format!("The internet exit changed: {before} -> {after}"),
                    },
                    details: details([
                        ("before", before),
                        ("after", after),
                        ("before_ip", prev.ip.clone()),
                        ("after_ip", next.ip.clone()),
                        ("before_country", prev.loc.clone().unwrap_or_default()),
                        ("after_country", next.loc.clone().unwrap_or_default()),
                        ("vpn", vpn.into()),
                    ]),
                    key: format!("egress:{}", next.ip),
                });
            }
        }
        if let Ok(e) = &r {
            self.last_egress = Some((e.clone(), tunnel));
        }
        self.egress = Some(r);
    }

    /// The default route moved (or went away). A move to another adapter is reported, with a
    /// VPN hint when a tunnel adapter came or went; a reconnect after a moment without a route
    /// is compared to the route before it. A new address on the same adapter (DHCP renewal,
    /// another Wi-Fi network) is not news here — the egress check reports a new exit.
    pub fn set_default_route(&mut self, route: Option<RouteInfo>) {
        let now = unix_now();
        if route != self.route && self.known_route.is_some() {
            // Resolver changes right after this are part of the same event.
            self.last_network_change = now;
        }
        if let (Some(prev), Some(next)) = (&self.known_route, &route) {
            if !prev.same_adapter(next) {
                let vpn = match (prev.tunnel, next.tunnel) {
                    (false, true) => "on",
                    (true, false) => "off",
                    _ => "",
                };
                let (before, after) = (prev.label(), next.label());
                self.alert_at(now, NewAlert {
                    severity: Severity::Medium,
                    kind: AlertKind::NetworkChange,
                    host: None,
                    name: None,
                    message: match vpn {
                        "on" => format!("Traffic now goes through the VPN adapter {after} (was {before})"),
                        "off" => format!("The VPN adapter {before} is no longer used; traffic goes through {after}"),
                        _ => format!("Network changed: traffic goes through {after} (was {before})"),
                    },
                    details: details([
                        ("before", before),
                        ("after", after),
                        ("before_ip", prev.ip.to_string()),
                        ("after_ip", next.ip.to_string()),
                        ("vpn", vpn.into()),
                    ]),
                    key: format!("net:{}", next.ip),
                });
            }
        }
        if route.is_some() {
            self.known_route = route.clone();
        }
        self.route = route;
    }

    pub fn default_route(&self) -> Option<&RouteInfo> {
        self.route.as_ref()
    }

    /// A DNS query went to `resolver`: after the learning period, a server never seen before
    /// is reported (unless the network just changed — that alert covers it).
    fn note_resolver(&mut self, resolver: IpAddr) {
        let known = self.dns_resolvers.contains(&resolver);
        let before = self.last_resolver;
        self.last_resolver = Some(resolver);
        if known {
            return;
        }
        if self.dns_resolvers.len() >= MAX_RESOLVERS {
            return;
        }
        self.dns_resolvers.insert(resolver);
        let learning = self.first_ts.is_none_or(|f| self.now - f < RESOLVER_LEARNING_SECS);
        let after_network_change = unix_now() - self.last_network_change < RESOLVER_QUIET_SECS;
        let Some(before) = before.filter(|_| !learning && !after_network_change) else { return };
        self.alert(NewAlert {
            severity: Severity::Medium,
            kind: AlertKind::DnsResolverChange,
            host: Some(resolver.to_string()),
            name: None,
            message: format!("DNS queries now go to a new server {resolver} (before: {before})"),
            details: details([("before", before.to_string()), ("after", resolver.to_string())]),
            key: format!("resolver:{resolver}"),
        });
    }

    /// Port scans (many distinct ports of one host within a short window, either way) and
    /// large uploads (many bytes to one external host within the upload window).
    #[allow(clippy::too_many_arguments)]
    fn watch_probes_and_uploads(&mut self, sec: i64, len: u64, info: &PacketInfo, remote: IpAddr, remote_port: u16, outbound: bool, flow_id: u64) {
        let syn = matches!(info.transport, Transport::Tcp { syn: true, ack: false, .. });
        let (scan_ports, window, up_min, up_window) = (self.cfg.scan_ports, self.cfg.scan_window_secs, self.cfg.upload_min_bytes, self.cfg.upload_window_secs);
        let process = || self.flows.get(flow_id).and_then(|f| f.process.as_ref()).map(|p| p.name.clone());
        let Some(h) = self.hosts.get_mut(&remote) else { return };
        if syn && !outbound {
            let n = h.probe_in.observe(info.dst_port, sec, window);
            if n >= scan_ports {
                let seconds = (sec - h.probe_in.since).max(1);
                h.probe_in.reset();
                h.flagged = true;
                self.alert(NewAlert {
                    severity: Severity::High,
                    kind: AlertKind::PortScan,
                    host: Some(remote.to_string()),
                    name: None,
                    message: format!("Port scan from {remote}: {n} ports in {seconds} s"),
                    details: details([("direction", "in".into()), ("ports", n.to_string()), ("seconds", seconds.to_string())]),
                    key: format!("scan-in:{remote}"),
                });
            }
            return;
        }
        if syn && outbound {
            let n = h.probe_out.observe(remote_port, sec, window);
            if n >= scan_ports {
                let seconds = (sec - h.probe_out.since).max(1);
                h.probe_out.reset();
                let process = process().unwrap_or_else(|| "?".into());
                self.alert(NewAlert {
                    severity: Severity::Medium,
                    kind: AlertKind::PortScan,
                    host: Some(remote.to_string()),
                    name: None,
                    message: format!("{process} scans ports of {remote}: {n} ports in {seconds} s"),
                    details: details([("direction", "out".into()), ("process", process), ("ports", n.to_string()), ("seconds", seconds.to_string())]),
                    key: format!("scan-out:{remote}"),
                });
            }
            return;
        }
        if outbound && is_external(&remote) {
            if sec - h.up_since > up_window {
                h.up_since = sec;
                h.up_bytes = 0;
            }
            h.up_bytes += len;
            if h.up_bytes >= up_min {
                let bytes = h.up_bytes;
                let minutes = ((sec - h.up_since).max(1) + 59) / 60;
                h.up_since = sec;
                h.up_bytes = 0;
                let destination = self.names.get(&remote).map_or_else(|| remote.to_string(), |n| n.name.clone());
                let process = process().unwrap_or_else(|| "?".into());
                self.alert(NewAlert {
                    severity: Severity::Medium,
                    kind: AlertKind::LargeUpload,
                    host: Some(remote.to_string()),
                    name: self.names.get(&remote).map(|n| n.name.clone()),
                    message: format!("{process} sent {bytes} bytes to {destination} in {minutes} min"),
                    details: details([("process", process), ("destination", destination), ("bytes", bytes.to_string()), ("minutes", minutes.to_string())]),
                    key: format!("upload:{remote}"),
                });
            }
        }
    }

    /// Outbound connections that look wrong by their port: remote-control/malware ports,
    /// SMB to the internet, direct SMTP from something that is not a mail program.
    fn check_suspicious(&mut self, flow_id: u64) {
        let Some(f) = self.flows.get(flow_id) else { return };
        let Some(p) = &f.process else { return };
        if p.pid == std::process::id() || f.key.l4 != L4::Tcp || f.initiated_locally != Some(true) {
            return;
        }
        let remote = f.key.remote;
        if !is_external(&remote.ip()) {
            return;
        }
        let process = p.name.clone();
        let port = remote.port();
        let Some((reason, service, severity)) = suspicious_port(port, &process) else { return };
        let endpoint = remote.to_string();
        self.alert(NewAlert {
            severity,
            kind: AlertKind::SuspiciousConnection,
            host: Some(remote.ip().to_string()),
            name: f.name.clone(),
            message: match reason {
                "remote_control" => format!("{process} connects to {endpoint}: port {port} is typical of remote control and malware ({service})"),
                "smb" => format!("{process} opens {service} file sharing to {endpoint} on the internet"),
                _ => format!("{process} sends mail directly to {endpoint} (SMTP)"),
            },
            details: details([
                ("process", process.clone()),
                ("endpoint", endpoint),
                ("port", port.to_string()),
                ("reason", reason.into()),
                ("service", service.into()),
            ]),
            key: format!("susp:{reason}:{process}:{remote}"),
        });
    }

    /// Connections to bare IPs whose grace period is over: an unsigned (or badly signed)
    /// program talking to an address with no DNS/SNI/Host name on an uncommon port.
    fn check_unnamed_connections(&mut self) {
        let now_us = self.now.saturating_mul(1_000_000);
        while let Some(&(deadline, id, attempts)) = self.ip_checks.front() {
            if deadline > now_us {
                break;
            }
            self.ip_checks.pop_front();
            let Some(f) = self.flows.get(id) else { continue };
            let Some(p) = f.process.clone() else { continue };
            let remote = f.key.remote;
            if p.pid == std::process::id() || f.name.is_some() || self.names.contains_key(&remote.ip()) || !is_external(&remote.ip()) {
                continue;
            }
            // Common ports are fine; ports the other rule reports are reported there.
            if matches!(remote.port(), 80 | 443 | 853 | 53 | 123 | 22 | 21 | 990 | 993 | 995 | 1194 | 51820 | 500 | 4500 | 8080 | 8443)
                || suspicious_port(remote.port(), &p.name).is_some()
            {
                continue;
            }
            let Some(sig) = self.signature_for(&p) else {
                // Not verified yet: look again later (the deadline stays after the others').
                if attempts < IP_CHECK_ATTEMPTS {
                    self.ip_checks.push_back((now_us + IP_CHECK_GRACE_US, id, attempts + 1));
                }
                continue;
            };
            if !matches!(sig.status, SigStatus::Unsigned | SigStatus::Invalid) {
                continue;
            }
            let endpoint = remote.to_string();
            self.alert(NewAlert {
                severity: Severity::Medium,
                kind: AlertKind::SuspiciousConnection,
                host: Some(remote.ip().to_string()),
                name: None,
                message: format!("Unsigned program {} connects to {endpoint} by IP without a domain name", p.name),
                details: details([
                    ("process", p.name.clone()),
                    ("endpoint", endpoint),
                    ("port", remote.port().to_string()),
                    ("reason", "unsigned_ip".into()),
                    ("path", p.path.clone().unwrap_or_default()),
                ]),
                key: format!("susp:unsigned_ip:{}:{}", p.name, remote.ip()),
            });
        }
        if self.ip_checks.len() > 10_000 {
            self.ip_checks.drain(..5_000);
        }
    }

    /// A new connection could not be attributed yet.
    pub fn wants_owner_refresh(&self) -> bool {
        self.want_owners
    }

    pub fn owners(&self) -> Option<&Arc<OwnerIndex>> {
        self.owners.as_ref()
    }

    pub fn flow(&self, id: u64) -> Option<&Flow> {
        self.flows.get(id)
    }

    pub fn flows(&self) -> impl Iterator<Item = &Flow> {
        self.flows.iter()
    }

    pub fn process_stats(&self) -> impl Iterator<Item = &(ProcInfo, ProcStats)> {
        self.proc_stats.values()
    }

    /// A private address that opens TCP connections or sends DNS queries is a client,
    /// i.e. one of "our" machines.
    fn learn_local_address(&mut self, i: &PacketInfo) {
        const MAX_LEARNED: usize = 16;
        let client = matches!(i.transport, Transport::Tcp { syn: true, ack: false, .. })
            || matches!(&i.app, App::Dns(m) if !m.response);
        if client && is_local_scope(&i.src) && self.local.len() < MAX_LEARNED {
            self.local.insert(i.src);
        }
    }

    /// (remote address, outbound?, remote port) from the local machine's point of view.
    fn orient(&self, i: &PacketInfo) -> (IpAddr, bool, u16) {
        let outbound = if self.local.contains(&i.src) {
            true
        } else if self.local.contains(&i.dst) {
            false
        } else {
            // Unknown local addresses (pcap file): local-scope source talking out = outbound.
            !(is_local_scope(&i.dst) && !is_local_scope(&i.src))
        };
        if outbound {
            (i.dst, true, i.dst_port)
        } else {
            (i.src, false, i.src_port)
        }
    }

    fn inspect(&mut self, ts_us: i64, info: &PacketInfo, remote: IpAddr, remote_port: u16, requester: Option<Requester>) {
        if let App::Dns(m) = &info.app {
            let transport = if info.src_port == 5353 || info.dst_port == 5353 {
                "mdns"
            } else if matches!(info.transport, Transport::Tcp { .. }) {
                "tcp"
            } else {
                "udp"
            };
            for e in self.dns_log.record(ts_us, m, remote, requester, transport) {
                self.journal_dns(e);
            }
        }
        match &info.app {
            App::Dns(m) if m.response => {
                let Some(q) = m.questions.first() else { return };
                for a in &m.answers {
                    let keep_existing = self.names.get(&a.addr).is_some_and(|n| n.source != NameSource::Dns);
                    if !keep_existing {
                        self.names.insert(a.addr, Named { name: q.name.clone(), source: NameSource::Dns });
                    }
                }
            }
            App::Dns(m) => {
                // A query to port 53 of another machine: that machine is our resolver. Queries
                // this machine answers (hotspot, local DNS server) come from clients' ephemeral
                // ports or, once a client is learned as local, go to our own address; mDNS and
                // LLMNR use their own ports.
                if remote_port == 53 && !remote.is_multicast() && !self.local.contains(&remote) && !m.questions.is_empty() {
                    self.note_resolver(remote);
                }
                for q in &m.questions {
                    if self.dns_queries.len() < MAX_DNS_NAMES || self.dns_queries.contains_key(&q.name) {
                        *self.dns_queries.entry(q.name.clone()).or_default() += 1;
                    }
                    if let Some(f) = inspect_dns(&q.name, q.qtype) {
                        self.alert(NewAlert {
                            severity: f.severity,
                            kind: AlertKind::SuspiciousDns,
                            host: Some(remote.to_string()),
                            name: Some(q.name.clone()),
                            message: format!("DNS query for {}: {}", q.name, f.message),
                            details: details([("domain", q.name.clone()), ("reason", f.reason.into()), ("value", f.value)]),
                            key: format!("dns:{}", registrable_domain(&q.name)),
                        });
                    }
                }
            }
            App::TlsHello(h) => {
                if let Some(sni) = &h.sni {
                    self.names.insert(remote, Named { name: sni.clone(), source: NameSource::Sni });
                }
            }
            App::Http(req) => {
                if let Some(h) = &req.host {
                    let replace = self.names.get(&remote).is_none_or(|n| n.source == NameSource::Dns);
                    if replace {
                        self.names.insert(remote, Named { name: h.clone(), source: NameSource::Http });
                    }
                }
                if !req.sensitive.is_empty() {
                    let host = req.host.clone().unwrap_or_else(|| remote.to_string());
                    self.alert(NewAlert {
                        severity: Severity::High,
                        kind: AlertKind::SensitiveHttp,
                        host: Some(remote.to_string()),
                        name: req.host.clone(),
                        message: format!(
                            "Unencrypted HTTP {} http://{host}{} contains {}",
                            req.method,
                            req.path,
                            req.sensitive.join(", ")
                        ),
                        details: details([
                            ("method", req.method.clone()),
                            ("url", format!("http://{host}{}", req.path)),
                            ("data", req.sensitive.join(", ")),
                        ]),
                        key: format!("http:{remote}:{}:{}", req.path, req.sensitive.join(",")),
                    });
                }
            }
            App::None => {}
        }

        if let Transport::Tcp { syn: true, ack: false, .. } = info.transport {
            if let Some(service) = cleartext_service(remote_port) {
                self.alert(NewAlert {
                    severity: Severity::Low,
                    kind: AlertKind::CleartextProtocol,
                    host: Some(remote.to_string()),
                    name: self.names.get(&remote).map(|n| n.name.clone()),
                    message: format!("{service} connection to {remote}:{remote_port} sends data unencrypted"),
                    details: details([("service", service.into()), ("endpoint", format!("{remote}:{remote_port}"))]),
                    key: format!("clear:{remote}:{remote_port}"),
                });
            }
        }
    }

    /// Records an alert at the traffic clock (packet time).
    fn alert(&mut self, a: NewAlert) {
        self.alert_at(self.now, a);
    }

    /// Records an alert at an explicit time: events observed outside the packet stream
    /// (routes, listeners, signatures) are stamped with wall-clock time, because when a
    /// file is replayed the traffic clock is the capture's time, not today's.
    fn alert_at(&mut self, ts: i64, a: NewAlert) {
        if self.alerts.push(ts, a) {
            tracing::debug!("alert recorded at {ts}");
            if let (Some(j), Some(alert)) = (self.journal_on(), self.alerts.last()) {
                // The alert carries its own `ts` (packet time в‰€ wall time in a live capture).
                if let Some(r) = JournalRecord::new(Kind::Alerts, alert.ts, alert) {
                    j.push(r);
                }
            }
        }
    }

    /// Spike detection for every host that had traffic in the second being closed.
    fn close_second(&mut self) {
        let active = std::mem::take(&mut self.active);
        for ip in active {
            let Some(h) = self.hosts.get_mut(&ip) else { continue };
            let bytes = std::mem::take(&mut h.sec_bytes);
            if bytes == 0 {
                continue;
            }
            let threshold = (self.cfg.spike_min_bytes as f64).max(self.cfg.spike_factor * h.baseline);
            let spike = bytes as f64 > threshold;
            let baseline = h.baseline;
            // Grows gradually from zero: a new host's first (possibly partial) second
            // must not instantly become its "usual" volume and hide a spike right after.
            h.baseline = 0.8 * h.baseline + 0.2 * bytes as f64;
            h.peak_bytes_per_sec = h.peak_bytes_per_sec.max(bytes);
            if !spike || self.names.contains_key(&ip) || !is_external(&ip) {
                continue;
            }
            h.flagged = true;
            let severity = if bytes as f64 > 10.0 * threshold { Severity::High } else { Severity::Medium };
            // Plain bytes per second: the UI picks units and locale.
            let baseline = baseline.round() as u64;
            self.alert(NewAlert {
                severity,
                kind: AlertKind::VolumeSpike,
                host: Some(ip.to_string()),
                name: None,
                message: format!("Traffic spike to unrecognized host {ip}: {bytes} bytes/s (usual {baseline} bytes/s), no DNS/SNI name seen for it"),
                details: details([("rate", bytes.to_string()), ("baseline", baseline.to_string())]),
                key: format!("spike:{ip}"),
            });
        }
    }

    fn evict(&mut self) {
        for f in self.flows.evict() {
            if !f.journaled {
                self.journal_flow(&f, "evicted");
            }
        }
        if self.proc_stats.len() > 2048 {
            let horizon = self.proc_stats.values().map(|(_, s)| s.last_us).max().unwrap_or(0) - 3_600_000_000;
            self.proc_stats.retain(|_, (_, s)| s.last_us >= horizon);
        }
        if self.hosts.len() > self.cfg.max_hosts {
            let mut by_age: Vec<(i64, IpAddr)> = self.hosts.iter().map(|(ip, h)| (h.last_seen, *ip)).collect();
            by_age.sort_unstable();
            let remove = self.hosts.len() - self.cfg.max_hosts * 9 / 10;
            for (_, ip) in by_age.into_iter().take(remove) {
                self.hosts.remove(&ip);
            }
            self.active.retain(|ip| self.hosts.contains_key(ip));
        }
        if self.names.len() > self.cfg.max_hosts * 4 {
            let hosts = &self.hosts;
            self.names.retain(|ip, _| hosts.contains_key(ip));
        }
    }
}

/// Routers between us and a host, from the TTL of its packets: the distance below the
/// nearest common initial TTL (64 for Linux/macOS, 128 for Windows, 255 for network gear).
pub fn estimate_hops(ttl: u8) -> u8 {
    match ttl {
        0..=64 => 64 - ttl,
        65..=128 => 128 - ttl,
        _ => 255 - ttl,
    }
}
/// `(reason, service, severity)` when an outbound connection to `port` by `process` is
/// suspicious by the port alone.
fn suspicious_port(port: u16, process: &str) -> Option<(&'static str, &'static str, Severity)> {
    Some(match port {
        4444 => ("remote_control", "Metasploit", Severity::High),
        1337 | 31337 => ("remote_control", "backdoor", Severity::High),
        5555 => ("remote_control", "ADB", Severity::High),
        3389 => ("remote_control", "RDP", Severity::Medium),
        5900..=5903 => ("remote_control", "VNC", Severity::Medium),
        445 => ("smb", "SMB", Severity::Medium),
        139 => ("smb", "NetBIOS", Severity::Medium),
        135 => ("smb", "RPC", Severity::Medium),
        25 if !is_mail_program(process) => ("mail", "SMTP", Severity::Medium),
        _ => return None,
    })
}

/// Programs expected to talk SMTP (port 25) themselves.
/// Known mail clients and servers, by program name (without `.exe`, any case). The whole
/// name must match: a substring test would let "notmailware.exe" send mail unnoticed.
fn is_mail_program(name: &str) -> bool {
    const MAIL: &[&str] = &[
        "outlook", "olk", "hxoutlook", "hxtsr", "thunderbird", "betterbird", "mail", "postbox", "mailbird", "mailclient", "emclient",
        "evolution", "kmail", "geary", "mutt", "neomutt", "claws-mail", "sylpheed", "sendmail", "postfix", "smtp", "smtpd", "exim",
        "exim4", "msmtp", "hmailserver", "mailenable", "memta",
    ];
    let n = name.trim().to_lowercase();
    let n = n.strip_suffix(".exe").unwrap_or(&n);
    MAIL.contains(&n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analytics::flows::FlowState;
    use crate::decode::{dns, http::HttpRequest};

    const ME: &str = "192.168.1.50";

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn state() -> State {
        let info = CaptureInfo {
            mode: "demo",
            source: "test".into(),
            description: None,
            filter: None,
            libpcap: None,
            status: CaptureStatus::Running,
        };
        State::new(Config::default(), [ip(ME)].into_iter().collect(), info)
    }

    fn pkt(src: &str, dst: &str, sport: u16, dport: u16, proto: Proto, app: App) -> PacketInfo {
        let transport = if matches!(proto, Proto::Dns | Proto::Udp | Proto::Quic) {
            Transport::Udp
        } else {
            Transport::TCP_ACK
        };
        PacketInfo { src: ip(src), dst: ip(dst), src_port: sport, dst_port: dport, transport, proto, app, ttl: 64, tcp: None }
    }

    const T0: i64 = 1_760_000_000;

    fn us(sec: i64) -> i64 {
        sec * 1_000_000
    }

    #[test]
    fn direction_and_totals() {
        let mut s = state();
        s.record(us(T0), 100, Some(&pkt(ME, "8.8.8.8", 5000, 443, Proto::Tls, App::None)));
        s.record(us(T0), 1500, Some(&pkt("8.8.8.8", ME, 443, 5000, Proto::Tls, App::None)));
        s.record(us(T0), 60, None);
        let t = s.totals();
        assert_eq!((t.packets, t.bytes, t.bytes_out, t.bytes_in, t.non_ip_packets), (3, 1660, 100, 1560, 1));
        let h = s.host(&ip("8.8.8.8")).unwrap();
        assert_eq!((h.bytes_out, h.bytes_in, h.packets), (100, 1500, 2));
        assert_eq!(h.ports.iter().copied().collect::<Vec<_>>(), vec![443]);
        assert_eq!(h.protocols(), vec![Proto::Tls]);
        assert_eq!(s.protocol(Proto::Tls).bytes, 1600);
        assert_eq!(s.protocol(Proto::Other).packets, 1);
    }

    #[test]
    fn direction_without_known_local_addresses() {
        let mut s = State::new(Config::default(), HashSet::new(), state().capture);
        s.record(us(T0), 10, Some(&pkt("10.0.0.2", "1.1.1.1", 1, 443, Proto::Tls, App::None)));
        s.record(us(T0), 20, Some(&pkt("1.1.1.1", "10.0.0.2", 443, 1, Proto::Tls, App::None)));
        assert_eq!((s.totals().bytes_out, s.totals().bytes_in), (10, 20));
        assert_eq!(s.hosts.len(), 1);
    }

    #[test]
    fn learns_local_addresses_when_unknown() {
        let mut s = State::new(Config::default(), HashSet::new(), state().capture);
        let q = dns::parse(&dns::build_query(1, "example.org", dns::TYPE_A)).unwrap();
        s.record(us(T0), 80, Some(&pkt("192.168.1.50", "192.168.1.1", 5000, 53, Proto::Dns, App::Dns(q))));
        let r = dns::parse(&dns::build_response(1, "example.org", &[ip("93.184.215.14")], 60)).unwrap();
        s.record(us(T0), 90, Some(&pkt("192.168.1.1", "192.168.1.50", 53, 5000, Proto::Dns, App::Dns(r))));
        // The LAN resolver is the remote side; our machine never shows up as a "destination".
        assert_eq!(s.host(&ip("192.168.1.1")).unwrap().packets, 2);
        assert!(s.host(&ip("192.168.1.50")).is_none());
        assert_eq!((s.totals().bytes_out, s.totals().bytes_in), (80, 90));
    }

    #[test]
    fn traffic_between_other_devices_is_not_attributed() {
        use crate::procs::{OsSnapshot, OwnerIndex, SocketEntry};
        let mut s = state();
        let mut procs = HashMap::new();
        procs.insert(77, ProcInfo { pid: 77, name: "mdns.exe".into(), path: None, parent: None });
        s.set_owners(Arc::new(OwnerIndex::new(OsSnapshot {
            sockets: vec![SocketEntry { proto: SockProto::Udp, local: "0.0.0.0:5353".parse().unwrap(), remote: None, state: None, pid: 77 }],
            procs,
            error: None,
        })));
        // Another device's mDNS announcement vs. our own query from the same port.
        s.record(us(T0), 100, Some(&pkt("192.168.1.7", "224.0.0.251", 5353, 5353, Proto::Dns, App::None)));
        s.record(us(T0), 100, Some(&pkt(ME, "224.0.0.251", 5353, 5353, Proto::Dns, App::None)));
        let owned: Vec<u32> = s.flows().filter_map(|f| f.process.as_ref().map(|p| p.pid)).collect();
        assert_eq!(owned, vec![77], "only our own packet is attributed");
        assert!(!s.wants_owner_refresh());
    }

    #[test]
    fn constant_timestamps_still_respect_memory_limits() {
        let mut s = state();
        s.flows = FlowTable::new(50);
        for i in 0..500u16 {
            s.record_frame(us(T0), 100, &[0u8; 100], Some(&pkt(ME, "203.0.113.1", 10_000 + i, 443, Proto::Tls, App::None)));
        }
        assert!(s.flows.len() <= 55, "{} flows kept", s.flows.len());
    }

    #[test]
    fn names_from_dns_sni_and_http() {
        let mut s = state();
        let resp = dns::parse(&dns::build_response(1, "example.org", &[ip("93.184.215.14")], 60)).unwrap();
        s.record(us(T0), 90, Some(&pkt("1.1.1.1", ME, 53, 5000, Proto::Dns, App::Dns(resp))));
        assert_eq!(s.name_of(&ip("93.184.215.14")).unwrap().name, "example.org");

        s.record(us(T0), 300, Some(&pkt(ME, "140.82.121.4", 5001, 443, Proto::Tls, App::TlsHello(crate::decode::TlsHello::with_sni("github.com")))));
        assert_eq!(s.name_of(&ip("140.82.121.4")).unwrap().source, NameSource::Sni);

        // SNI wins over a later DNS answer for the same IP.
        let resp = dns::parse(&dns::build_response(2, "other.test", &[ip("140.82.121.4")], 60)).unwrap();
        s.record(us(T0), 90, Some(&pkt("1.1.1.1", ME, 53, 5000, Proto::Dns, App::Dns(resp))));
        assert_eq!(s.name_of(&ip("140.82.121.4")).unwrap().name, "github.com");

        let req = HttpRequest { method: "GET".into(), path: "/".into(), host: Some("plain.test".into()), sensitive: vec![] };
        s.record(us(T0), 200, Some(&pkt(ME, "198.51.100.7", 5002, 80, Proto::Http, App::Http(req))));
        assert_eq!(s.name_of(&ip("198.51.100.7")).unwrap().name, "plain.test");
        assert_eq!(s.alerts.counts().total, 0);
    }

    #[test]
    fn sensitive_http_alert_is_deduplicated() {
        let mut s = state();
        let req = HttpRequest {
            method: "POST".into(),
            path: "/login".into(),
            host: Some("shop.test".into()),
            sensitive: vec!["password"],
        };
        let p = pkt(ME, "198.51.100.7", 5000, 80, Proto::Http, App::Http(req));
        s.record(us(T0), 500, Some(&p));
        s.record(us(T0 + 5), 500, Some(&p));
        let alerts = s.alerts.recent(10);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::High);
        assert!(alerts[0].message.contains("http://shop.test/login") && alerts[0].message.contains("password"));
    }

    #[test]
    fn suspicious_dns_and_cleartext_alerts() {
        let mut s = state();
        let q = dns::parse(&dns::build_query(1, "x7k2p9q4m1v8b3n6c5z0w1.exfil.example", dns::TYPE_A)).unwrap();
        s.record(us(T0), 90, Some(&pkt(ME, "1.1.1.1", 5000, 53, Proto::Dns, App::Dns(q))));
        let mut syn = pkt(ME, "198.51.100.23", 5001, 23, Proto::Tcp, App::None);
        syn.transport = Transport::TCP_SYN;
        s.record(us(T0), 60, Some(&syn));
        let kinds: Vec<AlertKind> = s.alerts.recent(10).iter().map(|a| a.kind).collect();
        assert_eq!(kinds, vec![AlertKind::CleartextProtocol, AlertKind::SuspiciousDns]);
        assert_eq!(s.dns_queries.get("x7k2p9q4m1v8b3n6c5z0w1.exfil.example"), Some(&1));
    }

    fn syn(src: &str, dst: &str, sport: u16, dport: u16) -> PacketInfo {
        let mut p = pkt(src, dst, sport, dport, Proto::Tcp, App::None);
        p.transport = Transport::TCP_SYN;
        p
    }

    fn owners(sockets: Vec<(SockProto, &str, Option<&str>, u32)>, procs: Vec<(u32, &str, Option<&str>)>) -> Arc<OwnerIndex> {
        use crate::procs::{OsSnapshot, SocketEntry};
        let procs = procs
            .into_iter()
            .map(|(pid, name, path)| (pid, ProcInfo { pid, name: name.into(), path: path.map(String::from), parent: None }))
            .collect();
        let sockets = sockets
            .into_iter()
            .map(|(proto, local, remote, pid)| SocketEntry {
                proto,
                local: local.parse().unwrap(),
                remote: remote.map(|r| r.parse().unwrap()),
                state: (proto == SockProto::Tcp).then_some("ESTABLISHED"),
                pid,
            })
            .collect();
        Arc::new(OwnerIndex::new(OsSnapshot { sockets, procs, error: None }))
    }

    #[test]
    fn inbound_and_outbound_port_scans() {
        let mut s = state();
        for port in 1..=14 {
            s.record(us(T0), 60, Some(&syn("192.168.1.66", ME, 40000 + port, port)));
        }
        assert!(s.alerts.recent(10).is_empty(), "14 ports are below the threshold");
        s.record(us(T0) + 500_000, 60, Some(&syn("192.168.1.66", ME, 40015, 15)));
        let a = s.alerts.recent(10);
        assert_eq!(a.len(), 1, "{a:?}");
        assert_eq!((a[0].kind, a[0].severity, a[0].host.as_deref()), (AlertKind::PortScan, Severity::High, Some("192.168.1.66")));
        assert_eq!((a[0].details["direction"].as_str(), a[0].details["ports"].as_str(), a[0].details["seconds"].as_str()), ("in", "15", "1"));
        // The window restarts: the same host must probe 15 more ports for another alert.
        for port in 100..=114 {
            s.record(us(T0) + 600_000, 60, Some(&syn("192.168.1.66", ME, 41000 + port, port)));
        }
        assert_eq!(s.alerts.recent(10).len(), 1, "a repeat within the suppression window is dropped");

        // Outbound: a program sweeping a host. Ports probed 20 s apart do not add up.
        let mut s = state();
        for port in 1..=14 {
            s.record(us(T0 + 20 * i64::from(port)), 60, Some(&syn(ME, "203.0.113.5", 50000 + port, port)));
        }
        assert!(s.alerts.recent(10).is_empty());
        for port in 1..=15 {
            s.record(us(T0 + 1000), 60, Some(&syn(ME, "203.0.113.5", 51000 + port, 8000 + port)));
        }
        let a = s.alerts.recent(10);
        assert_eq!(a.len(), 1, "{a:?}");
        assert_eq!((a[0].kind, a[0].severity, a[0].details["direction"].as_str(), a[0].details["process"].as_str()), (AlertKind::PortScan, Severity::Medium, "out", "?"));
        // Ordinary browsing: many connections to the same two ports are not a scan.
        let mut s = state();
        for i in 0..40u16 {
            s.record(us(T0), 60, Some(&syn(ME, "203.0.113.5", 52000 + i, if i % 2 == 0 { 80 } else { 443 })));
        }
        assert!(s.alerts.recent(10).is_empty());
    }

    #[test]
    fn large_upload_to_one_host() {
        let cfg = Config { upload_min_bytes: 10_000, upload_window_secs: 600, ..Config::default() };
        let mut s = State::new(cfg, [ip(ME)].into_iter().collect(), state().capture);
        s.names.insert(ip("203.0.113.9"), Named { name: "drop.example".into(), source: NameSource::Sni });
        s.set_owners(owners(vec![(SockProto::Tcp, "192.168.1.50:5000", Some("203.0.113.9:443"), 9)], vec![(9, "sync.exe", None)]));
        for i in 0..6 {
            s.record(us(T0 + i * 30), 1400, Some(&pkt(ME, "203.0.113.9", 5000, 443, Proto::Tls, App::None)));
            // Downloads do not count.
            s.record(us(T0 + i * 30), 1400, Some(&pkt("203.0.113.9", ME, 443, 5000, Proto::Tls, App::None)));
        }
        assert!(s.alerts.recent(10).is_empty(), "8400 bytes sent");
        s.record(us(T0 + 180), 1400, Some(&pkt(ME, "203.0.113.9", 5000, 443, Proto::Tls, App::None)));
        s.record(us(T0 + 180), 1400, Some(&pkt(ME, "203.0.113.9", 5000, 443, Proto::Tls, App::None)));
        let a = s.alerts.recent(10);
        assert_eq!(a.len(), 1, "{a:?}");
        assert_eq!((a[0].kind, a[0].host.as_deref(), a[0].name.as_deref()), (AlertKind::LargeUpload, Some("203.0.113.9"), Some("drop.example")));
        assert_eq!((a[0].details["process"].as_str(), a[0].details["destination"].as_str(), a[0].details["bytes"].as_str(), a[0].details["minutes"].as_str()), ("sync.exe", "drop.example", "11200", "3"));
        // LAN transfers are not uploads to the internet.
        for _ in 0..20 {
            s.record(us(T0 + 181), 1400, Some(&pkt(ME, "192.168.1.9", 5001, 445, Proto::Tcp, App::None)));
        }
        assert_eq!(s.alerts.recent(10).len(), 1);
    }

    #[test]
    fn resolver_changes_after_learning_unless_the_network_just_changed() {
        let mut s = state();
        let query = |name: &str| App::Dns(dns::parse(&dns::build_query(1, name, dns::TYPE_A)).unwrap());
        s.record(us(T0), 80, Some(&pkt(ME, "192.168.1.1", 5000, 53, Proto::Dns, query("a.example"))));
        s.record(us(T0 + 10), 80, Some(&pkt(ME, "192.168.1.2", 5000, 53, Proto::Dns, query("a.example"))));
        s.record(us(T0 + 30), 80, Some(&pkt(ME, "224.0.0.251", 5353, 5353, Proto::Dns, query("tv.local"))));
        assert!(s.alerts.recent(10).is_empty(), "two resolvers in the first minute are the baseline; mDNS never counts");
        s.record(us(T0 + 61), 80, Some(&pkt(ME, "192.168.1.1", 5000, 53, Proto::Dns, query("b.example"))));
        s.record(us(T0 + 62), 80, Some(&pkt(ME, "8.8.8.8", 5000, 53, Proto::Dns, query("b.example"))));
        let a = s.alerts.recent(10);
        assert_eq!(a.len(), 1, "{a:?}");
        assert_eq!((a[0].kind, a[0].host.as_deref(), a[0].details["before"].as_str(), a[0].details["after"].as_str()), (AlertKind::DnsResolverChange, Some("8.8.8.8"), "192.168.1.1", "8.8.8.8"));
        s.record(us(T0 + 63), 80, Some(&pkt(ME, "8.8.8.8", 5000, 53, Proto::Dns, query("c.example"))));
        assert_eq!(s.alerts.recent(10).len(), 1, "a known resolver is not news");
        // Right after the network changed, a new resolver is part of that event.
        let home = RouteInfo { ip: ip("192.168.1.50"), adapter: Some("Wi-Fi".into()), tunnel: false };
        let vpn = RouteInfo { ip: ip("10.8.0.2"), adapter: Some("WireGuard".into()), tunnel: true };
        s.set_default_route(Some(home.clone()));
        s.set_default_route(Some(vpn));
        assert_eq!(s.alerts.recent(10)[0].kind, AlertKind::NetworkChange);
        s.record(us(T0 + 70), 80, Some(&pkt(ME, "10.8.0.1", 5000, 53, Proto::Dns, query("d.example"))));
        assert_eq!(s.alerts.recent(10).len(), 2, "no resolver alert within the quiet period");
        assert_eq!(s.default_route().map(|r| r.tunnel), Some(true));
    }

    #[test]
    fn network_and_egress_changes_with_vpn_hints() {
        let mut s = state();
        let home = RouteInfo { ip: ip("192.168.1.50"), adapter: Some("Wi-Fi".into()), tunnel: false };
        let vpn = RouteInfo { ip: ip("10.8.0.2"), adapter: Some("WireGuard Tunnel".into()), tunnel: true };
        let eg = |ip: &str, loc: &str| Egress { ip: ip.into(), colo: None, loc: Some(loc.into()), geo: None, checked_at: 0 };
        s.set_default_route(Some(home.clone()));
        s.set_egress(Ok(eg("203.0.113.1", "RU")));
        s.set_egress(Ok(eg("203.0.113.1", "RU")));
        s.set_egress(Err("timeout".into()));
        assert!(s.alerts.recent(10).is_empty(), "the first route, an unchanged address and a failed check are not news");
        s.set_default_route(Some(vpn.clone()));
        s.set_egress(Ok(eg("198.51.100.7", "NL")));
        let a = s.alerts.recent(10);
        assert_eq!(a.iter().map(|a| a.kind).collect::<Vec<_>>(), vec![AlertKind::EgressChange, AlertKind::NetworkChange]);
        let net = &a[1];
        assert_eq!((net.details["before"].as_str(), net.details["after"].as_str(), net.details["vpn"].as_str()), ("Wi-Fi", "WireGuard Tunnel", "on"));
        let eg_a = &a[0];
        assert_eq!((eg_a.details["before"].as_str(), eg_a.details["after"].as_str(), eg_a.details["vpn"].as_str()), ("203.0.113.1 (RU)", "198.51.100.7 (NL)", "on"));
        assert_eq!(eg_a.details["after_country"], "NL");
        // Back home: the VPN is off.
        s.set_default_route(Some(home));
        s.set_egress(Ok(eg("203.0.113.1", "RU")));
        let a = s.alerts.recent(10);
        assert_eq!(a.len(), 4);
        assert_eq!((a[0].kind, a[0].details["vpn"].as_str()), (AlertKind::EgressChange, "off"));
        assert_eq!((a[1].kind, a[1].details["vpn"].as_str()), (AlertKind::NetworkChange, "off"));
        // Losing the route is not reported; coming back to the same adapter is not either.
        s.set_default_route(None);
        assert_eq!(s.default_route(), None);
        s.set_default_route(Some(RouteInfo { ip: ip("192.168.1.50"), adapter: Some("Wi-Fi".into()), tunnel: false }));
        assert_eq!(s.alerts.recent(10).len(), 4);
        // A reconnect elsewhere is compared to the route before the gap.
        s.set_default_route(None);
        s.set_default_route(Some(RouteInfo { ip: ip("172.16.0.5"), adapter: None, tunnel: false }));
        let a = s.alerts.recent(10);
        assert_eq!(a.len(), 5);
        assert_eq!((a[0].kind, a[0].details["before"].as_str(), a[0].details["after"].as_str()), (AlertKind::NetworkChange, "Wi-Fi", "172.16.0.5"));
        assert_eq!(s.default_route().unwrap().label(), "172.16.0.5");
    }

    #[test]
    fn a_new_address_on_the_same_adapter_is_not_a_network_change() {
        let mut s = state();
        let wifi = |addr: &str| Some(RouteInfo { ip: ip(addr), adapter: Some("Wi-Fi".into()), tunnel: false });
        s.set_default_route(wifi("192.168.1.50"));
        assert_eq!(s.last_network_change, 0, "the first route is not a change");
        s.set_default_route(wifi("192.168.1.51"));
        s.set_default_route(wifi("10.20.30.40"));
        assert!(s.alerts.recent(10).is_empty(), "DHCP renewal / another Wi-Fi network: {:?}", s.alerts.recent(10));
        assert!(s.last_network_change > 0, "still a change for the resolver quiet period");
        assert_eq!(s.default_route().unwrap().ip, ip("10.20.30.40"));
        // The same adapter turning into a tunnel is a change of role.
        s.set_default_route(Some(RouteInfo { ip: ip("10.20.30.40"), adapter: Some("Wi-Fi".into()), tunnel: true }));
        assert_eq!(s.alerts.recent(10)[0].details["vpn"], "on");
    }

    #[test]
    fn a_reconnect_starts_the_resolver_quiet_period() {
        let mut s = state();
        let query = |name: &str| App::Dns(dns::parse(&dns::build_query(1, name, dns::TYPE_A)).unwrap());
        s.set_default_route(Some(RouteInfo { ip: ip(ME), adapter: Some("Wi-Fi".into()), tunnel: false }));
        s.record(us(T0), 80, Some(&pkt(ME, "192.168.1.1", 5000, 53, Proto::Dns, query("a.example"))));
        s.record(us(T0 + 61), 80, Some(&pkt(ME, "192.168.1.1", 5000, 53, Proto::Dns, query("a.example"))));
        // Offline for a while, then back on another network with its own resolver.
        s.set_default_route(None);
        s.set_default_route(Some(RouteInfo { ip: ip(ME), adapter: Some("Wi-Fi".into()), tunnel: false }));
        s.record(us(T0 + 300), 80, Some(&pkt(ME, "10.0.0.1", 5000, 53, Proto::Dns, query("b.example"))));
        assert!(s.alerts.recent(10).is_empty(), "{:?}", s.alerts.recent(10));
    }

    #[test]
    fn queries_this_machine_answers_are_not_resolvers() {
        let mut s = state();
        let query = |name: &str| App::Dns(dns::parse(&dns::build_query(1, name, dns::TYPE_A)).unwrap());
        s.record(us(T0), 80, Some(&pkt(ME, "192.168.1.1", 5000, 53, Proto::Dns, query("a.example"))));
        // After the learning minute: hotspot / local DNS server clients ask this machine.
        for (n, client) in ["192.168.137.5", "192.168.137.6", "10.0.0.9"].iter().enumerate() {
            let t = T0 + 61 + n as i64;
            s.record(us(t), 80, Some(&pkt(client, ME, 50000 + n as u16, 53, Proto::Dns, query("x.example"))));
            s.record(us(t), 80, Some(&pkt(client, ME, 50100 + n as u16, 53, Proto::Dns, query("y.example"))));
        }
        // Queries to a resolver on an unusual port (not DNS-over-53) are not resolver changes.
        s.record(us(T0 + 70), 80, Some(&pkt(ME, "203.0.113.53", 5000, 5300, Proto::Dns, query("z.example"))));
        let a: Vec<_> = s.alerts.recent(10).into_iter().filter(|a| a.kind == AlertKind::DnsResolverChange).collect();
        assert!(a.is_empty(), "{a:?}");
        // A real new resolver is still reported.
        s.record(us(T0 + 71), 80, Some(&pkt(ME, "9.9.9.9", 5001, 53, Proto::Dns, query("q.example"))));
        let a: Vec<_> = s.alerts.recent(10).into_iter().filter(|a| a.kind == AlertKind::DnsResolverChange).collect();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].details["after"], "9.9.9.9");
    }

    #[test]
    fn mail_programs_match_by_whole_name() {
        for name in ["thunderbird.exe", "OUTLOOK.EXE", "olk.exe", "HxTsr.exe", "MailClient.exe", "mail", "exim4", "smtp"] {
            assert!(is_mail_program(name), "{name}");
        }
        for name in ["notmailware.exe", "smtp-backdoor.exe", "mailstealer.exe", "outlook-update.exe", "", ".exe"] {
            assert!(!is_mail_program(name), "{name}");
        }
    }

    #[test]
    fn suspicious_connections_by_port_and_unsigned_programs_on_bare_ips() {
        let mut s = state();
        // Attribution arrives with the socket table: the check runs then.
        s.record(us(T0), 60, Some(&syn(ME, "203.0.113.9", 5002, 4444)));
        s.record(us(T0), 60, Some(&syn(ME, "203.0.113.9", 5003, 25)));
        s.record(us(T0), 60, Some(&syn(ME, "203.0.113.9", 5004, 25)));
        s.record(us(T0), 60, Some(&syn(ME, "203.0.113.9", 5005, 445)));
        s.record(us(T0), 60, Some(&syn(ME, "192.168.1.9", 5006, 445)));
        s.record(us(T0), 60, Some(&syn(ME, "203.0.113.9", 5007, 9999)));
        s.record(us(T0), 60, Some(&syn(ME, "203.0.113.9", 5008, 9999)));
        assert!(s.alerts.recent(10).is_empty());
        s.set_owners(owners(
            vec![
                (SockProto::Tcp, "192.168.1.50:5002", Some("203.0.113.9:4444"), 11),
                (SockProto::Tcp, "192.168.1.50:5003", Some("203.0.113.9:25"), 12),
                (SockProto::Tcp, "192.168.1.50:5004", Some("203.0.113.9:25"), 13),
                (SockProto::Tcp, "192.168.1.50:5005", Some("203.0.113.9:445"), 11),
                (SockProto::Tcp, "192.168.1.50:5006", Some("192.168.1.9:445"), 11),
                (SockProto::Tcp, "192.168.1.50:5007", Some("203.0.113.9:9999"), 14),
                (SockProto::Tcp, "192.168.1.50:5008", Some("203.0.113.9:9999"), 11),
            ],
            vec![
                (11, "dropper.exe", Some(r"C:\Users\x\AppData\Local\Temp\dropper.exe")),
                (12, "thunderbird.exe", Some(r"C:\Program Files\Mozilla Thunderbird\thunderbird.exe")),
                (13, "svc.exe", Some(r"C:\tools\svc.exe")),
                (14, "good.exe", Some(r"C:\Program Files\Good\good.exe")),
            ],
        ));
        let a = s.alerts.recent(10);
        let mut reasons: Vec<(String, String, Severity)> = a.iter().map(|x| (x.details["reason"].clone(), x.details["process"].clone(), x.severity)).collect();
        reasons.sort();
        assert_eq!(
            reasons,
            vec![
                ("mail".to_string(), "svc.exe".to_string(), Severity::Medium),
                ("remote_control".to_string(), "dropper.exe".to_string(), Severity::High),
                ("smb".to_string(), "dropper.exe".to_string(), Severity::Medium),
            ],
            "{a:?}"
        );
        assert!(a.iter().all(|x| x.kind == AlertKind::SuspiciousConnection && x.host.as_deref() == Some("203.0.113.9")));
        assert_eq!(a.iter().find(|x| x.details["reason"] == "remote_control").unwrap().details["service"], "Metasploit");

        // Bare-IP rule: only unsigned programs, only after the grace period, only without a name.
        let mut sigs = HashMap::new();
        sigs.insert(r"C:\Users\x\AppData\Local\Temp\dropper.exe".to_string(), Signature { status: SigStatus::Unsigned, signer: None });
        sigs.insert(r"C:\Program Files\Good\good.exe".to_string(), Signature { status: SigStatus::Signed, signer: Some("Good Inc".into()) });
        s.set_signatures(sigs);
        let before = s.alerts.recent(20).len();
        s.advance(T0 + 2);
        assert_eq!(s.alerts.recent(20).len(), before, "nothing before the grace period");
        s.advance(T0 + 4);
        let a = s.alerts.recent(20);
        let unnamed: Vec<&super::super::Alert> = a.iter().filter(|x| x.details.get("reason").is_some_and(|r| r == "unsigned_ip")).collect();
        assert_eq!(unnamed.len(), 1, "{a:?}");
        assert_eq!((unnamed[0].details["process"].as_str(), unnamed[0].details["endpoint"].as_str()), ("dropper.exe", "203.0.113.9:9999"));
    }

    #[test]
    fn a_bare_ip_connection_waits_for_the_signature_check() {
        let mut s = state();
        s.record(us(T0), 60, Some(&syn(ME, "203.0.113.9", 5007, 9999)));
        s.record(us(T0), 60, Some(&syn(ME, "203.0.113.10", 5008, 9999)));
        s.set_owners(owners(
            vec![(SockProto::Tcp, "192.168.1.50:5007", Some("203.0.113.9:9999"), 11), (SockProto::Tcp, "192.168.1.50:5008", Some("203.0.113.10:9999"), 12)],
            vec![(11, "fresh.exe", Some(r"C:	oolsresh.exe")), (12, "slow.exe", Some(r"C:	ools\slow.exe"))],
        ));
        let unsigned_ip = |s: &State| s.alerts.recent(20).into_iter().filter(|a| a.details.get("reason").is_some_and(|r| r == "unsigned_ip")).map(|a| a.details["process"].clone()).collect::<Vec<_>>();
        // The grace period is over, but the (slow) Authenticode check has not answered yet.
        s.advance(T0 + 4);
        assert!(unsigned_ip(&s).is_empty());
        assert_eq!(s.ip_checks.len(), 2, "both connections are queued again");
        // The answer arrives ten seconds later: the connection is still judged.
        let mut sigs = HashMap::new();
        sigs.insert(r"C:	oolsresh.exe".to_string(), Signature { status: SigStatus::Unsigned, signer: None });
        s.set_signatures(sigs);
        s.advance(T0 + 14);
        assert_eq!(unsigned_ip(&s), vec!["fresh.exe".to_string()]);
        // A program whose signature never gets checked is given up on after a bounded time.
        for t in 15..(15 + 4 * IP_CHECK_ATTEMPTS as i64) {
            s.advance(T0 + t);
        }
        assert!(s.ip_checks.is_empty(), "{:?}", s.ip_checks);
        assert_eq!(unsigned_ip(&s).len(), 1);
    }

    #[test]
    fn a_failed_capture_is_an_alert_once() {
        let mut s = state();
        s.set_status(CaptureStatus::Failed("adapter gone".into()));
        s.set_status(CaptureStatus::Failed("adapter gone".into()));
        let a = s.alerts.recent(10);
        assert_eq!(a.len(), 1);
        assert_eq!((a[0].kind, a[0].severity, a[0].details["error"].as_str()), (AlertKind::CaptureFailed, Severity::High, "adapter gone"));
        s.set_status(CaptureStatus::Finished);
        assert_eq!(s.alerts.recent(10).len(), 1);
    }

    #[test]
    fn spike_only_for_unrecognized_external_hosts() {
        let mut s = state();
        let named = ip("93.184.215.14");
        s.names.insert(named, Named { name: "example.org".into(), source: NameSource::Dns });
        for (dst, n) in [("203.0.113.77", 2000), ("93.184.215.14", 2000), ("192.168.1.9", 2000), ("203.0.113.80", 10)] {
            for _ in 0..n {
                s.record(us(T0), 1400, Some(&pkt(ME, dst, 5000, 9000, Proto::Tcp, App::None)));
            }
        }
        s.advance(T0 + 1);
        let alerts = s.alerts.recent(10);
        assert_eq!(alerts.len(), 1, "{alerts:?}");
        assert_eq!(alerts[0].kind, AlertKind::VolumeSpike);
        assert_eq!(alerts[0].host.as_deref(), Some("203.0.113.77"));
        assert_eq!(alerts[0].details["rate"], (2000 * 1400).to_string(), "plain bytes per second");
        assert_eq!(alerts[0].details["baseline"], "0");
        assert!(alerts[0].details["rate"].bytes().all(|b| b.is_ascii_digit()));
        assert!(s.host(&ip("203.0.113.77")).unwrap().flagged);
        assert_eq!(s.host(&ip("203.0.113.77")).unwrap().peak_bytes_per_sec, 2000 * 1400);
    }

    #[test]
    fn spike_right_after_a_partial_first_second_is_caught() {
        let mut s = state();
        // Transfer starts late in a second (0.9 MB, under the 1 MiB floor)...
        for _ in 0..600 {
            s.record(us(T0), 1500, Some(&pkt(ME, "203.0.113.9", 1, 2, Proto::Tcp, App::None)));
        }
        // ...and continues at 2.9 MB/s in the next one.
        for _ in 0..2000 {
            s.record(us(T0 + 1), 1450, Some(&pkt(ME, "203.0.113.9", 1, 2, Proto::Tcp, App::None)));
        }
        s.advance(T0 + 2);
        assert_eq!(s.alerts.counts().total, 1);
        assert!(s.host(&ip("203.0.113.9")).unwrap().flagged);
    }

    #[test]
    fn steady_heavy_traffic_is_not_a_spike_after_baseline() {
        let mut s = state();
        s.cfg.spike_min_bytes = 1000;
        // First second establishes the baseline (and alerts once); later equal seconds don't.
        for sec in 0..5 {
            s.record(us(T0 + sec), 5000, Some(&pkt(ME, "203.0.113.5", 1, 2, Proto::Tcp, App::None)));
        }
        s.advance(T0 + 10);
        assert_eq!(s.alerts.counts().total, 1);
        // A 10x jump after the suppression window alerts again.
        s.record(us(T0 + 100), 60_000, Some(&pkt(ME, "203.0.113.5", 1, 2, Proto::Tcp, App::None)));
        s.advance(T0 + 101);
        assert_eq!(s.alerts.counts().total, 2);
    }

    #[test]
    fn history_is_bounded_and_gaps_filled() {
        let mut s = state();
        s.record(us(T0), 10, None);
        s.record(us(T0 + 3), 10, None);
        assert_eq!(s.series.iter().map(|x| x.ts - T0).collect::<Vec<_>>(), vec![0, 1, 2, 3]);
        s.record(us(T0 + 10_000), 10, None);
        assert_eq!(s.series.len(), s.cfg.history_secs);
        assert_eq!(s.series.back().unwrap().ts, T0 + 10_000);
        // Late packets go into the current second.
        s.record(us(T0 + 5), 10, None);
        assert_eq!(s.series.back().unwrap().packets, 2);
    }

    #[test]
    fn hosts_are_evicted_lru() {
        let mut s = state();
        s.cfg.max_hosts = 10;
        for i in 0..20u8 {
            s.record(us(T0 + i as i64), 10, Some(&pkt(ME, &format!("198.51.100.{i}"), 1, 2, Proto::Tcp, App::None)));
        }
        s.advance(T0 + 100);
        assert!(s.hosts.len() <= 10);
        assert!(s.host(&ip("198.51.100.19")).is_some(), "most recent kept");
        assert!(s.host(&ip("198.51.100.0")).is_none(), "oldest evicted");
    }

    #[test]
    fn hop_estimates() {
        assert_eq!(estimate_hops(64), 0);
        assert_eq!(estimate_hops(52), 12);
        assert_eq!(estimate_hops(116), 12);
        assert_eq!(estimate_hops(240), 15);
    }

    #[test]
    fn hop_estimate_boundaries_and_only_inbound_packets_set_them() {
        for (ttl, hops) in [(0, 64), (1, 63), (63, 1), (64, 0), (65, 63), (127, 1), (128, 0), (129, 126), (200, 55), (254, 1), (255, 0)] {
            assert_eq!(estimate_hops(ttl), hops, "ttl {ttl}");
        }
        let mut s = state();
        let mut out = pkt(ME, "8.8.8.8", 5000, 443, Proto::Tls, App::None);
        out.ttl = 128;
        s.record(us(T0), 100, Some(&out));
        assert_eq!(s.host(&ip("8.8.8.8")).unwrap().hops, None, "our own TTL says nothing about the distance");
        assert_eq!(s.flows().next().unwrap().hops, None);
        let mut back = pkt("8.8.8.8", ME, 443, 5000, Proto::Tls, App::None);
        back.ttl = 55;
        s.record(us(T0), 100, Some(&back));
        assert_eq!(s.host(&ip("8.8.8.8")).unwrap().hops, Some(9));
        assert_eq!(s.flows().next().unwrap().hops, Some(9));
        back.ttl = 250;
        s.record(us(T0), 100, Some(&back));
        assert_eq!(s.host(&ip("8.8.8.8")).unwrap().hops, Some(5), "the latest inbound packet wins");
    }

    #[test]
    fn pid_reuse_resets_the_process_counters() {
        let mut s = state();
        let a = ProcInfo { pid: 7, name: "a.exe".into(), path: Some(r"C:\a.exe".into()), parent: None };
        {
            let st = s.proc_entry(&a, 10);
            st.bytes_in = 500;
            st.connections = 3;
            st.last_us = 20;
        }
        // Same program, updated details (path, parent): counters are kept.
        let a2 = ProcInfo { path: Some(r"D:\a.exe".into()), parent: Some(1), ..a.clone() };
        assert_eq!(s.proc_entry(&a2, 30).bytes_in, 500);
        assert_eq!((s.proc_stats[&7].0.path.as_deref(), s.proc_stats[&7].0.parent), (Some(r"D:\a.exe"), Some(1)));
        // A different program under the same PID starts from zero, at its own first packet.
        let b = ProcInfo { pid: 7, name: "b.exe".into(), path: Some(r"C:\b.exe".into()), parent: None };
        let st = s.proc_entry(&b, 40);
        assert_eq!((st.bytes_in, st.connections, st.first_us, st.last_us), (0, 0, 40, 0));
        assert_eq!((s.proc_stats.len(), s.proc_stats[&7].0.name.as_str()), (1, "b.exe"));

        // End to end: the OS reports PID 7 as a.exe, later as b.exe.
        use crate::procs::{OsSnapshot, OwnerIndex, SocketEntry};
        let owners = |name: &str, lport: u16| {
            let mut procs = HashMap::new();
            procs.insert(7, ProcInfo { pid: 7, name: name.into(), path: None, parent: None });
            let sock = SocketEntry { proto: SockProto::Tcp, local: format!("{ME}:{lport}").parse().unwrap(), remote: Some("1.1.1.1:443".parse().unwrap()), state: Some("ESTABLISHED"), pid: 7 };
            Arc::new(OwnerIndex::new(OsSnapshot { sockets: vec![sock], procs, error: None }))
        };
        let mut s = state();
        s.set_owners(owners("a.exe", 5000));
        for _ in 0..3 {
            s.record(us(T0), 300, Some(&pkt(ME, "1.1.1.1", 5000, 443, Proto::Tls, App::None)));
        }
        let p = s.processes().processes;
        assert_eq!((p.len(), p[0].name.as_str(), p[0].bytes_out, p[0].connections_total), (1, "a.exe", 900, 1));
        s.set_owners(owners("b.exe", 5001));
        s.record(us(T0 + 1), 100, Some(&pkt(ME, "1.1.1.1", 5001, 443, Proto::Tls, App::None)));
        let p = s.processes().processes;
        assert_eq!((p.len(), p[0].name.as_str(), p[0].bytes_out, p[0].connections_total, p[0].first_us), (1, "b.exe", 100, 1, us(T0 + 1)));
    }

    #[test]
    fn connection_filter_knows_lan_and_idle() {
        use crate::analytics::filter::Filter;
        use crate::analytics::views::CONN_FIELDS;
        let mut s = state();
        s.record(us(T0), 60, Some(&syn(ME, "192.168.1.9", 5000, 445)));
        // The idle time counts from the last packet, not the first.
        s.record(us(T0 + 20), 60, Some(&pkt(ME, "192.168.1.9", 5000, 445, Proto::Tcp, App::None)));
        s.record(us(T0 + 50), 60, Some(&syn(ME, "203.0.113.9", 5001, 443)));
        s.advance(T0 + 60);
        let n = |q: &str| s.connections(None, Some(&Filter::parse(q, CONN_FIELDS).unwrap()), 10).0;
        assert_eq!((n("lan"), n("not lan"), n("lan == false"), n("local_net")), (1, 1, 1, 1));
        assert_eq!(n("idle < 30s"), 1, "the external one was active 10 s ago");
        assert_eq!(n("idle >= 1m"), 0, "the LAN one was last active 40 s ago");
        assert_eq!(n("idle >= 40s"), 1);
        assert_eq!(n("age > 2m"), 0, "alias");
        assert_eq!(n("idle < 1m and not lan"), 1);
        let (_, list) = s.connections(None, None, 10);
        let lan = list.iter().find(|c| c.remote_ip == "192.168.1.9").unwrap();
        assert!((lan.lan, lan.idle_ms) == (true, 40_000.0), "{} {}", lan.lan, lan.idle_ms);
        let v = serde_json::to_value(lan).unwrap();
        assert_eq!(v["lan"], true);
        assert!(v.get("idle_ms").is_none(), "the idle time is a filter field, not part of the JSON");
    }

    #[test]
    fn hosts_list_the_programs_that_talked_to_them() {
        let mut s = state();
        let mut sockets = Vec::new();
        let mut procs = Vec::new();
        let names: Vec<String> = (0..10).map(|i| format!("p{}.exe", 9 - i)).collect();
        let locals: Vec<String> = (0..10).map(|i| format!("192.168.1.50:{}", 6000 + i)).collect();
        for i in 0..10u16 {
            s.record(us(T0), 60, Some(&syn(ME, "203.0.113.9", 6000 + i, 443)));
            sockets.push((SockProto::Tcp, locals[i as usize].as_str(), Some("203.0.113.9:443"), 100 + u32::from(i)));
            procs.push((100 + u32::from(i), names[i as usize].as_str(), None));
        }
        s.record(us(T0), 60, Some(&syn(ME, "198.51.100.1", 7000, 443)));
        s.set_owners(owners(sockets, procs));
        let snap = s.snapshot(10, 0);
        let busy = snap.hosts.iter().find(|h| h.ip == "203.0.113.9").unwrap();
        assert_eq!(busy.processes.len(), 8, "capped: {:?}", busy.processes);
        assert!(busy.processes.windows(2).all(|w| w[0] < w[1]), "sorted, no duplicates: {:?}", busy.processes);
        let quiet = snap.hosts.iter().find(|h| h.ip == "198.51.100.1").unwrap();
        assert!(quiet.processes.is_empty(), "no owner known");
    }

    #[test]
    fn dns_journal_filters_and_counts_by_field() {
        use crate::analytics::facets::Facets;
        use crate::analytics::views::{DnsFilter, DNS_FACETS};
        let mut s = state();
        s.set_owners(owners(vec![(SockProto::Udp, "192.168.1.50:5000", None, 7), (SockProto::Udp, "192.168.1.50:5001", None, 8)], vec![(7, "chrome.exe", None), (8, "svc.exe", None)]));
        let q = |id: u16, name: &str, t: u16| App::Dns(dns::parse(&dns::build_query(id, name, t)).unwrap());
        let nx = |id: u16, name: &str| {
            let mut r = dns::build_response(id, name, &[], 60);
            r[3] = (r[3] & 0xF0) | 3; // NXDOMAIN
            App::Dns(dns::parse(&r).unwrap())
        };
        // chrome: a.example (answered in 5 ms), b.example (NXDOMAIN after 300 ms); svc: an AAAA
        // query left unanswered; and an mDNS query nobody owns.
        s.record(us(T0), 80, Some(&pkt(ME, "1.1.1.1", 5000, 53, Proto::Dns, q(1, "a.example", dns::TYPE_A))));
        let ok = App::Dns(dns::parse(&dns::build_response(1, "a.example", &[ip("93.184.215.14")], 60)).unwrap());
        s.record(us(T0) + 5_000, 90, Some(&pkt("1.1.1.1", ME, 53, 5000, Proto::Dns, ok)));
        s.record(us(T0 + 1), 80, Some(&pkt(ME, "1.1.1.1", 5000, 53, Proto::Dns, q(2, "b.example", dns::TYPE_A))));
        s.record(us(T0 + 1) + 300_000, 90, Some(&pkt("1.1.1.1", ME, 53, 5000, Proto::Dns, nx(2, "b.example"))));
        s.record(us(T0 + 2), 80, Some(&pkt(ME, "8.8.8.8", 5001, 53, Proto::Dns, q(3, "c.example", dns::TYPE_AAAA))));
        s.record(us(T0 + 3), 80, Some(&pkt(ME, "224.0.0.251", 5353, 5353, Proto::Dns, q(4, "tv.local", 12))));
        let f = |spec: &str| DnsFilter { facets: Facets::parse(Some(spec), DNS_FACETS).unwrap(), ..DnsFilter::default() };
        let names = |v: &crate::analytics::views::DnsView| v.entries.iter().map(|e| e.entry.name.as_str()).collect::<Vec<_>>().join(",");
        let all = s.dns_filtered(&DnsFilter::default(), 100);
        assert_eq!(names(&all), "tv.local,c.example,b.example,a.example");
        assert_eq!(names(&s.dns_filtered(&f(r#"{"rcode":["nxdomain"]}"#), 100)), "b.example");
        assert_eq!(names(&s.dns_filtered(&f(r#"{"rcode":["pending"]}"#), 100)), "tv.local,c.example", "no answer yet");
        assert_eq!(names(&s.dns_filtered(&f(r#"{"process":["chrome.exe"]}"#), 100)), "b.example,a.example");
        assert_eq!(names(&s.dns_filtered(&f(r#"{"process":["chrome.exe"],"rcode":["NOERROR"]}"#), 100)), "a.example");
        assert_eq!(names(&s.dns_filtered(&f(r#"{"qtype":["AAAA"],"resolver":["8.8.8.8"]}"#), 100)), "c.example");
        assert_eq!(names(&s.dns_filtered(&f(r#"{"transport":["mdns"]}"#), 100)), "tv.local");
        let slow = DnsFilter { slow_ms: Some(100.0), ..DnsFilter::default() };
        assert_eq!(names(&s.dns_filtered(&slow, 100)), "b.example", "only answers that took 100 ms or more");
        let quiet = DnsFilter { hide_local: true, ..DnsFilter::default() };
        assert_eq!(names(&s.dns_filtered(&quiet, 100)), "c.example,b.example,a.example");
        let text = DnsFilter { q: Some("example".into()), facets: Facets::parse(Some(r#"{"process":["svc.exe"]}"#), DNS_FACETS).unwrap(), ..DnsFilter::default() };
        assert_eq!(names(&s.dns_filtered(&text, 100)), "c.example", "text and fields combine");
        // Counts: each field's list ignores its own filter, follows the others.
        let v = s.dns_filtered(&f(r#"{"process":["chrome.exe"]}"#), 1);
        assert_eq!((v.total, v.entries.len()), (2, 1), "total before the limit");
        assert_eq!(v.facets["process"], vec![("chrome.exe".to_string(), 2), ("svc.exe".to_string(), 1)]);
        assert_eq!(v.facets["rcode"], vec![("NOERROR".to_string(), 1), ("NXDOMAIN".to_string(), 1)]);
        assert_eq!(v.facets["resolver"], vec![("1.1.1.1".to_string(), 2)]);
        assert_eq!(all.facets["transport"], vec![("udp".to_string(), 3), ("mdns".to_string(), 1)]);
        assert_eq!(s.dns(Some("b.exa"), 10).total, 1, "the old text-only search still works");
    }

    #[test]
    fn dns_journal_is_capped_at_3000_entries_and_classifies_transports() {
        let mut s = state();
        for i in 0..3100u32 {
            let q = dns::parse(&dns::build_query(i as u16, &format!("h{i}.example"), dns::TYPE_A)).unwrap();
            s.record(us(T0) + i as i64, 80, Some(&pkt(ME, "1.1.1.1", 5000 + (i % 1000) as u16, 53, Proto::Dns, App::Dns(q))));
        }
        assert_eq!((s.dns_log.len(), s.dns_log.queries), (3000, 3100));
        let v = s.dns(None, usize::MAX);
        assert_eq!((v.total, v.entries.len(), v.queries, v.failures), (3000, 3000, 3100, 0));
        assert_eq!(v.entries[0].entry.name, "h3099.example", "newest first");
        assert_eq!(v.entries.last().unwrap().entry.name, "h100.example", "the oldest 100 were evicted");
        assert_eq!(s.dns(None, 5).entries.len(), 5);
        assert_eq!(s.dns(Some("H3099"), usize::MAX).total, 1, "case-insensitive");
        assert_eq!(s.dns(Some("h30"), 2).total, 110, "h300-h309 and h3000-h3099: total counts all matches, not the page");
        // A late answer to an evicted query is kept as an orphan response.
        let r = dns::parse(&dns::build_response(5, "h5.example", &[ip("93.184.215.14")], 60)).unwrap();
        s.record(us(T0) + 5000, 90, Some(&pkt("1.1.1.1", ME, 53, 5005, Proto::Dns, App::Dns(r))));
        let v = s.dns(Some("h5.example"), 10);
        assert_eq!((v.total, v.entries[0].entry.rcode, v.entries[0].entry.latency_ms), (1, Some("NOERROR"), None));
        assert_eq!(s.dns_log.len(), 3000, "still capped");
        // Transports: multicast DNS and DNS over TCP are labelled.
        let q = dns::parse(&dns::build_query(1, "_printer._tcp.local", 12)).unwrap();
        s.record(us(T0) + 6000, 80, Some(&pkt(ME, "224.0.0.251", 5353, 5353, Proto::Dns, App::Dns(q))));
        let q = dns::parse(&dns::build_query(2, "big.example", dns::TYPE_A)).unwrap();
        let mut tcp = pkt(ME, "1.1.1.1", 6000, 53, Proto::Dns, App::Dns(q));
        tcp.transport = Transport::TCP_ACK;
        s.record(us(T0) + 7000, 80, Some(&tcp));
        assert_eq!(s.dns(Some("_printer"), 1).entries[0].entry.transport, "mdns");
        assert_eq!(s.dns(Some("big.example"), 1).entries[0].entry.transport, "tcp");
        assert_eq!(s.dns(Some("h3099"), 1).entries[0].entry.transport, "udp");
    }

    #[test]
    fn ipv6_and_dual_stack_sockets_attribute_our_flows_only() {
        use crate::procs::{OsSnapshot, OwnerIndex, SocketEntry};
        let mut s = State::new(Config::default(), [ip(ME), ip("2001:db8::2")].into_iter().collect(), state().capture);
        let mut procs = HashMap::new();
        procs.insert(31, ProcInfo { pid: 31, name: "srv.exe".into(), path: None, parent: None });
        procs.insert(32, ProcInfo { pid: 32, name: "client.exe".into(), path: None, parent: None });
        let sock = |local: &str, remote: Option<&str>, pid| SocketEntry {
            proto: SockProto::Tcp,
            local: local.parse().unwrap(),
            remote: remote.map(|r| r.parse().unwrap()),
            state: Some(if remote.is_some() { "ESTABLISHED" } else { "LISTEN" }),
            pid,
        };
        s.set_owners(Arc::new(OwnerIndex::new(OsSnapshot {
            sockets: vec![
                sock("[::]:8443", None, 31),
                sock("[2001:db8::2]:40000", Some("[2606:4700::1111]:443"), 32),
                // A dual-stack socket reports its IPv4 peer v4-mapped.
                sock("[::ffff:192.168.1.50]:40001", Some("[::ffff:1.1.1.1]:443"), 32),
            ],
            procs,
            error: None,
        })));
        // Incoming IPv4 connection to the dual-stack listener.
        let mut syn = pkt("203.0.113.5", ME, 51000, 8443, Proto::Tcp, App::None);
        syn.transport = Transport::TCP_SYN;
        s.record(us(T0), 60, Some(&syn));
        // Outgoing IPv6, and the IPv4 flow of the v4-mapped socket.
        s.record(us(T0), 60, Some(&pkt("2001:db8::2", "2606:4700::1111", 40000, 443, Proto::Tls, App::None)));
        s.record(us(T0), 60, Some(&pkt(ME, "1.1.1.1", 40001, 443, Proto::Tls, App::None)));
        // Traffic between two other IPv6 hosts on the listener's port: never ours.
        s.record(us(T0), 60, Some(&pkt("2001:db8::9", "2001:db8::8", 5000, 8443, Proto::Tcp, App::None)));
        let owner = |remote: &str| s.flows().find(|f| f.key.remote.to_string() == remote).map(|f| f.process.as_ref().map(|p| p.pid));
        assert_eq!(owner("203.0.113.5:51000"), Some(Some(31)), "IPv4 client of the [::] listener");
        assert_eq!(owner("[2606:4700::1111]:443"), Some(Some(32)));
        assert_eq!(owner("1.1.1.1:443"), Some(Some(32)), "v4-mapped socket matches the plain IPv4 flow");
        assert_eq!(owner("[2001:db8::8]:8443"), Some(None), "foreign IPv6 traffic is seen but unattributed");
        assert!(!s.wants_owner_refresh(), "foreign traffic never asks for a socket table refresh");
        let v = s.processes();
        assert_eq!((v.processes.len(), v.unattributed.connections), (2, 1));
        let incoming = s.connections(Some(31), None, 10).1;
        assert_eq!((incoming[0].initiated, incoming[0].local.as_str()), (Some("remote"), "192.168.1.50:8443"));
        assert_eq!(s.local_addresses(), vec![ip(ME), ip("2001:db8::2")], "sorted, IPv4 first");
    }

    fn snapshot(sockets: Vec<crate::procs::SocketEntry>, error: Option<&str>) -> Arc<crate::procs::OwnerIndex> {
        use crate::procs::{OsSnapshot, OwnerIndex};
        let mut procs = HashMap::new();
        procs.insert(5, ProcInfo { pid: 5, name: "srv.exe".into(), path: None, parent: None });
        Arc::new(OwnerIndex::new(OsSnapshot { sockets, procs, error: error.map(String::from) }))
    }

    fn listen(port: u16) -> crate::procs::SocketEntry {
        crate::procs::SocketEntry { proto: SockProto::Tcp, local: format!("0.0.0.0:{port}").parse().unwrap(), remote: None, state: Some("LISTEN"), pid: 5 }
    }

    #[test]
    fn listener_baseline_ignores_failed_and_empty_snapshots() {
        let mut s = state();
        s.record(us(T0), 10, None);
        s.set_owners(snapshot(vec![listen(445)], Some("access denied")));
        s.set_owners(snapshot(vec![], None));
        // The first usable table is the baseline, even though it brings a new port.
        s.set_owners(snapshot(vec![listen(445), listen(8080)], None));
        assert_eq!(s.alerts.counts().total, 0, "{:?}", s.alerts.recent(5));
        s.set_owners(snapshot(vec![listen(445), listen(8080), listen(9000)], None));
        let a = s.alerts.recent(5);
        assert_eq!(a.len(), 1);
        assert_eq!((a[0].kind, a[0].host.as_deref(), a[0].details["port"].as_str()), (AlertKind::NewListener, None, "9000"));
        assert!((a[0].ts - unix_now()).abs() < 5, "stamped with wall-clock time, not the traffic clock {}", a[0].ts);
    }

    #[test]
    fn persisted_state_restores_routes_and_skips_the_learning_period() {
        use crate::procs::{OsSnapshot, OwnerIndex, SocketEntry};
        use crate::trace::watch::MAX_TARGETS;
        let owners = |name: &str, lport: u16| {
            let mut procs = HashMap::new();
            procs.insert(7, ProcInfo { pid: 7, name: name.into(), path: None, parent: None });
            let sock = SocketEntry { proto: SockProto::Tcp, local: format!("{ME}:{lport}").parse().unwrap(), remote: Some("1.1.1.1:443".parse().unwrap()), state: Some("ESTABLISHED"), pid: 7 };
            Arc::new(OwnerIndex::new(OsSnapshot { sockets: vec![sock], procs, error: None }))
        };
        // First run: a.exe is seen while learning, two routes are watched.
        let mut s = state();
        s.set_owners(owners("a.exe", 5000));
        s.record(us(T0), 300, Some(&pkt(ME, "1.1.1.1", 5000, 443, Proto::Tls, App::None)));
        s.routes.add(ip("203.0.113.9"), Some("example".into()), 0);
        s.routes.add(ip("2001:db8::1"), None, 0);
        let p = s.persisted();
        assert_eq!(p.version, persist::VERSION);
        assert!((p.saved_at - unix_now()).abs() < 5);
        assert_eq!(p.watch, vec![
            WatchEntry { ip: ip("203.0.113.9"), label: Some("example".into()) },
            WatchEntry { ip: ip("2001:db8::1"), label: None },
        ]);
        assert_eq!((p.novelty.processes.as_slice(), p.novelty.learn_until_us), (&["a.exe".to_string()][..], Some(us(T0) + super::super::novelty::LEARNING_US)));
        assert!(s.alerts.recent(5).is_empty(), "learning");

        // Second run, well after the first run's learning deadline.
        let mut r = state();
        r.restore(p.clone());
        assert_eq!(r.persisted().watch, p.watch, "targets and labels survive");
        assert!(r.routes.contains(&ip("203.0.113.9")) && r.routes.len() == 2);
        r.set_owners(owners("a.exe", 5000));
        r.record(us(T0 + 600), 300, Some(&pkt(ME, "1.1.1.1", 5000, 443, Proto::Tls, App::None)));
        assert!(r.alerts.recent(5).is_empty(), "a program known from before the restart is not new: {:?}", r.alerts.recent(5));
        r.set_owners(owners("b.exe", 5001));
        r.record(us(T0 + 600), 300, Some(&pkt(ME, "1.1.1.1", 5001, 443, Proto::Tls, App::None)));
        let a = r.alerts.recent(5);
        assert_eq!(a.len(), 1, "{a:?}");
        assert_eq!((a[0].kind, a[0].details["process"].as_str()), (AlertKind::NewProcess, "b.exe"), "a new one is reported at once");
        // Without the baseline the same traffic would still be learning.
        let mut f = state();
        f.set_owners(owners("b.exe", 5001));
        f.record(us(T0 + 600), 300, Some(&pkt(ME, "1.1.1.1", 5001, 443, Proto::Tls, App::None)));
        assert!(f.alerts.recent(5).is_empty());

        // More saved routes than the cap: the first ones win, nothing panics.
        let many: Vec<WatchEntry> = (0..MAX_TARGETS + 8).map(|i| WatchEntry { ip: ip(&format!("203.0.113.{i}")), label: Some(format!("t{i}")) }).collect();
        let mut c = state();
        c.restore(Persisted { watch: many.clone(), ..Persisted::default() });
        assert_eq!(c.routes.len(), MAX_TARGETS);
        assert_eq!(c.persisted().watch, many[..MAX_TARGETS]);
    }

    #[test]
    fn route_alerts_use_wall_clock_time() {
        use crate::trace::{Hop, Trace};
        let hop = |asn: u32| Hop { ttl: 1, ip: Some("203.0.113.1".into()), name: None, rtt_ms: vec![Some(5.0)], geo: Some(crate::geo::GeoInfo { asn: Some(asn), country_code: Some("DE".into()), ..Default::default() }), private: false };
        let tr = |asn| Trace { target: "203.0.113.9".into(), hops: vec![hop(asn)], reached: true, method: "test", duration_ms: 1, error: None };
        let mut s = state();
        s.record(us(T0), 10, None);
        let target = ip("203.0.113.9");
        s.routes.add(target, None, 0);
        s.routes.take_due(0);
        s.record_route(target, tr(1));
        s.routes.take_due(i64::MAX);
        s.record_route(target, tr(2));
        let a = s.alerts.recent(5);
        assert_eq!(a.len(), 1);
        assert_eq!((a[0].kind, a[0].host.as_deref()), (AlertKind::RouteChange, Some("203.0.113.9")));
        assert!((a[0].ts - unix_now()).abs() < 5 && a[0].ts != T0, "{}", a[0].ts);
    }

    #[test]
    fn journal_gets_exactly_one_connection_record_per_flow() {
        let mut s = state();
        s.flows = FlowTable::new(10);
        let j = Arc::new(Journal::new("unused", 1));
        s.set_journal(j.clone());
        // A connection closed by a RST: journaled once the close is five seconds old (traffic
        // clock), not again for later packets.
        let mut rst = pkt(ME, "203.0.113.1", 5000, 443, Proto::Tls, App::None);
        rst.transport = Transport::Tcp { syn: false, ack: true, fin: false, rst: true };
        s.record(us(T0), 100, Some(&pkt(ME, "203.0.113.1", 5000, 443, Proto::Tls, App::None)));
        s.record(us(T0), 60, Some(&rst));
        s.record(us(T0), 60, Some(&rst));
        s.advance(T0 + 4);
        assert_eq!(j.pending(), 0, "still within the grace period");
        s.advance(T0 + 5);
        assert_eq!(j.pending(), 1);
        s.advance(T0 + 6);
        assert_eq!(j.pending(), 1, "once only");
        // Thirty more connections overflow the table: the oldest are evicted (the closed one
        // first, already journaled), the open ones get an `evicted` record.
        for i in 0..30u16 {
            s.record(us(T0 + 7 + i64::from(i)), 100, Some(&pkt(ME, "203.0.113.2", 6000 + i, 443, Proto::Tls, App::None)));
        }
        s.advance(T0 + 100);
        let left = s.flows.len();
        assert!(left < 30 && left > 0, "{left}");
        assert_eq!(s.journal_remaining(), left, "shutdown journals what is left");
        assert_eq!(s.journal_remaining(), 0, "nothing twice");
        let recs: Vec<serde_json::Value> = j.take_pending().iter().filter(|r| r.kind == Kind::Connections).map(|r| serde_json::from_str(&r.line).unwrap()).collect();
        assert_eq!(recs.len(), 31, "one record per connection");
        let mut ids: Vec<u64> = recs.iter().map(|c| c["id"].as_u64().unwrap()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 31);
        let by_reason = |r: &str| recs.iter().filter(|c| c["reason"] == r).count();
        assert_eq!((by_reason("closed"), by_reason("evicted"), by_reason("shutdown")), (1, 30 - left, left));
        let closed = recs.iter().find(|c| c["reason"] == "closed").unwrap();
        assert_eq!((closed["state"].as_str(), closed["remote"].as_str(), closed["l4"].as_str(), closed["app"].as_str()), (Some("closed"), Some("203.0.113.1:443"), Some("tcp"), Some("tls")));
        // Written after the grace period: the packet after the RST is in it too.
        assert_eq!((closed["bytes_out"].as_u64(), closed["packets_out"].as_u64(), closed["retrans"].as_u64()), (Some(220), Some(3), Some(0)));
        assert!((closed["ts"].as_i64().unwrap() - unix_now()).abs() < 5, "stamped with wall-clock time");
        assert_eq!(closed["first_us"], us(T0));
        for key in ["process", "name", "geo", "initiated", "tls", "rtt_ms", "hops"] {
            assert!(closed[key].is_null(), "{key}: {closed}");
        }
        assert_eq!(closed.as_object().unwrap().len(), 23, "the documented field set: {closed}");

        // Switched off (0 days): nothing is produced, flows are not marked.
        j.set_retention_days(0);
        s.record(us(T0 + 200), 100, Some(&pkt(ME, "203.0.113.3", 7000, 443, Proto::Tls, App::None)));
        let mut rst = pkt(ME, "203.0.113.3", 7000, 443, Proto::Tls, App::None);
        rst.transport = Transport::Tcp { syn: false, ack: true, fin: false, rst: true };
        s.record(us(T0 + 200), 60, Some(&rst));
        s.advance(T0 + 210);
        assert_eq!(j.pending(), 0);
        let f = s.flows().find(|f| f.key.local.port() == 7000).unwrap();
        assert!(f.state == FlowState::Closed && !f.journaled, "not marked while the journal is off");
    }

    /// The socket table is polled after the fact: a short connection closed before the
    /// poll is attributed later, and the grace period lets the record carry the process.
    #[test]
    fn journal_record_of_a_short_connection_carries_a_late_attribution() {
        use crate::procs::{OsSnapshot, OwnerIndex, SocketEntry};
        let mut s = state();
        let j = Arc::new(Journal::new("unused", 1));
        s.set_journal(j.clone());
        let mut rst = pkt(ME, "203.0.113.1", 5000, 443, Proto::Tls, App::None);
        rst.transport = Transport::Tcp { syn: false, ack: true, fin: false, rst: true };
        s.record(us(T0), 100, Some(&pkt(ME, "203.0.113.1", 5000, 443, Proto::Tls, App::None)));
        s.record(us(T0), 60, Some(&rst));
        assert!(s.flows().next().unwrap().process.is_none() && s.wants_owner_refresh());
        // Two seconds later the OS reports the socket's owner.
        s.advance(T0 + 2);
        let mut procs = HashMap::new();
        procs.insert(42, ProcInfo { pid: 42, name: "python.exe".into(), path: Some(r"C:\py\python.exe".into()), parent: None });
        let sock = SocketEntry { proto: SockProto::Tcp, local: format!("{ME}:5000").parse().unwrap(), remote: Some("203.0.113.1:443".parse().unwrap()), state: Some("TIME_WAIT"), pid: 42 };
        s.set_owners(Arc::new(OwnerIndex::new(OsSnapshot { sockets: vec![sock], procs, error: None })));
        assert_eq!(j.pending(), 0, "not journaled yet");
        s.advance(T0 + 5);
        let recs: Vec<serde_json::Value> = j.take_pending().iter().filter(|r| r.kind == Kind::Connections).map(|r| serde_json::from_str(&r.line).unwrap()).collect();
        assert_eq!(recs.len(), 1);
        assert_eq!((recs[0]["reason"].as_str(), recs[0]["process"]["pid"].as_u64(), recs[0]["process"]["name"].as_str()), (Some("closed"), Some(42), Some("python.exe")));
        assert_eq!(recs[0]["process"]["path"], r"C:\py\python.exe");
        assert_eq!(s.journal_remaining(), 0, "already journaled");
    }

    #[test]
    fn journal_records_dns_lookups_and_alerts() {
        let mut s = state();
        let j = Arc::new(Journal::new("unused", 1));
        s.set_journal(j.clone());
        let q = dns::parse(&dns::build_query(1, "example.org", dns::TYPE_A)).unwrap();
        s.record(us(T0), 80, Some(&pkt(ME, "1.1.1.1", 5000, 53, Proto::Dns, App::Dns(q))));
        assert_eq!(j.pending(), 0, "a pending query is not a record yet");
        let r = dns::parse(&dns::build_response(1, "example.org", &[ip("93.184.215.14")], 60)).unwrap();
        s.record(us(T0) + 25_000, 90, Some(&pkt("1.1.1.1", ME, 53, 5000, Proto::Dns, App::Dns(r))));
        let recs = j.take_pending();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].kind, Kind::Dns);
        let d: serde_json::Value = serde_json::from_str(&recs[0].line).unwrap();
        assert_eq!((d["name"].as_str(), d["rcode"].as_str(), d["latency_ms"].as_f64(), d["transport"].as_str()), (Some("example.org"), Some("NOERROR"), Some(25.0), Some("udp")));
        assert_eq!(d["answers"], serde_json::json!(["93.184.215.14"]));
        assert_eq!(d["used_by"], serde_json::json!([]));
        assert_eq!(d["ts_us"], us(T0));
        assert!((d["ts"].as_i64().unwrap() - unix_now()).abs() < 5);
        assert!(d.get("txid").is_none());

        // An alert is journaled as served by the API, with its own packet-time `ts`.
        let q = dns::parse(&dns::build_query(2, "x7k2p9q4m1v8b3n6c5z0w1.exfil.example", dns::TYPE_A)).unwrap();
        s.record(us(T0 + 3), 90, Some(&pkt(ME, "1.1.1.1", 5001, 53, Proto::Dns, App::Dns(q))));
        let recs = j.take_pending();
        assert_eq!(recs.iter().map(|r| r.kind).collect::<Vec<_>>(), vec![Kind::Alerts]);
        let a: serde_json::Value = serde_json::from_str(&recs[0].line).unwrap();
        assert_eq!((a["kind"].as_str(), a["severity"].as_str(), a["ts"].as_i64(), a["id"].as_u64()), (Some("suspicious_dns"), Some("medium"), Some(T0 + 3), Some(1)));
        assert_eq!(a["details"]["reason"], "entropy");
        assert_eq!(recs[0].ts, T0 + 3);
        // A suppressed repeat produces no record.
        s.record(us(T0 + 4), 90, Some(&pkt(ME, "1.1.1.1", 5002, 53, Proto::Dns, App::Dns(dns::parse(&dns::build_query(3, "x7k2p9q4m1v8b3n6c5z0w1.exfil.example", dns::TYPE_A)).unwrap()))));
        assert_eq!(j.pending(), 0);
        // Without a journal nothing happens at all.
        let mut plain = state();
        plain.record(us(T0 + 3), 90, Some(&pkt(ME, "1.1.1.1", 5001, 53, Proto::Dns, App::Dns(dns::parse(&dns::build_query(2, "x7k2p9q4m1v8b3n6c5z0w1.exfil.example", dns::TYPE_A)).unwrap()))));
        assert!(plain.journal().is_none() && plain.journal_remaining() == 0);
    }

    #[test]
    fn processes_without_a_path_are_unknown_not_pending() {
        let mut s = state();
        let no_path = ProcInfo { pid: 1, name: "System".into(), path: None, parent: None };
        let with_path = ProcInfo { pid: 2, name: "a.exe".into(), path: Some(r"C:\a.exe".into()), parent: None };
        assert_eq!(s.signature_for(&no_path), Some(Signature { status: SigStatus::Unknown, signer: None }));
        assert_eq!(s.signature_for(&with_path), None, "pending until verified");
        s.set_signatures([(r"C:\a.exe".to_string(), Signature { status: SigStatus::Signed, signer: Some("A".into()) })].into_iter().collect());
        assert_eq!(s.signature_for(&with_path).unwrap().status, SigStatus::Signed);
    }
}
