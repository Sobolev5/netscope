//! JSON views of processes, connections, packets, streams and OS sockets.

use std::collections::HashMap;

use serde::Serialize;

use super::flows::{Flow, FlowState, L4};
use super::state::State;
use super::stream::{printable_ratio, reassemble, render_text};
use crate::decode::dissect::{dissect, summary, Layer};
use crate::decode::sha256::hex;
use crate::decode::Proto;
use super::addr::is_local_scope;
use super::dnslog::{encrypted_dns_kind, DnsEntry};
use super::facets::{Counter, FacetCounts, Facets};
use super::filter::{FieldValue, Filter, Record};
use crate::decode::tlsinfo::{cipher_name, parse_server_stream, version_name, CertInfo};
use crate::geo::{GeoInfo, GeoStatus};
use crate::procs::signature::{suspicious_location, SigStatus, Signature};
use crate::netpath::{is_tunnel_adapter, is_vpn_process, Egress};
use crate::procs::{unmap, ProcInfo, SockProto};

/// Connections idle longer than this are not "active".
const ACTIVE_US: i64 = 120_000_000;
/// Streams larger than this are cut in the API response.
const STREAM_MAX: usize = 512 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct ProcRef {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
    pub parent: Option<u32>,
    pub parent_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnView {
    pub id: u64,
    pub l4: L4,
    pub app: &'static str,
    pub local: String,
    pub remote: String,
    pub remote_ip: String,
    pub remote_port: u16,
    pub local_port: u16,
    /// SNI / Host / DNS question, or a name learned for the remote IP.
    pub name: Option<String>,
    pub process: Option<ProcRef>,
    pub state: FlowState,
    /// `local`, `remote` or `null` when the opening was not captured.
    pub initiated: Option<&'static str>,
    pub first_us: i64,
    pub last_us: i64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub stored_packets: usize,
    pub geo: Option<GeoInfo>,
    pub hops: Option<u8>,
    /// TCP handshake round trip in milliseconds.
    pub rtt_ms: Option<f64>,
    pub retrans_out: u32,
    pub retrans_in: u32,
    pub zero_window: u32,
    pub tls: Option<TlsView>,
    /// `DoH`, `DoT` or `DoQ` when the connection carries encrypted DNS.
    pub encrypted_dns: Option<&'static str>,
    /// Code signature of the owning executable: `true` signed, `false` unsigned/invalid.
    pub signed: Option<bool>,
    /// The remote end is in a local network (private, link-local, loopback…).
    pub lan: bool,
    /// Milliseconds since the last packet, by the traffic clock (filter field `idle`).
    #[serde(skip)]
    pub idle_ms: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsView {
    pub sni: Option<String>,
    pub version: &'static str,
    pub alpn: Vec<String>,
    pub ja4: String,
}

/// TLS details of the server side, read from the captured handshake.
#[derive(Debug, Clone, Serialize)]
pub struct ServerTlsView {
    pub version: Option<&'static str>,
    pub cipher: Option<String>,
    pub alpn: Option<String>,
    /// Leaf first; empty for TLS 1.3 (encrypted) or when not captured.
    pub certificates: Vec<CertInfo>,
    pub encrypted_certificates: bool,
    /// The handshake start is no longer stored, so nothing could be read.
    pub incomplete: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsEntryView {
    #[serde(flatten)]
    pub entry: DnsEntry,
    /// Programs that then connected to one of the answered addresses.
    pub used_by: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsView {
    pub entries: Vec<DnsEntryView>,
    pub total: usize,
    pub queries: u64,
    pub failures: u64,
    /// Connections carrying encrypted DNS (DoH/DoT/DoQ): lookups the journal cannot see.
    pub encrypted: Vec<ConnView>,
    /// Values of [`DNS_FACETS`] with their counts (see `analytics::facets`).
    pub facets: FacetCounts,
}

/// Fields the DNS journal can be narrowed by, value lists as in `analytics::facets`.
pub const DNS_FACETS: &[&str] = &["rcode", "qtype", "process", "resolver", "transport"];

/// What the DNS page asks for: a text search, value lists per field, slow answers only,
/// and whether to leave out the local-network chatter (mDNS, `.local` names).
#[derive(Debug, Clone, Default)]
pub struct DnsFilter {
    pub q: Option<String>,
    pub facets: Facets,
    /// Only answers that took at least this many milliseconds.
    pub slow_ms: Option<f64>,
    pub hide_local: bool,
}

impl DnsFilter {
    pub fn text(q: Option<&str>) -> Self {
        Self { q: q.map(String::from), ..Self::default() }
    }

    /// The value of a facet field for an entry (`pending`: no answer yet).
    fn value(e: &DnsEntry, field: &str) -> Vec<String> {
        match field {
            "rcode" => vec![e.rcode.unwrap_or("pending").to_string()],
            "qtype" => vec![e.qtype.to_string()],
            "process" => vec![e.requester.as_ref().map(|r| r.name.clone()).unwrap_or_default()],
            "resolver" => vec![e.resolver.clone()],
            "transport" => vec![e.transport.to_string()],
            _ => vec![],
        }
    }

    /// Everything but the value lists (those are counted separately).
    fn base_matches(&self, e: &DnsEntry, q: Option<&str>) -> bool {
        let text = q.is_none_or(|q| {
            e.name.contains(q) || e.requester.as_ref().is_some_and(|r| r.name.to_lowercase().contains(q)) || e.answers.iter().any(|a| a.contains(q)) || e.rcode.is_some_and(|r| r.eq_ignore_ascii_case(q))
        });
        let slow = self.slow_ms.is_none_or(|min| e.latency_ms.is_some_and(|l| l >= min));
        let local = !self.hide_local || !(e.transport == "mdns" || e.name.ends_with(".local") || e.name.ends_with(".local."));
        text && slow && local
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessView {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
    pub parent: Option<u32>,
    pub parent_name: Option<String>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets: u64,
    pub connections_total: u64,
    pub connections_active: usize,
    pub first_us: i64,
    pub last_us: i64,
    pub protocols: Vec<&'static str>,
    /// Busiest destinations among the connections still in memory.
    pub top_remotes: Vec<String>,
    pub signature: Option<Signature>,
    /// The executable lives in a temporary/download folder.
    pub suspicious_path: bool,
    /// Distinct TLS client fingerprints (JA4) the program used.
    pub ja4: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Unattributed {
    pub connections: usize,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessesView {
    pub processes: Vec<ProcessView>,
    pub unattributed: Unattributed,
    /// Set when the OS socket table cannot be read (fully or partly).
    pub attribution_error: Option<String>,
    pub attribution_enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketRow {
    pub n: u64,
    pub ts_us: i64,
    pub outbound: bool,
    pub wire_len: u32,
    pub captured: usize,
    pub info: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SocketView {
    pub proto: SockProto,
    pub local: String,
    pub remote: Option<String>,
    pub state: Option<&'static str>,
    pub pid: u32,
    pub process: Option<String>,
    /// This socket is the local end of the connection being viewed.
    pub current: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnDetail {
    pub conn: ConnView,
    /// TCP state of the socket in the OS table right now, if it still exists.
    pub os_state: Option<&'static str>,
    pub packets: Vec<PacketRow>,
    pub dropped_packets: u64,
    /// Other sockets of the same process.
    pub sockets: Vec<SocketView>,
    /// Server side of a TLS connection (version, cipher, certificate).
    pub tls_server: Option<ServerTlsView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketDetail {
    pub n: u64,
    pub ts_us: i64,
    pub outbound: bool,
    pub wire_len: u32,
    pub layers: Vec<Layer>,
    /// The captured bytes as lowercase hex.
    pub hex: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StreamSegment {
    pub outbound: bool,
    pub ts_us: i64,
    pub packets: u32,
    pub gap_before: u64,
    pub bytes: usize,
    /// Mostly printable: show `text`; otherwise prefer `hex`.
    pub readable: bool,
    pub text: String,
    pub hex: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StreamView {
    pub id: u64,
    pub encrypted: bool,
    pub segments: Vec<StreamSegment>,
    pub bytes_out: usize,
    pub bytes_in: usize,
    /// Older packets that are no longer stored, so the beginning may be missing.
    pub dropped_packets: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SocketsView {
    pub sockets: Vec<SocketView>,
    pub error: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct VpnServer {
    pub addr: String,
    pub state: Option<&'static str>,
    pub geo: Option<GeoInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VpnTunnel {
    pub process: String,
    pub pid: u32,
    pub path: Option<String>,
    pub servers: Vec<VpnServer>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CountryStat {
    pub code: String,
    /// English name; `name_ru` when the database has a different Russian one.
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_ru: Option<String>,
    pub hosts: usize,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetPathView {
    /// Capture interface description (or name).
    pub interface: String,
    /// The capture interface itself is a virtual tunnel adapter (traffic is seen inside the VPN).
    pub interface_is_tunnel: bool,
    pub local_ips: Vec<String>,
    pub vpn: Vec<VpnTunnel>,
    pub egress: Option<Egress>,
    pub egress_error: Option<String>,
    pub egress_enabled: bool,
    pub countries: Vec<CountryStat>,
    pub geo: Option<GeoStatus>,
}

/// Filter fields for connections: canonical name and aliases (see `analytics::filter`).
pub const CONN_FIELDS: &[(&str, &[&str])] = &[
    ("process", &["proc", "program", "app.name"]),
    ("pid", &[]),
    ("path", &["exe"]),
    ("app", &["proto", "protocol"]),
    ("l4", &["transport"]),
    ("name", &["host", "domain", "sni"]),
    ("ip", &["addr", "remote_ip"]),
    ("port", &["rport"]),
    ("lport", &["local_port"]),
    ("local", &[]),
    ("remote", &[]),
    ("country", &["cc"]),
    ("city", &[]),
    ("org", &["provider", "isp", "as"]),
    ("asn", &[]),
    ("anycast", &["cdn"]),
    ("state", &[]),
    ("dir", &["direction"]),
    ("bytes", &["size", "total"]),
    ("in", &["rx", "down"]),
    ("out", &["tx", "up"]),
    ("packets", &["pkts"]),
    ("rtt", &["latency"]),
    ("retrans", &["retransmissions"]),
    ("hops", &[]),
    ("tls", &["tlsver"]),
    ("alpn", &[]),
    ("ja4", &[]),
    ("signed", &[]),
    ("doh", &["encrypted_dns"]),
    ("lan", &["local_net"]),
    ("idle", &["age"]),
];

impl Record for ConnView {
    fn field(&self, name: &str) -> FieldValue {
        let s = |v: &str| FieldValue::Str(v.to_string());
        let opt = |v: Option<&String>| v.map_or(FieldValue::Missing, |x| FieldValue::Str(x.clone()));
        let geo = self.geo.as_ref();
        match name {
            "process" => opt(self.process.as_ref().map(|p| &p.name)),
            "pid" => self.process.as_ref().map_or(FieldValue::Missing, |p| FieldValue::Num(p.pid as f64)),
            "path" => opt(self.process.as_ref().and_then(|p| p.path.as_ref())),
            "app" => s(self.app),
            "l4" => FieldValue::Str(format!("{:?}", self.l4).to_lowercase()),
            "name" => opt(self.name.as_ref()),
            "ip" => s(&self.remote_ip),
            "port" => FieldValue::Num(self.remote_port as f64),
            "lport" => FieldValue::Num(self.local_port as f64),
            "local" => s(&self.local),
            "remote" => s(&self.remote),
            "country" => match geo {
                Some(g) => FieldValue::List([g.country_code.clone(), g.country.clone()].into_iter().flatten().collect()),
                None => FieldValue::Missing,
            },
            "city" => opt(geo.and_then(|g| g.city.as_ref())),
            "org" => opt(geo.and_then(|g| g.org.as_ref())),
            "asn" => geo.and_then(|g| g.asn).map_or(FieldValue::Missing, |a| FieldValue::Num(a as f64)),
            "anycast" => geo.map_or(FieldValue::Missing, |g| FieldValue::Bool(g.anycast)),
            "state" => FieldValue::Str(format!("{:?}", self.state).to_lowercase()),
            "dir" => match self.initiated {
                Some("local") => s("out"),
                Some(_) => s("in"),
                None => FieldValue::Missing,
            },
            "bytes" => FieldValue::Num((self.bytes_in + self.bytes_out) as f64),
            "in" => FieldValue::Num(self.bytes_in as f64),
            "out" => FieldValue::Num(self.bytes_out as f64),
            "packets" => FieldValue::Num((self.packets_in + self.packets_out) as f64),
            "rtt" => self.rtt_ms.map_or(FieldValue::Missing, FieldValue::Num),
            "retrans" => FieldValue::Num((self.retrans_in + self.retrans_out) as f64),
            "hops" => self.hops.map_or(FieldValue::Missing, |h| FieldValue::Num(h as f64)),
            "tls" => self.tls.as_ref().map_or(FieldValue::Missing, |t| s(t.version)),
            "alpn" => self.tls.as_ref().map_or(FieldValue::Missing, |t| FieldValue::List(t.alpn.clone())),
            "ja4" => self.tls.as_ref().map_or(FieldValue::Missing, |t| s(&t.ja4)),
            "signed" => self.signed.map_or(FieldValue::Missing, FieldValue::Bool),
            "doh" => FieldValue::Bool(self.encrypted_dns.is_some()),
            "lan" => FieldValue::Bool(self.lan),
            "idle" => FieldValue::Num(self.idle_ms),
            _ => FieldValue::Missing,
        }
    }

    fn text(&self) -> String {
        let mut t = vec![self.app.to_string(), self.local.clone(), self.remote.clone()];
        if let Some(p) = &self.process {
            t.push(p.name.clone());
        }
        if let Some(n) = &self.name {
            t.push(n.clone());
        }
        if let Some(g) = &self.geo {
            t.extend([g.country_code.clone(), g.country.clone(), g.city.clone(), g.org.clone()].into_iter().flatten());
        }
        t.join(" ")
    }
}

impl State {
    fn proc_ref(&self, p: &ProcInfo) -> ProcRef {
        let parent_name = p.parent.and_then(|pp| self.owners().and_then(|o| o.process(pp)).map(|x| x.name.clone()));
        ProcRef { pid: p.pid, name: p.name.clone(), path: p.path.clone(), parent: p.parent, parent_name }
    }

    pub fn conn_view(&self, f: &Flow) -> ConnView {
        let name = f.name.clone().or_else(|| self.name_of(&f.key.remote.ip()).map(|n| n.name.clone()));
        ConnView {
            id: f.id,
            l4: f.key.l4,
            app: f.app.name(),
            local: f.key.local.to_string(),
            remote: f.key.remote.to_string(),
            remote_ip: f.key.remote.ip().to_string(),
            remote_port: f.key.remote.port(),
            local_port: f.key.local.port(),
            name,
            process: f.process.as_ref().map(|p| self.proc_ref(p)),
            state: f.state,
            initiated: f.initiated_locally.map(|l| if l { "local" } else { "remote" }),
            first_us: f.first_us,
            last_us: f.last_us,
            bytes_in: f.bytes_in,
            bytes_out: f.bytes_out,
            packets_in: f.packets_in,
            packets_out: f.packets_out,
            stored_packets: f.stored_count(),
            geo: self.geo.as_ref().and_then(|g| g.lookup(f.key.remote.ip())),
            hops: f.hops,
            rtt_ms: f.rtt_us.map(|r| r as f64 / 1000.0),
            retrans_out: f.retrans_out,
            retrans_in: f.retrans_in,
            zero_window: f.zero_window,
            tls: f.tls.as_ref().map(|t| TlsView { sni: t.sni.clone(), version: version_name(t.version), alpn: t.alpn.clone(), ja4: t.ja4.clone() }),
            encrypted_dns: encrypted_dns_kind(f.key.l4, f.key.remote, f.name.as_deref()),
            signed: f
                .process
                .as_ref()
                .and_then(|p| p.path.as_deref())
                .and_then(|path| self.signature_of(path))
                .and_then(|s| match s.status {
                    SigStatus::Signed => Some(true),
                    SigStatus::Unsigned | SigStatus::Invalid => Some(false),
                    SigStatus::Unknown => None,
                }),
            lan: is_local_scope(&f.key.remote.ip()),
            idle_ms: (self.now.saturating_mul(1_000_000) - f.last_us).max(0) as f64 / 1000.0,
        }
    }

    /// Most recently active first. `pid` filters by owner (0 = unattributed), `filter`
    /// is a parsed query (see [`CONN_FIELDS`]). Returns (matching count, first `limit`).
    pub fn connections(&self, pid: Option<u32>, filter: Option<&Filter>, limit: usize) -> (usize, Vec<ConnView>) {
        let mut list: Vec<&Flow> = self
            .flows()
            .filter(|f| match pid {
                None => true,
                Some(0) => f.process.is_none(),
                Some(p) => f.process.as_ref().is_some_and(|x| x.pid == p),
            })
            .collect();
        list.sort_unstable_by(|a, b| b.last_us.cmp(&a.last_us).then(b.id.cmp(&a.id)));
        match filter.filter(|f| !f.is_empty()) {
            None => (list.len(), list.into_iter().take(limit).map(|f| self.conn_view(f)).collect()),
            Some(flt) => {
                let views: Vec<ConnView> = list.into_iter().map(|f| self.conn_view(f)).filter(|c| flt.matches(c)).collect();
                (views.len(), views.into_iter().take(limit).collect())
            }
        }
    }

    /// Flows matching like [`State::connections`], for exports.
    pub fn matching_flows(&self, pid: Option<u32>, filter: Option<&Filter>) -> Vec<&Flow> {
        let ids: std::collections::HashSet<u64> = self.connections(pid, filter, usize::MAX).1.into_iter().map(|c| c.id).collect();
        let mut v: Vec<&Flow> = self.flows().filter(|f| ids.contains(&f.id)).collect();
        v.sort_unstable_by_key(|f| f.first_us);
        v
    }

    /// The DNS journal, newest first; `q` matches the name, requester or answers.
    pub fn dns(&self, q: Option<&str>, limit: usize) -> DnsView {
        self.dns_filtered(&DnsFilter::text(q), limit)
    }

    /// The DNS journal narrowed by `filter`, newest first, with the value counts of
    /// [`DNS_FACETS`] for the filter bar.
    pub fn dns_filtered(&self, filter: &DnsFilter, limit: usize) -> DnsView {
        let q = filter.q.as_deref().map(str::to_lowercase).filter(|q| !q.is_empty());
        // Which programs connected to which addresses (to show who used an answer).
        let mut users: HashMap<String, Vec<String>> = HashMap::new();
        for f in self.flows() {
            if let Some(p) = &f.process {
                let list = users.entry(f.key.remote.ip().to_string()).or_default();
                if !list.contains(&p.name) {
                    list.push(p.name.clone());
                }
            }
        }
        let mut counter = Counter::new(DNS_FACETS);
        let mut matching: Vec<&DnsEntry> = Vec::new();
        for e in self.dns_log.iter().filter(|e| filter.base_matches(e, q.as_deref())) {
            counter.add(&filter.facets, |f| DnsFilter::value(e, f));
            if filter.facets.matches(|f| DnsFilter::value(e, f)) {
                matching.push(e);
            }
        }
        let total = matching.len();
        let entries = matching
            .into_iter()
            .take(limit)
            .map(|e| {
                let mut used_by: Vec<String> = e.answers.iter().filter_map(|a| users.get(a)).flatten().cloned().collect();
                used_by.sort();
                used_by.dedup();
                DnsEntryView { entry: e.clone(), used_by }
            })
            .collect();
        let mut encrypted: Vec<ConnView> = self
            .flows()
            .filter(|f| encrypted_dns_kind(f.key.l4, f.key.remote, f.name.as_deref()).is_some())
            .map(|f| self.conn_view(f))
            .collect();
        encrypted.sort_unstable_by_key(|c| std::cmp::Reverse(c.last_us));
        DnsView { entries, total, queries: self.dns_log.queries, failures: self.dns_log.failures, encrypted, facets: counter.finish() }
    }

    pub fn processes(&self) -> ProcessesView {
        let now_us = self.flows().map(|f| f.last_us).max().unwrap_or(0);
        let mut active: HashMap<u32, usize> = HashMap::new();
        let mut protos: HashMap<u32, u16> = HashMap::new();
        let mut remotes: HashMap<u32, HashMap<String, u64>> = HashMap::new();
        let mut ja4: HashMap<u32, Vec<String>> = HashMap::new();
        let mut unattributed = Unattributed::default();
        for f in self.flows() {
            let live = f.state != FlowState::Closed && now_us - f.last_us < ACTIVE_US;
            match &f.process {
                Some(p) => {
                    *active.entry(p.pid).or_default() += usize::from(live);
                    *protos.entry(p.pid).or_default() |= 1 << f.app.index();
                    let label = f.name.clone().or_else(|| self.name_of(&f.key.remote.ip()).map(|n| n.name.clone())).unwrap_or_else(|| f.key.remote.ip().to_string());
                    *remotes.entry(p.pid).or_default().entry(label).or_default() += f.total();
                    if let Some(t) = &f.tls {
                        let list = ja4.entry(p.pid).or_default();
                        if !list.contains(&t.ja4) && list.len() < 8 {
                            list.push(t.ja4.clone());
                        }
                    }
                }
                None => {
                    unattributed.connections += 1;
                    unattributed.bytes_in += f.bytes_in;
                    unattributed.bytes_out += f.bytes_out;
                }
            }
        }
        let mut processes: Vec<ProcessView> = self
            .process_stats()
            .map(|(p, s)| {
                let r = self.proc_ref(p);
                let mut top: Vec<(String, u64)> = remotes.remove(&p.pid).unwrap_or_default().into_iter().collect();
                top.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                let bits = protos.get(&p.pid).copied().unwrap_or(0);
                ProcessView {
                    pid: r.pid,
                    name: r.name,
                    path: r.path,
                    parent: r.parent,
                    parent_name: r.parent_name,
                    bytes_in: s.bytes_in,
                    bytes_out: s.bytes_out,
                    packets: s.packets,
                    connections_total: s.connections,
                    connections_active: active.get(&p.pid).copied().unwrap_or(0),
                    first_us: s.first_us,
                    last_us: s.last_us,
                    protocols: Proto::ALL.into_iter().filter(|x| bits & (1 << x.index()) != 0).map(Proto::name).collect(),
                    top_remotes: top.into_iter().take(5).map(|x| x.0).collect(),
                    signature: self.signature_for(p),
                    suspicious_path: p.path.as_deref().is_some_and(suspicious_location),
                    ja4: ja4.remove(&p.pid).unwrap_or_default(),
                }
            })
            .collect();
        processes.sort_unstable_by(|a, b| (b.bytes_in + b.bytes_out).cmp(&(a.bytes_in + a.bytes_out)).then(a.pid.cmp(&b.pid)));
        ProcessesView {
            processes,
            unattributed,
            attribution_error: self.owners().and_then(|o| o.error().map(String::from)),
            attribution_enabled: self.owners().is_some(),
        }
    }

    fn socket_view(&self, s: &crate::procs::SocketEntry, current: bool) -> SocketView {
        SocketView {
            proto: s.proto,
            local: s.local.to_string(),
            remote: s.remote.map(|r| r.to_string()),
            state: s.state,
            pid: s.pid,
            process: self.owners().and_then(|o| o.process(s.pid)).map(|p| p.name.clone()),
            current,
        }
    }

    pub fn sockets(&self, pid: Option<u32>) -> SocketsView {
        let Some(o) = self.owners() else {
            return SocketsView { sockets: vec![], error: None, enabled: false };
        };
        let mut sockets: Vec<SocketView> =
            o.sockets().iter().filter(|s| pid.is_none_or(|p| s.pid == p)).map(|s| self.socket_view(s, false)).collect();
        sockets.sort_by(|a, b| a.pid.cmp(&b.pid).then(a.local.cmp(&b.local)));
        SocketsView { sockets, error: o.error().map(String::from), enabled: true }
    }

    pub fn netpath(&self) -> NetPathView {
        let geo = self.geo.as_deref();
        let mut vpn: Vec<VpnTunnel> = Vec::new();
        if let Some(o) = self.owners() {
            for s in o.sockets() {
                let Some(remote) = s.remote else { continue };
                if !crate::analytics::addr::is_external(&remote.ip()) {
                    continue;
                }
                let Some(p) = o.process(s.pid).filter(|p| is_vpn_process(&p.name)) else { continue };
                let entry = match vpn.iter_mut().position(|t| t.pid == p.pid) {
                    Some(i) => &mut vpn[i],
                    None => {
                        vpn.push(VpnTunnel { process: p.name.clone(), pid: p.pid, path: p.path.clone(), servers: vec![] });
                        vpn.last_mut().expect("just pushed")
                    }
                };
                if entry.servers.len() < 8 && !entry.servers.iter().any(|x| x.addr == remote.to_string()) {
                    entry.servers.push(VpnServer { addr: remote.to_string(), state: s.state, geo: geo.and_then(|g| g.lookup(remote.ip())) });
                }
            }
        }

        let mut countries: HashMap<String, CountryStat> = HashMap::new();
        if let Some(g) = geo {
            for (ip, h) in &self.hosts {
                if let Some(info) = g.lookup(*ip) {
                    let code = info.country_code.clone().unwrap_or_else(|| "??".into());
                    let c = countries.entry(code.clone()).or_insert(CountryStat { code, name: info.country.clone(), name_ru: info.country_ru.clone(), hosts: 0, bytes: 0 });
                    c.hosts += 1;
                    c.bytes += h.total();
                }
            }
        }
        let mut countries: Vec<CountryStat> = countries.into_values().collect();
        countries.sort_unstable_by(|a, b| b.bytes.cmp(&a.bytes).then(a.code.cmp(&b.code)));

        let (egress, egress_error) = match &self.egress {
            Some(Ok(e)) => {
                let mut e = e.clone();
                e.geo = e.ip.parse().ok().and_then(|ip| geo.and_then(|g| g.lookup(ip)));
                (Some(e), None)
            }
            Some(Err(err)) => (None, Some(err.clone())),
            None => (None, None),
        };
        let interface = self.capture.description.clone().unwrap_or_else(|| self.capture.source.clone());
        NetPathView {
            interface_is_tunnel: self.capture.mode == "live" && is_tunnel_adapter(&interface),
            interface,
            local_ips: self.local_addresses().iter().map(|ip| ip.to_string()).collect(),
            vpn,
            egress,
            egress_error,
            egress_enabled: self.egress_enabled,
            countries,
            geo: geo.map(|g| g.status()),
        }
    }

    pub fn connection_detail(&self, id: u64) -> Option<ConnDetail> {
        let f = self.flow(id)?;
        let lt = self.linktype;
        let packets = f
            .stored()
            .map(|p| PacketRow { n: p.n, ts_us: p.ts_us, outbound: p.outbound, wire_len: p.wire_len, captured: p.data.len(), info: summary(lt, &p.data) })
            .collect();
        let mut os_state = None;
        let mut sockets = Vec::new();
        if let (Some(o), Some(p)) = (self.owners(), &f.process) {
            for s in o.sockets().iter().filter(|s| s.pid == p.pid) {
                // Bound/listening sockets have no peer; connected ones must match ours exactly
                // (several connections from the same local port go to different peers).
                let remote = f.key.remote;
                let current = Some(s.proto) == f.key.l4.sock()
                    && s.local.port() == f.key.local.port()
                    && s.remote.map(unmap).is_none_or(|r| r.port() == remote.port() && r.ip() == unmap(remote).ip());
                if current && os_state.is_none() {
                    os_state = s.state;
                }
                sockets.push(self.socket_view(s, current));
            }
            sockets.sort_by(|a, b| b.current.cmp(&a.current).then(a.local.cmp(&b.local)));
        }
        let tls_server = (f.app == Proto::Tls && f.key.l4 == L4::Tcp).then(|| self.server_tls(f));
        Some(ConnDetail { conn: self.conn_view(f), os_state, packets, dropped_packets: f.dropped_packets(), sockets, tls_server })
    }

    /// Reads ServerHello and certificates from the start of the server's byte stream.
    fn server_tls(&self, f: &Flow) -> ServerTlsView {
        let incomplete = !f.has_beginning();
        let mut inbound = Vec::new();
        if !incomplete {
            let refs: Vec<_> = f.stored().collect();
            for s in reassemble(self.linktype, L4::Tcp, &refs).into_iter().filter(|s| !s.outbound) {
                if s.gap_before > 0 || inbound.len() > 256 * 1024 {
                    break;
                }
                inbound.extend_from_slice(&s.data);
            }
        }
        let side = parse_server_stream(&inbound);
        let hello = side.hello.as_ref();
        ServerTlsView {
            version: hello.map(|h| version_name(h.version)),
            cipher: hello.map(|h| cipher_name(h.cipher).map_or_else(|| format!("0x{:04x}", h.cipher), String::from)),
            alpn: hello.and_then(|h| h.alpn.clone()),
            certificates: side.certificates,
            encrypted_certificates: side.encrypted_certificates,
            incomplete,
        }
    }

    pub fn packet_detail(&self, id: u64, n: u64) -> Option<PacketDetail> {
        let p = self.flow(id)?.packet(n)?;
        Some(PacketDetail { n: p.n, ts_us: p.ts_us, outbound: p.outbound, wire_len: p.wire_len, layers: dissect(self.linktype, &p.data), hex: hex(&p.data) })
    }

    pub fn stream(&self, id: u64) -> Option<StreamView> {
        let f = self.flow(id)?;
        let refs: Vec<_> = f.stored().collect();
        let segs = reassemble(self.linktype, f.key.l4, &refs);
        let (mut out_b, mut in_b, mut budget, mut truncated) = (0, 0, STREAM_MAX, false);
        let mut segments = Vec::new();
        for s in segs {
            if s.outbound {
                out_b += s.data.len();
            } else {
                in_b += s.data.len();
            }
            if budget == 0 {
                truncated = true;
                continue;
            }
            let data = &s.data[..s.data.len().min(budget)];
            truncated |= data.len() < s.data.len();
            budget -= data.len();
            let readable = printable_ratio(data) > 0.85;
            segments.push(StreamSegment {
                outbound: s.outbound,
                ts_us: s.ts_us,
                packets: s.packets,
                gap_before: s.gap_before,
                bytes: s.data.len(),
                readable,
                text: if readable { render_text(data) } else { String::new() },
                hex: if readable { String::new() } else { hex(&data[..data.len().min(4096)]) },
            });
        }
        Some(StreamView {
            id,
            encrypted: matches!(f.app, Proto::Tls | Proto::Quic),
            segments,
            bytes_out: out_b,
            bytes_in: in_b,
            dropped_packets: f.dropped_packets(),
            truncated,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap as Map, HashSet};
    use std::sync::Arc;

    use super::*;
    use crate::analytics::{CaptureInfo, CaptureStatus, Config};
    use crate::decode::{decode, linktype};
    use crate::demo::frames::{tcp_frame_seq, TcpFlags};
    use crate::procs::{OsSnapshot, OwnerIndex, SocketEntry};

    const ME: [u8; 4] = [10, 0, 0, 2];
    const SRV: [u8; 4] = [93, 184, 215, 14];

    fn state() -> State {
        let info = CaptureInfo { mode: "live", source: "t".into(), description: None, filter: None, libpcap: None, status: CaptureStatus::Running };
        State::new(Config::default(), [std::net::IpAddr::from(ME)].into_iter().collect::<HashSet<_>>(), info)
    }

    fn owners() -> Arc<OwnerIndex> {
        let mut procs = Map::new();
        procs.insert(4000, ProcInfo { pid: 4000, name: "Code.exe".into(), path: Some(r"C:\Code\Code.exe".into()), parent: None });
        procs.insert(4100, ProcInfo { pid: 4100, name: "Code.exe".into(), path: Some(r"C:\Code\Code.exe".into()), parent: Some(4000) });
        let tcp = |local: &str, remote: Option<&str>, state: &'static str| SocketEntry {
            proto: SockProto::Tcp,
            local: local.parse().unwrap(),
            remote: remote.map(|r| r.parse().unwrap()),
            state: Some(state),
            pid: 4100,
        };
        Arc::new(OwnerIndex::new(OsSnapshot {
            sockets: vec![
                // Same local port, other peer: a dual-stack socket reports it v4-mapped.
                tcp("[::ffff:10.0.0.2]:50000", Some("[::ffff:198.51.100.9]:80"), "CLOSE_WAIT"),
                tcp("10.0.0.2:50000", Some("93.184.215.14:80"), "ESTABLISHED"),
                tcp("127.0.0.1:9229", None, "LISTEN"),
            ],
            procs,
            error: None,
        }))
    }

    fn feed(s: &mut State, ts: i64, frame: Vec<u8>) {
        let info = decode(linktype::ETHERNET, &frame);
        s.record_frame(ts, frame.len() as u32, &frame, info.as_ref());
    }

    fn conversation(s: &mut State) {
        let t0 = 1_760_000_000_000_000;
        feed(s, t0, tcp_frame_seq(ME, SRV, 50000, 80, TcpFlags::Syn, 99, b""));
        feed(s, t0 + 10, tcp_frame_seq(SRV, ME, 80, 50000, TcpFlags::SynAck, 499, b""));
        feed(s, t0 + 20, tcp_frame_seq(ME, SRV, 50000, 80, TcpFlags::Data, 100, b"GET /index.html HTTP/1.1\r\nHost: example.org\r\n\r\n"));
        feed(s, t0 + 30, tcp_frame_seq(SRV, ME, 80, 50000, TcpFlags::Data, 500, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"));
    }

    #[test]
    fn process_attribution_detail_and_stream() {
        let mut s = state();
        s.set_owners(owners());
        conversation(&mut s);

        let procs = s.processes();
        assert_eq!(procs.processes.len(), 1);
        let p = &procs.processes[0];
        assert_eq!((p.pid, p.name.as_str(), p.parent_name.as_deref()), (4100, "Code.exe", Some("Code.exe")));
        assert_eq!((p.connections_total, p.connections_active), (1, 1));
        assert_eq!(p.top_remotes, vec!["example.org"]);
        assert_eq!(p.protocols, vec!["http"]);

        let (total, list) = s.connections(Some(4100), None, 10);
        assert_eq!(total, 1);
        let c = &list[0];
        assert_eq!((c.local.as_str(), c.remote.as_str(), c.app), ("10.0.0.2:50000", "93.184.215.14:80", "http"));
        assert_eq!((c.initiated, c.state, c.name.as_deref()), (Some("local"), FlowState::Established, Some("example.org")));
        let code = Filter::parse("code", CONN_FIELDS).unwrap();
        assert_eq!(s.connections(None, Some(&code), 10).0, 1);
        let nothing = Filter::parse("nothing", CONN_FIELDS).unwrap();
        assert_eq!(s.connections(None, Some(&nothing), 10).0, 0);
        let typed = Filter::parse("process == code.exe and app == http and port = 80 and dir == out and bytes > 100", CONN_FIELDS).unwrap();
        assert_eq!(s.connections(None, Some(&typed), 10).0, 1);
        let other = Filter::parse("process == chrome.exe or app == tls", CONN_FIELDS).unwrap();
        assert_eq!(s.connections(None, Some(&other), 10).0, 0);
        assert_eq!(s.connections(Some(0), None, 10).0, 0);

        let d = s.connection_detail(c.id).unwrap();
        assert_eq!(d.packets.len(), 4);
        assert!(d.packets[0].info.starts_with("TCP: 50000 → 80 [SYN]"));
        assert_eq!(d.packets[2].info, "HTTP: GET /index.html");
        assert!(d.packets[3].info.starts_with("HTTP: HTTP/1.1 200 OK"));
        assert_eq!(d.os_state, Some("ESTABLISHED"), "the socket with our peer, not the one with another peer on the same port");
        assert_eq!(d.sockets.len(), 3);
        assert_eq!(d.sockets.iter().filter(|s| s.current).count(), 1);
        assert_eq!(d.sockets[0].remote.as_deref(), Some("93.184.215.14:80"));
        assert_eq!(p.signature, None, "path known, verification pending");

        let pkt = s.packet_detail(c.id, 3).unwrap();
        assert_eq!(pkt.layers.iter().map(|l| l.name.as_str()).collect::<Vec<_>>(), vec!["Ethernet II", "IPv4", "TCP", "HTTP"]);
        assert_eq!(pkt.hex.len(), 2 * pkt.wire_len as usize);
        assert!(s.packet_detail(c.id, 99).is_none());

        let st = s.stream(c.id).unwrap();
        assert!(!st.encrypted);
        assert_eq!(st.segments.len(), 2);
        assert!(st.segments[0].outbound && st.segments[0].text.starts_with("GET /index.html HTTP/1.1\nHost: example.org"));
        assert!(!st.segments[1].outbound && st.segments[1].text.ends_with("hello"));

        let socks = s.sockets(Some(4100));
        assert!(socks.enabled && socks.sockets.len() == 3);
        assert_eq!(socks.sockets[0].process.as_deref(), Some("Code.exe"));
    }

    #[test]
    fn pathless_process_has_an_unknown_signature() {
        let mut s = state();
        let mut procs = Map::new();
        procs.insert(4, ProcInfo { pid: 4, name: "System".into(), path: None, parent: None });
        s.set_owners(Arc::new(OwnerIndex::new(OsSnapshot {
            sockets: vec![SocketEntry { proto: SockProto::Tcp, local: "10.0.0.2:50000".parse().unwrap(), remote: Some("93.184.215.14:80".parse().unwrap()), state: Some("ESTABLISHED"), pid: 4 }],
            procs,
            error: None,
        })));
        conversation(&mut s);
        let p = &s.processes().processes[0];
        assert_eq!((p.pid, p.path.as_deref()), (4, None));
        assert_eq!(p.signature, Some(Signature { status: SigStatus::Unknown, signer: None }));
        assert_eq!(serde_json::to_value(p).unwrap()["signature"]["status"], "unknown");
    }

    #[test]
    fn country_names_are_english_with_russian_alongside() {
        use crate::geo::mmdb::{testdb::*, Mmdb};
        use crate::geo::GeoDb;
        let mut data = Vec::new();
        map(&mut data, &[("country", &|o: &mut Vec<u8>| {
            map(o, &[
                ("iso_code", &|o: &mut Vec<u8>| string(o, "DE")),
                ("names", &|o: &mut Vec<u8>| map(o, &[("en", &|o: &mut Vec<u8>| string(o, "Germany")), ("ru", &|o: &mut Vec<u8>| string(o, "Германия"))])),
            ])
        })]);
        let city = Mmdb::from_bytes(build([93, 0, 0, 0], 8, &data)).unwrap();
        let mut s = state();
        s.geo = Some(Arc::new(GeoDb::from_dbs(Some(city), None)));
        conversation(&mut s);
        let np = s.netpath();
        assert_eq!(np.countries.len(), 1);
        let c = &np.countries[0];
        assert_eq!((c.code.as_str(), c.name.as_deref(), c.name_ru.as_deref(), c.hosts), ("DE", Some("Germany"), Some("Германия"), 1));
        let json = serde_json::to_value(&np).unwrap();
        assert_eq!(json["countries"][0]["name_ru"], "Германия");
        let conn = &s.connections(None, None, 1).1[0];
        assert_eq!(conn.geo.as_ref().unwrap().country_ru.as_deref(), Some("Германия"));
    }

    #[test]
    fn late_owner_snapshot_attributes_existing_connections() {
        let mut s = state();
        conversation(&mut s);
        assert!(s.wants_owner_refresh());
        assert_eq!(s.processes().unattributed.connections, 1);
        s.set_owners(owners());
        assert!(!s.wants_owner_refresh());
        let p = &s.processes().processes[0];
        assert_eq!((p.pid, p.packets), (4100, 4));
        assert_eq!(s.processes().unattributed.connections, 0);
    }
}
