//! JSON-ready view of [`State`] served by `/api/stats` and streamed over `/api/ws`.

use serde::Serialize;

use super::addr::is_local_scope;
use super::anomaly::{Alert, AlertCounts};
use super::flows::FlowState;
use super::state::{CaptureInfo, NameSource, Sample, State, Totals};
use super::views::{ConnView, NetPathView, ProcessesView};
use crate::geo::GeoInfo;
use crate::decode::Proto;

/// Seconds of bandwidth history sent to clients.
const SERIES_POINTS: usize = 120;
const DNS_TOP: usize = 15;
/// Connections included in every snapshot (the UI pages through `/api/connections` for more).
const CONNECTIONS: usize = 300;

#[derive(Debug, Serialize)]
pub struct Snapshot {
    /// Current second of the traffic clock (unix seconds).
    pub now: i64,
    pub uptime_secs: i64,
    pub capture: CaptureInfo,
    pub totals: Totals,
    pub rates: Rates,
    pub protocols: Vec<ProtoView>,
    pub host_count: usize,
    pub hosts: Vec<HostView>,
    pub series: Vec<Sample>,
    pub dns_top: Vec<DnsView>,
    pub alert_counts: AlertCounts,
    pub alerts: Vec<Alert>,
    /// Network activity per process.
    pub processes: ProcessesView,
    /// Most recently active connections.
    pub connections: Vec<ConnView>,
    pub connection_count: usize,
    /// Connections (of all in memory, not only those listed) that are not closed.
    pub open_connections: usize,
    /// Egress address, VPN tunnels and traffic per country.
    pub netpath: NetPathView,
    pub version: &'static str,
}

/// Throughput of the last complete second.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Rates {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets: u64,
}

#[derive(Debug, Serialize)]
pub struct ProtoView {
    pub name: &'static str,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct HostView {
    pub ip: String,
    pub name: Option<String>,
    pub name_source: Option<NameSource>,
    pub scope: &'static str,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets: u64,
    pub protocols: Vec<&'static str>,
    pub ports: Vec<u16>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub peak_bytes_per_sec: u64,
    pub flagged: bool,
    pub geo: Option<GeoInfo>,
    pub hops: Option<u8>,
    /// Best TCP handshake round trip in milliseconds.
    pub rtt_ms: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct DnsView {
    pub name: String,
    pub count: u64,
}

impl State {
    pub fn snapshot(&self, max_hosts: usize, max_alerts: usize) -> Snapshot {
        let mut hosts: Vec<_> = self.hosts.iter().collect();
        hosts.sort_unstable_by(|a, b| b.1.total().cmp(&a.1.total()).then(a.0.cmp(b.0)));
        let hosts = hosts
            .into_iter()
            .take(max_hosts)
            .map(|(ip, h)| {
                let named = self.names.get(ip);
                HostView {
                    ip: ip.to_string(),
                    name: named.map(|n| n.name.clone()),
                    name_source: named.map(|n| n.source),
                    scope: if is_local_scope(ip) { "local" } else { "external" },
                    bytes_in: h.bytes_in,
                    bytes_out: h.bytes_out,
                    packets: h.packets,
                    protocols: h.protocols().into_iter().map(Proto::name).collect(),
                    ports: h.ports.iter().copied().collect(),
                    first_seen: h.first_seen,
                    last_seen: h.last_seen,
                    peak_bytes_per_sec: h.peak_bytes_per_sec,
                    flagged: h.flagged,
                    geo: self.geo.as_ref().and_then(|g| g.lookup(*ip)),
                    hops: h.hops,
                    rtt_ms: h.rtt_us.map(|r| r as f64 / 1000.0),
                }
            })
            .collect();

        let mut dns: Vec<_> = self.dns_queries.iter().collect();
        dns.sort_unstable_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let dns_top = dns.into_iter().take(DNS_TOP).map(|(n, &c)| DnsView { name: n.clone(), count: c }).collect();

        let (connection_count, connections) = self.connections(None, None, CONNECTIONS);
        Snapshot {
            now: self.now,
            uptime_secs: self.uptime_secs(),
            capture: self.capture.clone(),
            totals: self.totals,
            rates: self.rates(),
            protocols: Proto::ALL
                .into_iter()
                .map(|p| ProtoView { name: p.name(), packets: self.protocols[p.index()].packets, bytes: self.protocols[p.index()].bytes })
                .collect(),
            host_count: self.hosts.len(),
            hosts,
            series: self.series.iter().rev().take(SERIES_POINTS).rev().copied().collect(),
            dns_top,
            alert_counts: self.alerts.counts(),
            alerts: self.alerts.recent(max_alerts),
            processes: self.processes(),
            connections,
            connection_count,
            open_connections: self.flows().filter(|f| f.state != FlowState::Closed).count(),
            netpath: self.netpath(),
            version: env!("CARGO_PKG_VERSION"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::analytics::state::{CaptureStatus, Config};
    use crate::decode::{App, PacketInfo, Transport};

    #[test]
    fn snapshot_orders_hosts_and_serializes() {
        let info = CaptureInfo {
            mode: "file",
            source: "x.pcap".into(),
            description: None,
            filter: None,
            libpcap: None,
            status: CaptureStatus::Finished,
        };
        let mut s = State::new(Config::default(), HashSet::new(), info);
        let t0 = 1_760_000_000_000_000i64;
        for (i, (dst, n)) in [("8.8.8.8", 3u32), ("1.1.1.1", 10), ("10.0.0.9", 1)].into_iter().enumerate() {
            let p = PacketInfo {
                src: "10.0.0.2".parse().unwrap(),
                dst: dst.parse().unwrap(),
                src_port: 1000,
                dst_port: 443,
                transport: Transport::TCP_ACK,
                proto: Proto::Tls,
                app: App::None,
                ttl: 64,
                tcp: None,
            };
            for _ in 0..n {
                s.record(t0 + i as i64 * 1_000_000, 100, Some(&p));
            }
        }
        let snap = s.snapshot(2, 10);
        assert_eq!(snap.host_count, 3);
        assert_eq!(snap.hosts.iter().map(|h| h.ip.as_str()).collect::<Vec<_>>(), vec!["1.1.1.1", "8.8.8.8"]);
        assert_eq!(snap.hosts[0].scope, "external");
        assert_eq!(snap.hosts[0].protocols, vec!["tls"]);
        assert_eq!(snap.uptime_secs, 2);
        assert_eq!(snap.rates.packets, 10, "second-to-last sample");
        assert_eq!(snap.series.len(), 3);

        let json: serde_json::Value = serde_json::to_value(&snap).unwrap();
        assert_eq!(json["capture"]["status"]["state"], "finished");
        assert_eq!(json["protocols"][1]["name"], "tls");
        assert_eq!(json["protocols"][1]["packets"], 14);
        assert_eq!(json["totals"]["bytes_out"], 1400);
        assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(json["open_connections"], 3, "all three TCP flows are open");
    }

    #[test]
    fn open_connections_counts_every_flow_not_closed() {
        let info = CaptureInfo { mode: "file", source: "x".into(), description: None, filter: None, libpcap: None, status: CaptureStatus::Finished };
        let mut s = State::new(Config::default(), HashSet::new(), info);
        let t0 = 1_760_000_000_000_000i64;
        let mk = |port: u16, transport: Transport| PacketInfo {
            src: "10.0.0.2".parse().unwrap(),
            dst: "1.1.1.1".parse().unwrap(),
            src_port: port,
            dst_port: 443,
            transport,
            proto: Proto::Tcp,
            app: App::None,
            ttl: 64,
            tcp: None,
        };
        for port in 1000..1400u16 {
            s.record(t0, 60, Some(&mk(port, Transport::TCP_ACK)));
        }
        for port in 1000..1010u16 {
            s.record(t0 + 1, 60, Some(&mk(port, Transport::Tcp { syn: false, ack: true, fin: false, rst: true })));
        }
        let snap = s.snapshot(1, 1);
        assert_eq!(snap.connections.len(), 300, "listing is capped");
        assert_eq!((snap.connection_count, snap.open_connections), (400, 390), "counted over all flows");
    }
}
