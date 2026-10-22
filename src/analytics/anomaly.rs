//! Alerts and the heuristics that raise them.

use std::collections::{BTreeMap, HashMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::decode::dns;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    SensitiveHttp,
    SuspiciousDns,
    VolumeSpike,
    CleartextProtocol,
    /// A program used the network for the first time.
    NewProcess,
    /// A program contacted a domain/provider it never contacted before.
    NewDestination,
    /// A program contacted a new country.
    NewCountry,
    /// A program started listening on a port reachable from the network.
    NewListener,
    /// An unsigned (or badly signed) executable uses the network.
    UnsignedProcess,
    /// A watched route changed its path.
    RouteChange,
    /// A watched route became markedly slower.
    LatencyIncrease,
    /// The default route moved to another adapter (Wi-Fi ↔ Ethernet, a VPN tunnel came or went).
    NetworkChange,
    /// The public egress address (or country) changed: a VPN was switched on/off, another network.
    EgressChange,
    /// DNS queries started going to a resolver never seen before.
    DnsResolverChange,
    /// A program opened a connection that looks like remote control, SMB to the internet,
    /// direct SMTP, or an unsigned program talking to a bare IP.
    SuspiciousConnection,
    /// Many ports of one host probed in a short time (inbound: someone scans us; outbound: a
    /// program scans a host).
    PortScan,
    /// A program sent a lot of data to one host.
    LargeUpload,
    /// Live capture stopped with an error (adapter gone, driver problem).
    CaptureFailed,
}

/// What an alert is about; the desktop app lets notifications be switched per category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    /// Threat indicators: credentials, suspicious DNS, scans, unsigned programs…
    Security,
    /// "First time seen": programs, destinations, countries, listeners.
    Novelty,
    /// The machine's own connectivity: adapters, VPN, egress, resolver, capture.
    Network,
    /// Watched routes.
    Routes,
}

impl Category {
    pub const ALL: [Category; 4] = [Category::Security, Category::Novelty, Category::Network, Category::Routes];

    /// The name used in settings and JSON (`security`, `novelty`, `network`, `routes`).
    pub fn name(self) -> &'static str {
        match self {
            Category::Security => "security",
            Category::Novelty => "novelty",
            Category::Network => "network",
            Category::Routes => "routes",
        }
    }

    pub fn parse(s: &str) -> Option<Category> {
        Category::ALL.into_iter().find(|c| c.name() == s.trim().to_ascii_lowercase())
    }
}

impl AlertKind {
    pub const ALL: [AlertKind; 18] = [
        AlertKind::SensitiveHttp,
        AlertKind::SuspiciousDns,
        AlertKind::VolumeSpike,
        AlertKind::CleartextProtocol,
        AlertKind::NewProcess,
        AlertKind::NewDestination,
        AlertKind::NewCountry,
        AlertKind::NewListener,
        AlertKind::UnsignedProcess,
        AlertKind::RouteChange,
        AlertKind::LatencyIncrease,
        AlertKind::NetworkChange,
        AlertKind::EgressChange,
        AlertKind::DnsResolverChange,
        AlertKind::SuspiciousConnection,
        AlertKind::PortScan,
        AlertKind::LargeUpload,
        AlertKind::CaptureFailed,
    ];

    pub fn category(self) -> Category {
        match self {
            AlertKind::SensitiveHttp
            | AlertKind::SuspiciousDns
            | AlertKind::VolumeSpike
            | AlertKind::CleartextProtocol
            | AlertKind::UnsignedProcess
            | AlertKind::SuspiciousConnection
            | AlertKind::PortScan
            | AlertKind::LargeUpload => Category::Security,
            AlertKind::NewProcess | AlertKind::NewDestination | AlertKind::NewCountry | AlertKind::NewListener => Category::Novelty,
            AlertKind::NetworkChange | AlertKind::EgressChange | AlertKind::DnsResolverChange | AlertKind::CaptureFailed => Category::Network,
            AlertKind::RouteChange | AlertKind::LatencyIncrease => Category::Routes,
        }
    }

    /// The snake_case name used in JSON (`new_process`, `egress_change`…).
    pub fn name(self) -> &'static str {
        match self {
            AlertKind::SensitiveHttp => "sensitive_http",
            AlertKind::SuspiciousDns => "suspicious_dns",
            AlertKind::VolumeSpike => "volume_spike",
            AlertKind::CleartextProtocol => "cleartext_protocol",
            AlertKind::NewProcess => "new_process",
            AlertKind::NewDestination => "new_destination",
            AlertKind::NewCountry => "new_country",
            AlertKind::NewListener => "new_listener",
            AlertKind::UnsignedProcess => "unsigned_process",
            AlertKind::RouteChange => "route_change",
            AlertKind::LatencyIncrease => "latency_increase",
            AlertKind::NetworkChange => "network_change",
            AlertKind::EgressChange => "egress_change",
            AlertKind::DnsResolverChange => "dns_resolver_change",
            AlertKind::SuspiciousConnection => "suspicious_connection",
            AlertKind::PortScan => "port_scan",
            AlertKind::LargeUpload => "large_upload",
            AlertKind::CaptureFailed => "capture_failed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: u64,
    /// Unix seconds (packet time).
    pub ts: i64,
    pub severity: Severity,
    pub kind: AlertKind,
    /// `kind.category()`, repeated so clients need not know the mapping.
    pub category: Category,
    /// Remote IP the alert is about; `null` for alerts about a program or a route.
    pub host: Option<String>,
    pub name: Option<String>,
    /// English text; the UI composes localized text from `kind` and `details`.
    pub message: String,
    /// Structured parameters of the message (e.g. `process`, `domain`, `reason`).
    pub details: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct AlertCounts {
    pub low: u64,
    pub medium: u64,
    pub high: u64,
    pub total: u64,
}

/// Bounded alert history with per-key suppression of repeats.
pub struct AlertLog {
    items: VecDeque<Alert>,
    capacity: usize,
    next_id: u64,
    last_by_key: HashMap<String, i64>,
    suppress_secs: i64,
    counts: AlertCounts,
}

pub struct NewAlert {
    pub severity: Severity,
    pub kind: AlertKind,
    pub host: Option<String>,
    pub name: Option<String>,
    pub message: String,
    pub details: BTreeMap<String, String>,
    /// Alerts with the same key within the suppression window are dropped.
    pub key: String,
}

/// Builds a details map from key/value pairs.
pub fn details<const N: usize>(pairs: [(&str, String); N]) -> BTreeMap<String, String> {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

impl AlertLog {
    pub fn new(capacity: usize, suppress_secs: i64) -> Self {
        Self {
            items: VecDeque::with_capacity(capacity),
            capacity,
            next_id: 1,
            last_by_key: HashMap::new(),
            suppress_secs,
            counts: AlertCounts::default(),
        }
    }

    /// Returns `true` if the alert was recorded (not suppressed).
    pub fn push(&mut self, ts: i64, a: NewAlert) -> bool {
        if let Some(&last) = self.last_by_key.get(&a.key) {
            if ts - last < self.suppress_secs {
                return false;
            }
        }
        if self.last_by_key.len() >= 10_000 {
            let horizon = ts - self.suppress_secs;
            self.last_by_key.retain(|_, &mut t| t >= horizon);
        }
        self.last_by_key.insert(a.key, ts);

        match a.severity {
            Severity::Low => self.counts.low += 1,
            Severity::Medium => self.counts.medium += 1,
            Severity::High => self.counts.high += 1,
        }
        self.counts.total += 1;
        if self.items.len() == self.capacity {
            self.items.pop_front();
        }
        self.items.push_back(Alert {
            id: self.next_id,
            ts,
            severity: a.severity,
            kind: a.kind,
            category: a.kind.category(),
            host: a.host,
            name: a.name,
            message: a.message,
            details: a.details,
        });
        self.next_id += 1;
        true
    }

    /// Newest first.
    pub fn recent(&self, limit: usize) -> Vec<Alert> {
        self.items.iter().rev().take(limit).cloned().collect()
    }

    /// The most recently recorded alert.
    pub fn last(&self) -> Option<&Alert> {
        self.items.back()
    }

    pub fn counts(&self) -> AlertCounts {
        self.counts
    }
}

/// Shannon entropy in bits per character.
pub fn entropy(s: &str) -> f64 {
    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    let n = s.len() as f64;
    freq.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f64 / n;
        -p * p.log2()
    }).sum()
}

/// Why a DNS lookup looks suspicious.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsFinding {
    pub severity: Severity,
    /// `long_name`, `long_label`, `entropy` or `rare_type`.
    pub reason: &'static str,
    /// The measured value (length, label or record type).
    pub value: String,
    pub message: String,
}

/// Heuristics for DNS tunneling / exfiltration and unusual lookups.
pub fn inspect_dns(name: &str, qtype: u16) -> Option<DnsFinding> {
    // Reverse lookups and local service discovery are noisy and benign.
    if name.ends_with(".arpa") || name.ends_with(".local") || name == "." {
        return None;
    }
    let finding = |severity, reason, value: String, message: String| Some(DnsFinding { severity, reason, value, message });
    if name.len() > 100 {
        return finding(Severity::Medium, "long_name", name.len().to_string(), format!("very long DNS name ({} chars), typical of DNS tunneling", name.len()));
    }
    if let Some(label) = name.split('.').find(|l| l.len() > 50) {
        return finding(Severity::Medium, "long_label", label.len().to_string(), format!("oversized DNS label ({} chars)", label.len()));
    }
    if let Some(label) = name.split('.').find(|l| l.len() >= 20 && l.bytes().any(|b| b.is_ascii_digit()) && entropy(l) > 3.8) {
        return finding(Severity::Medium, "entropy", label.to_string(), format!("high-entropy subdomain `{label}` (possible data exfiltration)"));
    }
    match qtype {
        dns::TYPE_TXT | dns::TYPE_NULL | dns::TYPE_ANY => {
            let t = dns::qtype_name(qtype);
            finding(Severity::Low, "rare_type", t.to_string(), format!("unusual DNS record type {t} requested"))
        }
        _ => None,
    }
}

/// Plain-text legacy protocols worth flagging when a connection is opened.
pub fn cleartext_service(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "FTP",
        23 => "Telnet",
        110 => "POP3",
        143 => "IMAP",
        512 => "rexec",
        513 => "rlogin",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(key: &str, sev: Severity) -> NewAlert {
        NewAlert {
            severity: sev,
            kind: AlertKind::SuspiciousDns,
            host: Some("1.2.3.4".into()),
            name: None,
            message: "m".into(),
            details: BTreeMap::new(),
            key: key.into(),
        }
    }

    #[test]
    fn host_serializes_as_null_when_absent() {
        let mut log = AlertLog::new(3, 60);
        log.push(1, NewAlert { host: None, kind: AlertKind::NewProcess, ..alert("p", Severity::Low) });
        log.push(2, alert("h", Severity::Low));
        let json = serde_json::to_value(log.recent(10)).unwrap();
        assert_eq!(json[0]["host"], "1.2.3.4");
        assert!(json[1]["host"].is_null(), "{json}");
        assert_eq!(json[1]["kind"], "new_process");
    }

    #[test]
    fn log_suppresses_repeats_and_is_bounded() {
        let mut log = AlertLog::new(3, 60);
        assert!(log.push(100, alert("a", Severity::High)));
        assert!(!log.push(130, alert("a", Severity::High)), "within window");
        assert!(log.push(160, alert("a", Severity::High)), "window passed");
        assert!(log.push(161, alert("b", Severity::Low)));
        assert!(log.push(162, alert("c", Severity::Medium)));
        let recent = log.recent(10);
        assert_eq!(recent.len(), 3, "capacity");
        assert_eq!(recent.iter().map(|a| a.id).collect::<Vec<_>>(), vec![4, 3, 2], "newest first, ids increase");
        let c = log.counts();
        assert_eq!((c.low, c.medium, c.high, c.total), (1, 1, 2, 4), "counts include evicted alerts");
    }

    #[test]
    fn entropy_values() {
        assert_eq!(entropy("aaaa"), 0.0);
        assert!((entropy("ab") - 1.0).abs() < 1e-9);
        assert!(entropy("x7k2p9q4m1v8b3n6c5z0") > 4.0);
    }

    #[test]
    fn dns_heuristics() {
        assert!(inspect_dns("www.google.com", dns::TYPE_A).is_none());
        assert!(inspect_dns("1.0.168.192.in-addr.arpa", dns::TYPE_A).is_none());
        assert!(inspect_dns("_googlecast._tcp.local", dns::TYPE_ANY).is_none());
        assert!(inspect_dns("cdn-assets-production-eu-west.example.com", dns::TYPE_A).is_none(), "long but low entropy");

        let f = inspect_dns("x7k2p9q4m1v8b3n6c5z0w1.tunnel.example", dns::TYPE_A).unwrap();
        assert_eq!((f.severity, f.reason, f.value.as_str()), (Severity::Medium, "entropy", "x7k2p9q4m1v8b3n6c5z0w1"));
        assert!(f.message.contains("high-entropy"));

        let long = format!("{}.example.com", "a".repeat(60));
        assert_eq!(inspect_dns(&long, dns::TYPE_A).unwrap().reason, "long_label");
        let huge = format!("{}.example.com", ["abcdefghij"; 11].join("."));
        assert_eq!(inspect_dns(&huge, dns::TYPE_A).unwrap().reason, "long_name");

        let txt = inspect_dns("example.com", dns::TYPE_TXT).unwrap();
        assert_eq!((txt.severity, txt.reason, txt.value.as_str()), (Severity::Low, "rare_type", "TXT"));
    }

    #[test]
    fn kind_names_match_serde_and_every_kind_has_a_category() {
        for k in AlertKind::ALL {
            let json = serde_json::to_value(k).unwrap();
            assert_eq!(json.as_str(), Some(k.name()), "{k:?}");
            let _ = k.category();
        }
        for c in Category::ALL {
            assert_eq!(serde_json::to_value(c).unwrap().as_str(), Some(c.name()));
            assert_eq!(Category::parse(c.name()), Some(c));
            assert_eq!(Category::parse(&format!(" {} ", c.name().to_uppercase())), Some(c));
        }
        assert_eq!(Category::parse("bogus"), None);
        assert_eq!(AlertKind::EgressChange.category(), Category::Network);
        assert_eq!(AlertKind::PortScan.category(), Category::Security);
    }

    #[test]
    fn alerts_carry_their_category() {
        let mut log = AlertLog::new(4, 60);
        log.push(1, NewAlert { severity: Severity::Low, kind: AlertKind::RouteChange, host: None, name: None, message: "m".into(), details: BTreeMap::new(), key: "k".into() });
        assert_eq!(log.last().unwrap().category, Category::Routes);
        let v = serde_json::to_value(log.last().unwrap()).unwrap();
        assert_eq!(v["category"], "routes");
    }

    #[test]
    fn cleartext_ports() {
        assert_eq!(cleartext_service(23), Some("Telnet"));
        assert_eq!(cleartext_service(443), None);
    }
}
