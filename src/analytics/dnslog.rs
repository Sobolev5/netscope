//! DNS journal: every query with its answer, latency, resolver and the process that
//! asked, plus detection of encrypted DNS (DoH / DoT / DoQ) that hides lookups.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};

use serde::Serialize;

use super::flows::L4;
use crate::decode::dns::{qtype_name, DnsMessage};

/// Responses are matched against this many most recent queries.
const MATCH_WINDOW: usize = 512;

/// Public DoH endpoints by TLS SNI / HTTP host.
const DOH_HOSTS: &[&str] = &[
    "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com",
    "dns.google", "dns.google.com", "dns.quad9.net", "dns9.quad9.net", "dns11.quad9.net", "doh.opendns.com",
    "dns.adguard.com", "dns.adguard-dns.com", "dns.nextdns.io", "doh.cleanbrowsing.org", "common.dot.dns.yandex.net",
    "dns.yandex.net", "chrome.cloudflare-dns.com", "doh.dns.sb", "dns.alidns.com", "doh.pub",
];

/// Well-known resolver addresses that also serve DoH on port 443.
const DOH_IPS: &[&str] = &[
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
    "94.140.14.14", "94.140.15.15", "77.88.8.8", "77.88.8.1", "2606:4700:4700::1111", "2001:4860:4860::8888",
];

/// `Some("DoT" | "DoQ" | "DoH")` when a connection carries encrypted DNS.
pub fn encrypted_dns_kind(l4: L4, remote: SocketAddr, name: Option<&str>) -> Option<&'static str> {
    match (l4, remote.port()) {
        (L4::Tcp, 853) => Some("DoT"),
        (L4::Udp, 853) => Some("DoQ"),
        (L4::Tcp | L4::Udp, 443) => {
            let by_name = name.is_some_and(|n| DOH_HOSTS.iter().any(|h| n.eq_ignore_ascii_case(h)));
            let ip = remote.ip().to_string();
            (by_name || DOH_IPS.contains(&ip.as_str())).then_some("DoH")
        }
        _ => None,
    }
}

pub fn rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "OTHER",
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Requester {
    pub pid: u32,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DnsEntry {
    pub seq: u64,
    pub ts_us: i64,
    pub name: String,
    pub qtype: &'static str,
    /// Resolver address (the remote side of the DNS exchange).
    pub resolver: String,
    /// Process that sent the query (on Windows usually the DNS client service).
    pub requester: Option<Requester>,
    pub answers: Vec<String>,
    /// `None` until the response arrives.
    pub rcode: Option<&'static str>,
    pub latency_ms: Option<f64>,
    /// `udp`, `tcp` or `mdns`.
    pub transport: &'static str,
    #[serde(skip)]
    txid: u16,
}

pub struct DnsLog {
    entries: VecDeque<DnsEntry>,
    cap: usize,
    next: u64,
    pub queries: u64,
    pub failures: u64,
}

impl DnsLog {
    pub fn new(cap: usize) -> Self {
        Self { entries: VecDeque::with_capacity(cap.min(4096)), cap, next: 1, queries: 0, failures: 0 }
    }

    fn push(&mut self, e: DnsEntry) {
        if self.entries.len() == self.cap {
            self.entries.pop_front();
        }
        self.entries.push_back(e);
        self.next += 1;
    }

    /// Records a query or the matching response.
    pub fn record(&mut self, ts_us: i64, m: &DnsMessage, resolver: IpAddr, requester: Option<Requester>, transport: &'static str) {
        let answers: Vec<String> = m.answers.iter().map(|a| a.addr.to_string()).collect();
        for q in &m.questions {
            if !m.response {
                self.queries += 1;
                let e = DnsEntry {
                    seq: self.next,
                    ts_us,
                    name: q.name.clone(),
                    qtype: qtype_name(q.qtype),
                    resolver: resolver.to_string(),
                    requester: requester.clone(),
                    answers: vec![],
                    rcode: None,
                    latency_ms: None,
                    transport,
                    txid: m.id,
                };
                self.push(e);
                continue;
            }
            let rcode = rcode_name(m.rcode);
            if m.rcode != 0 {
                self.failures += 1;
            }
            let resolver_s = resolver.to_string();
            let pending = self
                .entries
                .iter_mut()
                .rev()
                .take(MATCH_WINDOW)
                .find(|e| e.rcode.is_none() && e.txid == m.id && e.name == q.name && e.resolver == resolver_s);
            match pending {
                Some(e) => {
                    e.rcode = Some(rcode);
                    e.answers = answers.clone();
                    e.latency_ms = Some((ts_us - e.ts_us).max(0) as f64 / 1000.0);
                }
                // The query was not captured (e.g. capture started in between).
                None => {
                    let e = DnsEntry {
                        seq: self.next,
                        ts_us,
                        name: q.name.clone(),
                        qtype: qtype_name(q.qtype),
                        resolver: resolver_s,
                        requester: requester.clone(),
                        answers: answers.clone(),
                        rcode: Some(rcode),
                        latency_ms: None,
                        transport,
                        txid: m.id,
                    };
                    self.push(e);
                }
            }
        }
    }

    /// Newest first.
    pub fn iter(&self) -> impl Iterator<Item = &DnsEntry> {
        self.entries.iter().rev()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::dns::{build_query, build_response, parse, TYPE_A};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn query_and_response_are_joined() {
        let mut log = DnsLog::new(10);
        let who = Some(Requester { pid: 1844, name: "svchost.exe".into() });
        log.record(1_000_000, &parse(&build_query(7, "example.org", TYPE_A)).unwrap(), ip("192.168.1.1"), who.clone(), "udp");
        let resp = parse(&build_response(7, "example.org", &[ip("93.184.215.14")], 60)).unwrap();
        log.record(1_025_000, &resp, ip("192.168.1.1"), who, "udp");
        assert_eq!(log.len(), 1);
        let e = log.iter().next().unwrap();
        assert_eq!((e.rcode, e.latency_ms, e.answers.clone()), (Some("NOERROR"), Some(25.0), vec!["93.184.215.14".to_string()]));
        assert_eq!(e.requester.as_ref().unwrap().name, "svchost.exe");
        assert_eq!(log.queries, 1);
    }

    #[test]
    fn failures_and_orphan_responses() {
        let mut log = DnsLog::new(2);
        let mut nx = build_response(9, "nope.invalid", &[], 60);
        nx[3] = (nx[3] & 0xF0) | 3;
        log.record(5, &parse(&nx).unwrap(), ip("1.1.1.1"), None, "udp");
        assert_eq!(log.iter().next().unwrap().rcode, Some("NXDOMAIN"));
        assert_eq!(log.failures, 1);
        // A response from another resolver does not complete a pending query.
        log.record(6, &parse(&build_query(1, "a.test", TYPE_A)).unwrap(), ip("1.1.1.1"), None, "udp");
        log.record(7, &parse(&build_response(1, "a.test", &[ip("1.2.3.4")], 1)).unwrap(), ip("8.8.8.8"), None, "udp");
        assert_eq!(log.len(), 2, "bounded");
        assert!(log.iter().any(|e| e.resolver == "1.1.1.1" && e.rcode.is_none()));
    }

    #[test]
    fn encrypted_dns_edge_cases() {
        let sa = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert_eq!(encrypted_dns_kind(L4::Tcp, sa("203.0.113.1:853"), None), Some("DoT"), "any host on 853");
        assert_eq!(encrypted_dns_kind(L4::Udp, sa("203.0.113.1:853"), Some("github.com")), Some("DoQ"), "the port decides, not the name");
        assert_eq!(encrypted_dns_kind(L4::Icmp, sa("1.1.1.1:853"), None), None);
        assert_eq!(encrypted_dns_kind(L4::Other, sa("1.1.1.1:443"), None), None);
        assert_eq!(encrypted_dns_kind(L4::Udp, sa("1.1.1.1:443"), None), Some("DoH"), "DoH over QUIC");
        assert_eq!(encrypted_dns_kind(L4::Tcp, sa("[2606:4700:4700::1111]:443"), None), Some("DoH"));
        assert_eq!(encrypted_dns_kind(L4::Tcp, sa("[2001:4860:4860::8888]:443"), None), Some("DoH"));
        assert_eq!(encrypted_dns_kind(L4::Tcp, sa("104.16.248.249:443"), Some("DNS.GOOGLE")), Some("DoH"), "case-insensitive");
        assert_eq!(encrypted_dns_kind(L4::Tcp, sa("104.16.248.249:443"), Some("dns.google.evil.example")), None, "whole host, not a suffix");
        assert_eq!(encrypted_dns_kind(L4::Tcp, sa("104.16.248.249:443"), Some("xdns.google")), None);
        assert_eq!(encrypted_dns_kind(L4::Tcp, sa("104.16.248.249:443"), Some("")), None);
        assert_eq!(encrypted_dns_kind(L4::Tcp, sa("1.1.1.1:8443"), None), None);
        assert_eq!(encrypted_dns_kind(L4::Tcp, sa("1.1.1.1:53"), None), None, "plain DNS to a DoH resolver is plain DNS");
        assert_eq!(encrypted_dns_kind(L4::Tcp, sa("1.1.1.2:443"), None), None);
        assert_eq!(rcode_name(3), "NXDOMAIN");
        assert_eq!(rcode_name(6), "OTHER");
    }

    #[test]
    fn matching_window_latency_and_multi_question_messages() {
        let mut log = DnsLog::new(5000);
        let r = ip("192.168.1.1");
        log.record(1_000, &parse(&build_query(1, "first.example", TYPE_A)).unwrap(), r, None, "udp");
        for i in 0..MATCH_WINDOW as u16 {
            log.record(2_000 + i64::from(i), &parse(&build_query(100 + i, &format!("q{i}.example"), TYPE_A)).unwrap(), r, None, "udp");
        }
        // The response arrives after MATCH_WINDOW newer queries: it is no longer matched.
        log.record(9_000, &parse(&build_response(1, "first.example", &[ip("1.2.3.4")], 1)).unwrap(), r, None, "udp");
        assert_eq!(log.len(), MATCH_WINDOW + 2);
        let first: Vec<&DnsEntry> = log.iter().filter(|e| e.name == "first.example").collect();
        assert_eq!(first.len(), 2);
        assert!(first[0].rcode.is_some() && first[0].latency_ms.is_none(), "orphan response");
        assert!(first[1].rcode.is_none(), "the query stays pending");
        // Same id and resolver but another name: not a match either.
        log.record(9_100, &parse(&build_query(7, "a.example", TYPE_A)).unwrap(), r, None, "udp");
        log.record(9_200, &parse(&build_response(7, "b.example", &[], 1)).unwrap(), r, None, "udp");
        assert!(log.iter().find(|e| e.name == "a.example").unwrap().rcode.is_none());
        // A response stamped before its query (clock skew in a file) gives latency 0, not negative.
        log.record(10_000, &parse(&build_query(8, "skew.example", TYPE_A)).unwrap(), r, None, "udp");
        log.record(9_900, &parse(&build_response(8, "skew.example", &[], 1)).unwrap(), r, None, "udp");
        assert_eq!(log.iter().find(|e| e.name == "skew.example").unwrap().latency_ms, Some(0.0));
        // Two questions in one message produce two entries, both with the requester.
        let mut two = build_query(9, "one.example", TYPE_A);
        two[5] = 2;
        two.extend_from_slice(&[3, b't', b'w', b'o', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0, 28, 0, 1]);
        let who = Some(Requester { pid: 1, name: "svc".into() });
        log.record(11_000, &parse(&two).unwrap(), r, who.clone(), "udp");
        let mine: Vec<&DnsEntry> = log.iter().take(2).collect();
        assert_eq!((mine[0].name.as_str(), mine[0].qtype, mine[1].name.as_str()), ("two.example", "AAAA", "one.example"));
        assert!(mine.iter().all(|e| e.requester == who));
        assert_eq!(log.queries, 1 + MATCH_WINDOW as u64 + 1 + 1 + 2);
        assert_eq!(log.failures, 0);
    }

    #[test]
    fn encrypted_dns_detection() {
        let sa = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert_eq!(encrypted_dns_kind(L4::Tcp, sa("9.9.9.9:853"), None), Some("DoT"));
        assert_eq!(encrypted_dns_kind(L4::Udp, sa("94.140.14.14:853"), None), Some("DoQ"));
        assert_eq!(encrypted_dns_kind(L4::Tcp, sa("1.1.1.1:443"), None), Some("DoH"));
        assert_eq!(encrypted_dns_kind(L4::Tcp, sa("104.16.248.249:443"), Some("Mozilla.cloudflare-dns.com")), Some("DoH"));
        assert_eq!(encrypted_dns_kind(L4::Tcp, sa("140.82.121.4:443"), Some("github.com")), None);
        assert_eq!(encrypted_dns_kind(L4::Udp, sa("1.1.1.1:53"), None), None);
    }
}
