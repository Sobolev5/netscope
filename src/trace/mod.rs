//! Route tracing: which routers a packet passes on its way to a host.
//!
//! Probes are sent with TTL 1, 2, 3...; every router that drops a probe because its
//! TTL hit zero answers with ICMP "time exceeded" from its own address.
//! * Windows: `IcmpSendEcho` (no administrator rights needed), all TTLs in parallel
//! * Linux/macOS: the system `traceroute`, parsed
//!
//! Routers that do not answer show up as hops without an address, like `* * *`.

pub mod watch;
#[cfg(windows)]
mod windows;

use std::net::IpAddr;
use std::time::Instant;

use serde::Serialize;

use crate::geo::{GeoDb, GeoInfo};

pub const MAX_HOPS: u8 = 30;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Hop {
    pub ttl: u8,
    pub ip: Option<String>,
    pub name: Option<String>,
    /// Round-trip time of each probe in milliseconds; `None` = no answer.
    pub rtt_ms: Vec<Option<f64>>,
    pub geo: Option<GeoInfo>,
    /// Private/LAN address (home router, corporate network, VPN internals).
    pub private: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Trace {
    pub target: String,
    pub hops: Vec<Hop>,
    pub reached: bool,
    /// How the probes were sent: `icmp` (Windows IcmpSendEcho) or `traceroute` (system tool).
    pub method: &'static str,
    pub duration_ms: u64,
    /// Short English text when the trace could not run at all.
    pub error: Option<String>,
}

/// Raw result of a platform tracer, before names and geolocation.
pub(crate) struct RawHop {
    pub ttl: u8,
    pub ip: Option<IpAddr>,
    pub name: Option<String>,
    pub rtt_ms: Vec<Option<f64>>,
}

pub fn trace(target: IpAddr, geo: Option<&GeoDb>) -> Trace {
    let started = Instant::now();
    let (method, result) = run(target);
    let mut t = Trace {
        target: target.to_string(),
        hops: vec![],
        reached: false,
        method,
        duration_ms: 0,
        error: None,
    };
    match result {
        Ok(raw) => {
            t.reached = raw.iter().any(|h| h.ip == Some(target));
            t.hops = raw
                .into_iter()
                .map(|h| Hop {
                    ttl: h.ttl,
                    private: h.ip.is_some_and(|ip| crate::analytics::addr::is_local_scope(&ip)),
                    geo: h.ip.and_then(|ip| geo.and_then(|g| g.lookup(ip))),
                    name: h.name,
                    ip: h.ip.map(|ip| ip.to_string()),
                    rtt_ms: h.rtt_ms,
                })
                .collect();
        }
        Err(e) => t.error = Some(e),
    }
    t.duration_ms = started.elapsed().as_millis() as u64;
    t
}

#[cfg(windows)]
fn run(target: IpAddr) -> (&'static str, Result<Vec<RawHop>, String>) {
    ("icmp", windows::trace(target))
}

#[cfg(not(windows))]
fn run(target: IpAddr) -> (&'static str, Result<Vec<RawHop>, String>) {
    let out = std::process::Command::new("traceroute")
        .args(["-q", "2", "-w", "1", "-m", &MAX_HOPS.to_string(), &target.to_string()])
        .output();
    let result = match out {
        Ok(o) if o.status.success() || !o.stdout.is_empty() => Ok(parse_traceroute(&String::from_utf8_lossy(&o.stdout))),
        Ok(o) => Err(format!("traceroute failed: {}", String::from_utf8_lossy(&o.stderr).trim())),
        Err(e) => Err(format!("traceroute not available ({e})")),
    };
    ("traceroute", result)
}

/// Parses `traceroute` output (Linux and BSD/macOS formats, with or without names):
/// ` 3  router.example.net (10.0.0.1)  1.234 ms  1.100 ms`, ` 4  * *`, ` 5  10.0.0.9  2.0 ms *`.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn parse_traceroute(text: &str) -> Vec<RawHop> {
    let mut hops: Vec<RawHop> = Vec::new();
    for line in text.lines() {
        let mut tok = line.split_whitespace().peekable();
        let Some(ttl) = tok.peek().and_then(|t| t.parse::<u8>().ok()) else { continue };
        tok.next();
        let mut hop = RawHop { ttl, ip: None, name: None, rtt_ms: vec![] };
        let words: Vec<&str> = tok.collect();
        let mut i = 0;
        while i < words.len() {
            let w = words[i];
            if w == "*" {
                hop.rtt_ms.push(None);
            } else if words.get(i + 1) == Some(&"ms") {
                hop.rtt_ms.push(w.parse().ok());
                i += 1;
            } else if let Ok(ip) = w.trim_start_matches('(').trim_end_matches(')').parse::<IpAddr>() {
                if hop.ip.is_none() {
                    hop.ip = Some(ip);
                }
            } else if hop.ip.is_none() && hop.name.is_none() && !w.starts_with('!') {
                hop.name = Some(w.to_string());
            }
            i += 1;
        }
        if hop.name.as_deref() == hop.ip.map(|ip| ip.to_string()).as_deref() {
            hop.name = None;
        }
        hops.push(hop);
    }
    hops
}

/// Cuts everything after the first hop that is the target itself.
pub(crate) fn truncate_at_target(hops: &mut Vec<RawHop>, target: IpAddr) {
    if let Some(i) = hops.iter().position(|h| h.ip == Some(target)) {
        hops.truncate(i + 1);
    } else {
        // Drop the trailing run of silent hops: they carry no information.
        while hops.len() > 1 && hops.last().is_some_and(|h| h.ip.is_none()) {
            hops.pop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_and_macos_output() {
        let out = "traceroute to 1.1.1.1 (1.1.1.1), 30 hops max, 60 byte packets
 1  _gateway (192.168.1.1)  0.512 ms  0.400 ms
 2  * *
 3  10.20.0.1  3.100 ms *
 4  one.one.one.one (1.1.1.1)  9.8 ms  9.7 ms
";
        let h = parse_traceroute(out);
        assert_eq!(h.len(), 4);
        assert_eq!((h[0].ttl, h[0].ip, h[0].name.as_deref()), (1, Some("192.168.1.1".parse().unwrap()), Some("_gateway")));
        assert_eq!(h[0].rtt_ms, vec![Some(0.512), Some(0.4)]);
        assert_eq!((h[1].ip, h[1].rtt_ms.len()), (None, 2));
        assert_eq!((h[2].name.as_deref(), h[2].rtt_ms.clone()), (None, vec![Some(3.1), None]));
        assert_eq!(h[3].name.as_deref(), Some("one.one.one.one"));
    }

    #[test]
    fn truncation() {
        let mk = |ttl, ip: Option<&str>| RawHop { ttl, ip: ip.map(|s| s.parse().unwrap()), name: None, rtt_ms: vec![] };
        let target: IpAddr = "1.1.1.1".parse().unwrap();
        let mut a = vec![mk(1, Some("10.0.0.1")), mk(2, Some("1.1.1.1")), mk(3, Some("1.1.1.1"))];
        truncate_at_target(&mut a, target);
        assert_eq!(a.len(), 2);
        let mut b = vec![mk(1, Some("10.0.0.1")), mk(2, None), mk(3, Some("9.9.9.9")), mk(4, None), mk(5, None)];
        truncate_at_target(&mut b, target);
        assert_eq!(b.len(), 3);
    }

    #[test]
    fn traces_loopback() {
        // Works without network access: the target answers at hop 1.
        let t = trace("127.0.0.1".parse().unwrap(), None);
        assert!(t.error.is_none(), "{:?}", t.error);
        assert!(t.reached, "{t:?}");
        assert_eq!(t.hops.last().unwrap().ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(t.method, if cfg!(windows) { "icmp" } else { "traceroute" }, "machine code, not prose");
    }

    #[cfg(windows)]
    #[test]
    fn ipv6_is_a_short_error() {
        let t = trace("::1".parse().unwrap(), None);
        let e = t.error.unwrap();
        assert!(e.len() < 60 && e.contains("IPv6"), "{e}");
        assert!(t.hops.is_empty() && !t.reached && t.method == "icmp");
    }
}
