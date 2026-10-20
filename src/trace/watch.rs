//! Watched routes: chosen hosts are traced periodically; a change of the path
//! (other providers/countries on the way) or a marked latency increase raises an alert.

use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::Serialize;

use super::{trace, Trace};
use crate::analytics::SharedState;
use crate::capture::engine::unix_now;

pub const DEFAULT_INTERVAL_SECS: i64 = 600;
const HISTORY: usize = 48;
/// Watched hosts at most; each trace costs dozens of probe threads every interval.
pub const MAX_TARGETS: usize = 32;
pub const MAX_LABEL_CHARS: usize = 64;
/// Traces started per watcher pass, so one pass stays short and `stop` is noticed.
const MAX_PER_PASS: usize = 4;

/// One trace reduced to what is compared between runs.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RouteSample {
    pub ts: i64,
    pub reached: bool,
    pub hops: usize,
    /// Best round trip to the last answering hop.
    pub rtt_ms: Option<f64>,
    /// Networks crossed, e.g. `AS198178 DE` (consecutive duplicates merged).
    pub path: Vec<String>,
    /// The path differs from the previous sample.
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RouteEvent {
    Changed { before: Vec<String>, after: Vec<String> },
    Slower { before_ms: f64, after_ms: f64 },
}

#[derive(Debug, Clone)]
pub struct WatchTarget {
    pub label: Option<String>,
    pub added_at: i64,
    pub next_run: i64,
    pub history: VecDeque<RouteSample>,
    pub last: Option<Arc<Trace>>,
    pub running: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct WatchView {
    pub ip: String,
    pub label: Option<String>,
    pub added_at: i64,
    pub next_run: i64,
    pub running: bool,
    pub history: Vec<RouteSample>,
    pub last: Option<Trace>,
}

pub struct RouteWatch {
    targets: BTreeMap<IpAddr, WatchTarget>,
    pub interval_secs: i64,
}

impl Default for RouteWatch {
    fn default() -> Self {
        Self { targets: BTreeMap::new(), interval_secs: DEFAULT_INTERVAL_SECS }
    }
}

/// Reduces a trace to its comparable shape.
pub fn summarize(t: &Trace, ts: i64) -> RouteSample {
    let mut path: Vec<String> = Vec::new();
    for h in t.hops.iter().filter(|h| !h.private) {
        let Some(g) = &h.geo else { continue };
        let label = match (g.asn, g.country_code.as_deref()) {
            (Some(a), Some(c)) => format!("AS{a} {c}"),
            (Some(a), None) => format!("AS{a}"),
            (None, Some(c)) => c.to_string(),
            (None, None) => continue,
        };
        if path.last() != Some(&label) {
            path.push(label);
        }
    }
    let rtt_ms = t
        .hops
        .iter()
        .rev()
        .find(|h| h.ip.is_some())
        .and_then(|h| h.rtt_ms.iter().flatten().copied().reduce(f64::min));
    RouteSample { ts, reached: t.reached, hops: t.hops.len(), rtt_ms, path, changed: false }
}

impl RouteWatch {
    /// Adds (or re-labels) a target; `false` when the list is full. Labels are cut to
    /// [`MAX_LABEL_CHARS`] rather than rejected.
    pub fn add(&mut self, ip: IpAddr, label: Option<String>, now: i64) -> bool {
        if !self.targets.contains_key(&ip) && self.targets.len() >= MAX_TARGETS {
            return false;
        }
        let t = self.targets.entry(ip).or_insert(WatchTarget {
            label: None,
            added_at: now,
            next_run: now,
            history: VecDeque::new(),
            last: None,
            running: false,
        });
        if let Some(l) = label {
            t.label = Some(l.chars().take(MAX_LABEL_CHARS).collect());
        }
        t.next_run = t.next_run.min(now);
        true
    }

    pub fn len(&self) -> usize {
        self.targets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    pub fn remove(&mut self, ip: &IpAddr) -> bool {
        self.targets.remove(ip).is_some()
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.targets.contains_key(ip)
    }

    /// Targets and labels only (what is persisted), in address order.
    pub fn entries(&self) -> impl Iterator<Item = (IpAddr, Option<&str>)> + '_ {
        self.targets.iter().map(|(ip, t)| (*ip, t.label.as_deref()))
    }

    /// Up to [`MAX_PER_PASS`] targets whose next run is due, longest overdue first; they are marked running.
    pub fn take_due(&mut self, now: i64) -> Vec<IpAddr> {
        let mut due: Vec<(i64, IpAddr)> = self.targets.iter().filter(|(_, t)| !t.running && t.next_run <= now).map(|(ip, t)| (t.next_run, *ip)).collect();
        due.sort_unstable();
        let due: Vec<IpAddr> = due.into_iter().take(MAX_PER_PASS).map(|(_, ip)| ip).collect();
        for ip in &due {
            if let Some(t) = self.targets.get_mut(ip) {
                t.running = true;
            }
        }
        due
    }

    /// Stores a finished trace and reports what changed compared with the previous one.
    pub fn record(&mut self, ip: IpAddr, t: Trace, now: i64) -> Vec<RouteEvent> {
        let interval = self.interval_secs;
        let Some(target) = self.targets.get_mut(&ip) else { return vec![] };
        target.running = false;
        target.next_run = now + interval;
        let mut sample = summarize(&t, now);
        let mut events = Vec::new();
        if let Some(prev) = target.history.back() {
            // Compare only traces that saw any public network: silent runs say nothing.
            if !prev.path.is_empty() && !sample.path.is_empty() && prev.path != sample.path {
                sample.changed = true;
                events.push(RouteEvent::Changed { before: prev.path.clone(), after: sample.path.clone() });
            }
            if let (Some(a), Some(b)) = (prev.rtt_ms, sample.rtt_ms) {
                if b > a * 1.5 && b - a > 20.0 {
                    events.push(RouteEvent::Slower { before_ms: a, after_ms: b });
                }
            }
        }
        if target.history.len() == HISTORY {
            target.history.pop_front();
        }
        target.history.push_back(sample);
        target.last = Some(Arc::new(t));
        events
    }

    pub fn view(&self) -> Vec<WatchView> {
        self.targets
            .iter()
            .map(|(ip, t)| WatchView {
                ip: ip.to_string(),
                label: t.label.clone(),
                added_at: t.added_at,
                next_run: t.next_run,
                running: t.running,
                history: t.history.iter().rev().cloned().collect(),
                last: t.last.as_deref().cloned(),
            })
            .collect()
    }
}

/// Runs due traces until `stop`.
pub fn spawn_watcher(shared: SharedState, stop: Arc<AtomicBool>) -> std::io::Result<JoinHandle<()>> {
    thread::Builder::new().name("route-watch".into()).spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            let due = shared.write().routes.take_due(unix_now());
            for ip in due {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                let geo = shared.read().geo.clone();
                let t = trace(ip, geo.as_deref());
                shared.write().record_route(ip, t);
            }
            thread::sleep(Duration::from_millis(500));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geo::GeoInfo;
    use crate::trace::Hop;

    fn hop(ttl: u8, asn: Option<u32>, cc: &str, rtt: f64) -> Hop {
        Hop {
            ttl,
            ip: Some(format!("203.0.113.{ttl}")),
            name: None,
            rtt_ms: vec![Some(rtt), None],
            geo: asn.map(|a| GeoInfo { asn: Some(a), country_code: Some(cc.into()), ..GeoInfo::default() }),
            private: false,
        }
    }

    fn tr(hops: Vec<Hop>) -> Trace {
        Trace { target: "203.0.113.9".into(), reached: true, hops, method: "test", duration_ms: 1, error: None }
    }

    #[test]
    fn summary_merges_networks() {
        let s = summarize(&tr(vec![hop(1, Some(1), "DE", 5.0), hop(2, Some(1), "DE", 7.0), hop(3, Some(2), "US", 50.0)]), 10);
        assert_eq!(s.path, vec!["AS1 DE", "AS2 US"]);
        assert_eq!((s.rtt_ms, s.hops, s.reached), (Some(50.0), 3, true));
    }

    #[test]
    fn detects_path_change_and_slowdown() {
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let mut w = RouteWatch::default();
        w.add(ip, Some("example".into()), 0);
        assert_eq!(w.take_due(0), vec![ip]);
        assert!(w.take_due(0).is_empty(), "running targets are not handed out twice");
        assert!(w.record(ip, tr(vec![hop(1, Some(1), "DE", 40.0)]), 0).is_empty(), "first sample is the baseline");
        assert!(w.take_due(1).is_empty(), "not due before the interval");
        let ev = w.record(ip, tr(vec![hop(1, Some(9), "NL", 100.0)]), DEFAULT_INTERVAL_SECS);
        assert_eq!(ev, vec![
            RouteEvent::Changed { before: vec!["AS1 DE".into()], after: vec!["AS9 NL".into()] },
            RouteEvent::Slower { before_ms: 40.0, after_ms: 100.0 },
        ]);
        let v = w.view();
        assert_eq!(v[0].history.len(), 2);
        assert!(v[0].history[0].changed, "newest first");
        assert!(w.remove(&ip) && !w.contains(&ip));
    }

    #[test]
    fn summary_edge_cases() {
        let geo = |asn: Option<u32>, cc: Option<&str>| Some(GeoInfo { asn, country_code: cc.map(String::from), ..GeoInfo::default() });
        let hops = vec![
            Hop { ttl: 1, ip: Some("192.168.1.1".into()), name: None, rtt_ms: vec![Some(1.0)], geo: geo(Some(5), Some("XX")), private: true },
            Hop { ttl: 2, ip: Some("203.0.113.2".into()), name: None, rtt_ms: vec![None, None], geo: None, private: false },
            Hop { ttl: 3, ip: Some("203.0.113.3".into()), name: None, rtt_ms: vec![Some(30.0)], geo: geo(None, None), private: false },
            Hop { ttl: 4, ip: Some("203.0.113.4".into()), name: None, rtt_ms: vec![Some(40.0)], geo: geo(Some(7), None), private: false },
            Hop { ttl: 5, ip: Some("203.0.113.5".into()), name: None, rtt_ms: vec![Some(50.0)], geo: geo(None, Some("NL")), private: false },
            Hop { ttl: 6, ip: Some("203.0.113.6".into()), name: None, rtt_ms: vec![Some(60.0)], geo: geo(None, Some("NL")), private: false },
            Hop { ttl: 7, ip: Some("203.0.113.7".into()), name: None, rtt_ms: vec![Some(90.0), Some(70.0), None], geo: geo(Some(9), Some("NL")), private: false },
            Hop { ttl: 8, ip: None, name: None, rtt_ms: vec![None, None], geo: None, private: false },
        ];
        let s = summarize(&Trace { target: "203.0.113.9".into(), reached: false, hops, method: "test", duration_ms: 0, error: None }, 42);
        assert_eq!(s.path, vec!["AS7", "NL", "AS9 NL"], "private hops and hops without ASN/country are skipped, duplicates merged");
        assert_eq!((s.rtt_ms, s.hops, s.reached, s.ts, s.changed), (Some(70.0), 8, false, 42, false), "best RTT of the last answering hop");
        let silent = summarize(&tr(vec![Hop { ttl: 1, ip: Some("203.0.113.1".into()), name: None, rtt_ms: vec![None], geo: None, private: false }]), 0);
        assert_eq!((silent.rtt_ms, silent.path.is_empty()), (None, true));
        let empty = summarize(&tr(vec![]), 0);
        assert_eq!((empty.hops, empty.rtt_ms, empty.path.len()), (0, None, 0));
    }

    #[test]
    fn record_thresholds_history_and_rescheduling() {
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let other: IpAddr = "203.0.113.10".parse().unwrap();
        let mut w = RouteWatch { interval_secs: 5, ..RouteWatch::default() };
        assert!(w.record(other, tr(vec![hop(1, Some(1), "DE", 1.0)]), 0).is_empty(), "unknown target: nothing recorded");
        assert!(w.add(ip, None, 100));
        assert_eq!(w.take_due(100), vec![ip]);
        assert!(w.record(ip, tr(vec![hop(1, Some(1), "DE", 100.0)]), 100).is_empty());
        let v = &w.view()[0];
        assert_eq!((v.next_run, v.running, v.history.len(), v.last.is_some(), v.label.is_none()), (105, false, 1, true, true));
        assert!(w.take_due(104).is_empty() && w.take_due(105) == vec![ip], "due again after the interval");
        // Slower needs both +50% and +20 ms; a path change needs two non-empty paths.
        assert!(w.record(ip, tr(vec![hop(1, Some(1), "DE", 140.0)]), 105).is_empty(), "+40%");
        w.take_due(200);
        assert!(w.record(ip, tr(vec![hop(1, Some(1), "DE", 10.0)]), 200).is_empty(), "faster is never an event");
        w.take_due(300);
        assert!(w.record(ip, tr(vec![hop(1, Some(1), "DE", 25.0)]), 300).is_empty(), "+150% but only 15 ms");
        w.take_due(400);
        assert_eq!(w.record(ip, tr(vec![hop(1, Some(1), "DE", 160.0)]), 400), vec![RouteEvent::Slower { before_ms: 25.0, after_ms: 160.0 }]);
        w.take_due(500);
        assert!(w.record(ip, tr(vec![]), 500).is_empty(), "a silent run says nothing about the path");
        w.take_due(600);
        assert!(w.record(ip, tr(vec![hop(1, Some(1), "DE", 160.0)]), 600).is_empty(), "same path as before the silent run? no: compared with the silent sample only");
        w.take_due(700);
        let ev = w.record(ip, tr(vec![hop(1, Some(2), "DE", 160.0)]), 700);
        assert_eq!(ev, vec![RouteEvent::Changed { before: vec!["AS1 DE".into()], after: vec!["AS2 DE".into()] }]);
        // History is bounded; re-adding a target makes it due immediately but keeps its history.
        for i in 0..(HISTORY as i64 + 10) {
            w.take_due(1_000 + i * 10);
            w.record(ip, tr(vec![hop(1, Some(2), "DE", 1.0)]), 1_000 + i * 10);
        }
        assert_eq!(w.view()[0].history.len(), HISTORY);
        let next = w.view()[0].next_run;
        assert!(w.add(ip, Some("again".into()), next - 3));
        let v = &w.view()[0];
        assert_eq!((v.next_run, v.label.as_deref(), v.history.len()), (next - 3, Some("again"), HISTORY));
        assert_eq!(w.take_due(next - 3), vec![ip]);
        assert!(w.add(ip, None, 0), "no label keeps the old one");
        assert_eq!(w.view()[0].label.as_deref(), Some("again"));
        assert!(w.view()[0].running, "re-adding does not clear the running flag");
    }

    #[test]
    fn limits_targets_labels_and_work_per_pass() {
        let mut w = RouteWatch::default();
        let ip = |i: usize| -> IpAddr { format!("203.0.113.{i}").parse().unwrap() };
        for i in 0..MAX_TARGETS {
            assert!(w.add(ip(i), None, i as i64), "target {i}");
        }
        assert!(!w.add(ip(200), None, 0), "full");
        assert!(w.add(ip(3), Some("x".repeat(100)), 3), "re-labelling an existing target is fine when full");
        assert_eq!(w.view().iter().find(|v| v.ip == "203.0.113.3").unwrap().label.as_ref().unwrap().chars().count(), MAX_LABEL_CHARS);
        assert_eq!(w.len(), MAX_TARGETS);
        // Oldest due first, four per pass, nothing twice.
        let mut all = w.take_due(1_000);
        assert_eq!(all, vec![ip(0), ip(1), ip(2), ip(3)]);
        loop {
            let more = w.take_due(1_000);
            if more.is_empty() {
                break;
            }
            assert_eq!(more.len(), MAX_PER_PASS);
            all.extend(more);
        }
        assert_eq!(all.len(), MAX_TARGETS);
        all.sort();
        all.dedup();
        assert_eq!(all.len(), MAX_TARGETS, "every target handed out exactly once");
    }
}
