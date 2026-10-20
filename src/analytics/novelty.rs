//! "First time seen" tracking: a program going online for the first time, contacting a
//! new domain or a new country, or starting to listen on a network port. Everything seen
//! during a short learning period after start is treated as the baseline.

use std::collections::HashSet;
use std::net::SocketAddr;

use super::persist::NoveltyBaseline;

/// Silent baseline after the first observation.
pub const LEARNING_US: i64 = 60_000_000;
const MAX_KEYS: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Novel {
    /// A program used the network for the first time.
    Process { process: String },
    /// A program contacted a domain (or provider) it never contacted before.
    Destination { process: String, destination: String },
    /// A program contacted a country it never contacted before.
    Country { process: String, country: String },
    /// A program listens on a port reachable from outside this machine.
    Listener { process: String, addr: SocketAddr },
}

#[derive(Default)]
pub struct Novelty {
    seen: HashSet<String>,
    learn_until_us: Option<i64>,
    listeners_known: bool,
}

/// `a.b.example.com` -> `example.com` (good enough to group subdomains).
pub fn registrable_domain(name: &str) -> &str {
    let mut dots = name.trim_end_matches('.').rmatch_indices('.');
    match (dots.next(), dots.next()) {
        (Some((last, _)), Some((i, _))) => {
            // Two-letter second level under a country TLD (co.uk, com.au...): keep three labels.
            let sld = &name[i + 1..last];
            if name.len() - last <= 3 && matches!(sld, "co" | "com" | "net" | "org" | "gov" | "ac" | "edu") {
                name[..i].rfind('.').map_or(name, |j| &name[j + 1..])
            } else {
                &name[i + 1..]
            }
        }
        _ => name,
    }
}

impl Novelty {
    fn first(&mut self, key: String) -> bool {
        if self.seen.len() >= MAX_KEYS {
            return false;
        }
        self.seen.insert(key)
    }

    fn learning(&mut self, now_us: i64) -> bool {
        let until = *self.learn_until_us.get_or_insert(now_us + LEARNING_US);
        now_us < until
    }

    /// The baseline for the next run (sorted, so equal tables compare equal).
    pub fn export(&self) -> NoveltyBaseline {
        let mut b = NoveltyBaseline { learn_until_us: self.learn_until_us, listeners_known: self.listeners_known, ..NoveltyBaseline::default() };
        for key in &self.seen {
            let mut parts = key.splitn(3, '\0');
            match (parts.next(), parts.next(), parts.next()) {
                (Some("p"), Some(p), None) => b.processes.push(p.into()),
                (Some("d"), Some(p), Some(d)) => b.destinations.push((p.into(), d.into())),
                (Some("c"), Some(p), Some(c)) => b.countries.push((p.into(), c.into())),
                (Some("l"), Some(p), Some(port)) => {
                    if let Ok(port) = port.parse() {
                        b.listeners.push((p.into(), port));
                    }
                }
                _ => {}
            }
        }
        b.processes.sort_unstable();
        b.destinations.sort_unstable();
        b.countries.sort_unstable();
        b.listeners.sort_unstable();
        b
    }

    /// Seeds the tables from a previous run. The learning deadline is restored as it was:
    /// it is wall-clock time, so unless this is a restart within the first minute of ever
    /// running, learning is over and everything not in the baseline is reported at once.
    /// The table stays bounded by [`MAX_KEYS`]; destinations (the most numerous and least
    /// telling) are imported last, so they are what gets dropped.
    pub fn import(&mut self, b: &NoveltyBaseline) {
        self.learn_until_us = match (self.learn_until_us, b.learn_until_us) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.listeners_known |= b.listeners_known;
        for p in &b.processes {
            self.first(format!("p\0{p}"));
        }
        for (p, c) in &b.countries {
            self.first(format!("c\0{p}\0{c}"));
        }
        for (p, port) in &b.listeners {
            self.first(format!("l\0{p}\0{port}"));
        }
        for (p, d) in &b.destinations {
            self.first(format!("d\0{p}\0{d}"));
        }
    }

    /// Checks one connection of `process`; returns what is new (empty while learning).
    pub fn observe_flow(&mut self, now_us: i64, process: &str, destination: Option<&str>, country: Option<&str>) -> Vec<Novel> {
        let learning = self.learning(now_us);
        let mut out = Vec::new();
        if self.first(format!("p\0{process}")) {
            out.push(Novel::Process { process: process.into() });
        }
        if let Some(d) = destination {
            let d = registrable_domain(d).to_ascii_lowercase();
            if self.first(format!("d\0{process}\0{d}")) {
                out.push(Novel::Destination { process: process.into(), destination: d });
            }
        }
        if let Some(c) = country {
            if self.first(format!("c\0{process}\0{c}")) {
                out.push(Novel::Country { process: process.into(), country: c.into() });
            }
        }
        if learning {
            out.clear();
        }
        out
    }

    /// Checks the current listening sockets; the first non-empty call only records the
    /// baseline (an empty table says nothing about what is normal on this machine).
    pub fn observe_listeners<'a>(&mut self, listeners: impl Iterator<Item = (&'a str, SocketAddr)>) -> Vec<Novel> {
        let baseline = !self.listeners_known;
        let mut out = Vec::new();
        for (process, addr) in listeners {
            self.listeners_known = true;
            if addr.ip().is_loopback() {
                continue;
            }
            if self.first(format!("l\0{process}\0{}", addr.port())) && !baseline {
                out.push(Novel::Listener { process: process.into(), addr });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains() {
        assert_eq!(registrable_domain("a.b.example.com"), "example.com");
        assert_eq!(registrable_domain("example.com"), "example.com");
        assert_eq!(registrable_domain("www.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(registrable_domain("localhost"), "localhost");
        assert_eq!(registrable_domain("x.y.com.au"), "y.com.au");
    }

    #[test]
    fn learning_period_then_alerts_once() {
        let mut n = Novelty::default();
        assert!(n.observe_flow(0, "chrome.exe", Some("www.google.com"), Some("US")).is_empty(), "learning");
        let t = LEARNING_US + 1;
        assert!(n.observe_flow(t, "chrome.exe", Some("mail.google.com"), Some("US")).is_empty(), "same domain and country");
        let got = n.observe_flow(t, "chrome.exe", Some("example.org"), Some("DE"));
        assert_eq!(got, vec![
            Novel::Destination { process: "chrome.exe".into(), destination: "example.org".into() },
            Novel::Country { process: "chrome.exe".into(), country: "DE".into() },
        ]);
        let got = n.observe_flow(t, "updater.exe", None, None);
        assert_eq!(got, vec![Novel::Process { process: "updater.exe".into() }]);
        assert!(n.observe_flow(t, "updater.exe", None, None).is_empty(), "only once");
    }

    #[test]
    fn learning_window_ends_exactly_after_sixty_seconds() {
        let mut n = Novelty::default();
        let t0 = 1_000;
        assert!(n.observe_flow(t0, "a.exe", None, None).is_empty(), "the first observation opens the window");
        assert!(n.observe_flow(t0 + LEARNING_US - 1, "b.exe", Some("x.example"), Some("DE")).is_empty(), "last microsecond inside");
        let got = n.observe_flow(t0 + LEARNING_US, "c.exe", Some("z.example"), Some("FR"));
        assert_eq!(got.len(), 3, "exactly 60 s after the first observation everything new alerts: {got:?}");
        assert_eq!(got[0], Novel::Process { process: "c.exe".into() });
        // What was seen during learning stays known, including other subdomains of the same domain.
        assert!(n.observe_flow(t0 + LEARNING_US, "b.exe", Some("www.x.example"), Some("DE")).is_empty());
        // Destinations are compared case-insensitively on their registrable domain.
        let got = n.observe_flow(t0 + LEARNING_US + 1, "c.exe", Some("WWW.Example.ORG."), None);
        assert_eq!(got, vec![Novel::Destination { process: "c.exe".into(), destination: "example.org.".into() }]);
        // A timestamp before the window's end (a late packet) is still "learning", and the window never moves.
        assert!(n.observe_flow(0, "d.exe", None, None).is_empty());
        assert!(n.observe_flow(t0 + LEARNING_US, "d.exe", None, None).is_empty(), "d.exe was recorded while learning");
        assert_eq!(n.observe_flow(t0 + 10 * LEARNING_US, "e.exe", None, None).len(), 1);
    }

    #[test]
    fn export_import_resumes_without_a_learning_period() {
        let mut n = Novelty::default();
        let t0 = 1_000;
        n.observe_flow(t0, "chrome.exe", Some("www.google.com"), Some("US"));
        n.observe_flow(t0, "chrome.exe", Some("GitHub.com"), None);
        let pub80: SocketAddr = "0.0.0.0:80".parse().unwrap();
        n.observe_listeners([("nginx.exe", pub80), ("node.exe", "127.0.0.1:3000".parse().unwrap())].into_iter());
        let b = n.export();
        assert_eq!(b, NoveltyBaseline {
            learn_until_us: Some(t0 + LEARNING_US),
            listeners_known: true,
            processes: vec!["chrome.exe".into()],
            destinations: vec![("chrome.exe".into(), "github.com".into()), ("chrome.exe".into(), "google.com".into())],
            countries: vec![("chrome.exe".into(), "US".into())],
            listeners: vec![("nginx.exe".into(), 80)],
        });
        // The "next run": far past the deadline, as any real restart is.
        let mut m = Novelty::default();
        m.import(&b);
        let t = t0 + 10 * LEARNING_US;
        assert!(m.observe_flow(t, "chrome.exe", Some("mail.google.com"), Some("US")).is_empty(), "known before the restart");
        assert_eq!(m.observe_flow(t, "updater.exe", None, None), vec![Novel::Process { process: "updater.exe".into() }], "new: reported at once");
        assert_eq!(m.observe_flow(t, "chrome.exe", Some("example.org"), Some("DE")).len(), 2);
        assert!(m.observe_listeners([("nginx.exe", pub80)].into_iter()).is_empty(), "the listener baseline is known too");
        assert_eq!(m.observe_listeners([("other.exe", pub80)].into_iter()).len(), 1, "no second baseline pass");
        assert_eq!(m.export(), m.export(), "deterministic");
        assert!(m.export().processes.contains(&"updater.exe".to_string()));
        // An empty baseline (nothing ever seen) changes nothing: the fresh run learns.
        let mut e = Novelty::default();
        e.import(&NoveltyBaseline::default());
        assert!(e.observe_flow(0, "a.exe", None, None).is_empty());
        assert_eq!(e.observe_listeners([("x", pub80)].into_iter()).len(), 0, "first table is still the baseline");
    }

    #[test]
    fn import_respects_the_key_bound_dropping_destinations_first() {
        let mut b = NoveltyBaseline { learn_until_us: Some(0), ..NoveltyBaseline::default() };
        for i in 0..MAX_KEYS {
            b.destinations.push(("p".into(), format!("d{i}.example")));
        }
        b.processes.push("p".into());
        b.countries.push(("p".into(), "DE".into()));
        let mut n = Novelty::default();
        n.import(&b);
        assert_eq!(n.seen.len(), MAX_KEYS);
        let e = n.export();
        assert_eq!((e.processes.len(), e.countries.len(), e.destinations.len()), (1, 1, MAX_KEYS - 2));
    }

    #[test]
    fn key_table_is_bounded() {
        let mut n = Novelty::default();
        let t = LEARNING_US * 2;
        n.observe_flow(0, "start", None, None);
        for i in 0..MAX_KEYS - 1 {
            n.observe_flow(t, &format!("p{i}"), None, None);
        }
        assert_eq!(n.seen.len(), MAX_KEYS);
        assert!(n.observe_flow(t, "one-more.exe", Some("new.example"), Some("ZZ")).is_empty(), "full table: nothing is reported as new");
        assert_eq!(n.seen.len(), MAX_KEYS);
        assert!(n.observe_listeners([("x", "0.0.0.0:1".parse().unwrap())].into_iter()).is_empty());
    }

    #[test]
    fn loopback_only_tables_still_set_the_baseline_and_ports_are_per_process() {
        let mut n = Novelty::default();
        let lo: SocketAddr = "127.0.0.1:9229".parse().unwrap();
        let pub80: SocketAddr = "0.0.0.0:80".parse().unwrap();
        let pub6: SocketAddr = "[::]:80".parse().unwrap();
        assert!(n.observe_listeners([("node.exe", lo)].into_iter()).is_empty());
        let got = n.observe_listeners([("node.exe", lo), ("nginx.exe", pub80)].into_iter());
        assert_eq!(got, vec![Novel::Listener { process: "nginx.exe".into(), addr: pub80 }], "a loopback-only table was the baseline");
        assert!(n.observe_listeners([("nginx.exe", pub6)].into_iter()).is_empty(), "same process and port on IPv6 is not news");
        let got = n.observe_listeners([("other.exe", pub80)].into_iter());
        assert_eq!(got.len(), 1, "another program on a known port is");
        assert!(n.observe_listeners([("x", "[::1]:80".parse().unwrap())].into_iter()).is_empty(), "IPv6 loopback is skipped too");
    }

    #[test]
    fn listeners_after_baseline() {
        let mut n = Novelty::default();
        let a: SocketAddr = "0.0.0.0:445".parse().unwrap();
        assert!(n.observe_listeners(std::iter::empty()).is_empty());
        assert!(n.observe_listeners([("System", a)].into_iter()).is_empty(), "an empty table was not the baseline; this is");
        let b: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let lo: SocketAddr = "127.0.0.1:9229".parse().unwrap();
        let got = n.observe_listeners([("System", a), ("node.exe", b), ("Code.exe", lo)].into_iter());
        assert_eq!(got, vec![Novel::Listener { process: "node.exe".into(), addr: b }]);
    }
}
