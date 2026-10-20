//! `/metrics`: the state as Prometheus text exposition (version 0.0.4).

use std::collections::HashMap;
use std::fmt::Write;

use crate::analytics::flows::FlowState;
use crate::analytics::journal::Kind;
use crate::analytics::{CaptureStatus, State};

pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";
/// Processes with their own series, by traffic.
const TOP_PROCESSES: usize = 50;

/// A label value per the exposition format: backslash, double quote and newline escaped.
pub fn escape_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

struct Exposition {
    out: String,
}

impl Exposition {
    fn head(&mut self, name: &str, kind: &str, help: &str) {
        let _ = writeln!(self.out, "# HELP {name} {help}\n# TYPE {name} {kind}");
    }

    fn sample(&mut self, name: &str, labels: &[(&str, &str)], value: impl std::fmt::Display) {
        self.out.push_str(name);
        if !labels.is_empty() {
            self.out.push('{');
            for (i, (k, v)) in labels.iter().enumerate() {
                if i > 0 {
                    self.out.push(',');
                }
                let _ = write!(self.out, "{k}=\"{}\"", escape_label(v));
            }
            self.out.push('}');
        }
        let _ = writeln!(self.out, " {value}");
    }
}

/// Renders every metric from one read of the state (no sorting of hosts, no snapshots).
pub fn render(st: &State) -> String {
    let mut e = Exposition { out: String::with_capacity(8 * 1024) };
    e.head("netscope_build_info", "gauge", "Build information.");
    e.sample("netscope_build_info", &[("version", env!("CARGO_PKG_VERSION"))], 1);
    e.head("netscope_up", "gauge", "1 while the capture is running.");
    e.sample("netscope_up", &[], u8::from(st.capture.status == CaptureStatus::Running));
    e.head("netscope_uptime_seconds", "gauge", "Seconds since the first packet.");
    e.sample("netscope_uptime_seconds", &[], st.uptime_secs());

    let t = st.totals();
    e.head("netscope_bytes_total", "counter", "Bytes on the wire by direction.");
    e.sample("netscope_bytes_total", &[("direction", "in")], t.bytes_in);
    e.sample("netscope_bytes_total", &[("direction", "out")], t.bytes_out);
    e.head("netscope_packets_total", "counter", "Packets by direction.");
    e.sample("netscope_packets_total", &[("direction", "in")], t.packets_in);
    e.sample("netscope_packets_total", &[("direction", "out")], t.packets_out);
    let r = st.rates();
    e.head("netscope_rate_bytes_per_second", "gauge", "Throughput of the last complete second.");
    e.sample("netscope_rate_bytes_per_second", &[("direction", "in")], r.bytes_in);
    e.sample("netscope_rate_bytes_per_second", &[("direction", "out")], r.bytes_out);

    let (mut active, mut closed) = (0u64, 0u64);
    for f in st.flows() {
        if f.state == FlowState::Closed {
            closed += 1;
        } else {
            active += 1;
        }
    }
    e.head("netscope_connections", "gauge", "Connections in memory by state.");
    e.sample("netscope_connections", &[("state", "active")], active);
    e.sample("netscope_connections", &[("state", "closed")], closed);
    e.sample("netscope_connections", &[("state", "total")], active + closed);
    e.head("netscope_hosts", "gauge", "Remote hosts in memory.");
    e.sample("netscope_hosts", &[], st.host_count());

    let a = st.alert_counts();
    e.head("netscope_alerts_total", "counter", "Alerts raised by severity.");
    e.sample("netscope_alerts_total", &[("severity", "low")], a.low);
    e.sample("netscope_alerts_total", &[("severity", "medium")], a.medium);
    e.sample("netscope_alerts_total", &[("severity", "high")], a.high);
    let (queries, failures) = st.dns_counts();
    e.head("netscope_dns_queries_total", "counter", "DNS queries seen.");
    e.sample("netscope_dns_queries_total", &[], queries);
    e.head("netscope_dns_failures_total", "counter", "DNS answers with an error code.");
    e.sample("netscope_dns_failures_total", &[], failures);

    // Several PIDs of one program are one series (label sets must be unique).
    let mut by_name: HashMap<&str, (u64, u64)> = HashMap::new();
    for (p, s) in st.process_stats() {
        let v = by_name.entry(p.name.as_str()).or_default();
        v.0 += s.bytes_in;
        v.1 += s.bytes_out;
    }
    let mut procs: Vec<(&str, (u64, u64))> = by_name.into_iter().collect();
    procs.sort_unstable_by(|a, b| (b.1 .0 + b.1 .1).cmp(&(a.1 .0 + a.1 .1)).then(a.0.cmp(b.0)));
    procs.truncate(TOP_PROCESSES);
    e.head("netscope_process_bytes_total", "counter", "Bytes per program (top 50 by traffic) and direction.");
    for (name, (bytes_in, bytes_out)) in procs {
        e.sample("netscope_process_bytes_total", &[("process", name), ("direction", "in")], bytes_in);
        e.sample("netscope_process_bytes_total", &[("process", name), ("direction", "out")], bytes_out);
    }
    e.head("netscope_country_bytes_total", "counter", "Bytes exchanged with hosts per country (hosts in memory).");
    for (code, bytes) in st.country_bytes() {
        e.sample("netscope_country_bytes_total", &[("country_code", &code)], bytes);
    }

    e.head("netscope_journal_records_total", "counter", "Journal records written to disk since the start.");
    for kind in Kind::ALL {
        e.sample("netscope_journal_records_total", &[("kind", kind.as_str())], st.journal().map_or(0, |j| j.written(kind)));
    }
    e.head("netscope_journal_pending", "gauge", "Journal records queued, not yet written.");
    e.sample("netscope_journal_pending", &[], st.journal().map_or(0, |j| j.pending()));
    e.out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_escaping() {
        assert_eq!(escape_label("plain"), "plain");
        assert_eq!(escape_label("say \"hi\""), "say \\\"hi\\\"");
        assert_eq!(escape_label("C:\\x\n"), "C:\\\\x\\n");
    }

    #[test]
    fn empty_state_renders_every_family() {
        use crate::analytics::{CaptureInfo, Config};
        let info = CaptureInfo { mode: "file", source: "x".into(), description: None, filter: None, libpcap: None, status: CaptureStatus::Finished };
        let st = State::new(Config::default(), Default::default(), info);
        let text = render(&st);
        for name in [
            "netscope_build_info", "netscope_up", "netscope_uptime_seconds", "netscope_bytes_total", "netscope_packets_total",
            "netscope_rate_bytes_per_second", "netscope_connections", "netscope_hosts", "netscope_alerts_total", "netscope_dns_queries_total",
            "netscope_dns_failures_total", "netscope_process_bytes_total", "netscope_country_bytes_total", "netscope_journal_records_total",
            "netscope_journal_pending",
        ] {
            assert!(text.contains(&format!("# TYPE {name} ")), "{name} missing in:\n{text}");
        }
        assert!(text.contains("netscope_up 0\n"));
        assert!(text.contains("netscope_connections{state=\"total\"} 0\n"));
        assert!(text.contains("netscope_journal_records_total{kind=\"dns\"} 0\n"));
        assert!(text.ends_with('\n'));
    }
}
