//! CSV and pcap exports of what the dashboard shows.

use crate::analytics::filter::Filter;
use crate::analytics::journal::Kind;
use crate::analytics::views::DnsFilter;
use crate::analytics::{SharedState, State};
use crate::capture::file::PcapWriter;

/// Byte-order mark so spreadsheet programs read the file as UTF-8.
const BOM: &str = "\u{feff}";

/// Quotes a CSV field when needed (RFC 4180). Cells starting like a formula get a
/// leading apostrophe: names and paths come from the network/OS and could otherwise run
/// as formulas when the export is opened in a spreadsheet.
pub fn csv_field(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) { format!("'{s}") } else { s.to_string() };
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

fn csv(header: &[&str], rows: impl Iterator<Item = Vec<String>>) -> String {
    let mut out = String::from(BOM);
    out.push_str(&header.join(","));
    out.push_str("\r\n");
    for r in rows {
        out.push_str(&r.iter().map(|f| csv_field(f)).collect::<Vec<_>>().join(","));
        out.push_str("\r\n");
    }
    out
}

/// `2026-10-17 04:14:49` (UTC) from unix microseconds.
pub fn utc(us: i64) -> String {
    let secs = us.div_euclid(1_000_000);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", rem / 3600, rem / 60 % 60, rem % 60)
}

fn opt<T: ToString>(v: Option<T>) -> String {
    v.map(|x| x.to_string()).unwrap_or_default()
}

pub fn connections_csv(st: &State, pid: Option<u32>, filter: Option<&Filter>) -> String {
    let (_, list) = st.connections(pid, filter, usize::MAX);
    csv(
        &[
            "id", "first_seen_utc", "last_seen_utc", "process", "pid", "path", "app", "transport", "local", "remote", "name",
            "country", "city", "provider", "asn", "state", "direction", "bytes_in", "bytes_out", "packets", "rtt_ms",
            "retransmissions", "hops", "tls", "alpn", "ja4", "encrypted_dns",
        ],
        list.into_iter().map(|c| {
            let g = c.geo.as_ref();
            vec![
                c.id.to_string(),
                utc(c.first_us),
                utc(c.last_us),
                opt(c.process.as_ref().map(|p| p.name.clone())),
                opt(c.process.as_ref().map(|p| p.pid)),
                opt(c.process.as_ref().and_then(|p| p.path.clone())),
                c.app.to_string(),
                format!("{:?}", c.l4).to_lowercase(),
                c.local,
                c.remote,
                opt(c.name),
                opt(g.and_then(|g| g.country_code.clone())),
                opt(g.and_then(|g| g.city.clone())),
                opt(g.and_then(|g| g.org.clone())),
                opt(g.and_then(|g| g.asn)),
                format!("{:?}", c.state).to_lowercase(),
                match c.initiated {
                    Some("local") => "out".into(),
                    Some(_) => "in".into(),
                    None => String::new(),
                },
                c.bytes_in.to_string(),
                c.bytes_out.to_string(),
                (c.packets_in + c.packets_out).to_string(),
                opt(c.rtt_ms.map(|r| format!("{r:.1}"))),
                (c.retrans_in + c.retrans_out).to_string(),
                opt(c.hops),
                opt(c.tls.as_ref().map(|t| t.version)),
                c.tls.as_ref().map(|t| t.alpn.join(" ")).unwrap_or_default(),
                opt(c.tls.as_ref().map(|t| t.ja4.clone())),
                opt(c.encrypted_dns),
            ]
        }),
    )
}

pub fn hosts_csv(st: &State) -> String {
    let snap = st.snapshot(usize::MAX, 0);
    csv(
        &["ip", "name", "name_source", "scope", "country", "city", "provider", "asn", "anycast", "hops", "rtt_ms", "bytes_in", "bytes_out", "packets", "protocols", "ports", "first_seen_utc", "last_seen_utc"],
        snap.hosts.into_iter().map(|h| {
            let g = h.geo.as_ref();
            vec![
                h.ip,
                opt(h.name),
                opt(h.name_source.map(|s| format!("{s:?}").to_lowercase())),
                h.scope.to_string(),
                opt(g.and_then(|g| g.country_code.clone())),
                opt(g.and_then(|g| g.city.clone())),
                opt(g.and_then(|g| g.org.clone())),
                opt(g.and_then(|g| g.asn)),
                g.is_some_and(|g| g.anycast).to_string(),
                opt(h.hops),
                opt(h.rtt_ms.map(|r| format!("{r:.1}"))),
                h.bytes_in.to_string(),
                h.bytes_out.to_string(),
                h.packets.to_string(),
                h.protocols.join(" "),
                h.ports.iter().map(u16::to_string).collect::<Vec<_>>().join(" "),
                utc(h.first_seen * 1_000_000),
                utc(h.last_seen * 1_000_000),
            ]
        }),
    )
}

pub fn processes_csv(st: &State) -> String {
    csv(
        &["pid", "name", "path", "parent_pid", "parent", "signature", "signer", "suspicious_path", "bytes_in", "bytes_out", "packets", "connections", "protocols", "top_destinations", "ja4"],
        st.processes().processes.into_iter().map(|p| {
            vec![
                p.pid.to_string(),
                p.name,
                opt(p.path),
                opt(p.parent),
                opt(p.parent_name),
                opt(p.signature.as_ref().map(|s| format!("{:?}", s.status).to_lowercase())),
                opt(p.signature.and_then(|s| s.signer)),
                p.suspicious_path.to_string(),
                p.bytes_in.to_string(),
                p.bytes_out.to_string(),
                p.packets.to_string(),
                p.connections_total.to_string(),
                p.protocols.join(" "),
                p.top_remotes.join(" "),
                p.ja4.join(" "),
            ]
        }),
    )
}

pub fn dns_csv(st: &State, filter: &DnsFilter) -> String {
    let v = st.dns_filtered(filter, usize::MAX);
    csv(
        &["time_utc", "name", "type", "result", "answers", "latency_ms", "requester", "resolver", "transport", "used_by"],
        v.entries.into_iter().map(|e| {
            vec![
                utc(e.entry.ts_us),
                e.entry.name,
                e.entry.qtype.to_string(),
                opt(e.entry.rcode),
                e.entry.answers.join(" "),
                opt(e.entry.latency_ms.map(|l| format!("{l:.1}"))),
                opt(e.entry.requester.map(|r| r.name)),
                e.entry.resolver,
                e.entry.transport.to_string(),
                e.used_by.join(" "),
            ]
        }),
    )
}

/// Columns of a journal CSV: dotted paths into the record (`time_utc` is derived from `ts`).
pub fn journal_columns(kind: Kind) -> &'static [&'static str] {
    match kind {
        Kind::Connections => &[
            "ts", "time_utc", "first_us", "last_us", "id", "process.pid", "process.name", "process.path", "l4", "app", "local", "remote",
            "remote_ip", "name", "geo.country_code", "geo.country", "geo.city", "geo.org", "geo.asn", "bytes_in", "bytes_out", "packets_in",
            "packets_out", "state", "initiated", "tls.sni", "tls.version", "tls.alpn", "tls.ja4", "rtt_ms", "retrans", "hops", "reason",
        ],
        Kind::Dns => &["ts", "time_utc", "seq", "ts_us", "name", "qtype", "resolver", "requester.pid", "requester.name", "answers", "rcode", "latency_ms", "transport", "used_by"],
        Kind::Alerts => &["ts", "time_utc", "id", "severity", "kind", "host", "name", "message", "details"],
    }
}

/// The cell for `path` in a journal record: nested objects by dotted path, lists joined
/// with spaces, objects as JSON, `null` as empty.
fn cell(record: &serde_json::Value, path: &str) -> String {
    if path == "time_utc" {
        return record.get("ts").and_then(serde_json::Value::as_i64).map(|ts| utc(ts * 1_000_000)).unwrap_or_default();
    }
    let mut v = record;
    for key in path.split('.') {
        match v.get(key) {
            Some(x) => v = x,
            None => return String::new(),
        }
    }
    match v {
        serde_json::Value::Null => String::new(),
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(a) => a.iter().map(|x| match x {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        }).collect::<Vec<_>>().join(" "),
        other => other.to_string(),
    }
}

/// Journal records as CSV with a fixed column set per kind.
pub fn journal_csv(kind: Kind, records: &[serde_json::Value]) -> String {
    let columns = journal_columns(kind);
    csv(columns, records.iter().map(|r| columns.iter().map(|c| cell(r, c)).collect()))
}

/// Journal records as JSON lines.
pub fn journal_jsonl(records: &[serde_json::Value]) -> String {
    let mut out = String::new();
    for r in records {
        out.push_str(&r.to_string());
        out.push('\n');
    }
    out
}

/// Packets copied out of the state, so the file is written without holding its lock.
pub struct PcapFrames {
    linktype: i32,
    /// (timestamp, length on the wire, stored bytes)
    frames: Vec<(i64, u32, Box<[u8]>)>,
}

/// Stored packets of the given connections, in time order. The state is locked once per
/// connection, not for the whole copy, so the capture thread keeps recording in between.
pub fn pcap_frames(shared: &SharedState, ids: &[u64]) -> PcapFrames {
    let linktype = shared.read().linktype;
    let mut frames = Vec::new();
    for id in ids {
        let st = shared.read();
        if let Some(f) = st.flow(*id) {
            frames.extend(f.stored().map(|p| (p.ts_us, p.wire_len, p.data.clone())));
        }
    }
    frames.sort_by_key(|f| f.0);
    PcapFrames { linktype, frames }
}

impl PcapFrames {
    pub fn write(&self) -> std::io::Result<Vec<u8>> {
        let mut w = PcapWriter::new(Vec::new(), self.linktype)?;
        for (ts, wire_len, data) in &self.frames {
            w.write_truncated(*ts, data, *wire_len)?;
        }
        w.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_quoting() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("line\nbreak"), "\"line\nbreak\"");
        assert_eq!(csv_field("=HYPERLINK(\"http://x\")"), "\"'=HYPERLINK(\"\"http://x\"\")\"");
        assert_eq!(csv_field("@SUM(A1)"), "'@SUM(A1)");
        assert_eq!(csv_field("-1"), "'-1");
        let out = csv(&["a", "b"], vec![vec!["1".into(), "x,y".into()]].into_iter());
        assert_eq!(out, "\u{feff}a,b\r\n1,\"x,y\"\r\n");
    }

    #[test]
    fn journal_csv_flattens_nested_objects_and_escapes_formulas() {
        let rec = serde_json::json!({
            "ts": 1_709_164_800, "first_us": 1, "last_us": 2, "id": 7,
            "process": { "pid": 5, "name": "=cmd.exe", "path": null },
            "l4": "tcp", "app": "tls", "local": "10.0.0.2:1", "remote": "1.1.1.1:443", "remote_ip": "1.1.1.1", "name": "a,b",
            "geo": null, "bytes_in": 10, "bytes_out": 20, "packets_in": 1, "packets_out": 2, "state": "closed", "initiated": "local",
            "tls": { "sni": "x", "version": "TLS 1.3", "alpn": ["h2", "http/1.1"], "ja4": "j" }, "rtt_ms": 1.5, "retrans": 0, "hops": null, "reason": "closed"
        });
        let text = journal_csv(Kind::Connections, std::slice::from_ref(&rec));
        let lines: Vec<&str> = text.trim_start_matches('\u{feff}').lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("ts,time_utc,first_us,last_us,id,process.pid,process.name,process.path,l4,"));
        assert_eq!(lines[0].split(',').count(), journal_columns(Kind::Connections).len());
        let cells: Vec<&str> = lines[1].split(',').collect();
        assert_eq!(&cells[..9], &["1709164800", "2024-02-29 00:00:00", "1", "2", "7", "5", "'=cmd.exe", "", "tcp"]);
        assert!(lines[1].contains(",\"a,b\",,"), "geo is null → empty cells: {}", lines[1]);
        assert!(lines[1].contains(",x,TLS 1.3,h2 http/1.1,j,1.5,0,,closed"), "{}", lines[1]);
        let alert = serde_json::json!({ "ts": 5, "id": 1, "severity": "high", "kind": "k", "host": null, "name": null, "message": "m", "details": { "a": "1" } });
        let text = journal_csv(Kind::Alerts, &[alert]);
        assert!(text.ends_with("5,1970-01-01 00:00:05,1,high,k,,,m,\"{\"\"a\"\":\"\"1\"\"}\"\r\n"), "{text:?}");
        assert_eq!(journal_jsonl(&[rec.clone(), rec]).lines().count(), 2);
        assert!(journal_csv(Kind::Dns, &[]).contains("requester.name,answers,"));
    }

    #[test]
    fn utc_formatting() {
        assert_eq!(utc(0), "1970-01-01 00:00:00");
        assert_eq!(utc(971_186_136_000_000), "2000-10-10 13:55:36");
        assert_eq!(utc(1_709_164_800_000_000), "2024-02-29 00:00:00");
    }

    #[test]
    fn pcap_frames_collects_per_connection_in_time_order() {
        use crate::analytics::{CaptureInfo, CaptureStatus, Config};
        use crate::decode::{decode, linktype};
        use crate::demo::frames::{tcp_frame, TcpFlags};
        let info = CaptureInfo { mode: "file", source: "t".into(), description: None, filter: None, libpcap: None, status: CaptureStatus::Finished };
        let shared = SharedState::new(State::new(Config::default(), std::collections::HashSet::new(), info));
        let t0 = 1_760_000_000_000_000;
        let me = [10, 0, 0, 2];
        for (ts, port) in [(t0 + 30, 5001), (t0 + 10, 5000), (t0 + 20, 5001), (t0 + 40, 5002)] {
            let f = tcp_frame(me, [93, 184, 215, 14], port, 80, TcpFlags::Data, b"x");
            shared.write().record_frame(ts, f.len() as u32, &f, decode(linktype::ETHERNET, &f).as_ref());
        }
        let ids: Vec<u64> = {
            let st = shared.read();
            let mut v: Vec<&crate::analytics::flows::Flow> = st.flows().filter(|f| f.key.local.port() != 5002).collect();
            v.sort_by_key(|f| f.key.local.port());
            v.iter().map(|f| f.id).collect()
        };
        let frames = pcap_frames(&shared, &[ids[1], ids[0], 999_999]);
        assert_eq!(frames.frames.iter().map(|f| f.0).collect::<Vec<_>>(), vec![t0 + 10, t0 + 20, t0 + 30], "two connections, time order, unknown id skipped");
        let bytes = frames.write().unwrap();
        assert_eq!(&bytes[..4], &0xA1B2_C3D4u32.to_le_bytes());
        assert!(shared.read().flows().count() == 3, "the state is untouched and unlocked");
    }
}
