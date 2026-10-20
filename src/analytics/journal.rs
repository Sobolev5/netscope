//! The journal: finished connections, DNS lookups and alerts written to disk as JSON lines,
//! one file per kind and UTC day, kept for a configurable number of days.
//!
//! Records are produced inside [`State`](super::State) (under its lock) into a bounded
//! queue; a writer thread drains the queue every second and writes outside the lock, so
//! a slow disk never stalls the capture. Everything still queued is written at shutdown.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::Serialize;

use super::flows::{FlowState, L4};
use super::views::{ConnView, TlsView};
use crate::capture::engine::unix_now;

/// Records waiting for the writer; beyond this the oldest are dropped (and counted).
pub const QUEUE_CAP: usize = 50_000;
/// Most records one query returns.
pub const MAX_LIMIT: usize = 5000;
pub const DEFAULT_LIMIT: usize = 500;
/// Longest retention the settings accept.
pub const MAX_DAYS: u32 = 365;
const RETENTION_INTERVAL: Duration = Duration::from_secs(3600);
const WRITE_INTERVAL: Duration = Duration::from_secs(1);
const SECS_PER_DAY: i64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Connections,
    Dns,
    Alerts,
}

impl Kind {
    pub const ALL: [Kind; 3] = [Kind::Connections, Kind::Dns, Kind::Alerts];

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Connections => "connections",
            Kind::Dns => "dns",
            Kind::Alerts => "alerts",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.as_str() == s)
    }

    fn index(self) -> usize {
        match self {
            Kind::Connections => 0,
            Kind::Dns => 1,
            Kind::Alerts => 2,
        }
    }
}

/// One line of a journal file, already rendered.
#[derive(Debug, Clone)]
pub struct JournalRecord {
    pub kind: Kind,
    /// Unix seconds; decides the day file.
    pub ts: i64,
    /// A JSON object without the trailing newline.
    pub line: String,
}

impl JournalRecord {
    pub fn new<T: Serialize>(kind: Kind, ts: i64, value: &T) -> Option<Self> {
        let line = serde_json::to_string(value).ok()?;
        Some(Self { kind, ts, line })
    }
}

/// `value` plus a `ts` field (unix seconds): the journal's stamp on views that lack one.
#[derive(Serialize)]
pub struct Stamped<'a, T: Serialize> {
    pub ts: i64,
    #[serde(flatten)]
    pub inner: &'a T,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcRecord {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeoRecord {
    pub country_code: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub org: Option<String>,
    pub asn: Option<u32>,
}

/// A finished connection as written to `connections-<day>.jsonl`.
#[derive(Debug, Clone, Serialize)]
pub struct ConnRecord {
    pub ts: i64,
    pub first_us: i64,
    pub last_us: i64,
    pub id: u64,
    pub process: Option<ProcRecord>,
    pub l4: L4,
    pub app: &'static str,
    pub local: String,
    pub remote: String,
    pub remote_ip: String,
    pub name: Option<String>,
    pub geo: Option<GeoRecord>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub state: FlowState,
    pub initiated: Option<&'static str>,
    pub tls: Option<TlsView>,
    pub rtt_ms: Option<f64>,
    pub retrans: u32,
    pub hops: Option<u8>,
    /// `closed`, `evicted` or `shutdown`.
    pub reason: &'static str,
}

impl ConnRecord {
    pub fn from_view(ts: i64, c: ConnView, reason: &'static str) -> Self {
        ConnRecord {
            ts,
            first_us: c.first_us,
            last_us: c.last_us,
            id: c.id,
            process: c.process.map(|p| ProcRecord { pid: p.pid, name: p.name, path: p.path }),
            l4: c.l4,
            app: c.app,
            local: c.local,
            remote: c.remote,
            remote_ip: c.remote_ip,
            name: c.name,
            geo: c.geo.map(|g| GeoRecord { country_code: g.country_code, country: g.country, city: g.city, org: g.org, asn: g.asn }),
            bytes_in: c.bytes_in,
            bytes_out: c.bytes_out,
            packets_in: c.packets_in,
            packets_out: c.packets_out,
            state: c.state,
            initiated: c.initiated,
            tls: c.tls,
            rtt_ms: c.rtt_ms,
            retrans: c.retrans_in + c.retrans_out,
            hops: c.hops,
            reason,
        }
    }
}

#[derive(Default)]
struct Queue {
    pending: std::collections::VecDeque<JournalRecord>,
    dropped: u64,
}

/// The journal's shared handle: the queue, the retention setting and counters. Held by
/// the state (producer), the writer thread (consumer) and the web layer (stats).
pub struct Journal {
    dir: PathBuf,
    days: AtomicU32,
    queue: Mutex<Queue>,
    written: [AtomicU64; 3],
}

impl Journal {
    pub fn new(dir: impl Into<PathBuf>, days: u32) -> Self {
        Self { dir: dir.into(), days: AtomicU32::new(days), queue: Mutex::new(Queue::default()), written: Default::default() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn retention_days(&self) -> u32 {
        self.days.load(Ordering::Relaxed)
    }

    /// Takes effect at once: no new records with 0, and the writer thread prunes files on
    /// its next tick.
    pub fn set_retention_days(&self, days: u32) {
        self.days.store(days.min(MAX_DAYS), Ordering::Relaxed);
    }

    /// Records are produced only while this is `true` (retention above zero days).
    pub fn enabled(&self) -> bool {
        self.retention_days() > 0
    }

    fn queue(&self) -> std::sync::MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Queues a record; when the queue is full the oldest one is dropped (and counted).
    pub fn push(&self, r: JournalRecord) {
        let mut q = self.queue();
        if q.pending.len() >= QUEUE_CAP {
            q.pending.pop_front();
            q.dropped += 1;
        }
        q.pending.push_back(r);
    }

    pub fn take_pending(&self) -> Vec<JournalRecord> {
        self.queue().pending.drain(..).collect()
    }

    pub fn pending(&self) -> usize {
        self.queue().pending.len()
    }

    pub fn dropped(&self) -> u64 {
        self.queue().dropped
    }

    /// Records written to disk since the start.
    pub fn written(&self, kind: Kind) -> u64 {
        self.written[kind.index()].load(Ordering::Relaxed)
    }

    fn count_written(&self, kind: Kind) {
        self.written[kind.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Deletes day files older than the retention; returns how many.
    pub fn apply_retention(&self) -> usize {
        prune(&self.dir, self.retention_days(), unix_now().div_euclid(SECS_PER_DAY))
    }
}

/// Appends records to the day files, keeping one file per kind open.
pub struct JournalWriter {
    dir: PathBuf,
    open: HashMap<Kind, (i64, BufWriter<File>)>,
}

impl JournalWriter {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into(), open: HashMap::new() }
    }

    fn file_for(&mut self, kind: Kind, day: i64) -> io::Result<&mut BufWriter<File>> {
        let stale = self.open.get(&kind).is_some_and(|(d, _)| *d != day);
        if stale {
            if let Some((_, mut w)) = self.open.remove(&kind) {
                let _ = w.flush();
            }
        }
        if !self.open.contains_key(&kind) {
            fs::create_dir_all(&self.dir)?;
            let path = self.dir.join(file_name(kind, day));
            let f = OpenOptions::new().append(true).create(true).open(path)?;
            self.open.insert(kind, (day, BufWriter::new(f)));
        }
        Ok(&mut self.open.get_mut(&kind).expect("inserted above").1)
    }

    /// Writes one record (buffered; `flush` makes it visible).
    pub fn write_one(&mut self, r: &JournalRecord) -> io::Result<()> {
        let w = self.file_for(r.kind, r.ts.div_euclid(SECS_PER_DAY))?;
        w.write_all(r.line.as_bytes())?;
        w.write_all(b"\n")
    }

    pub fn flush(&mut self) -> io::Result<()> {
        for (_, w) in self.open.values_mut() {
            w.flush()?;
        }
        Ok(())
    }

    /// Writes and flushes a batch; returns how many records made it to disk.
    pub fn write_all(&mut self, records: &[JournalRecord]) -> io::Result<usize> {
        let mut n = 0;
        for r in records {
            self.write_one(r)?;
            n += 1;
        }
        self.flush()?;
        Ok(n)
    }
}

/// Drains `journal` every second and at `stop`, prunes old files at start, hourly and
/// when the retention changes. Join the thread after `stop` to be sure the last records
/// were written.
pub fn spawn_writer(journal: Arc<Journal>, stop: Arc<AtomicBool>) -> io::Result<JoinHandle<()>> {
    thread::Builder::new().name("journal".into()).spawn(move || {
        if let Err(e) = fs::create_dir_all(journal.dir()) {
            tracing::warn!("cannot create the journal directory {}: {e}", journal.dir().display());
        }
        let mut w = JournalWriter::new(journal.dir().to_path_buf());
        let mut days = journal.retention_days();
        prune_logged(&journal);
        let mut next_prune = Instant::now() + RETENTION_INTERVAL;
        let mut next_write = Instant::now() + WRITE_INTERVAL;
        loop {
            let stopping = stop.load(Ordering::Relaxed);
            if stopping || Instant::now() >= next_write {
                let batch = journal.take_pending();
                if !batch.is_empty() {
                    let mut failed = None;
                    for r in &batch {
                        match w.write_one(r) {
                            Ok(()) => journal.count_written(r.kind),
                            Err(e) => {
                                failed = Some(e);
                                break;
                            }
                        }
                    }
                    if let Err(e) = w.flush() {
                        failed.get_or_insert(e);
                    }
                    if let Some(e) = failed {
                        tracing::warn!("cannot write the journal in {}: {e}", journal.dir().display());
                    }
                }
                next_write = Instant::now() + WRITE_INTERVAL;
            }
            let d = journal.retention_days();
            if d != days || Instant::now() >= next_prune {
                days = d;
                prune_logged(&journal);
                next_prune = Instant::now() + RETENTION_INTERVAL;
            }
            if stopping {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
    })
}

fn prune_logged(journal: &Journal) {
    let n = journal.apply_retention();
    if n > 0 {
        tracing::info!("journal: removed {n} day file(s) older than {} day(s)", journal.retention_days());
    }
}

/// Deletes files in `dir` whose date is more than `days` days before `today` (days since
/// the epoch); returns how many were removed. A missing directory is fine.
pub fn prune(dir: &Path, days: u32, today: i64) -> usize {
    let mut removed = 0;
    for (_, day, path) in day_files(dir) {
        if today - day > i64::from(days) && fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

// ----- queries and statistics -----

#[derive(Debug, Default, Serialize)]
pub struct QueryResult {
    /// Matching records before `limit`.
    pub total: usize,
    pub records: Vec<serde_json::Value>,
}

/// Records of `kind` with `from <= ts <= to` (unix seconds, both optional) whose JSON
/// line contains `q` (case-insensitive), newest first, at most `limit` (capped at
/// [`MAX_LIMIT`]). Only the day files overlapping the range are read; a line being
/// written at that moment (no newline yet) or one that is not JSON is ignored.
pub fn query(dir: &Path, kind: Kind, from: Option<i64>, to: Option<i64>, q: Option<&str>, limit: usize) -> io::Result<QueryResult> {
    let limit = limit.min(MAX_LIMIT);
    let needle = q.map(str::to_lowercase).filter(|s| !s.is_empty());
    let from_day = from.map(|t| t.div_euclid(SECS_PER_DAY));
    let to_day = to.map(|t| t.div_euclid(SECS_PER_DAY));
    let mut files: Vec<(i64, PathBuf)> = day_files(dir)
        .into_iter()
        .filter(|(k, d, _)| *k == kind && from_day.is_none_or(|f| *d >= f) && to_day.is_none_or(|t| *d <= t))
        .map(|(_, d, p)| (d, p))
        .collect();
    files.sort_unstable_by_key(|f| std::cmp::Reverse(f.0));
    let mut out = QueryResult::default();
    for (day, path) in files {
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            // Pruned between the listing and the read.
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let text = String::from_utf8_lossy(&bytes);
        let complete = complete_lines(&text);
        // Only the first and last day of the range need a look at every timestamp.
        let edge = from_day == Some(day) || to_day == Some(day);
        for line in complete.lines().rev() {
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }
            if edge {
                if let Some(ts) = line_ts(line) {
                    if from.is_some_and(|f| ts < f) || to.is_some_and(|t| ts > t) {
                        continue;
                    }
                }
            }
            if let Some(n) = &needle {
                if !line.to_lowercase().contains(n.as_str()) {
                    continue;
                }
            }
            out.total += 1;
            if out.records.len() < limit {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                    out.records.push(v);
                }
            }
        }
    }
    Ok(out)
}

/// The text up to and including its last newline: a trailing partial line is left out.
fn complete_lines(text: &str) -> &str {
    match text.rfind('\n') {
        Some(i) => &text[..=i],
        None => "",
    }
}

/// The value of the first `"ts":` key in a JSON line, without parsing the whole line.
/// (A string value containing `"ts":` would carry escaped quotes, so it cannot match.)
fn line_ts(line: &str) -> Option<i64> {
    let i = line.find("\"ts\":")? + 5;
    let rest = line[i..].trim_start();
    let end = rest.find(|c: char| !(c.is_ascii_digit() || c == '-')).unwrap_or(rest.len());
    rest[..end].parse().ok()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct KindCounts {
    pub connections: u64,
    pub dns: u64,
    pub alerts: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DayStats {
    /// `YYYY-MM-DD` (UTC).
    pub date: String,
    pub records: KindCounts,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct JournalStats {
    pub dir: String,
    /// Newest first.
    pub days: Vec<DayStats>,
    pub bytes_total: u64,
}

/// Sizes and line counts of the day files (a missing directory is simply empty).
pub fn stats(dir: &Path) -> JournalStats {
    let mut by_day: HashMap<i64, DayStats> = HashMap::new();
    for (kind, day, path) in day_files(dir) {
        let (bytes, lines) = match fs::read(&path) {
            Ok(b) => (b.len() as u64, memchr::memchr_iter(b'\n', &b).count() as u64),
            Err(_) => continue,
        };
        let e = by_day.entry(day).or_insert_with(|| DayStats { date: date_string(day), records: KindCounts::default(), bytes: 0 });
        e.bytes += bytes;
        match kind {
            Kind::Connections => e.records.connections += lines,
            Kind::Dns => e.records.dns += lines,
            Kind::Alerts => e.records.alerts += lines,
        }
    }
    let mut days: Vec<(i64, DayStats)> = by_day.into_iter().collect();
    days.sort_unstable_by_key(|d| std::cmp::Reverse(d.0));
    let bytes_total = days.iter().map(|(_, d)| d.bytes).sum();
    JournalStats { dir: dir.display().to_string(), days: days.into_iter().map(|(_, d)| d).collect(), bytes_total }
}

/// `(kind, day, path)` of every journal file in `dir`; other files are ignored.
fn day_files(dir: &Path) -> Vec<(Kind, i64, PathBuf)> {
    let Ok(entries) = fs::read_dir(dir) else { return Vec::new() };
    entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name();
            let (kind, day) = parse_file_name(name.to_str()?)?;
            Some((kind, day, e.path()))
        })
        .collect()
}

fn file_name(kind: Kind, day: i64) -> String {
    format!("{}-{}.jsonl", kind.as_str(), date_string(day))
}

/// `connections-2026-10-20.jsonl` → (`Connections`, days since the epoch).
pub fn parse_file_name(name: &str) -> Option<(Kind, i64)> {
    let stem = name.strip_suffix(".jsonl")?;
    // The date is the last ten characters, after the kind and a dash.
    let i = stem.len().checked_sub(10)?;
    let (kind, date) = (stem.get(..i)?.strip_suffix('-')?, stem.get(i..)?);
    Some((Kind::parse(kind)?, parse_date(date)?))
}

/// Start of the UTC day containing `secs`.
pub fn day_start(secs: i64) -> i64 {
    secs.div_euclid(SECS_PER_DAY) * SECS_PER_DAY
}

/// `YYYY-MM-DD` of a day counted from the epoch (Howard Hinnant's civil_from_days).
pub fn date_string(days: i64) -> String {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Days since the epoch of a `YYYY-MM-DD` date (days_from_civil).
pub fn parse_date(s: &str) -> Option<i64> {
    let mut it = s.split('-');
    let y: i64 = it.next()?.parse().ok()?;
    let m: i64 = it.next()?.parse().ok()?;
    let d: i64 = it.next()?.parse().ok()?;
    if it.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("netscope-journal-{}-{n}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn rec(kind: Kind, ts: i64, extra: &str) -> JournalRecord {
        JournalRecord { kind, ts, line: format!("{{\"ts\":{ts},\"x\":\"{extra}\"}}") }
    }

    #[test]
    fn dates_round_trip_and_file_names_parse() {
        assert_eq!(date_string(0), "1970-01-01");
        assert_eq!(date_string(parse_date("2024-02-29").unwrap()), "2024-02-29");
        assert_eq!(date_string(1_760_000_000 / SECS_PER_DAY), "2025-10-09");
        assert_eq!(parse_date("2025-10-09"), Some(1_760_000_000 / SECS_PER_DAY));
        assert_eq!(parse_date("2025-13-01"), None);
        assert_eq!(parse_date("nope"), None);
        assert_eq!(day_start(1_760_000_000), 1_759_968_000);
        assert_eq!(day_start(-1), -SECS_PER_DAY);
        assert_eq!(parse_file_name("connections-2026-10-20.jsonl"), Some((Kind::Connections, parse_date("2026-10-20").unwrap())));
        assert_eq!(parse_file_name("dns-2026-10-20.jsonl"), Some((Kind::Dns, parse_date("2026-10-20").unwrap())));
        assert_eq!(parse_file_name("alerts-2026-10-20.jsonl").map(|x| x.0), Some(Kind::Alerts));
        for bad in ["alerts-2026-10-20.json", "other-2026-10-20.jsonl", "alerts2026-10-20.jsonl", "alerts-.jsonl", "x.jsonl", "alerts-2026-10-20.jsonl.tmp"] {
            assert_eq!(parse_file_name(bad), None, "{bad}");
        }
        assert_eq!(file_name(Kind::Alerts, parse_date("2026-01-05").unwrap()), "alerts-2026-01-05.jsonl");
        assert_eq!(Kind::parse("dns"), Some(Kind::Dns));
        assert_eq!(Kind::parse("DNS"), None);
    }

    #[test]
    fn line_timestamps_and_partial_lines() {
        assert_eq!(line_ts(r#"{"ts":1760000000,"x":1}"#), Some(1_760_000_000));
        assert_eq!(line_ts(r#"{"id":5,"ts": -3,"x":1}"#), Some(-3));
        assert_eq!(line_ts(r#"{"name":"a \"ts\": b","ts":7}"#), Some(7), "an escaped key inside a string is not the key");
        assert_eq!(line_ts(r#"{"ts_us":5}"#), None);
        assert_eq!(complete_lines("a\nb\nc"), "a\nb\n");
        assert_eq!(complete_lines("a\nb\n"), "a\nb\n");
        assert_eq!(complete_lines("partial"), "");
    }

    #[test]
    fn writer_appends_per_kind_and_day_and_queries_newest_first() {
        let dir = temp("writer");
        let day0 = parse_date("2026-10-19").unwrap();
        let t = |day: i64, s: i64| day * SECS_PER_DAY + s;
        let mut w = JournalWriter::new(&dir);
        let batch = vec![
            rec(Kind::Connections, t(day0, 10), "first"),
            rec(Kind::Connections, t(day0, 20), "Second"),
            rec(Kind::Dns, t(day0, 30), "lookup"),
            rec(Kind::Connections, t(day0 + 1, 5), "next day"),
            rec(Kind::Alerts, t(day0 + 1, 6), "alert"),
        ];
        assert_eq!(w.write_all(&batch).unwrap(), 5);
        let mut names: Vec<String> = fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        names.sort();
        assert_eq!(names, ["alerts-2026-10-20.jsonl", "connections-2026-10-19.jsonl", "connections-2026-10-20.jsonl", "dns-2026-10-19.jsonl"]);
        // Appending to an existing file keeps what was there.
        assert_eq!(JournalWriter::new(&dir).write_all(&[rec(Kind::Connections, t(day0, 25), "third")]).unwrap(), 1);
        let text = fs::read_to_string(dir.join("connections-2026-10-19.jsonl")).unwrap();
        assert_eq!(text.lines().count(), 3);
        assert!(text.ends_with('\n'));

        let all = query(&dir, Kind::Connections, None, None, None, 10).unwrap();
        assert_eq!(all.total, 4);
        let xs: Vec<&str> = all.records.iter().map(|r| r["x"].as_str().unwrap()).collect();
        assert_eq!(xs, ["next day", "third", "Second", "first"], "newest day first, newest line first within a day");
        // Time range: only the files overlapping it are read, and edge days are filtered by ts.
        let r = query(&dir, Kind::Connections, Some(t(day0, 15)), Some(t(day0, 25)), None, 10).unwrap();
        assert_eq!(r.records.iter().map(|r| r["x"].as_str().unwrap()).collect::<Vec<_>>(), ["third", "Second"]);
        let r = query(&dir, Kind::Connections, Some(t(day0 + 1, 0)), None, None, 10).unwrap();
        assert_eq!(r.total, 1);
        // Substring, case-insensitive, over the whole line; limit keeps `total`.
        let r = query(&dir, Kind::Connections, None, None, Some("SECOND"), 10).unwrap();
        assert_eq!((r.total, r.records.len()), (1, 1));
        let r = query(&dir, Kind::Connections, None, None, Some("\"x\""), 1).unwrap();
        assert_eq!((r.total, r.records.len()), (4, 1));
        assert_eq!(query(&dir, Kind::Dns, None, None, None, 10).unwrap().total, 1);
        assert_eq!(query(&dir, Kind::Alerts, Some(t(day0, 0)), Some(t(day0, 100)), None, 10).unwrap().total, 0);
        assert_eq!(query(&dir, Kind::Connections, None, None, None, 0).unwrap().records.len(), 0);
        assert_eq!(query(&temp("missing"), Kind::Connections, None, None, None, 10).unwrap().total, 0, "no directory, no records");

        // A partial trailing line (being written) and garbage are skipped.
        let p = dir.join("connections-2026-10-20.jsonl");
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"not json\n{\"ts\":1,\"x\":\"half").unwrap();
        let r = query(&dir, Kind::Connections, None, None, None, 10).unwrap();
        assert_eq!(r.total, 5, "a complete non-JSON line counts but is not returned");
        assert_eq!(r.records.len(), 4);
        assert!(r.records.iter().all(|r| r["x"] != "half"));

        let s = stats(&dir);
        assert_eq!(s.dir, dir.display().to_string());
        assert_eq!(s.days.iter().map(|d| d.date.as_str()).collect::<Vec<_>>(), ["2026-10-20", "2026-10-19"]);
        assert_eq!(s.days[1].records, KindCounts { connections: 3, dns: 1, alerts: 0 });
        assert_eq!(s.days[0].records, KindCounts { connections: 2, dns: 0, alerts: 1 });
        assert_eq!(s.bytes_total, s.days.iter().map(|d| d.bytes).sum::<u64>());
        assert!(s.bytes_total > 100);
        assert!(stats(&temp("missing2")).days.is_empty());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn retention_removes_old_day_files_only() {
        let dir = temp("prune");
        fs::create_dir_all(&dir).unwrap();
        let today = parse_date("2026-10-20").unwrap();
        for (name, _) in [("connections-2026-10-20.jsonl", 0), ("dns-2026-10-19.jsonl", 1), ("alerts-2026-10-18.jsonl", 2), ("connections-2026-09-01.jsonl", 49), ("notes.txt", 0), ("connections-2026-10-21.jsonl", -1)] {
            fs::write(dir.join(name), "x\n").unwrap();
        }
        assert_eq!(prune(&dir, 1, today), 2, "older than one day: the 18th and September");
        let mut left: Vec<String> = fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        left.sort();
        assert_eq!(left, ["connections-2026-10-20.jsonl", "connections-2026-10-21.jsonl", "dns-2026-10-19.jsonl", "notes.txt"]);
        assert_eq!(prune(&dir, 0, today), 1, "zero days keeps today only (and a file from the future)");
        assert_eq!(prune(&dir, 0, today), 0);
        assert_eq!(prune(&temp("prune-missing"), 3, today), 0);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn queue_is_bounded_and_counts_drops() {
        let j = Journal::new("unused", 1);
        assert!(j.enabled());
        for i in 0..(QUEUE_CAP as i64 + 10) {
            j.push(rec(Kind::Dns, i, "q"));
        }
        assert_eq!((j.pending(), j.dropped()), (QUEUE_CAP, 10));
        let batch = j.take_pending();
        assert_eq!(batch.len(), QUEUE_CAP);
        assert_eq!(batch[0].ts, 10, "the oldest ten were dropped");
        assert_eq!(j.pending(), 0);
        j.set_retention_days(0);
        assert!(!j.enabled());
        j.set_retention_days(9999);
        assert_eq!(j.retention_days(), MAX_DAYS);
        assert_eq!(j.written(Kind::Dns), 0);
    }

    #[test]
    fn writer_thread_drains_on_stop_and_prunes_on_a_retention_change() {
        let dir = temp("thread");
        fs::create_dir_all(&dir).unwrap();
        let old = dir.join("alerts-2000-01-01.jsonl");
        fs::write(&old, "{}\n").unwrap();
        let j = Arc::new(Journal::new(&dir, 3));
        let stop = Arc::new(AtomicBool::new(false));
        let h = spawn_writer(j.clone(), stop.clone()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while old.exists() {
            assert!(Instant::now() < deadline, "the start-up prune did not run");
            thread::sleep(Duration::from_millis(10));
        }
        let now = unix_now();
        j.push(rec(Kind::Alerts, now, "a"));
        j.push(rec(Kind::Connections, now, "c"));
        let deadline = Instant::now() + Duration::from_secs(5);
        while j.written(Kind::Alerts) + j.written(Kind::Connections) < 2 {
            assert!(Instant::now() < deadline, "the periodic write did not happen");
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(query(&dir, Kind::Alerts, None, None, None, 5).unwrap().total, 1, "visible on disk after the flush");
        // Lowering the retention prunes at once: a file from two days ago goes with 1 day kept.
        let two_days_ago = dir.join(file_name(Kind::Dns, now.div_euclid(SECS_PER_DAY) - 2));
        fs::write(&two_days_ago, "{}\n").unwrap();
        j.set_retention_days(1);
        let deadline = Instant::now() + Duration::from_secs(5);
        while two_days_ago.exists() {
            assert!(Instant::now() < deadline, "the prune after the retention change did not run");
            thread::sleep(Duration::from_millis(10));
        }
        j.push(rec(Kind::Dns, now, "late"));
        stop.store(true, Ordering::Relaxed);
        h.join().unwrap();
        assert_eq!(j.written(Kind::Dns), 1, "written on stop");
        assert_eq!(j.pending(), 0);
        assert_eq!(query(&dir, Kind::Dns, None, None, Some("late"), 5).unwrap().total, 1);
        fs::remove_dir_all(&dir).ok();
    }
}
