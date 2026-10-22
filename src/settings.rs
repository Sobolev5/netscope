//! The settings file (`netscope.ini`) behind the dashboard's Settings page and the desktop
//! program's start-up configuration.
//!
//! Format: `key=value` lines; `#` and `;` start comments; keys are case-insensitive; values
//! may be quoted; a key given twice counts once, with its last value. A UTF-8 byte order
//! mark (Notepad's "UTF-8 with BOM") is tolerated and preserved. Saving keeps comments and
//! unknown lines, writes exactly one line per known key and replaces the file atomically.

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::analytics::Category;

pub const FILE_NAME: &str = "netscope.ini";
const BOM: char = '\u{feff}';
/// Known keys, in the order new lines are appended to a file that lacks them.
pub const KEYS: [&str; 13] = [
    "port",
    "host",
    "interface",
    "filter",
    "geoip",
    "egress_check",
    "promiscuous",
    "verbose",
    "show_window",
    "notifications",
    "notify_categories",
    "notify_snooze_until",
    "journal_days",
];
/// Longest journal retention the settings accept (days).
pub const MAX_JOURNAL_DAYS: u32 = 365;
pub const NOTIFICATION_LEVELS: [&str; 3] = ["medium", "high", "off"];

/// Where the settings live: `<data dir>/netscope.ini`.
pub fn settings_path() -> PathBuf {
    crate::app::data_dir().join(FILE_NAME)
}

/// What the running program can do for the settings page; implemented by the desktop app.
/// The defaults describe the plain CLI: nothing beyond reading and writing the file.
pub trait SettingsHost: Send + Sync {
    /// Whether the program starts with the user's session; `None` = not supported here.
    fn autostart(&self) -> Option<bool> {
        None
    }
    fn set_autostart(&self, _on: bool) -> Result<(), String> {
        Err("not supported".into())
    }
    fn can_restart(&self) -> bool {
        false
    }
    /// Asks the program to stop and start again with the settings file; returns at once.
    fn request_restart(&self) -> Result<(), String> {
        Err("not supported".into())
    }
    /// The running configuration did not come from the settings file (command-line arguments).
    fn started_from_cli(&self) -> bool {
        false
    }
    /// The file the settings page reads and writes.
    fn settings_path(&self) -> PathBuf {
        settings_path()
    }
    /// The program's own log file, if it writes one (the desktop app does; the CLI logs
    /// to the console).
    fn log_path(&self) -> Option<PathBuf> {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Dashboard port; `None` = 8888 or the next free one.
    pub port: Option<u16>,
    pub host: String,
    /// Capture interface: index, name or part of the description; `None` = the best active one.
    pub interface: Option<String>,
    /// BPF capture filter.
    pub filter: Option<String>,
    /// Directory with the geolocation databases.
    pub geoip: Option<PathBuf>,
    pub egress_check: bool,
    pub promiscuous: bool,
    pub verbose: bool,
    /// Desktop app: show the window at start (`false` = start in the tray).
    pub show_window: bool,
    /// Desktop app notifications: `medium`, `high` or `off`.
    pub notifications: String,
    /// Alert categories the desktop app notifies about (`security`, `novelty`, `network`,
    /// `routes`), in `Category::ALL` order; a missing key means all of them.
    pub notify_categories: Vec<Category>,
    /// Notifications are muted until this unix time (0 = not muted).
    pub notify_snooze_until: i64,
    /// Days of journal (finished connections, DNS, alerts) kept on disk; 0 = no journal.
    pub journal_days: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            port: None,
            host: "127.0.0.1".into(),
            interface: None,
            filter: None,
            geoip: None,
            egress_check: true,
            promiscuous: true,
            verbose: false,
            show_window: true,
            notifications: "medium".into(),
            notify_categories: Category::ALL.to_vec(),
            notify_snooze_until: 0,
            journal_days: 1,
        }
    }
}

/// Changes from the settings page; every field is optional. `port_auto: true` clears the port
/// (the JSON form cannot tell "no port given" from "no fixed port" otherwise).
#[derive(Debug, Default, Clone, Deserialize)]
pub struct SettingsPatch {
    pub port: Option<u16>,
    pub port_auto: Option<bool>,
    pub host: Option<String>,
    pub interface: Option<String>,
    pub filter: Option<String>,
    pub geoip: Option<String>,
    pub egress_check: Option<bool>,
    pub promiscuous: Option<bool>,
    pub verbose: Option<bool>,
    pub show_window: Option<bool>,
    pub notifications: Option<String>,
    pub notify_categories: Option<Vec<String>>,
    pub notify_snooze_until: Option<i64>,
    pub journal_days: Option<u32>,
}

/// Parses a comma-separated category list; unknown names are reported.
pub fn parse_categories(v: &str) -> Result<Vec<Category>, String> {
    let mut out = Vec::new();
    for part in v.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match Category::parse(part) {
            Some(c) if !out.contains(&c) => out.push(c),
            Some(_) => {}
            None => return Err(format!("unknown notification category `{part}` (expected one of security, novelty, network, routes)")),
        }
    }
    out.sort_by_key(|c| Category::ALL.iter().position(|x| x == c));
    Ok(out)
}

fn categories_text(cats: &[Category]) -> String {
    cats.iter().map(|c| c.name()).collect::<Vec<_>>().join(",")
}

fn is_off(v: &str) -> bool {
    matches!(v.to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off")
}

fn is_on(v: &str) -> bool {
    matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

fn flag(b: bool) -> &'static str {
    if b { "1" } else { "0" }
}

fn non_empty(v: &str) -> Option<String> {
    let v = v.trim();
    (!v.is_empty()).then(|| v.to_string())
}

/// `key=value` pairs of a settings file text, keys lowercased, duplicates collapsed to the
/// last value (in the position of the first line).
pub fn read_pairs(text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for l in text.trim_start_matches(BOM).lines() {
        let l = l.trim();
        if l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        let Some((k, v)) = l.split_once('=') else { continue };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().trim_matches('"').to_string());
        match out.iter_mut().find(|(seen, _)| *seen == k) {
            Some(e) => e.1 = v,
            None => out.push((k, v)),
        }
    }
    out
}

/// The raw value of one key (`None` when the file or the key is missing).
pub fn setting(path: &Path, key: &str) -> Option<String> {
    let text = fs::read_to_string(path).unwrap_or_default();
    read_pairs(&text).into_iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// Replaces every line for `key` — active or commented out — in `old` by a single
/// `key=value` line at the position of the first of them (appended when there is none), so
/// the file never holds two values for one key.
fn set_line(lines: &mut Vec<String>, key: &str, value: &str) {
    let mut done = false;
    lines.retain_mut(|l| {
        let bare = l.trim().trim_start_matches(['#', ';']).trim();
        let mine = bare.split_once('=').is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case(key));
        if !mine {
            return true;
        }
        if done {
            return false;
        }
        done = true;
        *l = format!("{key}={value}");
        true
    });
    if !done {
        lines.push(format!("{key}={value}"));
    }
}

/// Lines of the file (without the byte order mark) and the mark itself, if present.
fn read_lines(path: &Path) -> (Vec<String>, String) {
    let old = fs::read_to_string(path).unwrap_or_default();
    let bom = if old.starts_with(BOM) { BOM.to_string() } else { String::new() };
    (old.trim_start_matches(BOM).lines().map(str::to_string).collect(), bom)
}

/// Writes the file through a temporary neighbour and a rename: a crash leaves either the
/// old or the new file, never a truncated one. The parent directory is created.
fn write_atomic(path: &Path, text: &str) -> Result<(), String> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".{}.tmp", std::process::id()));
    let tmp = PathBuf::from(tmp);
    fs::write(&tmp, text).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(format!("cannot replace {}: {e}", path.display()));
    }
    Ok(())
}

/// Sets one `key=value`, keeping comments and the other lines (CRLF line endings).
pub fn write_setting(path: &Path, key: &str, value: &str) -> Result<(), String> {
    let (mut lines, bom) = read_lines(path);
    set_line(&mut lines, key, value);
    write_atomic(path, &(bom + &lines.join("\r\n") + "\r\n"))
}

impl Settings {
    /// Reads the file; a missing file or an unreadable value means the default. Values
    /// that cannot be used (a port that is not a number) are logged and ignored.
    pub fn load(path: &Path) -> Settings {
        let text = fs::read_to_string(path).unwrap_or_default();
        Self::from_pairs(&read_pairs(&text))
    }

    pub fn from_pairs(pairs: &[(String, String)]) -> Settings {
        let mut s = Settings::default();
        let mut show_window = None;
        for (k, v) in pairs {
            match k.as_str() {
                "port" if !v.is_empty() => match v.parse::<u16>() {
                    Ok(p) if p > 0 => s.port = Some(p),
                    _ => tracing::warn!("{FILE_NAME}: ignoring port={v}: not a number between 1 and 65535"),
                },
                "host" if !v.is_empty() => s.host = v.clone(),
                "interface" => s.interface = non_empty(v),
                "filter" => s.filter = non_empty(v),
                "geoip" => s.geoip = non_empty(v).map(PathBuf::from),
                "egress_check" => s.egress_check = !is_off(v),
                "promiscuous" => s.promiscuous = !is_off(v),
                "verbose" => s.verbose = is_on(v),
                "show_window" => show_window = Some(!is_off(v)),
                // `open_browser` is the pre-0.2 name of `show_window`.
                "open_browser" if show_window.is_none() => s.show_window = !is_off(v),
                "notifications" => s.notifications = normalize_level(v),
                "notify_categories" => match parse_categories(v) {
                    Ok(c) => s.notify_categories = c,
                    Err(e) => tracing::warn!("{FILE_NAME}: ignoring notify_categories={v}: {e}"),
                },
                "notify_snooze_until" => s.notify_snooze_until = v.trim().parse::<i64>().unwrap_or(0).max(0),
                "journal_days" if !v.is_empty() => match v.parse::<u32>() {
                    Ok(d) if d <= MAX_JOURNAL_DAYS => s.journal_days = d,
                    _ => tracing::warn!("{FILE_NAME}: ignoring journal_days={v}: not a number between 0 and {MAX_JOURNAL_DAYS}"),
                },
                _ => {}
            }
        }
        if let Some(w) = show_window {
            s.show_window = w;
        }
        s
    }

    /// Rewrites the file: one line per key, comments and unknown lines kept, atomic.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let (mut lines, bom) = read_lines(path);
        for (key, value) in self.pairs() {
            set_line(&mut lines, key, &value);
        }
        write_atomic(path, &(bom + &lines.join("\r\n") + "\r\n"))
    }

    /// The values as they are written to the file, in `KEYS` order.
    pub fn pairs(&self) -> Vec<(&'static str, String)> {
        let opt = |v: &Option<String>| v.clone().unwrap_or_default();
        vec![
            ("port", self.port.map(|p| p.to_string()).unwrap_or_default()),
            ("host", self.host.clone()),
            ("interface", opt(&self.interface)),
            ("filter", opt(&self.filter)),
            ("geoip", self.geoip.as_ref().map(|p| p.display().to_string()).unwrap_or_default()),
            ("egress_check", flag(self.egress_check).into()),
            ("promiscuous", flag(self.promiscuous).into()),
            ("verbose", flag(self.verbose).into()),
            ("show_window", flag(self.show_window).into()),
            ("notifications", self.notifications.clone()),
            ("notify_categories", categories_text(&self.notify_categories)),
            ("notify_snooze_until", self.notify_snooze_until.to_string()),
            ("journal_days", self.journal_days.to_string()),
        ]
    }

    /// Whether the desktop app should notify about an alert of `category` at `now`.
    pub fn notifies(&self, category: Category, now: i64) -> bool {
        self.notifications != "off" && self.notify_categories.contains(&category) && self.notify_snooze_until <= now
    }

    /// Command-line arguments for clap (`cli::Args`) equivalent to these settings.
    pub fn to_args(&self, program: &str) -> Vec<String> {
        let mut argv = vec![program.to_string()];
        if let Some(p) = self.port {
            argv.extend(["--port".into(), p.to_string()]);
        }
        if !self.host.is_empty() {
            argv.extend(["--host".into(), self.host.clone()]);
        }
        if let Some(i) = &self.interface {
            argv.extend(["--interface".into(), i.clone()]);
        }
        if let Some(f) = &self.filter {
            argv.extend(["--filter".into(), f.clone()]);
        }
        if let Some(g) = &self.geoip {
            argv.extend(["--geoip".into(), g.display().to_string()]);
        }
        if !self.egress_check {
            argv.push("--no-egress-check".into());
        }
        if !self.promiscuous {
            argv.push("--no-promisc".into());
        }
        if self.verbose {
            argv.push("-v".into());
        }
        if self.journal_days != Settings::default().journal_days {
            argv.extend(["--journal-days".into(), self.journal_days.to_string()]);
        }
        argv
    }

    /// Applies a patch after validating all of it; on an error nothing is changed and the
    /// message names the field.
    pub fn apply(&mut self, patch: &SettingsPatch) -> Result<(), String> {
        let mut next = self.clone();
        if patch.port_auto == Some(true) {
            next.port = None;
        } else if let Some(p) = patch.port {
            if p == 0 {
                return Err("port must be between 1 and 65535".into());
            }
            next.port = Some(p);
        }
        if let Some(h) = &patch.host {
            let h = h.trim();
            if h != "localhost" && h.parse::<IpAddr>().is_err() {
                return Err("host must be an IP address (e.g. 127.0.0.1 or 0.0.0.0) or localhost".into());
            }
            next.host = h.to_string();
        }
        if let Some(n) = &patch.notifications {
            let n = n.trim().to_ascii_lowercase();
            if !NOTIFICATION_LEVELS.contains(&n.as_str()) {
                return Err("notifications must be one of medium, high, off".into());
            }
            next.notifications = n;
        }
        if let Some(c) = &patch.notify_categories {
            next.notify_categories = parse_categories(&c.join(","))?;
        }
        if let Some(t) = patch.notify_snooze_until {
            next.notify_snooze_until = t.max(0);
        }
        if let Some(i) = &patch.interface {
            next.interface = non_empty(i);
        }
        if let Some(f) = &patch.filter {
            next.filter = non_empty(f);
        }
        if let Some(g) = &patch.geoip {
            next.geoip = non_empty(g).map(PathBuf::from);
        }
        if let Some(b) = patch.egress_check {
            next.egress_check = b;
        }
        if let Some(b) = patch.promiscuous {
            next.promiscuous = b;
        }
        if let Some(b) = patch.verbose {
            next.verbose = b;
        }
        if let Some(b) = patch.show_window {
            next.show_window = b;
        }
        if let Some(d) = patch.journal_days {
            if d > MAX_JOURNAL_DAYS {
                return Err(format!("journal_days must be between 0 and {MAX_JOURNAL_DAYS}"));
            }
            next.journal_days = d;
        }
        *self = next;
        Ok(())
    }

    /// Whether going from `previous` to these settings changes anything the running program
    /// read at start (capture, dashboard address, geolocation, logging). `show_window`,
    /// the notification keys and `journal_days` are read on the fly.
    pub fn needs_restart(&self, previous: &Settings) -> bool {
        self.port != previous.port
            || self.host != previous.host
            || self.interface != previous.interface
            || self.filter != previous.filter
            || self.geoip != previous.geoip
            || self.egress_check != previous.egress_check
            || self.promiscuous != previous.promiscuous
            || self.verbose != previous.verbose
    }
}

/// `off`-like values become `off`; known levels are lowercased; anything else is `medium`.
fn normalize_level(v: &str) -> String {
    let l = v.trim().to_ascii_lowercase();
    if is_off(&l) {
        "off".into()
    } else if matches!(l.as_str(), "high" | "medium" | "low" | "all") {
        l
    } else {
        "medium".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_categories_and_snooze() {
        let s = Settings::from_pairs(&[("notify_categories".into(), "network, SECURITY,network,bogus".into())]);
        assert_eq!(s.notify_categories, Category::ALL.to_vec(), "an unknown name leaves the default in place");
        let s = Settings::from_pairs(&[("notify_categories".into(), "routes, Security".into()), ("notify_snooze_until".into(), "1760000000".into())]);
        assert_eq!(s.notify_categories, vec![Category::Security, Category::Routes], "canonical order");
        assert_eq!(s.pairs().iter().find(|(k, _)| *k == "notify_categories").unwrap().1, "security,routes");
        assert!(s.notifies(Category::Security, 1_760_000_000) && !s.notifies(Category::Security, 1_759_999_999));
        assert!(!s.notifies(Category::Novelty, 1_760_000_000), "not in the list");
        let s = Settings::from_pairs(&[("notify_categories".into(), "".into())]);
        assert!(s.notify_categories.is_empty(), "an empty list is none");
        let s = Settings::from_pairs(&[("notify_snooze_until".into(), "-5".into()), ("notifications".into(), "off".into())]);
        assert_eq!(s.notify_snooze_until, 0);
        assert!(!s.notifies(Category::Network, 0), "off is off");

        let mut s = Settings::default();
        let bad = SettingsPatch { notify_categories: Some(vec!["network".into(), "nope".into()]), ..SettingsPatch::default() };
        assert!(s.apply(&bad).unwrap_err().contains("nope"));
        assert_eq!(s.notify_categories, Category::ALL.to_vec(), "nothing changed");
        let ok = SettingsPatch { notify_categories: Some(vec!["routes".into(), "network".into()]), notify_snooze_until: Some(-1), ..SettingsPatch::default() };
        s.apply(&ok).unwrap();
        assert_eq!((s.notify_categories.clone(), s.notify_snooze_until), (vec![Category::Network, Category::Routes], 0));
        assert!(!s.needs_restart(&Settings::default()), "notification keys apply on the fly");
        assert_eq!(parse_categories("security,novelty,network,routes").unwrap(), Category::ALL.to_vec());
    }
    use crate::cli::Args;
    use clap::Parser;

    fn with_ini(text: &str, f: impl FnOnce(&Path)) {
        // Tests run in parallel: a counter keeps two inputs of the same length apart.
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("netscope-settings-{}-{}-{n}", std::process::id(), text.len()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(FILE_NAME);
        fs::write(&path, text).unwrap();
        f(&path);
        fs::remove_dir_all(&dir).ok();
    }

    fn args(path: &Path) -> Args {
        Args::try_parse_from(Settings::load(path).to_args("netscope-app")).unwrap()
    }

    #[test]
    fn settings_become_arguments() {
        with_ini("# comment\nport = 9000\ninterface=\"Wi-Fi\"\negress_check=0\nshow_window=0\nbogus=1\n", |p| {
            assert_eq!(setting(p, "port").as_deref(), Some("9000"));
            assert_eq!(setting(p, "interface").as_deref(), Some("Wi-Fi"));
            let s = Settings::load(p);
            assert!(!s.show_window);
            let a = args(p);
            assert_eq!((a.port, a.interface.as_deref(), a.no_egress_check), (Some(9000), Some("Wi-Fi"), true));
        });
    }

    #[test]
    fn missing_or_broken_settings() {
        with_ini("", |p| assert_eq!(Settings::load(p), Settings::default()));
        assert_eq!(Settings::load(Path::new("definitely/missing/netscope.ini")), Settings::default(), "a missing file means defaults");
        with_ini("port=notanumber\nport=\n", |p| assert_eq!(Settings::load(p).port, None, "an unusable port is ignored"));
        with_ini("port=70000\n", |p| assert_eq!(Settings::load(p).port, None));
        with_ini("port=0\n", |p| assert_eq!(Settings::load(p).port, None));
        with_ini("notifications=loud\n", |p| assert_eq!(Settings::load(p).notifications, "medium"));
    }

    #[test]
    fn writing_a_setting_keeps_the_rest() {
        with_ini("# NetScope\r\nport=8888\r\n# notifications=medium\r\nshow_window=1\r\n", |p| {
            write_setting(p, "notifications", "off").unwrap();
            write_setting(p, "port", "9001").unwrap();
            write_setting(p, "verbose", "1").unwrap();
            let text = fs::read_to_string(p).unwrap();
            assert_eq!(text, "# NetScope\r\nport=9001\r\nnotifications=off\r\nshow_window=1\r\nverbose=1\r\n");
            assert_eq!(setting(p, "notifications").as_deref(), Some("off"));
        });
    }

    #[test]
    fn settings_with_lf_endings_case_and_both_comment_styles() {
        with_ini("port=9000\n;host=0.0.0.0\n# interface=x\n  Verbose = yes  \npromiscuous=No\negress_check=OFF\nfilter=\"tcp port 443\"\ngeoip=C:\\geo data\nempty=\nnovalue\n", |p| {
            assert_eq!(setting(p, "host"), None, "`;` starts a comment");
            assert_eq!(setting(p, "interface"), None, "`#` starts a comment");
            assert_eq!(setting(p, "verbose").as_deref(), Some("yes"), "keys are lowercased and trimmed");
            assert_eq!(setting(p, "Verbose"), None, "lookups use the lowercase key");
            assert_eq!(setting(p, "empty").as_deref(), Some(""));
            assert_eq!(setting(p, "novalue"), None);
            let a = args(p);
            assert_eq!((a.port, a.host.as_str(), a.interface.as_deref()), (Some(9000), "127.0.0.1", None));
            assert_eq!((a.verbose, a.no_promisc, a.no_egress_check), (1, true, true));
            assert_eq!((a.filter.as_deref(), a.geoip.as_deref()), (Some("tcp port 443"), Some(Path::new(r"C:\geo data"))));
            assert!(!a.demo && a.read.is_none() && !a.open);
        });
        with_ini("verbose=2\npromiscuous=yes\negress_check=1\nread=x.pcap\ndemo=1\n", |p| {
            let a = args(p);
            assert_eq!((a.verbose, a.no_promisc, a.no_egress_check), (0, false, false), "only 1/true/yes/on switch verbose on; unknown keys are ignored");
            assert!(a.read.is_none() && !a.demo);
        });
        with_ini("port=1\nport=2\n", |p| assert_eq!(args(p).port, Some(2), "a duplicated key is not passed twice: the last value wins"));
        with_ini("port=8888\nshow_window=1\n", |p| {
            write_setting(p, "port", "9001").unwrap();
            assert_eq!(fs::read_to_string(p).unwrap(), "port=9001\r\nshow_window=1\r\n", "LF files are rewritten with CRLF");
        });
        with_ini("# port=9000\n;Host=x\n# portal=1\n", |p| {
            write_setting(p, "port", "9001").unwrap();
            write_setting(p, "host", "127.0.0.1").unwrap();
            assert_eq!(fs::read_to_string(p).unwrap(), "port=9001\r\nhost=127.0.0.1\r\n# portal=1\r\n", "a commented-out key is reactivated in place; a longer key is not it");
            assert_eq!(setting(p, "port").as_deref(), Some("9001"));
        });
        let fresh = std::env::temp_dir().join(format!("netscope-settings-fresh-{}", std::process::id())).join("sub").join(FILE_NAME);
        write_setting(&fresh, "notifications", "high").unwrap();
        assert_eq!(setting(&fresh, "notifications").as_deref(), Some("high"), "created when missing, with its directory");
        fs::remove_dir_all(fresh.parent().unwrap().parent().unwrap()).ok();
    }

    /// A file saved by Notepad as "UTF-8 with BOM": the first key must not be read as
    /// `\u{feff}port`, and writing must not append a second `port=` line.
    #[test]
    fn settings_files_with_a_byte_order_mark() {
        with_ini("\u{feff}port=9000\nshow_window=0\n", |p| {
            assert_eq!(setting(p, "port").as_deref(), Some("9000"));
            assert_eq!(args(p).port, Some(9000));
            write_setting(p, "port", "9001").unwrap();
            assert_eq!(setting(p, "port").as_deref(), Some("9001"));
            let text = fs::read_to_string(p).unwrap();
            assert_eq!(text.matches("port=").count(), 1);
            assert_eq!(text, "\u{feff}port=9001\r\nshow_window=0\r\n", "the byte order mark is kept, once");
            let mut s = Settings::load(p);
            s.port = None;
            s.save(p).unwrap();
            let text = fs::read_to_string(p).unwrap();
            assert!(text.starts_with("\u{feff}port=\r\nshow_window=0\r\n"), "{text:?}");
            assert_eq!(text.matches(BOM).count(), 1);
        });
    }

    /// `setting` reads the last value of a key; writing must therefore leave exactly one line
    /// for the key, or toggling a setting from the tray menu would have no visible effect.
    #[test]
    fn writing_a_duplicated_key_takes_effect() {
        with_ini("notifications=medium\nnotifications=high\n", |p| {
            write_setting(p, "notifications", "off").unwrap();
            assert_eq!(setting(p, "notifications").as_deref(), Some("off"));
            assert_eq!(fs::read_to_string(p).unwrap(), "notifications=off\r\n");
        });
        with_ini("# notifications=medium\nnotifications=high\n", |p| {
            write_setting(p, "notifications", "off").unwrap();
            assert_eq!(setting(p, "notifications").as_deref(), Some("off"));
        });
        with_ini("port=1\n; Notifications = high\nshow_window=1\nnotifications=medium\n", |p| {
            write_setting(p, "notifications", "off").unwrap();
            assert_eq!(fs::read_to_string(p).unwrap(), "port=1\r\nnotifications=off\r\nshow_window=1\r\n", "one line, at the position of the first occurrence (commented or not)");
        });
    }

    #[test]
    fn duplicated_keys_reach_clap_once_with_the_last_value() {
        with_ini("port=1\nport=2\nPORT=3\nverbose=1\nverbose=0\nhost=0.0.0.0\nhost=::1\n", |p| {
            let text = fs::read_to_string(p).unwrap();
            assert_eq!(read_pairs(&text).iter().filter(|(k, _)| k == "port").count(), 1);
            assert_eq!(setting(p, "port").as_deref(), Some("3"));
            let a = args(p);
            assert_eq!((a.port, a.verbose, a.host.as_str()), (Some(3), 0, "::1"));
        });
    }

    #[test]
    fn legacy_open_browser_key_and_notification_levels() {
        with_ini("open_browser=0\n", |p| assert!(!Settings::load(p).show_window, "open_browser is the old name"));
        with_ini("open_browser=0\nshow_window=1\n", |p| assert!(Settings::load(p).show_window, "show_window wins"));
        with_ini("show_window=0\nopen_browser=1\n", |p| assert!(!Settings::load(p).show_window));
        for (raw, level) in [("off", "off"), ("0", "off"), ("No", "off"), ("HIGH", "high"), ("medium", "medium"), ("low", "low"), ("", "medium"), ("x", "medium")] {
            with_ini(&format!("notifications={raw}\n"), |p| assert_eq!(Settings::load(p).notifications, level, "{raw:?}"));
        }
    }

    #[test]
    fn to_args_round_trips_through_clap() {
        let d = Settings::default();
        assert_eq!(d.to_args("netscope-app"), ["netscope-app", "--host", "127.0.0.1"]);
        let s = Settings {
            port: Some(9000),
            host: "0.0.0.0".into(),
            interface: Some("Wi-Fi".into()),
            filter: Some("tcp port 443".into()),
            geoip: Some(PathBuf::from(r"C:\geo data")),
            egress_check: false,
            promiscuous: false,
            verbose: true,
            show_window: false,
            notifications: "high".into(),
            notify_categories: vec![Category::Security],
            notify_snooze_until: 0,
            journal_days: 7,
        };
        let argv = s.to_args("netscope");
        assert_eq!(
            argv,
            ["netscope", "--port", "9000", "--host", "0.0.0.0", "--interface", "Wi-Fi", "--filter", "tcp port 443", "--geoip", r"C:\geo data", "--no-egress-check", "--no-promisc", "-v", "--journal-days", "7"]
        );
        let a = Args::try_parse_from(&argv).unwrap();
        assert_eq!((a.port, a.host.as_str(), a.interface.as_deref(), a.filter.as_deref()), (Some(9000), "0.0.0.0", Some("Wi-Fi"), Some("tcp port 443")));
        assert_eq!((a.geoip.as_deref(), a.no_egress_check, a.no_promisc, a.verbose), (Some(Path::new(r"C:\geo data")), true, true, 1));
        assert_eq!(a.journal_days, 7);
        assert_eq!(Args::try_parse_from(Settings { journal_days: 0, ..Settings::default() }.to_args("x")).unwrap().journal_days, 0, "zero is passed (it disables the journal)");
    }

    #[test]
    fn journal_days_from_the_file() {
        with_ini("journal_days=30\n", |p| assert_eq!(Settings::load(p).journal_days, 30));
        with_ini("journal_days=0\n", |p| assert_eq!(args(p).journal_days, 0));
        for bad in ["journal_days=x\n", "journal_days=400\n", "journal_days=-1\n", "journal_days=\n"] {
            with_ini(bad, |p| assert_eq!(Settings::load(p).journal_days, 1, "{bad:?} falls back to the default"));
        }
    }

    #[test]
    fn save_writes_every_key_once_and_loads_back() {
        with_ini("# NetScope settings\r\nport=8888\r\n# notifications=medium\r\nshow_window=1\r\nunknown=keep me\r\n", |p| {
            let mut s = Settings::load(p);
            assert_eq!(s.port, Some(8888));
            s.port = Some(9001);
            s.filter = Some("udp".into());
            s.notifications = "off".into();
            s.geoip = Some(PathBuf::from(r"D:\geo"));
            s.save(p).unwrap();
            let text = fs::read_to_string(p).unwrap();
            assert_eq!(
                text,
                "# NetScope settings\r\nport=9001\r\nnotifications=off\r\nshow_window=1\r\nunknown=keep me\r\nhost=127.0.0.1\r\ninterface=\r\nfilter=udp\r\ngeoip=D:\\geo\r\negress_check=1\r\npromiscuous=1\r\nverbose=0\r\nnotify_categories=security,novelty,network,routes\r\nnotify_snooze_until=0\r\njournal_days=1\r\n"
            );
            for key in KEYS {
                assert_eq!(text.lines().filter(|l| l.to_ascii_lowercase().starts_with(&format!("{key}="))).count(), 1, "{key} appears once");
            }
            assert_eq!(Settings::load(p), s, "what was saved is what loads");
            assert_eq!(fs::read_dir(p.parent().unwrap()).unwrap().count(), 1, "no temporary file is left behind");
        });
        // A fresh file in a missing directory.
        let dir = std::env::temp_dir().join(format!("netscope-settings-save-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("deeper").join(FILE_NAME);
        Settings { port: Some(1), ..Settings::default() }.save(&path).unwrap();
        assert_eq!(Settings::load(&path).port, Some(1));
        assert!(fs::read_to_string(&path).unwrap().starts_with("port=1\r\nhost=127.0.0.1\r\n"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_validates_and_trims() {
        let mut s = Settings::default();
        let ok = SettingsPatch {
            port: Some(9000),
            host: Some(" 0.0.0.0 ".into()),
            interface: Some("  Wi-Fi ".into()),
            filter: Some("   ".into()),
            geoip: Some(" C:\\geo ".into()),
            egress_check: Some(false),
            verbose: Some(true),
            show_window: Some(false),
            notifications: Some(" HIGH ".into()),
            ..SettingsPatch::default()
        };
        s.apply(&ok).unwrap();
        assert_eq!((s.port, s.host.as_str(), s.interface.as_deref(), s.filter.as_deref()), (Some(9000), "0.0.0.0", Some("Wi-Fi"), None));
        assert_eq!((s.geoip.as_deref(), s.egress_check, s.promiscuous, s.verbose), (Some(Path::new("C:\\geo")), false, true, true));
        assert_eq!((s.show_window, s.notifications.as_str()), (false, "high"));
        s.apply(&SettingsPatch { port_auto: Some(true), port: Some(1), ..SettingsPatch::default() }).unwrap();
        assert_eq!(s.port, None, "port_auto wins over a port");
        s.apply(&SettingsPatch { port_auto: Some(false), port: Some(2), ..SettingsPatch::default() }).unwrap();
        assert_eq!(s.port, Some(2));
        s.apply(&SettingsPatch { host: Some("localhost".into()), interface: Some(String::new()), ..SettingsPatch::default() }).unwrap();
        assert_eq!((s.host.as_str(), s.interface.as_deref()), ("localhost", None));
        s.apply(&SettingsPatch { host: Some("::1".into()), ..SettingsPatch::default() }).unwrap();
        assert_eq!(s.host, "::1");
        s.apply(&SettingsPatch { journal_days: Some(0), ..SettingsPatch::default() }).unwrap();
        assert_eq!(s.journal_days, 0);
        s.apply(&SettingsPatch { journal_days: Some(365), ..SettingsPatch::default() }).unwrap();
        assert_eq!(s.journal_days, 365);
        s.apply(&SettingsPatch::default()).unwrap();
        let before = s.clone();
        for (bad, field) in [
            (SettingsPatch { journal_days: Some(366), ..SettingsPatch::default() }, "journal_days"),
            (SettingsPatch { port: Some(0), ..SettingsPatch::default() }, "port"),
            (SettingsPatch { host: Some("example.org".into()), ..SettingsPatch::default() }, "host"),
            (SettingsPatch { host: Some("127.0.0.1:80".into()), ..SettingsPatch::default() }, "host"),
            (SettingsPatch { host: Some("LOCALHOST".into()), ..SettingsPatch::default() }, "host"),
            (SettingsPatch { notifications: Some("loud".into()), ..SettingsPatch::default() }, "notifications"),
            (SettingsPatch { notifications: Some("all".into()), ..SettingsPatch::default() }, "notifications"),
            (SettingsPatch { notifications: Some("off".into()), host: Some("nope".into()), ..SettingsPatch::default() }, "host"),
        ] {
            let e = s.apply(&bad).unwrap_err();
            assert!(e.starts_with(field), "{e}");
            assert_eq!(s, before, "a rejected patch changes nothing");
        }
    }

    #[test]
    fn patch_json_and_restart_detection() {
        let p: SettingsPatch = serde_json::from_str(r#"{"port": 9000, "port_auto": false, "verbose": true, "autostart": true}"#).unwrap();
        assert_eq!((p.port, p.port_auto, p.verbose, p.host), (Some(9000), Some(false), Some(true), None), "unknown fields are ignored");
        assert!(serde_json::from_str::<SettingsPatch>(r#"{"port": 70000}"#).is_err());
        assert!(serde_json::from_str::<SettingsPatch>(r#"{"port": "x"}"#).is_err());
        let p: SettingsPatch = serde_json::from_str("{}").unwrap();
        assert!(p.port.is_none() && p.notifications.is_none());

        let base = Settings::default();
        let mut s = base.clone();
        s.apply(&SettingsPatch { notifications: Some("off".into()), show_window: Some(false), journal_days: Some(5), ..SettingsPatch::default() }).unwrap();
        assert!(!s.needs_restart(&base), "notifications, the window and the journal retention are read on the fly");
        assert!(serde_json::from_str::<SettingsPatch>(r#"{"journal_days": -1}"#).is_err());
        assert_eq!(serde_json::from_str::<SettingsPatch>(r#"{"journal_days": 3}"#).unwrap().journal_days, Some(3));
        for patch in [
            SettingsPatch { port: Some(1), ..SettingsPatch::default() },
            SettingsPatch { host: Some("0.0.0.0".into()), ..SettingsPatch::default() },
            SettingsPatch { interface: Some("x".into()), ..SettingsPatch::default() },
            SettingsPatch { filter: Some("udp".into()), ..SettingsPatch::default() },
            SettingsPatch { geoip: Some("g".into()), ..SettingsPatch::default() },
            SettingsPatch { egress_check: Some(false), ..SettingsPatch::default() },
            SettingsPatch { promiscuous: Some(false), ..SettingsPatch::default() },
            SettingsPatch { verbose: Some(true), ..SettingsPatch::default() },
        ] {
            let mut s = base.clone();
            s.apply(&patch).unwrap();
            assert!(s.needs_restart(&base), "{patch:?}");
        }
        assert!(settings_path().ends_with(FILE_NAME));
    }
}
