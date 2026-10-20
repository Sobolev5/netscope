//! Who signed the executables that use the network.
//!
//! * Windows: `Get-AuthenticodeSignature` in one PowerShell call per batch; unlike a
//!   bare `WinVerifyTrust` it also understands catalog-signed system files.
//! * macOS: `codesign -dv`.
//! * Linux: no general code signing; reported as unknown.
//!
//! An unsigned program running from a temporary or download folder that talks to the
//! network is the classic picture of malware or an unwanted updater.

use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::analytics::SharedState;

/// A verification batch that runs longer than this is killed and reported as unknown
/// (PowerShell can hang on revocation checks or a wedged catalog service).
const BATCH_TIMEOUT: Duration = Duration::from_secs(25);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SigStatus {
    /// Valid signature from a trusted publisher.
    Signed,
    Unsigned,
    /// Signed, but the signature is broken, revoked, expired or not trusted.
    Invalid,
    /// Could not be checked (unsupported OS, file gone, access denied).
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Signature {
    pub status: SigStatus,
    /// Publisher (certificate subject common name / organisation).
    pub signer: Option<String>,
}

/// Executables in places where installed software does not normally live.
pub fn suspicious_location(path: &str) -> bool {
    let p = path.replace('/', "\\").to_lowercase();
    ["\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\downloads\\", "\\users\\public\\", "\\$recycle.bin\\", "\\tmp\\", "\\var\\tmp\\", "\\dev\\shm\\"]
        .iter()
        .any(|k| p.contains(k))
        || p.starts_with("\\tmp\\")
}

/// `CN=Microsoft Windows, O=Microsoft Corporation, ...` -> `Microsoft Corporation`.
pub fn signer_from_subject(subject: &str) -> Option<String> {
    // Split on commas outside double quotes: `O="Yandex, LLC", C=RU`.
    let mut parts = Vec::new();
    let (mut cur, mut quoted) = (String::new(), false);
    for ch in subject.chars() {
        match ch {
            '"' => quoted = !quoted,
            ',' if !quoted => parts.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    parts.push(cur);
    let get = |key: &str| parts.iter().find_map(|p| p.trim().strip_prefix(key)).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    get("O=").or_else(|| get("CN="))
}

/// Windows PowerShell by its fixed path: `PATH` may hold a different `powershell` first.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn powershell() -> PathBuf {
    match std::env::var_os("SystemRoot") {
        Some(root) => PathBuf::from(root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe"),
        None => PathBuf::from("powershell"),
    }
}

/// Runs `cmd` and returns its stdout; `None` if it cannot start, fails, or outlives
/// `timeout` (then it is killed).
pub fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Option<Vec<u8>> {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = cmd.spawn().ok()?;
    let mut stdout = child.stdout.take()?;
    // Drain on a thread: a child blocked on a full pipe would never exit.
    let reader = thread::spawn(move || {
        let mut out = Vec::new();
        stdout.read_to_end(&mut out).ok();
        out
    });
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return reader.join().ok().filter(|_| status.success()),
            Ok(None) if Instant::now() >= deadline => {
                child.kill().ok();
                child.wait().ok();
                return None;
            }
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(_) => {
                child.kill().ok();
                return None;
            }
        }
    }
}

#[cfg(windows)]
pub fn check(paths: &[String]) -> HashMap<String, Signature> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let list = serde_json::to_string(paths).unwrap_or_else(|_| "[]".into());
    // The paths never become part of the script text: file names are attacker-controlled
    // and PowerShell treats several Unicode quotes as string delimiters. They are passed
    // as JSON in an environment variable instead.
    // UTF-8 output: otherwise non-ASCII paths (Cyrillic user names) come back in the OEM code page.
    const SCRIPT: &str = "$ErrorActionPreference='SilentlyContinue'; [Console]::OutputEncoding = [Text.Encoding]::UTF8; $p = $env:NETSCOPE_SIG_PATHS | ConvertFrom-Json; \
         $r = foreach ($f in $p) { $s = Get-AuthenticodeSignature -LiteralPath $f; \
         [pscustomobject]@{ path = $f; status = [string]$s.Status; subject = [string]$s.SignerCertificate.Subject } }; \
         @($r) | ConvertTo-Json -Compress";
    let mut cmd = Command::new(powershell());
    cmd.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", SCRIPT])
        .env("NETSCOPE_SIG_PATHS", list)
        .creation_flags(CREATE_NO_WINDOW);
    let mut res = HashMap::new();
    let Some(out) = run_with_timeout(cmd, BATCH_TIMEOUT) else { return res };
    let text = String::from_utf8_lossy(&out);
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text.trim()) else { return res };
    for item in v.as_array().cloned().unwrap_or_else(|| vec![v]) {
        let (Some(path), Some(status)) = (item["path"].as_str(), item["status"].as_str()) else { continue };
        let status = match status {
            "Valid" => SigStatus::Signed,
            "NotSigned" => SigStatus::Unsigned,
            "HashMismatch" | "NotTrusted" | "Incompatible" => SigStatus::Invalid,
            _ => SigStatus::Unknown,
        };
        let signer = item["subject"].as_str().and_then(signer_from_subject);
        res.insert(path.to_string(), Signature { status, signer });
    }
    res
}

#[cfg(target_os = "macos")]
pub fn check(paths: &[String]) -> HashMap<String, Signature> {
    paths
        .iter()
        .map(|p| {
            let out = std::process::Command::new("codesign").args(["-dv", "--verbose=2", p]).output();
            let sig = match out {
                Ok(o) => {
                    let err = String::from_utf8_lossy(&o.stderr);
                    let signer = err.lines().find_map(|l| l.strip_prefix("Authority=")).map(String::from);
                    let status = if err.contains("not signed") {
                        SigStatus::Unsigned
                    } else if o.status.success() {
                        SigStatus::Signed
                    } else {
                        SigStatus::Invalid
                    };
                    Signature { status, signer }
                }
                Err(_) => Signature { status: SigStatus::Unknown, signer: None },
            };
            (p.clone(), sig)
        })
        .collect()
}

#[cfg(not(any(windows, target_os = "macos")))]
pub fn check(paths: &[String]) -> HashMap<String, Signature> {
    paths.iter().map(|p| (p.clone(), Signature { status: SigStatus::Unknown, signer: None })).collect()
}

/// Verifies new executables every few seconds until `stop`.
pub fn spawn_checker(shared: SharedState, stop: Arc<AtomicBool>) -> std::io::Result<JoinHandle<()>> {
    thread::Builder::new().name("signatures".into()).spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            let todo = shared.read().paths_to_verify(32);
            if !todo.is_empty() {
                let mut found = check(&todo);
                // Whatever the checker could not answer is remembered as unknown, not retried forever.
                for p in &todo {
                    found.entry(p.clone()).or_insert(Signature { status: SigStatus::Unknown, signer: None });
                }
                shared.write().set_signatures(found);
            }
            for _ in 0..30 {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locations() {
        assert!(suspicious_location(r"C:\Users\demo\AppData\Local\Temp\updater.exe"));
        assert!(suspicious_location(r"C:\Users\demo\Downloads\setup.exe"));
        assert!(suspicious_location("/tmp/x"));
        assert!(!suspicious_location(r"C:\Program Files\Google\Chrome\Application\chrome.exe"));
        assert!(!suspicious_location("/usr/bin/curl"));
    }

    #[test]
    fn signer_names() {
        assert_eq!(signer_from_subject("CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, C=US").as_deref(), Some("Microsoft Corporation"));
        assert_eq!(signer_from_subject("CN=Some Dev").as_deref(), Some("Some Dev"));
        assert_eq!(signer_from_subject("CN=Yandex, O=\"Yandex, LLC\", C=RU").as_deref(), Some("Yandex, LLC"));
        assert_eq!(signer_from_subject(""), None);
    }

    #[test]
    fn location_edge_cases() {
        for risky in [
            "C:/Users/x/Downloads/a.exe",
            r"C:\WINDOWS\TEMP\x.exe",
            r"c:\users\demo\appdata\local\temp\sub\dir\x.exe",
            r"C:\Users\Public\x.exe",
            r"C:\$Recycle.Bin\S-1-5-21\x.exe",
            r"D:\tmp\a.exe",
            r"\\server\share\Downloads\x.exe",
            "/var/tmp/x",
            "/dev/shm/x",
            "/tmp/x/y",
            "/home/u/Downloads/x",
        ] {
            assert!(suspicious_location(risky), "{risky}");
        }
        for fine in [
            "/tmp",
            "/tmpfoo/x",
            r"C:\Users\demo\Downloads",
            r"C:\Users\demo\DownloadsX\a.exe",
            r"C:\Users\demo\AppData\Local\Temporary\a.exe",
            r"C:\Users\demo\AppData\Local\Temp",
            r"C:\Program Files\tmp-tool\a.exe",
            r"C:\Windows\System32\svchost.exe",
            "/usr/local/bin/tmpwatch",
            "",
        ] {
            assert!(!suspicious_location(fine), "{fine}");
        }
    }

    #[test]
    fn signer_subject_edge_cases() {
        let s = signer_from_subject;
        assert_eq!(s("O=, CN=Dev").as_deref(), Some("Dev"), "an empty O falls back to CN");
        assert_eq!(s("CN=   "), None);
        assert_eq!(s("OU=Unit, CN=Name").as_deref(), Some("Name"), "OU is not O");
        assert_eq!(s("O=\"A, B\", CN=C").as_deref(), Some("A, B"));
        assert_eq!(s("CN=A ,O=B").as_deref(), Some("B"));
        assert_eq!(s("  O=Spaced  ").as_deref(), Some("Spaced"));
        assert_eq!(s("O = Spaced"), None, "no spaces around `=`");
        assert_eq!(s("o=lower"), None, "keys are case-sensitive");
        assert_eq!(s("O=\"Unbalanced, CN=X").as_deref(), Some("Unbalanced, CN=X"), "an open quote runs to the end");
        assert_eq!(s("CN=First, CN=Second").as_deref(), Some("First"));
        assert_eq!(s("C=US, ST=WA, L=Redmond"), None);
        assert_eq!(s("O=\"\", CN=\"\""), None);
        assert_eq!(s("CN=Yandex LLC, O=\"Yandex, LLC\", C=RU").as_deref(), Some("Yandex, LLC"));
        assert_eq!(s("CN=Ünïcödé Ltd, O=Ünïcödé Ltd.").as_deref(), Some("Ünïcödé Ltd."));
        assert_eq!(s(",,,O=X,,,").as_deref(), Some("X"));
    }

    #[test]
    fn powershell_path_is_absolute_when_system_root_is_known() {
        let p = powershell();
        if std::env::var_os("SystemRoot").is_some() {
            assert!(p.is_absolute() && p.ends_with(r"System32\WindowsPowerShell\v1.0\powershell.exe"), "{}", p.display());
            if cfg!(windows) {
                assert!(p.exists(), "{}", p.display());
            }
        } else {
            assert_eq!(p, PathBuf::from("powershell"));
        }
    }

    #[test]
    fn child_processes_are_killed_at_the_timeout() {
        fn cmd(program: &str, args: &[&str]) -> Command {
            let mut c = Command::new(program);
            c.args(args);
            c
        }
        let (quick, slow) = if cfg!(windows) {
            (cmd("cmd", &["/c", "echo hi"]), cmd("ping", &["-n", "30", "127.0.0.1"]))
        } else {
            (cmd("sh", &["-c", "echo hi"]), cmd("sleep", &["30"]))
        };
        let out = run_with_timeout(quick, Duration::from_secs(20)).unwrap();
        assert_eq!(String::from_utf8_lossy(&out).trim(), "hi");
        let started = Instant::now();
        assert!(run_with_timeout(slow, Duration::from_millis(500)).is_none());
        assert!(started.elapsed() < Duration::from_secs(10), "killed, not waited for: {:?}", started.elapsed());
        assert!(run_with_timeout(Command::new("netscope-no-such-program"), Duration::from_secs(1)).is_none());
    }

    #[cfg(windows)]
    #[test]
    fn checks_real_files() {
        let sys = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let notepad = format!(r"{sys}\System32\notepad.exe");
        let me = std::env::current_exe().unwrap().display().to_string();
        let r = check(&[notepad.clone(), me.clone(), r"C:\definitely\missing.exe".into()]);
        assert_eq!(r[&notepad].status, SigStatus::Signed, "{r:?}");
        assert!(r[&notepad].signer.as_deref().is_some_and(|s| s.contains("Microsoft")));
        assert_eq!(r[&me].status, SigStatus::Unsigned, "test binaries are not signed");
    }

    #[cfg(windows)]
    #[test]
    fn hostile_file_names_are_data_not_code() {
        // Typographic quotes end a single-quoted PowerShell string; `$(...)` would then run.
        let dir = std::env::temp_dir().join(format!("netscope-sig-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // File names cannot contain `\` or `:`, so the payload builds the marker path itself.
        let marker_name = format!("netscope-pwned-{}", std::process::id());
        let marker = std::env::temp_dir().join(&marker_name);
        let name = format!("a\u{2019}+$(New-Item -Path (Join-Path $env:TEMP '{marker_name}') -ItemType File)+\u{2019}'b.exe");
        let exe = dir.join(name);
        std::fs::write(&exe, b"MZ not really an exe").unwrap();
        let path = exe.display().to_string();
        let r = check(std::slice::from_ref(&path));
        assert!(!marker.exists(), "file name was executed as code");
        assert!(r.get(&path).is_some_and(|s| s.status != SigStatus::Signed), "{r:?}");
        std::fs::remove_dir_all(&dir).ok();
    }
}
