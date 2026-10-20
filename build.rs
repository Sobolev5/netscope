//! Embeds the icon, version information and manifest into the Windows executables.
//!
//! `assets/netscope.rc` is a template (`@VERSION@`, `@FILENAME@`, …) filled in per binary
//! and compiled with the toolchain's resource compiler (`windres` for GNU, `rc.exe` for
//! MSVC). When neither is available the build still succeeds, just without an icon.
//! (The application manifest comes from rustc; adding another one makes the linker fail.)

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/netscope.rc");
    println!("cargo:rerun-if-changed=assets/netscope.ico");
    println!("cargo:rerun-if-changed=assets/webview2/WebView2Loader.dll");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    if let Err(e) = copy_webview2_loader(&out) {
        println!("cargo:warning=WebView2Loader.dll not copied next to the binaries: {e}");
    }
    let gnu = env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu");
    let version = env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let mut parts = version.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    let numeric = format!("{},{},{},0", parts.next().unwrap_or(0), parts.next().unwrap_or(0), parts.next().unwrap_or(0));
    let template = fs::read_to_string("assets/netscope.rc").expect("assets/netscope.rc");
    let bins = [
        ("netscope", "netscope.exe", "NetScope network analyzer (command line)"),
        ("netscope-app", "netscope-app.exe", "NetScope network analyzer"),
    ];
    for (bin, file, description) in bins {
        let rc = out.join(format!("{bin}.rc"));
        let res = out.join(format!("{bin}.res"));
        // rustc links a default manifest for both toolchains; a second one would clash.
        let manifest = "";
        let text = template
            .replace("@NUMERIC@", &numeric)
            .replace("@VERSION@", &version)
            .replace("@FILENAME@", file)
            .replace("@DESCRIPTION@", description)
            .replace("@MANIFEST@", manifest);
        fs::write(&rc, text).expect("writing the resource script");
        let ok = if gnu { windres(&rc, &res) } else { rc_exe(&rc, &res) };
        match ok {
            Ok(()) => println!("cargo:rustc-link-arg-bin={bin}={}", res.display()),
            Err(e) => println!("cargo:warning=no icon/version resource for {bin}: {e}"),
        }
    }
}

/// Puts `assets/webview2/WebView2Loader.dll` next to the binaries: `netscope-app` loads it
/// from its own directory only. `OUT_DIR` is `<target>/<profile>/build/<pkg>-<hash>/out`,
/// so the profile directory is three levels up; the name is checked against `PROFILE`
/// (custom profiles and unusual layouts are skipped rather than guessed).
fn copy_webview2_loader(out_dir: &Path) -> Result<(), String> {
    let src = Path::new("assets/webview2/WebView2Loader.dll");
    if !src.exists() {
        return Err(format!("{} does not exist", src.display()));
    }
    let profile = env::var("PROFILE").map_err(|e| format!("PROFILE: {e}"))?;
    let profile_dir = out_dir.ancestors().nth(3).ok_or("OUT_DIR has no profile directory")?;
    if profile_dir.file_name().and_then(|n| n.to_str()) != Some(profile.as_str()) {
        return Err(format!("{} is not the `{profile}` directory", profile_dir.display()));
    }
    let dst = profile_dir.join("WebView2Loader.dll");
    let same = match (fs::metadata(src), fs::metadata(&dst)) {
        (Ok(a), Ok(b)) => a.len() == b.len() && a.modified().ok() == b.modified().ok(),
        _ => false,
    };
    if same {
        return Ok(());
    }
    fs::copy(src, &dst).map(|_| ()).map_err(|e| format!("copying to {}: {e}", dst.display()))
}

fn windres(rc: &Path, res: &Path) -> Result<(), String> {
    let mut c = Command::new("windres");
    c.args(["--include-dir", "assets", "-O", "coff", "-i"]).arg(rc).arg("-o").arg(res);
    run(c)
}

fn rc_exe(rc: &Path, res: &Path) -> Result<(), String> {
    let mut c = Command::new("rc.exe");
    c.args(["/nologo", "/i", "assets"]).arg(format!("/fo{}", res.display())).arg(rc);
    run(c)
}

fn run(mut c: Command) -> Result<(), String> {
    match c.output() {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(format!("{:?} failed: {}{}", c.get_program(), String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))),
        Err(e) => Err(format!("{:?} not available: {e}", c.get_program())),
    }
}
