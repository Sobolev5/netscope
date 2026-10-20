//! Wiring: open the packet source, start the capture thread and the web server,
//! shut both down on Ctrl+C (or whatever `run_with` is told to wait for).

use std::collections::HashSet;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::analytics::{persist, CaptureInfo, CaptureStatus, Config, SharedState, State};
use crate::capture::engine::{self, Pacing};
use crate::capture::file::{is_pcapng_error, PcapFile};
use crate::capture::live::{default_route_ip, score, select_device, LiveOptions, Pcap};
use crate::capture::{CaptureError, PacketSource};
use crate::cli::Args;
use crate::demo::{DemoSource, LOCAL_IP};
use crate::geo::GeoDb;
use crate::netpath;
use crate::procs::{self, OsOwners, OwnerSource};
use crate::web;

pub struct Opened {
    pub source: Box<dyn PacketSource>,
    pub info: CaptureInfo,
    /// Addresses of this machine on the captured interface (empty if unknown).
    pub local: HashSet<IpAddr>,
    /// Advance the traffic clock with wall time (live sources).
    pub live_clock: bool,
    /// Who owns local sockets; `None` for capture files from other machines.
    pub owners: Option<Box<dyn OwnerSource>>,
}

fn info(mode: &'static str, source: String) -> CaptureInfo {
    CaptureInfo { mode, source, description: None, filter: None, libpcap: None, status: CaptureStatus::Starting }
}

/// Opens the source selected by the CLI. Errors carry installation/permission hints.
pub fn open_source(args: &Args) -> Result<Opened, CaptureError> {
    if args.demo {
        let mut i = info("demo", "synthetic traffic".into());
        i.description = Some("built-in demo generator".into());
        let demo = DemoSource::new();
        let owners: Box<dyn OwnerSource> = Box::new(demo.owners());
        return Ok(Opened {
            source: Box::new(demo),
            info: i,
            local: [IpAddr::from(LOCAL_IP)].into_iter().collect(),
            live_clock: true,
            owners: Some(owners),
        });
    }

    if let Some(path) = &args.read {
        let mut i = info("file", path.display().to_string());
        i.filter = args.filter.clone();
        // The built-in reader needs no libpcap; pcapng and BPF filters go through libpcap.
        if args.filter.is_none() {
            match PcapFile::open(path) {
                Ok(f) => return Ok(Opened { source: Box::new(f), info: i, local: HashSet::new(), live_clock: false, owners: None }),
                Err(e) if is_pcapng_error(&e) => tracing::info!("pcapng file, reading it through libpcap"),
                Err(e) => return Err(e),
            }
        }
        let pcap = Pcap::load()?;
        i.libpcap = Some(pcap.version());
        let h = pcap.open_offline(path, args.filter.as_deref())?;
        return Ok(Opened { source: Box::new(h), info: i, local: HashSet::new(), live_clock: false, owners: None });
    }

    let pcap = Pcap::load()?;
    let devices = pcap.devices()?;
    let dev = select_device(&devices, args.interface.as_deref(), default_route_ip())?;
    let opts = LiveOptions {
        snaplen: args.snaplen,
        promisc: !args.no_promisc,
        filter: args.filter.clone(),
        ..LiveOptions::default()
    };
    let handle = pcap.open_live(&dev.name, &opts)?;
    tracing::info!("capturing on {} ({}) with {}", dev.label(), dev.name, pcap.version());

    let mut i = info("live", dev.name.clone());
    i.description = dev.description.clone();
    i.filter = args.filter.clone();
    i.libpcap = Some(pcap.version());
    Ok(Opened {
        source: Box::new(handle),
        info: i,
        local: dev.addresses.iter().copied().collect(),
        live_clock: true,
        owners: Some(Box::new(OsOwners::default())),
    })
}

pub fn list_interfaces() -> Result<()> {
    let pcap = Pcap::load()?;
    let devices = pcap.devices()?;
    println!("{} — {}\n", pcap.library, pcap.version());
    if devices.is_empty() {
        println!("no interfaces visible; on Linux/macOS this usually means missing capture permissions");
        println!("  hint: {}", crate::capture::permission_hint());
        return Ok(());
    }
    let route = default_route_ip();
    let default = select_device(&devices, None, route).ok().map(|d| d.name);
    for (i, d) in devices.iter().enumerate() {
        let mark = if default.as_deref() == Some(d.name.as_str()) { "*" } else { " " };
        let mut flags = Vec::new();
        if d.up {
            flags.push("up");
        }
        if d.running {
            flags.push("running");
        }
        if d.loopback {
            flags.push("loopback");
        }
        if d.wireless {
            flags.push("wireless");
        }
        let addrs: Vec<String> = d.addresses.iter().map(IpAddr::to_string).collect();
        println!("{mark}{:>3}. {}", i + 1, d.label());
        println!("       name:  {}", d.name);
        println!("       addrs: {}", if addrs.is_empty() { "-".into() } else { addrs.join(", ") });
        println!("       flags: {}  (score {})", if flags.is_empty() { "-".into() } else { flags.join(", ") }, score(d, route));
    }
    if let Some(ip) = route {
        println!("\ninternet traffic currently leaves via {ip}");
    }
    println!("* = used by default; choose another with --interface <index|name|text>");
    Ok(())
}

/// Per-user directory for what netscope keeps between runs: `%LOCALAPPDATA%\NetScope`,
/// `$XDG_STATE_HOME/netscope` or `~/.local/state/netscope`; the temp dir when none is set.
pub fn data_dir() -> PathBuf {
    let var = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    let dir = if cfg!(windows) {
        var("LOCALAPPDATA").map(|d| d.join("NetScope"))
    } else {
        var("XDG_STATE_HOME").or_else(|| var("HOME").map(|h| h.join(".local").join("state"))).map(|d| d.join("netscope"))
    };
    dir.unwrap_or_else(|| std::env::temp_dir().join("netscope"))
}

/// Where the state file lives for these arguments; `None` with `--no-state`.
pub fn state_path(args: &Args) -> Option<PathBuf> {
    if args.no_state {
        return None;
    }
    Some(args.state.clone().unwrap_or_else(|| data_dir().join("state.json")))
}

/// Runs until Ctrl+C.
pub fn run(args: Args) -> Result<()> {
    run_with(args, shutdown_signal(), |_| {})
}

/// Runs until `shutdown` completes; `on_ready` gets the dashboard address once it listens.
pub fn run_with(
    args: Args,
    shutdown: impl Future<Output = ()> + Send + 'static,
    on_ready: impl FnOnce(SocketAddr) + Send + 'static,
) -> Result<()> {
    run_with_host(args, shutdown, on_ready, None)
}

/// `run_with` plus a `SettingsHost`: what the desktop application can do for the settings
/// page (restart with new settings, autostart) that a plain command-line run cannot.
pub fn run_with_host(
    args: Args,
    shutdown: impl Future<Output = ()> + Send + 'static,
    on_ready: impl FnOnce(SocketAddr) + Send + 'static,
    host: Option<Arc<dyn crate::settings::SettingsHost>>,
) -> Result<()> {
    if args.list_interfaces {
        return list_interfaces();
    }
    // Open the capture first so permission problems fail fast, before any server starts.
    let opened = open_source(&args)?;
    // Probes of the real machine make no sense for demo traffic or a replayed file.
    let live_capture = opened.info.mode == "live";

    let cfg = Config { spike_min_bytes: (args.spike_mib * 1024.0 * 1024.0) as u64, ..Config::default() };
    let mut state = State::new(cfg, opened.local, opened.info);
    let geo = GeoDb::open(args.geoip.as_deref());
    match geo.status() {
        s if geo.enabled() => tracing::info!("geolocation: city={} asn={} from {}", s.city, s.asn, s.dir.unwrap_or_default()),
        s => tracing::warn!("geolocation disabled: {}", s.note.unwrap_or_default()),
    }
    state.geo = Some(Arc::new(geo));
    let check_egress = live_capture && !args.no_egress_check;
    state.egress_enabled = check_egress;
    // Only a live capture learns about this machine: the demo and replayed files must
    // neither pollute the saved baseline nor be judged by it.
    let state_file = if live_capture { state_path(&args) } else { None };
    let mut loaded = None;
    if let Some(path) = &state_file {
        tracing::info!("state file: {}", path.display());
        match persist::load(path) {
            Ok(Some(p)) => {
                tracing::info!("restored {} watched routes and {} known programs", p.watch.len(), p.novelty.processes.len());
                state.restore(p.clone());
                loaded = Some(p);
            }
            Ok(None) => {}
            Err(e) => tracing::warn!("cannot load the saved state, starting fresh: {e}"),
        }
    }
    let shared = SharedState::new(state);
    let stop = Arc::new(AtomicBool::new(false));
    let pacing = if args.realtime { Pacing::Realtime } else { Pacing::Fast };
    let capture = engine::spawn(opened.source, shared.clone(), stop.clone(), pacing).context("starting capture thread")?;
    let egress = if check_egress { Some(netpath::spawn_egress_checker(shared.clone(), stop.clone()).context("starting egress check")?) } else { None };
    // Signatures only mean something for programs on this machine (live capture).
    let signatures = if live_capture {
        Some(procs::signature::spawn_checker(shared.clone(), stop.clone()).context("starting signature checker")?)
    } else {
        None
    };
    // Route watching probes the real network too: pointless for a replayed file or the demo.
    let watcher = if live_capture {
        Some(crate::trace::watch::spawn_watcher(shared.clone(), stop.clone()).context("starting route watcher")?)
    } else {
        None
    };
    let refresher = match opened.owners {
        Some(src) => Some(procs::spawn_refresher(src, shared.clone(), stop.clone()).context("starting process tracker")?),
        None => None,
    };
    // Its own stop flag: the final save must see what the capture thread recorded, so it is
    // asked for only once that thread is joined.
    let save_stop = Arc::new(AtomicBool::new(false));
    let saver = match &state_file {
        Some(path) => Some(persist::spawn_saver(shared.clone(), path.clone(), save_stop.clone(), loaded, persist::SAVE_INTERVAL).context("starting state saver")?),
        None => None,
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("starting async runtime")?;
    let served = runtime.block_on(async {
        let listener = web::bind_default(&args.host, args.port).await?;
        let addr = web::local_addr(&listener)?;
        if !is_loopback(&args.host) {
            tracing::warn!("dashboard is reachable from the network on {addr} and has no authentication");
        }
        let url = dashboard_url(addr);
        println!("netscope dashboard: {url}  (Ctrl+C to stop)");
        on_ready(addr);
        if args.open {
            open_in_browser(&url);
        }
        web::run_with_host(listener, shared.clone(), opened.live_clock, shutdown, host).await
    });

    stop.store(true, Ordering::Relaxed);
    // The capture loop wakes up at least every read timeout (200 ms) to see `stop`.
    if capture.join().is_err() {
        tracing::error!("capture thread panicked");
    }
    // Joined fully, unlike the other helpers: the final save is a quick local write and the
    // one thing that must not be lost on exit.
    save_stop.store(true, Ordering::Relaxed);
    if let Some(h) = saver {
        if h.join().is_err() {
            tracing::error!("state saver panicked");
        }
    }
    // The helpers may be inside slow blocking calls (a signature check, a traceroute, a
    // connect to a black-holed network); they are daemons, so do not make Ctrl+C wait.
    for (name, h) in [("process tracker", refresher), ("egress check", egress), ("signature checker", signatures), ("route watcher", watcher)] {
        if let Some(h) = h {
            join_with_grace(name, h, Duration::from_secs(2));
        }
    }
    runtime.shutdown_timeout(Duration::from_secs(2));
    served
}

/// Joins a helper thread, giving up (and leaving it to die with the process) after `grace`.
fn join_with_grace(name: &str, h: JoinHandle<()>, grace: Duration) {
    let start = Instant::now();
    while !h.is_finished() {
        if start.elapsed() > grace {
            tracing::debug!("{name} is still busy; not waiting for it");
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = h.join();
}

/// `http://127.0.0.1:8888`; a wildcard bind is shown as the loopback address.
pub fn dashboard_url(addr: SocketAddr) -> String {
    let shown = if addr.ip().is_unspecified() { SocketAddr::new(IpAddr::from([127, 0, 0, 1]), addr.port()) } else { addr };
    format!("http://{shown}")
}

/// Opens `url` in the user's default browser; failures only log, the URL is printed anyway.
pub fn open_in_browser(url: &str) {
    let result = if cfg!(windows) {
        // `start` is a cmd builtin; the empty string is the window title it expects first.
        let mut c = std::process::Command::new("cmd");
        c.args(["/C", "start", "", url]);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        c.spawn()
    } else if cfg!(target_os = "macos") {
        std::process::Command::new("open").arg(url).spawn()
    } else {
        std::process::Command::new("xdg-open").arg(url).spawn()
    };
    if let Err(e) = result {
        tracing::warn!("cannot open the browser: {e}");
    }
}

fn is_loopback(host: &str) -> bool {
    host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!("cannot listen for Ctrl+C: {e}");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("shutting down");
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn dashboard_urls_and_loopback_detection() {
        let url = |s: &str| dashboard_url(s.parse().unwrap());
        assert_eq!(url("0.0.0.0:8888"), "http://127.0.0.1:8888");
        assert_eq!(url("[::]:9000"), "http://127.0.0.1:9000", "an IPv6 wildcard is shown as the IPv4 loopback");
        assert_eq!(url("[::1]:80"), "http://[::1]:80");
        assert_eq!(url("192.168.1.5:1"), "http://192.168.1.5:1");
        assert_eq!(url("[fe80::1]:8888"), "http://[fe80::1]:8888");
        assert!(is_loopback("localhost") && is_loopback("127.0.0.1") && is_loopback("::1") && is_loopback("127.5.5.5"));
        for not in ["0.0.0.0", "::", "LOCALHOST", "192.168.1.1", "example.org", "", "127.0.0.1:8888"] {
            assert!(!is_loopback(not), "{not}");
        }
    }

    #[test]
    fn join_with_grace_waits_at_most_the_grace_period() {
        let done = std::thread::spawn(|| {});
        let t = Instant::now();
        join_with_grace("done", done, Duration::from_secs(5));
        assert!(t.elapsed() < Duration::from_secs(1), "a finished thread is joined immediately");
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let stuck = std::thread::spawn(move || {
            let _ = rx.recv();
        });
        let t = Instant::now();
        join_with_grace("stuck", stuck, Duration::from_millis(200));
        let waited = t.elapsed();
        assert!(waited >= Duration::from_millis(200) && waited < Duration::from_secs(2), "{waited:?}");
        drop(tx);
    }

    #[test]
    fn data_dir_and_state_path() {
        let d = data_dir();
        assert!(d.is_absolute(), "{}", d.display());
        assert_eq!(d.file_name().unwrap().to_str().unwrap().to_ascii_lowercase(), "netscope");
        let a = Args::try_parse_from(["netscope"]).unwrap();
        assert_eq!(state_path(&a), Some(d.join("state.json")));
        let a = Args::try_parse_from(["netscope", "--state", "custom.json"]).unwrap();
        assert_eq!(state_path(&a), Some(PathBuf::from("custom.json")));
        let a = Args::try_parse_from(["netscope", "--no-state"]).unwrap();
        assert_eq!(state_path(&a), None);
    }

    #[test]
    fn demo_run_returns_once_the_shutdown_future_is_ready() {
        // The demo never persists anything, even when told where to.
        let state_file = std::env::temp_dir().join(format!("netscope-app-{}-demo-state.json", std::process::id()));
        let _ = std::fs::remove_file(&state_file);
        let state_arg = state_file.to_str().unwrap().to_owned();
        let args = Args::try_parse_from(["netscope", "--demo", "--port", "0", "--no-egress-check", "--geoip", "definitely/missing", "--state", &state_arg]).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let t = Instant::now();
        let r = run_with(args, async {}, move |addr| {
            tx.send(addr).ok();
        });
        assert!(r.is_ok(), "{r:?}");
        let addr = rx.try_recv().expect("on_ready was called with the bound address");
        assert!(addr.ip().is_loopback() && addr.port() != 0, "{addr}");
        assert!(t.elapsed() < Duration::from_secs(8), "took {:?}", t.elapsed());
        assert!(!state_file.exists(), "--demo must not write a state file");
        // A source that cannot be opened fails before anything listens.
        let args = Args::try_parse_from(["netscope", "--read", "definitely-missing.pcap"]).unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<SocketAddr>();
        let e = run_with(args, async {}, move |a| {
            tx.send(a).ok();
        })
        .unwrap_err()
        .to_string();
        assert!(e.contains("definitely-missing.pcap"), "{e}");
        assert!(rx.try_recv().is_err(), "on_ready must not run when the source fails");
    }
}
