//! HTTP API, WebSocket stream and the embedded dashboard.
//!
//! A publisher task renders one JSON snapshot per second into a `watch` channel;
//! `/api/ws` clients and plain `/api/stats` requests share that rendering.

use std::future::Future;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, Request, State};
use axum::middleware::{self, Next};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;

mod css;
mod export;
mod metrics;

use crate::analytics::filter::{Filter, FilterError};
use crate::analytics::journal::{self, Kind};
use crate::analytics::views::CONN_FIELDS;
use crate::analytics::SharedState;
use crate::capture::engine::unix_now;
use crate::settings::{Settings, SettingsHost, SettingsPatch};

pub const INDEX_HTML: &str = include_str!("../../assets/index.html");
/// Natural Earth 1:110m land outlines (public domain) for the map, as TopoJSON.
const LAND_TOPOJSON: &str = include_str!("../../assets/land-110m.json");

const DEFAULT_HOSTS: usize = 50;
const DEFAULT_ALERTS: usize = 100;
const MAX_LIMIT: usize = 1000;

type TraceCache = Arc<std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, (std::time::Instant, Arc<crate::trace::Trace>)>>>;
/// The latest rendered snapshot, or why rendering failed.
type Feed = Result<Arc<str>, String>;

#[derive(Clone)]
struct AppState {
    shared: SharedState,
    feed: watch::Receiver<Feed>,
    stop: watch::Receiver<bool>,
    traces: TraceCache,
    /// Route traces are expensive (dozens of probe threads); only a few may run at once.
    trace_slots: Arc<tokio::sync::Semaphore>,
    /// What the program around us can do for the settings page (`None`: the plain CLI).
    host: Option<Arc<dyn SettingsHost>>,
    /// The address the dashboard listens on.
    bound: SocketAddr,
    settings_path: PathBuf,
    /// Where the journal files are (or would be) read from.
    journal_dir: PathBuf,
}

impl AppState {
    /// Days of journal kept: the live value, or the settings file's when no journal is attached.
    fn journal_days(&self) -> u32 {
        let live = self.shared.read().journal().map(|j| j.retention_days());
        live.unwrap_or_else(|| Settings::load(&self.settings_path).journal_days)
    }
}

/// Default dashboard port; without `--port`, the next free one is used when it is busy.
pub const DEFAULT_PORT: u16 = 8888;
/// How many ports above the default are tried before asking the OS for any free one.
const PORT_FALLBACKS: u16 = 12;

/// Binds the dashboard socket with actionable error messages.
pub async fn bind(host: &str, port: u16) -> Result<TcpListener> {
    TcpListener::bind((host, port)).await.map_err(|e| bind_error(host, port, e))
}

/// `port` when given; otherwise 8888, then 8889…8900, then whatever the OS has free.
pub async fn bind_default(host: &str, port: Option<u16>) -> Result<TcpListener> {
    if let Some(p) = port {
        return bind(host, p).await;
    }
    for p in (DEFAULT_PORT..=DEFAULT_PORT + PORT_FALLBACKS).chain([0]) {
        match TcpListener::bind((host, p)).await {
            Ok(l) => {
                if p != DEFAULT_PORT {
                    tracing::warn!("port {DEFAULT_PORT} is busy (another netscope?); using {}", l.local_addr().map_or(p, |a| a.port()));
                }
                return Ok(l);
            }
            Err(e) if e.kind() == ErrorKind::AddrInUse => continue,
            Err(e) => return Err(bind_error(host, p, e)),
        }
    }
    Err(anyhow!("no free port on {host}; pick one with --port"))
}

fn bind_error(host: &str, port: u16, e: std::io::Error) -> anyhow::Error {
    match e.kind() {
        ErrorKind::AddrInUse => anyhow!("port {port} on {host} is already in use; pick another one with --port"),
        ErrorKind::PermissionDenied => {
            anyhow!("not allowed to listen on {host}:{port} (ports below 1024 need extra privileges); use --port")
        }
        ErrorKind::AddrNotAvailable => anyhow!("{host} is not an address of this machine; check --host"),
        _ => anyhow!("cannot listen on {host}:{port}: {e}"),
    }
}

fn render(shared: &SharedState, hosts: usize, alerts: usize) -> Feed {
    let snap = shared.read().snapshot(hosts, alerts);
    serde_json::to_string(&snap).map(Arc::from).map_err(|e| format!("cannot render snapshot: {e}"))
}

/// Serves until `shutdown` resolves. `live_clock` advances the traffic clock every
/// second so rates fall to zero when the network goes quiet (live and demo modes).
pub async fn run(
    listener: TcpListener,
    shared: SharedState,
    live_clock: bool,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    run_with_host(listener, shared, live_clock, shutdown, None).await
}

/// `run` with the program's [`SettingsHost`]: restart and autostart on the settings page
/// work only through it, and it names the settings file. `None` is the plain CLI: the page
/// still reads and writes the default file, restart and autostart are reported unavailable.
pub async fn run_with_host(
    listener: TcpListener,
    shared: SharedState,
    live_clock: bool,
    shutdown: impl Future<Output = ()> + Send + 'static,
    host: Option<Arc<dyn SettingsHost>>,
) -> Result<()> {
    let bound = local_addr(&listener)?;
    let settings_path = host.as_ref().map_or_else(crate::settings::settings_path, |h| h.settings_path());
    let (feed_tx, feed_rx) = watch::channel(render(&shared, DEFAULT_HOSTS, DEFAULT_ALERTS));
    let (stop_tx, stop_rx) = watch::channel(false);

    let publisher = tokio::spawn({
        let shared = shared.clone();
        async move {
            let mut every = tokio::time::interval(Duration::from_secs(1));
            every.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                every.tick().await;
                if live_clock {
                    shared.write().advance(unix_now());
                }
                let shared = shared.clone();
                // Snapshotting sorts all hosts; keep it off the async workers.
                let Ok(json) = tokio::task::spawn_blocking(move || render(&shared, DEFAULT_HOSTS, DEFAULT_ALERTS)).await
                else {
                    break;
                };
                if feed_tx.send(json).is_err() {
                    break;
                }
            }
        }
    });

    let loopback_only = bound.ip().is_loopback();
    let journal_dir = shared.read().journal().map_or_else(|| crate::app::data_dir().join("journal"), |j| j.dir().to_path_buf());
    let state = AppState {
        shared,
        feed: feed_rx,
        stop: stop_rx,
        traces: TraceCache::default(),
        trace_slots: Arc::new(tokio::sync::Semaphore::new(MAX_PARALLEL_TRACES)),
        host,
        bound,
        settings_path,
        journal_dir,
    };
    let app = router(state, loopback_only);
    let graceful = async move {
        shutdown.await;
        // WebSocket handlers watch this and close, or graceful shutdown would wait on them forever.
        let _ = stop_tx.send(true);
    };
    let result = axum::serve(listener, app).with_graceful_shutdown(graceful).await;
    publisher.abort();
    result.map_err(|e| anyhow!("web server error: {e}"))
}

fn router(state: AppState, loopback_only: bool) -> Router {
    Router::new()
        .route("/api/settings", get(settings_get).post(settings_post))
        .route("/api/interfaces", get(interfaces))
        .route("/api/restart", post(restart))
        .route("/api/journal", get(journal_query))
        .route("/api/journal/stats", get(journal_stats))
        .route("/api/logs", get(logs))
        .route("/metrics", get(metrics_text))
        .route("/", get(index))
        .route("/static/land-110m.json", get(land))
        .route("/static/app.css", get(app_css))
        .route("/api/stats", get(stats))
        .route("/api/alerts", get(alerts))
        .route("/api/health", get(health))
        .route("/api/processes", get(processes))
        .route("/api/connections", get(connections))
        .route("/api/connections/{id}", get(connection))
        .route("/api/connections/{id}/packets/{n}", get(packet))
        .route("/api/connections/{id}/stream", get(stream))
        .route("/api/sockets", get(sockets))
        .route("/api/netpath", get(netpath))
        .route("/api/trace", get(trace_route))
        .route("/api/geo", get(geo))
        .route("/api/dns", get(dns))
        .route("/api/filter/fields", get(filter_fields))
        .route("/api/watch", get(watch_list).post(watch_add).delete(watch_remove))
        .route("/api/export/connections.csv", get(export_connections))
        .route("/api/export/hosts.csv", get(export_hosts))
        .route("/api/export/processes.csv", get(export_processes))
        .route("/api/export/dns.csv", get(export_dns))
        .route("/api/export/connections.pcap", get(export_pcap))
        .route("/api/connections/{id}/pcap", get(connection_pcap))
        .route("/api/ws", get(ws))
        .fallback(|| async { (StatusCode::NOT_FOUND, "not found") })
        .with_state(state)
        .layer(middleware::from_fn(api_errors))
        .layer(middleware::from_fn_with_state(loopback_only, guard))
}

fn forbidden(why: &str) -> Response {
    (StatusCode::FORBIDDEN, why.to_string()).into_response()
}

/// Every API error is `{"error":{"code","message"}}`, so the UI has one place to read it.
fn api_error(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    let body = serde_json::json!({ "error": { "code": code, "message": message.into() } });
    (status, [(header::CONTENT_TYPE, "application/json"), (header::CACHE_CONTROL, "no-store")], body.to_string()).into_response()
}

fn error_code(status: StatusCode) -> &'static str {
    match status {
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::TOO_MANY_REQUESTS => "rate_limited",
        s if s.is_client_error() => "bad_request",
        _ => "internal",
    }
}

/// Wraps the plain-text errors axum itself produces for `/api/*` (bad query strings,
/// wrong methods, unknown paths) in the JSON envelope; handler errors already have it.
async fn api_errors(req: Request, next: Next) -> Response {
    let api = req.uri().path().starts_with("/api/");
    let res = next.run(req).await;
    let status = res.status();
    if !api || !(status.is_client_error() || status.is_server_error()) {
        return res;
    }
    let is_json = res.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_some_and(|c| c.starts_with("application/json"));
    if is_json {
        return res;
    }
    let text = match axum::body::to_bytes(res.into_body(), 64 * 1024).await {
        Ok(b) => String::from_utf8_lossy(&b).trim().to_string(),
        Err(_) => String::new(),
    };
    let message = if text.is_empty() { status.canonical_reason().unwrap_or("error").to_string() } else { text };
    api_error(status, error_code(status), message)
}

/// Host part of a `Host` header or an origin URL, lowercased, without the port.
fn host_only(s: &str) -> String {
    let s = s.split("://").nth(1).unwrap_or(s);
    let s = s.split('/').next().unwrap_or(s);
    let host = if s.starts_with('[') { s.split(']').next().map(|h| format!("{h}]")).unwrap_or_default() } else { s.split(':').next().unwrap_or(s).to_string() };
    host.to_ascii_lowercase()
}

/// Keeps other web pages away from the API: the dashboard shows private traffic and can
/// start route traces, so a page the user happens to visit must not be able to use it.
/// * DNS rebinding: with a loopback bind only loopback `Host` names are accepted.
/// * Cross-site requests: browsers mark them with `Sec-Fetch-Site: cross-site`.
/// * WebSockets/POST/DELETE from other origins: `Origin` must match `Host`.
async fn guard(State(loopback_only): State<bool>, req: Request, next: Next) -> Response {
    let h = req.headers();
    let header = |name: header::HeaderName| h.get(name).and_then(|v| v.to_str().ok()).map(str::to_string);
    let host = header(header::HOST).unwrap_or_default();
    let fetch_site = header(header::HeaderName::from_static("sec-fetch-site"));
    let origin = header(header::ORIGIN);
    if loopback_only && !matches!(host_only(&host).as_str(), "localhost" | "127.0.0.1" | "[::1]") {
        return forbidden("unexpected Host header (possible DNS rebinding)");
    }
    if fetch_site.as_deref() == Some("cross-site") {
        return forbidden("cross-site requests are not allowed");
    }
    if let Some(origin) = origin {
        if origin != "null" && host_only(&origin) != host_only(&host) {
            return forbidden("origin does not match host");
        }
        if origin == "null" {
            return forbidden("opaque origin");
        }
    }
    next.run(req).await
}

async fn index() -> impl IntoResponse {
    (
        [
            (header::CACHE_CONTROL, "no-cache"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        Html(INDEX_HTML),
    )
}

/// The utility stylesheet, generated once from the page (see `css`).
async fn app_css() -> impl IntoResponse {
    static CSS: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let css = CSS.get_or_init(|| css::generate(INDEX_HTML)).as_str();
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8"), (header::CACHE_CONTROL, "no-cache")], css)
}

async fn land() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "application/json"), (header::CACHE_CONTROL, "public, max-age=86400")], LAND_TOPOJSON)
}

fn json(body: Arc<str>) -> Response {
    let mut res = body.to_string().into_response();
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

#[derive(Debug, Deserialize)]
struct Limits {
    hosts: Option<usize>,
    alerts: Option<usize>,
}

fn feed_response(feed: Feed) -> Response {
    match feed {
        Ok(body) => json(body),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", e),
    }
}

/// Latest snapshot; `?hosts=N&alerts=M` renders a fresh one with other limits.
async fn stats(State(s): State<AppState>, Query(q): Query<Limits>) -> Response {
    if q.hosts.is_none() && q.alerts.is_none() {
        return feed_response(s.feed.borrow().clone());
    }
    let hosts = q.hosts.unwrap_or(DEFAULT_HOSTS).min(MAX_LIMIT);
    let alerts = q.alerts.unwrap_or(DEFAULT_ALERTS).min(MAX_LIMIT);
    match tokio::task::spawn_blocking(move || render(&s.shared, hosts, alerts)).await {
        Ok(feed) => feed_response(feed),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", format!("snapshot failed: {e}")),
    }
}

async fn alerts(State(s): State<AppState>) -> Response {
    let body = {
        let st = s.shared.read();
        serde_json::json!({ "counts": st.alert_counts(), "alerts": st.alerts(MAX_LIMIT) })
    };
    json(body.to_string().into())
}

async fn health(State(s): State<AppState>) -> Response {
    let body = {
        let st = s.shared.read();
        serde_json::json!({ "status": "ok", "capture": st.capture.status, "now": st.now(), "version": env!("CARGO_PKG_VERSION") })
    };
    json(body.to_string().into())
}

fn to_json<T: serde::Serialize>(v: &T) -> Response {
    match serde_json::to_string(v) {
        Ok(s) => json(s.into()),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string()),
    }
}

fn not_found(what: &str) -> Response {
    api_error(StatusCode::NOT_FOUND, "not_found", format!("{what} not found (it may have been evicted)"))
}

fn bad_ip() -> Response {
    api_error(StatusCode::BAD_REQUEST, "bad_request", "ip must be an IPv4 or IPv6 address")
}

async fn processes(State(s): State<AppState>) -> Response {
    let v = s.shared.read().processes();
    to_json(&v)
}

#[derive(Debug, Deserialize)]
struct ConnQuery {
    /// Owner PID; 0 = connections without a known process.
    pid: Option<u32>,
    /// Filter expression, e.g. `process == chrome.exe and country != RU`.
    q: Option<String>,
    limit: Option<usize>,
}

/// Parses `?q=`; a syntax error becomes a 400 with `{error: {code: "filter", message, position}}`.
fn parse_filter(q: Option<&str>) -> Result<Option<Filter>, Box<Response>> {
    match q.map(str::trim).filter(|q| !q.is_empty()) {
        None => Ok(None),
        Some(text) => Filter::parse(text, CONN_FIELDS).map(Some).map_err(|e: FilterError| {
            let body = serde_json::json!({ "error": { "code": "filter", "message": e.message, "position": e.position } });
            Box::new((StatusCode::BAD_REQUEST, [(header::CONTENT_TYPE, "application/json"), (header::CACHE_CONTROL, "no-store")], body.to_string()).into_response())
        }),
    }
}

async fn connections(State(s): State<AppState>, Query(q): Query<ConnQuery>) -> Response {
    let filter = match parse_filter(q.q.as_deref()) {
        Ok(f) => f,
        Err(r) => return *r,
    };
    let (total, list) = s.shared.read().connections(q.pid, filter.as_ref(), q.limit.unwrap_or(300).min(5000));
    to_json(&serde_json::json!({ "total": total, "connections": list }))
}

async fn filter_fields() -> Response {
    let fields: Vec<_> = CONN_FIELDS.iter().map(|(name, aliases)| serde_json::json!({ "name": name, "aliases": aliases })).collect();
    to_json(&fields)
}

#[derive(Debug, Deserialize)]
struct DnsQuery {
    q: Option<String>,
    limit: Option<usize>,
}

async fn dns(State(s): State<AppState>, Query(q): Query<DnsQuery>) -> Response {
    let v = s.shared.read().dns(q.q.as_deref(), q.limit.unwrap_or(500).min(MAX_LIMIT * 5));
    to_json(&v)
}

#[derive(Debug, Deserialize)]
struct WatchQuery {
    ip: String,
    label: Option<String>,
}

async fn watch_list(State(s): State<AppState>) -> Response {
    let st = s.shared.read();
    to_json(&serde_json::json!({ "interval_secs": st.routes.interval_secs, "targets": st.routes.view() }))
}

async fn watch_add(State(s): State<AppState>, Query(q): Query<WatchQuery>) -> Response {
    let Ok(ip) = q.ip.trim().parse::<std::net::IpAddr>() else { return bad_ip() };
    if !s.shared.write().routes.add(ip, q.label, unix_now()) {
        return api_error(StatusCode::BAD_REQUEST, "limit", format!("at most {} routes can be watched; remove one first", crate::trace::watch::MAX_TARGETS));
    }
    watch_list(State(s)).await
}

async fn watch_remove(State(s): State<AppState>, Query(q): Query<WatchQuery>) -> Response {
    let Ok(ip) = q.ip.trim().parse::<std::net::IpAddr>() else { return bad_ip() };
    if !s.shared.write().routes.remove(&ip) {
        return not_found("watched route");
    }
    watch_list(State(s)).await
}

fn download(body: Vec<u8>, content_type: &'static str, filename: String) -> Response {
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (header::CONTENT_DISPOSITION, HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")).unwrap_or(HeaderValue::from_static("attachment"))),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        body,
    )
        .into_response()
}

fn stamp() -> String {
    export::utc(unix_now() * 1_000_000).replace([' ', ':'], "-")
}

async fn export_connections(State(s): State<AppState>, Query(q): Query<ConnQuery>) -> Response {
    let filter = match parse_filter(q.q.as_deref()) {
        Ok(f) => f,
        Err(r) => return *r,
    };
    let body = export::connections_csv(&s.shared.read(), q.pid, filter.as_ref());
    download(body.into_bytes(), "text/csv; charset=utf-8", format!("netscope-connections-{}.csv", stamp()))
}

async fn export_hosts(State(s): State<AppState>) -> Response {
    let body = export::hosts_csv(&s.shared.read());
    download(body.into_bytes(), "text/csv; charset=utf-8", format!("netscope-hosts-{}.csv", stamp()))
}

async fn export_processes(State(s): State<AppState>) -> Response {
    let body = export::processes_csv(&s.shared.read());
    download(body.into_bytes(), "text/csv; charset=utf-8", format!("netscope-processes-{}.csv", stamp()))
}

async fn export_dns(State(s): State<AppState>, Query(q): Query<DnsQuery>) -> Response {
    let body = export::dns_csv(&s.shared.read(), q.q.as_deref());
    download(body.into_bytes(), "text/csv; charset=utf-8", format!("netscope-dns-{}.csv", stamp()))
}

async fn export_pcap(State(s): State<AppState>, Query(q): Query<ConnQuery>) -> Response {
    let filter = match parse_filter(q.q.as_deref()) {
        Ok(f) => f,
        Err(r) => return *r,
    };
    let ids: Vec<u64> = s.shared.read().matching_flows(q.pid, filter.as_ref()).iter().map(|f| f.id).collect();
    pcap_download(s.shared, ids, format!("netscope-{}.pcap", stamp())).await
}

/// Copies and serializes the frames off the async workers, locking the state only briefly.
async fn pcap_download(shared: SharedState, ids: Vec<u64>, name: String) -> Response {
    match tokio::task::spawn_blocking(move || export::pcap_frames(&shared, &ids).write()).await {
        Ok(Ok(b)) => download(b, "application/vnd.tcpdump.pcap", name),
        Ok(Err(e)) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string()),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string()),
    }
}

async fn connection_pcap(State(s): State<AppState>, Path(id): Path<u64>) -> Response {
    if s.shared.read().flow(id).is_none() {
        return not_found("connection");
    }
    pcap_download(s.shared, vec![id], format!("netscope-connection-{id}.pcap")).await
}

async fn connection(State(s): State<AppState>, Path(id): Path<u64>) -> Response {
    let v = s.shared.read().connection_detail(id);
    v.map_or_else(|| not_found("connection"), |d| to_json(&d))
}

async fn packet(State(s): State<AppState>, Path((id, n)): Path<(u64, u64)>) -> Response {
    let v = s.shared.read().packet_detail(id, n);
    v.map_or_else(|| not_found("packet"), |d| to_json(&d))
}

async fn stream(State(s): State<AppState>, Path(id): Path<u64>) -> Response {
    let v = s.shared.read().stream(id);
    v.map_or_else(|| not_found("connection"), |d| to_json(&d))
}

#[derive(Debug, Deserialize)]
struct SockQuery {
    pid: Option<u32>,
}

async fn sockets(State(s): State<AppState>, Query(q): Query<SockQuery>) -> Response {
    let v = s.shared.read().sockets(q.pid);
    to_json(&v)
}

async fn netpath(State(s): State<AppState>) -> Response {
    let v = s.shared.read().netpath();
    to_json(&v)
}

#[derive(Debug, Deserialize)]
struct TraceQuery {
    ip: String,
    /// Ignore a cached result.
    fresh: Option<bool>,
}

const TRACE_TTL: Duration = Duration::from_secs(300);
/// A `fresh` trace of the same address is not repeated more often than this.
const TRACE_MIN_INTERVAL: Duration = Duration::from_secs(15);
const MAX_PARALLEL_TRACES: usize = 2;

/// Traces the route to `ip` (takes a few seconds); results are cached for 5 minutes.
async fn trace_route(State(s): State<AppState>, Query(q): Query<TraceQuery>) -> Response {
    let Ok(ip) = q.ip.trim().parse::<std::net::IpAddr>() else { return bad_ip() };
    let max_age = if q.fresh.unwrap_or(false) { TRACE_MIN_INTERVAL } else { TRACE_TTL };
    let hit = s.traces.lock().ok().and_then(|c| c.get(&ip).filter(|(t, _)| t.elapsed() < max_age).map(|(_, r)| r.clone()));
    if let Some(r) = hit {
        return to_json(r.as_ref());
    }
    let Ok(_slot) = s.trace_slots.clone().try_acquire_owned() else {
        return api_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "too many route traces running; try again in a few seconds");
    };
    let geo = s.shared.read().geo.clone();
    match tokio::task::spawn_blocking(move || crate::trace::trace(ip, geo.as_deref())).await {
        Ok(t) => {
            let t = Arc::new(t);
            if let Ok(mut c) = s.traces.lock() {
                c.retain(|_, (at, _)| at.elapsed() < TRACE_TTL);
                c.insert(ip, (std::time::Instant::now(), t.clone()));
            }
            to_json(t.as_ref())
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", format!("trace failed: {e}")),
    }
}

#[derive(Debug, Deserialize)]
struct GeoQuery {
    ip: String,
}

async fn geo(State(s): State<AppState>, Query(q): Query<GeoQuery>) -> Response {
    let Ok(ip) = q.ip.trim().parse::<std::net::IpAddr>() else { return bad_ip() };
    let g = s.shared.read().geo.clone();
    to_json(&serde_json::json!({ "ip": ip, "geo": g.as_ref().and_then(|g| g.lookup(ip)), "status": g.as_ref().map(|g| g.status()) }))
}

async fn ws(upgrade: WebSocketUpgrade, State(s): State<AppState>) -> Response {
    upgrade.on_upgrade(move |socket| client(socket, s.feed, s.stop))
}

async fn client(mut socket: WebSocket, mut feed: watch::Receiver<Feed>, mut stop: watch::Receiver<bool>) {
    // A snapshot that failed to render is simply not streamed; the client keeps the last good one.
    let first = feed.borrow_and_update().clone();
    if let Ok(first) = first {
        if socket.send(Message::text(first.to_string())).await.is_err() {
            return;
        }
    }
    loop {
        tokio::select! {
            changed = feed.changed() => {
                if changed.is_err() {
                    break;
                }
                let msg = feed.borrow_and_update().clone();
                if let Ok(msg) = msg {
                    if socket.send(Message::text(msg.to_string())).await.is_err() {
                        break;
                    }
                }
            }
            incoming = socket.recv() => match incoming {
                // Pings are answered by axum; other client messages are ignored.
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(_)) => {}
            },
            _ = stop.changed() => {
                let _ = socket.send(Message::Close(None)).await;
                break;
            }
        }
    }
}

// ----- journal, metrics, logs -----

#[derive(Debug, Deserialize)]
struct JournalQuery {
    kind: Option<String>,
    /// Unix seconds, inclusive.
    from: Option<i64>,
    to: Option<i64>,
    /// Case-insensitive substring of the record's JSON.
    q: Option<String>,
    limit: Option<usize>,
    /// `json` (default), `jsonl` or `csv`.
    format: Option<String>,
}

/// Journal records of one kind, newest first; `jsonl` and `csv` are downloads.
async fn journal_query(State(s): State<AppState>, Query(q): Query<JournalQuery>) -> Response {
    let Some(kind) = q.kind.as_deref().and_then(Kind::parse) else {
        return api_error(StatusCode::BAD_REQUEST, "bad_request", "kind must be connections, dns or alerts");
    };
    let format = q.format.as_deref().unwrap_or("json");
    if !matches!(format, "json" | "jsonl" | "csv") {
        return api_error(StatusCode::BAD_REQUEST, "bad_request", "format must be json, jsonl or csv");
    }
    let limit = q.limit.unwrap_or(journal::DEFAULT_LIMIT).min(journal::MAX_LIMIT);
    let now = unix_now();
    let to = q.to.unwrap_or(now);
    // Default range: the days kept, i.e. today and `journal_days` days before it.
    let from = q.from.unwrap_or_else(|| journal::day_start(now) - i64::from(s.journal_days()) * 86_400);
    if from > to {
        return api_error(StatusCode::BAD_REQUEST, "bad_request", "from must not be after to");
    }
    let dir = s.journal_dir.clone();
    let text = q.q.clone();
    let result = tokio::task::spawn_blocking(move || journal::query(&dir, kind, Some(from), Some(to), text.as_deref(), limit)).await;
    let r = match result {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", format!("cannot read the journal: {e}")),
        Err(e) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string()),
    };
    match format {
        "jsonl" => download(export::journal_jsonl(&r.records).into_bytes(), "application/x-ndjson", format!("netscope-{}-{}.jsonl", kind.as_str(), stamp())),
        "csv" => download(export::journal_csv(kind, &r.records).into_bytes(), "text/csv; charset=utf-8", format!("netscope-{}-{}.csv", kind.as_str(), stamp())),
        _ => to_json(&serde_json::json!({ "kind": kind, "from": from, "to": to, "total": r.total, "records": r.records })),
    }
}

/// Day files on disk plus the live journal's retention, queue and drop counters.
async fn journal_stats(State(s): State<AppState>) -> Response {
    let dir = s.journal_dir.clone();
    let stats = match tokio::task::spawn_blocking(move || journal::stats(&dir)).await {
        Ok(st) => st,
        Err(e) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string()),
    };
    let (days_kept, enabled, pending, dropped) = {
        let st = s.shared.read();
        match st.journal() {
            Some(j) => (j.retention_days(), j.enabled(), j.pending(), j.dropped()),
            None => (Settings::load(&s.settings_path).journal_days, false, 0, 0),
        }
    };
    let mut v = match serde_json::to_value(&stats) {
        Ok(v) => v,
        Err(e) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string()),
    };
    if let Some(o) = v.as_object_mut() {
        o.insert("days_kept".into(), days_kept.into());
        o.insert("enabled".into(), enabled.into());
        o.insert("pending".into(), pending.into());
        o.insert("dropped".into(), dropped.into());
    }
    to_json(&v)
}

/// Prometheus text exposition of the counters (one read lock, no snapshot).
async fn metrics_text(State(s): State<AppState>) -> Response {
    let body = metrics::render(&s.shared.read());
    ([(header::CONTENT_TYPE, metrics::CONTENT_TYPE), (header::CACHE_CONTROL, "no-store")], body).into_response()
}

#[derive(Debug, Deserialize)]
struct LogsQuery {
    lines: Option<usize>,
}

const DEFAULT_LOG_LINES: usize = 200;
const MAX_LOG_LINES: usize = 5000;
/// Only this much of the end of the log file is read.
const LOG_TAIL_BYTES: u64 = 4 << 20;

/// The last `n` lines of the file; `Ok(empty)` when it does not exist.
fn tail_lines(path: &std::path::Path, n: usize) -> std::io::Result<Vec<String>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let len = f.metadata()?.len();
    let start = len.saturating_sub(LOG_TAIL_BYTES);
    f.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)?;
    let text = String::from_utf8_lossy(&bytes);
    let mut lines: Vec<&str> = text.lines().collect();
    if start > 0 {
        // The first line is most likely cut in the middle.
        lines.remove(0);
    }
    let skip = lines.len().saturating_sub(n);
    Ok(lines[skip..].iter().map(|l| l.to_string()).collect())
}

/// The end of the program's own log file (`{"file":null,"lines":[]}` when it has none).
async fn logs(State(s): State<AppState>, Query(q): Query<LogsQuery>) -> Response {
    let n = q.lines.unwrap_or(DEFAULT_LOG_LINES).min(MAX_LOG_LINES);
    let Some(path) = s.host.as_deref().and_then(SettingsHost::log_path) else {
        return to_json(&serde_json::json!({ "file": null, "lines": [] }));
    };
    let shown = path.display().to_string();
    match tokio::task::spawn_blocking(move || tail_lines(&path, n)).await {
        Ok(Ok(lines)) => to_json(&serde_json::json!({ "file": shown, "lines": lines })),
        Ok(Err(e)) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", format!("cannot read {shown}: {e}")),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string()),
    }
}

// ----- settings page -----

fn settings_values(s: &Settings) -> serde_json::Value {
    serde_json::json!({
        "port": s.port,
        "host": s.host,
        "interface": s.interface,
        "filter": s.filter,
        "geoip": s.geoip.as_ref().map(|p| p.display().to_string()),
        "egress_check": s.egress_check,
        "promiscuous": s.promiscuous,
        "verbose": s.verbose,
        "show_window": s.show_window,
        "notifications": s.notifications,
        "notify_categories": s.notify_categories.iter().map(|c| c.name()).collect::<Vec<_>>(),
        "notify_snooze_until": s.notify_snooze_until,
        "journal_days": s.journal_days,
    })
}

/// The settings file, what the running program actually uses, and what the host can do.
async fn settings_get(State(s): State<AppState>) -> Response {
    let values = Settings::load(&s.settings_path);
    let (active, geo, journal) = {
        let st = s.shared.read();
        let c = &st.capture;
        let active = serde_json::json!({
            "interface": c.source,
            "interface_description": c.description,
            "host": s.bound.ip().to_string(),
            "port": s.bound.port(),
            "mode": c.mode,
        });
        let (days, enabled) = st.journal().map_or((values.journal_days, false), |j| (j.retention_days(), j.enabled()));
        let journal = serde_json::json!({ "dir": s.journal_dir.display().to_string(), "days": days, "enabled": enabled });
        (active, st.geo.as_ref().map(|g| (g.enabled(), g.status())), journal)
    };
    let geo = match geo {
        Some((enabled, st)) => serde_json::json!({ "enabled": enabled, "dir": st.dir, "note": st.note }),
        None => serde_json::json!({ "enabled": false, "dir": null, "note": null }),
    };
    let host = s.host.as_deref();
    to_json(&serde_json::json!({
        "file": s.settings_path.display().to_string(),
        "values": settings_values(&values),
        "active": active,
        "autostart": host.and_then(SettingsHost::autostart),
        "can_restart": host.is_some_and(SettingsHost::can_restart),
        "from_cli": host.is_none_or(SettingsHost::started_from_cli),
        "geoip": geo,
        "journal": journal,
        "api": { "base": crate::app::dashboard_url(s.bound), "metrics": "/metrics" },
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

#[derive(Debug, Deserialize)]
struct SettingsPost {
    #[serde(flatten)]
    patch: SettingsPatch,
    /// Start with the user's session (desktop app only).
    autostart: Option<bool>,
}

/// Parses the body; a wrongly typed value is reported with its field name (serde's own
/// message only has a position in the text).
fn parse_settings_post(body: &[u8]) -> Result<SettingsPost, String> {
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|e| format!("settings must be a JSON object: {e}"))?;
    let Some(map) = value.as_object() else { return Err("settings must be a JSON object".into()) };
    match serde_json::from_value::<SettingsPost>(value.clone()) {
        Ok(p) => Ok(p),
        Err(e) => {
            for (k, v) in map {
                if let Err(fe) = serde_json::from_value::<SettingsPost>(serde_json::json!({ k: v })) {
                    return Err(format!("{k}: {fe}"));
                }
            }
            Err(e.to_string())
        }
    }
}

/// Validates and saves a patch. `restart_required` compares the new file with the previous
/// file content, not with the live run: a change made by hand and not yet applied by a
/// restart is therefore not reported again — an approximation that keeps the server
/// unaware of how it was started.
async fn settings_post(State(s): State<AppState>, body: Bytes) -> Response {
    let post = match parse_settings_post(&body) {
        Ok(p) => p,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, "bad_request", e),
    };
    let host = s.host.as_deref();
    // Checked before anything is written, so a rejected request leaves the file alone.
    if post.autostart.is_some() && host.and_then(SettingsHost::autostart).is_none() {
        return api_error(StatusCode::BAD_REQUEST, "bad_request", "autostart is not available here");
    }
    let previous = Settings::load(&s.settings_path);
    let mut next = previous.clone();
    if let Err(e) = next.apply(&post.patch) {
        return api_error(StatusCode::BAD_REQUEST, "bad_request", e);
    }
    if let Err(e) = next.save(&s.settings_path) {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", e);
    }
    // The journal retention is read on the fly: apply it to the running journal at once.
    if let Some(j) = s.shared.read().journal() {
        j.set_retention_days(next.journal_days);
    }
    if let (Some(on), Some(h)) = (post.autostart, host) {
        if let Err(e) = h.set_autostart(on) {
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", format!("settings saved, but autostart could not be changed: {e}"));
        }
    }
    to_json(&serde_json::json!({ "saved": true, "restart_required": next.needs_restart(&previous) }))
}

/// Capture interfaces as libpcap sees them; an empty list when libpcap is unavailable
/// (the reason goes to the log, the page shows the free-text field either way).
async fn interfaces() -> Response {
    use crate::capture::live::{default_route_ip, select_device, Pcap};
    let listed = tokio::task::spawn_blocking(|| -> Result<Vec<serde_json::Value>, crate::capture::CaptureError> {
        let pcap = Pcap::load()?;
        let devices = pcap.devices()?;
        let default = select_device(&devices, None, default_route_ip()).ok().map(|d| d.name);
        Ok(devices
            .iter()
            .map(|d| {
                serde_json::json!({
                    "name": d.name,
                    "description": d.description,
                    "addresses": d.addresses.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "up": d.up,
                    "loopback": d.loopback,
                    "default": default.as_deref() == Some(d.name.as_str()),
                })
            })
            .collect())
    })
    .await;
    match listed {
        Ok(Ok(list)) => to_json(&list),
        Ok(Err(e)) => {
            tracing::warn!("cannot list capture interfaces: {e}");
            to_json(&Vec::<serde_json::Value>::new())
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", format!("interface listing failed: {e}")),
    }
}

/// Asks the host program to restart with the saved settings.
async fn restart(State(s): State<AppState>) -> Response {
    let Some(host) = s.host.as_deref().filter(|h| h.can_restart()) else {
        return api_error(StatusCode::BAD_REQUEST, "bad_request", "restart is not available here; restart NetScope manually");
    };
    match host.request_restart() {
        Ok(()) => {
            let mut res = to_json(&serde_json::json!({ "restarting": true }));
            *res.status_mut() = StatusCode::ACCEPTED;
            res
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", e),
    }
}

/// Address actually bound (useful with port 0).
pub fn local_addr(listener: &TcpListener) -> Result<SocketAddr> {
    Ok(listener.local_addr()?)
}
