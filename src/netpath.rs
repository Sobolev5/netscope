//! "Where does my traffic leave?": the public egress address (one plain HTTP request
//! to Cloudflare's trace endpoint), VPN/proxy tunnels found through the sockets of
//! VPN client processes, and traffic per destination country.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::analytics::SharedState;
use crate::capture::engine::unix_now;
use crate::geo::GeoInfo;

/// Plain-HTTP trace endpoints tried in order (1.1.1.1 now redirects HTTP to HTTPS on some edges).
const TRACE_HOSTS: &[&str] = &["cloudflare.com", "1.1.1.1", "one.one.one.one"];
const RECHECK: Duration = Duration::from_secs(600);

/// Process name fragments of VPN / proxy clients (lowercase).
const VPN_CLIENTS: &[&str] = &[
    "vpnagent", "anyconnect", "openvpn", "wireguard", "tailscale", "zerotier", "nordvpn", "expressvpn",
    "protonvpn", "surfshark", "windscribe", "mullvad", "forticlient", "fortitray", "pangps", "globalprotect",
    "happ", "hiddify", "v2ray", "xray", "sing-box", "clash", "nekoray", "outline", "amnezia", "warp-svc",
    "cloudflared", "psiphon", "lantern", "shadowsocks", "ss-local", "trojan", "adguardvpn", "kaspersky vpn",
];

/// Interface description fragments of virtual tunnel adapters (lowercase).
const TUNNEL_ADAPTERS: &[&str] = &[
    "anyconnect", "vpn", "tap-windows", "wintun", "wireguard", "tunnel", "openvpn", "fortinet", "pangp", "zerotier",
    "tailscale", "tun",
];

pub fn is_vpn_process(name: &str) -> bool {
    let n = name.to_lowercase();
    VPN_CLIENTS.iter().any(|k| n.contains(k))
}

pub fn is_tunnel_adapter(description: &str) -> bool {
    let d = description.to_lowercase();
    TUNNEL_ADAPTERS.iter().any(|k| d.contains(k))
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Egress {
    pub ip: String,
    /// Cloudflare data centre that answered (IATA airport code).
    pub colo: Option<String>,
    /// Country Cloudflare sees the address in.
    pub loc: Option<String>,
    pub geo: Option<GeoInfo>,
    pub checked_at: i64,
}

/// Parses `key=value` lines of /cdn-cgi/trace.
pub fn parse_cf_trace(body: &str) -> Option<Egress> {
    let get = |k: &str| body.lines().find_map(|l| l.strip_prefix(k).and_then(|v| v.strip_prefix('='))).map(|v| v.trim().to_string());
    let ip = get("ip").filter(|ip| ip.parse::<std::net::IpAddr>().is_ok())?;
    Some(Egress { ip, colo: get("colo"), loc: get("loc"), geo: None, checked_at: 0 })
}

/// Per host: TCP connect, and the whole read; the check must finish (or give up) within
/// seconds so shutdown is not held up by an unreachable network.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const READ_TIMEOUT: Duration = Duration::from_secs(4);

/// Asks Cloudflare which public address our traffic comes from; gives up early once `stop` is set.
pub fn check_egress(stop: &AtomicBool) -> Result<Egress, String> {
    let mut errors = Vec::new();
    for host in TRACE_HOSTS {
        if stop.load(Ordering::Relaxed) {
            errors.push("stopped".into());
            break;
        }
        match check_host(host) {
            Ok(e) => return Ok(e),
            Err(e) => errors.push(format!("{host}: {e}")),
        }
    }
    Err(errors.join("; "))
}

fn check_host(host: &str) -> Result<Egress, String> {
    let addr = (host, 80).to_socket_addrs().map_err(|e| e.to_string())?.next().ok_or("no address")?;
    let mut s = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).map_err(|e| format!("cannot connect: {e}"))?;
    s.set_read_timeout(Some(READ_TIMEOUT)).ok();
    s.set_write_timeout(Some(CONNECT_TIMEOUT)).ok();
    s.write_all(format!("GET /cdn-cgi/trace HTTP/1.1\r\nHost: {host}\r\nUser-Agent: netscope\r\nConnection: close\r\n\r\n").as_bytes())
        .map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let started = Instant::now();
    while buf.len() < 64 * 1024 && started.elapsed() < READ_TIMEOUT {
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let body = text.split_once("\r\n\r\n").map_or(text.as_ref(), |(_, b)| b);
    let status = text.lines().next().unwrap_or("").to_string();
    let mut e = parse_cf_trace(body).ok_or_else(|| format!("unexpected answer `{status}`"))?;
    e.checked_at = unix_now();
    Ok(e)
}

/// Re-checks the egress address every 10 minutes until `stop`.
pub fn spawn_egress_checker(shared: SharedState, stop: Arc<AtomicBool>) -> std::io::Result<JoinHandle<()>> {
    thread::Builder::new().name("egress".into()).spawn(move || {
        let mut last: Option<Instant> = None;
        while !stop.load(Ordering::Relaxed) {
            if last.is_none_or(|t| t.elapsed() >= RECHECK) {
                let r = check_egress(&stop);
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                if let Err(e) = &r {
                    tracing::warn!("egress check: {e}");
                }
                shared.write().set_egress(r);
                last = Some(Instant::now());
            }
            thread::sleep(Duration::from_millis(200));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_trace_body() {
        let body = "fl=12f1\nh=1.1.1.1\nip=203.0.113.9\nts=1760000000.1\nvisit_scheme=http\ncolo=FRA\nloc=DE\ntls=off\n";
        let e = parse_cf_trace(body).unwrap();
        assert_eq!((e.ip.as_str(), e.colo.as_deref(), e.loc.as_deref()), ("203.0.113.9", Some("FRA"), Some("DE")));
        assert!(parse_cf_trace("<html>blocked</html>").is_none());
        assert!(parse_cf_trace("ip=not-an-ip").is_none());
    }

    #[test]
    fn malformed_trace_bodies() {
        assert!(parse_cf_trace("").is_none());
        assert!(parse_cf_trace("ip=").is_none());
        assert!(parse_cf_trace("ip").is_none());
        assert!(parse_cf_trace("IP=1.2.3.4").is_none(), "keys are case-sensitive");
        assert!(parse_cf_trace(" ip=1.2.3.4").is_none(), "no leading whitespace in the key");
        assert!(parse_cf_trace("ip=1.2.3.4.5\ncolo=FRA").is_none());
        assert!(parse_cf_trace("ip=1.2.3.4:443").is_none(), "a socket address is not an address");
        let e = parse_cf_trace("ipv6=no\nip= 203.0.113.9 \r\nts=1\r\ncolo=FRA\r\n").unwrap();
        assert_eq!((e.ip.as_str(), e.colo.as_deref(), e.loc), ("203.0.113.9", Some("FRA"), None), "CRLF and padding tolerated, `ipv6` is not `ip`");
        let e = parse_cf_trace("ip=2001:db8::1\nloc=DE").unwrap();
        assert_eq!((e.ip.as_str(), e.colo, e.loc.as_deref()), ("2001:db8::1", None, Some("DE")));
        let e = parse_cf_trace("ip=1.1.1.1\nip=2.2.2.2\ncolo=A\ncolo=B").unwrap();
        assert_eq!((e.ip.as_str(), e.colo.as_deref()), ("1.1.1.1", Some("A")), "first occurrence wins");
        assert_eq!((e.geo, e.checked_at), (None, 0));
        let e = parse_cf_trace("<html>\nip=9.9.9.9\n</html>").unwrap();
        assert_eq!(e.ip, "9.9.9.9", "the body may be wrapped in junk");
        let e = parse_cf_trace(&format!("{}ip=8.8.8.8\n", "x=y\n".repeat(10_000))).unwrap();
        assert_eq!(e.ip, "8.8.8.8");
    }

    #[test]
    fn stop_ends_the_check_before_any_network_access() {
        let started = Instant::now();
        let err = check_egress(&AtomicBool::new(true)).unwrap_err();
        assert_eq!(err, "stopped");
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(CONNECT_TIMEOUT <= Duration::from_secs(3) && READ_TIMEOUT <= Duration::from_secs(4));
    }

    #[test]
    fn recognizes_vpn_clients_and_adapters() {
        assert!(is_vpn_process("vpnagent.exe"));
        assert!(is_vpn_process("happd.exe"));
        assert!(is_vpn_process("WireGuard.exe"));
        assert!(!is_vpn_process("chrome.exe"));
        assert!(is_tunnel_adapter("Cisco AnyConnect Virtual Miniport Adapter for Windows x64"));
        assert!(is_tunnel_adapter("WireGuard Tunnel"));
        assert!(!is_tunnel_adapter("Intel(R) Wi-Fi 6 AX201 160MHz"));
    }
}
