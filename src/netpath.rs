//! "Where does my traffic leave?": the public egress address (one plain HTTP request
//! to Cloudflare's trace endpoint), VPN/proxy tunnels found through the sockets of
//! VPN client processes, and traffic per destination country.

use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
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

/// The adapter carrying the default route right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteInfo {
    /// The local address packets to the internet leave from.
    pub ip: IpAddr,
    /// Adapter name as Windows shows it ("Wi-Fi", "Ethernet 2", "WireGuard Tunnel"); `None`
    /// where the OS does not tell.
    pub adapter: Option<String>,
    /// A virtual tunnel adapter (VPN) carries the route.
    pub tunnel: bool,
}

impl RouteInfo {
    /// What to show: the adapter name, else the address.
    pub fn label(&self) -> String {
        self.adapter.clone().unwrap_or_else(|| self.ip.to_string())
    }

    /// The same adapter (by name, or by address where the OS gives no name) in the same role:
    /// a new address on it is not a move to another network adapter.
    pub fn same_adapter(&self, other: &RouteInfo) -> bool {
        self.tunnel == other.tunnel
            && match (&self.adapter, &other.adapter) {
                (Some(a), Some(b)) => a == b,
                _ => self.ip == other.ip,
            }
    }
}

/// Whether a default-route change calls for an egress check soon: any change to a working
/// route except the first poll (the periodic check at start covers that). Losing the route
/// does not — a check while offline would only fail — the reconnect does, however long the
/// gap was.
fn recheck_egress_after(first_poll: bool, route: Option<&RouteInfo>) -> bool {
    !first_poll && route.is_some()
}

/// Where traffic to the internet leaves from, as the routing table says now.
pub fn current_route() -> Option<RouteInfo> {
    let ip = crate::capture::live::default_route_ip()?;
    let (adapter, virtual_type) = adapter_of(ip).unwrap_or((None, false));
    let tunnel = virtual_type || adapter.as_deref().is_some_and(is_tunnel_adapter);
    Some(RouteInfo { ip, adapter, tunnel })
}

/// `(friendly name, is a tunnel/virtual interface type)` of the adapter holding `ip`.
#[cfg(windows)]
fn adapter_of(ip: IpAddr) -> Option<(Option<String>, bool)> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IF_TYPE_PPP, IF_TYPE_PROP_VIRTUAL,
        IF_TYPE_TUNNEL, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6};

    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 16 * 1024;
    let mut buf: Vec<u64> = Vec::new();
    // SAFETY: the buffer is sized by the call itself; every pointer read below comes from
    // the linked list the call filled in and is checked for null first.
    unsafe {
        let mut ok = false;
        for _ in 0..4 {
            buf.resize((size as usize).div_ceil(8), 0);
            let r = GetAdaptersAddresses(AF_UNSPEC as u32, flags, std::ptr::null(), buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(), &mut size);
            if r == NO_ERROR {
                ok = true;
                break;
            }
            if r != ERROR_BUFFER_OVERFLOW {
                return None;
            }
        }
        if !ok {
            return None;
        }
        let mut a = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !a.is_null() {
            let adapter = &*a;
            let mut u = adapter.FirstUnicastAddress;
            while !u.is_null() {
                let sa = (*u).Address.lpSockaddr;
                let found = if sa.is_null() {
                    None
                } else {
                    match (*sa).sa_family {
                        AF_INET => Some(IpAddr::V4(Ipv4Addr::from((*sa.cast::<SOCKADDR_IN>()).sin_addr.S_un.S_addr.to_ne_bytes()))),
                        AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from((*sa.cast::<SOCKADDR_IN6>()).sin6_addr.u.Byte))),
                        _ => None,
                    }
                };
                if found == Some(ip) {
                    let name = wide_string(adapter.FriendlyName);
                    let desc = wide_string(adapter.Description);
                    let virtual_type = matches!(adapter.IfType, IF_TYPE_TUNNEL | IF_TYPE_PROP_VIRTUAL | IF_TYPE_PPP) || is_tunnel_adapter(&desc);
                    return Some((if name.is_empty() { None } else { Some(name) }, virtual_type));
                }
                u = (*u).Next;
            }
            a = adapter.Next;
        }
    }
    None
}

/// Copies a NUL-terminated UTF-16 string from the OS.
///
/// # Safety
/// `p` is null or points to a NUL-terminated UTF-16 string.
#[cfg(windows)]
unsafe fn wide_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    // SAFETY: as documented above; the loop stops at the terminator.
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    }
}

#[cfg(not(windows))]
fn adapter_of(_ip: IpAddr) -> Option<(Option<String>, bool)> {
    None
}

/// How often the routing table is looked at.
const ROUTE_POLL: Duration = Duration::from_secs(2);
/// A route change is followed by an egress check after this long (VPNs settle), repeated
/// a few times when the check fails (the tunnel may still be connecting).
const SETTLE: Duration = Duration::from_secs(3);
const RETRY: Duration = Duration::from_secs(5);
const RETRIES: u32 = 4;

/// Watches the default route (every 2 s, nothing is sent) and, with `check_egress`, the
/// public egress address: every 10 minutes and a few seconds after each route change.
/// Both go to the state, which raises the network alerts.
pub fn spawn_network_watcher(shared: SharedState, stop: Arc<AtomicBool>, egress_enabled: bool) -> std::io::Result<JoinHandle<()>> {
    thread::Builder::new().name("network".into()).spawn(move || {
        let mut last_check: Option<Instant> = None;
        let mut last_route_poll: Option<Instant> = None;
        let mut route: Option<RouteInfo> = None;
        // (when, attempts left) of an egress check scheduled after a route change.
        let mut pending: Option<(Instant, u32)> = None;
        while !stop.load(Ordering::Relaxed) {
            if last_route_poll.is_none_or(|t| t.elapsed() >= ROUTE_POLL) {
                let first_poll = last_route_poll.is_none();
                last_route_poll = Some(Instant::now());
                let now = current_route();
                if now != route {
                    tracing::info!("default route: {}", now.as_ref().map_or_else(|| "none".to_string(), RouteInfo::label));
                    if egress_enabled && recheck_egress_after(first_poll, now.as_ref()) {
                        pending = Some((Instant::now() + SETTLE, RETRIES));
                    }
                    route = now.clone();
                    shared.write().set_default_route(now);
                }
            }
            let due_periodic = egress_enabled && last_check.is_none_or(|t| t.elapsed() >= RECHECK);
            let due_pending = pending.is_some_and(|(at, _)| Instant::now() >= at);
            if due_periodic || due_pending {
                let r = check_egress(&stop);
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                let failed = r.is_err();
                if let Err(e) = &r {
                    tracing::warn!("egress check: {e}");
                }
                shared.write().set_egress(r);
                last_check = Some(Instant::now());
                pending = match pending {
                    Some((_, left)) if failed && left > 1 => Some((Instant::now() + RETRY, left - 1)),
                    _ => None,
                };
            }
            thread::sleep(Duration::from_millis(200));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_changes_that_call_for_an_egress_check() {
        let wifi = RouteInfo { ip: "192.168.1.50".parse().unwrap(), adapter: Some("Wi-Fi".into()), tunnel: false };
        assert!(!recheck_egress_after(true, Some(&wifi)), "the first poll: the periodic check runs anyway");
        assert!(!recheck_egress_after(true, None));
        assert!(!recheck_egress_after(false, None), "offline: a check would only fail");
        assert!(recheck_egress_after(false, Some(&wifi)), "a reconnect after any gap is checked");
    }

    #[test]
    fn same_adapter_ignores_the_address_but_not_the_role() {
        let r = |ip: &str, adapter: Option<&str>, tunnel| RouteInfo { ip: ip.parse().unwrap(), adapter: adapter.map(Into::into), tunnel };
        assert!(r("192.168.1.50", Some("Wi-Fi"), false).same_adapter(&r("10.0.0.7", Some("Wi-Fi"), false)), "DHCP renewal, another Wi-Fi network");
        assert!(!r("192.168.1.50", Some("Wi-Fi"), false).same_adapter(&r("192.168.1.50", Some("Ethernet"), false)));
        assert!(!r("10.8.0.2", Some("Tun"), false).same_adapter(&r("10.8.0.2", Some("Tun"), true)), "tunnel role differs");
        assert!(r("172.16.0.5", None, false).same_adapter(&r("172.16.0.5", None, false)));
        assert!(!r("172.16.0.5", None, false).same_adapter(&r("172.16.0.6", None, false)), "no names: the address decides");
        assert!(!r("172.16.0.5", Some("Wi-Fi"), false).same_adapter(&r("172.16.0.6", None, false)));
    }

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
