//! Safe wrapper over the runtime-loaded libpcap: device listing, live and offline handles.

use std::ffi::{c_char, c_int, CStr, CString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::ptr::{self, NonNull};
use std::sync::Arc;

use serde::Serialize;

use super::error::CaptureError;
use super::ffi::{self, Api};
use super::{Next, Packet, PacketSource};

/// A loaded libpcap / Npcap.
pub struct Pcap {
    api: Arc<Api>,
    /// Which library file was loaded.
    pub library: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Device {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<IpAddr>,
    pub loopback: bool,
    pub up: bool,
    pub running: bool,
    pub wireless: bool,
}

impl Device {
    pub fn label(&self) -> &str {
        self.description.as_deref().unwrap_or(&self.name)
    }
}

#[derive(Debug, Clone)]
pub struct LiveOptions {
    pub snaplen: i32,
    pub promisc: bool,
    /// Read timeout, so the capture loop can notice shutdown requests.
    pub timeout_ms: i32,
    pub buffer_bytes: i32,
    pub filter: Option<String>,
}

impl Default for LiveOptions {
    fn default() -> Self {
        Self { snaplen: 65_535, promisc: true, timeout_ms: 200, buffer_bytes: 16 << 20, filter: None }
    }
}

fn cstr(p: *const c_char) -> String {
    if p.is_null() {
        String::new()
    } else {
        // SAFETY: libpcap returns NUL-terminated strings that live at least until the next call.
        unsafe { CStr::from_ptr(p) }.to_string_lossy().trim().to_string()
    }
}

fn errbuf_text(buf: &[c_char]) -> String {
    let bytes: Vec<u8> = buf.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
    String::from_utf8_lossy(&bytes).trim().to_string()
}

/// The OS reason a library failed to load (libloading's own text is just "LoadLibraryExW failed").
fn load_error(e: &libloading::Error) -> String {
    std::error::Error::source(e).map_or_else(|| e.to_string(), |s| s.to_string()).trim().to_string()
}

impl Pcap {
    pub fn load() -> Result<Self, CaptureError> {
        Self::load_from(ffi::candidates())
    }

    /// Tries the given library files in order.
    pub fn load_from(candidates: Vec<String>) -> Result<Self, CaptureError> {
        let mut tried = Vec::new();
        for name in candidates {
            match ffi::open_library(&name) {
                // SAFETY: the candidates are libpcap builds exporting the standard C API.
                Ok(lib) => match unsafe { Api::from_library(lib) } {
                    Ok(api) => {
                        api.init_utf8();
                        return Ok(Self { api: Arc::new(api), library: name });
                    }
                    Err(e) => tried.push(format!("{name} ({})", load_error(&e))),
                },
                // A file that exists but cannot be loaded (wrong architecture, broken install)
                // deserves the OS error; a missing file is just listed.
                Err(e) if Path::new(&name).exists() => tried.push(format!("{name} ({})", load_error(&e))),
                Err(_) => tried.push(name),
            }
        }
        Err(CaptureError::LibraryNotFound { tried: tried.join(", ") })
    }

    pub fn version(&self) -> String {
        // SAFETY: returns a static string.
        cstr(unsafe { (self.api.pcap_lib_version)() })
    }

    pub fn devices(&self) -> Result<Vec<Device>, CaptureError> {
        let mut err = [0 as c_char; ffi::PCAP_ERRBUF_SIZE];
        let mut list: *mut ffi::pcap_if = ptr::null_mut();
        // SAFETY: out-pointers are valid; the list is freed below.
        if unsafe { (self.api.pcap_findalldevs)(&mut list, err.as_mut_ptr()) } != 0 {
            return Err(CaptureError::from_pcap("listing interfaces on", "system", errbuf_text(&err)));
        }
        let mut out = Vec::new();
        let mut cur = list;
        while !cur.is_null() {
            // SAFETY: `cur` walks the linked list returned by pcap_findalldevs.
            let d = unsafe { &*cur };
            let mut addresses = Vec::new();
            let mut a = d.addresses;
            while !a.is_null() {
                // SAFETY: same list ownership as above.
                let addr = unsafe { &*a };
                if let Some(ip) = unsafe { sockaddr_ip(addr.addr as *const u8) } {
                    addresses.push(ip);
                }
                a = addr.next;
            }
            let description = Some(cstr(d.description)).filter(|s| !s.is_empty());
            out.push(Device {
                name: cstr(d.name),
                description,
                addresses,
                loopback: d.flags & ffi::PCAP_IF_LOOPBACK != 0,
                up: d.flags & ffi::PCAP_IF_UP != 0,
                running: d.flags & ffi::PCAP_IF_RUNNING != 0,
                wireless: d.flags & ffi::PCAP_IF_WIRELESS != 0,
            });
            cur = d.next;
        }
        // SAFETY: frees the list obtained above exactly once.
        unsafe { (self.api.pcap_freealldevs)(list) };
        Ok(out)
    }

    pub fn open_live(&self, device: &str, o: &LiveOptions) -> Result<Handle, CaptureError> {
        let name = CString::new(device).map_err(|_| CaptureError::InterfaceNotFound(device.to_string()))?;
        let mut err = [0 as c_char; ffi::PCAP_ERRBUF_SIZE];
        // SAFETY: valid C string and error buffer.
        let p = unsafe { (self.api.pcap_create)(name.as_ptr(), err.as_mut_ptr()) };
        let p = NonNull::new(p).ok_or_else(|| CaptureError::from_pcap("opening", device, errbuf_text(&err)))?;
        // From here on `Drop` closes the handle on every error path.
        let mut h = Handle { api: self.api.clone(), p, linktype: 0, live: true };
        let api = &self.api;
        // SAFETY: `p` is a created, not yet activated handle; these setters are valid before activation.
        let rc = unsafe {
            (api.pcap_set_snaplen)(p.as_ptr(), o.snaplen);
            (api.pcap_set_promisc)(p.as_ptr(), o.promisc as c_int);
            (api.pcap_set_timeout)(p.as_ptr(), o.timeout_ms);
            (api.pcap_set_immediate_mode)(p.as_ptr(), 1);
            (api.pcap_set_buffer_size)(p.as_ptr(), o.buffer_bytes);
            (api.pcap_activate)(p.as_ptr())
        };
        if rc < 0 {
            let mut detail = h.last_error();
            if detail.is_empty() {
                // SAFETY: returns a static string for any status code.
                detail = cstr(unsafe { (api.pcap_statustostr)(rc) });
            }
            return Err(match rc {
                ffi::PCAP_ERROR_PERM_DENIED | ffi::PCAP_ERROR_PROMISC_PERM_DENIED => {
                    CaptureError::PermissionDenied { device: device.to_string(), detail }
                }
                ffi::PCAP_ERROR_NO_SUCH_DEVICE => CaptureError::InterfaceNotFound(device.to_string()),
                _ => CaptureError::from_pcap("activating", device, detail),
            });
        }
        if rc > 0 {
            tracing::warn!("{device}: {}", h.last_error());
        }
        // SAFETY: activated handle.
        h.linktype = unsafe { (api.pcap_datalink)(p.as_ptr()) };
        if let Some(f) = &o.filter {
            h.set_filter(f)?;
        }
        Ok(h)
    }

    /// Reads a capture file (pcap or pcapng) through libpcap.
    pub fn open_offline(&self, path: &Path, filter: Option<&str>) -> Result<Handle, CaptureError> {
        let shown = path.display().to_string();
        let c = CString::new(shown.clone()).map_err(|_| CaptureError::BadFile { path: shown.clone(), detail: "invalid path".into() })?;
        let mut err = [0 as c_char; ffi::PCAP_ERRBUF_SIZE];
        // SAFETY: valid C string and error buffer.
        let p = unsafe { (self.api.pcap_open_offline)(c.as_ptr(), err.as_mut_ptr()) };
        let p = NonNull::new(p).ok_or_else(|| CaptureError::BadFile { path: shown, detail: errbuf_text(&err) })?;
        let mut h = Handle { api: self.api.clone(), p, linktype: 0, live: false };
        // SAFETY: opened handle.
        h.linktype = unsafe { (self.api.pcap_datalink)(p.as_ptr()) };
        if let Some(f) = filter {
            h.set_filter(f)?;
        }
        Ok(h)
    }
}

/// An open libpcap capture.
pub struct Handle {
    api: Arc<Api>,
    p: NonNull<ffi::pcap_t>,
    linktype: i32,
    live: bool,
}

// SAFETY: a pcap_t may be used from any thread as long as it is not used concurrently;
// `Handle` is only ever owned and driven by one thread at a time.
unsafe impl Send for Handle {}

impl Handle {
    fn last_error(&self) -> String {
        // SAFETY: valid handle; the returned buffer belongs to it.
        cstr(unsafe { (self.api.pcap_geterr)(self.p.as_ptr()) })
    }

    pub fn set_filter(&mut self, filter: &str) -> Result<(), CaptureError> {
        let bad = |detail: String| CaptureError::Filter { filter: filter.to_string(), detail };
        let c = CString::new(filter).map_err(|_| bad("contains a NUL byte".into()))?;
        let mut prog = ffi::bpf_program { bf_len: 0, bf_insns: ptr::null_mut() };
        // SAFETY: valid handle, program out-struct and C string; netmask "unknown".
        if unsafe { (self.api.pcap_compile)(self.p.as_ptr(), &mut prog, c.as_ptr(), 1, 0xFFFF_FFFF) } != 0 {
            return Err(bad(self.last_error()));
        }
        // SAFETY: `prog` was compiled above and is freed right after installing it.
        let rc = unsafe { (self.api.pcap_setfilter)(self.p.as_ptr(), &mut prog) };
        unsafe { (self.api.pcap_freecode)(&mut prog) };
        if rc != 0 {
            return Err(bad(self.last_error()));
        }
        Ok(())
    }
}

impl PacketSource for Handle {
    fn next_packet(&mut self) -> Result<Next<'_>, CaptureError> {
        let mut hdr: *mut ffi::pcap_pkthdr = ptr::null_mut();
        let mut data: *const u8 = ptr::null();
        // SAFETY: valid handle and out-pointers.
        let rc = unsafe { (self.api.pcap_next_ex)(self.p.as_ptr(), &mut hdr, &mut data) };
        match rc {
            ffi::NEXT_OK if !hdr.is_null() && !data.is_null() => {
                // SAFETY: on success libpcap returns a header and `caplen` bytes that stay
                // valid until the next call on this handle, which needs `&mut self`.
                let (h, bytes) = unsafe { (&*hdr, std::slice::from_raw_parts(data, (*hdr).caplen as usize)) };
                Ok(Next::Packet(Packet {
                    ts_us: super::timestamp_us(h.ts.tv_sec as i64, h.ts.tv_usec as i64),
                    wire_len: h.len,
                    data: bytes,
                }))
            }
            ffi::NEXT_OK | ffi::NEXT_TIMEOUT => Ok(Next::Timeout),
            ffi::NEXT_EOF => Ok(Next::End),
            _ => Err(CaptureError::Pcap { context: "reading packets".into(), detail: self.last_error() }),
        }
    }

    fn linktype(&self) -> i32 {
        self.linktype
    }

    fn is_live(&self) -> bool {
        self.live
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle is closed exactly once.
        unsafe { (self.api.pcap_close)(self.p.as_ptr()) };
    }
}

const AF_INET: u16 = 2;
const AF_INET6: u16 = if cfg!(windows) {
    23
} else if cfg!(any(target_os = "macos", target_os = "ios")) {
    30
} else if cfg!(any(target_os = "freebsd", target_os = "dragonfly")) {
    28
} else if cfg!(any(target_os = "openbsd", target_os = "netbsd")) {
    24
} else {
    10
};
const BSD_SOCKADDR: bool = cfg!(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
));

/// Reads an IPv4/IPv6 address out of a `struct sockaddr`.
///
/// # Safety
/// `sa` must be null or point to a valid `sockaddr_in`/`sockaddr_in6`/other sockaddr.
unsafe fn sockaddr_ip(sa: *const u8) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    let family = if BSD_SOCKADDR { *sa.add(1) as u16 } else { u16::from_ne_bytes([*sa, *sa.add(1)]) };
    if family == AF_INET {
        let o = std::slice::from_raw_parts(sa.add(4), 4);
        Some(IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3])))
    } else if family == AF_INET6 {
        let mut o = [0u8; 16];
        o.copy_from_slice(std::slice::from_raw_parts(sa.add(8), 16));
        Some(IpAddr::V6(Ipv6Addr::from(o)))
    } else {
        None
    }
}

/// The local address the OS would use to reach the internet, i.e. the interface
/// carrying the default route (a VPN adapter when a full-tunnel VPN is up).
/// "Connecting" a UDP socket only consults the routing table; nothing is sent.
pub fn default_route_ip() -> Option<IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("1.1.1.1:53").ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_unspecified()).then_some(ip)
}

/// Picks the interface to capture on.
///
/// `query` may be a 1-based index from `--list-interfaces`, an exact name, or a
/// case-insensitive fragment of the name/description. Without a query the best
/// candidate is chosen: the one holding `route_ip` (see [`default_route_ip`]),
/// otherwise up and running, with a non-link-local address, not loopback or virtual.
pub fn select_device(devices: &[Device], query: Option<&str>, route_ip: Option<IpAddr>) -> Result<Device, CaptureError> {
    if let Some(q) = query {
        if let Ok(i) = q.parse::<usize>() {
            return devices.get(i.wrapping_sub(1)).cloned().ok_or_else(|| CaptureError::InterfaceNotFound(q.to_string()));
        }
        if let Some(d) = devices.iter().find(|d| d.name == q) {
            return Ok(d.clone());
        }
        let ql = q.to_lowercase();
        let matches: Vec<&Device> = devices
            .iter()
            .filter(|d| d.name.to_lowercase().contains(&ql) || d.label().to_lowercase().contains(&ql))
            .collect();
        return match matches.as_slice() {
            [one] => Ok((*one).clone()),
            [] => Err(CaptureError::InterfaceNotFound(q.to_string())),
            many => {
                // Prefer the one that would be auto-selected among the matches.
                let owned: Vec<Device> = many.iter().map(|d| (*d).clone()).collect();
                auto_select(&owned, route_ip).ok_or_else(|| CaptureError::InterfaceNotFound(q.to_string()))
            }
        };
    }
    auto_select(devices, route_ip).ok_or(CaptureError::NoDevice)
}

fn auto_select(devices: &[Device], route_ip: Option<IpAddr>) -> Option<Device> {
    devices
        .iter()
        .map(|d| (score(d, route_ip), d))
        .filter(|(s, _)| *s > 0)
        .max_by_key(|(s, _)| *s)
        .map(|(_, d)| d.clone())
}

/// Higher is better; 0 means "never pick automatically".
pub fn score(d: &Device, route_ip: Option<IpAddr>) -> i32 {
    if d.loopback {
        return 0;
    }
    if route_ip.is_some_and(|ip| d.addresses.contains(&ip)) {
        return 100;
    }
    let routable = d.addresses.iter().any(|a| match a {
        IpAddr::V4(v) => !v.is_link_local() && !v.is_loopback() && !v.is_unspecified(),
        IpAddr::V6(v) => (v.segments()[0] & 0xFFC0) != 0xFE80 && !v.is_loopback(),
    });
    if !routable {
        return 0;
    }
    let label = d.label().to_lowercase();
    let virtual_nic = ["virtual", "vmware", "virtualbox", "hyper-v", "vethernet", "docker", "wsl", "bluetooth", "miniport", "tap-", "tun", "zerotier", "tailscale"]
        .iter()
        .any(|k| label.contains(k) || d.name.to_lowercase().starts_with(k));
    let has_v4 = d.addresses.iter().any(IpAddr::is_ipv4);
    1 + 4 * (d.up && d.running) as i32 + 2 * has_v4 as i32 + 2 * (!virtual_nic) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(name: &str, desc: &str, addrs: &[&str], loopback: bool, up: bool) -> Device {
        Device {
            name: name.into(),
            description: (!desc.is_empty()).then(|| desc.into()),
            addresses: addrs.iter().map(|a| a.parse().unwrap()).collect(),
            loopback,
            up,
            running: up,
            wireless: false,
        }
    }

    fn sample() -> Vec<Device> {
        vec![
            dev(r"\Device\NPF_Loopback", "Adapter for loopback traffic capture", &["127.0.0.1"], true, true),
            dev(r"\Device\NPF_{AAA}", "Hyper-V Virtual Ethernet Adapter", &["172.20.0.1"], false, true),
            dev(r"\Device\NPF_{BBB}", "Intel(R) Wi-Fi 6 AX201", &["fe80::1", "192.168.1.50"], false, true),
            dev(r"\Device\NPF_{CCC}", "Realtek Ethernet", &["169.254.10.1"], false, false),
        ]
    }

    #[test]
    fn auto_selects_physical_up_interface() {
        assert_eq!(select_device(&sample(), None, None).unwrap().label(), "Intel(R) Wi-Fi 6 AX201");
        let only_bad = vec![sample()[0].clone(), sample()[3].clone()];
        assert!(matches!(select_device(&only_bad, None, None), Err(CaptureError::NoDevice)));
    }

    #[test]
    fn default_route_wins_even_for_virtual_adapters() {
        let mut d = sample();
        d.push(dev(r"\Device\NPF_{VPN}", "Cisco AnyConnect Virtual Miniport Adapter", &["10.50.50.218"], false, true));
        let route = Some("10.50.50.218".parse().unwrap());
        assert_eq!(select_device(&d, None, route).unwrap().name, r"\Device\NPF_{VPN}");
        // An unknown route address falls back to the heuristic.
        assert_eq!(select_device(&d, None, Some("10.9.9.9".parse().unwrap())).unwrap().name, r"\Device\NPF_{BBB}");
        assert_eq!(select_device(&d, Some("npf_{"), route).unwrap().name, r"\Device\NPF_{VPN}");
    }

    #[test]
    fn unloadable_libraries_are_reported_with_the_reason() {
        // A text file exists but is no shared library; a missing name is simply listed.
        let not_a_lib = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml").display().to_string();
        let Err(err) = Pcap::load_from(vec!["netscope-no-such-library".into(), not_a_lib.clone()]) else { panic!("a text file loaded as a library") };
        let text = err.to_string();
        assert!(text.starts_with("could not load the packet capture library"), "{text}");
        assert!(text.contains("netscope-no-such-library, "), "{text}");
        let CaptureError::LibraryNotFound { tried } = err else { panic!("{err}") };
        let reason = tried.rsplit_once(&format!("{not_a_lib} (")).map(|(_, r)| r).unwrap_or_default();
        assert!(reason.len() > 3 && reason.ends_with(')'), "OS error expected after the file name: {tried}");
    }

    #[test]
    fn real_library_if_installed() {
        let Ok(p) = Pcap::load() else { return };
        assert!(!p.version().is_empty());
        // Calling pcap_init again with the same option is allowed; a second UTF-8 init must not break anything.
        p.api.init_utf8();
        assert!(!p.version().is_empty());
    }

    #[test]
    fn default_route_ip_is_a_real_local_address() {
        // Offline machines have no route; otherwise the address must be usable.
        if let Some(ip) = default_route_ip() {
            assert!(!ip.is_unspecified() && !ip.is_loopback(), "{ip}");
        }
    }

    #[test]
    fn query_by_index_name_and_fragment() {
        let d = sample();
        assert_eq!(select_device(&d, Some("2"), None).unwrap().name, r"\Device\NPF_{AAA}");
        assert_eq!(select_device(&d, Some(r"\Device\NPF_{CCC}"), None).unwrap().label(), "Realtek Ethernet");
        assert_eq!(select_device(&d, Some("wi-fi"), None).unwrap().name, r"\Device\NPF_{BBB}");
        // Ambiguous fragment: best-scoring match wins.
        assert_eq!(select_device(&d, Some("npf_{"), None).unwrap().name, r"\Device\NPF_{BBB}");
        for bad in ["0", "9", "nope"] {
            assert!(matches!(select_device(&d, Some(bad), None), Err(CaptureError::InterfaceNotFound(_))), "{bad}");
        }
    }

    #[test]
    fn scoring_table() {
        let d = |desc: &str, addrs: &[&str], up: bool| dev("\\Device\\NPF_{X}", desc, addrs, false, up);
        let route: Option<IpAddr> = Some("10.0.0.5".parse().unwrap());
        assert_eq!(score(&dev("lo", "Loopback", &["127.0.0.1", "10.0.0.5"], true, true), route), 0, "loopback never, even with the route address");
        assert_eq!(score(&d("Virtual Box", &["10.0.0.5"], false), route), 100, "the default route beats everything");
        assert_eq!(score(&d("Realtek", &[], true), None), 0, "no address");
        assert_eq!(score(&d("Realtek", &["169.254.1.1"], true), None), 0, "link-local v4 only");
        assert_eq!(score(&d("Realtek", &["fe80::1"], true), None), 0, "link-local v6 only");
        assert_eq!(score(&d("Realtek", &["0.0.0.0"], true), None), 0);
        assert_eq!(score(&d("Realtek", &["192.168.1.2"], true), None), 9, "up + v4 + physical");
        assert_eq!(score(&d("Realtek", &["2001:db8::1"], true), None), 7, "no IPv4");
        assert_eq!(score(&d("Realtek", &["192.168.1.2"], false), None), 5, "down");
        assert_eq!(score(&d("Hyper-V Virtual Ethernet", &["172.20.0.1"], true), None), 7, "virtual by description");
        assert_eq!(score(&d("WSL (Hyper-V firewall)", &["172.20.0.1"], true), None), 7);
        assert_eq!(score(&d("VMware Network Adapter VMnet8", &["172.20.0.1"], false), None), 3, "virtual and down");
        assert_eq!(score(&dev("tun0", "", &["10.8.0.2"], false, true), None), 7, "virtual by name prefix");
        assert_eq!(score(&dev("docker0", "", &["172.17.0.1"], false, true), None), 7);
        assert_eq!(score(&dev("eth0", "", &["10.0.0.2"], false, true), None), 9, "no description: the name is the label");
        assert_eq!(score(&dev("en0", "", &["10.0.0.2", "fe80::1"], false, true), None), 9, "a link-local address alongside does not hurt");
        // Ties: the later device wins (max_by_key keeps the last maximum), so the order from libpcap matters.
        let two = vec![dev("a", "Realtek", &["10.0.0.1"], false, true), dev("b", "Intel", &["10.0.0.2"], false, true)];
        assert_eq!(select_device(&two, None, None).unwrap().name, "b");
        let mut partly = two.clone();
        partly[1].running = false;
        assert_eq!(select_device(&partly, None, None).unwrap().name, "a", "up but not running scores lower");
        assert_eq!(select_device(&two, Some(""), None).unwrap().name, "b", "an empty query matches everything and picks the best");
        assert_eq!(select_device(&two, Some("INTEL"), None).unwrap().name, "b", "case-insensitive description match");
        assert!(matches!(select_device(&[], None, None), Err(CaptureError::NoDevice)));
        assert!(matches!(select_device(&[], Some("1"), None), Err(CaptureError::InterfaceNotFound(_))));
    }

    #[test]
    fn parses_sockaddrs() {
        let mut v4 = [0u8; 16];
        if BSD_SOCKADDR {
            v4[0] = 16;
            v4[1] = AF_INET as u8;
        } else {
            v4[..2].copy_from_slice(&AF_INET.to_ne_bytes());
        }
        v4[4..8].copy_from_slice(&[10, 1, 2, 3]);
        assert_eq!(unsafe { sockaddr_ip(v4.as_ptr()) }, Some("10.1.2.3".parse().unwrap()));

        let mut v6 = [0u8; 28];
        if BSD_SOCKADDR {
            v6[0] = 28;
            v6[1] = AF_INET6 as u8;
        } else {
            v6[..2].copy_from_slice(&AF_INET6.to_ne_bytes());
        }
        v6[8..24].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(unsafe { sockaddr_ip(v6.as_ptr()) }, Some("2001:db8::1".parse().unwrap()));
        assert_eq!(unsafe { sockaddr_ip(ptr::null()) }, None);
    }
}
