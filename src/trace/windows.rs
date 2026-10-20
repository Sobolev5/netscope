//! Windows tracer: one `IcmpSendEcho` probe per TTL, all TTLs in parallel threads,
//! then reverse DNS for the routers that answered.

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Once;

use windows_sys::Win32::NetworkManagement::IpHelper::{
    IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY, IP_OPTION_INFORMATION, IP_SUCCESS, IP_TTL_EXPIRED_REASSEM,
    IP_TTL_EXPIRED_TRANSIT,
};
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Networking::WinSock::{GetNameInfoW, WSAStartup, AF_INET, NI_NAMEREQD, SOCKADDR, SOCKADDR_IN, WSADATA};

use super::{truncate_at_target, RawHop, MAX_HOPS};

const PROBES: usize = 3;
/// Probe threads start this far apart per TTL: a burst of 30 simultaneous ICMP
/// requests is often rate-limited (VPN clients, firewalls) and the first round lost.
const STAGGER_MS: u64 = 25;
const TIMEOUT_MS: u32 = 1500;

/// One probe with the given TTL: (answering router, RTT ms).
fn probe(dst: Ipv4Addr, ttl: u8) -> Result<Option<(Ipv4Addr, f64)>, String> {
    // SAFETY: the handle is checked and closed; buffers outlive the call.
    unsafe {
        let h = IcmpCreateFile();
        if h == INVALID_HANDLE_VALUE || h.is_null() {
            return Err("IcmpCreateFile failed".into());
        }
        let payload = [0x6Eu8; 32];
        let opts = IP_OPTION_INFORMATION { Ttl: ttl, Tos: 0, Flags: 0, OptionsSize: 0, OptionsData: std::ptr::null_mut() };
        let mut reply = vec![0u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + payload.len() + 64];
        let n = IcmpSendEcho(
            h,
            u32::from_ne_bytes(dst.octets()),
            payload.as_ptr() as *const c_void,
            payload.len() as u16,
            &opts,
            reply.as_mut_ptr() as *mut c_void,
            reply.len() as u32,
            TIMEOUT_MS,
        );
        IcmpCloseHandle(h);
        if n == 0 {
            // Timeout or no route: this hop stays silent.
            return Ok(None);
        }
        let r = std::ptr::read_unaligned(reply.as_ptr() as *const ICMP_ECHO_REPLY);
        // Only "time exceeded" (a router on the way) and the echo reply (the target) say
        // where a hop is; other errors (unreachable, ...) are not hops of this TTL.
        if !matches!(r.Status, IP_SUCCESS | IP_TTL_EXPIRED_TRANSIT | IP_TTL_EXPIRED_REASSEM) {
            return Ok(None);
        }
        let from = Ipv4Addr::from(r.Address.to_ne_bytes());
        Ok(Some((from, r.RoundTripTime as f64)))
    }
}

/// Reverse DNS name of an IPv4 address, if it has one.
fn reverse_name(ip: Ipv4Addr) -> Option<String> {
    static INIT: Once = Once::new();
    // SAFETY: WSAStartup is reference counted and may be called repeatedly.
    INIT.call_once(|| unsafe {
        let mut data: WSADATA = std::mem::zeroed();
        WSAStartup(0x0202, &mut data);
    });
    // SAFETY: a properly initialized SOCKADDR_IN and output buffer are passed with their sizes.
    unsafe {
        let mut sa: SOCKADDR_IN = std::mem::zeroed();
        sa.sin_family = AF_INET;
        sa.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
        let mut host = [0u16; 256];
        let rc = GetNameInfoW(
            &sa as *const SOCKADDR_IN as *const SOCKADDR,
            std::mem::size_of::<SOCKADDR_IN>() as i32,
            host.as_mut_ptr(),
            host.len() as u32,
            std::ptr::null_mut(),
            0,
            NI_NAMEREQD as i32,
        );
        if rc != 0 {
            return None;
        }
        let len = host.iter().position(|&c| c == 0).unwrap_or(host.len());
        Some(String::from_utf16_lossy(&host[..len]))
    }
}

pub fn trace(target: IpAddr) -> Result<Vec<RawHop>, String> {
    let IpAddr::V4(dst) = target else {
        return Err("IPv6 tracing is not supported on Windows".into());
    };
    let results: Vec<Result<RawHop, String>> = std::thread::scope(|s| {
        let handles: Vec<_> = (1..=MAX_HOPS)
            .map(|ttl| {
                s.spawn(move || -> Result<RawHop, String> {
                    std::thread::sleep(std::time::Duration::from_millis(STAGGER_MS * u64::from(ttl - 1)));
                    let mut hop = RawHop { ttl, ip: None, name: None, rtt_ms: Vec::with_capacity(PROBES) };
                    for _ in 0..PROBES {
                        match probe(dst, ttl)? {
                            Some((from, rtt)) => {
                                hop.ip.get_or_insert(IpAddr::V4(from));
                                hop.rtt_ms.push(Some(rtt));
                            }
                            None => hop.rtt_ms.push(None),
                        }
                    }
                    Ok(hop)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap_or_else(|_| Err("probe thread panicked".into()))).collect()
    });
    let mut hops = results.into_iter().collect::<Result<Vec<_>, _>>()?;
    truncate_at_target(&mut hops, target);

    // Names in parallel too: each lookup may wait on DNS.
    std::thread::scope(|s| {
        for h in hops.iter_mut() {
            if let Some(IpAddr::V4(ip)) = h.ip {
                s.spawn(move || h.name = reverse_name(ip));
            }
        }
    });
    Ok(hops)
}
