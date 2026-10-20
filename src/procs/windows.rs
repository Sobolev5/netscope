//! Windows: IP Helper owner-PID tables and a Toolhelp process snapshot.

use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, INVALID_HANDLE_VALUE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
    MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION};

use super::{tcp_state_name, OsSnapshot, ProcInfo, SockProto, SocketEntry};

/// Image paths survive between snapshots; keyed by (pid, exe name) so a reused PID
/// of a different program is looked up again.
#[derive(Default)]
pub struct PathCache {
    paths: HashMap<(u32, String), Option<String>>,
}

/// Ports in the IP Helper tables are in network byte order in the low 16 bits.
fn port(raw: u32) -> u16 {
    u16::from_be(raw as u16)
}

fn v4(raw: u32) -> IpAddr {
    // The DWORD holds the address bytes in network order as laid out in memory.
    IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes()))
}

/// Calls a `GetExtended*Table` function with a growing buffer; returns the rows.
fn table<Row: Copy>(call: impl Fn(*mut c_void, *mut u32) -> u32) -> Result<Vec<Row>, String> {
    let mut size: u32 = 0;
    let mut buf: Vec<u64> = Vec::new();
    for _ in 0..5 {
        let rc = call(if buf.is_empty() { std::ptr::null_mut() } else { buf.as_mut_ptr().cast() }, &mut size);
        if rc == NO_ERROR && !buf.is_empty() {
            // Layout: DWORD dwNumEntries, then the rows (aligned like the row type).
            let base = buf.as_ptr().cast::<u8>();
            // SAFETY: the OS wrote a table header followed by `n` rows into `buf`.
            let n = unsafe { *base.cast::<u32>() } as usize;
            let align = std::mem::align_of::<Row>().max(4);
            let rows = unsafe { base.add(align) }.cast::<Row>();
            let fits = (size as usize).saturating_sub(align) / std::mem::size_of::<Row>();
            return Ok((0..n.min(fits)).map(|i| unsafe { *rows.add(i) }).collect());
        }
        if rc != ERROR_INSUFFICIENT_BUFFER && !(rc == NO_ERROR && buf.is_empty()) {
            return Err(format!("IP Helper error {rc}"));
        }
        buf = vec![0u64; (size as usize).div_ceil(8) + 64];
        size = (buf.len() * 8) as u32;
    }
    Err("socket table kept growing".into())
}

fn sockets() -> Result<Vec<SocketEntry>, String> {
    let mut out = Vec::new();
    // SAFETY (all four calls): valid out-pointers sized by `table`.
    let tcp4: Vec<MIB_TCPROW_OWNER_PID> =
        table(|p, s| unsafe { GetExtendedTcpTable(p, s, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0) })?;
    for r in tcp4 {
        let listening = r.dwState == 2;
        out.push(SocketEntry {
            proto: SockProto::Tcp,
            local: SocketAddr::new(v4(r.dwLocalAddr), port(r.dwLocalPort)),
            remote: (!listening).then(|| SocketAddr::new(v4(r.dwRemoteAddr), port(r.dwRemotePort))),
            state: Some(tcp_state_name(r.dwState)),
            pid: r.dwOwningPid,
        });
    }
    let tcp6: Vec<MIB_TCP6ROW_OWNER_PID> =
        table(|p, s| unsafe { GetExtendedTcpTable(p, s, 0, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0) })?;
    for r in tcp6 {
        let listening = r.dwState == 2;
        out.push(SocketEntry {
            proto: SockProto::Tcp,
            local: SocketAddr::new(IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)), port(r.dwLocalPort)),
            remote: (!listening).then(|| SocketAddr::new(IpAddr::V6(Ipv6Addr::from(r.ucRemoteAddr)), port(r.dwRemotePort))),
            state: Some(tcp_state_name(r.dwState)),
            pid: r.dwOwningPid,
        });
    }
    let udp4: Vec<MIB_UDPROW_OWNER_PID> =
        table(|p, s| unsafe { GetExtendedUdpTable(p, s, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0) })?;
    for r in udp4 {
        out.push(SocketEntry {
            proto: SockProto::Udp,
            local: SocketAddr::new(v4(r.dwLocalAddr), port(r.dwLocalPort)),
            remote: None,
            state: None,
            pid: r.dwOwningPid,
        });
    }
    let udp6: Vec<MIB_UDP6ROW_OWNER_PID> =
        table(|p, s| unsafe { GetExtendedUdpTable(p, s, 0, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0) })?;
    for r in udp6 {
        out.push(SocketEntry {
            proto: SockProto::Udp,
            local: SocketAddr::new(IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)), port(r.dwLocalPort)),
            remote: None,
            state: None,
            pid: r.dwOwningPid,
        });
    }
    Ok(out)
}

fn processes() -> Result<Vec<(u32, u32, String)>, String> {
    // SAFETY: plain Toolhelp enumeration; the handle is closed below.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE || snap.is_null() {
            return Err("cannot enumerate processes".into());
        }
        let mut out = Vec::new();
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = Process32FirstW(snap, &mut e);
        while ok != 0 {
            let len = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(e.szExeFile.len());
            out.push((e.th32ProcessID, e.th32ParentProcessID, String::from_utf16_lossy(&e.szExeFile[..len])));
            ok = Process32NextW(snap, &mut e);
        }
        CloseHandle(snap);
        Ok(out)
    }
}

fn image_path(pid: u32) -> Option<String> {
    // SAFETY: the handle is checked and closed; the buffer length is passed in/out.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }
}

pub fn snapshot(cache: &mut PathCache) -> OsSnapshot {
    let mut snap = OsSnapshot::default();
    match sockets() {
        Ok(s) => snap.sockets = s,
        Err(e) => snap.error = Some(e),
    }
    let list = match processes() {
        Ok(l) => l,
        Err(e) => {
            snap.error = Some(e);
            return snap;
        }
    };
    // Paths only for processes that own sockets: OpenProcess on hundreds of PIDs is slow.
    let owners: std::collections::HashSet<u32> = snap.sockets.iter().map(|s| s.pid).collect();
    let mut live_keys = std::collections::HashSet::new();
    for (pid, parent, name) in list {
        let key = (pid, name.clone());
        let path = if owners.contains(&pid) {
            cache.paths.entry(key.clone()).or_insert_with(|| image_path(pid)).clone()
        } else {
            cache.paths.get(&key).cloned().flatten()
        };
        live_keys.insert(key);
        snap.procs.insert(pid, ProcInfo { pid, name, path, parent: (parent != 0).then_some(parent) });
    }
    cache.paths.retain(|k, _| live_keys.contains(k));
    snap
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_order_helpers() {
        // 443 in network order stored in a little-endian DWORD.
        assert_eq!(port(u32::from(443u16.to_be())), 443);
        assert_eq!(v4(u32::from_ne_bytes([10, 1, 2, 3])), "10.1.2.3".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn sees_a_socket_we_open() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let socks = sockets().unwrap();
        let mine = socks.iter().find(|s| s.local == addr).expect("own listener in table");
        assert_eq!((mine.pid, mine.state), (std::process::id(), Some("LISTEN")));
        let snap = snapshot(&mut PathCache::default());
        let me = &snap.procs[&std::process::id()];
        assert!(me.path.as_deref().is_some_and(|p| p.ends_with(".exe")), "{me:?}");
    }
}
