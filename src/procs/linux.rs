//! Linux: `/proc/net/{tcp,tcp6,udp,udp6}` give sockets with their inode; scanning
//! `/proc/<pid>/fd` maps inodes to processes. Reading other users' fds needs root
//! or CAP_SYS_PTRACE; without it only our own processes are attributed.
//!
//! The parsers are platform independent so they are tested everywhere.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::SockProto;

/// One parsed row of a `/proc/net/*` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcNetRow {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: u8,
    pub inode: u64,
}

/// `0100007F:0035` (IPv4) or 32 hex digits `:port` (IPv6, four little-endian words).
fn parse_addr(s: &str) -> Option<SocketAddr> {
    let (ip, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = match ip.len() {
        8 => IpAddr::V4(Ipv4Addr::from(u32::from_str_radix(ip, 16).ok()?.to_le_bytes())),
        32 => {
            let mut bytes = [0u8; 16];
            for (i, chunk) in bytes.chunks_mut(4).enumerate() {
                let word = u32::from_str_radix(&ip[i * 8..i * 8 + 8], 16).ok()?;
                chunk.copy_from_slice(&word.to_le_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

pub fn parse_proc_net(text: &str) -> Vec<ProcNetRow> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            Some(ProcNetRow {
                local: parse_addr(f.get(1)?)?,
                remote: parse_addr(f.get(2)?)?,
                state: u8::from_str_radix(f.get(3)?, 16).ok()?,
                inode: f.get(9)?.parse().ok()?,
            })
        })
        .collect()
}

/// Linux TCP state numbers from include/net/tcp_states.h.
pub fn linux_tcp_state(code: u8) -> &'static str {
    match code {
        1 => "ESTABLISHED",
        2 => "SYN_SENT",
        3 => "SYN_RECV",
        4 => "FIN_WAIT1",
        5 => "FIN_WAIT2",
        6 => "TIME_WAIT",
        7 => "CLOSE",
        8 => "CLOSE_WAIT",
        9 => "LAST_ACK",
        10 => "LISTEN",
        11 => "CLOSING",
        _ => "UNKNOWN",
    }
}

/// `socket:[12345]` -> 12345.
pub fn socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
}

/// Parent PID from `/proc/<pid>/stat` (the field after the parenthesised command).
pub fn stat_parent(stat: &str) -> Option<u32> {
    let after = &stat[stat.rfind(')')? + 1..];
    after.split_whitespace().nth(1)?.parse().ok()
}

pub fn proto_of(file: &str) -> SockProto {
    if file.starts_with("tcp") {
        SockProto::Tcp
    } else {
        SockProto::Udp
    }
}

#[cfg(target_os = "linux")]
pub fn snapshot() -> super::OsSnapshot {
    use std::collections::HashMap;
    use std::fs;

    use super::{OsSnapshot, ProcInfo, SocketEntry};

    let mut snap = OsSnapshot::default();
    let mut rows = Vec::new();
    for file in ["tcp", "tcp6", "udp", "udp6"] {
        if let Ok(text) = fs::read_to_string(format!("/proc/net/{file}")) {
            rows.extend(parse_proc_net(&text).into_iter().map(|r| (proto_of(file), r)));
        }
    }

    let mut inode_pid: HashMap<u64, u32> = HashMap::new();
    let mut denied = 0usize;
    if let Ok(dir) = fs::read_dir("/proc") {
        for entry in dir.flatten() {
            let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
            let base = entry.path();
            let name = fs::read_to_string(base.join("comm")).map(|s| s.trim().to_string()).unwrap_or_default();
            let path = fs::read_link(base.join("exe")).ok().map(|p| p.display().to_string());
            let parent = fs::read_to_string(base.join("stat")).ok().and_then(|s| stat_parent(&s));
            snap.procs.insert(pid, ProcInfo { pid, name, path, parent });
            match fs::read_dir(base.join("fd")) {
                Ok(fds) => {
                    for fd in fds.flatten() {
                        if let Some(inode) = fs::read_link(fd.path()).ok().and_then(|l| socket_inode(&l.to_string_lossy())) {
                            inode_pid.insert(inode, pid);
                        }
                    }
                }
                Err(_) => denied += 1,
            }
        }
    }
    if denied > 0 && inode_pid.is_empty() {
        snap.error = Some("cannot read /proc/<pid>/fd; run as root or grant CAP_SYS_PTRACE to see all owners".into());
    }

    for (proto, r) in rows {
        let Some(&pid) = inode_pid.get(&r.inode) else { continue };
        let (remote, state) = match proto {
            SockProto::Tcp => {
                let listening = r.state == 10;
                ((!listening).then_some(r.remote), Some(linux_tcp_state(r.state)))
            }
            SockProto::Udp => ((!r.remote.ip().is_unspecified()).then_some(r.remote), None),
        };
        snap.sockets.push(SocketEntry { proto, local: r.local, remote, state, pid });
    }
    snap
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 21614 1 0000000000000000 100 0 0 10 0
   1: 0200000A:C350 0101A8C0:01BB 01 00000000:00000000 02:000A7C2A 00000000  1000        0 98765 2 0000000000000000 20 4 30 10 -1
";
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn parses_ipv4_rows() {
        let rows = parse_proc_net(TCP);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].local, "127.0.0.1:631".parse().unwrap());
        assert_eq!((rows[0].state, rows[0].inode), (0x0A, 21614));
        assert_eq!(rows[1].local, "10.0.0.2:50000".parse().unwrap());
        assert_eq!(rows[1].remote, "192.168.1.1:443".parse().unwrap());
        assert_eq!(linux_tcp_state(rows[1].state), "ESTABLISHED");
    }

    #[test]
    fn parses_ipv6_rows() {
        let rows = parse_proc_net(TCP6);
        assert_eq!(rows[0].local, "[::1]:22".parse().unwrap());
        assert_eq!(linux_tcp_state(rows[0].state), "LISTEN");
    }

    #[test]
    fn helpers() {
        assert_eq!(socket_inode("socket:[98765]"), Some(98765));
        assert_eq!(socket_inode("pipe:[1]"), None);
        assert_eq!(stat_parent("1234 (Web Content (x)) S 1000 1234 1234 0 -1"), Some(1000));
        assert_eq!(proto_of("udp6"), SockProto::Udp);
        assert!(parse_proc_net("header\ngarbage line\n").is_empty());
    }
}
