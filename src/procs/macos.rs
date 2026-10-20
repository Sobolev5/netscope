//! macOS: parses `lsof -nP -iTCP -iUDP -FpcRPnT` machine-readable output.
//! Without root, lsof only lists the current user's processes.
//!
//! The parser is platform independent so it is tested everywhere.

#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::collections::HashMap;
use std::net::SocketAddr;

use super::{OsSnapshot, ProcInfo, SockProto, SocketEntry};

/// `10.0.0.2:51515->1.2.3.4:443`, `*:5353`, `[::1]:631`.
fn parse_endpoints(n: &str) -> Option<(SocketAddr, Option<SocketAddr>)> {
    let parse = |s: &str| -> Option<SocketAddr> {
        let s = s.replace('*', "0.0.0.0");
        s.parse().ok().or_else(|| {
            // lsof prints IPv6 wildcard as "[::]:port" or "*:port"; already handled; try bracketless v6.
            let (ip, port) = s.rsplit_once(':')?;
            format!("[{ip}]:{port}").parse().ok()
        })
    };
    match n.split_once("->") {
        Some((l, r)) => Some((parse(l)?, Some(parse(r)?))),
        None => Some((parse(n)?, None)),
    }
}

fn state_name(s: &str) -> &'static str {
    match s {
        "ESTABLISHED" => "ESTABLISHED",
        "LISTEN" => "LISTEN",
        "SYN_SENT" => "SYN_SENT",
        "SYN_RECEIVED" => "SYN_RCVD",
        "CLOSE_WAIT" => "CLOSE_WAIT",
        "FIN_WAIT_1" => "FIN_WAIT1",
        "FIN_WAIT_2" => "FIN_WAIT2",
        "CLOSING" => "CLOSING",
        "LAST_ACK" => "LAST_ACK",
        "TIME_WAIT" => "TIME_WAIT",
        "CLOSED" => "CLOSED",
        _ => "UNKNOWN",
    }
}

pub fn parse_lsof(out: &str) -> OsSnapshot {
    let mut snap = OsSnapshot::default();
    let mut procs: HashMap<u32, ProcInfo> = HashMap::new();
    let (mut pid, mut proto, mut name, mut state) = (0u32, None, None::<String>, None);

    let flush = |pid: u32, proto: Option<SockProto>, name: &mut Option<String>, state: &mut Option<&'static str>, snap: &mut OsSnapshot| {
        if let (Some(proto), Some(n)) = (proto, name.take()) {
            if let Some((local, remote)) = parse_endpoints(&n) {
                snap.sockets.push(SocketEntry { proto, local, remote, state: state.take(), pid });
            }
        }
        *state = None;
    };

    for line in out.lines() {
        let (tag, val) = line.split_at(line.len().min(1));
        match tag {
            "p" => {
                flush(pid, proto, &mut name, &mut state, &mut snap);
                pid = val.parse().unwrap_or(0);
                procs.entry(pid).or_insert(ProcInfo { pid, name: String::new(), path: None, parent: None });
            }
            "c" => {
                if let Some(p) = procs.get_mut(&pid) {
                    p.name = val.to_string();
                }
            }
            "R" => {
                if let Some(p) = procs.get_mut(&pid) {
                    p.parent = val.parse().ok().filter(|&v: &u32| v != 0);
                }
            }
            "f" => flush(pid, proto, &mut name, &mut state, &mut snap),
            "P" => proto = if val == "TCP" { Some(SockProto::Tcp) } else if val == "UDP" { Some(SockProto::Udp) } else { None },
            "n" => name = Some(val.to_string()),
            "T" => {
                if let Some(s) = val.strip_prefix("ST=") {
                    state = Some(state_name(s));
                }
            }
            _ => {}
        }
    }
    flush(pid, proto, &mut name, &mut state, &mut snap);
    snap.procs = procs;
    snap
}

#[cfg(target_os = "macos")]
pub fn snapshot() -> OsSnapshot {
    match std::process::Command::new("lsof").args(["-nP", "-iTCP", "-iUDP", "-FpcRfPnT"]).output() {
        Ok(o) => parse_lsof(&String::from_utf8_lossy(&o.stdout)),
        Err(e) => OsSnapshot { error: Some(format!("cannot run lsof: {e}")), ..OsSnapshot::default() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUT: &str = "p501\ncCode Helper\nR500\nf23\nPTCP\nn10.0.0.2:51515->140.82.121.4:443\nTST=ESTABLISHED\nTQR=0\nf24\nPUDP\nn*:5353\np88\nclaunchd\nR0\nf7\nPTCP\nn[::1]:631\nTST=LISTEN\n";

    #[test]
    fn parses_processes_and_sockets() {
        let s = parse_lsof(OUT);
        assert_eq!(s.procs[&501].name, "Code Helper");
        assert_eq!(s.procs[&501].parent, Some(500));
        assert_eq!(s.procs[&88].parent, None);
        assert_eq!(s.sockets.len(), 3);
        assert_eq!(s.sockets[0].remote, Some("140.82.121.4:443".parse().unwrap()));
        assert_eq!(s.sockets[0].state, Some("ESTABLISHED"));
        assert_eq!((s.sockets[1].proto, s.sockets[1].local.port()), (SockProto::Udp, 5353));
        assert_eq!(s.sockets[2].pid, 88);
        assert_eq!(s.sockets[2].state, Some("LISTEN"));
    }
}
