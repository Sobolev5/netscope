//! `--demo`: a synthetic traffic source that needs no privileges or libpcap.
//!
//! It emits real Ethernet frames (DNS lookups, TCP handshakes, TLS with SNI, QUIC,
//! plain HTTP with responses, ICMP, mDNS) that go through the normal decoder and
//! analytics, plus a matching fake OS socket table so every connection belongs to a
//! plausible process (VS Code, Chrome, Spotify, svchost...). A scripted set of
//! incidents makes every alert type show up within ~15 seconds: credentials over
//! HTTP, a DNS-tunneling lookup, an upload spike to an unknown host and Telnet.

pub mod frames;

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use etherparse::PacketBuilder;

use crate::capture::{CaptureError, Next, Packet, PacketSource};
use crate::decode::{dns, linktype, tls};
use crate::procs::{tcp_state_name, OsSnapshot, OwnerSource, ProcInfo, SockProto, SocketEntry};
use frames::{tcp_frame_seq, udp_frame, TcpFlags};

pub const LOCAL_IP: [u8; 4] = [192, 168, 1, 50];
const RESOLVER: [u8; 4] = [192, 168, 1, 1];
const TICK: Duration = Duration::from_millis(100);
const MTU_PAYLOAD: usize = 1400;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Tls,
    Quic,
    Http,
}

struct Site {
    name: &'static str,
    ip: [u8; 4],
    kind: Kind,
    /// Average download in KiB/s.
    kib_per_sec: u32,
    pid: u32,
}

// Fake processes: (pid, name, path, parent).
const CODE: u32 = 4120;
const CHROME: u32 = 5216;
const SPOTIFY: u32 = 6104;
const SLACK: u32 = 6332;
const SVCHOST: u32 = 1844;
const PYTHON: u32 = 7408;
const UPDATER: u32 = 8812;
const TELNET: u32 = 9120;

const PROCESSES: &[(u32, &str, &str, u32)] = &[
    (4, "System", "", 0),
    (760, "services.exe", r"C:\Windows\System32\services.exe", 4),
    (SVCHOST, "svchost.exe", r"C:\Windows\System32\svchost.exe", 760),
    (3988, "explorer.exe", r"C:\Windows\explorer.exe", 0),
    (4000, "Code.exe", r"C:\Users\demo\AppData\Local\Programs\Microsoft VS Code\Code.exe", 3988),
    (CODE, "Code.exe", r"C:\Users\demo\AppData\Local\Programs\Microsoft VS Code\Code.exe", 4000),
    (5100, "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", 3988),
    (CHROME, "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", 5100),
    (SPOTIFY, "Spotify.exe", r"C:\Users\demo\AppData\Roaming\Spotify\Spotify.exe", 3988),
    (SLACK, "slack.exe", r"C:\Users\demo\AppData\Local\slack\slack.exe", 3988),
    (7300, "pwsh.exe", r"C:\Program Files\PowerShell\7\pwsh.exe", 3988),
    (PYTHON, "python.exe", r"C:\Users\demo\AppData\Local\Programs\Python\Python313\python.exe", 7300),
    (UPDATER, "updater.exe", r"C:\Users\demo\AppData\Local\Temp\updater.exe", 3988),
    (TELNET, "telnet.exe", r"C:\Windows\System32\telnet.exe", 7300),
];

const SITES: &[Site] = &[
    Site { name: "github.com", ip: [140, 82, 121, 4], kind: Kind::Tls, kib_per_sec: 90, pid: CODE },
    Site { name: "www.youtube.com", ip: [142, 250, 74, 46], kind: Kind::Quic, kib_per_sec: 520, pid: CHROME },
    Site { name: "cdn.jsdelivr.net", ip: [151, 101, 1, 229], kind: Kind::Tls, kib_per_sec: 70, pid: CHROME },
    Site { name: "api.spotify.com", ip: [35, 186, 224, 25], kind: Kind::Tls, kib_per_sec: 140, pid: SPOTIFY },
    Site { name: "slack.com", ip: [52, 85, 151, 28], kind: Kind::Tls, kib_per_sec: 30, pid: SLACK },
    Site { name: "download.windowsupdate.com", ip: [13, 107, 4, 50], kind: Kind::Tls, kib_per_sec: 220, pid: SVCHOST },
    Site { name: "example.org", ip: [93, 184, 215, 14], kind: Kind::Http, kib_per_sec: 12, pid: CHROME },
    Site { name: "ocsp.digicert.com", ip: [192, 229, 211, 108], kind: Kind::Http, kib_per_sec: 4, pid: SVCHOST },
];

const EXFIL_HOST: [u8; 4] = [203, 0, 113, 77];
const TELNET_HOST: [u8; 4] = [198, 51, 100, 23];
const EXFIL_PORT: u16 = 51_000;

/// The fake socket table, shared between the script and [`DemoOwners`].
#[derive(Default)]
struct Sockets {
    /// Most recent last; bounded.
    entries: VecDeque<SocketEntry>,
}

impl Sockets {
    fn open(&mut self, proto: SockProto, lport: u16, remote: Option<([u8; 4], u16)>, pid: u32) {
        let local = SocketAddr::new(IpAddr::from(LOCAL_IP), lport);
        self.entries.retain(|e| !(e.proto == proto && e.local == local));
        let state = (proto == SockProto::Tcp).then(|| tcp_state_name(5));
        self.entries.push_back(SocketEntry { proto, local, remote: remote.map(|(ip, p)| SocketAddr::new(IpAddr::from(ip), p)), state, pid });
        while self.entries.len() > 400 {
            self.entries.pop_front();
        }
    }
}

/// Per-connection TCP sequence numbers, so stream reassembly works on demo traffic.
#[derive(Clone, Copy)]
struct Conn {
    port: u16,
    seq_out: u32,
    seq_in: u32,
}

/// Deterministic traffic script; one call to `tick` produces 100 ms of frames.
struct Script {
    tick: u64,
    rng: u64,
    next_port: u16,
    dns_id: u16,
    conns: HashMap<usize, Conn>,
    exfil_seq: u32,
    sockets: Arc<Mutex<Sockets>>,
}

impl Script {
    fn new(sockets: Arc<Mutex<Sockets>>) -> Self {
        Self { tick: 0, rng: 0x9E37_79B9_7F4A_7C15, next_port: 49_152, dns_id: 1, conns: HashMap::new(), exfil_seq: 1, sockets }
    }

    fn rand(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    fn unit(&mut self) -> f64 {
        (self.rand() >> 11) as f64 / (1u64 << 53) as f64
    }

    fn port(&mut self) -> u16 {
        self.next_port = if self.next_port >= 65_000 { 49_152 } else { self.next_port + 1 };
        self.next_port
    }

    fn register(&self, proto: SockProto, lport: u16, remote: Option<([u8; 4], u16)>, pid: u32) {
        if let Ok(mut s) = self.sockets.lock() {
            s.open(proto, lport, remote, pid);
        }
    }

    fn resolve(&mut self, out: &mut Vec<Vec<u8>>, name: &str, ip: [u8; 4]) {
        let id = self.dns_id;
        self.dns_id = self.dns_id.wrapping_add(1);
        let port = self.port();
        // The Windows DNS client service does the lookups on behalf of applications.
        self.register(SockProto::Udp, port, None, SVCHOST);
        out.push(udp_frame(LOCAL_IP, RESOLVER, port, 53, &dns::build_query(id, name, dns::TYPE_A)));
        out.push(udp_frame(RESOLVER, LOCAL_IP, 53, port, &dns::build_response(id, name, &[IpAddr::from(ip)], 300)));
    }

    /// Sends `payload` on connection `c` in the given direction, advancing its sequence.
    fn send(c: &mut Conn, out: &mut Vec<Vec<u8>>, ip: [u8; 4], rport: u16, outbound: bool, flags: TcpFlags, payload: &[u8]) {
        if outbound {
            out.push(tcp_frame_seq(LOCAL_IP, ip, c.port, rport, flags, c.seq_out, payload));
            c.seq_out = c.seq_out.wrapping_add(payload.len() as u32 + u32::from(matches!(flags, TcpFlags::Syn | TcpFlags::Fin)));
        } else {
            out.push(tcp_frame_seq(ip, LOCAL_IP, rport, c.port, flags, c.seq_in, payload));
            c.seq_in = c.seq_in.wrapping_add(payload.len() as u32 + u32::from(matches!(flags, TcpFlags::SynAck | TcpFlags::Fin)));
        }
    }

    fn connect(&mut self, out: &mut Vec<Vec<u8>>, i: usize, s: &Site) {
        let port = self.port();
        let mut c = Conn { port, seq_out: (self.rand() as u32) | 1, seq_in: (self.rand() as u32) | 1 };
        match s.kind {
            Kind::Tls | Kind::Http => {
                let rport = if s.kind == Kind::Http { 80 } else { 443 };
                self.register(SockProto::Tcp, port, Some((s.ip, rport)), s.pid);
                Self::send(&mut c, out, s.ip, rport, true, TcpFlags::Syn, b"");
                Self::send(&mut c, out, s.ip, rport, false, TcpFlags::SynAck, b"");
                Self::send(&mut c, out, s.ip, rport, true, TcpFlags::Ack, b"");
                if s.kind == Kind::Tls {
                    Self::send(&mut c, out, s.ip, rport, true, TcpFlags::Data, &tls::build_client_hello(s.name));
                } else {
                    let req = format!(
                        "GET /index.html HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0\r\nAccept: text/html\r\n\r\n",
                        s.name
                    );
                    Self::send(&mut c, out, s.ip, rport, true, TcpFlags::Data, req.as_bytes());
                    let body = format!("<!doctype html>\n<html><head><title>{}</title></head>\n<body><h1>Example Domain</h1>\n<p>This domain is for use in illustrative examples.</p></body></html>\n", s.name);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: {}\r\nCache-Control: max-age=604800\r\n\r\n{body}",
                        body.len()
                    );
                    Self::send(&mut c, out, s.ip, rport, false, TcpFlags::Data, resp.as_bytes());
                }
            }
            Kind::Quic => {
                self.register(SockProto::Udp, port, None, s.pid);
                out.push(udp_frame(LOCAL_IP, s.ip, port, 443, &[0xC3; 1200]));
            }
        }
        self.conns.insert(i, c);
    }

    fn tick(&mut self, out: &mut Vec<Vec<u8>>) {
        let t = self.tick;
        self.tick += 1;

        for (i, s) in SITES.iter().enumerate() {
            let start = i as u64 * 6;
            if t < start {
                continue;
            }
            if (t - start).is_multiple_of(300) {
                self.resolve(out, s.name, s.ip);
                self.connect(out, i, s);
            }
            let wave = 0.65 + 0.35 * ((t as f64 / 37.0) + i as f64).sin();
            let bytes = s.kib_per_sec as f64 * 1024.0 / 10.0 * wave * (0.7 + 0.6 * self.unit());
            let segments = (bytes / MTU_PAYLOAD as f64).round() as usize;
            let rport = if s.kind == Kind::Http { 80 } else { 443 };
            let Some(mut c) = self.conns.get(&i).copied() else { continue };
            for k in 0..segments {
                let payload = [0x17u8; MTU_PAYLOAD];
                if s.kind == Kind::Quic {
                    out.push(udp_frame(s.ip, LOCAL_IP, rport, c.port, &payload));
                } else {
                    Self::send(&mut c, out, s.ip, rport, false, TcpFlags::Data, &payload);
                    if k % 2 == 1 {
                        Self::send(&mut c, out, s.ip, rport, true, TcpFlags::Ack, b"");
                    }
                }
            }
            self.conns.insert(i, c);
        }

        if t % 50 == 10 {
            let mut ping = Vec::new();
            let b = PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2])
                .ipv4(LOCAL_IP, [1, 1, 1, 1], 64)
                .icmpv4_echo_request(7, (t / 50) as u16);
            if b.write(&mut ping, &[0u8; 32]).is_ok() {
                out.push(ping);
            }
        }
        if t % 100 == 25 {
            // Another device on the LAN: never attributed to a local process.
            let q = dns::build_query(0, "_googlecast._tcp.local", 12);
            out.push(udp_frame([192, 168, 1, 23], [224, 0, 0, 251], 5353, 5353, &q));
        }

        // Incident 1: a script posts credentials over plain HTTP.
        if t % 250 == 50 {
            let ip = [93, 184, 215, 14];
            let mut c = Conn { port: self.port(), seq_out: 1000, seq_in: 5000 };
            self.register(SockProto::Tcp, c.port, Some((ip, 80)), PYTHON);
            let body = "username=alice&password=hunter2&remember=1";
            let req = format!(
                "POST /login HTTP/1.1\r\nHost: example.org\r\nUser-Agent: python-requests/2.32.3\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            Self::send(&mut c, out, ip, 80, true, TcpFlags::Syn, b"");
            Self::send(&mut c, out, ip, 80, false, TcpFlags::SynAck, b"");
            Self::send(&mut c, out, ip, 80, true, TcpFlags::Data, req.as_bytes());
            Self::send(&mut c, out, ip, 80, false, TcpFlags::Data, b"HTTP/1.1 302 Found\r\nLocation: /account\r\nSet-Cookie: session=7f3a9c; HttpOnly\r\nContent-Length: 0\r\n\r\n");
            Self::send(&mut c, out, ip, 80, true, TcpFlags::Fin, b"");
            Self::send(&mut c, out, ip, 80, false, TcpFlags::Fin, b"");
        }
        // Incident 2: DNS tunneling-style lookup.
        if t % 400 == 80 {
            let label: String = (0..28).map(|_| b"0123456789abcdefghijklmnopqrstuvwxyz"[(self.rand() % 36) as usize] as char).collect();
            let name = format!("{label}.{}.t.exfil-data.net", t / 400);
            let port = self.port();
            self.register(SockProto::Udp, port, None, UPDATER);
            out.push(udp_frame(LOCAL_IP, RESOLVER, port, 53, &dns::build_query(self.dns_id, &name, dns::TYPE_TXT)));
        }
        // Incident 3: 1.5 s of heavy upload (~2.9 MB/s) to a host never seen in DNS/SNI.
        // Longer than a second so a full wall-clock second is covered whatever the phase.
        if (120..135).contains(&(t % 600)) {
            if t % 600 == 120 {
                self.register(SockProto::Tcp, EXFIL_PORT, Some((EXFIL_HOST, 4444)), UPDATER);
            }
            let payload = [0x5Au8; MTU_PAYLOAD];
            let mut c = Conn { port: EXFIL_PORT, seq_out: self.exfil_seq, seq_in: 1 };
            for _ in 0..200 {
                Self::send(&mut c, out, EXFIL_HOST, 4444, true, TcpFlags::Data, &payload);
            }
            self.exfil_seq = c.seq_out;
        }
        // Incident 4: Telnet.
        if t % 900 == 150 {
            let mut c = Conn { port: self.port(), seq_out: 77, seq_in: 1 };
            self.register(SockProto::Tcp, c.port, Some((TELNET_HOST, 23)), TELNET);
            Self::send(&mut c, out, TELNET_HOST, 23, true, TcpFlags::Syn, b"");
        }
    }
}

/// Frames of the first `seconds` of the demo script with timestamps from `start_us`,
/// e.g. to write a sample `.pcap` or drive tests.
pub fn script(seconds: u32, start_us: i64) -> Vec<(i64, Vec<u8>)> {
    let mut s = Script::new(Arc::default());
    let mut all = Vec::new();
    for tick in 0..seconds as i64 * 10 {
        let mut frames = Vec::new();
        s.tick(&mut frames);
        let n = frames.len().max(1) as i64;
        for (k, f) in frames.into_iter().enumerate() {
            all.push((start_us + tick * 100_000 + k as i64 * 100_000 / n, f));
        }
    }
    all
}

/// Live demo source: plays the script in real time with wall-clock timestamps.
pub struct DemoSource {
    script: Script,
    sockets: Arc<Mutex<Sockets>>,
    queue: VecDeque<Vec<u8>>,
    current: Vec<u8>,
    next_tick: Instant,
}

impl DemoSource {
    pub fn new() -> Self {
        let sockets = Arc::new(Mutex::new(Sockets::default()));
        Self { script: Script::new(sockets.clone()), sockets, queue: VecDeque::new(), current: Vec::new(), next_tick: Instant::now() }
    }

    /// The fake OS socket table matching this source's traffic.
    pub fn owners(&self) -> DemoOwners {
        DemoOwners { sockets: self.sockets.clone() }
    }
}

impl Default for DemoSource {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketSource for DemoSource {
    fn next_packet(&mut self) -> Result<Next<'_>, CaptureError> {
        if self.queue.is_empty() {
            let now = Instant::now();
            if now < self.next_tick {
                thread::sleep((self.next_tick - now).min(TICK));
                return Ok(Next::Timeout);
            }
            let mut frames = Vec::new();
            self.script.tick(&mut frames);
            self.queue.extend(frames);
            self.next_tick += TICK;
            // After a suspend or a debugger pause, resync instead of bursting.
            if Instant::now() > self.next_tick + Duration::from_secs(1) {
                self.next_tick = Instant::now();
            }
        }
        match self.queue.pop_front() {
            Some(frame) => {
                self.current = frame;
                let ts_us = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_micros() as i64);
                Ok(Next::Packet(Packet { ts_us, wire_len: self.current.len() as u32, data: &self.current }))
            }
            None => Ok(Next::Timeout),
        }
    }

    fn linktype(&self) -> i32 {
        linktype::ETHERNET
    }

    fn is_live(&self) -> bool {
        true
    }
}

/// Socket owners for demo traffic.
pub struct DemoOwners {
    sockets: Arc<Mutex<Sockets>>,
}

impl OwnerSource for DemoOwners {
    fn snapshot(&mut self) -> OsSnapshot {
        let sockets = self.sockets.lock().map(|s| s.entries.iter().cloned().collect()).unwrap_or_default();
        let procs = PROCESSES
            .iter()
            .map(|&(pid, name, path, parent)| {
                (pid, ProcInfo { pid, name: name.into(), path: (!path.is_empty()).then(|| path.into()), parent: (parent != 0).then_some(parent) })
            })
            .collect();
        OsSnapshot { sockets, procs, error: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{decode, App, Proto};

    #[test]
    fn script_is_deterministic_and_decodable() {
        let a = script(3, 0);
        assert_eq!(a.len(), script(3, 0).len());
        assert!(a.windows(2).all(|w| w[0].0 <= w[1].0), "timestamps ordered");
        let decoded: Vec<_> = a.iter().filter_map(|(_, f)| decode(linktype::ETHERNET, f)).collect();
        assert_eq!(decoded.len(), a.len(), "every demo frame is IP");
        assert!(decoded.iter().any(|p| matches!(&p.app, App::TlsHello(h) if h.sni.as_deref() == Some("github.com"))));
        assert!(decoded.iter().any(|p| p.proto == Proto::Quic));
        assert!(decoded.iter().any(|p| matches!(&p.app, App::Dns(m) if m.response)));
    }

    #[test]
    fn live_source_yields_packets_and_owners() {
        let mut src = DemoSource::new();
        let mut owners = src.owners();
        let mut packets = 0;
        for _ in 0..50 {
            if let Next::Packet(p) = src.next_packet().unwrap() {
                assert!(p.ts_us > 0 && !p.data.is_empty());
                packets += 1;
            }
        }
        assert!(packets > 0);
        let snap = owners.snapshot();
        assert!(snap.sockets.iter().any(|s| s.pid == CODE && s.remote.is_some_and(|r| r.port() == 443)));
        assert_eq!(snap.procs[&CODE].parent, Some(4000));
    }
}
