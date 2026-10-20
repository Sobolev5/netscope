//! Packet decoding: link layer → IP → TCP/UDP → application hints (DNS, HTTP, TLS SNI).
//!
//! Uses etherparse's lax slicer, which tolerates truncated captures and the zero IP
//! length that NIC segmentation offload produces on outgoing packets.

pub mod dissect;
pub mod dns;
pub mod http;
pub mod sha256;
pub mod tls;
pub mod tlsinfo;

use std::net::IpAddr;

use etherparse::{EtherType, LaxNetSlice, LaxSlicedPacket, TransportSlice};
use serde::Serialize;

/// pcap link-layer header types (<https://www.tcpdump.org/linktypes.html>).
pub mod linktype {
    pub const NULL: i32 = 0;
    pub const ETHERNET: i32 = 1;
    pub const RAW_BSD: i32 = 12;
    pub const RAW_OPENBSD: i32 = 14;
    pub const RAW: i32 = 101;
    pub const LOOP: i32 = 108;
    pub const LINUX_SLL: i32 = 113;
    pub const IPV4: i32 = 228;
    pub const IPV6: i32 = 229;
    pub const LINUX_SLL2: i32 = 276;
}

/// Well-known ports used for classification here and in the dissector.
pub const TLS_PORTS: [u16; 7] = [443, 465, 563, 853, 993, 995, 8443];
pub const HTTP_PORTS: [u16; 4] = [80, 8000, 8008, 8080];
pub const DNS_PORTS: [u16; 3] = [53, 5353, 5355];
pub const QUIC_PORTS: [u16; 1] = [443];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Http,
    Tls,
    Dns,
    Quic,
    Tcp,
    Udp,
    Icmp,
    Other,
}

impl Proto {
    pub const ALL: [Proto; 8] =
        [Proto::Http, Proto::Tls, Proto::Dns, Proto::Quic, Proto::Tcp, Proto::Udp, Proto::Icmp, Proto::Other];

    pub fn index(self) -> usize {
        self as usize
    }

    pub fn name(self) -> &'static str {
        match self {
            Proto::Http => "http",
            Proto::Tls => "tls",
            Proto::Dns => "dns",
            Proto::Quic => "quic",
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Icmp => "icmp",
            Proto::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp { syn: bool, ack: bool, fin: bool, rst: bool },
    Udp,
    Icmp,
    Other(u8),
}

impl Transport {
    /// A connection request (SYN without ACK).
    pub const TCP_SYN: Transport = Transport::Tcp { syn: true, ack: false, fin: false, rst: false };
    /// A plain segment of an established connection.
    pub const TCP_ACK: Transport = Transport::Tcp { syn: false, ack: true, fin: false, rst: false };
}

#[derive(Debug, Clone, PartialEq)]
pub enum App {
    None,
    Dns(dns::DnsMessage),
    Http(http::HttpRequest),
    /// TLS ClientHello: SNI, ALPN, version and JA4 fingerprint.
    TlsHello(Box<TlsHello>),
}

/// What a TLS ClientHello reveals before encryption starts.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TlsHello {
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    /// Highest version offered (0x0304 = TLS 1.3).
    pub version: u16,
    /// JA4 client fingerprint: identifies the TLS library/application, not the site.
    pub ja4: String,
}

impl TlsHello {
    pub fn from_client_hello(h: &tlsinfo::ClientHello, quic: bool) -> Self {
        // SNI is attacker-controlled: keep only plausible host names, lowercased.
        TlsHello { sni: h.sni.as_deref().and_then(tls::valid_hostname), alpn: h.alpn.clone(), version: h.max_version(), ja4: h.ja4(quic) }
    }

    #[cfg(test)]
    pub(crate) fn with_sni(sni: &str) -> Box<Self> {
        Box::new(TlsHello { sni: Some(sni.into()), alpn: vec![], version: 0x0304, ja4: String::new() })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PacketInfo {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// 0 when the transport has no ports.
    pub src_port: u16,
    pub dst_port: u16,
    pub transport: Transport,
    pub proto: Proto,
    pub app: App,
    /// IPv4 TTL / IPv6 hop limit as received (used to estimate the hop count).
    pub ttl: u8,
    /// TCP sequencing details (`None` for other transports).
    pub tcp: Option<TcpMeta>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpMeta {
    pub seq: u32,
    pub ack: u32,
    pub window: u16,
    /// Payload bytes actually present in the capture.
    pub payload_len: u32,
}

/// Slices a frame of any supported link type down to IP and transport headers.
pub fn slice_frame(linktype: i32, data: &[u8]) -> Option<LaxSlicedPacket<'_>> {
    Some(match linktype {
        linktype::ETHERNET => LaxSlicedPacket::from_ethernet(data).ok()?,
        linktype::NULL | linktype::LOOP => LaxSlicedPacket::from_ip(data.get(4..)?).ok()?,
        linktype::RAW | linktype::RAW_BSD | linktype::RAW_OPENBSD | linktype::IPV4 | linktype::IPV6 => {
            LaxSlicedPacket::from_ip(data).ok()?
        }
        linktype::LINUX_SLL => {
            let et = u16::from_be_bytes([*data.get(14)?, *data.get(15)?]);
            LaxSlicedPacket::from_ether_type(EtherType(et), data.get(16..)?)
        }
        linktype::LINUX_SLL2 => {
            let et = u16::from_be_bytes([*data.first()?, *data.get(1)?]);
            LaxSlicedPacket::from_ether_type(EtherType(et), data.get(20..)?)
        }
        _ => return None,
    })
}

/// Decodes one captured frame; `None` for non-IP traffic (ARP, LLDP, ...) or garbage.
pub fn decode(linktype: i32, data: &[u8]) -> Option<PacketInfo> {
    let sliced = slice_frame(linktype, data)?;

    let (src, dst, ip_number, ttl) = match sliced.net.as_ref()? {
        LaxNetSlice::Ipv4(s) => {
            let h = s.header();
            (IpAddr::V4(h.source_addr()), IpAddr::V4(h.destination_addr()), s.payload().ip_number.0, h.ttl())
        }
        LaxNetSlice::Ipv6(s) => {
            let h = s.header();
            (IpAddr::V6(h.source_addr()), IpAddr::V6(h.destination_addr()), s.payload().ip_number.0, h.hop_limit())
        }
    };

    let tcp = match &sliced.transport {
        Some(TransportSlice::Tcp(t)) => Some(TcpMeta {
            seq: t.sequence_number(),
            ack: t.acknowledgment_number(),
            window: t.window_size(),
            payload_len: t.payload().len() as u32,
        }),
        _ => None,
    };
    let (transport, src_port, dst_port, payload): (Transport, u16, u16, &[u8]) = match &sliced.transport {
        Some(TransportSlice::Tcp(t)) => {
            (Transport::Tcp { syn: t.syn(), ack: t.ack(), fin: t.fin(), rst: t.rst() }, t.source_port(), t.destination_port(), t.payload())
        }
        Some(TransportSlice::Udp(u)) => (Transport::Udp, u.source_port(), u.destination_port(), u.payload()),
        Some(TransportSlice::Icmpv4(_)) | Some(TransportSlice::Icmpv6(_)) => (Transport::Icmp, 0, 0, &[]),
        None => (Transport::Other(ip_number), 0, 0, &[]),
    };

    let (proto, app) = classify(transport, src_port, dst_port, payload);
    Some(PacketInfo { src, dst, src_port, dst_port, transport, proto, app, ttl, tcp })
}

fn classify(t: Transport, sport: u16, dport: u16, payload: &[u8]) -> (Proto, App) {
    let on = |ports: &[u16]| ports.contains(&sport) || ports.contains(&dport);
    match t {
        Transport::Tcp { .. } => {
            if on(&DNS_PORTS) {
                // DNS over TCP has a 2-byte length prefix.
                let app = payload.get(2..).and_then(dns::parse).map_or(App::None, App::Dns);
                return (Proto::Dns, app);
            }
            if let Some(req) = http::parse_request(payload) {
                return (Proto::Http, App::Http(req));
            }
            if tls::is_record(payload) || on(&TLS_PORTS) {
                let app = tlsinfo::parse_client_hello(payload)
                    .map_or(App::None, |h| App::TlsHello(Box::new(TlsHello::from_client_hello(&h, false))));
                return (Proto::Tls, app);
            }
            if http::is_response(payload) || on(&HTTP_PORTS) {
                return (Proto::Http, App::None);
            }
            (Proto::Tcp, App::None)
        }
        Transport::Udp => {
            if on(&DNS_PORTS) {
                (Proto::Dns, dns::parse(payload).map_or(App::None, App::Dns))
            } else if on(&QUIC_PORTS) {
                (Proto::Quic, App::None)
            } else {
                (Proto::Udp, App::None)
            }
        }
        Transport::Icmp => (Proto::Icmp, App::None),
        Transport::Other(_) => (Proto::Other, App::None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo::frames::{tcp_frame, udp_frame, TcpFlags};

    const A: [u8; 4] = [192, 168, 1, 50];
    const B: [u8; 4] = [93, 184, 215, 14];

    #[test]
    fn dns_over_udp() {
        let f = udp_frame(A, B, 53000, 53, &dns::build_query(1, "example.org", dns::TYPE_A));
        let p = decode(linktype::ETHERNET, &f).unwrap();
        assert_eq!(p.src, IpAddr::from(A));
        assert_eq!(p.dst, IpAddr::from(B));
        assert_eq!((p.src_port, p.dst_port, p.proto), (53000, 53, Proto::Dns));
        assert!(matches!(p.app, App::Dns(ref m) if m.questions[0].name == "example.org"));
    }

    #[test]
    fn http_tls_and_plain_tcp() {
        let http = tcp_frame(A, B, 50000, 8081, TcpFlags::Data, b"POST /x HTTP/1.1\r\nHost: h\r\n\r\npassword=1");
        let p = decode(linktype::ETHERNET, &http).unwrap();
        assert_eq!(p.proto, Proto::Http, "detected by content, not port");
        assert!(matches!(p.app, App::Http(ref r) if r.sensitive == ["password"]));

        let tls = tcp_frame(A, B, 50001, 443, TcpFlags::Data, &tls::build_client_hello("github.com"));
        let p = decode(linktype::ETHERNET, &tls).unwrap();
        assert!(matches!(&p.app, App::TlsHello(h) if h.sni.as_deref() == Some("github.com") && h.ja4.starts_with("t12d0202")), "{:?}", p.app);

        let syn = tcp_frame(A, B, 50002, 22, TcpFlags::Syn, b"");
        let p = decode(linktype::ETHERNET, &syn).unwrap();
        assert_eq!(p.proto, Proto::Tcp);
        assert_eq!(p.transport, Transport::TCP_SYN);
    }

    #[test]
    fn quic_and_udp() {
        assert_eq!(decode(linktype::ETHERNET, &udp_frame(A, B, 5000, 443, b"x")).unwrap().proto, Proto::Quic);
        assert_eq!(decode(linktype::ETHERNET, &udp_frame(A, B, 5000, 5001, b"x")).unwrap().proto, Proto::Udp);
    }

    #[test]
    fn decoder_and_dissector_agree_on_ports() {
        // mDNS on 5353 and QUIC on 443 are recognized by both from the same tables.
        let mdns = udp_frame(A, [224, 0, 0, 251], 5353, 5353, &dns::build_query(1, "_googlecast._tcp.local", dns::TYPE_ANY));
        assert_eq!(decode(linktype::ETHERNET, &mdns).unwrap().proto, Proto::Dns);
        assert!(dissect::summary(linktype::ETHERNET, &mdns).starts_with("DNS: query"));
        let quic = udp_frame(A, B, 5000, QUIC_PORTS[0], &[0xC3, 0, 0, 0, 1, 9]);
        assert_eq!(decode(linktype::ETHERNET, &quic).unwrap().proto, Proto::Quic);
        assert!(dissect::summary(linktype::ETHERNET, &quic).starts_with("QUIC:"));
        assert!(DNS_PORTS.contains(&53) && TLS_PORTS.contains(&853) && HTTP_PORTS.contains(&80));
    }

    #[test]
    fn other_link_types() {
        let eth = udp_frame(A, B, 1, 2, b"hi");
        let ip = &eth[14..];
        assert_eq!(decode(linktype::RAW, ip).unwrap().dst, IpAddr::from(B));
        let mut null = vec![2, 0, 0, 0];
        null.extend_from_slice(ip);
        assert_eq!(decode(linktype::NULL, &null).unwrap().src, IpAddr::from(A));
        let mut sll = vec![0u8; 14];
        sll.extend_from_slice(&0x0800u16.to_be_bytes());
        sll.extend_from_slice(ip);
        assert_eq!(decode(linktype::LINUX_SLL, &sll).unwrap().proto, Proto::Udp);
        assert!(decode(9999, &eth).is_none());
    }

    #[test]
    fn non_ip_and_truncated_frames() {
        let mut arp = vec![0u8; 12];
        arp.extend_from_slice(&0x0806u16.to_be_bytes());
        arp.extend_from_slice(&[0u8; 28]);
        assert!(decode(linktype::ETHERNET, &arp).is_none());
        assert!(decode(linktype::ETHERNET, &[0u8; 5]).is_none());
        // Snaplen-truncated payload still yields addresses and ports.
        let f = tcp_frame(A, B, 1234, 443, TcpFlags::Data, &[0x17, 3, 3, 0, 200, 1, 2, 3]);
        let p = decode(linktype::ETHERNET, &f[..f.len() - 4]).unwrap();
        assert_eq!((p.dst_port, p.proto), (443, Proto::Tls));
    }
}
