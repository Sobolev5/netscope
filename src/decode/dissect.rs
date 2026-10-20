//! Field-by-field dissection of one stored frame for the packet inspector: every
//! layer and field carries its byte range so the UI can highlight it in the hex dump.

use serde::Serialize;

use super::{dns, http, linktype, tls, DNS_PORTS, QUIC_PORTS};

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Field {
    pub name: String,
    pub value: String,
    /// Byte range `[start, end)` within the frame.
    pub range: [usize; 2],
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Layer {
    pub name: String,
    pub summary: String,
    pub range: [usize; 2],
    pub fields: Vec<Field>,
}

struct Builder<'a> {
    b: &'a [u8],
    layers: Vec<Layer>,
}

impl<'a> Builder<'a> {
    fn layer(&mut self, name: &str, start: usize, end: usize) -> &mut Layer {
        self.layers.push(Layer { name: name.into(), summary: String::new(), range: [start, end.min(self.b.len())], fields: vec![] });
        self.layers.last_mut().expect("just pushed")
    }
}

fn field(l: &mut Layer, name: &str, value: impl Into<String>, start: usize, len: usize) {
    l.fields.push(Field { name: name.into(), value: value.into(), range: [start, start + len] });
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes([*b.get(i)?, *b.get(i + 1)?, *b.get(i + 2)?, *b.get(i + 3)?]))
}

fn mac(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":")
}

fn ether_name(t: u16) -> &'static str {
    match t {
        0x0800 => "IPv4",
        0x86DD => "IPv6",
        0x0806 => "ARP",
        0x8100 => "802.1Q VLAN",
        0x88CC => "LLDP",
        _ => "other",
    }
}

fn ip_proto_name(p: u8) -> &'static str {
    match p {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        2 => "IGMP",
        _ => "other",
    }
}

/// Dissects a frame of the given link type. Unknown or truncated parts end the list.
pub fn dissect(lt: i32, b: &[u8]) -> Vec<Layer> {
    let mut d = Builder { b, layers: vec![] };
    let (ether_type, off) = match lt {
        linktype::ETHERNET => {
            if b.len() < 14 {
                return d.layers;
            }
            let mut t = u16_at(b, 12).unwrap_or(0);
            let mut off = 14;
            let l = d.layer("Ethernet II", 0, 14);
            field(l, "Destination MAC", mac(&b[0..6]), 0, 6);
            field(l, "Source MAC", mac(&b[6..12]), 6, 6);
            field(l, "EtherType", format!("0x{t:04x} ({})", ether_name(t)), 12, 2);
            l.summary = format!("{} → {}", mac(&b[6..12]), mac(&b[0..6]));
            if t == 0x8100 {
                if let (Some(tci), Some(inner)) = (u16_at(b, 14), u16_at(b, 16)) {
                    let v = d.layer("802.1Q VLAN", 14, 18);
                    field(v, "VLAN ID", (tci & 0x0FFF).to_string(), 14, 2);
                    field(v, "EtherType", format!("0x{inner:04x} ({})", ether_name(inner)), 16, 2);
                    v.summary = format!("VLAN {}", tci & 0x0FFF);
                    t = inner;
                    off = 18;
                }
            }
            (t, off)
        }
        linktype::NULL | linktype::LOOP => {
            let l = d.layer("Loopback", 0, 4);
            field(l, "Address family", format!("{:?}", b.get(0..4).unwrap_or(&[])), 0, 4);
            (if b.get(4).is_some_and(|v| v >> 4 == 6) { 0x86DD } else { 0x0800 }, 4)
        }
        linktype::LINUX_SLL => {
            let t = u16_at(b, 14).unwrap_or(0);
            let l = d.layer("Linux cooked capture", 0, 16);
            field(l, "Protocol", format!("0x{t:04x} ({})", ether_name(t)), 14, 2);
            (t, 16)
        }
        linktype::LINUX_SLL2 => {
            let t = u16_at(b, 0).unwrap_or(0);
            let l = d.layer("Linux cooked capture v2", 0, 20);
            field(l, "Protocol", format!("0x{t:04x} ({})", ether_name(t)), 0, 2);
            (t, 20)
        }
        _ => (if b.first().is_some_and(|v| v >> 4 == 6) { 0x86DD } else { 0x0800 }, 0),
    };

    let (proto, l4_off, l4_end) = match ether_type {
        0x0800 => match ipv4(&mut d, off) {
            Some(x) => x,
            None => return d.layers,
        },
        0x86DD => match ipv6(&mut d, off) {
            Some(x) => x,
            None => return d.layers,
        },
        _ => return d.layers,
    };

    let payload = match proto {
        6 => tcp(&mut d, l4_off, l4_end),
        17 => udp(&mut d, l4_off, l4_end),
        1 | 58 => {
            icmp(&mut d, l4_off, l4_end, proto == 58);
            None
        }
        _ => None,
    };
    if let Some((start, end, sport, dport)) = payload {
        if end > start {
            application(&mut d, start, end, sport, dport, proto);
        }
    }
    d.layers
}

fn ipv4(d: &mut Builder, o: usize) -> Option<(u8, usize, usize)> {
    let b = d.b;
    let vihl = *b.get(o)?;
    let ihl = ((vihl & 0x0F) as usize) * 4;
    if vihl >> 4 != 4 || ihl < 20 || b.len() < o + 20 {
        return None;
    }
    let total = u16_at(b, o + 2)? as usize;
    // NIC offload often reports 0 or a larger length than captured.
    let end = if total >= ihl { (o + total).min(b.len()) } else { b.len() };
    let flags = u16_at(b, o + 6)?;
    let proto = b[o + 9];
    let src = std::net::Ipv4Addr::new(b[o + 12], b[o + 13], b[o + 14], b[o + 15]);
    let dst = std::net::Ipv4Addr::new(b[o + 16], b[o + 17], b[o + 18], b[o + 19]);
    let l = d.layer("IPv4", o, o + ihl);
    field(l, "Version / header length", format!("4 / {ihl} bytes"), o, 1);
    field(l, "DSCP / ECN", format!("{} / {}", b[o + 1] >> 2, b[o + 1] & 3), o + 1, 1);
    field(l, "Total length", if total == 0 { "0 (offloaded, see capture length)".into() } else { total.to_string() }, o + 2, 2);
    field(l, "Identification", format!("0x{:04x}", u16_at(b, o + 4)?), o + 4, 2);
    let df = if flags & 0x4000 != 0 { "DF " } else { "" };
    let mf = if flags & 0x2000 != 0 { "MF " } else { "" };
    field(l, "Flags / fragment offset", format!("{df}{mf}/ {}", (flags & 0x1FFF) * 8), o + 6, 2);
    field(l, "TTL", b[o + 8].to_string(), o + 8, 1);
    field(l, "Protocol", format!("{proto} ({})", ip_proto_name(proto)), o + 9, 1);
    field(l, "Header checksum", format!("0x{:04x}", u16_at(b, o + 10)?), o + 10, 2);
    field(l, "Source", src.to_string(), o + 12, 4);
    field(l, "Destination", dst.to_string(), o + 16, 4);
    if ihl > 20 {
        field(l, "Options", format!("{} bytes", ihl - 20), o + 20, ihl - 20);
    }
    l.summary = format!("{src} → {dst}, TTL {}", b[o + 8]);
    Some((proto, o + ihl, end))
}

fn ipv6(d: &mut Builder, o: usize) -> Option<(u8, usize, usize)> {
    let b = d.b;
    if b.len() < o + 40 || b[o] >> 4 != 6 {
        return None;
    }
    let plen = u16_at(b, o + 4)? as usize;
    let mut next = b[o + 6];
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[o + 8..o + 24]);
    let src = std::net::Ipv6Addr::from(a);
    a.copy_from_slice(&b[o + 24..o + 40]);
    let dst = std::net::Ipv6Addr::from(a);
    let end = if plen > 0 { (o + 40 + plen).min(b.len()) } else { b.len() };
    let l = d.layer("IPv6", o, o + 40);
    field(l, "Version / traffic class / flow label", format!("6 / {} / 0x{:05x}", (u32_at(b, o)? >> 20) & 0xFF, u32_at(b, o)? & 0xFFFFF), o, 4);
    field(l, "Payload length", plen.to_string(), o + 4, 2);
    field(l, "Next header", format!("{next} ({})", ip_proto_name(next)), o + 6, 1);
    field(l, "Hop limit", b[o + 7].to_string(), o + 7, 1);
    field(l, "Source", src.to_string(), o + 8, 16);
    field(l, "Destination", dst.to_string(), o + 24, 16);
    l.summary = format!("{src} → {dst}, hop limit {}", b[o + 7]);

    // Skip common extension headers (hop-by-hop, routing, fragment, destination options).
    // A layer is only added once all of its bytes are in the frame: a truncated header ends
    // the dissection and the layers found so far are kept.
    let mut off = o + 40;
    for _ in 0..4 {
        let (name, len) = match next {
            0 | 43 | 60 => ("IPv6 extension header", (*b.get(off + 1)? as usize + 1) * 8),
            44 => ("IPv6 fragment header", 8),
            _ => break,
        };
        if b.len() < off + len {
            return None;
        }
        let e = d.layer(name, off, off + len);
        field(e, "Next header", b[off].to_string(), off, 1);
        next = b[off];
        off += len;
    }
    Some((next, off, end))
}

fn tcp(d: &mut Builder, o: usize, end: usize) -> Option<(usize, usize, u16, u16)> {
    let b = d.b;
    if b.len() < o + 20 {
        return None;
    }
    let (sport, dport) = (u16_at(b, o)?, u16_at(b, o + 2)?);
    let (seq, ack) = (u32_at(b, o + 4)?, u32_at(b, o + 8)?);
    let hlen = ((b[o + 12] >> 4) as usize) * 4;
    let flags = b[o + 13];
    let names: Vec<&str> = [(0x02, "SYN"), (0x10, "ACK"), (0x08, "PSH"), (0x01, "FIN"), (0x04, "RST"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")]
        .iter()
        .filter(|(m, _)| flags & m != 0)
        .map(|(_, n)| *n)
        .collect();
    let hlen = hlen.max(20);
    let l = d.layer("TCP", o, o + hlen);
    field(l, "Source port", sport.to_string(), o, 2);
    field(l, "Destination port", dport.to_string(), o + 2, 2);
    field(l, "Sequence number", seq.to_string(), o + 4, 4);
    field(l, "Acknowledgment number", ack.to_string(), o + 8, 4);
    field(l, "Header length", format!("{hlen} bytes"), o + 12, 1);
    field(l, "Flags", format!("0x{flags:02x} [{}]", names.join(", ")), o + 13, 1);
    field(l, "Window", u16_at(b, o + 14)?.to_string(), o + 14, 2);
    field(l, "Checksum", format!("0x{:04x}", u16_at(b, o + 16)?), o + 16, 2);
    field(l, "Urgent pointer", u16_at(b, o + 18)?.to_string(), o + 18, 2);

    let mut p = o + 20;
    while p < (o + hlen).min(b.len()) {
        let kind = b[p];
        match kind {
            0 => break,
            1 => {
                p += 1;
                continue;
            }
            _ => {
                let Some(&len) = b.get(p + 1) else { break };
                let len = (len as usize).max(2);
                let value = match (kind, len) {
                    (2, 4) => format!("MSS {}", u16_at(b, p + 2).unwrap_or(0)),
                    (3, 3) => format!("window scale ×{}", 1u32 << b.get(p + 2).copied().unwrap_or(0).min(14)),
                    (4, 2) => "SACK permitted".into(),
                    (5, _) => format!("SACK {} block(s)", (len - 2) / 8),
                    (8, 10) => format!("timestamps {} / {}", u32_at(b, p + 2).unwrap_or(0), u32_at(b, p + 6).unwrap_or(0)),
                    _ => format!("kind {kind}, {len} bytes"),
                };
                field(l, "Option", value, p, len);
                p += len;
            }
        }
    }
    let payload_len = end.saturating_sub(o + hlen);
    l.summary = format!("{sport} → {dport} [{}] seq={seq} ack={ack} len={payload_len}", names.join(", "));
    Some((o + hlen, end, sport, dport))
}

fn udp(d: &mut Builder, o: usize, end: usize) -> Option<(usize, usize, u16, u16)> {
    let b = d.b;
    if b.len() < o + 8 {
        return None;
    }
    let (sport, dport, len) = (u16_at(b, o)?, u16_at(b, o + 2)?, u16_at(b, o + 4)?);
    let l = d.layer("UDP", o, o + 8);
    field(l, "Source port", sport.to_string(), o, 2);
    field(l, "Destination port", dport.to_string(), o + 2, 2);
    field(l, "Length", len.to_string(), o + 4, 2);
    field(l, "Checksum", format!("0x{:04x}", u16_at(b, o + 6)?), o + 6, 2);
    l.summary = format!("{sport} → {dport}, {} bytes payload", end.saturating_sub(o + 8));
    Some((o + 8, end, sport, dport))
}

fn icmp(d: &mut Builder, o: usize, end: usize, v6: bool) {
    let b = d.b;
    let (Some(&t), Some(&c)) = (b.get(o), b.get(o + 1)) else { return };
    let kind = match (v6, t) {
        (false, 8) | (true, 128) => "echo request",
        (false, 0) | (true, 129) => "echo reply",
        (false, 3) | (true, 1) => "destination unreachable",
        (false, 11) | (true, 3) => "time exceeded",
        (true, 135) => "neighbor solicitation",
        (true, 136) => "neighbor advertisement",
        (true, 133) => "router solicitation",
        (true, 134) => "router advertisement",
        _ => "other",
    };
    let l = d.layer(if v6 { "ICMPv6" } else { "ICMP" }, o, end);
    field(l, "Type", format!("{t} ({kind})"), o, 1);
    field(l, "Code", c.to_string(), o + 1, 1);
    if let Some(cs) = u16_at(b, o + 2) {
        field(l, "Checksum", format!("0x{cs:04x}"), o + 2, 2);
    }
    if matches!(kind, "echo request" | "echo reply") {
        if let (Some(id), Some(seq)) = (u16_at(b, o + 4), u16_at(b, o + 6)) {
            field(l, "Identifier", id.to_string(), o + 4, 2);
            field(l, "Sequence", seq.to_string(), o + 6, 2);
        }
    }
    l.summary = kind.to_string();
}

fn application(d: &mut Builder, start: usize, end: usize, sport: u16, dport: u16, proto: u8) {
    let b = d.b;
    let p = &b[start..end];
    let on = |ports: &[u16]| ports.contains(&sport) || ports.contains(&dport);

    if on(&DNS_PORTS) {
        let msg = if proto == 6 { p.get(2..).and_then(dns::parse) } else { dns::parse(p) };
        if let Some(m) = msg {
            let l = d.layer("DNS", start, end);
            field(l, "Transaction ID", format!("0x{:04x}", m.id), start, 2);
            field(l, "Type", if m.response { format!("response, rcode {}", m.rcode) } else { "query".into() }, start + 2, 2);
            for q in &m.questions {
                l.fields.push(Field { name: "Question".into(), value: format!("{} {}", dns::qtype_name(q.qtype), q.name), range: [start + 12, end] });
            }
            for a in &m.answers {
                l.fields.push(Field { name: "Answer".into(), value: format!("{} → {} (TTL {})", a.name, a.addr, a.ttl), range: [start + 12, end] });
            }
            l.summary = match (m.response, m.questions.first()) {
                (false, Some(q)) => format!("query {} {}", dns::qtype_name(q.qtype), q.name),
                (true, Some(q)) => format!("response {} → {} address(es)", q.name, m.answers.len()),
                _ => "DNS".into(),
            };
            return;
        }
    }
    if let Some(req) = http::parse_request(p) {
        http_layer(d, start, end, &format!("{} {}", req.method, req.path), req.sensitive.join(", "));
        return;
    }
    if http::is_response(p) {
        let line = p.split(|&c| c == b'\r').next().map(|l| String::from_utf8_lossy(l).to_string()).unwrap_or_default();
        http_layer(d, start, end, &line, String::new());
        return;
    }
    if tls::is_record(p) {
        tls_layer(d, start, end);
        return;
    }
    if proto == 17 && on(&QUIC_PORTS) && !p.is_empty() {
        let l = d.layer("QUIC", start, end);
        let long = p[0] & 0x80 != 0;
        field(l, "Header form", if long { "long (handshake)" } else { "short (1-RTT, encrypted)" }, start, 1);
        if long {
            if let Some(v) = u32_at(p, 1) {
                field(l, "Version", format!("0x{v:08x}"), start + 1, 4);
            }
        }
        l.summary = if long { "QUIC handshake packet".into() } else { "QUIC encrypted data".into() };
        return;
    }
    let l = d.layer("Data", start, end);
    l.summary = format!("{} bytes", end - start);
}

fn http_layer(d: &mut Builder, start: usize, end: usize, first: &str, sensitive: String) {
    let b = d.b;
    let p = &b[start..end];
    let l = d.layer("HTTP", start, end);
    let mut pos = start;
    for (i, line) in p.split(|&c| c == b'\n').enumerate() {
        let text = String::from_utf8_lossy(line).trim_end_matches('\r').to_string();
        let len = line.len() + 1;
        if text.is_empty() {
            if pos + len < end {
                field(l, "Body", format!("{} bytes", end - pos - len), pos + len, end - pos - len);
            }
            break;
        }
        let name = if i == 0 { "Start line".to_string() } else { text.split(':').next().unwrap_or("Header").to_string() };
        field(l, &name, text, pos, len.min(end - pos));
        pos += len;
        if i > 60 {
            break;
        }
    }
    if !sensitive.is_empty() {
        l.fields.push(Field { name: "⚠ Sensitive data".into(), value: sensitive, range: [start, end] });
    }
    l.summary = first.to_string();
}

fn tls_layer(d: &mut Builder, start: usize, end: usize) {
    let b = d.b;
    let l = d.layer("TLS", start, end);
    let mut pos = start;
    let mut parts = Vec::new();
    while pos + 5 <= end {
        let ct = b[pos];
        let ver = u16_at(b, pos + 1).unwrap_or(0);
        let len = u16_at(b, pos + 3).unwrap_or(0) as usize;
        let ct_name = match ct {
            20 => "ChangeCipherSpec",
            21 => "Alert",
            22 => "Handshake",
            23 => "Application data (encrypted)",
            _ => break,
        };
        let mut desc = ct_name.to_string();
        if ct == 22 {
            let hs = match b.get(pos + 5) {
                Some(1) => "ClientHello",
                Some(2) => "ServerHello",
                Some(11) => "Certificate",
                Some(12) => "ServerKeyExchange",
                Some(14) => "ServerHelloDone",
                Some(16) => "ClientKeyExchange",
                Some(4) => "NewSessionTicket",
                _ => "encrypted handshake",
            };
            desc = format!("Handshake: {hs}");
            if hs == "ClientHello" {
                if let Some(sni) = tls::client_hello_sni(&b[pos..end]) {
                    desc.push_str(&format!(", SNI {sni}"));
                }
            }
        }
        let rec_end = (pos + 5 + len).min(end);
        field(l, "Record", format!("{desc} — version 0x{ver:04x}, {len} bytes"), pos, rec_end - pos);
        parts.push(desc);
        pos = pos + 5 + len;
    }
    if pos < end && parts.is_empty() {
        field(l, "Data", format!("{} bytes", end - start), start, end - start);
    }
    l.summary = if parts.is_empty() { "TLS continuation".into() } else { parts.join(" · ") };
}

/// One-line description like Wireshark's "Info" column.
pub fn summary(lt: i32, b: &[u8]) -> String {
    let layers = dissect(lt, b);
    let top = layers.last();
    let transport = layers.iter().find(|l| matches!(l.name.as_str(), "TCP" | "UDP" | "ICMP" | "ICMPv6"));
    match (top, transport) {
        (Some(t), Some(tr)) if t.name != tr.name && t.name != "Data" => format!("{}: {}", t.name, t.summary),
        (_, Some(tr)) => format!("{}: {}", tr.name, tr.summary),
        (Some(t), None) => format!("{}: {}", t.name, t.summary),
        _ => "undecoded frame".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo::frames::{tcp_frame, udp_frame, TcpFlags};

    const A: [u8; 4] = [10, 0, 0, 2];
    const B: [u8; 4] = [93, 184, 215, 14];

    fn names(l: &[Layer]) -> Vec<&str> {
        l.iter().map(|l| l.name.as_str()).collect()
    }

    #[test]
    fn tcp_syn_layers_and_ranges() {
        let f = tcp_frame(A, B, 50000, 443, TcpFlags::Syn, b"");
        let l = dissect(linktype::ETHERNET, &f);
        assert_eq!(names(&l), vec!["Ethernet II", "IPv4", "TCP"]);
        assert_eq!(l[1].range, [14, 34]);
        let flags = l[2].fields.iter().find(|f| f.name == "Flags").unwrap();
        assert!(flags.value.contains("SYN") && !flags.value.contains("ACK"));
        assert_eq!(flags.range, [34 + 13, 34 + 14]);
        let src = l[1].fields.iter().find(|f| f.name == "Source").unwrap();
        assert_eq!((src.value.as_str(), src.range), ("10.0.0.2", [26, 30]));
        assert!(summary(linktype::ETHERNET, &f).starts_with("TCP: 50000 → 443 [SYN]"));
    }

    #[test]
    fn application_layers() {
        let http = tcp_frame(A, B, 5000, 80, TcpFlags::Data, b"POST /login HTTP/1.1\r\nHost: x.test\r\n\r\npassword=1");
        let l = dissect(linktype::ETHERNET, &http);
        let h = l.last().unwrap();
        assert_eq!((h.name.as_str(), h.summary.as_str()), ("HTTP", "POST /login"));
        assert!(h.fields.iter().any(|f| f.name == "Host" && f.value == "Host: x.test"));
        assert!(h.fields.iter().any(|f| f.name == "Body" && f.value == "10 bytes"));
        assert!(h.fields.iter().any(|f| f.name.contains("Sensitive")));
        assert_eq!(summary(linktype::ETHERNET, &http), "HTTP: POST /login");

        let hello = tcp_frame(A, B, 5000, 443, TcpFlags::Data, &tls::build_client_hello("github.com"));
        assert_eq!(summary(linktype::ETHERNET, &hello), "TLS: Handshake: ClientHello, SNI github.com");

        let q = udp_frame(A, B, 5353, 53, &dns::build_query(1, "example.org", dns::TYPE_A));
        assert_eq!(summary(linktype::ETHERNET, &q), "DNS: query A example.org");

        let quic = udp_frame(A, B, 5000, 443, &[0xC3, 0, 0, 0, 1, 9]);
        assert_eq!(summary(linktype::ETHERNET, &quic), "QUIC: QUIC handshake packet");

        let data = tcp_frame(A, B, 5000, 9000, TcpFlags::Data, b"hello");
        assert_eq!(dissect(linktype::ETHERNET, &data).last().unwrap().name, "Data");
        assert!(summary(linktype::ETHERNET, &data).starts_with("TCP: 5000 → 9000 [ACK, PSH]"));
    }

    #[test]
    fn truncated_and_unknown_frames_do_not_panic() {
        let f = tcp_frame(A, B, 1, 2, TcpFlags::Data, &[0x17, 3, 3, 0, 50, 1, 2]);
        for cut in 0..f.len() {
            dissect(linktype::ETHERNET, &f[..cut]);
            summary(linktype::ETHERNET, &f[..cut]);
        }
        assert_eq!(summary(9999, &[0xFF; 3]), "undecoded frame");
        assert_eq!(dissect(linktype::RAW, &f[14..])[0].name, "IPv4");
    }

    const SRC6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const DST6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    fn v6_udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let b = etherparse::PacketBuilder::ethernet2([2; 6], [4; 6]).ipv6(SRC6, DST6, 64).udp(sport, dport);
        let mut out = Vec::new();
        b.write(&mut out, payload).unwrap();
        out
    }

    fn icmp6_echo() -> Vec<u8> {
        let b = etherparse::PacketBuilder::ethernet2([2; 6], [4; 6]).ipv6(SRC6, DST6, 64).icmpv6_echo_request(1, 2);
        let mut out = Vec::new();
        b.write(&mut out, &[0u8; 8]).unwrap();
        out
    }

    fn icmp4_echo() -> Vec<u8> {
        let b = etherparse::PacketBuilder::ethernet2([2; 6], [4; 6]).ipv4(A, [1, 1, 1, 1], 64).icmpv4_echo_request(7, 9);
        let mut out = Vec::new();
        b.write(&mut out, &[0u8; 32]).unwrap();
        out
    }

    /// IPv6 with a hop-by-hop and a fragment header before UDP (hand-built).
    fn v6_with_extension_headers(payload: &[u8]) -> Vec<u8> {
        let mut f = vec![4, 4, 4, 4, 4, 4, 2, 2, 2, 2, 2, 2, 0x86, 0xDD];
        let plen = (8 + 8 + 8 + payload.len()) as u16;
        f.extend_from_slice(&[0x60, 0, 0, 0]);
        f.extend_from_slice(&plen.to_be_bytes());
        f.extend_from_slice(&[0, 64]); // next = hop-by-hop, hop limit
        f.extend_from_slice(&SRC6);
        f.extend_from_slice(&DST6);
        f.extend_from_slice(&[44, 0, 1, 4, 0, 0, 0, 0]); // hop-by-hop: next = fragment, 8 bytes
        f.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 1]); // fragment: next = UDP
        f.extend_from_slice(&5000u16.to_be_bytes());
        f.extend_from_slice(&53u16.to_be_bytes());
        f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(payload);
        f
    }

    fn vlan(frame: &[u8], vid: u16) -> Vec<u8> {
        let mut f = frame[..12].to_vec();
        f.extend_from_slice(&[0x81, 0x00]);
        f.extend_from_slice(&vid.to_be_bytes());
        f.extend_from_slice(&frame[12..]);
        f
    }

    /// IPv4 with a 24-byte header (one 4-byte option) carrying UDP.
    fn ipv4_with_options(payload: &[u8]) -> Vec<u8> {
        let mut f = vec![4, 4, 4, 4, 4, 4, 2, 2, 2, 2, 2, 2, 0x08, 0x00];
        let total = (24 + 8 + payload.len()) as u16;
        f.extend_from_slice(&[0x46, 0]);
        f.extend_from_slice(&total.to_be_bytes());
        f.extend_from_slice(&[0x12, 0x34, 0x40, 0x00, 64, 17, 0, 0]);
        f.extend_from_slice(&A);
        f.extend_from_slice(&B);
        f.extend_from_slice(&[1, 1, 1, 0]); // NOP NOP NOP EOL
        f.extend_from_slice(&[0x13, 0x88, 0, 53]);
        f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(payload);
        f
    }

    fn tcp_with_options() -> Vec<u8> {
        use etherparse::TcpOptionElement::*;
        let b = etherparse::PacketBuilder::ethernet2([2; 6], [4; 6])
            .ipv4(A, B, 64)
            .tcp(40000, 443, 1, 64_240)
            .syn()
            .options(&[MaximumSegmentSize(1460), Noop, WindowScale(7), SelectiveAcknowledgementPermitted, Timestamp(1, 2)])
            .unwrap();
        let mut out = Vec::new();
        b.write(&mut out, &[]).unwrap();
        out
    }

    fn fields<'a>(l: &'a Layer, name: &str) -> Vec<&'a str> {
        l.fields.iter().filter(|f| f.name == name).map(|f| f.value.as_str()).collect()
    }

    fn corpus() -> Vec<(i32, Vec<u8>)> {
        let hello = tls::build_client_hello("multi.example");
        let mut multi = hello.clone();
        multi.extend_from_slice(&[0x14, 3, 3, 0, 1, 1]);
        multi.extend_from_slice(&[0x17, 3, 3, 0, 4, 9, 9, 9, 9]);
        let q = dns::build_query(1, "example.org", dns::TYPE_A);
        let mut dns_tcp = (q.len() as u16).to_be_bytes().to_vec();
        dns_tcp.extend_from_slice(&q);
        let v6 = v6_udp(5000, 53, &q);
        let mut null = vec![30, 0, 0, 0];
        null.extend_from_slice(&v6[14..]);
        let mut sll2 = vec![0x86, 0xDD];
        sll2.extend_from_slice(&[0u8; 18]);
        sll2.extend_from_slice(&v6[14..]);
        vec![
            (linktype::ETHERNET, tcp_frame(A, B, 5000, 443, TcpFlags::Data, &multi)),
            (linktype::ETHERNET, tcp_frame(A, B, 5000, 443, TcpFlags::Data, &[0x17, 3, 3, 0xff, 0xff, 1, 2, 3])),
            (linktype::ETHERNET, tcp_frame(A, B, 5000, 443, TcpFlags::Data, &[1, 2, 3, 4, 5, 6])),
            (linktype::ETHERNET, tcp_frame(B, A, 80, 5000, TcpFlags::Data, b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nhi")),
            (linktype::ETHERNET, tcp_frame(A, B, 5000, 53, TcpFlags::Data, &dns_tcp)),
            (linktype::ETHERNET, udp_frame(B, A, 53, 5000, &dns::build_response(1, "example.org", &[std::net::IpAddr::from(B)], 60))),
            (linktype::ETHERNET, udp_frame(A, B, 5000, 443, &[0x40, 1, 2, 3])),
            (linktype::ETHERNET, udp_frame(A, B, 5000, 443, &[])),
            (linktype::ETHERNET, vlan(&tcp_frame(A, B, 5000, 80, TcpFlags::Data, b"GET / HTTP/1.1\r\nHost: v\r\n\r\n"), 5)),
            (linktype::ETHERNET, ipv4_with_options(&q)),
            (linktype::ETHERNET, tcp_with_options()),
            (linktype::ETHERNET, icmp4_echo()),
            (linktype::ETHERNET, icmp6_echo()),
            (linktype::ETHERNET, v6),
            (linktype::ETHERNET, v6_with_extension_headers(&q)),
            (linktype::RAW, v6_udp(1, 2, b"raw6")[14..].to_vec()),
            (linktype::RAW, udp_frame(A, B, 1, 2, b"raw4")[14..].to_vec()),
            (linktype::NULL, null),
            (linktype::LINUX_SLL2, sll2),
        ]
    }

    #[test]
    fn layers_of_many_frame_types() {
        let c = corpus();
        let l = dissect(c[0].0, &c[0].1);
        let tls_l = l.last().unwrap();
        assert_eq!(tls_l.name, "TLS");
        assert_eq!(fields(tls_l, "Record").len(), 3);
        assert_eq!(summary(c[0].0, &c[0].1), "TLS: Handshake: ClientHello, SNI multi.example · ChangeCipherSpec · Application data (encrypted)");
        assert!(summary(c[1].0, &c[1].1).starts_with("TLS: Application data (encrypted)"), "record longer than the frame is clamped");
        assert_eq!(dissect(c[2].0, &c[2].1).last().unwrap().name, "Data", "port 443 without a record header is just data");
        let http = dissect(c[3].0, &c[3].1);
        assert_eq!((http.last().unwrap().name.as_str(), http.last().unwrap().summary.as_str()), ("HTTP", "HTTP/1.1 404 Not Found"));
        assert_eq!(fields(http.last().unwrap(), "Body"), vec!["2 bytes"]);
        assert_eq!(summary(c[4].0, &c[4].1), "DNS: query A example.org", "DNS over TCP skips the length prefix");
        assert_eq!(summary(c[5].0, &c[5].1), "DNS: response example.org → 1 address(es)");
        assert!(dissect(c[5].0, &c[5].1).last().unwrap().fields.iter().any(|f| f.name == "Answer" && f.value.contains("93.184.215.14")));
        assert_eq!(summary(c[6].0, &c[6].1), "QUIC: QUIC encrypted data");
        assert!(summary(c[7].0, &c[7].1).starts_with("UDP: 5000 → 443, 0 bytes payload"), "empty payload: no application layer");

        let v = dissect(c[8].0, &c[8].1);
        assert_eq!(names(&v), vec!["Ethernet II", "802.1Q VLAN", "IPv4", "TCP", "HTTP"]);
        assert_eq!((v[1].summary.as_str(), v[1].range, v[2].range), ("VLAN 5", [14, 18], [18, 38]));
        assert_eq!(summary(c[8].0, &c[8].1), "HTTP: GET /");

        let o = dissect(c[9].0, &c[9].1);
        assert_eq!(names(&o), vec!["Ethernet II", "IPv4", "UDP", "DNS"]);
        assert_eq!(o[1].range, [14, 38]);
        assert_eq!(fields(&o[1], "Options"), vec!["4 bytes"]);
        assert_eq!(fields(&o[1], "Flags / fragment offset"), vec!["DF / 0"]);

        let t = dissect(c[10].0, &c[10].1);
        assert_eq!(fields(&t[2], "Header length"), vec!["40 bytes"]);
        assert_eq!(fields(&t[2], "Option"), vec!["MSS 1460", "window scale ×128", "SACK permitted", "timestamps 1 / 2"]);
        assert_eq!(t[2].range, [34, 74]);

        let i4 = dissect(c[11].0, &c[11].1);
        assert_eq!(names(&i4), vec!["Ethernet II", "IPv4", "ICMP"]);
        assert_eq!((fields(&i4[2], "Type"), fields(&i4[2], "Identifier"), fields(&i4[2], "Sequence")), (vec!["8 (echo request)"], vec!["7"], vec!["9"]));
        assert_eq!(summary(c[11].0, &c[11].1), "ICMP: echo request");
        assert_eq!(summary(c[12].0, &c[12].1), "ICMPv6: echo request");

        let v6 = dissect(c[13].0, &c[13].1);
        assert_eq!(names(&v6), vec!["Ethernet II", "IPv6", "UDP", "DNS"]);
        assert_eq!(v6[1].range, [14, 54]);
        assert_eq!(v6[1].summary, "2001:db8::1 → 2001:db8::2, hop limit 64");
        let ext = dissect(c[14].0, &c[14].1);
        assert_eq!(names(&ext), vec!["Ethernet II", "IPv6", "IPv6 extension header", "IPv6 fragment header", "UDP", "DNS"]);
        assert_eq!((ext[2].range, ext[3].range, ext[4].range), ([54, 62], [62, 70], [70, 78]));
        assert_eq!(summary(c[14].0, &c[14].1), "DNS: query A example.org");

        assert_eq!(names(&dissect(c[15].0, &c[15].1)), vec!["IPv6", "UDP", "Data"], "raw IPv6 recognized by its version nibble");
        assert_eq!(names(&dissect(c[16].0, &c[16].1)), vec!["IPv4", "UDP", "Data"]);
        assert_eq!(names(&dissect(c[17].0, &c[17].1)), vec!["Loopback", "IPv6", "UDP", "DNS"]);
        assert_eq!(names(&dissect(c[18].0, &c[18].1)), vec!["Linux cooked capture v2", "IPv6", "UDP", "DNS"]);
        // The decoder agrees on VLAN and extension-header frames.
        let p = super::super::decode(linktype::ETHERNET, &c[8].1).unwrap();
        assert_eq!((p.src_port, p.dst_port, p.proto), (5000, 80, super::super::Proto::Http));
        let p = super::super::decode(linktype::ETHERNET, &c[14].1).unwrap();
        assert_eq!((p.dst_port, p.proto), (53, super::super::Proto::Dns));
    }

    fn check_invariants(lt: i32, b: &[u8], complete: bool) {
        for l in dissect(lt, b) {
            assert!(l.range[1] <= b.len(), "layer {} range {:?} in {} bytes", l.name, l.range, b.len());
            if complete {
                assert!(l.range[0] <= l.range[1], "layer {} range {:?}", l.name, l.range);
            }
            for f in &l.fields {
                assert!(f.range[0] <= f.range[1], "{}/{}: {:?}", l.name, f.name, f.range);
                if complete {
                    assert!(f.range[1] <= b.len(), "{}/{} range {:?} beyond the {}-byte frame", l.name, f.name, f.range, b.len());
                }
            }
        }
        let _ = summary(lt, b);
    }

    #[test]
    fn every_prefix_of_every_frame_type_is_handled() {
        for (lt, f) in corpus() {
            check_invariants(lt, &f, true);
            for cut in 0..f.len() {
                check_invariants(lt, &f[..cut], false);
            }
        }
    }

    /// Regression: `ipv6()` used to push the "IPv6 fragment header" layer before checking that
    /// its 8 bytes exist, so a frame cut after a hop-by-hop header got a layer whose range
    /// started beyond the frame, e.g. `[62, 56]` in 56 bytes.
    #[test]
    fn layer_ranges_never_start_beyond_the_frame() {
        let f = v6_with_extension_headers(&dns::build_query(1, "example.org", dns::TYPE_A));
        for cut in 0..f.len() {
            let layers = dissect(linktype::ETHERNET, &f[..cut]);
            for l in &layers {
                assert!(l.range[0] <= l.range[1] && l.range[1] <= cut, "cut {cut}: layer {} range {:?}", l.name, l.range);
            }
            // Extension-header layers only appear once they are complete.
            let names: Vec<&str> = layers.iter().map(|l| l.name.as_str()).collect();
            assert_eq!(names.contains(&"IPv6 extension header"), cut >= 62, "cut {cut}: {names:?}");
            assert_eq!(names.contains(&"IPv6 fragment header"), cut >= 70, "cut {cut}: {names:?}");
        }
    }

    #[test]
    fn random_mutations_do_not_panic() {
        let base = corpus();
        let mut seed = 0x0123_4567_89ab_cdefu64;
        let mut rnd = move || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 33) as u32
        };
        for _ in 0..4000 {
            let (lt, f) = &base[rnd() as usize % base.len()];
            let mut m = f.clone();
            for _ in 0..1 + rnd() % 4 {
                let i = rnd() as usize % m.len();
                m[i] = rnd() as u8;
            }
            let lt = if rnd() % 8 == 0 { [linktype::RAW, linktype::NULL, linktype::LINUX_SLL, linktype::LINUX_SLL2, linktype::ETHERNET][rnd() as usize % 5] } else { *lt };
            check_invariants(lt, &m, false);
            let _ = super::super::decode(lt, &m);
            let garbage: Vec<u8> = (0..rnd() % 120).map(|_| rnd() as u8).collect();
            check_invariants(lt, &garbage, false);
        }
    }
}
