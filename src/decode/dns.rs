//! Minimal DNS wire-format parser (RFC 1035): questions plus A/AAAA answers,
//! with compression-pointer loop protection. Builders are used by demo mode and tests.

use std::net::IpAddr;

pub const TYPE_A: u16 = 1;
pub const TYPE_NULL: u16 = 10;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_ANY: u16 = 255;

const MAX_QUESTIONS: u16 = 16;
const MAX_ANSWERS: u16 = 64;
const MAX_POINTER_JUMPS: usize = 16;
const MAX_NAME_LEN: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub name: String,
    pub addr: IpAddr,
    pub ttl: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub id: u16,
    pub response: bool,
    pub rcode: u8,
    pub questions: Vec<Question>,
    /// Only A and AAAA records; other answer types are skipped.
    pub answers: Vec<Answer>,
}

pub fn qtype_name(t: u16) -> &'static str {
    match t {
        TYPE_A => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        TYPE_NULL => "NULL",
        12 => "PTR",
        15 => "MX",
        TYPE_TXT => "TXT",
        TYPE_AAAA => "AAAA",
        33 => "SRV",
        65 => "HTTPS",
        TYPE_ANY => "ANY",
        _ => "OTHER",
    }
}

pub fn parse(b: &[u8]) -> Option<DnsMessage> {
    if b.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([b[0], b[1]]);
    let flags = u16::from_be_bytes([b[2], b[3]]);
    let qd = u16::from_be_bytes([b[4], b[5]]);
    let an = u16::from_be_bytes([b[6], b[7]]);
    // Opcode must be QUERY (0); anything else is unlikely to be DNS on these ports.
    if (flags >> 11) & 0xF != 0 || qd == 0 || qd > MAX_QUESTIONS {
        return None;
    }

    let mut pos = 12;
    let mut questions = Vec::with_capacity(qd as usize);
    for _ in 0..qd {
        let (name, next) = read_name(b, pos)?;
        let qtype = u16::from_be_bytes([*b.get(next)?, *b.get(next + 1)?]);
        b.get(next + 3)?; // qclass
        questions.push(Question { name, qtype });
        pos = next + 4;
    }

    let mut answers = Vec::new();
    for _ in 0..an.min(MAX_ANSWERS) {
        let Some((name, next)) = read_name(b, pos) else { break };
        let Some(fixed) = b.get(next..next + 10) else { break };
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let ttl = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
        let rdlen = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        let Some(rdata) = b.get(next + 10..next + 10 + rdlen) else { break };
        let addr = match (rtype, rdlen) {
            (TYPE_A, 4) => Some(IpAddr::from(<[u8; 4]>::try_from(rdata).ok()?)),
            (TYPE_AAAA, 16) => Some(IpAddr::from(<[u8; 16]>::try_from(rdata).ok()?)),
            _ => None,
        };
        if let Some(addr) = addr {
            answers.push(Answer { name, addr, ttl });
        }
        pos = next + 10 + rdlen;
    }

    Some(DnsMessage { id, response: flags & 0x8000 != 0, rcode: (flags & 0xF) as u8, questions, answers })
}

/// Reads a possibly compressed name at `pos`; returns it lowercased and the offset after it.
fn read_name(b: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut after = None;
    let mut jumps = 0;
    loop {
        let len = *b.get(pos)? as usize;
        match len {
            0 => {
                return Some((if name.is_empty() { ".".into() } else { name }, after.unwrap_or(pos + 1)));
            }
            l if l & 0xC0 == 0xC0 => {
                let target = ((l & 0x3F) << 8) | *b.get(pos + 1)? as usize;
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS || target >= b.len() {
                    return None;
                }
                after.get_or_insert(pos + 2);
                pos = target;
            }
            l if l <= 63 => {
                let label = b.get(pos + 1..pos + 1 + l)?;
                if !name.is_empty() {
                    name.push('.');
                }
                for &c in label {
                    // Keep names printable; anything else is shown escaped.
                    if c.is_ascii_graphic() {
                        name.push(c.to_ascii_lowercase() as char);
                    } else {
                        name.push_str(&format!("\\{c:03}"));
                    }
                }
                if name.len() > MAX_NAME_LEN * 4 {
                    return None;
                }
                pos += 1 + l;
            }
            _ => return None,
        }
    }
}

fn write_name(out: &mut Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.').filter(|l| !l.is_empty()) {
        let bytes = &label.as_bytes()[..label.len().min(63)];
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);
}

fn header(id: u16, flags: u16, qd: u16, an: u16) -> Vec<u8> {
    let mut h = Vec::with_capacity(512);
    for v in [id, flags, qd, an, 0, 0] {
        h.extend_from_slice(&v.to_be_bytes());
    }
    h
}

/// A recursive query for `name`.
pub fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut m = header(id, 0x0100, 1, 0);
    write_name(&mut m, name);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    m
}

/// A response answering `name` with `addrs` (compressed names pointing at the question).
pub fn build_response(id: u16, name: &str, addrs: &[IpAddr], ttl: u32) -> Vec<u8> {
    let qtype = if addrs.first().is_some_and(IpAddr::is_ipv6) { TYPE_AAAA } else { TYPE_A };
    let mut m = header(id, 0x8180, 1, addrs.len() as u16);
    write_name(&mut m, name);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    for addr in addrs {
        m.extend_from_slice(&[0xC0, 12]);
        let (t, data): (u16, Vec<u8>) = match addr {
            IpAddr::V4(a) => (TYPE_A, a.octets().to_vec()),
            IpAddr::V6(a) => (TYPE_AAAA, a.octets().to_vec()),
        };
        m.extend_from_slice(&t.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&ttl.to_be_bytes());
        m.extend_from_slice(&(data.len() as u16).to_be_bytes());
        m.extend_from_slice(&data);
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_roundtrip() {
        let m = parse(&build_query(7, "WWW.Example.COM", TYPE_AAAA)).unwrap();
        assert_eq!(m.id, 7);
        assert!(!m.response);
        assert_eq!(m.questions, vec![Question { name: "www.example.com".into(), qtype: TYPE_AAAA }]);
        assert!(m.answers.is_empty());
    }

    #[test]
    fn response_with_compressed_answers() {
        let addrs: Vec<IpAddr> = vec!["93.184.215.14".parse().unwrap(), "93.184.215.15".parse().unwrap()];
        let m = parse(&build_response(9, "example.org", &addrs, 300)).unwrap();
        assert!(m.response);
        assert_eq!(m.rcode, 0);
        assert_eq!(m.answers.len(), 2);
        assert_eq!(m.answers[0], Answer { name: "example.org".into(), addr: addrs[0], ttl: 300 });
        let v6 = parse(&build_response(1, "v6.example", &["2001:db8::1".parse().unwrap()], 5)).unwrap();
        assert_eq!(v6.answers[0].addr, "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn rejects_garbage_and_loops() {
        assert!(parse(b"").is_none());
        assert!(parse(&[0u8; 11]).is_none());
        assert!(parse(&[0u8; 12]).is_none(), "zero questions");
        // A name that points at itself.
        let mut looped = header(1, 0x0100, 1, 0);
        looped.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]);
        assert!(parse(&looped).is_none());
        // Truncated question.
        let q = build_query(1, "example.com", TYPE_A);
        assert!(parse(&q[..q.len() - 3]).is_none());
        // Non-QUERY opcode.
        let mut notify = build_query(1, "example.com", TYPE_A);
        notify[2] = 0x20;
        assert!(parse(&notify).is_none());
    }

    #[test]
    fn non_printable_labels_are_escaped() {
        let mut q = header(1, 0x0100, 1, 0);
        q.extend_from_slice(&[3, b'a', 0x01, b'<', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1]);
        assert_eq!(parse(&q).unwrap().questions[0].name, "a\\001<.com");
    }

    #[test]
    fn type_names() {
        assert_eq!(qtype_name(TYPE_TXT), "TXT");
        assert_eq!(qtype_name(9999), "OTHER");
    }

    /// Valid messages of every shape the builders produce, for the sweeps below.
    fn corpus() -> Vec<Vec<u8>> {
        let v4: Vec<IpAddr> = (1..=5).map(|i| IpAddr::from([93, 184, 215, i])).collect();
        let v6: Vec<IpAddr> = vec!["2001:db8::1".parse().unwrap(), "2001:db8::2".parse().unwrap()];
        let mut mixed = build_response(3, "mixed.example", &v4[..1], 60);
        // A CNAME answer (rdata is a name) between two A records.
        mixed[7] = 3;
        mixed.extend_from_slice(&[0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xC0, 12]);
        mixed.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        vec![
            build_query(1, "example.org", TYPE_A),
            build_query(2, "a.very.long.sub.domain.name.with.many.labels.example.co.uk", TYPE_AAAA),
            build_response(3, "example.org", &v4, 300),
            build_response(4, "v6.example", &v6, 5),
            build_response(5, "nothing.example", &[], 1),
            mixed,
        ]
    }

    #[test]
    fn every_prefix_and_random_mutation_is_handled() {
        for m in corpus() {
            assert!(parse(&m).is_some(), "corpus message must parse");
            for cut in 0..m.len() {
                let _ = parse(&m[..cut]);
            }
            for i in 0..m.len() {
                for v in [0x00, 0x3F, 0x40, 0xC0, 0xFF] {
                    let mut x = m.clone();
                    x[i] = v;
                    let _ = parse(&x);
                }
            }
        }
        // Tiny LCG: deterministic byte flips and random buffers.
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        let mut rnd = move || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 33) as u32
        };
        let base = corpus();
        for _ in 0..3000 {
            let mut x = base[rnd() as usize % base.len()].clone();
            for _ in 0..1 + rnd() % 4 {
                let i = rnd() as usize % x.len();
                x[i] = rnd() as u8;
            }
            let _ = parse(&x);
            let garbage: Vec<u8> = (0..rnd() % 80).map(|_| rnd() as u8).collect();
            let _ = parse(&garbage);
        }
    }

    #[test]
    fn question_and_answer_limits() {
        // More questions than MAX_QUESTIONS is refused outright, at the limit it is fine.
        let mut many = header(1, 0x0100, MAX_QUESTIONS + 1, 0);
        many.extend_from_slice(&[0, 0, 1, 0, 1]);
        assert!(parse(&many).is_none());
        let mut at_limit = header(1, 0x0100, MAX_QUESTIONS, 0);
        for _ in 0..MAX_QUESTIONS {
            at_limit.extend_from_slice(&[0, 0, 1, 0, 1]); // root name, A, IN
        }
        let m = parse(&at_limit).unwrap();
        assert_eq!(m.questions.len(), MAX_QUESTIONS as usize);
        assert!(m.questions.iter().all(|q| q.name == "."), "the root is shown as a dot");

        // An answer count beyond MAX_ANSWERS only yields the first MAX_ANSWERS records.
        let addrs: Vec<IpAddr> = (0..200u16).map(|i| IpAddr::from([10, 0, (i >> 8) as u8, i as u8])).collect();
        let m = parse(&build_response(1, "many.example", &addrs, 1)).unwrap();
        assert_eq!(m.answers.len(), MAX_ANSWERS as usize);
        assert_eq!(m.answers[0].addr, addrs[0]);

        // Answers are best effort: a truncated answer section keeps what was complete.
        let full = build_response(1, "cut.example", &addrs[..3], 1);
        let m = parse(&full[..full.len() - 2]).unwrap();
        assert_eq!(m.answers.len(), 2);
        // Wrong rdata length for the type: skipped, not an address made of garbage.
        let mut odd = build_response(1, "odd.example", &addrs[..1], 1);
        let at = odd.len() - 6;
        odd[at + 1] = 5;
        odd.push(9);
        assert!(parse(&odd).unwrap().answers.is_empty());
        // A compression pointer to the end of the message (or past it) is an error.
        let mut ptr = header(1, 0x0100, 1, 0);
        ptr.extend_from_slice(&[0xC0, 0xFF, 0, 1, 0, 1]);
        assert!(parse(&ptr).is_none());
        // Label length bytes 0x40..0xBF are neither labels nor pointers.
        let mut bad_len = header(1, 0x0100, 1, 0);
        bad_len.extend_from_slice(&[0x41, b'a', 0, 0, 1, 0, 1]);
        assert!(parse(&bad_len).is_none());
        // A chain of pointers longer than MAX_POINTER_JUMPS gives up.
        let mut chain = header(1, 0x0100, 1, 0);
        for j in 0..20u8 {
            chain.extend_from_slice(&[0xC0, 12 + 2 * (j + 1)]);
        }
        chain.extend_from_slice(&[0, 0, 1, 0, 1]);
        assert!(parse(&chain).is_none());
        // Response/rcode flags are reported, qclass must be present.
        let mut nx = build_response(7, "nx.example", &[], 0);
        nx[3] |= 3;
        let m = parse(&nx).unwrap();
        assert!((m.response, m.rcode) == (true, 3));
        let q = build_query(1, "x.example", TYPE_A);
        assert!(parse(&q[..q.len() - 1]).is_none(), "qclass cut");
    }

    #[test]
    fn long_names_are_bounded() {
        // 63-byte labels up to the 255-byte wire limit parse; the builder caps longer labels.
        let name = ["a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61)].join(".");
        let m = parse(&build_query(1, &name, TYPE_A)).unwrap();
        assert_eq!(m.questions[0].name, name);
        assert_eq!(build_query(1, &"z".repeat(100), TYPE_A)[12], 63);
        // Hand-built: many labels of non-printable bytes, escaped 4x, stop before a huge string.
        let mut huge = header(1, 0x0100, 1, 0);
        for _ in 0..40 {
            huge.push(63);
            huge.extend(std::iter::repeat_n(0x01u8, 63));
        }
        huge.extend_from_slice(&[0, 0, 1, 0, 1]);
        assert!(parse(&huge).is_none(), "escaped name beyond MAX_NAME_LEN * 4 is refused");
        let mut four = header(1, 0x0100, 1, 0);
        for _ in 0..4 {
            four.push(63);
            four.extend(std::iter::repeat_n(0x01u8, 63));
        }
        four.extend_from_slice(&[0, 0, 1, 0, 1]);
        let name = &parse(&four).unwrap().questions[0].name;
        assert!(name.starts_with("\\001\\001") && name.len() == 4 * 63 * 4 + 3);
    }
}
