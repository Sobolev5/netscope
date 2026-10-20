//! TLS handshake details for the packet inspector: ClientHello fields and JA4
//! fingerprint, ServerHello, and the server certificate chain (TLS 1.2 and below).

use serde::Serialize;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::sha256::{hex, sha256};

/// Fields of a TLS ClientHello relevant for display and fingerprinting.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ClientHello {
    pub legacy_version: u16,
    /// supported_versions extension values, GREASE removed, original order.
    pub versions: Vec<u16>,
    /// GREASE removed, original order.
    pub ciphers: Vec<u16>,
    /// Extension types in original order, GREASE removed.
    pub extensions: Vec<u16>,
    pub sni: Option<String>,
    /// ALPN protocol names. Bytes are mapped 1:1 to chars (Latin-1), so
    /// non-UTF-8 identifiers survive unchanged for the JA4 computation.
    pub alpn: Vec<String>,
    /// signature_algorithms extension values in original order.
    pub sig_algs: Vec<u16>,
}

/// Fields of a TLS ServerHello.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ServerHello {
    /// From supported_versions if present, else the legacy version field.
    pub version: u16,
    pub cipher: u16,
    pub alpn: Option<String>,
}

/// Summary of an X.509 certificate.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CertInfo {
    pub subject_cn: Option<String>,
    pub subject_org: Option<String>,
    pub issuer_cn: Option<String>,
    pub issuer_org: Option<String>,
    /// "YYYY-MM-DD HH:MM:SS UTC"
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    /// Unix seconds, for expiry checks.
    pub not_after_unix: Option<i64>,
    /// dNSName and iPAddress SAN entries (IPs as text).
    pub san: Vec<String>,
    /// Subject DN bytes == issuer DN bytes.
    pub self_signed: bool,
    /// Serial number, lowercase hex.
    pub serial: String,
}

/// What could be learned from the server side of a TLS handshake.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct ServerSide {
    pub hello: Option<ServerHello>,
    /// Leaf first. Empty when TLS 1.3 (certificates are encrypted) or not captured.
    pub certificates: Vec<CertInfo>,
    /// True when the negotiated version is TLS 1.3, i.e. the certificate is not visible on the wire.
    pub encrypted_certificates: bool,
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }
    /// Up to `n` bytes: whatever is left if the input is shorter.
    fn take_upto(&mut self, n: usize) -> &'a [u8] {
        let (head, rest) = self.0.split_at(n.min(self.0.len()));
        self.0 = rest;
        head
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_be_bytes([s[0], s[1]]))
    }
    fn u24(&mut self) -> Option<usize> {
        self.take(3).map(|s| usize::from(s[0]) << 16 | usize::from(s[1]) << 8 | usize::from(s[2]))
    }
    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()?;
        self.take(n.into())
    }
    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()?;
        self.take(n.into())
    }
    fn vec24(&mut self) -> Option<&'a [u8]> {
        let n = self.u24()?;
        self.take(n)
    }
}

/// GREASE values (RFC 8701): 0x0a0a, 0x1a1a, ... 0xfafa.
fn is_grease(v: u16) -> bool {
    v >> 8 == v & 0xff && v & 0x0f == 0x0a
}

fn u16s(b: &[u8]) -> impl Iterator<Item = u16> + '_ {
    b.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c))
}

fn latin1(b: &[u8]) -> String {
    b.iter().map(|&c| char::from(c)).collect()
}

/// Parses a ClientHello starting at the TLS record header (0x16 0x03 ..).
/// A truncated record is parsed as far as possible; returns None if the
/// cipher list or extension block is cut off.
pub fn parse_client_hello(record: &[u8]) -> Option<ClientHello> {
    let mut c = Cursor(record);
    if c.u8()? != 0x16 || c.u8()? != 3 {
        return None;
    }
    c.u8()?;
    let len = c.u16()?;
    parse_client_hello_handshake(c.take_upto(len.into()))
}

/// Parses a ClientHello starting at the handshake header (type 1), e.g. the
/// content of QUIC CRYPTO frames.
pub fn parse_client_hello_handshake(hs: &[u8]) -> Option<ClientHello> {
    let mut c = Cursor(hs);
    if c.u8()? != 1 {
        return None;
    }
    let len = c.u24()?;
    let mut c = Cursor(c.take_upto(len));
    let legacy_version = c.u16()?;
    c.take(32)?; // random
    c.vec8()?; // session id
    let ciphers = c.vec16()?;
    c.vec8()?; // compression methods
    let mut hello = ClientHello {
        legacy_version,
        versions: Vec::new(),
        ciphers: u16s(ciphers).filter(|&v| !is_grease(v)).collect(),
        extensions: Vec::new(),
        sni: None,
        alpn: Vec::new(),
        sig_algs: Vec::new(),
    };
    if c.0.is_empty() {
        return Some(hello); // no extension block at all (SSL 3.0 style)
    }
    let mut ext = Cursor(c.vec16()?);
    while !ext.0.is_empty() {
        let typ = ext.u16()?;
        let data = ext.vec16()?;
        if is_grease(typ) {
            continue;
        }
        hello.extensions.push(typ);
        match typ {
            0x0000 => hello.sni = parse_sni(data),
            0x0010 => hello.alpn = parse_alpn(data).unwrap_or_default(),
            0x000d => hello.sig_algs = Cursor(data).vec16().map(|b| u16s(b).collect()).unwrap_or_default(),
            0x002b => {
                hello.versions = Cursor(data)
                    .vec8()
                    .map(|b| u16s(b).filter(|&v| !is_grease(v)).collect())
                    .unwrap_or_default()
            }
            _ => {}
        }
    }
    Some(hello)
}

fn parse_sni(data: &[u8]) -> Option<String> {
    let mut list = Cursor(Cursor(data).vec16()?);
    while !list.0.is_empty() {
        let kind = list.u8()?;
        let name = list.vec16()?;
        if kind == 0 {
            return Some(String::from_utf8_lossy(name).into_owned());
        }
    }
    None
}

fn parse_alpn(data: &[u8]) -> Option<Vec<String>> {
    let mut list = Cursor(Cursor(data).vec16()?);
    let mut out = Vec::new();
    while !list.0.is_empty() {
        out.push(latin1(list.vec8()?));
    }
    Some(out)
}

fn hash12(s: &str) -> String {
    let mut h = hex(&sha256(s.as_bytes()));
    h.truncate(12);
    h
}

fn hex_list(v: &[u16]) -> String {
    v.iter().map(|x| format!("{x:04x}")).collect::<Vec<_>>().join(",")
}

impl ClientHello {
    /// Highest supported_versions value, or the legacy version if the extension is absent.
    pub fn max_version(&self) -> u16 {
        self.versions.iter().copied().max().unwrap_or(self.legacy_version)
    }

    /// JA4 fingerprint (FoxIO spec); `quic` selects the 'q' protocol prefix instead of 't'.
    pub fn ja4(&self, quic: bool) -> String {
        let version = match self.max_version() {
            0x0304 => "13",
            0x0303 => "12",
            0x0302 => "11",
            0x0301 => "10",
            0x0300 => "s3",
            0x0002 => "s2",
            0xfeff => "d1",
            0xfefd => "d2",
            0xfefc => "d3",
            _ => "00",
        };
        let ends = self.alpn.first().and_then(|s| Some((s.chars().next()?, s.chars().last()?)));
        let alpn = match ends {
            None => "00".to_string(),
            Some((f, l)) if f.is_ascii_alphanumeric() && l.is_ascii_alphanumeric() => format!("{f}{l}"),
            Some((f, l)) => {
                // Spec: first hex digit of the first byte, last hex digit of the last byte.
                let (f, l) = (hex(&[f as u32 as u8]), hex(&[l as u32 as u8]));
                format!("{}{}", &f[..1], &l[1..])
            }
        };
        let a = format!(
            "{}{}{}{:02}{:02}{}",
            if quic { 'q' } else { 't' },
            version,
            if self.sni.is_some() { 'd' } else { 'i' },
            self.ciphers.len().min(99),
            self.extensions.len().min(99),
            alpn
        );

        let mut ciphers = self.ciphers.clone();
        ciphers.sort_unstable();
        let b = if ciphers.is_empty() { "000000000000".to_string() } else { hash12(&hex_list(&ciphers)) };

        let mut exts: Vec<u16> = self.extensions.iter().copied().filter(|&e| e != 0x0000 && e != 0x0010).collect();
        exts.sort_unstable();
        let c = if exts.is_empty() {
            "000000000000".to_string()
        } else if self.sig_algs.is_empty() {
            hash12(&hex_list(&exts))
        } else {
            hash12(&format!("{}_{}", hex_list(&exts), hex_list(&self.sig_algs)))
        };
        format!("{a}_{b}_{c}")
    }
}

/// Human-readable protocol version.
pub fn version_name(v: u16) -> &'static str {
    match v {
        0x0304 => "TLS 1.3",
        0x0303 => "TLS 1.2",
        0x0302 => "TLS 1.1",
        0x0301 => "TLS 1.0",
        0x0300 => "SSL 3.0",
        _ => "unknown",
    }
}

/// IANA name of common cipher suites.
pub fn cipher_name(c: u16) -> Option<&'static str> {
    Some(match c {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0x1304 => "TLS_AES_128_CCM_SHA256",
        0x1305 => "TLS_AES_128_CCM_8_SHA256",
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        0xc009 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        0xc00a => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        0xc013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xc014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        _ => return None,
    })
}

/// Parses the reassembled server->client byte stream from its start: the
/// ServerHello and, for TLS 1.2 and below, the Certificate message.
/// Truncated input yields whatever was parsed.
pub fn parse_server_stream(stream: &[u8]) -> ServerSide {
    // Concatenate consecutive handshake records; anything else (CCS, alert,
    // application data) ends the plaintext part of the handshake.
    let mut hs = Vec::new();
    let mut rest = Cursor(stream);
    while let Some(&[22, 3, _, hi, lo]) = rest.take(5) {
        hs.extend_from_slice(rest.take_upto(usize::from(u16::from_be_bytes([hi, lo]))));
    }

    let mut out = ServerSide::default();
    let mut c = Cursor(&hs);
    while let (Some(typ), Some(len)) = (c.u8(), c.u24()) {
        let body = c.take_upto(len);
        match typ {
            2 if out.hello.is_none() => {
                out.hello = parse_server_hello(body);
                out.encrypted_certificates = out.hello.as_ref().is_some_and(|h| h.version == 0x0304);
            }
            11 if !out.encrypted_certificates && out.certificates.is_empty() => {
                let mut c = Cursor(body);
                if let Some(len) = c.u24() {
                    let mut list = Cursor(c.take_upto(len));
                    while let Some(der) = list.vec24() {
                        out.certificates.extend(parse_certificate(der));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn parse_server_hello(body: &[u8]) -> Option<ServerHello> {
    let mut c = Cursor(body);
    let mut hello = ServerHello { version: c.u16()?, cipher: 0, alpn: None };
    c.take(32)?; // random
    c.vec8()?; // session id
    hello.cipher = c.u16()?;
    c.u8()?; // compression
    let mut ext = Cursor(c.vec16().unwrap_or_default());
    while let (Some(typ), Some(data)) = (ext.u16(), ext.vec16()) {
        let mut d = Cursor(data);
        match typ {
            0x002b => hello.version = d.u16().unwrap_or(hello.version),
            0x0010 => hello.alpn = d.vec16().and_then(|l| Cursor(l).vec8()).map(latin1),
            _ => {}
        }
    }
    Some(hello)
}

// ---- X.509 / DER ----

/// One DER TLV: (tag, content, rest). Only low tag numbers and definite lengths.
fn der(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, b) = b.split_first()?;
    let (&l, b) = b.split_first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (len, b) = if l < 0x80 {
        (usize::from(l), b)
    } else {
        let n = usize::from(l & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let (lb, b) = b.split_at_checked(n)?;
        (lb.iter().fold(0usize, |a, &x| a << 8 | usize::from(x)), b)
    };
    let (content, rest) = b.split_at_checked(len)?;
    Some((tag, content, rest))
}

/// The TLVs inside a constructed value.
fn items(mut b: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    std::iter::from_fn(move || {
        let (tag, content, rest) = der(b)?;
        b = rest;
        Some((tag, content))
    })
}

const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_O: &[u8] = &[0x55, 0x04, 0x0a];
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];

/// Parses a DER-encoded X.509 certificate.
pub fn parse_certificate(der_bytes: &[u8]) -> Option<CertInfo> {
    let (0x30, cert, _) = der(der_bytes)? else { return None };
    let (0x30, tbs, _) = der(cert)? else { return None };
    let mut it = items(tbs).peekable();
    if it.peek()?.0 == 0xa0 {
        it.next(); // version
    }
    let (0x02, serial) = it.next()? else { return None };
    it.next()?; // signature algorithm
    let (0x30, issuer) = it.next()? else { return None };
    let (0x30, validity) = it.next()? else { return None };
    let (0x30, subject) = it.next()? else { return None };
    let san = it.find(|&(t, _)| t == 0xa3).map(|(_, e)| parse_san(e)).unwrap_or_default();

    let mut times = items(validity).map(|(t, v)| parse_time(t, v));
    let not_before = times.next().flatten();
    let not_after = times.next().flatten();
    let serial = match serial {
        [0, rest @ ..] if !rest.is_empty() => rest,
        s => s,
    };
    Some(CertInfo {
        subject_cn: name_attr(subject, OID_CN),
        subject_org: name_attr(subject, OID_O),
        issuer_cn: name_attr(issuer, OID_CN),
        issuer_org: name_attr(issuer, OID_O),
        not_before: not_before.map(|t| t.to_string()),
        not_after: not_after.map(|t| t.to_string()),
        not_after_unix: not_after.map(|t| t.unix()),
        san,
        self_signed: subject == issuer,
        serial: hex(serial),
    })
}

/// First value of attribute `oid` in a Name (SEQUENCE OF SET OF AttributeTypeAndValue).
fn name_attr(name: &[u8], oid: &[u8]) -> Option<String> {
    items(name)
        .filter(|&(t, _)| t == 0x31)
        .flat_map(|(_, rdn)| items(rdn))
        .find_map(|(_, atv)| {
            let mut a = items(atv);
            if a.next()? != (0x06, oid) {
                return None;
            }
            let (tag, v) = a.next()?;
            Some(decode_string(tag, v))
        })
}

fn decode_string(tag: u8, v: &[u8]) -> String {
    match tag {
        0x1e => char::decode_utf16(u16s(v)).map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER)).collect(),
        0x1c => v
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| char::from_u32(u32::from_be_bytes(*c)).unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect(),
        0x14 => latin1(v),
        _ => String::from_utf8_lossy(v).into_owned(),
    }
}

/// subjectAltName dNSName / iPAddress entries from the [3] extensions field.
fn parse_san(explicit: &[u8]) -> Vec<String> {
    let Some((0x30, exts, _)) = der(explicit) else { return Vec::new() };
    for (_, ext) in items(exts) {
        let mut f = items(ext);
        if f.next() != Some((0x06, OID_SAN)) {
            continue;
        }
        let Some((_, value)) = f.find(|&(t, _)| t == 0x04) else { continue };
        let Some((0x30, names, _)) = der(value) else { continue };
        return items(names)
            .filter_map(|(t, v)| match t {
                0x82 => Some(String::from_utf8_lossy(v).into_owned()),
                0x87 => match v.len() {
                    4 => <[u8; 4]>::try_from(v).ok().map(|a| Ipv4Addr::from(a).to_string()),
                    16 => <[u8; 16]>::try_from(v).ok().map(|a| Ipv6Addr::from(a).to_string()),
                    _ => None,
                },
                _ => None,
            })
            .collect();
    }
    Vec::new()
}

#[derive(Clone, Copy)]
struct Time {
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    min: u32,
    sec: u32,
}

impl std::fmt::Display for Time {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Time { year, month, day, hour, min, sec } = *self;
        write!(f, "{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02} UTC")
    }
}

impl Time {
    fn unix(&self) -> i64 {
        days_from_civil(self.year, self.month, self.day) * 86400
            + i64::from(self.hour * 3600 + self.min * 60 + self.sec)
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// UTCTime (YYMMDDHHMMSSZ, YY < 50 => 20YY) or GeneralizedTime (YYYYMMDDHHMMSSZ).
fn parse_time(tag: u8, v: &[u8]) -> Option<Time> {
    let num = |b: Option<&[u8]>| -> Option<u32> {
        let b = b?;
        b.iter().all(u8::is_ascii_digit).then(|| b.iter().fold(0, |a, &d| a * 10 + u32::from(d - b'0')))
    };
    let (year, r) = match tag {
        0x17 => {
            let yy = i64::from(num(v.get(..2))?);
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, v.get(2..)?)
        }
        0x18 => (i64::from(num(v.get(..4))?), v.get(4..)?),
        _ => return None,
    };
    let t = Time {
        year,
        month: num(r.get(0..2))?,
        day: num(r.get(2..4))?,
        hour: num(r.get(4..6))?,
        min: num(r.get(6..8))?,
        sec: num(r.get(8..10))?,
    };
    let valid = (1..=12).contains(&t.month) && (1..=31).contains(&t.day) && t.hour < 24 && t.min < 60 && t.sec <= 60;
    valid.then_some(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-signed cert from New-SelfSignedCertificate: CN=test.example, O=Netscope Test,
    /// SAN test.example + alt.example, valid 2026-10-17 04:47:37 .. 2027-10-17 04:57:36 UTC.
    const CERT_B64: &str = "MIIDXjCCAkagAwIBAgIQF2LKh1qYMoJC9Gt5TQkzIDANBgkqhkiG9w0BAQsFADAvMRYwFAYDVQQKDA1OZXRzY29wZSBUZXN0MRUwEwYDVQQDDAx0ZXN0LmV4YW1wbGUwHhcNMjYxMDE3MDQ0NzM3WhcNMjcxMDE3MDQ1NzM2WjAvMRYwFAYDVQQKDA1OZXRzY29wZSBUZXN0MRUwEwYDVQQDDAx0ZXN0LmV4YW1wbGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6BOh/LqxWiWXE/JbWD8J9WnVwmPe/iMh6TNs6HwKBLMqFKswGItRE3g9C48kQZPZZ3ZJJ/ASTIUdCM7M6XWR7K09Gc3BzR7OqyJ0kbS9up77uobjNTE1Qyt9BxmbcNdh16kqDIHZKRjsegjfUxFo8TS6Bh6GV5OghsczR+clfb1zFt1+JsQzjkDk4lxQ4M4GYq3AqYFYpsT4DajftXDcUD3aNd8xRHHBsubPJlmTi4n8C3Cp5V5x8M/Ust1C/7pIstiXw2UaJLaCBlmzhM+Bnj6jZXN7/eEgklQa6ane89Z/OJWlf+SXpFbyAWCNsEQXL+EJQTTvBnZdYJ8yw9tjhAgMBAAGjdjB0MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwJAYDVR0RBB0wG4IMdGVzdC5leGFtcGxlggthbHQuZXhhbXBsZTAdBgNVHQ4EFgQUfWqP/OHD8v2DHErLm91r7/vKq/cwDQYJKoZIhvcNAQELBQADggEBAGYKhkmzGeYD9XBprydI6vAPyGYK7LA2ZXkc9fEdvpnBQvR9ehI0zDbJ4OCcwJ8V5zd8nCDzhqBJCqeml8ncmEZv4b2kPGEbBdmUVZK1xO1lgo9fX0M+wMl/GQRnPpo2WeaSDzAy+MCHuEc7z59xPVjBoyptX8fZhCnOSOc5VwuW/YWOdwuHnjNNY3XJdlr3OOUH7g/NTgVZfDL8Lu8CrEU/pvX8ZpPhpZrFWQ+GA8VAavyWv/SkKAqbbP+ZfQxXNSt+u7U2GC++9hKE0V6tAj1DBuhgx++Hzo4r4zN+WliMbFYWj2Gzze5Jgw9b8+mnG8h7+hmR//7HWmeFMze+oBw=";

    fn b64(s: &str) -> Vec<u8> {
        let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0);
        for c in s.bytes() {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => continue,
            };
            acc = (acc << 6 | u32::from(v)) & 0xff_ffff;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        out
    }

    fn v8(b: &[u8]) -> Vec<u8> {
        [&[b.len() as u8][..], b].concat()
    }
    fn v16(b: &[u8]) -> Vec<u8> {
        [&(b.len() as u16).to_be_bytes()[..], b].concat()
    }
    fn v24(b: &[u8]) -> Vec<u8> {
        [&(b.len() as u32).to_be_bytes()[1..], b].concat()
    }
    fn ext(t: u16, data: &[u8]) -> Vec<u8> {
        [&t.to_be_bytes()[..], &v16(data)].concat()
    }
    fn be(v: &[u16]) -> Vec<u8> {
        v.iter().flat_map(|x| x.to_be_bytes()).collect()
    }
    fn handshake(typ: u8, body: &[u8]) -> Vec<u8> {
        [&[typ][..], &v24(body)].concat()
    }
    fn record(ct: u8, payload: &[u8]) -> Vec<u8> {
        [&[ct, 3, 3][..], &v16(payload)].concat()
    }

    /// ClientHello record: GREASE cipher + extension, SNI, ALPN [h2, http/1.1],
    /// supported_versions [GREASE, 1.3, 1.2], signature_algorithms.
    fn sample_hello() -> Vec<u8> {
        let sni = v16(&[&[0u8][..], &v16(b"example.com")].concat());
        let alpn = v16(&[v8(b"h2"), v8(b"http/1.1")].concat());
        let exts = [
            ext(0x3a3a, &[]),
            ext(0x0000, &sni),
            ext(0x0017, &[]),
            ext(0x0010, &alpn),
            ext(0x000a, &v16(&be(&[0x001d, 0x0017]))),
            ext(0x000d, &v16(&be(&[0x0403, 0x0804, 0x0401]))),
            ext(0x002b, &v8(&be(&[0x5a5a, 0x0304, 0x0303]))),
        ]
        .concat();
        let body = [
            &[3, 3][..],
            &[7; 32],
            &v8(&[1; 32]),
            &v16(&be(&[0x2a2a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f])),
            &v8(&[0]),
            &v16(&exts),
        ]
        .concat();
        [&[0x16, 3, 1][..], &v16(&handshake(1, &body))].concat()
    }

    #[test]
    fn grease_detection() {
        assert!(is_grease(0x0a0a) && is_grease(0xfafa) && is_grease(0x5a5a));
        assert!(!is_grease(0x0a1a) && !is_grease(0x0b0b) && !is_grease(0x1301));
    }

    #[test]
    fn client_hello_parse_and_ja4() {
        let rec = sample_hello();
        let h = parse_client_hello(&rec).unwrap();
        assert_eq!(h.legacy_version, 0x0303);
        assert_eq!(h.versions, vec![0x0304, 0x0303]);
        assert_eq!(h.ciphers, vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f]);
        assert_eq!(h.extensions, vec![0x0000, 0x0017, 0x0010, 0x000a, 0x000d, 0x002b]);
        assert_eq!(h.sni.as_deref(), Some("example.com"));
        assert_eq!(h.alpn, vec!["h2", "http/1.1"]);
        assert_eq!(h.sig_algs, vec![0x0403, 0x0804, 0x0401]);
        assert_eq!(h.max_version(), 0x0304);
        let b = hash12("1301,1302,1303,c02b,c02f");
        let c = hash12("000a,000d,0017,002b_0403,0804,0401");
        assert_eq!(h.ja4(false), format!("t13d0506h2_{b}_{c}"));
        assert!(h.ja4(true).starts_with("q13d0506h2_"));
        // Bare handshake (QUIC CRYPTO content) parses identically.
        assert_eq!(parse_client_hello_handshake(&rec[5..]), Some(h));
    }

    #[test]
    fn ja4_spec_example() {
        // Lists from FoxIO JA4.md (JA4_ro of the worked example).
        let h = ClientHello {
            legacy_version: 0x0303,
            versions: vec![0x0304, 0x0303],
            ciphers: vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c,
                0x009d, 0x002f, 0x0035,
            ],
            extensions: vec![
                0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b,
                0xff01, 0x000b, 0x000a, 0x0015,
            ],
            sni: Some("example.com".into()),
            alpn: vec!["h2".into(), "http/1.1".into()],
            sig_algs: vec![0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
        };
        assert_eq!(h.ja4(false), "t13d1516h2_8daaf6152771_e5627efa2ab1");
        let no_sig = ClientHello { sig_algs: vec![], ..h.clone() };
        assert!(no_sig.ja4(false).ends_with("_8daaf6152771_6d807ffa2a79"));
        let empty = ClientHello { ciphers: vec![], extensions: vec![], sni: None, alpn: vec![], ..h };
        assert_eq!(empty.ja4(false), "t13i000000_000000000000_000000000000");
    }

    #[test]
    fn ja4_alpn_chars() {
        let ja4_alpn = |a: &str| {
            let h = ClientHello {
                legacy_version: 0x0303,
                versions: vec![],
                ciphers: vec![],
                extensions: vec![],
                sni: None,
                alpn: vec![a.into()],
                sig_algs: vec![],
            };
            h.ja4(false)[8..10].to_string()
        };
        // Cases from the spec's "ALPN Extension Value" section.
        let cases = [
            ("h2", "h2"),
            ("http/1.1", "h1"),
            ("x", "xx"),
            ("", "00"),
            ("\u{ab}", "ab"),
            ("\u{20}", "20"),
            ("\u{ab}\u{cd}", "ad"),
            ("\u{20}a", "21"),
            ("0\u{ab}", "3b"),
            ("a\u{20}", "60"),
            ("01\u{ab}\u{cd}", "3d"),
            ("0\u{ab}\u{cd}1", "01"),
        ];
        for (alpn, want) in cases {
            assert_eq!(ja4_alpn(alpn), want, "{alpn:?}");
        }
    }

    #[test]
    fn truncated_and_garbage_input() {
        let rec = sample_hello();
        for n in 0..rec.len() {
            let _ = parse_client_hello(&rec[..n]);
            let _ = parse_client_hello_handshake(&rec[5..n.max(5)]);
        }
        // Cut inside the extension block -> None.
        assert_eq!(parse_client_hello(&rec[..rec.len() - 1]), None);
        let mut seed = 0x1234_5678_9abc_def0u64;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..2000 {
            let len = (rnd() % 300) as usize;
            let mut buf: Vec<u8> = (0..len).map(|_| rnd() as u8).collect();
            let _ = parse_client_hello(&buf);
            let _ = parse_client_hello_handshake(&buf);
            let _ = parse_server_stream(&buf);
            let _ = parse_certificate(&buf);
            if buf.len() > 5 {
                buf[..5].copy_from_slice(&[0x16, 3, 3, 1, 0]);
                let _ = parse_client_hello(&buf);
                let _ = parse_server_stream(&buf);
            }
        }
        // Single-byte mutations of valid inputs.
        let cert = b64(CERT_B64);
        for base in [rec.clone(), cert.clone(), tls12_stream(&cert)] {
            for i in 0..base.len() {
                for v in [0x00, 0x80, 0x84, 0xff] {
                    let mut m = base.clone();
                    m[i] = v;
                    let _ = parse_client_hello(&m);
                    let _ = parse_certificate(&m);
                    let _ = parse_server_stream(&m);
                }
            }
        }
    }

    fn check_test_cert(c: &CertInfo) {
        assert_eq!(c.subject_cn.as_deref(), Some("test.example"));
        assert_eq!(c.subject_org.as_deref(), Some("Netscope Test"));
        assert_eq!(c.issuer_cn, c.subject_cn);
        assert_eq!(c.issuer_org, c.subject_org);
        assert!(c.self_signed);
        assert_eq!(c.san, vec!["test.example", "alt.example"]);
        assert_eq!(c.not_before.as_deref(), Some("2026-10-17 04:47:37 UTC"));
        assert_eq!(c.not_after.as_deref(), Some("2027-10-17 04:57:36 UTC"));
        assert_eq!(c.not_after_unix, Some(1_823_749_056));
        assert_eq!(c.serial, "1762ca875a98328242f46b794d093320");
    }

    #[test]
    fn certificate_fields() {
        let cert = b64(CERT_B64);
        check_test_cert(&parse_certificate(&cert).unwrap());
        for n in 0..cert.len() {
            let _ = parse_certificate(&cert[..n]);
        }
    }

    #[test]
    fn time_math() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
        let t = parse_time(0x17, b"491231235959Z").unwrap();
        assert_eq!((t.year, t.unix()), (2049, 2_524_607_999));
        assert_eq!(parse_time(0x17, b"500101000000Z").unwrap().year, 1950);
        assert_eq!(parse_time(0x18, b"20380119031408Z").unwrap().unix(), 2_147_483_648);
        assert!(parse_time(0x18, b"20381319031408Z").is_none());
        assert!(parse_time(0x17, b"2501").is_none());
    }

    fn server_hello(version: u16, cipher: u16, exts: &[u8]) -> Vec<u8> {
        let body = [&version.to_be_bytes()[..], &[9; 32], &v8(&[]), &cipher.to_be_bytes(), &[0], &v16(exts)].concat();
        handshake(2, &body)
    }

    /// TLS 1.2 ServerHello + Certificate + ServerHelloDone split across two records, then CCS.
    fn tls12_stream(cert: &[u8]) -> Vec<u8> {
        let alpn = v16(&v8(b"h2"));
        let msgs = [
            server_hello(0x0303, 0xc02f, &ext(0x0010, &alpn)),
            handshake(11, &v24(&v24(cert))),
            handshake(14, &[]),
        ]
        .concat();
        let split = 300;
        [record(22, &msgs[..split]), record(22, &msgs[split..]), record(20, &[1])].concat()
    }

    #[test]
    fn server_stream_tls12() {
        let cert = b64(CERT_B64);
        let stream = tls12_stream(&cert);
        let s = parse_server_stream(&stream);
        assert_eq!(s.hello, Some(ServerHello { version: 0x0303, cipher: 0xc02f, alpn: Some("h2".into()) }));
        assert!(!s.encrypted_certificates);
        assert_eq!(s.certificates.len(), 1);
        check_test_cert(&s.certificates[0]);
        for n in 0..stream.len() {
            let s = parse_server_stream(&stream[..n]);
            assert!(s.certificates.len() <= 1);
        }
    }

    #[test]
    fn server_stream_tls13() {
        let sh = server_hello(0x0303, 0x1301, &ext(0x002b, &be(&[0x0304])));
        let stream =
            [record(22, &sh), record(20, &[1]), record(23, &[0xaa; 40]), record(22, &handshake(11, &[]))].concat();
        let s = parse_server_stream(&stream);
        assert_eq!(s.hello, Some(ServerHello { version: 0x0304, cipher: 0x1301, alpn: None }));
        assert!(s.encrypted_certificates);
        assert!(s.certificates.is_empty());
    }

    #[test]
    fn names() {
        assert_eq!(version_name(0x0304), "TLS 1.3");
        assert_eq!(version_name(0x0303), "TLS 1.2");
        assert_eq!(version_name(0x0300), "SSL 3.0");
        assert_eq!(version_name(0x9999), "unknown");
        assert_eq!(cipher_name(0x1301), Some("TLS_AES_128_GCM_SHA256"));
        assert_eq!(cipher_name(0xcca9), Some("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"));
        assert_eq!(cipher_name(0x0035), Some("TLS_RSA_WITH_AES_256_CBC_SHA"));
        assert_eq!(cipher_name(0x0000), None);
    }
}
