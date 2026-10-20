//! TLS record detection and host-name validation; handshake parsing lives in `tlsinfo`.

/// Looks like a TLS record header: content type 20..=23, protocol version 3.x.
pub fn is_record(p: &[u8]) -> bool {
    p.len() >= 5 && (0x14..=0x17).contains(&p[0]) && p[1] == 3 && p[2] <= 4
}

/// A server name as sent in SNI or a Host header, if it is a plausible DNS name:
/// 1..=253 chars of letters, digits, `.`, `-`, `_`; returned lowercased.
pub fn valid_hostname(name: &str) -> Option<String> {
    let ok = !name.is_empty() && name.len() <= 253 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_');
    ok.then(|| name.to_ascii_lowercase())
}

/// The validated SNI host name of a ClientHello record at the start of `p`.
pub fn client_hello_sni(p: &[u8]) -> Option<String> {
    super::tlsinfo::parse_client_hello(p)?.sni.as_deref().and_then(valid_hostname)
}
/// A minimal but well-formed TLS 1.2-style ClientHello carrying `sni` (demo mode and tests).
pub fn build_client_hello(sni: &str) -> Vec<u8> {
    let name = sni.as_bytes();
    let mut server_name = Vec::new();
    server_name.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    server_name.push(0);
    server_name.extend_from_slice(&(name.len() as u16).to_be_bytes());
    server_name.extend_from_slice(name);

    let mut extensions = Vec::new();
    // A non-SNI extension first, so the parser has to skip one.
    extensions.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]); // extended_master_secret
    extensions.extend_from_slice(&0u16.to_be_bytes());
    extensions.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&server_name);

    let mut hello = vec![0x03, 0x03];
    hello.extend((0..32u8).map(|i| i.wrapping_mul(37)));
    hello.push(0); // session id
    hello.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0xC0, 0x2F]); // cipher suites
    hello.extend_from_slice(&[0x01, 0x00]); // compression: null
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);

    let mut handshake = vec![0x01];
    handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&hello);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_sni() {
        let hello = build_client_hello("GitHub.com");
        assert!(is_record(&hello));
        assert_eq!(client_hello_sni(&hello).as_deref(), Some("github.com"));
    }

    #[test]
    fn rejects_non_hello_and_truncation() {
        let hello = build_client_hello("example.org");
        for cut in [0, 5, 10, 40, hello.len() - 1] {
            assert_eq!(client_hello_sni(&hello[..cut]), None, "cut at {cut}");
        }
        let mut app_data = hello.clone();
        app_data[0] = 0x17;
        assert_eq!(client_hello_sni(&app_data), None);
        let mut server_hello = hello.clone();
        server_hello[5] = 0x02;
        assert_eq!(client_hello_sni(&server_hello), None);
        assert!(!is_record(b"GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn rejects_invalid_host_names() {
        assert_eq!(client_hello_sni(&build_client_hello("bad<script>")), None);
    }

    #[test]
    fn record_detection_boundaries() {
        assert!(is_record(&[0x14, 3, 0, 0, 0]) && is_record(&[0x17, 3, 4, 0xff, 0xff]));
        assert!(!is_record(&[0x16, 3, 1, 0]), "needs the full 5-byte header");
        assert!(!is_record(&[0x13, 3, 1, 0, 0]) && !is_record(&[0x18, 3, 1, 0, 0]), "content types 20..=23 only");
        assert!(!is_record(&[0x16, 2, 0, 0, 0]) && !is_record(&[0x16, 3, 5, 0, 0]), "protocol version 3.0..=3.4");
        assert!(!is_record(b"SSH-2.0-OpenSSH") && !is_record(&[]));
    }

    #[test]
    fn every_prefix_and_random_mutation_of_a_hello_is_handled() {
        for name in ["a", "example.org", &"x".repeat(200)] {
            let hello = build_client_hello(name);
            assert_eq!(client_hello_sni(&hello).as_deref(), Some(name));
            for cut in 0..hello.len() {
                assert_eq!(client_hello_sni(&hello[..cut]), None, "cut at {cut} of {}", hello.len());
            }
            for i in 0..hello.len() {
                for v in [0x00, 0x01, 0x7f, 0x80, 0xff] {
                    let mut m = hello.clone();
                    m[i] = v;
                    if let Some(sni) = client_hello_sni(&m) {
                        assert!(valid_hostname(&sni).is_some(), "an extracted SNI is always a valid lowercase host name: {sni:?}");
                    }
                }
            }
        }
        let mut seed = 0x1234_5678_9abc_def1u64;
        let mut rnd = move || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 33) as u32
        };
        let base = build_client_hello("mutate.example");
        for _ in 0..3000 {
            let mut m = base.clone();
            for _ in 0..1 + rnd() % 4 {
                let i = rnd() as usize % m.len();
                m[i] = rnd() as u8;
            }
            let _ = client_hello_sni(&m);
        }
        // An SNI with uppercase and a trailing NUL byte: the parser keeps bytes, validation refuses them.
        let mut hello = build_client_hello("UPPER.Example");
        assert_eq!(client_hello_sni(&hello).as_deref(), Some("upper.example"));
        let at = hello.len() - 1;
        hello[at] = 0;
        assert_eq!(client_hello_sni(&hello), None);
    }
}

#[cfg(test)]
mod hostname_tests {
    use super::*;

    #[test]
    fn hostnames() {
        assert_eq!(valid_hostname("GitHub.COM").as_deref(), Some("github.com"));
        assert_eq!(valid_hostname("_dmarc.example.org").as_deref(), Some("_dmarc.example.org"));
        for bad in ["", "a b", "x\u{1}y", "<script>", "é.example", &"a".repeat(254)] {
            assert_eq!(valid_hostname(bad), None, "{bad:?}");
        }
    }
}
