//! Plain-text HTTP/1.x request detection and sensitive-data scanning.

use memchr::memmem;

const METHODS: [&str; 9] = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"];
const MAX_PATH: usize = 200;

/// Case-insensitive needles and the label reported when one matches.
const SENSITIVE: &[(&str, &str)] = &[
    ("password", "password"),
    ("passwd", "password"),
    ("pwd=", "password"),
    ("access_token", "token"),
    ("auth_token", "token"),
    ("token=", "token"),
    ("\"token\"", "token"),
    ("authorization: bearer", "bearer token"),
    ("authorization: basic", "basic auth"),
    ("api_key", "api key"),
    ("apikey", "api key"),
    ("api-key", "api key"),
    ("client_secret", "secret"),
    ("secret=", "secret"),
    ("card_number", "card data"),
    ("cardnumber", "card data"),
    ("credit_card", "card data"),
    ("cvv=", "card data"),
    ("ssn=", "ssn"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    /// Request target without the query string, truncated to 200 chars.
    pub path: String,
    pub host: Option<String>,
    /// Distinct labels of sensitive markers found anywhere in the payload.
    pub sensitive: Vec<&'static str>,
}

pub fn is_response(p: &[u8]) -> bool {
    p.starts_with(b"HTTP/1.")
}

pub fn parse_request(p: &[u8]) -> Option<HttpRequest> {
    let method = METHODS.iter().find(|m| p.starts_with(m.as_bytes()) && p.get(m.len()) == Some(&b' '))?;
    let line_end = memmem::find(p, b"\r\n").unwrap_or(p.len());
    let line = std::str::from_utf8(&p[..line_end]).ok()?;
    let mut parts = line.split(' ');
    parts.next();
    let target = parts.next()?;
    if !parts.next()?.starts_with("HTTP/") {
        return None;
    }
    let path: String = target.split('?').next().unwrap_or("/").chars().take(MAX_PATH).collect();

    let head_end = memmem::find(p, b"\r\n\r\n").unwrap_or(p.len());
    let host = p[line_end.min(head_end)..head_end]
        .split(|&b| b == b'\n')
        .filter_map(|l| std::str::from_utf8(l).ok())
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case("host").then(|| v.trim().to_ascii_lowercase())
        })
        .filter(|h| !h.is_empty() && h.len() <= 253);

    Some(HttpRequest { method: method.to_string(), path, host, sensitive: scan_sensitive(p) })
}

/// Distinct sensitive-data labels present in `p` (ASCII case-insensitive).
pub fn scan_sensitive(p: &[u8]) -> Vec<&'static str> {
    let lower = p.to_ascii_lowercase();
    let mut found: Vec<&'static str> = Vec::new();
    for &(needle, label) in SENSITIVE {
        if !found.contains(&label) && memmem::find(&lower, needle.as_bytes()).is_some() {
            found.push(label);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_request_line_and_host() {
        let r = parse_request(b"GET /a/b?x=1 HTTP/1.1\r\nUser-Agent: t\r\nHOST:  Example.ORG \r\n\r\n").unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/a/b");
        assert_eq!(r.host.as_deref(), Some("example.org"));
        assert!(r.sensitive.is_empty());
    }

    #[test]
    fn finds_credentials_in_body_query_and_headers() {
        let body = b"POST /login HTTP/1.1\r\nHost: shop.test\r\n\r\nuser=alice&PASSWORD=hunter2";
        assert_eq!(parse_request(body).unwrap().sensitive, vec!["password"]);
        let q = b"GET /cb?access_token=abc&api_key=1 HTTP/1.1\r\n\r\n";
        assert_eq!(parse_request(q).unwrap().sensitive, vec!["token", "api key"]);
        let h = b"GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n";
        assert_eq!(parse_request(h).unwrap().sensitive, vec!["basic auth"]);
    }

    #[test]
    fn rejects_non_http() {
        assert!(parse_request(b"GETX / HTTP/1.1\r\n").is_none());
        assert!(parse_request(b"GET / SMTP\r\n").is_none());
        assert!(parse_request(b"GET /").is_none());
        assert!(parse_request(b"\x16\x03\x01").is_none());
        assert!(is_response(b"HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn long_paths_are_truncated() {
        let long = format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(1000));
        assert_eq!(parse_request(long.as_bytes()).unwrap().path.len(), MAX_PATH);
    }

    #[test]
    fn host_header_edge_cases() {
        let host = |req: &[u8]| parse_request(req).unwrap().host;
        assert_eq!(host(b"GET / HTTP/1.1\r\nHost:\r\n\r\n"), None, "empty host");
        assert_eq!(host(b"GET / HTTP/1.1\r\nHost:   \r\n\r\n"), None);
        assert_eq!(host(b"GET / HTTP/1.1\r\nhost: A.b:8080\r\n\r\n").as_deref(), Some("a.b:8080"), "port kept, lowercased");
        assert_eq!(host(b"GET / HTTP/1.1\r\nX-Host: no\r\nHostname: no\r\nHost: yes\r\n\r\n").as_deref(), Some("yes"));
        let long = format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", "h".repeat(254));
        assert_eq!(host(long.as_bytes()), None, "longer than a DNS name");
        let ok = format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", "h".repeat(253));
        assert_eq!(host(ok.as_bytes()).unwrap().len(), 253);
        // The Host header after the body separator is body, not a header.
        assert_eq!(host(b"GET / HTTP/1.1\r\n\r\nHost: body.test\r\n"), None);
        // Non-UTF-8 header lines are skipped, a non-UTF-8 request line is not HTTP.
        assert_eq!(host(b"GET / HTTP/1.1\r\nHost: \xff\xfe\r\nHost: second.test\r\n\r\n").as_deref(), Some("second.test"));
        assert!(parse_request(b"GET /\xff HTTP/1.1\r\n\r\n").is_none());
        // Request target without a path component and a bare query.
        assert_eq!(parse_request(b"GET ?x=1 HTTP/1.0\r\n\r\n").unwrap().path, "");
        assert_eq!(parse_request(b"OPTIONS * HTTP/1.1\r\n\r\n").unwrap().path, "*");
        assert!(parse_request(b"GET / HTTP/1.1").is_some(), "no CRLF at all is still a request line");
        assert!(parse_request(b"GET  / HTTP/1.1\r\n").is_none(), "double space: the version slot is empty");
        assert!(parse_request(b"get / HTTP/1.1\r\n").is_none(), "methods are case-sensitive");
        for m in METHODS {
            assert!(parse_request(format!("{m} / HTTP/1.1\r\n\r\n").as_bytes()).is_some(), "{m}");
        }
    }

    #[test]
    fn sensitive_scan_is_case_insensitive_and_deduplicated() {
        assert_eq!(scan_sensitive(b"PASSWORD=1&passwd=2&pwd=3"), vec!["password"], "one label per family");
        assert_eq!(scan_sensitive(b"Authorization: BEARER x"), vec!["bearer token"]);
        assert_eq!(scan_sensitive(b"{\"token\":\"x\"}"), vec!["token"]);
        assert_eq!(scan_sensitive(b"client_secret=1&cvv=2&ssn=3"), vec!["secret", "card data", "ssn"]);
        assert!(scan_sensitive(b"tokenizer=1&secretary=2&cvvx=3").is_empty(), "needles ending in `=` need the `=`");
        assert!(scan_sensitive(b"").is_empty());
        assert!(scan_sensitive(&[0xff; 64]).is_empty());
        let r = parse_request(b"POST / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert!(r.sensitive.is_empty());
    }

    #[test]
    fn every_prefix_and_random_mutation_is_handled() {
        let base: Vec<&[u8]> = vec![
            b"GET /a/b?x=1 HTTP/1.1\r\nUser-Agent: t\r\nHOST:  Example.ORG \r\n\r\n",
            b"POST /login HTTP/1.1\r\nHost: shop.test\r\nContent-Length: 27\r\n\r\nuser=alice&PASSWORD=hunter2",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        ];
        for b in &base {
            for cut in 0..b.len() {
                let _ = parse_request(&b[..cut]);
                let _ = is_response(&b[..cut]);
            }
        }
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut rnd = move || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 33) as u32
        };
        for _ in 0..3000 {
            let mut x = base[rnd() as usize % base.len()].to_vec();
            for _ in 0..1 + rnd() % 3 {
                let i = rnd() as usize % x.len();
                x[i] = rnd() as u8;
            }
            if let Some(r) = parse_request(&x) {
                assert!(r.path.chars().count() <= MAX_PATH);
                assert!(r.host.as_ref().is_none_or(|h| !h.is_empty() && h.len() <= 253));
            }
        }
    }
}
