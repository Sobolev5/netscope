//! Minimal reader for the MaxMind DB format (`.mmdb`, spec v2.0), used by
//! GeoLite2 and DB-IP databases: binary search tree over IP bits + typed data section.
//! <https://maxmind.github.io/MaxMind-DB/>

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;

const METADATA_MARKER: &[u8] = b"\xAB\xCD\xEFMaxMind.com";
/// Depth limit for nested maps/arrays (malformed files must not overflow the stack).
const MAX_DEPTH: usize = 32;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    String(String),
    Double(f64),
    Bytes(Vec<u8>),
    Uint(u128),
    Int(i32),
    Map(BTreeMap<String, Value>),
    Array(Vec<Value>),
    Bool(bool),
    Float(f32),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(m) => m.get(key),
            _ => None,
        }
    }

    /// Follows a path of map keys and array indexes (`"0"`, `"1"`...).
    pub fn path(&self, keys: &[&str]) -> Option<&Value> {
        keys.iter().try_fold(self, |v, k| match v {
            Value::Map(m) => m.get(*k),
            Value::Array(a) => a.get(k.parse::<usize>().ok()?),
            _ => None,
        })
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Uint(v) => u64::try_from(*v).ok(),
            Value::Int(v) => u64::try_from(*v).ok(),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Double(v) => Some(*v),
            Value::Float(v) => Some(*v as f64),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct Mmdb {
    buf: Vec<u8>,
    node_count: usize,
    record_size: usize,
    ip_version: u16,
    tree_size: usize,
    /// First node for IPv4 lookups in an IPv6 tree (after 96 zero bits).
    ipv4_start: usize,
    pub database_type: String,
    pub build_epoch: u64,
}

fn err(msg: impl Into<String>) -> String {
    msg.into()
}

impl Mmdb {
    pub fn open(path: &Path) -> Result<Self, String> {
        let buf = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        // An interrupted download leaves an empty or cut-off file; say so instead of "not a database".
        if buf.is_empty() {
            return Err(format!("{}: empty file (interrupted download?)", path.display()));
        }
        Self::from_bytes(buf).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn from_bytes(buf: Vec<u8>) -> Result<Self, String> {
        let window = buf.len().saturating_sub(128 * 1024);
        let marker = buf[window..]
            .windows(METADATA_MARKER.len())
            .rposition(|w| w == METADATA_MARKER)
            .map(|i| window + i + METADATA_MARKER.len())
            .ok_or_else(|| err("not a MaxMind DB file (metadata marker missing; truncated download?)"))?;
        let meta = Decoder { buf: &buf, base: marker }.value(marker, 0).map_err(|e| format!("metadata unreadable: {e} (truncated download?)"))?.0;
        let num = |k: &str| meta.get(k).and_then(Value::as_u64).ok_or_else(|| format!("metadata `{k}` missing"));
        let node_count = num("node_count")? as usize;
        let record_size = num("record_size")? as usize;
        let ip_version = num("ip_version")? as u16;
        if ![24, 28, 32].contains(&record_size) {
            return Err(format!("unsupported record size {record_size}"));
        }
        let tree_size = node_count.checked_mul(record_size * 2 / 8).ok_or_else(|| err("search tree size overflows"))?;
        if tree_size.checked_add(16).is_none_or(|end| end > marker) {
            return Err(err("search tree larger than file"));
        }
        let mut db = Mmdb {
            buf,
            node_count,
            record_size,
            ip_version,
            tree_size,
            ipv4_start: 0,
            database_type: meta.get("database_type").and_then(Value::as_str).unwrap_or("").to_string(),
            build_epoch: num("build_epoch").unwrap_or(0),
        };
        if ip_version == 6 {
            let mut node = 0;
            for _ in 0..96 {
                if node >= node_count {
                    break;
                }
                node = db.record(node, 0)?;
            }
            db.ipv4_start = node;
        }
        Ok(db)
    }

    fn record(&self, node: usize, side: usize) -> Result<usize, String> {
        let width = self.record_size * 2 / 8;
        let b = self.buf.get(node * width..node * width + width).ok_or_else(|| err("tree node out of range"))?;
        let be = |s: &[u8]| s.iter().fold(0usize, |acc, &x| acc << 8 | x as usize);
        Ok(match (self.record_size, side) {
            (24, 0) => be(&b[0..3]),
            (24, _) => be(&b[3..6]),
            (28, 0) => ((b[3] as usize & 0xF0) << 20) | be(&b[0..3]),
            (28, _) => ((b[3] as usize & 0x0F) << 24) | be(&b[4..7]),
            (_, 0) => be(&b[0..4]),
            _ => be(&b[4..8]),
        })
    }

    /// Data record for `ip` and the prefix length of the matching network.
    pub fn lookup(&self, ip: IpAddr) -> Result<Option<(Value, u8)>, String> {
        let (bits, start): (Vec<u8>, usize) = match ip {
            IpAddr::V4(a) if self.ip_version == 6 => (a.octets().to_vec(), self.ipv4_start),
            IpAddr::V4(a) => (a.octets().to_vec(), 0),
            IpAddr::V6(a) if self.ip_version == 4 => match a.to_ipv4_mapped() {
                Some(v4) => (v4.octets().to_vec(), 0),
                None => return Ok(None),
            },
            IpAddr::V6(a) => (a.octets().to_vec(), 0),
        };
        let mut node = start;
        let total = bits.len() * 8;
        let mut depth = 0;
        while depth < total && node < self.node_count {
            let bit = (bits[depth / 8] >> (7 - depth % 8)) & 1;
            node = self.record(node, bit as usize)?;
            depth += 1;
        }
        if node == self.node_count {
            return Ok(None);
        }
        if node < self.node_count {
            return Err(err("address deeper than the tree"));
        }
        let offset = (node - self.node_count).checked_sub(16).ok_or_else(|| err("pointer into the data separator"))?;
        let base = self.tree_size + 16;
        let value = Decoder { buf: &self.buf, base }.value(base + offset, 0)?.0;
        Ok(Some((value, depth as u8)))
    }
}

/// Decodes data-section values; `base` is the start of the section pointers are relative to.
struct Decoder<'a> {
    buf: &'a [u8],
    base: usize,
}

impl Decoder<'_> {
    fn byte(&self, at: usize) -> Result<u8, String> {
        self.buf.get(at).copied().ok_or_else(|| err("unexpected end of data"))
    }

    fn uint(&self, at: usize, len: usize) -> Result<u128, String> {
        let s = self.buf.get(at..at + len).ok_or_else(|| err("unexpected end of data"))?;
        Ok(s.iter().fold(0u128, |acc, &x| acc << 8 | x as u128))
    }

    /// Returns the value at `at` and the offset right after it.
    fn value(&self, at: usize, depth: usize) -> Result<(Value, usize), String> {
        if depth > MAX_DEPTH {
            return Err(err("data nested too deeply"));
        }
        let ctrl = self.byte(at)?;
        let mut pos = at + 1;
        let mut kind = u16::from(ctrl >> 5);
        if kind == 1 {
            // Pointer: resolve and decode the target, but continue after the pointer itself.
            let ss = (ctrl >> 3) & 0x3;
            let vvv = (ctrl & 0x7) as usize;
            let (ptr, len) = match ss {
                0 => ((vvv << 8) | self.uint(pos, 1)? as usize, 1),
                1 => (((vvv << 16) | self.uint(pos, 2)? as usize) + 2048, 2),
                2 => (((vvv << 24) | self.uint(pos, 3)? as usize) + 526_336, 3),
                _ => (self.uint(pos, 4)? as usize, 4),
            };
            let target = self.base.checked_add(ptr).ok_or_else(|| err("pointer out of range"))?;
            let (v, _) = self.value(target, depth + 1)?;
            return Ok((v, pos + len));
        }
        if kind == 0 {
            kind = 7 + u16::from(self.byte(pos)?);
            pos += 1;
        }
        let mut size = (ctrl & 0x1F) as usize;
        match size {
            29 => {
                size = 29 + self.uint(pos, 1)? as usize;
                pos += 1;
            }
            30 => {
                size = 285 + self.uint(pos, 2)? as usize;
                pos += 2;
            }
            31 => {
                size = 65_821 + self.uint(pos, 3)? as usize;
                pos += 3;
            }
            _ => {}
        }
        let bytes = |len: usize| self.buf.get(pos..pos + len).ok_or_else(|| err("unexpected end of data"));
        Ok(match kind {
            2 => (Value::String(String::from_utf8_lossy(bytes(size)?).into_owned()), pos + size),
            3 => {
                let b = bytes(8)?;
                (Value::Double(f64::from_be_bytes(b.try_into().map_err(|_| err("bad double"))?)), pos + 8)
            }
            4 => (Value::Bytes(bytes(size)?.to_vec()), pos + size),
            5 | 6 | 9 | 10 => (Value::Uint(self.uint(pos, size)?), pos + size),
            8 => {
                let v = self.uint(pos, size)? as u32;
                // Sign-extend from `size` bytes.
                let shift = 32 - 8 * size.min(4) as u32;
                (Value::Int(if shift == 32 { 0 } else { ((v << shift) as i32) >> shift }), pos + size)
            }
            7 => {
                let mut m = BTreeMap::new();
                for _ in 0..size {
                    let (k, next) = self.value(pos, depth + 1)?;
                    let (v, next) = self.value(next, depth + 1)?;
                    pos = next;
                    if let Value::String(k) = k {
                        m.insert(k, v);
                    }
                }
                (Value::Map(m), pos)
            }
            11 => {
                let mut a = Vec::with_capacity(size.min(64));
                for _ in 0..size {
                    let (v, next) = self.value(pos, depth + 1)?;
                    pos = next;
                    a.push(v);
                }
                (Value::Array(a), pos)
            }
            14 => (Value::Bool(size != 0), pos),
            15 => {
                let b = bytes(4)?;
                (Value::Float(f32::from_be_bytes(b.try_into().map_err(|_| err("bad float"))?)), pos + 4)
            }
            other => return Err(format!("unsupported data type {other}")),
        })
    }
}

#[cfg(test)]
pub(crate) mod testdb {
    //! A tiny writer for building MMDB files in tests.

    use super::*;

    pub fn ctrl(out: &mut Vec<u8>, kind: u8, size: usize) {
        let (k, ext) = if kind > 7 { (0u8, Some(kind - 7)) } else { (kind, None) };
        let (s, extra): (u8, Vec<u8>) = match size {
            0..=28 => (size as u8, vec![]),
            29..=284 => (29, vec![(size - 29) as u8]),
            _ => (30, ((size - 285) as u16).to_be_bytes().to_vec()),
        };
        out.push(k << 5 | s);
        if let Some(e) = ext {
            out.push(e);
        }
        out.extend(extra);
    }

    pub fn string(out: &mut Vec<u8>, s: &str) {
        ctrl(out, 2, s.len());
        out.extend_from_slice(s.as_bytes());
    }

    pub fn uint(out: &mut Vec<u8>, kind: u8, v: u64) {
        let bytes: Vec<u8> = v.to_be_bytes().iter().copied().skip_while(|&b| b == 0).collect();
        ctrl(out, kind, bytes.len());
        out.extend(bytes);
    }

    /// Writes one value into the buffer.
    pub type Writer<'a> = &'a dyn Fn(&mut Vec<u8>);

    pub fn map(out: &mut Vec<u8>, entries: &[(&str, Writer<'_>)]) {
        ctrl(out, 7, entries.len());
        for (k, v) in entries {
            string(out, k);
            v(out);
        }
    }

    /// An IPv4 database (record size 24) mapping `prefix/len` to `data`; everything else is empty.
    pub fn build(prefix: [u8; 4], len: usize, data: &[u8]) -> Vec<u8> {
        let node_count = len;
        let mut tree = Vec::new();
        for depth in 0..len {
            let bit = (prefix[depth / 8] >> (7 - depth % 8)) & 1;
            let next = if depth + 1 == len { node_count + 16 } else { depth + 1 };
            let (l, r) = if bit == 0 { (next, node_count) } else { (node_count, next) };
            tree.extend_from_slice(&(l as u32).to_be_bytes()[1..]);
            tree.extend_from_slice(&(r as u32).to_be_bytes()[1..]);
        }
        let mut out = tree;
        out.extend([0u8; 16]);
        out.extend_from_slice(data);
        out.extend_from_slice(METADATA_MARKER);
        map(
            &mut out,
            &[
                ("node_count", &|o: &mut Vec<u8>| uint(o, 6, node_count as u64)),
                ("record_size", &|o: &mut Vec<u8>| uint(o, 5, 24)),
                ("ip_version", &|o: &mut Vec<u8>| uint(o, 5, 4)),
                ("database_type", &|o: &mut Vec<u8>| string(o, "Test-City")),
                ("build_epoch", &|o: &mut Vec<u8>| uint(o, 9, 1_760_000_000)),
            ],
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::testdb::*;
    use super::*;

    fn sample() -> Mmdb {
        let mut data = Vec::new();
        map(
            &mut data,
            &[
                ("country", &|o: &mut Vec<u8>| {
                    map(o, &[("iso_code", &|o: &mut Vec<u8>| string(o, "AU")), ("names", &|o: &mut Vec<u8>| map(o, &[("en", &|o: &mut Vec<u8>| string(o, "Australia"))]))])
                }),
                ("location", &|o: &mut Vec<u8>| {
                    map(o, &[("latitude", &|o: &mut Vec<u8>| {
                        ctrl(o, 3, 8);
                        o.extend((-33.86f64).to_be_bytes());
                    })])
                }),
                // A pointer (type 1, ss=0) back to the "AU" string at data offset 19.
                ("alias", &|o: &mut Vec<u8>| o.extend([0x20, 19])),
                ("ok", &|o: &mut Vec<u8>| ctrl(o, 14, 1)),
                ("tags", &|o: &mut Vec<u8>| {
                    ctrl(o, 11, 2);
                    string(o, "a");
                    uint(o, 5, 7);
                }),
            ],
        );
        Mmdb::from_bytes(build([1, 0, 0, 0], 8, &data)).unwrap()
    }

    #[test]
    fn metadata_and_lookup() {
        let db = sample();
        assert_eq!((db.database_type.as_str(), db.build_epoch, db.node_count), ("Test-City", 1_760_000_000, 8));
        let (v, prefix) = db.lookup("1.2.3.4".parse().unwrap()).unwrap().unwrap();
        assert_eq!(prefix, 8);
        assert_eq!(v.path(&["country", "iso_code"]).and_then(Value::as_str), Some("AU"));
        assert_eq!(v.path(&["country", "names", "en"]).and_then(Value::as_str), Some("Australia"));
        assert_eq!(v.path(&["location", "latitude"]).and_then(Value::as_f64), Some(-33.86));
        assert_eq!(v.get("alias").and_then(Value::as_str), Some("AU"), "pointer resolved");
        assert_eq!(v.get("ok"), Some(&Value::Bool(true)));
        assert_eq!(v.path(&["tags", "1"]).and_then(Value::as_u64), Some(7));
        assert!(db.lookup("2.0.0.1".parse().unwrap()).unwrap().is_none());
        assert!(db.lookup("::ffff:1.9.9.9".parse().unwrap()).unwrap().is_some(), "v4-mapped v6 in a v4 db");
        assert!(db.lookup("2001:db8::1".parse().unwrap()).unwrap().is_none());
    }

    #[test]
    fn pointer_into_the_data_separator_is_an_error() {
        let mut b = build([1, 0, 0, 0], 8, &[0xE0]);
        // Last node, right record (bit 1 of 1.0.0.0): point 5 bytes into the separator.
        b[7 * 6 + 3..7 * 6 + 6].copy_from_slice(&(8u32 + 5).to_be_bytes()[1..]);
        let db = Mmdb::from_bytes(b).unwrap();
        assert!(db.lookup("1.2.3.4".parse().unwrap()).is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(Mmdb::from_bytes(b"not a database".to_vec()).is_err());
        let mut truncated = build([1, 0, 0, 0], 8, &[]);
        truncated.truncate(truncated.len() - 5);
        assert!(Mmdb::from_bytes(truncated).is_err());
    }

    #[test]
    fn empty_and_partial_downloads_are_clear_errors() {
        assert!(Mmdb::from_bytes(Vec::new()).is_err());
        let full = build([1, 0, 0, 0], 8, &[0xE0]);
        // Every prefix of a valid file (a download cut off anywhere) is an error, never a panic.
        for cut in 0..full.len() {
            assert!(Mmdb::from_bytes(full[..cut].to_vec()).is_err(), "prefix of {cut} bytes accepted");
        }
        let dir = std::env::temp_dir().join(format!("netscope-mmdb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let empty = dir.join("empty.mmdb");
        std::fs::write(&empty, b"").unwrap();
        let e = Mmdb::open(&empty).unwrap_err();
        assert!(e.contains("empty file") && e.contains("empty.mmdb"), "{e}");
        let partial = dir.join("partial.mmdb");
        std::fs::write(&partial, &full[..full.len() / 2]).unwrap();
        let e = Mmdb::open(&partial).unwrap_err();
        assert!(e.contains("truncated") && e.contains("partial.mmdb"), "{e}");
        assert!(Mmdb::open(&dir.join("missing.mmdb")).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A database of any record size and IP version: `path` is the bit sequence leading to `data`.
    fn build_db(record_size: usize, ip_version: u16, path: &[u8], data: &[u8]) -> Vec<u8> {
        let n = path.len();
        let mut tree = Vec::new();
        for (depth, &bit) in path.iter().enumerate() {
            let next = if depth + 1 == n { n + 16 } else { depth + 1 };
            let (l, r) = if bit == 0 { (next, n) } else { (n, next) };
            match record_size {
                24 => {
                    tree.extend_from_slice(&(l as u32).to_be_bytes()[1..]);
                    tree.extend_from_slice(&(r as u32).to_be_bytes()[1..]);
                }
                28 => {
                    tree.extend_from_slice(&(l as u32).to_be_bytes()[1..]);
                    tree.push((((l >> 24) & 0xF) << 4) as u8 | ((r >> 24) & 0xF) as u8);
                    tree.extend_from_slice(&(r as u32).to_be_bytes()[1..]);
                }
                _ => {
                    tree.extend_from_slice(&(l as u32).to_be_bytes());
                    tree.extend_from_slice(&(r as u32).to_be_bytes());
                }
            }
        }
        let mut out = tree;
        out.extend([0u8; 16]);
        out.extend_from_slice(data);
        out.extend_from_slice(METADATA_MARKER);
        map(
            &mut out,
            &[
                ("node_count", &|o: &mut Vec<u8>| uint(o, 6, n as u64)),
                ("record_size", &|o: &mut Vec<u8>| uint(o, 5, record_size as u64)),
                ("ip_version", &|o: &mut Vec<u8>| uint(o, 5, u64::from(ip_version))),
                ("database_type", &|o: &mut Vec<u8>| string(o, "Test")),
            ],
        );
        out
    }

    fn bits(b: &[u8]) -> Vec<u8> {
        b.iter().flat_map(|&x| (0..8).map(move |i| (x >> (7 - i)) & 1)).collect()
    }

    #[test]
    fn record_sizes_and_ipv6_trees() {
        let mut data = Vec::new();
        string(&mut data, "hit");
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        for rs in [24, 28, 32] {
            // IPv4 tree: 10.0.0.0/8.
            let db = Mmdb::from_bytes(build_db(rs, 4, &bits(&[10]), &data)).unwrap();
            assert_eq!(db.lookup(ip("10.200.3.4")).unwrap(), Some((Value::String("hit".into()), 8)), "record size {rs}");
            assert_eq!(db.lookup(ip("11.0.0.1")).unwrap(), None);
            assert_eq!(db.lookup(ip("::ffff:10.1.1.1")).unwrap().map(|v| v.1), Some(8), "v4-mapped in a v4 tree");
            assert_eq!(db.lookup(ip("2001:db8::1")).unwrap(), None, "v6 in a v4 tree");
            // IPv6 tree with the IPv4 subtree after 96 zero bits: 1.0.0.0/8.
            let mut path = vec![0u8; 96];
            path.extend(bits(&[1]));
            let db6 = Mmdb::from_bytes(build_db(rs, 6, &path, &data)).unwrap();
            assert_eq!(db6.ipv4_start, 96);
            assert_eq!(db6.lookup(ip("1.2.3.4")).unwrap().map(|v| v.1), Some(8), "record size {rs}: v4 through ipv4_start");
            assert_eq!(db6.lookup(ip("2.0.0.1")).unwrap(), None);
            assert_eq!(db6.lookup(ip("::1")).unwrap(), None);
            assert_eq!(db6.lookup(ip("::ffff:1.2.3.4")).unwrap(), None, "the v4-mapped block itself is not in this tree");
            // A real IPv6 prefix: 2001:db8::/32.
            let db6 = Mmdb::from_bytes(build_db(rs, 6, &bits(&[0x20, 0x01, 0x0d, 0xb8]), &data)).unwrap();
            assert_eq!(db6.lookup(ip("2001:db8:1234::1")).unwrap().map(|v| v.1), Some(32));
            assert_eq!(db6.lookup(ip("2001:db9::1")).unwrap(), None);
            assert_eq!(db6.lookup(ip("8.8.8.8")).unwrap(), None, "v4 falls off the empty v4 subtree");
        }
        let e = Mmdb::from_bytes(build_db(32, 4, &bits(&[10]), &data)).unwrap().lookup(ip("10.0.0.1"));
        assert!(e.is_ok());
        assert!(Mmdb::from_bytes(build_db(20, 4, &bits(&[10]), &data)).unwrap_err().contains("unsupported record size 20"));
        // The metadata is read from the last marker; a tree that does not fit the file is refused.
        let mut small = build_db(24, 4, &bits(&[10]), &data);
        let marker = small.windows(METADATA_MARKER.len()).rposition(|w| w == METADATA_MARKER).unwrap();
        small.drain(0..marker - 8);
        assert!(Mmdb::from_bytes(small).unwrap_err().contains("larger than file"));
    }

    #[test]
    fn random_mutations_never_panic() {
        let mut data = Vec::new();
        map(&mut data, &[
            ("s", &|o: &mut Vec<u8>| string(o, "x")),
            ("n", &|o: &mut Vec<u8>| uint(o, 6, 7)),
            ("a", &|o: &mut Vec<u8>| {
                ctrl(o, 11, 2);
                ctrl(o, 14, 1);
                o.extend([0x20, 3]);
            }),
            ("d", &|o: &mut Vec<u8>| {
                ctrl(o, 3, 8);
                o.extend(1.5f64.to_be_bytes());
            }),
            ("f", &|o: &mut Vec<u8>| {
                ctrl(o, 15, 4);
                o.extend(2.5f32.to_be_bytes());
            }),
            ("i", &|o: &mut Vec<u8>| {
                ctrl(o, 8, 1);
                o.push(0xFF);
            }),
            ("b", &|o: &mut Vec<u8>| {
                ctrl(o, 4, 2);
                o.extend([1, 2]);
            }),
        ]);
        let base = build([1, 0, 0, 0], 8, &data);
        let db = Mmdb::from_bytes(base.clone()).unwrap();
        let (v, _) = db.lookup("1.2.3.4".parse().unwrap()).unwrap().unwrap();
        assert_eq!(v.get("i"), Some(&Value::Int(-1)), "sign extension from one byte");
        assert_eq!(v.get("f").and_then(Value::as_f64), Some(2.5));
        assert_eq!(v.get("b"), Some(&Value::Bytes(vec![1, 2])));
        assert_eq!(v.path(&["a", "0"]), Some(&Value::Bool(true)));
        let ips: Vec<IpAddr> = ["1.2.3.4", "1.0.0.0", "255.255.255.255", "0.0.0.0", "::", "::ffff:1.1.1.1", "2001:db8::1"].iter().map(|s| s.parse().unwrap()).collect();
        let mut seed = 0xDEAD_BEEF_CAFE_F00Du64;
        let mut rnd = move || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 33) as u32
        };
        for i in 0..base.len() {
            for v in [0x00, 0x1F, 0x20, 0x7F, 0xE0, 0xFF] {
                let mut m = base.clone();
                m[i] = v;
                if let Ok(db) = Mmdb::from_bytes(m) {
                    for ip in &ips {
                        let _ = db.lookup(*ip);
                    }
                }
            }
        }
        for _ in 0..2000 {
            let mut m = base.clone();
            for _ in 0..1 + rnd() % 5 {
                let i = rnd() as usize % m.len();
                m[i] = rnd() as u8;
            }
            if let Ok(db) = Mmdb::from_bytes(m) {
                for ip in &ips {
                    let _ = db.lookup(*ip);
                }
            }
        }
    }

    #[test]
    fn real_dbip_databases_if_present() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("geoip");
        let Ok(city) = Mmdb::open(&dir.join("dbip-city-lite.mmdb")) else { return };
        let (v, _) = city.lookup("8.8.8.8".parse().unwrap()).unwrap().unwrap();
        assert_eq!(v.path(&["country", "iso_code"]).and_then(Value::as_str), Some("US"));
        if let Ok(asn) = Mmdb::open(&dir.join("dbip-asn-lite.mmdb")) {
            let (v, _) = asn.lookup("1.1.1.1".parse().unwrap()).unwrap().unwrap();
            assert_eq!(v.get("autonomous_system_number").and_then(Value::as_u64), Some(13335));
        }
    }
}
