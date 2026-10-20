//! Offline IP geolocation and provider (AS) lookup from DB-IP Lite / GeoLite2 `.mmdb`
//! files. Nothing leaves the machine; lookups take microseconds and are cached.

pub mod mmdb;

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::Serialize;

use crate::analytics::addr::is_external;
use mmdb::{Mmdb, Value};

pub const CITY_FILE: &str = "dbip-city-lite.mmdb";
pub const ASN_FILE: &str = "dbip-asn-lite.mmdb";
const CACHE: usize = 20_000;

/// Networks whose addresses are served from many places at once: a city for them
/// says little about where the traffic really goes.
const ANYCAST_ASNS: &[(u32, &str)] = &[
    (13335, "Cloudflare"),
    (209242, "Cloudflare"),
    (15169, "Google"),
    (396982, "Google Cloud"),
    (16509, "Amazon"),
    (14618, "Amazon"),
    (54113, "Fastly"),
    (20940, "Akamai"),
    (16625, "Akamai"),
    (8075, "Microsoft"),
    (32934, "Meta"),
    (13414, "X/Twitter"),
    (2906, "Netflix"),
    (40027, "Netflix"),
    (19551, "Incapsula"),
    (60068, "CDN77"),
    (200325, "Bunny CDN"),
    (13238, "Yandex"),
    (47541, "VK"),
];

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct GeoInfo {
    pub country_code: Option<String>,
    /// English name; `country_ru` carries the Russian one when the database has it.
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_ru: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city_ru: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub asn: Option<u32>,
    /// Provider / organisation owning the address block.
    pub org: Option<String>,
    /// Anycast/CDN network: the location is one of many.
    pub anycast: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeoStatus {
    pub city: bool,
    pub asn: bool,
    pub dir: Option<String>,
    pub note: Option<String>,
}

pub struct GeoDb {
    city: Option<Mmdb>,
    asn: Option<Mmdb>,
    dir: Option<PathBuf>,
    note: Option<String>,
    cache: Mutex<HashMap<IpAddr, Option<GeoInfo>>>,
}

/// English name (the API's canonical form), falling back to any language present.
fn name(v: Option<&Value>) -> Option<String> {
    let names = v?.get("names")?;
    names
        .get("en")
        .or_else(|| match names {
            Value::Map(m) => m.values().next(),
            _ => None,
        })
        .and_then(Value::as_str)
        .map(String::from)
}

/// Russian name, only when the database has one that differs from the English.
fn name_ru(v: Option<&Value>, en: Option<&str>) -> Option<String> {
    let ru = v?.get("names")?.get("ru")?.as_str()?;
    (Some(ru) != en).then(|| ru.to_string())
}

/// Where to look for the databases, most specific first.
pub fn candidate_dirs(explicit: Option<&Path>) -> Vec<PathBuf> {
    if let Some(p) = explicit {
        return vec![p.to_path_buf()];
    }
    let mut dirs = vec![PathBuf::from("geoip")];
    if let Ok(exe) = std::env::current_exe() {
        for anc in exe.ancestors().skip(1).take(4) {
            dirs.push(anc.join("geoip"));
        }
    }
    // Where the Windows installer and the tray's downloader put the files (per user / all users).
    for (var, vendor) in [("LOCALAPPDATA", "NetScope"), ("PROGRAMDATA", "NetScope")] {
        if let Some(d) = std::env::var_os(var) {
            dirs.push(PathBuf::from(d).join(vendor).join("geoip"));
        }
    }
    if let Some(d) = std::env::var_os("LOCALAPPDATA").or_else(|| std::env::var_os("XDG_DATA_HOME")) {
        dirs.push(PathBuf::from(d).join("netscope").join("geoip"));
    }
    if let Some(h) = std::env::var_os("HOME") {
        dirs.push(PathBuf::from(h).join(".local/share/netscope/geoip"));
    }
    dirs
}

impl GeoDb {
    /// Opens whatever databases exist in the first directory that has any.
    pub fn open(explicit: Option<&Path>) -> Self {
        for dir in candidate_dirs(explicit) {
            let (c, a) = (dir.join(CITY_FILE), dir.join(ASN_FILE));
            if !c.exists() && !a.exists() {
                continue;
            }
            let mut notes = Vec::new();
            let mut load = |p: &Path| -> Option<Mmdb> {
                if !p.exists() {
                    return None;
                }
                Mmdb::open(p).map_err(|e| notes.push(e)).ok()
            };
            let (city, asn) = (load(&c), load(&a));
            return GeoDb { city, asn, dir: Some(dir), note: (!notes.is_empty()).then(|| notes.join("; ")), cache: Mutex::default() };
        }
        GeoDb::disabled("GeoIP databases not found: use the tray menu “Download geolocation data”, run scripts/fetch-geoip.ps1, or pass --geoip DIR")
    }

    pub fn disabled(note: &str) -> Self {
        GeoDb { city: None, asn: None, dir: None, note: Some(note.into()), cache: Mutex::default() }
    }

    #[cfg(test)]
    pub(crate) fn from_dbs(city: Option<Mmdb>, asn: Option<Mmdb>) -> Self {
        GeoDb { city, asn, dir: None, note: None, cache: Mutex::default() }
    }

    pub fn status(&self) -> GeoStatus {
        GeoStatus {
            city: self.city.is_some(),
            asn: self.asn.is_some(),
            dir: self.dir.as_ref().map(|d| d.display().to_string()),
            note: self.note.clone(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.city.is_some() || self.asn.is_some()
    }

    /// Location and provider of a public address; `None` for private/local ones.
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoInfo> {
        if !self.enabled() || !is_external(&ip) {
            return None;
        }
        if let Some(hit) = self.cache.lock().ok().and_then(|c| c.get(&ip).cloned()) {
            return hit;
        }
        let info = self.resolve(ip);
        if let Ok(mut c) = self.cache.lock() {
            if c.len() >= CACHE {
                c.clear();
            }
            c.insert(ip, info.clone());
        }
        info
    }

    fn resolve(&self, ip: IpAddr) -> Option<GeoInfo> {
        let mut g = GeoInfo::default();
        if let Some(Ok(Some((v, _)))) = self.city.as_ref().map(|db| db.lookup(ip)) {
            let country = v.get("country");
            g.country_code = country.and_then(|c| c.get("iso_code")).and_then(Value::as_str).map(String::from);
            g.country = name(country);
            g.country_ru = name_ru(country, g.country.as_deref());
            g.region = name(v.path(&["subdivisions", "0"]));
            g.city = name(v.get("city"));
            g.city_ru = name_ru(v.get("city"), g.city.as_deref());
            g.lat = v.path(&["location", "latitude"]).and_then(Value::as_f64);
            g.lon = v.path(&["location", "longitude"]).and_then(Value::as_f64);
        }
        if let Some(Ok(Some((v, _)))) = self.asn.as_ref().map(|db| db.lookup(ip)) {
            g.asn = v.get("autonomous_system_number").and_then(Value::as_u64).map(|n| n as u32);
            g.org = v.get("autonomous_system_organization").and_then(Value::as_str).map(String::from);
        }
        if let Some(asn) = g.asn {
            if let Some((_, brand)) = ANYCAST_ASNS.iter().find(|(n, _)| *n == asn) {
                g.anycast = true;
                if g.org.is_none() {
                    g.org = Some((*brand).into());
                }
            }
        }
        (g != GeoInfo::default()).then_some(g)
    }
}

#[cfg(test)]
mod tests {
    use super::mmdb::testdb::*;
    use super::*;

    fn city_db() -> Mmdb {
        let mut data = Vec::new();
        map(
            &mut data,
            &[
                ("country", &|o: &mut Vec<u8>| {
                    map(o, &[
                        ("iso_code", &|o: &mut Vec<u8>| string(o, "DE")),
                        ("names", &|o: &mut Vec<u8>| map(o, &[("en", &|o: &mut Vec<u8>| string(o, "Germany")), ("ru", &|o: &mut Vec<u8>| string(o, "Германия"))])),
                    ])
                }),
                ("city", &|o: &mut Vec<u8>| {
                    map(o, &[("names", &|o: &mut Vec<u8>| map(o, &[("en", &|o: &mut Vec<u8>| string(o, "Frankfurt am Main")), ("ru", &|o: &mut Vec<u8>| string(o, "Frankfurt am Main"))]))])
                }),
            ],
        );
        Mmdb::from_bytes(build([8, 0, 0, 0], 8, &data)).unwrap()
    }

    fn asn_db() -> Mmdb {
        let mut data = Vec::new();
        map(
            &mut data,
            &[
                ("autonomous_system_number", &|o: &mut Vec<u8>| uint(o, 6, 13335)),
                ("autonomous_system_organization", &|o: &mut Vec<u8>| string(o, "Cloudflare, Inc.")),
            ],
        );
        Mmdb::from_bytes(build([8, 0, 0, 0], 8, &data)).unwrap()
    }

    #[test]
    fn combines_city_and_asn() {
        let g = GeoDb::from_dbs(Some(city_db()), Some(asn_db()));
        let info = g.lookup("8.1.2.3".parse().unwrap()).unwrap();
        assert_eq!(info.country_code.as_deref(), Some("DE"));
        assert_eq!(info.country.as_deref(), Some("Germany"), "English is canonical");
        assert_eq!(info.country_ru.as_deref(), Some("Германия"));
        assert_eq!(info.city.as_deref(), Some("Frankfurt am Main"));
        assert_eq!(info.city_ru, None, "same as English: omitted");
        assert_eq!((info.asn, info.org.as_deref(), info.anycast), (Some(13335), Some("Cloudflare, Inc."), true));
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["country_ru"], "Германия");
        assert!(json.get("city_ru").is_none(), "absent, not null: {json}");
        assert_eq!(g.lookup("8.1.2.3".parse().unwrap()), Some(info), "cached");
        assert!(g.lookup("9.9.9.9".parse().unwrap()).is_none(), "not in db");
        assert!(g.lookup("192.168.1.1".parse().unwrap()).is_none(), "private addresses skipped");
    }

    #[test]
    fn disabled_without_files() {
        let g = GeoDb::open(Some(Path::new("definitely/missing/dir")));
        assert!(!g.enabled());
        let note = g.status().note.unwrap();
        assert!(note.contains("Download geolocation data") && note.contains("--geoip"), "{note}");
        assert!(g.lookup("8.8.8.8".parse().unwrap()).is_none());
    }

    #[test]
    fn installer_directories_are_candidates() {
        let dirs = candidate_dirs(None);
        assert_eq!(dirs[0], PathBuf::from("geoip"));
        if std::env::var_os("PROGRAMDATA").is_some() {
            assert!(dirs.iter().any(|d| d.ends_with(Path::new("NetScope").join("geoip")) && d.starts_with(std::env::var_os("PROGRAMDATA").unwrap())), "{dirs:?}");
        }
        if std::env::var_os("LOCALAPPDATA").is_some() {
            assert!(dirs.iter().any(|d| d.ends_with(Path::new("NetScope").join("geoip")) && d.starts_with(std::env::var_os("LOCALAPPDATA").unwrap())), "{dirs:?}");
        }
        assert_eq!(candidate_dirs(Some(Path::new("x"))), vec![PathBuf::from("x")]);
    }

    #[test]
    fn real_databases_if_present() {
        let g = GeoDb::open(Some(&Path::new(env!("CARGO_MANIFEST_DIR")).join("geoip")));
        if !g.enabled() {
            return;
        }
        let google = g.lookup("8.8.8.8".parse().unwrap()).unwrap();
        assert_eq!(google.country_code.as_deref(), Some("US"));
        assert!(google.anycast && google.asn == Some(15169));
    }
}
