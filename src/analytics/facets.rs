//! Value-list filters for the dashboard's filter bars ("any of these values" per field, all
//! fields at once) and the counts shown next to each value.
//!
//! A filter arrives as a JSON object, `{"country":["DE","NL"],"process":["chrome.exe"]}`,
//! so values may contain any character (provider names have commas). Values compare
//! case-insensitively. The count of a value is taken with every *other* field's filter
//! applied — the usual faceted-search behaviour: picking a country does not hide the other
//! countries from the list, but the program list shrinks to the programs in that country.

use std::collections::{BTreeMap, HashMap};

/// Values listed per field in a response (the most frequent first).
pub const TOP_VALUES: usize = 50;

/// Selected values per field; an empty filter matches everything.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Facets {
    selected: BTreeMap<String, Vec<String>>,
}

/// `field -> [(value, count)]`, most frequent first.
pub type FacetCounts = BTreeMap<&'static str, Vec<(String, usize)>>;

impl Facets {
    /// Parses `{"field": ["value", …], …}`; every field must be one of `fields`. An empty
    /// string, `{}` and empty lists mean "no filter" for that part.
    pub fn parse(spec: Option<&str>, fields: &[&str]) -> Result<Self, String> {
        let spec = spec.map(str::trim).unwrap_or("");
        if spec.is_empty() {
            return Ok(Self::default());
        }
        let raw: BTreeMap<String, serde_json::Value> = serde_json::from_str(spec).map_err(|e| format!("filter must be a JSON object of value lists: {e}"))?;
        let mut selected = BTreeMap::new();
        for (field, v) in raw {
            if !fields.contains(&field.as_str()) {
                return Err(format!("unknown filter field {field:?}; known: {}", fields.join(", ")));
            }
            let values: Vec<String> = match v {
                serde_json::Value::Array(a) => a
                    .into_iter()
                    .map(|x| match x {
                        serde_json::Value::String(s) => Ok(s.to_lowercase()),
                        serde_json::Value::Number(n) => Ok(n.to_string()),
                        other => Err(format!("filter {field}: values must be strings, not {other}")),
                    })
                    .collect::<Result<_, _>>()?,
                serde_json::Value::String(s) => vec![s.to_lowercase()],
                other => return Err(format!("filter {field}: expected a list of values, not {other}")),
            };
            if !values.is_empty() {
                selected.insert(field, values);
            }
        }
        Ok(Self { selected })
    }

    pub fn is_empty(&self) -> bool {
        self.selected.is_empty()
    }

    /// Every selected field has one of its values among the record's (`value_of(field)`).
    pub fn matches(&self, value_of: impl Fn(&str) -> Vec<String>) -> bool {
        self.matches_except(None, &value_of)
    }

    fn matches_except(&self, skip: Option<&str>, value_of: &impl Fn(&str) -> Vec<String>) -> bool {
        self.selected
            .iter()
            .filter(|(f, _)| Some(f.as_str()) != skip)
            .all(|(f, want)| value_of(f).iter().any(|v| want.iter().any(|w| v.eq_ignore_ascii_case(w) || v.to_lowercase() == *w)))
    }
}

/// Collects the per-value counts of `fields` over records fed with [`Counter::add`].
pub struct Counter {
    fields: &'static [&'static str],
    counts: Vec<HashMap<String, usize>>,
}

impl Counter {
    pub fn new(fields: &'static [&'static str]) -> Self {
        Self { fields, counts: fields.iter().map(|_| HashMap::new()).collect() }
    }

    /// Counts the record's values for each field it would be listed under: the record
    /// passes every filter except the one on that field. Empty values are not listed.
    pub fn add(&mut self, facets: &Facets, value_of: impl Fn(&str) -> Vec<String>) {
        for (i, f) in self.fields.iter().enumerate() {
            if !facets.matches_except(Some(f), &value_of) {
                continue;
            }
            let mut seen: Vec<String> = value_of(f).into_iter().filter(|v| !v.is_empty()).collect();
            seen.sort();
            seen.dedup();
            for v in seen {
                *self.counts[i].entry(v).or_default() += 1;
            }
        }
    }

    pub fn finish(self) -> FacetCounts {
        self.fields
            .iter()
            .zip(self.counts)
            .map(|(f, c)| {
                let mut v: Vec<(String, usize)> = c.into_iter().collect();
                v.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                v.truncate(TOP_VALUES);
                (*f, v)
            })
            .collect()
    }
}

/// The string at a JSON pointer (`/geo/country_code`); numbers as text, `null`/absent as
/// `missing`.
pub fn json_value(v: &serde_json::Value, pointer: &str, missing: &str) -> String {
    match v.pointer(pointer) {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        Some(serde_json::Value::Bool(b)) => b.to_string(),
        _ => missing.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIELDS: &[&str] = &["country", "process"];

    fn rec<'a>(country: &'a str, process: &'a str) -> impl Fn(&str) -> Vec<String> + 'a {
        move |f| match f {
            "country" => vec![country.to_string()],
            "process" => vec![process.to_string()],
            _ => vec![],
        }
    }

    #[test]
    fn parses_value_lists_and_rejects_the_rest() {
        assert!(Facets::parse(None, FIELDS).unwrap().is_empty());
        assert!(Facets::parse(Some("  "), FIELDS).unwrap().is_empty());
        assert!(Facets::parse(Some("{}"), FIELDS).unwrap().is_empty());
        assert!(Facets::parse(Some(r#"{"country":[]}"#), FIELDS).unwrap().is_empty(), "an empty list is no filter");
        let f = Facets::parse(Some(r#"{"country":["DE","nl"],"process":"Chrome.exe"}"#), FIELDS).unwrap();
        assert!(f.matches(rec("de", "chrome.EXE")));
        assert!(f.matches(rec("NL", "Chrome.exe")));
        assert!(!f.matches(rec("US", "chrome.exe")));
        assert!(!f.matches(rec("DE", "firefox.exe")), "fields combine with and");
        let commas = Facets::parse(Some(r#"{"process":["Google, LLC"]}"#), FIELDS).unwrap();
        assert!(commas.matches(rec("x", "google, llc")), "values may contain commas");
        for bad in [r#"{"ip":["1.2.3.4"]}"#, "[1,2]", "country=DE", r#"{"country":[{"a":1}]}"#, r#"{"country":true}"#, "{"] {
            assert!(Facets::parse(Some(bad), FIELDS).is_err(), "{bad}");
        }
        let n = Facets::parse(Some(r#"{"country":[7]}"#), FIELDS).unwrap();
        assert!(n.matches(rec("7", "")), "numbers compare as text");
    }

    #[test]
    fn counts_ignore_the_fields_own_filter() {
        let rows = [("DE", "chrome.exe"), ("DE", "svc.exe"), ("NL", "chrome.exe"), ("US", "curl.exe"), ("", "x.exe")];
        let f = Facets::parse(Some(r#"{"country":["DE"]}"#), FIELDS).unwrap();
        let mut c = Counter::new(FIELDS);
        for (cc, p) in rows {
            c.add(&f, rec(cc, p));
        }
        let out = c.finish();
        assert_eq!(out["country"], vec![("DE".into(), 2), ("NL".into(), 1), ("US".into(), 1)], "every country stays listed; empty values are not");
        assert_eq!(out["process"], vec![("chrome.exe".into(), 1), ("svc.exe".into(), 1)], "programs of the chosen country only");
        assert_eq!(rows.iter().filter(|(cc, p)| f.matches(rec(cc, p))).count(), 2);
    }

    #[test]
    fn counts_are_capped_and_ordered() {
        let mut c = Counter::new(FIELDS);
        let mut records = 0;
        for i in 0..(TOP_VALUES + 20) {
            for _ in 0..(i % 3 + 1) {
                c.add(&Facets::default(), rec("x", &format!("p{i:03}")));
                records += 1;
            }
        }
        let out = c.finish();
        assert_eq!(out["process"].len(), TOP_VALUES);
        assert!(out["process"].windows(2).all(|w| w[0].1 > w[1].1 || (w[0].1 == w[1].1 && w[0].0 < w[1].0)));
        assert_eq!(out["country"], vec![("x".into(), records)], "every record counts once");
        // A list field naming one value twice still counts that record once.
        let mut c = Counter::new(FIELDS);
        for _ in 0..3 {
            c.add(&Facets::default(), |f: &str| if f == "process" { vec!["a.exe".into(), "a.exe".into(), "b.exe".into()] } else { vec![] });
        }
        assert_eq!(c.finish()["process"], vec![("a.exe".into(), 3), ("b.exe".into(), 3)]);
    }

    #[test]
    fn json_pointers() {
        let v = serde_json::json!({ "geo": { "country_code": "DE", "asn": 15169 }, "rcode": null, "ok": true });
        assert_eq!(json_value(&v, "/geo/country_code", "-"), "DE");
        assert_eq!(json_value(&v, "/geo/asn", "-"), "15169");
        assert_eq!(json_value(&v, "/rcode", "pending"), "pending");
        assert_eq!(json_value(&v, "/nope", ""), "");
        assert_eq!(json_value(&v, "/ok", ""), "true");
    }
}
