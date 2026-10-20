//! A small Wireshark-display-filter-like query language for dashboard tables.
//!
//! Grammar (keywords `and`, `or`, `not`, `in` are case-insensitive):
//!
//! ```text
//! filter  := or?                                  (empty input matches everything)
//! or      := and (("or" | "||") and)*
//! and     := unary (("and" | "&&")? unary)*       (juxtaposition = and)
//! unary   := ("not" | "!") unary | primary
//! primary := "(" or ")"
//!          | FIELD op VALUE                       op: == = : != > < >= <= ~ !~
//!          | FIELD ("not")? "in" "{" [VALUE ("," VALUE)* ","?] "}"
//!          | WORD | STRING                        free-text substring of Record::text()
//! VALUE   := WORD | STRING
//! ```
//!
//! * WORD: a run of characters other than whitespace and `( ) " ' { } , = ! < > ~ : & |`.
//!   Because `:` is an operator (`port:80`), IPv6 addresses must be quoted: `ip == "::1"`.
//! * STRING: `"..."` or `'...'`; a backslash escapes the next character (`\n`, `\t` too).
//! * Numbers accept units. Bytes (1024-based): `B K KB KiB M MB MiB G GB GiB T TB` and
//!   `Б КБ МБ ГБ ТБ`, case-insensitive, with one exception: a lone lowercase `m` means
//!   minutes (uppercase `M` means MiB). Durations convert to milliseconds:
//!   `us µs мкс ms мс s sec с m min мин h ч`.
//! * `>`/`<`/`>=`/`<=` require a numeric value (parse error otherwise).
//! * String equality is case-insensitive and supports `*` / `?` wildcards (also in sets).
//! * `~` is a case-insensitive "contains". Negated forms (`!=`, `!~`, `not in`) are the exact
//!   negation of their positive form, so lists match when *no* element matches and missing
//!   values make them true.
//! * The token right after an operator (or inside `{...}`) is always a value, even if it is
//!   a keyword: `dir == in` works.
//! * A bare word that names a field whose record value is `Bool` means `field == true`
//!   (`not signed`); otherwise it is a substring search.

use std::fmt;

/// A value a record exposes for a field.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    Str(String),
    Num(f64),
    Bool(bool),
    List(Vec<String>),
    Missing,
}

/// Something that can be filtered (implemented by the project for its row types).
pub trait Record {
    /// Value of a (canonical, lowercase) field name. Unknown or absent -> FieldValue::Missing.
    fn field(&self, name: &str) -> FieldValue;
    /// Free text searched by bare words (e.g. process name, host name, IPs, ports joined by spaces).
    fn text(&self) -> String;
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct FilterError {
    /// Char offset in the input.
    pub position: usize,
    pub message: String,
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (at {})", self.message, self.position)
    }
}

impl std::error::Error for FilterError {}

/// A parsed filter expression.
#[derive(Debug, Clone)]
pub struct Filter {
    root: Option<Node>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Op {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
    Contains,
    NotContains,
}

#[derive(Debug, Clone)]
struct Value {
    lower: String,
    num: Option<f64>,
}

#[derive(Debug, Clone)]
enum Node {
    /// Lowercased needle; `field` is set when the word names a field (boolean shorthand).
    Text { needle: String, field: Option<String> },
    Cmp { field: String, op: Op, value: Value },
    In { field: String, values: Vec<Value>, negated: bool },
    Not(Box<Node>),
    And(Box<Node>, Box<Node>),
    Or(Box<Node>, Box<Node>),
}

const MAX_DEPTH: usize = 64;
/// Longer inputs are rejected: `and`/`or` chains become a tree as deep as the number of
/// terms, and evaluating or dropping a very deep tree would exhaust the stack.
const MAX_INPUT_CHARS: usize = 4096;
const MAX_TOKENS: usize = 512;

fn err<T>(position: usize, message: impl Into<String>) -> Result<T, FilterError> {
    Err(FilterError { position, message: message.into() })
}

// ---------------------------------------------------------------- lexer

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    Str(String),
    Op(Op),
    And,
    Or,
    Not,
    In,
    LParen,
    RParen,
    LBrace,
    RBrace,
    Comma,
}

#[derive(Debug, Clone)]
struct Token {
    tok: Tok,
    pos: usize,
    text: String,
}

fn is_word_char(c: char) -> bool {
    !c.is_whitespace() && !"()\"'{},=!<>~:&|".contains(c)
}

fn lex(input: &str) -> Result<Vec<Token>, FilterError> {
    let chars: Vec<char> = input.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        let start = i;
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '"' || c == '\'' {
            let mut s = String::new();
            i += 1;
            loop {
                match chars.get(i) {
                    None => return err(start, "unterminated string"),
                    Some(&q) if q == c => break,
                    Some('\\') => {
                        match chars.get(i + 1) {
                            None => return err(start, "unterminated string"),
                            Some('n') => s.push('\n'),
                            Some('t') => s.push('\t'),
                            Some(&e) => s.push(e),
                        }
                        i += 1;
                    }
                    Some(&ch) => s.push(ch),
                }
                i += 1;
            }
            i += 1;
            out.push(Token { tok: Tok::Str(s), pos: start, text: chars[start..i].iter().collect() });
            continue;
        }
        if is_word_char(c) {
            while chars.get(i).is_some_and(|&ch| is_word_char(ch)) {
                i += 1;
            }
            let w: String = chars[start..i].iter().collect();
            let tok = match w.to_lowercase().as_str() {
                "and" => Tok::And,
                "or" => Tok::Or,
                "not" => Tok::Not,
                "in" => Tok::In,
                _ => Tok::Word(w.clone()),
            };
            out.push(Token { tok, pos: start, text: w });
            continue;
        }
        let next = chars.get(i + 1).copied();
        let (tok, len) = match (c, next) {
            ('(', _) => (Tok::LParen, 1),
            (')', _) => (Tok::RParen, 1),
            ('{', _) => (Tok::LBrace, 1),
            ('}', _) => (Tok::RBrace, 1),
            (',', _) => (Tok::Comma, 1),
            ('=', Some('=')) => (Tok::Op(Op::Eq), 2),
            ('=', _) | (':', _) => (Tok::Op(Op::Eq), 1),
            ('!', Some('=')) => (Tok::Op(Op::Ne), 2),
            ('!', Some('~')) => (Tok::Op(Op::NotContains), 2),
            ('!', _) => (Tok::Not, 1),
            ('>', Some('=')) => (Tok::Op(Op::Ge), 2),
            ('>', _) => (Tok::Op(Op::Gt), 1),
            ('<', Some('=')) => (Tok::Op(Op::Le), 2),
            ('<', _) => (Tok::Op(Op::Lt), 1),
            ('~', _) => (Tok::Op(Op::Contains), 1),
            ('&', Some('&')) => (Tok::And, 2),
            ('|', Some('|')) => (Tok::Or, 2),
            _ => return err(i, format!("unexpected `{c}`; did you mean `{c}{c}`?")),
        };
        i += len;
        out.push(Token { tok, pos: start, text: chars[start..i].iter().collect() });
    }
    Ok(out)
}

// ---------------------------------------------------------------- parser

struct Parser {
    toks: Vec<Token>,
    i: usize,
    end: usize,
    fields: Vec<(String, Vec<String>)>,
    depth: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.i).map(|t| &t.tok)
    }

    fn pos(&self) -> usize {
        self.toks.get(self.i).map_or(self.end, |t| t.pos)
    }

    fn found(&self) -> String {
        self.toks.get(self.i).map_or("end of input".into(), |t| format!("`{}`", t.text))
    }

    fn enter(&mut self) -> Result<(), FilterError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return err(self.pos(), "expression nested too deeply");
        }
        Ok(())
    }

    fn lookup(&self, name: &str) -> Option<String> {
        let n = name.to_lowercase();
        self.fields
            .iter()
            .find(|(c, aliases)| *c == n || aliases.contains(&n))
            .map(|(c, _)| c.clone())
    }

    fn or(&mut self) -> Result<Node, FilterError> {
        let mut l = self.and()?;
        while self.peek() == Some(&Tok::Or) {
            self.i += 1;
            l = Node::Or(Box::new(l), Box::new(self.and()?));
        }
        Ok(l)
    }

    fn and(&mut self) -> Result<Node, FilterError> {
        let mut l = self.unary()?;
        loop {
            match self.peek() {
                Some(Tok::And) => self.i += 1,
                Some(Tok::Word(_) | Tok::Str(_) | Tok::Not | Tok::LParen) => {}
                _ => break,
            }
            l = Node::And(Box::new(l), Box::new(self.unary()?));
        }
        Ok(l)
    }

    fn unary(&mut self) -> Result<Node, FilterError> {
        if self.peek() != Some(&Tok::Not) {
            return self.primary();
        }
        self.i += 1;
        self.enter()?;
        let e = self.unary()?;
        self.depth -= 1;
        Ok(Node::Not(Box::new(e)))
    }

    fn primary(&mut self) -> Result<Node, FilterError> {
        let Some(t) = self.toks.get(self.i).cloned() else {
            return err(self.end, "expected expression, found end of input");
        };
        match t.tok {
            Tok::LParen => {
                self.i += 1;
                self.enter()?;
                let e = self.or()?;
                self.depth -= 1;
                match self.peek() {
                    Some(Tok::RParen) => {
                        self.i += 1;
                        Ok(e)
                    }
                    None => err(t.pos, "unclosed `(`"),
                    Some(_) => err(self.pos(), format!("expected `)`, found {}", self.found())),
                }
            }
            Tok::Str(s) => {
                self.i += 1;
                Ok(Node::Text { needle: s.to_lowercase(), field: None })
            }
            Tok::Word(w) => {
                self.i += 1;
                let next2 = self.toks.get(self.i + 1).map(|t| &t.tok);
                match self.peek() {
                    Some(Tok::Op(op)) => {
                        let op = *op;
                        let field = self.field(&w, t.pos)?;
                        self.comparison(field, op)
                    }
                    Some(Tok::In) => {
                        let field = self.field(&w, t.pos)?;
                        self.i += 1;
                        self.set(field, false)
                    }
                    Some(Tok::Not) if next2 == Some(&Tok::In) => {
                        let field = self.field(&w, t.pos)?;
                        self.i += 2;
                        self.set(field, true)
                    }
                    _ => Ok(Node::Text { needle: w.to_lowercase(), field: self.lookup(&w) }),
                }
            }
            _ => err(t.pos, format!("expected expression, found `{}`", t.text)),
        }
    }

    fn field(&self, name: &str, pos: usize) -> Result<String, FilterError> {
        self.lookup(name).ok_or_else(|| {
            let known: Vec<&str> = self.fields.iter().map(|(c, _)| c.as_str()).collect();
            FilterError {
                position: pos,
                message: format!("unknown field \"{name}\"; known: {}", known.join(", ")),
            }
        })
    }

    /// Consumes a WORD or STRING value token.
    fn value(&mut self) -> Option<(Value, usize, String)> {
        let t = self.toks.get(self.i)?;
        let raw = match &t.tok {
            Tok::Word(s) | Tok::Str(s) => s.clone(),
            // keywords in value position are plain values: `dir == in`
            Tok::And | Tok::Or | Tok::Not | Tok::In => t.text.clone(),
            _ => return None,
        };
        let pos = t.pos;
        self.i += 1;
        Some((Value { lower: raw.to_lowercase(), num: parse_number(&raw) }, pos, raw))
    }

    fn comparison(&mut self, field: String, op: Op) -> Result<Node, FilterError> {
        let op_text = self.toks.get(self.i).map(|t| t.text.clone()).unwrap_or_default();
        self.i += 1;
        let Some((value, pos, raw)) = self.value() else {
            let hint = if self.peek() == Some(&Tok::Op(Op::Eq)) { " (quote IPv6 addresses)" } else { "" };
            return err(
                self.pos(),
                format!("missing value after `{op_text}`, found {}{hint}", self.found()),
            );
        };
        if matches!(op, Op::Gt | Op::Lt | Op::Ge | Op::Le) && value.num.is_none() {
            return err(pos, format!("bad number or unit \"{raw}\""));
        }
        Ok(Node::Cmp { field, op, value })
    }

    fn set(&mut self, field: String, negated: bool) -> Result<Node, FilterError> {
        let open = self.pos();
        if self.peek() != Some(&Tok::LBrace) {
            return err(open, format!("expected `{{` after `in`, found {}", self.found()));
        }
        self.i += 1;
        let mut values = Vec::new();
        loop {
            if self.peek() == Some(&Tok::RBrace) {
                self.i += 1;
                break;
            }
            match self.value() {
                Some((v, _, _)) => values.push(v),
                None if self.peek().is_none() => return err(open, "unclosed `{`"),
                None => return err(self.pos(), format!("expected value or `}}`, found {}", self.found())),
            }
            match self.peek() {
                Some(Tok::Comma) => self.i += 1,
                Some(Tok::RBrace) => {}
                None => return err(open, "unclosed `{`"),
                Some(_) => return err(self.pos(), format!("expected `,` or `}}`, found {}", self.found())),
            }
        }
        Ok(Node::In { field, values, negated })
    }
}

/// Parses `123`, `1.5`, `-2` with an optional byte or duration unit (see module docs).
fn parse_number(s: &str) -> Option<f64> {
    let s = s.trim();
    let split = s
        .char_indices()
        .find(|&(i, c)| !(c.is_ascii_digit() || c == '.' || (i == 0 && (c == '-' || c == '+'))))
        .map_or(s.len(), |(i, _)| i);
    let (num, unit) = s.split_at(split);
    if !num.chars().any(|c| c.is_ascii_digit()) {
        return None;
    }
    let n: f64 = num.parse().ok()?;
    const KB: f64 = 1024.0;
    let mul = if unit == "m" {
        60_000.0
    } else {
        match unit.to_lowercase().as_str() {
            "" | "b" | "б" | "ms" | "мс" => 1.0,
            "k" | "kb" | "kib" | "кб" => KB,
            "m" | "mb" | "mib" | "мб" => KB * KB,
            "g" | "gb" | "gib" | "гб" => KB * KB * KB,
            "t" | "tb" | "tib" | "тб" => KB * KB * KB * KB,
            "us" | "µs" | "μs" | "мкс" => 0.001,
            "s" | "sec" | "с" => 1000.0,
            "min" | "мин" => 60_000.0,
            "h" | "ч" => 3_600_000.0,
            _ => return None,
        }
    };
    Some(n * mul)
}

// ---------------------------------------------------------------- matching

fn glob(text: &str, pat: &str) -> bool {
    let t: Vec<char> = text.chars().collect();
    let p: Vec<char> = pat.chars().collect();
    let (mut ti, mut pi) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            ti += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

fn num_eq(a: f64, b: f64) -> bool {
    (a - b).abs() <= 1e-9 * a.abs().max(b.abs()).max(1.0)
}

fn fmt_num(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "true" | "yes" | "1" | "on" => Some(true),
        "false" | "no" | "0" | "off" => Some(false),
        _ => None,
    }
}

fn str_eq(s: &str, v: &Value) -> bool {
    glob(&s.to_lowercase(), &v.lower)
        || matches!((parse_number(s), v.num), (Some(a), Some(b)) if num_eq(a, b))
}

fn eq(fv: &FieldValue, v: &Value) -> bool {
    match fv {
        FieldValue::Str(s) => str_eq(s, v),
        FieldValue::Num(n) => match v.num {
            Some(x) => num_eq(*n, x),
            None => glob(&fmt_num(*n), &v.lower),
        },
        FieldValue::Bool(b) => parse_bool(&v.lower) == Some(*b),
        FieldValue::List(l) => l.iter().any(|s| str_eq(s, v)),
        FieldValue::Missing => false,
    }
}

fn contains(fv: &FieldValue, v: &Value) -> bool {
    match fv {
        FieldValue::Str(s) => s.to_lowercase().contains(&v.lower),
        FieldValue::Num(n) => fmt_num(*n).contains(&v.lower),
        FieldValue::Bool(b) => b.to_string().contains(&v.lower),
        FieldValue::List(l) => l.iter().any(|s| s.to_lowercase().contains(&v.lower)),
        FieldValue::Missing => false,
    }
}

fn ordered(fv: &FieldValue, op: Op, v: &Value) -> bool {
    let Some(b) = v.num else { return false };
    let test = |a: f64| match op {
        Op::Gt => a > b,
        Op::Lt => a < b,
        Op::Ge => a >= b || num_eq(a, b),
        _ => a <= b || num_eq(a, b),
    };
    match fv {
        FieldValue::Num(n) => test(*n),
        FieldValue::Str(s) => parse_number(s).is_some_and(test),
        FieldValue::List(l) => l.iter().filter_map(|s| parse_number(s)).any(test),
        FieldValue::Bool(_) | FieldValue::Missing => false,
    }
}

impl Node {
    fn eval(&self, r: &dyn Record) -> bool {
        match self {
            Node::Text { needle, field } => {
                if let Some(f) = field {
                    if let FieldValue::Bool(b) = r.field(f) {
                        return b;
                    }
                }
                r.text().to_lowercase().contains(needle.as_str())
            }
            Node::Cmp { field, op, value } => {
                let fv = r.field(field);
                match op {
                    Op::Eq => eq(&fv, value),
                    Op::Ne => !eq(&fv, value),
                    Op::Contains => contains(&fv, value),
                    Op::NotContains => !contains(&fv, value),
                    _ => ordered(&fv, *op, value),
                }
            }
            Node::In { field, values, negated } => {
                let fv = r.field(field);
                values.iter().any(|v| eq(&fv, v)) != *negated
            }
            Node::Not(e) => !e.eval(r),
            Node::And(a, b) => a.eval(r) && b.eval(r),
            Node::Or(a, b) => a.eval(r) || b.eval(r),
        }
    }
}

impl Filter {
    /// `fields`: allowed canonical field names with their aliases, e.g. &[("process", &["proc","program"]), ("bytes", &["size"])].
    pub fn parse(input: &str, fields: &[(&str, &[&str])]) -> Result<Filter, FilterError> {
        if input.chars().count() > MAX_INPUT_CHARS {
            return err(MAX_INPUT_CHARS, format!("filter is too long (more than {MAX_INPUT_CHARS} characters)"));
        }
        let toks = lex(input)?;
        if let Some(t) = toks.get(MAX_TOKENS) {
            return err(t.pos, format!("filter has too many terms (more than {MAX_TOKENS})"));
        }
        if toks.is_empty() {
            return Ok(Filter { root: None });
        }
        let fields = fields
            .iter()
            .map(|(c, a)| (c.to_lowercase(), a.iter().map(|s| s.to_lowercase()).collect()))
            .collect();
        let mut p = Parser { toks, i: 0, end: input.chars().count(), fields, depth: 0 };
        let root = p.or()?;
        match p.peek() {
            None => Ok(Filter { root: Some(root) }),
            Some(Tok::RParen) => err(p.pos(), "unmatched `)`"),
            Some(_) => err(p.pos(), format!("unexpected {}", p.found())),
        }
    }

    pub fn matches(&self, r: &dyn Record) -> bool {
        self.root.as_ref().is_none_or(|n| n.eval(r))
    }

    /// Empty / whitespace-only input parses to a filter that matches everything.
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use FieldValue::*;

    const FIELDS: &[(&str, &[&str])] = &[
        ("process", &["proc", "program"]),
        ("pid", &[]),
        ("bytes", &["size"]),
        ("country", &["cc"]),
        ("app", &["proto"]),
        ("protocols", &[]),
        ("port", &[]),
        ("name", &["host"]),
        ("rtt", &[]),
        ("org", &[]),
        ("asn", &[]),
        ("ip", &["addr"]),
        ("signed", &[]),
        ("dir", &["direction"]),
        ("note", &[]),
    ];

    struct Rec(Vec<(&'static str, FieldValue)>, &'static str);

    impl Record for Rec {
        fn field(&self, name: &str) -> FieldValue {
            self.0.iter().find(|(n, _)| *n == name).map_or(Missing, |(_, v)| v.clone())
        }
        fn text(&self) -> String {
            self.1.to_string()
        }
    }

    fn s(v: &str) -> FieldValue {
        Str(v.into())
    }

    fn chrome() -> Rec {
        Rec(
            vec![
                ("process", s("chrome.exe")),
                ("pid", Num(4242.0)),
                ("bytes", Num(3.0 * 1024.0 * 1024.0)),
                ("country", s("US")),
                ("app", s("TLS")),
                ("protocols", List(vec!["tls".into(), "dns".into()])),
                ("port", s("443")),
                ("name", s("www.google.com")),
                ("rtt", Num(150.0)),
                ("org", s("Google LLC")),
                ("asn", Num(15169.0)),
                ("ip", s("140.82.112.3")),
                ("signed", Bool(true)),
                ("dir", s("out")),
            ],
            "chrome.exe www.google.com 140.82.112.3 443 Привет",
        )
    }

    fn code() -> Rec {
        Rec(
            vec![
                ("process", s("Code.exe")),
                ("bytes", Num(512.0)),
                ("country", s("RU")),
                ("app", s("http")),
                ("protocols", List(vec![])),
                ("port", Num(80.0)),
                ("name", s("update.cloudflare.net")),
                ("rtt", Num(2500.0)),
                ("org", s("Cloudflare, Inc.")),
                ("asn", s("13335")),
                ("ip", s("2606:4700::1111")),
                ("signed", Bool(false)),
                ("dir", s("in")),
            ],
            "Code.exe update.cloudflare.net 80",
        )
    }

    fn m(q: &str, r: &Rec) -> bool {
        match Filter::parse(q, FIELDS) {
            Ok(f) => f.matches(r),
            Err(e) => panic!("parse {q:?} failed: {e}"),
        }
    }

    fn e(q: &str) -> FilterError {
        match Filter::parse(q, FIELDS) {
            Ok(f) => panic!("{q:?} parsed unexpectedly: {f:?}"),
            Err(e) => e,
        }
    }

    #[test]
    fn empty_matches_all() {
        for q in ["", "   ", "\t\n"] {
            let f = Filter::parse(q, FIELDS).unwrap();
            assert!(f.is_empty());
            assert!(f.matches(&chrome()) && f.matches(&code()));
        }
        assert!(!Filter::parse("x", FIELDS).unwrap().is_empty());
    }

    #[test]
    fn bare_words_and_implicit_and() {
        assert!(m("chrome", &chrome()));
        assert!(m("CHROME google", &chrome()));
        assert!(m("chrome and google", &chrome()));
        assert!(!m("chrome cloudflare", &chrome()));
        assert!(m("\"www.google\"", &chrome()));
        assert!(m("'.EXE www'", &chrome()));
        assert!(m("привет", &chrome()), "unicode case-insensitive");
        assert!(m("140.82.112.3", &chrome()));
        // `tls` is not in text(): bare words search text() only
        assert!(!m("chrome tls", &chrome()));
    }

    #[test]
    fn combinators_and_precedence() {
        let c = chrome();
        assert!(m("chrome && google", &c));
        assert!(m("nope || chrome", &c));
        assert!(m("nope OR chrome", &c));
        assert!(m("NOT nope", &c));
        assert!(m("!nope", &c));
        assert!(!m("!!nope", &c));
        // not > and > or
        assert!(m("chrome or nope and nope", &c)); // chrome or (nope and nope)
        assert!(!m("(chrome or nope) and nope", &c));
        assert!(!m("not chrome or nope", &c)); // (not chrome) or nope
        assert!(m("not (chrome and nope)", &c));
        assert!(m("chrome !nope", &c)); // implicit and with not
        assert!(m("((chrome) and ((google or x)))", &c));
        assert!(m("chrome (nope or google)", &c));
    }

    #[test]
    fn equality_ops() {
        let (c, k) = (chrome(), code());
        assert!(m("process == \"chrome.exe\"", &c));
        assert!(m("process = CHROME.EXE", &c));
        assert!(m("process:chrome.exe", &c));
        assert!(!m("process == chrome", &c), "equality is not substring");
        assert!(!m("process == \"Code.exe\" and country != RU", &c));
        assert!(m("process == \"Code.exe\" and country != US", &k));
        assert!(m("app:http or port:80", &k));
        assert!(!m("app:http or port:80", &c));
        assert!(m("dir == out", &c) && m("direction==IN", &k));
        assert!(m("dir == in or dir:not", &k) && m("dir in {in, out}", &k), "keywords as values");
    }

    #[test]
    fn numbers_and_text_numbers() {
        let (c, k) = (chrome(), code());
        assert!(m("port == 443", &c)); // Str field, number literal
        assert!(m("port == 80", &k)); // Num field
        assert!(m("port == \"80\"", &k)); // Num field, string literal
        assert!(m("asn = 13335", &k) && m("asn = 15169", &c));
        assert!(m("pid > 4000 and pid < 5000 and pid >= 4242 and pid <= 4242", &c));
        assert!(!m("pid > 4242", &c) && !m("pid < 4242", &c));
        assert!(m("port > 400", &c), "Str field parsed for ordering");
        assert!(m("asn >= 13335", &k));
        assert!(m("rtt > 100.5", &c) && m("rtt == 150.0", &c));
        assert!(m("pid == 42*", &c), "Num field glob as text");
        assert!(m("pid ~ 24", &c));
        assert!(m("bytes == -0", &Rec(vec![("bytes", Num(0.0))], "")));
    }

    #[test]
    fn units() {
        let (c, k) = (chrome(), code());
        assert!(m("bytes > 1MB && bytes < 4M && bytes == 3mb && bytes = 3MiB", &c));
        assert!(m("bytes == 3072KB and bytes == 3072k and size == 3145728b", &c));
        assert!(m("bytes >= 0.5kb and bytes < 1K and bytes = 512B", &k));
        assert!(m("bytes < 1GB and bytes < 1g and bytes < 1тб", &c));
        assert!(m("bytes > 2МБ and bytes < 4мб and bytes == 3072кб", &c));
        assert!(m("bytes == 512Б and bytes < 1ГБ", &k));
        assert!(m("rtt > 100ms and rtt < 1s and rtt == 150мс", &c));
        assert!(m("rtt == 2.5s and rtt > 2000000us and rtt < 1m and rtt < 1h", &k));
        assert!(m("rtt < 1min and rtt < 1ч and rtt == 2.5с", &k));
        let slow = Rec(vec![("rtt", Num(120_000.0))], "");
        assert!(m("rtt == 2m and rtt == 2min", &slow));
        assert!(!m("rtt == 2M", &slow), "uppercase M is MiB");
        assert_eq!(parse_number("1.5k"), Some(1536.0));
        assert_eq!(parse_number("-2"), Some(-2.0));
        assert_eq!(parse_number("140.82.*"), None);
        assert_eq!(parse_number("1.2.3"), None);
        assert_eq!(parse_number("ms"), None);
    }

    #[test]
    fn contains_ops() {
        let (c, k) = (chrome(), code());
        assert!(m("name ~ google and rtt > 100ms", &c));
        assert!(m("org ~ \"cloudflare\" or asn = 13335", &k));
        assert!(m("org ~ CLOUD", &k) && !m("org ~ cloud", &c));
        assert!(m("org !~ cloud", &c) && !m("org !~ cloud", &k));
        assert!(m("signed ~ tru", &c));
    }

    #[test]
    fn wildcards() {
        let (c, k) = (chrome(), code());
        assert!(m("ip = 140.82.*", &c) && !m("ip = 140.82.*", &k));
        assert!(m("name == *.GOOGLE.com", &c));
        assert!(m("name == www.goo?le.com", &c));
        assert!(!m("name == www.goo?e.com", &c));
        assert!(m("name != *.google.com", &k));
        assert!(m("process in {*.EXE}", &c));
        assert!(m("ip == \"2606:4700::*\"", &k));
        assert!(glob("abc", "***") && glob("", "*") && !glob("", "?") && glob("aaab", "*a*b"));
    }

    #[test]
    fn sets() {
        let (c, k) = (chrome(), code());
        assert!(m("country in {US, DE}", &c) && !m("country in {US, DE}", &k));
        assert!(!m("bytes > 1MB && !(country in {us, de})", &k));
        assert!(m("bytes > 1MB && !(country in {RU, DE})", &c));
        assert!(m("country not in {RU, \"DE\",}", &c));
        assert!(m("country NOT IN {us} or cc in {ru}", &k));
        assert!(!m("country in {}", &c) && m("country not in {}", &c));
        assert!(m("port in {80, 8080}", &k) && m("port in {443}", &c));
    }

    #[test]
    fn lists() {
        let (c, k) = (chrome(), code());
        assert!(m("protocols == TLS", &c) && m("protocols == dns", &c));
        assert!(!m("protocols == http", &c));
        assert!(m("protocols != http", &c) && !m("protocols != dns", &c));
        assert!(m("protocols ~ n", &c) && m("protocols !~ quic", &c) && !m("protocols !~ t", &c));
        assert!(m("protocols in {quic, dns}", &c) && !m("protocols not in {quic, dns}", &c));
        assert!(!m("protocols == tls", &k) && m("protocols != tls", &k), "empty list");
        let l = Rec(vec![("port", List(vec!["53".into(), "x".into()]))], "");
        assert!(m("port > 50", &l) && !m("port > 60", &l) && m("port == 53", &l));
    }

    #[test]
    fn booleans() {
        let (c, k) = (chrome(), code());
        assert!(m("signed", &c) && !m("signed", &k));
        assert!(m("not signed and dir == out", &Rec(vec![("signed", Bool(false)), ("dir", s("out"))], "")));
        assert!(!m("not signed and dir == out", &c));
        for t in ["true", "yes", "1", "TRUE", "on"] {
            assert!(m(&format!("signed == {t}"), &c) && !m(&format!("signed == {t}"), &k));
        }
        for f in ["false", "no", "0", "Off"] {
            assert!(m(&format!("signed == {f}"), &k));
        }
        assert!(m("signed != false", &c) && !m("signed == maybe", &c));
        // a field-named bare word on a non-bool value is a text search
        let r = Rec(vec![("signed", s("x"))], "unsigned binary");
        assert!(m("signed", &r));
        assert!(!m("signed", &Rec(vec![], "nothing")), "missing -> text search");
        // `program` alias resolves, but non-bool -> text search
        assert!(m("program", &Rec(vec![("process", s("a"))], "my program")));
    }

    #[test]
    fn missing_values() {
        let r = Rec(vec![], "");
        for q in ["note == x", "note = *", "note ~ x", "note > 1", "note < 1", "note >= 0", "note <= 0", "note in {x}"] {
            assert!(!m(q, &r), "{q}");
        }
        for q in ["note != x", "note !~ x", "note not in {x}"] {
            assert!(m(q, &r), "{q}");
        }
    }

    #[test]
    fn aliases_and_case() {
        let c = chrome();
        assert!(m("PROC == chrome.exe", &c) && m("Program:CHROME.EXE", &c));
        assert!(m("size > 1mb AND Host ~ GOOGLE Or x", &c));
        assert!(m("CC iN {us}", &c) && m("addr = 140.*", &c));
        let f = Filter::parse("Proc == x", FIELDS).unwrap();
        assert!(format!("{f:?}").contains("\"process\""), "canonical name stored");
    }

    #[test]
    fn quoting_and_escapes() {
        let r = Rec(vec![("name", s("say \"hi\" it's"))], "a \"quoted\" word\tand tab");
        assert!(m(r#"name == "say \"hi\" it's""#, &r));
        assert!(m(r#"name == 'say \"hi\" it\'s'"#, &r));
        assert!(m(r#""\"quoted\"""#, &r));
        assert!(m(r#""word\tand""#, &r));
        assert!(m(r#""a \"quoted\" word""#, &r));
        assert!(m("name ~ 'and'", &Rec(vec![("name", s("band"))], "")), "quoted keyword value");
        assert!(m("'and'", &Rec(vec![], "this and that")), "quoted keyword is text");
        assert!(m("ip == \"2606:4700::1111\"", &code()));
    }

    fn check(q: &str, pos: usize, msg: &str) {
        let er = e(q);
        assert_eq!(er.position, pos, "{q}: {er:?}");
        assert!(er.message.contains(msg), "{q}: {er:?}");
    }

    #[test]
    fn errors() {
        check("name == \"abc", 8, "unterminated string");
        check("x 'abc\\'", 2, "unterminated string");
        check("\"abc\\", 0, "unterminated string");
        check("foo == 1", 0, "unknown field \"foo\"; known: process, pid, bytes");
        check("a and Foo in {x}", 6, "unknown field \"Foo\"");
        check("(a or b", 0, "unclosed `(`");
        check("(a or b c", 0, "unclosed `(`");
        check("a or b)", 6, "unmatched `)`");
        check("()", 1, "expected expression, found `)`");
        check("(a b ,", 5, "expected `)`, found `,`");
        check("bytes >", 7, "missing value after `>`, found end of input");
        check("bytes > )", 8, "missing value after `>`");
        check("ip == ::1", 6, "quote IPv6");
        check("bytes > 1XB", 8, "bad number or unit \"1XB\"");
        check("rtt < fast", 6, "bad number or unit");
        check("a and", 5, "expected expression, found end of input");
        check("or a", 0, "expected expression, found `or`");
        check("== 5", 0, "expected expression, found `==`");
        check("a & b", 2, "unexpected `&`; did you mean `&&`?");
        check("a | b", 2, "unexpected `|`");
        check("a , b", 2, "unexpected `,`");
        check("cc in US", 6, "expected `{` after `in`");
        check("cc in {US", 6, "unclosed `{`");
        check("cc in {US,", 6, "unclosed `{`");
        check("cc in {US DE}", 10, "expected `,` or `}`");
        check("cc in {,}", 7, "expected value or `}`");
        check("cc not in {(}", 11, "expected value or `}`");
        check("Привет == 1", 0, "unknown field \"Привет\"");
        check("Привет и )", 9, "unmatched `)`"); // char offset, not byte
        let deep = "(".repeat(100) + "a" + &")".repeat(100);
        assert!(e(&deep).message.contains("too deeply"));
        assert!(e(&"!".repeat(300)).message.contains("too deeply"));
        let ok = "(".repeat(30) + "a" + &")".repeat(30);
        assert!(Filter::parse(&ok, FIELDS).is_ok());
    }

    #[test]
    fn error_serializes() {
        let er = FilterError { position: 3, message: "x".into() };
        assert_eq!(er.to_string(), "x (at 3)");
    }

    #[test]
    fn no_panics_on_garbage() {
        let complex = r#"(process == "Code.exe" && country != RU) or !(cc not in {US, 'DE',}) app:http bytes>=1.5MB rtt<100ms name ~ goo* ip = "::1" signed || ""#;
        let mut inputs: Vec<String> = Vec::new();
        let chars: Vec<char> = complex.chars().collect();
        for i in 0..=chars.len() {
            inputs.push(chars[..i].iter().collect());
            inputs.push(chars[i..].iter().collect());
        }
        let alphabet: Vec<char> =
            "ab1.*?-_/ :=!<>~&|(){},\"'\\ \t\nMBKmsиБ€😀andornotin".chars().collect();
        let words = ["and", "or", "not", "in", "process", "bytes", "==", "!", "{", "}", "(", ")", "1MB", "\""];
        let mut seed: u64 = 0x2545_F491_4F6C_DD1D;
        let mut rnd = |n: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % n as u64) as usize
        };
        for _ in 0..5000 {
            let len = rnd(24);
            let mut q = String::new();
            for _ in 0..len {
                if rnd(3) == 0 {
                    q.push_str(words[rnd(words.len())]);
                    q.push(' ');
                } else {
                    q.push(alphabet[rnd(alphabet.len())]);
                }
            }
            inputs.push(q);
        }
        let recs = [chrome(), code(), Rec(vec![], "")];
        for q in &inputs {
            match Filter::parse(q, FIELDS) {
                Ok(f) => {
                    for r in &recs {
                        let _ = f.matches(r);
                    }
                }
                Err(er) => assert!(er.position <= q.chars().count(), "{q:?} -> {er:?}"),
            }
        }
        assert!(Filter::parse(complex, FIELDS).is_err(), "trailing `\"` is unterminated");
        let valid = &complex[..complex.len() - 4];
        assert!(Filter::parse(valid, FIELDS).is_ok());
    }

    #[test]
    fn exact_limit_boundaries() {
        let fields: &[(&str, &[&str])] = &[("bytes", &[])];
        // MAX_DEPTH nested parentheses (or negations) parse; one more does not.
        let nested = |n: usize| "(".repeat(n) + "a" + &")".repeat(n);
        assert!(Filter::parse(&nested(MAX_DEPTH), fields).is_ok());
        let e = Filter::parse(&nested(MAX_DEPTH + 1), fields).unwrap_err();
        assert!(e.message.contains("too deeply") && e.position == MAX_DEPTH + 1, "points right after the offending `(`: {e:?}");
        assert!(Filter::parse(&("!".repeat(MAX_DEPTH) + "a"), fields).is_ok());
        assert!(Filter::parse(&("!".repeat(MAX_DEPTH + 1) + "a"), fields).is_err());
        // MAX_INPUT_CHARS is counted in characters, not bytes.
        let cyrillic = "я".repeat(MAX_INPUT_CHARS);
        assert!(Filter::parse(&cyrillic, fields).is_ok(), "{} bytes but {} chars", cyrillic.len(), MAX_INPUT_CHARS);
        let e = Filter::parse(&format!("{cyrillic}я"), fields).unwrap_err();
        assert_eq!((e.position, e.message.contains("too long")), (MAX_INPUT_CHARS, true));
        // MAX_TOKENS: the error points at the first token over the limit.
        let words = (0..MAX_TOKENS).map(|_| "a").collect::<Vec<_>>().join(" ");
        assert!(Filter::parse(&words, fields).is_ok());
        let e = Filter::parse(&format!("{words} b"), fields).unwrap_err();
        assert_eq!((e.position, e.message.contains("too many terms")), (2 * MAX_TOKENS, true));
        // A flat `and` chain just under the token limit evaluates without blowing the stack.
        let r = Rec(vec![("bytes", FieldValue::Num(1.0))], "a");
        let flat = Filter::parse(&(0..100).map(|_| "bytes>0").collect::<Vec<_>>().join(" and "), fields).unwrap();
        assert!(flat.matches(&r));
    }

    #[test]
    fn number_parsing_edges() {
        assert_eq!(parse_number("+5"), Some(5.0));
        assert_eq!(parse_number("5."), Some(5.0));
        assert_eq!(parse_number(".5"), Some(0.5));
        assert_eq!(parse_number("  7 "), Some(7.0), "trimmed");
        assert_eq!(parse_number("1e3"), None, "exponents are not units");
        assert_eq!(parse_number("-"), None);
        assert_eq!(parse_number("."), None);
        assert_eq!(parse_number(""), None);
        assert_eq!(parse_number("1.5.k"), None);
        assert_eq!(parse_number("5-"), None, "sign only at the start");
        assert_eq!(parse_number("0x10"), None);
        assert_eq!(parse_number("1KiB"), Some(1024.0));
        assert_eq!(parse_number("2TB"), Some(2.0 * 1024f64.powi(4)));
        assert_eq!(parse_number("3μs"), Some(0.003), "Greek mu as well as the micro sign");
        assert_eq!(parse_number("3µs"), Some(0.003));
        assert_eq!(parse_number("1 k"), None, "no space before the unit");
        assert_eq!(parse_number("1Mb"), Some(1024.0 * 1024.0), "mixed case is still MiB");
        assert_eq!(parse_number("1mB"), Some(1024.0 * 1024.0));
        assert_eq!(parse_number("1m"), Some(60_000.0), "lone lowercase m is minutes");
        assert_eq!(parse_number("1M"), Some(1024.0 * 1024.0));
        assert_eq!(fmt_num(1e15), "1000000000000000");
        assert_eq!(fmt_num(1e16), "10000000000000000");
        assert_eq!(fmt_num(-0.0), "0");
        assert_eq!(fmt_num(2.5), "2.5");
        assert!(num_eq(1e12, 1e12 + 1e2) && !num_eq(1.0, 1.0001));
        assert!(!glob("ÄÖ", "ä?") && glob("ab", "a*b*") && !glob("ab", "a?b"));
    }

    #[test]
    fn character_level_mutations_of_valid_filters() {
        let valid = [
            "process == chrome.exe and (bytes > 1MB or rtt < 20ms) and not signed",
            "country in {US, DE, \"RU\"} or name ~ 'goo*' || ip = \"2606:4700::*\"",
            "pid >= 4000 pid <= 5000 !(app:http) dir==in note !~ x",
        ];
        let alphabet: Vec<char> = "ab(){}\"'=!<>~:&|, \t*?\\-.0123456789MBkmsяé".chars().collect();
        let mut seed = 0x1234_5678u64;
        let mut rnd = move || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 33) as usize
        };
        let recs = [chrome(), code(), Rec(vec![], "")];
        for _ in 0..3000 {
            let mut chars: Vec<char> = valid[rnd() % valid.len()].chars().collect();
            for _ in 0..1 + rnd() % 3 {
                let i = rnd() % chars.len();
                match rnd() % 3 {
                    0 => chars[i] = alphabet[rnd() % alphabet.len()],
                    1 => {
                        chars.remove(i);
                    }
                    _ => chars.insert(i, alphabet[rnd() % alphabet.len()]),
                }
            }
            let q: String = chars.iter().collect();
            match Filter::parse(&q, FIELDS) {
                Ok(f) => {
                    for r in &recs {
                        let _ = f.matches(r);
                    }
                }
                Err(e) => assert!(e.position <= q.chars().count() && !e.message.is_empty(), "{q:?}: {e:?}"),
            }
        }
    }
}

#[cfg(test)]
mod limit_tests {
    use super::*;

    #[test]
    fn long_and_term_heavy_inputs_are_rejected_not_crashing() {
        let fields: &[(&str, &[&str])] = &[("process", &[])];
        let e = Filter::parse(&"a ".repeat(100_000), fields).unwrap_err();
        assert!(e.message.contains("too long"), "{e:?}");
        let e = Filter::parse(&"a ".repeat(1_000), fields).unwrap_err();
        assert!(e.message.contains("too many terms"), "{e:?}");
        // Just below the limits it still works.
        let ok = Filter::parse("a or ".repeat(100).trim_end_matches(" or "), fields).unwrap();
        assert!(!ok.is_empty());
    }
}
