//! Generates the utility CSS the dashboard uses, so the page needs no Tailwind CDN.
//!
//! The HTML is written with Tailwind class names (`px-4`, `text-slate-500`, `md:grid-cols-3`).
//! Loading the CDN build means ~300 KB of JavaScript that compiles CSS in the browser and
//! does not work offline or behind a strict proxy, which an installed desktop program must
//! tolerate. This module scans the page for class tokens and emits only the rules it uses:
//! a small, deterministic subset of Tailwind v3 (spacing, colors, flex/grid, sizes, text,
//! borders, position, `hover:`/breakpoint variants and `[arbitrary]` values).

use std::fmt::Write;

const BREAKPOINTS: [(&str, u32); 5] = [("sm", 640), ("md", 768), ("lg", 1024), ("xl", 1280), ("2xl", 1536)];

/// Tailwind v3 palette, the shades the dashboard draws from.
const PALETTE: [(&str, [&str; 10]); 10] = [
    ("slate", ["#f8fafc", "#f1f5f9", "#e2e8f0", "#cbd5e1", "#94a3b8", "#64748b", "#475569", "#334155", "#1e293b", "#0f172a"]),
    ("gray", ["#f9fafb", "#f3f4f6", "#e5e7eb", "#d1d5db", "#9ca3af", "#6b7280", "#4b5563", "#374151", "#1f2937", "#111827"]),
    ("red", ["#fef2f2", "#fee2e2", "#fecaca", "#fca5a5", "#f87171", "#ef4444", "#dc2626", "#b91c1c", "#991b1b", "#7f1d1d"]),
    ("amber", ["#fffbeb", "#fef3c7", "#fde68a", "#fcd34d", "#fbbf24", "#f59e0b", "#d97706", "#b45309", "#92400e", "#78350f"]),
    ("emerald", ["#ecfdf5", "#d1fae5", "#a7f3d0", "#6ee7b7", "#34d399", "#10b981", "#059669", "#047857", "#065f46", "#064e3b"]),
    ("sky", ["#f0f9ff", "#e0f2fe", "#bae6fd", "#7dd3fc", "#38bdf8", "#0ea5e9", "#0284c7", "#0369a1", "#075985", "#0c4a6e"]),
    ("blue", ["#eff6ff", "#dbeafe", "#bfdbfe", "#93c5fd", "#60a5fa", "#3b82f6", "#2563eb", "#1d4ed8", "#1e40af", "#1e3a8a"]),
    ("indigo", ["#eef2ff", "#e0e7ff", "#c7d2fe", "#a5b4fc", "#818cf8", "#6366f1", "#4f46e5", "#4338ca", "#3730a3", "#312e81"]),
    ("violet", ["#f5f3ff", "#ede9fe", "#ddd6fe", "#c4b5fd", "#a78bfa", "#8b5cf6", "#7c3aed", "#6d28d9", "#5b21b6", "#4c1d95"]),
    ("orange", ["#fff7ed", "#ffedd5", "#fed7aa", "#fdba74", "#fb923c", "#f97316", "#ea580c", "#c2410c", "#9a3412", "#7c2d12"]),
];
const SHADES: [&str; 10] = ["50", "100", "200", "300", "400", "500", "600", "700", "800", "900"];

/// Tailwind's "preflight": the browser defaults the utilities assume.
const PREFLIGHT: &str = "\
*,::before,::after{box-sizing:border-box;border-width:0;border-style:solid;border-color:#e5e7eb}\
html{line-height:1.5;-webkit-text-size-adjust:100%;tab-size:4}\
body{margin:0;line-height:inherit}\
h1,h2,h3,h4,h5,h6,p,pre,blockquote,figure{margin:0}\
h1,h2,h3,h4,h5,h6{font-size:inherit;font-weight:inherit}\
a{color:inherit;text-decoration:inherit}\
b,strong{font-weight:bolder}\
code,kbd,samp,pre{font-family:ui-monospace,Consolas,Menlo,monospace;font-size:1em}\
small{font-size:80%}\
table{text-indent:0;border-color:inherit;border-collapse:collapse}\
button,input,optgroup,select,textarea{font-family:inherit;font-size:100%;font-weight:inherit;line-height:inherit;color:inherit;margin:0;padding:0}\
button,select{text-transform:none}\
button,[type=button],[type=reset],[type=submit]{-webkit-appearance:button;background-color:transparent;background-image:none}\
input::placeholder,textarea::placeholder{opacity:1;color:#9ca3af}\
summary{display:list-item}\
ol,ul,menu{list-style:none;margin:0;padding:0}\
img,svg,video,canvas,audio,iframe,embed,object{display:block;vertical-align:middle}\
img,video{max-width:100%;height:auto}\
[hidden]{display:none}\n";

/// Complete stylesheet for `html`: preflight plus one rule per utility class found in it.
pub fn generate(html: &str) -> String {
    let mut plain: Vec<(u8, String)> = Vec::new();
    let mut media: Vec<(u32, Vec<(u8, String)>)> = BREAKPOINTS.iter().map(|(_, w)| (*w, Vec::new())).collect();
    let mut seen = std::collections::BTreeSet::new();
    for token in tokens(html) {
        if !seen.insert(token.to_string()) {
            continue;
        }
        let Some(Compiled { rule, min_width, rank }) = compile(token) else { continue };
        match min_width {
            None => plain.push((rank, rule)),
            Some(w) => media.iter_mut().find(|(bp, _)| *bp == w).expect("known breakpoint").1.push((rank, rule)),
        }
    }
    // Shorthands before the longhands that refine them, as Tailwind orders them; the sort is
    // stable, so rules of equal rank keep their first-appearance order.
    let concat = |mut rules: Vec<(u8, String)>| {
        rules.sort_by_key(|(rank, _)| *rank);
        rules.into_iter().map(|(_, r)| r).collect::<String>()
    };
    let mut out = String::from(PREFLIGHT);
    out.push_str(&concat(plain));
    for (w, rules) in media {
        if !rules.is_empty() {
            let _ = write!(out, "@media (min-width:{w}px){{{}}}", concat(rules));
        }
    }
    out
}

/// Tokens in `html` that look like utility classes but this generator cannot compile:
/// either a typo in the page or a utility to add here. Empty for a healthy page.
///
/// Two scans: every token of the page that has the shape of a utility (`utility_like`, which
/// catches class names in JavaScript constants too), and, stricter, every token written in a
/// `class="…"` attribute, which is a class by construction and so must either compile or be
/// one the page defines itself (its `<style>` block, `classList` calls).
#[cfg(test)]
pub fn unknown_utilities(html: &str) -> Vec<String> {
    let defined = page_classes(html);
    let mut out: Vec<String> = tokens(html).filter(|t| utility_like(t) && compile(t).is_none()).map(str::to_string).collect();
    out.extend(class_attribute_tokens(html).into_iter().filter(|t| !defined.contains(t) && compile(t).is_none()).map(str::to_string));
    out.sort();
    out.dedup();
    out
}

struct Compiled {
    rule: String,
    min_width: Option<u32>,
    /// Emission order within a block: shorthands (0, 1) before the longhands overriding them.
    rank: u8,
}

/// Tailwind emits a shorthand before the longhands that refine it (`p-4` before `px-2` before
/// `pt-1`; `rounded` before `rounded-t-lg`; `border` before `border-b`; `text-sm` before
/// `leading-5`; `inset-0` before `top-2`), so a class list may rely on the longhand winning.
/// Utilities outside these groups rank 0.
fn rank(base: &str) -> u8 {
    let mut segments = base.split('-');
    let (first, second) = (segments.next().unwrap_or(base), segments.next());
    match first {
        "p" | "m" | "inset" => 1,
        "px" | "py" | "mx" | "my" => 2,
        "pt" | "pr" | "pb" | "pl" | "mt" | "mr" | "mb" | "ml" | "top" | "right" | "bottom" | "left" => 3,
        "rounded" if matches!(second, Some("t" | "b" | "l" | "r")) => 2,
        "rounded" => 1,
        "border" if matches!(second, Some("t" | "r" | "b" | "l" | "x" | "y")) => 2,
        "border" => 1,
        "text" if matches!(base, "text-xs" | "text-sm" | "text-base" | "text-lg" | "text-xl" | "text-2xl") => 1,
        "text" if base.starts_with("text-[") && !base.starts_with("text-[#") && !base.starts_with("text-[rgb") => 1,
        "leading" => 2,
        _ => 0,
    }
}

/// Splits the page into candidate class tokens: runs of the characters a Tailwind class
/// may contain. Words of prose come out too; `compile` simply ignores them.
fn tokens(html: &str) -> impl Iterator<Item = &str> {
    html.split(|c: char| !(c.is_ascii_alphanumeric() || "-:/.[]#%()_".contains(c))).filter(|t| !t.is_empty())
}

/// Whether a token has the shape of a utility class, so a compile failure means a typo:
/// a known prefix with a value that looks like a size, a palette color or `[arbitrary]`.
/// Words such as `self-signed`, `grid-table` or the SVG attribute `stroke-width` are not.
#[cfg(test)]
fn utility_like(token: &str) -> bool {
    let Some((variants, base)) = split_variants(token) else { return false };
    if !variants.iter().all(|v| STATES.contains(v) || BREAKPOINTS.iter().any(|(b, _)| b == v)) {
        return false;
    }
    if base.is_empty() || !base.starts_with(|c: char| c.is_ascii_lowercase()) || base.ends_with(['-', '.', '/']) {
        return false;
    }
    let Some((prefix, value)) = base.split_once('-') else { return false };
    let (prefix, value) = match prefix {
        "max" | "min" | "grid" | "space" | "col" => match value.split_once('-') {
            Some((p2, v)) => (format!("{prefix}-{p2}"), v),
            None => return false,
        },
        _ => (prefix.to_string(), value),
    };
    const PREFIXES: &[&str] = &[
        "text", "bg", "border", "divide", "w", "h", "p", "px", "py", "pt", "pr", "pb", "pl", "m", "mx", "my", "mt", "mr", "mb", "ml", "gap", "gap-x",
        "gap-y", "space-x", "space-y", "max-w", "max-h", "min-w", "min-h", "grid-cols", "col-span", "z", "top", "left", "right", "bottom", "inset",
        "leading", "opacity", "fill", "stroke",
    ];
    if !PREFIXES.contains(&prefix.as_str()) {
        return false;
    }
    // SVG path data like `h-8z` or `m-2a4` is not a class.
    if prefix.len() == 1 && value.chars().next().is_some_and(|c| c.is_ascii_digit()) && value.contains(|c: char| c.is_ascii_alphabetic()) {
        return false;
    }
    let numeric = value.starts_with(|c: char| c.is_ascii_digit()) && value.chars().all(|c| c.is_ascii_digit() || c == '.' || c == '/');
    // A known family with any shade (`slate-950`), or any family with a known shade
    // (`green-600`, `yellow-50`): both are color typos, not prose.
    let palette = value.split('/').next().and_then(|v| v.rsplit_once('-')).is_some_and(|(family, shade)| {
        let word = !family.is_empty() && family.chars().all(|c| c.is_ascii_lowercase());
        PALETTE.iter().any(|(f, _)| *f == family) || (word && SHADES.contains(&shade))
    });
    numeric || palette || value.starts_with('[') || matches!(value, "auto" | "full" | "screen" | "px" | "white" | "black" | "transparent")
}

/// Class names written inside `class="…"` attributes of the markup and of the JavaScript
/// template literals that render it. `${…}` interpolations are skipped, and a name glued to
/// one (`lyr${i}`, `${tone}-500`) is dropped as a fragment. Everything left is meant as a
/// class, so a token that neither compiles nor is defined by the page is a typo.
#[cfg(test)]
fn class_attribute_tokens(html: &str) -> Vec<&str> {
    let b = html.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(off) = html[i..].find("class=") {
        let start = i + off;
        i = start + "class=".len();
        let word_before = start > 0 && (b[start - 1].is_ascii_alphanumeric() || b[start - 1] == b'_' || b[start - 1] == b'-');
        let Some(&quote) = b.get(i) else { break };
        if word_before || (quote != b'"' && quote != b'\'') {
            continue;
        }
        i += 1;
        let (mut token_start, mut fragment) = (i, false);
        loop {
            let Some(&c) = b.get(i) else { return out };
            if c == quote || c.is_ascii_whitespace() {
                if !fragment && token_start < i {
                    out.push(&html[token_start..i]);
                }
                i += 1;
                if c == quote {
                    break;
                }
                (token_start, fragment) = (i, false);
            } else if c == b'$' && b.get(i + 1) == Some(&b'{') {
                fragment = true;
                i = skip_interpolation(b, i + 2);
            } else {
                i += 1;
            }
        }
    }
    out
}

/// Index just past the `}` closing a template-literal interpolation whose body starts at
/// `i`. Braces nest, and string literals inside may hold braces and quotes of their own.
#[cfg(test)]
fn skip_interpolation(b: &[u8], mut i: usize) -> usize {
    let mut depth = 1;
    while let Some(&c) = b.get(i) {
        i += 1;
        match c {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return i;
                }
            }
            b'"' | b'\'' | b'`' => {
                while let Some(&s) = b.get(i) {
                    i += 1;
                    if s == b'\\' {
                        i += 1;
                    } else if s == c {
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    i
}

/// Classes the page defines itself: `.name` selectors in its `<style>` blocks and the names
/// its JavaScript sets through `classList.add/remove/toggle/contains("name")`.
#[cfg(test)]
fn page_classes(html: &str) -> std::collections::HashSet<&str> {
    let ident = |s: &str| s.find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_')).unwrap_or(s.len());
    let mut out = std::collections::HashSet::new();
    let mut rest = html;
    while let Some(open) = rest.find("<style") {
        let Some(body_start) = rest[open..].find('>').map(|p| open + p + 1) else { break };
        let body_end = rest[body_start..].find("</style>").map_or(rest.len(), |p| body_start + p);
        let css = &rest[body_start..body_end];
        for (dot, _) in css.match_indices('.') {
            let name = &css[dot + 1..];
            if name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_' || c == '-') {
                out.insert(&name[..ident(name)]);
            }
        }
        rest = &rest[body_end..];
    }
    for (pos, _) in html.match_indices("classList.") {
        let call = &html[pos + "classList.".len()..];
        let Some(paren) = call.find('(') else { continue };
        if !matches!(&call[..paren], "add" | "remove" | "toggle" | "contains") {
            continue;
        }
        let args = call[paren + 1..].trim_start();
        if let Some(name) = args.strip_prefix('"').or_else(|| args.strip_prefix('\'')) {
            out.insert(&name[..ident(name)]);
        }
    }
    out
}

fn split_variants(token: &str) -> Option<(Vec<&str>, &str)> {
    let mut parts: Vec<&str> = token.split(':').collect();
    let base = parts.pop()?;
    if base.is_empty() || parts.iter().any(|p| p.is_empty()) {
        return None;
    }
    Some((parts, base))
}

/// CSS escape of a class name used as a selector: `.md\:w-1\/3`. An identifier cannot start
/// with a digit, so a leading one becomes a hex escape: `2xl:flex` → `\32 xl\:flex`.
fn escape(class: &str) -> String {
    let mut s = String::with_capacity(class.len() + 4);
    for (i, c) in class.chars().enumerate() {
        if i == 0 && c.is_ascii_digit() {
            let _ = write!(s, "\\{:x} ", c as u32);
        } else if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
            s.push(c);
        } else {
            s.push('\\');
            s.push(c);
        }
    }
    s
}

/// State variants: `hover:bg-slate-50` → `.hover\:bg-slate-50:hover`.
const STATES: [&str; 4] = ["hover", "focus", "active", "disabled"];

/// One utility class → its CSS rule (with variants applied), or `None` if unknown.
fn compile(token: &str) -> Option<Compiled> {
    let (variants, base) = split_variants(token)?;
    let mut min_width = None;
    let mut pseudo = String::new();
    for v in variants {
        if STATES.contains(&v) {
            pseudo.push(':');
            pseudo.push_str(v);
        } else {
            let w = BREAKPOINTS.iter().find(|(b, _)| *b == v)?.1;
            min_width = Some(min_width.map_or(w, |m: u32| m.max(w)));
        }
    }
    let selector = format!(".{}{}", escape(token), pseudo);
    let (tail, body) = declarations(base)?;
    Some(Compiled { rule: format!("{selector}{tail}{{{body}}}"), min_width, rank: rank(base) })
}

/// Declarations for a bare utility. The first element is a selector suffix (used by the
/// `space-*`/`divide-*` child combinators), empty for ordinary utilities.
fn declarations(base: &str) -> Option<(&'static str, String)> {
    const CHILDREN: &str = ">:not([hidden])~:not([hidden])";
    let plain = |s: &str| Some(("", s.to_string()));
    let fixed = match base {
        "flex" => "display:flex",
        "inline-flex" => "display:inline-flex",
        "grid" => "display:grid",
        "block" => "display:block",
        "inline-block" => "display:inline-block",
        "inline" => "display:inline",
        "hidden" => "display:none",
        "relative" => "position:relative",
        "absolute" => "position:absolute",
        "sticky" => "position:sticky",
        "fixed" => "position:fixed",
        "truncate" => "overflow:hidden;text-overflow:ellipsis;white-space:nowrap",
        "uppercase" => "text-transform:uppercase",
        "lowercase" => "text-transform:lowercase",
        "capitalize" => "text-transform:capitalize",
        "italic" => "font-style:italic",
        "underline" => "text-decoration-line:underline",
        "antialiased" => "-webkit-font-smoothing:antialiased",
        "invisible" => "visibility:hidden",
        "visible" => "visibility:visible",
        "flex-wrap" => "flex-wrap:wrap",
        "flex-nowrap" => "flex-wrap:nowrap",
        "flex-col" => "flex-direction:column",
        "flex-row" => "flex-direction:row",
        "flex-1" => "flex:1 1 0%",
        "flex-auto" => "flex:1 1 auto",
        "flex-none" => "flex:none",
        "shrink-0" => "flex-shrink:0",
        "shrink" => "flex-shrink:1",
        "grow" => "flex-grow:1",
        "grow-0" => "flex-grow:0",
        "items-center" => "align-items:center",
        "items-start" => "align-items:flex-start",
        "items-end" => "align-items:flex-end",
        "items-stretch" => "align-items:stretch",
        "items-baseline" => "align-items:baseline",
        "justify-center" => "justify-content:center",
        "justify-between" => "justify-content:space-between",
        "justify-end" => "justify-content:flex-end",
        "justify-start" => "justify-content:flex-start",
        "self-center" => "align-self:center",
        "self-start" => "align-self:flex-start",
        "self-end" => "align-self:flex-end",
        "self-stretch" => "align-self:stretch",
        "overflow-hidden" => "overflow:hidden",
        "overflow-auto" => "overflow:auto",
        "overflow-x-auto" => "overflow-x:auto",
        "overflow-y-auto" => "overflow-y:auto",
        "overflow-visible" => "overflow:visible",
        "whitespace-nowrap" => "white-space:nowrap",
        "whitespace-pre" => "white-space:pre",
        "whitespace-pre-wrap" => "white-space:pre-wrap",
        "whitespace-normal" => "white-space:normal",
        "break-words" => "overflow-wrap:break-word",
        "break-all" => "word-break:break-all",
        "cursor-pointer" => "cursor:pointer",
        "cursor-default" => "cursor:default",
        "cursor-wait" => "cursor:wait",
        "cursor-move" => "cursor:move",
        "cursor-grab" => "cursor:grab",
        "cursor-grabbing" => "cursor:grabbing",
        "cursor-crosshair" => "cursor:crosshair",
        "select-none" => "user-select:none",
        "select-text" => "user-select:text",
        "pointer-events-none" => "pointer-events:none",
        "pointer-events-auto" => "pointer-events:auto",
        "text-center" => "text-align:center",
        "text-left" => "text-align:left",
        "text-right" => "text-align:right",
        "font-sans" => "font-family:\"Segoe UI\",ui-sans-serif,system-ui,-apple-system,Roboto,sans-serif",
        "font-mono" => "font-family:ui-monospace,Consolas,Menlo,monospace",
        "font-normal" => "font-weight:400",
        "font-medium" => "font-weight:500",
        "font-semibold" => "font-weight:600",
        "font-bold" => "font-weight:700",
        "tracking-tight" => "letter-spacing:-.025em",
        "tracking-wide" => "letter-spacing:.025em",
        "tracking-wider" => "letter-spacing:.05em",
        "rounded" => "border-radius:.25rem",
        "rounded-sm" => "border-radius:.125rem",
        "rounded-md" => "border-radius:.375rem",
        "rounded-lg" => "border-radius:.5rem",
        "rounded-xl" => "border-radius:.75rem",
        "rounded-full" => "border-radius:9999px",
        "rounded-none" => "border-radius:0",
        "border" => "border-width:1px",
        "border-0" => "border-width:0",
        "border-t" => "border-top-width:1px",
        "border-r" => "border-right-width:1px",
        "border-b" => "border-bottom-width:1px",
        "border-l" => "border-left-width:1px",
        "border-transparent" => "border-color:transparent",
        "divide-y" => return Some((CHILDREN, "border-top-width:1px;border-bottom-width:0".into())),
        "divide-x" => return Some((CHILDREN, "border-right-width:0;border-left-width:1px".into())),
        "w-full" => "width:100%",
        "w-screen" => "width:100vw",
        "w-auto" => "width:auto",
        "h-full" => "height:100%",
        "h-screen" => "height:100vh",
        "h-auto" => "height:auto",
        "min-w-0" => "min-width:0",
        "min-w-full" => "min-width:100%",
        "min-h-0" => "min-height:0",
        "min-h-screen" => "min-height:100vh",
        "min-h-full" => "min-height:100%",
        "max-w-full" => "max-width:100%",
        "max-w-none" => "max-width:none",
        "max-h-full" => "max-height:100%",
        "inset-0" => "inset:0",
        "text-white" => "color:#fff",
        "text-black" => "color:#000",
        "text-transparent" => "color:transparent",
        "bg-white" => "background-color:#fff",
        "bg-black" => "background-color:#000",
        "bg-transparent" => "background-color:transparent",
        "text-xs" => "font-size:.75rem;line-height:1rem",
        "text-sm" => "font-size:.875rem;line-height:1.25rem",
        "text-base" => "font-size:1rem;line-height:1.5rem",
        "text-lg" => "font-size:1.125rem;line-height:1.75rem",
        "text-xl" => "font-size:1.25rem;line-height:1.75rem",
        "text-2xl" => "font-size:1.5rem;line-height:2rem",
        "shadow" => "box-shadow:0 1px 3px 0 rgb(0 0 0/.1),0 1px 2px -1px rgb(0 0 0/.1)",
        "shadow-sm" => "box-shadow:0 1px 2px 0 rgb(0 0 0/.05)",
        "shadow-md" => "box-shadow:0 4px 6px -1px rgb(0 0 0/.1),0 2px 4px -2px rgb(0 0 0/.1)",
        "shadow-lg" => "box-shadow:0 10px 15px -3px rgb(0 0 0/.1),0 4px 6px -4px rgb(0 0 0/.1)",
        "shadow-none" => "box-shadow:none",
        "transition" => "transition-property:color,background-color,border-color,opacity,box-shadow,transform;transition-duration:.15s;transition-timing-function:cubic-bezier(.4,0,.2,1)",
        "outline-none" => "outline:2px solid transparent;outline-offset:2px",
        "order-first" => "order:-9999",
        "order-last" => "order:9999",
        "order-none" => "order:0",
        _ => "",
    };
    if !fixed.is_empty() {
        return plain(fixed);
    }

    let (prefix, value) = base.split_once('-')?;
    // Prefixes with a second word: `max-w-…`, `min-h-…`, `grid-cols-…`, `space-y-…`, `gap-x-…`.
    let (prefix, value) = match prefix {
        "max" | "min" | "grid" | "space" | "col" => {
            let (p2, v) = value.split_once('-')?;
            (format!("{prefix}-{p2}"), v)
        }
        "gap" if value.starts_with("x-") || value.starts_with("y-") => (format!("gap-{}", &value[..1]), &value[2..]),
        _ => (prefix.to_string(), value),
    };
    let body = match prefix.as_str() {
        "p" => format!("padding:{}", length(value)?),
        "px" => format!("padding-left:{0};padding-right:{0}", length(value)?),
        "py" => format!("padding-top:{0};padding-bottom:{0}", length(value)?),
        "pt" => format!("padding-top:{}", length(value)?),
        "pr" => format!("padding-right:{}", length(value)?),
        "pb" => format!("padding-bottom:{}", length(value)?),
        "pl" => format!("padding-left:{}", length(value)?),
        "m" => format!("margin:{}", margin(value)?),
        "mx" => format!("margin-left:{0};margin-right:{0}", margin(value)?),
        "my" => format!("margin-top:{0};margin-bottom:{0}", margin(value)?),
        "mt" => format!("margin-top:{}", margin(value)?),
        "mr" => format!("margin-right:{}", margin(value)?),
        "mb" => format!("margin-bottom:{}", margin(value)?),
        "ml" => format!("margin-left:{}", margin(value)?),
        "gap" => format!("gap:{}", length(value)?),
        "gap-x" => format!("column-gap:{}", length(value)?),
        "gap-y" => format!("row-gap:{}", length(value)?),
        "space-y" => return Some((CHILDREN, format!("margin-top:{}", length(value)?))),
        "space-x" => return Some((CHILDREN, format!("margin-left:{}", length(value)?))),
        "w" => format!("width:{}", size(Axis::X, value)?),
        "h" => format!("height:{}", size(Axis::Y, value)?),
        "min-w" => format!("min-width:{}", size(Axis::X, value)?),
        "min-h" => format!("min-height:{}", size(Axis::Y, value)?),
        "max-w" => format!("max-width:{}", size(Axis::X, value)?),
        "max-h" => format!("max-height:{}", size(Axis::Y, value)?),
        "top" => format!("top:{}", margin(value)?),
        "right" => format!("right:{}", margin(value)?),
        "bottom" => format!("bottom:{}", margin(value)?),
        "left" => format!("left:{}", margin(value)?),
        "inset" => format!("inset:{}", margin(value)?),
        "z" => format!("z-index:{}", arbitrary(value).or_else(|| value.parse::<u32>().ok().map(|z| z.to_string()))?),
        "opacity" => format!("opacity:{}", value.parse::<u32>().ok().filter(|v| *v <= 100).map(|v| trim_float(v as f64 / 100.0))?),
        "leading" => format!("line-height:{}", match value {
            "none" => "1".to_string(),
            "tight" => "1.25".to_string(),
            "snug" => "1.375".to_string(),
            "normal" => "1.5".to_string(),
            "relaxed" => "1.625".to_string(),
            _ => length(value)?,
        }),
        "grid-cols" => format!(
            "grid-template-columns:{}",
            arbitrary(value).or_else(|| value.parse::<u32>().ok().map(|n| format!("repeat({n},minmax(0,1fr))")))?
        ),
        "col-span" => format!("grid-column:span {0}/span {0}", value.parse::<u32>().ok()?),
        "order" => format!("order:{}", value.parse::<i32>().ok()?),
        "text" => match arbitrary(value) {
            Some(v) if v.starts_with('#') || v.starts_with("rgb") => format!("color:{v}"),
            Some(v) => format!("font-size:{v}"),
            None => format!("color:{}", color(value)?),
        },
        "bg" => format!("background-color:{}", arbitrary(value).or_else(|| color(value))?),
        "border" => {
            if let Some(v) = arbitrary(value) {
                format!("border-color:{v}")
            } else if let Some(c) = color(value) {
                format!("border-color:{c}")
            } else {
                let (side, width) = match value.split_once('-') {
                    Some((s, w)) => (s, w),
                    None => ("", value),
                };
                let width = width.parse::<u32>().ok()?;
                match side {
                    "" => format!("border-width:{width}px"),
                    "t" => format!("border-top-width:{width}px"),
                    "r" => format!("border-right-width:{width}px"),
                    "b" => format!("border-bottom-width:{width}px"),
                    "l" => format!("border-left-width:{width}px"),
                    "x" => format!("border-left-width:{width}px;border-right-width:{width}px"),
                    "y" => format!("border-top-width:{width}px;border-bottom-width:{width}px"),
                    _ => return None,
                }
            }
        }
        "divide" => return Some((CHILDREN, format!("border-color:{}", arbitrary(value).or_else(|| color(value))?))),
        "fill" => format!("fill:{}", arbitrary(value).or_else(|| color(value))?),
        "stroke" => format!("stroke:{}", arbitrary(value).or_else(|| color(value))?),
        "rounded" => {
            let (side, radius) = value.split_once('-')?;
            let r = match radius {
                "sm" => ".125rem",
                "md" => ".375rem",
                "lg" => ".5rem",
                "full" => "9999px",
                _ => return None,
            };
            match side {
                "t" => format!("border-top-left-radius:{r};border-top-right-radius:{r}"),
                "b" => format!("border-bottom-left-radius:{r};border-bottom-right-radius:{r}"),
                "l" => format!("border-top-left-radius:{r};border-bottom-left-radius:{r}"),
                "r" => format!("border-top-right-radius:{r};border-bottom-right-radius:{r}"),
                _ => return None,
            }
        }
        _ => return None,
    };
    plain(&body)
}

/// `[…]` arbitrary value, with Tailwind's conventions: `_` is a space and `calc()` gets
/// the spaces CSS needs around its operators (`calc(100vh-45px)` → `calc(100vh - 45px)`).
fn arbitrary(value: &str) -> Option<String> {
    let inner = value.strip_prefix('[')?.strip_suffix(']')?;
    if inner.is_empty() || inner.contains(['[', ']', ';', '{', '}']) {
        return None;
    }
    let inner = inner.replace('_', " ");
    if !inner.contains("calc(") {
        return Some(inner);
    }
    let chars: Vec<char> = inner.chars().collect();
    let mut out = String::new();
    for (i, &c) in chars.iter().enumerate() {
        let operand_before = i > 0 && (chars[i - 1].is_ascii_alphanumeric() || chars[i - 1] == ')' || chars[i - 1] == '%');
        let operand_after = chars.get(i + 1).is_some_and(|n| n.is_ascii_digit() || *n == '(' || *n == '.');
        if matches!(c, '+' | '-' | '*' | '/') && operand_before && operand_after {
            out.push(' ');
            out.push(c);
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    Some(out)
}

/// Spacing scale: `4` → `1rem`, `1.5` → `.375rem`, `px` → `1px`, `[…]` raw.
fn length(value: &str) -> Option<String> {
    if let Some(v) = arbitrary(value) {
        return Some(v);
    }
    match value {
        "0" => Some("0".into()),
        "px" => Some("1px".into()),
        "full" => Some("100%".into()),
        _ => {
            let n: f64 = value.parse().ok()?;
            ((0.0..=96.0).contains(&n) && (n * 4.0).fract() == 0.0).then(|| format!("{}rem", trim_float(n / 4.0)))
        }
    }
}

fn margin(value: &str) -> Option<String> {
    match value {
        "auto" => Some("auto".into()),
        _ => length(value),
    }
}

/// The axis a size applies to: `screen` is the viewport width for `w-*`, its height for `h-*`.
#[derive(Clone, Copy)]
enum Axis {
    X,
    Y,
}

/// Width/height values: the spacing scale plus fractions (`1/3`), `full`, `screen`.
fn size(axis: Axis, value: &str) -> Option<String> {
    if let Some(v) = arbitrary(value) {
        return Some(v); // before the fraction check: `[calc(100%/3)]` is not a fraction
    }
    match value {
        "full" => Some("100%".into()),
        "screen" => Some(match axis {
            Axis::X => "100vw".into(),
            Axis::Y => "100vh".into(),
        }),
        "min" => Some("min-content".into()),
        "max" => Some("max-content".into()),
        "fit" => Some("fit-content".into()),
        "xs" => Some("20rem".into()),
        "sm" => Some("24rem".into()),
        "md" => Some("28rem".into()),
        "lg" => Some("32rem".into()),
        "xl" => Some("36rem".into()),
        _ => {
            if let Some((a, b)) = value.split_once('/') {
                let (a, b): (f64, f64) = (a.parse().ok()?, b.parse().ok()?);
                return (b > 0.0 && a <= b).then(|| format!("{}%", trim_float((a / b * 1_000_000.0).round() / 10_000.0)));
            }
            length(value)
        }
    }
}

/// `slate-500` → `#64748b`; `amber-50/60` → `rgb(255 251 235/.6)`.
fn color(value: &str) -> Option<String> {
    let (name, alpha) = match value.split_once('/') {
        Some((v, a)) => (v, Some(a.parse::<u32>().ok().filter(|a| *a <= 100)?)),
        None => (value, None),
    };
    let hex = match name {
        "white" => "#ffffff",
        "black" => "#000000",
        "transparent" => return alpha.is_none().then(|| "transparent".to_string()),
        _ => {
            let (family, shade) = name.rsplit_once('-')?;
            let shades = PALETTE.iter().find(|(f, _)| *f == family)?.1;
            let i = SHADES.iter().position(|s| *s == shade)?;
            shades[i]
        }
    };
    Some(match alpha {
        None => hex.to_string(),
        Some(a) => {
            let v = u32::from_str_radix(&hex[1..], 16).ok()?;
            format!("rgb({} {} {}/{})", v >> 16, (v >> 8) & 0xff, v & 0xff, trim_float(a as f64 / 100.0))
        }
    })
}

/// `0.375` → `.375`, `1` → `1`, `1.5` → `1.5`.
fn trim_float(v: f64) -> String {
    let s = format!("{v}");
    let s = if s.contains('.') { s.trim_end_matches('0').trim_end_matches('.').to_string() } else { s };
    match s.strip_prefix("0.") {
        Some(rest) => format!(".{rest}"),
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(c: &str) -> String {
        compile(c).unwrap_or_else(|| panic!("{c} did not compile")).rule
    }

    #[test]
    fn spacing_sizes_and_colors() {
        assert_eq!(rule("px-4"), ".px-4{padding-left:1rem;padding-right:1rem}");
        assert_eq!(rule("py-1.5"), ".py-1\\.5{padding-top:.375rem;padding-bottom:.375rem}");
        assert_eq!(rule("mt-0.5"), ".mt-0\\.5{margin-top:.125rem}");
        assert_eq!(rule("ml-auto"), ".ml-auto{margin-left:auto}");
        assert_eq!(rule("gap-1.5"), ".gap-1\\.5{gap:.375rem}");
        assert_eq!(rule("w-1/3"), ".w-1\\/3{width:33.3333%}");
        assert_eq!(rule("w-52"), ".w-52{width:13rem}");
        assert_eq!(rule("max-h-96"), ".max-h-96{max-height:24rem}");
        assert_eq!(rule("max-w-[220px]"), ".max-w-\\[220px\\]{max-width:220px}");
        assert_eq!(rule("h-[calc(100vh-45px)]"), ".h-\\[calc\\(100vh-45px\\)\\]{height:calc(100vh - 45px)}");
        assert_eq!(rule("text-slate-500"), ".text-slate-500{color:#64748b}");
        assert_eq!(rule("text-[12px]"), ".text-\\[12px\\]{font-size:12px}");
        assert_eq!(rule("bg-amber-50/60"), ".bg-amber-50\\/60{background-color:rgb(255 251 235/.6)}");
        assert_eq!(rule("bg-[#fbfbfc]"), ".bg-\\[\\#fbfbfc\\]{background-color:#fbfbfc}");
        assert_eq!(rule("border-l-4"), ".border-l-4{border-left-width:4px}");
        assert_eq!(rule("border-[#e3e6eb]"), ".border-\\[\\#e3e6eb\\]{border-color:#e3e6eb}");
        assert_eq!(rule("divide-[#eef0f3]"), ".divide-\\[\\#eef0f3\\]>:not([hidden])~:not([hidden]){border-color:#eef0f3}");
        assert_eq!(rule("space-y-0.5"), ".space-y-0\\.5>:not([hidden])~:not([hidden]){margin-top:.125rem}");
        assert_eq!(rule("z-[1]"), ".z-\\[1\\]{z-index:1}");
        assert_eq!(rule("opacity-70"), ".opacity-70{opacity:.7}");
        assert_eq!(rule("grid-cols-2"), ".grid-cols-2{grid-template-columns:repeat(2,minmax(0,1fr))}");
    }

    #[test]
    fn variants() {
        let c = compile("md:grid-cols-3").unwrap();
        assert_eq!((c.rule.as_str(), c.min_width), (".md\\:grid-cols-3{grid-template-columns:repeat(3,minmax(0,1fr))}", Some(768)));
        assert_eq!(rule("hover:bg-slate-50"), ".hover\\:bg-slate-50:hover{background-color:#f8fafc}");
        assert_eq!(compile("xl:hidden").unwrap().min_width, Some(1280));
    }

    #[test]
    fn rejects_garbage_but_knows_what_a_utility_looks_like() {
        for bad in ["h-8z", "m-2a4", "font-size:12px", "border-bottom:", "ui.connError", "px-", "text-slate-950", "w-1/0", "bg-[]"] {
            assert!(compile(bad).is_none(), "{bad} compiled");
        }
        assert!(utility_like("text-slate-950"), "a typo in a real utility must be reported");
        assert!(utility_like("px-7"));
        for not in ["h-8z", "m-2a4", "font-size:12px", "border-bottom:", "ui.connError", "px-", "hosts", "panel-h", "stroke-width", "fill-opacity", "self-signed", "grid-table", "font-size"] {
            assert!(!utility_like(not), "{not} looks like a utility");
        }
    }

    #[test]
    fn generates_grouped_media_queries() {
        let css = generate(r#"<div class="flex md:block xl:grid-cols-2 hover:bg-slate-50 flex">"#);
        assert!(css.starts_with(PREFLIGHT));
        assert_eq!(css.matches(".flex{").count(), 1, "deduplicated");
        assert!(css.contains("@media (min-width:768px){.md\\:block{display:block}}"));
        assert!(css.contains("@media (min-width:1280px){.xl\\:grid-cols-2{"));
        assert!(css.find("@media (min-width:768px)").unwrap() < css.find("@media (min-width:1280px)").unwrap());
    }

    /// The declarations of a utility, without selector and braces.
    fn body(c: &str) -> String {
        let r = rule(c);
        let open = r.find('{').unwrap();
        r[open + 1..r.len() - 1].to_string()
    }

    #[test]
    fn spacing_scale_matches_tailwind() {
        let scale = [
            ("0", "0"), ("px", "1px"), ("0.5", ".125rem"), ("1", ".25rem"), ("1.5", ".375rem"), ("2", ".5rem"), ("2.5", ".625rem"),
            ("3", ".75rem"), ("3.5", ".875rem"), ("4", "1rem"), ("5", "1.25rem"), ("6", "1.5rem"), ("7", "1.75rem"), ("8", "2rem"),
            ("9", "2.25rem"), ("10", "2.5rem"), ("11", "2.75rem"), ("12", "3rem"), ("14", "3.5rem"), ("16", "4rem"), ("20", "5rem"),
            ("24", "6rem"), ("28", "7rem"), ("32", "8rem"), ("36", "9rem"), ("40", "10rem"), ("44", "11rem"), ("48", "12rem"),
            ("52", "13rem"), ("56", "14rem"), ("60", "15rem"), ("64", "16rem"), ("72", "18rem"), ("80", "20rem"), ("96", "24rem"),
        ];
        for (v, css) in scale {
            assert_eq!(body(&format!("p-{v}")), format!("padding:{css}"));
            assert_eq!(body(&format!("m-{v}")), format!("margin:{css}"));
            assert_eq!(body(&format!("gap-{v}")), format!("gap:{css}"));
            assert_eq!(body(&format!("w-{v}")), format!("width:{css}"));
            assert_eq!(body(&format!("h-{v}")), format!("height:{css}"));
            assert_eq!(body(&format!("top-{v}")), format!("top:{css}"));
            assert_eq!(body(&format!("inset-{v}")), format!("inset:{css}"));
            assert_eq!(body(&format!("leading-{v}")), format!("line-height:{css}"));
            assert_eq!(rule(&format!("space-x-{v}")), format!(".{}>:not([hidden])~:not([hidden]){{margin-left:{css}}}", escape(&format!("space-x-{v}"))));
        }
        let sides = [
            ("pt", "padding-top"), ("pr", "padding-right"), ("pb", "padding-bottom"), ("pl", "padding-left"),
            ("mt", "margin-top"), ("mr", "margin-right"), ("mb", "margin-bottom"), ("ml", "margin-left"),
            ("gap-x", "column-gap"), ("gap-y", "row-gap"), ("right", "right"), ("bottom", "bottom"), ("left", "left"),
            ("min-w", "min-width"), ("min-h", "min-height"), ("max-w", "max-width"), ("max-h", "max-height"),
        ];
        for (prefix, prop) in sides {
            assert_eq!(body(&format!("{prefix}-3")), format!("{prop}:.75rem"), "{prefix}");
        }
        assert_eq!(body("px-2"), "padding-left:.5rem;padding-right:.5rem");
        assert_eq!(body("py-2"), "padding-top:.5rem;padding-bottom:.5rem");
        assert_eq!(body("mx-auto"), "margin-left:auto;margin-right:auto");
        assert_eq!(body("my-auto"), "margin-top:auto;margin-bottom:auto");
        for m in ["mt", "mb", "ml", "mr", "m", "top", "left", "inset"] {
            assert_eq!(body(&format!("{m}-auto")).split(':').next_back(), Some("auto"), "{m}-auto");
        }
        assert_eq!(body("w-px"), "width:1px");
        for bad in ["p-7.3", "p-100", "p-1/2", "gap-auto", "p-auto", "w--1", "p-", "p-4px", "p-NaN", "p-inf", "pt", "gap", "m", "pxx-4", "p-4-4"] {
            assert!(compile(bad).is_none(), "{bad} compiled to {:?}", compile(bad).map(|c| c.rule));
        }
    }

    #[test]
    fn fractions_and_named_sizes_match_tailwind() {
        let fractions = [
            ("1/2", 50.0), ("1/3", 33.333333), ("2/3", 66.666667), ("1/4", 25.0), ("2/4", 50.0), ("3/4", 75.0), ("1/5", 20.0), ("2/5", 40.0),
            ("3/5", 60.0), ("4/5", 80.0), ("1/6", 16.666667), ("5/6", 83.333333), ("1/12", 8.333333), ("5/12", 41.666667), ("7/12", 58.333333),
            ("11/12", 91.666667), ("12/12", 100.0),
        ];
        for (f, pct) in fractions {
            for (prefix, prop) in [("w", "width"), ("h", "height"), ("max-w", "max-width"), ("min-h", "min-height")] {
                let b = body(&format!("{prefix}-{f}"));
                let v: f64 = b.strip_prefix(&format!("{prop}:")).and_then(|v| v.strip_suffix('%')).unwrap_or_else(|| panic!("{b}")).parse().unwrap();
                assert!((v - pct).abs() < 0.001, "{prefix}-{f} -> {b}, Tailwind says {pct}%");
            }
        }
        assert_eq!(body("w-full"), "width:100%");
        assert_eq!(body("w-screen"), "width:100vw");
        assert_eq!(body("h-screen"), "height:100vh");
        assert_eq!(body("min-h-screen"), "min-height:100vh");
        assert_eq!(body("w-min"), "width:min-content");
        assert_eq!(body("w-max"), "width:max-content");
        assert_eq!(body("w-fit"), "width:fit-content");
        for (n, rem) in [("xs", "20rem"), ("sm", "24rem"), ("md", "28rem"), ("lg", "32rem"), ("xl", "36rem")] {
            assert_eq!(body(&format!("max-w-{n}")), format!("max-width:{rem}"));
        }
        for bad in ["w-1/0", "w-3/2", "w-0/0", "w-a/2", "w-1/2/3", "w-/2", "w-1/", "w-2xl", "max-w-7xl"] {
            assert!(compile(bad).is_none(), "{bad}");
        }
    }

    /// `screen` follows the axis: the viewport height for `h-*`, its width for `w-*`.
    #[test]
    fn max_h_screen_is_a_viewport_height() {
        assert_eq!(body("max-h-screen"), "max-height:100vh");
        assert_eq!(body("min-h-screen"), "min-height:100vh");
        assert_eq!(body("h-screen"), "height:100vh");
        assert_eq!(body("max-w-screen"), "max-width:100vw");
        assert_eq!(body("min-w-screen"), "min-width:100vw");
        assert_eq!(body("w-screen"), "width:100vw");
    }

    #[test]
    fn palette_and_alpha_match_tailwind() {
        let spots = [
            ("slate", ["#f8fafc", "#64748b", "#0f172a"]),
            ("gray", ["#f9fafb", "#6b7280", "#111827"]),
            ("red", ["#fef2f2", "#ef4444", "#7f1d1d"]),
            ("amber", ["#fffbeb", "#f59e0b", "#78350f"]),
            ("emerald", ["#ecfdf5", "#10b981", "#064e3b"]),
            ("sky", ["#f0f9ff", "#0ea5e9", "#0c4a6e"]),
            ("blue", ["#eff6ff", "#3b82f6", "#1e3a8a"]),
            ("indigo", ["#eef2ff", "#6366f1", "#312e81"]),
            ("violet", ["#f5f3ff", "#8b5cf6", "#4c1d95"]),
            ("orange", ["#fff7ed", "#f97316", "#7c2d12"]),
        ];
        for (fam, [c50, c500, c900]) in spots {
            assert_eq!(body(&format!("text-{fam}-50")), format!("color:{c50}"));
            assert_eq!(body(&format!("bg-{fam}-500")), format!("background-color:{c500}"));
            assert_eq!(body(&format!("border-{fam}-900")), format!("border-color:{c900}"));
            assert_eq!(body(&format!("fill-{fam}-500")), format!("fill:{c500}"));
            assert_eq!(body(&format!("stroke-{fam}-500")), format!("stroke:{c500}"));
            assert_eq!(rule(&format!("divide-{fam}-500")), format!(".divide-{fam}-500>:not([hidden])~:not([hidden]){{border-color:{c500}}}"));
        }
        for shade in SHADES {
            assert!(compile(&format!("bg-slate-{shade}")).is_some(), "{shade}");
        }
        assert_eq!(body("bg-slate-900/50"), "background-color:rgb(15 23 42/.5)");
        assert_eq!(body("text-white/80"), "color:rgb(255 255 255/.8)");
        assert_eq!(body("bg-black/5"), "background-color:rgb(0 0 0/.05)");
        assert_eq!(body("bg-red-500/0"), "background-color:rgb(239 68 68/0)");
        assert_eq!(body("bg-red-500/100"), "background-color:rgb(239 68 68/1)");
        assert_eq!(body("border-white"), "border-color:#ffffff");
        assert_eq!(body("bg-white"), "background-color:#fff");
        assert_eq!(body("bg-transparent"), "background-color:transparent");
        assert_eq!(body("border-transparent"), "border-color:transparent");
        for bad in ["bg-slate-950", "bg-slate-500/101", "bg-transparent/50", "bg-slate", "bg-slate-5000", "text-purple-500", "bg-slate-500/", "bg-slate-500/-1", "bg-slate-500/5.5", "bg-Slate-500", "bg-slate-500/50/50"] {
            assert!(compile(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn breakpoints_and_state_variants() {
        for (bp, w) in BREAKPOINTS {
            let c = compile(&format!("{bp}:flex")).unwrap();
            assert_eq!(c.min_width, Some(w), "{bp}");
            assert!(c.rule.ends_with("{display:flex}"), "{bp}: {}", c.rule);
        }
        assert_eq!((640, 768, 1024, 1280, 1536), (BREAKPOINTS[0].1, BREAKPOINTS[1].1, BREAKPOINTS[2].1, BREAKPOINTS[3].1, BREAKPOINTS[4].1), "Tailwind v3 defaults");
        let c = compile("md:hover:bg-slate-50").unwrap();
        assert_eq!((c.rule.as_str(), c.min_width), (".md\\:hover\\:bg-slate-50:hover{background-color:#f8fafc}", Some(768)));
        let c = compile("hover:md:bg-slate-50").unwrap();
        assert_eq!((c.rule.as_str(), c.min_width), (".hover\\:md\\:bg-slate-50:hover{background-color:#f8fafc}", Some(768)));
        assert_eq!(compile("sm:lg:flex").unwrap().min_width, Some(1024), "the larger breakpoint wins");
        assert_eq!(rule("focus:outline-none"), ".focus\\:outline-none:focus{outline:2px solid transparent;outline-offset:2px}");
        assert_eq!(rule("active:bg-slate-100"), ".active\\:bg-slate-100:active{background-color:#f1f5f9}");
        assert_eq!(rule("disabled:opacity-50"), ".disabled\\:opacity-50:disabled{opacity:.5}");
        assert_eq!(rule("hover:focus:underline"), ".hover\\:focus\\:underline:hover:focus{text-decoration-line:underline}");
        for bad in ["dark:flex", "group-hover:flex", "md:", "md::flex", ":flex", "focus-within:flex", "print:hidden", "MD:flex", "md:nope-1"] {
            assert!(compile(bad).is_none(), "{bad}");
        }
    }

    /// A class name starting with a digit must be escaped in a selector (Tailwind writes
    /// `.\32 xl\:flex`); `.2xl\:flex` is an invalid selector browsers drop.
    #[test]
    fn leading_digit_in_a_class_is_escaped() {
        let r = rule("2xl:flex");
        assert!(!r.starts_with(".2"), "{r}");
        assert!(r.starts_with(".\\32 xl\\:flex") || r.starts_with(".\\32xl\\:flex"), "{r}");
        assert_eq!(rule("2xl:px-1"), ".\\32 xl\\:px-1{padding-left:.25rem;padding-right:.25rem}");
        assert_eq!(escape("0a"), "\\30 a");
        assert_eq!(escape("9"), "\\39 ");
        assert_eq!(escape("a2"), "a2", "only a leading digit needs the hex escape");
    }

    #[test]
    fn arbitrary_values_calc_and_escaping() {
        assert_eq!(body("w-[200px]"), "width:200px");
        assert_eq!(body("w-[calc(100%-2rem)]"), "width:calc(100% - 2rem)");
        assert_eq!(body("top-[calc(50%+10px)]"), "top:calc(50% + 10px)");
        assert_eq!(body("p-[calc(100%/3)]"), "padding:calc(100% / 3)", "division in calc, where no fraction syntax competes");
        assert_eq!(body("w-[calc(2rem*3)]"), "width:calc(2rem * 3)");
        assert_eq!(body("w-[calc(var(--x)-1px)]"), "width:calc(var(--x) - 1px)");
        assert_eq!(body("w-[calc(-1*var(--x))]"), "width:calc(-1*var(--x))", "a leading sign is not an operator");
        assert_eq!(body("h-[calc(100vh-4.5rem)]"), "height:calc(100vh - 4.5rem)");
        assert_eq!(body("max-h-[calc(100vh-200px)]"), "max-height:calc(100vh - 200px)");
        assert_eq!(body("grid-cols-[1fr_2fr]"), "grid-template-columns:1fr 2fr");
        assert_eq!(body("grid-cols-[repeat(auto-fill,minmax(120px,1fr))]"), "grid-template-columns:repeat(auto-fill,minmax(120px,1fr))");
        assert_eq!(body("grid-cols-[minmax(0,1fr)_auto]"), "grid-template-columns:minmax(0,1fr) auto");
        assert_eq!(body("text-[#fff]"), "color:#fff");
        assert_eq!(body("text-[rgb(1_2_3)]"), "color:rgb(1 2 3)");
        assert_eq!(body("text-[1.1rem]"), "font-size:1.1rem");
        assert_eq!(body("bg-[rgba(0,0,0,.5)]"), "background-color:rgba(0,0,0,.5)");
        assert_eq!(body("z-[-1]"), "z-index:-1");
        assert_eq!(body("z-10"), "z-index:10");
        assert_eq!(body("leading-[1.1]"), "line-height:1.1");
        for (n, v) in [("none", "1"), ("tight", "1.25"), ("snug", "1.375"), ("normal", "1.5"), ("relaxed", "1.625")] {
            assert_eq!(body(&format!("leading-{n}")), format!("line-height:{v}"));
        }
        assert_eq!(body("opacity-0"), "opacity:0");
        assert_eq!(body("opacity-5"), "opacity:.05");
        assert_eq!(body("opacity-100"), "opacity:1");
        assert_eq!(body("border-2"), "border-width:2px");
        assert_eq!(body("border-t-2"), "border-top-width:2px");
        assert_eq!(body("border-x-2"), "border-left-width:2px;border-right-width:2px");
        assert_eq!(body("border-y-0"), "border-top-width:0px;border-bottom-width:0px");
        assert_eq!(body("rounded-t-lg"), "border-top-left-radius:.5rem;border-top-right-radius:.5rem");
        assert_eq!(body("rounded-b-md"), "border-bottom-left-radius:.375rem;border-bottom-right-radius:.375rem");
        assert_eq!(body("rounded-l-full"), "border-top-left-radius:9999px;border-bottom-left-radius:9999px");
        assert_eq!(body("rounded-r-sm"), "border-top-right-radius:.125rem;border-bottom-right-radius:.125rem");
        assert_eq!(body("grid-cols-12"), "grid-template-columns:repeat(12,minmax(0,1fr))");
        assert_eq!(body("col-span-3"), "grid-column:span 3/span 3");
        assert_eq!(body("order-2"), "order:2");
        for bad in [
            "w-[]", "w-[a[b]]", "w-[a;b]", "w-[{a}]", "w-[1px", "w-1px]", "opacity-101", "opacity-5.5", "z-1.5", "z-a", "border-z-2", "border-t-x",
            "rounded-t-xl", "rounded-x-lg", "rounded-t", "grid-cols-none", "col-span-full", "col-span-1.5", "order-first-1", "leading-x",
        ] {
            assert!(compile(bad).is_none(), "{bad} compiled to {:?}", compile(bad).map(|c| c.rule));
        }
        // Selector escaping of every special character a class may contain.
        assert_eq!(rule("w-[50%]"), ".w-\\[50\\%\\]{width:50%}");
        assert_eq!(rule("md:w-1/2"), ".md\\:w-1\\/2{width:50%}");
        assert_eq!(rule("bg-[#0f172a]"), ".bg-\\[\\#0f172a\\]{background-color:#0f172a}");
        assert_eq!(rule("w-[calc(100%-2rem)]"), ".w-\\[calc\\(100\\%-2rem\\)\\]{width:calc(100% - 2rem)}");
        assert_eq!(rule("grid-cols-[1fr_2fr]"), ".grid-cols-\\[1fr_2fr\\]{grid-template-columns:1fr 2fr}", "underscores need no escape");
        assert_eq!(rule("py-1.5"), ".py-1\\.5{padding-top:.375rem;padding-bottom:.375rem}");
        assert_eq!(escape("a-b_c1"), "a-b_c1");
        assert_eq!(escape("[(#%./:)]"), "\\[\\(\\#\\%\\.\\/\\:\\)\\]");
        assert_eq!(trim_float(0.375), ".375");
        assert_eq!(trim_float(1.0), "1");
        assert_eq!(trim_float(10.0), "10");
        assert_eq!(trim_float(1.5), "1.5");
        assert_eq!(trim_float(0.0), "0");
    }

    /// An arbitrary width or height may contain a `/` (`w-[calc(100%/3)]`, `h-[50vh/2]`):
    /// `size()` must try `[…]` before reading the value as a fraction.
    #[test]
    fn arbitrary_sizes_may_contain_a_slash() {
        assert_eq!(body("w-[calc(100%/3)]"), "width:calc(100% / 3)");
        assert_eq!(body("max-h-[calc(100vh/2)]"), "max-height:calc(100vh / 2)");
        assert_eq!(body("h-[50vh/2]"), "height:50vh/2");
        assert_eq!(body("w-1/3"), "width:33.3333%", "fractions still work");
    }

    #[test]
    fn shorthands_precede_longhands() {
        // Every longhand is written before its shorthand; the stylesheet must reverse that.
        let css = generate(
            r#"<div class="pt-2 px-3 p-4 ml-1 my-2 m-0 rounded-t-lg rounded-md leading-5 text-sm border-b-2 border-slate-200 border top-0 inset-0 flex md:pl-2 md:px-1 md:p-1">"#,
        );
        let pos = |s: &str| css.find(s).unwrap_or_else(|| panic!("{s} missing in {css}"));
        assert!(pos(".p-4{") < pos(".px-3{") && pos(".px-3{") < pos(".pt-2{"), "{css}");
        assert!(pos(".m-0{") < pos(".my-2{") && pos(".my-2{") < pos(".ml-1{"), "{css}");
        assert!(pos(".rounded-md{") < pos(".rounded-t-lg{"), "{css}");
        assert!(pos(".border{") < pos(".border-b-2{") && pos(".border-slate-200{") < pos(".border-b-2{"), "{css}");
        assert!(pos(".text-sm{") < pos(".leading-5{"), "{css}");
        assert!(pos(".inset-0{") < pos(".top-0{"), "{css}");
        assert!(pos(".md\\:p-1{") < pos(".md\\:px-1{") && pos(".md\\:px-1{") < pos(".md\\:pl-2{"), "within a media block too: {css}");
        assert!(pos(".flex{") < pos(".p-4{"), "unranked utilities keep their first-appearance order");
        // Equal ranks keep first-appearance order (the sort is stable).
        let css = generate(r#"<div class="pb-1 pt-1 pl-1">"#);
        let pos = |s: &str| css.find(s).unwrap();
        assert!(pos(".pb-1{") < pos(".pt-1{") && pos(".pt-1{") < pos(".pl-1{"), "{css}");
        assert_eq!(rank("border-transparent"), 1, "`t` must be a whole segment, not a prefix");
        assert_eq!(rank("text-slate-500"), 0, "a color does not compete with line-height");
        assert_eq!(rank("text-[12px]"), 1);
    }

    #[test]
    fn media_grouping_dedup_and_ordering() {
        let css = generate("<p class='px-4 sm:px-6 md:px-8 lg:flex xl:px-2 2xl:px-1 sm:hover:bg-slate-50 md:px-8 px-4'>flex items-center</p>");
        assert!(css.starts_with(PREFLIGHT));
        for (_, w) in BREAKPOINTS {
            assert_eq!(css.matches(&format!("@media (min-width:{w}px)")).count(), 1, "{w}");
        }
        let pos = |s: &str| css.find(s).unwrap_or_else(|| panic!("{s} missing in {css}"));
        assert!(pos(".px-4{") < pos("@media"), "plain rules come before the media blocks");
        assert!(pos("@media (min-width:640px)") < pos("@media (min-width:768px)"));
        assert!(pos("@media (min-width:768px)") < pos("@media (min-width:1024px)"));
        assert!(pos("@media (min-width:1024px)") < pos("@media (min-width:1280px)"));
        assert!(pos("@media (min-width:1280px)") < pos("@media (min-width:1536px)"));
        let md = &css[pos("@media (min-width:768px)")..pos("@media (min-width:1024px)")];
        assert_eq!(md, "@media (min-width:768px){.md\\:px-8{padding-left:2rem;padding-right:2rem}}");
        let sm = &css[pos("@media (min-width:640px)")..pos("@media (min-width:768px)")];
        assert!(sm.contains(".sm\\:px-6{") && sm.contains(".sm\\:hover\\:bg-slate-50:hover{"), "{sm}");
        assert_eq!(css.matches(".px-4{").count(), 1);
        assert_eq!(css.matches(".md\\:px-8{").count(), 1);
        assert!(css.contains(".flex{display:flex}") && css.contains(".items-center{"), "prose words that are utilities compile too");
        let plain = generate("<div class=\"flex\">");
        assert!(!plain.contains("@media"), "no breakpoints used, no media blocks");
        assert_eq!(generate(""), PREFLIGHT);
        // Attribute quotes, braces and prose punctuation never leak into tokens.
        let weird = generate("class=\"w-1/3\" {ui.connError} <b>flex,</b> text.slate-500 h-[calc(1px-1px)]");
        assert!(weird.contains(".w-1\\/3{") && weird.contains(".flex{") && weird.contains(".h-\\[calc\\(1px-1px\\)\\]{height:calc(1px - 1px)}"), "{weird}");
        assert!(!weird.contains("connError") && !weird.contains("slate-500"), "{weird}");
    }

    #[test]
    fn unknown_utilities_on_tricky_input() {
        let classes = "px-4 text-slate-950 w-1/0 bg-[] hover:px-7 dark:px-4 gap-x-3 h-8z self-signed stroke-width md:hover:text-sky-500 text-[#123] opacity-70 bg-amber-50/60 w-1/3 px- text-slate-950 border-b min-w-0 col-span-2 grid-cols-7 max-w-[220px] z-50 opacity-101 w-[calc(1px-1px)]";
        // In prose or JavaScript only tokens shaped like utilities are suspect.
        assert_eq!(unknown_utilities(&format!("const C = \"{classes}\";")), vec!["bg-[]", "opacity-101", "text-slate-950", "w-1/0"]);
        // In a class attribute every token is a class, so garbage there is reported too.
        assert_eq!(
            unknown_utilities(&format!("<div class=\"{classes}\">")),
            vec!["bg-[]", "dark:px-4", "h-8z", "opacity-101", "px-", "self-signed", "stroke-width", "text-slate-950", "w-1/0"]
        );
        assert!(unknown_utilities("").is_empty());
        assert!(unknown_utilities("hosts panel-h grid-table font-size:12px").is_empty());
        assert!(utility_like("md:hover:text-sky-500") && utility_like("focus:w-[1px]") && utility_like("text-white") && utility_like("bg-transparent"));
        assert!(utility_like("active:bg-slate-100") && utility_like("disabled:opacity-50") && utility_like("md:active:px-3"), "the variants `compile` accepts");
        assert!(utility_like("text-green-600") && utility_like("bg-yellow-50") && utility_like("border-teal-500/50"), "unknown families with a real shade are color typos");
        assert!(!utility_like("dark:px-4") && !utility_like("gap-x-3") && !utility_like("border-b") && !utility_like("Px-4") && !utility_like("md:"));
        assert!(!utility_like("text-green-6000") && !utility_like("bg-Green-500"), "an unknown family needs a real shade and a lowercase name");
        assert_eq!(unknown_utilities("<p class='text-green-600'>self-signed certificate</p>"), vec!["text-green-600"]);
    }

    #[test]
    fn class_attribute_typos_are_reported() {
        let page = r#"<style>.panel, .num { color: red; } .pk tr.sel td, .input.bad { x: 1.5 } .lyr0 { } .btn[disabled] { } @media (max-width: 767px) { .nav-m a.on { } }</style>
            <div class="panel flex itemz-center text-green-600 sel">self-signed grid-table text-sm</div>
            <script>
              el.classList.toggle("hl", on); el.classList.add('dragging');
              const row = `<tr class="pk ${cls} ${x.state === "closed" ? "text-slate-400" : "text-slate-700"}"><td class="lyr${i % 7} num">`;
              const btn = `<a class="btn ${ui.sel === k ? `on ${extra}` : ""} px-3">`;
              const bad = `<b class="nav-m font-semibld ${fn({a: "}"})} ok-${tone}">`;
              el.className = "chip " + v[1];
            </script>"#;
        assert_eq!(unknown_utilities(page), vec!["font-semibld", "itemz-center", "text-green-600"]);
        let defined = page_classes(page);
        for c in ["panel", "pk", "sel", "input", "bad", "lyr0", "nav-m", "on", "hl", "dragging"] {
            assert!(defined.contains(c), "{c} is defined by the page");
        }
        assert!(!defined.contains("5") && !defined.contains("closed") && !defined.contains("chip"), "{defined:?}");
        assert_eq!(
            class_attribute_tokens(page),
            vec!["panel", "flex", "itemz-center", "text-green-600", "sel", "pk", "num", "btn", "px-3", "nav-m", "font-semibld"],
            "interpolations and the fragments glued to them are skipped"
        );
        // Prose and JavaScript strings are not class attributes; a hyphenated word there is fine.
        assert!(unknown_utilities("<p>self-signed certificate, items-center</p> const K = \"itemz-center\";").is_empty());
        assert!(unknown_utilities(r#"<div class="flex itemz-center">"#) == ["itemz-center"]);
        assert!(unknown_utilities(r#"<div class='flex' data-class="nope">"#).is_empty(), "`data-class` is not a class attribute");
        assert!(unknown_utilities(r#"<div class="flex"#).is_empty(), "an unterminated attribute ends the scan");
        assert!(unknown_utilities(r#"<div class="flex ${x"#).is_empty(), "an unterminated interpolation ends the scan");
    }

    #[test]
    fn the_dashboard_compiles_completely() {
        let unknown = unknown_utilities(super::super::INDEX_HTML);
        assert!(unknown.is_empty(), "utility classes without a rule: {unknown:?}");
        assert!(!super::super::INDEX_HTML.contains("cdn.tailwindcss.com"), "the dashboard must work offline");
    }
}
