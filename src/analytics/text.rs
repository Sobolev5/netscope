//! Human-readable alert texts in Russian and English, built from `kind` and `details` —
//! the same templates the dashboard uses, for places without the dashboard's JavaScript
//! (Windows notifications of the desktop app).

use super::anomaly::{Alert, AlertKind, Category};

/// Short label of an alert kind ("New destination", "Port scan"…).
pub fn kind_label(kind: AlertKind, ru: bool) -> &'static str {
    match (kind, ru) {
        (AlertKind::SensitiveHttp, true) => "Пароли/токены по HTTP",
        (AlertKind::SensitiveHttp, false) => "Credentials over HTTP",
        (AlertKind::SuspiciousDns, true) => "Подозрительный DNS",
        (AlertKind::SuspiciousDns, false) => "Suspicious DNS",
        (AlertKind::VolumeSpike, true) => "Всплеск трафика",
        (AlertKind::VolumeSpike, false) => "Traffic spike",
        (AlertKind::CleartextProtocol, true) => "Незашифрованный протокол",
        (AlertKind::CleartextProtocol, false) => "Cleartext protocol",
        (AlertKind::NewProcess, true) => "Новая программа в сети",
        (AlertKind::NewProcess, false) => "New program online",
        (AlertKind::NewDestination, true) => "Новое направление",
        (AlertKind::NewDestination, false) => "New destination",
        (AlertKind::NewCountry, true) => "Новая страна",
        (AlertKind::NewCountry, false) => "New country",
        (AlertKind::NewListener, true) => "Новый открытый порт",
        (AlertKind::NewListener, false) => "New open port",
        (AlertKind::UnsignedProcess, true) => "Неподписанная программа",
        (AlertKind::UnsignedProcess, false) => "Unsigned program",
        (AlertKind::RouteChange, true) => "Смена маршрута",
        (AlertKind::RouteChange, false) => "Route change",
        (AlertKind::LatencyIncrease, true) => "Рост задержки",
        (AlertKind::LatencyIncrease, false) => "Latency increase",
        (AlertKind::NetworkChange, true) => "Смена сети",
        (AlertKind::NetworkChange, false) => "Network change",
        (AlertKind::EgressChange, true) => "Смена точки выхода",
        (AlertKind::EgressChange, false) => "Internet exit changed",
        (AlertKind::DnsResolverChange, true) => "Новый DNS-сервер",
        (AlertKind::DnsResolverChange, false) => "New DNS resolver",
        (AlertKind::SuspiciousConnection, true) => "Подозрительное соединение",
        (AlertKind::SuspiciousConnection, false) => "Suspicious connection",
        (AlertKind::PortScan, true) => "Сканирование портов",
        (AlertKind::PortScan, false) => "Port scan",
        (AlertKind::LargeUpload, true) => "Большая отправка данных",
        (AlertKind::LargeUpload, false) => "Large upload",
        (AlertKind::CaptureFailed, true) => "Захват остановлен",
        (AlertKind::CaptureFailed, false) => "Capture stopped",
    }
}

pub fn category_label(c: Category, ru: bool) -> &'static str {
    match (c, ru) {
        (Category::Security, true) => "Безопасность",
        (Category::Security, false) => "Security",
        (Category::Novelty, true) => "Новое в сети",
        (Category::Novelty, false) => "New activity",
        (Category::Network, true) => "Сеть и VPN",
        (Category::Network, false) => "Network and VPN",
        (Category::Routes, true) => "Маршруты",
        (Category::Routes, false) => "Routes",
    }
}

/// The template for an alert: `{key}` placeholders are the alert's details plus `{host}`.
fn template(a: &Alert, ru: bool) -> Option<&'static str> {
    let d = |k: &str| a.details.get(k).map(String::as_str).unwrap_or("");
    Some(match (a.kind, ru) {
        (AlertKind::SensitiveHttp, true) => "Незашифрованный HTTP {method} {url} передаёт: {data}",
        (AlertKind::SensitiveHttp, false) => "Unencrypted HTTP {method} {url} carries: {data}",
        (AlertKind::SuspiciousDns, ru) => match (d("reason"), ru) {
            ("long_name", true) => "DNS-запрос {domain}: очень длинное имя ({value} симв.) — похоже на DNS-туннель",
            ("long_name", false) => "DNS query {domain}: very long name ({value} chars) — looks like DNS tunneling",
            ("long_label", true) => "DNS-запрос {domain}: слишком длинная метка ({value} симв.)",
            ("long_label", false) => "DNS query {domain}: oversized label ({value} chars)",
            ("entropy", true) => "DNS-запрос {domain}: случайная поддоменная метка «{value}» — возможна утечка данных",
            ("entropy", false) => "DNS query {domain}: random-looking label “{value}” — possible data exfiltration",
            ("rare_type", true) => "DNS-запрос {domain}: редкий тип записи {value}",
            ("rare_type", false) => "DNS query {domain}: unusual record type {value}",
            _ => return None,
        },
        (AlertKind::VolumeSpike, true) => "Всплеск трафика к неизвестному хосту {host}: {rate} (обычно {baseline}), имя не встречалось ни в DNS, ни в SNI",
        (AlertKind::VolumeSpike, false) => "Traffic spike to unknown host {host}: {rate} (usually {baseline}), no DNS/SNI name seen for it",
        (AlertKind::CleartextProtocol, true) => "Соединение {service} с {endpoint}: данные передаются без шифрования",
        (AlertKind::CleartextProtocol, false) => "{service} connection to {endpoint} sends data unencrypted",
        (AlertKind::NewProcess, true) => "{process} впервые вышел в сеть",
        (AlertKind::NewProcess, false) => "{process} used the network for the first time",
        (AlertKind::NewDestination, true) => "{process} впервые обратился к {destination}",
        (AlertKind::NewDestination, false) => "{process} contacted {destination} for the first time",
        (AlertKind::NewCountry, true) => "{process} впервые подключился к стране {country}",
        (AlertKind::NewCountry, false) => "{process} connected to a new country: {country}",
        (AlertKind::NewListener, true) => "{process} начал слушать порт {port} ({address}) — доступен из сети",
        (AlertKind::NewListener, false) => "{process} started listening on port {port} ({address}) — reachable from the network",
        (AlertKind::UnsignedProcess, ru) => match (d("risky_location") == "true", ru) {
            (true, true) => "{process} не подписан, запущен из временной папки ({path}) и ходит в сеть",
            (true, false) => "{process} is unsigned, runs from a temporary folder ({path}) and uses the network",
            (false, true) => "{process} ({path}) не подписан и ходит в сеть",
            (false, false) => "{process} ({path}) is unsigned and uses the network",
        },
        (AlertKind::RouteChange, true) => "Маршрут до {host} изменился: {before} → {after}",
        (AlertKind::RouteChange, false) => "Route to {host} changed: {before} → {after}",
        (AlertKind::LatencyIncrease, true) => "Маршрут до {host} стал медленнее: {before_ms} мс → {after_ms} мс",
        (AlertKind::LatencyIncrease, false) => "Route to {host} got slower: {before_ms} ms → {after_ms} ms",
        (AlertKind::NetworkChange, ru) => match (d("vpn"), ru) {
            ("on", true) => "Трафик пошёл через VPN-адаптер «{after}» (раньше — {before})",
            ("on", false) => "Traffic now goes through the VPN adapter “{after}” (was {before})",
            ("off", true) => "VPN-адаптер «{before}» больше не используется, трафик идёт через {after}",
            ("off", false) => "The VPN adapter “{before}” is no longer used; traffic goes through {after}",
            (_, true) => "Сеть изменилась: трафик идёт через {after} (раньше — {before})",
            (_, false) => "Network changed: traffic goes through {after} (was {before})",
        },
        (AlertKind::EgressChange, ru) => match (d("vpn"), ru) {
            ("on", true) => "VPN включён: выход в интернет теперь {after} (был {before})",
            ("on", false) => "VPN is on: the internet exit is now {after} (was {before})",
            ("off", true) => "VPN выключен: выход в интернет снова {after} (был {before})",
            ("off", false) => "VPN is off: the internet exit is {after} again (was {before})",
            (_, true) => "Точка выхода в интернет изменилась: {before} → {after}",
            (_, false) => "The internet exit changed: {before} → {after}",
        },
        (AlertKind::DnsResolverChange, true) => "DNS-запросы пошли на новый сервер {after} (раньше — {before})",
        (AlertKind::DnsResolverChange, false) => "DNS queries now go to a new server {after} (before: {before})",
        (AlertKind::SuspiciousConnection, ru) => match (d("reason"), ru) {
            ("remote_control", true) => "{process} подключается к {endpoint}: порт {port} типичен для удалённого управления и вредоносных программ ({service})",
            ("remote_control", false) => "{process} connects to {endpoint}: port {port} is typical of remote control and malware ({service})",
            ("smb", true) => "{process} открывает файловый доступ {service} к {endpoint} в интернете",
            ("smb", false) => "{process} opens {service} file sharing to {endpoint} on the internet",
            ("mail", true) => "{process} отправляет почту напрямую на {endpoint} (SMTP) — так ведут себя спам-боты",
            ("mail", false) => "{process} sends mail directly to {endpoint} (SMTP) — spam bots do that",
            ("unsigned_ip", true) => "Неподписанная программа {process} подключается к {endpoint} по IP без доменного имени",
            ("unsigned_ip", false) => "Unsigned program {process} connects to {endpoint} by IP without a domain name",
            _ => return None,
        },
        (AlertKind::PortScan, ru) => match (d("direction"), ru) {
            ("in", true) => "Сканирование портов с {host}: {ports} портов за {seconds} с",
            ("in", false) => "Port scan from {host}: {ports} ports in {seconds} s",
            (_, true) => "{process} сканирует порты {host}: {ports} портов за {seconds} с",
            (_, false) => "{process} scans ports of {host}: {ports} ports in {seconds} s",
        },
        (AlertKind::LargeUpload, true) => "{process} отправил {size} на {destination} за {minutes} мин",
        (AlertKind::LargeUpload, false) => "{process} sent {size} to {destination} in {minutes} min",
        (AlertKind::CaptureFailed, true) => "Захват трафика остановился: {error}",
        (AlertKind::CaptureFailed, false) => "Traffic capture stopped: {error}",
    })
}

/// Bytes with units, as the dashboard shows them.
pub fn size(bytes: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1000.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

/// Localized one-line description of an alert; the English `message` when a template is
/// missing.
pub fn alert_text(a: &Alert, ru: bool) -> String {
    let Some(t) = template(a, ru) else { return a.message.clone() };
    let mut out = String::with_capacity(t.len() + 64);
    let mut rest = t;
    while let Some(i) = rest.find('{') {
        out.push_str(&rest[..i]);
        let Some(j) = rest[i..].find('}') else {
            out.push_str(&rest[i..]);
            return out;
        };
        let key = &rest[i + 1..i + j];
        let detail = |k: &str| a.details.get(k).cloned();
        let value = match key {
            "host" => a.host.clone().unwrap_or_default(),
            "rate" | "baseline" => match detail(key).and_then(|v| v.parse::<u64>().ok()) {
                Some(b) => format!("{}/s", size(b)),
                None => detail(key).unwrap_or_default(),
            },
            "size" => match detail("bytes").and_then(|v| v.parse::<u64>().ok()) {
                Some(b) => size(b),
                None => detail(key).unwrap_or_default(),
            },
            _ => detail(key).unwrap_or_else(|| format!("{{{key}}}")),
        };
        out.push_str(&value);
        rest = &rest[i + j + 1..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::super::anomaly::{AlertLog, NewAlert, Severity};
    use super::*;

    fn alert(kind: AlertKind, host: Option<&str>, details: &[(&str, &str)]) -> Alert {
        let mut log = AlertLog::new(2, 0);
        log.push(
            1,
            NewAlert {
                severity: Severity::Medium,
                kind,
                host: host.map(String::from),
                name: None,
                message: "english fallback".into(),
                details: details.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<BTreeMap<_, _>>(),
                key: "k".into(),
            },
        );
        log.last().unwrap().clone()
    }

    #[test]
    fn every_kind_has_labels_and_a_template() {
        for k in AlertKind::ALL {
            assert!(!kind_label(k, true).is_empty() && !kind_label(k, false).is_empty());
            let a = alert(k, Some("1.2.3.4"), &[("reason", "long_name"), ("direction", "in")]);
            let (ru, en) = (alert_text(&a, true), alert_text(&a, false));
            // The suspicious-connection reasons do not include `long_name`: that one falls back.
            if k != AlertKind::SuspiciousConnection {
                assert_ne!(ru, "english fallback", "{k:?}");
                assert_ne!(en, "english fallback", "{k:?}");
                assert_ne!(ru, en, "{k:?}");
            }
        }
        for reason in ["remote_control", "smb", "mail", "unsigned_ip"] {
            let a = alert(AlertKind::SuspiciousConnection, None, &[("reason", reason)]);
            assert_ne!(alert_text(&a, true), alert_text(&a, false), "{reason}");
        }
        for c in Category::ALL {
            assert_ne!(category_label(c, true), category_label(c, false));
        }
    }

    #[test]
    fn placeholders_are_filled_and_sizes_formatted() {
        let a = alert(AlertKind::NewDestination, None, &[("process", "Code.exe"), ("destination", "github.com")]);
        assert_eq!(alert_text(&a, true), "Code.exe впервые обратился к github.com");
        assert_eq!(alert_text(&a, false), "Code.exe contacted github.com for the first time");

        let a = alert(AlertKind::VolumeSpike, Some("5.6.7.8"), &[("rate", "3000000"), ("baseline", "120")]);
        assert_eq!(alert_text(&a, false), "Traffic spike to unknown host 5.6.7.8: 2.9 MB/s (usually 120 B/s), no DNS/SNI name seen for it");

        let a = alert(AlertKind::LargeUpload, None, &[("process", "x.exe"), ("destination", "drop.io"), ("bytes", "314572800"), ("minutes", "7")]);
        assert_eq!(alert_text(&a, true), "x.exe отправил 300.0 MB на drop.io за 7 мин");

        let a = alert(AlertKind::EgressChange, None, &[("vpn", "on"), ("before", "1.1.1.1 (RU)"), ("after", "5.5.5.5 (NL)")]);
        assert_eq!(alert_text(&a, true), "VPN включён: выход в интернет теперь 5.5.5.5 (NL) (был 1.1.1.1 (RU))");

        let a = alert(AlertKind::SuspiciousConnection, None, &[("reason", "nonsense")]);
        assert_eq!(alert_text(&a, true), "english fallback", "unknown variants fall back to the English message");

        let a = alert(AlertKind::NewProcess, None, &[]);
        assert_eq!(alert_text(&a, false), "{process} used the network for the first time", "a missing detail stays visible");
        assert_eq!(size(999), "999 B");
        assert_eq!(size(1536), "1.5 KB");
    }
}
