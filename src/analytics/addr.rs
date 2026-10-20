//! Address scope helpers used to decide traffic direction and what counts as "external".

use std::net::IpAddr;

/// Private, loopback, link-local, unspecified, unique-local (v6), CGNAT.
pub fn is_local_scope(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_unspecified()
                || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        IpAddr::V6(a) => {
            let s = a.segments()[0];
            a.is_loopback() || a.is_unspecified() || (s & 0xFE00) == 0xFC00 || (s & 0xFFC0) == 0xFE80
        }
    }
}

pub fn is_multicast_or_broadcast(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_multicast() || a.is_broadcast(),
        IpAddr::V6(a) => a.is_multicast(),
    }
}

/// A routable unicast address outside the local network.
pub fn is_external(ip: &IpAddr) -> bool {
    !is_local_scope(ip) && !is_multicast_or_broadcast(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn scopes() {
        for local in ["10.1.2.3", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "::1", "fe80::1", "fd00::1"] {
            assert!(is_local_scope(&ip(local)), "{local}");
            assert!(!is_external(&ip(local)), "{local}");
        }
        for ext in ["8.8.8.8", "93.184.215.14", "100.128.0.1", "2001:4860::8888"] {
            assert!(is_external(&ip(ext)), "{ext}");
        }
        for group in ["224.0.0.251", "255.255.255.255", "ff02::fb"] {
            assert!(is_multicast_or_broadcast(&ip(group)), "{group}");
            assert!(!is_external(&ip(group)), "{group}");
        }
    }
}
