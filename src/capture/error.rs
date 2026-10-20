use thiserror::Error;

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("could not load the packet capture library (tried: {tried})\n  hint: {}", install_hint())]
    LibraryNotFound { tried: String },

    #[error("permission denied while opening `{device}`: {detail}\n  hint: {}", permission_hint())]
    PermissionDenied { device: String, detail: String },

    #[error("no usable capture interface found\n  hint: run `netscope --list-interfaces` and pick one with --interface, or try --demo")]
    NoDevice,

    #[error("interface `{0}` not found\n  hint: run `netscope --list-interfaces` for names and indexes")]
    InterfaceNotFound(String),

    #[error("invalid BPF filter `{filter}`: {detail}")]
    Filter { filter: String, detail: String },

    #[error("{context}: {detail}")]
    Pcap { context: String, detail: String },

    #[error("{path}: {detail}")]
    BadFile { path: String, detail: String },

    #[error("{path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

impl CaptureError {
    /// Turns a raw libpcap error into `PermissionDenied` when the text says so.
    pub fn from_pcap(context: &str, device: &str, detail: String) -> Self {
        let lower = detail.to_ascii_lowercase();
        let denied = ["permission", "not permitted", "access is denied", "access denied", "administrator"]
            .iter()
            .any(|k| lower.contains(k));
        if denied {
            CaptureError::PermissionDenied { device: device.to_string(), detail }
        } else {
            CaptureError::Pcap { context: format!("{context} `{device}`"), detail }
        }
    }
}

pub fn install_hint() -> &'static str {
    if cfg!(windows) {
        "install Npcap from https://npcap.com (keep \"WinPcap API-compatible Mode\" checked), \
         or point NETSCOPE_LIBPCAP at wpcap.dll; `netscope --demo` works without it"
    } else if cfg!(target_os = "macos") {
        "libpcap ships with macOS; set NETSCOPE_LIBPCAP=/usr/lib/libpcap.A.dylib if it is not found"
    } else {
        "install libpcap (Debian/Ubuntu: `sudo apt install libpcap0.8`, Fedora: `sudo dnf install libpcap`, \
         Alpine: `apk add libpcap`) or set NETSCOPE_LIBPCAP to its path"
    }
}

pub fn permission_hint() -> &'static str {
    if cfg!(windows) {
        "Npcap was probably installed with \"Restrict Npcap driver's access to Administrators only\"; \
         run the terminal as Administrator or reinstall Npcap without that option"
    } else if cfg!(target_os = "macos") {
        "run with sudo, or give your user read access to /dev/bpf* (Wireshark's ChmodBPF package does this)"
    } else {
        "run as root, or grant the binary capture capabilities once: \
         `sudo setcap cap_net_raw,cap_net_admin=eip $(command -v netscope || echo ./target/release/netscope)`"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_permission_errors() {
        for msg in [
            "eth0: You don't have permission to capture on that device (socket: Operation not permitted)",
            "Error opening adapter: Access is denied.  (5)",
        ] {
            assert!(matches!(CaptureError::from_pcap("open", "eth0", msg.into()), CaptureError::PermissionDenied { .. }), "{msg}");
        }
        let other = CaptureError::from_pcap("open", "eth0", "No such device exists".into());
        assert!(matches!(other, CaptureError::Pcap { .. }));
        assert_eq!(other.to_string(), "open `eth0`: No such device exists");
    }

    #[test]
    fn messages_carry_hints() {
        let e = CaptureError::LibraryNotFound { tried: "wpcap.dll (error 193)".into() };
        assert!(e.to_string().contains("hint:"));
        assert!(e.to_string().starts_with("could not load the packet capture library (tried: wpcap.dll (error 193))"), "{e}");
        let e = CaptureError::PermissionDenied { device: "eth0".into(), detail: "x".into() };
        assert!(e.to_string().contains(permission_hint()));
    }
}
