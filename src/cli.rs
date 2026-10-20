use std::path::PathBuf;

use clap::{ArgAction, Parser};

/// Real-time network traffic analyzer with anomaly detection and a web dashboard.
///
/// Without arguments it captures on the best active interface and serves the
/// dashboard at http://127.0.0.1:8888.
#[derive(Debug, Parser)]
#[command(name = "netscope", version, about, long_about = None)]
pub struct Args {
    /// Address to serve the dashboard on (anything but loopback exposes it to the network)
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Port to serve the dashboard on [default: 8888, or the next free one when it is busy]
    #[arg(short, long)]
    pub port: Option<u16>,

    /// Interface: index or name from --list-interfaces, or part of its description
    #[arg(short, long)]
    pub interface: Option<String>,

    /// List capture interfaces and exit
    #[arg(short, long)]
    pub list_interfaces: bool,

    /// BPF capture filter, e.g. "tcp port 443 or udp port 53"
    #[arg(short, long)]
    pub filter: Option<String>,

    /// Analyze a .pcap/.pcapng file instead of a live interface
    #[arg(short, long, value_name = "FILE", conflicts_with_all = ["interface", "demo"])]
    pub read: Option<PathBuf>,

    /// With --read: replay at the original speed instead of as fast as possible
    #[arg(long, requires = "read")]
    pub realtime: bool,

    /// Analyze synthetic traffic (no capture privileges or libpcap needed)
    #[arg(long, conflicts_with_all = ["interface", "filter"])]
    pub demo: bool,

    /// Do not put the interface into promiscuous mode
    #[arg(long)]
    pub no_promisc: bool,

    /// Bytes captured per packet
    #[arg(long, default_value_t = 65_535, value_parser = clap::value_parser!(i32).range(64..=262_144))]
    pub snaplen: i32,

    /// Per-second volume (MiB) to a host without a DNS/SNI name that counts as a spike
    #[arg(long, default_value_t = 1.0, value_parser = parse_positive)]
    pub spike_mib: f64,

    /// Directory with dbip-city-lite.mmdb / dbip-asn-lite.mmdb (see scripts/fetch-geoip.*)
    #[arg(long, value_name = "DIR")]
    pub geoip: Option<PathBuf>,

    /// Do not ask 1.1.1.1 for the public egress address
    #[arg(long)]
    pub no_egress_check: bool,

    /// Open the dashboard in the default browser once it is up
    #[arg(long)]
    pub open: bool,

    /// File where learned state (watched routes, what is "normal") survives restarts; live
    /// capture only [default: <data dir>/state.json, see --help]
    #[arg(long, value_name = "FILE", conflicts_with = "no_state", long_help = "File where learned state (watched routes, what is \"normal\") survives restarts; \
        used for live capture only, never with --demo or --read.\n\nDefault: %LOCALAPPDATA%\\NetScope\\state.json on Windows, $XDG_STATE_HOME/netscope/state.json \
        or ~/.local/state/netscope/state.json elsewhere")]
    pub state: Option<PathBuf>,

    /// Start from scratch and remember nothing when exiting
    #[arg(long)]
    pub no_state: bool,

    /// More logging (-v debug, -vv trace); RUST_LOG overrides
    #[arg(short, long, action = ArgAction::Count)]
    pub verbose: u8,
}

fn parse_positive(s: &str) -> Result<f64, String> {
    match s.parse::<f64>() {
        Ok(v) if v.is_finite() && v > 0.0 => Ok(v),
        _ => Err(format!("`{s}` is not a positive number")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        let a = Args::try_parse_from(["netscope"]).unwrap();
        assert_eq!((a.host.as_str(), a.port), ("127.0.0.1", None));
        assert!(a.interface.is_none() && a.read.is_none() && !a.demo);
        assert_eq!(a.snaplen, 65_535);
    }

    #[test]
    fn overrides_and_conflicts() {
        let a = Args::try_parse_from(["netscope", "--host", "0.0.0.0", "--port", "9000", "-i", "2", "-vv"]).unwrap();
        assert_eq!((a.host.as_str(), a.port, a.interface.as_deref(), a.verbose), ("0.0.0.0", Some(9000), Some("2"), 2));
        assert!(Args::try_parse_from(["netscope", "--realtime"]).is_err(), "--realtime needs --read");
        assert!(Args::try_parse_from(["netscope", "--demo", "-i", "eth0"]).is_err());
        assert!(Args::try_parse_from(["netscope", "-r", "x.pcap", "-i", "eth0"]).is_err());
        assert!(Args::try_parse_from(["netscope", "--spike-mib", "0"]).is_err());
        assert!(Args::try_parse_from(["netscope", "--port", "70000"]).is_err());
        assert!(Args::try_parse_from(["netscope", "--snaplen", "10"]).is_err());
    }

    #[test]
    fn state_flags() {
        let a = Args::try_parse_from(["netscope"]).unwrap();
        assert!(a.state.is_none() && !a.no_state, "the default path is decided by the app, not here");
        let a = Args::try_parse_from(["netscope", "--state", "x/state.json"]).unwrap();
        assert_eq!(a.state.as_deref(), Some(std::path::Path::new("x/state.json")));
        assert!(Args::try_parse_from(["netscope", "--no-state"]).unwrap().no_state);
        assert!(Args::try_parse_from(["netscope", "--no-state", "--state", "x"]).is_err(), "either, not both");
    }
}
