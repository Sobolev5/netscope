//! netscope: packet capture → decoding → analytics → web dashboard.
//!
//! ```text
//!  capture/  libpcap (runtime-loaded) | .pcap reader | demo ──┐  capture thread
//!  decode/   Ethernet/IP/TCP/UDP + DNS, TLS SNI, HTTP        ◄┘
//!  analytics/ Arc<RwLock<State>>: hosts, protocols, bandwidth, alerts
//!  web/      axum: /, /api/stats, /api/alerts, /api/health, /api/ws
//! ```

pub mod analytics;
pub mod app;
pub mod capture;
pub mod cli;
pub mod decode;
pub mod demo;
pub mod geo;
pub mod netpath;
pub mod procs;
pub mod settings;
pub mod trace;
pub mod web;
