//! The real binary: argument handling and friendly failures.

mod common;

use std::process::{Command, Output};

fn netscope(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_netscope")).args(args).output().unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

#[test]
fn help_lists_main_options() {
    let o = netscope(&["--help"]);
    assert!(o.status.success());
    let out = String::from_utf8_lossy(&o.stdout);
    for flag in ["--host", "--port", "--interface", "--list-interfaces", "--read", "--demo", "--filter"] {
        assert!(out.contains(flag), "missing {flag}");
    }
}

#[test]
fn invalid_arguments_are_rejected() {
    assert!(!netscope(&["--realtime"]).status.success());
    assert!(!netscope(&["--port", "99999"]).status.success());
}

#[test]
fn bad_capture_files_fail_with_a_clear_message() {
    let missing = netscope(&["--read", "definitely-missing.pcap"]);
    assert!(!missing.status.success());
    assert!(stderr(&missing).starts_with("error: definitely-missing.pcap"), "{}", stderr(&missing));

    let junk = common::temp_path("junk.pcap");
    std::fs::write(&junk, b"this is not a capture file at all").unwrap();
    let o = netscope(&["--read", junk.to_str().unwrap()]);
    std::fs::remove_file(&junk).ok();
    assert!(!o.status.success());
    assert!(stderr(&o).contains("not a pcap capture file"), "{}", stderr(&o));
}

#[test]
fn busy_port_is_reported_after_opening_the_source() {
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port().to_string();
    let o = netscope(&["--demo", "--port", &port]);
    assert!(!o.status.success());
    assert!(stderr(&o).contains("already in use"), "{}", stderr(&o));
}
