//! CLI contract tests: drive the built `dig-relay` binary and assert its subcommand surface
//! (the surface the DIG installer + operators depend on). No network, no service install.

use std::process::Command;

/// Path to the built `dig-relay` binary for this test run.
fn bin() -> std::path::PathBuf {
    // CARGO_BIN_EXE_<name> is set by cargo for integration tests of a binary crate.
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_dig-relay"))
}

#[test]
fn help_lists_the_service_subcommands() {
    let out = Command::new(bin())
        .arg("--help")
        .output()
        .expect("run --help");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    for verb in ["serve", "install", "uninstall", "start", "stop", "status"] {
        assert!(text.contains(verb), "--help should list `{verb}`");
    }
}

#[test]
fn version_prints() {
    let out = Command::new(bin())
        .arg("--version")
        .output()
        .expect("run --version");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("dig-relay"), "version line names the binary");
}

#[test]
fn status_against_a_dead_port_exits_nonzero_and_emits_json() {
    // Point status at a health port nothing listens on → serving:false → exit 1 + JSON envelope.
    let out = Command::new(bin())
        .args(["status", "--json", "--health-listen", "127.0.0.1:1"])
        .output()
        .expect("run status");
    assert!(
        !out.status.success(),
        "status must exit non-zero when not serving"
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(text.trim()).expect("status --json is JSON");
    assert_eq!(v["ok"], true);
    assert_eq!(v["result"]["serving"], false);
}

#[test]
fn run_service_is_hidden_from_help() {
    let out = Command::new(bin())
        .arg("--help")
        .output()
        .expect("run --help");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !text.contains("run-service"),
        "the Windows SCM entrypoint is hidden from --help"
    );
}
