//! `dig-relay` — the DIG Network NAT-traversal relay server (binary entrypoint).
//!
//! Serves the DIG relay protocol (RLY-001..RLY-007) over WebSocket so DIG Nodes behind NAT can
//! register, discover peers, coordinate hole-punching, and fall back to relayed transport. The
//! canonical deployment is `relay.dig.net`; nodes may also run their own (installable via the DIG
//! installer, which delegates to the `install`/`start` subcommands below). TLS is terminated at the
//! load balancer in production (DESIGN.md), so the process speaks plain `ws://` internally.
//!
//! Subcommands: `serve` (default) · `install`/`uninstall` (register as an OS service) ·
//! `start`/`stop`/`status` (control it) · `run-service` (Windows SCM entrypoint, not run by hand).

use std::net::SocketAddr;
use std::time::Duration;

use clap::{Parser, Subcommand};

use dig_relay::service;
use dig_relay::RelayServerConfig;

#[derive(Parser, Debug)]
#[command(
    name = "dig-relay",
    version,
    about = "DIG Network NAT-traversal relay (rendezvous + circuit relay)",
    long_about = "Publicly-reachable rendezvous + circuit relay for the DIG Network L2 peer layer. \
DIG Nodes behind NAT register a constant reservation, discover peers, coordinate hole-punching, and \
fall back to relayed transport through this server when a direct dial fails. Speaks the DIG relay \
protocol (RLY-001..RLY-007) as JSON over WebSocket. Canonical deployment: relay.dig.net."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Emit machine-readable JSON for service subcommands (install/uninstall/start/stop/status).
    #[arg(long, global = true)]
    json: bool,

    // ---- `serve` flags (also accepted at the top level so bare `dig-relay` serves) ----
    /// Address the relay WebSocket listener binds (default [::]:9450, dual-stack IPv6+IPv4).
    #[arg(long, value_name = "ADDR", global = true)]
    listen: Option<SocketAddr>,
    /// Address the HTTP /health listener binds (default [::]:9451, dual-stack IPv6+IPv4).
    #[arg(long, value_name = "ADDR", global = true)]
    health_listen: Option<SocketAddr>,
    /// Address the STUN (RFC 5389) UDP listener binds (default [::]:3478, dual-stack IPv6+IPv4).
    #[arg(long, value_name = "ADDR", global = true)]
    stun_listen: Option<SocketAddr>,
    /// Maximum concurrent relay connections (default 4096).
    #[arg(long, value_name = "N", global = true)]
    max_connections: Option<usize>,
    /// Seconds of silence before an idle connection is reaped (default 120).
    #[arg(long, value_name = "SECS", global = true)]
    idle_timeout_secs: Option<u64>,
    /// STUN Binding responses per second per source IP (default 5; 0 disables the per-IP limit).
    #[arg(long, value_name = "N", global = true)]
    stun_per_ip_rps: Option<u32>,
    /// STUN Binding responses per second across all sources (default 1000; 0 disables the cap).
    #[arg(long, value_name = "N", global = true)]
    stun_global_rps: Option<u32>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the relay in the foreground (the default if no subcommand is given).
    Serve,
    /// Install the relay as an auto-starting OS service (Windows SCM / systemd / launchd).
    Install,
    /// Uninstall the relay service.
    Uninstall,
    /// Start the installed service.
    Start,
    /// Stop the running service.
    Stop,
    /// Report whether the relay is serving (probes /health). Exit 1 if not serving.
    Status,
    /// Windows SCM entrypoint — installed by `install`; not meant to be run by hand.
    #[command(name = "run-service", hide = true)]
    RunService,
}

/// Build a [`RelayServerConfig`] from the service env (set by `install`) then apply CLI overrides.
fn config_from(cli: &Cli) -> RelayServerConfig {
    apply_overrides(service::config_from_env(), cli)
}

/// Apply a parsed [`Cli`]'s `--listen`/`--health-listen`/`--stun-listen`/`--max-connections`/
/// `--idle-timeout-secs` overrides onto a base config. PURE (takes the base explicitly, no env read)
/// so the precedence — CLI flag beats the base value, an unset flag leaves the base untouched — is
/// unit-testable.
fn apply_overrides(mut config: RelayServerConfig, cli: &Cli) -> RelayServerConfig {
    if let Some(a) = cli.listen {
        config.listen = a;
    }
    if let Some(a) = cli.health_listen {
        config.health_listen = a;
    }
    if let Some(a) = cli.stun_listen {
        config.stun_listen = a;
    }
    if let Some(n) = cli.max_connections {
        config.max_connections = n;
    }
    if let Some(s) = cli.idle_timeout_secs {
        config.idle_timeout = Duration::from_secs(s);
    }
    if let Some(n) = cli.stun_per_ip_rps {
        config.stun_per_ip_responses_per_sec = n;
    }
    if let Some(n) = cli.stun_global_rps {
        config.stun_global_responses_per_sec = n;
    }
    config
}

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let config = config_from(&cli);

    match cli.command.as_ref().unwrap_or(&Command::Serve) {
        Command::Serve => run_serve(config),
        Command::RunService => run_service_entry(config),
        Command::Install => emit(cli.json, service::install(&config)),
        Command::Uninstall => emit(cli.json, service::uninstall()),
        Command::Start => emit(cli.json, service::start()),
        Command::Stop => emit(cli.json, service::stop()),
        Command::Status => {
            // Status maps serving:false to a non-zero exit so scripts can gate on it.
            match service::status(&config) {
                Ok(o) => {
                    print_outcome(cli.json, &o);
                    if is_serving(&o) {
                        std::process::ExitCode::SUCCESS
                    } else {
                        std::process::ExitCode::from(1)
                    }
                }
                Err(e) => fail(cli.json, e),
            }
        }
    }
}

/// Did a `status` outcome report the relay as serving? PURE — reads `result.serving`, defaulting to
/// `false` when the field is absent/non-bool, so the `status` exit code is unit-testable.
fn is_serving(o: &service::Outcome) -> bool {
    o.result["serving"].as_bool().unwrap_or(false)
}

/// Run the foreground relay server on its own tokio runtime.
fn run_serve(config: RelayServerConfig) -> std::process::ExitCode {
    if let Err(e) = config.validate() {
        eprintln!("dig-relay: invalid config: {e}");
        return std::process::ExitCode::from(2);
    }
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("dig-relay: cannot start runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match rt.block_on(dig_relay::serve(config)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("dig-relay: fatal: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// The Windows SCM service entrypoint. On non-Windows there is no SCM, so `run-service` simply runs
/// the foreground server (systemd/launchd exec the process directly).
#[cfg(windows)]
fn run_service_entry(_config: RelayServerConfig) -> std::process::ExitCode {
    match dig_relay::win_service::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("dig-relay: service dispatcher error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
#[cfg(not(windows))]
fn run_service_entry(config: RelayServerConfig) -> std::process::ExitCode {
    run_serve(config)
}

/// Emit a service [`Outcome`](service::Outcome) as pretty text or JSON; map an error to exit 1.
fn emit(json: bool, result: std::io::Result<service::Outcome>) -> std::process::ExitCode {
    match result {
        Ok(o) => {
            print_outcome(json, &o);
            std::process::ExitCode::SUCCESS
        }
        Err(e) => fail(json, e),
    }
}

fn print_outcome(json: bool, o: &service::Outcome) {
    if json {
        println!("{}", outcome_line(o));
    } else {
        println!("{}", o.summary);
    }
}

/// The `--json` success envelope for a service [`Outcome`]: `{"ok":true,"result":{…}}`. PURE
/// (returns the string) so the machine-readable contract agents depend on is unit-testable.
fn outcome_line(o: &service::Outcome) -> String {
    serde_json::to_string(&serde_json::json!({ "ok": true, "result": o.result }))
        .unwrap_or_default()
}

fn fail(json: bool, e: std::io::Error) -> std::process::ExitCode {
    if json {
        println!("{}", error_line(&e.to_string()));
    } else {
        eprintln!("dig-relay: error: {e}");
    }
    std::process::ExitCode::FAILURE
}

/// The `--json` error envelope: `{"ok":false,"error":{"message":…}}`. PURE so the error contract is
/// unit-testable.
fn error_line(message: &str) -> String {
    serde_json::to_string(&serde_json::json!({ "ok": false, "error": { "message": message } }))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a `dig-relay` argv (the program name is prepended) into a [`Cli`], mirroring runtime.
    fn parse(args: &[&str]) -> Cli {
        let mut argv = vec!["dig-relay"];
        argv.extend_from_slice(args);
        Cli::try_parse_from(argv).expect("args should parse")
    }

    #[test]
    fn bare_invocation_has_no_subcommand_and_defaults_to_serve() {
        let cli = parse(&[]);
        assert!(cli.command.is_none(), "bare `dig-relay` has no subcommand");
        // main() maps a missing subcommand to Serve.
        assert!(matches!(
            cli.command.as_ref().unwrap_or(&Command::Serve),
            Command::Serve
        ));
    }

    #[test]
    fn each_service_subcommand_parses_to_its_variant() {
        assert!(matches!(parse(&["serve"]).command, Some(Command::Serve)));
        assert!(matches!(
            parse(&["install"]).command,
            Some(Command::Install)
        ));
        assert!(matches!(
            parse(&["uninstall"]).command,
            Some(Command::Uninstall)
        ));
        assert!(matches!(parse(&["start"]).command, Some(Command::Start)));
        assert!(matches!(parse(&["stop"]).command, Some(Command::Stop)));
        assert!(matches!(parse(&["status"]).command, Some(Command::Status)));
        assert!(matches!(
            parse(&["run-service"]).command,
            Some(Command::RunService)
        ));
    }

    #[test]
    fn unknown_subcommand_is_rejected() {
        assert!(Cli::try_parse_from(["dig-relay", "frobnicate"]).is_err());
    }

    #[test]
    fn invalid_listen_addr_is_rejected() {
        // --listen takes a SocketAddr; a bare host without a port is not one.
        assert!(Cli::try_parse_from(["dig-relay", "--listen", "not-an-addr"]).is_err());
    }

    #[test]
    fn invalid_max_connections_is_rejected() {
        assert!(Cli::try_parse_from(["dig-relay", "--max-connections", "lots"]).is_err());
    }

    #[test]
    fn apply_overrides_leaves_base_untouched_when_no_flags() {
        let base = RelayServerConfig {
            listen: "10.0.0.1:1111".parse().unwrap(),
            health_listen: "10.0.0.1:2222".parse().unwrap(),
            stun_listen: "10.0.0.1:3333".parse().unwrap(),
            max_connections: 7,
            idle_timeout: Duration::from_secs(33),
            ..Default::default()
        };
        let cli = parse(&["serve"]);
        let out = apply_overrides(base.clone(), &cli);
        assert_eq!(out, base, "no flags → base config is returned verbatim");
    }

    #[test]
    fn apply_overrides_applies_every_flag_over_the_base() {
        let base = RelayServerConfig::default();
        let cli = parse(&[
            "serve",
            "--listen",
            "127.0.0.1:8000",
            "--health-listen",
            "127.0.0.1:8001",
            "--stun-listen",
            "127.0.0.1:8002",
            "--max-connections",
            "10",
            "--idle-timeout-secs",
            "5",
            "--stun-per-ip-rps",
            "7",
            "--stun-global-rps",
            "500",
        ]);
        let out = apply_overrides(base, &cli);
        assert_eq!(out.listen, "127.0.0.1:8000".parse().unwrap());
        assert_eq!(out.health_listen, "127.0.0.1:8001".parse().unwrap());
        assert_eq!(out.stun_listen, "127.0.0.1:8002".parse().unwrap());
        assert_eq!(out.max_connections, 10);
        assert_eq!(out.idle_timeout, Duration::from_secs(5));
        assert_eq!(out.stun_per_ip_responses_per_sec, 7);
        assert_eq!(out.stun_global_responses_per_sec, 500);
    }

    #[test]
    fn apply_overrides_applies_only_the_flags_given() {
        // Only --max-connections set; the other fields keep the base values.
        let base = RelayServerConfig {
            listen: "10.0.0.1:1111".parse().unwrap(),
            health_listen: "10.0.0.1:2222".parse().unwrap(),
            stun_listen: "10.0.0.1:3333".parse().unwrap(),
            max_connections: 7,
            idle_timeout: Duration::from_secs(33),
            ..Default::default()
        };
        let cli = parse(&["serve", "--max-connections", "99"]);
        let out = apply_overrides(base.clone(), &cli);
        assert_eq!(out.max_connections, 99, "the one flag wins");
        assert_eq!(out.listen, base.listen, "unset flag leaves listen alone");
        assert_eq!(out.health_listen, base.health_listen);
        assert_eq!(
            out.stun_listen, base.stun_listen,
            "unset flag leaves stun alone"
        );
        assert_eq!(out.idle_timeout, base.idle_timeout);
    }

    #[test]
    fn json_flag_is_global_and_parses_with_a_subcommand() {
        let cli = parse(&["status", "--json"]);
        assert!(cli.json, "--json is a global flag");
        assert!(matches!(cli.command, Some(Command::Status)));
    }

    #[test]
    fn is_serving_reads_the_serving_field() {
        let serving = service::Outcome {
            summary: "x".into(),
            result: serde_json::json!({ "serving": true }),
        };
        let not = service::Outcome {
            summary: "x".into(),
            result: serde_json::json!({ "serving": false }),
        };
        let absent = service::Outcome {
            summary: "x".into(),
            result: serde_json::json!({}),
        };
        assert!(is_serving(&serving));
        assert!(!is_serving(&not));
        assert!(!is_serving(&absent), "absent serving field → not serving");
    }

    #[test]
    fn outcome_line_is_an_ok_envelope_wrapping_the_result() {
        let o = service::Outcome {
            summary: "ignored in json".into(),
            result: serde_json::json!({ "installed": true, "label": "x" }),
        };
        let v: serde_json::Value = serde_json::from_str(&outcome_line(&o)).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["result"]["installed"], true);
        assert_eq!(v["result"]["label"], "x");
    }

    #[test]
    fn error_line_is_a_not_ok_envelope_with_the_message() {
        let v: serde_json::Value = serde_json::from_str(&error_line("boom")).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"]["message"], "boom");
    }
}
