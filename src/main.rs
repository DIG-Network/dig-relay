//! `dig-relay` — the DIG Network NAT-traversal relay server (binary entrypoint).
//!
//! Serves the DIG relay protocol (RLY-001..RLY-007) over WebSocket so DIG Nodes behind NAT can
//! register, discover peers, coordinate hole-punching, and fall back to relayed transport. The
//! canonical deployment is `relay.dig.net`; nodes may also run their own (installable via the DIG
//! installer, which delegates to the `install`/`start` subcommands below). By default TLS is
//! terminated at the load balancer in production (DESIGN.md), so the process speaks plain `ws://`
//! internally. Passing `--tls-cert`/`--tls-key` switches the relay to terminating mTLS itself,
//! REQUIRING a client certificate and binding `Register`'s `peer_id` to it (proof-of-possession —
//! SPEC.md §3.2/§8).
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
    /// Address the plain-HTTP→HTTPS redirect listener binds (default [::]:8080, dual-stack IPv6+IPv4;
    /// unprivileged so a non-root relay can bind it — front it at public :80 in the orchestrator).
    #[arg(long, value_name = "ADDR", global = true)]
    dashboard_listen: Option<SocketAddr>,
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
    /// Per-connection outbound queue depth (default 1024). A slow reader past this has messages dropped.
    #[arg(long, value_name = "N", global = true)]
    outbound_queue_capacity: Option<usize>,
    /// Max bytes for a single inbound WebSocket message/frame (default 262144).
    #[arg(long, value_name = "BYTES", global = true)]
    max_message_bytes: Option<usize>,
    /// Seconds an accepted connection has to Register before being dropped (default 10).
    #[arg(long, value_name = "SECS", global = true)]
    register_timeout_secs: Option<u64>,
    /// How often the periodic health sweep runs, pruning dead/half-open connections (default 30;
    /// #1382). Strictly shorter than --liveness-deadline-secs.
    #[arg(long, value_name = "SECS", global = true)]
    health_check_interval_secs: Option<u64>,
    /// Seconds of silence (no inbound frame, including the node's own RLY-006 keepalive) before the
    /// health sweep prunes a registration as dead/stale (default 90; #1382). Strictly shorter than
    /// --idle-timeout-secs, which remains the longer backstop.
    #[arg(long, value_name = "SECS", global = true)]
    liveness_deadline_secs: Option<u64>,
    /// Max concurrent OPEN connections from a single source IP (default 64; 0 disables; #1386).
    /// Must be <= --max-connections. Stops one host from monopolising the relay's global cap.
    #[arg(long, value_name = "N", global = true)]
    max_connections_per_ip: Option<u32>,
    /// RLY-001 Register attempts per second per source IP (default 10; 0 disables; #1386).
    #[arg(long, value_name = "N", global = true)]
    registrations_per_ip_per_sec: Option<u32>,
    /// Max concurrent live registrations from a single source IP (default 128; 0 disables; #1386).
    #[arg(long, value_name = "N", global = true)]
    max_registrations_per_ip: Option<u32>,
    /// Inbound frames per second per connection before it is disconnected (default 256; 0 disables;
    /// #1386).
    #[arg(long, value_name = "N", global = true)]
    messages_per_conn_per_sec: Option<u32>,
    /// Inbound bytes per second per connection before it is disconnected (default 1048576; 0
    /// disables; #1386).
    #[arg(long, value_name = "BYTES", global = true)]
    bytes_per_conn_per_sec: Option<u32>,
    /// Cumulative inbound bytes a single connection may relay before it is disconnected (default
    /// 1073741824; 0 disables; #1386).
    #[arg(long, value_name = "BYTES", global = true)]
    max_relayed_bytes_per_conn: Option<u64>,
    /// Path to the relay's own TLS certificate (PEM). Set together with --tls-key to make the relay
    /// terminate mTLS itself: every client MUST present a certificate, and a `Register`'s `peer_id`
    /// must match the one derived from it (proof-of-possession, SPEC.md §3.2/§8). Unset (default):
    /// the relay speaks plain ws:// (TLS terminated upstream, e.g. the relay.dig.net load balancer).
    #[arg(long, value_name = "PATH", global = true)]
    tls_cert: Option<std::path::PathBuf>,
    /// Path to the relay's own TLS private key (PEM), paired with --tls-cert.
    #[arg(long, value_name = "PATH", global = true)]
    tls_key: Option<std::path::PathBuf>,
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
    if let Some(a) = cli.dashboard_listen {
        config.dashboard_listen = a;
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
    if let Some(n) = cli.outbound_queue_capacity {
        config.outbound_queue_capacity = n;
    }
    if let Some(n) = cli.max_message_bytes {
        config.max_message_bytes = n;
    }
    if let Some(s) = cli.register_timeout_secs {
        config.register_timeout = Duration::from_secs(s);
    }
    if let Some(s) = cli.health_check_interval_secs {
        config.health_check_interval = Duration::from_secs(s);
    }
    if let Some(s) = cli.liveness_deadline_secs {
        config.liveness_deadline = Duration::from_secs(s);
    }
    if let Some(n) = cli.max_connections_per_ip {
        config.max_connections_per_ip = n;
    }
    if let Some(n) = cli.registrations_per_ip_per_sec {
        config.registrations_per_ip_per_sec = n;
    }
    if let Some(n) = cli.max_registrations_per_ip {
        config.max_registrations_per_ip = n;
    }
    if let Some(n) = cli.messages_per_conn_per_sec {
        config.messages_per_conn_per_sec = n;
    }
    if let Some(n) = cli.bytes_per_conn_per_sec {
        config.bytes_per_conn_per_sec = n;
    }
    if let Some(n) = cli.max_relayed_bytes_per_conn {
        config.max_relayed_bytes_per_conn = n;
    }
    if let Some(p) = cli.tls_cert.clone() {
        config.tls_cert_path = Some(p);
    }
    if let Some(p) = cli.tls_key.clone() {
        config.tls_key_path = Some(p);
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
            "--dashboard-listen",
            "127.0.0.1:8080",
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
            "--outbound-queue-capacity",
            "256",
            "--max-message-bytes",
            "4096",
            "--register-timeout-secs",
            "3",
            "--health-check-interval-secs",
            "15",
            "--liveness-deadline-secs",
            "45",
            "--max-connections-per-ip",
            "8",
            "--registrations-per-ip-per-sec",
            "3",
            "--max-registrations-per-ip",
            "16",
            "--messages-per-conn-per-sec",
            "64",
            "--bytes-per-conn-per-sec",
            "2048",
            "--max-relayed-bytes-per-conn",
            "4096",
        ]);
        let out = apply_overrides(base, &cli);
        assert_eq!(out.listen, "127.0.0.1:8000".parse().unwrap());
        assert_eq!(out.health_listen, "127.0.0.1:8001".parse().unwrap());
        assert_eq!(out.dashboard_listen, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(out.stun_listen, "127.0.0.1:8002".parse().unwrap());
        assert_eq!(out.max_connections, 10);
        assert_eq!(out.idle_timeout, Duration::from_secs(5));
        assert_eq!(out.stun_per_ip_responses_per_sec, 7);
        assert_eq!(out.stun_global_responses_per_sec, 500);
        assert_eq!(out.outbound_queue_capacity, 256);
        assert_eq!(out.max_message_bytes, 4096);
        assert_eq!(out.register_timeout, Duration::from_secs(3));
        assert_eq!(out.health_check_interval, Duration::from_secs(15));
        assert_eq!(out.liveness_deadline, Duration::from_secs(45));
        assert_eq!(out.max_connections_per_ip, 8);
        assert_eq!(out.registrations_per_ip_per_sec, 3);
        assert_eq!(out.max_registrations_per_ip, 16);
        assert_eq!(out.messages_per_conn_per_sec, 64);
        assert_eq!(out.bytes_per_conn_per_sec, 2048);
        assert_eq!(out.max_relayed_bytes_per_conn, 4096);
    }

    /// #1386: the abuse-limit flags are unset by default → the base config's values are preserved
    /// (each is `Option::None` unless the operator passes the flag).
    #[test]
    fn apply_overrides_leaves_abuse_limits_alone_when_no_flags() {
        let base = RelayServerConfig::default();
        let cli = parse(&["serve"]);
        let out = apply_overrides(base.clone(), &cli);
        assert_eq!(out.max_connections_per_ip, base.max_connections_per_ip);
        assert_eq!(
            out.registrations_per_ip_per_sec,
            base.registrations_per_ip_per_sec
        );
        assert_eq!(out.max_registrations_per_ip, base.max_registrations_per_ip);
        assert_eq!(
            out.messages_per_conn_per_sec,
            base.messages_per_conn_per_sec
        );
        assert_eq!(out.bytes_per_conn_per_sec, base.bytes_per_conn_per_sec);
        assert_eq!(
            out.max_relayed_bytes_per_conn,
            base.max_relayed_bytes_per_conn
        );
    }

    #[test]
    fn apply_overrides_applies_health_sweep_flags_only_when_given() {
        let base = RelayServerConfig::default();
        let cli = parse(&["serve"]);
        let out = apply_overrides(base.clone(), &cli);
        assert_eq!(
            out.health_check_interval, base.health_check_interval,
            "unset flag leaves the base health_check_interval alone"
        );
        assert_eq!(
            out.liveness_deadline, base.liveness_deadline,
            "unset flag leaves the base liveness_deadline alone"
        );
    }

    #[test]
    fn apply_overrides_applies_tls_cert_and_key_paths() {
        let base = RelayServerConfig::default();
        let cli = parse(&[
            "serve",
            "--tls-cert",
            "/etc/dig-relay/cert.pem",
            "--tls-key",
            "/etc/dig-relay/key.pem",
        ]);
        let out = apply_overrides(base, &cli);
        assert_eq!(
            out.tls_cert_path,
            Some(std::path::PathBuf::from("/etc/dig-relay/cert.pem"))
        );
        assert_eq!(
            out.tls_key_path,
            Some(std::path::PathBuf::from("/etc/dig-relay/key.pem"))
        );
    }

    #[test]
    fn apply_overrides_leaves_tls_paths_unset_when_no_flags() {
        let base = RelayServerConfig::default();
        let cli = parse(&["serve"]);
        let out = apply_overrides(base, &cli);
        assert!(out.tls_cert_path.is_none());
        assert!(out.tls_key_path.is_none());
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
