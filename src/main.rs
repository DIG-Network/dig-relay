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
    /// Address the relay WebSocket listener binds (default 0.0.0.0:9450).
    #[arg(long, value_name = "ADDR", global = true)]
    listen: Option<SocketAddr>,
    /// Address the HTTP /health listener binds (default 0.0.0.0:9451).
    #[arg(long, value_name = "ADDR", global = true)]
    health_listen: Option<SocketAddr>,
    /// Maximum concurrent relay connections (default 4096).
    #[arg(long, value_name = "N", global = true)]
    max_connections: Option<usize>,
    /// Seconds of silence before an idle connection is reaped (default 120).
    #[arg(long, value_name = "SECS", global = true)]
    idle_timeout_secs: Option<u64>,
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
    let mut config = service::config_from_env();
    if let Some(a) = cli.listen {
        config.listen = a;
    }
    if let Some(a) = cli.health_listen {
        config.health_listen = a;
    }
    if let Some(n) = cli.max_connections {
        config.max_connections = n;
    }
    if let Some(s) = cli.idle_timeout_secs {
        config.idle_timeout = Duration::from_secs(s);
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
                    let serving = o.result["serving"].as_bool().unwrap_or(false);
                    print_outcome(cli.json, &o);
                    if serving {
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
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({ "ok": true, "result": o.result }))
                .unwrap_or_default()
        );
    } else {
        println!("{}", o.summary);
    }
}

fn fail(json: bool, e: std::io::Error) -> std::process::ExitCode {
    if json {
        println!(
            "{}",
            serde_json::to_string(
                &serde_json::json!({ "ok": false, "error": { "message": e.to_string() } })
            )
            .unwrap_or_default()
        );
    } else {
        eprintln!("dig-relay: error: {e}");
    }
    std::process::ExitCode::FAILURE
}
