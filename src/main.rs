//! `dig-relay` — the DIG Network NAT-traversal relay server (binary entrypoint).
//!
//! Serves the `dig_gossip` relay protocol (RLY-001..RLY-007) over WebSocket so DIG Nodes behind
//! NAT can register, discover peers, coordinate hole-punching, and fall back to relayed transport.
//! The canonical deployment is `relay.dig.net`; nodes may also run their own (installable via the
//! DIG installer). TLS is terminated at the load balancer in production (see DESIGN.md), so the
//! process speaks plain `ws://` internally.

use std::net::SocketAddr;
use std::time::Duration;

use clap::Parser;

use dig_relay::RelayServerConfig;

#[derive(Parser, Debug)]
#[command(
    name = "dig-relay",
    version,
    about = "DIG Network NAT-traversal relay (rendezvous + circuit relay)",
    long_about = "Publicly-reachable rendezvous + circuit relay for the DIG Network L2 peer layer. \
DIG Nodes behind NAT register a constant reservation, discover peers, coordinate hole-punching, and \
fall back to relayed transport through this server when a direct dial fails. Speaks the dig-gossip \
relay protocol (RLY-001..RLY-007) as JSON over WebSocket. Canonical deployment: relay.dig.net."
)]
struct Cli {
    /// Address the relay WebSocket listener binds (default 0.0.0.0:9450).
    #[arg(long, value_name = "ADDR")]
    listen: Option<SocketAddr>,

    /// Address the HTTP /health listener binds (default 0.0.0.0:9451).
    #[arg(long, value_name = "ADDR")]
    health_listen: Option<SocketAddr>,

    /// Maximum concurrent relay connections (default 4096).
    #[arg(long, value_name = "N")]
    max_connections: Option<usize>,

    /// Seconds of silence before an idle connection is reaped (default 120).
    #[arg(long, value_name = "SECS")]
    idle_timeout_secs: Option<u64>,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let mut config = RelayServerConfig::default();
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

    if let Err(e) = config.validate() {
        eprintln!("dig-relay: invalid config: {e}");
        return std::process::ExitCode::from(2);
    }

    match dig_relay::serve(config).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("dig-relay: fatal: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
