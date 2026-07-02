//! HTTP `/health` endpoint for the AWS load-balancer target-group check.
//!
//! Kept on a SEPARATE small HTTP listener from the relay WebSocket so that, behind an NLB, the
//! HTTP health probe never collides with raw relay traffic. Returns `200` + a tiny JSON body the
//! load balancer ignores but operators/agents can read.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::{extract::State, routing::get, Json, Router};
use serde::Serialize;

use crate::net::bind_tcp_dual_stack;
use crate::server::RelayState;

/// The `/health` JSON body — self-describing, stable field names (agent-friendly).
#[derive(Debug, Clone, Serialize)]
pub struct Health {
    /// Always `"ok"` while the process is serving.
    pub status: &'static str,
    /// Number of currently-registered relay peers.
    pub connected_peers: u64,
    /// Seconds since the relay started.
    pub uptime_secs: u64,
    /// The relay server version (`CARGO_PKG_VERSION`).
    pub version: &'static str,
}

/// Build the health snapshot from shared state. Pure (no I/O) so it is unit-testable.
pub fn snapshot(state: &RelayState) -> Health {
    Health {
        status: "ok",
        connected_peers: state.connected.load(Ordering::Relaxed),
        uptime_secs: state.uptime_secs(),
        version: env!("CARGO_PKG_VERSION"),
    }
}

async fn health(State(state): State<Arc<RelayState>>) -> Json<Health> {
    Json(snapshot(&state))
}

/// Serve the health endpoint until the listener errors. Binds `state.config.health_listen`.
pub async fn run(state: Arc<RelayState>) -> std::io::Result<()> {
    let app = Router::new()
        .route("/health", get(health))
        .with_state(state.clone());
    // IPv6-first, IPv4-fallback: dual-stack bind (see `crate::net`) so the default `[::]` health
    // listener still answers the load balancer's IPv4 health check on the same socket.
    let listener = bind_tcp_dual_stack(state.config.health_listen)?;
    tracing::info!(addr = %state.config.health_listen, "dig-relay /health listening");
    axum::serve(listener, app).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RelayServerConfig;

    #[test]
    fn snapshot_reports_status_and_version() {
        let state = RelayState::new(RelayServerConfig::default());
        let h = snapshot(&state);
        assert_eq!(h.status, "ok");
        assert_eq!(h.connected_peers, 0);
        assert_eq!(h.version, env!("CARGO_PKG_VERSION"));
    }
}
