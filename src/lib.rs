//! DIG Relay — NAT-traversal rendezvous + circuit relay for the DIG Network L2 peer layer.
//!
//! `dig-relay` is the publicly-reachable SERVER side of the DIG relay protocol (RLY-001..RLY-007,
//! JSON over WebSocket): DIG Nodes behind NAT register a constant reservation, discover peers,
//! coordinate hole-punching, and — when a direct dial fails — exchange gossip traffic THROUGH the
//! relay as a fallback. The canonical deployment is `relay.dig.net`.
//!
//! The wire types ([`wire::RelayMessage`], [`wire::RelayPeerInfo`]) are vendored byte-identical to
//! the `dig-gossip` relay CLIENT's, so the server and client wire can never drift (pinned by
//! `tests/wire_conformance.rs`). See `DESIGN.md` for why this is the protocol-grade fit (and why
//! NOT libp2p).
//!
//! Layering: [`wire`] is the vendored relay wire types; [`config`] is pure validated configuration;
//! [`registry`] is the in-memory peer registry + pure routing decisions; [`server`] is the
//! WebSocket accept loop + per-connection task + the pure `RelayMessage` dispatcher; [`health`] is
//! the load-balancer HTTP probe; [`service`] installs/controls the relay as an OS service
//! (run-your-own-relay) and [`win_service`] is the Windows SCM dispatcher.

pub mod config;
pub mod health;
pub mod registry;
pub mod server;
pub mod service;
pub mod wire;

#[cfg(windows)]
pub mod win_service;

pub use config::RelayServerConfig;
pub use server::RelayState;

/// Start the relay: bind the WebSocket relay listener and the HTTP `/health` listener and serve
/// both until one errors (or the process is signalled). Returns the first listener error.
pub async fn serve(config: RelayServerConfig) -> std::io::Result<()> {
    serve_with_shutdown(config, std::future::pending::<()>()).await
}

/// Like [`serve`] but stops gracefully when `shutdown` resolves (used by the Windows service body,
/// which resolves it on an SCM `Stop`). Returns the first listener error, or `Ok(())` on shutdown.
pub async fn serve_with_shutdown(
    config: RelayServerConfig,
    shutdown: impl std::future::Future<Output = ()>,
) -> std::io::Result<()> {
    config
        .validate()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let state = RelayState::new(config);

    let relay = server::run(state.clone());
    let health = health::run(state.clone());

    // Whichever listener exits first (or the shutdown signal) ends serving.
    tokio::select! {
        r = relay => r,
        h = health => h,
        _ = shutdown => Ok(()),
    }
}
