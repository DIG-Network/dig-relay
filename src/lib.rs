//! DIG Relay — NAT-traversal rendezvous + circuit relay for the DIG Network L2 peer layer.
//!
//! `dig-relay` is the publicly-reachable SERVER side of the `dig_gossip` relay protocol
//! (RLY-001..RLY-007, JSON over WebSocket): DIG Nodes behind NAT register a constant reservation,
//! discover peers, coordinate hole-punching, and — when a direct dial fails — exchange gossip
//! traffic THROUGH the relay as a fallback. The canonical deployment is `relay.dig.net`.
//!
//! The wire types ([`dig_gossip::RelayMessage`], [`dig_gossip::RelayPeerInfo`]) are imported from
//! `dig-gossip`, which holds the matching CLIENT — so the server and client wire can never drift.
//! See `DESIGN.md` for why this is the protocol-grade fit (and why NOT libp2p).
//!
//! Layering: [`wire`] is the vendored relay wire types (byte-identical to dig-gossip); [`config`]
//! is pure validated configuration; [`registry`] is the in-memory peer registry + pure routing
//! decisions; [`server`] is the WebSocket accept loop + per-connection task + the pure
//! `RelayMessage` dispatcher; [`health`] is the load-balancer HTTP probe.

pub mod config;
pub mod health;
pub mod registry;
pub mod server;
pub mod wire;

pub use config::RelayServerConfig;
pub use server::RelayState;

/// Start the relay: bind the WebSocket relay listener and the HTTP `/health` listener and serve
/// both until one errors (or the process is signalled). Returns the first listener error.
pub async fn serve(config: RelayServerConfig) -> std::io::Result<()> {
    config
        .validate()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let state = RelayState::new(config);

    let relay = server::run(state.clone());
    let health = health::run(state.clone());

    // Whichever listener exits first ends the process; both are long-lived.
    tokio::select! {
        r = relay => r,
        h = health => h,
    }
}
