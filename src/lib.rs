//! DIG Relay — NAT-traversal rendezvous + circuit relay for the DIG Network L2 peer layer.
//!
//! `dig-relay` is the publicly-reachable SERVER side of the DIG relay protocol (RLY-001..RLY-008,
//! JSON over WebSocket): DIG Nodes behind NAT register a constant reservation, discover peers,
//! coordinate hole-punching, and — when a direct dial fails — exchange gossip traffic THROUGH the
//! relay as a fallback. As its introducer role it also speaks the DIG Peer Exchange protocol (PEX)
//! toward registered nodes — **RLY-008**, a purely-additive ride on the same WebSocket. The
//! canonical deployment is `relay.dig.net`.
//!
//! The RLY-001..RLY-007 wire types ([`wire::RelayMessage`], [`wire::RelayPeerInfo`]) are vendored
//! byte-identical to the `dig-gossip` relay CLIENT's, so the server and client wire can never drift
//! (pinned by `tests/wire_conformance.rs`). RLY-008 rides `dig_pex::PexMessage` (re-exported as
//! [`wire::PexMessage`]). See `DESIGN.md` for why this is the protocol-grade fit (and why NOT libp2p).
//!
//! Layering: [`wire`] is the vendored relay wire types plus the RLY-008 PEX message; [`config`] is
//! pure validated configuration; [`registry`] is the in-memory peer registry plus pure routing
//! decisions; [`pex`] embeds the `dig-pex` `PexEngine` for the introducer PEX binding (registry
//! mirroring, per-network scoping, and the introducer-only discard rule); [`server`] is the
//! WebSocket accept loop, the per-connection task, the pure `RelayMessage` dispatcher, and the PEX
//! housekeeping tick; [`stun`] is the RFC 5389 STUN Binding responder (UDP) that tells a node its
//! reflexive address; [`health`] is the load-balancer HTTP probe; [`service`] installs/controls the
//! relay as an OS service (run-your-own-relay) and [`win_service`] is the Windows SCM dispatcher.

pub mod config;
pub mod health;
pub mod pex;
pub mod registry;
pub mod server;
pub mod service;
pub mod stun;
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
    let stun = stun::run(state.clone());

    // Whichever listener exits first (or the shutdown signal) ends serving.
    tokio::select! {
        r = relay => r,
        h = health => h,
        s = stun => s,
        _ = shutdown => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An already-bound port forces the relay listener to fail, so the `relay` arm of the select
    /// resolves with that bind error — proving the error is propagated, not swallowed.
    #[tokio::test]
    async fn serve_with_shutdown_resolves_ok_when_shutdown_fires_first() {
        // Bind free ports for the relay + health listeners (and a free UDP port for STUN) so the
        // test never collides with the default ports on a busy CI runner.
        let relay = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        drop(relay);
        let health = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let health_addr = health.local_addr().unwrap();
        drop(health);
        let stun = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stun_addr = stun.local_addr().unwrap();
        drop(stun);

        let config = RelayServerConfig {
            listen: relay_addr,
            health_listen: health_addr,
            stun_listen: stun_addr,
            ..Default::default()
        };
        // An immediately-ready shutdown future → the `shutdown` select arm wins → Ok(()).
        let out = serve_with_shutdown(config, std::future::ready(())).await;
        assert!(out.is_ok(), "shutdown-first must return Ok(()): {out:?}");
    }

    #[tokio::test]
    async fn serve_with_shutdown_rejects_an_invalid_config_before_binding() {
        let config = RelayServerConfig {
            max_connections: 0, // invalid → validate() fails before any bind
            ..Default::default()
        };
        let err = serve_with_shutdown(config, std::future::pending::<()>())
            .await
            .expect_err("invalid config must error");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn serve_with_shutdown_surfaces_a_listener_bind_error() {
        // Occupy a port, then point the relay listener at it so bind fails and the relay arm
        // resolves with the error (not a hang, not Ok).
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let busy_addr = occupied.local_addr().unwrap();
        let health = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let health_addr = health.local_addr().unwrap();
        drop(health);
        let stun = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stun_addr = stun.local_addr().unwrap();
        drop(stun);

        let config = RelayServerConfig {
            listen: busy_addr, // already bound above (still held) → relay bind fails
            health_listen: health_addr,
            stun_listen: stun_addr, // free → only the relay bind is the intended failure
            ..Default::default()
        };
        let out = serve_with_shutdown(config, std::future::pending::<()>()).await;
        assert!(out.is_err(), "a failed relay bind must surface as an error");
        drop(occupied);
    }
}
