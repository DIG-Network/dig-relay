//! Relay-side **Peer Exchange (PEX)** — the introducer binding, **RLY-008**.
//!
//! The relay embeds the transport-agnostic, sans-IO [`dig_pex::PexEngine`] and speaks PEX in its
//! **introducer** role toward registered nodes, riding the existing `RelayMessage` WebSocket as a
//! purely-additive message set (RLY-008 — see `DESIGN.md`). This module is the thin I/O-adapter the
//! server calls; all of the protocol (wire, caps, timing, state machine, first-hand rule) lives in
//! `dig-pex` (SPEC §10.2 + Appendix A). The relay only ever advertises peers it knows **first-hand**
//! — i.e. currently registered — and **never** folds inbound node-sent PEX data into what it
//! advertises (an introducer is not a gossip amplifier).
//!
//! ## Registry mirroring (SPEC §10.2, Appendix A step 3)
//!
//! The relay MIRRORS its registry into the engine: on register → [`PexRelay::on_register`]
//! (`upsert_known` with `via: introducer`, the observed reflexive address, and the `relay-only`
//! flag); on unregister / disconnect / liveness-timeout → [`PexRelay::on_unregister`]
//! (`remove_known` + `link_down`). Registration **is** the relay's first-hand evidence; `last_seen`
//! is the registrant's relay-connection liveness.
//!
//! ## Network scoping
//!
//! PEX is scoped to a node's registered `network_id` exactly like every other relay route. This is
//! enforced structurally by keeping **one [`PexEngine`] per `network_id`** — an engine only ever
//! knows (and therefore only advertises) that one network's registrants, so a node on network A can
//! never receive network B's peers.
//!
//! ## Introducer-only (the discard rule)
//!
//! A node's own `pex_handshake` is a capability signal; a node SHOULD NOT send data messages to the
//! relay, and the relay MUST NOT fold node-sent PEX entries into its introducer registry (a PEX hint
//! must never impersonate a registration). Inbound node data messages are still fed to the engine so
//! the relay enforces the anti-flood rate floor (SPEC §6.4) against a chatty node, but the resulting
//! candidate/dropped events are **discarded** — only advisory `pex_error` replies flow back.

use std::collections::HashMap;
use std::net::SocketAddr;

use tokio::sync::mpsc::UnboundedSender;

use dig_pex::{
    Address, AddressKind, PeerEntry, PexConfig, PexEngine, PexErrorCode, PexMessage, Provenance,
};

/// The relay engine's internal `local_peer_id`. It is used only to exclude "self" from the engine's
/// advertise set and receive path; it is **never** put on the wire (PEX identity is the transport
/// identity — the registered `peer_id`). It is deliberately **not** `<64hex>` so it can never collide
/// with a real registrant's `peer_id`, and so it is never accidentally advertised.
const INTRODUCER_LOCAL_ID: &str = "dig-relay-introducer";

/// The relay's own capability flag, sent in its `pex_handshake` (SPEC §3.2 `introducer`).
const FLAG_INTRODUCER: &str = "introducer";

/// The per-entry flag the relay stamps on every registrant: the relay never learns a node's direct
/// inbound path from an RLY-001 `Register` (which carries no address) — only the reflexive source of
/// its WebSocket — so a node is reachable via relay rendezvous by `peer_id` (SPEC §3.2 `relay-only`).
const FLAG_RELAY_ONLY: &str = "relay-only";

/// The relay's PEX subsystem: one [`PexEngine`] per `network_id`, plus the per-connection PEX
/// outbound senders used to route tick-driven output to the right WebSocket.
///
/// The server holds this behind a `Mutex`. Every method is synchronous and cheap (map ops + engine
/// calls); the lock is held only for the call.
#[derive(Debug, Default)]
pub struct PexRelay {
    /// One engine per `network_id` — the structural enforcement of per-network scoping. Created
    /// lazily on the first registration for a network.
    engines: HashMap<String, PexEngine>,
    /// `peer_id → ` that connection's PEX outbound sender (the writer's PEX channel). Keyed by
    /// `peer_id` (globally unique across the relay, mirroring the registry's own keying), so
    /// [`tick`](Self::tick) can route each engine output `(peer_id, message)` to the matching socket.
    conns: HashMap<String, UnboundedSender<PexMessage>>,
}

impl PexRelay {
    /// Create an empty PEX relay (no networks, no connections).
    #[must_use]
    pub fn new() -> Self {
        PexRelay::default()
    }

    /// The engine for `network_id`, creating it (as the introducer) on first use.
    fn engine_for(&mut self, network_id: &str) -> &mut PexEngine {
        self.engines.entry(network_id.to_string()).or_insert_with(|| {
            PexEngine::new(
                PexConfig::new(INTRODUCER_LOCAL_ID, network_id)
                    .with_flags(vec![FLAG_INTRODUCER.to_string()]),
            )
        })
    }

    /// Mirror a registration into the introducer's first-hand set (SPEC §10.2, Appendix A step 3).
    /// The registrant becomes advertisable to every other same-network PEX subscriber; `pex_tx` is
    /// retained so tick-driven deltas/snapshots can be routed to this connection.
    ///
    /// `observed` is the socket address the relay sees for the connection (its reflexive source) and
    /// `now_ms` the current Unix-epoch milliseconds. Called for **every** registration — a legacy
    /// node that never speaks PEX is still a real registrant others must learn about.
    pub fn on_register(
        &mut self,
        peer_id: &str,
        network_id: &str,
        observed: SocketAddr,
        pex_tx: UnboundedSender<PexMessage>,
        now_ms: u64,
    ) {
        let entry = introducer_entry(peer_id, network_id, observed, now_ms / 1000);
        self.engine_for(network_id).upsert_known(entry);
        self.conns.insert(peer_id.to_string(), pex_tx);
    }

    /// Mirror an unregister / disconnect / liveness-timeout (SPEC §10.2, Appendix A step 3): drop the
    /// peer from the advertise set (surfacing as `dropped` in the next delta on links that were told
    /// it) and discard its own link state.
    pub fn on_unregister(&mut self, peer_id: &str, network_id: &str) {
        if let Some(engine) = self.engines.get_mut(network_id) {
            engine.remove_known(peer_id);
            engine.link_down(peer_id);
        }
        self.conns.remove(peer_id);
    }

    /// The node sent its `pex_handshake` — the RLY-008 capability signal (SPEC §10.2). Process the
    /// node's handshake (records its interval / advances its receiver state, or mutes the direction
    /// on a version/network mismatch), and — unless muted — bring our sending direction up: our
    /// `pex_handshake` followed by a `pex_snapshot` of the OTHER same-network registrants. Returns
    /// the messages to send back to this node on its PEX channel (identity is the transport
    /// `peer_id`, never a wire field).
    pub fn on_node_handshake(
        &mut self,
        peer_id: &str,
        network_id: &str,
        msg: PexMessage,
        now_ms: u64,
    ) -> Vec<PexMessage> {
        let engine = self.engine_for(network_id);
        let outcome = engine.on_message(peer_id, msg, now_ms);
        if engine.is_muted(peer_id) {
            // Incompatible peer (unsupported version / wrong network) — do NOT advertise to it; PEX
            // is an optional overlay, so we only relay the advisory pex_error and stay silent.
            return outcome.replies;
        }
        let mut out = engine.link_up(peer_id, now_ms);
        out.extend(outcome.replies);
        out
    }

    /// A subsequent inbound PEX message from a node whose PEX is already active. The engine validates
    /// and rate-limits it, but its candidate/dropped events are **discarded** — the introducer
    /// registry is registration-backed only and MUST NEVER fold node-sent PEX peer data (SPEC §10.2).
    /// Only advisory `pex_error` replies (rate/oversize/protocol violations) flow back to the node.
    pub fn on_node_message(
        &mut self,
        peer_id: &str,
        network_id: &str,
        msg: PexMessage,
        now_ms: u64,
    ) -> Vec<PexMessage> {
        match self.engines.get_mut(network_id) {
            // `.replies` only — the `.events` (candidates/dropped) are dropped on the floor.
            Some(engine) => engine.on_message(peer_id, msg, now_ms).replies,
            None => Vec::new(),
        }
    }

    /// An undecodable but `pex_`-typed frame from an active node — a `PEX_BAD_MESSAGE` (SPEC §7.3).
    /// Count a strike (muting the direction at the limit) and relay the advisory `pex_error`.
    pub fn on_node_bad_frame(
        &mut self,
        peer_id: &str,
        network_id: &str,
        now_ms: u64,
    ) -> Vec<PexMessage> {
        match self.engines.get_mut(network_id) {
            Some(engine) => engine
                .record_violation(peer_id, PexErrorCode::BadMessage, now_ms)
                .replies,
            None => Vec::new(),
        }
    }

    /// Drive every engine's send cadence (call ~1/s) and route each per-link output to the matching
    /// WebSocket via the retained PEX sender (SPEC §6, Appendix A step 4). A link that has not sent
    /// `pex_handshake` has no snapshot and so is never emitted to; a peer that dropped between
    /// computing and routing is skipped.
    pub fn tick(&mut self, now_ms: u64) {
        let mut routed: Vec<(String, PexMessage)> = Vec::new();
        for engine in self.engines.values_mut() {
            routed.extend(engine.tick(now_ms));
        }
        for (peer_id, msg) in routed {
            if let Some(tx) = self.conns.get(&peer_id) {
                let _ = tx.send(msg);
            }
        }
    }

    // ---- observability accessors (tests / diagnostics) ----

    /// The size of the introducer's advertise set for `network_id` (registrants known first-hand).
    #[must_use]
    pub fn known_count(&self, network_id: &str) -> usize {
        self.engines.get(network_id).map_or(0, PexEngine::known_count)
    }

    /// The number of live PEX links (handshaked subscribers) for `network_id`.
    #[must_use]
    pub fn link_count(&self, network_id: &str) -> usize {
        self.engines.get(network_id).map_or(0, PexEngine::link_count)
    }

    /// The number of registered connections with a retained PEX sender (all networks).
    #[must_use]
    pub fn conn_count(&self) -> usize {
        self.conns.len()
    }
}

/// Build the introducer's first-hand entry for a registrant (SPEC §10.2). `via: introducer`,
/// `last_seen` = the registrant's relay-connection liveness (now), the relay-observed **reflexive**
/// address as a best-effort hole-punch hint, and the **`relay-only`** flag — the relay never learns
/// a node's direct inbound listener from RLY-001 registration (which carries no address), only the
/// reflexive source of its WebSocket, so the authoritative way to reach the node is relay rendezvous
/// by `peer_id`.
fn introducer_entry(
    peer_id: &str,
    network_id: &str,
    observed: SocketAddr,
    now_secs: u64,
) -> PeerEntry {
    PeerEntry::new(peer_id, network_id, now_secs, Provenance::Introducer)
        .with_address(Address::new(
            observed.ip().to_string(),
            observed.port(),
            AddressKind::Reflexive,
        ))
        .with_flag(FLAG_RELAY_ONLY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc::{self, UnboundedReceiver};

    /// A `<64hex>` peer id from a byte (each byte repeated 32× → 64 hex chars).
    fn hex(b: u8) -> String {
        format!("{b:02x}").repeat(32)
    }

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    /// A node's `pex_handshake` on `network_id`, version 1, default interval.
    fn node_handshake(network_id: &str) -> PexMessage {
        PexMessage::PexHandshake {
            version: 1,
            network_id: network_id.into(),
            interval: 60,
            flags: vec![],
        }
    }

    fn chan() -> (UnboundedSender<PexMessage>, UnboundedReceiver<PexMessage>) {
        mpsc::unbounded_channel()
    }

    /// Drain everything currently queued on a receiver (non-blocking).
    fn drain(rx: &mut UnboundedReceiver<PexMessage>) -> Vec<PexMessage> {
        let mut out = Vec::new();
        while let Ok(m) = rx.try_recv() {
            out.push(m);
        }
        out
    }

    fn snapshot_ids(msg: &PexMessage) -> Vec<String> {
        match msg {
            PexMessage::PexSnapshot { peers } => peers.iter().map(|p| p.peer_id.clone()).collect(),
            other => panic!("expected pex_snapshot, got {other:?}"),
        }
    }

    #[test]
    fn handshake_yields_our_handshake_then_a_snapshot_of_other_peers_not_self() {
        let mut pex = PexRelay::new();
        let (a, b) = (hex(0x0a), hex(0x0b));
        pex.on_register(&a, "net", addr(4001), chan().0, 1_000_000);
        pex.on_register(&b, "net", addr(4002), chan().0, 1_000_000);

        // A subscribes.
        let out = pex.on_node_handshake(&a, "net", node_handshake("net"), 1_000_000);
        assert!(
            matches!(out[0], PexMessage::PexHandshake { .. }),
            "first reply is our handshake"
        );
        let ids = snapshot_ids(&out[1]);
        assert_eq!(ids, vec![b.clone()], "snapshot has the OTHER peer, not A itself");
    }

    #[test]
    fn snapshot_is_scoped_to_the_links_network() {
        let mut pex = PexRelay::new();
        let (a, b, z) = (hex(0x0a), hex(0x0b), hex(0x0c));
        pex.on_register(&a, "netX", addr(4001), chan().0, 1_000_000);
        pex.on_register(&b, "netX", addr(4002), chan().0, 1_000_000);
        // A peer on a DIFFERENT network — must never appear in netX's snapshot.
        pex.on_register(&z, "netY", addr(4003), chan().0, 1_000_000);

        let out = pex.on_node_handshake(&a, "netX", node_handshake("netX"), 1_000_000);
        let ids = snapshot_ids(&out[1]);
        assert_eq!(ids, vec![b.clone()], "only same-network peers; Z (netY) excluded");
        assert!(!ids.contains(&z), "cross-network peer must not leak");
    }

    #[test]
    fn a_new_registration_surfaces_as_an_added_delta_on_tick() {
        let mut pex = PexRelay::new();
        let (a, b, c) = (hex(0x0a), hex(0x0b), hex(0x0c));
        let (atx, mut arx) = chan();
        pex.on_register(&a, "net", addr(4001), atx, 1_000_000);
        pex.on_register(&b, "net", addr(4002), chan().0, 1_000_000);
        // A subscribes and receives its snapshot back on its own channel via on_node_handshake's
        // return (routed by the server); here we assert the tick-driven DELTA path.
        let _ = pex.on_node_handshake(&a, "net", node_handshake("net"), 1_000_000);

        // C registers AFTER A's snapshot → it must arrive as an `added` delta on the next tick.
        pex.on_register(&c, "net", addr(4003), chan().0, 1_050_000);
        // Tick far past the effective interval + max jitter so eligibility is deterministic.
        pex.tick(1_000_000 + 3_600_000);

        let msgs = drain(&mut arx);
        let delta = msgs
            .iter()
            .find(|m| matches!(m, PexMessage::PexDelta { .. }))
            .expect("A receives a delta");
        match delta {
            PexMessage::PexDelta { added, dropped } => {
                let ids: Vec<_> = added.iter().map(|e| e.peer_id.clone()).collect();
                assert_eq!(ids, vec![c.clone()], "added carries the new registrant C");
                assert!(dropped.is_empty());
            }
            other => panic!("expected pex_delta, got {other:?}"),
        }
    }

    #[test]
    fn an_unregister_surfaces_as_a_dropped_delta_on_tick() {
        let mut pex = PexRelay::new();
        let (a, b, c) = (hex(0x0a), hex(0x0b), hex(0x0c));
        let (atx, mut arx) = chan();
        pex.on_register(&a, "net", addr(4001), atx, 1_000_000);
        pex.on_register(&b, "net", addr(4002), chan().0, 1_000_000);
        pex.on_register(&c, "net", addr(4003), chan().0, 1_000_000);
        // A's snapshot told it about B and C.
        let out = pex.on_node_handshake(&a, "net", node_handshake("net"), 1_000_000);
        let told = snapshot_ids(&out[1]);
        assert!(told.contains(&b) && told.contains(&c), "snapshot told A of B and C");

        // C leaves → next tick must drop it on A's link.
        pex.on_unregister(&c, "net");
        pex.tick(1_000_000 + 3_600_000);

        let msgs = drain(&mut arx);
        let delta = msgs
            .iter()
            .find(|m| matches!(m, PexMessage::PexDelta { .. }))
            .expect("A receives a delta");
        match delta {
            PexMessage::PexDelta { added, dropped } => {
                assert!(added.is_empty());
                assert_eq!(dropped, &vec![c.clone()], "dropped carries the departed C");
            }
            other => panic!("expected pex_delta, got {other:?}"),
        }
    }

    #[test]
    fn inbound_node_pex_data_is_never_folded_into_the_introducer_set() {
        // The introducer-only discard rule (SPEC §10.2): a node advertising a peer to the relay must
        // NOT cause the relay to re-advertise that peer to others.
        let mut pex = PexRelay::new();
        let (a, b, injected) = (hex(0x0a), hex(0x0b), hex(0x0f));
        pex.on_register(&a, "net", addr(4001), chan().0, 1_000_000);
        pex.on_register(&b, "net", addr(4002), chan().0, 1_000_000);
        assert_eq!(pex.known_count("net"), 2, "only the two registrants are known");

        // A activates PEX, then sends a snapshot advertising a NEW (valid, fresh) peer `injected`.
        let _ = pex.on_node_handshake(&a, "net", node_handshake("net"), 1_000_000);
        let node_snapshot = PexMessage::PexSnapshot {
            peers: vec![PeerEntry::new(injected.clone(), "net", 1000, Provenance::Direct)
                .with_address(Address::direct("203.0.113.9", 9444))],
        };
        let replies = pex.on_node_message(&a, "net", node_snapshot, 1_000_000);
        assert!(replies.is_empty(), "a well-formed node snapshot yields no error reply");

        // The injected peer is NOT in the advertise set …
        assert_eq!(
            pex.known_count("net"),
            2,
            "node-sent PEX data must not grow the introducer's first-hand set"
        );
        // … and never appears in another node's snapshot.
        let out = pex.on_node_handshake(&b, "net", node_handshake("net"), 1_000_000);
        let b_told = snapshot_ids(&out[1]);
        assert_eq!(b_told, vec![a.clone()], "B learns only A — never the injected peer");
        assert!(!b_told.contains(&injected));
    }

    #[test]
    fn tick_only_routes_to_handshaked_links() {
        let mut pex = PexRelay::new();
        let (a, b, c) = (hex(0x0a), hex(0x0b), hex(0x0c));
        let (atx, mut arx) = chan();
        let (btx, mut brx) = chan();
        pex.on_register(&a, "net", addr(4001), atx, 1_000_000);
        pex.on_register(&b, "net", addr(4002), btx, 1_000_000);
        // Only A subscribes; B is a legacy (non-PEX) node.
        let _ = pex.on_node_handshake(&a, "net", node_handshake("net"), 1_000_000);

        pex.on_register(&c, "net", addr(4003), chan().0, 1_050_000);
        pex.tick(1_000_000 + 3_600_000);

        assert!(
            drain(&mut arx).iter().any(|m| matches!(m, PexMessage::PexDelta { .. })),
            "the subscribed node A gets a delta"
        );
        assert!(
            drain(&mut brx).is_empty(),
            "a node that never sent pex_handshake receives no PEX"
        );
    }

    #[test]
    fn unregister_clears_the_connection_and_the_known_entry() {
        let mut pex = PexRelay::new();
        let a = hex(0x0a);
        pex.on_register(&a, "net", addr(4001), chan().0, 1_000_000);
        assert_eq!(pex.conn_count(), 1);
        assert_eq!(pex.known_count("net"), 1);

        pex.on_unregister(&a, "net");
        assert_eq!(pex.conn_count(), 0);
        assert_eq!(pex.known_count("net"), 0);
    }

    #[test]
    fn an_unsupported_version_handshake_mutes_and_only_returns_an_error() {
        let mut pex = PexRelay::new();
        let a = hex(0x0a);
        pex.on_register(&a, "net", addr(4001), chan().0, 1_000_000);

        let bad = PexMessage::PexHandshake {
            version: 2, // unsupported
            network_id: "net".into(),
            interval: 60,
            flags: vec![],
        };
        let out = pex.on_node_handshake(&a, "net", bad, 1_000_000);
        assert_eq!(out.len(), 1, "no handshake/snapshot to an incompatible peer");
        match &out[0] {
            PexMessage::PexError { code, .. } => {
                assert_eq!(*code, PexErrorCode::UnsupportedVersion.as_u16())
            }
            other => panic!("expected pex_error(2), got {other:?}"),
        }
    }

    #[test]
    fn a_network_mismatch_handshake_mutes_and_only_returns_an_error() {
        let mut pex = PexRelay::new();
        let a = hex(0x0a);
        pex.on_register(&a, "net", addr(4001), chan().0, 1_000_000);

        // Registered on "net" but the PEX handshake claims a different network.
        let out = pex.on_node_handshake(&a, "net", node_handshake("other"), 1_000_000);
        assert_eq!(out.len(), 1);
        match &out[0] {
            PexMessage::PexError { code, .. } => {
                assert_eq!(*code, PexErrorCode::NetworkMismatch.as_u16())
            }
            other => panic!("expected pex_error(5), got {other:?}"),
        }
    }

    #[test]
    fn a_bad_node_frame_strikes_and_returns_an_error() {
        let mut pex = PexRelay::new();
        let a = hex(0x0a);
        pex.on_register(&a, "net", addr(4001), chan().0, 1_000_000);
        let _ = pex.on_node_handshake(&a, "net", node_handshake("net"), 1_000_000);

        let replies = pex.on_node_bad_frame(&a, "net", 1_000_000);
        match replies.as_slice() {
            [PexMessage::PexError { code, .. }] => {
                assert_eq!(*code, PexErrorCode::BadMessage.as_u16())
            }
            other => panic!("expected a single pex_error(1), got {other:?}"),
        }
    }

    #[test]
    fn introducer_entry_carries_reflexive_address_and_relay_only_flag() {
        let a = hex(0x0a);
        let e = introducer_entry(&a, "net", addr(5555), 1000);
        assert_eq!(e.via, Provenance::Introducer);
        assert_eq!(e.last_seen, 1000);
        assert_eq!(e.addresses.len(), 1);
        assert_eq!(e.addresses[0].kind, AddressKind::Reflexive);
        assert_eq!(e.addresses[0].port, 5555);
        assert!(e.flags.iter().any(|f| f == FLAG_RELAY_ONLY));
    }
}
