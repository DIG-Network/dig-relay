//! In-memory peer registry — the relay's only state.
//!
//! Each connected DIG node registers a `peer_id` + `network_id` (RLY-001). The registry maps
//! `peer_id → ` a [`Peer`] holding the node's `network_id`, its [`RelayPeerInfo`], and an outbound
//! message sender (the per-connection task's channel). Routing is by `peer_id`, scoped to the
//! sender's `network_id` so two networks sharing one relay never cross over.
//!
//! The relay is an **untrusted forwarder**: it never inspects or trusts `payload` bytes (those are
//! authenticated end-to-end by the gossip layer). It only routes by id.
//!
//! Concurrency: the registry is wrapped in a `Mutex` by the server; the methods here are written to
//! hold the lock briefly (clone out the sender, drop the lock, then send) — see [`Registry`] doc.

use std::collections::HashMap;

use tokio::sync::mpsc;

use crate::wire::{RelayMessage, RelayPeerInfo};

/// A registered peer's server-side record.
pub struct Peer {
    /// The network this peer registered under (RLY-001). Routing is scoped to it.
    pub network_id: String,
    /// Public peer info, returned in `Peers`/`PeerConnected` (RLY-005).
    pub info: RelayPeerInfo,
    /// Outbound channel to this peer's connection task — the task forwards each `RelayMessage`
    /// it receives here onto the WebSocket. BOUNDED (SECURITY_AUDIT_P2P dig-relay #3): a full queue
    /// means the peer is not draining, and further sends to it are dropped rather than buffered
    /// without limit, so a slow/hostile reader cannot grow the relay heap.
    pub tx: mpsc::Sender<RelayMessage>,
}

/// The outcome of a [`Registry::register`] call — a first registration, a reconnect that reclaimed
/// a dead prior connection, or a refusal because a LIVE peer already holds the id (anti-hijack).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterOutcome {
    /// The `peer_id` was unused — a fresh registration. The caller increments the connected count.
    Registered,
    /// The `peer_id` was held by a prior connection whose channel is already CLOSED (a genuine
    /// reconnect after the old socket dropped); the stale record was replaced. The connected count
    /// is unchanged (one dead slot swapped for one live one).
    Reconnected,
    /// The `peer_id` is held by a LIVE peer (its channel is still open). The registration is REFUSED
    /// so an unauthenticated client cannot evict + impersonate an existing peer. The incumbent keeps
    /// its slot.
    Occupied,
}

/// The relay's peer registry, keyed by `peer_id`.
#[derive(Default)]
pub struct Registry {
    peers: HashMap<String, Peer>,
}

impl Registry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Registry {
            peers: HashMap::new(),
        }
    }

    /// Number of currently-registered peers (all networks).
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether the registry holds no peers.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Register a peer, refusing to evict a LIVE incumbent holding the same `peer_id`.
    ///
    /// # Security — peer-ID hijack protection (SECURITY_AUDIT_P2P dig-relay #1)
    ///
    /// The relay does not (yet) prove that a registrant owns the identity key its `peer_id` commits
    /// to (the node-class mTLS transport / signed-`Register` proof-of-possession is a coordinated
    /// cross-repo follow-up — see `SPEC.md` §3.2). Until identity is bound, a plain replace-on-collide
    /// would let ANY unauthenticated client register a `peer_id` already held by a live peer, evict
    /// the incumbent, and thereafter receive every message routed to that id — a full
    /// rendezvous-hijack and availability primitive. This method therefore treats a `peer_id` whose
    /// incumbent channel is still OPEN as occupied and REFUSES the registration
    /// ([`RegisterOutcome::Occupied`]); the live peer keeps its slot and its rendezvous.
    ///
    /// A genuine reconnect is still honoured: when the incumbent's outbound channel is already CLOSED
    /// (its connection task has torn down — `tx.is_closed()`), the stale record is reclaimed and
    /// replaced ([`RegisterOutcome::Reconnected`]). A first registration for an unused id is
    /// [`RegisterOutcome::Registered`].
    pub fn register(
        &mut self,
        peer_id: String,
        network_id: String,
        info: RelayPeerInfo,
        tx: mpsc::Sender<RelayMessage>,
    ) -> RegisterOutcome {
        if let Some(existing) = self.peers.get(&peer_id) {
            // A live incumbent holds this id: refuse (anti-hijack). Only a demonstrably-dead prior
            // connection (closed channel) may be reclaimed.
            if !existing.tx.is_closed() {
                return RegisterOutcome::Occupied;
            }
            self.peers.insert(
                peer_id,
                Peer {
                    network_id,
                    info,
                    tx,
                },
            );
            return RegisterOutcome::Reconnected;
        }
        self.peers.insert(
            peer_id,
            Peer {
                network_id,
                info,
                tx,
            },
        );
        RegisterOutcome::Registered
    }

    /// Remove a peer by id, returning its record if present.
    pub fn unregister(&mut self, peer_id: &str) -> Option<Peer> {
        self.peers.remove(peer_id)
    }

    /// Look up a peer's outbound sender, but only if it is on `network_id` (cross-network routing
    /// is never allowed). Returns a clone of the sender so the caller can release the lock first.
    pub fn sender_in_network(
        &self,
        peer_id: &str,
        network_id: &str,
    ) -> Option<mpsc::Sender<RelayMessage>> {
        self.peers
            .get(peer_id)
            .filter(|p| p.network_id == network_id)
            .map(|p| p.tx.clone())
    }

    /// The public peer list for `GetPeers` (RLY-005). When `network_id` is `Some`, only peers on
    /// that network are returned; `None` returns all. Deterministic order (sorted by `peer_id`) so
    /// the response is stable and testable.
    pub fn peers(&self, network_id: Option<&str>) -> Vec<RelayPeerInfo> {
        let mut out: Vec<RelayPeerInfo> = self
            .peers
            .values()
            .filter(|p| network_id.is_none_or(|n| p.network_id == n))
            .map(|p| p.info.clone())
            .collect();
        out.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));
        out
    }

    /// Senders to broadcast to (RLY-003): every peer on `network_id` except `from` and any id in
    /// `exclude`. Returns `(peer_id, sender)` pairs so the caller can release the lock then send.
    pub fn broadcast_targets(
        &self,
        from: &str,
        network_id: &str,
        exclude: &[String],
    ) -> Vec<(String, mpsc::Sender<RelayMessage>)> {
        self.peers
            .iter()
            .filter(|(id, p)| {
                p.network_id == network_id
                    && id.as_str() != from
                    && !exclude.iter().any(|e| e == *id)
            })
            .map(|(id, p)| (id.clone(), p.tx.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(id: &str, net: &str) -> RelayPeerInfo {
        RelayPeerInfo::new(id.to_string(), net.to_string(), 1)
    }

    /// A sender whose receiver is immediately dropped → the channel reads as CLOSED (`is_closed()`).
    /// Fine for the distinct-id registration tests that never route through it; the live/dead
    /// incumbent tests build their own channels and hold the receiver where liveness matters.
    fn chan() -> mpsc::Sender<RelayMessage> {
        mpsc::channel(8).0
    }

    #[test]
    fn register_then_lookup_in_same_network() {
        let mut r = Registry::new();
        r.register("a".into(), "net1".into(), info("a", "net1"), chan());
        assert_eq!(r.len(), 1);
        assert!(r.sender_in_network("a", "net1").is_some());
    }

    #[test]
    fn lookup_across_networks_is_denied() {
        let mut r = Registry::new();
        r.register("a".into(), "net1".into(), info("a", "net1"), chan());
        // Same peer_id but asked for under a different network → not routable.
        assert!(r.sender_in_network("a", "net2").is_none());
    }

    #[test]
    fn unregister_removes_the_peer() {
        let mut r = Registry::new();
        r.register("a".into(), "net1".into(), info("a", "net1"), chan());
        assert!(r.unregister("a").is_some());
        assert!(r.is_empty());
        assert!(r.unregister("a").is_none());
    }

    #[test]
    fn first_registration_reports_registered() {
        let mut r = Registry::new();
        assert_eq!(
            r.register("a".into(), "net1".into(), info("a", "net1"), chan()),
            RegisterOutcome::Registered
        );
        assert_eq!(r.len(), 1);
    }

    /// Anti-hijack (SECURITY_AUDIT_P2P dig-relay #1): a second registration for a `peer_id` whose
    /// incumbent connection is still LIVE must be REFUSED — never replace + drop the live peer — so an
    /// unauthenticated client cannot evict and impersonate an existing node's rendezvous.
    #[test]
    fn duplicate_id_with_a_live_incumbent_is_refused() {
        let mut r = Registry::new();
        // First registration keeps a live sender (rx held → channel stays open).
        let (tx1, _rx1) = mpsc::channel(8);
        assert_eq!(
            r.register("a".into(), "net1".into(), info("a", "net1"), tx1),
            RegisterOutcome::Registered
        );

        // A hijack attempt under the same id while the incumbent is live: refused.
        let (tx2, _rx2) = mpsc::channel(8);
        assert_eq!(
            r.register("a".into(), "net1".into(), info("a", "net1"), tx2),
            RegisterOutcome::Occupied,
            "a live incumbent must NOT be evicted by a duplicate-id register"
        );
        assert_eq!(r.len(), 1, "still exactly one peer for that id");

        // The incumbent's sender is still the one in the registry (not replaced): it can still route.
        assert!(
            r.sender_in_network("a", "net1").is_some(),
            "the original live peer keeps its slot"
        );
    }

    /// A genuine reconnect: when the incumbent's channel is CLOSED (its connection task tore down),
    /// the same id may be reclaimed. The dead record is replaced and the count is unchanged.
    #[test]
    fn duplicate_id_with_a_dead_incumbent_reconnects() {
        let mut r = Registry::new();
        let (tx1, rx1) = mpsc::channel(8);
        assert_eq!(
            r.register("a".into(), "net1".into(), info("a", "net1"), tx1),
            RegisterOutcome::Registered
        );
        // Drop the receiver → the incumbent's sender is now closed (its connection is gone).
        drop(rx1);

        let (tx2, _rx2) = mpsc::channel(8);
        assert_eq!(
            r.register("a".into(), "net1".into(), info("a", "net1"), tx2),
            RegisterOutcome::Reconnected,
            "a dead prior connection may be reclaimed by a reconnect"
        );
        assert_eq!(r.len(), 1, "still exactly one peer for that id");
    }

    #[test]
    fn peers_filters_by_network_and_is_sorted() {
        let mut r = Registry::new();
        r.register("c".into(), "net1".into(), info("c", "net1"), chan());
        r.register("a".into(), "net1".into(), info("a", "net1"), chan());
        r.register("b".into(), "net2".into(), info("b", "net2"), chan());

        let net1 = r.peers(Some("net1"));
        let ids: Vec<_> = net1.iter().map(|p| p.peer_id.as_str()).collect();
        assert_eq!(ids, vec!["a", "c"], "only net1, sorted");

        assert_eq!(r.peers(None).len(), 3, "None returns all networks");
    }

    #[test]
    fn broadcast_excludes_sender_and_excluded_and_other_networks() {
        let mut r = Registry::new();
        r.register("a".into(), "net1".into(), info("a", "net1"), chan());
        r.register("b".into(), "net1".into(), info("b", "net1"), chan());
        r.register("c".into(), "net1".into(), info("c", "net1"), chan());
        r.register("z".into(), "net2".into(), info("z", "net2"), chan());

        let targets = r.broadcast_targets("a", "net1", &["c".to_string()]);
        let ids: Vec<_> = targets.iter().map(|(id, _)| id.clone()).collect();
        // From "a" on net1, excluding "c": only "b" remains ("z" is another network).
        assert_eq!(ids, vec!["b".to_string()]);
    }
}
