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
use std::net::SocketAddr;

use tokio::sync::mpsc;

use crate::wire::{KnownPeerInfo, RelayMessage, RelayPeerInfo};

/// A registered peer's server-side record.
pub struct Peer {
    /// The network this peer registered under (RLY-001). Routing is scoped to it.
    pub network_id: String,
    /// Public peer info, returned in `Peers`/`PeerConnected` (RLY-005).
    pub info: RelayPeerInfo,
    /// The peer's announced externally-reachable candidate addresses (RLY-010 `AnnouncePeer`),
    /// handed out in `KnownPeers` (RLY-012) so requesters can dial/hole-punch directly. Empty until
    /// the peer announces.
    pub addrs: Vec<SocketAddr>,
    /// Outbound channel to this peer's connection task — the task forwards each `RelayMessage`
    /// it receives here onto the WebSocket.
    pub tx: mpsc::UnboundedSender<RelayMessage>,
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

    /// Register (or replace) a peer. Returns the prior record if this `peer_id` was already
    /// registered (a reconnect / duplicate id) so the caller can close the stale connection.
    pub fn register(
        &mut self,
        peer_id: String,
        network_id: String,
        info: RelayPeerInfo,
        tx: mpsc::UnboundedSender<RelayMessage>,
    ) -> Option<Peer> {
        self.peers.insert(
            peer_id,
            Peer {
                network_id,
                info,
                addrs: Vec::new(),
                tx,
            },
        )
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
    ) -> Option<mpsc::UnboundedSender<RelayMessage>> {
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

    /// Record a peer's announced candidate addresses (RLY-010 `AnnouncePeer`), scoped to
    /// `network_id`. Returns `false` (a no-op) if `peer_id` is not registered on `network_id` — a
    /// peer may only announce for its own id (the caller passes the connection's registered id, so
    /// this is the network-scoping guard, mirroring `sender_in_network`). Also refreshes `last_seen`.
    pub fn announce(&mut self, peer_id: &str, network_id: &str, addrs: Vec<SocketAddr>) -> bool {
        match self.peers.get_mut(peer_id) {
            Some(p) if p.network_id == network_id => {
                p.addrs = addrs;
                p.info.last_seen = crate::wire::unix_secs();
                true
            }
            _ => false,
        }
    }

    /// The sampled known-peer list for `GetKnownPeers` (RLY-011): up to `max` OTHER peers on
    /// `network_id` (never the requester `from`, never another network), each with its announced
    /// candidate addresses. Deterministic order (sorted by `peer_id`) so the sample is stable and
    /// testable; `max` bounds the result (the server caps `max` before calling). A peer that has not
    /// announced still appears (empty `addrs`) so the requester at least learns the id to hole-punch.
    pub fn known_peers(&self, from: &str, network_id: &str, max: usize) -> Vec<KnownPeerInfo> {
        let mut out: Vec<KnownPeerInfo> = self
            .peers
            .iter()
            .filter(|(id, p)| id.as_str() != from && p.network_id == network_id)
            .map(|(id, p)| KnownPeerInfo {
                peer_id: id.clone(),
                network_id: p.network_id.clone(),
                addrs: p.addrs.clone(),
                connected_at: p.info.connected_at,
                last_seen: p.info.last_seen,
            })
            .collect();
        out.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));
        out.truncate(max);
        out
    }

    /// Senders to broadcast to (RLY-003): every peer on `network_id` except `from` and any id in
    /// `exclude`. Returns `(peer_id, sender)` pairs so the caller can release the lock then send.
    pub fn broadcast_targets(
        &self,
        from: &str,
        network_id: &str,
        exclude: &[String],
    ) -> Vec<(String, mpsc::UnboundedSender<RelayMessage>)> {
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

    fn chan() -> mpsc::UnboundedSender<RelayMessage> {
        mpsc::unbounded_channel().0
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
    fn register_same_id_returns_prior_record() {
        let mut r = Registry::new();
        assert!(r
            .register("a".into(), "net1".into(), info("a", "net1"), chan())
            .is_none());
        let prior = r.register("a".into(), "net1".into(), info("a", "net1"), chan());
        assert!(prior.is_some(), "reconnect must surface the stale record");
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
    fn announce_sets_addrs_and_is_returned_in_known_peers() {
        let mut r = Registry::new();
        r.register("a".into(), "net1".into(), info("a", "net1"), chan());
        r.register("b".into(), "net1".into(), info("b", "net1"), chan());

        let a1: std::net::SocketAddr = "203.0.113.1:9444".parse().unwrap();
        let a2: std::net::SocketAddr = "203.0.113.2:9444".parse().unwrap();
        assert!(
            r.announce("a", "net1", vec![a1, a2]),
            "announce for a known peer succeeds"
        );

        // b asks for known peers → gets a (with its announced addrs), not itself.
        let known = r.known_peers("b", "net1", 10);
        assert_eq!(known.len(), 1, "b sees only a (not itself)");
        assert_eq!(known[0].peer_id, "a");
        assert_eq!(
            known[0].addrs,
            vec![a1, a2],
            "a's announced candidate addrs are returned"
        );
    }

    #[test]
    fn announce_for_wrong_network_or_unknown_peer_fails() {
        let mut r = Registry::new();
        r.register("a".into(), "net1".into(), info("a", "net1"), chan());
        let a1: std::net::SocketAddr = "203.0.113.1:9444".parse().unwrap();
        // Wrong network → refused (can't announce for a peer id in another network).
        assert!(!r.announce("a", "net2", vec![a1]));
        // Unknown peer → refused.
        assert!(!r.announce("ghost", "net1", vec![a1]));
    }

    #[test]
    fn known_peers_excludes_self_and_other_networks() {
        let mut r = Registry::new();
        r.register("a".into(), "net1".into(), info("a", "net1"), chan());
        r.register("b".into(), "net1".into(), info("b", "net1"), chan());
        r.register("z".into(), "net2".into(), info("z", "net2"), chan());

        let ids: Vec<_> = r
            .known_peers("a", "net1", 10)
            .into_iter()
            .map(|p| p.peer_id)
            .collect();
        assert_eq!(
            ids,
            vec!["b".to_string()],
            "only same-network others; never self, never net2"
        );
    }

    #[test]
    fn known_peers_respects_the_max_bound() {
        let mut r = Registry::new();
        r.register("req".into(), "net1".into(), info("req", "net1"), chan());
        for id in ["a", "b", "c", "d", "e"] {
            r.register(id.into(), "net1".into(), info(id, "net1"), chan());
        }
        // 5 other peers exist, but max=2 caps the sample.
        assert_eq!(r.known_peers("req", "net1", 2).len(), 2);
        // max=0 → empty.
        assert!(r.known_peers("req", "net1", 0).is_empty());
        // max above the count → all others.
        assert_eq!(r.known_peers("req", "net1", 100).len(), 5);
    }

    #[test]
    fn known_peers_returns_entries_even_without_announced_addrs() {
        // A peer that registered but hasn't announced still appears (with empty addrs) so a
        // requester at least learns the peer_id exists to hole-punch toward.
        let mut r = Registry::new();
        r.register("a".into(), "net1".into(), info("a", "net1"), chan());
        r.register("b".into(), "net1".into(), info("b", "net1"), chan());
        let known = r.known_peers("b", "net1", 10);
        assert_eq!(known.len(), 1);
        assert_eq!(known[0].peer_id, "a");
        assert!(
            known[0].addrs.is_empty(),
            "no announced addrs yet → empty list"
        );
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
