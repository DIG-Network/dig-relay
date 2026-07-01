//! Relay protocol wire types — **vendored, byte-identical** to `dig-gossip`'s
//! `src/relay/relay_types.rs` (requirements **RLY-001** through **RLY-007**).
//!
//! # Provenance
//!
//! The canonical definition of the relay wire lives in the `dig-gossip` crate
//! (`DIG-Network/dig-gossip`, `src/relay/relay_types.rs`), which also holds the matching relay
//! CLIENT. `dig-relay` is the SERVER side of the same wire. These types are copied here verbatim
//! (the `RelayMessage` `#[serde(tag = "type")]` enum and `RelayPeerInfo`) instead of depending on
//! the `dig-gossip` crate, because:
//!
//! - the wire types depend only on `serde` + `std` (no transport, no Chia stack), so vendoring is
//!   tiny and self-contained, whereas the `dig-gossip` crate pulls the entire L2 gossip/consensus/
//!   TLS dependency tree just to re-export these two structs; and
//! - the published `dig-gossip` tag does not build against the `dig-protocol` it resolves.
//!
//! **Contract:** these types MUST stay byte-identical to `dig-gossip`'s, so the server and client
//! speak the same JSON. The serde shape is pinned by `tests/wire_conformance.rs` (exact `type`
//! discriminators + field names). The superproject `SYSTEM.md` records the change-impact edge: a
//! change to the relay wire in `dig-gossip` must be mirrored here in the same unit of work.
//!
//! # Wire format
//!
//! Relay messages use **JSON** over WebSocket (not Chia's binary protocol). The
//! `#[serde(tag = "type")]` attribute produces `{"type": "register", ...}`.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Complete relay protocol message enum.
///
/// JSON-serialized over WebSocket. `#[serde(tag = "type")]` uses the variant's
/// `#[serde(rename = "...")]` as the `type` discriminator field.
///
/// SPEC §7 — "Relay messages use JSON over WebSocket."
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RelayMessage {
    // -- RLY-001: Registration --
    /// Client → Relay: register after WebSocket connect.
    #[serde(rename = "register")]
    Register {
        peer_id: String,
        network_id: String,
        protocol_version: u32,
    },

    /// Relay → Client: registration acknowledgement.
    #[serde(rename = "register_ack")]
    RegisterAck {
        success: bool,
        message: String,
        connected_peers: usize,
    },

    /// Client → Relay: graceful disconnect.
    #[serde(rename = "unregister")]
    Unregister { peer_id: String },

    // -- RLY-002: Targeted message forwarding --
    /// Client → Relay → Client: forward to specific peer.
    #[serde(rename = "relay_message")]
    RelayGossipMessage {
        from: String,
        to: String,
        payload: Vec<u8>,
        seq: u64,
    },

    // -- RLY-003: Broadcast --
    /// Client → Relay → All: broadcast to all relay peers.
    #[serde(rename = "broadcast")]
    Broadcast {
        from: String,
        payload: Vec<u8>,
        exclude: Vec<String>,
    },

    // -- Peer notifications --
    /// Relay → Client: new peer connected to relay.
    #[serde(rename = "peer_connected")]
    PeerConnected { peer: RelayPeerInfo },

    /// Relay → Client: peer disconnected from relay.
    #[serde(rename = "peer_disconnected")]
    PeerDisconnected { peer_id: String },

    // -- RLY-005: Peer list --
    /// Client → Relay: request connected peer list.
    #[serde(rename = "get_peers")]
    GetPeers { network_id: Option<String> },

    /// Relay → Client: peer list response.
    #[serde(rename = "peers")]
    Peers { peers: Vec<RelayPeerInfo> },

    // -- RLY-006: Keepalive --
    /// Bidirectional keepalive.
    #[serde(rename = "ping")]
    Ping { timestamp: u64 },

    /// Keepalive response.
    #[serde(rename = "pong")]
    Pong { timestamp: u64 },

    // -- RLY-010: Introducer announce (additive; peer advertises dialable candidate addresses) --
    /// Client → Relay: announce this peer's externally-reachable candidate addresses (e.g. the
    /// reflexive address learned via STUN, plus any configured/UPnP-mapped ports). The relay stores
    /// them against the connection's registered `peer_id`/`network_id` (re-stamped server-side, so a
    /// peer cannot announce for another id) and hands them out in `KnownPeers`, letting a requester
    /// attempt a DIRECT dial / hole-punch before falling back to relayed transport.
    #[serde(rename = "announce_peer")]
    AnnouncePeer { addrs: Vec<SocketAddr> },

    // -- RLY-011: Introducer request (additive; peer discovery WITH dialable addresses) --
    /// Client → Relay: request a sampled list of OTHER known peers and their candidate addresses.
    /// `network_id` defaults to the requester's own network; `max` bounds the sample (the relay
    /// caps it regardless). Unlike RLY-005 `GetPeers` (which returns address-less `RelayPeerInfo`),
    /// this returns dialable candidates so the requester can bootstrap the mesh directly.
    #[serde(rename = "get_known_peers")]
    GetKnownPeers {
        network_id: Option<String>,
        max: Option<usize>,
    },

    // -- RLY-012: Introducer response --
    /// Relay → Client: the sampled known-peer list, each entry carrying dialable candidate
    /// addresses. Never includes the requester itself.
    #[serde(rename = "known_peers")]
    KnownPeers { peers: Vec<KnownPeerInfo> },

    // -- RLY-007: NAT traversal --
    /// Client → Relay: request hole punch coordination.
    #[serde(rename = "hole_punch_request")]
    HolePunchRequest {
        peer_id: String,
        target_peer_id: String,
        external_addr: SocketAddr,
    },

    /// Relay → Client: hole punch coordination.
    #[serde(rename = "hole_punch_coordinate")]
    HolePunchCoordinate {
        peer_id: String,
        external_addr: SocketAddr,
    },

    /// Client → Relay: hole punch result.
    #[serde(rename = "hole_punch_result")]
    HolePunchResult { peer_id: String, success: bool },

    // -- Error --
    /// Relay → Client: error notification.
    #[serde(rename = "error")]
    Error { code: u32, message: String },
}

/// Peer info as tracked by the relay server.
///
/// SPEC §2.9 — `RelayPeerInfo`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayPeerInfo {
    pub peer_id: String,
    pub network_id: String,
    pub protocol_version: u32,
    pub connected_at: u64,
    pub last_seen: u64,
}

impl RelayPeerInfo {
    /// Build a `RelayPeerInfo` stamped with the current unix time for `connected_at`/`last_seen`.
    pub fn new(peer_id: String, network_id: String, protocol_version: u32) -> Self {
        let now = unix_secs();
        Self {
            peer_id,
            network_id,
            protocol_version,
            connected_at: now,
            last_seen: now,
        }
    }
}

/// A discoverable peer WITH its dialable candidate addresses, returned in
/// [`RelayMessage::KnownPeers`] (RLY-012, the introducer response).
///
/// This is the address-carrying counterpart to [`RelayPeerInfo`] (RLY-005, which is address-less):
/// the `peer_id` is the hex SHA-256 of the peer's TLS SubjectPublicKeyInfo DER (the same identity
/// `dig-gossip` uses), and `addrs` are the externally-reachable `host:port` candidates the peer
/// announced via [`RelayMessage::AnnouncePeer`]. A requester dials/hole-punches these directly to
/// bootstrap the mesh, only falling back to relayed transport if none connect.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnownPeerInfo {
    /// The peer's stable id (hex SHA-256 of its TLS SPKI DER), matching `dig-gossip`'s `PeerId`.
    pub peer_id: String,
    /// The network the peer registered under; routing/discovery is scoped to it.
    pub network_id: String,
    /// The peer's externally-reachable candidate addresses (dial these directly / hole-punch).
    pub addrs: Vec<SocketAddr>,
    /// Unix time (secs) the peer connected to the relay.
    pub connected_at: u64,
    /// Unix time (secs) the peer was last seen (announce/keepalive).
    pub last_seen: u64,
}

/// Current unix time in seconds (saturating). Mirrors dig-gossip's
/// `types::peer::metric_unix_timestamp_secs`.
pub(crate) fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
