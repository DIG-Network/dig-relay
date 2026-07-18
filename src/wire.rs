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
//!
//! # RLY-008 — the PEX message
//!
//! The relay's introducer role also carries the DIG Peer Exchange protocol (PEX) toward registered
//! nodes. PEX messages ride this same `type`-tagged JSON WebSocket as **RLY-008**, a purely-additive
//! binding: the `pex_handshake` / `pex_snapshot` / `pex_delta` / `pex_error` `type` tags do **not**
//! collide with any RLY-001..RLY-007 tag, so no existing relay message changes shape or meaning. The
//! PEX message type is [`dig_pex::PexMessage`], re-exported here as [`PexMessage`] so this module is
//! the single description of the whole relay wire (RLY-001..RLY-008). On this binding a PEX message
//! is one WebSocket **text** frame containing the bare JSON object (`PexMessage::to_json` /
//! `PexMessage::from_json`) — **not** the node↔node length-prefixed byte framing. The relay-side
//! embedding lives in [`crate::pex`]; the shapes + non-collision are pinned by
//! `tests/wire_conformance.rs`.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// The **RLY-008** PEX message that rides this relay wire — re-exported from `dig-pex` (its normative
/// home). See the module docs and `DESIGN.md`; the relay uses the bare-JSON text-frame form
/// (`to_json`/`from_json`), never the byte-stream framing.
pub use dig_pex::PexMessage;

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
        /// The node's advertised gossip LISTEN candidate address(es), IPv6-first (§5.2).
        ///
        /// The relay uses each candidate's PORT together with the node's observed reflexive IP to
        /// build a dialable [`RelayPeerInfo::addresses`] entry it hands to other peers, enabling the
        /// connect-leg direct-dial path (dig_ecosystem #924, B1). The host is usually the unspecified
        /// dual-stack address (`[::]`); the useful part the relay keeps is the port.
        ///
        /// Additive since protocol v1 (NC-6 soft-fork): pre-#924 peers omit it, so it defaults to
        /// empty and is skipped from serialization when empty — keeping the wire byte-identical for
        /// existing peers, which fall back to today's identity-only relayed reachability.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        listen_addrs: Vec<SocketAddr>,
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
    /// The relay-resolved dialable candidate address(es) for this peer, IPv6-first (§5.2).
    ///
    /// The relay computes these from the peer's advertised [`RelayMessage::Register`]`::listen_addrs`
    /// by substituting the peer's observed reflexive IP for any unspecified/loopback/private
    /// advertised host (keeping the advertised port), so each entry is a real `reflexive_IP:port`
    /// another node can direct-dial over the existing mTLS path (dig_ecosystem #924, B1).
    ///
    /// Additive since protocol v1 (NC-6 soft-fork): pre-#924 relays omit it, so it defaults to empty
    /// and is skipped from serialization when empty — keeping the wire byte-identical for existing
    /// relays, whose peers fall back to today's identity-only relayed reachability.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<SocketAddr>,
}

impl RelayPeerInfo {
    /// Build a `RelayPeerInfo` stamped with the current unix time for `connected_at`/`last_seen` and
    /// no resolved dialable addresses (the relay populates [`addresses`](RelayPeerInfo::addresses)
    /// when it has an observed reflexive IP for the peer).
    pub fn new(peer_id: String, network_id: String, protocol_version: u32) -> Self {
        let now = unix_secs();
        Self {
            peer_id,
            network_id,
            protocol_version,
            connected_at: now,
            last_seen: now,
            addresses: Vec::new(),
        }
    }
}

/// Current unix time in seconds (saturating). Mirrors dig-gossip's
/// `types::peer::metric_unix_timestamp_secs`.
fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
