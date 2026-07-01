//! Conformance test pinning the relay wire (`src/wire.rs`) to the canonical dig-gossip shape.
//!
//! The vendored `RelayMessage`/`RelayPeerInfo` types MUST serialize to the exact JSON the
//! dig-gossip relay CLIENT emits/expects, or the server and client cannot talk. This test freezes
//! the `type` discriminators and field names so an accidental rename here fails CI loudly.

use dig_relay::wire::{KnownPeerInfo, RelayMessage, RelayPeerInfo};

fn json(m: &RelayMessage) -> serde_json::Value {
    serde_json::to_value(m).unwrap()
}

#[test]
fn register_shape() {
    let v = json(&RelayMessage::Register {
        peer_id: "a".into(),
        network_id: "DIG_MAINNET".into(),
        protocol_version: 1,
    });
    assert_eq!(v["type"], "register");
    assert_eq!(v["peer_id"], "a");
    assert_eq!(v["network_id"], "DIG_MAINNET");
    assert_eq!(v["protocol_version"], 1);
}

#[test]
fn register_ack_shape() {
    let v = json(&RelayMessage::RegisterAck {
        success: true,
        message: "registered".into(),
        connected_peers: 3,
    });
    assert_eq!(v["type"], "register_ack");
    assert_eq!(v["success"], true);
    assert_eq!(v["message"], "registered");
    assert_eq!(v["connected_peers"], 3);
}

#[test]
fn relay_message_shape() {
    let v = json(&RelayMessage::RelayGossipMessage {
        from: "a".into(),
        to: "b".into(),
        payload: vec![1, 2],
        seq: 9,
    });
    // The dig-gossip variant `RelayGossipMessage` serializes under `type:"relay_message"`.
    assert_eq!(v["type"], "relay_message");
    assert_eq!(v["from"], "a");
    assert_eq!(v["to"], "b");
    assert_eq!(v["payload"], serde_json::json!([1, 2]));
    assert_eq!(v["seq"], 9);
}

#[test]
fn broadcast_shape() {
    let v = json(&RelayMessage::Broadcast {
        from: "a".into(),
        payload: vec![7],
        exclude: vec!["c".into()],
    });
    assert_eq!(v["type"], "broadcast");
    assert_eq!(v["from"], "a");
    assert_eq!(v["payload"], serde_json::json!([7]));
    assert_eq!(v["exclude"], serde_json::json!(["c"]));
}

#[test]
fn get_peers_and_peers_shape() {
    let v = json(&RelayMessage::GetPeers {
        network_id: Some("DIG_MAINNET".into()),
    });
    assert_eq!(v["type"], "get_peers");
    assert_eq!(v["network_id"], "DIG_MAINNET");

    let info = RelayPeerInfo::new("a".into(), "DIG_MAINNET".into(), 1);
    let v = json(&RelayMessage::Peers { peers: vec![info] });
    assert_eq!(v["type"], "peers");
    assert_eq!(v["peers"][0]["peer_id"], "a");
    assert_eq!(v["peers"][0]["network_id"], "DIG_MAINNET");
    assert_eq!(v["peers"][0]["protocol_version"], 1);
    assert!(v["peers"][0]["connected_at"].is_u64());
    assert!(v["peers"][0]["last_seen"].is_u64());
}

#[test]
fn keepalive_shape() {
    assert_eq!(json(&RelayMessage::Ping { timestamp: 5 })["type"], "ping");
    assert_eq!(json(&RelayMessage::Pong { timestamp: 5 })["type"], "pong");
}

#[test]
fn hole_punch_shapes() {
    let addr = "203.0.113.1:9444".parse().unwrap();
    let v = json(&RelayMessage::HolePunchRequest {
        peer_id: "a".into(),
        target_peer_id: "b".into(),
        external_addr: addr,
    });
    assert_eq!(v["type"], "hole_punch_request");
    assert_eq!(v["peer_id"], "a");
    assert_eq!(v["target_peer_id"], "b");
    assert_eq!(v["external_addr"], "203.0.113.1:9444");

    let v = json(&RelayMessage::HolePunchCoordinate {
        peer_id: "a".into(),
        external_addr: addr,
    });
    assert_eq!(v["type"], "hole_punch_coordinate");

    let v = json(&RelayMessage::HolePunchResult {
        peer_id: "a".into(),
        success: true,
    });
    assert_eq!(v["type"], "hole_punch_result");
    assert_eq!(v["success"], true);
}

#[test]
fn error_and_unregister_shape() {
    let v = json(&RelayMessage::Error {
        code: 3,
        message: "nope".into(),
    });
    assert_eq!(v["type"], "error");
    assert_eq!(v["code"], 3);

    let v = json(&RelayMessage::Unregister {
        peer_id: "a".into(),
    });
    assert_eq!(v["type"], "unregister");
}

// ---- Introducer / peer-discovery additions (RLY-010..RLY-012), additive to RLY-001..007. ----
//
// These pin the NEW message shapes so they, too, can never silently drift. The peer entry
// (`KnownPeerInfo`) mirrors the dig-gossip peer semantics: a hex `peer_id` plus dialable candidate
// addresses (host:port), so the requester can attempt a direct dial / hole-punch before relaying.

#[test]
fn announce_peer_shape() {
    // RLY-010: a peer announces its externally-reachable candidate addresses.
    let v = json(&RelayMessage::AnnouncePeer {
        addrs: vec![
            "203.0.113.7:9444".parse().unwrap(),
            "[2001:db8::1]:9444".parse().unwrap(),
        ],
    });
    assert_eq!(v["type"], "announce_peer");
    assert_eq!(v["addrs"][0], "203.0.113.7:9444");
    assert_eq!(v["addrs"][1], "[2001:db8::1]:9444");
}

#[test]
fn get_known_peers_shape() {
    // RLY-011: request the known-peer list (optionally filtered + bounded).
    let v = json(&RelayMessage::GetKnownPeers {
        network_id: Some("DIG_MAINNET".into()),
        max: Some(16),
    });
    assert_eq!(v["type"], "get_known_peers");
    assert_eq!(v["network_id"], "DIG_MAINNET");
    assert_eq!(v["max"], 16);

    // Both fields are optional — omitted → null, which the server reads as "no filter / default".
    let v = json(&RelayMessage::GetKnownPeers {
        network_id: None,
        max: None,
    });
    assert_eq!(v["type"], "get_known_peers");
    assert!(v["network_id"].is_null());
    assert!(v["max"].is_null());
}

#[test]
fn known_peers_shape() {
    // RLY-012: the known-peer response, each entry carrying dialable candidate addresses.
    let entry = KnownPeerInfo {
        peer_id: "a".into(),
        network_id: "DIG_MAINNET".into(),
        addrs: vec!["203.0.113.7:9444".parse().unwrap()],
        connected_at: 100,
        last_seen: 200,
    };
    let v = json(&RelayMessage::KnownPeers { peers: vec![entry] });
    assert_eq!(v["type"], "known_peers");
    assert_eq!(v["peers"][0]["peer_id"], "a");
    assert_eq!(v["peers"][0]["network_id"], "DIG_MAINNET");
    assert_eq!(v["peers"][0]["addrs"][0], "203.0.113.7:9444");
    assert_eq!(v["peers"][0]["connected_at"], 100);
    assert_eq!(v["peers"][0]["last_seen"], 200);
}

#[test]
fn round_trips_through_json() {
    let original = RelayMessage::RelayGossipMessage {
        from: "a".into(),
        to: "b".into(),
        payload: b"hello".to_vec(),
        seq: 1,
    };
    let s = serde_json::to_string(&original).unwrap();
    let back: RelayMessage = serde_json::from_str(&s).unwrap();
    match back {
        RelayMessage::RelayGossipMessage {
            from,
            to,
            payload,
            seq,
        } => {
            assert_eq!(from, "a");
            assert_eq!(to, "b");
            assert_eq!(payload, b"hello".to_vec());
            assert_eq!(seq, 1);
        }
        other => panic!("round-trip changed the variant: {other:?}"),
    }
}
