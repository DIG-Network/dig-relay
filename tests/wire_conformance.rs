//! Conformance test pinning the relay wire (`src/wire.rs`) to the canonical dig-gossip shape.
//!
//! The vendored `RelayMessage`/`RelayPeerInfo` types MUST serialize to the exact JSON the
//! dig-gossip relay CLIENT emits/expects, or the server and client cannot talk. This test freezes
//! the `type` discriminators and field names so an accidental rename here fails CI loudly.
//!
//! It also pins the **RLY-008** PEX binding as purely additive: the re-exported `PexMessage`'s
//! `pex_*` `type` tags must be disjoint from every RLY-001..RLY-007 tag (so no existing message
//! changes meaning), and the PEX shapes are frozen too (their normative home is `dig-pex`, but the
//! relay wire depends on them so we pin them here as well).

use dig_relay::wire::{PexMessage, RelayMessage, RelayPeerInfo};

fn json(m: &RelayMessage) -> serde_json::Value {
    serde_json::to_value(m).unwrap()
}

#[test]
fn register_shape() {
    let v = json(&RelayMessage::Register {
        peer_id: "a".into(),
        network_id: "DIG_MAINNET".into(),
        protocol_version: 1,
        listen_addrs: vec![],
    });
    assert_eq!(v["type"], "register");
    assert_eq!(v["peer_id"], "a");
    assert_eq!(v["network_id"], "DIG_MAINNET");
    assert_eq!(v["protocol_version"], 1);
    // B1 (#924): empty `listen_addrs` is omitted from the wire (`skip_serializing_if`), so a legacy
    // node's register frame is byte-identical to before (NC-6 soft-fork).
    assert!(
        v.get("listen_addrs").is_none(),
        "empty listen_addrs must be omitted from the wire (NC-6 soft-fork)"
    );

    // A node advertising listen candidates carries them as a flat `listen_addrs` array.
    let v = json(&RelayMessage::Register {
        peer_id: "a".into(),
        network_id: "DIG_MAINNET".into(),
        protocol_version: 1,
        listen_addrs: vec!["[::]:9445".parse().unwrap()],
    });
    assert_eq!(v["listen_addrs"][0], "[::]:9445");
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
    // B1 (#924): the additive `addresses` field is omitted from the wire when empty
    // (`skip_serializing_if`), so a peer with no resolved dialable candidates serializes exactly as
    // before — old readers see an unchanged shape.
    assert!(
        v["peers"][0].get("addresses").is_none(),
        "empty addresses must be omitted from the wire (NC-6 soft-fork)"
    );

    // A peer WITH resolved dialable candidates carries them as a flat `addresses` array.
    let mut info = RelayPeerInfo::new("b".into(), "DIG_MAINNET".into(), 1);
    info.addresses = vec!["203.0.113.7:9445".parse().unwrap()];
    let v = json(&RelayMessage::Peers { peers: vec![info] });
    assert_eq!(v["peers"][0]["addresses"][0], "203.0.113.7:9445");
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

// ---- RLY-008: the additive PEX binding ----

/// The RLY-001..RLY-007 `type` tags (the frozen relay wire, unchanged by RLY-008).
const RLY_TAGS: &[&str] = &[
    "register",
    "register_ack",
    "unregister",
    "relay_message",
    "broadcast",
    "peer_connected",
    "peer_disconnected",
    "get_peers",
    "peers",
    "ping",
    "pong",
    "hole_punch_request",
    "hole_punch_coordinate",
    "hole_punch_result",
    "error",
];

#[test]
fn pex_type_tags_do_not_collide_with_any_rly_tag() {
    // RLY-008 is purely additive: every PEX tag begins with `pex_` and none is an RLY tag, so no
    // existing relay message changes shape or meaning.
    for tag in ["pex_handshake", "pex_snapshot", "pex_delta", "pex_error"] {
        assert!(tag.starts_with("pex_"));
        assert!(
            !RLY_TAGS.contains(&tag),
            "PEX tag {tag} must not collide with an RLY-001..007 tag"
        );
    }
}

#[test]
fn pex_message_shapes_are_frozen() {
    // The relay uses the bare-JSON text-frame form on this binding (`to_json`).
    let hs = PexMessage::PexHandshake {
        version: 1,
        network_id: "DIG_MAINNET".into(),
        interval: 60,
        flags: vec![],
    };
    let v: serde_json::Value = serde_json::from_str(&hs.to_json()).unwrap();
    assert_eq!(v["type"], "pex_handshake");
    assert_eq!(v["version"], 1);
    assert_eq!(v["network_id"], "DIG_MAINNET");
    assert_eq!(v["interval"], 60);

    let snap = PexMessage::PexSnapshot { peers: vec![] };
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&snap.to_json()).unwrap()["type"],
        "pex_snapshot"
    );

    let delta = PexMessage::PexDelta {
        added: vec![],
        dropped: vec![],
    };
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&delta.to_json()).unwrap()["type"],
        "pex_delta"
    );

    let err = PexMessage::PexError {
        code: 3,
        message: "rate violation".into(),
    };
    let v: serde_json::Value = serde_json::from_str(&err.to_json()).unwrap();
    assert_eq!(v["type"], "pex_error");
    assert_eq!(v["code"], 3);
}

#[test]
fn a_pex_frame_is_not_a_valid_relay_message_and_vice_versa() {
    // The two tag spaces are disjoint, so a PEX frame never deserializes as a RelayMessage (the
    // server routes it via the `pex_` type peek before the RLY parse).
    let pex = PexMessage::PexHandshake {
        version: 1,
        network_id: "n".into(),
        interval: 60,
        flags: vec![],
    }
    .to_json();
    assert!(
        serde_json::from_str::<RelayMessage>(&pex).is_err(),
        "a PEX frame must not parse as a RelayMessage"
    );
    // An RLY frame is not a PEX message either.
    let rly = serde_json::to_string(&RelayMessage::Ping { timestamp: 1 }).unwrap();
    assert!(PexMessage::from_json(&rly).is_err());
}
