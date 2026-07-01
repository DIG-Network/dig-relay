//! Integration test: the relay as a low-bandwidth **hole-punch SIGNALING** channel — distinct from
//! the TURN-like full data-relay path.
//!
//! The DIG relay offers two clearly-separated NAT-traversal tiers (DESIGN.md):
//!
//! 1. **Hole-punch signaling (preferred, low bandwidth).** Two NAT'd peers use the relay ONLY to
//!    (a) discover each other's dialable candidate addresses (RLY-010 `AnnouncePeer` + RLY-011
//!    `GetKnownPeers` → RLY-012 `KnownPeers`) and (b) coordinate a simultaneous open (RLY-007
//!    `HolePunchRequest` → `HolePunchCoordinate`). The relay brokers the introduction + the "punch
//!    now" rendezvous, then the peers connect DIRECTLY — the relay carries NONE of their subsequent
//!    application data. Only the small coordination messages pass through it.
//!
//! 2. **Full relayed transport (TURN-like, last resort, high bandwidth).** The relay proxies ALL
//!    data (RLY-002 `RelayGossipMessage` / RLY-003 `Broadcast`). This is the fallback AFTER a hole
//!    punch fails — covered by `relay_fallback.rs`.
//!
//! This test drives the SIGNALING path with two mock peers and asserts: candidate exchange works,
//! a coordinated punch trigger reaches the target with the requester's external address, and the
//! relay does NOT proxy any application data on this path (no `RelayGossipMessage` is involved).

use std::time::Duration;

use dig_relay::wire::RelayMessage;
use dig_relay::RelayServerConfig;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

/// Read frames until a `RelayMessage` arrives (skipping ws control frames), or time out.
async fn next_relay_msg<S>(ws: &mut S) -> RelayMessage
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let frame = tokio::time::timeout_at(deadline, ws.next())
            .await
            .expect("timed out waiting for a relay message")
            .expect("stream closed")
            .expect("ws error");
        match frame {
            Message::Text(t) => {
                if let Ok(m) = serde_json::from_str::<RelayMessage>(&t) {
                    return m;
                }
            }
            Message::Binary(b) => {
                if let Ok(m) = serde_json::from_slice::<RelayMessage>(&b) {
                    return m;
                }
            }
            _ => continue,
        }
    }
}

async fn send_relay_msg<S>(ws: &mut S, msg: &RelayMessage)
where
    S: SinkExt<Message> + Unpin,
    <S as futures_util::Sink<Message>>::Error: std::fmt::Debug,
{
    let txt = serde_json::to_string(msg).unwrap();
    ws.send(Message::Text(txt)).await.expect("send failed");
}

/// Start the relay on free ephemeral ports; return the relay WebSocket URL.
async fn start_relay() -> String {
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
    tokio::spawn(async move {
        let _ = dig_relay::serve(config).await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;
    format!("ws://{relay_addr}")
}

/// Register a peer over a fresh WebSocket, returning the connected socket after a success ack.
async fn connect_and_register(
    url: &str,
    peer_id: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let (mut ws, _) = tokio_tungstenite::connect_async(url)
        .await
        .expect("connect");
    send_relay_msg(
        &mut ws,
        &RelayMessage::Register {
            peer_id: peer_id.into(),
            network_id: "DIG_MAINNET".into(),
            protocol_version: 1,
        },
    )
    .await;
    match next_relay_msg(&mut ws).await {
        RelayMessage::RegisterAck { success, .. } => assert!(success, "{peer_id} should register"),
        other => panic!("expected RegisterAck for {peer_id}, got {other:?}"),
    }
    ws
}

#[tokio::test]
async fn relay_brokers_candidate_exchange_and_a_coordinated_punch_without_proxying_data() {
    let url = start_relay().await;

    // Two NAT'd peers connect + register. B first so it is present when A discovers it.
    let mut b = connect_and_register(&url, "peerB").await;
    let mut a = connect_and_register(&url, "peerA").await;

    // B announces its dialable candidate addresses (reflexive from STUN + a local candidate).
    let b_reflexive: std::net::SocketAddr = "198.51.100.20:9444".parse().unwrap();
    let b_local: std::net::SocketAddr = "192.168.1.20:9444".parse().unwrap();
    send_relay_msg(
        &mut b,
        &RelayMessage::AnnouncePeer {
            addrs: vec![b_reflexive, b_local],
        },
    )
    .await;

    // --- SIGNALING step 1: A discovers B's candidates via the introducer (low bandwidth). ---
    send_relay_msg(
        &mut a,
        &RelayMessage::GetKnownPeers {
            network_id: None,
            max: Some(16),
        },
    )
    .await;
    let b_candidates = loop {
        match next_relay_msg(&mut a).await {
            RelayMessage::KnownPeers { peers } => {
                let entry = peers
                    .iter()
                    .find(|p| p.peer_id == "peerB")
                    .expect("A discovers B in the known-peer list");
                assert!(
                    entry.addrs.contains(&b_reflexive) && entry.addrs.contains(&b_local),
                    "A learns B's announced candidate addresses to dial directly"
                );
                break entry.addrs.clone();
            }
            RelayMessage::PeerConnected { .. } => continue, // A may see its own connect notice
            other => panic!("expected KnownPeers, got {other:?}"),
        }
    };
    assert_eq!(b_candidates.len(), 2);

    // --- SIGNALING step 2: A asks the relay to broker a coordinated punch to B, carrying A's own
    // reflexive address. The relay forwards a "punch now" coordinate to B with A's external addr —
    // it is a rendezvous broker, NOT a data path. ---
    let a_reflexive: std::net::SocketAddr = "203.0.113.10:9444".parse().unwrap();
    send_relay_msg(
        &mut a,
        &RelayMessage::HolePunchRequest {
            peer_id: "peerA".into(),
            target_peer_id: "peerB".into(),
            external_addr: a_reflexive,
        },
    )
    .await;

    // B receives the coordinated punch trigger carrying A's external address (the rendezvous).
    loop {
        match next_relay_msg(&mut b).await {
            RelayMessage::HolePunchCoordinate {
                peer_id,
                external_addr,
            } => {
                assert_eq!(peer_id, "peerA", "coordinate names the initiating peer");
                assert_eq!(
                    external_addr, a_reflexive,
                    "B learns A's external addr → both can now simultaneous-open DIRECTLY"
                );
                break;
            }
            RelayMessage::PeerConnected { .. } => continue, // B's notice that A connected
            other => panic!("B got unexpected signaling message: {other:?}"),
        }
    }

    // --- Assert the relay did NOT proxy any application DATA on the signaling path. After the punch
    // is coordinated, peers connect directly; the relay carries none of their data. We prove the
    // signaling path never produced a data-relay frame by confirming neither side has a pending
    // `RelayGossipMessage` (the TURN-like data path is a DISTINCT message + code path). ---
    let quiet_a = tokio::time::timeout(Duration::from_millis(300), a.next()).await;
    let quiet_b = tokio::time::timeout(Duration::from_millis(300), b.next()).await;
    for (who, r) in [("A", quiet_a), ("B", quiet_b)] {
        if let Ok(Some(Ok(Message::Text(t)))) = r {
            if let Ok(m) = serde_json::from_str::<RelayMessage>(&t) {
                assert!(
                    !matches!(m, RelayMessage::RelayGossipMessage { .. }),
                    "the SIGNALING path must never carry proxied data (peer {who})"
                );
            }
        }
    }
}

#[tokio::test]
async fn data_relay_path_is_separate_and_available_as_the_fallback() {
    // The TURN-like data-relay path (RLY-002) is a DISTINCT capability, used only after a hole punch
    // fails. Here we exercise it directly to confirm the two paths are separate: A relays a data
    // payload to B THROUGH the relay (the high-bandwidth fallback).
    let url = start_relay().await;
    let mut b = connect_and_register(&url, "peerB").await;
    let mut a = connect_and_register(&url, "peerA").await;

    send_relay_msg(
        &mut a,
        &RelayMessage::RelayGossipMessage {
            from: "peerA".into(),
            to: "peerB".into(),
            payload: b"fallback-data".to_vec(),
            seq: 1,
        },
    )
    .await;

    loop {
        match next_relay_msg(&mut b).await {
            RelayMessage::RelayGossipMessage { from, payload, .. } => {
                assert_eq!(from, "peerA");
                assert_eq!(payload, b"fallback-data".to_vec());
                break;
            }
            RelayMessage::PeerConnected { .. } => continue,
            other => panic!("B got unexpected message: {other:?}"),
        }
    }
}
