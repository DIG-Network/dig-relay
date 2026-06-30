//! Integration test: two simulated DIG nodes whose DIRECT path is blocked connect THROUGH the
//! relay and exchange a message.
//!
//! This is the core proof of the relay's purpose (DESIGN.md): when peers cannot dial each other
//! directly, they fall back to relayed transport. Both peers are plain WebSocket clients (they do
//! NOT know each other's address — there is no direct path); they each connect only to the relay,
//! register (RLY-001), and peer A sends a `RelayGossipMessage` to peer B (RLY-002) which the relay
//! forwards. We assert B receives A's payload with `from` correctly stamped to A's id.

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

#[tokio::test]
async fn two_nat_blocked_peers_exchange_through_the_relay() {
    // Start the relay on ephemeral ports (no fixed port collisions in CI).
    let config = RelayServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        health_listen: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    };
    // Bind the relay listener ourselves so we know the chosen port, then hand the socket to the
    // server via a real bind inside serve()? Simpler: bind a TcpListener to find a free port,
    // drop it, and pass that addr (tiny race, acceptable for a test). Instead we use port 0 and
    // discover the port by binding here and reusing the addr.
    let relay_listener = tokio::net::TcpListener::bind(config.listen).await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();
    drop(relay_listener);
    let health_listener = tokio::net::TcpListener::bind(config.health_listen)
        .await
        .unwrap();
    let health_addr = health_listener.local_addr().unwrap();
    drop(health_listener);

    let config = RelayServerConfig {
        listen: relay_addr,
        health_listen: health_addr,
        ..Default::default()
    };
    tokio::spawn(async move {
        let _ = dig_relay::serve(config).await;
    });
    // Give the listeners a moment to bind.
    tokio::time::sleep(Duration::from_millis(150)).await;

    let url = format!("ws://{relay_addr}");

    // Peer B connects + registers first so it is present when A forwards.
    let (mut b, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("B connect");
    send_relay_msg(
        &mut b,
        &RelayMessage::Register {
            peer_id: "peerB".into(),
            network_id: "DIG_MAINNET".into(),
            protocol_version: 1,
        },
    )
    .await;
    match next_relay_msg(&mut b).await {
        RelayMessage::RegisterAck { success, .. } => assert!(success, "B should register"),
        other => panic!("expected RegisterAck for B, got {other:?}"),
    }

    // Peer A connects + registers.
    let (mut a, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("A connect");
    send_relay_msg(
        &mut a,
        &RelayMessage::Register {
            peer_id: "peerA".into(),
            network_id: "DIG_MAINNET".into(),
            protocol_version: 1,
        },
    )
    .await;
    match next_relay_msg(&mut a).await {
        RelayMessage::RegisterAck { success, .. } => assert!(success, "A should register"),
        other => panic!("expected RegisterAck for A, got {other:?}"),
    }

    // B may receive a PeerConnected notice for A — drain non-target frames below.

    // A → relay → B: the relayed-transport fallback (direct path does not exist; A only knows the
    // relay, addresses peer B by id).
    send_relay_msg(
        &mut a,
        &RelayMessage::RelayGossipMessage {
            from: "peerA".into(),
            to: "peerB".into(),
            payload: b"hello-over-relay".to_vec(),
            seq: 1,
        },
    )
    .await;

    // B must receive A's gossip message through the relay.
    loop {
        match next_relay_msg(&mut b).await {
            RelayMessage::RelayGossipMessage {
                from, to, payload, ..
            } => {
                assert_eq!(from, "peerA", "from is stamped to the real sender id");
                assert_eq!(to, "peerB");
                assert_eq!(payload, b"hello-over-relay".to_vec());
                break;
            }
            // Skip the PeerConnected notification B gets when A registers.
            RelayMessage::PeerConnected { .. } => continue,
            other => panic!("B got unexpected message: {other:?}"),
        }
    }
}

#[tokio::test]
async fn forward_to_unknown_peer_returns_peer_not_found() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = l.local_addr().unwrap();
    drop(l);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let health_addr = l.local_addr().unwrap();
    drop(l);

    let config = RelayServerConfig {
        listen: relay_addr,
        health_listen: health_addr,
        ..Default::default()
    };
    tokio::spawn(async move {
        let _ = dig_relay::serve(config).await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let url = format!("ws://{relay_addr}");
    let (mut a, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    send_relay_msg(
        &mut a,
        &RelayMessage::Register {
            peer_id: "peerA".into(),
            network_id: "DIG_MAINNET".into(),
            protocol_version: 1,
        },
    )
    .await;
    let _ = next_relay_msg(&mut a).await; // RegisterAck

    send_relay_msg(
        &mut a,
        &RelayMessage::RelayGossipMessage {
            from: "peerA".into(),
            to: "ghost".into(),
            payload: vec![1],
            seq: 1,
        },
    )
    .await;

    match next_relay_msg(&mut a).await {
        RelayMessage::Error { code, .. } => {
            assert_eq!(code, dig_relay::server::errcode::PEER_NOT_FOUND);
        }
        other => panic!("expected PEER_NOT_FOUND error, got {other:?}"),
    }
}
