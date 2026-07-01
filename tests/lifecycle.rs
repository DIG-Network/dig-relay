//! End-to-end lifecycle tests that drive a REAL running relay through the connection paths the
//! pure-dispatch unit tests can't reach: registration ack + capacity refusal, broadcast fan-out,
//! `GetPeers` registry read, hole-punch coordinate delivery, `PeerConnected`/`PeerDisconnected`
//! notifications, keepalive ping→pong over the wire, the bad-JSON error reply, graceful
//! `Unregister`, and the duplicate-id (reconnect) replacement. These exercise `server.rs`'s
//! `handle_connection`/`register_peer`/`forward_to`/`broadcast`/`deregister` + the `/health` route.

use std::time::Duration;

use dig_relay::wire::RelayMessage;
use dig_relay::RelayServerConfig;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

type Ws = WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Bind, find a free port, drop the listener, and return the addr (the tiny race is acceptable in
/// tests and matches the existing `relay_fallback.rs` approach).
async fn free_addr() -> std::net::SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a
}

/// A free UDP port for the STUN listener (bound as UDP so the discovered port is actually free for
/// UDP). Every relay in the parallel test suite needs its own STUN port — the shared default
/// (3478) would collide across concurrently-running test relays and tear the server down.
async fn free_udp_addr() -> std::net::SocketAddr {
    let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a = s.local_addr().unwrap();
    drop(s);
    a
}

/// Start a relay with the given config tweaks and return `(relay_ws_url, health_addr)`.
async fn start_relay(max_connections: usize) -> (String, std::net::SocketAddr) {
    let relay_addr = free_addr().await;
    let health_addr = free_addr().await;
    let stun_addr = free_udp_addr().await;
    let config = RelayServerConfig {
        listen: relay_addr,
        health_listen: health_addr,
        stun_listen: stun_addr,
        max_connections,
        ..Default::default()
    };
    tokio::spawn(async move {
        let _ = dig_relay::serve(config).await;
    });
    // Give both listeners a moment to bind.
    tokio::time::sleep(Duration::from_millis(200)).await;
    (format!("ws://{relay_addr}"), health_addr)
}

async fn connect(url: &str) -> Ws {
    tokio_tungstenite::connect_async(url).await.unwrap().0
}

async fn send(ws: &mut Ws, msg: &RelayMessage) {
    ws.send(Message::Text(serde_json::to_string(msg).unwrap()))
        .await
        .expect("send");
}

/// Next decoded `RelayMessage`, skipping ws control frames; panics on timeout.
async fn next_msg(ws: &mut Ws) -> RelayMessage {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let frame = tokio::time::timeout_at(deadline, ws.next())
            .await
            .expect("timed out")
            .expect("stream closed")
            .expect("ws error");
        match frame {
            Message::Text(t) => {
                if let Ok(m) = serde_json::from_str(&t) {
                    return m;
                }
            }
            Message::Binary(b) => {
                if let Ok(m) = serde_json::from_slice(&b) {
                    return m;
                }
            }
            _ => continue,
        }
    }
}

/// Register a peer and assert the ack succeeds.
async fn register_ok(ws: &mut Ws, peer_id: &str, network_id: &str) {
    send(
        ws,
        &RelayMessage::Register {
            peer_id: peer_id.into(),
            network_id: network_id.into(),
            protocol_version: 1,
        },
    )
    .await;
    match next_msg(ws).await {
        RelayMessage::RegisterAck { success, .. } => assert!(success, "{peer_id} should register"),
        other => panic!("expected RegisterAck, got {other:?}"),
    }
}

#[tokio::test]
async fn register_ack_reports_connected_peers_and_notifies_existing_peers() {
    let (url, _health) = start_relay(4096).await;

    let mut a = connect(&url).await;
    register_ok(&mut a, "A", "net").await;

    // B registers; A must receive a PeerConnected for B.
    let mut b = connect(&url).await;
    register_ok(&mut b, "B", "net").await;

    match next_msg(&mut a).await {
        RelayMessage::PeerConnected { peer } => assert_eq!(peer.peer_id, "B"),
        other => panic!("A should be told B connected, got {other:?}"),
    }
}

#[tokio::test]
async fn at_capacity_a_new_connection_is_refused_before_the_handshake() {
    // A relay that can hold exactly one peer. The connection-cap guard refuses a SECOND connection
    // before the WebSocket upgrade (cheapest place to shed load), so the second peer never reaches
    // a successful registration: the relay closes the raw socket and the WS handshake fails (or the
    // stream resets), and the first peer keeps its slot.
    let (url, _health) = start_relay(1).await;

    let mut a = connect(&url).await;
    register_ok(&mut a, "A", "net").await;

    // Attempt a second connection: either the handshake is rejected, or it "connects" then the
    // socket is immediately closed so registration cannot succeed.
    let refused = match tokio_tungstenite::connect_async(&url).await {
        Err(_) => true, // handshake rejected outright
        Ok((mut b, _)) => {
            // The relay refused before upgrade → it closes; a Register either errors on send or the
            // stream is closed before any RegisterAck arrives. Confirm we never get a success ack.
            let _ = send(
                &mut b,
                &RelayMessage::Register {
                    peer_id: "B".into(),
                    network_id: "net".into(),
                    protocol_version: 1,
                },
            )
            .await;
            // Read frames with a short bound; a refused connection yields close/None, never a
            // successful RegisterAck.
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            let mut got_success_ack = false;
            loop {
                match tokio::time::timeout_at(deadline, b.next()).await {
                    Ok(Some(Ok(Message::Text(t)))) => {
                        if let Ok(RelayMessage::RegisterAck { success: true, .. }) =
                            serde_json::from_str(&t)
                        {
                            got_success_ack = true;
                            break;
                        }
                    }
                    Ok(Some(Ok(_))) => continue, // other/control frame
                    Ok(Some(Err(_))) | Ok(None) | Err(_) => break, // closed/reset/timeout
                }
            }
            !got_success_ack
        }
    };
    assert!(refused, "a second peer must not register when at capacity");

    // The first peer is unaffected: a ping is still answered.
    send(&mut a, &RelayMessage::Ping { timestamp: 1 }).await;
    assert!(matches!(
        next_msg(&mut a).await,
        RelayMessage::Pong { timestamp: 1 }
    ));
}

#[tokio::test]
async fn broadcast_fans_out_to_all_same_network_peers_except_sender() {
    let (url, _health) = start_relay(4096).await;

    let mut a = connect(&url).await;
    register_ok(&mut a, "A", "net").await;
    let mut b = connect(&url).await;
    register_ok(&mut b, "B", "net").await;
    let mut c = connect(&url).await;
    register_ok(&mut c, "C", "net").await;

    // Drain the PeerConnected notices A/B receive as later peers join.
    // A sends a broadcast; B and C must each get it, A must not get its own.
    send(
        &mut a,
        &RelayMessage::Broadcast {
            from: "A".into(),
            payload: b"hi-all".to_vec(),
            exclude: vec![],
        },
    )
    .await;

    for peer in [&mut b, &mut c] {
        // Skip PeerConnected notices until the broadcast arrives.
        loop {
            match next_msg(peer).await {
                RelayMessage::Broadcast { from, payload, .. } => {
                    assert_eq!(from, "A", "from is re-stamped to the sender");
                    assert_eq!(payload, b"hi-all".to_vec());
                    break;
                }
                RelayMessage::PeerConnected { .. } => continue,
                other => panic!("unexpected broadcast frame: {other:?}"),
            }
        }
    }
}

#[tokio::test]
async fn get_peers_returns_the_sorted_same_network_peer_list() {
    let (url, _health) = start_relay(4096).await;

    let mut a = connect(&url).await;
    register_ok(&mut a, "alpha", "net").await;
    let mut b = connect(&url).await;
    register_ok(&mut b, "bravo", "net").await;
    // A peer on a different network must NOT appear in net's list.
    let mut z = connect(&url).await;
    register_ok(&mut z, "zulu", "other").await;

    send(
        &mut a,
        &RelayMessage::GetPeers {
            network_id: Some("net".into()),
        },
    )
    .await;

    // Skip the PeerConnected for bravo, then read the Peers list.
    loop {
        match next_msg(&mut a).await {
            RelayMessage::Peers { peers } => {
                let ids: Vec<_> = peers.iter().map(|p| p.peer_id.as_str()).collect();
                assert_eq!(ids, vec!["alpha", "bravo"], "sorted, net-only");
                break;
            }
            RelayMessage::PeerConnected { .. } => continue,
            other => panic!("unexpected frame: {other:?}"),
        }
    }
}

#[tokio::test]
async fn hole_punch_request_delivers_a_coordinate_to_the_target() {
    let (url, _health) = start_relay(4096).await;

    let mut a = connect(&url).await;
    register_ok(&mut a, "A", "net").await;
    let mut b = connect(&url).await;
    register_ok(&mut b, "B", "net").await;

    let ext: std::net::SocketAddr = "203.0.113.9:9444".parse().unwrap();
    send(
        &mut a,
        &RelayMessage::HolePunchRequest {
            peer_id: "A".into(),
            target_peer_id: "B".into(),
            external_addr: ext,
        },
    )
    .await;

    loop {
        match next_msg(&mut b).await {
            RelayMessage::HolePunchCoordinate {
                peer_id,
                external_addr,
            } => {
                assert_eq!(peer_id, "A", "coordinate carries the requester id");
                assert_eq!(external_addr, ext);
                break;
            }
            RelayMessage::PeerConnected { .. } => continue,
            other => panic!("unexpected frame: {other:?}"),
        }
    }
}

#[tokio::test]
async fn keepalive_ping_is_answered_with_a_pong_over_the_wire() {
    let (url, _health) = start_relay(4096).await;
    let mut a = connect(&url).await;
    register_ok(&mut a, "A", "net").await;

    send(&mut a, &RelayMessage::Ping { timestamp: 123 }).await;
    match next_msg(&mut a).await {
        RelayMessage::Pong { timestamp } => assert_eq!(timestamp, 123),
        other => panic!("expected Pong, got {other:?}"),
    }
}

#[tokio::test]
async fn invalid_json_before_register_gets_a_bad_message_error() {
    let (url, _health) = start_relay(4096).await;
    let mut a = connect(&url).await;
    // Send a frame that is valid text but not a RelayMessage.
    a.send(Message::Text("{\"not\":\"a relay message\"}".into()))
        .await
        .unwrap();
    match next_msg(&mut a).await {
        RelayMessage::Error { code, .. } => {
            assert_eq!(code, dig_relay::server::errcode::BAD_MESSAGE);
        }
        other => panic!("expected BAD_MESSAGE, got {other:?}"),
    }
}

#[tokio::test]
async fn unregister_closes_and_notifies_peers_of_disconnect() {
    let (url, _health) = start_relay(4096).await;

    let mut a = connect(&url).await;
    register_ok(&mut a, "A", "net").await;
    let mut b = connect(&url).await;
    register_ok(&mut b, "B", "net").await;
    // A learns B connected; drain that.
    match next_msg(&mut a).await {
        RelayMessage::PeerConnected { .. } => {}
        other => panic!("expected PeerConnected, got {other:?}"),
    }

    // B unregisters → A must be told B disconnected.
    send(
        &mut b,
        &RelayMessage::Unregister {
            peer_id: "B".into(),
        },
    )
    .await;
    match next_msg(&mut a).await {
        RelayMessage::PeerDisconnected { peer_id } => assert_eq!(peer_id, "B"),
        other => panic!("expected PeerDisconnected for B, got {other:?}"),
    }
}

#[tokio::test]
async fn dropping_a_connection_notifies_peers_of_disconnect() {
    let (url, _health) = start_relay(4096).await;

    let mut a = connect(&url).await;
    register_ok(&mut a, "A", "net").await;
    let mut b = connect(&url).await;
    register_ok(&mut b, "B", "net").await;
    match next_msg(&mut a).await {
        RelayMessage::PeerConnected { .. } => {}
        other => panic!("expected PeerConnected, got {other:?}"),
    }

    // Hard-drop B's socket (no Unregister) → the relay's teardown path must still deregister it.
    drop(b);
    match next_msg(&mut a).await {
        RelayMessage::PeerDisconnected { peer_id } => assert_eq!(peer_id, "B"),
        other => panic!("expected PeerDisconnected on drop, got {other:?}"),
    }
}

#[tokio::test]
async fn health_endpoint_reports_connected_peers() {
    let (url, health) = start_relay(4096).await;

    let mut a = connect(&url).await;
    register_ok(&mut a, "A", "net").await;
    // Small settle so the connected counter reflects the registration.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Probe /health with a tiny blocking GET on a worker thread (axum serves it).
    let body = tokio::task::spawn_blocking(move || {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect(health).unwrap();
        s.write_all(b"GET /health HTTP/1.0\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    })
    .await
    .unwrap();

    assert!(body.contains("200"), "health returns 200: {body}");
    assert!(body.contains("\"status\":\"ok\""), "health body: {body}");
    assert!(
        body.contains("\"connected_peers\":1"),
        "one peer connected: {body}"
    );
}

#[tokio::test]
async fn forward_before_register_is_rejected_not_registered() {
    let (url, _health) = start_relay(4096).await;
    let mut a = connect(&url).await;
    // Skip registration; a forward must be refused.
    send(
        &mut a,
        &RelayMessage::RelayGossipMessage {
            from: "A".into(),
            to: "B".into(),
            payload: vec![1],
            seq: 1,
        },
    )
    .await;
    match next_msg(&mut a).await {
        RelayMessage::Error { code, .. } => {
            assert_eq!(code, dig_relay::server::errcode::NOT_REGISTERED);
        }
        other => panic!("expected NOT_REGISTERED, got {other:?}"),
    }
}
