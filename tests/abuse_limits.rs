//! Integration tests for the relay's app-level abuse protection (#1386): per-source-IP connection
//! cap, per-IP registration-flood limits, and per-connection message-rate disconnect.
//!
//! Each test spins up a real relay on ephemeral loopback ports and drives real WebSocket clients,
//! asserting the same shape every time: **the breach is rejected AND a legitimate peer is
//! unaffected**. The "different source IP" cases bind the client's local socket to `127.0.0.2`
//! (still loopback on Linux CI) so the relay observes a distinct source address — proving the caps
//! are keyed per source IP (`limits::ip_key`), not global.

use std::net::SocketAddr;
use std::time::Duration;

use dig_relay::wire::RelayMessage;
use dig_relay::RelayServerConfig;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Start a relay on ephemeral loopback ports with the given `config` overrides applied, returning
/// its WebSocket listen address. Binds each listener to discover a free port, drops it, then hands
/// the address to `serve` (a tiny bind race, acceptable for a test).
async fn start_relay(mut config: RelayServerConfig) -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = l.local_addr().unwrap();
    drop(l);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let health_addr = l.local_addr().unwrap();
    drop(l);
    let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let stun_addr = s.local_addr().unwrap();
    drop(s);

    config.listen = relay_addr;
    config.health_listen = health_addr;
    config.stun_listen = stun_addr;
    tokio::spawn(async move {
        let _ = dig_relay::serve(config).await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;
    relay_addr
}

/// Connect a WebSocket client whose local (source) socket is bound to `local_ip`, so the relay
/// observes that specific source IP — the way the per-IP caps are keyed.
async fn connect_from(local_ip: &str, relay_addr: SocketAddr) -> Ws {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket
        .bind(format!("{local_ip}:0").parse().unwrap())
        .expect("bind local source ip");
    let stream = socket.connect(relay_addr).await.expect("tcp connect");
    let url = format!("ws://{relay_addr}");
    let (ws, _) = tokio_tungstenite::client_async(url, MaybeTlsStream::Plain(stream))
        .await
        .expect("ws handshake");
    ws
}

async fn send(ws: &mut Ws, msg: &RelayMessage) {
    ws.send(Message::Text(serde_json::to_string(msg).unwrap()))
        .await
        .expect("send");
}

async fn register(ws: &mut Ws, peer_id: &str) {
    send(
        ws,
        &RelayMessage::Register {
            peer_id: peer_id.into(),
            network_id: "DIG_MAINNET".into(),
            protocol_version: 1,
            listen_addrs: vec![],
        },
    )
    .await;
}

/// Read frames until a `RelayMessage` arrives (skipping ws control frames), or time out.
async fn next_relay_msg(ws: &mut Ws) -> RelayMessage {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let frame = tokio::time::timeout_at(deadline, ws.next())
            .await
            .expect("timed out")
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

/// Whether the stream closes (a `Close`, `None`, or ws error) within `within` — i.e. the relay
/// disconnected the connection. Returns `false` if it stayed open for the whole window.
async fn stream_closes(ws: &mut Ws, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Err(_) => return false, // still open at the deadline
            Ok(None) => return true,
            Ok(Some(Ok(Message::Close(_)))) => return true,
            Ok(Some(Err(_))) => return true,
            Ok(Some(Ok(_))) => continue, // a pong / other frame; keep waiting
        }
    }
}

/// (a) One source IP opening more than `max_connections_per_ip` sockets is refused, while a DIFFERENT
/// source IP still connects.
#[tokio::test]
async fn per_ip_connection_cap_refuses_the_excess_but_a_second_ip_connects() {
    let relay_addr = start_relay(RelayServerConfig {
        max_connections_per_ip: 2,
        ..Default::default()
    })
    .await;

    // Two connections from 127.0.0.1 fill this source's per-IP cap (held open).
    let _c1 = connect_from("127.0.0.1", relay_addr).await;
    let _c2 = connect_from("127.0.0.1", relay_addr).await;

    // A third from the SAME source IP is refused: the relay drops the socket before the WS upgrade,
    // so the client handshake fails.
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let stream = socket.connect(relay_addr).await.expect("tcp connect ok");
    let third = tokio_tungstenite::client_async(
        format!("ws://{relay_addr}"),
        MaybeTlsStream::Plain(stream),
    )
    .await;
    assert!(
        third.is_err(),
        "a third connection from the same source IP must be refused"
    );

    // A different source IP is unaffected — it still gets a connection.
    let mut other = connect_from("127.0.0.2", relay_addr).await;
    register(&mut other, "other-ip-peer").await;
    match next_relay_msg(&mut other).await {
        RelayMessage::RegisterAck { success, .. } => {
            assert!(success, "a different source IP connects + registers fine")
        }
        other => panic!("expected RegisterAck, got {other:?}"),
    }
}

/// (b) A registration flood from one source IP eventually gets `RegisterAck{success:false}` +
/// `RATE_LIMITED`, while a normal first register succeeds.
#[tokio::test]
async fn registration_flood_is_rate_limited_but_a_normal_register_succeeds() {
    let relay_addr = start_relay(RelayServerConfig {
        // Disable the per-IP CONNECTION cap and the concurrent-registration cap so this test isolates
        // the registration RATE limit; keep the rate small so a burst trips it.
        max_connections_per_ip: 0,
        max_registrations_per_ip: 0,
        registrations_per_ip_per_sec: 2,
        ..Default::default()
    })
    .await;

    let mut saw_success = false;
    let mut saw_rate_limited = false;
    // Open a fresh connection per attempt (all from 127.0.0.1 → one source-IP budget) and register.
    for i in 0..10 {
        let mut ws = connect_from("127.0.0.1", relay_addr).await;
        register(&mut ws, &format!("flood-{i}")).await;
        match next_relay_msg(&mut ws).await {
            RelayMessage::RegisterAck { success: true, .. } => saw_success = true,
            RelayMessage::RegisterAck { success: false, .. } => {
                // The refusal is accompanied by a RATE_LIMITED error frame.
                if let RelayMessage::Error { code, .. } = next_relay_msg(&mut ws).await {
                    if code == dig_relay::server::errcode::RATE_LIMITED {
                        saw_rate_limited = true;
                    }
                }
            }
            other => panic!("expected a RegisterAck, got {other:?}"),
        }
    }
    assert!(saw_success, "a normal register within budget succeeds");
    assert!(
        saw_rate_limited,
        "a 10-deep register burst from one IP trips RATE_LIMITED"
    );
}

/// (c) A connection exceeding the per-connection message rate is disconnected, while a well-behaved
/// peer persists.
#[tokio::test]
async fn per_connection_message_flood_is_disconnected_but_a_calm_peer_persists() {
    let relay_addr = start_relay(RelayServerConfig {
        max_connections_per_ip: 0, // both clients share loopback; don't let the per-IP cap interfere
        messages_per_conn_per_sec: 5,
        ..Default::default()
    })
    .await;

    // A calm peer: register, exchange one keepalive, stay connected.
    let mut calm = connect_from("127.0.0.1", relay_addr).await;
    register(&mut calm, "calm").await;
    assert!(
        matches!(
            next_relay_msg(&mut calm).await,
            RelayMessage::RegisterAck { success: true, .. }
        ),
        "calm peer registers"
    );

    // A flooding peer: register (1 frame), then blast well over the 5-frame/sec budget.
    let mut flood = connect_from("127.0.0.1", relay_addr).await;
    register(&mut flood, "flood").await;
    for i in 0..50 {
        // Ignore send errors: once the relay disconnects mid-blast the socket closes.
        let _ = flood
            .send(Message::Text(
                serde_json::to_string(&RelayMessage::Ping { timestamp: i }).unwrap(),
            ))
            .await;
    }
    assert!(
        stream_closes(&mut flood, Duration::from_secs(5)).await,
        "the flooding connection is disconnected"
    );

    // The calm peer is still alive: a ping still gets a pong.
    send(&mut calm, &RelayMessage::Ping { timestamp: 1 }).await;
    let mut got_pong = false;
    for _ in 0..5 {
        if let RelayMessage::Pong { .. } = next_relay_msg(&mut calm).await {
            got_pong = true;
            break;
        }
    }
    assert!(got_pong, "the well-behaved peer is unaffected");
}

/// (d) #1396: a source that REPEATEDLY trips a per-IP cap (here, the registration rate) accrues
/// strikes and, once past the ban threshold, is BANNED at accept — its subsequent connections are
/// refused before the WebSocket upgrade — while a different source IP is untouched.
#[tokio::test]
async fn repeat_registration_abuse_earns_an_accept_time_ban() {
    let relay_addr = start_relay(RelayServerConfig {
        // Disable the per-IP CONNECTION cap so a plain connect never strikes on its own — only the
        // registration-rate trips do — making the accept-time refusal below unambiguously the ban.
        max_connections_per_ip: 0,
        max_registrations_per_ip: 0,
        registrations_per_ip_per_sec: 1, // tiny rate → a register burst trips it repeatedly
        ban_threshold: 3,                // 3 rate-limit trips within the window → ban
        ban_duration: Duration::from_secs(300),
        ban_strike_window: Duration::from_secs(60),
        ..Default::default()
    })
    .await;

    // Hammer registrations from one source IP (a fresh connection each — register is once per
    // connection). Each rate-limited register is a strike; after `ban_threshold` strikes the source
    // is banned and further CONNECTIONS are refused at accept: the relay closes the socket before the
    // WS upgrade, so the client handshake (`client_async`) fails. Detect that transition.
    let mut banned_at_accept = false;
    for i in 0..20 {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        // The TCP connect succeeds (the relay accepts then closes a banned socket); the ban surfaces
        // as a failed WS handshake.
        let stream = match socket.connect(relay_addr).await {
            Ok(s) => s,
            Err(_) => {
                banned_at_accept = true;
                break;
            }
        };
        match tokio_tungstenite::client_async(
            format!("ws://{relay_addr}"),
            MaybeTlsStream::Plain(stream),
        )
        .await
        {
            Ok((mut ws, _)) => {
                register(&mut ws, &format!("abuser-{i}")).await;
                let _ = next_relay_msg(&mut ws).await; // RegisterAck (success or the rate-limit refusal)
            }
            Err(_) => {
                banned_at_accept = true; // refused at accept → the source is banned
                break;
            }
        }
    }
    assert!(
        banned_at_accept,
        "sustained registration abuse from one IP earns an accept-time ban (#1396)"
    );

    // A DIFFERENT source IP is unaffected by the ban — the ban is keyed per source, not global.
    let mut other = connect_from("127.0.0.2", relay_addr).await;
    register(&mut other, "innocent").await;
    assert!(
        matches!(
            next_relay_msg(&mut other).await,
            RelayMessage::RegisterAck { success: true, .. }
        ),
        "a different source IP is not caught by the ban"
    );
}
