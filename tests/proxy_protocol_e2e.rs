//! End-to-end proof that the relay recovers a peer's REAL source address from a PROXY protocol v2
//! header, and refuses to do so for anyone it has not been told to trust (dig_ecosystem #1930).
//!
//! These drive a real relay over a real socket rather than calling the parser directly, because the
//! bug being fixed lives in the seam, not the parser: the relay was reading the load balancer's
//! address off the socket and feeding it to `dial::resolve_dialable`, so every peer was advertised
//! to every other peer at the balancer's own address. A test that only exercised the parser would
//! have passed happily throughout.

use std::net::SocketAddr;
use std::time::Duration;

use dig_relay::proxy_protocol::TrustedProxies;
use dig_relay::wire::RelayMessage;
use dig_relay::RelayServerConfig;
use futures_util::{SinkExt, StreamExt};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// The address a peer half a world away would really have — the case the live fleet exposed, where
/// a Singapore node was being recorded as the us-east-1 load balancer.
const REAL_CLIENT_IP: &str = "2406:da18:1192:6100:eaeb:92d3:c730:9688";
/// The port the peer advertises as its gossip listener; the relay pairs it with the source IP.
const ADVERTISED_PORT: u16 = 9444;

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

/// A PROXY protocol v2 header declaring `src` as the original TCP6 client.
fn v2_tcp6_header(src: std::net::Ipv6Addr, src_port: u16) -> Vec<u8> {
    let mut h = vec![
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ];
    h.push(0x21); // v2, PROXY
    h.push(0x21); // TCP over IPv6
    h.extend_from_slice(&36u16.to_be_bytes());
    h.extend_from_slice(&src.octets());
    h.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
    h.extend_from_slice(&src_port.to_be_bytes());
    h.extend_from_slice(&443u16.to_be_bytes());
    h
}

/// Open a TCP connection, optionally prefix a PROXY header, then complete the WebSocket handshake.
async fn connect_with_proxy_header(relay: SocketAddr, header: Option<Vec<u8>>) -> Option<Ws> {
    let mut stream = TcpStream::connect(relay).await.expect("tcp connect");
    if let Some(h) = header {
        stream.write_all(&h).await.expect("write proxy header");
        stream.flush().await.expect("flush");
    }
    let url = format!("ws://{relay}");
    tokio_tungstenite::client_async(url, MaybeTlsStream::Plain(stream))
        .await
        .ok()
        .map(|(ws, _)| ws)
}

async fn register(ws: &mut Ws, peer_id: &str) {
    let msg = RelayMessage::Register {
        peer_id: peer_id.to_string(),
        network_id: "DIG_MAINNET".to_string(),
        protocol_version: 1,
        // What a real dual-stack node advertises: the unspecified host, so the relay MUST supply
        // the IP itself. This is precisely the substitution that was using the wrong address.
        listen_addrs: vec![format!("[::]:{ADVERTISED_PORT}").parse().unwrap()],
    };
    ws.send(Message::Text(serde_json::to_string(&msg).unwrap()))
        .await
        .expect("send register");
    // Drain the RegisterAck.
    let _ = tokio::time::timeout(Duration::from_secs(3), ws.next()).await;
}

async fn peers_seen_by(ws: &mut Ws) -> Vec<dig_relay::wire::RelayPeerInfo> {
    let q = RelayMessage::GetPeers { network_id: None };
    ws.send(Message::Text(serde_json::to_string(&q).unwrap()))
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        let Ok(Some(Ok(Message::Text(t)))) =
            tokio::time::timeout(Duration::from_secs(3), ws.next()).await
        else {
            continue;
        };
        if let Ok(RelayMessage::Peers { peers }) = serde_json::from_str::<RelayMessage>(&t) {
            return peers;
        }
    }
    panic!("no peers response");
}

#[tokio::test]
async fn a_trusted_proxys_header_gives_the_peer_its_real_address_not_the_proxys() {
    let config = RelayServerConfig {
        // In the live deployment this is the load balancer's prefix; in the test the "proxy" is
        // loopback, because that is where the connection genuinely comes from.
        trusted_proxies: TrustedProxies::parse("127.0.0.0/8").unwrap(),
        ..Default::default()
    };
    let relay = start_relay(config).await;

    let real: std::net::Ipv6Addr = REAL_CLIENT_IP.parse().unwrap();
    let mut far_peer = connect_with_proxy_header(relay, Some(v2_tcp6_header(real, 51234)))
        .await
        .expect("handshake after a proxy header");
    register(&mut far_peer, &"a".repeat(64)).await;

    // A second peer asks who is on the relay — the introduction path that feeds direct dialling.
    let mut observer = connect_with_proxy_header(relay, Some(v2_tcp6_header(real, 51235)))
        .await
        .expect("handshake");
    register(&mut observer, &"b".repeat(64)).await;
    let peers = peers_seen_by(&mut observer).await;

    let far = peers
        .iter()
        .find(|p| p.peer_id == "a".repeat(64))
        .expect("the far peer is listed");
    let expected: SocketAddr = SocketAddr::from((real, ADVERTISED_PORT));
    assert!(
        far.addresses.contains(&expected),
        "the relay must advertise the peer at its REAL address {expected}, got {:?}",
        far.addresses
    );
    assert!(
        !far.addresses.iter().any(|a| a.ip().is_loopback()),
        "the proxy's own address must never be handed out as the peer's: {:?}",
        far.addresses
    );
}

#[tokio::test]
async fn an_untrusted_client_cannot_declare_its_own_source_address() {
    // The security property. With no trusted proxies configured the relay must not read a header at
    // all, so a client that sends one cannot pick its own IP — which would otherwise let it shed a
    // ban, evade the per-IP caps, and place itself anywhere on the map.
    let relay = start_relay(RelayServerConfig::default()).await;

    let spoofed: std::net::Ipv6Addr = REAL_CLIENT_IP.parse().unwrap();
    let attacker = connect_with_proxy_header(relay, Some(v2_tcp6_header(spoofed, 51234))).await;

    // The header bytes are left in the stream and are not a valid WebSocket upgrade, so the
    // handshake fails outright. What must NOT happen is a successful registration under the
    // declared address.
    if let Some(mut ws) = attacker {
        register(&mut ws, &"c".repeat(64)).await;
        let mut honest = connect_with_proxy_header(relay, None)
            .await
            .expect("honest handshake");
        register(&mut honest, &"d".repeat(64)).await;
        for p in peers_seen_by(&mut honest).await {
            assert!(
                !p.addresses.iter().any(|a| a.ip() == spoofed),
                "an untrusted client must never be recorded at the address it declared"
            );
        }
    }
}

#[tokio::test]
async fn a_peer_that_sends_no_header_through_a_trusted_proxy_still_connects() {
    // Rollout safety: the target group's proxy_protocol flag and the relay deploy cannot flip in the
    // same instant, so for a window a trusted source will connect with NO header. That must keep
    // working on the observed address rather than hanging or being dropped.
    let config = RelayServerConfig {
        trusted_proxies: TrustedProxies::parse("127.0.0.0/8").unwrap(),
        ..Default::default()
    };
    let relay = start_relay(config).await;

    let mut ws = connect_with_proxy_header(relay, None)
        .await
        .expect("a headerless peer from a trusted source must still connect");
    register(&mut ws, &"e".repeat(64)).await;
    let peers = peers_seen_by(&mut ws).await;
    assert!(
        peers.iter().any(|p| p.peer_id == "e".repeat(64)),
        "the headerless peer must be registered normally"
    );
}
