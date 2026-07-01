//! Integration test: a real UDP client sends a STUN Binding Request to the running relay's STUN
//! listener and learns its reflexive address (RFC 5389).
//!
//! This is the end-to-end proof of the STUN capability (DESIGN.md): a NAT'd DIG Node discovers the
//! public `IP:port` the outside world sees for it. We start the relay, send a real Binding Request
//! over UDP from a loopback socket, and assert the Binding Success Response decodes to exactly that
//! socket's address (the source the server observed) — the whole point of STUN.

use std::time::Duration;

use dig_relay::stun::{self, TransactionId};
use dig_relay::RelayServerConfig;
use tokio::net::UdpSocket;

/// Build a bare STUN Binding Request (header only) with the given transaction id.
fn binding_request(tid: &TransactionId) -> Vec<u8> {
    let mut m = Vec::with_capacity(20);
    m.extend_from_slice(&stun::msgtype::BINDING_REQUEST.to_be_bytes());
    m.extend_from_slice(&0u16.to_be_bytes()); // no attributes
    m.extend_from_slice(&stun::MAGIC_COOKIE.to_be_bytes());
    m.extend_from_slice(tid);
    m
}

#[tokio::test]
async fn stun_binding_request_returns_the_clients_reflexive_address() {
    // Pick free ports for every listener so the test never collides on a busy runner.
    let relay = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay.local_addr().unwrap();
    drop(relay);
    let health = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let health_addr = health.local_addr().unwrap();
    drop(health);
    let stun_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let stun_addr = stun_sock.local_addr().unwrap();
    drop(stun_sock);

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

    // A client UDP socket on loopback: its local addr is exactly what the server should reflect back.
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();

    let tid: TransactionId = [9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 42, 17];
    client
        .send_to(&binding_request(&tid), stun_addr)
        .await
        .expect("send Binding Request");

    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
        .await
        .expect("STUN response should arrive")
        .expect("recv ok");

    let response = &buf[..n];
    // The response must be a Binding Success Response echoing our transaction id.
    assert_eq!(
        u16::from_be_bytes([response[0], response[1]]),
        stun::msgtype::BINDING_SUCCESS_RESPONSE
    );
    assert_eq!(&response[8..20], &tid, "transaction id echoed");

    let value = stun::find_xor_mapped_address(response).expect("has XOR-MAPPED-ADDRESS");
    let reflexive = stun::decode_xor_mapped_address(&tid, value).expect("decodes");
    assert_eq!(
        reflexive, client_addr,
        "the relay reflects the client's own source address"
    );
}

#[tokio::test]
async fn stun_ignores_a_non_stun_datagram() {
    let relay = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay.local_addr().unwrap();
    drop(relay);
    let health = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let health_addr = health.local_addr().unwrap();
    drop(health);
    let stun_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let stun_addr = stun_sock.local_addr().unwrap();
    drop(stun_sock);

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

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // Garbage (no magic cookie) → the STUN server must NOT reply.
    client
        .send_to(b"this is not a stun message at all", stun_addr)
        .await
        .expect("send garbage");

    let mut buf = [0u8; 256];
    let got = tokio::time::timeout(Duration::from_millis(400), client.recv(&mut buf)).await;
    assert!(
        got.is_err(),
        "a non-STUN datagram must get no reply (timeout expected)"
    );
}
