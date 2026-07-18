//! End-to-end integration test for the peer-stats dashboard (#1012): bind the real dashboard HTTP
//! listener, seed the relay's registry + counters, then make actual `GET /` and `GET /stats.json`
//! requests over a raw TCP socket and assert the responses — proving the live axum handlers, not just
//! the pure snapshot builder.

use std::sync::atomic::Ordering;

use dig_relay::wire::RelayPeerInfo;
use dig_relay::{dashboard, RelayServerConfig, RelayState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Start the dashboard on an ephemeral loopback port and return its bound address. The relay state is
/// seeded with one registered peer and non-zero counters so the response has content to assert on.
async fn start_seeded_dashboard() -> std::net::SocketAddr {
    // Bind an ephemeral port first to learn a free address, then hand that exact address to the
    // dashboard config (the dashboard re-binds it dual-stack via the shared net helper).
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let config = RelayServerConfig {
        dashboard_listen: addr,
        ..Default::default()
    };
    let state = RelayState::new(config);

    // Seed one peer with a resolved IPv4 dialable address (so it renders as via=direct, family=v4).
    {
        let mut reg = state.registry.lock().await;
        let mut info = RelayPeerInfo::new("peeralphabravocharlie".into(), "mainnet".into(), 1);
        info.addresses = vec!["203.0.113.7:9444".parse().unwrap()];
        reg.register(
            "peeralphabravocharlie".into(),
            "mainnet".into(),
            info,
            tokio::sync::mpsc::channel(1).0,
        );
    }
    state.connected.store(1, Ordering::Relaxed);
    state.stun_requests.store(9, Ordering::Relaxed);
    state.hole_punch_successes.store(2, Ordering::Relaxed);

    tokio::spawn(async move { dashboard::run(state).await });
    // Give the listener a moment to bind before the first request.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    addr
}

/// Make a raw HTTP/1.1 GET and return the full response text (headers + body).
async fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(addr)
        .await
        .expect("connect to dashboard");
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: relay.dig.net\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8_lossy(&response).into_owned()
}

#[tokio::test]
async fn stats_json_endpoint_serves_the_live_snapshot() {
    let addr = start_seeded_dashboard().await;
    let response = http_get(addr, "/stats.json").await;

    assert!(
        response.contains("200 OK"),
        "expected 200, got:\n{response}"
    );
    assert!(response.contains("application/json"));
    // Aggregate + counter fields reflect the seeded state.
    assert!(response.contains("\"active_reservations\":1"));
    assert!(response.contains("\"connected_peers\":1"));
    assert!(response.contains("\"stun_requests\":9"));
    assert!(response.contains("\"hole_punch_successes\":2"));
    assert!(response.contains("\"schema_version\":1"));
    // The peer row is present, via=direct, family=v4; peer_id truncated by default.
    assert!(response.contains("\"via\":\"direct\""));
    assert!(response.contains("\"address_family\":\"v4\""));
    assert!(response.contains("peeralphabra…"));
    assert!(
        !response.contains("peeralphabravocharlie"),
        "full peer_id must be truncated without ?full=1"
    );
}

#[tokio::test]
async fn stats_json_full_query_reveals_the_untruncated_peer_id() {
    let addr = start_seeded_dashboard().await;
    let response = http_get(addr, "/stats.json?full=1").await;
    assert!(response.contains("200 OK"));
    assert!(
        response.contains("peeralphabravocharlie"),
        "?full=1 must reveal the full peer_id"
    );
}

#[tokio::test]
async fn index_serves_the_html_dashboard() {
    let addr = start_seeded_dashboard().await;
    let response = http_get(addr, "/").await;
    assert!(response.contains("200 OK"));
    assert!(response.contains("text/html"));
    assert!(response.contains("DIG</span> Relay"));
    assert!(response.contains("/stats.json"));
}
