//! End-to-end integration test for the peer-stats dashboard (#1012, #1041). The relay supports only
//! HTTPS/WSS, so the dashboard is served over the WIRE listener itself (a browser `GET /` on the same
//! TLS-terminated port that carries the WebSocket wire), and the separate `--dashboard-listen` port
//! only redirects plain HTTP to `https://`. These tests bind the real listeners, seed the relay's
//! registry + counters, and make actual `GET` requests over raw TCP — proving the live serving path,
//! not just the pure snapshot builder.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use dig_relay::wire::RelayPeerInfo;
use dig_relay::{server, RelayServerConfig, RelayState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Reserve a free loopback address, then drop the probe so a real listener can rebind it.
async fn free_addr() -> std::net::SocketAddr {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    addr
}

/// Seed a relay state with one registered peer (resolved IPv4 dialable → via=direct, family=v4) and
/// non-zero counters so the dashboard response has content to assert on.
async fn seeded_state(config: RelayServerConfig) -> Arc<RelayState> {
    let state = RelayState::new(config);
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
    state
}

/// Start the WIRE listener (which serves the dashboard for non-WebSocket GETs) on a free loopback
/// port and return its address.
async fn start_seeded_dashboard() -> std::net::SocketAddr {
    let addr = free_addr().await;
    let config = RelayServerConfig {
        listen: addr,
        ..Default::default()
    };
    let state = seeded_state(config).await;
    tokio::spawn(async move { server::run(state).await });
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

#[tokio::test]
async fn mascot_endpoint_serves_the_embedded_png() {
    let addr = start_seeded_dashboard().await;
    let response = http_get(addr, "/mascot.png").await;
    assert!(response.contains("200 OK"));
    assert!(response.contains("image/png"));
    assert!(
        response.contains("Cache-Control: public, max-age=31536000, immutable"),
        "the mascot is served with a long immutable cache"
    );
}

#[tokio::test]
async fn plain_http_redirects_to_https() {
    // The dedicated redirect listener (the `--dashboard-listen` port) 301s every plain-HTTP request
    // to the https origin — the relay serves content only over HTTPS/WSS (#1041).
    let addr = free_addr().await;
    tokio::spawn(async move { dig_relay::dashboard::run_redirect(addr).await });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let response = http_get(addr, "/stats.json?full=1").await;
    assert!(
        response.contains("301 Moved Permanently"),
        "expected a 301, got:\n{response}"
    );
    assert!(
        response.contains("Location: https://relay.dig.net/stats.json?full=1"),
        "must redirect to the https origin preserving host + path, got:\n{response}"
    );
}
