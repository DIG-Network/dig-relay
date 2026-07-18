//! End-to-end mTLS proof-of-possession tests (SPEC.md §3.2/§8, super-repo issue
//! `DIG-Network/dig_ecosystem#5`): drive a REAL relay with `tls_cert_path`/`tls_key_path`
//! configured, connect real mTLS clients (self-signed identities via `rcgen`, exactly the shape a
//! real DIG node identity takes), and prove:
//!
//! - a client registering the `peer_id` its OWN certificate commits to is accepted;
//! - a client registering a DIFFERENT (spoofed) `peer_id` is refused with `IDENTITY_MISMATCH`,
//!   even though nothing else about the connection is wrong;
//! - a client presenting NO certificate at all never reaches the `RelayMessage` wire — the relay's
//!   mandatory client-auth TLS config refuses the handshake itself (the "unsigned Register" case).
//!
//! `src/tls.rs`'s own unit tests cover the handshake/identity-derivation plumbing directly over an
//! in-memory duplex stream; this file is the full stack over real TCP sockets.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dig_relay::wire::RelayMessage;
use dig_relay::RelayServerConfig;
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

type TlsWs = WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;

async fn free_addr() -> std::net::SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a
}

async fn free_udp_addr() -> std::net::SocketAddr {
    let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a = s.local_addr().unwrap();
    drop(s);
    a
}

/// A throwaway self-signed identity (cert DER + key DER + PEM forms) via `rcgen` — exactly the
/// self-signed shape a real DIG node/relay identity takes (CLAUDE.md §5.2/§5.3: no CA, the key IS
/// the identity).
struct Identity {
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
    cert_pem: String,
    key_pem: String,
}

fn generate_identity() -> Identity {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["dig-relay-mtls-test".to_string()]).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let cert_der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());
    Identity {
        cert_der,
        key_der,
        cert_pem,
        key_pem,
    }
}

/// Write `identity`'s PEM cert/key to two unique files under the OS temp dir, returning their paths.
fn write_pem_files(identity: &Identity) -> (std::path::PathBuf, std::path::PathBuf) {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir();
    let cert_path = dir.join(format!(
        "dig-relay-mtls-test-{}-{n}-cert.pem",
        std::process::id()
    ));
    let key_path = dir.join(format!(
        "dig-relay-mtls-test-{}-{n}-key.pem",
        std::process::id()
    ));
    std::fs::write(&cert_path, &identity.cert_pem).unwrap();
    std::fs::write(&key_path, &identity.key_pem).unwrap();
    (cert_path, key_path)
}

/// Start a relay with mTLS enabled (the server's own throwaway identity) and free ports for every
/// listener. Returns `(relay_addr, health_addr)`.
async fn start_mtls_relay() -> (std::net::SocketAddr, std::net::SocketAddr) {
    let server_identity = generate_identity();
    let (cert_path, key_path) = write_pem_files(&server_identity);

    let relay_addr = free_addr().await;
    let health_addr = free_addr().await;
    let stun_addr = free_udp_addr().await;
    let config = RelayServerConfig {
        listen: relay_addr,
        health_listen: health_addr,
        stun_listen: stun_addr,
        tls_cert_path: Some(cert_path),
        tls_key_path: Some(key_path),
        ..Default::default()
    };
    tokio::spawn(async move {
        let _ = dig_relay::serve(config).await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    (relay_addr, health_addr)
}

/// A permissive "accept any server certificate" verifier for the TEST client — the relay's own TLS
/// identity in these tests is a throwaway self-signed cert; the tests only exercise the CLIENT-auth
/// (mTLS) side.
#[derive(Debug)]
struct AcceptAnyServerCert;
impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Dial the relay over mTLS presenting `client_identity`'s certificate, returning the WebSocket
/// stream. `None` client identity dials with NO client certificate at all (anonymous TLS client) —
/// used to prove the mandatory-client-auth rejection.
async fn dial_mtls(
    relay_addr: std::net::SocketAddr,
    client_identity: Option<&Identity>,
) -> std::io::Result<TlsWs> {
    let builder = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert));
    let client_config = Arc::new(match client_identity {
        Some(id) => builder
            .with_client_auth_cert(vec![id.cert_der.clone()], id.key_der.clone_key())
            .expect("valid client identity"),
        None => builder.with_no_client_auth(),
    });

    let tcp = tokio::net::TcpStream::connect(relay_addr).await?;
    let connector = TlsConnector::from(client_config);
    let server_name = ServerName::try_from("dig-relay-mtls-test").unwrap();
    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(std::io::Error::other)?;
    let url = format!("wss://{relay_addr}");
    let (ws, _resp) = tokio_tungstenite::client_async(url, tls)
        .await
        .map_err(std::io::Error::other)?;
    Ok(ws)
}

async fn send(ws: &mut TlsWs, msg: &RelayMessage) {
    ws.send(Message::Text(serde_json::to_string(msg).unwrap()))
        .await
        .expect("send");
}

async fn next_msg(ws: &mut TlsWs) -> RelayMessage {
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

#[tokio::test]
async fn a_client_registering_its_own_certificate_derived_peer_id_is_accepted() {
    let (relay_addr, _health) = start_mtls_relay().await;
    let client = generate_identity();
    let peer_id = dig_relay::tls::peer_id_from_client_cert_der(client.cert_der.as_ref())
        .expect("cert parses");

    let mut ws = dial_mtls(relay_addr, Some(&client))
        .await
        .expect("mTLS handshake with a valid client cert must succeed");
    send(
        &mut ws,
        &RelayMessage::Register {
            peer_id: peer_id.clone(),
            network_id: "net".into(),
            protocol_version: 1,
            listen_addrs: vec![],
        },
    )
    .await;
    match next_msg(&mut ws).await {
        RelayMessage::RegisterAck { success, .. } => {
            assert!(success, "the certificate's own peer_id must register");
        }
        other => panic!("expected RegisterAck, got {other:?}"),
    }
}

#[tokio::test]
async fn a_client_registering_a_spoofed_peer_id_is_rejected_with_identity_mismatch() {
    let (relay_addr, _health) = start_mtls_relay().await;
    let client = generate_identity();
    // The client presents ITS OWN certificate over TLS (a valid mTLS handshake — it genuinely
    // holds this key) but then claims a DIFFERENT peer_id in the RLY-001 Register payload.
    let mut ws = dial_mtls(relay_addr, Some(&client))
        .await
        .expect("a valid client certificate must still complete the mTLS handshake");
    send(
        &mut ws,
        &RelayMessage::Register {
            peer_id: "0".repeat(64), // spoofed: not this client's own cert-derived id
            network_id: "net".into(),
            protocol_version: 1,
            listen_addrs: vec![],
        },
    )
    .await;
    match next_msg(&mut ws).await {
        RelayMessage::RegisterAck { success, .. } => {
            assert!(!success, "a spoofed peer_id must be refused");
        }
        other => panic!("expected a failing RegisterAck, got {other:?}"),
    }
    match next_msg(&mut ws).await {
        RelayMessage::Error { code, .. } => {
            assert_eq!(code, dig_relay::server::errcode::IDENTITY_MISMATCH);
        }
        other => panic!("expected IDENTITY_MISMATCH error, got {other:?}"),
    }
}

#[tokio::test]
async fn a_connection_with_no_client_certificate_never_reaches_the_relay_message_wire() {
    let (relay_addr, _health) = start_mtls_relay().await;
    // No client identity at all: the relay's mandatory-client-auth TLS config must refuse the
    // handshake itself — the "unsigned Register" case never even reaches RLY-001.
    let result = dial_mtls(relay_addr, None).await;
    assert!(
        result.is_err(),
        "an anonymous (no client cert) connection must fail the mTLS handshake"
    );
}

#[tokio::test]
async fn health_endpoint_still_answers_plain_http_when_relay_listener_is_mtls() {
    // The mTLS listener is the RELAY (RLY-001..008) listener only; `/health` stays plain HTTP for
    // the load balancer's target-group probe (SPEC.md §2/§6) regardless of relay-listener TLS.
    let (_relay_addr, health_addr) = start_mtls_relay().await;
    let body = tokio::task::spawn_blocking(move || {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect(health_addr).unwrap();
        s.write_all(b"GET /health HTTP/1.0\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    })
    .await
    .unwrap();
    assert!(body.contains("200"), "health returns 200: {body}");
}
