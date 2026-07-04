//! Optional mTLS termination for the relay's own listener — proof-of-possession for `peer_id`
//! registration (SPEC.md §3.2/§8, super-repo issue `DIG-Network/dig_ecosystem#5`).
//!
//! # Why
//!
//! CLAUDE.md §5.2/§5.3 fixes the DIG identity model: `peer_id = SHA-256(TLS SPKI DER)`, and every
//! node-class connection is mutually-authenticated TLS. Before this module, `dig-relay` spoke plain
//! `ws://` and relied ONLY on the anti-hijack registry check (`src/registry.rs` —
//! `RegisterOutcome::Occupied`): a `Register` could still name any `peer_id`, live or not, with no
//! proof the registrant actually held the matching private key. This module closes that gap: when
//! an operator configures [`crate::config::RelayServerConfig::tls_cert_path`] /
//! `tls_key_path`, the relay terminates TLS itself on its main listener and REQUIRES a client
//! certificate. `src/server.rs::register_peer` then requires the `Register` message's claimed
//! `peer_id` to equal the one derived from the certificate actually used for the TLS session
//! (`errcode::IDENTITY_MISMATCH` otherwise) — a peer cannot register an id it does not hold the key
//! for.
//!
//! # Why this needs no `dig-gossip` wire change
//!
//! The proof-of-possession is enforced by the TLS handshake itself, not by an extra signature field
//! in the JSON `Register` message: TLS client authentication requires the client to sign the
//! handshake transcript with the private key matching its presented certificate
//! (`ClientCertVerifier::verify_tls12_signature`/`verify_tls13_signature` below, delegated to
//! rustls/ring), and a client cannot complete the handshake without that key. The relay derives the
//! resulting `peer_id` from the certificate AFTER the handshake ([`extract_client_peer_id`]) and
//! compares it to the already-existing `peer_id` field the wire has always carried. No new
//! `RelayMessage` field, and therefore no coordinated `dig-gossip` `relay_types.rs` change, is
//! required — see SPEC.md §3.2 for the full rationale and the (unchanged) wire shape.
//!
//! # Verification model — no CA, key-is-identity
//!
//! DIG peers use self-signed certificates whose *public key* is the identity (matching
//! `dig-nat::mtls`/`dig-gossip`'s inbound listener — there is no CA to validate a chain against).
//! [`AnyClientCertVerifier`] therefore does not check a chain of trust; it only requires a
//! well-formed, parseable X.509 leaf certificate, and delegates the actual cryptographic
//! signature-over-the-transcript check to rustls/ring (the real proof-of-possession). Because the
//! verifier is shared across every accepted connection on the listener, it does NOT stash any
//! per-connection identity (that would race); [`extract_client_peer_id`] reads the peer_id
//! per-connection, directly off the completed [`tokio_rustls::server::TlsStream`].

use std::sync::Arc;

use rustls::client::danger::HandshakeSignatureValid;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use sha2::{Digest, Sha256};

/// Parse a PEM certificate chain + PEM private key (the relay's OWN TLS identity — may itself be a
/// throwaway self-signed cert; the relay's server identity is not what `peer_id` binds to) into the
/// DER forms [`build_server_config`] needs. Uses `rustls-pki-types`' own [`PemObject`] trait (not the
/// separate, now-unmaintained `rustls-pemfile` crate — RUSTSEC-2025-0134 — which wrapped this exact
/// code); already a transitive dependency of `rustls`, so this adds no new dependency.
pub fn load_pem_identity(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("dig-relay: could not parse TLS certificate PEM: {e}"))?;
    if certs.is_empty() {
        return Err("dig-relay: TLS certificate PEM contains no certificates".to_string());
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem)
        .map_err(|e| format!("dig-relay: could not parse TLS private key PEM: {e}"))?;
    Ok((certs, key))
}

/// Build a [`rustls::ServerConfig`] for the relay's mTLS listener: the relay's own identity is
/// `cert_chain`/`key`; every inbound connection MUST present a client certificate
/// ([`AnyClientCertVerifier::client_auth_mandatory`]).
pub fn build_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<rustls::ServerConfig>, String> {
    let verifier: Arc<dyn ClientCertVerifier> = Arc::new(AnyClientCertVerifier::new());
    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, key)
        .map_err(|e| format!("dig-relay: invalid TLS server certificate/key: {e}"))?;
    Ok(Arc::new(config))
}

/// A [`ClientCertVerifier`] for the DIG self-authenticating peer overlay — see the module docs
/// "Verification model" for the full rationale.
#[derive(Debug)]
struct AnyClientCertVerifier {
    schemes: Vec<SignatureScheme>,
}

impl AnyClientCertVerifier {
    fn new() -> Self {
        AnyClientCertVerifier {
            schemes: rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes(),
        }
    }
}

impl ClientCertVerifier for AnyClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        // mTLS is REQUIRED on this listener: an inbound connection presenting no client certificate
        // fails the TLS handshake before it ever reaches the RelayMessage wire — the transport-level
        // rejection of an "unsigned Register" (issue #5 acceptance criterion).
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // No CA: DIG peer certs are self-signed, so there is no trust-anchor subject to hint.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        // Accept any WELL-FORMED leaf certificate — no chain-of-trust check (see module docs). A
        // certificate that does not even parse as X.509 is rejected here; a parseable one is
        // accepted, and its `peer_id` is derived + checked against the `Register` claim AFTER the
        // handshake (`extract_client_peer_id` + `server::register_peer`).
        if x509_parser::parse_x509_certificate(end_entity.as_ref()).is_err() {
            return Err(TlsError::General(
                "client leaf certificate could not be parsed as X.509".to_string(),
            ));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        // THE proof-of-possession check: rustls/ring verifies the client actually signed this TLS
        // handshake transcript with the private key matching `cert`'s public key. A client cannot
        // reach this point without holding that key.
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
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

/// Derive `peer_id = SHA-256(TLS SubjectPublicKeyInfo DER)` (lowercase hex) from a leaf certificate
/// DER, matching `dig-nat`/`dig-gossip`'s identity derivation byte-for-byte (CLAUDE.md §5.2/§5.3).
/// Returns `None` if `cert_der` does not parse as X.509 (should not happen for a certificate that
/// already passed [`AnyClientCertVerifier::verify_client_cert`]).
pub fn peer_id_from_client_cert_der(cert_der: &[u8]) -> Option<String> {
    let (_, x509) = x509_parser::parse_x509_certificate(cert_der).ok()?;
    let spki_der = x509.tbs_certificate.subject_pki.raw;
    let digest = Sha256::digest(spki_der);
    Some(hex_lower(&digest))
}

/// Lowercase-hex encode `bytes` (no external hex crate — mirrors `dig-nat::identity::PeerId::to_hex`).
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// After an mTLS handshake completes, read the `peer_id` derived from the certificate the CLIENT
/// actually presented for THIS connection. `None` only if the peer presented no certificate at all
/// (impossible once [`AnyClientCertVerifier::client_auth_mandatory`] has accepted the handshake) or
/// its leaf could not be parsed (already rejected during the handshake) — kept as `Option` rather
/// than panicking so a future rustls/verifier change fails closed (no identity ⇒ no match) instead
/// of crashing the accept loop.
pub fn extract_client_peer_id<IO>(
    tls_stream: &tokio_rustls::server::TlsStream<IO>,
) -> Option<String> {
    let (_, conn) = tls_stream.get_ref();
    let certs = conn.peer_certificates()?;
    let leaf = certs.first()?;
    peer_id_from_client_cert_der(leaf.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Build a throwaway self-signed cert (rcgen), returning `(cert_der, key_der, key_pem, cert_pem)`.
    fn self_signed() -> (
        CertificateDer<'static>,
        PrivateKeyDer<'static>,
        String,
        String,
    ) {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["dig-relay-test".to_string()]).unwrap();
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());
        (cert_der, key_der, key_pair.serialize_pem(), cert.pem())
    }

    #[test]
    fn peer_id_from_client_cert_der_matches_sha256_of_spki() {
        let (cert_der, _key, _key_pem, _cert_pem) = self_signed();
        let (_, x509) = x509_parser::parse_x509_certificate(cert_der.as_ref()).unwrap();
        let expected = hex_lower(&Sha256::digest(x509.tbs_certificate.subject_pki.raw));

        let got = peer_id_from_client_cert_der(cert_der.as_ref()).expect("parses");
        assert_eq!(got, expected);
        assert_eq!(got.len(), 64, "SHA-256 hex is 64 chars");
    }

    #[test]
    fn peer_id_from_client_cert_der_is_none_for_garbage() {
        assert!(peer_id_from_client_cert_der(b"not a certificate").is_none());
    }

    #[test]
    fn different_certs_derive_different_peer_ids() {
        let (a, ..) = self_signed();
        let (b, ..) = self_signed();
        assert_ne!(
            peer_id_from_client_cert_der(a.as_ref()),
            peer_id_from_client_cert_der(b.as_ref())
        );
    }

    #[test]
    fn load_pem_identity_round_trips_an_rcgen_cert() {
        let (_der, _key, key_pem, cert_pem) = self_signed();
        let (certs, _key) =
            load_pem_identity(cert_pem.as_bytes(), key_pem.as_bytes()).expect("valid PEM");
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn load_pem_identity_rejects_empty_cert_pem() {
        let (_der, _key, key_pem, _cert_pem) = self_signed();
        let err = load_pem_identity(b"", key_pem.as_bytes()).unwrap_err();
        assert!(err.contains("no certificates"), "{err}");
    }

    #[test]
    fn load_pem_identity_rejects_empty_key_pem() {
        let (_der, _key, _key_pem, cert_pem) = self_signed();
        let err = load_pem_identity(cert_pem.as_bytes(), b"").unwrap_err();
        assert!(err.contains("private key"), "{err}");
    }

    /// A minimal "accept any server cert" rustls verifier for the TEST client only — dig-relay's own
    /// server identity in these tests is a throwaway self-signed cert, and the test only cares about
    /// the CLIENT-auth (mTLS) side of the handshake.
    #[derive(Debug)]
    struct AcceptAnyServerCert;
    impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, TlsError> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
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
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &rustls::crypto::ring::default_provider().signature_verification_algorithms,
            )
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    fn client_config_with_cert(
        cert_der: CertificateDer<'static>,
        key_der: PrivateKeyDer<'static>,
    ) -> Arc<rustls::ClientConfig> {
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
            .with_client_auth_cert(vec![cert_der], key_der)
            .expect("valid client identity");
        Arc::new(config)
    }

    /// End-to-end over an in-memory duplex "socket": a real rustls handshake proving (a) a client
    /// presenting ITS OWN cert derives that cert's `peer_id` on the server side (proof-of-possession
    /// is enforced by the TLS layer itself — the client could not complete the handshake without the
    /// matching private key), and (b) a connection presenting NO client certificate is refused by the
    /// mandatory-client-auth server config (the "unsigned Register" rejection happens at the TRANSPORT
    /// layer, before any `RelayMessage` is ever read).
    #[tokio::test]
    async fn server_derives_the_exact_peer_id_the_client_certificate_commits_to() {
        let (server_cert, server_key, ..) = self_signed();
        let server_config = build_server_config(vec![server_cert], server_key).unwrap();

        let (client_cert, client_key, ..) = self_signed();
        let expected_peer_id = peer_id_from_client_cert_der(client_cert.as_ref()).unwrap();
        let client_config = client_config_with_cert(client_cert, client_key);

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let server_task = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            let mut tls = acceptor.accept(server_io).await.expect("server handshake");
            let derived = extract_client_peer_id(&tls);
            // Echo a probe byte back so BOTH sides observe a full round trip before either tears
            // down. Without this, the client completing its handshake and immediately dropping its
            // stream can race the server's post-handshake NewSessionTicket write over the in-memory
            // duplex, surfacing as a spurious `BrokenPipe` on the SERVER side even though the
            // handshake itself (and the identity derivation above) already succeeded.
            let mut probe = [0u8; 1];
            tls.read_exact(&mut probe).await.expect("read probe byte");
            tls.write_all(&probe).await.expect("echo probe byte");
            let _ = tls.shutdown().await;
            derived
        });

        let client_task = tokio::spawn(async move {
            let connector = tokio_rustls::TlsConnector::from(client_config);
            let server_name = rustls::pki_types::ServerName::try_from("dig-relay-test").unwrap();
            let mut tls = connector
                .connect(server_name, client_io)
                .await
                .expect("client handshake");
            tls.write_all(b"x").await.unwrap();
            let mut echoed = [0u8; 1];
            tls.read_exact(&mut echoed).await.expect("read echo");
            assert_eq!(&echoed, b"x", "server must echo the exact probe byte");
        });

        let (server_res, client_res) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(server_task, client_task)
        })
        .await
        .expect("handshake must not hang");
        client_res.unwrap();
        let derived = server_res.unwrap();
        assert_eq!(
            derived,
            Some(expected_peer_id),
            "the server must derive exactly the peer_id the client's own certificate commits to"
        );
    }

    #[tokio::test]
    async fn a_connection_with_no_client_certificate_fails_the_handshake() {
        let (server_cert, server_key, ..) = self_signed();
        let server_config = build_server_config(vec![server_cert], server_key).unwrap();

        // A client config with NO client certificate configured (anonymous TLS client).
        let client_config = Arc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
                .with_no_client_auth(),
        );

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let server_task = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            acceptor.accept(server_io).await
        });
        let client_task = tokio::spawn(async move {
            let connector = tokio_rustls::TlsConnector::from(client_config);
            let server_name = rustls::pki_types::ServerName::try_from("dig-relay-test").unwrap();
            let mut tls = connector.connect(server_name, client_io).await?;
            // Drive the connection so the server side observes the post-handshake alert.
            let mut buf = [0u8; 1];
            let _ = tls.read(&mut buf).await;
            Ok::<_, std::io::Error>(())
        });

        let (server_res, _client_res) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(server_task, client_task)
        })
        .await
        .expect("handshake must not hang");
        assert!(
            server_res.unwrap().is_err(),
            "mandatory client auth must reject a connection with no client certificate"
        );
    }
}
