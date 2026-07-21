//! Relay WebSocket server — accept loop, per-connection task, and `RelayMessage` dispatch.
//!
//! Implements the SERVER side of the dig-gossip relay wire (RLY-001..RLY-007), JSON over
//! WebSocket. The matching CLIENT lives in `dig-gossip` (`relay/relay_client.rs`); both sides use
//! the same [`RelayMessage`] shape — here via the vendored [`crate::wire`] types pinned to
//! dig-gossip's by `tests/wire_conformance.rs` — so the wire cannot drift.
//!
//! Per connection: read frames → parse [`RelayMessage`] → [`dispatch`] decides the action →
//! the task performs it (reply, forward, fan-out, register/unregister). Outbound to a peer is via
//! that peer's `mpsc` sender held in the [`Registry`]; a dedicated writer task drains the channel
//! onto the socket so forwards from OTHER connections reach this peer without lock contention.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message;

use crate::config::RelayServerConfig;
use crate::net::bind_tcp_dual_stack;
use crate::pex::PexRelay;
use crate::registry::{RegisterOutcome, Registry};
use crate::wire::{PexMessage, RelayMessage, RelayPeerInfo};

/// How often the PEX housekeeping timer drives [`PexRelay::tick`] (SPEC §6, Appendix A step 4). The
/// PEX engine spaces each link's own `pex_delta`s by its effective interval (≥ 30 s); this cadence is
/// only how often the relay *checks* whether a link is due, so ~1/s is ample and cheap.
const PEX_TICK_INTERVAL: Duration = Duration::from_secs(1);

/// Stable relay error codes (the `code` field of [`RelayMessage::Error`]). Catalogued so an agent
/// never has to scrape prose to learn what the relay rejected.
pub mod errcode {
    /// A message arrived before the connection completed `Register` (RLY-001).
    pub const NOT_REGISTERED: u32 = 1;
    /// The frame was not valid relay JSON.
    pub const BAD_MESSAGE: u32 = 2;
    /// `RelayGossipMessage`/`HolePunch*` named a `to`/`target` peer not on this network.
    pub const PEER_NOT_FOUND: u32 = 3;
    /// The relay is at its connection cap (RLY-001 register refused).
    pub const CAPACITY: u32 = 4;
    /// A `Register` named a `peer_id` already held by a LIVE connection — refused so an
    /// unauthenticated client cannot evict + impersonate an existing peer (SECURITY_AUDIT_P2P #1).
    pub const ID_IN_USE: u32 = 5;
    /// mTLS is active on this listener and the `Register`'s claimed `peer_id` does NOT match the
    /// `peer_id` derived from the client certificate actually used for this TLS session — refused so
    /// a peer cannot register an id it does not hold the key for (proof-of-possession, SPEC.md
    /// §3.2/§8, super-repo issue `DIG-Network/dig_ecosystem#5`).
    pub const IDENTITY_MISMATCH: u32 = 6;
    /// A `Register` was refused by the app-level abuse limits (#1386): the source IP exceeded its
    /// per-IP registration RATE budget or its per-IP concurrent-registration cap. Distinct from
    /// `CAPACITY` (the GLOBAL connection cap) so a client can tell a per-source throttle from the
    /// relay being globally full. Like `CAPACITY`, it accompanies a failing `register_ack`.
    pub const RATE_LIMITED: u32 = 7;
}

/// Shared relay state: the registry plus a connected-peer counter for `/health`.
pub struct RelayState {
    /// The peer registry (the only routing state). Guarded by an async mutex; locks are held
    /// briefly (clone a sender out, drop the lock, then send).
    pub registry: Mutex<Registry>,
    /// The introducer PEX subsystem (RLY-008): one `PexEngine` per network + per-connection PEX
    /// senders. Registration mirrors into it; the housekeeping tick routes its deltas out. Guarded by
    /// its own async mutex so PEX work never blocks the RLY routing lock (and vice versa).
    pub pex: Mutex<PexRelay>,
    /// Live connected-peer count, mirrored from the registry for a lock-free `/health` read.
    pub connected: AtomicU64,
    /// Live OPEN-socket count — every accepted connection (whether or not it has registered) counts
    /// here, so the connection cap covers half-open / never-registering sockets too (SECURITY_AUDIT_P2P
    /// dig-relay #5). Incremented right after the WebSocket upgrade, decremented when the connection
    /// task exits (via an RAII guard so it can never leak).
    pub open_connections: AtomicU64,
    /// Total STUN Binding Requests answered since start (RFC 5389, `src/stun.rs`). A cheap monotonic
    /// counter surfaced on the peer-stats dashboard — a rising value confirms NAT'd nodes are reaching
    /// the relay's reflexive-address service, invaluable for debugging the connect leg.
    pub stun_requests: AtomicU64,
    /// Total `HolePunchRequest`s received + forwarded as a `HolePunchCoordinate` (RLY-007).
    pub hole_punch_requests: AtomicU64,
    /// Total `HolePunchResult`s reporting `success: true` (a direct path was established).
    pub hole_punch_successes: AtomicU64,
    /// Total `HolePunchResult`s reporting `success: false` (hole-punch failed → relayed fallback).
    pub hole_punch_failures: AtomicU64,
    /// Total payload bytes accepted for relaying (the summed `payload` length of every inbound
    /// `RelayGossipMessage` + `Broadcast`). Counts bytes RECEIVED for forwarding, once per inbound
    /// frame regardless of fan-out — a cheap gauge of relayed-fallback traffic volume.
    pub bytes_relayed: AtomicU64,
    /// Process start time, for `/health` uptime.
    pub started: SystemTime,
    /// Validated config.
    pub config: RelayServerConfig,
    /// The relay's mTLS server config (`src/tls.rs`), built once at startup from
    /// [`RelayServerConfig::tls_cert_path`]/`tls_key_path`. `None` keeps the listener plain `ws://`
    /// (the default — SPEC.md §3.2/§8).
    pub tls: Option<Arc<rustls::ServerConfig>>,
    /// App-level abuse protection (#1386): the shared per-source-IP connection / registration limits
    /// (`src/limits.rs`). The accept loop reserves a per-IP connection slot and `register_peer`
    /// checks the per-IP registration rate + concurrent-registration cap. The per-connection
    /// message/byte limiter is task-local (a `PerConnLimiter`), not held here.
    pub abuse: crate::limits::AbusePolicy,
}

impl RelayState {
    /// Build shared state from a validated config, with mTLS disabled (plain `ws://`). Most tests
    /// use this; TLS-specific tests use [`RelayState::new_with_tls`].
    pub fn new(config: RelayServerConfig) -> Arc<Self> {
        RelayState::new_with_tls(config, None)
    }

    /// Build shared state from a validated config and an OPTIONAL pre-built mTLS server config
    /// (`Some` enables client-cert-mandatory TLS termination on the relay listener — SPEC.md §3.2/§8).
    pub fn new_with_tls(
        config: RelayServerConfig,
        tls: Option<Arc<rustls::ServerConfig>>,
    ) -> Arc<Self> {
        Arc::new(RelayState {
            abuse: crate::limits::AbusePolicy::new(&config),
            registry: Mutex::new(Registry::new()),
            pex: Mutex::new(PexRelay::new()),
            connected: AtomicU64::new(0),
            open_connections: AtomicU64::new(0),
            stun_requests: AtomicU64::new(0),
            hole_punch_requests: AtomicU64::new(0),
            hole_punch_successes: AtomicU64::new(0),
            hole_punch_failures: AtomicU64::new(0),
            bytes_relayed: AtomicU64::new(0),
            started: SystemTime::now(),
            config,
            tls,
        })
    }

    /// Seconds since process start (saturating).
    pub fn uptime_secs(&self) -> u64 {
        self.started.elapsed().map(|d| d.as_secs()).unwrap_or(0)
    }

    /// Fold one inbound [`RelayMessage`] into the dashboard traffic counters. Called for every parsed
    /// RLY frame; only relayed-traffic and NAT-traversal kinds move a counter, everything else is a
    /// no-op. Cheap (a `match` + a `Relaxed` atomic add) so it never slows the hot path.
    ///
    /// The counters are observational gauges: `HolePunchRequest`/`Result` are counted as they arrive
    /// (an attempt/outcome the requester reported), and relayed bytes are the `payload` length of each
    /// inbound `RelayGossipMessage`/`Broadcast` — counted once per frame, independent of fan-out.
    pub fn record_relayed(&self, msg: &RelayMessage) {
        match msg {
            RelayMessage::RelayGossipMessage { payload, .. }
            | RelayMessage::Broadcast { payload, .. } => {
                self.bytes_relayed
                    .fetch_add(payload.len() as u64, Ordering::Relaxed);
            }
            RelayMessage::HolePunchRequest { .. } => {
                self.hole_punch_requests.fetch_add(1, Ordering::Relaxed);
            }
            RelayMessage::HolePunchResult { success, .. } => {
                let counter = if *success {
                    &self.hole_punch_successes
                } else {
                    &self.hole_punch_failures
                };
                counter.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }
}

/// RAII guard for the open-socket counter (SECURITY_AUDIT_P2P dig-relay #5). Incrementing on
/// construction and decrementing on `Drop` means an accepted connection is counted for its entire
/// lifetime and released on EVERY exit path (normal close, ws error, idle/register timeout, panic
/// unwinding) — the count can never leak, so the open-connection cap stays accurate.
struct OpenConnectionGuard {
    state: Arc<RelayState>,
}

impl OpenConnectionGuard {
    fn acquire(state: &Arc<RelayState>) -> Self {
        state.open_connections.fetch_add(1, Ordering::Relaxed);
        OpenConnectionGuard {
            state: state.clone(),
        }
    }
}

impl Drop for OpenConnectionGuard {
    fn drop(&mut self) {
        self.state.open_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Current Unix-epoch time in milliseconds (saturating) — the clock the [`PexRelay`] runs on (SPEC
/// timestamps are Unix-epoch ms). Wall-clock, matching the registrant `last_seen` semantics.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Current Unix-epoch time in SECONDS (saturating) — the clock the per-connection `last_activity`
/// liveness timestamps and the health sweep (#1382) run on. Same wall-clock basis as the wire's
/// `RelayPeerInfo::last_seen`.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Per-connection registration state, set after a successful `Register`.
#[derive(Debug, Clone, Default)]
struct Session {
    peer_id: Option<String>,
    network_id: Option<String>,
    /// Whether this connection has sent its `pex_handshake` (RLY-008 capability gate). The relay
    /// MUST NOT send any PEX to a connection until this is `true`; a legacy node that never sends one
    /// sees the wire exactly as RLY-001..RLY-007 (SPEC §10.2).
    pex_active: bool,
}

/// What the dispatcher decided a parsed [`RelayMessage`] should do. Pure data — the async task
/// carries it out. Keeping this separate from I/O makes the routing logic unit-testable.
#[derive(Debug)]
pub enum Action {
    /// Send these messages back to the SENDER's own socket.
    ReplyToSelf(Vec<RelayMessage>),
    /// Mark this connection registered as (`peer_id`, `network_id`) and reply with `register_ack`.
    Register {
        peer_id: String,
        network_id: String,
        protocol_version: u32,
        /// The node's advertised gossip listen candidates (RLY-001 `listen_addrs`, B1). The relay
        /// combines these with the observed reflexive source IP to publish dialable
        /// `RelayPeerInfo::addresses` to other peers.
        listen_addrs: Vec<std::net::SocketAddr>,
    },
    /// Forward `msg` to the single peer `to` (scoped to the sender's network).
    ForwardTo { to: String, msg: RelayMessage },
    /// Fan `msg` out to every peer on the network except `from` + `exclude`.
    Broadcast {
        from: String,
        exclude: Vec<String>,
        msg: RelayMessage,
    },
    /// Cleanly unregister the sender and close.
    Close,
    /// Nothing to do (e.g. a `Pong` we received).
    Nothing,
    /// Reply with an error to the sender.
    Error { code: u32, message: String },
}

/// Decide what to do with one inbound [`RelayMessage`], given the connection's current
/// [`Session`]. Pure: no I/O, no registry access (the caller does registry lookups for the
/// `ForwardTo`/`Broadcast`/peer-list actions it returns). Returns the [`Action`] and, for a
/// successful `Register`, leaves the session update to the caller via [`Action::Register`].
fn dispatch(session: &Session, msg: RelayMessage) -> Action {
    // Before registration, ONLY `register` is allowed (RLY-001).
    let registered = session.peer_id.is_some();
    match msg {
        RelayMessage::Register {
            peer_id,
            network_id,
            protocol_version,
            listen_addrs,
        } => Action::Register {
            peer_id,
            network_id,
            protocol_version,
            listen_addrs,
        },

        _ if !registered => Action::Error {
            code: errcode::NOT_REGISTERED,
            message: "register before sending other messages (RLY-001)".to_string(),
        },

        RelayMessage::Unregister { .. } => Action::Close,

        // RLY-002: targeted forward. Re-stamp `from` to the registered id so a peer can't spoof.
        RelayMessage::RelayGossipMessage {
            to, payload, seq, ..
        } => {
            let from = session.peer_id.clone().unwrap_or_default();
            Action::ForwardTo {
                to: to.clone(),
                msg: RelayMessage::RelayGossipMessage {
                    from,
                    to,
                    payload,
                    seq,
                },
            }
        }

        // RLY-003: broadcast. `from` is re-stamped to the registered id.
        RelayMessage::Broadcast {
            payload, exclude, ..
        } => {
            let from = session.peer_id.clone().unwrap_or_default();
            Action::Broadcast {
                from: from.clone(),
                exclude,
                msg: RelayMessage::Broadcast {
                    from,
                    payload,
                    exclude: Vec::new(),
                },
            }
        }

        // RLY-005: peer list. The caller fills `peers` from the registry; signalled via a
        // placeholder GetPeers echoed back as an Action so the caller can do the lookup.
        RelayMessage::GetPeers { network_id } => Action::ReplyToSelf(vec![
            // Sentinel: the caller replaces this with the real Peers list. We encode the request
            // by returning an empty Peers the caller overwrites; simpler is a dedicated action,
            // but ReplyToSelf keeps the async task uniform. The caller intercepts GetPeers before
            // calling dispatch for the registry read, so this arm is only reached in tests.
            RelayMessage::Peers { peers: Vec::new() },
        ])
        .tap_network(network_id),

        // RLY-006: keepalive. A ping is answered with a pong; a pong we receive is ignored.
        RelayMessage::Ping { timestamp } => {
            Action::ReplyToSelf(vec![RelayMessage::Pong { timestamp }])
        }
        RelayMessage::Pong { .. } => Action::Nothing,

        // RLY-007: NAT traversal. The relay forwards the request to the target as a
        // HolePunchCoordinate carrying the REQUESTER's external addr, so both sides can
        // simultaneously open. The result is informational and forwarded to the target too.
        RelayMessage::HolePunchRequest {
            target_peer_id,
            external_addr,
            ..
        } => {
            let from = session.peer_id.clone().unwrap_or_default();
            Action::ForwardTo {
                to: target_peer_id,
                msg: RelayMessage::HolePunchCoordinate {
                    peer_id: from,
                    external_addr,
                },
            }
        }
        RelayMessage::HolePunchResult {
            peer_id, success, ..
        } => Action::ForwardTo {
            to: peer_id.clone(),
            msg: RelayMessage::HolePunchResult { peer_id, success },
        },

        // Server→client messages a client should never send us: ignore politely.
        RelayMessage::RegisterAck { .. }
        | RelayMessage::Peers { .. }
        | RelayMessage::PeerConnected { .. }
        | RelayMessage::PeerDisconnected { .. }
        | RelayMessage::HolePunchCoordinate { .. }
        | RelayMessage::Error { .. } => Action::Nothing,
    }
}

/// Tiny helper to thread the `GetPeers` network filter into a follow-up; in the async path the
/// caller handles `GetPeers` directly (registry read), so this is a no-op carrier used only by the
/// pure-dispatch unit tests.
trait TapNetwork {
    fn tap_network(self, _network_id: Option<String>) -> Self;
}
impl TapNetwork for Action {
    fn tap_network(self, _network_id: Option<String>) -> Self {
        self
    }
}

/// Whether a raw inbound text/binary frame is a PEX message (RLY-008) rather than an RLY-001..007
/// `RelayMessage`. PEX rides the same `type`-tagged JSON WebSocket; every PEX `type` tag begins with
/// `pex_` and none collides with an RLY tag, so a cheap `"type":"pex_…"` peek classifies the frame
/// before a full parse — a legacy RLY frame never enters the PEX path and vice versa (SPEC §10.2).
fn is_pex_frame(frame: &[u8]) -> bool {
    // Parse just the `type` discriminator; anything that isn't an object with a `pex_`-prefixed
    // `type` is not ours.
    serde_json::from_slice::<serde_json::Value>(frame)
        .ok()
        .and_then(|v| {
            v.get("type")
                .and_then(|t| t.as_str())
                .map(|t| t.starts_with("pex_"))
        })
        .unwrap_or(false)
}

/// What to do with a `pex_`-typed frame from a connection, decided purely from the connection's
/// registration/handshake state and whether the frame decoded (SPEC §10.2). Keeping this separate
/// from the async I/O makes the RLY-008 gating unit-testable.
#[derive(Debug, PartialEq, Eq)]
enum PexAction {
    /// Not registered yet — answer with the relay's own `error` envelope code `1` (`NOT_REGISTERED`),
    /// consistent with every other pre-registration message (SPEC §10.2). Never processed as PEX.
    NotRegistered,
    /// The node's first `pex_handshake` — bring PEX up for this link (`link_up` + `on_message`) and
    /// mark the session PEX-active. Carries the decoded handshake.
    Handshake(PexMessage),
    /// A subsequent PEX data message on an already-active link — fed to the engine for validation +
    /// rate-limiting; candidate/dropped events are discarded (introducer-only), only errors reply.
    Data(PexMessage),
    /// A `pex_`-typed but undecodable frame from an active link — a `PEX_BAD_MESSAGE` strike.
    BadFrame,
    /// A PEX frame arriving before the node ever handshaked (and not itself a handshake) — the relay
    /// has not brought PEX up for this link, so it is silently ignored (no RLY error; PEX is optional).
    IgnorePreHandshake,
}

/// Decide how to treat a `pex_`-typed `frame` given the connection's [`Session`]. Pure: no I/O, no
/// engine access. `decoded` is the result of [`PexMessage::from_json`] on the frame.
fn pex_dispatch(session: &Session, decoded: Option<&PexMessage>) -> PexAction {
    if session.peer_id.is_none() {
        // A `pex_handshake` (or any PEX) before RLY-001 registration is answered like any other
        // pre-registration message: the relay's own NOT_REGISTERED error (SPEC §10.2).
        return PexAction::NotRegistered;
    }
    match decoded {
        Some(msg @ PexMessage::PexHandshake { .. }) if !session.pex_active => {
            PexAction::Handshake(msg.clone())
        }
        Some(msg) if session.pex_active => PexAction::Data(msg.clone()),
        // A non-handshake PEX frame before the node handshaked: the relay never brought PEX up for
        // this link, so there is nothing to validate against — ignore it (PEX is an optional overlay).
        Some(_) => PexAction::IgnorePreHandshake,
        // Undecodable `pex_` frame: a bad message only counts once PEX is active (there is no link
        // state to strike otherwise); before handshake it is ignored.
        None if session.pex_active => PexAction::BadFrame,
        None => PexAction::IgnorePreHandshake,
    }
}

/// Run the relay WebSocket accept loop until the listener errors or the process is cancelled.
/// Each accepted TCP connection is upgraded to a WebSocket and handled in its own task. A background
/// task drives the PEX housekeeping tick (RLY-008) on [`PEX_TICK_INTERVAL`].
pub async fn run(state: Arc<RelayState>) -> std::io::Result<()> {
    // IPv6-first, IPv4-fallback: dual-stack bind so the default `[::]` listener still accepts
    // IPv4 (and IPv4-mapped) peers on the same socket (see `crate::net`).
    let listener = bind_tcp_dual_stack(state.config.listen)?;
    tracing::info!(addr = %state.config.listen, "dig-relay listening (RelayMessage/WebSocket)");

    // PEX housekeeping (RLY-008): drive every network's engine cadence and route its per-link deltas
    // to the matching connection's PEX channel. Runs for the lifetime of the accept loop.
    tokio::spawn(pex_housekeeping(state.clone()));

    // Periodic health sweep (#1382): prune dead/stale registrations promptly rather than waiting
    // for the (much longer) idle timeout, so a half-open peer stops poisoning introductions + PEX
    // quickly. Runs for the lifetime of the accept loop.
    tokio::spawn(health_sweep(state.clone()));

    // Optional mTLS termination (SPEC.md §3.2/§8, `src/tls.rs`): when configured, every accepted TCP
    // connection is first wrapped in a client-cert-mandatory TLS handshake; the `peer_id` derived
    // from the certificate the client actually used is threaded into `handle_connection` so
    // `register_peer` can require the `Register` message's claimed `peer_id` to match it
    // (proof-of-possession). `None` keeps the listener plain `ws://`, unchanged from before.
    let tls_acceptor = state.tls.clone().map(tokio_rustls::TlsAcceptor::from);

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                continue;
            }
        };
        let state = state.clone();
        match tls_acceptor.clone() {
            Some(acceptor) => {
                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            // A client with no certificate (mandatory client auth), an unparseable
                            // certificate, or any other TLS failure never reaches the RelayMessage
                            // wire at all — rejected at the transport layer.
                            tracing::debug!(error = %e, %peer_addr, "mTLS handshake failed");
                            return;
                        }
                    };
                    let verified_peer_id = crate::tls::extract_client_peer_id(&tls_stream);
                    if let Err(e) =
                        handle_connection(state, tls_stream, peer_addr, verified_peer_id).await
                    {
                        tracing::debug!(error = %e, %peer_addr, "connection ended");
                    }
                });
            }
            None => {
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(state, stream, peer_addr, None).await {
                        tracing::debug!(error = %e, %peer_addr, "connection ended");
                    }
                });
            }
        }
    }
}

/// The PEX housekeeping loop (RLY-008, SPEC §6 + Appendix A step 4): on [`PEX_TICK_INTERVAL`], drive
/// every per-network engine's send cadence and route each due `pex_delta` to the matching connection.
/// [`PexRelay::tick`] itself does the per-network scoping + routing to the retained PEX senders; this
/// loop only supplies the clock. It ends when the process is torn down (the task is aborted with the
/// runtime).
async fn pex_housekeeping(state: Arc<RelayState>) {
    let mut ticker = tokio::time::interval(PEX_TICK_INTERVAL);
    loop {
        ticker.tick().await;
        state.pex.lock().await.tick(now_ms());
    }
}

/// Handle one WebSocket connection: enforce the connection cap, then read/dispatch frames until
/// close. A dedicated writer task drains the peer's outbound channel onto the socket so messages
/// forwarded by OTHER connections are delivered concurrently with this connection's own replies.
/// PEX frames (RLY-008) ride a parallel outbound channel merged by the same writer.
///
/// Generic over the transport (`S`) so the SAME dispatch/registration logic serves both the plain
/// `ws://` path (`S = tokio::net::TcpStream`) and the optional mTLS path
/// (`S = tokio_rustls::server::TlsStream<tokio::net::TcpStream>`, SPEC.md §3.2/§8) with no
/// duplicated code. `verified_peer_id` is `Some(id)` when mTLS derived an identity from the
/// client's certificate for this connection (`crate::tls::extract_client_peer_id`); `register_peer`
/// requires the `Register` message's claimed `peer_id` to equal it.
async fn handle_connection<S>(
    state: Arc<RelayState>,
    mut stream: S,
    peer_addr: std::net::SocketAddr,
    verified_peer_id: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Connection cap (SECURITY_AUDIT_P2P dig-relay #5): count OPEN sockets, not just registered peers,
    // so a flood of connect-but-never-register sockets can't bypass the cap. The guard increments the
    // open-connection counter here and decrements it on ANY exit path (RAII), so the count can never
    // leak. Refuse before the (cheap) handshake when full.
    if state.open_connections.load(Ordering::Relaxed) as usize >= state.config.max_connections {
        tracing::warn!(%peer_addr, "refusing connection: at open-connection cap");
        return Ok(());
    }
    let _open_guard = OpenConnectionGuard::acquire(&state);

    // Per-source-IP connection cap (#1386): the global cap above bounds the relay in aggregate, but
    // one source IP could still hold every slot. Reserve a per-IP slot (RAII, released on ANY exit
    // path beside `_open_guard`); refuse the connection when this source is already at its per-IP cap
    // so a single host cannot monopolise the relay. `peer_addr` is the observed reflexive source; the
    // slot's key normalises IPv4-mapped IPv6 + groups an IPv6 /64 (see `limits::ip_key`).
    let Some(_ip_slot) = state.abuse.try_acquire_conn(peer_addr.ip()) else {
        tracing::warn!(%peer_addr, "refusing connection: at per-IP connection cap (#1386)");
        return Ok(());
    };

    // This one TLS-terminated port carries BOTH surfaces (dig_ecosystem #1041): peek the HTTP request
    // head, and route on it. A WebSocket upgrade is a relay-wire peer — its request bytes are replayed
    // to the handshake unchanged via `Prefixed`, so the wire path stays byte-for-byte the same. Any
    // other request is a browser reaching the peer-stats dashboard over https://relay.dig.net/ — it is
    // served here and the connection closes. (Plain http://:80 is a separate redirect listener.)
    let (head, consumed) = crate::http_serve::read_request_head(&mut stream).await?;
    if !head.is_websocket_upgrade {
        crate::dashboard::serve_http(&state, &mut stream, &head).await?;
        return Ok(());
    }

    // Cap the WebSocket message/frame size at a small realistic bound (SECURITY_AUDIT_P2P dig-relay
    // #4). All relay control/gossip frames (register, ping, hole_punch, get_peers, RelayGossipMessage,
    // PEX) are tiny; tungstenite's 64 MiB default would let each connection force the server to buffer
    // up to 64 MiB reassembling one message (and a Broadcast of that size would then be cloned to
    // every same-network peer). A `max_message_size`/`max_frame_size` ceiling rejects an oversized
    // frame at the protocol layer before that allocation.
    let ws_config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
        max_message_size: Some(state.config.max_message_bytes),
        max_frame_size: Some(state.config.max_message_bytes),
        ..Default::default()
    };
    let stream = crate::http_serve::Prefixed::new(consumed, stream);
    let ws = tokio_tungstenite::accept_async_with_config(stream, Some(ws_config)).await?;
    let (mut write, mut read) = ws.split();

    // Outbound RLY channel: anything (this task, or another peer forwarding to us) pushes a
    // RelayMessage here; the writer half drains it to the socket. BOUNDED (SECURITY_AUDIT_P2P
    // dig-relay #3): a peer that stops reading its socket can only ever hold `outbound_queue_capacity`
    // buffered messages before further `try_send`s to it are dropped, so a slow/hostile reader cannot
    // grow the relay heap without limit.
    let queue_cap = state.config.outbound_queue_capacity;
    let (out_tx, mut out_rx) = mpsc::channel::<RelayMessage>(queue_cap);
    // Outbound PEX channel (RLY-008): the PEX subsystem (handshake reply + tick-driven deltas) pushes
    // `PexMessage`s here. Kept separate from the RLY channel so the registry / RLY-001..007 wire is
    // byte-for-byte unchanged; the one writer merges both onto the socket as JSON text frames. Also
    // bounded, for the same reason.
    let (pex_tx, mut pex_rx) = mpsc::channel::<PexMessage>(queue_cap);

    // Writer task: serialize each outbound RLY or PEX message as one JSON text frame and write it.
    // Both are `type`-tagged JSON on the same WebSocket; a PEX frame uses the bare-JSON form
    // (`PexMessage::to_json`, no length prefix — SPEC §10.2). The loop ends when the RLY channel
    // closes (teardown drops `out_tx`); a closed PEX channel just stops being polled.
    let writer = tokio::spawn(async move {
        let mut pex_open = true;
        loop {
            let txt = tokio::select! {
                m = out_rx.recv() => match m {
                    Some(msg) => match serde_json::to_string(&msg) {
                        Ok(t) => t,
                        Err(_) => continue,
                    },
                    None => break, // RLY channel closed → connection is tearing down
                },
                m = pex_rx.recv(), if pex_open => match m {
                    Some(msg) => msg.to_json(),
                    None => {
                        pex_open = false; // PEX channel closed; keep serving RLY
                        continue;
                    }
                },
            };
            if write.send(Message::Text(txt)).await.is_err() {
                break;
            }
        }
        let _ = write.close().await;
    });

    let mut session = Session::default();
    let idle = state.config.idle_timeout;
    let register_timeout = state.config.register_timeout;
    // The health sweep's liveness clock for THIS connection (#1382): stamped to "now" on every
    // inbound frame, shared (`Arc`) with the registry record once registered so `sweep_once` can
    // read it without touching this task.
    let last_activity = Arc::new(AtomicU64::new(now_secs()));

    // Per-connection abuse limiter (#1386): task-local (no shared lock), enforcing this connection's
    // inbound message-rate, byte-rate, and cumulative-byte budgets. A breach DISCONNECTS (breaks the
    // loop) — a connection flooding far past the generous defaults is shed, not throttled. The
    // per-IP caps (`_ip_slot`, `register_peer`) are the shared dimension; this is the hot per-frame one.
    let mut conn_limiter = crate::limits::PerConnLimiter::new(&state.config, now_ms());
    // The per-IP concurrent-registration slot (#1386), acquired in `register_peer` on a successful
    // register and released when this connection ends (dropped at teardown below).
    let mut reg_slot: Option<crate::limits::RegSlot> = None;

    loop {
        // Until the connection has registered (RLY-001), it is held only to the SHORT register
        // timeout, so a connect-but-never-register socket is reaped quickly (SECURITY_AUDIT_P2P
        // dig-relay #5) rather than sitting for the full (longer) post-register idle timeout. Once
        // registered, the generous idle timeout applies (keepalive is the node's 30 s ping).
        let deadline = if session.peer_id.is_some() {
            idle
        } else {
            register_timeout
        };
        let next = tokio::time::timeout(deadline, read.next()).await;
        let frame = match next {
            Err(_) => {
                if session.peer_id.is_some() {
                    tracing::debug!(%peer_addr, "idle timeout; reaping");
                } else {
                    tracing::debug!(%peer_addr, "register timeout; reaping unregistered connection");
                }
                break;
            }
            Ok(None) => break,         // stream closed
            Ok(Some(Err(_))) => break, // ws error
            Ok(Some(Ok(Message::Close(_)))) => break,
            Ok(Some(Ok(Message::Ping(_)))) | Ok(Some(Ok(Message::Pong(_)))) => continue,
            Ok(Some(Ok(Message::Text(t)))) => t.into_bytes(),
            Ok(Some(Ok(Message::Binary(b)))) => b,
            Ok(Some(Ok(Message::Frame(_)))) => continue,
        };

        // Health-sweep liveness (#1382): ANY inbound frame — RLY or PEX, valid or not — counts as
        // activity, mirroring the node's own RLY-006 keepalive (the client answers relay-initiated
        // pings never; its ~30s keepalive ping is the only inbound liveness signal we can rely on).
        last_activity.store(now_secs(), Ordering::Relaxed);

        // Per-connection abuse limits (#1386): account for this inbound frame's size against the
        // message-rate, byte-rate, and cumulative-byte budgets. A breach means the peer is flooding
        // far past the generous defaults — disconnect it (the RAII guards release its slots on the
        // way out). Checked for every frame (RLY or PEX, valid or not) since all consume resources.
        if let crate::limits::Admit::Disconnect = conn_limiter.admit(frame.len(), now_ms()) {
            tracing::warn!(%peer_addr, "disconnecting: per-connection abuse limit exceeded (#1386)");
            break;
        }

        // RLY-008: a PEX frame (`type:"pex_…"`) is routed to the PEX subsystem, never parsed as an
        // RLY message. This is checked BEFORE the RLY parse so a valid PEX frame never trips the
        // BAD_MESSAGE path, and a legacy RLY frame never enters PEX (their tag spaces are disjoint).
        if is_pex_frame(&frame) {
            handle_pex_frame(&state, &mut session, &frame, peer_addr, &pex_tx, &out_tx).await;
            continue;
        }

        let msg: RelayMessage = match serde_json::from_slice(&frame) {
            Ok(m) => m,
            Err(_) => {
                let _ = out_tx.try_send(RelayMessage::Error {
                    code: errcode::BAD_MESSAGE,
                    message: "invalid relay JSON".to_string(),
                });
                continue;
            }
        };

        // Observational dashboard counters (relayed bytes + hole-punch attempts/outcomes). A cheap
        // no-op for every other kind; done once per parsed frame, before any routing.
        state.record_relayed(&msg);

        // GetPeers is handled here (needs a registry read the pure dispatcher can't do).
        if let RelayMessage::GetPeers { network_id } = &msg {
            let filter = network_id.clone().or_else(|| session.network_id.clone());
            let peers = state.registry.lock().await.peers(filter.as_deref());
            // RLY-005 observability (issue #862/P2P): log each peer-list request + how many peers
            // were returned. A `get_peers` that returns only the requester (or none) is the tell-tale
            // that no OTHER peer holds a live registration at query time — the exact signal that
            // distinguishes a persistent-reservation network from ephemeral register-and-drop clients.
            tracing::info!(
                requester = session.peer_id.as_deref().unwrap_or("<unregistered>"),
                network = filter.as_deref().unwrap_or("<all>"),
                returned = peers.len(),
                "RLY-005 get_peers: returning peer list"
            );
            let _ = out_tx.try_send(RelayMessage::Peers { peers });
            continue;
        }

        match dispatch(&session, msg) {
            Action::Register {
                peer_id,
                network_id,
                protocol_version,
                listen_addrs,
            } => {
                if !register_peer(
                    &state,
                    &mut session,
                    peer_id,
                    network_id,
                    protocol_version,
                    &listen_addrs,
                    peer_addr,
                    &out_tx,
                    &pex_tx,
                    verified_peer_id.as_deref(),
                    last_activity.clone(),
                    &mut reg_slot,
                )
                .await
                {
                    // At capacity → ack failure and close.
                    break;
                }
            }
            Action::ForwardTo { to, msg } => {
                forward_to(&state, &session, &to, msg, &out_tx).await;
            }
            Action::Broadcast { from, exclude, msg } => {
                broadcast(&state, &session, &from, &exclude, msg).await;
            }
            Action::ReplyToSelf(msgs) => {
                for m in msgs {
                    let _ = out_tx.try_send(m);
                }
            }
            Action::Error { code, message } => {
                let _ = out_tx.try_send(RelayMessage::Error { code, message });
            }
            Action::Close => break,
            Action::Nothing => {}
        }
    }

    // Connection teardown: unregister from the registry + the PEX subsystem, notify peers, and stop
    // the writer (dropping both outbound channels ends the writer's select loop).
    deregister(&state, &session).await;
    drop(pex_tx);
    drop(out_tx);
    let _ = writer.await;
    Ok(())
}

/// Route one PEX frame (RLY-008) to the introducer PEX subsystem, per the [`pex_dispatch`] decision
/// (SPEC §10.2). On the node's first `pex_handshake` this brings PEX up for the link and marks the
/// session PEX-active; subsequent data messages are validated + rate-limited only (their peer hints
/// are discarded — introducer-only); replies (our handshake + snapshot, or a `pex_error`) go out on
/// the PEX channel, and a pre-registration PEX frame gets the relay's own NOT_REGISTERED error.
async fn handle_pex_frame(
    state: &Arc<RelayState>,
    session: &mut Session,
    frame: &[u8],
    peer_addr: std::net::SocketAddr,
    pex_tx: &mpsc::Sender<PexMessage>,
    out_tx: &mpsc::Sender<RelayMessage>,
) {
    let decoded = std::str::from_utf8(frame)
        .ok()
        .and_then(|s| PexMessage::from_json(s).ok());

    let peer_id = session.peer_id.clone().unwrap_or_default();
    let network_id = session.network_id.clone().unwrap_or_default();
    let now = now_ms();

    match pex_dispatch(session, decoded.as_ref()) {
        PexAction::NotRegistered => {
            let _ = out_tx.try_send(RelayMessage::Error {
                code: errcode::NOT_REGISTERED,
                message: "register before sending PEX (RLY-001)".to_string(),
            });
        }
        PexAction::Handshake(msg) => {
            // First handshake: register this link's PEX sender, bring PEX up, and reply with our
            // handshake + a snapshot of the OTHER same-network registrants (routed on the PEX channel).
            let replies = {
                let mut pex = state.pex.lock().await;
                // Ensure our engine has this connection's PEX sender for tick-driven deltas. The
                // register-time mirror already inserted it, but a connection could handshake before
                // its register mirror ran in an unusual interleaving; re-registering is idempotent.
                pex.on_register(&peer_id, &network_id, peer_addr, pex_tx.clone(), now);
                pex.on_node_handshake(&peer_id, &network_id, msg, now)
            };
            session.pex_active = true;
            for m in replies {
                let _ = pex_tx.try_send(m);
            }
        }
        PexAction::Data(msg) => {
            let replies = state
                .pex
                .lock()
                .await
                .on_node_message(&peer_id, &network_id, msg, now);
            for m in replies {
                let _ = pex_tx.try_send(m);
            }
        }
        PexAction::BadFrame => {
            let replies = state
                .pex
                .lock()
                .await
                .on_node_bad_frame(&peer_id, &network_id, now);
            for m in replies {
                let _ = pex_tx.try_send(m);
            }
        }
        PexAction::IgnorePreHandshake => {}
    }
}

/// Register the connection (RLY-001), enforcing the cap. Returns `false` (after sending a failing
/// `register_ack`) if the relay is full. On success it also MIRRORS the registration into the PEX
/// introducer subsystem (RLY-008, SPEC §10.2): the registrant becomes a first-hand, advertisable
/// entry (`via: introducer`, its observed reflexive `peer_addr`, `relay-only`), and its PEX sender is
/// retained for tick-driven deltas. Mirroring happens for EVERY registration — a legacy node that
/// never speaks PEX is still a real peer other nodes must learn about.
///
/// # Proof-of-possession (SPEC.md §3.2/§8, `DIG-Network/dig_ecosystem#5`)
///
/// `verified_peer_id` is `Some(id)` when the connection came in over the relay's mTLS listener
/// (`crate::tls::extract_client_peer_id`) — `id` is derived from the certificate the client actually
/// presented for THIS TLS session, which it could only do by holding the matching private key. When
/// set, the claimed `peer_id` MUST equal it; a mismatch is refused BEFORE touching the registry
/// (failing `register_ack` + `errcode::IDENTITY_MISMATCH`), exactly like the capacity/anti-hijack
/// refusals below. `None` (plain `ws://`, the default) skips this check — identity is unauthenticated
/// on that listener, same as before this feature (the registry's live-incumbent refusal in
/// `src/registry.rs` is the only protection there).
#[allow(clippy::too_many_arguments)]
async fn register_peer(
    state: &Arc<RelayState>,
    session: &mut Session,
    peer_id: String,
    network_id: String,
    protocol_version: u32,
    listen_addrs: &[std::net::SocketAddr],
    peer_addr: std::net::SocketAddr,
    out_tx: &mpsc::Sender<RelayMessage>,
    pex_tx: &mpsc::Sender<PexMessage>,
    verified_peer_id: Option<&str>,
    last_activity: Arc<AtomicU64>,
    reg_slot: &mut Option<crate::limits::RegSlot>,
) -> bool {
    // App-level registration-flood protection (#1386), BEFORE any registry work or the mTLS check:
    // (1) the per-source-IP registration RATE, then (2) the per-source-IP CONCURRENT-registration
    // cap. Both refuse with a failing `register_ack` + an `Error{RATE_LIMITED}`, mirroring the
    // capacity/anti-hijack refusal shape below, so a client distinguishes a per-source throttle from
    // the relay being globally full. The concurrent slot is held in a local and only moved into the
    // caller's `reg_slot` on a fully-successful register — any later refusal drops it (releasing the
    // count). `peer_addr` is the observed reflexive source; `limits::ip_key` normalises it.
    let connected_now = state.connected.load(Ordering::Relaxed) as usize;
    if !state.abuse.allow_registration(peer_addr.ip(), now_ms()) {
        tracing::warn!(%peer_id, %peer_addr, "refusing register: per-IP registration rate exceeded (#1386)");
        let _ = out_tx.try_send(RelayMessage::RegisterAck {
            success: false,
            message: "registration rate limit exceeded for your address".to_string(),
            connected_peers: connected_now,
        });
        let _ = out_tx.try_send(RelayMessage::Error {
            code: errcode::RATE_LIMITED,
            message: "registration rate limit exceeded for your address".to_string(),
        });
        return false;
    }
    let acquired_reg_slot = match state.abuse.try_acquire_registration(peer_addr.ip()) {
        Some(slot) => slot,
        None => {
            tracing::warn!(%peer_id, %peer_addr, "refusing register: per-IP concurrent-registration cap reached (#1386)");
            let _ = out_tx.try_send(RelayMessage::RegisterAck {
                success: false,
                message: "too many concurrent registrations from your address".to_string(),
                connected_peers: connected_now,
            });
            let _ = out_tx.try_send(RelayMessage::Error {
                code: errcode::RATE_LIMITED,
                message: "too many concurrent registrations from your address".to_string(),
            });
            return false;
        }
    };

    let mut reg = state.registry.lock().await;

    if let Some(verified) = verified_peer_id {
        if verified != peer_id {
            let connected_peers = reg.len();
            drop(reg);
            tracing::warn!(
                claimed = %peer_id,
                %verified,
                %peer_addr,
                "refusing register: claimed peer_id does not match the mTLS client certificate"
            );
            let _ = out_tx.try_send(RelayMessage::RegisterAck {
                success: false,
                message: "peer_id does not match the mTLS client certificate presented".to_string(),
                connected_peers,
            });
            let _ = out_tx.try_send(RelayMessage::Error {
                code: errcode::IDENTITY_MISMATCH,
                message: "peer_id does not match the mTLS client certificate presented".to_string(),
            });
            return false;
        }
    }

    if reg.len() >= state.config.max_connections {
        let _ = out_tx.try_send(RelayMessage::RegisterAck {
            success: false,
            message: "relay at capacity".to_string(),
            connected_peers: reg.len(),
        });
        let _ = out_tx.try_send(RelayMessage::Error {
            code: errcode::CAPACITY,
            message: "relay at capacity".to_string(),
        });
        return false;
    }

    // `RelayPeerInfo::new` stamps connected_at/last_seen with the current unix time. B1 (#924): fill
    // in dialable candidate addresses by substituting the observed reflexive source IP (`peer_addr`)
    // for any unroutable advertised listen host, keeping the advertised port — so other peers receive
    // a real `reflexive_IP:port` they can direct-dial. A legacy peer that advertised nothing keeps the
    // empty list and falls back to identity-only relayed reachability.
    let mut info = RelayPeerInfo::new(peer_id.clone(), network_id.clone(), protocol_version);
    info.addresses = crate::dial::resolve_dialable(listen_addrs, peer_addr.ip());

    // Anti-hijack (SECURITY_AUDIT_P2P dig-relay #1): the registry refuses to evict a LIVE peer that
    // already holds this id. A genuine reconnect (dead prior channel) is reclaimed; a fresh id is a
    // new registration that bumps the connected count.
    match reg.register(
        peer_id.clone(),
        network_id.clone(),
        info.clone(),
        out_tx.clone(),
        last_activity,
    ) {
        RegisterOutcome::Registered => {
            state.connected.fetch_add(1, Ordering::Relaxed);
        }
        RegisterOutcome::Reconnected => {
            // A dead slot was swapped for a live one — the count is unchanged.
            tracing::debug!(%peer_id, "reconnect reclaimed a dead prior registration for the same id");
        }
        RegisterOutcome::Occupied => {
            // A live peer holds this id: refuse rather than let an unauthenticated client evict +
            // impersonate it. The session stays unregistered; the incumbent is untouched.
            let connected_peers = reg.len();
            drop(reg);
            tracing::warn!(%peer_id, %peer_addr, "refusing register: peer_id already held by a live peer (anti-hijack)");
            let _ = out_tx.try_send(RelayMessage::RegisterAck {
                success: false,
                message: "peer_id already registered by a live connection".to_string(),
                connected_peers,
            });
            let _ = out_tx.try_send(RelayMessage::Error {
                code: errcode::ID_IN_USE,
                message: "peer_id already registered by a live connection".to_string(),
            });
            return false;
        }
    }

    let connected_peers = reg.len();
    // Notify existing same-network peers of the newcomer (RLY-005 PeerConnected).
    let targets = reg.broadcast_targets(&peer_id, &network_id, &[]);
    drop(reg);

    // RLY-001 observability (issue #862/P2P): log every successful registration at INFO so the
    // live relay's registrations are operationally visible (the empty-CloudWatch gap this closes —
    // a successful register previously emitted NOTHING, only refusals warned). The observed
    // reflexive `peer_addr` is the source address the relay saw, invaluable for diagnosing whether
    // a node is registering EPHEMERALLY (register-then-immediately-disconnect) vs. holding a
    // persistent reservation.
    tracing::info!(
        %peer_id,
        %network_id,
        %peer_addr,
        protocol_version,
        connected_peers,
        "RLY-001 register: peer registered"
    );

    let _ = out_tx.try_send(RelayMessage::RegisterAck {
        success: true,
        message: "registered".to_string(),
        connected_peers,
    });
    for (_, tx) in targets {
        let _ = tx.try_send(RelayMessage::PeerConnected { peer: info.clone() });
    }

    // RLY-008: mirror the registration into the PEX introducer set. Done after the RLY lock is
    // released to keep the two subsystems' locks independent.
    state
        .pex
        .lock()
        .await
        .on_register(&peer_id, &network_id, peer_addr, pex_tx.clone(), now_ms());

    // Registration fully succeeded: retain the per-IP concurrent-registration slot for the lifetime
    // of this connection (#1386). It is released when the connection task ends (dropped at teardown).
    *reg_slot = Some(acquired_reg_slot);

    session.peer_id = Some(peer_id);
    session.network_id = Some(network_id);
    true
}

/// Forward one message to a single peer on the sender's network (RLY-002 / RLY-007).
async fn forward_to(
    state: &Arc<RelayState>,
    session: &Session,
    to: &str,
    msg: RelayMessage,
    out_tx: &mpsc::Sender<RelayMessage>,
) {
    let Some(network_id) = session.network_id.as_deref() else {
        return;
    };
    let sender = state
        .registry
        .lock()
        .await
        .sender_in_network(to, network_id);
    match sender {
        Some(tx) => {
            let _ = tx.try_send(msg);
        }
        None => {
            let _ = out_tx.try_send(RelayMessage::Error {
                code: errcode::PEER_NOT_FOUND,
                message: format!("peer {to} not connected to this relay"),
            });
        }
    }
}

/// Fan one message out to all same-network peers except the sender + `exclude` (RLY-003).
async fn broadcast(
    state: &Arc<RelayState>,
    session: &Session,
    from: &str,
    exclude: &[String],
    msg: RelayMessage,
) {
    let Some(network_id) = session.network_id.as_deref() else {
        return;
    };
    let targets = state
        .registry
        .lock()
        .await
        .broadcast_targets(from, network_id, exclude);
    for (_, tx) in targets {
        let _ = tx.try_send(msg.clone());
    }
}

/// Remove one peer from the registry (if present) and adjust the live `connected` counter,
/// returning the same-network peers that should be told it's gone (RLY-005 `PeerDisconnected`
/// targets). Pure registry bookkeeping under the caller's held lock — the caller sends the
/// notifications and mirrors the departure into PEX AFTER releasing the lock, so the two
/// call sites ([`deregister`] for a graceful close, [`sweep_once`] for a pruned dead/stale
/// registration) share one authoritative "remove a peer" path.
fn remove_locked(
    reg: &mut Registry,
    state: &RelayState,
    peer_id: &str,
    network_id: &str,
) -> Option<Vec<(String, mpsc::Sender<RelayMessage>)>> {
    if reg.unregister(peer_id).is_some() {
        state.connected.fetch_sub(1, Ordering::Relaxed);
        Some(reg.broadcast_targets(peer_id, network_id, &[]))
    } else {
        None
    }
}

/// Remove the connection from the registry on teardown and notify same-network peers (RLY-005
/// PeerDisconnected). Also MIRRORS the departure into the PEX introducer subsystem (RLY-008, SPEC
/// §10.2): the peer drops from the advertise set (surfacing as a `dropped` delta to the links that
/// were told it) and its PEX link state is discarded.
async fn deregister(state: &Arc<RelayState>, session: &Session) {
    let (Some(peer_id), Some(network_id)) = (&session.peer_id, &session.network_id) else {
        return;
    };
    let mut reg = state.registry.lock().await;
    let Some(targets) = remove_locked(&mut reg, state, peer_id, network_id) else {
        return;
    };
    let remaining = reg.len();
    drop(reg);
    // RLY observability (issue #862/P2P): log the departure + remaining count. Paired with the
    // register log above, a rapid register→deregister of the same peer_id exposes an ephemeral
    // (non-persistent) reservation client at a glance.
    tracing::info!(%peer_id, %network_id, remaining, "peer deregistered");
    for (_, tx) in targets {
        let _ = tx.try_send(RelayMessage::PeerDisconnected {
            peer_id: peer_id.clone(),
        });
    }
    state.pex.lock().await.on_unregister(peer_id, network_id);
}

/// One pass of the periodic health sweep (#1382): under ONE registry-lock hold, find every
/// dead/stale registration ([`Registry::dead_or_stale`]) and remove it — collecting the
/// `PeerDisconnected` fan-out targets for each as it goes — then, AFTER releasing the lock, send
/// those notifications and mirror each departure into PEX. Collecting + removing under a single
/// lock acquisition (rather than re-locking per victim) closes the race a naive
/// find-then-remove-later sweep would have: a peer that reconnects between "found dead" and
/// "removed" could have its brand-new LIVE registration evicted by this sweep instead of the stale
/// one it was meant to prune. Because the registry is re-checked and mutated atomically in one
/// critical section, that window never opens.
async fn sweep_once(state: &Arc<RelayState>, now: u64) {
    /// One pruned peer's id, network, and the `PeerDisconnected` fan-out targets it needs.
    type PrunedPeer = (String, String, Vec<(String, mpsc::Sender<RelayMessage>)>);

    let pruned: Vec<PrunedPeer> = {
        let mut reg = state.registry.lock().await;
        let victims = reg.dead_or_stale(now, state.config.liveness_deadline.as_secs());
        victims
            .into_iter()
            .filter_map(|(peer_id, network_id)| {
                let targets = remove_locked(&mut reg, state, &peer_id, &network_id)?;
                Some((peer_id, network_id, targets))
            })
            .collect()
    };

    for (peer_id, network_id, targets) in pruned {
        tracing::info!(%peer_id, %network_id, "health sweep: pruned dead/stale peer (#1382)");
        for (_, tx) in targets {
            let _ = tx.try_send(RelayMessage::PeerDisconnected {
                peer_id: peer_id.clone(),
            });
        }
        state.pex.lock().await.on_unregister(&peer_id, &network_id);
    }
}

/// The periodic health-sweep loop (#1382, SPEC "Liveness & pruning"): on
/// [`RelayServerConfig::health_check_interval`], run [`sweep_once`] to prune registrations that
/// have gone dead (closed channel) or silently stale (no inbound activity — including the node's
/// own RLY-006 keepalive — within [`RelayServerConfig::liveness_deadline`]). This is an ACTIVE,
/// promptly-running complement to the [`RelayServerConfig::idle_timeout`] backstop each
/// connection's own read loop already enforces (strictly longer, `config.rs` validates it) — the
/// sweep is what stops a half-open peer from poisoning introductions + PEX for the whole idle
/// window. Runs for the lifetime of the accept loop, same as [`pex_housekeeping`].
async fn health_sweep(state: Arc<RelayState>) {
    let mut ticker = tokio::time::interval(state.config.health_check_interval);
    loop {
        ticker.tick().await;
        sweep_once(&state, now_secs()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn registered_session() -> Session {
        Session {
            peer_id: Some("me".to_string()),
            network_id: Some("net1".to_string()),
            ..Default::default()
        }
    }

    /// A test peer address (the observed reflexive source a real connection would carry).
    fn test_addr() -> SocketAddr {
        "127.0.0.1:40000".parse().unwrap()
    }

    /// A throwaway PEX outbound sender for `register_peer` call sites that don't assert on PEX
    /// output (the PEX mirroring is exercised directly in the dedicated PEX tests below).
    fn pex_sink() -> mpsc::Sender<PexMessage> {
        mpsc::channel(64).0
    }

    /// A fresh `last_activity` clock for a test registration, stamped to "now" — the health sweep
    /// (#1382) test cases that care about staleness build their own explicit value instead.
    fn fresh_activity() -> Arc<AtomicU64> {
        Arc::new(AtomicU64::new(now_secs()))
    }

    #[test]
    fn unregistered_connection_rejects_non_register() {
        let s = Session::default();
        let act = dispatch(&s, RelayMessage::Ping { timestamp: 1 });
        match act {
            Action::Error { code, .. } => assert_eq!(code, errcode::NOT_REGISTERED),
            other => panic!("expected NOT_REGISTERED, got {other:?}"),
        }
    }

    #[test]
    fn register_is_allowed_before_registration() {
        let s = Session::default();
        let act = dispatch(
            &s,
            RelayMessage::Register {
                peer_id: "a".into(),
                network_id: "net1".into(),
                protocol_version: 1,
                listen_addrs: vec![],
            },
        );
        assert!(matches!(act, Action::Register { .. }));
    }

    #[test]
    fn ping_is_answered_with_pong() {
        let act = dispatch(&registered_session(), RelayMessage::Ping { timestamp: 42 });
        match act {
            Action::ReplyToSelf(msgs) => {
                assert!(matches!(
                    msgs.as_slice(),
                    [RelayMessage::Pong { timestamp: 42 }]
                ));
            }
            other => panic!("expected Pong reply, got {other:?}"),
        }
    }

    #[test]
    fn relay_message_restamps_from_to_registered_id() {
        let act = dispatch(
            &registered_session(),
            RelayMessage::RelayGossipMessage {
                from: "SPOOFED".into(),
                to: "b".into(),
                payload: vec![1, 2, 3],
                seq: 7,
            },
        );
        match act {
            Action::ForwardTo { to, msg } => {
                assert_eq!(to, "b");
                match msg {
                    RelayMessage::RelayGossipMessage {
                        from, payload, seq, ..
                    } => {
                        assert_eq!(from, "me", "from must be re-stamped to the registered id");
                        assert_eq!(payload, vec![1, 2, 3]);
                        assert_eq!(seq, 7);
                    }
                    other => panic!("wrong forwarded msg: {other:?}"),
                }
            }
            other => panic!("expected ForwardTo, got {other:?}"),
        }
    }

    #[test]
    fn hole_punch_request_forwards_coordinate_to_target() {
        let addr: SocketAddr = "203.0.113.7:9444".parse().unwrap();
        let act = dispatch(
            &registered_session(),
            RelayMessage::HolePunchRequest {
                peer_id: "me".into(),
                target_peer_id: "b".into(),
                external_addr: addr,
            },
        );
        match act {
            Action::ForwardTo { to, msg } => {
                assert_eq!(to, "b");
                match msg {
                    RelayMessage::HolePunchCoordinate {
                        peer_id,
                        external_addr,
                    } => {
                        assert_eq!(peer_id, "me");
                        assert_eq!(external_addr, addr);
                    }
                    other => panic!("expected HolePunchCoordinate, got {other:?}"),
                }
            }
            other => panic!("expected ForwardTo, got {other:?}"),
        }
    }

    #[test]
    fn unregister_maps_to_close() {
        let act = dispatch(
            &registered_session(),
            RelayMessage::Unregister {
                peer_id: "me".into(),
            },
        );
        assert!(matches!(act, Action::Close));
    }

    #[test]
    fn pong_we_receive_is_ignored() {
        let act = dispatch(&registered_session(), RelayMessage::Pong { timestamp: 1 });
        assert!(matches!(act, Action::Nothing));
    }

    #[test]
    fn hole_punch_result_is_forwarded_to_the_named_peer() {
        let act = dispatch(
            &registered_session(),
            RelayMessage::HolePunchResult {
                peer_id: "b".into(),
                success: true,
            },
        );
        match act {
            Action::ForwardTo { to, msg } => {
                assert_eq!(to, "b");
                assert!(matches!(
                    msg,
                    RelayMessage::HolePunchResult { success: true, .. }
                ));
            }
            other => panic!("expected ForwardTo, got {other:?}"),
        }
    }

    #[test]
    fn get_peers_dispatch_returns_a_peers_sentinel() {
        // In the async path GetPeers is intercepted before dispatch (needs a registry read); the
        // pure dispatcher returns a placeholder Peers list so the routing logic stays uniform.
        let act = dispatch(
            &registered_session(),
            RelayMessage::GetPeers {
                network_id: Some("net1".into()),
            },
        );
        match act {
            Action::ReplyToSelf(msgs) => {
                assert!(matches!(msgs.as_slice(), [RelayMessage::Peers { .. }]));
            }
            other => panic!("expected ReplyToSelf(Peers), got {other:?}"),
        }
    }

    #[test]
    fn server_to_client_only_messages_are_ignored_when_received() {
        let s = registered_session();
        // A well-behaved client never sends these to us; we must not act on them.
        let info = RelayPeerInfo::new("x".into(), "net1".into(), 1);
        for msg in [
            RelayMessage::RegisterAck {
                success: true,
                message: "x".into(),
                connected_peers: 0,
            },
            RelayMessage::Peers { peers: vec![] },
            RelayMessage::PeerConnected { peer: info.clone() },
            RelayMessage::PeerDisconnected {
                peer_id: "x".into(),
            },
            RelayMessage::HolePunchCoordinate {
                peer_id: "x".into(),
                external_addr: "127.0.0.1:1".parse().unwrap(),
            },
            RelayMessage::Error {
                code: 9,
                message: "x".into(),
            },
        ] {
            assert!(
                matches!(dispatch(&s, msg), Action::Nothing),
                "server→client message must be ignored"
            );
        }
    }

    #[test]
    fn unregistered_rejects_every_non_register_kind() {
        let s = Session::default();
        for msg in [
            RelayMessage::Unregister {
                peer_id: "a".into(),
            },
            RelayMessage::RelayGossipMessage {
                from: "a".into(),
                to: "b".into(),
                payload: vec![1],
                seq: 1,
            },
            RelayMessage::Broadcast {
                from: "a".into(),
                payload: vec![1],
                exclude: vec![],
            },
            RelayMessage::GetPeers { network_id: None },
            RelayMessage::HolePunchRequest {
                peer_id: "a".into(),
                target_peer_id: "b".into(),
                external_addr: "127.0.0.1:1".parse().unwrap(),
            },
        ] {
            match dispatch(&s, msg) {
                Action::Error { code, .. } => assert_eq!(code, errcode::NOT_REGISTERED),
                other => panic!("expected NOT_REGISTERED, got {other:?}"),
            }
        }
    }

    /// The dashboard traffic counters (#1012): `record_relayed` folds each inbound frame into the
    /// right gauge — relayed bytes for gossip/broadcast payloads, hole-punch request/success/failure
    /// tallies — and leaves every other kind untouched.
    #[test]
    fn record_relayed_folds_each_kind_into_the_right_counter() {
        let st = RelayState::new(RelayServerConfig::default());

        st.record_relayed(&RelayMessage::RelayGossipMessage {
            from: "a".into(),
            to: "b".into(),
            payload: vec![0u8; 10],
            seq: 1,
        });
        st.record_relayed(&RelayMessage::Broadcast {
            from: "a".into(),
            payload: vec![0u8; 5],
            exclude: vec![],
        });
        assert_eq!(
            st.bytes_relayed.load(Ordering::Relaxed),
            15,
            "10 + 5 payload bytes"
        );

        st.record_relayed(&RelayMessage::HolePunchRequest {
            peer_id: "a".into(),
            target_peer_id: "b".into(),
            external_addr: "127.0.0.1:1".parse().unwrap(),
        });
        assert_eq!(st.hole_punch_requests.load(Ordering::Relaxed), 1);

        st.record_relayed(&RelayMessage::HolePunchResult {
            peer_id: "b".into(),
            success: true,
        });
        st.record_relayed(&RelayMessage::HolePunchResult {
            peer_id: "b".into(),
            success: false,
        });
        assert_eq!(st.hole_punch_successes.load(Ordering::Relaxed), 1);
        assert_eq!(st.hole_punch_failures.load(Ordering::Relaxed), 1);

        // A non-traffic frame moves nothing.
        st.record_relayed(&RelayMessage::Ping { timestamp: 1 });
        assert_eq!(st.bytes_relayed.load(Ordering::Relaxed), 15);
        assert_eq!(st.hole_punch_requests.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn relay_state_new_starts_empty_with_zero_uptime() {
        let st = RelayState::new(RelayServerConfig::default());
        assert_eq!(st.connected.load(Ordering::Relaxed), 0);
        assert_eq!(st.open_connections.load(Ordering::Relaxed), 0);
        assert!(st.registry.try_lock().unwrap().is_empty());
        // uptime is monotonic and small right after construction.
        assert!(st.uptime_secs() < 5);
    }

    /// SECURITY_AUDIT_P2P dig-relay #5: the open-connection guard counts a socket for its whole
    /// lifetime and releases it on drop — the count tracks OPEN sockets (registered or not), so the
    /// connection cap can't be bypassed by connect-but-never-register sockets, and it never leaks.
    #[test]
    fn open_connection_guard_counts_and_releases() {
        let st = RelayState::new(RelayServerConfig::default());
        assert_eq!(st.open_connections.load(Ordering::Relaxed), 0);
        {
            let _g1 = OpenConnectionGuard::acquire(&st);
            assert_eq!(st.open_connections.load(Ordering::Relaxed), 1);
            {
                // A second UNREGISTERED socket still counts toward the cap (the bug this closes).
                let _g2 = OpenConnectionGuard::acquire(&st);
                assert_eq!(st.open_connections.load(Ordering::Relaxed), 2);
            }
            assert_eq!(
                st.open_connections.load(Ordering::Relaxed),
                1,
                "dropping a guard releases exactly one slot"
            );
        }
        assert_eq!(
            st.open_connections.load(Ordering::Relaxed),
            0,
            "all slots released on drop — no leak"
        );
    }

    // ---- Direct tests of the connection-state functions (no socket; an mpsc channel stands in for
    // the per-connection outbound writer). These reach `register_peer`/`forward_to`/`broadcast`/
    // `deregister` branches the WebSocket integration tests can't isolate (e.g. the register-time
    // capacity ack and the duplicate-id replacement, which the pre-handshake cap guard masks). ----

    /// Drain everything currently queued on an unbounded receiver into a Vec (non-blocking).
    fn drain(rx: &mut mpsc::Receiver<RelayMessage>) -> Vec<RelayMessage> {
        let mut out = Vec::new();
        while let Ok(m) = rx.try_recv() {
            out.push(m);
        }
        out
    }

    /// A SocketAddr on a specific IP (the observed reflexive source a real connection carries), for
    /// the per-IP abuse-limit tests (#1386).
    fn addr_on(ip: &str) -> SocketAddr {
        format!("{ip}:40000").parse().unwrap()
    }

    /// #1386: `RelayState` wires the per-IP connection cap from config — one source IP is capped
    /// while a DIFFERENT source IP still gets a connection slot (the accept loop's `try_acquire_conn`
    /// gate, exercised at the shared-state level since the loop itself needs a real socket).
    #[tokio::test]
    async fn per_ip_connection_cap_is_wired_and_a_second_ip_is_unaffected() {
        let state = RelayState::new(RelayServerConfig {
            max_connections_per_ip: 1,
            ..Default::default()
        });
        let ip1 = addr_on("198.51.100.10").ip();
        let ip2 = addr_on("198.51.100.11").ip();
        let _slot = state.abuse.try_acquire_conn(ip1).expect("ip1 first allowed");
        assert!(
            state.abuse.try_acquire_conn(ip1).is_none(),
            "ip1 at its per-IP cap → refused"
        );
        assert!(
            state.abuse.try_acquire_conn(ip2).is_some(),
            "a different source IP still gets a slot"
        );
    }

    /// #1386: `register_peer` refuses with a failing ack + `RATE_LIMITED` once the per-IP CONCURRENT
    /// registration cap is reached, while a register from a DIFFERENT IP still succeeds.
    #[tokio::test]
    async fn register_peer_refuses_over_the_concurrent_registration_cap_with_rate_limited() {
        let state = RelayState::new(RelayServerConfig {
            max_registrations_per_ip: 1,
            ..Default::default()
        });
        let mut session_a = Session::default();
        let (tx_a, _rx_a) = mpsc::channel(64);
        let mut slot_a: Option<crate::limits::RegSlot> = None;
        // Peer A from IP1 registers and RETAINS its concurrent slot (held in slot_a).
        let ok_a = register_peer(
            &state,
            &mut session_a,
            "a".into(),
            "net".into(),
            1,
            &[],
            addr_on("203.0.113.1"),
            &tx_a,
            &pex_sink(),
            None,
            fresh_activity(),
            &mut slot_a,
        )
        .await;
        assert!(ok_a, "first register from the IP succeeds");
        assert!(slot_a.is_some(), "and retains its concurrent-registration slot");

        // Peer B from the SAME IP1 is over the concurrent cap → refused with RATE_LIMITED.
        let mut session_b = Session::default();
        let (tx_b, mut rx_b) = mpsc::channel(64);
        let ok_b = register_peer(
            &state,
            &mut session_b,
            "b".into(),
            "net".into(),
            1,
            &[],
            addr_on("203.0.113.1"),
            &tx_b,
            &pex_sink(),
            None,
            fresh_activity(),
            &mut None,
        )
        .await;
        assert!(!ok_b, "second concurrent register from the same IP is refused");
        assert!(session_b.peer_id.is_none(), "refused session stays unregistered");
        let msgs = drain(&mut rx_b);
        assert!(
            msgs.iter().any(|m| matches!(
                m,
                RelayMessage::RegisterAck { success: false, .. }
            )),
            "a failing register_ack is sent"
        );
        assert!(
            msgs.iter().any(|m| matches!(
                m,
                RelayMessage::Error { code, .. } if *code == errcode::RATE_LIMITED
            )),
            "a RATE_LIMITED error is sent, got {msgs:?}"
        );

        // A register from a DIFFERENT IP is unaffected by IP1's concurrent cap.
        let mut session_c = Session::default();
        let (tx_c, _rx_c) = mpsc::channel(64);
        let ok_c = register_peer(
            &state,
            &mut session_c,
            "c".into(),
            "net".into(),
            1,
            &[],
            addr_on("203.0.113.2"),
            &tx_c,
            &pex_sink(),
            None,
            fresh_activity(),
            &mut None,
        )
        .await;
        assert!(ok_c, "a different source IP still registers");
    }

    /// #1386: a burst of registers from one source IP eventually trips the per-IP registration RATE
    /// budget — at least one is refused with a failing ack + `RATE_LIMITED`. Robust across a
    /// one-second window boundary (a rate of 2 admits at most 4 across two windows, so a burst of 10
    /// always sees a refusal).
    #[tokio::test]
    async fn register_peer_registration_rate_flood_is_eventually_rate_limited() {
        let state = RelayState::new(RelayServerConfig {
            registrations_per_ip_per_sec: 2,
            ..Default::default()
        });
        let mut saw_rate_limited = false;
        for i in 0..10 {
            let mut session = Session::default();
            let (tx, mut rx) = mpsc::channel(64);
            let _ = register_peer(
                &state,
                &mut session,
                format!("peer-{i}"),
                "net".into(),
                1,
                &[],
                addr_on("203.0.113.50"),
                &tx,
                &pex_sink(),
                None,
                fresh_activity(),
                &mut None,
            )
            .await;
            if drain(&mut rx).iter().any(|m| matches!(
                m,
                RelayMessage::Error { code, .. } if *code == errcode::RATE_LIMITED
            )) {
                saw_rate_limited = true;
            }
        }
        assert!(
            saw_rate_limited,
            "a 10-deep register burst from one IP must trip the per-IP rate limit"
        );
    }

    #[tokio::test]
    async fn register_peer_acks_success_and_bumps_connected() {
        let state = RelayState::new(RelayServerConfig::default());
        let (tx, mut rx) = mpsc::channel(64);
        let mut session = Session::default();

        let ok = register_peer(
            &state,
            &mut session,
            "p".into(),
            "net".into(),
            1,
            &[],
            test_addr(),
            &tx,
            &pex_sink(),
            None,
            fresh_activity(),
            &mut None,
        )
        .await;
        assert!(ok);
        assert_eq!(state.connected.load(Ordering::Relaxed), 1);
        assert_eq!(session.peer_id.as_deref(), Some("p"));
        assert_eq!(session.network_id.as_deref(), Some("net"));
        match drain(&mut rx).as_slice() {
            [RelayMessage::RegisterAck {
                success,
                connected_peers,
                ..
            }] => {
                assert!(success);
                assert_eq!(*connected_peers, 1);
            }
            other => panic!("expected one success RegisterAck, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn register_peer_at_capacity_acks_failure_and_keeps_session_unregistered() {
        // Cap of 1, one peer already in the registry → a second register hits the register-time cap
        // guard: a failed ack + a CAPACITY error, no session mutation, no counter bump.
        let state = RelayState::new(RelayServerConfig {
            max_connections: 1,
            ..Default::default()
        });
        {
            let (tx0, _rx0) = mpsc::channel(64);
            let info = RelayPeerInfo::new("first".into(), "net".into(), 1);
            state.registry.lock().await.register(
                "first".into(),
                "net".into(),
                info,
                tx0,
                fresh_activity(),
            );
            state.connected.store(1, Ordering::Relaxed);
        }

        let (tx, mut rx) = mpsc::channel(64);
        let mut session = Session::default();
        let ok = register_peer(
            &state,
            &mut session,
            "second".into(),
            "net".into(),
            1,
            &[],
            test_addr(),
            &tx,
            &pex_sink(),
            None,
            fresh_activity(),
            &mut None,
        )
        .await;
        assert!(!ok, "register must fail at capacity");
        assert!(session.peer_id.is_none(), "session stays unregistered");
        assert_eq!(state.connected.load(Ordering::Relaxed), 1, "no extra bump");

        let msgs = drain(&mut rx);
        assert!(matches!(
            msgs[0],
            RelayMessage::RegisterAck { success: false, .. }
        ));
        assert!(matches!(
            msgs[1],
            RelayMessage::Error {
                code: errcode::CAPACITY,
                ..
            }
        ));
    }

    /// Anti-hijack (SECURITY_AUDIT_P2P dig-relay #1): a second `register_peer` for a `peer_id` whose
    /// incumbent connection is still LIVE is REFUSED (failing ack + `ID_IN_USE` error), the session
    /// stays unregistered, the count does not change, and the incumbent's sender is NOT replaced — so
    /// an unauthenticated client cannot evict + impersonate an existing peer's rendezvous.
    #[tokio::test]
    async fn register_peer_refuses_to_evict_a_live_incumbent() {
        let state = RelayState::new(RelayServerConfig::default());
        // First peer registers with a LIVE outbound channel (rx1 held).
        let (tx1, mut rx1) = mpsc::channel(64);
        let mut s1 = Session::default();
        assert!(
            register_peer(
                &state,
                &mut s1,
                "p".into(),
                "net".into(),
                1,
                &[],
                test_addr(),
                &tx1,
                &pex_sink(),
                None,
                fresh_activity(),
                &mut None,
            )
            .await
        );
        assert_eq!(state.connected.load(Ordering::Relaxed), 1);
        // Drain the incumbent's own RegisterAck so we can later prove its channel still routes.
        assert!(matches!(
            drain(&mut rx1)[0],
            RelayMessage::RegisterAck { success: true, .. }
        ));

        // A hijack attempt under the same id while the incumbent is live.
        let (tx2, mut rx2) = mpsc::channel(64);
        let mut s2 = Session::default();
        let ok = register_peer(
            &state,
            &mut s2,
            "p".into(),
            "net".into(),
            1,
            &[],
            test_addr(),
            &tx2,
            &pex_sink(),
            None,
            fresh_activity(),
            &mut None,
        )
        .await;
        assert!(!ok, "a duplicate-id register against a live peer must fail");
        assert!(
            s2.peer_id.is_none(),
            "the hijacker's session stays unregistered"
        );
        assert_eq!(
            state.connected.load(Ordering::Relaxed),
            1,
            "the refused register must not change the count"
        );
        assert_eq!(state.registry.lock().await.len(), 1);

        // The hijacker gets a failing ack + the ID_IN_USE error.
        let msgs = drain(&mut rx2);
        assert!(matches!(
            msgs[0],
            RelayMessage::RegisterAck { success: false, .. }
        ));
        assert!(matches!(
            msgs[1],
            RelayMessage::Error {
                code: errcode::ID_IN_USE,
                ..
            }
        ));

        // The incumbent still owns the id: a forward to "p" reaches tx1, never tx2.
        state
            .registry
            .lock()
            .await
            .sender_in_network("p", "net")
            .expect("incumbent keeps its slot")
            .try_send(RelayMessage::Ping { timestamp: 1 })
            .unwrap();
        assert_eq!(
            drain(&mut rx1).len(),
            1,
            "the incumbent still receives routed traffic"
        );
        assert!(drain(&mut rx2).is_empty(), "the hijacker receives nothing");
    }

    /// A genuine reconnect: when the prior connection's channel is CLOSED (its task tore down), the
    /// same id may be reclaimed WITHOUT double-counting.
    #[tokio::test]
    async fn register_peer_reconnect_reclaims_a_dead_incumbent_without_double_count() {
        let state = RelayState::new(RelayServerConfig::default());
        let (tx1, rx1) = mpsc::channel(64);
        let mut s1 = Session::default();
        assert!(
            register_peer(
                &state,
                &mut s1,
                "p".into(),
                "net".into(),
                1,
                &[],
                test_addr(),
                &tx1,
                &pex_sink(),
                None,
                fresh_activity(),
                &mut None,
            )
            .await
        );
        assert_eq!(state.connected.load(Ordering::Relaxed), 1);
        // The prior connection dies: its receiver drops → tx1 is closed.
        drop(rx1);

        let (tx2, mut rx2) = mpsc::channel(64);
        let mut s2 = Session::default();
        assert!(
            register_peer(
                &state,
                &mut s2,
                "p".into(),
                "net".into(),
                1,
                &[],
                test_addr(),
                &tx2,
                &pex_sink(),
                None,
                fresh_activity(),
                &mut None,
            )
            .await,
            "a reconnect over a dead prior connection must succeed"
        );
        assert_eq!(
            state.connected.load(Ordering::Relaxed),
            1,
            "reclaiming a dead slot must not double-count"
        );
        assert_eq!(state.registry.lock().await.len(), 1);
        assert!(matches!(
            drain(&mut rx2)[0],
            RelayMessage::RegisterAck { success: true, .. }
        ));
    }

    #[tokio::test]
    async fn forward_to_delivers_to_a_same_network_peer() {
        let state = RelayState::new(RelayServerConfig::default());
        let (btx, mut brx) = mpsc::channel(64);
        state.registry.lock().await.register(
            "b".into(),
            "net".into(),
            RelayPeerInfo::new("b".into(), "net".into(), 1),
            btx,
            fresh_activity(),
        );

        let (atx, mut arx) = mpsc::channel(64);
        let session = Session {
            peer_id: Some("me".into()),
            network_id: Some("net".into()),
            ..Default::default()
        };
        forward_to(
            &state,
            &session,
            "b",
            RelayMessage::Ping { timestamp: 7 },
            &atx,
        )
        .await;

        assert!(
            matches!(
                drain(&mut brx).as_slice(),
                [RelayMessage::Ping { timestamp: 7 }]
            ),
            "the target receives the forwarded message"
        );
        assert!(drain(&mut arx).is_empty(), "sender gets nothing on success");
    }

    #[tokio::test]
    async fn forward_to_unknown_peer_errors_back_to_sender() {
        let state = RelayState::new(RelayServerConfig::default());
        let (atx, mut arx) = mpsc::channel(64);
        let session = Session {
            peer_id: Some("me".into()),
            network_id: Some("net".into()),
            ..Default::default()
        };
        forward_to(
            &state,
            &session,
            "ghost",
            RelayMessage::Ping { timestamp: 1 },
            &atx,
        )
        .await;
        assert!(matches!(
            drain(&mut arx)[0],
            RelayMessage::Error {
                code: errcode::PEER_NOT_FOUND,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn forward_to_without_a_network_is_a_noop() {
        // A session that never registered a network can't route; forward_to returns silently.
        let state = RelayState::new(RelayServerConfig::default());
        let (atx, mut arx) = mpsc::channel(64);
        let session = Session::default();
        forward_to(
            &state,
            &session,
            "b",
            RelayMessage::Ping { timestamp: 1 },
            &atx,
        )
        .await;
        assert!(drain(&mut arx).is_empty());
    }

    /// SECURITY_AUDIT_P2P dig-relay #3: a peer that stops draining its socket cannot make the relay
    /// buffer without bound. `forward_to` uses a bounded channel + `try_send`, so once the target's
    /// queue is full, further forwards to it are DROPPED (never buffered past the capacity) — the
    /// relay heap for that peer is capped at `outbound_queue_capacity`.
    #[tokio::test]
    async fn forward_to_a_stalled_reader_is_bounded_and_drops_the_overflow() {
        let cap = 4usize;
        let state = RelayState::new(RelayServerConfig {
            outbound_queue_capacity: cap,
            ..Default::default()
        });
        // The target "b" NEVER reads its receiver (a stalled/hostile reader): rx is held but idle.
        let (btx, _brx_never_read) = mpsc::channel(cap);
        state.registry.lock().await.register(
            "b".into(),
            "net".into(),
            RelayPeerInfo::new("b".into(), "net".into(), 1),
            btx,
            fresh_activity(),
        );
        let (atx, _arx) = mpsc::channel(64);
        let session = Session {
            peer_id: Some("me".into()),
            network_id: Some("net".into()),
            ..Default::default()
        };

        // Forward far more than the capacity. None of these block, and none grow the queue past `cap`.
        for i in 0..(cap as u64 * 100) {
            forward_to(
                &state,
                &session,
                "b",
                RelayMessage::Ping { timestamp: i },
                &atx,
            )
            .await;
        }

        // The target's queue holds at most `cap` messages — the overflow was dropped, not buffered.
        let tx = state
            .registry
            .lock()
            .await
            .sender_in_network("b", "net")
            .unwrap();
        // A bounded Sender reports remaining capacity; the queue is full (0 free), never over-full.
        assert_eq!(
            tx.capacity(),
            0,
            "the stalled reader's queue is full at capacity, not grown past it"
        );
        assert_eq!(tx.max_capacity(), cap, "capacity is the configured bound");
    }

    #[tokio::test]
    async fn broadcast_reaches_only_same_network_non_excluded_peers() {
        let state = RelayState::new(RelayServerConfig::default());
        let mut rxs = std::collections::HashMap::new();
        for (id, net) in [("a", "net"), ("b", "net"), ("c", "net"), ("z", "other")] {
            let (tx, rx) = mpsc::channel(64);
            state.registry.lock().await.register(
                id.into(),
                net.into(),
                RelayPeerInfo::new(id.into(), net.into(), 1),
                tx,
                fresh_activity(),
            );
            rxs.insert(id, rx);
        }
        let session = Session {
            peer_id: Some("a".into()),
            network_id: Some("net".into()),
            ..Default::default()
        };
        broadcast(
            &state,
            &session,
            "a",
            &["c".to_string()],
            RelayMessage::Ping { timestamp: 5 },
        )
        .await;

        // b (net, not excluded) gets it; a (sender) does not; c (excluded) does not; z (other net)
        // does not.
        assert_eq!(drain(rxs.get_mut("b").unwrap()).len(), 1);
        assert!(drain(rxs.get_mut("a").unwrap()).is_empty());
        assert!(drain(rxs.get_mut("c").unwrap()).is_empty());
        assert!(drain(rxs.get_mut("z").unwrap()).is_empty());
    }

    #[tokio::test]
    async fn deregister_removes_the_peer_and_notifies_others() {
        let state = RelayState::new(RelayServerConfig::default());
        let (atx, mut arx) = mpsc::channel(64);
        let (btx, _brx) = mpsc::channel(64);
        state.registry.lock().await.register(
            "a".into(),
            "net".into(),
            RelayPeerInfo::new("a".into(), "net".into(), 1),
            atx,
            fresh_activity(),
        );
        state.registry.lock().await.register(
            "b".into(),
            "net".into(),
            RelayPeerInfo::new("b".into(), "net".into(), 1),
            btx,
            fresh_activity(),
        );
        state.connected.store(2, Ordering::Relaxed);

        // Deregister B: A must be told B disconnected, and the counter drops.
        let b_session = Session {
            peer_id: Some("b".into()),
            network_id: Some("net".into()),
            ..Default::default()
        };
        deregister(&state, &b_session).await;
        assert_eq!(state.connected.load(Ordering::Relaxed), 1);
        assert_eq!(state.registry.lock().await.len(), 1);
        match drain(&mut arx).as_slice() {
            [RelayMessage::PeerDisconnected { peer_id }] => assert_eq!(peer_id, "b"),
            other => panic!("A should get PeerDisconnected for b, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn deregister_of_an_unregistered_session_is_a_noop() {
        let state = RelayState::new(RelayServerConfig::default());
        // Never-registered session: deregister returns early, touches nothing.
        deregister(&state, &Session::default()).await;
        assert_eq!(state.connected.load(Ordering::Relaxed), 0);
    }

    // ---- Periodic health sweep (#1382): active pruning of dead/half-open registrations, mirrored
    // into introductions (the registry) + PEX, independent of and strictly faster than the idle
    // timeout backstop. ----

    /// (a) A peer whose connection task already tore down (its outbound channel is CLOSED) is pruned
    /// by `sweep_once` — removed from the registry AND mirrored out of PEX (`known_count`/
    /// `conn_count` both drop) — while an unrelated live peer is untouched.
    #[tokio::test]
    async fn sweep_prunes_a_dead_closed_channel_peer_and_updates_pex() {
        let state = RelayState::new(RelayServerConfig::default());
        let live = register_into(&state, &hex(0x0a), "net", 5001).await;

        // A second peer whose channel is already closed (its connection task tore down) — mirrored
        // into PEX exactly as a live registration would be, so the sweep's PEX cleanup is exercised.
        let (dead_tx, dead_rx) = mpsc::channel(64);
        let dead_id = hex(0x0b);
        {
            let mut reg = state.registry.lock().await;
            reg.register(
                dead_id.clone(),
                "net".into(),
                RelayPeerInfo::new(dead_id.clone(), "net".into(), 1),
                dead_tx,
                fresh_activity(),
            );
        }
        state.connected.fetch_add(1, Ordering::Relaxed);
        state.pex.lock().await.on_register(
            &dead_id,
            "net",
            "127.0.0.1:5002".parse().unwrap(),
            pex_sink(),
            now_ms(),
        );
        drop(dead_rx); // the connection is gone: the sender now reads closed

        assert_eq!(state.pex.lock().await.known_count("net"), 2);
        assert_eq!(state.pex.lock().await.conn_count(), 2);

        sweep_once(&state, now_secs()).await;

        assert!(
            state
                .registry
                .lock()
                .await
                .sender_in_network(&dead_id, "net")
                .is_none(),
            "the dead peer is removed from the registry"
        );
        assert!(
            state
                .registry
                .lock()
                .await
                .sender_in_network(&live.0.peer_id.clone().unwrap(), "net")
                .is_some(),
            "the unrelated live peer is untouched"
        );
        assert_eq!(state.connected.load(Ordering::Relaxed), 1);
        assert_eq!(
            state.pex.lock().await.known_count("net"),
            1,
            "the dead peer drops out of the introducer's advertise set"
        );
        assert_eq!(state.pex.lock().await.conn_count(), 1);
    }

    /// (b) A peer whose channel is still OPEN but whose last inbound activity is older than the
    /// liveness deadline (a half-open / silently-dead peer — no more RLY-006 keepalives) is pruned
    /// exactly as a closed-channel peer would be.
    #[tokio::test]
    async fn sweep_prunes_a_stale_activity_peer_with_an_open_channel() {
        let state = RelayState::new(RelayServerConfig::default());
        let now = now_secs();
        let stale_id = hex(0x0c);
        let (stale_tx, _stale_rx_kept_open) = mpsc::channel(64);
        {
            let mut reg = state.registry.lock().await;
            reg.register(
                stale_id.clone(),
                "net".into(),
                RelayPeerInfo::new(stale_id.clone(), "net".into(), 1),
                stale_tx,
                Arc::new(AtomicU64::new(now.saturating_sub(1_000))), // long past any sane deadline
            );
        }

        sweep_once(&state, now).await;

        assert!(
            state
                .registry
                .lock()
                .await
                .sender_in_network(&stale_id, "net")
                .is_none(),
            "a silently-stale peer is pruned even with its channel still open"
        );
    }

    /// (c) A peer with an open channel and activity within the liveness deadline survives a sweep
    /// untouched — the sweep is a no-op for a genuinely live, keepalive-sending peer.
    #[tokio::test]
    async fn sweep_spares_a_live_and_fresh_peer() {
        let state = RelayState::new(RelayServerConfig::default());
        let (_session, _rly_rx, _pex_tx, _pex_rx) =
            register_into(&state, &hex(0x0d), "net", 5003).await;

        sweep_once(&state, now_secs()).await;

        assert_eq!(
            state.registry.lock().await.len(),
            1,
            "a live, fresh peer is never pruned"
        );
    }

    /// (d) Anti-hijack: a reconnect that reclaims a formerly-dead `peer_id` BEFORE the sweep runs
    /// (`Registry::register`'s own `Reconnected` path) leaves a live, open-channel record in the
    /// registry — `dead_or_stale` scans the registry fresh on every call, so the sweep never prunes
    /// that live incumbent even though the SAME id was dead moments earlier. `sweep_once` collects and
    /// removes victims under one held registry lock (no `.await` between the scan and the removal), so
    /// a racing register can never land in the gap between "found dead" and "removed" — the reconnect
    /// either completes entirely before the sweep's lock acquisition (this test) or waits for it
    /// (structurally, since both take the same `Mutex`).
    #[tokio::test]
    async fn sweep_never_prunes_a_peer_that_reconnected_over_a_dead_incumbent() {
        let state = RelayState::new(RelayServerConfig::default());
        let id = hex(0x0e);

        // First registration goes dead (its channel closes).
        let (dead_tx, dead_rx) = mpsc::channel(64);
        {
            let mut reg = state.registry.lock().await;
            reg.register(
                id.clone(),
                "net".into(),
                RelayPeerInfo::new(id.clone(), "net".into(), 1),
                dead_tx,
                Arc::new(AtomicU64::new(now_secs().saturating_sub(1_000))), // also stale
            );
        }
        drop(dead_rx);

        // A reconnect reclaims the id with a LIVE, fresh registration — as `register_peer` would do
        // for a genuine reconnecting node — before the sweep ever runs.
        let (live_tx, _live_rx) = mpsc::channel(64);
        let outcome = state.registry.lock().await.register(
            id.clone(),
            "net".into(),
            RelayPeerInfo::new(id.clone(), "net".into(), 1),
            live_tx,
            fresh_activity(),
        );
        assert_eq!(outcome, RegisterOutcome::Reconnected);

        sweep_once(&state, now_secs()).await;

        assert!(
            state
                .registry
                .lock()
                .await
                .sender_in_network(&id, "net")
                .is_some(),
            "the reconnected LIVE incumbent must survive the sweep, never the stale record it replaced"
        );
        assert_eq!(state.registry.lock().await.len(), 1);
    }

    #[test]
    fn broadcast_clears_exclude_on_the_wire_but_keeps_it_for_routing() {
        let act = dispatch(
            &registered_session(),
            RelayMessage::Broadcast {
                from: "SPOOF".into(),
                payload: vec![9],
                exclude: vec!["c".into()],
            },
        );
        match act {
            Action::Broadcast { from, exclude, msg } => {
                assert_eq!(from, "me");
                assert_eq!(exclude, vec!["c".to_string()], "routing keeps exclude");
                match msg {
                    RelayMessage::Broadcast { from, exclude, .. } => {
                        assert_eq!(from, "me");
                        assert!(exclude.is_empty(), "wire copy drops exclude");
                    }
                    other => panic!("wrong broadcast msg: {other:?}"),
                }
            }
            other => panic!("expected Broadcast, got {other:?}"),
        }
    }

    // ---- RLY-008 PEX binding (frame classification, gating, and the server wiring) ----

    /// A `<64hex>` peer id from a byte.
    fn hex(b: u8) -> String {
        format!("{b:02x}").repeat(32)
    }

    /// A node `pex_handshake` on `net`, version 1 — as the bare JSON text a node sends.
    fn handshake_json(network_id: &str) -> String {
        PexMessage::PexHandshake {
            version: 1,
            network_id: network_id.into(),
            interval: 60,
            flags: vec![],
        }
        .to_json()
    }

    /// Drain a PEX receiver (non-blocking).
    fn drain_pex(rx: &mut mpsc::Receiver<PexMessage>) -> Vec<PexMessage> {
        let mut out = Vec::new();
        while let Ok(m) = rx.try_recv() {
            out.push(m);
        }
        out
    }

    #[test]
    fn is_pex_frame_recognizes_only_pex_typed_frames() {
        assert!(is_pex_frame(handshake_json("net").as_bytes()));
        assert!(is_pex_frame(br#"{"type":"pex_snapshot","peers":[]}"#));
        // RLY frames are not PEX.
        assert!(!is_pex_frame(br#"{"type":"register","peer_id":"a"}"#));
        assert!(!is_pex_frame(br#"{"type":"ping","timestamp":1}"#));
        // Non-JSON / no type / non-pex type.
        assert!(!is_pex_frame(b"not json"));
        assert!(!is_pex_frame(br#"{"no":"type"}"#));
        assert!(!is_pex_frame(br#"{"type":"pexish"}"#));
    }

    #[test]
    fn pex_dispatch_unregistered_is_not_registered() {
        let s = Session::default();
        let hs = PexMessage::from_json(&handshake_json("net")).unwrap();
        assert_eq!(pex_dispatch(&s, Some(&hs)), PexAction::NotRegistered);
    }

    #[test]
    fn pex_dispatch_first_handshake_brings_pex_up() {
        let s = registered_session();
        let hs = PexMessage::from_json(&handshake_json("net1")).unwrap();
        assert!(matches!(
            pex_dispatch(&s, Some(&hs)),
            PexAction::Handshake(_)
        ));
    }

    #[test]
    fn pex_dispatch_data_before_handshake_is_ignored() {
        // A registered but not-yet-PEX-active connection sending a non-handshake PEX frame: the relay
        // never brought PEX up, so it is ignored (not an RLY error, not fed to the engine).
        let s = registered_session();
        let snap = PexMessage::PexSnapshot { peers: vec![] };
        assert_eq!(pex_dispatch(&s, Some(&snap)), PexAction::IgnorePreHandshake);
    }

    #[test]
    fn pex_dispatch_data_after_handshake_is_data() {
        let s = Session {
            pex_active: true,
            ..registered_session()
        };
        let snap = PexMessage::PexSnapshot { peers: vec![] };
        assert!(matches!(pex_dispatch(&s, Some(&snap)), PexAction::Data(_)));
        // A second handshake once active is a data message (the engine strikes it as a protocol
        // violation), not a re-handshake.
        let hs = PexMessage::from_json(&handshake_json("net1")).unwrap();
        assert!(matches!(pex_dispatch(&s, Some(&hs)), PexAction::Data(_)));
    }

    #[test]
    fn pex_dispatch_bad_frame_only_strikes_when_active() {
        let inactive = registered_session();
        assert_eq!(pex_dispatch(&inactive, None), PexAction::IgnorePreHandshake);
        let active = Session {
            pex_active: true,
            ..registered_session()
        };
        assert_eq!(pex_dispatch(&active, None), PexAction::BadFrame);
    }

    /// Register a peer into a real `RelayState` and return its (RLY rx, PEX rx). Mirrors what a live
    /// connection does at register time (RLY-005 + the RLY-008 PEX mirror).
    async fn register_into(
        state: &Arc<RelayState>,
        peer_id: &str,
        network_id: &str,
        port: u16,
    ) -> (
        Session,
        mpsc::Receiver<RelayMessage>,
        mpsc::Sender<PexMessage>,
        mpsc::Receiver<PexMessage>,
    ) {
        let (out_tx, out_rx) = mpsc::channel(64);
        let (pex_tx, pex_rx) = mpsc::channel(64);
        let mut session = Session::default();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let ok = register_peer(
            state,
            &mut session,
            peer_id.into(),
            network_id.into(),
            1,
            &[],
            addr,
            &out_tx,
            &pex_tx,
            None,
            fresh_activity(),
            &mut None,
        )
        .await;
        assert!(ok, "registration should succeed");
        (session, out_rx, pex_tx, pex_rx)
    }

    // ---- B1: dialable-address emission (#924) ----

    /// B1: on register, the relay resolves the peer's advertised (private/unspecified) listen
    /// candidate into a dialable `reflexive_IP:advertised_port` using the observed reflexive source
    /// IP, and stores it on the peer's `RelayPeerInfo` so `get_peers`/`PeerConnected` hand it to other
    /// peers for a direct dial.
    #[tokio::test]
    async fn register_populates_dialable_addresses_from_reflexive_ip_and_advertised_port() {
        let state = RelayState::new(RelayServerConfig::default());
        let (tx, _rx) = mpsc::channel(64);
        let mut session = Session::default();
        let reflexive: SocketAddr = "203.0.113.7:55000".parse().unwrap(); // observed NAT source
        let advertised: SocketAddr = "192.168.1.5:9445".parse().unwrap(); // node's private listener

        assert!(
            register_peer(
                &state,
                &mut session,
                "p".into(),
                "net".into(),
                1,
                &[advertised],
                reflexive,
                &tx,
                &pex_sink(),
                None,
                fresh_activity(),
                &mut None,
            )
            .await
        );

        let peers = state.registry.lock().await.peers(Some("net"));
        assert_eq!(
            peers[0].addresses,
            vec!["203.0.113.7:9445".parse::<SocketAddr>().unwrap()],
            "the private listen host is replaced by the reflexive IP, keeping the advertised port"
        );
    }

    /// B1 anti-reflection (#926, security HIGH): a peer advertising a globally-routable host it does
    /// NOT own (a victim's public address) must never be handed to other peers verbatim, or the relay
    /// would fan out connection-attempts at the victim. The unverifiable third-party host is dropped
    /// and only the safe reflexive substitution (which points back at the registrant) is emitted.
    #[tokio::test]
    async fn register_drops_a_public_address_that_does_not_match_the_reflexive_source() {
        let state = RelayState::new(RelayServerConfig::default());
        let (tx, _rx) = mpsc::channel(64);
        let mut session = Session::default();
        let reflexive: SocketAddr = "198.51.100.9:55000".parse().unwrap(); // attacker's real source
        let victim: SocketAddr = "203.0.113.200:9445".parse().unwrap(); // a public addr it doesn't own

        assert!(
            register_peer(
                &state,
                &mut session,
                "attacker".into(),
                "net".into(),
                1,
                &[victim],
                reflexive,
                &tx,
                &pex_sink(),
                None,
                fresh_activity(),
                &mut None,
            )
            .await
        );

        let peers = state.registry.lock().await.peers(Some("net"));
        assert!(
            !peers[0].addresses.contains(&victim),
            "the unverifiable third-party public address must not be emitted (reflection vector)"
        );
        assert_eq!(
            peers[0].addresses,
            vec!["198.51.100.9:9445".parse::<SocketAddr>().unwrap()],
            "only the safe reflexive_IP:advertised_port substitution is emitted"
        );
    }

    /// B1 legacy fallback: a peer that advertises no listen candidates (a pre-#924 node) gets an
    /// empty `addresses` list — it keeps today's identity-only relayed reachability, no regression.
    #[tokio::test]
    async fn register_without_advertised_listen_addrs_leaves_addresses_empty() {
        let state = RelayState::new(RelayServerConfig::default());
        let (tx, _rx) = mpsc::channel(64);
        let mut session = Session::default();
        assert!(
            register_peer(
                &state,
                &mut session,
                "p".into(),
                "net".into(),
                1,
                &[],
                test_addr(),
                &tx,
                &pex_sink(),
                None,
                fresh_activity(),
                &mut None,
            )
            .await
        );
        let peers = state.registry.lock().await.peers(Some("net"));
        assert!(
            peers[0].addresses.is_empty(),
            "no advertised candidates → no resolved dialable addresses"
        );
    }

    // ---- B2: relayed-forwarder hardening (#924) ----

    /// B2 network-scope: `forward_to` only reaches a peer on the SENDER's network. A peer registered
    /// on a DIFFERENT network is not routable — the forward is refused with `PEER_NOT_FOUND`, never
    /// crossing the network boundary (the relay forwards only between same-`network_id` peers).
    #[tokio::test]
    async fn forward_to_a_peer_on_another_network_is_refused() {
        let state = RelayState::new(RelayServerConfig::default());
        // "b" is registered on net2.
        let (btx, mut brx) = mpsc::channel(64);
        state.registry.lock().await.register(
            "b".into(),
            "net2".into(),
            RelayPeerInfo::new("b".into(), "net2".into(), 1),
            btx,
            fresh_activity(),
        );
        // The sender is on net1 and tries to forward to "b".
        let (atx, mut arx) = mpsc::channel(64);
        let session = Session {
            peer_id: Some("me".into()),
            network_id: Some("net1".into()),
            ..Default::default()
        };
        forward_to(
            &state,
            &session,
            "b",
            RelayMessage::RelayGossipMessage {
                from: "me".into(),
                to: "b".into(),
                payload: vec![1, 2, 3],
                seq: 1,
            },
            &atx,
        )
        .await;

        assert!(
            matches!(
                drain(&mut arx)[0],
                RelayMessage::Error {
                    code: errcode::PEER_NOT_FOUND,
                    ..
                }
            ),
            "a cross-network forward must be refused, not delivered"
        );
        assert!(
            drain(&mut brx).is_empty(),
            "the other-network peer must receive nothing"
        );
    }

    // ---- Proof-of-possession (mTLS `verified_peer_id`, SPEC.md §3.2/§8, issue #5) ----
    //
    // These exercise `register_peer`'s identity check directly (no real TLS socket needed — the
    // dedicated end-to-end mTLS handshake is covered by `tests/mtls.rs` and `src/tls.rs`'s own
    // handshake tests). `verified_peer_id` stands in for whatever `crate::tls::extract_client_peer_id`
    // derived from the actual certificate used for the connection.

    #[tokio::test]
    async fn register_peer_accepts_a_claimed_id_matching_the_verified_certificate_identity() {
        let state = RelayState::new(RelayServerConfig::default());
        let (tx, mut rx) = mpsc::channel(64);
        let mut session = Session::default();

        let ok = register_peer(
            &state,
            &mut session,
            "abc123".into(),
            "net".into(),
            1,
            &[],
            test_addr(),
            &tx,
            &pex_sink(),
            Some("abc123"),
            fresh_activity(),
            &mut None,
        )
        .await;
        assert!(ok, "a claimed id matching the mTLS identity must register");
        assert_eq!(session.peer_id.as_deref(), Some("abc123"));
        assert!(matches!(
            drain(&mut rx).as_slice(),
            [RelayMessage::RegisterAck { success: true, .. }]
        ));
    }

    /// The core proof-of-possession guarantee (issue #5 acceptance criterion): a `Register` claiming
    /// a `peer_id` OTHER than the one derived from the mTLS certificate actually used for the
    /// connection is REFUSED — a peer cannot register an id it does not hold the key for — even
    /// though that exact id is otherwise unused in the registry (this is not the anti-hijack/
    /// `ID_IN_USE` path; it is a fresh identity-mismatch rejection).
    #[tokio::test]
    async fn register_peer_rejects_a_claimed_id_that_does_not_match_the_verified_certificate_identity(
    ) {
        let state = RelayState::new(RelayServerConfig::default());
        let (tx, mut rx) = mpsc::channel(64);
        let mut session = Session::default();

        let ok = register_peer(
            &state,
            &mut session,
            "spoofed-id".into(),
            "net".into(),
            1,
            &[],
            test_addr(),
            &tx,
            &pex_sink(),
            Some("the-real-cert-derived-id"),
            fresh_activity(),
            &mut None,
        )
        .await;
        assert!(!ok, "a peer_id/certificate mismatch must be refused");
        assert!(session.peer_id.is_none(), "session stays unregistered");
        assert_eq!(
            state.connected.load(Ordering::Relaxed),
            0,
            "no bump on a rejected registration"
        );
        assert!(state.registry.try_lock().unwrap().is_empty());

        let msgs = drain(&mut rx);
        assert!(matches!(
            msgs[0],
            RelayMessage::RegisterAck { success: false, .. }
        ));
        assert!(matches!(
            msgs[1],
            RelayMessage::Error {
                code: errcode::IDENTITY_MISMATCH,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn register_peer_identity_check_runs_before_the_capacity_check() {
        // Even at capacity, a mismatched claimed id must fail with IDENTITY_MISMATCH, not CAPACITY —
        // proving the identity check is not merely a side effect of the ordinary registration path.
        let state = RelayState::new(RelayServerConfig {
            max_connections: 0,
            ..Default::default()
        });
        // max_connections: 0 fails RelayServerConfig::validate() in production, but register_peer
        // itself doesn't call validate() — using it here isolates the ordering without needing a
        // real full registry.
        let (tx, mut rx) = mpsc::channel(64);
        let mut session = Session::default();

        let ok = register_peer(
            &state,
            &mut session,
            "spoofed".into(),
            "net".into(),
            1,
            &[],
            test_addr(),
            &tx,
            &pex_sink(),
            Some("real-id"),
            fresh_activity(),
            &mut None,
        )
        .await;
        assert!(!ok);
        assert!(matches!(
            drain(&mut rx)[1],
            RelayMessage::Error {
                code: errcode::IDENTITY_MISMATCH,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn register_mirrors_into_the_pex_introducer_set() {
        let state = RelayState::new(RelayServerConfig::default());
        let _a = register_into(&state, &hex(0x0a), "net", 4001).await;
        let _b = register_into(&state, &hex(0x0b), "net", 4002).await;
        assert_eq!(
            state.pex.lock().await.known_count("net"),
            2,
            "both registrants are first-hand known to the introducer"
        );
        assert_eq!(state.pex.lock().await.conn_count(), 2);
    }

    #[tokio::test]
    async fn node_handshake_gets_our_handshake_then_a_snapshot_of_other_peers() {
        let state = RelayState::new(RelayServerConfig::default());
        let (a, b) = (hex(0x0a), hex(0x0b));
        let (mut sess_a, _a_rly, a_pex_tx, mut a_pex_rx) =
            register_into(&state, &a, "net", 4001).await;
        let _b = register_into(&state, &b, "net", 4002).await;

        // A sends its pex_handshake as a raw frame → handled by the server PEX path.
        let (dummy_rly, _drx) = mpsc::channel(64);
        handle_pex_frame(
            &state,
            &mut sess_a,
            handshake_json("net").as_bytes(),
            "127.0.0.1:4001".parse().unwrap(),
            &a_pex_tx,
            &dummy_rly,
        )
        .await;

        assert!(sess_a.pex_active, "A is now PEX-active");
        let msgs = drain_pex(&mut a_pex_rx);
        assert!(
            matches!(msgs[0], PexMessage::PexHandshake { .. }),
            "first reply is our handshake"
        );
        match &msgs[1] {
            PexMessage::PexSnapshot { peers } => {
                let ids: Vec<_> = peers.iter().map(|p| p.peer_id.clone()).collect();
                assert_eq!(
                    ids,
                    vec![b.clone()],
                    "snapshot has the OTHER peer, not A itself"
                );
            }
            other => panic!("expected snapshot, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_pex_frame_before_registration_gets_not_registered() {
        let state = RelayState::new(RelayServerConfig::default());
        let mut session = Session::default(); // never registered
        let (rly_tx, mut rly_rx) = mpsc::channel(64);
        let (pex_tx, mut pex_rx) = mpsc::channel(64);
        handle_pex_frame(
            &state,
            &mut session,
            handshake_json("net").as_bytes(),
            "127.0.0.1:4001".parse().unwrap(),
            &pex_tx,
            &rly_tx,
        )
        .await;
        // The relay's own error envelope, code NOT_REGISTERED, on the RLY channel — never PEX.
        match drain(&mut rly_rx).as_slice() {
            [RelayMessage::Error { code, .. }] => assert_eq!(*code, errcode::NOT_REGISTERED),
            other => panic!("expected NOT_REGISTERED error, got {other:?}"),
        }
        assert!(
            drain_pex(&mut pex_rx).is_empty(),
            "no PEX before registration"
        );
        assert!(!session.pex_active);
    }

    #[tokio::test]
    async fn snapshot_is_scoped_to_the_registered_network() {
        let state = RelayState::new(RelayServerConfig::default());
        let (a, z) = (hex(0x0a), hex(0x0c));
        let (mut sess_a, _rly, a_pex_tx, mut a_pex_rx) =
            register_into(&state, &a, "netX", 4001).await;
        // A peer on a DIFFERENT network — must never appear in netX's snapshot.
        let _z = register_into(&state, &z, "netY", 4003).await;

        let (dummy_rly, _drx) = mpsc::channel(64);
        handle_pex_frame(
            &state,
            &mut sess_a,
            handshake_json("netX").as_bytes(),
            "127.0.0.1:4001".parse().unwrap(),
            &a_pex_tx,
            &dummy_rly,
        )
        .await;
        let msgs = drain_pex(&mut a_pex_rx);
        match &msgs[1] {
            PexMessage::PexSnapshot { peers } => {
                assert!(
                    peers.is_empty(),
                    "no same-network peer besides A; Z (netY) excluded"
                );
            }
            other => panic!("expected snapshot, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn inbound_node_pex_data_never_enters_the_introducer_registry() {
        // The introducer-only discard rule (SPEC §10.2): a node advertising a peer to the relay must
        // NOT cause the relay to re-advertise it.
        let state = RelayState::new(RelayServerConfig::default());
        let a = hex(0x0a);
        let injected = hex(0x0f);
        let (mut sess_a, _rly, a_pex_tx, _a_pex_rx) = register_into(&state, &a, "net", 4001).await;
        assert_eq!(state.pex.lock().await.known_count("net"), 1);

        // A activates PEX, then sends a snapshot advertising a NEW peer.
        let (dummy_rly, _drx) = mpsc::channel(64);
        handle_pex_frame(
            &state,
            &mut sess_a,
            handshake_json("net").as_bytes(),
            "127.0.0.1:4001".parse().unwrap(),
            &a_pex_tx,
            &dummy_rly,
        )
        .await;
        // A well-formed node snapshot advertising a fresh, valid injected peer (fresh `last_seen` so
        // the entry itself validates — proving the peer is discarded by the introducer-only rule, not
        // merely rejected as stale).
        let injected_entry = dig_pex::PeerEntry::new(
            injected.clone(),
            "net",
            now_ms() / 1000,
            dig_pex::Provenance::Direct,
        )
        .with_address(dig_pex::Address::direct("203.0.113.9", 9444));
        let node_snapshot = PexMessage::PexSnapshot {
            peers: vec![injected_entry],
        };
        handle_pex_frame(
            &state,
            &mut sess_a,
            node_snapshot.to_json().as_bytes(),
            "127.0.0.1:4001".parse().unwrap(),
            &a_pex_tx,
            &dummy_rly,
        )
        .await;

        assert_eq!(
            state.pex.lock().await.known_count("net"),
            1,
            "node-sent PEX data must not grow the introducer's first-hand set"
        );
    }

    #[tokio::test]
    async fn deregister_drops_the_peer_from_the_pex_set() {
        let state = RelayState::new(RelayServerConfig::default());
        let (sess_a, _rly, _pt, _pr) = register_into(&state, &hex(0x0a), "net", 4001).await;
        assert_eq!(state.pex.lock().await.known_count("net"), 1);
        assert_eq!(state.pex.lock().await.conn_count(), 1);

        deregister(&state, &sess_a).await;
        assert_eq!(
            state.pex.lock().await.known_count("net"),
            0,
            "unregister drops the peer from the advertise set"
        );
        assert_eq!(state.pex.lock().await.conn_count(), 0);
    }
}
