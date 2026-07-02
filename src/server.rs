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
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message;

use crate::config::RelayServerConfig;
use crate::net::bind_tcp_dual_stack;
use crate::pex::PexRelay;
use crate::registry::Registry;
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
    /// Process start time, for `/health` uptime.
    pub started: SystemTime,
    /// Validated config.
    pub config: RelayServerConfig,
}

impl RelayState {
    /// Build shared state from a validated config.
    pub fn new(config: RelayServerConfig) -> Arc<Self> {
        Arc::new(RelayState {
            registry: Mutex::new(Registry::new()),
            pex: Mutex::new(PexRelay::new()),
            connected: AtomicU64::new(0),
            started: SystemTime::now(),
            config,
        })
    }

    /// Seconds since process start (saturating).
    pub fn uptime_secs(&self) -> u64 {
        self.started.elapsed().map(|d| d.as_secs()).unwrap_or(0)
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
        } => Action::Register {
            peer_id,
            network_id,
            protocol_version,
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

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(state, stream, peer_addr).await {
                tracing::debug!(error = %e, %peer_addr, "connection ended");
            }
        });
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
async fn handle_connection(
    state: Arc<RelayState>,
    stream: tokio::net::TcpStream,
    peer_addr: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Connection cap (RLY-001 capacity guard): refuse before the handshake when full.
    if state.connected.load(Ordering::Relaxed) as usize >= state.config.max_connections {
        tracing::warn!(%peer_addr, "refusing connection: at capacity");
        return Ok(());
    }

    let ws = tokio_tungstenite::accept_async(stream).await?;
    let (mut write, mut read) = ws.split();

    // Outbound RLY channel: anything (this task, or another peer forwarding to us) pushes a
    // RelayMessage here; the writer half drains it to the socket.
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<RelayMessage>();
    // Outbound PEX channel (RLY-008): the PEX subsystem (handshake reply + tick-driven deltas) pushes
    // `PexMessage`s here. Kept separate from the RLY channel so the registry / RLY-001..007 wire is
    // byte-for-byte unchanged; the one writer merges both onto the socket as JSON text frames.
    let (pex_tx, mut pex_rx) = mpsc::unbounded_channel::<PexMessage>();

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

    loop {
        let next = tokio::time::timeout(idle, read.next()).await;
        let frame = match next {
            Err(_) => {
                tracing::debug!(%peer_addr, "idle timeout; reaping");
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
                let _ = out_tx.send(RelayMessage::Error {
                    code: errcode::BAD_MESSAGE,
                    message: "invalid relay JSON".to_string(),
                });
                continue;
            }
        };

        // GetPeers is handled here (needs a registry read the pure dispatcher can't do).
        if let RelayMessage::GetPeers { network_id } = &msg {
            let filter = network_id.clone().or_else(|| session.network_id.clone());
            let peers = state.registry.lock().await.peers(filter.as_deref());
            let _ = out_tx.send(RelayMessage::Peers { peers });
            continue;
        }

        match dispatch(&session, msg) {
            Action::Register {
                peer_id,
                network_id,
                protocol_version,
            } => {
                if !register_peer(
                    &state,
                    &mut session,
                    peer_id,
                    network_id,
                    protocol_version,
                    peer_addr,
                    &out_tx,
                    &pex_tx,
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
                    let _ = out_tx.send(m);
                }
            }
            Action::Error { code, message } => {
                let _ = out_tx.send(RelayMessage::Error { code, message });
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
    pex_tx: &mpsc::UnboundedSender<PexMessage>,
    out_tx: &mpsc::UnboundedSender<RelayMessage>,
) {
    let decoded = std::str::from_utf8(frame)
        .ok()
        .and_then(|s| PexMessage::from_json(s).ok());

    let peer_id = session.peer_id.clone().unwrap_or_default();
    let network_id = session.network_id.clone().unwrap_or_default();
    let now = now_ms();

    match pex_dispatch(session, decoded.as_ref()) {
        PexAction::NotRegistered => {
            let _ = out_tx.send(RelayMessage::Error {
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
                let _ = pex_tx.send(m);
            }
        }
        PexAction::Data(msg) => {
            let replies = state
                .pex
                .lock()
                .await
                .on_node_message(&peer_id, &network_id, msg, now);
            for m in replies {
                let _ = pex_tx.send(m);
            }
        }
        PexAction::BadFrame => {
            let replies = state
                .pex
                .lock()
                .await
                .on_node_bad_frame(&peer_id, &network_id, now);
            for m in replies {
                let _ = pex_tx.send(m);
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
#[allow(clippy::too_many_arguments)]
async fn register_peer(
    state: &Arc<RelayState>,
    session: &mut Session,
    peer_id: String,
    network_id: String,
    protocol_version: u32,
    peer_addr: std::net::SocketAddr,
    out_tx: &mpsc::UnboundedSender<RelayMessage>,
    pex_tx: &mpsc::UnboundedSender<PexMessage>,
) -> bool {
    let mut reg = state.registry.lock().await;
    if reg.len() >= state.config.max_connections {
        let _ = out_tx.send(RelayMessage::RegisterAck {
            success: false,
            message: "relay at capacity".to_string(),
            connected_peers: reg.len(),
        });
        let _ = out_tx.send(RelayMessage::Error {
            code: errcode::CAPACITY,
            message: "relay at capacity".to_string(),
        });
        return false;
    }

    // `RelayPeerInfo::new` stamps connected_at/last_seen with the current unix time.
    let info = RelayPeerInfo::new(peer_id.clone(), network_id.clone(), protocol_version);

    // If a stale connection held this id, replace it (and let its task notice the channel close).
    if let Some(prior) = reg.register(
        peer_id.clone(),
        network_id.clone(),
        info.clone(),
        out_tx.clone(),
    ) {
        tracing::debug!(%peer_id, "replaced a prior registration for the same id");
        drop(prior); // closes the prior outbound channel → its writer task exits
    } else {
        state.connected.fetch_add(1, Ordering::Relaxed);
    }

    let connected_peers = reg.len();
    // Notify existing same-network peers of the newcomer (RLY-005 PeerConnected).
    let targets = reg.broadcast_targets(&peer_id, &network_id, &[]);
    drop(reg);

    let _ = out_tx.send(RelayMessage::RegisterAck {
        success: true,
        message: "registered".to_string(),
        connected_peers,
    });
    for (_, tx) in targets {
        let _ = tx.send(RelayMessage::PeerConnected { peer: info.clone() });
    }

    // RLY-008: mirror the registration into the PEX introducer set. Done after the RLY lock is
    // released to keep the two subsystems' locks independent.
    state
        .pex
        .lock()
        .await
        .on_register(&peer_id, &network_id, peer_addr, pex_tx.clone(), now_ms());

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
    out_tx: &mpsc::UnboundedSender<RelayMessage>,
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
            let _ = tx.send(msg);
        }
        None => {
            let _ = out_tx.send(RelayMessage::Error {
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
        let _ = tx.send(msg.clone());
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
    if reg.unregister(peer_id).is_some() {
        state.connected.fetch_sub(1, Ordering::Relaxed);
        let targets = reg.broadcast_targets(peer_id, network_id, &[]);
        drop(reg);
        for (_, tx) in targets {
            let _ = tx.send(RelayMessage::PeerDisconnected {
                peer_id: peer_id.clone(),
            });
        }
        state.pex.lock().await.on_unregister(peer_id, network_id);
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
    fn pex_sink() -> mpsc::UnboundedSender<PexMessage> {
        mpsc::unbounded_channel().0
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

    #[test]
    fn relay_state_new_starts_empty_with_zero_uptime() {
        let st = RelayState::new(RelayServerConfig::default());
        assert_eq!(st.connected.load(Ordering::Relaxed), 0);
        assert!(st.registry.try_lock().unwrap().is_empty());
        // uptime is monotonic and small right after construction.
        assert!(st.uptime_secs() < 5);
    }

    // ---- Direct tests of the connection-state functions (no socket; an mpsc channel stands in for
    // the per-connection outbound writer). These reach `register_peer`/`forward_to`/`broadcast`/
    // `deregister` branches the WebSocket integration tests can't isolate (e.g. the register-time
    // capacity ack and the duplicate-id replacement, which the pre-handshake cap guard masks). ----

    /// Drain everything currently queued on an unbounded receiver into a Vec (non-blocking).
    fn drain(rx: &mut mpsc::UnboundedReceiver<RelayMessage>) -> Vec<RelayMessage> {
        let mut out = Vec::new();
        while let Ok(m) = rx.try_recv() {
            out.push(m);
        }
        out
    }

    #[tokio::test]
    async fn register_peer_acks_success_and_bumps_connected() {
        let state = RelayState::new(RelayServerConfig::default());
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut session = Session::default();

        let ok = register_peer(
            &state,
            &mut session,
            "p".into(),
            "net".into(),
            1,
            test_addr(),
            &tx,
            &pex_sink(),
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
            let (tx0, _rx0) = mpsc::unbounded_channel();
            let info = RelayPeerInfo::new("first".into(), "net".into(), 1);
            state
                .registry
                .lock()
                .await
                .register("first".into(), "net".into(), info, tx0);
            state.connected.store(1, Ordering::Relaxed);
        }

        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut session = Session::default();
        let ok = register_peer(
            &state,
            &mut session,
            "second".into(),
            "net".into(),
            1,
            test_addr(),
            &tx,
            &pex_sink(),
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

    #[tokio::test]
    async fn register_peer_replacing_same_id_does_not_double_count() {
        // A reconnect under an existing id replaces the prior record WITHOUT incrementing the count.
        let state = RelayState::new(RelayServerConfig::default());
        let (tx1, _rx1) = mpsc::unbounded_channel();
        let mut s1 = Session::default();
        assert!(
            register_peer(
                &state,
                &mut s1,
                "p".into(),
                "net".into(),
                1,
                test_addr(),
                &tx1,
                &pex_sink()
            )
            .await
        );
        assert_eq!(state.connected.load(Ordering::Relaxed), 1);

        let (tx2, mut rx2) = mpsc::unbounded_channel();
        let mut s2 = Session::default();
        assert!(
            register_peer(
                &state,
                &mut s2,
                "p".into(),
                "net".into(),
                1,
                test_addr(),
                &tx2,
                &pex_sink()
            )
            .await
        );
        assert_eq!(
            state.connected.load(Ordering::Relaxed),
            1,
            "replacing the same id must not double-count"
        );
        assert_eq!(state.registry.lock().await.len(), 1);
        // The new connection still gets a success ack.
        assert!(matches!(
            drain(&mut rx2)[0],
            RelayMessage::RegisterAck { success: true, .. }
        ));
    }

    #[tokio::test]
    async fn forward_to_delivers_to_a_same_network_peer() {
        let state = RelayState::new(RelayServerConfig::default());
        let (btx, mut brx) = mpsc::unbounded_channel();
        state.registry.lock().await.register(
            "b".into(),
            "net".into(),
            RelayPeerInfo::new("b".into(), "net".into(), 1),
            btx,
        );

        let (atx, mut arx) = mpsc::unbounded_channel();
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
        let (atx, mut arx) = mpsc::unbounded_channel();
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
        let (atx, mut arx) = mpsc::unbounded_channel();
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

    #[tokio::test]
    async fn broadcast_reaches_only_same_network_non_excluded_peers() {
        let state = RelayState::new(RelayServerConfig::default());
        let mut rxs = std::collections::HashMap::new();
        for (id, net) in [("a", "net"), ("b", "net"), ("c", "net"), ("z", "other")] {
            let (tx, rx) = mpsc::unbounded_channel();
            state.registry.lock().await.register(
                id.into(),
                net.into(),
                RelayPeerInfo::new(id.into(), net.into(), 1),
                tx,
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
        let (atx, mut arx) = mpsc::unbounded_channel();
        let (btx, _brx) = mpsc::unbounded_channel();
        state.registry.lock().await.register(
            "a".into(),
            "net".into(),
            RelayPeerInfo::new("a".into(), "net".into(), 1),
            atx,
        );
        state.registry.lock().await.register(
            "b".into(),
            "net".into(),
            RelayPeerInfo::new("b".into(), "net".into(), 1),
            btx,
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
    fn drain_pex(rx: &mut mpsc::UnboundedReceiver<PexMessage>) -> Vec<PexMessage> {
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
        mpsc::UnboundedReceiver<RelayMessage>,
        mpsc::UnboundedSender<PexMessage>,
        mpsc::UnboundedReceiver<PexMessage>,
    ) {
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let (pex_tx, pex_rx) = mpsc::unbounded_channel();
        let mut session = Session::default();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let ok = register_peer(
            state,
            &mut session,
            peer_id.into(),
            network_id.into(),
            1,
            addr,
            &out_tx,
            &pex_tx,
        )
        .await;
        assert!(ok, "registration should succeed");
        (session, out_rx, pex_tx, pex_rx)
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
        let (dummy_rly, _drx) = mpsc::unbounded_channel();
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
        let (rly_tx, mut rly_rx) = mpsc::unbounded_channel();
        let (pex_tx, mut pex_rx) = mpsc::unbounded_channel();
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

        let (dummy_rly, _drx) = mpsc::unbounded_channel();
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
        let (dummy_rly, _drx) = mpsc::unbounded_channel();
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
