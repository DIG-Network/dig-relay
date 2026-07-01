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
use std::time::SystemTime;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message;

use crate::config::RelayServerConfig;
use crate::registry::Registry;
use crate::wire::{RelayMessage, RelayPeerInfo};

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

/// Per-connection registration state, set after a successful `Register`.
#[derive(Debug, Clone, Default)]
struct Session {
    peer_id: Option<String>,
    network_id: Option<String>,
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

        // RLY-010: announce candidate addresses. Needs a registry WRITE, so the async path
        // intercepts it before dispatch (like GetPeers). Reaching here (registered) is a no-op.
        RelayMessage::AnnouncePeer { .. } => Action::Nothing,

        // RLY-011: known-peer list. The async path intercepts this for the registry read; the pure
        // dispatcher returns a placeholder KnownPeers so the routing logic stays uniform.
        RelayMessage::GetKnownPeers { .. } => {
            Action::ReplyToSelf(vec![RelayMessage::KnownPeers { peers: Vec::new() }])
        }

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
        | RelayMessage::KnownPeers { .. }
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

/// Run the relay WebSocket accept loop until the listener errors or the process is cancelled.
/// Each accepted TCP connection is upgraded to a WebSocket and handled in its own task.
pub async fn run(state: Arc<RelayState>) -> std::io::Result<()> {
    let listener = TcpListener::bind(state.config.listen).await?;
    tracing::info!(addr = %state.config.listen, "dig-relay listening (RelayMessage/WebSocket)");
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

/// Handle one WebSocket connection: enforce the connection cap, then read/dispatch frames until
/// close. A dedicated writer task drains the peer's outbound channel onto the socket so messages
/// forwarded by OTHER connections are delivered concurrently with this connection's own replies.
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

    // Outbound channel: anything (this task, or another peer forwarding to us) pushes a
    // RelayMessage here; the writer half drains it to the socket.
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<RelayMessage>();

    // Writer task: serialize each RelayMessage as JSON text and write it.
    let writer = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            let txt = match serde_json::to_string(&msg) {
                Ok(t) => t,
                Err(_) => continue,
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

        // RLY-010 AnnouncePeer + RLY-011 GetKnownPeers also touch the registry (a write / an
        // address-carrying read), so they are handled here rather than in the pure dispatcher. Both
        // require a registered session; an unregistered one gets NOT_REGISTERED (as dispatch would).
        if let RelayMessage::AnnouncePeer { addrs } = &msg {
            announce_peer(&state, &session, addrs.clone(), &out_tx).await;
            continue;
        }
        if let RelayMessage::GetKnownPeers { network_id, max } = &msg {
            get_known_peers(&state, &session, network_id.clone(), *max, &out_tx).await;
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
                    &out_tx,
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

    // Connection teardown: unregister + notify peers + stop the writer.
    deregister(&state, &session).await;
    drop(out_tx);
    let _ = writer.await;
    Ok(())
}

/// Register the connection (RLY-001), enforcing the cap. Returns `false` (after sending a failing
/// `register_ack`) if the relay is full.
async fn register_peer(
    state: &Arc<RelayState>,
    session: &mut Session,
    peer_id: String,
    network_id: String,
    protocol_version: u32,
    out_tx: &mpsc::UnboundedSender<RelayMessage>,
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

/// Hard cap on how many peers a single `GetKnownPeers` (RLY-011) may return, regardless of the
/// client's requested `max`. Bounds the response size (introducer sampling) so one request can't
/// pull the entire registry; a client wanting more pages by reconnecting/re-requesting.
pub const MAX_KNOWN_PEERS: usize = 64;

/// Record a peer's announced candidate addresses (RLY-010 `AnnouncePeer`). Requires a registered
/// session; the announce is scoped to the session's registered id + network (a peer can only
/// announce for itself). An unregistered session gets a NOT_REGISTERED error.
async fn announce_peer(
    state: &Arc<RelayState>,
    session: &Session,
    addrs: Vec<std::net::SocketAddr>,
    out_tx: &mpsc::UnboundedSender<RelayMessage>,
) {
    let (Some(peer_id), Some(network_id)) = (&session.peer_id, &session.network_id) else {
        let _ = out_tx.send(RelayMessage::Error {
            code: errcode::NOT_REGISTERED,
            message: "register before announcing (RLY-001)".to_string(),
        });
        return;
    };
    state
        .registry
        .lock()
        .await
        .announce(peer_id, network_id, addrs);
}

/// Reply with a sampled known-peer list carrying dialable candidate addresses (RLY-011 →
/// RLY-012). Requires a registered session; `network_id` defaults to the session's network and the
/// requested `max` is clamped to [`MAX_KNOWN_PEERS`]. Never returns the requester itself.
async fn get_known_peers(
    state: &Arc<RelayState>,
    session: &Session,
    network_id: Option<String>,
    max: Option<usize>,
    out_tx: &mpsc::UnboundedSender<RelayMessage>,
) {
    let (Some(peer_id), Some(session_net)) = (&session.peer_id, &session.network_id) else {
        let _ = out_tx.send(RelayMessage::Error {
            code: errcode::NOT_REGISTERED,
            message: "register before requesting known peers (RLY-001)".to_string(),
        });
        return;
    };
    let net = network_id.unwrap_or_else(|| session_net.clone());
    let cap = max.unwrap_or(MAX_KNOWN_PEERS).min(MAX_KNOWN_PEERS);
    let peers = state.registry.lock().await.known_peers(peer_id, &net, cap);
    let _ = out_tx.send(RelayMessage::KnownPeers { peers });
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
/// PeerDisconnected).
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
        }
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
    fn announce_peer_dispatch_is_nothing_handled_in_async_path() {
        // Like GetPeers, AnnouncePeer needs a registry WRITE, so the async path intercepts it before
        // dispatch; the pure dispatcher just treats it as a no-op for a registered session.
        let act = dispatch(
            &registered_session(),
            RelayMessage::AnnouncePeer {
                addrs: vec!["203.0.113.1:9444".parse().unwrap()],
            },
        );
        assert!(matches!(act, Action::Nothing));
    }

    #[test]
    fn get_known_peers_dispatch_returns_a_known_peers_sentinel() {
        // The async path intercepts GetKnownPeers for the registry read; the pure dispatcher returns
        // a placeholder KnownPeers so the routing logic stays uniform (mirrors GetPeers).
        let act = dispatch(
            &registered_session(),
            RelayMessage::GetKnownPeers {
                network_id: Some("net1".into()),
                max: Some(8),
            },
        );
        match act {
            Action::ReplyToSelf(msgs) => {
                assert!(matches!(msgs.as_slice(), [RelayMessage::KnownPeers { .. }]));
            }
            other => panic!("expected ReplyToSelf(KnownPeers), got {other:?}"),
        }
    }

    #[test]
    fn announce_and_get_known_peers_are_rejected_before_registration() {
        let s = Session::default();
        for msg in [
            RelayMessage::AnnouncePeer {
                addrs: vec!["203.0.113.1:9444".parse().unwrap()],
            },
            RelayMessage::GetKnownPeers {
                network_id: None,
                max: None,
            },
        ] {
            match dispatch(&s, msg) {
                Action::Error { code, .. } => assert_eq!(code, errcode::NOT_REGISTERED),
                other => panic!("expected NOT_REGISTERED, got {other:?}"),
            }
        }
    }

    #[test]
    fn known_peers_message_received_from_a_client_is_ignored() {
        // KnownPeers is a server→client message; a well-behaved client never sends it to us.
        let act = dispatch(
            &registered_session(),
            RelayMessage::KnownPeers { peers: vec![] },
        );
        assert!(matches!(act, Action::Nothing));
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

        let ok = register_peer(&state, &mut session, "p".into(), "net".into(), 1, &tx).await;
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
        let ok = register_peer(&state, &mut session, "second".into(), "net".into(), 1, &tx).await;
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
        assert!(register_peer(&state, &mut s1, "p".into(), "net".into(), 1, &tx1).await);
        assert_eq!(state.connected.load(Ordering::Relaxed), 1);

        let (tx2, mut rx2) = mpsc::unbounded_channel();
        let mut s2 = Session::default();
        assert!(register_peer(&state, &mut s2, "p".into(), "net".into(), 1, &tx2).await);
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
    async fn announce_peer_stores_addrs_and_get_known_peers_returns_them() {
        // A registers + announces; B (registered) requests known peers and sees A with its addrs.
        let state = RelayState::new(RelayServerConfig::default());
        let (atx, _arx) = mpsc::unbounded_channel();
        let (btx, mut brx) = mpsc::unbounded_channel();
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
            btx.clone(),
        );

        let a_session = Session {
            peer_id: Some("a".into()),
            network_id: Some("net".into()),
        };
        let addr: std::net::SocketAddr = "203.0.113.9:9444".parse().unwrap();
        announce_peer(&state, &a_session, vec![addr], &btx).await;

        let b_session = Session {
            peer_id: Some("b".into()),
            network_id: Some("net".into()),
        };
        get_known_peers(&state, &b_session, None, None, &btx).await;

        match drain(&mut brx).as_slice() {
            [RelayMessage::KnownPeers { peers }] => {
                assert_eq!(peers.len(), 1, "b sees a, not itself");
                assert_eq!(peers[0].peer_id, "a");
                assert_eq!(
                    peers[0].addrs,
                    vec![addr],
                    "a's announced addrs are returned"
                );
            }
            other => panic!("expected one KnownPeers reply, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn announce_and_get_known_peers_require_registration() {
        let state = RelayState::new(RelayServerConfig::default());
        let unregistered = Session::default();

        let (tx, mut rx) = mpsc::unbounded_channel();
        announce_peer(&state, &unregistered, vec![], &tx).await;
        assert!(matches!(
            drain(&mut rx)[0],
            RelayMessage::Error {
                code: errcode::NOT_REGISTERED,
                ..
            }
        ));

        let (tx, mut rx) = mpsc::unbounded_channel();
        get_known_peers(&state, &unregistered, None, None, &tx).await;
        assert!(matches!(
            drain(&mut rx)[0],
            RelayMessage::Error {
                code: errcode::NOT_REGISTERED,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn get_known_peers_clamps_max_to_the_hard_cap() {
        // Requesting more than MAX_KNOWN_PEERS is clamped; register cap+5 peers and ask for a huge max.
        let state = RelayState::new(RelayServerConfig::default());
        for i in 0..(MAX_KNOWN_PEERS + 5) {
            let (tx, _rx) = mpsc::unbounded_channel();
            let id = format!("peer{i:03}");
            state.registry.lock().await.register(
                id.clone(),
                "net".into(),
                RelayPeerInfo::new(id, "net".into(), 1),
                tx,
            );
        }
        let (rtx, _rrx) = mpsc::unbounded_channel();
        state.registry.lock().await.register(
            "req".into(),
            "net".into(),
            RelayPeerInfo::new("req".into(), "net".into(), 1),
            rtx.clone(),
        );
        let req_session = Session {
            peer_id: Some("req".into()),
            network_id: Some("net".into()),
        };
        let (tx, mut rx) = mpsc::unbounded_channel();
        get_known_peers(&state, &req_session, None, Some(10_000), &tx).await;
        match drain(&mut rx).as_slice() {
            [RelayMessage::KnownPeers { peers }] => {
                assert_eq!(peers.len(), MAX_KNOWN_PEERS, "clamped to the hard cap");
            }
            other => panic!("expected KnownPeers, got {other:?}"),
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
}
