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
