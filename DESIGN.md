# dig-relay — Design

`dig-relay` is the **publicly-reachable rendezvous + circuit-relay server** for the DIG Network L2
peer-to-peer layer. It lets DIG Nodes behind NAT discover each other, coordinate hole-punching, and —
when a direct path cannot be established — exchange gossip traffic **through** the relay as a fallback.

The canonical deployment is `relay.dig.net`. A node may also run its own relay (installable via the
DIG installer). The AWS deployment of `relay.dig.net` is maintained privately and is **not** part of
this repository.

## The design question: which wire does the relay speak?

A relay is only useful if it speaks the **exact wire the nodes already speak**. So the first task was
to find the DIG node's existing peer/transport stack. There are **two distinct networks** in the DIG
ecosystem, and they must not be conflated:

1. **The content network** — `digstore`'s `dig-node` crate, the §21 remote protocol, and
   `rpc.dig.net`. This is a **hub-and-spoke HTTP/JSON-RPC** system (axum server + reqwest client over
   rustls): a node reads/serves content by talking to a public host over **outbound HTTPS**, which
   already traverses NAT with no relay needed. There is **no node↔node dialing** here, and no
   `libp2p` anywhere in the `digstore` tree (verified against `Cargo.lock`). This network does **not**
   need a NAT-traversal relay.

2. **The L2 blockchain network** — the `dig-gossip` crate (`DIG-Network/dig-gossip`), the peer-to-peer
   gossip/consensus layer for the DIG L2 chain. This is a **mesh** of nodes that must connect to each
   other: blocks, transactions, peer exchange. This is where NAT traversal matters — two NAT'd full
   nodes cannot always dial one another — and **this is the network the relay serves.**

`dig-gossip` uses the **Chia peer protocol**, not libp2p:

- **Transport:** TLS WebSocket peers (`tokio-tungstenite` + `chia-sdk-client`'s `Peer`), default P2P
  port **9444**.
- **Identity:** a `PeerId` = `SHA256(TLS SubjectPublicKeyInfo DER)` (no libp2p `PeerId`/`Multiaddr`).
- **Discovery:** DNS seeds + a Chia-style **introducer** (opcodes 63/64, `RequestPeersIntroducer` /
  `RespondPeersIntroducer`) + a Bitcoin-`CAddrMan`-shaped address manager.
- **Relay fallback:** an already-specified **`RelayMessage` protocol** (JSON over WebSocket, default
  port **9450**) with a full client + state machines already implemented in `dig-gossip`.

### Decision: align to the existing `dig-gossip` relay protocol — NOT libp2p

The task brief suggested "strongly consider libp2p (circuit-relay-v2 + identify + autonat + dcutr)".
We deliberately **do not** use libp2p, because the protocol-grade fit is already defined and the
ecosystem already speaks it:

- `dig-gossip` ships `src/relay/relay_types.rs` — the canonical `RelayMessage` enum (requirements
  **RLY-001..RLY-007**): `Register`/`RegisterAck`, `RelayGossipMessage` (targeted forward),
  `Broadcast` (fan-out), `GetPeers`/`Peers`, `Ping`/`Pong`, and the NAT-traversal trio
  `HolePunchRequest`/`HolePunchCoordinate`/`HolePunchResult`. The wire is **JSON over WebSocket**.
- `dig-gossip` ships the **client** side (`relay_client.rs`) and the client **state machines**
  (`relay_service.rs`: reconnect/backoff per RLY-004, hole-punch state machine per RLY-007, transport
  selection per RLY-008) — but **no server**. There is no code anywhere that *accepts* a `Register`,
  answers `RegisterAck`, forwards a `RelayGossipMessage`, fans out a `Broadcast`, or coordinates a
  hole punch.
- That **server is exactly what `dig-relay` is.**

Adopting libp2p would introduce a *second*, incompatible peer/identity/transport stack that no DIG
node speaks, plus a large dependency tree — for zero benefit over the protocol that already exists.
libp2p's circuit-relay-v2 / dcutr / autonat map one-to-one onto the DIG `RelayMessage` primitives we
already have (relayed forward = `RelayGossipMessage`/`Broadcast`; hole-punch coordination =
`HolePunch*`; reservation = `Register`/`RegisterAck`), so re-implementing them in libp2p's framing
would only break compatibility.

### Drift-proofing: vendor the wire types, lock them with a conformance test

The canonical relay wire is defined in `dig-gossip` (`src/relay/relay_types.rs`). `dig-relay`
**vendors a byte-identical copy** of `RelayMessage` + `RelayPeerInfo` into `src/wire.rs` rather than
depending on the `dig-gossip` crate, because:

- the wire types depend only on `serde` + `std` (no transport, no Chia stack), so vendoring is tiny
  and self-contained — whereas depending on the `dig-gossip` crate would pull the entire L2
  gossip/consensus/TLS dependency tree (`chia-sdk-client`, `tokio-tungstenite` w/ `native-tls`, …)
  just to re-export two `serde` structs; and
- the published `dig-gossip` tag does not currently build against the `dig-protocol` version it
  resolves, so depending on it would break `dig-relay`'s own build.

This mirrors the ecosystem's existing vendoring pattern (e.g. `dig-sdk` vendors the `dig_client`
WASM with a provenance note). The vendored types carry a provenance header, and
`tests/wire_conformance.rs` **freezes the serde shape** (exact `type` discriminators + field names),
so an accidental rename fails CI loudly. The superproject `SYSTEM.md` records the change-impact edge:
a change to the relay wire in `dig-gossip` must be mirrored in `dig-relay/src/wire.rs` in the same
unit of work.

## What the server does (RLY-001..RLY-007)

`dig-relay` is a stateful WebSocket connection broker. Per the `RelayMessage` contract:

| Concern | Messages | Server behaviour |
|---|---|---|
| **Reservation / registration** (RLY-001) | `Register` → `RegisterAck` | A node connects over WebSocket and registers its `peer_id` + `network_id` + `protocol_version`. The relay records it in the in-memory registry and replies with `RegisterAck { success, message, connected_peers }`. A `network_id` mismatch is rejected. This *reservation* keeps the NAT'd node reachable: it holds a constant connection so the relay can push traffic to it. |
| **Targeted relayed transport** (RLY-002) | `RelayGossipMessage { from, to, payload, seq }` | Forward the payload to the single registered peer `to` (same `network_id`). The fallback path when a direct dial to `to` failed. |
| **Broadcast** (RLY-003) | `Broadcast { from, payload, exclude }` | Fan-out the payload to every registered peer in the sender's `network_id` except `from` and any in `exclude`. |
| **Peer discovery / rendezvous** (RLY-005) | `GetPeers { network_id }` → `Peers { peers }` | Return the relay's current registered-peer list (optionally filtered by `network_id`) so a node can discover candidates to dial directly or hole-punch toward. Also push `PeerConnected` / `PeerDisconnected` notifications. |
| **Keepalive** (RLY-006) | `Ping`/`Pong` | Bidirectional liveness. The relay reaps connections idle past a timeout so the registry stays accurate. |
| **NAT traversal coordination** (RLY-007) | `HolePunchRequest { peer_id, target_peer_id, external_addr }` → `HolePunchCoordinate { peer_id, external_addr }` (to the target) → `HolePunchResult` | The relay is the rendezvous point that exchanges each side's externally-observed address so both nodes can attempt a **simultaneous open** (UDP/TCP hole punch). On success the nodes migrate to a direct connection and stop relaying; the relay is fallback, not the steady state. |
| **Errors** | `Error { code, message }` | Stable error envelope for protocol violations. |

The hole-punch *state machine* (waiting → connecting → succeeded/failed, 300 s retry) and the
**reconnect/backoff** + **transport selection** (direct-first, relay-fallback, `prefer_relay`
override) all live on the **client** in `dig-gossip` (`relay_service.rs`); the relay's job is purely
to be the always-on public coordinator.

## Operational surface

- **Listen address/port:** configurable (`--listen`, default `0.0.0.0:9450` =
  `dig_gossip` `DEFAULT_RELAY_PORT`). The relay endpoint clients use is `wss://relay.dig.net:9450`.
- **Limits:** configurable max concurrent connections and max reservations (so a single relay can be
  sized to its instance), and a per-connection keepalive/idle timeout.
- **Health:** an HTTP **`/health`** endpoint (separate small HTTP listener, default
  `0.0.0.0:9451` / `--health-listen`) returning `200` + a tiny JSON `{status, connected_peers,
  uptime_secs, version}` for the AWS load balancer's target-group health check. Raw TCP/UDP for the
  relay WebSocket goes through an NLB; the health check is the only HTTP surface.
- **Agent-friendly:** `--help`, a `--health`-style JSON status, stable `RelayMessage` JSON wire,
  catalogued `Error` codes, and structured `tracing` logs.

## TLS

The relay WebSocket is `wss://` in production, but TLS is **terminated at the AWS load balancer**
(ACM cert on the NLB/ALB) so the container speaks plain `ws://` internally — the smallest, cheapest
container. For run-your-own-relay without a load balancer, a future flag can enable in-process rustls
(out of scope for the first server; documented as a follow-up). The `RelayMessage` payloads carry
gossip data that is itself authenticated end-to-end by the gossip layer (peers verify each other via
the Chia TLS-SPKI `PeerId` and the consensus BLS keys), so the relay is an **untrusted forwarder** — it
never needs to inspect or trust payloads, only route them by `peer_id`.

## Why this is cheap + scalable on AWS

The relay is **stateless across instances** at the protocol level: each connection's reservation lives
only on the instance holding that WebSocket. A node keeps **one** long-lived connection to **one**
relay; horizontal scale = more relay instances behind an NLB, each holding a slice of connections.
Memory per connection is tiny (a `RelayPeerInfo` + a WebSocket). This makes the smallest always-on
instance (autoscaling min=1) sufficient for launch, scaling out only when connection count climbs.
The private AWS infra (Elastic Beanstalk single-container Docker or a small Fargate service behind an
NLB, `relay.dig.net` via Route53 + ACM) is documented in the superproject `infra/dig-relay/` and
`runbooks/dig-relay.md`, not here.

## Repository layout

```
src/
  main.rs        # CLI (clap): --listen / --health-listen / limits / --json; starts the server
  lib.rs         # public surface; re-exports
  registry.rs    # in-memory peer registry (register/unregister/lookup/list, per network_id)
  server.rs      # WebSocket accept loop + per-connection task; RelayMessage dispatch
  health.rs      # /health HTTP endpoint for the load balancer
  config.rs      # RelayServerConfig (listen addrs, limits, timeouts) — pure, unit-tested
Dockerfile       # public container image (app only; deploy wiring is private/superproject)
```

The pure logic (registry, config, message-routing decisions) is unit-tested; an integration test
drives two simulated peers whose **direct path is blocked** and asserts they exchange a message
**through** the relay (registration → targeted forward → delivery), proving the fallback path.
