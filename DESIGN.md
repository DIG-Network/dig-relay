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
  (`relay_service.rs`: reconnect/backoff, the RLY-007 hole-punch state machine, and direct-first
  transport selection) — but **no server**. There is no code anywhere that *accepts* a `Register`,
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

## What the server does (RLY-001..RLY-008)

`dig-relay` is a stateful WebSocket connection broker. Per the `RelayMessage` contract (RLY-001..
RLY-007, as pinned by the DIG node peer-network protocol) plus the purely-additive **RLY-008** PEX
binding (defined in `dig-pex`'s `SPEC.md` §10.2, and detailed below):

| Concern | Messages | Server behaviour |
|---|---|---|
| **Reservation / registration** (RLY-001) | `Register` → `RegisterAck` | A node connects over WebSocket and registers its `peer_id` + `network_id` + `protocol_version`. The relay records it in the in-memory registry and replies with `RegisterAck { success, message, connected_peers }`. A `network_id` mismatch is rejected. This *reservation* keeps the NAT'd node reachable: it holds a constant connection so the relay can push traffic to it. |
| **Targeted relayed transport** (RLY-002) | `RelayGossipMessage { from, to, payload, seq }` | Forward the payload to the single registered peer `to` (same `network_id`). The fallback path when a direct dial to `to` failed. |
| **Broadcast** (RLY-003) | `Broadcast { from, payload, exclude }` | Fan-out the payload to every registered peer in the sender's `network_id` except `from` and any in `exclude`. |
| **Introducer / peer discovery** (RLY-005) | `GetPeers { network_id }` → `Peers { peers }` | The relay's **introducer** role: return the relay's current registered-peer list (optionally filtered by `network_id`) so a node can discover peers to hole-punch toward. Registration (RLY-001) *is* the introducer advertisement; while registered, a node also receives `PeerConnected` / `PeerDisconnected` for same-network peers so its view stays fresh without polling. |
| **Keepalive** (RLY-006) | `Ping`/`Pong` | Bidirectional liveness. The relay reaps connections idle past a timeout so the registry stays accurate. |
| **NAT traversal coordination** (RLY-007) | `HolePunchRequest { peer_id, target_peer_id, external_addr }` → `HolePunchCoordinate { peer_id, external_addr }` (to the target) → `HolePunchResult` | The relay is the rendezvous point that exchanges each side's externally-observed (STUN-derived) reflexive address so both nodes can attempt a **simultaneous open** (UDP/TCP hole punch). On success the nodes migrate to a direct connection and stop relaying; the relay is fallback, not the steady state. |
| **Peer Exchange** (RLY-008) | `pex_handshake` / `pex_snapshot` / `pex_delta` / `pex_error` | The introducer's **PEX** binding (see the dedicated section below). After registration a PEX-capable node sends `pex_handshake`; the relay then pushes a snapshot of the OTHER same-network registrants and periodic add/drop deltas as registrations come and go. Purely additive — a node that never handshakes sees exactly RLY-001..RLY-007. |
| **Errors** | `Error { code, message }` | Stable error envelope for protocol violations (codes 1–4: `NOT_REGISTERED`, `BAD_MESSAGE`, `PEER_NOT_FOUND`, `CAPACITY`). PEX-level errors use the separate `pex_error` envelope (the PEX §4.5 code table), keeping the RLY code space intact. |

The hole-punch *state machine* (waiting → connecting → succeeded/failed, 300 s retry) and the
**reconnect/backoff** + **transport selection** (direct-first, relay-fallback, `prefer_relay`
override) all live on the **client** in `dig-gossip` (`relay_service.rs`); the relay's job is purely
to be the always-on public coordinator.

## Two NAT-traversal tiers: signalling (preferred) vs. relayed transport (fallback)

The relay offers two **clearly separated** NAT-traversal capabilities, and a client tries the
low-bandwidth one first (matching the peer-network protocol's "four relay roles" — STUN + introducer
+ hole-punch signalling are low-bandwidth control; only relayed transport carries data):

1. **Hole-punch SIGNALLING (preferred, low bandwidth).** Two NAT'd peers use the relay ONLY to
   discover each other via the introducer (RLY-005 `GetPeers` → `Peers`) and to coordinate a
   simultaneous open (RLY-007 `HolePunchRequest` → `HolePunchCoordinate`), each side supplying its
   STUN-derived reflexive `external_addr`. The relay brokers the candidate exchange + the "punch now"
   rendezvous, then the peers connect **directly** — the relay carries **none** of their subsequent
   application data. Only the small coordination messages pass through it (the `HolePunch*` dispatch),
   and it never touches the data-forwarding path.
2. **Full relayed transport (TURN-like, last resort, high bandwidth).** The relay proxies ALL data
   for the peer pair (RLY-002 `RelayGossipMessage` / RLY-003 `Broadcast`). This is a **distinct**
   message set + code path (`forward_to` / `broadcast`), used only AFTER a hole punch fails. Because
   it consumes relay bandwidth, it is the fallback, not the steady state.

`tests/holepunch_signaling.rs` pins this separation: two mock peers discover each other + get a
coordinated punch trigger via the signalling path while asserting the relay proxies no data, and a
separate test exercises the data-relay path as the distinct fallback.

## Peer Exchange (PEX) — the introducer binding (RLY-008)

The relay's introducer role also speaks the **DIG Peer Exchange protocol (PEX)** toward registered
nodes. Where RLY-005 (`GetPeers` → `Peers`) is a *pull* the node polls, PEX is a *push*: after a node
opts in, the relay proactively streams it a warm snapshot of the network's other registrants and then
only the incremental changes, so a node's address book stays current without polling. PEX is defined
normatively in the `dig-pex` crate (its `SPEC.md`); the relay embeds `dig-pex`'s transport-agnostic,
sans-IO `PexEngine` and is a thin I/O adapter over it (`src/pex.rs`). The wire designation is
**RLY-008**.

**Purely additive to RLY-001..RLY-007.** PEX rides the *same* `type`-tagged JSON WebSocket. The four
PEX `type` tags (`pex_handshake`, `pex_snapshot`, `pex_delta`, `pex_error`) all begin with `pex_` and
none collides with an RLY-001..RLY-007 tag, so no existing relay message changes shape or meaning. On
this binding a PEX message is one WebSocket **text** frame carrying the bare JSON object
(`PexMessage::to_json` / `PexMessage::from_json`) — *not* the node↔node u32-length-prefixed byte
framing. A frame's `type` is peeked before the RLY parse so a PEX frame never trips the RLY
`BAD_MESSAGE` path and a legacy RLY frame never enters the PEX path. `tests/wire_conformance.rs` pins
both the frozen PEX shapes and the tag non-collision.

**Capability gate.** The relay MUST NOT send any PEX to a connection that has not sent
`pex_handshake` — a legacy node that never handshakes sees the wire exactly as RLY-001..RLY-007. A PEX
frame from a connection that has not completed RLY-001 registration is answered with the relay's own
`error` envelope code `1` (`NOT_REGISTERED`), consistent with every other pre-registration message. On
the node's first `pex_handshake` the relay brings PEX up for that link and replies with its own
`pex_handshake` followed by a `pex_snapshot` of the OTHER same-network registrants (never the node
itself).

**Registry mirroring.** The relay MIRRORS its RLY-001 registry into the PEX engine: on register, the
registrant becomes a first-hand, advertisable entry (`via: introducer`, the relay-observed
**reflexive** source address of its WebSocket, and the `relay-only` flag — the relay never learns a
node's direct inbound listener from a `Register`, which carries no address); on
unregister/disconnect/idle-timeout it is removed (surfacing as a `dropped` delta to the links that
were told it). Registration **is** the relay's first-hand evidence; `last_seen` is the registrant's
relay-connection liveness. Mirroring happens for *every* registration, so even a legacy non-PEX node
is advertised to the PEX subscribers that must learn about it.

**Introducer-only (no gossip amplification).** A node's `pex_handshake` is a capability signal; a node
SHOULD NOT send PEX data messages to the relay, and the relay **MUST NOT** fold node-sent PEX entries
into its introducer set (a PEX hint must never impersonate a registration). Inbound node data messages
are still fed to the engine so the relay enforces the anti-flood rate floor / caps against a chatty
node, but the resulting candidate/dropped events are **discarded** — only advisory `pex_error` replies
flow back. The relay's advertise set is therefore *exactly* its live registrations, nothing more.

**Scoping & timing.** All PEX is scoped to the node's registered `network_id`, structurally enforced
by keeping **one `PexEngine` per network** (an engine only ever knows that one network's registrants).
A background housekeeping task drives `PexEngine::tick` on a ~1 s cadence; the engine spaces each
link's own `pex_delta`s by its effective interval (≥ 30 s, jittered) and routes each due delta to the
matching connection's PEX channel. The per-connection writer merges the PEX channel with the existing
RLY outbound channel onto the one socket, so the registry and the RLY-001..007 wire are byte-for-byte
unchanged.

> **Change-impact.** The PEX message shapes and the RLY-008 binding rules are normative in `dig-pex`
> (`SPEC.md`). A change to either must be mirrored across `dig-pex`, this relay, and `dig-node`'s PEX
> client in the same unit of work, and the docs.dig.net peer-network page updated to list RLY-008.

## STUN (RFC 5389) — learning the reflexive address

Before a node can announce a *useful* candidate for hole-punching or the introducer, it must know the
public `IP:port` the outside world sees for it (its **server-reflexive** address). `dig-relay`
answers classic STUN Binding Requests on a dedicated **UDP** port (default `0.0.0.0:3478` = the
IANA-assigned STUN port, `--stun-listen`): a node sends a Binding Request and the relay replies with
a Binding Success Response carrying an **XOR-MAPPED-ADDRESS** attribute — the source address it
observed. The implementation (`src/stun.rs`) is a minimal, correct RFC 5389 responder (magic cookie
`0x2112A442`, 96-bit transaction id echo, XOR-MAPPED-ADDRESS for IPv4 + IPv6); it answers only the
Binding Request and silently ignores anything that is not a well-formed one (a STUN server must never
reply to a non-STUN packet). STUN is stateless, so it needs none of the relay's connection state.

> **Alignment note.** The DIG node peer-network protocol page
> (`docs.dig.net/docs/protocol/peer-network.md`, the normative spec) is the authoritative contract,
> and this server conforms to it exactly:
> - **STUN** is served on the IANA port **3478** (matching `relay.dig.net:3478`), RFC 5389 Binding,
>   XOR-MAPPED-ADDRESS — the spec's STUN role. (dig-gossip itself has no STUN client yet; any
>   conformant STUN client — including the one `dig-nat` is built to — works.)
> - **The relay wire is RLY-001..RLY-007 plus the purely-additive RLY-008 PEX binding** — no other
>   message types. The relay's **introducer** role is RLY-005 (`GetPeers` → `Peers` of address-less
>   `RelayPeerInfo`) + the RLY-001 registration-as-advertisement + the RLY-008 PEX push (which does
>   carry address-bearing entries: the registrant's relay-observed reflexive address, `via:
>   introducer`). The address-carrying candidate `PeerRecord`
>   (`{ peer_id, addresses:[{host,port,kind}], network_id, last_seen, via }`) also belongs to the node
>   **RPC** layer (`dig.getPeers` / `dig.announce`), a node-side surface distinct from the relay wire.
> - **Hole-punch signalling vs. relayed transport** are two distinct roles/code paths, with signalling
>   preferred — matching the spec's "four relay roles" and the NAT-traversal ladder's strategy (e)
>   before (f). Candidate reflexive addresses travel as the `external_addr` of the `HolePunch*` trio.
> - **`peer_id`** is the hex SHA-256 of the TLS SPKI DER — matching the spec + dig-gossip
>   `types/peer.rs`.
>
> The dedicated binary introducer in dig-gossip (opcodes 63/64/218/219) remains a **separate**
> transport from this JSON-over-WebSocket relay wire.

## Operational surface

- **Listen address/port:** configurable (`--listen`, default `0.0.0.0:9450` =
  `dig_gossip` `DEFAULT_RELAY_PORT`). The relay endpoint clients use is `wss://relay.dig.net:9450`.
- **Limits:** configurable max concurrent connections and max reservations (so a single relay can be
  sized to its instance), and a per-connection keepalive/idle timeout.
- **Health:** an HTTP **`/health`** endpoint (separate small HTTP listener, default
  `0.0.0.0:9451` / `--health-listen`) returning `200` + a tiny JSON `{status, connected_peers,
  uptime_secs, version}` for the AWS load balancer's target-group health check. Raw TCP/UDP for the
  relay WebSocket goes through an NLB; the health check is the only HTTP surface.
- **STUN:** an RFC 5389 Binding responder on a dedicated **UDP** listener (default `0.0.0.0:3478`,
  the IANA STUN port / `--stun-listen`) so a NAT'd node can learn its reflexive `IP:port`. UDP, so it
  never collides with the TCP WebSocket/health listeners; behind the NLB it is a distinct UDP target
  group.
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
  main.rs        # CLI (clap): --listen / --health-listen / --stun-listen / limits / --json; starts the server
  lib.rs         # public surface; re-exports; binds the relay + health + STUN listeners
  registry.rs    # in-memory peer registry (register/unregister/lookup/list, per network_id)
  server.rs      # WebSocket accept loop + per-connection task; RelayMessage dispatch (RLY-001..007) + PEX (RLY-008) routing + housekeeping tick
  pex.rs         # RLY-008 introducer PEX binding: embeds dig-pex's PexEngine (registry mirroring, per-network scoping, introducer-only discard)
  stun.rs        # RFC 5389 STUN Binding responder (UDP) — reflexive-address discovery
  health.rs      # /health HTTP endpoint for the load balancer
  config.rs      # RelayServerConfig (listen addrs incl. stun_listen, limits, timeouts) — pure, unit-tested
Dockerfile       # public container image (app only; deploy wiring is private/superproject)
```

The pure logic (registry, config, message-routing decisions) is unit-tested; an integration test
drives two simulated peers whose **direct path is blocked** and asserts they exchange a message
**through** the relay (registration → targeted forward → delivery), proving the fallback path.
