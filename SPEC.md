# dig-relay — SPEC

Normative specification of what `dig-relay` implements: the wire it serves, its listener/binding
behavior, its state machine, and its operational contract. This is the authoritative contract an
independent reimplementation of the relay SERVER could be built against. For the design rationale
(why this wire, why not libp2p, why vendoring) see `DESIGN.md`; this document states only what IS.

## 1. Role

`dig-relay` is the publicly-reachable rendezvous + circuit-relay SERVER for the DIG Network L2
peer-to-peer (gossip) layer. It lets DIG Nodes behind NAT register a reachable reservation, discover
other same-network peers, coordinate NAT hole-punching, and — when a direct path cannot be
established — exchange gossip traffic THROUGH the relay as a bandwidth fallback. The canonical
deployment is `relay.dig.net`; an operator may also run a private relay via the `install`/`start`
service subcommands (`SERVICE_LABEL = net.dignetwork.dig-relay`).

## 2. Listeners

The relay exposes exactly three listeners, each independently configurable and independently
bindable:

| Listener | Transport | Default address | Config field / CLI flag | Purpose |
|---|---|---|---|---|
| Relay WebSocket | TCP | `[::]:9450` | `listen` / `--listen` | `RelayMessage`/PEX wire (§3) |
| Health | TCP (HTTP) | `[::]:9451` | `health_listen` / `--health-listen` | Load-balancer target-group check |
| STUN | UDP | `[::]:3478` | `stun_listen` / `--stun-listen` | RFC 5389 Binding responder |

Port 9450 matches `dig_gossip::constants::DEFAULT_RELAY_PORT`. Port 3478 is the IANA-assigned STUN
port. The health port is kept off the relay/STUN ports so an NLB's HTTP health probe can never
collide with relay or STUN traffic.

### 2.1 Listener binding — IPv6-first, IPv4-fallback (normative)

Every listener's default bind address MUST be the IPv6 unspecified address `[::]`
(`Ipv6Addr::UNSPECIFIED`), never the IPv4 wildcard `0.0.0.0`, per the DIG ecosystem's IPv6-first
peer-communication rule.

A default `[::]` bind MUST be **dual-stack**: the implementation binds the socket with
`IPV6_V6ONLY` explicitly cleared (`false`) before the socket starts listening/receiving, so the one
`[::]` socket accepts BOTH:

- native IPv6 connections/datagrams, and
- IPv4 connections/datagrams (arriving as IPv4-mapped IPv6 addresses, `::ffff:a.b.c.d`).

This is strictly additive to reachability: an IPv4-only DIG Node continues to reach the relay on the
exact same port with no client-side change. `RelayPeerInfo`'s observed reflexive/source address, and
the STUN `XOR-MAPPED-ADDRESS` response, reflect whichever family the peer actually connected with
(IPv4-mapped addresses are exposed in their canonical IPv4 form where the platform supports it).

An operator-supplied bind address that is explicitly IPv4 (e.g. `--listen 0.0.0.0:9450` or a
specific IPv4 host) is honored verbatim as an IPv4-only bind — `IPV6_V6ONLY` handling only applies
when the configured address is IPv6. A non-unspecified address (a specific host, IPv4 or IPv6) is
also bound verbatim with no family coercion.

Reference implementation: `src/config.rs` (defaults) + `src/net.rs` (`bind_tcp_dual_stack`,
`bind_udp_dual_stack` — the shared dual-stack bind helper every listener binds through).

### 2.2 Same-host status probing

The `status` operation (CLI `dig-relay status`, or `service::status`) probes the health listener
over loopback rather than the configured bind address (which may be unspecified and therefore not a
connectable destination). The probe target is derived from the configured `health_listen`:

- if `health_listen` is a **specific** address, it is probed as-is;
- if `health_listen` is **unspecified**, it is rewritten to the loopback address of the **same
  address family**: `[::]` → `::1`, `0.0.0.0` → `127.0.0.1`.

Same-family loopback (not an automatic fallback to `127.0.0.1` for an IPv6 bind) is required because
IPv4-mapped loopback is not universally supported by every OS/network stack.

Reference: `src/service.rs::loopback_probe_addr` (pure) + `probe_health` (the I/O wrapper).

## 3. Wire protocol

The relay implements the SERVER side of the `RelayMessage` wire (JSON, one message per WebSocket
text frame), canonically defined in `dig-gossip`'s `relay/relay_types.rs` and vendored
byte-identically into `src/wire.rs` (pinned by `tests/wire_conformance.rs`). Message kinds:

| Requirement | Messages | Behavior |
|---|---|---|
| RLY-001 Registration | `Register` → `RegisterAck` | Registers `peer_id` + `network_id` + `protocol_version` in the in-memory registry; rejects a `network_id` mismatch; `RegisterAck{success, message, connected_peers}`. Holding this connection open is the node's reachability reservation. |
| RLY-002 Targeted forward | `RelayGossipMessage{from,to,payload,seq}` | Forwards `payload` to the single registered peer `to` in the sender's network. |
| RLY-003 Broadcast | `Broadcast{from,payload,exclude}` | Fans `payload` out to every registered peer in the sender's network except `from` and any peer in `exclude`. |
| RLY-005 Introducer | `GetPeers{network_id}` → `Peers{peers}` | Returns the relay's registered-peer list for a network; while registered, a node additionally receives `PeerConnected`/`PeerDisconnected` pushes for same-network peers. |
| RLY-006 Keepalive | `Ping`/`Pong` | Bidirectional liveness; an idle connection past `idle_timeout` is reaped. |
| RLY-007 Hole-punch coordination | `HolePunchRequest{peer_id,target_peer_id,external_addr}` → `HolePunchCoordinate{peer_id,external_addr}` (to target) → `HolePunchResult` | Exchanges each side's STUN-derived reflexive address so both peers can attempt a simultaneous-open hole punch; the relay carries no application data for this path. |
| RLY-008 Peer Exchange (PEX) | `pex_handshake` / `pex_snapshot` / `pex_delta` / `pex_error` | Purely additive introducer PUSH binding (§4). |
| Errors | `Error{code,message}` | Stable envelope: `1=NOT_REGISTERED`, `2=BAD_MESSAGE`, `3=PEER_NOT_FOUND`, `4=CAPACITY`. |

A message before RLY-001 registration (other than `Register` itself) is answered with
`Error{code:1}`. Full message shapes are frozen by `tests/wire_conformance.rs`; a shape change here
requires a matching change in `dig-gossip` in the same unit of work (see `SYSTEM.md`).

### 3.1 Two NAT-traversal tiers

1. **Hole-punch signalling (preferred).** RLY-005 discovery + RLY-007 coordination only. The relay
   never proxies application data on this path — only small coordination messages.
2. **Relayed transport (fallback, TURN-like).** RLY-002/RLY-003. Used only when a direct connection
   cannot be established; consumes relay bandwidth per byte forwarded.

## 4. Peer Exchange (RLY-008)

The relay's introducer role also speaks the DIG Peer Exchange protocol (PEX), normatively defined in
`dig-pex`'s `SPEC.md`. The relay embeds `dig-pex`'s transport-agnostic `PexEngine` (`src/pex.rs`) as
a thin I/O adapter.

- **Additive framing.** PEX frames ride the same JSON-over-WebSocket connection as RLY-001..007,
  distinguished by a `pex_`-prefixed `type` tag (disjoint from every RLY tag). A connection that
  never sends `pex_handshake` sees the wire exactly as RLY-001..RLY-007.
- **Capability gate.** The relay MUST NOT push PEX to a connection that has not sent
  `pex_handshake`. A PEX frame before RLY-001 registration gets `Error{code:1}`. The first
  `pex_handshake` after registration brings PEX up for that link; the relay replies with its own
  `pex_handshake` then a `pex_snapshot` of the OTHER same-network registrants (never the sender).
- **Registry mirroring.** Every RLY-001 registration becomes a first-hand PEX entry
  (`via: introducer`, the relay-observed reflexive source address, `relay_only: true`); unregister/
  disconnect/idle-timeout removes it (a `dropped` delta to subscribed links).
- **Introducer-only.** Node-sent PEX candidate/dropped data is fed to the engine for rate-limit
  enforcement only and is NEVER folded into the advertised set — the relay only ever advertises its
  own live registrations.
- **Scoping.** One `PexEngine` per `network_id`; deltas for network A never reach a network-B link.
- **Timing.** A ~1 s housekeeping tick drives `PexEngine::tick`; each link's own `pex_delta`s are
  spaced ≥30 s (jittered) by the engine itself.

## 5. STUN (RFC 5389)

`src/stun.rs` implements a minimal RFC 5389 Binding responder over UDP on `stun_listen` (§2):

- Accepts only a well-formed **Binding Request** (correct magic cookie `0x2112A442`, 20-byte header,
  message-length-consistent attribute region); anything else (malformed, wrong magic cookie, other
  method, truncated, overrunning attribute length) is silently dropped — a STUN server must never
  reply to a non-STUN or malformed datagram.
- A valid Binding Request gets a **Binding Success Response** echoing the 96-bit transaction id and
  carrying an `XOR-MAPPED-ADDRESS` attribute encoding the request's observed source `IP:port` (both
  IPv4 and IPv6 source families are supported; §2.1 makes IPv6-family requests reachable on the same
  dual-stack socket as IPv4 ones).
- Stateless: no per-request state survives past the single reply.
- No authentication, `FINGERPRINT`, `SOFTWARE`, or non-XOR `MAPPED-ADDRESS` — out of scope; every
  modern STUN client reads `XOR-MAPPED-ADDRESS`.

## 6. Health

`GET /health` on `health_listen` (§2) returns `200` with:

```json
{ "status": "ok", "connected_peers": <u64>, "uptime_secs": <u64>, "version": "<CARGO_PKG_VERSION>" }
```

`connected_peers` is the live registry count; `uptime_secs` is wall-clock since process start. This
is the only HTTP surface; it is served on a separate listener so an NLB's HTTP health check can never
collide with the relay WebSocket.

## 7. Configuration

`RelayServerConfig` (`src/config.rs`) is validated pure data:

| Field | Default | Constraint |
|---|---|---|
| `listen` | `[::]:9450` | any `SocketAddr` |
| `health_listen` | `[::]:9451` | any `SocketAddr` |
| `stun_listen` | `[::]:3478` | any `SocketAddr` |
| `max_connections` | 4096 | MUST be ≥ 1 |
| `idle_timeout` | 120 s | MUST be > 0 |

`validate()` rejects `max_connections == 0` and a zero `idle_timeout` with a stable error string.
Config may be built from CLI flags (`main.rs`, `clap`) or environment variables consumed by the
service installer (`DIG_RELAY_LISTEN`, `DIG_RELAY_HEALTH_LISTEN`, `DIG_RELAY_STUN_LISTEN`,
`DIG_RELAY_MAX_CONNECTIONS` — see `src/service.rs::config_from_env`), so an installed OS service
serves identically to a manually-run `dig-relay serve` with the same flags.

## 8. Transport security

The relay speaks plain `ws://`/UDP internally; TLS (`wss://`) is terminated at the load balancer in
the canonical `relay.dig.net` deployment. `RelayMessage` payloads carry gossip data that is itself
authenticated end-to-end by the gossip layer (peers verify each other via the Chia TLS-SPKI
`peer_id` and consensus BLS keys) — the relay is an untrusted forwarder that routes by `peer_id`
without needing to inspect or trust payload contents.

## 9. Operational contract

- Horizontally scalable: relay state is per-instance (a node holds one long-lived connection to one
  relay instance); scaling out adds instances behind a load balancer, not relay-to-relay
  coordination.
- Agent-friendly: `--help`, `--json` on service subcommands, the stable `RelayMessage`/PEX JSON wire,
  catalogued numeric error codes (§3), and structured `tracing` logs.
- OS service (`install`/`uninstall`/`start`/`stop`/`status`): user-level on Linux (systemd) / macOS
  (launchd); system-level only on Windows (SCM), requiring an elevated console for
  install/uninstall. `status` never hard-errors — an unreachable health endpoint is reported as
  `serving: false`, not a process error.

## 10. Conformance

- `tests/wire_conformance.rs` freezes the RLY-001..008 JSON shapes and the PEX/RLY tag
  non-collision — the byte-identical-wire contract with `dig-gossip` and `dig-pex`.
- `tests/holepunch_signaling.rs` proves the two NAT-traversal tiers (§3.1) are genuinely separate
  code paths (no data proxied on the signalling path).
- `tests/relay_fallback.rs` proves the relayed-transport fallback works end-to-end between two
  simulated NAT-blocked peers.
- `tests/stun_e2e.rs` proves the STUN responder end-to-end over a real UDP socket.
- `tests/lifecycle.rs` proves the full connection lifecycle (register → traffic → keepalive →
  disconnect notification) over real WebSocket connections.
- `src/net.rs`'s unit tests prove the dual-stack bind (§2.1): an `[::]`-bound TCP listener/UDP socket
  accepts an IPv4 loopback client/datagram on the same port, and an explicit IPv4 bind is unaffected.

A change to any behavior in this document MUST update this SPEC in the same unit of work.
