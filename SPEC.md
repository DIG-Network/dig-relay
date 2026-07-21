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

The relay exposes exactly four listeners, each independently configurable and independently
bindable:

| Listener | Transport | Default address | Config field / CLI flag | Purpose |
|---|---|---|---|---|
| Relay WebSocket + dashboard | TCP | `[::]:9450` | `listen` / `--listen` | `RelayMessage`/PEX wire (§3) AND the peer-stats dashboard (§6.1) — a WebSocket upgrade is the wire, any other `GET` is the dashboard |
| Health | TCP (HTTP) | `[::]:9451` | `health_listen` / `--health-listen` | Load-balancer target-group check |
| HTTP→HTTPS redirect | TCP (HTTP) | `[::]:80` | `dashboard_listen` / `--dashboard-listen` | 301 every plain-HTTP request to `https://` (§6.1) |
| STUN | UDP | `[::]:3478` | `stun_listen` / `--stun-listen` | RFC 5389 Binding responder |

Port 9450 matches `dig_gossip::constants::DEFAULT_RELAY_PORT`. Port 3478 is the IANA-assigned STUN
port. The relay serves content ONLY over HTTPS/WSS: the dashboard shares the wire listener (TLS is
terminated upstream at the load balancer, so `https://relay.dig.net/` and `wss://relay.dig.net/` both
arrive on the wire port), and port 80 exists solely to redirect plain HTTP to the secure origin.

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

### 2.9 Dialable-address resolution (B1, normative)

On registration the relay observes the peer's reflexive source address (the remote address of its
outbound WebSocket) — a public IP, but an ephemeral NAT source PORT, not the node's inbound gossip
listener. A node therefore advertises its gossip LISTEN candidate(s) in `Register.listen_addrs`
(IPv6-first, §2.1), where the useful part is the PORT (a dual-stack node binds the unspecified host
`[::]`). The relay resolves each advertised candidate into a DIALABLE `RelayPeerInfo.addresses` entry:

- if the advertised host is **not globally routable** (unspecified, loopback, IPv4 private/link-local,
  or IPv6 unique-local `fc00::/7`/link-local `fe80::/10`, including IPv4-mapped forms) → substitute the
  observed reflexive IP and keep the advertised PORT → a real `reflexive_IP:port`;
- if the advertised host is **globally routable**, it is kept verbatim ONLY when it verifiably belongs
  to the peer's own observed source — the advertised IPv4 equals the reflexive IP, or the advertised
  IPv6 shares the reflexive `/64` prefix (one prefix covers a peer's privacy/temporary addresses).
  Otherwise the advertised host is an unverifiable third party (an attacker advertising a victim's
  public address to make the relay fan out connection-attempts at it — a reflection vector): the relay
  **MUST NOT emit that address**. It is dropped and replaced by the safe `reflexive_IP:advertised_port`
  substitution, which can only point back at the registrant's own source. The relay therefore never
  emits a public address that is not tied to the peer's own observed source.

The emitted candidate set is **capped at 8** so one registration cannot make the relay publish an
unbounded address list. Results are ordered IPv6-first (§2.1) via the ecosystem's canonical
`dig_ip::Family` keying — the single source of truth for the address-family judgement shared with
every DIG peer crate, so an IPv4-mapped IPv6 candidate (`::ffff:a.b.c.d`) is ranked as IPv4 — and
de-duplicated. A peer that advertises no
`listen_addrs` (a pre-#924 node)
gets an empty `addresses` list and falls back to identity-only relayed reachability. A dialer treats
each entry as a Direct candidate and races them IPv6-first (happy-eyeballs, §2.1); a bogus candidate
merely fails to connect — the mTLS handshake still binds the dialed endpoint to the expected
`peer_id = SHA-256(TLS SPKI DER)` (§8), so the relay cannot cause a peer to be impersonated.

Reference: `src/dial.rs::resolve_dialable` (pure) + `src/server.rs::register_peer` (population).

## 3. Wire protocol

The relay implements the SERVER side of the `RelayMessage` wire (JSON, one message per WebSocket
text frame), canonically defined in `dig-gossip`'s `relay/relay_types.rs` and vendored
byte-identically into `src/wire.rs` (pinned by `tests/wire_conformance.rs`). Message kinds:

| Requirement | Messages | Behavior |
|---|---|---|
| RLY-001 Registration | `Register{peer_id,network_id,protocol_version,listen_addrs}` → `RegisterAck` | Registers `peer_id` + `network_id` + `protocol_version` in the in-memory registry; rejects a `network_id` mismatch; rejects a `peer_id` already held by a LIVE connection (§3.2); `RegisterAck{success, message, connected_peers}`. Holding this connection open is the node's reachability reservation. `listen_addrs` (optional, additive) advertises the node's gossip LISTEN candidate(s), IPv6-first — the relay uses each candidate's PORT with the observed reflexive source IP to publish dialable `RelayPeerInfo.addresses` (§2.9). An empty/absent `listen_addrs` is a pre-#924 node and yields no resolved addresses. |
| RLY-002 Targeted forward | `RelayGossipMessage{from,to,payload,seq}` | Forwards `payload` to the single registered peer `to` in the sender's network; re-stamps `from` to the registered id (no sender spoofing); refuses a `to` on another network (`PEER_NOT_FOUND`). Bounded per-target outbound queue + oversized-frame rejection cap the relay's memory (§3.2). |
| RLY-003 Broadcast | `Broadcast{from,payload,exclude}` | Fans `payload` out to every registered peer in the sender's network except `from` and any peer in `exclude`. |
| RLY-005 Introducer | `GetPeers{network_id}` → `Peers{peers}` | Returns the relay's registered-peer list for a network; while registered, a node additionally receives `PeerConnected`/`PeerDisconnected` pushes for same-network peers. Each `RelayPeerInfo` carries `addresses` — the relay-resolved dialable candidates (§2.9), IPv6-first — so a querying peer learns a real `IP:port` to direct-dial. |
| RLY-006 Keepalive | `Ping`/`Pong` | Bidirectional liveness; an idle connection past `idle_timeout` is reaped. |
| RLY-007 Hole-punch coordination | `HolePunchRequest{peer_id,target_peer_id,external_addr}` → `HolePunchCoordinate{peer_id,external_addr}` (to target) → `HolePunchResult` | Exchanges each side's STUN-derived reflexive address so both peers can attempt a simultaneous-open hole punch; the relay carries no application data for this path. |
| RLY-008 Peer Exchange (PEX) | `pex_handshake` / `pex_snapshot` / `pex_delta` / `pex_error` | Purely additive introducer PUSH binding (§4). |
| Errors | `Error{code,message}` | Stable envelope: `1=NOT_REGISTERED`, `2=BAD_MESSAGE`, `3=PEER_NOT_FOUND`, `4=CAPACITY`, `5=ID_IN_USE`, `6=IDENTITY_MISMATCH` (§3.2), `7=RATE_LIMITED` (per-source-IP register throttle, §3.0). |

A message before RLY-001 registration (other than `Register` itself) is answered with
`Error{code:1}`. Full message shapes are frozen by `tests/wire_conformance.rs`; a shape change here
requires a matching change in `dig-gossip` in the same unit of work (see `SYSTEM.md`).

### 3.2 Registration identity — peer-ID occupancy + proof-of-possession (normative)

A `peer_id` is the hex `SHA-256(TLS SPKI DER)` of the node's identity key (matching `dig-gossip`).
The relay MUST NOT let a `Register` for a `peer_id` that is **already held by a live connection**
evict that connection: a duplicate-id `Register` while the incumbent's connection is still open is
REFUSED with `RegisterAck{success:false}` + `Error{code:5, ID_IN_USE}`, and the incumbent keeps its
slot and its rendezvous. Only a **stale** registration — one whose connection has already torn down
(its outbound channel is closed) — may be reclaimed by a reconnecting node under the same `peer_id`;
that reclaim replaces the dead record without changing `connected_peers`.

This closes an unauthenticated peer-ID hijack: without it, any client could register a `peer_id`
belonging to a live peer, evict it, and thereafter receive every message routed to that id. It does
NOT by itself prove the registrant owns the identity key `peer_id` commits to — that
proof-of-possession is provided by the OPTIONAL mTLS listener below.

**Proof-of-possession via mTLS (implemented, opt-in).** When the relay is configured with
`tls_cert_path`/`tls_key_path` (§7), it terminates TLS itself on the relay listener (`wss://`
instead of `ws://`) and REQUIRES every connecting client to present a TLS client certificate
(`src/tls.rs`). The relay does not validate a certificate chain — DIG peer certificates are
self-signed and the *public key itself* is the identity, matching `dig-nat`/`dig-gossip`'s
`peer_id = SHA-256(TLS SPKI DER)` model — it only requires a well-formed, parseable X.509 leaf. The
TLS handshake itself is the proof of possession: TLS client authentication requires the client to
cryptographically sign the handshake transcript with the private key matching its certificate, which
rustls verifies during the handshake; a client cannot complete the connection without holding that
key. After the handshake, the relay derives `peer_id` from the certificate the client actually
presented (`extract_client_peer_id`) and REQUIRES the `Register` message's claimed `peer_id` to equal
it — a mismatch is REFUSED with `RegisterAck{success:false}` + `Error{code:6, IDENTITY_MISMATCH}`
before the registry is touched at all (this check runs even before the capacity check, §3.0). A
connection presenting no client certificate never reaches the `RelayMessage` wire — mandatory client
auth fails the TLS handshake itself.

This design requires **no `Register` wire change and no `dig-gossip` coordination**: the proof lives
entirely at the TLS transport layer, and the wire's pre-existing `peer_id` field is simply checked
against the transport identity rather than trusted blindly. `Error` code `6` is a purely-additive
addition to the existing numeric error taxonomy (§3), not a shape change.

**When mTLS is not configured (default).** The relay speaks plain `ws://`, matching the canonical
`relay.dig.net` deployment where TLS is terminated at the load balancer (§8) and the relay process
cannot see a client certificate. On that listener, identity remains unauthenticated at the transport
layer and the live-incumbent refusal above is the only protection; payloads remain end-to-end
authenticated by the gossip layer (§8) regardless. Enabling mTLS end-to-end for the canonical
deployment requires the load balancer to pass TLS through rather than terminate it (an infra change,
tracked separately — see `DESIGN.md` / the superproject's private `infra/dig-relay/`), or running a
private relay (`dig-relay install`/`start`) with `--tls-cert`/`--tls-key` set directly.

### 3.0 Resource bounds (normative)

Every per-connection resource is bounded so a slow, hostile, or never-registering client cannot
exhaust the relay:

- **Bounded outbound queues.** Each connection's RLY and PEX outbound queues are bounded at
  `outbound_queue_capacity` (default 1024). A forward/broadcast/notification to a peer whose queue is
  full is DROPPED (non-blocking `try_send`), never buffered without limit — a peer that stops draining
  its socket can hold at most `outbound_queue_capacity` buffered messages.
- **Bounded inbound message size.** A single inbound WebSocket message or frame larger than
  `max_message_bytes` (default 262144) is rejected at the WebSocket protocol layer before a large
  allocation. All legitimate relay/PEX frames are far smaller.
- **Open-connection cap.** The `max_connections` cap counts OPEN sockets (registered or not), checked
  before the WebSocket handshake, so a flood of connect-but-never-register sockets cannot bypass it.
- **Register timeout.** An accepted connection that has not completed RLY-001 `Register` within
  `register_timeout` (default 10 s) is dropped. This is distinct from — and shorter than — the
  post-register `idle_timeout` (§7), so half-open / never-registering sockets are reaped promptly.

**App-level abuse protection — per-source-IP + per-connection limits (normative, #1386).** The
aggregate bounds above cap the relay as a whole; these add the per-SOURCE dimension so one abusive
source cannot deny service to legitimate peers. Every limit defaults ON; setting any to `0` disables
THAT dimension. Source IPs are keyed by `limits::ip_key`: an IPv4-mapped IPv6 address collapses to its
IPv4 form, IPv4 is keyed on the full /32, and IPv6 is keyed on its **/64 prefix** (so the many
addresses within one delegated /64 share a budget).

- **Per-IP connection cap.** At most `max_connections_per_ip` (default 64) concurrent OPEN connections
  per source IP, checked before the WebSocket handshake beside the global `max_connections` cap; the
  excess is refused (the socket is dropped). MUST be `<= max_connections`.
- **Per-IP registration rate.** RLY-001 `Register` attempts from one source IP are throttled to
  `registrations_per_ip_per_sec` (default 10) per second; an over-rate register is REFUSED with
  `RegisterAck{success:false}` + `Error{code:7, RATE_LIMITED}`.
- **Per-IP concurrent registrations.** At most `max_registrations_per_ip` (default 128) live
  registrations per source IP; the excess is REFUSED with `RegisterAck{success:false}` +
  `Error{code:7, RATE_LIMITED}`.
- **Per-connection message + byte rate.** A connection exceeding `messages_per_conn_per_sec`
  (default 256) inbound frames/sec, `bytes_per_conn_per_sec` (default 1048576) inbound bytes/sec, or
  a cumulative `max_relayed_bytes_per_conn` (default 1073741824) over its lifetime is DISCONNECTED
  (the socket is closed). This limiter is per-connection state, checked on every inbound frame.

The registration checks run in order **rate → concurrent-cap →** the existing mTLS / capacity /
anti-hijack checks (§3.2), so a per-source throttle is reported (code 7) distinctly from the global
capacity cap (code 4).

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

### 5.1 Reflection rate limiting (normative)

Because STUN answers spoofable, unauthenticated UDP, the responder MUST bound its outbound response
rate so it can never act as an unlimited open reflector:

- **Per-source-IP budget.** At most `stun_per_ip_responses_per_sec` Binding Success Responses are
  sent to any single source IP per one-second window (default 5). A request over this budget is
  dropped WITHOUT a reply. IPv4-mapped IPv6 (`::ffff:a.b.c.d`) and plain IPv4 for the same address
  share ONE budget.
- **Global budget.** At most `stun_global_responses_per_sec` responses are sent in total across all
  sources per one-second window (default 1000), a backstop against a distributed spoof across many
  forged source IPs. A per-IP rejection does NOT consume a global token.
- **Bounded limiter state.** The per-IP accounting map is itself capacity-bounded with
  least-recently-seen eviction, so a flood of forged source IPs cannot grow the relay's memory
  without limit.
- Either budget set to `0` disables that dimension. Both default to non-zero, so a
  default-configured relay is never an unlimited reflector.

The response is also non-amplifying: a Binding Success Response (32 bytes IPv4 / 44 bytes IPv6) is a
small bounded multiple of the 20-byte minimal request, so the reflector is never an amplifier.

## 6. Health

`GET /health` on `health_listen` (§2) returns `200` with:

```json
{ "status": "ok", "connected_peers": <u64>, "uptime_secs": <u64>, "version": "<CARGO_PKG_VERSION>" }
```

`connected_peers` is the live registry count; `uptime_secs` is wall-clock since process start. It is
served on its own listener so an NLB's HTTP health check can never collide with the relay WebSocket.

## 6.1 Dashboard (peer-stats overview)

A READ-ONLY dashboard is served over HTTPS at `https://relay.dig.net/` — the relay supports only
HTTPS/WSS, so the dashboard is served on the WIRE listener itself (`listen`, §2): TLS is terminated
upstream at the load balancer, so both a WebSocket-upgrade request (the `RelayMessage` wire) and an
ordinary browser `GET` (the dashboard) arrive on the same port. The relay reads each connection's HTTP
request head and routes on it — a `Connection: Upgrade` + `Upgrade: websocket` request is handed to
the wire handshake byte-for-byte unchanged; any other request is served the dashboard. The dashboard
is built entirely from the relay's EXISTING in-memory state (the peer registry + cheap atomic
counters); it never mutates state and never disturbs the wire.

Plain HTTP is redirect-only: the `dashboard_listen` port (default `[::]:80`) responds to every request
with `301 Moved Permanently → https://<host><path>` (using the request's `Host`). Because it binds a
privileged port, this redirect listener is NON-FATAL: if it cannot bind (e.g. `:80` on an unprivileged
self-hosted relay), the relay logs a warning and keeps serving the wire/health/STUN listeners normally
(point `--dashboard-listen` at a high port to enable it there). The dashboard itself is always
available on the wire port regardless.

- `GET /` → an HTML overview page (auto-refreshing ~every 5 s) that fetches `/stats.json` and renders
  it, handling the loading / error / empty / success states.
- `GET /stats.json` → the SAME data machine-readable. Stable snake_case field names + a
  `schema_version` (currently `1`) an integrator MAY pin; new fields are additive and do NOT bump it.
- `GET /mascot.png` → the DIG Network robot mascot (branding), served immutably.

`/stats.json` body:

```json
{
  "schema_version": 1,
  "status": "ok",
  "version": "<CARGO_PKG_VERSION>",
  "uptime_secs": <u64>,
  "active_reservations": <usize>,
  "connected_peers": <u64>,
  "open_connections": <u64>,
  "stun_requests": <u64>,
  "hole_punch_requests": <u64>,
  "hole_punch_successes": <u64>,
  "hole_punch_failures": <u64>,
  "bytes_relayed": <u64>,
  "networks": [ { "network_id": "<string>", "peers": <usize> } ],
  "peers": [ {
    "peer_id": "<string>", "network_id": "<string>",
    "via": "direct" | "relay", "address_family": "v6" | "v4" | "none",
    "protocol_version": <u32>, "connected_at": <u64>, "connected_secs": <u64>
  } ]
}
```

- `active_reservations` = live registry count (== `connected_peers`); `open_connections` includes
  accepted-but-unregistered sockets. `networks` aggregates the reservation count per `network_id`.
- Per-peer `via` is `direct` when the relay resolved a dialable address for the peer (§2.9), else
  `relay`; `address_family` is that address's family, or `none` when no dialable address is known.
- The counters (`stun_requests`, `hole_punch_*`, `bytes_relayed`) are cheap monotonic gauges the relay
  maintains as it serves STUN (§5), forwards `HolePunchRequest`/`HolePunchResult` (§3, RLY-007), and
  relays `RelayGossipMessage`/`Broadcast` payloads. They are observational; a restart resets them.

**Privacy (normative):** aggregate counts are always exposed. Per-peer rows expose the `peer_id` (a
public SHA-256 identity hash, not PII) and only the ADDRESS FAMILY of each peer — never a full IP, so
the dashboard does not publish the network's dialable topology. By default `peer_id` is TRUNCATED to a
short prefix; the query `?full=1` returns the un-truncated `peer_id`. No key material or payload is
ever exposed (the relay is an untrusted forwarder and holds none).

## 6.2 Peer globe (`/map`) — coarse, privacy-first geo visualization

A second, PURELY VISUAL surface shares the same wire listener + routing as §6.1: `GET /map` renders a
self-contained 3D globe (no CDN — the WebGL runtime + earth texture are embedded in the binary) showing
where the relay's registered peers are, in AGGREGATE, worldwide. Accuracy is explicitly not a goal —
the intent is "watch the network form," never a locator for any individual peer.

- `GET /map` → the globe HTML page. Fetches `/map.json` on load and every ~5 s; the four async states
  (loading / error / empty / success) are handled client-side.
- `GET /map.json` → the same data machine-readable (stable snake_case, a pinnable `schema_version`).
- `GET /map/globe.gl.min.js`, `GET /map/earth.jpg` → the vendored, immutably-cached WebGL runtime +
  earth texture the page renders with (see `assets/map/PROVENANCE.md` for exact pinned versions +
  licenses).

`/map.json` body:

```json
{
  "schema_version": 1,
  "generated_at": <u64>,
  "cell_deg": 5.0,
  "total_peers": <usize>,
  "located_peers": <usize>,
  "unknown_peers": <usize>,
  "cells": [ { "lat": <f64>, "lon": <f64>, "count": <usize> } ]
}
```

**Privacy (normative, load-bearing).** No raw peer IP, no `peer_id`, and no precise per-peer
coordinate is ever computed into or serialized by this endpoint:

- Geo-location happens SERVER-SIDE ONLY, in-memory, from a bundled OFFLINE MaxMind-format database
  (`DIG_RELAY_GEOIP_DB`, default `/opt/dig-relay/geoip/dbip-city-lite.mmdb`) — never a third-party geo
  API call per request, which would itself leak the peer's IP to whoever runs that service. The relay
  image ships the free, CC-BY **DB-IP City Lite** database baked in at that default path (coarse
  city-level accuracy, which is all the ~5° grid needs); an operator may point `DIG_RELAY_GEOIP_DB` at
  a different `.mmdb`. The database is opened once; each lookup is a direct in-memory read performed
  fresh, with NO per-IP cache — an attacker cycling source IPs (trivially cheap across an IPv6 /64)
  therefore cannot grow unbounded process memory.
- Every located point is snapped to a deliberately COARSE global grid (`cell_deg`, ~5°, roughly 300
  miles at the equator) BEFORE it is published; only the grid cell's CENTROID + a peer COUNT for that
  cell is ever exposed. A published coordinate means "somewhere in this ~300-mile cell," never a
  peer's actual location. Co-located peers (same cell) are exactly the visual "column" the globe
  renders — the coarse cell IS the stacking bucket.
- A peer with no public/dialable address (relay-only reachability), or whose IP the database has no
  answer for, contributes to `unknown_peers` — never a fabricated location.
- The database file is optional: if absent/unreadable, every peer lands in `unknown_peers` and the
  globe still renders (empty-state visualization, not an error).

## 7. Configuration

`RelayServerConfig` (`src/config.rs`) is validated pure data:

| Field | Default | Constraint |
|---|---|---|
| `listen` | `[::]:9450` | any `SocketAddr` |
| `health_listen` | `[::]:9451` | any `SocketAddr` |
| `dashboard_listen` | `[::]:80` | any `SocketAddr` |
| `stun_listen` | `[::]:3478` | any `SocketAddr` |
| `max_connections` | 4096 | MUST be ≥ 1 |
| `idle_timeout` | 120 s | MUST be > 0 |
| `stun_per_ip_responses_per_sec` | 5 | `0` disables the per-IP STUN limit (§5.1) |
| `stun_global_responses_per_sec` | 1000 | `0` disables the global STUN limit (§5.1) |
| `outbound_queue_capacity` | 1024 | MUST be ≥ 1 (per-connection queue bound, §3.0) |
| `max_message_bytes` | 262144 | MUST be ≥ 1 (inbound frame size bound, §3.0) |
| `register_timeout` | 10 s | MUST be > 0 (register deadline, §3.0) |
| `health_check_interval` | 30 s | MUST be > 0; MUST be ≤ `liveness_deadline` (§7.1) |
| `liveness_deadline` | 90 s | MUST be > 0; MUST be ≥ `health_check_interval`; MUST be < `idle_timeout` (§7.1) |
| `max_connections_per_ip` | 64 | `0` disables; when non-zero MUST be ≤ `max_connections` (per-IP conn cap, §3.0) |
| `registrations_per_ip_per_sec` | 10 | `0` disables the per-IP registration rate (§3.0) |
| `max_registrations_per_ip` | 128 | `0` disables the per-IP concurrent-registration cap (§3.0) |
| `messages_per_conn_per_sec` | 256 | `0` disables the per-connection message-rate limit (§3.0) |
| `bytes_per_conn_per_sec` | 1048576 | `0` disables the per-connection byte-rate limit (§3.0) |
| `max_relayed_bytes_per_conn` | 1073741824 | `0` disables the per-connection cumulative-byte cap (§3.0) |
| `tls_cert_path` | `None` | Optional; MUST be set together with `tls_key_path` (§3.2/§8) |
| `tls_key_path` | `None` | Optional; MUST be set together with `tls_cert_path` (§3.2/§8) |

`validate()` rejects `max_connections == 0`, a zero `idle_timeout`, a zero `outbound_queue_capacity`,
a zero `max_message_bytes`, a zero `register_timeout`, a zero `health_check_interval` or
`liveness_deadline`, a `liveness_deadline` shorter than `health_check_interval`, a `liveness_deadline`
not strictly shorter than `idle_timeout`, a non-zero `max_connections_per_ip` greater than
`max_connections`, and exactly one of `tls_cert_path`/`tls_key_path` being set, with a stable error
string. Config may be built from CLI flags (`main.rs`, `clap` —
`--tls-cert`/`--tls-key`/`--health-check-interval-secs`/`--liveness-deadline-secs`/
`--max-connections-per-ip`/`--registrations-per-ip-per-sec`/`--max-registrations-per-ip`/
`--messages-per-conn-per-sec`/`--bytes-per-conn-per-sec`/`--max-relayed-bytes-per-conn` alongside the
others) or environment variables consumed by the service installer (`DIG_RELAY_LISTEN`,
`DIG_RELAY_HEALTH_LISTEN`, `DIG_RELAY_DASHBOARD_LISTEN`, `DIG_RELAY_STUN_LISTEN`,
`DIG_RELAY_MAX_CONNECTIONS`, `DIG_RELAY_STUN_PER_IP_RPS`, `DIG_RELAY_STUN_GLOBAL_RPS`,
`DIG_RELAY_OUTBOUND_QUEUE_CAPACITY`, `DIG_RELAY_MAX_MESSAGE_BYTES`,
`DIG_RELAY_REGISTER_TIMEOUT_SECS`, `DIG_RELAY_HEALTH_CHECK_INTERVAL_SECS`,
`DIG_RELAY_LIVENESS_DEADLINE_SECS`, `DIG_RELAY_MAX_CONNECTIONS_PER_IP`,
`DIG_RELAY_REGISTRATIONS_PER_IP_PER_SEC`, `DIG_RELAY_MAX_REGISTRATIONS_PER_IP`,
`DIG_RELAY_MESSAGES_PER_CONN_PER_SEC`, `DIG_RELAY_BYTES_PER_CONN_PER_SEC`,
`DIG_RELAY_MAX_RELAYED_BYTES_PER_CONN`, `DIG_RELAY_TLS_CERT_PATH`, `DIG_RELAY_TLS_KEY_PATH` — see
`src/service.rs::config_from_env`), so an installed OS service serves identically to a manually-run
`dig-relay serve` with the same flags.

### 7.1 Liveness & pruning (#1382)

The relay actively, promptly prunes registrations belonging to dead or half-open connections, rather
than leaving them to poison peer discovery until the (much longer) idle timeout finally reaps them:

- **A periodic health sweep** runs every `health_check_interval` (default 30 s) alongside the PEX
  housekeeping tick, for the lifetime of the accept loop. Each pass removes every registration that is
  **dead** (its outbound channel is closed — the connection task has already torn down) OR **stale**
  (no inbound activity for longer than `liveness_deadline`, default 90 s) — collecting and removing
  under ONE registry-lock hold so a concurrent reconnect can never be evicted in the sweep's place
  (`src/server.rs::sweep_once`/`Registry::dead_or_stale`).
- **Liveness is INBOUND-activity-based, never pong-dependent.** A registration's liveness clock
  (`last_activity`) is stamped to "now" on EVERY inbound frame from that connection — valid or
  invalid, RLY or PEX. The relay never actively pings a peer and waits for a pong to judge liveness:
  the dig-gossip relay CLIENT does not answer relay-initiated `Ping`s, so an expect-a-pong liveness
  check would prune every live peer. The node's own RLY-006 keepalive ping (roughly every 30 s) is
  what keeps a genuinely live, quiet connection's activity fresh.
- **A pruned peer is evicted from BOTH introductions and PEX**, exactly as a graceful `Unregister`/
  disconnect is (§4): same-network peers receive `PeerDisconnected`, and the PEX introducer subsystem
  drops it from the advertise set (`PexRelay::on_unregister`) — a dead/stale peer stops being handed
  out to new nodes as soon as the next sweep catches it, not up to `idle_timeout` later.
- **The idle timeout remains a strictly LONGER backstop**, not a replacement: `liveness_deadline` MUST
  be `< idle_timeout` (config validation enforces it). The sweep is the fast, active path; the idle
  timeout is the connection's own read loop failing safe if the sweep were ever disabled or delayed.

## 8. Transport security

By DEFAULT the relay speaks plain `ws://`/UDP internally; TLS (`wss://`) is terminated at the load
balancer in the canonical `relay.dig.net` deployment. `RelayMessage` payloads carry gossip data that
is itself authenticated end-to-end by the gossip layer (peers verify each other via the Chia
TLS-SPKI `peer_id` and consensus BLS keys) — the relay is an untrusted forwarder that routes by
`peer_id` without needing to inspect or trust payload contents.

**Optional mTLS termination (`src/tls.rs`).** When `tls_cert_path`/`tls_key_path` are configured
(§7), the relay terminates TLS itself on the relay listener using `rustls` (pure Rust — reliable
client-certificate capture on every OS, unlike OS-native TLS backends) and REQUIRES a client
certificate on every connection (`AnyClientCertVerifier::client_auth_mandatory`); §3.2 is the
normative registration-identity contract this enables. The relay's own TLS identity
(`tls_cert_path`/`tls_key_path`) may itself be a throwaway self-signed certificate — it authenticates
the SERVER side of the channel only and is unrelated to any `peer_id`. The STUN (UDP) and `/health`
listeners are UNAFFECTED by this setting; only the relay WebSocket listener terminates TLS.

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
- `tests/mtls.rs` proves the mTLS proof-of-possession contract (§3.2) end-to-end over real TCP
  sockets: a client registering the `peer_id` its own certificate commits to is accepted; a client
  registering a different (spoofed) `peer_id` is refused with `IDENTITY_MISMATCH`; a connection with
  no client certificate never reaches the `RelayMessage` wire; `/health` stays plain HTTP regardless.
  `src/tls.rs`'s own unit tests cover the handshake/identity-derivation plumbing directly.

## 11. Release pipeline — nightly cron + manual dispatch

How the `dig-relay` binary is built and released. The shape is copied from the ecosystem's
reference nightlies implementation (`dig-updater`); the ops runbook is `runbooks/release.md`.

Releases are **batched to a nightly cron plus manual dispatch** — NOT cut on every merge to `main`.
Two channels ship from one orchestrator (`.github/workflows/nightly-release.yml`):

### 11.1 Trigger

The orchestrator triggers ONLY on:

- `schedule: cron '0 0 * * *'` — **midnight UTC** (GitHub Actions cron is always UTC; a top-of-hour
  cron MAY be delayed under load — acceptable, since both channels are idempotent), and
- `workflow_dispatch` with two inputs: `channel` (`both` | `stable` | `nightly`, default `both`) and
  `force` (boolean, default `false`).

It MUST NOT trigger on `push` to `main`. A schedule run exercises BOTH channels; a dispatch runs the
selected channel(s).

**60-day auto-disable caveat.** GitHub auto-disables a `schedule:` trigger after 60 days with no
repo activity on a public repo, with no auto-re-enable — and since this cron is the ONLY automatic
release trigger, a quiet repo can silently stop releasing with no error surfaced anywhere. Detect
it with `gh api repos/DIG-Network/dig-relay/actions/workflows/nightly-release.yml --jq .state` (a
value of `disabled_inactivity` means it was auto-disabled) and recover with `gh workflow enable
nightly-release.yml` (see `runbooks/release.md`). Any repo activity resets the 60-day counter.

### 11.2 Stable channel

Cuts a semver `vX.Y.Z` **stable** release when — and only when — the version in `Cargo.toml`
(`[package].version`) has advanced beyond the newest existing `vX.Y.Z` tag. The
**skip-if-already-tagged** check IS the version-changed check: an unchanged version means the tag
already exists, so the run is a no-op. Cutting a release means: `git-cliff` regenerates
`CHANGELOG.md` from the Conventional-Commit history, commits it to `main` as `chore(release):
vX.Y.Z`, tags THAT commit `vX.Y.Z` (so the changelog is inside the tag), and pushes commit + tag
with `RELEASE_TOKEN`. The pushed `v*` tag fires `release.yml`, which builds every OS/arch and
publishes a GitHub Release with `prerelease: false` + `make_latest: true` — the stable release is
the ONLY one that moves `latest`.

`force: true` on a manual dispatch bypasses the skip-if-tagged guard and re-cuts the current version
(moving the existing tag onto a fresh changelog commit — `main` is never force-pushed). This is the
manual "re-release this version" escape hatch (e.g. after a failed build).

**Force is guarded against mutating a published release (supply-chain invariant).** A force re-cut
MUST be refused — with a non-zero exit and a clear error — when BOTH: (a) a PUBLISHED (non-draft)
GitHub Release already exists at the version's `vX.Y.Z` tag, AND (b) that tag currently points at a
commit DIFFERENT from the commit this run would build. Moving a published release's tag to different
code would silently replace its shipped binaries with unreviewed code under the same version number.
Force MAY proceed when either condition is false: a same-commit re-cut (the tag already points at
the commit being built — a legitimate "the build failed, re-fire `release.yml`" retry) or a tag with
no published release yet (repairing a bare/failed tag). A version that genuinely needs new code
released MUST bump `Cargo.toml`, not force-move an existing tag. (Force-moving a tag breaks git
tag-immutability for that version; the shipped release artifacts remain the integrity anchor.)

### 11.3 Nightly channel

Every night (and on demand) builds `main` HEAD for every OS/arch and publishes a GitHub
**pre-release** — so a fresh nightly always exists regardless of a version bump. It:

- **Synthesizes the version at build time** (nothing is committed): `X.Y.Z-nightly.YYYYMMDD.<shortsha>`
  from the current `Cargo.toml` version + UTC date + `git rev-parse --short HEAD`. As a semver
  prerelease it sorts BELOW the plain `X.Y.Z`, so a nightly never outranks the stable release.
- Publishes under a **dated tag `nightly-YYYYMMDD`** AND force-moves a **rolling `nightly` tag** to
  the same build, with `prerelease: true` and **never** `latest`. Both carry this run's binaries.
  Idempotent: a same-day re-run refreshes today's dated release + the rolling pointer.
- **Retention:** keeps the newest **14** dated nightlies plus the rolling `nightly`, pruning older
  dated pre-releases AND their `nightly-YYYYMMDD` tags together (`gh release delete --cleanup-tag`).
  `v*` stable tags/releases and the rolling `nightly` are NEVER pruned.

Neither `nightly-*` nor `nightly` matches `release.yml`'s `v*` trigger, so the nightly channel never
fires the stable build; the nightly job builds and publishes directly.

### 11.4 Reusable build

The cross-OS binary build lives once in `.github/workflows/build-binaries.yml` (`on: workflow_call`,
inputs `version` + `ref`). Both `release.yml` (stable) and the nightly channel call it, so the two
paths can never diverge on HOW a binary is produced. It builds the `dig-relay` binary for
`windows-x64`, `linux-x64`, `macos-arm64`, and `macos-x64`, stamping the caller's `version` into
each artifact filename (`dig-relay-<ver>-<os-arch>[.exe]`).

### 11.5 RELEASE_TOKEN posture (both channels)

Releasing uses the `RELEASE_TOKEN` org PAT, not the default `GITHUB_TOKEN`: a tag pushed by
`GITHUB_TOKEN` does not trigger downstream workflows (GitHub anti-recursion) and `GITHUB_TOKEN`
cannot push a changelog commit past branch protection. If `RELEASE_TOKEN` is absent, EVERY channel
NO-OPS with a clear `::warning::` — never a half-release. A `concurrency: nightly-release` group
(cancel-in-progress `false`) serializes runs so an overlapping cron + dispatch cannot race.

### 11.6 Pre-merge build coverage caveat

`ci.yml` runs the full fmt/clippy/test/coverage gate on every PR, but only on `ubuntu-latest` — it
does NOT build the Windows or macOS targets. A cross-platform build break on `main` is therefore
first surfaced by the nightly channel (which builds all four targets from `main` HEAD every night),
not by PR CI. This is an accepted trade-off (the pure-Rust/rustls graph rarely breaks per-OS), and
the nightly channel bounds the detection lag to ~24h; widening `ci.yml` to a cross-OS build matrix
is a future hardening.

A change to any behavior in this document MUST update this SPEC in the same unit of work.
