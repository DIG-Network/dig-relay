# dig-relay

**NAT-traversal rendezvous + circuit relay for the DIG Network.** DIG Nodes behind NAT can't always
dial each other directly; `dig-relay` is a publicly-reachable rendezvous point that lets nodes
register a constant reservation, discover peers, coordinate hole-punching, and bridge connections via
relayed transport when a direct path can't be established.

- **Default relay:** `relay.dig.net` (WebSocket on port `9450`).
- A DIG Node maintains a **constant connection / reservation** with a relay so it stays reachable to
  peers behind NAT.
- Installable as an optional component via the DIG installer (run your own relay).

This repository is the **relay server** (open source, GPL-2.0-only). The AWS deployment
infrastructure for the canonical `relay.dig.net` is maintained separately and is **not** part of this
repo or the installer.

## Protocol

`dig-relay` implements the **server side** of the DIG Network's relay protocol — the same
`RelayMessage` wire (JSON over WebSocket, requirements RLY-001..RLY-007) that the `dig-gossip` L2
peer layer speaks as a client. It is **not** libp2p; see [`DESIGN.md`](./DESIGN.md) for why aligning
to the existing DIG/Chia-style peer protocol is the right fit. The wire types are vendored
byte-identically in `src/wire.rs` and pinned by `tests/wire_conformance.rs`.

What the server does:

- **Register / RegisterAck** (RLY-001) — a node registers its `peer_id` + `network_id`; the relay
  holds the connection as the node's reservation.
- **Relayed transport** (RLY-002 targeted, RLY-003 broadcast) — forwards gossip payloads between
  registered peers when a direct dial isn't possible. The relay is an untrusted forwarder; payloads
  are authenticated end-to-end by the gossip layer.
- **Peer discovery** (RLY-005 `GetPeers`/`Peers`, `PeerConnected`/`PeerDisconnected`).
- **Keepalive** (RLY-006 `Ping`/`Pong`) with idle reaping.
- **NAT-traversal coordination** (RLY-007 `HolePunchRequest` → `HolePunchCoordinate`) — exchanges
  each side's external address so two NAT'd nodes can attempt a simultaneous open and migrate to a
  direct connection.

## Build

```bash
cargo build --release
cargo test
```

## Run

```bash
dig-relay                          # serve on 0.0.0.0:9450 (relay) + 0.0.0.0:9451 (/health)
dig-relay --listen 0.0.0.0:9450 --health-listen 0.0.0.0:9451 \
          --max-connections 4096 --idle-timeout-secs 120
```

- `GET /health` (on the health port) returns `200` + `{status, connected_peers, uptime_secs,
  version}` for a load balancer's target-group check.
- `RUST_LOG=debug dig-relay` for verbose tracing.

## Docker

```bash
docker build -t dig-relay .
docker run -p 9450:9450 -p 9451:9451 dig-relay
```

TLS is terminated at the load balancer in the canonical deployment, so the container speaks plain
`ws://`.

## Releases

Tag-driven: pushing a `vX.Y.Z` tag builds per-OS/arch binaries
(`dig-relay-<ver>-{windows-x64.exe,linux-x64,macos-arm64,macos-x64}`) and attaches them to a GitHub
Release, so the DIG installer can resolve a `dig-relay` binary for the host.

## License

GPL-2.0-only. See [LICENSE](./LICENSE).
