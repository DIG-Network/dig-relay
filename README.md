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
peer layer speaks as a client, plus the purely-additive **RLY-008** Peer Exchange (PEX) binding. It is
**not** libp2p; see [`DESIGN.md`](./DESIGN.md) for why aligning to the existing DIG/Chia-style peer
protocol is the right fit. The RLY-001..007 wire types are vendored byte-identically in `src/wire.rs`
and pinned by `tests/wire_conformance.rs`; RLY-008 rides `dig-pex`'s `PexMessage`.

What the server does:

- **Register / RegisterAck** (RLY-001) — a node registers its `peer_id` + `network_id`; the relay
  holds the connection as the node's reservation.
- **Relayed transport** (RLY-002 targeted, RLY-003 broadcast) — forwards gossip payloads between
  registered peers when a direct dial isn't possible. The relay is an untrusted forwarder; payloads
  are authenticated end-to-end by the gossip layer.
- **Introducer / peer discovery** (RLY-005 `GetPeers`/`Peers`, `PeerConnected`/`PeerDisconnected`) —
  a registered node is advertised to other nodes' `GetPeers`, so registration *is* the introducer
  advertisement; a node discovers peers to hole-punch toward.
- **Keepalive** (RLY-006 `Ping`/`Pong`) with idle reaping.
- **NAT-traversal coordination — two tiers.** *Signalling (preferred, low bandwidth):* the relay only
  brokers discovery (`GetPeers`) + a coordinated hole punch (RLY-007 `HolePunchRequest` →
  `HolePunchCoordinate`, carrying each side's STUN-derived reflexive `external_addr`), then peers
  connect **directly** and the relay carries none of their data. *Relayed transport (last resort,
  high bandwidth):* the relay proxies all data (RLY-002 `RelayGossipMessage` / RLY-003 `Broadcast`)
  only after a hole punch fails.
- **Peer Exchange / PEX** (RLY-008 `pex_handshake`/`pex_snapshot`/`pex_delta`/`pex_error`) — the
  introducer *pushes* a registered node a warm snapshot of the OTHER same-network registrants and then
  only incremental add/drop deltas, so its address book stays current without polling. Gated on the
  node's `pex_handshake` (legacy nodes see the wire exactly as RLY-001..007); registration-backed +
  network-scoped; node-sent PEX data is never re-advertised (introducer-only). Normative in `dig-pex`.
- **STUN (RFC 5389)** — a UDP Binding responder (default port `3478`, the IANA STUN port) so a NAT'd
  node learns its public reflexive `IP:port` (XOR-MAPPED-ADDRESS) to advertise as a candidate.

## Build

```bash
cargo build --release
cargo test
```

## Run

```bash
dig-relay                          # serve on [::]:9450 (relay) + :9451 (/health) + :3478/udp (STUN)
                                    # dual-stack: also reachable over IPv4 on the same ports
dig-relay --listen [::]:9450 --health-listen [::]:9451 --stun-listen [::]:3478 \
          --max-connections 4096 --idle-timeout-secs 120
```

- `GET /health` (on the health port) returns `200` + `{status, connected_peers, uptime_secs,
  version}` for a load balancer's target-group check.
- **STUN** (UDP `3478` by default): send an RFC 5389 Binding Request to learn your reflexive
  `IP:port`.
- `RUST_LOG=debug dig-relay` for verbose tracing.

## Docker

```bash
docker build -t dig-relay .
docker run -p 9450:9450 -p 9451:9451 -p 3478:3478/udp dig-relay
```

TLS is terminated at the load balancer in the canonical deployment, so the container speaks plain
`ws://` by default. Pass `--tls-cert`/`--tls-key` (PEM files) to make the relay terminate **mTLS**
itself instead: every client must present a certificate, and a `Register`'s claimed `peer_id` must
match the one derived from it (proof-of-possession — see `SPEC.md` §3.2/§8).

## Releases

Tag-driven: pushing a `vX.Y.Z` tag builds per-OS/arch binaries
(`dig-relay-<ver>-{windows-x64.exe,linux-x64,macos-arm64,macos-x64}`) and attaches them to a GitHub
Release, so the DIG installer can resolve a `dig-relay` binary for the host.

## License

GPL-2.0-only. See [LICENSE](./LICENSE).
