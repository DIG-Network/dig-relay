# dig-relay

**NAT-traversal rendezvous + circuit relay for the DIG Network.** DIG Nodes behind NAT can't always
dial each other directly; `dig-relay` is a publicly-reachable rendezvous point that lets nodes
discover peers, coordinate hole-punching, and bridge connections via relayed transport when a direct
path can't be established.

- **Default relay:** `relay.dig.net`.
- A DIG Node maintains a **constant connection / reservation** with a relay so it stays reachable to
  peers behind NAT.
- Installable as an optional component via the DIG installer (run your own relay).

This repository is the **relay server** (open source, GPL-2.0-only). The AWS deployment
infrastructure for the canonical `relay.dig.net` is maintained separately and is **not** part of this
repo or the installer.

## Status

Scaffold — the relay server implementation lands on top of this initial commit.

## Build

```bash
cargo build --release
cargo test
```

## Run

```bash
dig-relay            # serve the relay (flags/config documented as the server lands)
```

## License

GPL-2.0-only. See [LICENSE](./LICENSE).
