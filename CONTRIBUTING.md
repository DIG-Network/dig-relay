# Contributing to dig-relay

Thanks for your interest in improving dig-relay. This is the NAT-traversal rendezvous + circuit
relay for the DIG Network — a publicly-reachable server that lets DIG Nodes behind NAT register a
constant reservation, discover peers, coordinate hole-punching, and bridge connections via relayed
transport when a direct path can't be established.

**The RLY-001..RLY-007 wire protocol (`src/wire.rs`) is vendored byte-identically from the
`dig-gossip` L2 gossip layer**, which holds the matching client. If you change anything in
`src/wire.rs`, it must stay byte-identical with dig-gossip's copy — `tests/wire_conformance.rs`
pins the shape, but the two crates are not otherwise linked, so a change here needs a matching
change (or an explicit decision not to make one) on the dig-gossip side. See `SYSTEM.md` for the
change-impact edge and `Cargo.toml`'s dependency comment for why the types are vendored rather than
imported.

This repo is licensed **GPL-2.0-only** (see [LICENSE](./LICENSE)) — the AWS deployment
infrastructure for the canonical `relay.dig.net` is maintained separately
(`DIG-Network/relay.dig.net`) and is not part of this repo.

## Reporting an issue

File it at https://github.com/DIG-Network/dig-relay/issues. Include what you observed, what you
expected, and steps to reproduce (relay version, OS, and whether you hit it against the canonical
`relay.dig.net` or a self-run relay).

## Prerequisites

- A stable Rust toolchain (CI uses `dtolnay/rust-toolchain@stable`; there's no
  `rust-toolchain.toml` pin in this repo, so whatever `rustup`'s current stable is will do).
  `rustfmt` and `clippy` components.
- No external services are needed to test. The integration suite (`tests/`) spins up real
  `dig-relay` instances bound to ephemeral loopback ports for its WebSocket, STUN, and mTLS
  end-to-end tests (`stun_e2e.rs`, `mtls.rs`, `holepunch_signaling.rs`, `proxy_protocol_e2e.rs`,
  `relay_fallback.rs`) — no network access, Docker, or external relay required.

## Build & test

```sh
# build
cargo build --release

# run the full test suite (CI uses nextest; plain `cargo test` works too)
cargo test --workspace
```

## The gate (must pass before a PR is merged)

CI (`.github/workflows/ci.yml`) runs four jobs on every PR — run the same commands locally first:

```sh
# build-test
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo nextest run --all --locked --retries 2
cargo build --release --locked
for t in scripts/tests/*.test.sh; do bash "$t"; done

# coverage — CI-gated at >=80% lines (nextest + cargo-llvm-cov)
cargo llvm-cov nextest --all --retries 2 --ignore-filename-regex 'win_service\.rs' --fail-under-lines 80

# deny — RustSec advisories, license allowlist, banned/duplicate crates, trusted sources
cargo deny check
```

`--locked` matters: the release build uses it too, so a `Cargo.lock` left stale by a manual
`Cargo.toml` edit passes nothing locally but fails CI. Run `cargo update -w` (or a scoped
`cargo update -p <crate>`) and commit the lockfile whenever you touch a dependency.

`win_service.rs` (the Windows SCM dispatcher, `#[cfg(windows)]`) is excluded from the coverage
report because it never compiles on the Linux CI runner.

A separate `commitlint` workflow enforces the Conventional Commit format below on every PR title
and commit.

## Commit and PR conventions

- **Conventional Commits**, enforced by commitlint (`commitlint.config.mjs`):
  `type(scope): summary`, `type` one of `feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert`.
  A breaking change appends `!` and/or a `BREAKING CHANGE:` footer.
- **Bump the version** in `Cargo.toml` before merging — `ensure-version-increment.yml` fails any PR
  whose version doesn't increase over `main`. `fix` → patch, `feat` → minor, a breaking change →
  major.
- `main` is a **protected branch**: PR required, all CI checks green, zero unresolved review
  threads, squash-merge only.
- **Releases are cut by manual dispatch only — never automatically.** `nightly-release.yml`'s
  `stable` job runs ONLY on a manual `workflow_dispatch(channel: stable|both)` (CLAUDE.md §3.6-A) —
  the midnight-UTC cron drives the nightly channel alone and can never cut a stable `vX.Y.Z` tag,
  bumped version or not. So merging your PR with a bumped `Cargo.toml` version does nothing on its
  own: someone dispatches `channel: stable` (or `both`) from Actions → **Nightly + stable release**
  → Run workflow when it's time to ship (git-cliff regenerates `CHANGELOG.md`, commits, tags, and
  pushes with `RELEASE_TOKEN`), which in turn fires `release.yml` (per-OS binary build) and
  `deploy.yml` (ships the canonical `relay.dig.net` service). Get the version bump and the gate
  right before merging — the dispatch is the deliberate step after.
