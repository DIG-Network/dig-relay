# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.6.0] - 2026-07-18

### Features
- **dig-relay:** B1 dialable-address emit + B2 forwarder hardening (#924) (#6)

## [0.7.0] - 2026-07-18

### Features
- **dashboard:** Public peer-stats + connections overview on `:80` — `GET /` (HTML, DIG dark theme, ~5s auto-refresh) + `GET /stats.json` (machine-readable). Aggregate-by-default privacy (truncated peer ids, address family only; `?full=1` for full ids). Reuses the registry + cheap STUN/hole-punch/bytes-relayed counters (#1012)

## [0.5.0] - 2026-07-18

### Features
- **observability:** Log RLY-001 register + RLY-005 get_peers at INFO (#5)

## [0.4.3] - 2026-07-15

### CI
- **release:** Nightlies system (cron + dispatch, nightly channel) (#592) (#3)- **release:** Nightlies polish (#4)

## [0.4.1] - 2026-07-12

### Bug Fixes
- **deps:** Re-resolve DIG git deps to rewritten (co-author/signed) revs

### CI
- Add flaky-test management (#489) (#2)

## [0.4.0] - 2026-07-04

### Features
- **tls:** MTLS + Register proof-of-possession for peer_id registration (#1)

## [0.3.0] - 2026-07-04

### CI
- Enforce version increment in PRs (package.json / Cargo.toml)- Enforce Conventional Commits with commitlint on PRs- Enforce Conventional Commits with commitlint on PRs- Changelog + tag on merge feeding the existing tag-driven binary release (#230)

### Chores
- **changelog:** Add git-cliff config for Conventional-Commit changelog

### CI
- Gate line coverage at >=80% via cargo-llvm-cov

## [0.1.0] - 2026-06-30


