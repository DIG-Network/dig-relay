# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.13.0] - 2026-07-21

### Features
- **relay:** /map — 3D globe of registered peers (coarse-geo, privacy-first) (#1452) (#16)

## [0.12.0] - 2026-07-21

### Features
- **relay:** App-level abuse protection — per-IP conn/registration/bandwidth limits (#1386) (#14)

## [0.11.0] - 2026-07-21

### Features
- **relay:** Periodic health-sweep prunes dead/half-open connections (#1382) (#13)

## [0.10.0] - 2026-07-19

### Features
- **dial:** Order reflexive candidates via canonical dig-ip Family (#12)

## [0.9.0] - 2026-07-18

### Features
- **dashboard:** Serve dashboard over HTTPS/WSS + redirect http→https (#11)

## [0.8.1] - 2026-07-18

### Bug Fixes
- **docker:** Copy assets/ into the build context for the embedded mascot (#10)

## [0.8.0] - 2026-07-18

### Features
- **dashboard:** DIG Network branding with the robot mascot (#9)

## [0.7.0] - 2026-07-18

### Features
- **dig-relay:** Peer-stats dashboard on :80 (#1012) (#8)

### CI
- **deploy:** Add Fargate deploy to relay.dig.net on release (#7)

## [0.6.0] - 2026-07-18

### Features
- **dig-relay:** B1 dialable-address emit + B2 forwarder hardening (#924) (#6)

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


