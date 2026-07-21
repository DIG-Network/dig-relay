# Geo-IP test fixture — provenance + license

## `GeoIP2-City-Test.mmdb`

- **Source:** https://github.com/maxmind/MaxMind-DB/raw/main/test-data/GeoIP2-City-Test.mmdb
- **What:** MaxMind's tiny, synthetic MaxMind-DB test database (~22 KiB) — the canonical fixture for
  exercising an `.mmdb` reader without shipping a real ~130 MiB production database.
- **License:** Apache-2.0 (the `maxmind/MaxMind-DB` repository, which the test data lives in). Synthetic
  test data, not real subscriber data.
- **SHA-256:** `ed972738e4e03a3e56e12041a6af4d91592249d110f7e4a647e5f2fa0e639c09`

## Why it's here

`src/geoip.rs` loads the production database through a process-lifetime `OnceLock` singleton whose value
is fixed by its first caller, so the database-PRESENT resolution path cannot be exercised by pointing an
env var at a file per-test. `geoip::lookup_ip(reader, ip)` takes an explicit reader so a unit test can
open THIS fixture directly and prove a known public IP (`81.2.69.142` → London, GB) resolves and snaps
to its coarse 5° cell. The shipped image bundles **DB-IP City Lite** instead (see
`assets/map/PROVENANCE.md` + the `Dockerfile` `geoip` stage); this fixture is test-only and never
deployed.
