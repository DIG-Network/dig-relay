# dig-relay — development log

Durable realizations from developing dig-relay. Context, not a change diary (CLAUDE.md §4.5).

## Liveness sweep must run on a MONOTONIC clock + ban-list keying trade-off (#1395/#1396)

- **The health sweep's clock must be `Instant`, never `SystemTime` (#1395).** The sweep prunes a
  registration when `now - last_activity > liveness_deadline`. If both readings are wall-clock
  (`SystemTime`), a host clock jump breaks it in BOTH directions: a forward NTP step (or DST) makes
  `now` leap so EVERY live registration suddenly reads as stale → a mass false-prune of the whole peer
  set at once; a backward step freezes the deadline so dead records linger. The fix is `liveness_now_secs()`
  — monotonic elapsed-since-start from a process-start `Instant` in a `OnceLock` — used for BOTH the
  `last_activity` stamp and the sweep's `now`, so a decision is the difference of two monotonic readings.
  Crucially this is a SEPARATE clock from the wire `RelayPeerInfo.last_seen`/`connected_at`, which MUST
  stay real Unix timestamps (other peers read them as such) — don't "simplify" by making them one clock.
- **The ban list (#1396) keys on the IPv6 /64, same as every #1386 per-IP cap — so a ban is a /64-wide
  hammer.** The mitigation is NOT finer keying (a /64 is the smallest a site is reliably delegated;
  finer lets an attacker walk addresses to dodge it) but a HIGH strike threshold (default 20) + a rolling
  strike window (default 60s) + a short TTL (default 300s): only sustained, clustered abuse earns a ban,
  so one misbehaving host in a shared /64 never bans the whole site on a stray cap-trip. Strikes are fed
  from the EXISTING #1386 choke points (each cap-trip = one `record_strike`); the ban only adds the
  accept-time refusal, it invents no new detection. In-memory only — a restart clears all bans.

## `/map` — coarse-grid privacy contract + the globe-column technique (#1452)

- **The grid cell IS the anonymity set, not a display convenience.** `/map.json` never carries a
  per-peer coordinate — every located peer is snapped to a ~5° global grid cell (`map::MAP_CELL_DEG`)
  and only the cell's CENTROID + a COUNT is published. This means the smallest thing a client can ever
  learn about any one peer is "somewhere in a ~300-mile region, sharing it with N others" — there is no
  way to sharpen that by querying more, because the server never computed anything sharper to leak.
  Snapping happens with `floor(coord / cell_deg)`, not `round` or truncation, so negative
  latitudes/longitudes and the antimeridian snap consistently (verified in `map::tests`).
- **Colocated peers become a "column" for free.** The globe just reads `count` per cell and maps it to
  `pointAltitude` (log-scaled) — the privacy aggregation and the "watch hotspots rise" visual are the
  SAME data structure; no separate stacking logic needed.
- **A permanent in-process cache, not a TTL cache.** `geoip::locate` caches every resolved IP (hit or
  miss) for the life of the process (`geoip::CACHE`), because a peer's IP is realistically static across
  the relay's lifetime and the offline mmdb lookup is the only non-free part of building `/map.json` on
  its 5s refresh cadence. This is also a privacy reinforcement: a peer's IP is only ever handed to the
  geo database once, never on a schedule.
- **`maxminddb` 0.24's `Reader::lookup<T>` returns `Result<T, Error>`, not
  `Result<Option<T>, Error>`** — an absent record is a plain `AddressNotFoundError`, so `.ok()` alone
  (not `.ok()?.ok()??`) collapses "not found" into `None`. Easy to over-apply `?` here since so much of
  the surrounding code chains `Option`.
- **`r#"..."#` raw strings break the instant the content contains a literal `"#`** — a CSS hex color
  written `"#8ab4ff"` inside an `r#"...HTML...`"#` Rust raw string prematurely closes it. Any HTML/CSS
  template containing a quoted `#colorhex` needs one more hash (`r##"..."##`) than the dashboard's
  existing `DASHBOARD_HTML` const, which happens not to quote a hex color anywhere.

## App-level abuse protection — keying + breach response (#1386)

- **IPv6 is keyed on the /64 prefix, not the full /128.** A single IPv6 assignment is typically a /64
  (or larger); an attacker on one delegated /64 owns 2^64 addresses, so per-/128 caps would be trivial
  to sidestep by walking addresses. Keying the per-IP connection/registration caps on the /64 prefix
  (low 64 bits zeroed, `limits::ip_key`) makes the caps bite per real source. IPv4 stays /32, and an
  IPv4-mapped IPv6 source collapses to its IPv4 form so a dual-stack client can't earn two budgets —
  the same `.to_canonical()` normalization the STUN limiter already uses.
- **Breach response differs by dimension on purpose.** A per-CONNECTION message/byte/cumulative breach
  DISCONNECTS (closes the socket): a connection flooding far past the generous defaults is not a
  well-behaved peer to slow down but an abusive one to shed, and disconnecting reclaims the resource
  immediately. A per-IP registration breach REFUSES with `RegisterAck{success:false}` +
  `Error{code:7, RATE_LIMITED}` (mirroring the CAPACITY/ID_IN_USE refusal shape) rather than
  disconnecting, because the connection itself may be legitimate — only the register attempt is
  over-budget — and a distinct code lets the client tell a per-source throttle from the global cap.
- **The hot path takes no shared lock.** The per-connection limiter (`PerConnLimiter`) is TASK-LOCAL
  (owned by the one connection task), so the per-frame check never contends. The shared `AbusePolicy`
  (a `std::sync::Mutex` over small per-IP maps) is touched only at the cold once-per-lifecycle choke
  points — connection open/close and registration — where an O(1) non-async critical section is free.
  Using `std::sync::Mutex` (never tokio's) is safe precisely because no `.await` crosses it.
- **RAII slots mirror `OpenConnectionGuard`.** Per-IP connection and concurrent-registration counts are
  released on `Drop` (`ConnSlot`/`RegSlot`), so a count can never leak on any exit path — normal close,
  ws error, timeout, health-sweep prune, or panic — exactly like the existing open-connection guard.
