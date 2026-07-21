# dig-relay — development log

Durable realizations from developing dig-relay. Context, not a change diary (CLAUDE.md §4.5).

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
