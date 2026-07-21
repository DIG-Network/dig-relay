//! App-level abuse protection for the relay (per-IP connection / registration / bandwidth limits).
//!
//! TODO(#1386): `AbusePolicy` (shared per-IP/per-key state) + `PerConnLimiter` (task-local
//! per-connection message/byte limiter), built on a relocated `TokenBucket` (shared with `stun.rs`).
