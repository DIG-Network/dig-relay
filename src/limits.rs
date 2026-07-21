//! App-level abuse protection for the relay (#1386): per-source-IP connection / registration limits
//! plus per-connection message/byte-rate + cumulative-byte caps.
//!
//! The global [`crate::config::RelayServerConfig::max_connections`] cap and the existing
//! per-connection frame-size / register-timeout / bounded-queue hardening (SECURITY_AUDIT_P2P #3/#4/#5)
//! bound the relay in aggregate, but nothing stops ONE source IP from opening every slot or hammering
//! `Register`. This module adds the missing per-SOURCE dimension:
//!
//! * [`AbusePolicy`] — shared, cheap per-IP state touched only at the cold, once-per-lifecycle
//!   choke points (connection open/close, registration): a per-IP concurrent-connection cap, a per-IP
//!   registration RATE limit, and a per-IP concurrent-registration cap. It holds a
//!   [`std::sync::Mutex`] over small maps; every critical section is non-`async`, O(1), and never
//!   `.await`s, so it never blocks the runtime. Acquisitions hand back RAII slots
//!   ([`ConnSlot`]/[`RegSlot`]) that release their count on `Drop` — like `server::OpenConnectionGuard`
//!   — so a count can never leak on any exit path (normal close, error, timeout, sweep prune, panic).
//! * [`PerConnLimiter`] — the HOT per-frame limiter, deliberately TASK-LOCAL (owned by the one
//!   connection task, NO shared lock): a message-rate bucket, a byte-rate bucket, and a cumulative
//!   inbound-byte ceiling. [`PerConnLimiter::admit`] returns [`Admit::Disconnect`] on a breach so the
//!   connection task closes the socket.
//!
//! Keying is IPv6-aware (CLAUDE.md §5.2): [`ip_key`] canonicalises an IPv4-mapped IPv6 address to its
//! IPv4 form (so a dual-stack client cannot get two budgets), keys IPv4 on the full /32, and keys IPv6
//! on the **/64 prefix** — the smallest block a site is typically delegated — so an attacker cannot
//! trivially sidestep the per-IP caps by walking the many addresses within one assigned /64.
//!
//! An ephemeral ban list is deliberately NOT built here (a separate ticket): this module provides the
//! [`ip_key`] normalisation + the [`AbusePolicy`] choke points a ban map would later slot into.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use crate::config::RelayServerConfig;

/// Upper bound on the number of distinct source-IP keys any per-IP map tracks, so the limiter's own
/// state cannot be grown without bound by a flood of distinct (possibly spoofed) source IPs. When a
/// rate-bucket map is full and a new key arrives, the least-recently-seen entry is evicted (LRU).
///
/// Shared with [`crate::stun`], which re-imports it so the relay has ONE tracked-IP bound.
pub(crate) const MAX_TRACKED_IPS: usize = 65_536;

/// A per-source token bucket: a whole-token count refilled to `capacity` once per one-second window.
///
/// A fixed one-second refill window (rather than a continuous drip) keeps the arithmetic integer-only
/// and trivially testable, while still bounding the sustained rate to `capacity` events/second. This
/// is the leaf primitive shared by the STUN reflector limiter ([`crate::stun`]) and the per-IP
/// registration-rate + per-connection message-rate limiters here.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TokenBucket {
    /// Tokens remaining in the current window.
    pub(crate) tokens: u32,
    /// The one-second window this bucket's `tokens` belong to (`now_ms / 1000`).
    pub(crate) window: u64,
    /// Last time (ms) this bucket was touched — used for LRU eviction when a map is full.
    pub(crate) last_seen_ms: u64,
}

impl TokenBucket {
    pub(crate) fn new(capacity: u32, now_ms: u64) -> Self {
        TokenBucket {
            tokens: capacity,
            window: now_ms / 1000,
            last_seen_ms: now_ms,
        }
    }

    /// Try to spend one token in the window containing `now_ms`, refilling to `capacity` at each new
    /// one-second window. Returns `true` if a token was available (the caller may proceed).
    pub(crate) fn try_spend(&mut self, capacity: u32, now_ms: u64) -> bool {
        let window = now_ms / 1000;
        if window != self.window {
            self.window = window;
            self.tokens = capacity;
        }
        self.last_seen_ms = now_ms;
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

/// A byte-budget variant of [`TokenBucket`]: a byte allowance refilled to `capacity` bytes once per
/// one-second window, spent in variable-sized chunks. Used ONLY by the task-local [`PerConnLimiter`]
/// (never shared), so it needs no LRU bookkeeping — same one-second-window arithmetic as
/// [`TokenBucket`], just counting bytes rather than whole tokens.
#[derive(Debug, Clone, Copy)]
struct ByteBucket {
    /// Bytes remaining in the current window.
    remaining: u64,
    /// The one-second window `remaining` belongs to (`now_ms / 1000`).
    window: u64,
}

impl ByteBucket {
    fn new(capacity: u64, now_ms: u64) -> Self {
        ByteBucket {
            remaining: capacity,
            window: now_ms / 1000,
        }
    }

    /// Try to spend `cost` bytes in the window containing `now_ms`, refilling to `capacity` at each
    /// new one-second window. Returns `true` if the whole `cost` fit within the remaining budget. A
    /// `cost` larger than a full window's `capacity` can never fit and always returns `false`.
    fn try_spend(&mut self, capacity: u64, cost: u64, now_ms: u64) -> bool {
        let window = now_ms / 1000;
        if window != self.window {
            self.window = window;
            self.remaining = capacity;
        }
        if self.remaining >= cost {
            self.remaining -= cost;
            true
        } else {
            false
        }
    }
}

/// A normalised per-source-IP key. IPv4-mapped IPv6 is canonicalised to IPv4; IPv4 is keyed on the
/// full /32; IPv6 is keyed on the /64 prefix (the low 64 bits zeroed). See [`ip_key`].
pub type IpKey = IpAddr;

/// Normalise a source address into the [`IpKey`] the per-IP limits are counted against (CLAUDE.md
/// §5.2): an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) collapses to its IPv4 form so a dual-stack
/// client can't earn two budgets; a genuine IPv6 address is truncated to its **/64 prefix** (low 64
/// bits zeroed) so the many addresses within one delegated /64 share a single budget; IPv4 is keyed
/// on the full address.
pub fn ip_key(ip: IpAddr) -> IpKey {
    match ip.to_canonical() {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let mut prefix = [0u8; 16];
            prefix[..8].copy_from_slice(&octets[..8]);
            IpAddr::V6(Ipv6Addr::from(prefix))
        }
    }
}

/// The mutable per-IP maps behind [`AbusePolicy`], guarded by one [`std::sync::Mutex`]. Held in an
/// [`Arc`] so an RAII slot ([`ConnSlot`]/[`RegSlot`]) can release its count independently of the
/// [`AbusePolicy`]'s own lifetime.
#[derive(Default)]
struct AbuseState {
    /// Live OPEN connections per source IP.
    conns_per_ip: HashMap<IpKey, u32>,
    /// Per-IP registration-RATE token buckets (LRU-bounded to [`MAX_TRACKED_IPS`]).
    reg_buckets: HashMap<IpKey, TokenBucket>,
    /// Live CONCURRENT registrations per source IP.
    regs_per_ip: HashMap<IpKey, u32>,
}

/// Shared, cheap per-source-IP abuse limits (#1386): a per-IP concurrent-connection cap, a per-IP
/// registration RATE limit, and a per-IP concurrent-registration cap.
///
/// Every method is non-`async`, takes the internal [`std::sync::Mutex`] only briefly for an O(1)
/// map op, and never `.await`s while holding it — the maps are touched only at the cold
/// once-per-lifecycle choke points (connection open/close, registration), never on the hot per-frame
/// path (that is the task-local [`PerConnLimiter`]). A `0` limit disables THAT dimension (matching
/// the STUN-limit convention), so an operator can opt out of any single check.
pub struct AbusePolicy {
    max_connections_per_ip: u32,
    registrations_per_ip_per_sec: u32,
    max_registrations_per_ip: u32,
    state: Arc<Mutex<AbuseState>>,
}

impl AbusePolicy {
    /// Build the policy from the relevant [`RelayServerConfig`] limits.
    pub fn new(config: &RelayServerConfig) -> Self {
        AbusePolicy {
            max_connections_per_ip: config.max_connections_per_ip,
            registrations_per_ip_per_sec: config.registrations_per_ip_per_sec,
            max_registrations_per_ip: config.max_registrations_per_ip,
            state: Arc::new(Mutex::new(AbuseState::default())),
        }
    }

    /// Try to reserve one connection slot for `ip`. Returns `Some(ConnSlot)` if this source is below
    /// its per-IP connection cap (the count is incremented and released when the slot drops), or
    /// `None` if the source is already at the cap. A `0` cap disables the check (always `Some`).
    ///
    /// The returned [`ConnSlot`] MUST be held for the whole connection lifetime (beside
    /// `server::OpenConnectionGuard`) so the count reflects live connections and is released on every
    /// exit path.
    pub fn try_acquire_conn(&self, ip: IpAddr) -> Option<ConnSlot> {
        let key = ip_key(ip);
        if self.max_connections_per_ip == 0 {
            // Cap disabled: hand back an untracked slot so the caller path is uniform, but do not
            // touch the map (nothing to release).
            return Some(ConnSlot { state: None, key });
        }
        let mut state = lock(&self.state);
        let count = state.conns_per_ip.entry(key).or_insert(0);
        if *count >= self.max_connections_per_ip {
            // At cap: do not leave a zero entry we just created dangling.
            if *count == 0 {
                state.conns_per_ip.remove(&key);
            }
            return None;
        }
        *count += 1;
        Some(ConnSlot {
            state: Some(self.state.clone()),
            key,
        })
    }

    /// Whether a `Register` from `ip` is within the per-IP registration RATE budget at `now_ms`.
    /// Spends one token from the source's per-second bucket; returns `false` when the budget is
    /// exhausted this window. A `0` rate disables the check (always `true`). The per-IP bucket map is
    /// LRU-bounded to [`MAX_TRACKED_IPS`], so a flood of distinct source IPs cannot grow it without
    /// bound.
    pub fn allow_registration(&self, ip: IpAddr, now_ms: u64) -> bool {
        if self.registrations_per_ip_per_sec == 0 {
            return true;
        }
        let key = ip_key(ip);
        let capacity = self.registrations_per_ip_per_sec;
        let mut state = lock(&self.state);
        evict_lru_if_full(&mut state.reg_buckets, key);
        state
            .reg_buckets
            .entry(key)
            .or_insert_with(|| TokenBucket::new(capacity, now_ms))
            .try_spend(capacity, now_ms)
    }

    /// Try to reserve one CONCURRENT registration slot for `ip`. Returns `Some(RegSlot)` if the source
    /// is below its per-IP concurrent-registration cap (released when the slot drops — on deregister
    /// or health-sweep prune), or `None` at the cap. A `0` cap disables the check (always `Some`).
    pub fn try_acquire_registration(&self, ip: IpAddr) -> Option<RegSlot> {
        let key = ip_key(ip);
        if self.max_registrations_per_ip == 0 {
            return Some(RegSlot { state: None, key });
        }
        let mut state = lock(&self.state);
        let count = state.regs_per_ip.entry(key).or_insert(0);
        if *count >= self.max_registrations_per_ip {
            if *count == 0 {
                state.regs_per_ip.remove(&key);
            }
            return None;
        }
        *count += 1;
        Some(RegSlot {
            state: Some(self.state.clone()),
            key,
        })
    }
}

/// Evict the least-recently-seen bucket when `map` is at [`MAX_TRACKED_IPS`] and `key` is not already
/// tracked — the same LRU bound the STUN limiter uses, so per-IP state stays bounded under a
/// distinct-key flood.
fn evict_lru_if_full(map: &mut HashMap<IpKey, TokenBucket>, key: IpKey) {
    if !map.contains_key(&key) && map.len() >= MAX_TRACKED_IPS {
        if let Some(&victim) = map
            .iter()
            .min_by_key(|(_, b)| b.last_seen_ms)
            .map(|(ip, _)| ip)
        {
            map.remove(&victim);
        }
    }
}

/// Lock a policy mutex, recovering the guard even if a prior holder panicked. The critical sections
/// here never panic, so poisoning is not expected; recovering keeps a stray panic elsewhere from
/// cascading into every later connection.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// RAII reservation of one per-IP connection slot (#1386). Decrements the source's live-connection
/// count on `Drop`, on EVERY exit path — mirroring `server::OpenConnectionGuard` so the count can
/// never leak. A slot from a disabled cap (`state == None`) is a no-op.
pub struct ConnSlot {
    state: Option<Arc<Mutex<AbuseState>>>,
    key: IpKey,
}

impl Drop for ConnSlot {
    fn drop(&mut self) {
        if let Some(state) = &self.state {
            let mut state = lock(state);
            if let Some(count) = state.conns_per_ip.get_mut(&self.key) {
                *count -= 1;
                if *count == 0 {
                    state.conns_per_ip.remove(&self.key);
                }
            }
        }
    }
}

/// RAII reservation of one per-IP concurrent-registration slot (#1386). Decrements the source's live
/// registration count on `Drop` (deregister / health-sweep prune / teardown). A slot from a disabled
/// cap (`state == None`) is a no-op.
pub struct RegSlot {
    state: Option<Arc<Mutex<AbuseState>>>,
    key: IpKey,
}

impl Drop for RegSlot {
    fn drop(&mut self) {
        if let Some(state) = &self.state {
            let mut state = lock(state);
            if let Some(count) = state.regs_per_ip.get_mut(&self.key) {
                *count -= 1;
                if *count == 0 {
                    state.regs_per_ip.remove(&self.key);
                }
            }
        }
    }
}

/// The verdict [`PerConnLimiter::admit`] returns for one inbound frame.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Admit {
    /// The frame is within every per-connection budget; keep serving.
    Ok,
    /// A per-connection budget (message rate, byte rate, or cumulative total) was breached — the
    /// connection task MUST close the socket.
    Disconnect,
}

/// The HOT per-frame limiter for one connection (#1386): a message-rate bucket, a byte-rate bucket,
/// and a cumulative inbound-byte ceiling. Deliberately TASK-LOCAL — owned by the single connection
/// task and taking NO shared lock — so the per-frame path never contends with any other connection.
///
/// A breach DISCONNECTS (rather than throttling) because a relay connection flooding frames or bytes
/// far past the generous defaults is not a well-behaved peer to slow down but an abusive one to shed.
/// Each `0` limit disables THAT dimension.
pub struct PerConnLimiter {
    msgs: TokenBucket,
    msgs_per_sec: u32,
    bytes: ByteBucket,
    bytes_per_sec: u64,
    relayed_total: u64,
    max_relayed_bytes: u64,
}

impl PerConnLimiter {
    /// Build the per-connection limiter from the relevant [`RelayServerConfig`] limits, starting its
    /// rate windows at `now_ms`.
    pub fn new(config: &RelayServerConfig, now_ms: u64) -> Self {
        PerConnLimiter {
            msgs: TokenBucket::new(config.messages_per_conn_per_sec, now_ms),
            msgs_per_sec: config.messages_per_conn_per_sec,
            bytes: ByteBucket::new(config.bytes_per_conn_per_sec as u64, now_ms),
            bytes_per_sec: config.bytes_per_conn_per_sec as u64,
            relayed_total: 0,
            max_relayed_bytes: config.max_relayed_bytes_per_conn,
        }
    }

    /// Account for one inbound frame of `frame_len` bytes at `now_ms` and decide whether to keep the
    /// connection. Checks the message rate, the byte rate, and the cumulative total in turn; any
    /// breach returns [`Admit::Disconnect`]. A disabled (`0`) dimension is skipped.
    pub fn admit(&mut self, frame_len: usize, now_ms: u64) -> Admit {
        let frame_len = frame_len as u64;

        if self.msgs_per_sec > 0 && !self.msgs.try_spend(self.msgs_per_sec, now_ms) {
            return Admit::Disconnect;
        }
        if self.bytes_per_sec > 0 && !self.bytes.try_spend(self.bytes_per_sec, frame_len, now_ms) {
            return Admit::Disconnect;
        }
        self.relayed_total = self.relayed_total.saturating_add(frame_len);
        if self.max_relayed_bytes > 0 && self.relayed_total > self.max_relayed_bytes {
            return Admit::Disconnect;
        }
        Admit::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// A config with just the abuse limits set to the given values, everything else default.
    fn cfg(
        conns_per_ip: u32,
        regs_per_sec: u32,
        max_regs: u32,
        msgs_per_sec: u32,
        bytes_per_sec: u32,
        max_relayed: u64,
    ) -> RelayServerConfig {
        RelayServerConfig {
            max_connections_per_ip: conns_per_ip,
            registrations_per_ip_per_sec: regs_per_sec,
            max_registrations_per_ip: max_regs,
            messages_per_conn_per_sec: msgs_per_sec,
            bytes_per_conn_per_sec: bytes_per_sec,
            max_relayed_bytes_per_conn: max_relayed,
            ..Default::default()
        }
    }

    // ---- ip_key normalisation ----

    #[test]
    fn ipv4_mapped_ipv6_shares_one_key_with_the_bare_ipv4() {
        let bare = v4(203, 0, 113, 7);
        let mapped = IpAddr::V6("::ffff:203.0.113.7".parse::<Ipv6Addr>().unwrap());
        assert_eq!(
            ip_key(bare),
            ip_key(mapped),
            "dual-stack must not earn two budgets"
        );
    }

    #[test]
    fn two_ipv6_addrs_in_one_slash64_share_a_key() {
        let a: IpAddr = "2001:db8:abcd:1::1".parse().unwrap();
        let b: IpAddr = "2001:db8:abcd:1:ffff:ffff:ffff:ffff".parse().unwrap();
        assert_eq!(ip_key(a), ip_key(b), "same /64 → one budget");
    }

    #[test]
    fn different_slash64_prefixes_are_separate_keys() {
        let a: IpAddr = "2001:db8:abcd:1::1".parse().unwrap();
        let b: IpAddr = "2001:db8:abcd:2::1".parse().unwrap();
        assert_ne!(ip_key(a), ip_key(b), "different /64 → separate budgets");
    }

    // ---- per-IP connection cap ----

    #[test]
    fn conn_cap_allows_n_and_rejects_the_next() {
        let policy = AbusePolicy::new(&cfg(3, 0, 0, 0, 0, 0));
        let ip = v4(10, 0, 0, 1);
        let _s1 = policy.try_acquire_conn(ip).expect("1st allowed");
        let _s2 = policy.try_acquire_conn(ip).expect("2nd allowed");
        let _s3 = policy.try_acquire_conn(ip).expect("3rd allowed");
        assert!(
            policy.try_acquire_conn(ip).is_none(),
            "4th over the cap → refused"
        );
    }

    #[test]
    fn dropping_a_conn_slot_frees_capacity() {
        let policy = AbusePolicy::new(&cfg(1, 0, 0, 0, 0, 0));
        let ip = v4(10, 0, 0, 2);
        let slot = policy.try_acquire_conn(ip).expect("1st allowed");
        assert!(policy.try_acquire_conn(ip).is_none(), "at cap");
        drop(slot);
        assert!(
            policy.try_acquire_conn(ip).is_some(),
            "slot freed → room again"
        );
    }

    #[test]
    fn conn_cap_is_per_ip_not_global() {
        let policy = AbusePolicy::new(&cfg(1, 0, 0, 0, 0, 0));
        let _a = policy
            .try_acquire_conn(v4(10, 0, 0, 1))
            .expect("ip A allowed");
        assert!(
            policy.try_acquire_conn(v4(10, 0, 0, 2)).is_some(),
            "a different IP is unaffected by A's cap"
        );
    }

    #[test]
    fn zero_conn_cap_disables_the_check() {
        let policy = AbusePolicy::new(&cfg(0, 0, 0, 0, 0, 0));
        let ip = v4(10, 0, 0, 3);
        for _ in 0..1000 {
            assert!(
                policy.try_acquire_conn(ip).is_some(),
                "disabled cap never refuses"
            );
        }
    }

    #[test]
    fn ipv6_conn_cap_groups_the_whole_slash64() {
        let policy = AbusePolicy::new(&cfg(1, 0, 0, 0, 0, 0));
        let a: IpAddr = "2001:db8:1:1::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:1::2".parse().unwrap(); // same /64 as a
        let _s = policy.try_acquire_conn(a).expect("first in /64 allowed");
        assert!(
            policy.try_acquire_conn(b).is_none(),
            "a second address in the same /64 shares the cap"
        );
    }

    // ---- per-IP registration RATE ----

    #[test]
    fn registration_rate_allows_the_budget_then_refills_next_window() {
        let policy = AbusePolicy::new(&cfg(0, 2, 0, 0, 0, 0));
        let ip = v4(10, 0, 1, 1);
        assert!(policy.allow_registration(ip, 1_000));
        assert!(policy.allow_registration(ip, 1_000));
        assert!(
            !policy.allow_registration(ip, 1_000),
            "3rd in the window refused"
        );
        // Next one-second window refills the budget.
        assert!(policy.allow_registration(ip, 2_000), "new window refills");
    }

    #[test]
    fn registration_rate_is_per_ip() {
        let policy = AbusePolicy::new(&cfg(0, 1, 0, 0, 0, 0));
        assert!(policy.allow_registration(v4(10, 0, 1, 1), 1_000));
        assert!(
            !policy.allow_registration(v4(10, 0, 1, 1), 1_000),
            "A exhausted"
        );
        assert!(
            policy.allow_registration(v4(10, 0, 1, 2), 1_000),
            "B independent"
        );
    }

    #[test]
    fn zero_registration_rate_disables_the_check() {
        let policy = AbusePolicy::new(&cfg(0, 0, 0, 0, 0, 0));
        let ip = v4(10, 0, 1, 3);
        for _ in 0..1000 {
            assert!(
                policy.allow_registration(ip, 1_000),
                "disabled rate never refuses"
            );
        }
    }

    #[test]
    fn registration_bucket_map_is_lru_bounded_under_a_distinct_ip_flood() {
        let policy = AbusePolicy::new(&cfg(0, 1, 0, 0, 0, 0));
        // Feed far more distinct /64s than the cap; the map must never exceed MAX_TRACKED_IPS.
        for i in 0..(MAX_TRACKED_IPS as u64 + 5_000) {
            let ip: IpAddr = format!("2001:db8:{:x}:{:x}::1", i >> 16, i & 0xffff)
                .parse()
                .unwrap();
            policy.allow_registration(ip, 1_000);
        }
        let len = lock(&policy.state).reg_buckets.len();
        assert!(
            len <= MAX_TRACKED_IPS,
            "reg-bucket map stayed bounded ({len})"
        );
    }

    // ---- per-IP concurrent registrations ----

    #[test]
    fn concurrent_registration_cap_allows_n_and_rejects_the_next() {
        let policy = AbusePolicy::new(&cfg(0, 0, 2, 0, 0, 0));
        let ip = v4(10, 0, 2, 1);
        let _r1 = policy.try_acquire_registration(ip).expect("1st");
        let _r2 = policy.try_acquire_registration(ip).expect("2nd");
        assert!(
            policy.try_acquire_registration(ip).is_none(),
            "3rd over cap → refused"
        );
    }

    #[test]
    fn dropping_a_registration_slot_frees_capacity() {
        let policy = AbusePolicy::new(&cfg(0, 0, 1, 0, 0, 0));
        let ip = v4(10, 0, 2, 2);
        let slot = policy.try_acquire_registration(ip).expect("1st");
        assert!(policy.try_acquire_registration(ip).is_none(), "at cap");
        drop(slot);
        assert!(
            policy.try_acquire_registration(ip).is_some(),
            "freed → room again"
        );
    }

    #[test]
    fn zero_concurrent_registration_cap_disables_the_check() {
        let policy = AbusePolicy::new(&cfg(0, 0, 0, 0, 0, 0));
        let ip = v4(10, 0, 2, 3);
        for _ in 0..1000 {
            assert!(policy.try_acquire_registration(ip).is_some());
        }
    }

    // ---- per-connection message / byte / cumulative limiter ----

    #[test]
    fn per_conn_message_rate_disconnects_on_flood_but_admits_under_the_limit() {
        let mut lim = PerConnLimiter::new(&cfg(0, 0, 0, 3, 0, 0), 0);
        assert_eq!(lim.admit(10, 0), Admit::Ok);
        assert_eq!(lim.admit(10, 0), Admit::Ok);
        assert_eq!(lim.admit(10, 0), Admit::Ok);
        assert_eq!(
            lim.admit(10, 0),
            Admit::Disconnect,
            "4th frame in the window floods"
        );
    }

    #[test]
    fn per_conn_message_rate_refills_each_window() {
        let mut lim = PerConnLimiter::new(&cfg(0, 0, 0, 1, 0, 0), 0);
        assert_eq!(lim.admit(1, 0), Admit::Ok);
        assert_eq!(lim.admit(1, 0), Admit::Disconnect);
        assert_eq!(lim.admit(1, 1_000), Admit::Ok, "new window refills");
    }

    #[test]
    fn per_conn_byte_rate_disconnects_when_the_window_budget_is_exceeded() {
        // 100 bytes/sec budget.
        let mut lim = PerConnLimiter::new(&cfg(0, 0, 0, 0, 100, 0), 0);
        assert_eq!(lim.admit(60, 0), Admit::Ok);
        assert_eq!(lim.admit(40, 0), Admit::Ok, "exactly at the budget");
        assert_eq!(
            lim.admit(1, 0),
            Admit::Disconnect,
            "1 byte over the window budget"
        );
    }

    #[test]
    fn per_conn_cumulative_cap_disconnects_regardless_of_rate() {
        // Generous per-second budgets, tiny lifetime cap of 100 bytes.
        let mut lim = PerConnLimiter::new(&cfg(0, 0, 0, 0, 1_000_000, 100), 0);
        // Spread across windows so the rate never trips — only the cumulative cap should.
        assert_eq!(lim.admit(60, 0), Admit::Ok);
        assert_eq!(lim.admit(40, 1_000), Admit::Ok, "at the cumulative cap");
        assert_eq!(
            lim.admit(1, 2_000),
            Admit::Disconnect,
            "over the lifetime total"
        );
    }

    #[test]
    fn per_conn_limiter_all_zero_never_disconnects() {
        let mut lim = PerConnLimiter::new(&cfg(0, 0, 0, 0, 0, 0), 0);
        for i in 0..10_000 {
            assert_eq!(lim.admit(4096, i), Admit::Ok, "all limits disabled");
        }
    }
}
