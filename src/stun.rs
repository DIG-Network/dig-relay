//! STUN server (RFC 5389 Binding) — lets a DIG Node learn its public reflexive address.
//!
//! A DIG Node behind NAT needs to know the `IP:port` the outside world sees for it (its
//! *server-reflexive* address) before it can advertise a useful candidate for hole-punching
//! (RLY-007, supplied as the `external_addr`) or peer exchange. Classic STUN answers exactly that: the
//! node sends a **Binding Request** to a public STUN server over UDP, and the server replies with a
//! **Binding Success Response** carrying an **XOR-MAPPED-ADDRESS** attribute — the source address of
//! the request as observed by the server.
//!
//! The RFC 5389 Binding wire format (both directions) is owned by the `dig_stun` crate — the DIG
//! ecosystem's one home for this codec, shared with `dig-nat`'s STUN client so the two can never
//! diverge on it again. They already had: dig-relay's own encoder used to raw-match on the local
//! `SocketAddr` enum variant, which tagged a genuine IPv4 caller's answer as IPv6 whenever the
//! dual-stack socket handed it back as `::ffff:a.b.c.d` (dig-relay#35) — a strict RFC 5389 client
//! rejects that response as unrelated to itself. `dig_stun::encode_binding_success` folds the peer's
//! IP to its canonical family BEFORE encoding, so that class of defect has exactly one place left to
//! recur, and this file's own test suite (below) still stands watch over it.
//!
//! This module owns only what is genuinely dig-relay's: [`run`], the thin UDP serve loop that wires
//! the codec to a socket, and [`StunRateLimiter`], the per-source-IP + global response budget that
//! keeps the relay from being an open UDP reflector (SECURITY_AUDIT_P2P dig-relay #2). The STUN
//! listener binds its own UDP port ([`crate::config`] `stun_listen`, default `[::]:3478` = the
//! IANA-assigned STUN port, matching the DIG node peer-network protocol) alongside the WebSocket
//! (9450) and health (9451) listeners, dual-stack (see [`crate::net`]) so it answers both IPv6 and
//! IPv4 Binding Requests on the one socket.
//!
//! Server behaviour, unchanged by the adoption: the only request type answered is the Binding
//! Request; every other well-formed request gets nothing (silently ignored, per the RFC's "unknown
//! method" latitude for a stateless server) and a malformed datagram is rejected without a reply.
//! The relay does not do authentication, `FINGERPRINT`, `SOFTWARE`, or the deprecated (non-XOR)
//! MAPPED-ADDRESS — a DIG Node only needs its reflexive address, and every modern STUN client reads
//! XOR-MAPPED-ADDRESS.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dig_stun::{encode_binding_success, parse_binding_request};

use crate::limits::{TokenBucket, MAX_TRACKED_IPS};
use crate::net::bind_udp_dual_stack;
use crate::server::RelayState;

/// Rate limiter for STUN responses (SECURITY_AUDIT_P2P dig-relay #2): a per-source-IP token bucket
/// plus a single global token bucket. `allow(src, now)` returns whether the relay may send a Binding
/// Success Response to `src` right now. Both budgets must permit the response; a `0` capacity for
/// either dimension disables THAT dimension (the check is skipped).
///
/// STUN answers spoofable, unauthenticated UDP, so without this the relay is a listed open reflector
/// that reflects at the attacker's send rate toward any forged victim IP. The per-IP bucket caps how
/// fast the relay reflects toward any single (spoofed) address; the global bucket caps total
/// reflection so a distributed spoof across many forged IPs still cannot make the relay a
/// high-volume reflector. The per-IP map is LRU-bounded ([`MAX_TRACKED_IPS`]) so the limiter's own
/// state cannot be grown without bound by spoofed source IPs.
struct StunRateLimiter {
    per_ip_capacity: u32,
    global_capacity: u32,
    per_ip: HashMap<IpAddr, TokenBucket>,
    global: TokenBucket,
}

impl StunRateLimiter {
    fn new(per_ip_capacity: u32, global_capacity: u32, now_ms: u64) -> Self {
        StunRateLimiter {
            per_ip_capacity,
            global_capacity,
            per_ip: HashMap::new(),
            // The global bucket starts full for the current window regardless of whether it is used.
            global: TokenBucket::new(global_capacity.max(1), now_ms),
        }
    }

    /// Whether a STUN response to `src` is allowed at `now_ms`. Checks the per-IP budget first (so a
    /// single spoofed IP cannot drain the global budget), then the global budget; a token is spent in
    /// each enabled dimension only when BOTH permit, so a request rejected by the per-IP limit does
    /// not consume a global token.
    fn allow(&mut self, src: IpAddr, now_ms: u64) -> bool {
        // Normalize IPv4-mapped IPv6 to the canonical IPv4 so a client cannot get two budgets by
        // switching between `a.b.c.d` and `::ffff:a.b.c.d` on the dual-stack socket.
        let key = src.to_canonical();
        let per_ip_capacity = self.per_ip_capacity;
        let global_capacity = self.global_capacity;
        let now_window = now_ms / 1000;

        // Per-IP check WITHOUT committing yet: peek whether a token is available.
        if per_ip_capacity > 0 {
            let bucket = self.bucket_for(key, now_ms);
            let available = if bucket.window != now_window {
                per_ip_capacity // a new window will refill
            } else {
                bucket.tokens
            };
            if available == 0 {
                // Touch last_seen so an actively-probing (even if throttled) IP isn't evicted first.
                bucket.last_seen_ms = now_ms;
                return false;
            }
        }

        // Global check (peek): if the global budget is exhausted this window, reject before spending
        // the per-IP token, so a global-cap rejection doesn't unfairly drain one IP's budget.
        if global_capacity > 0 {
            let global_available = if self.global.window != now_window {
                global_capacity
            } else {
                self.global.tokens
            };
            if global_available == 0 {
                return false;
            }
        }

        // Both permit: commit a token in each enabled dimension.
        if per_ip_capacity > 0 {
            self.bucket_for(key, now_ms)
                .try_spend(per_ip_capacity, now_ms);
        }
        if global_capacity > 0 {
            self.global.try_spend(global_capacity, now_ms);
        }
        true
    }

    /// Get (or create) the bucket for `key`, evicting the least-recently-seen bucket first when the
    /// map is at [`MAX_TRACKED_IPS`] and `key` is not already tracked.
    fn bucket_for(&mut self, key: IpAddr, now_ms: u64) -> &mut TokenBucket {
        if !self.per_ip.contains_key(&key) && self.per_ip.len() >= MAX_TRACKED_IPS {
            if let Some(&victim) = self
                .per_ip
                .iter()
                .min_by_key(|(_, b)| b.last_seen_ms)
                .map(|(ip, _)| ip)
            {
                self.per_ip.remove(&victim);
            }
        }
        self.per_ip
            .entry(key)
            .or_insert_with(|| TokenBucket::new(self.per_ip_capacity.max(1), now_ms))
    }
}

/// Current Unix-epoch time in milliseconds (saturating) — the monotone-enough wall clock the STUN
/// rate limiter's one-second windows run on.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Serve STUN Binding Requests over UDP until the socket errors.
///
/// Binds `state.config.stun_listen`, then loops: receive a datagram, parse it as a Binding Request
/// (`dig_stun::parse_binding_request`), and — on success AND within the response-rate budget — reply
/// with a Binding Success Response (`dig_stun::encode_binding_success`) carrying the sender's
/// reflexive address. A datagram that is not a valid Binding Request is dropped without a reply (a
/// STUN server must never answer a non-STUN packet, and a stateless server ignores requests it
/// doesn't handle). A valid request that exceeds the per-source-IP or global response budget
/// ([`StunRateLimiter`]) is also dropped without a reply, so the relay can never be an unlimited open
/// UDP reflector (SECURITY_AUDIT_P2P dig-relay #2).
pub async fn run(state: Arc<RelayState>) -> std::io::Result<()> {
    // IPv6-first, IPv4-fallback: dual-stack bind (see `crate::net`) so the default `[::]` STUN
    // socket answers both native-IPv6 and IPv4 Binding Requests on the one UDP port.
    let socket = bind_udp_dual_stack(state.config.stun_listen)?;
    tracing::info!(
        addr = %state.config.stun_listen,
        per_ip_rps = state.config.stun_per_ip_responses_per_sec,
        global_rps = state.config.stun_global_responses_per_sec,
        "dig-relay STUN listening (RFC 5389/UDP, rate-limited)"
    );
    let mut limiter = StunRateLimiter::new(
        state.config.stun_per_ip_responses_per_sec,
        state.config.stun_global_responses_per_sec,
        now_ms(),
    );
    // Max STUN message we accept. Requests are tiny; a full MTU-sized buffer is generous.
    let mut buf = [0u8; 1500];
    loop {
        let (n, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "STUN recv failed");
                continue;
            }
        };
        match parse_binding_request(&buf[..n]) {
            Ok(transaction_id) => {
                // Rate-limit BEFORE building/sending the response so an over-budget (possibly spoofed)
                // source produces no outbound datagram at all — the relay never reflects past budget.
                if !limiter.allow(src.ip(), now_ms()) {
                    tracing::trace!(%src, "STUN response suppressed by rate limit");
                    continue;
                }
                // Count answered Binding Requests for the peer-stats dashboard (a rising value confirms
                // NAT'd nodes are learning their reflexive address here). Counted only for responses
                // actually sent — a rate-limited/dropped request never reflects, so it never counts.
                state
                    .stun_requests
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let response = encode_binding_success(&transaction_id, src);
                if let Err(e) = socket.send_to(&response, src).await {
                    tracing::debug!(error = %e, %src, "STUN response send failed");
                }
            }
            Err(err) => {
                tracing::trace!(?err, %src, "ignoring non-Binding-Request datagram");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_stun::{
        parse_binding_response, StunError, TransactionId, BINDING_REQUEST, BINDING_SUCCESS,
        MAGIC_COOKIE,
    };
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    /// A minimal well-formed Binding Request: header only (no attributes), given a transaction id.
    fn binding_request(tid: TransactionId) -> Vec<u8> {
        let mut m = Vec::with_capacity(20);
        m.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes()); // length 0
        m.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        m.extend_from_slice(&tid);
        m
    }

    /// A minimal well-formed Binding SUCCESS response carrying NO attributes at all — used to prove
    /// `parse_binding_response` reports [`StunError::NoMappedAddress`] rather than mis-decoding when
    /// the (XOR-)MAPPED-ADDRESS attribute is simply absent.
    fn binding_success_with_no_attributes(tid: TransactionId) -> Vec<u8> {
        let mut m = Vec::with_capacity(20);
        m.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes()); // length 0: no attributes
        m.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        m.extend_from_slice(&tid);
        m
    }

    const TID: TransactionId = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

    // ---- Codec correctness, now exercised against `dig_stun` (the codec's owner). These are the
    // same properties dig-relay's own local codec used to prove; porting them (rather than deleting
    // them) means a future `dig_stun` regression is still caught here, at the point of use, not only
    // in that crate's own suite. ----

    #[test]
    fn parses_a_well_formed_binding_request() {
        let got = parse_binding_request(&binding_request(TID)).expect("valid request parses");
        assert_eq!(got, TID);
    }

    #[test]
    fn rejects_a_datagram_shorter_than_the_header() {
        assert_eq!(parse_binding_request(&[0u8; 10]), Err(StunError::Truncated));
    }

    #[test]
    fn rejects_a_bad_magic_cookie() {
        let mut m = binding_request(TID);
        m[4] ^= 0xFF; // corrupt the cookie
        assert_eq!(parse_binding_request(&m), Err(StunError::BadMagicCookie));
    }

    /// dig-relay's own (now-deleted) parser reported this as a distinct `NotStun` variant; `dig_stun`
    /// folds it into the same exact-type-match check as "wrong method/class"
    /// ([`StunError::UnexpectedType`]) — a nonzero leading bit changes the 16-bit message-type field
    /// to a value other than [`BINDING_REQUEST`], so it is still rejected, just under one shared
    /// variant instead of two. The server's observable behaviour is identical either way: no reply.
    #[test]
    fn rejects_a_message_with_nonzero_leading_bits() {
        let mut m = binding_request(TID);
        m[0] |= 0x80; // set the top bit → no longer equals BINDING_REQUEST's own encoding
        assert!(matches!(
            parse_binding_request(&m),
            Err(StunError::UnexpectedType(_))
        ));
    }

    #[test]
    fn rejects_a_non_binding_request_message_type() {
        let mut m = binding_request(TID);
        // Turn it into a Binding Success Response (a response, not a request).
        m[0..2].copy_from_slice(&BINDING_SUCCESS.to_be_bytes());
        assert_eq!(
            parse_binding_request(&m),
            Err(StunError::UnexpectedType(BINDING_SUCCESS))
        );
    }

    #[test]
    fn rejects_a_stated_length_that_overruns_the_datagram() {
        let mut m = binding_request(TID);
        // Claim 8 attribute bytes that aren't there.
        m[2..4].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(parse_binding_request(&m), Err(StunError::Truncated));
    }

    #[test]
    fn response_has_the_correct_header_and_echoes_the_transaction_id() {
        let addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 5), 54321));
        let resp = encode_binding_success(&TID, addr);
        // Message type = Binding Success Response.
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), BINDING_SUCCESS);
        // Magic cookie present.
        assert_eq!(
            u32::from_be_bytes([resp[4], resp[5], resp[6], resp[7]]),
            MAGIC_COOKIE
        );
        // Transaction id echoed verbatim.
        assert_eq!(&resp[8..20], &TID);
        // Stated message length matches the actual attribute bytes.
        let stated = u16::from_be_bytes([resp[2], resp[3]]) as usize;
        assert_eq!(stated, resp.len() - 20);
    }

    /// Covers a genuine NATIVE `SocketAddr::V4` input (e.g. an explicit IPv4-only bind — see
    /// `crate::net`, which skips dual-stack setup entirely for an explicit IPv4 address). The
    /// default `[::]` dual-stack listener never hands the encoder this variant for an IPv4 peer; see
    /// [`ipv4_mapped_v6_peer_encodes_identically_to_native_ipv4`] below for the actual production
    /// path (dig-relay#35) — this test alone cannot see a regression there.
    #[test]
    fn native_ipv4_socketaddr_round_trips_through_xor_mapped_address() {
        let addr = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 17), 40000));
        let resp = encode_binding_success(&TID, addr);
        let decoded = parse_binding_response(&resp, Some(&TID)).expect("response decodes cleanly");
        assert_eq!(
            decoded, addr,
            "the client recovers exactly its reflexive addr"
        );
    }

    /// The production fixture (dig-relay#35): the STUN listener binds dual-stack with
    /// `IPV6_V6ONLY=false` (`crate::net`), so `socket.recv_from()` hands back a v4-mapped
    /// `SocketAddr::V6` (`::ffff:a.b.c.d`) for EVERY IPv4-originated datagram — never a native
    /// `SocketAddr::V4`. The property under test is exactly what separates a correct encoder from
    /// the nearest wrong one (dig-relay's own, pre-fix): the SAME real peer must produce the SAME
    /// response regardless of which `SocketAddr` variant the local socket happened to hand it back
    /// in. A test that only builds a literal `SocketAddr::V4` (above) cannot exercise this — that
    /// value is not one `recv_from()` on this socket can ever produce. This is now a standing
    /// regression guard on `dig_stun::encode_binding_success` itself, not a comparison against a
    /// second implementation — the second implementation is exactly what this adoption removes.
    #[test]
    fn ipv4_mapped_v6_peer_encodes_identically_to_native_ipv4() {
        let v4 = Ipv4Addr::new(198, 51, 100, 17);
        let port = 40000;
        let native = SocketAddr::from((v4, port));
        let mapped = SocketAddr::from((v4.to_ipv6_mapped(), port));
        assert!(
            mapped.is_ipv6(),
            "fixture sanity: this must really be a V6 SocketAddr, matching what recv_from() returns"
        );

        let native_resp = encode_binding_success(&TID, native);
        let mapped_resp = encode_binding_success(&TID, mapped);
        assert_eq!(
            native_resp, mapped_resp,
            "a v4-mapped V6 peer and the equivalent native V4 peer must produce byte-identical \
             responses — the local socket's representation is not part of the peer's identity"
        );
        assert_eq!(
            mapped_resp.len(),
            32,
            "an IPv4-family response is header(20)+attr-header(4)+value(8) = 32 bytes — a 44-byte \
             (IPv6-family) response here would mean the peer was tagged the wrong family"
        );

        let decoded =
            parse_binding_response(&mapped_resp, Some(&TID)).expect("response decodes cleanly");
        assert!(
            decoded.is_ipv4(),
            "a same-family IPv4 peer must decode back to an IPv4 SocketAddr, never IPv6"
        );
        assert_eq!(
            decoded, native,
            "the client recovers the real IPv4 address+port, never the ::ffff:-wrapped form"
        );
    }

    #[test]
    fn ipv6_reflexive_address_round_trips_through_xor_mapped_address() {
        let addr = SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1234), 41234));
        let resp = encode_binding_success(&TID, addr);
        let decoded = parse_binding_response(&resp, Some(&TID)).expect("response decodes cleanly");
        assert_eq!(
            decoded, addr,
            "IPv6 reflexive addr round-trips (uses tid in the XOR key)"
        );
    }

    #[test]
    fn xor_mapped_address_actually_obfuscates_the_port() {
        // The X-Port must differ from the raw port (proves the XOR is applied, per RFC 5389 §15.2).
        // `encode_binding_success` writes exactly one attribute (XOR-MAPPED-ADDRESS) as the first and
        // only attribute, so its value begins right after the 20-byte header + 4-byte attribute TLV
        // header, at a fixed offset: reserved(1) + family(1) then X-Port at bytes [26..28).
        let addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 1), 0x1234));
        let resp = encode_binding_success(&TID, addr);
        let xport = u16::from_be_bytes([resp[26], resp[27]]);
        assert_ne!(xport, 0x1234, "the port is XOR-obfuscated, not raw");
        assert_eq!(xport, 0x1234 ^ (MAGIC_COOKIE >> 16) as u16);
    }

    #[test]
    fn parse_binding_response_reports_no_mapped_address_when_none_is_present() {
        // A Binding Success response with no attributes at all has no (XOR-)MAPPED-ADDRESS to find.
        assert_eq!(
            parse_binding_response(&binding_success_with_no_attributes(TID), Some(&TID)),
            Err(StunError::NoMappedAddress)
        );
    }

    /// The response never amplifies beyond a small class bound: a Binding Success Response must be a
    /// bounded multiple of the minimal 20-byte request, never a large amplification (this is what
    /// keeps a rate-limited reflector from also being an amplifier). IPv4 = 32 bytes, IPv6 = 44.
    #[test]
    fn response_size_is_a_small_bounded_multiple_of_the_request() {
        let req_len = binding_request(TID).len(); // 20 (minimal)
        let v4 = encode_binding_success(&TID, SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), 5)));
        let v6 = encode_binding_success(
            &TID,
            SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 5)),
        );
        assert_eq!(v4.len(), 32, "IPv4 response is header(20)+attr(12)");
        assert_eq!(v6.len(), 44, "IPv6 response is header(20)+attr(24)");
        // Amplification factor stays under ~2.5x even against the smallest possible request.
        assert!((v6.len() as f64) / (req_len as f64) < 2.5);
    }

    // ---- STUN rate limiter (SECURITY_AUDIT_P2P dig-relay #2) — genuinely dig-relay's own, and
    // untouched by the codec adoption above. ----

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// A single source IP is capped at its per-second budget; the (N+1)th response in the same second
    /// is denied — the relay stops reflecting toward that (spoofable) address once the budget is spent.
    #[test]
    fn per_ip_budget_caps_a_single_source_within_one_second() {
        let mut rl = StunRateLimiter::new(3, 1000, 0);
        let victim = ip("203.0.113.7");
        // 3 allowed in the window [0,1000).
        assert!(rl.allow(victim, 10));
        assert!(rl.allow(victim, 20));
        assert!(rl.allow(victim, 30));
        // 4th within the same second is denied.
        assert!(!rl.allow(victim, 40), "over per-IP budget must be denied");
    }

    /// The per-IP budget refills each new one-second window.
    #[test]
    fn per_ip_budget_refills_next_second() {
        let mut rl = StunRateLimiter::new(2, 1000, 0);
        let a = ip("198.51.100.9");
        assert!(rl.allow(a, 0));
        assert!(rl.allow(a, 100));
        assert!(!rl.allow(a, 200), "budget spent this second");
        // Next second → refilled.
        assert!(rl.allow(a, 1000));
        assert!(rl.allow(a, 1100));
    }

    /// Distinct source IPs have independent per-IP budgets (one throttled IP does not starve others),
    /// but the GLOBAL cap still bounds the total across all of them.
    #[test]
    fn global_cap_bounds_total_across_sources() {
        // Generous per-IP (so per-IP never trips) but a global cap of 2/sec.
        let mut rl = StunRateLimiter::new(100, 2, 0);
        assert!(rl.allow(ip("203.0.113.1"), 0));
        assert!(rl.allow(ip("203.0.113.2"), 0));
        // Third distinct source in the same second is denied by the GLOBAL cap.
        assert!(
            !rl.allow(ip("203.0.113.3"), 0),
            "global cap must bound the aggregate"
        );
        // Global refills next second.
        assert!(rl.allow(ip("203.0.113.3"), 1000));
    }

    /// A per-IP rejection must NOT consume a global token (so one flooding IP can't drain the global
    /// budget and deny service to everyone else).
    #[test]
    fn a_per_ip_rejection_does_not_consume_global_budget() {
        let mut rl = StunRateLimiter::new(1, 5, 0);
        let flooder = ip("203.0.113.9");
        assert!(rl.allow(flooder, 0)); // spends flooder's only per-IP token (+1 global)
        assert!(!rl.allow(flooder, 1)); // per-IP denied — must not touch global
        assert!(!rl.allow(flooder, 2)); // still denied
                                        // Four other distinct IPs should still each get a response (global had 5, only 1 spent).
        for i in 1..=4u8 {
            assert!(
                rl.allow(ip(&format!("198.51.100.{i}")), 3),
                "other IPs keep their global share"
            );
        }
    }

    /// IPv4-mapped IPv6 and plain IPv4 for the same address share ONE budget (a client can't double
    /// its allowance by switching families on the dual-stack socket).
    #[test]
    fn ipv4_mapped_and_plain_ipv4_share_one_budget() {
        let mut rl = StunRateLimiter::new(1, 1000, 0);
        let plain = ip("203.0.113.5");
        let mapped = ip("::ffff:203.0.113.5");
        assert!(rl.allow(plain, 0));
        assert!(
            !rl.allow(mapped, 1),
            "the IPv4-mapped form must not get a second budget"
        );
    }

    /// A `0` capacity disables that dimension (limit off).
    #[test]
    fn zero_capacity_disables_a_dimension() {
        // per-IP disabled, global 1/sec.
        let mut rl = StunRateLimiter::new(0, 1, 0);
        let a = ip("203.0.113.1");
        assert!(rl.allow(a, 0));
        assert!(!rl.allow(ip("203.0.113.2"), 0), "global still enforced");
        // Both disabled → always allowed.
        let mut open = StunRateLimiter::new(0, 0, 0);
        for i in 0..100 {
            assert!(open.allow(a, i));
        }
    }

    /// The per-IP bucket map is LRU-bounded so a flood of forged source IPs cannot grow the limiter's
    /// own state without limit (the limiter must not itself be a memory-exhaustion vector).
    #[test]
    fn per_ip_map_is_bounded_under_a_flood_of_distinct_ips() {
        let mut rl = StunRateLimiter::new(1, u32::MAX, 0);
        // Feed many more distinct IPs than the cap; the map must never exceed MAX_TRACKED_IPS.
        for i in 0..(MAX_TRACKED_IPS as u64 + 5000) {
            let a = i & 0xFF;
            let b = (i >> 8) & 0xFF;
            let c = (i >> 16) & 0xFF;
            let d = (i >> 24) & 0xFF;
            let addr = IpAddr::from(Ipv6Addr::new(
                0x2001, 0xdb8, a as u16, b as u16, c as u16, d as u16, 0, 1,
            ));
            rl.allow(addr, i);
            assert!(
                rl.per_ip.len() <= MAX_TRACKED_IPS,
                "per-IP map must stay bounded"
            );
        }
    }
}
