//! STUN server (RFC 5389 Binding) — lets a DIG Node learn its public reflexive address.
//!
//! A DIG Node behind NAT needs to know the `IP:port` the outside world sees for it (its
//! *server-reflexive* address) before it can advertise a useful candidate for hole-punching
//! (RLY-007, supplied as the `external_addr`) or peer exchange. Classic STUN answers exactly that: the
//! node sends a **Binding Request** to a public STUN server over UDP, and the server replies with a
//! **Binding Success Response** carrying an **XOR-MAPPED-ADDRESS** attribute — the source address of
//! the request as observed by the server.
//!
//! This module implements the SERVER side of RFC 5389 (§6 message format, §15.2 XOR-MAPPED-ADDRESS).
//! It is intentionally minimal: the only request type it answers is the Binding Request; every other
//! well-formed request gets nothing (silently ignored, per the RFC's "unknown method" latitude for a
//! stateless server) and a malformed datagram is rejected without a reply. The relay does not do
//! authentication, `FINGERPRINT`, `SOFTWARE`, or the deprecated (non-XOR) MAPPED-ADDRESS — a DIG Node
//! only needs its reflexive address, and every modern STUN client reads XOR-MAPPED-ADDRESS.
//!
//! Layering mirrors the rest of the crate: the codec ([`parse_binding_request`],
//! [`build_binding_response`]) is PURE and fully unit-tested; [`run`] is the thin UDP serve loop that
//! wires the codec to a socket. The STUN listener binds its own UDP port ([`crate::config`]
//! `stun_listen`, default `[::]:3478` = the IANA-assigned STUN port, matching the DIG node
//! peer-network protocol) alongside the WebSocket (9450) and health (9451) listeners, dual-stack
//! (see [`crate::net`]) so it answers both IPv6 and IPv4 Binding Requests on the one socket.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::net::bind_udp_dual_stack;
use crate::server::RelayState;

/// Hard cap on the number of distinct source IPs the [`StunRateLimiter`] tracks at once. A STUN
/// server answers spoofable, unauthenticated datagrams, so the per-IP bucket map is itself an
/// attacker-controlled data structure: without a bound, a flood of forged source IPs would grow it
/// without limit (a memory-exhaustion vector). When the map is full and an unseen IP arrives, the
/// limiter evicts the least-recently-seen bucket. 65_536 buckets is far more than any legitimate
/// concurrent client population and is tiny in memory (~a few MiB).
const MAX_TRACKED_IPS: usize = 65_536;

/// The STUN magic cookie (RFC 5389 §6): a fixed 32-bit value in bytes 4..8 of every STUN message.
/// Its top 16 bits also key the XOR of XOR-MAPPED-ADDRESS.
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

/// STUN method+class values we handle (RFC 5389 §6, message-type field).
/// The 14-bit message type encodes a method + a class; for Binding these are:
pub mod msgtype {
    /// Binding Request (method Binding = 0x001, class Request = 0b00).
    pub const BINDING_REQUEST: u16 = 0x0001;
    /// Binding Success Response (method Binding = 0x001, class Success Response = 0b10).
    pub const BINDING_SUCCESS_RESPONSE: u16 = 0x0101;
}

/// STUN attribute type values (RFC 5389 §18.2).
pub mod attr {
    /// XOR-MAPPED-ADDRESS (RFC 5389 §15.2) — the reflexive address, XOR-obfuscated.
    pub const XOR_MAPPED_ADDRESS: u16 = 0x0020;
}

/// Address family byte inside a (XOR-)MAPPED-ADDRESS attribute (RFC 5389 §15.1).
mod family {
    pub const IPV4: u8 = 0x01;
    pub const IPV6: u8 = 0x02;
}

/// The fixed STUN header length in bytes (RFC 5389 §6).
const HEADER_LEN: usize = 20;

/// The 96-bit transaction id that ties a STUN response to its request (RFC 5389 §6).
///
/// The server echoes the request's transaction id back verbatim in the response, and — together
/// with the magic cookie — it is the key material for the XOR-MAPPED-ADDRESS obfuscation.
pub type TransactionId = [u8; 12];

/// A parsed, validated STUN Binding Request: just the transaction id (the only field the server
/// needs to echo). Produced by [`parse_binding_request`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingRequest {
    /// The request's 96-bit transaction id, echoed verbatim in the response.
    pub transaction_id: TransactionId,
}

/// Why a datagram was rejected as not a STUN Binding Request. Catalogued (like the relay's
/// [`crate::server::errcode`]) so behaviour is documented, not guessed. A rejected datagram gets NO
/// reply (a STUN server must never answer a non-STUN packet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StunError {
    /// Fewer than the 20 header bytes, or the stated attribute length overruns the datagram.
    Truncated,
    /// Bytes 4..8 are not the STUN magic cookie — not a STUN message.
    BadMagicCookie,
    /// The two most-significant bits of byte 0 are not zero (not a STUN message per §6).
    NotStun,
    /// A valid STUN message, but not a Binding Request (e.g. a response, or another method). The
    /// stateless server simply ignores these.
    NotBindingRequest,
}

/// Parse and validate a datagram as a STUN **Binding Request** (RFC 5389 §6, §7.3).
///
/// Checks, in order: the two leading zero bits (STUN marker), the 20-byte minimum, the magic
/// cookie, the message type (must be Binding Request), and that the declared message length does not
/// overrun the datagram. Returns the transaction id on success. PURE — no I/O — so it is exhaustively
/// unit-testable.
pub fn parse_binding_request(datagram: &[u8]) -> Result<BindingRequest, StunError> {
    if datagram.len() < HEADER_LEN {
        return Err(StunError::Truncated);
    }
    // RFC 5389 §6: the most-significant two bits of a STUN message MUST be zero.
    if datagram[0] & 0xC0 != 0 {
        return Err(StunError::NotStun);
    }
    let message_type = u16::from_be_bytes([datagram[0], datagram[1]]);
    let message_length = u16::from_be_bytes([datagram[2], datagram[3]]) as usize;
    let cookie = u32::from_be_bytes([datagram[4], datagram[5], datagram[6], datagram[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(StunError::BadMagicCookie);
    }
    // The stated length must not claim more attribute bytes than the datagram actually carries.
    if HEADER_LEN + message_length > datagram.len() {
        return Err(StunError::Truncated);
    }
    if message_type != msgtype::BINDING_REQUEST {
        return Err(StunError::NotBindingRequest);
    }

    let mut transaction_id = [0u8; 12];
    transaction_id.copy_from_slice(&datagram[8..20]);
    Ok(BindingRequest { transaction_id })
}

/// Build a STUN **Binding Success Response** carrying the XOR-MAPPED-ADDRESS of `reflexive`
/// (RFC 5389 §6, §15.2).
///
/// `reflexive` is the address the server observed the request come FROM — i.e. the client's public
/// reflexive address. The response echoes `transaction_id` and contains exactly one attribute
/// (XOR-MAPPED-ADDRESS). PURE — returns the bytes to send — so the encoding is unit-testable.
pub fn build_binding_response(transaction_id: &TransactionId, reflexive: SocketAddr) -> Vec<u8> {
    let attr_value = xor_mapped_address_value(transaction_id, reflexive);
    let attr_len = attr_value.len();
    // Message length = attribute header (4) + attribute value. STUN attributes are 4-byte aligned;
    // our value is already a multiple of 4 (IPv4 = 8, IPv6 = 20), so no padding is needed.
    let message_length = (4 + attr_len) as u16;

    let mut out = Vec::with_capacity(HEADER_LEN + 4 + attr_len);
    out.extend_from_slice(&msgtype::BINDING_SUCCESS_RESPONSE.to_be_bytes());
    out.extend_from_slice(&message_length.to_be_bytes());
    out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(transaction_id);
    // XOR-MAPPED-ADDRESS attribute: type, length, value.
    out.extend_from_slice(&attr::XOR_MAPPED_ADDRESS.to_be_bytes());
    out.extend_from_slice(&(attr_len as u16).to_be_bytes());
    out.extend_from_slice(&attr_value);
    out
}

/// Encode the VALUE of an XOR-MAPPED-ADDRESS attribute (RFC 5389 §15.2): the reserved byte, the
/// address family, the X-Port, and the X-Address.
///
/// - X-Port = port XOR the 16 most-significant bits of the magic cookie.
/// - X-Address (IPv4) = address XOR the magic cookie.
/// - X-Address (IPv6) = address XOR (magic cookie ‖ transaction id).
fn xor_mapped_address_value(transaction_id: &TransactionId, addr: SocketAddr) -> Vec<u8> {
    let xport = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;
    match addr {
        SocketAddr::V4(v4) => {
            let mut value = Vec::with_capacity(8);
            value.push(0x00); // reserved
            value.push(family::IPV4);
            value.extend_from_slice(&xport.to_be_bytes());
            let xaddr = u32::from(*v4.ip()) ^ MAGIC_COOKIE;
            value.extend_from_slice(&xaddr.to_be_bytes());
            value
        }
        SocketAddr::V6(v6) => {
            let mut value = Vec::with_capacity(20);
            value.push(0x00); // reserved
            value.push(family::IPV6);
            value.extend_from_slice(&xport.to_be_bytes());
            // XOR key for IPv6 = magic cookie (4 bytes) followed by the 12-byte transaction id.
            let mut key = [0u8; 16];
            key[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            key[4..16].copy_from_slice(transaction_id);
            let addr_bytes = v6.ip().octets();
            let xaddr: Vec<u8> = addr_bytes
                .iter()
                .zip(key.iter())
                .map(|(a, k)| a ^ k)
                .collect();
            value.extend_from_slice(&xaddr);
            value
        }
    }
}

/// Decode an XOR-MAPPED-ADDRESS attribute value back into a `SocketAddr` (RFC 5389 §15.2).
///
/// This is the client-side reverse of [`xor_mapped_address_value`]; the server never needs it, but
/// it is the natural way to unit-test that the server encoded a recoverable address, so it lives here
/// (and is available to any in-crate STUN client/test). Returns `None` on a malformed value.
pub fn decode_xor_mapped_address(
    transaction_id: &TransactionId,
    value: &[u8],
) -> Option<SocketAddr> {
    if value.len() < 4 {
        return None;
    }
    let fam = value[1];
    let xport = u16::from_be_bytes([value[2], value[3]]);
    let port = xport ^ (MAGIC_COOKIE >> 16) as u16;
    match fam {
        family::IPV4 => {
            if value.len() < 8 {
                return None;
            }
            let xaddr = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
            let ip = Ipv4Addr::from(xaddr ^ MAGIC_COOKIE);
            Some(SocketAddr::from((ip, port)))
        }
        family::IPV6 => {
            if value.len() < 20 {
                return None;
            }
            let mut key = [0u8; 16];
            key[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            key[4..16].copy_from_slice(transaction_id);
            let mut octets = [0u8; 16];
            for (i, o) in octets.iter_mut().enumerate() {
                *o = value[4 + i] ^ key[i];
            }
            Some(SocketAddr::from((Ipv6Addr::from(octets), port)))
        }
        _ => None,
    }
}

/// Locate the XOR-MAPPED-ADDRESS attribute value inside a STUN message (walks the TLV attribute
/// list). Server never needs this; it exists so tests (and any in-crate client) can read a response.
/// Returns `None` if the attribute is absent or the message is malformed.
pub fn find_xor_mapped_address(message: &[u8]) -> Option<&[u8]> {
    if message.len() < HEADER_LEN {
        return None;
    }
    let mut offset = HEADER_LEN;
    while offset + 4 <= message.len() {
        let attr_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let attr_len = u16::from_be_bytes([message[offset + 2], message[offset + 3]]) as usize;
        let value_start = offset + 4;
        let value_end = value_start + attr_len;
        if value_end > message.len() {
            return None;
        }
        if attr_type == attr::XOR_MAPPED_ADDRESS {
            return Some(&message[value_start..value_end]);
        }
        // Attributes are padded to a 4-byte boundary.
        offset = value_start + attr_len.div_ceil(4) * 4;
    }
    None
}

/// Per-source token bucket: a whole-token count refilled to `capacity` once per one-second window.
///
/// A fixed one-second refill window (rather than continuous drip) keeps the arithmetic integer-only
/// and trivially testable, while still bounding the sustained rate to `capacity` responses/second.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Tokens remaining in the current window.
    tokens: u32,
    /// The one-second window this bucket's `tokens` belong to (`now_ms / 1000`).
    window: u64,
    /// Last time (ms) this bucket was touched — used for LRU eviction when the map is full.
    last_seen_ms: u64,
}

impl Bucket {
    fn new(capacity: u32, now_ms: u64) -> Self {
        Bucket {
            tokens: capacity,
            window: now_ms / 1000,
            last_seen_ms: now_ms,
        }
    }

    /// Try to spend one token in the window containing `now_ms`, refilling to `capacity` at each new
    /// one-second window. Returns `true` if a token was available (the caller may respond).
    fn try_spend(&mut self, capacity: u32, now_ms: u64) -> bool {
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
    per_ip: HashMap<IpAddr, Bucket>,
    global: Bucket,
}

impl StunRateLimiter {
    fn new(per_ip_capacity: u32, global_capacity: u32, now_ms: u64) -> Self {
        StunRateLimiter {
            per_ip_capacity,
            global_capacity,
            per_ip: HashMap::new(),
            // The global bucket starts full for the current window regardless of whether it is used.
            global: Bucket::new(global_capacity.max(1), now_ms),
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
    fn bucket_for(&mut self, key: IpAddr, now_ms: u64) -> &mut Bucket {
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
            .or_insert_with(|| Bucket::new(self.per_ip_capacity.max(1), now_ms))
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
/// Binds `state.config.stun_listen`, then loops: receive a datagram, parse it as a Binding Request,
/// and — on success AND within the response-rate budget — reply with a Binding Success Response
/// carrying the sender's reflexive address. A datagram that is not a valid Binding Request is dropped
/// without a reply (a STUN server must never answer a non-STUN packet, and a stateless server ignores
/// requests it doesn't handle). A valid request that exceeds the per-source-IP or global response
/// budget ([`StunRateLimiter`]) is also dropped without a reply, so the relay can never be an
/// unlimited open UDP reflector (SECURITY_AUDIT_P2P dig-relay #2).
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
            Ok(req) => {
                // Rate-limit BEFORE building/sending the response so an over-budget (possibly spoofed)
                // source produces no outbound datagram at all — the relay never reflects past budget.
                if !limiter.allow(src.ip(), now_ms()) {
                    tracing::trace!(%src, "STUN response suppressed by rate limit");
                    continue;
                }
                let response = build_binding_response(&req.transaction_id, src);
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
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// A minimal well-formed Binding Request: header only (no attributes), given a transaction id.
    fn binding_request(tid: TransactionId) -> Vec<u8> {
        let mut m = Vec::with_capacity(HEADER_LEN);
        m.extend_from_slice(&msgtype::BINDING_REQUEST.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes()); // length 0
        m.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        m.extend_from_slice(&tid);
        m
    }

    const TID: TransactionId = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

    #[test]
    fn parses_a_well_formed_binding_request() {
        let got = parse_binding_request(&binding_request(TID)).expect("valid request parses");
        assert_eq!(got.transaction_id, TID);
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

    #[test]
    fn rejects_a_message_with_nonzero_leading_bits() {
        let mut m = binding_request(TID);
        m[0] |= 0x80; // set the top bit → not a STUN message
        assert_eq!(parse_binding_request(&m), Err(StunError::NotStun));
    }

    #[test]
    fn rejects_a_non_binding_request_message_type() {
        let mut m = binding_request(TID);
        // Turn it into a Binding Success Response (a response, not a request).
        m[0..2].copy_from_slice(&msgtype::BINDING_SUCCESS_RESPONSE.to_be_bytes());
        assert_eq!(parse_binding_request(&m), Err(StunError::NotBindingRequest));
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
        let resp = build_binding_response(&TID, addr);
        // Message type = Binding Success Response.
        assert_eq!(
            u16::from_be_bytes([resp[0], resp[1]]),
            msgtype::BINDING_SUCCESS_RESPONSE
        );
        // Magic cookie present.
        assert_eq!(
            u32::from_be_bytes([resp[4], resp[5], resp[6], resp[7]]),
            MAGIC_COOKIE
        );
        // Transaction id echoed verbatim.
        assert_eq!(&resp[8..20], &TID);
        // Stated message length matches the actual attribute bytes.
        let stated = u16::from_be_bytes([resp[2], resp[3]]) as usize;
        assert_eq!(stated, resp.len() - HEADER_LEN);
    }

    #[test]
    fn ipv4_reflexive_address_round_trips_through_xor_mapped_address() {
        let addr = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 17), 40000));
        let resp = build_binding_response(&TID, addr);
        let value = find_xor_mapped_address(&resp).expect("response carries XOR-MAPPED-ADDRESS");
        let decoded = decode_xor_mapped_address(&TID, value).expect("value decodes");
        assert_eq!(
            decoded, addr,
            "the client recovers exactly its reflexive addr"
        );
    }

    #[test]
    fn ipv6_reflexive_address_round_trips_through_xor_mapped_address() {
        let addr = SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1234), 41234));
        let resp = build_binding_response(&TID, addr);
        let value = find_xor_mapped_address(&resp).expect("response carries XOR-MAPPED-ADDRESS");
        let decoded = decode_xor_mapped_address(&TID, value).expect("value decodes");
        assert_eq!(
            decoded, addr,
            "IPv6 reflexive addr round-trips (uses tid in the XOR key)"
        );
    }

    #[test]
    fn xor_mapped_address_actually_obfuscates_the_port() {
        // The X-Port must differ from the raw port (proves the XOR is applied, per RFC 5389 §15.2).
        let addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 1), 0x1234));
        let resp = build_binding_response(&TID, addr);
        let value = find_xor_mapped_address(&resp).unwrap();
        let xport = u16::from_be_bytes([value[2], value[3]]);
        assert_ne!(xport, 0x1234, "the port is XOR-obfuscated, not raw");
        assert_eq!(xport, 0x1234 ^ (MAGIC_COOKIE >> 16) as u16);
    }

    #[test]
    fn find_xor_mapped_address_returns_none_when_absent() {
        // A bare header with no attributes has no XOR-MAPPED-ADDRESS.
        assert!(find_xor_mapped_address(&binding_request(TID)).is_none());
    }

    // ---- STUN rate limiter (SECURITY_AUDIT_P2P dig-relay #2) ----

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The response never amplifies beyond a small class bound: a Binding Success Response must be a
    /// bounded multiple of the minimal 20-byte request, never a large amplification (this is what
    /// keeps a rate-limited reflector from also being an amplifier). IPv4 = 32 bytes, IPv6 = 44.
    #[test]
    fn response_size_is_a_small_bounded_multiple_of_the_request() {
        let req_len = binding_request(TID).len(); // 20 (minimal)
        let v4 = build_binding_response(&TID, SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), 5)));
        let v6 = build_binding_response(
            &TID,
            SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 5)),
        );
        assert_eq!(v4.len(), 32, "IPv4 response is header(20)+attr(12)");
        assert_eq!(v6.len(), 44, "IPv6 response is header(20)+attr(24)");
        // Amplification factor stays under ~2.5x even against the smallest possible request.
        assert!((v6.len() as f64) / (req_len as f64) < 2.5);
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
