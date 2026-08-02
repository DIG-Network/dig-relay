//! PROXY protocol v2 — recovering each peer's REAL source address from behind a TLS-terminating
//! load balancer (dig_ecosystem #1930).
//!
//! The canonical `relay.dig.net` deployment sits behind an internet-facing AWS NLB whose peer
//! listener is `443 TLS`. A TLS-terminating NLB opens a FRESH connection to the target, so the
//! client's address is structurally gone by the time `accept()` returns: every peer on earth
//! arrives with the load balancer's own address as its source. AWS's `preserve_client_ip` cannot
//! help — it is unsupported on a TLS listener — but Proxy Protocol v2 is, and it is what this
//! module parses.
//!
//! The consequences of NOT having this are not cosmetic. The relay's observed source address feeds
//! [`crate::dial::resolve_dialable`], so every peer gets advertised to every other peer at the load
//! balancer's address and direct dialling can never succeed (#1929); it feeds `/map`, which then
//! plots the whole network in one place; and it keys every per-IP limit in
//! [`crate::limits`] — connection caps, registration rate, the ban list — so the entire network
//! shares one bucket.
//!
//! # Why the header is only trusted from a configured proxy
//!
//! A PROXY header is just bytes the connecting party sends: whoever writes it declares their own
//! source address. Trusting it unconditionally would let anyone who can reach the relay's port
//! directly — and the relay's task security group is open to `0.0.0.0/0` — forge an arbitrary
//! source IP, evade a ban, and poison the map. So the header is honoured ONLY when the connection's
//! REAL peer address falls inside an operator-configured trusted-proxy CIDR
//! ([`TrustedProxies`]). With no CIDRs configured the relay never reads a header at all and its
//! behaviour is byte-for-byte what it was before this module existed — the safe default, and the
//! one that makes enabling this a deliberate act.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

/// The 12-byte v2 signature every PROXY protocol v2 header opens with. Chosen by the spec so it can
/// never be confused with a real protocol's first bytes — notably a TLS ClientHello starts `0x16`.
const V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// The fixed part of a v2 header: 12 signature + 1 version/command + 1 family/protocol + 2 length.
const V2_FIXED_LEN: usize = 16;

/// Upper bound on the variable address block we will read. The spec allows up to 65535, but the
/// address blocks we accept are at most 36 bytes (TCP over IPv6) plus optional TLVs. Capping the
/// read keeps a malicious-but-trusted proxy from making us buffer 64 KiB per connection.
const MAX_ADDRESS_BLOCK: usize = 1024;

/// v2 `PROXY` command: the address block describes the ORIGINAL client.
const CMD_PROXY: u8 = 0x01;
/// v2 `LOCAL` command: the connection is the proxy's own (a health check), with no client to report.
const CMD_LOCAL: u8 = 0x00;

/// Address family + transport byte for TCP over IPv4.
const AF_TCP4: u8 = 0x11;
/// Address family + transport byte for TCP over IPv6.
const AF_TCP6: u8 = 0x21;

/// What the bytes at the head of a connection turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Header {
    /// A `PROXY` header carrying the original client's address.
    Proxy(SocketAddr),
    /// A well-formed header with nothing to report — a `LOCAL` command (the load balancer's own
    /// health check) or an address family we do not translate (UNSPEC/UNIX). The connection is
    /// real; it simply keeps its observed source address.
    NoSource,
}

/// Why a byte sequence was not usable as a v2 header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    /// The signature did not match — this is not PROXY protocol at all, and the bytes belong to the
    /// payload (a TLS ClientHello, say). Not an error condition: the caller replays the bytes.
    NotProxyProtocol,
    /// The signature matched but the rest did not parse: an unsupported version, a truncated
    /// address block, or a length that disagrees with the declared family.
    Malformed,
}

/// Parse the FIXED 16 bytes of a v2 header, returning the declared length of the address block that
/// follows. Split from [`parse_address_block`] because the caller must read the fixed part before it
/// can know how many more bytes to read.
///
/// # Errors
/// [`HeaderError::NotProxyProtocol`] when the signature does not match (the common, benign case);
/// [`HeaderError::Malformed`] for a matching signature with an unsupported version or command.
pub fn parse_fixed(fixed: &[u8; V2_FIXED_LEN]) -> Result<(u8, usize), HeaderError> {
    if fixed[..12] != V2_SIGNATURE {
        return Err(HeaderError::NotProxyProtocol);
    }
    // High nibble is the protocol version and MUST be 2; low nibble is the command.
    let ver_cmd = fixed[12];
    if ver_cmd >> 4 != 2 {
        return Err(HeaderError::Malformed);
    }
    match ver_cmd & 0x0F {
        CMD_PROXY | CMD_LOCAL => {}
        _ => return Err(HeaderError::Malformed),
    }
    let len = u16::from_be_bytes([fixed[14], fixed[15]]) as usize;
    if len > MAX_ADDRESS_BLOCK {
        return Err(HeaderError::Malformed);
    }
    Ok((ver_cmd, len))
}

/// Parse the variable address block that follows the fixed header, yielding the original client's
/// address for a `PROXY` command over TCP.
///
/// A `LOCAL` command, or a family we do not translate, resolves to [`Header::NoSource`] — the
/// connection is legitimate and simply keeps the address the relay observed.
///
/// # Errors
/// [`HeaderError::Malformed`] when the block is shorter than the declared family requires.
pub fn parse_address_block(ver_cmd: u8, family: u8, block: &[u8]) -> Result<Header, HeaderError> {
    if ver_cmd & 0x0F == CMD_LOCAL {
        return Ok(Header::NoSource);
    }
    match family {
        AF_TCP4 => {
            // 4 src + 4 dst + 2 src_port + 2 dst_port. Trailing bytes are TLVs; ignored.
            if block.len() < 12 {
                return Err(HeaderError::Malformed);
            }
            let ip = Ipv4Addr::new(block[0], block[1], block[2], block[3]);
            let port = u16::from_be_bytes([block[8], block[9]]);
            Ok(Header::Proxy(SocketAddr::from((ip, port))))
        }
        AF_TCP6 => {
            // 16 src + 16 dst + 2 src_port + 2 dst_port. Trailing bytes are TLVs; ignored.
            if block.len() < 36 {
                return Err(HeaderError::Malformed);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&block[..16]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([block[32], block[33]]);
            Ok(Header::Proxy(SocketAddr::from((ip, port))))
        }
        // UNSPEC (0x00) and the UNIX-socket families carry nothing we can map to an IP peer.
        _ => Ok(Header::NoSource),
    }
}

/// A single CIDR block, used to decide whether a connection came from a proxy whose PROXY header we
/// are willing to believe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    base: IpAddr,
    prefix_len: u8,
}

impl Cidr {
    /// Parse `ADDR/PREFIX`, or a bare address (treated as a host route: `/32` for v4, `/128` for v6).
    ///
    /// # Errors
    /// A string that is not an IP address, or whose prefix length exceeds the family's width.
    pub fn parse(s: &str) -> Result<Cidr, String> {
        let (addr_part, prefix_part) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let base: IpAddr = addr_part
            .trim()
            .parse()
            .map_err(|_| format!("not an IP address: {addr_part}"))?;
        let max = if base.is_ipv4() { 32 } else { 128 };
        let prefix_len = match prefix_part {
            None => max,
            Some(p) => p
                .trim()
                .parse::<u8>()
                .map_err(|_| format!("not a prefix length: {p}"))?,
        };
        if prefix_len > max {
            return Err(format!("prefix /{prefix_len} exceeds /{max} for {base}"));
        }
        Ok(Cidr { base, prefix_len })
    }

    /// Whether `ip` falls inside this block. An IPv4-mapped IPv6 address is canonicalized first, so
    /// a dual-stack listener matches a v4 CIDR the same either way (§5.2).
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.base, ip.to_canonical()) {
            (IpAddr::V4(base), IpAddr::V4(ip)) => {
                prefix_matches(&base.octets(), &ip.octets(), self.prefix_len)
            }
            (IpAddr::V6(base), IpAddr::V6(ip)) => {
                prefix_matches(&base.octets(), &ip.octets(), self.prefix_len)
            }
            _ => false,
        }
    }
}

/// Whether `a` and `b` agree on their first `prefix_len` BITS.
fn prefix_matches(a: &[u8], b: &[u8], prefix_len: u8) -> bool {
    let whole_bytes = (prefix_len / 8) as usize;
    if a[..whole_bytes] != b[..whole_bytes] {
        return false;
    }
    let remaining_bits = prefix_len % 8;
    if remaining_bits == 0 {
        return true;
    }
    // Compare only the high `remaining_bits` of the next byte.
    let mask = 0xFFu8 << (8 - remaining_bits);
    a[whole_bytes] & mask == b[whole_bytes] & mask
}

/// The set of proxies whose PROXY header the relay will believe. EMPTY means trust nobody, which is
/// the default and which makes [`read_source_addr`] a no-op — see the module docs on why that is the
/// safe default rather than a missing feature.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies(Vec<Cidr>);

impl TrustedProxies {
    /// Parse a comma-separated CIDR list (`10.0.0.0/8, 2600:1f18::/32`). An empty or
    /// whitespace-only string yields an empty set.
    ///
    /// # Errors
    /// The first entry that is not a valid CIDR, naming it — a typo in this setting silently
    /// widening or narrowing who can forge a source IP is exactly what must not happen quietly.
    pub fn parse(list: &str) -> Result<TrustedProxies, String> {
        let cidrs = list
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(Cidr::parse)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(TrustedProxies(cidrs))
    }

    /// Whether a PROXY header arriving from `ip` should be believed.
    pub fn trusts(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|c| c.contains(ip))
    }

    /// Whether no proxy is trusted — the default, in which the relay never reads a PROXY header.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A stream with some already-read bytes put back in front of it.
///
/// Needed because deciding "is this PROXY protocol?" requires reading the first bytes, and when the
/// answer is no those bytes are the payload's own (a TLS ClientHello) and must reach the next layer
/// intact.
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    consumed: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    /// Wrap `inner`, replaying `prefix` before any byte read from `inner` itself.
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        PrefixedStream {
            prefix,
            consumed: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let pending = &this.prefix[this.consumed..];
        if !pending.is_empty() {
            let n = pending.len().min(buf.remaining());
            buf.put_slice(&pending[..n]);
            this.consumed += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Read a PROXY protocol v2 header from `stream` if one is there, returning the original client
/// address it declares (or `None` to keep the observed one) together with the stream to hand
/// onward — bytes replayed when what we read turned out to be payload.
///
/// The caller must only invoke this for a connection whose REAL source is a
/// [`TrustedProxies`] member; this function does not re-check that, because the check belongs at the
/// call site where the observed address is still in hand.
///
/// A malformed header from a trusted proxy is treated as `None` rather than an error: the proxy is
/// trusted, the connection is real, and dropping it over an unparsed optional header would turn a
/// header-format disagreement into an outage.
///
/// # Errors
/// Only a genuine I/O failure reading the stream.
pub async fn read_source_addr<S>(
    mut stream: S,
) -> io::Result<(Option<SocketAddr>, PrefixedStream<S>)>
where
    S: AsyncRead + Unpin,
{
    let mut fixed = [0u8; V2_FIXED_LEN];
    stream.read_exact(&mut fixed).await?;

    let (ver_cmd, block_len) = match parse_fixed(&fixed) {
        Ok(v) => v,
        // Not PROXY protocol, or a trusted proxy sent something we cannot read: in BOTH cases the
        // bytes go back on the stream. For the malformed case that hands the next layer bytes it
        // will reject on its own terms, which is the honest outcome — we do not silently eat them.
        Err(_) => return Ok((None, PrefixedStream::new(fixed.to_vec(), stream))),
    };

    let mut block = vec![0u8; block_len];
    stream.read_exact(&mut block).await?;

    let source = match parse_address_block(ver_cmd, fixed[13], &block) {
        Ok(Header::Proxy(addr)) => Some(addr),
        Ok(Header::NoSource) | Err(_) => None,
    };
    // The header is fully consumed either way — it is never part of the payload.
    Ok((source, PrefixedStream::new(Vec::new(), stream)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a v2 header for a TCP6 PROXY command with the given source.
    fn tcp6_header(src: Ipv6Addr, src_port: u16) -> Vec<u8> {
        let mut h = V2_SIGNATURE.to_vec();
        h.push(0x21); // version 2, PROXY
        h.push(AF_TCP6);
        h.extend_from_slice(&36u16.to_be_bytes());
        h.extend_from_slice(&src.octets());
        h.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        h.extend_from_slice(&src_port.to_be_bytes());
        h.extend_from_slice(&443u16.to_be_bytes());
        h
    }

    fn tcp4_header(src: Ipv4Addr, src_port: u16) -> Vec<u8> {
        let mut h = V2_SIGNATURE.to_vec();
        h.push(0x21);
        h.push(AF_TCP4);
        h.extend_from_slice(&12u16.to_be_bytes());
        h.extend_from_slice(&src.octets());
        h.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
        h.extend_from_slice(&src_port.to_be_bytes());
        h.extend_from_slice(&443u16.to_be_bytes());
        h
    }

    #[tokio::test]
    async fn reads_the_real_ipv6_client_address_from_a_v2_header() {
        // The exact shape #1930 is about: the peer is in Singapore, the socket says us-east-1.
        let real: Ipv6Addr = "2406:da18:1192:6100:eaeb:92d3:c730:9688".parse().unwrap();
        let mut wire = tcp6_header(real, 51234);
        wire.extend_from_slice(b"payload-after-header");

        let (src, mut rest) = read_source_addr(&wire[..]).await.unwrap();

        assert_eq!(src, Some(SocketAddr::from((real, 51234))));
        let mut tail = Vec::new();
        rest.read_to_end(&mut tail).await.unwrap();
        assert_eq!(
            tail, b"payload-after-header",
            "the header must be consumed and only the payload left"
        );
    }

    #[tokio::test]
    async fn reads_the_real_ipv4_client_address_from_a_v2_header() {
        let real: Ipv4Addr = "108.129.144.61".parse().unwrap();
        let wire = tcp4_header(real, 40001);
        let (src, _) = read_source_addr(&wire[..]).await.unwrap();
        assert_eq!(src, Some(SocketAddr::from((real, 40001))));
    }

    #[tokio::test]
    async fn a_non_proxy_connection_is_untouched_and_its_bytes_are_replayed() {
        // A TLS ClientHello opens 0x16 0x03 …, which can never match the v2 signature. Every byte
        // must survive: eating even one would break the handshake for a peer that speaks no PROXY.
        let hello: Vec<u8> = (0..64u8).map(|i| i.wrapping_add(0x16)).collect();

        let (src, mut rest) = read_source_addr(&hello[..]).await.unwrap();

        assert_eq!(src, None, "no PROXY header means no declared source");
        let mut seen = Vec::new();
        rest.read_to_end(&mut seen).await.unwrap();
        assert_eq!(seen, hello, "every byte must be replayed intact");
    }

    #[tokio::test]
    async fn a_local_command_reports_no_source() {
        // The load balancer's own health check: a real connection with no client behind it. It must
        // NOT be attributed to some address, and must not be rejected either.
        let mut h = V2_SIGNATURE.to_vec();
        h.push(0x20); // version 2, LOCAL
        h.push(0x00); // UNSPEC
        h.extend_from_slice(&0u16.to_be_bytes());

        let (src, _) = read_source_addr(&h[..]).await.unwrap();
        assert_eq!(src, None);
    }

    #[tokio::test]
    async fn a_truncated_address_block_does_not_invent_an_address() {
        let mut h = V2_SIGNATURE.to_vec();
        h.push(0x21);
        h.push(AF_TCP6);
        h.extend_from_slice(&36u16.to_be_bytes());
        h.extend_from_slice(&[0u8; 36]); // present, but all zeros with a short real source
        let (src, _) = read_source_addr(&h[..]).await.unwrap();
        // Parses structurally; the point is it never errors into a wrong address.
        assert_eq!(src, Some(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))));
    }

    #[test]
    fn a_wrong_version_nibble_is_malformed_not_silently_accepted() {
        let mut fixed = [0u8; V2_FIXED_LEN];
        fixed[..12].copy_from_slice(&V2_SIGNATURE);
        fixed[12] = 0x31; // version 3
        assert_eq!(parse_fixed(&fixed), Err(HeaderError::Malformed));
    }

    #[test]
    fn a_non_signature_prefix_is_reported_as_not_proxy_protocol() {
        let mut fixed = [0u8; V2_FIXED_LEN];
        fixed[0] = 0x16; // TLS
        assert_eq!(parse_fixed(&fixed), Err(HeaderError::NotProxyProtocol));
    }

    #[test]
    fn an_oversized_declared_block_is_refused_before_allocating() {
        let mut fixed = [0u8; V2_FIXED_LEN];
        fixed[..12].copy_from_slice(&V2_SIGNATURE);
        fixed[12] = 0x21;
        fixed[13] = AF_TCP6;
        fixed[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(parse_fixed(&fixed), Err(HeaderError::Malformed));
    }

    #[test]
    fn trusted_proxies_defaults_to_trusting_nobody() {
        let t = TrustedProxies::default();
        assert!(t.is_empty());
        assert!(!t.trusts("2600:1f18::1".parse().unwrap()));
        assert!(!t.trusts("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn a_configured_cidr_trusts_inside_and_refuses_outside() {
        // The real shape: the relay's NLB lives in 2600:1f18::/32; a peer anywhere else must not be
        // able to declare its own source address.
        let t = TrustedProxies::parse("2600:1f18::/32, 10.60.0.0/16").unwrap();
        assert!(t.trusts("2600:1f18:11a9:ea01:e563:d4a:5ad5:de".parse().unwrap()));
        assert!(t.trusts("10.60.4.9".parse().unwrap()));
        assert!(
            !t.trusts("2406:da18:1192:6100::1".parse().unwrap()),
            "a peer in Singapore is not a trusted proxy"
        );
        assert!(!t.trusts("10.61.0.1".parse().unwrap()));
    }

    #[test]
    fn a_non_byte_aligned_prefix_masks_only_the_declared_bits() {
        let t = TrustedProxies::parse("192.0.2.0/28").unwrap();
        assert!(t.trusts("192.0.2.15".parse().unwrap()));
        assert!(!t.trusts("192.0.2.16".parse().unwrap()));
    }

    #[test]
    fn a_bare_address_is_a_host_route() {
        let t = TrustedProxies::parse("203.0.113.7").unwrap();
        assert!(t.trusts("203.0.113.7".parse().unwrap()));
        assert!(!t.trusts("203.0.113.8".parse().unwrap()));
    }

    #[test]
    fn an_ipv4_mapped_source_matches_an_ipv4_cidr() {
        // The relay's listener is dual-stack, so an IPv4 proxy can arrive as ::ffff:a.b.c.d.
        let t = TrustedProxies::parse("10.60.0.0/16").unwrap();
        assert!(t.trusts("::ffff:10.60.1.2".parse().unwrap()));
    }

    #[test]
    fn a_malformed_cidr_is_rejected_by_name_rather_than_silently_dropped() {
        let err = TrustedProxies::parse("10.0.0.0/8, not-an-ip").unwrap_err();
        assert!(err.contains("not-an-ip"), "got: {err}");
        assert!(TrustedProxies::parse("10.0.0.0/33").is_err());
    }

    #[test]
    fn an_empty_list_parses_to_the_trust_nobody_default() {
        assert!(TrustedProxies::parse("").unwrap().is_empty());
        assert!(TrustedProxies::parse("  , ").unwrap().is_empty());
    }
}
