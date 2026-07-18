//! B1 direct-dial candidate resolution (dig_ecosystem #924).
//!
//! A NAT'd DIG node's outbound WebSocket to the relay reveals its public reflexive IP (the source
//! address the relay observes), but that source PORT is an ephemeral NAT mapping, not the node's
//! inbound gossip LISTEN port. The node therefore advertises its gossip listen candidate(s) in
//! `Register.listen_addrs` — where the useful part is the PORT, since a dual-stack node binds the
//! unspecified host `[::]`. This module combines the two halves: the observed reflexive IP + the
//! advertised port → a real `reflexive_IP:port` another node can direct-dial over the existing mTLS
//! path, which the relay hands out as `RelayPeerInfo::addresses` (RLY-005 `Peers`/`PeerConnected`).

use dig_ip::Family;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

/// Upper bound on the dialable candidates the relay emits per registration. A registration's
/// advertised list is otherwise attacker-controlled and unbounded; capping the emitted set stops one
/// peer from making the relay fan out an arbitrarily long address list (§2.9).
const MAX_DIALABLE_CANDIDATES: usize = 8;

/// Resolve a peer's advertised gossip listen candidates into DIALABLE candidate addresses, using the
/// relay-observed reflexive source IP as the trust anchor so the relay never emits a public address
/// that isn't tied to the registering peer's own observed source.
///
/// For each advertised candidate:
/// - a non-routable host (unspecified/loopback/private/link-local — the usual NAT case, since a
///   dual-stack node binds `[::]`) yields `reflexive_IP:advertised_port`;
/// - a globally-routable host is only KEPT when it verifiably belongs to the peer's own source: it
///   must equal the reflexive IP (IPv4) or share its `/64` prefix (IPv6 — one prefix covers a peer's
///   privacy/temporary addresses). Otherwise the advertised host is an unverifiable third party (the
///   reflection vector — an attacker advertising `victim:port`): it is DROPPED and replaced by the
///   safe `reflexive_IP:advertised_port`, which can only point back at the peer itself.
///
/// Results are IPv6-first (§5.2), de-duplicated preserving first-occurrence order, and capped at
/// [`MAX_DIALABLE_CANDIDATES`]. An empty input yields an empty output — a legacy peer that advertised
/// nothing gets no resolved addresses and falls back to identity-only relayed reachability.
pub fn resolve_dialable(advertised: &[SocketAddr], reflexive: IpAddr) -> Vec<SocketAddr> {
    let mut seen = std::collections::HashSet::new();
    let mut resolved: Vec<SocketAddr> = advertised
        .iter()
        .map(|candidate| resolve_one(*candidate, reflexive))
        .filter(|addr| seen.insert(*addr))
        .take(MAX_DIALABLE_CANDIDATES)
        .collect();
    order_ipv6_first(&mut resolved);
    resolved
}

/// Order candidates IPv6-first (§5.2) using the ecosystem's canonical [`dig_ip::Family`] keying, so a
/// dialer races IPv6 before IPv4 (happy-eyeballs). A stable sort preserves each family's internal
/// discovery order. Using [`Family::of`] rather than a hand-rolled `is_ipv6()` key keeps the family
/// judgement consistent with every other DIG peer crate — notably an IPv4-mapped IPv6 candidate
/// (`::ffff:a.b.c.d`) is treated as IPv4, since it is IPv4 reachability wearing an IPv6 costume.
fn order_ipv6_first(candidates: &mut [SocketAddr]) {
    candidates.sort_by_key(|addr| Family::of(addr));
}

/// Resolve a single advertised candidate to the address the relay may safely emit for it.
///
/// A non-routable or unverifiable-public host is replaced by the observed reflexive IP (keeping the
/// advertised port); a public host that matches the peer's own source is kept verbatim. Either way the
/// emitted host is tied to the peer's observed source, so a third-party address can never be reflected.
fn resolve_one(candidate: SocketAddr, reflexive: IpAddr) -> SocketAddr {
    let keep_verbatim =
        !is_unroutable(candidate.ip()) && belongs_to_source(candidate.ip(), reflexive);
    if keep_verbatim {
        candidate
    } else {
        SocketAddr::new(reflexive, candidate.port())
    }
}

/// Whether a globally-routable advertised host verifiably belongs to the peer's own observed source:
/// IPv4 must match the reflexive IP exactly; IPv6 must share its `/64` prefix (so a peer's privacy/
/// temporary addresses under one prefix are accepted). Cross-family pairs can't be verified against
/// this source and are rejected. IPv4-mapped IPv6 forms are canonicalized to their IPv4 first.
fn belongs_to_source(advertised: IpAddr, reflexive: IpAddr) -> bool {
    match (canonical(advertised), canonical(reflexive)) {
        (IpAddr::V4(a), IpAddr::V4(r)) => a == r,
        (IpAddr::V6(a), IpAddr::V6(r)) => same_ipv6_prefix64(a, r),
        _ => false,
    }
}

/// Canonicalize an IPv4-mapped IPv6 host (`::ffff:a.b.c.d`) to the IPv4 it carries so a mapped and a
/// native form of the same address compare equal; all other addresses pass through unchanged.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Whether two IPv6 addresses share the same `/64` routing prefix (the leading four segments).
fn same_ipv6_prefix64(a: Ipv6Addr, b: Ipv6Addr) -> bool {
    a.segments()[..4] == b.segments()[..4]
}

/// Whether an advertised host is NOT a globally-routable address another node could dial directly —
/// i.e. one the relay must substitute the observed reflexive IP for. Covers unspecified, loopback,
/// and the private/link-local ranges of both families (plus IPv4-mapped IPv6 forms of the same).
fn is_unroutable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_unspecified() || v4.is_loopback() || v4.is_private() || v4.is_link_local()
        }
        // Unmap an IPv4-mapped IPv6 host (`::ffff:a.b.c.d`) and judge it as the IPv4 it carries, so a
        // dual-stack node advertising a mapped private v4 is handled identically to a native v4 one.
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_unroutable(IpAddr::V4(v4)),
            None => v6.is_unspecified() || v6.is_loopback() || is_ipv6_local(v6),
        },
    }
}

/// Whether an IPv6 address is in a non-global local range — unique-local (`fc00::/7`) or link-local
/// (`fe80::/10`). Implemented directly against the leading segment because the standard-library
/// predicates for these ranges are not yet stable.
fn is_ipv6_local(v6: Ipv6Addr) -> bool {
    let leading = v6.segments()[0];
    (leading & 0xfe00) == 0xfc00 || (leading & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn private_advertised_host_is_substituted_with_the_reflexive_ip_keeping_the_port() {
        // The common NAT case: a node binds a private/unspecified host but advertises its listen PORT.
        let out = resolve_dialable(&[addr("192.168.1.5:9445")], ip("203.0.113.7"));
        assert_eq!(out, vec![addr("203.0.113.7:9445")]);
    }

    #[test]
    fn unspecified_advertised_host_is_substituted() {
        // A dual-stack node's `[::]:9445` listen candidate — host useless, port kept.
        let out = resolve_dialable(&[addr("[::]:9445")], ip("203.0.113.7"));
        assert_eq!(out, vec![addr("203.0.113.7:9445")]);
    }

    #[test]
    fn loopback_advertised_host_is_substituted() {
        let out = resolve_dialable(&[addr("127.0.0.1:9445")], ip("203.0.113.7"));
        assert_eq!(out, vec![addr("203.0.113.7:9445")]);
    }

    #[test]
    fn public_advertised_host_matching_the_reflexive_ip_is_kept_verbatim() {
        // An EC2 peer that already knows its public address, and it matches its observed source: keep it.
        let out = resolve_dialable(&[addr("198.51.100.9:9445")], ip("198.51.100.9"));
        assert_eq!(out, vec![addr("198.51.100.9:9445")]);
    }

    #[test]
    fn public_advertised_host_not_matching_the_source_is_dropped_for_the_reflexive_substitution() {
        // The reflection vector: an attacker advertises a victim's public address it does not own.
        // The unverifiable third-party host is DROPPED; only the safe reflexive substitution is emitted,
        // which can point at nobody but the attacker's own source.
        let out = resolve_dialable(&[addr("203.0.113.200:9445")], ip("198.51.100.9"));
        assert_eq!(out, vec![addr("198.51.100.9:9445")]);
        assert!(!out.contains(&addr("203.0.113.200:9445")));
    }

    #[test]
    fn ipv6_public_host_in_the_same_prefix64_as_the_source_is_kept() {
        // A privacy/temporary IPv6 address under the peer's own /64: verifiable, kept verbatim.
        let out = resolve_dialable(&[addr("[2001:db8:0:1::abcd]:9445")], ip("2001:db8:0:1::1"));
        assert_eq!(out, vec![addr("[2001:db8:0:1::abcd]:9445")]);
    }

    #[test]
    fn ipv6_public_host_in_a_different_prefix64_is_dropped() {
        // A different /64 can't be verified against the source: dropped for the reflexive substitution.
        let out = resolve_dialable(&[addr("[2001:db8:0:2::abcd]:9445")], ip("2001:db8:0:1::1"));
        assert_eq!(out, vec![addr("[2001:db8:0:1::1]:9445")]);
        assert!(!out.contains(&addr("[2001:db8:0:2::abcd]:9445")));
    }

    #[test]
    fn advertised_candidates_are_capped() {
        // A registration advertising more than the cap gets at most MAX_DIALABLE_CANDIDATES emitted.
        let many: Vec<SocketAddr> = (0..20u16)
            .map(|i| addr(&format!("198.51.100.9:{}", 9000 + i)))
            .collect();
        let out = resolve_dialable(&many, ip("198.51.100.9"));
        assert_eq!(out.len(), MAX_DIALABLE_CANDIDATES);
    }

    #[test]
    fn ipv6_first_ordering_is_preserved() {
        // §5.2 IPv6-first ordering. Because the relay observes a single source IP per connection, an
        // emitted set is normally single-family; the stable sort still guarantees any IPv6 candidate
        // precedes any IPv4 one. Two same-/64 public v6 candidates stay ahead and keep their order.
        let out = resolve_dialable(
            &[
                addr("[2001:db8:0:1::a]:9445"),
                addr("[2001:db8:0:1::b]:9446"),
            ],
            ip("2001:db8:0:1::1"),
        );
        assert_eq!(
            out,
            vec![
                addr("[2001:db8:0:1::a]:9445"),
                addr("[2001:db8:0:1::b]:9446")
            ]
        );
        assert!(out.iter().all(|a| a.is_ipv6()));
    }

    #[test]
    fn ipv6_unique_local_and_link_local_are_substituted() {
        let reflexive = ip("2001:db8::99");
        assert_eq!(
            resolve_dialable(&[addr("[fc00::1]:9445")], reflexive),
            vec![addr("[2001:db8::99]:9445")]
        );
        assert_eq!(
            resolve_dialable(&[addr("[fe80::1]:9445")], reflexive),
            vec![addr("[2001:db8::99]:9445")]
        );
    }

    #[test]
    fn ipv4_mapped_private_host_is_treated_as_its_ipv4() {
        // `::ffff:192.168.0.4` must be judged as the private IPv4 it carries → substituted.
        let out = resolve_dialable(&[addr("[::ffff:192.168.0.4]:9445")], ip("203.0.113.7"));
        assert_eq!(out, vec![addr("203.0.113.7:9445")]);
    }

    #[test]
    fn duplicate_resolved_candidates_are_removed_preserving_order() {
        // Two different private hosts on the same port both resolve to the same reflexive address;
        // the duplicate is dropped.
        let out = resolve_dialable(
            &[addr("192.168.1.5:9445"), addr("10.0.0.9:9445")],
            ip("203.0.113.7"),
        );
        assert_eq!(out, vec![addr("203.0.113.7:9445")]);
    }

    #[test]
    fn empty_advertised_yields_empty() {
        assert!(resolve_dialable(&[], ip("203.0.113.7")).is_empty());
    }

    #[test]
    fn order_ipv6_first_places_every_v6_before_every_v4_via_dig_ip_family() {
        // The canonical dig_ip::Family keying (§5.2): every IPv6 candidate precedes every IPv4 one,
        // with each family's internal order preserved (stable sort). An IPv4-mapped IPv6 address
        // (`::ffff:a.b.c.d`) is IPv4 reachability, so Family::of ranks it AFTER native IPv6 — a
        // distinction the old `!is_ipv6()` key got wrong (it treated the mapped form as IPv6).
        let mut candidates = vec![
            addr("203.0.113.1:9445"),               // V4
            addr("[2001:db8::a]:9445"),             // V6
            addr("[::ffff:198.51.100.7]:9445"),     // V4 (mapped) — must NOT sort as V6
            addr("[2001:db8::b]:9446"),             // V6
        ];
        order_ipv6_first(&mut candidates);
        assert_eq!(
            candidates,
            vec![
                addr("[2001:db8::a]:9445"),
                addr("[2001:db8::b]:9446"),
                addr("203.0.113.1:9445"),
                addr("[::ffff:198.51.100.7]:9445"),
            ],
        );
    }
}
