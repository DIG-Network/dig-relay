//! B1 direct-dial candidate resolution (dig_ecosystem #924).
//!
//! A NAT'd DIG node's outbound WebSocket to the relay reveals its public reflexive IP (the source
//! address the relay observes), but that source PORT is an ephemeral NAT mapping, not the node's
//! inbound gossip LISTEN port. The node therefore advertises its gossip listen candidate(s) in
//! `Register.listen_addrs` — where the useful part is the PORT, since a dual-stack node binds the
//! unspecified host `[::]`. This module combines the two halves: the observed reflexive IP + the
//! advertised port → a real `reflexive_IP:port` another node can direct-dial over the existing mTLS
//! path, which the relay hands out as `RelayPeerInfo::addresses` (RLY-005 `Peers`/`PeerConnected`).

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

/// Resolve a peer's advertised gossip listen candidates into DIALABLE candidate addresses, using the
/// relay-observed reflexive source IP to fill in any non-routable advertised host.
///
/// For each advertised candidate: when its host is not itself dialable from the public internet
/// (unspecified/loopback/private/link-local — the usual case, since a dual-stack node binds `[::]`),
/// the observed `reflexive` IP is substituted while the advertised PORT is kept, yielding a real
/// `reflexive_IP:port`. An already-public advertised host passes through unchanged (an EC2 peer that
/// knows its own public address). Results are IPv6-first (§5.2) and de-duplicated, preserving the
/// first occurrence's relative order. An empty input yields an empty output — a legacy peer that
/// advertised nothing gets no resolved addresses and falls back to identity-only relayed reachability.
pub fn resolve_dialable(advertised: &[SocketAddr], reflexive: IpAddr) -> Vec<SocketAddr> {
    let mut seen = std::collections::HashSet::new();
    let mut resolved: Vec<SocketAddr> = advertised
        .iter()
        .map(|candidate| substitute_if_unroutable(*candidate, reflexive))
        .filter(|addr| seen.insert(*addr))
        .collect();
    // IPv6-first (§5.2): a stable sort keeps IPv6 candidates ahead of IPv4 while preserving the
    // relative order within each family, so a dialer races IPv6 first (happy-eyeballs).
    resolved.sort_by_key(|addr| !addr.is_ipv6());
    resolved
}

/// Replace a candidate's host with the observed reflexive IP (keeping its port) when the advertised
/// host is not publicly dialable; otherwise return it unchanged.
fn substitute_if_unroutable(candidate: SocketAddr, reflexive: IpAddr) -> SocketAddr {
    if is_unroutable(candidate.ip()) {
        SocketAddr::new(reflexive, candidate.port())
    } else {
        candidate
    }
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
    fn public_advertised_host_passes_through_unchanged() {
        // An EC2 peer that already knows its public address: keep it verbatim.
        let out = resolve_dialable(&[addr("198.51.100.9:9445")], ip("203.0.113.7"));
        assert_eq!(out, vec![addr("198.51.100.9:9445")]);
    }

    #[test]
    fn ipv6_candidates_come_first() {
        // §5.2 IPv6-first ordering: the v6 candidate must precede the v4 one in the result.
        let out = resolve_dialable(
            &[addr("198.51.100.9:9445"), addr("[2001:db8::1]:9445")],
            ip("203.0.113.7"),
        );
        assert_eq!(
            out,
            vec![addr("[2001:db8::1]:9445"), addr("198.51.100.9:9445")]
        );
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
}
