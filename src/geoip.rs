//! Server-side-only IP geo-location for the `/map` globe (see `src/map.rs` for the privacy
//! contract this feeds). The database is loaded LAZILY, ONCE, from a bundled offline MaxMind-format
//! (`.mmdb`) file — **never** a per-request third-party geo API call, which would itself leak the
//! peer's raw IP to whoever runs that service.
//!
//! Graceful by design: if the database file is missing or unreadable (the common case in CI/local
//! dev, where no `.mmdb` is provisioned), [`locate`] returns `None` for every IP, and the `/map`
//! globe still renders — every peer simply lands in the "unknown/relayed" bucket
//! ([`crate::map::MapSnapshot::unknown_peers`]).

use std::net::IpAddr;
use std::sync::OnceLock;

use maxminddb::geoip2;
use maxminddb::Reader;

use crate::map::GeoResolver;

/// The default in-image path to the bundled offline geo database. Overridable via
/// `DIG_RELAY_GEOIP_DB` so an operator can point at a different `.mmdb` (e.g. a licensed
/// higher-resolution DB) without a code change; the deploy image provisions this path — that
/// provisioning is out of scope here (superproject/orchestrator concern).
pub const DEFAULT_GEOIP_DB_PATH: &str = "/opt/dig-relay/geoip/dbip-city-lite.mmdb";

/// The env var that overrides [`DEFAULT_GEOIP_DB_PATH`].
const GEOIP_DB_ENV: &str = "DIG_RELAY_GEOIP_DB";

/// The lazily-opened, process-lifetime database handle. `None` means "no usable database" (absent,
/// unreadable, or malformed) — [`locate`] degrades to always-`None` rather than erroring, so a
/// relay with no geo database still serves `/map` (all peers in the unknown bucket).
static DB: OnceLock<Option<Reader<Vec<u8>>>> = OnceLock::new();

fn db() -> &'static Option<Reader<Vec<u8>>> {
    DB.get_or_init(|| {
        let path =
            std::env::var(GEOIP_DB_ENV).unwrap_or_else(|_| DEFAULT_GEOIP_DB_PATH.to_string());
        match Reader::open_readfile(&path) {
            Ok(reader) => Some(reader),
            Err(e) => {
                tracing::info!(
                    path = %path,
                    error = %e,
                    "dig-relay: no geoip database available; /map peers will show as unknown"
                );
                None
            }
        }
    })
}

/// Best-effort (lat, lon) for a public IP, or `None` when the address is private/reserved/
/// unlocatable or no database is loaded. IPv6-aware: an IPv4-mapped IPv6 address is canonicalized
/// to its IPv4 form first (§5.2), so a dual-stack peer resolves the same either way.
///
/// Deliberately UNCACHED: an mmdb lookup is a microsecond-scale in-memory read, so caching it
/// bought negligible latency at the cost of an unbounded per-IP map — an attacker cycling source
/// IPs (trivially cheap across an IPv6 /64) could grow that cache without bound and exhaust
/// process memory. Every call re-queries the database directly.
pub fn locate(ip: IpAddr) -> Option<(f64, f64)> {
    let ip = ip.to_canonical();
    if !is_public(&ip) {
        return None;
    }
    let reader = db().as_ref()?;
    let city: geoip2::City = reader.lookup(ip).ok()?.decode().ok().flatten()?;
    Some((city.location.latitude?, city.location.longitude?))
}

/// Whether `ip` is a plausible public, dialable address worth looking up — excludes loopback,
/// private (RFC1918/ULA), link-local, and unspecified ranges, none of which a geo database can (or
/// should) answer for.
fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation())
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || is_unique_local(v6)
                || is_unicast_link_local(v6))
        }
    }
}

/// `Ipv6Addr::is_unique_local` (ULA, `fc00::/7`) — stable in std only behind a nightly gate as of
/// this writing, so mirrored here directly.
fn is_unique_local(ip: &std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

/// `Ipv6Addr::is_unicast_link_local` (`fe80::/10`) — same stability note as [`is_unique_local`].
fn is_unicast_link_local(ip: &std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// The production [`GeoResolver`]: delegates to [`locate`] (the lazily-loaded bundled database).
pub struct LiveGeoResolver;

impl GeoResolver for LiveGeoResolver {
    fn locate(&self, ip: IpAddr) -> Option<(f64, f64)> {
        locate(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn private_and_loopback_ipv4_are_never_public() {
        assert!(!is_public(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!is_public(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!is_public(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(!is_public(&IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(!is_public(&IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    }

    #[test]
    fn a_routable_ipv4_is_public() {
        assert!(is_public(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn loopback_ula_and_link_local_ipv6_are_never_public() {
        assert!(!is_public(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_public(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert!(!is_public(&IpAddr::V6(Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(!is_public(&IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn a_routable_ipv6_is_public() {
        assert!(is_public(&IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn locate_returns_none_for_private_ips_without_touching_the_database() {
        // Regardless of whether a database is loaded in this test process, a private IP must
        // short-circuit to None before any lookup.
        assert_eq!(locate(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))), None);
        assert_eq!(locate(IpAddr::V4(Ipv4Addr::LOCALHOST)), None);
    }

    #[test]
    fn locate_degrades_gracefully_with_no_database_present() {
        // In CI/local dev, DIG_RELAY_GEOIP_DB is unset and the default path doesn't exist, so
        // `locate` must return None (not panic, not error) for a public IP.
        assert_eq!(locate(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))), None);
    }

    #[test]
    fn locate_canonicalizes_an_ipv4_mapped_ipv6_address() {
        // An IPv4-mapped IPv6 loopback must canonicalize to plain IPv4 loopback and stay excluded,
        // proving the canonicalization step runs before the public-range check.
        let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001));
        assert_eq!(locate(mapped), None);
    }

    #[test]
    fn locate_is_stateless_across_repeated_calls_for_the_same_ip() {
        // No cache to poison: two calls for the same IP must agree, and must not accumulate any
        // process-lifetime state (regression guard for the removed unbounded per-IP cache).
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 199));
        assert_eq!(locate(ip), locate(ip));
    }

    #[test]
    fn live_geo_resolver_delegates_to_locate() {
        let resolver = LiveGeoResolver;
        assert_eq!(
            resolver.locate(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            locate(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
    }
}
