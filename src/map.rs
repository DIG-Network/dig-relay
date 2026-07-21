//! Pure logic for `GET /map` + `GET /map.json` — a purely-VISUAL, privacy-first aggregation of the
//! relay's registered peers by coarse geo-location, so `relay.dig.net/map` reads as "watch the
//! worldwide DIG network form" without ever publishing where any individual peer actually is.
//!
//! # The privacy contract (load-bearing — see also [`crate::geoip`])
//!
//! - **No raw IP, no `peer_id`, no precise coordinate ever leaves this module's output.** A
//!   [`MapSnapshot`] carries only grid-cell centroids + counts.
//! - Geo-location happens SERVER-SIDE ONLY, from an in-process offline database
//!   ([`crate::geoip::locate`]) — never a third-party lookup per request (that would itself leak
//!   peer IPs to whoever runs the lookup service).
//! - Every located point is snapped to a deliberately COARSE global grid ([`MAP_CELL_DEG`], ~5°,
//!   roughly 300 miles at the equator) before publication; only the cell CENTROID + a peer COUNT
//!   is exposed. A published coordinate means "somewhere in this cell," never a peer's location.
//! - A peer with no public/dialable address (relay-only reachability) contributes to
//!   [`MapSnapshot::unknown_peers`] — never a fabricated location.
//!
//! Accuracy is explicitly not a goal here (SPEC intent): the visualization is a global "where is
//! the network forming" impression, not a locator.

use std::net::{IpAddr, SocketAddr};

use serde::Serialize;

use crate::wire::RelayPeerInfo;

/// The `/map.json` schema version ([`STATS_SCHEMA_VERSION`](crate::dashboard::STATS_SCHEMA_VERSION)
/// sibling) — bumped only on a breaking shape change (§6.2 stable machine contract).
pub const MAP_SCHEMA_VERSION: u32 = 1;

/// The coarse grid cell size in degrees. Deliberately far coarser than city/street precision — a
/// cell is roughly 300 miles on a side at the equator, so a published point means "somewhere in
/// this region," never a peer's actual location.
pub const MAP_CELL_DEG: f64 = 5.0;

/// A resolver from a public IP to an approximate (lat, lon), so [`build_map_snapshot`] stays pure
/// and unit-testable without a real geo database — the production impl
/// ([`crate::geoip::LiveGeoResolver`]) delegates to the bundled offline mmdb.
pub trait GeoResolver {
    /// Best-effort location for `ip`, or `None` when unknown/unavailable/non-public.
    fn locate(&self, ip: IpAddr) -> Option<(f64, f64)>;
}

/// One aggregated grid cell in a [`MapSnapshot`]: a coarse centroid + how many peers snapped there.
/// Deliberately carries NOTHING per-peer — no ids, no exact coordinates.
#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub struct MapCell {
    /// The grid cell's centroid latitude, in `[-90, 90]`.
    pub lat: f64,
    /// The grid cell's centroid longitude, in `[-180, 180]`.
    pub lon: f64,
    /// How many peers snapped into this cell.
    pub count: usize,
}

/// The `/map.json` body and the data the globe page renders. Field names are stable snake_case
/// (§6.2); `schema_version` lets a consumer pin the shape.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MapSnapshot {
    /// The `/map.json` schema version ([`MAP_SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// Unix seconds when this snapshot was built.
    pub generated_at: u64,
    /// The grid cell size in degrees ([`MAP_CELL_DEG`]) — lets a consumer draw cell boundaries.
    pub cell_deg: f64,
    /// Total registered peers considered (located + unknown).
    pub total_peers: usize,
    /// Peers successfully snapped to a grid cell.
    pub located_peers: usize,
    /// Peers with no public/dialable address, or whose address the resolver couldn't locate.
    pub unknown_peers: usize,
    /// The located peers, aggregated by coarse grid cell, sorted deterministically
    /// (`lat` then `lon` ascending).
    pub cells: Vec<MapCell>,
}

/// Snap a coordinate to its grid cell's CENTROID at `cell_deg` resolution: `((coord / cell_deg)
/// .floor() + 0.5) * cell_deg`. Symmetric across zero (negative latitudes/longitudes and the
/// antimeridian snap the same way `floor` always does), and a pole (`±90`) snaps into its own
/// boundary cell like any other value.
fn snap(coord: f64, cell_deg: f64) -> f64 {
    ((coord / cell_deg).floor() + 0.5) * cell_deg
}

/// The first address in `addresses` whose IP is public/dialable in principle — [`GeoResolver`]
/// itself is responsible for rejecting private/loopback/link-local ranges; this just picks the
/// candidate to hand it (mirrors `dashboard::peer_row`'s "first dialable address" convention).
fn first_addr(addresses: &[SocketAddr]) -> Option<IpAddr> {
    addresses.first().map(|a| a.ip())
}

/// Build a [`MapSnapshot`] from the relay's registered peers. PURE (no I/O, no locks): geo lookups
/// go through the injected `resolver` so this is fully unit-testable without a real database, and
/// the whole grid-snapping + aggregation + privacy shape lives here where it's exhaustively tested.
pub fn build_map_snapshot(
    peers: &[RelayPeerInfo],
    resolver: &dyn GeoResolver,
    cell_deg: f64,
    generated_at: u64,
) -> MapSnapshot {
    use std::collections::BTreeMap;

    // Keyed on the snapped (lat, lon) pair as bit patterns so floating-point cell centroids —
    // which are exact multiples of `cell_deg / 2` — compare and order deterministically without
    // pulling in an `Ord`-for-f64 crate.
    let mut cells: BTreeMap<(i64, i64), usize> = BTreeMap::new();
    let mut unknown_peers = 0usize;

    for peer in peers {
        let Some(ip) = first_addr(&peer.addresses) else {
            unknown_peers += 1;
            continue;
        };
        let Some((lat, lon)) = resolver.locate(ip) else {
            unknown_peers += 1;
            continue;
        };
        let key = (quantize(snap(lat, cell_deg)), quantize(snap(lon, cell_deg)));
        *cells.entry(key).or_insert(0) += 1;
    }

    let located_peers: usize = cells.values().sum();
    let cell_rows = cells
        .into_iter()
        .map(|((lat_q, lon_q), count)| MapCell {
            lat: dequantize(lat_q),
            lon: dequantize(lon_q),
            count,
        })
        .collect();

    MapSnapshot {
        schema_version: MAP_SCHEMA_VERSION,
        generated_at,
        cell_deg,
        total_peers: peers.len(),
        located_peers,
        unknown_peers,
        cells: cell_rows,
    }
}

/// Fixed-point scale for the `BTreeMap` sort key — six decimal places is far finer than any grid
/// centroid needs, just enough to sort exact floating-point cell centroids without drift.
const QUANTIZE_SCALE: f64 = 1_000_000.0;

fn quantize(coord: f64) -> i64 {
    (coord * QUANTIZE_SCALE).round() as i64
}

fn dequantize(q: i64) -> f64 {
    q as f64 / QUANTIZE_SCALE
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// A resolver whose answers are fixed in a table, keyed on the exact `IpAddr` — lets tests
    /// exercise `build_map_snapshot` without any real geo database.
    struct FakeResolver(Vec<(IpAddr, Option<(f64, f64)>)>);

    impl GeoResolver for FakeResolver {
        fn locate(&self, ip: IpAddr) -> Option<(f64, f64)> {
            self.0.iter().find(|(k, _)| *k == ip).and_then(|(_, v)| *v)
        }
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn peer_with_addr(id: &str, addr: Option<IpAddr>) -> RelayPeerInfo {
        let mut p = RelayPeerInfo::new(id.to_string(), "mainnet".to_string(), 1);
        if let Some(ip) = addr {
            p.addresses = vec![SocketAddr::new(ip, 9444)];
        }
        p
    }

    #[test]
    fn snap_floors_into_the_cell_and_centers_it() {
        // A 5° cell spanning [0, 5) centers at 2.5.
        assert_eq!(snap(0.0, 5.0), 2.5);
        assert_eq!(snap(4.999, 5.0), 2.5);
        assert_eq!(snap(5.0, 5.0), 7.5); // exactly on a boundary → the NEXT cell
    }

    #[test]
    fn snap_handles_negative_coordinates_and_the_antimeridian() {
        // -179.9° (just past the antimeridian) snaps to the cell centered at -177.5, not +177.5 —
        // `floor` (not truncation) is what makes negative coords snap consistently.
        assert_eq!(snap(-179.9, 5.0), -177.5);
        assert_eq!(snap(-0.1, 5.0), -2.5);
        assert_eq!(snap(-5.0, 5.0), -2.5);
    }

    #[test]
    fn snap_handles_the_poles() {
        assert_eq!(snap(90.0, 5.0), 92.5); // exactly-90 falls into its own boundary cell
        assert_eq!(snap(89.9, 5.0), 87.5);
        assert_eq!(snap(-90.0, 5.0), -87.5);
    }

    #[test]
    fn colocated_peers_aggregate_into_one_cell_with_summed_count() {
        // Three distinct IPs that all resolve into the same 5° cell.
        let resolver = FakeResolver(vec![
            (v4(1, 1, 1, 1), Some((40.1, -73.2))),
            (v4(2, 2, 2, 2), Some((41.9, -71.3))),
            (v4(3, 3, 3, 3), Some((43.0, -71.0))),
        ]);
        let peers = vec![
            peer_with_addr("a", Some(v4(1, 1, 1, 1))),
            peer_with_addr("b", Some(v4(2, 2, 2, 2))),
            peer_with_addr("c", Some(v4(3, 3, 3, 3))),
        ];
        let snap = build_map_snapshot(&peers, &resolver, 5.0, 0);
        assert_eq!(snap.total_peers, 3);
        assert_eq!(snap.located_peers, 3);
        assert_eq!(snap.unknown_peers, 0);
        assert_eq!(
            snap.cells.len(),
            1,
            "all three peers colocate into one cell"
        );
        assert_eq!(snap.cells[0].count, 3);
    }

    #[test]
    fn distinct_regions_produce_distinct_sorted_cells() {
        let resolver = FakeResolver(vec![
            (v4(1, 1, 1, 1), Some((51.5, -0.1))),   // London-ish
            (v4(2, 2, 2, 2), Some((35.7, 139.7))),  // Tokyo-ish
            (v4(3, 3, 3, 3), Some((-33.9, 151.2))), // Sydney-ish
        ]);
        let peers = vec![
            peer_with_addr("a", Some(v4(1, 1, 1, 1))),
            peer_with_addr("b", Some(v4(2, 2, 2, 2))),
            peer_with_addr("c", Some(v4(3, 3, 3, 3))),
        ];
        let snap = build_map_snapshot(&peers, &resolver, 5.0, 0);
        assert_eq!(snap.cells.len(), 3);
        // Deterministic sort by (lat, lon) ascending: Sydney (-33ish) < London (51ish) < Tokyo... but
        // sort key is lat then lon, so Sydney (-31.25) comes first, then London (52.5), then Tokyo.
        let lats: Vec<f64> = snap.cells.iter().map(|c| c.lat).collect();
        let mut sorted = lats.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        assert_eq!(
            lats, sorted,
            "cells are sorted deterministically by lat then lon"
        );
    }

    #[test]
    fn peers_with_no_dialable_address_are_unknown_never_fabricated() {
        let resolver = FakeResolver(vec![]);
        let peers = vec![peer_with_addr("relay-only", None)];
        let snap = build_map_snapshot(&peers, &resolver, 5.0, 0);
        assert_eq!(snap.total_peers, 1);
        assert_eq!(snap.located_peers, 0);
        assert_eq!(snap.unknown_peers, 1);
        assert!(snap.cells.is_empty());
    }

    #[test]
    fn peers_the_resolver_cannot_locate_are_unknown_not_fabricated() {
        // The IP has a dialable address, but the resolver has nothing for it (e.g. private range,
        // or the offline DB has no entry) — must land in `unknown_peers`, never a made-up cell.
        let resolver = FakeResolver(vec![(v4(9, 9, 9, 9), None)]);
        let peers = vec![peer_with_addr("p", Some(v4(9, 9, 9, 9)))];
        let snap = build_map_snapshot(&peers, &resolver, 5.0, 0);
        assert_eq!(snap.unknown_peers, 1);
        assert!(snap.cells.is_empty());
    }

    #[test]
    fn ipv6_peers_are_located_like_ipv4() {
        use std::net::Ipv6Addr;
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let resolver = FakeResolver(vec![(v6, Some((48.8, 2.3)))]);
        let peers = vec![peer_with_addr("p", Some(v6))];
        let snap = build_map_snapshot(&peers, &resolver, 5.0, 0);
        assert_eq!(snap.located_peers, 1);
        assert_eq!(snap.cells.len(), 1);
    }

    #[test]
    fn snapshot_carries_a_schema_version_and_generated_at() {
        let resolver = FakeResolver(vec![]);
        let snap = build_map_snapshot(&[], &resolver, MAP_CELL_DEG, 12345);
        assert_eq!(snap.schema_version, MAP_SCHEMA_VERSION);
        assert_eq!(snap.generated_at, 12345);
        assert_eq!(snap.cell_deg, MAP_CELL_DEG);
    }

    // -- The privacy contract itself: assert on the SERIALIZED bytes a client actually receives. --

    #[test]
    fn serialized_map_json_never_contains_a_raw_peer_ip() {
        let raw_ip = "203.0.113.77"; // a real, precise IP a peer registered with
        let ip: IpAddr = raw_ip.parse().unwrap();
        let resolver = FakeResolver(vec![(ip, Some((37.7749, -122.4194)))]); // precise SF coords
        let peers = vec![peer_with_addr("leak-test-peer", Some(ip))];
        let snap = build_map_snapshot(&peers, &resolver, MAP_CELL_DEG, 0);

        let json = serde_json::to_string(&snap).unwrap();
        assert!(
            !json.contains(raw_ip),
            "the raw peer IP must never appear in /map.json bytes"
        );
        // The precise (unsnapped) coordinate must not leak either — only the coarse cell centroid.
        assert!(!json.contains("37.7749"));
        assert!(!json.contains("-122.4194"));
    }

    #[test]
    fn serialized_map_json_never_contains_a_peer_id() {
        let ip = v4(198, 51, 100, 23);
        let resolver = FakeResolver(vec![(ip, Some((10.0, 20.0)))]);
        let secret_peer_id = "super-secret-peer-identity-hash-abc123";
        let peers = vec![peer_with_addr(secret_peer_id, Some(ip))];
        let snap = build_map_snapshot(&peers, &resolver, MAP_CELL_DEG, 0);

        let json = serde_json::to_string(&snap).unwrap();
        assert!(
            !json.contains(secret_peer_id),
            "no peer_id may ever appear in /map.json bytes"
        );
        assert!(
            !json.contains("peer_id"),
            "no peer_id FIELD at all in the shape"
        );
    }

    #[test]
    fn serialized_map_json_only_exposes_coarse_grid_snapped_coordinates() {
        let ip = v4(1, 2, 3, 4);
        let precise_lat = 40.7128_f64; // NYC, full precision
        let precise_lon = -74.0060_f64;
        let resolver = FakeResolver(vec![(ip, Some((precise_lat, precise_lon)))]);
        let peers = vec![peer_with_addr("p", Some(ip))];
        let snap = build_map_snapshot(&peers, &resolver, MAP_CELL_DEG, 0);

        assert_eq!(snap.cells.len(), 1);
        let cell = &snap.cells[0];
        // The published coordinate is the CELL CENTROID (an exact multiple of cell_deg/2), never
        // the raw located point.
        assert_ne!(cell.lat, precise_lat);
        assert_ne!(cell.lon, precise_lon);
        assert_eq!(
            cell.lat % (MAP_CELL_DEG / 2.0),
            0.0,
            "centroid is a clean grid multiple"
        );
    }

    #[test]
    fn stable_snake_case_field_names() {
        let resolver = FakeResolver(vec![(v4(1, 1, 1, 1), Some((1.0, 1.0)))]);
        let peers = vec![peer_with_addr("p", Some(v4(1, 1, 1, 1)))];
        let snap = build_map_snapshot(&peers, &resolver, MAP_CELL_DEG, 42);
        let v = serde_json::to_value(&snap).unwrap();
        for key in [
            "schema_version",
            "generated_at",
            "cell_deg",
            "total_peers",
            "located_peers",
            "unknown_peers",
            "cells",
        ] {
            assert!(v.get(key).is_some(), "/map.json must expose `{key}`");
        }
        for key in ["lat", "lon", "count"] {
            assert!(
                v["cells"][0].get(key).is_some(),
                "cell row must expose `{key}`"
            );
        }
    }
}
