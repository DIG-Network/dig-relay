//! Public peer-stats **dashboard** — a read-only HTTP overview of the relay's reservations +
//! connections, served on its own listener (default `[::]:80`) so `http://relay.dig.net/` resolves
//! to a live operations view.
//!
//! Two routes, both read-only, both reusing the relay's EXISTING in-memory state (the peer registry +
//! a handful of cheap atomic counters — no new heavy tracking):
//!
//! - `GET /` → an HTML overview (DIG dark theme, ~5 s auto-refresh) that fetches `/stats.json` and
//!   renders it, handling the four async states (loading / error / empty / success).
//! - `GET /stats.json` → the SAME data machine-readable: stable snake_case field names + a
//!   `schema_version`, so an agent scripts against it without scraping the HTML (§6.2).
//!
//! **Privacy (aggregate-by-default).** Aggregate counts are always shown. Per-peer rows expose a
//! `peer_id` (a public SHA-256 identity hash, not PII) and, to avoid publishing the network's
//! topology, only the ADDRESS FAMILY (`v6`/`v4`) of each peer — never a full IP. By default the
//! `peer_id` is TRUNCATED to a short prefix; `?full=1` shows the full `peer_id`. No key material or
//! payload is ever exposed — the relay is an untrusted forwarder and holds none.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::http_serve::RequestHead;
use crate::net::bind_tcp_dual_stack;
use crate::server::RelayState;
use crate::wire::RelayPeerInfo;

/// The `/stats.json` schema version. Bumped only on a BREAKING change to the shape so a machine
/// consumer can pin what it parses (additive fields do not bump it — §6.2 stable contract).
pub const STATS_SCHEMA_VERSION: u32 = 1;

/// How many leading characters of a `peer_id` a truncated (default, non-`?full`) row shows.
const PEER_ID_PREFIX_LEN: usize = 12;

/// The DIG Network robot mascot (the same `minion-dighub.png` hub.dig.net wears), compiled into the
/// binary so the dashboard is fully self-contained — no CDN, no external asset fetch, works offline.
/// Served immutably at `GET /mascot.png`.
const MASCOT_PNG: &[u8] = include_bytes!("../assets/minion-dighub.png");

/// A point-in-time read of the relay's cheap atomic counters — decoupled from [`RelayState`] so the
/// snapshot builder is pure and fully unit-testable without a live server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub connected_peers: u64,
    pub open_connections: u64,
    pub stun_requests: u64,
    pub hole_punch_requests: u64,
    pub hole_punch_successes: u64,
    pub hole_punch_failures: u64,
    pub bytes_relayed: u64,
}

/// One per-peer row in the dashboard — the connection detail we are willing to expose publicly.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PeerRow {
    /// The peer's identity hash — full when `?full=1`, otherwise a short prefix (privacy default).
    pub peer_id: String,
    /// The network the peer registered under.
    pub network_id: String,
    /// How the peer is reachable: `"direct"` when the relay resolved a dialable address for it,
    /// else `"relay"` (identity-only reachability through the relay fallback).
    pub via: &'static str,
    /// The address family of the peer's resolved dialable address: `"v6"`, `"v4"`, or `"none"` when
    /// the relay has no dialable address for it. Only the family is exposed, never the IP.
    pub address_family: &'static str,
    /// The peer's advertised relay protocol version.
    pub protocol_version: u32,
    /// Unix seconds when the peer registered (`connected_at`).
    pub connected_at: u64,
    /// Seconds the peer has been connected (`now - connected_at`, saturating).
    pub connected_secs: u64,
}

/// A per-network aggregate row (how many peers hold a reservation on each network).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NetworkRow {
    pub network_id: String,
    pub peers: usize,
}

/// The complete dashboard snapshot — the `/stats.json` body and the data the HTML renders.
///
/// Field names are stable snake_case (§6.2); `schema_version` lets a consumer pin the shape.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatsSnapshot {
    /// The `/stats.json` schema version ([`STATS_SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// Always `"ok"` while the process is serving.
    pub status: &'static str,
    /// The relay server version (`CARGO_PKG_VERSION`).
    pub version: &'static str,
    /// Seconds since the relay started.
    pub uptime_secs: u64,
    /// Active reservations = peers currently holding a registration (all networks).
    pub active_reservations: usize,
    /// Connected registered peers (mirrors `/health`; equals `active_reservations`).
    pub connected_peers: u64,
    /// Open sockets, including accepted-but-not-yet-registered connections.
    pub open_connections: u64,
    /// STUN Binding Requests answered since start.
    pub stun_requests: u64,
    /// Hole-punch requests coordinated (RLY-007).
    pub hole_punch_requests: u64,
    /// Hole-punch outcomes reported successful.
    pub hole_punch_successes: u64,
    /// Hole-punch outcomes reported failed.
    pub hole_punch_failures: u64,
    /// Payload bytes accepted for relaying.
    pub bytes_relayed: u64,
    /// Per-network reservation counts (sorted by `network_id`).
    pub networks: Vec<NetworkRow>,
    /// Per-peer connection rows (sorted by `peer_id`).
    pub peers: Vec<PeerRow>,
}

/// Whether a request target opts into un-truncated `peer_id`s via `?full=1`/`true`/`yes` (default:
/// truncated, the privacy default). Matches the query anywhere in the target so it works for both
/// `/stats.json?full=1` and `/?full=1`.
fn wants_full(target: &str) -> bool {
    ["full=1", "full=true", "full=yes"]
        .iter()
        .any(|needle| target.contains(needle))
}

/// Build the dashboard snapshot from the relay's registry peers + a counters read. PURE (no I/O, no
/// locks) so the whole shape — aggregation, `via`/family derivation, and the privacy truncation — is
/// unit-testable. `now_secs` is the caller's wall clock (so `connected_secs` is deterministic in
/// tests); `full` selects un-truncated `peer_id`s.
pub fn build_snapshot(
    peers: Vec<RelayPeerInfo>,
    counters: Counters,
    uptime_secs: u64,
    now_secs: u64,
    full: bool,
) -> StatsSnapshot {
    let active_reservations = peers.len();

    // Per-network reservation counts. A BTreeMap keeps the result sorted by network_id for a stable,
    // testable response.
    let mut per_network: BTreeMap<String, usize> = BTreeMap::new();
    for peer in &peers {
        *per_network.entry(peer.network_id.clone()).or_insert(0) += 1;
    }
    let networks = per_network
        .into_iter()
        .map(|(network_id, peers)| NetworkRow { network_id, peers })
        .collect();

    let mut peer_rows: Vec<PeerRow> = peers
        .into_iter()
        .map(|p| peer_row(p, now_secs, full))
        .collect();
    peer_rows.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));

    StatsSnapshot {
        schema_version: STATS_SCHEMA_VERSION,
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs,
        active_reservations,
        connected_peers: counters.connected_peers,
        open_connections: counters.open_connections,
        stun_requests: counters.stun_requests,
        hole_punch_requests: counters.hole_punch_requests,
        hole_punch_successes: counters.hole_punch_successes,
        hole_punch_failures: counters.hole_punch_failures,
        bytes_relayed: counters.bytes_relayed,
        networks,
        peers: peer_rows,
    }
}

/// Derive one [`PeerRow`] from a [`RelayPeerInfo`], applying the `via`/family derivation and the
/// privacy truncation of `peer_id`.
fn peer_row(info: RelayPeerInfo, now_secs: u64, full: bool) -> PeerRow {
    let dialable = info.addresses.first().copied();
    PeerRow {
        peer_id: if full {
            info.peer_id
        } else {
            truncate_peer_id(&info.peer_id)
        },
        network_id: info.network_id,
        via: if dialable.is_some() {
            "direct"
        } else {
            "relay"
        },
        address_family: address_family(dialable),
        protocol_version: info.protocol_version,
        connected_at: info.connected_at,
        connected_secs: now_secs.saturating_sub(info.connected_at),
    }
}

/// The address family label for a resolved dialable address — `"v6"`/`"v4"`, or `"none"` when the
/// relay has no dialable address for the peer. Only the family is exposed, never the IP itself.
fn address_family(addr: Option<SocketAddr>) -> &'static str {
    match addr.map(|a| a.ip().to_canonical()) {
        Some(ip) if ip.is_ipv4() => "v4",
        Some(_) => "v6",
        None => "none",
    }
}

/// Truncate a `peer_id` to a short prefix + an ellipsis for the privacy-default view. A `peer_id`
/// already shorter than the prefix is returned unchanged.
fn truncate_peer_id(peer_id: &str) -> String {
    if peer_id.len() <= PEER_ID_PREFIX_LEN {
        return peer_id.to_string();
    }
    format!("{}…", &peer_id[..PEER_ID_PREFIX_LEN])
}

/// Read the relay's live counters into a pure [`Counters`] value (one relaxed load per field).
fn counters_of(state: &RelayState) -> Counters {
    Counters {
        connected_peers: state.connected.load(Ordering::Relaxed),
        open_connections: state.open_connections.load(Ordering::Relaxed),
        stun_requests: state.stun_requests.load(Ordering::Relaxed),
        hole_punch_requests: state.hole_punch_requests.load(Ordering::Relaxed),
        hole_punch_successes: state.hole_punch_successes.load(Ordering::Relaxed),
        hole_punch_failures: state.hole_punch_failures.load(Ordering::Relaxed),
        bytes_relayed: state.bytes_relayed.load(Ordering::Relaxed),
    }
}

/// Current Unix-epoch time in seconds (saturating) — the wall clock for `connected_secs`.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A ready-to-write dashboard HTTP response — a status, a content type, an optional `Cache-Control`,
/// and the body bytes. Decoupled from any transport so [`route`] is pure/synchronous-to-reason-about
/// and the same responses serve the `:443` wire listener (over the TLS-terminated socket) directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DashboardResponse {
    pub status: u16,
    pub reason: &'static str,
    pub content_type: &'static str,
    pub cache_control: Option<&'static str>,
    pub body: Vec<u8>,
}

/// Route a dashboard request path to its response: `/` → the HTML overview, `/stats.json` → the
/// machine-readable snapshot, `/mascot.png` → the embedded mascot, anything else → 404. `snapshot` is
/// the already-built stats (the caller reads the live registry so this stays free of I/O and locks).
pub fn route(path: &str, snapshot: &StatsSnapshot) -> DashboardResponse {
    match path {
        "/" => DashboardResponse {
            status: 200,
            reason: "OK",
            content_type: "text/html; charset=utf-8",
            cache_control: None,
            body: DASHBOARD_HTML.as_bytes().to_vec(),
        },
        "/stats.json" => DashboardResponse {
            status: 200,
            reason: "OK",
            content_type: "application/json",
            cache_control: Some("no-store"),
            body: serde_json::to_vec(snapshot).unwrap_or_else(|_| b"{}".to_vec()),
        },
        "/mascot.png" => DashboardResponse {
            status: 200,
            reason: "OK",
            content_type: "image/png",
            cache_control: Some("public, max-age=31536000, immutable"),
            body: MASCOT_PNG.to_vec(),
        },
        _ => DashboardResponse {
            status: 404,
            reason: "Not Found",
            content_type: "text/plain; charset=utf-8",
            cache_control: None,
            body: b"not found\n".to_vec(),
        },
    }
}

/// Build the live stats snapshot from the relay's registry + counters (locks the registry briefly).
/// Shared by the `/stats.json` route and the HTML page's data.
pub async fn live_snapshot(state: &RelayState, full: bool) -> StatsSnapshot {
    let peers = state.registry.lock().await.peers(None);
    build_snapshot(
        peers,
        counters_of(state),
        state.uptime_secs(),
        now_secs(),
        full,
    )
}

/// Serve ONE dashboard HTTP request over an already-accepted (TLS-terminated-upstream) stream — the
/// non-WebSocket branch of the relay's `:443` listener. `head` is the request the wire accept loop
/// already peeked; this reads the live stats, routes the path, and writes the response.
pub async fn serve_http<S>(
    state: &RelayState,
    stream: &mut S,
    head: &RequestHead,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let snapshot = live_snapshot(state, wants_full(&head.target)).await;
    let resp = route(head.path(), &snapshot);
    let mut headers: Vec<(&str, &str)> = vec![("Content-Type", resp.content_type)];
    if let Some(cc) = resp.cache_control {
        headers.push(("Cache-Control", cc));
    }
    crate::http_serve::write_response(stream, resp.status, resp.reason, &headers, &resp.body).await
}

/// The absolute `https://` URL a plain-HTTP request should be redirected to. Uses the request's own
/// `Host` header so it works for any hostname the relay is fronted under; falls back to
/// `relay.dig.net` when a (non-conformant) request omits `Host`.
pub fn https_location(head: &RequestHead) -> String {
    let host = head.host.as_deref().unwrap_or("relay.dig.net");
    format!("https://{host}{}", head.target)
}

/// Run the plain-HTTP redirect listener on `listen` (dual-stack): every request gets a
/// `301 → https://<host><path>`. The relay supports only HTTPS/WSS, so `:80` exists solely to bounce
/// browsers to the secure origin — it never serves content.
pub async fn run_redirect(listen: SocketAddr) -> std::io::Result<()> {
    let listener = bind_tcp_dual_stack(listen)?;
    tracing::info!(addr = %listen, "dig-relay http→https redirect listening");
    loop {
        let (mut stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "redirect accept failed");
                continue;
            }
        };
        tokio::spawn(async move {
            if let Ok((head, _)) = crate::http_serve::read_request_head(&mut stream).await {
                let location = https_location(&head);
                let _ = crate::http_serve::write_response(
                    &mut stream,
                    301,
                    "Moved Permanently",
                    &[("Location", &location)],
                    b"",
                )
                .await;
            }
        });
    }
}

/// The dashboard page. Fully static (the live data arrives from `/stats.json`), so no server-side
/// templating is needed. DIG dark theme; the four async states are handled in the fetch loop below.
const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DIG Network Relay — peer stats</title>
<link rel="icon" type="image/png" href="/mascot.png">
<style>
  :root {
    /* DIG Network brand: the mascot's purple + teal on the dark network palette. */
    --bg: #0b0713; --panel: #171125; --border: #2c2140; --text: #ece7f7;
    --muted: #a394bd; --accent: #b14aed; --accent2: #2dd4bf;
    --warn: #f5a623; --error: #f87171;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background:
      radial-gradient(1200px 500px at 80% -10%, rgba(177,74,237,.12), transparent 60%),
      var(--bg);
    color: var(--text);
    font: 15px/1.5 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    padding: 2rem 1.25rem 3rem;
  }
  main { max-width: 960px; margin: 0 auto; }
  header { display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.75rem; }
  header .logo { width: 56px; height: 56px; flex: none; filter: drop-shadow(0 4px 14px rgba(177,74,237,.4)); }
  .titles { display: flex; flex-direction: column; gap: .1rem; }
  .brand { font-size: .8rem; font-weight: 600; letter-spacing: .12em; text-transform: uppercase; color: var(--accent); }
  h1 { font-size: 1.5rem; margin: 0; letter-spacing: -.01em; }
  h1 .dig { color: var(--accent); }
  .ver { color: var(--muted); font-size: .85rem; margin-left: auto; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: .75rem; margin-bottom: 1.75rem; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 1rem 1.1rem; }
  .card { position: relative; overflow: hidden; }
  .card::before { content: ""; position: absolute; inset: 0 auto 0 0; width: 3px; background: linear-gradient(var(--accent), var(--accent2)); }
  .card .n { font-size: 1.75rem; font-weight: 650; }
  .card .l { color: var(--muted); font-size: .8rem; margin-top: .15rem; }
  h2 { font-size: 1rem; color: var(--muted); font-weight: 600; margin: 0 0 .6rem; text-transform: uppercase; letter-spacing: .05em; }
  table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
  th, td { text-align: left; padding: .6rem .8rem; border-bottom: 1px solid var(--border); font-size: .9rem; }
  th { color: var(--muted); font-weight: 600; }
  tr:last-child td { border-bottom: none; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .pill { display: inline-block; padding: .1rem .5rem; border-radius: 999px; font-size: .78rem; }
  .pill.direct { background: rgba(45,212,191,.15); color: var(--accent2); }
  .pill.relay { background: rgba(139,152,173,.15); color: var(--muted); }
  .state { padding: 2.5rem 1rem; text-align: center; color: var(--muted); }
  .state.error { color: var(--error); }
  footer { margin-top: 2rem; color: var(--muted); font-size: .8rem; }
  a { color: var(--accent); }
</style>
</head>
<body>
<main>
  <header>
    <img class="logo" src="/mascot.png" width="56" height="56"
         alt="The DIG Network robot mascot">
    <div class="titles">
      <span class="brand">DIG Network</span>
      <h1><span class="dig">DIG</span> Relay</h1>
    </div>
    <span class="ver" id="version"></span>
  </header>

  <div id="content">
    <div class="state" id="loading">Loading relay stats…</div>
  </div>

  <footer>
    Part of the <a href="https://dig.net">DIG Network</a> ·
    <a href="https://hub.dig.net">DIGHub</a> ·
    <a href="/stats.json">stats.json</a><br>
    Auto-refreshes every 5s · aggregate by default; add <code>?full=1</code> for full peer ids.
  </footer>
</main>

<script>
  const params = new URLSearchParams(window.location.search);
  const full = params.get("full");
  const statsUrl = "/stats.json" + (full ? "?full=" + encodeURIComponent(full) : "");

  const esc = (s) => String(s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

  function fmtDuration(secs) {
    const d = Math.floor(secs / 86400), h = Math.floor((secs % 86400) / 3600);
    const m = Math.floor((secs % 3600) / 60), s = secs % 60;
    if (d) return d + "d " + h + "h";
    if (h) return h + "h " + m + "m";
    if (m) return m + "m " + s + "s";
    return s + "s";
  }

  function fmtBytes(n) {
    const u = ["B", "KiB", "MiB", "GiB", "TiB"];
    let i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i ? n.toFixed(1) : n) + " " + u[i];
  }

  function card(n, label) {
    return '<div class="card"><div class="n">' + esc(n) + '</div><div class="l">' + esc(label) + '</div></div>';
  }

  function render(d) {
    document.getElementById("version").textContent = "v" + d.version;
    const hp = d.hole_punch_requests + " req · " + d.hole_punch_successes + "✓ / " + d.hole_punch_failures + "✗";
    let html = '<div class="cards">'
      + card(d.active_reservations, "Active reservations")
      + card(d.open_connections, "Open connections")
      + card(d.networks.length, "Networks")
      + card(fmtDuration(d.uptime_secs), "Uptime")
      + card(d.stun_requests, "STUN requests")
      + card(hp, "Hole punches")
      + card(fmtBytes(d.bytes_relayed), "Relayed")
      + '</div>';

    html += '<h2>Connected peers</h2>';
    if (!d.peers.length) {
      html += '<div class="state">No peers connected yet.</div>';
    } else {
      html += '<table><thead><tr><th>Peer</th><th>Network</th><th>Via</th><th>Family</th><th>Proto</th><th>Connected</th></tr></thead><tbody>';
      for (const p of d.peers) {
        html += '<tr>'
          + '<td><code>' + esc(p.peer_id) + '</code></td>'
          + '<td>' + esc(p.network_id) + '</td>'
          + '<td><span class="pill ' + esc(p.via) + '">' + esc(p.via) + '</span></td>'
          + '<td>' + esc(p.address_family) + '</td>'
          + '<td>' + esc(p.protocol_version) + '</td>'
          + '<td>' + esc(fmtDuration(p.connected_secs)) + '</td>'
          + '</tr>';
      }
      html += '</tbody></table>';
    }
    document.getElementById("content").innerHTML = html;
  }

  async function refresh() {
    try {
      const res = await fetch(statsUrl, { cache: "no-store" });
      if (!res.ok) throw new Error("HTTP " + res.status);
      render(await res.json());
    } catch (e) {
      document.getElementById("content").innerHTML =
        '<div class="state error">Could not load relay stats: ' + esc(e.message) + '</div>';
    }
  }

  refresh();
  setInterval(refresh, 5000);
</script>
</body>
</html>
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn peer(id: &str, net: &str) -> RelayPeerInfo {
        RelayPeerInfo::new(id.to_string(), net.to_string(), 1)
    }

    fn peer_at(id: &str, net: &str, connected_at: u64, addr: Option<SocketAddr>) -> RelayPeerInfo {
        let mut p = peer(id, net);
        p.connected_at = connected_at;
        if let Some(a) = addr {
            p.addresses = vec![a];
        }
        p
    }

    #[test]
    fn empty_snapshot_reports_zero_and_no_peers() {
        let snap = build_snapshot(vec![], Counters::default(), 0, 0, false);
        assert_eq!(snap.schema_version, STATS_SCHEMA_VERSION);
        assert_eq!(snap.status, "ok");
        assert_eq!(snap.active_reservations, 0);
        assert!(snap.peers.is_empty());
        assert!(snap.networks.is_empty());
    }

    #[test]
    fn counters_are_surfaced_verbatim() {
        let counters = Counters {
            connected_peers: 3,
            open_connections: 5,
            stun_requests: 42,
            hole_punch_requests: 7,
            hole_punch_successes: 4,
            hole_punch_failures: 3,
            bytes_relayed: 4096,
        };
        let snap = build_snapshot(vec![], counters, 99, 0, false);
        assert_eq!(snap.connected_peers, 3);
        assert_eq!(snap.open_connections, 5);
        assert_eq!(snap.stun_requests, 42);
        assert_eq!(snap.hole_punch_requests, 7);
        assert_eq!(snap.hole_punch_successes, 4);
        assert_eq!(snap.hole_punch_failures, 3);
        assert_eq!(snap.bytes_relayed, 4096);
        assert_eq!(snap.uptime_secs, 99);
    }

    #[test]
    fn active_reservations_counts_all_peers_and_networks_aggregate() {
        let peers = vec![
            peer("aaaa", "mainnet"),
            peer("bbbb", "mainnet"),
            peer("cccc", "testnet"),
        ];
        let snap = build_snapshot(peers, Counters::default(), 0, 0, true);
        assert_eq!(snap.active_reservations, 3);
        assert_eq!(
            snap.networks,
            vec![
                NetworkRow {
                    network_id: "mainnet".into(),
                    peers: 2
                },
                NetworkRow {
                    network_id: "testnet".into(),
                    peers: 1
                },
            ],
            "networks are aggregated and sorted by id"
        );
    }

    #[test]
    fn peers_are_sorted_by_id() {
        let peers = vec![peer("cccc", "n"), peer("aaaa", "n"), peer("bbbb", "n")];
        let snap = build_snapshot(peers, Counters::default(), 0, 0, true);
        let ids: Vec<_> = snap.peers.iter().map(|p| p.peer_id.as_str()).collect();
        assert_eq!(ids, vec!["aaaa", "bbbb", "cccc"]);
    }

    #[test]
    fn via_is_direct_when_a_dialable_address_is_known_else_relay() {
        let v4: SocketAddr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 9444));
        let peers = vec![
            peer_at("dial", "n", 0, Some(v4)),
            peer_at("nodial", "n", 0, None),
        ];
        let snap = build_snapshot(peers, Counters::default(), 0, 0, true);
        let by_id = |id: &str| snap.peers.iter().find(|p| p.peer_id == id).unwrap();
        assert_eq!(by_id("dial").via, "direct");
        assert_eq!(by_id("dial").address_family, "v4");
        assert_eq!(by_id("nodial").via, "relay");
        assert_eq!(by_id("nodial").address_family, "none");
    }

    #[test]
    fn ipv6_address_family_is_reported_as_v6() {
        let v6: SocketAddr =
            SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 9444));
        let snap = build_snapshot(
            vec![peer_at("p", "n", 0, Some(v6))],
            Counters::default(),
            0,
            0,
            true,
        );
        assert_eq!(snap.peers[0].address_family, "v6");
    }

    #[test]
    fn connected_secs_is_now_minus_connected_at_saturating() {
        let peers = vec![peer_at("p", "n", 100, None)];
        let snap = build_snapshot(peers, Counters::default(), 0, 250, true);
        assert_eq!(snap.peers[0].connected_at, 100);
        assert_eq!(snap.peers[0].connected_secs, 150);
        // A clock skew where now < connected_at saturates to 0, never underflows.
        let peers = vec![peer_at("p", "n", 500, None)];
        let snap = build_snapshot(peers, Counters::default(), 0, 100, true);
        assert_eq!(snap.peers[0].connected_secs, 0);
    }

    #[test]
    fn peer_id_is_truncated_by_default_and_full_on_request() {
        let long = "0123456789abcdef0123456789abcdef";
        let truncated = build_snapshot(vec![peer(long, "n")], Counters::default(), 0, 0, false);
        assert_eq!(truncated.peers[0].peer_id, "0123456789ab…");
        let full = build_snapshot(vec![peer(long, "n")], Counters::default(), 0, 0, true);
        assert_eq!(full.peers[0].peer_id, long);
    }

    #[test]
    fn a_short_peer_id_is_not_truncated() {
        let snap = build_snapshot(vec![peer("short", "n")], Counters::default(), 0, 0, false);
        assert_eq!(
            snap.peers[0].peer_id, "short",
            "no ellipsis for an already-short id"
        );
    }

    #[test]
    fn stats_json_uses_stable_snake_case_field_names() {
        let snap = build_snapshot(
            vec![peer_at("p", "n", 0, None)],
            Counters::default(),
            1,
            2,
            false,
        );
        let v = serde_json::to_value(&snap).unwrap();
        for key in [
            "schema_version",
            "status",
            "version",
            "uptime_secs",
            "active_reservations",
            "connected_peers",
            "open_connections",
            "stun_requests",
            "hole_punch_requests",
            "hole_punch_successes",
            "hole_punch_failures",
            "bytes_relayed",
            "networks",
            "peers",
        ] {
            assert!(v.get(key).is_some(), "stats.json must expose `{key}`");
        }
        let row = &v["peers"][0];
        for key in [
            "peer_id",
            "network_id",
            "via",
            "address_family",
            "protocol_version",
            "connected_at",
            "connected_secs",
        ] {
            assert!(row.get(key).is_some(), "peer row must expose `{key}`");
        }
    }

    #[test]
    fn wants_full_only_for_truthy_query_values() {
        assert!(wants_full("/stats.json?full=1"));
        assert!(wants_full("/?full=true"));
        assert!(wants_full("/stats.json?full=yes"));
        assert!(!wants_full("/stats.json?full=0"));
        assert!(!wants_full("/stats.json"));
        assert!(!wants_full("/"));
    }

    #[test]
    fn route_serves_the_three_surfaces_and_404s_the_rest() {
        let snap = build_snapshot(vec![], Counters::default(), 0, 0, false);
        let html = route("/", &snap);
        assert_eq!(html.status, 200);
        assert_eq!(html.content_type, "text/html; charset=utf-8");
        assert!(html.body.starts_with(b"<!DOCTYPE html>"));

        let json = route("/stats.json", &snap);
        assert_eq!(json.status, 200);
        assert_eq!(json.content_type, "application/json");
        assert!(json.body.starts_with(b"{"));

        let png = route("/mascot.png", &snap);
        assert_eq!(png.status, 200);
        assert_eq!(png.content_type, "image/png");
        assert_eq!(&png.body[..8], b"\x89PNG\r\n\x1a\n");

        let missing = route("/nope", &snap);
        assert_eq!(missing.status, 404);
    }

    #[test]
    fn https_location_uses_the_request_host_and_target() {
        let head = RequestHead {
            method: "GET".into(),
            target: "/stats.json?full=1".into(),
            host: Some("relay.dig.net".into()),
            is_websocket_upgrade: false,
        };
        assert_eq!(
            https_location(&head),
            "https://relay.dig.net/stats.json?full=1"
        );
        // A (non-conformant) request without Host still yields an absolute, secure Location.
        let no_host = RequestHead { host: None, ..head };
        assert_eq!(
            https_location(&no_host),
            "https://relay.dig.net/stats.json?full=1"
        );
    }

    #[test]
    fn html_handles_the_four_states_and_uses_stats_json() {
        // The page must fetch the machine endpoint and carry copy for every async state.
        assert!(DASHBOARD_HTML.contains("/stats.json"));
        assert!(DASHBOARD_HTML.contains("Loading relay stats")); // loading
        assert!(DASHBOARD_HTML.contains("Could not load relay stats")); // error
        assert!(DASHBOARD_HTML.contains("No peers connected yet")); // empty
        assert!(DASHBOARD_HTML.contains("Connected peers")); // success
        assert!(DASHBOARD_HTML.contains("setInterval(refresh, 5000)")); // ~5s auto-refresh
    }

    #[test]
    fn embedded_mascot_is_a_real_png() {
        // The DIG robot mascot is compiled into the binary so the dashboard is self-contained
        // (no external asset fetch, no CDN). It must be the real PNG, not an empty placeholder.
        assert!(!MASCOT_PNG.is_empty(), "mascot must be embedded");
        assert_eq!(
            &MASCOT_PNG[..8],
            b"\x89PNG\r\n\x1a\n",
            "mascot must carry the PNG magic header"
        );
    }

    #[test]
    fn page_is_dig_network_branded_with_the_mascot() {
        // The dashboard wears the DIG Network brand: the robot mascot, the DIG wordmark, and links
        // back to the network's front doors (dig.net + hub.dig.net).
        assert!(DASHBOARD_HTML.contains("/mascot.png"), "shows the mascot");
        assert!(
            DASHBOARD_HTML.contains("DIG Network"),
            "carries the DIG Network wordmark"
        );
        assert!(
            DASHBOARD_HTML.contains("https://dig.net"),
            "links to dig.net"
        );
        assert!(
            DASHBOARD_HTML.contains("https://hub.dig.net"),
            "links to hub.dig.net"
        );
    }
}
