# Vendored assets — provenance + licenses

These assets are embedded into the `dig-relay` binary (`include_bytes!` in `src/dashboard.rs`) so
`GET /map` is fully self-contained (no CDN, matching the existing dashboard's offline ethos).

## `globe.gl.min.js`

- **Source:** https://unpkg.com/globe.gl@2.46.1/dist/globe.gl.min.js
- **Version:** `2.46.1` (pinned; fetched 2026-07-21)
- **License:** MIT (https://github.com/vasturiano/globe.gl/blob/master/LICENSE)
- This is the self-contained UMD build — it bundles `three` (WebGL), `three-globe`, and
  `three-render-objects` internally, so no separate `three.min.js` vendoring is needed.
- **SHA-256:** `2ab6767f47e2be0ac346cd7a5eb55d259ea3da06d479dc22f1820ddd698f496a`

## `earth.jpg`

- **Source:** https://raw.githubusercontent.com/vasturiano/three-globe/master/example/img/earth-blue-marble.jpg
- **Texture:** NASA **Blue Marble** — the standard `globe.gl` daytime earth texture (4096×2048
  equirectangular).
- **License:** **Public domain.** NASA imagery is not subject to copyright
  (https://visibleearth.nasa.gov/); redistributed here via the `three-globe` example assets (MIT).
- Daytime texture (#1475): `/map` reads as a bright, familiar globe. Peer markers are drawn
  near-opaque (alpha `0.95`, see `colorFor` in `src/dashboard.rs`) so they stay legible over the
  lighter surface rather than washing out (they were tuned for the previous dark texture).
- **Size:** ~1.4 MiB.
- **SHA-256:** `228deba2e4b600146bdcb6cfa359b8ead6aacc2b1c13550a29cd82824cfa1c01`

## Size note

`globe.gl.min.js` (~1.71 MiB) + `earth.jpg` (~1.4 MiB) totals ~3.1 MiB embedded (well under the
`dashboard.rs` 4 MiB embed guard). `globe.gl`'s only self-contained minified build bundles the whole
WebGL stack (three.js + three-globe + three-render-objects) rather than shipping a separate
`three.min.js` an app loads independently; splitting into a bare `three.min.js` + a `three-globe`
build that expects `THREE` as a global would trade a larger, harder-to-maintain vendoring surface
for a small size win, so the single self-contained bundle was kept.

## Geo-IP database (`/opt/dig-relay/geoip/dbip-city-lite.mmdb`, image-only — not embedded)

- **Source:** https://download.db-ip.com/free/dbip-city-lite-YYYY-MM.mmdb.gz (pinned month in the
  `Dockerfile` `geoip` stage; DB-IP retains ~2 recent months).
- **Database:** **DB-IP City Lite** — free, coarse city-level accuracy, which is all the deliberately
  coarse ~5° `/map` grid needs.
- **License:** **CC-BY 4.0** (NO license key required). Attribution ("IP Geolocation by DB-IP") is
  rendered in the `/map` page footer (`src/dashboard.rs`), satisfying the CC-BY term.
- Downloaded + unpacked in a throwaway Docker builder stage and `COPY`d into the final image at the
  path `src/geoip.rs::DEFAULT_GEOIP_DB_PATH` reads (overridable via `DIG_RELAY_GEOIP_DB`). It is NOT
  `include_bytes!`-embedded in the binary (it is ~130 MiB uncompressed).
