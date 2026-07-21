# Vendored assets — provenance + licenses

These assets are embedded into the `dig-relay` binary (`include_bytes!` in `src/dashboard.rs`) so
`GET /map` is fully self-contained (no CDN, matching the existing dashboard's offline ethos).

## `globe.gl.min.js`

- **Source:** https://unpkg.com/globe.gl@2.46.1/dist/globe.gl.min.js
- **Version:** `2.46.1` (pinned; fetched 2026-07-21)
- **License:** MIT (https://github.com/vasturiano/globe.gl/blob/master/LICENSE)
- This is the self-contained UMD build — it bundles `three` (WebGL), `three-globe`, and
  `three-render-objects` internally, so no separate `three.min.js` vendoring is needed.

## `earth.jpg`

- **Source:** https://raw.githubusercontent.com/vasturiano/three-globe/master/example/img/earth-dark.jpg
- **License:** MIT (same repo as `three-globe`, part of its example assets)
- Chosen over the repo's `earth-blue-marble.jpg` (1.4 MiB) specifically because it renders dark —
  matching the DIG dashboard's dark theme — and is a fraction of the size (~93 KiB).

## Size note

`globe.gl.min.js` (~1.71 MiB) + `earth.jpg` (~93 KiB) totals ~1.8 MiB embedded — slightly over the
original ≲1.5 MiB target, because `globe.gl`'s only self-contained minified build bundles the whole
WebGL stack (three.js + three-globe + three-render-objects) rather than shipping a separate
`three.min.js` an app loads independently. Splitting into a bare `three.min.js` + a `three-globe`
build that expects `THREE` as a global would trade a larger, harder-to-maintain vendoring surface
for a small size win, so the single self-contained bundle was kept. Flagged in the PR for review.
