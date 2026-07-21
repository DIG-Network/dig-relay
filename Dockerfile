# dig-relay — public container image (the APP only).
#
# This image builds and runs the dig-relay server. The deployment wiring for the canonical
# relay.dig.net (Terraform, DNS, ACM certs, load balancer) is maintained PRIVATELY and is NOT part
# of this repo or this image. The image speaks plain ws:// — in production TLS is terminated at the
# load balancer (see DESIGN.md). Anyone may run this image to operate their own relay.
#
# Build:  docker build -t dig-relay .
# Run:    docker run -p 9450:9450 -p 9451:9451 -p 3478:3478/udp dig-relay
#         (9450 = relay WebSocket, 9451 = HTTP /health for the load balancer,
#          3478/udp = STUN RFC 5389 Binding responder for reflexive-address discovery)

# ---- geoip stage: fetch the free offline geo-IP database ----
# The /map globe geo-locates registered peers SERVER-SIDE from a bundled offline MaxMind-format
# (.mmdb) database (see src/geoip.rs) — never a per-request third-party lookup (that would leak peer
# IPs). We bake in DB-IP City Lite: free, CC-BY (NO license key), coarse city-level accuracy — which
# is all the deliberately-coarse ~5° /map grid needs. Attribution is already in the /map footer.
# Downloaded + unpacked in this throwaway stage so the ~130 MB uncompressed .mmdb is the only geoip
# artifact copied into the final image (curl/gzip/apt caches stay out of it).
# Bump DBIP_MONTH monthly to the newest available YYYY-MM (DB-IP retains ~2 recent months).
FROM debian:bookworm-slim AS geoip
ARG DBIP_MONTH=2026-07
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    mkdir -p /opt/dig-relay/geoip; \
    curl -fsSL --retry 3 --retry-delay 2 \
      "https://download.db-ip.com/free/dbip-city-lite-${DBIP_MONTH}.mmdb.gz" -o /tmp/dbip.mmdb.gz; \
    gunzip -c /tmp/dbip.mmdb.gz > /opt/dig-relay/geoip/dbip-city-lite.mmdb; \
    rm /tmp/dbip.mmdb.gz; \
    test -s /opt/dig-relay/geoip/dbip-city-lite.mmdb

# ---- build stage ----
FROM rust:1-bookworm AS build
WORKDIR /src
# Copy the manifest first for layer caching, then the sources.
COPY Cargo.toml ./
COPY src ./src
COPY tests ./tests
# The dashboard embeds the DIG mascot via include_bytes!("../assets/…") — the asset dir must be
# present in the build context or the compile fails ("couldn't read assets/minion-dighub.png").
COPY assets ./assets
RUN cargo build --release --bin dig-relay

# ---- runtime stage ----
# Debian slim: small, glibc, no extra runtime deps (the relay is a static-ish Rust binary with only
# libc; no OpenSSL — TLS is at the load balancer).
FROM debian:bookworm-slim
RUN useradd --system --no-create-home --uid 10001 digrelay
COPY --from=build /src/target/release/dig-relay /usr/local/bin/dig-relay
# The offline geo-IP database for the /map globe (see the geoip stage above + src/geoip.rs). Path +
# env match src/geoip.rs::DEFAULT_GEOIP_DB_PATH; COPY leaves it world-readable so uid 10001 can read
# it. If this file is ever absent the relay still serves /map — every peer just shows as "unlocated".
COPY --from=geoip /opt/dig-relay/geoip/dbip-city-lite.mmdb /opt/dig-relay/geoip/dbip-city-lite.mmdb
ENV DIG_RELAY_GEOIP_DB=/opt/dig-relay/geoip/dbip-city-lite.mmdb
USER digrelay
EXPOSE 9450 9451
EXPOSE 3478/udp
# The peer-stats dashboard defaults to :80, which this non-root (uid 10001) user cannot bind; run it
# on an unprivileged port and front it at :80 in the orchestrator, e.g.
# `dig-relay serve --dashboard-listen [::]:8080` (relay.dig.net maps NLB :80 → container :8080).
EXPOSE 8080
# Bind all interfaces inside the container; the orchestrator maps/fronts the ports.
ENTRYPOINT ["/usr/local/bin/dig-relay"]
