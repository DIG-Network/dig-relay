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

# ---- build stage ----
FROM rust:1-bookworm AS build
WORKDIR /src
# Copy the manifest first for layer caching, then the sources.
COPY Cargo.toml ./
COPY src ./src
COPY tests ./tests
RUN cargo build --release --bin dig-relay

# ---- runtime stage ----
# Debian slim: small, glibc, no extra runtime deps (the relay is a static-ish Rust binary with only
# libc; no OpenSSL — TLS is at the load balancer).
FROM debian:bookworm-slim
RUN useradd --system --no-create-home --uid 10001 digrelay
COPY --from=build /src/target/release/dig-relay /usr/local/bin/dig-relay
USER digrelay
EXPOSE 9450 9451
EXPOSE 3478/udp
# Bind all interfaces inside the container; the orchestrator maps/fronts the ports.
ENTRYPOINT ["/usr/local/bin/dig-relay"]
