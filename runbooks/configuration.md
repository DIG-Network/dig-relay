# Runbook — configuring / running a dig-relay

How to run a relay and every knob you can tune. The normative contract is `SPEC.md` §7; this is the
operator's quick reference. Every knob has a CLI flag (`--flag`) AND an environment variable
(`DIG_RELAY_*`); the installed OS service persists the env form so it serves identically to a
foreground `serve`.

## Run it

```sh
dig-relay serve                       # foreground, all defaults
dig-relay serve --listen [::]:9450    # override a knob via a flag
dig-relay install && dig-relay start  # install + run as an OS service (SCM/systemd/launchd)
dig-relay status                      # probe /health (exit 1 if not serving)
```

## Listeners & core limits

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--listen` | `DIG_RELAY_LISTEN` | `[::]:9450` | Relay WebSocket listener (dual-stack). |
| `--health-listen` | `DIG_RELAY_HEALTH_LISTEN` | `[::]:9451` | HTTP `/health` for the load balancer. |
| `--dashboard-listen` | `DIG_RELAY_DASHBOARD_LISTEN` | `[::]:80` | Plain-HTTP → HTTPS redirect listener. |
| `--stun-listen` | `DIG_RELAY_STUN_LISTEN` | `[::]:3478` | STUN (RFC 5389) UDP listener. |
| `--max-connections` | `DIG_RELAY_MAX_CONNECTIONS` | 4096 | Global concurrent-connection cap. |
| `--idle-timeout-secs` | — | 120 | Reap a silent registered connection after this. |
| `--register-timeout-secs` | `DIG_RELAY_REGISTER_TIMEOUT_SECS` | 10 | Drop a connect-but-never-register socket. |
| `--outbound-queue-capacity` | `DIG_RELAY_OUTBOUND_QUEUE_CAPACITY` | 1024 | Per-connection outbound queue bound. |
| `--max-message-bytes` | `DIG_RELAY_MAX_MESSAGE_BYTES` | 262144 | Max inbound frame size. |

## STUN reflector limits (§5.1)

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--stun-per-ip-rps` | `DIG_RELAY_STUN_PER_IP_RPS` | 5 | STUN responses/sec/source IP (`0` disables). |
| `--stun-global-rps` | `DIG_RELAY_STUN_GLOBAL_RPS` | 1000 | STUN responses/sec across all sources (`0` disables). |

## Health sweep (#1382)

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--health-check-interval-secs` | `DIG_RELAY_HEALTH_CHECK_INTERVAL_SECS` | 30 | How often dead/half-open registrations are pruned. |
| `--liveness-deadline-secs` | `DIG_RELAY_LIVENESS_DEADLINE_SECS` | 90 | No-inbound-frame deadline before a registration is pruned. |

## App-level abuse protection (#1386)

Per-source-IP + per-connection limits (`SPEC.md` §3.0). All default ON; set any to `0` to disable that
dimension. Source IPs are keyed by `limits::ip_key` (IPv4 /32, IPv6 /64 prefix, IPv4-mapped collapses
to IPv4). Registration breaches are refused with `Error{code:7, RATE_LIMITED}`; per-connection breaches
disconnect the socket.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--max-connections-per-ip` | `DIG_RELAY_MAX_CONNECTIONS_PER_IP` | 64 | Concurrent connections/source IP (must be ≤ `max_connections`). |
| `--registrations-per-ip-per-sec` | `DIG_RELAY_REGISTRATIONS_PER_IP_PER_SEC` | 10 | `Register` attempts/sec/source IP. |
| `--max-registrations-per-ip` | `DIG_RELAY_MAX_REGISTRATIONS_PER_IP` | 128 | Concurrent live registrations/source IP. |
| `--messages-per-conn-per-sec` | `DIG_RELAY_MESSAGES_PER_CONN_PER_SEC` | 256 | Inbound frames/sec/connection before disconnect. |
| `--bytes-per-conn-per-sec` | `DIG_RELAY_BYTES_PER_CONN_PER_SEC` | 1048576 | Inbound bytes/sec/connection before disconnect. |
| `--max-relayed-bytes-per-conn` | `DIG_RELAY_MAX_RELAYED_BYTES_PER_CONN` | 1073741824 | Cumulative inbound bytes/connection before disconnect. |

## mTLS (optional, §3.2/§8)

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--tls-cert` | `DIG_RELAY_TLS_CERT_PATH` | unset | Relay's own cert (PEM); set with `--tls-key` to terminate mTLS. |
| `--tls-key` | `DIG_RELAY_TLS_KEY_PATH` | unset | Relay's own key (PEM), paired with `--tls-cert`. |
