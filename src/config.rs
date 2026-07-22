//! Relay server configuration — pure, validated, unit-tested.
//!
//! The relay listens for DIG-node WebSocket connections on [`RelayServerConfig::listen`]
//! (default `[::]:9450`, matching `dig_gossip`'s `DEFAULT_RELAY_PORT`), exposes a tiny
//! HTTP `/health` endpoint on [`RelayServerConfig::health_listen`] (default `[::]:9451`) for
//! the AWS load balancer's target-group health check, and answers STUN Binding Requests on
//! [`RelayServerConfig::stun_listen`] (default `[::]:3478`, the IANA STUN port, UDP) so a NAT'd
//! node can learn its public reflexive address (RFC 5389).
//!
//! **IPv6-first, IPv4-fallback (dig_ecosystem hard rule):** all three defaults bind the IPv6
//! unspecified address `[::]` rather than the IPv4 wildcard `0.0.0.0`. Each bind site
//! (`server.rs`, `health.rs`, `stun.rs`) clears `IPV6_V6ONLY` on the resulting socket via
//! `socket2`, so the one `[::]` socket stays **dual-stack**: it accepts native IPv6 connections
//! and IPv4 (via IPv4-mapped IPv6) connections on the same listener. A custom `--listen`/
//! `--health-listen`/`--stun-listen` value is used verbatim (an operator who passes an explicit
//! IPv4 address gets IPv4-only, as requested).
//!
//! Limits ([`max_connections`](RelayServerConfig::max_connections)) and the keepalive
//! [`idle_timeout`](RelayServerConfig::idle_timeout) let a single relay be sized to its instance:
//! a node holds ONE long-lived connection, so connection count is the dominant scaling axis.

use std::net::SocketAddr;
use std::time::Duration;

/// The default relay WebSocket port. Mirrors `dig_gossip::constants::DEFAULT_RELAY_PORT` (9450)
/// so a node configured with the gossip default reaches this server without extra config.
pub const DEFAULT_RELAY_PORT: u16 = 9450;

/// The default HTTP health-check port (relay port + 1). Kept separate from the WebSocket port so
/// the load balancer's HTTP health check never collides with relay traffic on an NLB.
pub const DEFAULT_HEALTH_PORT: u16 = 9451;

/// The default HTTP port for the public peer-stats **dashboard** — the **unprivileged** port
/// **8080**, so the relay's non-root service user (the Docker image runs as uid 10001; Fargate does
/// not grant `NET_BIND_SERVICE`) can bind it directly. The orchestrator fronts it at the public
/// well-known port (the `relay.dig.net` NLB maps `:80` → the container's `:8080`). Binding the
/// privileged port `:80` directly requires root / `CAP_NET_BIND_SERVICE`, which the relay does not
/// have — hence the unprivileged default. Kept off the relay/health/STUN ports (a distinct NLB
/// listener → this dashboard target port); it is a READ-ONLY HTTP surface and never touches the
/// `RelayMessage` wire.
pub const DEFAULT_DASHBOARD_PORT: u16 = 8080;

/// The default STUN (RFC 5389) UDP port: **3478**, the IANA-assigned STUN port, matching the DIG
/// node peer-network protocol (STUN served at `relay.dig.net:3478`). A NAT'd DIG Node sends a
/// Binding Request here to learn its public reflexive `IP:port` before advertising a
/// hole-punch/introducer candidate. UDP, so it never collides with the TCP WebSocket (9450) or
/// health (9451) listeners — on the NLB it is a distinct UDP target group.
pub const DEFAULT_STUN_PORT: u16 = 3478;

/// Default cap on concurrent relay connections. A connection is cheap (a `RelayPeerInfo` + a
/// WebSocket), so the smallest always-on instance handles many; horizontal scale adds instances.
pub const DEFAULT_MAX_CONNECTIONS: usize = 4096;

/// Default idle timeout: a connection with no ping/pong/traffic for this long is reaped so the
/// registry stays accurate. Generous relative to the gossip client's 30 s ping interval.
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 120;

/// Default per-source-IP STUN response budget (responses per second per IP). A legitimate NAT'd node
/// sends a Binding Request only occasionally (before advertising a candidate / on a refresh), so a
/// handful per second per IP is generous; it caps how fast the relay will reflect toward any single
/// (spoofable) source address, so it can never be an unlimited open reflector for one victim.
pub const DEFAULT_STUN_PER_IP_RESPONSES_PER_SEC: u32 = 5;

/// Default GLOBAL STUN response budget (responses per second across all sources). A backstop cap on
/// the relay's total outbound STUN reflection so a distributed spoof (many forged source IPs) still
/// cannot turn the relay into a high-volume reflector; well above any legitimate aggregate need.
pub const DEFAULT_STUN_GLOBAL_RESPONSES_PER_SEC: u32 = 1000;

/// Bound on each connection's outbound message queue depth (one bound applies to the RLY channel and,
/// separately, to the PEX channel). A relay peer only receives forwards, broadcasts, and peer
/// notifications — a small queue absorbs normal bursts, while the bound means a slow or hostile reader
/// that stops draining its socket can only ever hold this many buffered messages before further sends
/// to it are dropped, so the relay heap stays bounded (SECURITY_AUDIT_P2P dig-relay #3).
pub const DEFAULT_OUTBOUND_QUEUE_CAPACITY: usize = 1024;

/// Bound on the size (in bytes) of a single inbound WebSocket message / frame the relay will accept.
/// Relay control/gossip frames (register, ping, hole_punch, get_peers, RelayGossipMessage) are tiny;
/// a small ceiling rejects an oversized frame at the protocol layer before a large allocation, rather
/// than letting tungstenite's 64 MiB default reassemble it (SECURITY_AUDIT_P2P dig-relay #4).
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 256 * 1024;

/// Timeout (seconds) within which an accepted connection MUST complete RLY-001 `Register`. A socket
/// that connects and never registers is dropped after this, distinct from the (longer) post-register
/// idle timeout — so half-open/never-registering sockets cannot sit and consume resources
/// (SECURITY_AUDIT_P2P dig-relay #5).
pub const DEFAULT_REGISTER_TIMEOUT_SECS: u64 = 10;

/// Default cadence (seconds) of the ACTIVE registry health sweep (#1382). On this interval the relay
/// scans its whole registry and PROMPTLY prunes any registration whose connection is dead
/// (`tx.is_closed()`) or that has shown no inbound activity for longer than
/// [`liveness_deadline`](RelayServerConfig::liveness_deadline) — a half-open / silently-dead peer.
/// Pruning removes the record from introductions (RLY-005) + the PEX advertisable set (RLY-008) at
/// once, so a dead peer is never handed out. Aligned to the gossip client's 30 s keepalive: sweeping
/// once per keepalive is ample and cheap (a single registry scan).
pub const DEFAULT_HEALTH_CHECK_INTERVAL_SECS: u64 = 30;

/// Default liveness deadline (seconds): a REGISTERED connection with no inbound frame for this long is
/// treated as dead by the health sweep (#1382) and pruned. Set to 3× the gossip client's 30 s
/// keepalive so a live peer (which pings every 30 s) is never falsely pruned — only a peer that has
/// missed several consecutive keepalives (a half-open / vanished host) is. Deliberately SHORTER than
/// [`idle_timeout`](RelayServerConfig::idle_timeout) (120 s) so the active sweep — which also clears
/// the peer from introductions/PEX — reclaims a dead record well before the passive per-connection
/// idle backstop would, and the record is not handed out in the meantime.
///
/// Detection is by inbound activity, NOT by a returned pong: the relay client answers the relay's
/// keepalive pongs but does not itself reply to a relay-initiated ping (it only SENDS keepalive
/// pings), so a live peer's liveness is proven by its own inbound keepalive traffic, never by an
/// echo the client would not send.
pub const DEFAULT_LIVENESS_DEADLINE_SECS: u64 = 90;

/// Default cap on concurrent OPEN connections from a single source IP (#1386). The global
/// [`DEFAULT_MAX_CONNECTIONS`] cap alone lets one abusive host exhaust every slot; this per-IP cap
/// means no single source can hold more than a modest share, so a distributed set of legitimate
/// nodes always has room. A legitimate host runs one (or a handful of) node(s), so 64 is generous;
/// `0` disables the per-IP cap (STUN-limit precedent). SHOULD be `<= max_connections`.
pub const DEFAULT_MAX_CONNECTIONS_PER_IP: u32 = 64;

/// Default per-source-IP registration RATE budget (RLY-001 `Register` attempts per second per IP,
/// #1386). Registration is comparatively expensive (registry insert + PEX mirror + peer fan-out), so
/// a single IP hammering `Register` is throttled to this sustained rate; `0` disables the limit. A
/// real node registers once per connection, so a handful per second per IP is far above legitimate need.
pub const DEFAULT_REGISTRATIONS_PER_IP_PER_SEC: u32 = 10;

/// Default cap on CONCURRENT live registrations from a single source IP (#1386). Bounds how many
/// distinct `peer_id`s one source may hold registered at once (each is an advertisable introduction),
/// so one host cannot flood the peer set other nodes are handed. `0` disables the cap.
pub const DEFAULT_MAX_REGISTRATIONS_PER_IP: u32 = 128;

/// Default per-connection inbound MESSAGE-rate budget (frames per second, #1386). A well-behaved peer
/// sends keepalives + occasional control/gossip frames; a connection exceeding this sustained frame
/// rate is a flood and the connection is disconnected. `0` disables the per-connection message limit.
pub const DEFAULT_MESSAGES_PER_CONN_PER_SEC: u32 = 256;

/// Default per-connection inbound BYTE-rate budget (bytes per second, #1386). Caps sustained inbound
/// throughput per connection independently of frame count; a connection exceeding it is disconnected.
/// `0` disables the per-connection byte-rate limit. 1 MiB/s is generous for relay control/gossip.
pub const DEFAULT_BYTES_PER_CONN_PER_SEC: u32 = 1_048_576;

/// Default CUMULATIVE inbound-bytes ceiling for a single connection's whole lifetime (#1386). A
/// connection that has relayed more than this total is disconnected regardless of its instantaneous
/// rate, bounding the work one long-lived connection can extract. `0` disables the cumulative cap.
/// 1 GiB is far above any legitimate relay-fallback session.
pub const DEFAULT_MAX_RELAYED_BYTES_PER_CONN: u64 = 1_073_741_824;

/// Validated relay server configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayServerConfig {
    /// Address the relay WebSocket listener binds (default `[::]:9450`, dual-stack).
    pub listen: SocketAddr,
    /// Address the HTTP `/health` listener binds (default `[::]:9451`, dual-stack).
    pub health_listen: SocketAddr,
    /// Address the plain-HTTP **redirect** listener binds (default `[::]:8080`, dual-stack — the
    /// unprivileged port the non-root service user can bind; the orchestrator fronts it at public
    /// `:80`, e.g. the `relay.dig.net` NLB maps `:80` → this `:8080`). The relay serves content only
    /// over HTTPS/WSS, so this port `301`s every request to `https://<host><path>`; the dashboard
    /// itself (`GET /`, `/stats.json`, `/mascot.png`) is served over TLS on `listen`.
    pub dashboard_listen: SocketAddr,
    /// Address the STUN (RFC 5389) UDP listener binds (default `[::]:3478`, the IANA STUN port,
    /// dual-stack).
    pub stun_listen: SocketAddr,
    /// Maximum concurrent relay connections; new connections past this are refused.
    pub max_connections: usize,
    /// Idle timeout after which a silent connection is reaped.
    pub idle_timeout: Duration,
    /// Per-source-IP STUN response budget (responses/sec/IP). `0` disables the per-IP limit.
    pub stun_per_ip_responses_per_sec: u32,
    /// Global STUN response budget (responses/sec across all sources). `0` disables the global cap.
    pub stun_global_responses_per_sec: u32,
    /// Bound on each per-connection outbound queue (RLY and PEX each get this bound). A full queue
    /// means the peer is not draining; further sends to it are dropped so the relay heap stays bounded.
    pub outbound_queue_capacity: usize,
    /// Max bytes for a single inbound WebSocket message/frame; an oversized frame is rejected before
    /// a large allocation.
    pub max_message_bytes: usize,
    /// Time an accepted connection has to complete RLY-001 `Register` before it is dropped.
    pub register_timeout: Duration,
    /// Cadence of the active registry health sweep (#1382): how often the relay scans its registry and
    /// prunes dead / half-open registrations. See [`DEFAULT_HEALTH_CHECK_INTERVAL_SECS`].
    pub health_check_interval: Duration,
    /// How long a registered connection may go with no inbound activity before the health sweep prunes
    /// it as dead (#1382). Kept `< idle_timeout` so the active sweep reclaims a dead record — and pulls
    /// it from introductions/PEX — before the passive idle backstop. See
    /// [`DEFAULT_LIVENESS_DEADLINE_SECS`].
    pub liveness_deadline: Duration,
    /// Optional path to the relay's OWN TLS certificate (PEM). When set together with
    /// [`tls_key_path`](Self::tls_key_path), the relay terminates TLS itself on [`listen`](Self::listen)
    /// and REQUIRES every client to present a certificate (mTLS) — `src/tls.rs` derives
    /// `peer_id = SHA-256(TLS SPKI DER)` from it and `src/server.rs::register_peer` requires the
    /// `Register` message's claimed `peer_id` to match (SPEC.md §3.2/§8, proof-of-possession).
    /// `None` (the default) keeps the relay speaking plain `ws://`, matching the canonical
    /// `relay.dig.net` deployment where TLS is terminated at the load balancer.
    pub tls_cert_path: Option<std::path::PathBuf>,
    /// Optional path to the relay's OWN TLS private key (PEM), paired with
    /// [`tls_cert_path`](Self::tls_cert_path).
    pub tls_key_path: Option<std::path::PathBuf>,
    /// Max concurrent OPEN connections from a single source IP (#1386). `0` disables the per-IP cap.
    /// SHOULD be `<= max_connections` (a per-IP cap above the global cap can never bind). See
    /// [`DEFAULT_MAX_CONNECTIONS_PER_IP`].
    pub max_connections_per_ip: u32,
    /// Per-source-IP `Register` RATE budget (attempts/sec/IP, #1386). `0` disables the limit. See
    /// [`DEFAULT_REGISTRATIONS_PER_IP_PER_SEC`].
    pub registrations_per_ip_per_sec: u32,
    /// Max CONCURRENT live registrations from a single source IP (#1386). `0` disables the cap. See
    /// [`DEFAULT_MAX_REGISTRATIONS_PER_IP`].
    pub max_registrations_per_ip: u32,
    /// Per-connection inbound MESSAGE-rate budget (frames/sec, #1386). `0` disables the limit; a
    /// breach DISCONNECTS the connection. See [`DEFAULT_MESSAGES_PER_CONN_PER_SEC`].
    pub messages_per_conn_per_sec: u32,
    /// Per-connection inbound BYTE-rate budget (bytes/sec, #1386). `0` disables the limit; a breach
    /// DISCONNECTS the connection. See [`DEFAULT_BYTES_PER_CONN_PER_SEC`].
    pub bytes_per_conn_per_sec: u32,
    /// Cumulative inbound-bytes ceiling for a single connection's whole lifetime (#1386). `0`
    /// disables the cap; a breach DISCONNECTS the connection. See
    /// [`DEFAULT_MAX_RELAYED_BYTES_PER_CONN`].
    pub max_relayed_bytes_per_conn: u64,
}

impl Default for RelayServerConfig {
    fn default() -> Self {
        // IPv6-first, IPv4-fallback (dig_ecosystem hard rule): bind the unspecified IPv6 address
        // `[::]` rather than the IPv4 wildcard `0.0.0.0`. The TCP/UDP bind sites (server.rs,
        // health.rs, stun.rs) then clear IPV6_V6ONLY on the resulting socket so this single `[::]`
        // listener stays DUAL-STACK — it keeps accepting IPv4 (and IPv4-mapped) peers exactly as
        // before, it just also accepts native IPv6 ones.
        RelayServerConfig {
            listen: SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, DEFAULT_RELAY_PORT)),
            health_listen: SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, DEFAULT_HEALTH_PORT)),
            dashboard_listen: SocketAddr::from((
                std::net::Ipv6Addr::UNSPECIFIED,
                DEFAULT_DASHBOARD_PORT,
            )),
            stun_listen: SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, DEFAULT_STUN_PORT)),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            idle_timeout: Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS),
            stun_per_ip_responses_per_sec: DEFAULT_STUN_PER_IP_RESPONSES_PER_SEC,
            stun_global_responses_per_sec: DEFAULT_STUN_GLOBAL_RESPONSES_PER_SEC,
            outbound_queue_capacity: DEFAULT_OUTBOUND_QUEUE_CAPACITY,
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            register_timeout: Duration::from_secs(DEFAULT_REGISTER_TIMEOUT_SECS),
            health_check_interval: Duration::from_secs(DEFAULT_HEALTH_CHECK_INTERVAL_SECS),
            liveness_deadline: Duration::from_secs(DEFAULT_LIVENESS_DEADLINE_SECS),
            tls_cert_path: None,
            tls_key_path: None,
            max_connections_per_ip: DEFAULT_MAX_CONNECTIONS_PER_IP,
            registrations_per_ip_per_sec: DEFAULT_REGISTRATIONS_PER_IP_PER_SEC,
            max_registrations_per_ip: DEFAULT_MAX_REGISTRATIONS_PER_IP,
            messages_per_conn_per_sec: DEFAULT_MESSAGES_PER_CONN_PER_SEC,
            bytes_per_conn_per_sec: DEFAULT_BYTES_PER_CONN_PER_SEC,
            max_relayed_bytes_per_conn: DEFAULT_MAX_RELAYED_BYTES_PER_CONN,
        }
    }
}

impl RelayServerConfig {
    /// Validate the config, returning a stable error string on misconfiguration.
    ///
    /// Rejects a zero connection cap (a relay that can hold no peers is always a misconfiguration)
    /// and a zero idle timeout (would reap every connection instantly).
    pub fn validate(&self) -> Result<(), String> {
        if self.max_connections == 0 {
            return Err("max_connections must be >= 1".to_string());
        }
        if self.idle_timeout.is_zero() {
            return Err("idle_timeout must be > 0".to_string());
        }
        if self.outbound_queue_capacity == 0 {
            return Err("outbound_queue_capacity must be >= 1".to_string());
        }
        if self.max_message_bytes == 0 {
            return Err("max_message_bytes must be >= 1".to_string());
        }
        if self.register_timeout.is_zero() {
            return Err("register_timeout must be > 0".to_string());
        }
        if self.health_check_interval.is_zero() {
            return Err("health_check_interval must be > 0".to_string());
        }
        if self.liveness_deadline.is_zero() {
            return Err("liveness_deadline must be > 0".to_string());
        }
        if self.liveness_deadline < self.health_check_interval {
            return Err("liveness_deadline must be >= health_check_interval".to_string());
        }
        if self.liveness_deadline >= self.idle_timeout {
            return Err(
                "liveness_deadline must be < idle_timeout (idle timeout is the longer backstop)"
                    .to_string(),
            );
        }
        if self.tls_cert_path.is_some() != self.tls_key_path.is_some() {
            return Err("tls_cert_path and tls_key_path must be set together".to_string());
        }
        // A per-IP connection cap ABOVE the global cap could never bind (the global cap is reached
        // first), so it is always a misconfiguration (#1386). `0` disables the per-IP cap entirely.
        if self.max_connections_per_ip != 0
            && (self.max_connections_per_ip as usize) > self.max_connections
        {
            return Err("max_connections_per_ip must be <= max_connections".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_gossip_relay_port() {
        let c = RelayServerConfig::default();
        assert_eq!(
            c.listen.port(),
            9450,
            "must match dig_gossip DEFAULT_RELAY_PORT"
        );
        assert_eq!(c.health_listen.port(), 9451);
        assert_eq!(
            c.dashboard_listen.port(),
            8080,
            "dashboard defaults to the unprivileged port 8080 (non-root bind; fronted at :80)"
        );
        assert_eq!(c.stun_listen.port(), 3478, "STUN = IANA STUN port 3478");
        assert!(
            c.listen.ip().is_unspecified(),
            "binds all interfaces by default"
        );
        assert!(
            c.stun_listen.ip().is_unspecified(),
            "STUN binds all interfaces by default"
        );
    }

    /// IPv6-first, IPv4-fallback (dig_ecosystem hard rule + SPEC.md "Listener binding"): every
    /// listener's default bind address must be the IPv6 unspecified address `[::]`, not the IPv4
    /// wildcard `0.0.0.0`. Dual-stack (`IPV6_V6ONLY=false`, set at bind time in server.rs/health.rs/
    /// stun.rs) then lets the one `[::]` socket still accept IPv4-mapped peers, so this is additive
    /// to reachability, never a regression for IPv4-only clients.
    #[test]
    fn defaults_are_ipv6_unspecified_not_ipv4_wildcard() {
        let c = RelayServerConfig::default();
        assert!(
            c.listen.is_ipv6(),
            "relay WS listener must default to IPv6 [::], not 0.0.0.0"
        );
        assert_eq!(
            c.listen.ip(),
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        );
        assert!(
            c.health_listen.is_ipv6(),
            "health listener must default to IPv6 [::]"
        );
        assert_eq!(
            c.health_listen.ip(),
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        );
        assert!(
            c.dashboard_listen.is_ipv6(),
            "dashboard listener must default to IPv6 [::]"
        );
        assert_eq!(
            c.dashboard_listen.ip(),
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        );
        assert!(
            c.stun_listen.is_ipv6(),
            "STUN listener must default to IPv6 [::]"
        );
        assert_eq!(
            c.stun_listen.ip(),
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        );
    }

    #[test]
    fn default_is_valid() {
        assert!(RelayServerConfig::default().validate().is_ok());
    }

    /// The STUN reflector protection (SECURITY_AUDIT_P2P dig-relay #2) is ON by default: both the
    /// per-IP and the global response budgets are non-zero out of the box, so a freshly-defaulted
    /// relay is never an unlimited open STUN reflector.
    #[test]
    fn stun_rate_limits_are_enabled_by_default() {
        let c = RelayServerConfig::default();
        assert!(
            c.stun_per_ip_responses_per_sec > 0,
            "per-IP STUN limit must default ON"
        );
        assert!(
            c.stun_global_responses_per_sec > 0,
            "global STUN limit must default ON"
        );
    }

    #[test]
    fn zero_connection_cap_is_rejected() {
        let c = RelayServerConfig {
            max_connections: 0,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn zero_idle_timeout_is_rejected() {
        let c = RelayServerConfig {
            idle_timeout: Duration::from_secs(0),
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn zero_outbound_queue_capacity_is_rejected() {
        let c = RelayServerConfig {
            outbound_queue_capacity: 0,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn zero_max_message_bytes_is_rejected() {
        let c = RelayServerConfig {
            max_message_bytes: 0,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn zero_register_timeout_is_rejected() {
        let c = RelayServerConfig {
            register_timeout: Duration::from_secs(0),
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn tls_paths_default_to_unset_and_are_valid() {
        let c = RelayServerConfig::default();
        assert!(c.tls_cert_path.is_none());
        assert!(c.tls_key_path.is_none());
        assert!(c.validate().is_ok());
    }

    #[test]
    fn tls_cert_path_without_key_path_is_rejected() {
        let c = RelayServerConfig {
            tls_cert_path: Some("cert.pem".into()),
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn tls_key_path_without_cert_path_is_rejected() {
        let c = RelayServerConfig {
            tls_key_path: Some("key.pem".into()),
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn tls_cert_path_and_key_path_together_is_valid() {
        let c = RelayServerConfig {
            tls_cert_path: Some("cert.pem".into()),
            tls_key_path: Some("key.pem".into()),
            ..Default::default()
        };
        assert!(c.validate().is_ok());
    }

    /// Health-sweep defaults (#1382) are present, sane, and correctly ORDERED relative to the idle
    /// backstop: a non-zero sweep cadence, a liveness deadline at least one cadence long, and a
    /// deadline STRICTLY shorter than the passive idle timeout so the active sweep reclaims a dead
    /// record (and clears it from introductions/PEX) before the idle backstop would.
    #[test]
    fn health_sweep_defaults_are_present_and_ordered() {
        let c = RelayServerConfig::default();
        assert_eq!(c.health_check_interval, Duration::from_secs(30));
        assert_eq!(c.liveness_deadline, Duration::from_secs(90));
        assert!(
            c.health_check_interval > Duration::ZERO,
            "sweep cadence must be non-zero"
        );
        assert!(
            c.liveness_deadline >= c.health_check_interval,
            "deadline must be at least one sweep long"
        );
        assert!(
            c.liveness_deadline < c.idle_timeout,
            "liveness deadline must be a shorter, active reclaim vs the idle backstop"
        );
    }

    #[test]
    fn zero_health_check_interval_is_rejected() {
        let c = RelayServerConfig {
            health_check_interval: Duration::from_secs(0),
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn zero_liveness_deadline_is_rejected() {
        let c = RelayServerConfig {
            liveness_deadline: Duration::from_secs(0),
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn liveness_deadline_shorter_than_the_sweep_cadence_is_rejected() {
        let c = RelayServerConfig {
            health_check_interval: Duration::from_secs(60),
            liveness_deadline: Duration::from_secs(30),
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn liveness_deadline_not_shorter_than_idle_timeout_is_rejected() {
        // The idle timeout MUST remain a strictly-longer backstop; a deadline >= idle timeout would
        // make the active sweep pointless (idle would fire first) — reject it.
        let c = RelayServerConfig {
            liveness_deadline: Duration::from_secs(120),
            idle_timeout: Duration::from_secs(120),
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    /// The DoS-hardening defaults (SECURITY_AUDIT_P2P dig-relay #3/#4/#5) are all present and sane out
    /// of the box: a bounded outbound queue, a small max message size, and a finite register timeout.
    #[test]
    fn dos_hardening_defaults_are_bounded() {
        let c = RelayServerConfig::default();
        assert!(c.outbound_queue_capacity > 0, "outbound queue is bounded");
        assert!(
            c.max_message_bytes > 0 && c.max_message_bytes <= 1024 * 1024,
            "message size is bounded to a small realistic ceiling"
        );
        assert!(
            !c.register_timeout.is_zero() && c.register_timeout < c.idle_timeout,
            "register timeout is finite and shorter than the idle timeout"
        );
    }

    /// The app-level abuse limits (#1386) are all present and ON by default: a per-IP connection cap,
    /// per-IP registration rate + concurrent cap, and per-connection message/byte + cumulative caps
    /// are all non-zero out of the box, so a freshly-defaulted relay is protected without config.
    #[test]
    fn abuse_limits_are_enabled_by_default() {
        let c = RelayServerConfig::default();
        assert!(c.max_connections_per_ip > 0, "per-IP conn cap defaults ON");
        assert!(
            c.registrations_per_ip_per_sec > 0,
            "per-IP register rate defaults ON"
        );
        assert!(
            c.max_registrations_per_ip > 0,
            "per-IP concurrent-register cap defaults ON"
        );
        assert!(
            c.messages_per_conn_per_sec > 0,
            "per-conn message rate defaults ON"
        );
        assert!(
            c.bytes_per_conn_per_sec > 0,
            "per-conn byte rate defaults ON"
        );
        assert!(
            c.max_relayed_bytes_per_conn > 0,
            "per-conn cumulative-byte cap defaults ON"
        );
    }

    /// The default per-IP connection cap is within the global connection cap (a per-IP cap above the
    /// global cap could never bind), so the default config satisfies `validate()`'s ordering rule.
    #[test]
    fn default_per_ip_cap_is_within_the_global_cap() {
        let c = RelayServerConfig::default();
        assert!((c.max_connections_per_ip as usize) <= c.max_connections);
    }

    #[test]
    fn per_ip_conn_cap_above_the_global_cap_is_rejected() {
        let c = RelayServerConfig {
            max_connections: 100,
            max_connections_per_ip: 101,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn per_ip_conn_cap_equal_to_the_global_cap_is_allowed() {
        let c = RelayServerConfig {
            max_connections: 100,
            max_connections_per_ip: 100,
            ..Default::default()
        };
        assert!(c.validate().is_ok());
    }

    /// `0` disables the per-IP connection cap, so the "must be <= max_connections" ordering rule does
    /// not apply — a disabled per-IP cap is always valid regardless of the global cap.
    #[test]
    fn zero_per_ip_conn_cap_disables_the_ordering_check() {
        let c = RelayServerConfig {
            max_connections: 1,
            max_connections_per_ip: 0,
            ..Default::default()
        };
        assert!(c.validate().is_ok());
    }

    /// All abuse limits may be individually disabled with `0` (STUN-limit precedent) and the config
    /// stays valid — an operator can opt out of any single dimension.
    #[test]
    fn all_abuse_limits_may_be_disabled_with_zero() {
        let c = RelayServerConfig {
            max_connections_per_ip: 0,
            registrations_per_ip_per_sec: 0,
            max_registrations_per_ip: 0,
            messages_per_conn_per_sec: 0,
            bytes_per_conn_per_sec: 0,
            max_relayed_bytes_per_conn: 0,
            ..Default::default()
        };
        assert!(c.validate().is_ok());
    }
}
