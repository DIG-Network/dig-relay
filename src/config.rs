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

/// Validated relay server configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayServerConfig {
    /// Address the relay WebSocket listener binds (default `[::]:9450`, dual-stack).
    pub listen: SocketAddr,
    /// Address the HTTP `/health` listener binds (default `[::]:9451`, dual-stack).
    pub health_listen: SocketAddr,
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
            stun_listen: SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, DEFAULT_STUN_PORT)),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            idle_timeout: Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS),
            stun_per_ip_responses_per_sec: DEFAULT_STUN_PER_IP_RESPONSES_PER_SEC,
            stun_global_responses_per_sec: DEFAULT_STUN_GLOBAL_RESPONSES_PER_SEC,
            outbound_queue_capacity: DEFAULT_OUTBOUND_QUEUE_CAPACITY,
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            register_timeout: Duration::from_secs(DEFAULT_REGISTER_TIMEOUT_SECS),
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
}
