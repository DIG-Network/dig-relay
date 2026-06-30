//! Relay server configuration — pure, validated, unit-tested.
//!
//! The relay listens for DIG-node WebSocket connections on [`RelayServerConfig::listen`]
//! (default `0.0.0.0:9450`, matching `dig_gossip`'s `DEFAULT_RELAY_PORT`) and exposes a tiny
//! HTTP `/health` endpoint on [`RelayServerConfig::health_listen`] (default `0.0.0.0:9451`) for
//! the AWS load balancer's target-group health check.
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

/// Default cap on concurrent relay connections. A connection is cheap (a `RelayPeerInfo` + a
/// WebSocket), so the smallest always-on instance handles many; horizontal scale adds instances.
pub const DEFAULT_MAX_CONNECTIONS: usize = 4096;

/// Default idle timeout: a connection with no ping/pong/traffic for this long is reaped so the
/// registry stays accurate. Generous relative to the gossip client's 30 s ping interval.
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 120;

/// Validated relay server configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayServerConfig {
    /// Address the relay WebSocket listener binds (default `0.0.0.0:9450`).
    pub listen: SocketAddr,
    /// Address the HTTP `/health` listener binds (default `0.0.0.0:9451`).
    pub health_listen: SocketAddr,
    /// Maximum concurrent relay connections; new connections past this are refused.
    pub max_connections: usize,
    /// Idle timeout after which a silent connection is reaped.
    pub idle_timeout: Duration,
}

impl Default for RelayServerConfig {
    fn default() -> Self {
        RelayServerConfig {
            listen: SocketAddr::from(([0, 0, 0, 0], DEFAULT_RELAY_PORT)),
            health_listen: SocketAddr::from(([0, 0, 0, 0], DEFAULT_HEALTH_PORT)),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            idle_timeout: Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS),
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
        assert!(
            c.listen.ip().is_unspecified(),
            "binds all interfaces by default"
        );
    }

    #[test]
    fn default_is_valid() {
        assert!(RelayServerConfig::default().validate().is_ok());
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
}
