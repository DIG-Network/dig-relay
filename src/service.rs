//! OS-service registration for run-your-own-relay, across Windows (SCM), Linux (systemd) and macOS
//! (launchd) via the `service-manager` crate.
//!
//! Mirrors dig-node's service approach so the DIG installer delegates to `dig-relay install` /
//! `dig-relay start` exactly as it does for the node. `install` registers `dig-relay serve` to
//! auto-start; `uninstall` removes it; `start`/`stop` control it; `status` probes `/health`.
//!
//! Install level by platform:
//!   * Linux (systemd) / macOS (launchd) — **user-level** by default (no root needed).
//!   * Windows (SCM) — **system-level only** (no per-user services), so `install`/`uninstall`
//!     require an **elevated (Administrator)** console; this is detected up front and reported.

use std::ffi::OsString;
use std::net::SocketAddr;
use std::str::FromStr;

use serde_json::json;
use service_manager::{
    ServiceInstallCtx, ServiceLabel, ServiceLevel, ServiceManager, ServiceStartCtx, ServiceStopCtx,
    ServiceUninstallCtx,
};

use crate::config::RelayServerConfig;

/// The reverse-DNS service label. Becomes the SCM service name / launchd plist label / systemd
/// unit name. Stable so install/uninstall/start/stop address the same service.
pub const SERVICE_LABEL: &str = "net.dignetwork.dig-relay";

#[cfg(windows)]
const PREFERS_USER_LEVEL: bool = false;
#[cfg(not(windows))]
const PREFERS_USER_LEVEL: bool = true;

/// A human summary + a machine-readable JSON result for a service operation (so the CLI can emit
/// either pretty text or `--json`).
#[derive(Debug, Clone)]
pub struct Outcome {
    pub summary: String,
    pub result: serde_json::Value,
}

impl Outcome {
    fn new(summary: impl Into<String>, result: serde_json::Value) -> Self {
        Outcome {
            summary: summary.into(),
            result,
        }
    }
}

fn label() -> std::io::Result<ServiceLabel> {
    ServiceLabel::from_str(SERVICE_LABEL)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))
}

/// Acquire the native service manager at user level where supported (Linux/macOS), else system
/// (Windows). Returns the manager + whether it operates at user level (for messaging).
fn manager() -> std::io::Result<(Box<dyn ServiceManager>, bool)> {
    let mut mgr = <dyn ServiceManager>::native()?;
    let mut user_level = false;
    if PREFERS_USER_LEVEL && mgr.set_level(ServiceLevel::User).is_ok() {
        user_level = true;
    }
    Ok((mgr, user_level))
}

fn current_exe() -> std::io::Result<std::path::PathBuf> {
    std::env::current_exe()
}

/// On Windows, is this process elevated (Administrator)? Used to fail install/uninstall early with
/// a helpful message instead of a cryptic SCM access-denied. Always `true` off Windows.
#[cfg(windows)]
fn is_elevated() -> bool {
    std::process::Command::new("net")
        .arg("session")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
#[cfg(not(windows))]
fn is_elevated() -> bool {
    true
}

/// Install the relay as an auto-starting OS service that runs `dig-relay serve` on the configured
/// listen addrs. The listen/health addrs are passed as env so the service serves identically.
pub fn install(config: &RelayServerConfig) -> std::io::Result<Outcome> {
    if cfg!(windows) && !is_elevated() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "dig-relay: installing a Windows service requires an elevated (Administrator) console. \
             Re-run this in a terminal opened with \"Run as administrator\".",
        ));
    }

    let (mgr, user_level) = manager()?;
    let program = current_exe()?;

    let environment = vec![
        ("DIG_RELAY_LISTEN".to_string(), config.listen.to_string()),
        (
            "DIG_RELAY_HEALTH_LISTEN".to_string(),
            config.health_listen.to_string(),
        ),
        (
            "DIG_RELAY_STUN_LISTEN".to_string(),
            config.stun_listen.to_string(),
        ),
        (
            "DIG_RELAY_MAX_CONNECTIONS".to_string(),
            config.max_connections.to_string(),
        ),
    ];

    // The SCM-launched program must speak the Windows service protocol, so on Windows the installed
    // service runs the hidden `run-service` entrypoint; systemd/launchd exec `serve` directly.
    let entry_arg = if cfg!(windows) {
        "run-service"
    } else {
        "serve"
    };

    mgr.install(ServiceInstallCtx {
        label: label()?,
        program: program.clone(),
        args: vec![OsString::from(entry_arg)],
        contents: None,
        username: None,
        working_directory: None,
        environment: Some(environment),
        autostart: true,
    })?;

    let scope = if user_level { "user" } else { "system" };
    let summary = format!(
        "dig-relay: installed as a {scope}-level service \"{SERVICE_LABEL}\"\n  \
         program: {}\n  relay:   ws://{}\n  health:  http://{}\n  \
         Start it now with: dig-relay start",
        program.display(),
        config.listen,
        config.health_listen,
    );
    Ok(Outcome::new(
        summary,
        json!({
            "installed": true,
            "registered": true,
            "started": false,
            "label": SERVICE_LABEL,
            "scope": scope,
            "program": program.display().to_string(),
            "listen": config.listen.to_string(),
            "health_listen": config.health_listen.to_string(),
        }),
    ))
}

/// Uninstall the relay service (best-effort stop first).
pub fn uninstall() -> std::io::Result<Outcome> {
    if cfg!(windows) && !is_elevated() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "dig-relay: uninstalling a Windows service requires an elevated (Administrator) console.",
        ));
    }
    let (mgr, _user) = manager()?;
    let _ = mgr.stop(ServiceStopCtx { label: label()? });
    mgr.uninstall(ServiceUninstallCtx { label: label()? })?;
    Ok(Outcome::new(
        format!("dig-relay: uninstalled service \"{SERVICE_LABEL}\""),
        json!({ "installed": false, "registered": false, "label": SERVICE_LABEL }),
    ))
}

/// Start the installed service.
pub fn start() -> std::io::Result<Outcome> {
    let (mgr, _user) = manager()?;
    mgr.start(ServiceStartCtx { label: label()? })?;
    Ok(Outcome::new(
        format!("dig-relay: start requested for \"{SERVICE_LABEL}\""),
        json!({ "started": true, "label": SERVICE_LABEL }),
    ))
}

/// Stop the running service.
pub fn stop() -> std::io::Result<Outcome> {
    let (mgr, _user) = manager()?;
    mgr.stop(ServiceStopCtx { label: label()? })?;
    Ok(Outcome::new(
        format!("dig-relay: stop requested for \"{SERVICE_LABEL}\""),
        json!({ "stopped": true, "label": SERVICE_LABEL }),
    ))
}

/// Report whether the relay is actually serving, by probing its HTTP `/health` endpoint. Works the
/// same whether the relay runs as a service or a manual `serve`. `result.serving` is the answer.
pub fn status(config: &RelayServerConfig) -> std::io::Result<Outcome> {
    let addr = config.health_listen;
    let url = format!("http://{addr}/health");
    let serving = probe_health(&addr).unwrap_or(false);
    let summary = if serving {
        format!("dig-relay: SERVING (health {url})")
    } else {
        format!("dig-relay: NOT responding at {url} (the service may be stopped or not installed)")
    };
    Ok(Outcome::new(
        summary,
        json!({ "serving": serving, "health_url": url }),
    ))
}

/// Rewrite an unspecified bind address to the matching loopback address (a status check always
/// runs on the same host as the relay). PURE — no I/O, so the family-selection logic is
/// unit-testable without a socket.
///
/// IPv6-first: an unspecified `[::]` bind (this crate's default, per `RelayServerConfig`) probes
/// `::1`, not `127.0.0.1` — a dual-stack `[::]` listener answers on `::1` natively, and probing the
/// same family avoids depending on IPv4-mapped loopback support (not universal on Windows). An
/// unspecified `0.0.0.0` bind (an operator's explicit IPv4-only override) still probes
/// `127.0.0.1` as before. A non-unspecified address is returned unchanged.
fn loopback_probe_addr(addr: SocketAddr) -> SocketAddr {
    if !addr.ip().is_unspecified() {
        return addr;
    }
    let loopback = if addr.is_ipv6() {
        std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
    } else {
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    };
    SocketAddr::new(loopback, addr.port())
}

/// Minimal blocking HTTP/1.0 `GET /health` probe. Returns whether the status line is `2xx`. Avoids
/// pulling an async client into the status path.
fn probe_health(addr: &SocketAddr) -> std::io::Result<bool> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let connect_addr = loopback_probe_addr(*addr);
    let mut stream = match TcpStream::connect(connect_addr) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let req = format!("GET /health HTTP/1.0\r\nHost: {connect_addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes())?;
    let mut chunk = [0u8; 256];
    let n = stream.read(&mut chunk).unwrap_or(0);
    Ok(is_2xx_status_line(&String::from_utf8_lossy(&chunk[..n])))
}

/// Is the first line of an HTTP response a `2xx` status line? PURE — parses only the status line so
/// a stray `2` elsewhere (e.g. a year in a Date header) can never be mistaken for success.
fn is_2xx_status_line(response_head: &str) -> bool {
    let first = response_head.lines().next().unwrap_or("");
    if !first.starts_with("HTTP/") {
        return false;
    }
    first
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .map(|code| (200..300).contains(&code))
        .unwrap_or(false)
}

/// Build a [`RelayServerConfig`] from the service env vars set by [`install`], falling back to
/// defaults. Used by the service entrypoints (systemd/launchd `serve`, Windows `run-service`).
pub fn config_from_env() -> RelayServerConfig {
    let mut config = RelayServerConfig::default();
    if let Some(a) = std::env::var("DIG_RELAY_LISTEN")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        config.listen = a;
    }
    if let Some(a) = std::env::var("DIG_RELAY_HEALTH_LISTEN")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        config.health_listen = a;
    }
    if let Some(a) = std::env::var("DIG_RELAY_STUN_LISTEN")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        config.stun_listen = a;
    }
    if let Some(n) = std::env::var("DIG_RELAY_MAX_CONNECTIONS")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        config.max_connections = n;
    }
    config
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Mutex;

    /// Serializes the env-mutating tests: `config_from_env` reads process-global env, and cargo runs
    /// tests in parallel, so two env tests must never interleave.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// The env vars `config_from_env` reads, cleared so a test starts from a known state.
    const RELAY_ENV: [&str; 4] = [
        "DIG_RELAY_LISTEN",
        "DIG_RELAY_HEALTH_LISTEN",
        "DIG_RELAY_STUN_LISTEN",
        "DIG_RELAY_MAX_CONNECTIONS",
    ];
    fn clear_relay_env() {
        for k in RELAY_ENV {
            std::env::remove_var(k);
        }
    }

    /// Spawn a one-shot blocking HTTP server on 127.0.0.1 that replies with `response` to the first
    /// connection, then returns the bound address. Lets `probe_health` hit a real socket.
    fn one_shot_http(response: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 512];
                let _ = sock.read(&mut buf); // consume the request line
                let _ = sock.write_all(response.as_bytes());
                let _ = sock.flush();
            }
        });
        addr
    }

    #[test]
    fn service_label_parses_to_dig_relay() {
        let l = label().expect("constant label must parse");
        assert_eq!(l.application, "dig-relay");
    }

    #[test]
    fn outcome_new_carries_summary_and_result() {
        let o = Outcome::new("hi", json!({ "k": 1 }));
        assert_eq!(o.summary, "hi");
        assert_eq!(o.result["k"], 1);
    }

    #[test]
    fn is_elevated_is_true_off_windows() {
        // The cross-platform contract: off Windows there is no elevation gate, so it is always true.
        // (On Windows this depends on the console; we only assert the non-Windows guarantee here.)
        if !cfg!(windows) {
            assert!(is_elevated());
        }
    }

    #[test]
    fn status_reports_false_when_nothing_listens() {
        let cfg = RelayServerConfig {
            health_listen: "127.0.0.1:1".parse().unwrap(),
            ..Default::default()
        };
        let outcome = status(&cfg).expect("status never hard-errors on a closed port");
        assert_eq!(outcome.result["serving"], serde_json::json!(false));
        assert!(outcome.summary.contains("NOT responding"));
        assert!(outcome.result["health_url"]
            .as_str()
            .unwrap()
            .ends_with("/health"));
    }

    #[test]
    fn status_reports_true_against_a_live_2xx_health_endpoint() {
        let addr = one_shot_http("HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let cfg = RelayServerConfig {
            health_listen: addr,
            ..Default::default()
        };
        let outcome = status(&cfg).expect("status never hard-errors");
        assert_eq!(
            outcome.result["serving"],
            serde_json::json!(true),
            "a 2xx /health means serving"
        );
        assert!(outcome.summary.contains("SERVING"));
    }

    #[test]
    fn status_reports_false_against_a_live_non_2xx_endpoint() {
        let addr = one_shot_http("HTTP/1.0 503 Service Unavailable\r\n\r\n");
        let cfg = RelayServerConfig {
            health_listen: addr,
            ..Default::default()
        };
        let outcome = status(&cfg).expect("status never hard-errors");
        assert_eq!(
            outcome.result["serving"],
            serde_json::json!(false),
            "a 5xx /health is not serving"
        );
    }

    #[test]
    fn probe_health_true_for_2xx_false_for_4xx_and_closed() {
        // 2xx live server → true.
        let ok = one_shot_http("HTTP/1.1 204 No Content\r\n\r\n");
        assert!(probe_health(&ok).unwrap());
        // 4xx live server → false (connected, but not serving).
        let bad = one_shot_http("HTTP/1.1 404 Not Found\r\n\r\n");
        assert!(!probe_health(&bad).unwrap());
        // Nothing listening → Ok(false) (connect refused is not a hard error).
        let closed: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert!(!probe_health(&closed).unwrap());
    }

    #[test]
    fn probe_health_maps_unspecified_bind_to_loopback() {
        // A relay bound to 0.0.0.0 is probed on 127.0.0.1 (status runs on the same host). We can't
        // bind 0.0.0.0:<known-port> race-free, so assert the port is preserved against a loopback
        // server (the unspecified→loopback rewrite keeps the port).
        let addr = one_shot_http("HTTP/1.1 200 OK\r\n\r\n");
        let unspecified = SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), addr.port());
        // The rewrite targets 127.0.0.1:<port>, which is exactly where our server listens.
        assert!(probe_health(&unspecified).unwrap());
    }

    /// Regression test for IPv6-first (dig_ecosystem hard rule): `RelayServerConfig`'s default bind
    /// is now the IPv6 unspecified `[::]`, so the status probe must rewrite it to `::1` — the
    /// SAME-FAMILY loopback — not silently fall back to `127.0.0.1` (which would depend on
    /// IPv4-mapped loopback support that isn't universal, e.g. on Windows).
    #[test]
    fn loopback_probe_addr_prefers_ipv6_loopback_for_unspecified_ipv6() {
        let unspecified_v6 = SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 9451);
        let probe = loopback_probe_addr(unspecified_v6);
        assert_eq!(
            probe,
            SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), 9451),
            "an unspecified [::] bind must probe ::1, not 127.0.0.1"
        );
    }

    #[test]
    fn loopback_probe_addr_still_prefers_ipv4_loopback_for_unspecified_ipv4() {
        // An operator who explicitly overrides to 0.0.0.0 (IPv4-only) keeps the IPv4 loopback probe.
        let unspecified_v4 = SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 9451);
        let probe = loopback_probe_addr(unspecified_v4);
        assert_eq!(
            probe,
            SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 9451)
        );
    }

    #[test]
    fn loopback_probe_addr_leaves_a_specific_address_unchanged() {
        let specific: SocketAddr = "10.0.0.5:9451".parse().unwrap();
        assert_eq!(loopback_probe_addr(specific), specific);
        let specific_v6: SocketAddr = "[2001:db8::1]:9451".parse().unwrap();
        assert_eq!(loopback_probe_addr(specific_v6), specific_v6);
    }

    #[test]
    fn probe_health_against_ipv6_unspecified_bind_reaches_an_ipv6_loopback_server() {
        // End-to-end: a one-shot server bound to ::1 must be reachable via the unspecified-[::]
        // rewrite, proving `probe_health` itself (not just the pure helper) goes to the right family.
        let listener = std::net::TcpListener::bind("[::1]:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 512];
                let _ = sock.read(&mut buf);
                let _ = sock.write_all(b"HTTP/1.1 200 OK\r\n\r\n");
                let _ = sock.flush();
            }
        });
        let unspecified_v6 = SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), port);
        assert!(probe_health(&unspecified_v6).unwrap());
    }

    #[test]
    fn is_2xx_status_line_parses_the_code_not_stray_digits() {
        assert!(is_2xx_status_line("HTTP/1.1 200 OK\r\nDate: x\r\n"));
        assert!(is_2xx_status_line("HTTP/1.0 204 No Content"));
        assert!(is_2xx_status_line("HTTP/1.1 299 Custom"));
        assert!(!is_2xx_status_line(
            "HTTP/1.0 404 Not Found\r\nDate: Sat, 27 Jun 2026 00:00:00 GMT\r\n"
        ));
        assert!(!is_2xx_status_line("HTTP/1.1 500 Internal Server Error"));
        assert!(!is_2xx_status_line("HTTP/1.1 199 Early"));
        assert!(!is_2xx_status_line("HTTP/1.1 300 Multiple Choices"));
        assert!(!is_2xx_status_line("HTTP/1.1 notanumber x"));
        assert!(!is_2xx_status_line("200 OK")); // missing HTTP/ prefix
        assert!(!is_2xx_status_line("garbage"));
        assert!(!is_2xx_status_line(""));
    }

    #[test]
    fn config_from_env_uses_defaults_when_unset() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_relay_env();
        let c = config_from_env();
        assert_eq!(c, RelayServerConfig::default(), "no env → defaults");
    }

    #[test]
    fn config_from_env_applies_each_env_override() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_relay_env();
        std::env::set_var("DIG_RELAY_LISTEN", "127.0.0.1:7000");
        std::env::set_var("DIG_RELAY_HEALTH_LISTEN", "127.0.0.1:7001");
        std::env::set_var("DIG_RELAY_STUN_LISTEN", "127.0.0.1:7002");
        std::env::set_var("DIG_RELAY_MAX_CONNECTIONS", "12");
        let c = config_from_env();
        clear_relay_env();
        assert_eq!(c.listen, "127.0.0.1:7000".parse().unwrap());
        assert_eq!(c.health_listen, "127.0.0.1:7001".parse().unwrap());
        assert_eq!(c.stun_listen, "127.0.0.1:7002".parse().unwrap());
        assert_eq!(c.max_connections, 12);
        // idle_timeout is not env-driven → stays default.
        assert_eq!(c.idle_timeout, RelayServerConfig::default().idle_timeout);
    }

    #[test]
    fn config_from_env_ignores_unparseable_values() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_relay_env();
        std::env::set_var("DIG_RELAY_LISTEN", "not-an-addr");
        std::env::set_var("DIG_RELAY_MAX_CONNECTIONS", "heaps");
        let c = config_from_env();
        clear_relay_env();
        // Garbage parses to None → the default is kept (never panics).
        assert_eq!(c.listen, RelayServerConfig::default().listen);
        assert_eq!(
            c.max_connections,
            RelayServerConfig::default().max_connections
        );
    }
}
