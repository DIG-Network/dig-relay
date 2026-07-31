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

/// The scope a caller requests for `install`/`uninstall`/`start`/`stop` — mirrors dig-node's
/// `--scope` flag exactly (dig_ecosystem#526) so `dig-installer` emits one argument form for both
/// components. `Auto` (the default, unchanged behaviour) resolves from privilege via
/// [`resolve_scope`]; `System`/`User` are explicit overrides an operator can force.
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScopeChoice {
    #[default]
    Auto,
    System,
    User,
}

/// The concrete scope a service ends up registered at, after [`resolve_scope`] applies privilege +
/// platform constraints to a [`ScopeChoice`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceScope {
    System,
    User,
}

/// Decide the concrete [`ServiceScope`] for an install/uninstall/start/stop call. PURE — every input
/// is a parameter (no `cfg!`, no `geteuid()`, no filesystem), so the full decision table is testable
/// on any host with no privileges.
///
/// - `os_supports_user == false` (Windows SCM, which has no per-user service manager) ⇒ always
///   `System`. The platform is checked FIRST: there is exactly one scope, so even an explicit
///   `--scope user` cannot be honoured — it resolves to `System` rather than hard-failing, so one
///   installer argument form behaves identically on every OS (dig_ecosystem#526).
/// - Otherwise an explicit `System`/`User` choice is AUTHORITATIVE and always wins, never silently
///   overridden by the privilege level. (Whether the caller MAY register there is the separate,
///   loudly-reported question [`ensure_privilege_for_scope`] answers.)
/// - `Auto` resolves by privilege: `System` when running as root (an elevated `dig-installer` needs
///   a service that survives reboot with no login session — systemd `--user`/launchd per-user agents
///   have neither under `sudo`), else `User` (today's unelevated default, unchanged).
pub fn resolve_scope(choice: ScopeChoice, os_supports_user: bool, is_root: bool) -> ServiceScope {
    if !os_supports_user {
        return ServiceScope::System;
    }
    match choice {
        ScopeChoice::System => ServiceScope::System,
        ScopeChoice::User => ServiceScope::User,
        ScopeChoice::Auto if is_root => ServiceScope::System,
        ScopeChoice::Auto => ServiceScope::User,
    }
}

/// Refuse a system-scope registration the caller cannot actually make, BEFORE anything is written —
/// rather than failing cryptically deep inside `systemctl`/`launchctl` after the cross-scope
/// migration has already torn down a working registration, and rather than silently downgrading to
/// user scope (which on a headless host would not survive a reboot: exactly the defect #526 fixes).
/// PURE, so the policy is table-tested on any host at any privilege level.
///
/// Windows is exempt: it has no user scope, and its elevation requirement is reported by its own SCM
/// gate ([`is_elevated`]) with Windows-specific advice.
fn ensure_privilege_for_scope(
    scope: ServiceScope,
    os_supports_user: bool,
    is_root: bool,
) -> std::io::Result<()> {
    if !os_supports_user || scope == ServiceScope::User || is_root {
        return Ok(());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "dig-relay: registering a system-level (machine-wide, boot-started) service requires root. \
         Re-run with `sudo dig-relay install --scope system`, or install at user scope \
         (`--scope user`) — noting that a user-scope service only starts with your login session \
         and so may not come back after a reboot on a headless host.",
    ))
}

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

/// Is this process running as root? Used to pick `System` scope under `Auto` (dig_ecosystem#526):
/// an elevated `dig-installer` runs Linux/macOS installs as root, where systemd `--user`/launchd
/// per-user agents have no session to register into, so `Auto` must resolve to `System` there.
/// Mirrors [`is_elevated`]'s Administrator check on Windows (where every account able to install a
/// service is already "system-capable", so `Auto` forces `System` via `os_supports_user` instead —
/// see [`resolve_scope`]).
#[cfg(unix)]
fn is_root() -> bool {
    // SAFETY: `geteuid` takes no arguments and cannot fail; it is part of the platform's libc,
    // already linked into every Unix Rust binary.
    unsafe { geteuid() == 0 }
}
#[cfg(unix)]
extern "C" {
    fn geteuid() -> u32;
}
#[cfg(windows)]
fn is_root() -> bool {
    is_elevated()
}

/// Acquire the native service manager fixed at the given [`ServiceScope`] — used by every
/// scope-aware call so `install`/`uninstall`/`start`/`stop` all target the same resolved scope
/// (dig_ecosystem#526). `System` is the manager's baseline level, so it needs no explicit
/// `set_level` call; `User` calls `set_level(ServiceLevel::User)`, which is a no-op inside `manager`
/// but here surfaces a real error on a platform with no user-level manager (Windows) instead of
/// silently installing at system scope under a `User` request.
fn manager_at(scope: ServiceScope) -> std::io::Result<Box<dyn ServiceManager>> {
    let mut mgr = <dyn ServiceManager>::native()?;
    if scope == ServiceScope::User {
        mgr.set_level(ServiceLevel::User).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("dig-relay: this platform has no user-level service manager: {e}"),
            )
        })?;
    }
    Ok(mgr)
}

fn label() -> std::io::Result<ServiceLabel> {
    ServiceLabel::from_str(SERVICE_LABEL)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))
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

/// The `DIG_RELAY_TLS_CERT_PATH`/`DIG_RELAY_TLS_KEY_PATH` env pairs for an installed service's
/// environment (SPEC.md §3.2/§8) — PURE, so [`install`]'s optional mTLS threading is unit-testable
/// without touching a real OS service manager. Empty when either path is unset (a plain `ws://`
/// relay's installed env is unchanged from before this feature).
fn tls_environment_pairs(config: &RelayServerConfig) -> Vec<(String, String)> {
    match (&config.tls_cert_path, &config.tls_key_path) {
        (Some(cert), Some(key)) => vec![
            (
                "DIG_RELAY_TLS_CERT_PATH".to_string(),
                cert.display().to_string(),
            ),
            (
                "DIG_RELAY_TLS_KEY_PATH".to_string(),
                key.display().to_string(),
            ),
        ],
        _ => vec![],
    }
}

/// The scopes `uninstall` must sweep, in the order to sweep them. PURE, same shape as
/// [`resolve_scope`] — every input is a parameter, so the table is testable with no privileges.
///
/// An explicit choice removes exactly what was named. **`Auto` sweeps BOTH scopes** (the resolved
/// one first) on a user-capable OS, REGARDLESS of privilege: a plain `dig-relay uninstall` run by an
/// operator or an uninstall script must not exit 0 having left a system unit that keeps auto-starting
/// at every boot and re-binding the relay's ports (the dig_ecosystem#1863 defect class). Sweeping is
/// safe because the non-requested scope is PROBED before anything is deleted
/// ([`RemovalMode::Swept`]), so a scope holding nothing is never written to.
fn uninstall_scopes(
    choice: ScopeChoice,
    os_supports_user: bool,
    is_root: bool,
) -> Vec<ServiceScope> {
    let requested = resolve_scope(choice, os_supports_user, is_root);
    if !os_supports_user || choice != ScopeChoice::Auto {
        return vec![requested];
    }
    vec![requested, other_scope(requested)]
}

/// The other [`ServiceScope`] — the one [`install`]'s cross-scope migration deregisters from before
/// registering at the requested scope.
fn other_scope(scope: ServiceScope) -> ServiceScope {
    match scope {
        ServiceScope::System => ServiceScope::User,
        ServiceScope::User => ServiceScope::System,
    }
}

/// What to register at a scope: the program the SCM/launchd/systemd runs plus the environment that
/// reproduces the caller's [`RelayServerConfig`], so the installed service serves identically to the
/// `serve` that installed it. Separated from the OS call so [`install_at_scope`]'s ORDER is
/// unit-tested against a recording mock and CI never registers a real service.
#[derive(Debug, Clone, PartialEq, Eq)]
struct InstallPlan {
    program: std::path::PathBuf,
    args: Vec<OsString>,
    environment: Vec<(String, String)>,
    autostart: bool,
}

/// The four primitive OS-service operations the scope-aware flows compose. Behind a trait so the
/// removal policy ([`remove_registration`]) and the migration ORDER ([`install_at_scope`]) are
/// provable with a mock — the real implementation is [`RelayServiceBackend`].
trait ServiceBackend {
    /// Is this service registered at this backend's scope? Advisory — see [`ScopeRemoval`].
    fn is_installed(&self) -> std::io::Result<bool>;
    fn stop(&self) -> std::io::Result<()>;
    fn delete(&self) -> std::io::Result<()>;
    fn create(&self, plan: &InstallPlan) -> std::io::Result<()>;
}

/// What a per-scope removal attempt did — the reporting unit for the cross-scope migration
/// ([`install_at_scope`]) and for [`uninstall`].
///
/// `found` (what the PROBE saw) and `removed` (what the OS deregistration actually did) are
/// deliberately separate, because **the probe is advisory and the deregistration is authoritative**:
/// `systemctl --user` / `launchctl print gui/<uid>/…` issued from a root session address ROOT's own
/// user domain, never the desktop user's — so a probe can false-negative on a registration that
/// genuinely exists. Only `removed` proves anything; `found` explains; `indeterminate` admits when
/// absence was never established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeRemoval {
    /// The scope this attempt addressed.
    pub scope: ServiceScope,
    /// The probe SAW a registration here. Advisory only — `false` does NOT prove absence.
    pub found: bool,
    /// The OS deregistration succeeded. The authoritative signal.
    pub removed: bool,
    /// Absence was never established: the probe could not answer AND the removal did not succeed —
    /// so whether a registration remains is UNKNOWN, and must never be reported as a clean uninstall.
    pub indeterminate: bool,
    /// Why the probe or the removal failed, when one did. `None` on success and on a clean
    /// "nothing registered here".
    pub error: Option<String>,
}

impl ScopeRemoval {
    /// The removal attempt that never ran because the scope could not be addressed at all. A
    /// [`RemovalMode::Requested`] scope is left INDETERMINATE (the caller asked for it and we cannot
    /// say what is there); a swept scope is not (a platform with no manager at that scope holds no
    /// registration there to leave behind).
    fn unreachable(scope: ServiceScope, mode: RemovalMode, error: String) -> Self {
        ScopeRemoval {
            scope,
            found: false,
            removed: false,
            indeterminate: mode == RemovalMode::Requested,
            error: Some(error),
        }
    }

    /// A machine-readable record of this attempt for the `--json` envelope (CLAUDE.md §6.2).
    fn to_json(&self) -> serde_json::Value {
        json!({
            "scope": scope_label(self.scope),
            "found": self.found,
            "removed": self.removed,
            "indeterminate": self.indeterminate,
            "error": self.error,
        })
    }
}

/// How hard to try at a scope — the distinction that keeps a probe false-negative from turning a
/// requested removal into a silent no-op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemovalMode {
    /// The scope the operator NAMED (or that `Auto` resolved to). Deregistered UNCONDITIONALLY: the
    /// OS removal call is the authority, so a probe that wrongly reports absence can never turn the
    /// uninstall into a no-op. This is also the pre-#526 behaviour, which always called delete.
    Requested,
    /// A scope being swept for a stale registration nobody asked about (the other scope during
    /// [`install`], the second scope under `uninstall --scope auto`). PROBE-GATED: nothing is written
    /// unless a registration is actually seen, so a sweep never disturbs an unrelated scope.
    Swept,
}

/// Deregister the service at ONE scope, best-effort, reporting exactly what happened.
///
/// Never returns `Err`: the caller decides which combination of per-scope outcomes is fatal (a stale
/// swept registration is not; a named scope left behind is). See [`RemovalMode`] for why a
/// `Requested` scope is removed without trusting the probe.
fn remove_registration<B: ServiceBackend + ?Sized>(
    backend: &B,
    scope: ServiceScope,
    mode: RemovalMode,
) -> ScopeRemoval {
    let mut removal = ScopeRemoval {
        scope,
        found: false,
        removed: false,
        indeterminate: false,
        error: None,
    };
    let probe = backend.is_installed();
    match &probe {
        Ok(found) => removal.found = *found,
        Err(e) => {
            removal.error = Some(format!("could not determine whether it is registered: {e}"))
        }
    }
    // A sweep touches nothing it did not positively see — an unrelated scope must never be written
    // to on the strength of a guess. A probe FAILURE leaves the swept scope indeterminate: absence
    // was not established, and the caller reports that rather than assuming it is clean.
    if mode == RemovalMode::Swept && !removal.found {
        removal.indeterminate = probe.is_err();
        return removal;
    }
    // Best-effort stop first so nothing keeps holding the relay's ports past the deregistration.
    let _ = backend.stop();
    match backend.delete() {
        Ok(()) => removal.removed = true,
        Err(e) => {
            // A failed delete at a scope the probe never saw a registration at is the ordinary
            // "there was nothing here" case (the OS says so twice) — keep the reason for context,
            // but only a scope we DID see, or could not read at all, is unresolved.
            removal.indeterminate = probe.is_err() || removal.found;
            removal.error = Some(e.to_string());
        }
    }
    removal
}

/// Register at the requested scope, first clearing any registration at the OTHER scope.
///
/// **The other-scope sweep is a placement requirement, not a nicety.** A host upgrading from a prior
/// user-level install to a system-level one would otherwise end up with TWO registrations, both
/// starting a relay bound to the same ports; which one wins is a race, and the stale one can. So the
/// other scope is deregistered BEFORE the requested one is created — never after, which would delete
/// the registration just made.
///
/// The sweep is probe-gated and best-effort, and its result is RETURNED so the caller can report it:
/// an install that could not clear a stale registration must not claim an unqualified success. The
/// caller is responsible for refusing an impossible registration ([`ensure_privilege_for_scope`])
/// BEFORE calling this, so the sweep never tears down a working registration ahead of a create that
/// was never going to succeed. `other` is `None` where the platform has only one scope (Windows).
fn install_at_scope<T: ServiceBackend, O: ServiceBackend>(
    target: &T,
    other: Option<(&O, ServiceScope)>,
    plan: &InstallPlan,
) -> std::io::Result<Option<ScopeRemoval>> {
    let migration =
        other.map(|(backend, scope)| remove_registration(backend, scope, RemovalMode::Swept));
    target.create(plan)?;
    Ok(migration)
}

/// Turn per-scope removal results into the `uninstall` [`Outcome`], failing LOUDLY on anything less
/// than a complete removal. PURE, so every reporting row is table-tested with no OS involved.
///
/// * Any scope found-but-not-removed, or left indeterminate ⇒ `Err(PermissionDenied)`: an uninstall
///   that leaves a registration behind — or cannot tell whether it did — must never report success,
///   which is how a "removed" relay keeps starting at boot and re-binding 9450/9451.
/// * Nothing removed anywhere, and nothing unresolved ⇒ `Err(NotFound)`: there was nothing to
///   uninstall. Any removal error collected along the way is carried as context.
/// * Otherwise ⇒ success, naming every scope removed. `registered` is then unconditionally `false`
///   — the field means "is it still registered", which a successful uninstall answers `no`.
fn uninstall_outcome(removals: Vec<ScopeRemoval>) -> std::io::Result<Outcome> {
    let removed: Vec<&'static str> = removals
        .iter()
        .filter(|r| r.removed)
        .map(|r| scope_label(r.scope))
        .collect();
    let problems: Vec<String> = removals
        .iter()
        .filter(|r| r.indeterminate || (r.found && !r.removed))
        .map(|r| {
            let why = r.error.as_deref().unwrap_or("removal did not take effect");
            format!("{} scope: {why}", scope_label(r.scope))
        })
        .collect();

    if !problems.is_empty() {
        let removed_note = if removed.is_empty() {
            "nothing was removed".to_string()
        } else {
            format!("removed at: {}", removed.join(", "))
        };
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "dig-relay: could not fully uninstall service \"{SERVICE_LABEL}\" ({removed_note}). \
                 Unresolved: {}. Re-run elevated (e.g. `sudo dig-relay uninstall --scope system`) — \
                 a registration left behind will keep starting the relay.",
                problems.join("; ")
            ),
        ));
    }
    if removed.is_empty() {
        let scopes = removals
            .iter()
            .map(|r| scope_label(r.scope))
            .collect::<Vec<_>>()
            .join(" or ");
        let reasons = removals
            .iter()
            .filter_map(|r| {
                r.error
                    .as_deref()
                    .map(|e| format!("{} scope: {e}", scope_label(r.scope)))
            })
            .collect::<Vec<_>>();
        let mut msg = format!(
            "dig-relay: no service registration for \"{SERVICE_LABEL}\" was found at {scopes} \
             scope — nothing to uninstall."
        );
        if !reasons.is_empty() {
            msg.push_str(&format!(" ({})", reasons.join("; ")));
        }
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, msg));
    }
    Ok(Outcome::new(
        format!(
            "dig-relay: uninstalled service \"{SERVICE_LABEL}\" at {} scope",
            removed.join(" + ")
        ),
        json!({
            "installed": false,
            "registered": false,
            "label": SERVICE_LABEL,
            "removed_scopes": removed,
            "scopes": removals.iter().map(ScopeRemoval::to_json).collect::<Vec<_>>(),
        }),
    ))
}

/// The native service manager pinned to ONE [`ServiceScope`] — every probe/create/delete addresses
/// that scope only.
struct RelayServiceBackend {
    manager: Box<dyn ServiceManager>,
    scope: ServiceScope,
}

impl RelayServiceBackend {
    /// Acquire the native manager fixed at `scope`. A scope this platform cannot address is an
    /// ERROR naming the scope — never a silent downgrade to the other one, which is how a requested
    /// boot-surviving registration would quietly become a session-only one (#526).
    fn new(scope: ServiceScope) -> std::io::Result<Self> {
        Ok(RelayServiceBackend {
            manager: manager_at(scope)?,
            scope,
        })
    }
}

impl ServiceBackend for RelayServiceBackend {
    fn is_installed(&self) -> std::io::Result<bool> {
        query_installed(&os_native_service_name(&label()?), self.scope)
    }

    fn stop(&self) -> std::io::Result<()> {
        self.manager.stop(ServiceStopCtx { label: label()? })
    }

    fn delete(&self) -> std::io::Result<()> {
        self.manager
            .uninstall(ServiceUninstallCtx { label: label()? })
    }

    fn create(&self, plan: &InstallPlan) -> std::io::Result<()> {
        self.manager.install(ServiceInstallCtx {
            label: label()?,
            program: plan.program.clone(),
            args: plan.args.clone(),
            contents: None,
            username: None,
            working_directory: None,
            environment: Some(plan.environment.clone()),
            autostart: plan.autostart,
        })
    }
}

/// The identifier [`query_installed`] must probe the OS with — the SAME identifier
/// `service-manager` registers the service under, which is **NOT uniformly
/// [`ServiceLabel::to_qualified_name`]**: its Windows (`sc`) and launchd backends use the reverse-DNS
/// qualified name, but its **systemd** backend derives the unit file name from `to_script_name()`
/// (`dignetwork-dig-relay`, dropping the `net` qualifier). Probing systemd with the qualified name
/// looks for a unit that never exists, so the probe would always report `false` and silently defeat
/// the whole sweep. PURE, so the per-platform choice is asserted without touching the OS.
fn os_native_service_name(label: &ServiceLabel) -> String {
    if cfg!(all(unix, not(target_os = "macos"))) {
        label.to_script_name()
    } else {
        label.to_qualified_name()
    }
}

/// Probe whether `service_name` is registered AT `scope`. Windows SCM has exactly one scope, so
/// `scope` carries no information there. An `Err` means the question could not be ANSWERED (the
/// probe tool could not be run at all) — distinct from `Ok(false)`, "the OS says nothing is here".
#[cfg(windows)]
fn query_installed(service_name: &str, _scope: ServiceScope) -> std::io::Result<bool> {
    // `sc query <name>` exits 0 when the service exists, 1060 (does-not-exist) otherwise.
    std::process::Command::new("sc.exe")
        .args(["query", service_name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
}

/// macOS launchd existence probe: `launchctl print <domain>/<label>` exits 0 when the service is
/// bootstrapped in that scope's domain.
#[cfg(target_os = "macos")]
fn query_installed(service_name: &str, scope: ServiceScope) -> std::io::Result<bool> {
    let domain = if scope == ServiceScope::User {
        format!("gui/{}/{}", unix_uid().unwrap_or(0), service_name)
    } else {
        format!("system/{service_name}")
    };
    std::process::Command::new("launchctl")
        .args(["print", &domain])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
}

/// Linux systemd existence probe: `systemctl [--user] cat <unit>` exits 0 when the unit file exists
/// in that scope (non-zero "No files found" otherwise). `--user` addresses the per-user manager, its
/// absence the system manager — the two hold DIFFERENT unit files, so the flag must track the scope
/// being probed or the probe reports on the wrong registration.
#[cfg(all(unix, not(target_os = "macos")))]
fn query_installed(service_name: &str, scope: ServiceScope) -> std::io::Result<bool> {
    let unit = format!("{service_name}.service");
    let mut cmd = std::process::Command::new("systemctl");
    if scope == ServiceScope::User {
        cmd.arg("--user");
    }
    cmd.args(["cat", &unit])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
}

/// The effective uid via `id -u`, or `None` when it cannot be determined (the launchd domain target).
#[cfg(target_os = "macos")]
fn unix_uid() -> Option<u32> {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u32>().ok())
}

/// Install the relay as an auto-starting OS service that runs `dig-relay serve` on the configured
/// listen addrs. The listen/health addrs are passed as env so the service serves identically.
///
/// `scope` picks WHERE it registers (dig_ecosystem#526): `Auto` resolves to `System` when running
/// as root (an elevated `dig-installer` needs reboot survival with no login session — see
/// [`resolve_scope`]) or on Windows (no user-level SCM), else `User` (unchanged default).
///
/// A registration the caller cannot actually make is refused BEFORE any side effect
/// ([`ensure_privilege_for_scope`]); only then is the OTHER scope swept (probe-gated,
/// [`install_at_scope`]) so a host upgrading from a prior install there doesn't end up with two
/// registrations both binding the relay's ports. The sweep's result is REPORTED in the outcome — an
/// install that could not clear a stale registration never claims an unqualified success.
pub fn install(config: &RelayServerConfig, scope: ScopeChoice) -> std::io::Result<Outcome> {
    if cfg!(windows) && !is_elevated() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "dig-relay: installing a Windows service requires an elevated (Administrator) console. \
             Re-run this in a terminal opened with \"Run as administrator\".",
        ));
    }

    // Every fallible pre-condition is settled BEFORE the cross-scope sweep writes anything: an
    // unprivileged `--scope system` must refuse outright, not first tear down the user-level
    // registration that was working and then fail inside systemd (dig_ecosystem#526).
    let resolved = resolve_scope(scope, PREFERS_USER_LEVEL, is_root());
    ensure_privilege_for_scope(resolved, PREFERS_USER_LEVEL, is_root())?;
    let target = RelayServiceBackend::new(resolved)?;
    let program = current_exe()?;

    let mut environment = vec![
        ("DIG_RELAY_LISTEN".to_string(), config.listen.to_string()),
        (
            "DIG_RELAY_HEALTH_LISTEN".to_string(),
            config.health_listen.to_string(),
        ),
        (
            "DIG_RELAY_DASHBOARD_LISTEN".to_string(),
            config.dashboard_listen.to_string(),
        ),
        (
            "DIG_RELAY_STUN_LISTEN".to_string(),
            config.stun_listen.to_string(),
        ),
        (
            "DIG_RELAY_MAX_CONNECTIONS".to_string(),
            config.max_connections.to_string(),
        ),
        // App-level abuse limits (#1386): persist the configured caps so the installed service runs
        // with the same protection as the foreground `serve` that installed it.
        (
            "DIG_RELAY_MAX_CONNECTIONS_PER_IP".to_string(),
            config.max_connections_per_ip.to_string(),
        ),
        (
            "DIG_RELAY_REGISTRATIONS_PER_IP_PER_SEC".to_string(),
            config.registrations_per_ip_per_sec.to_string(),
        ),
        (
            "DIG_RELAY_MAX_REGISTRATIONS_PER_IP".to_string(),
            config.max_registrations_per_ip.to_string(),
        ),
        (
            "DIG_RELAY_MESSAGES_PER_CONN_PER_SEC".to_string(),
            config.messages_per_conn_per_sec.to_string(),
        ),
        (
            "DIG_RELAY_BYTES_PER_CONN_PER_SEC".to_string(),
            config.bytes_per_conn_per_sec.to_string(),
        ),
        (
            "DIG_RELAY_MAX_RELAYED_BYTES_PER_CONN".to_string(),
            config.max_relayed_bytes_per_conn.to_string(),
        ),
        // Ephemeral ban list (#1396): persist the ban knobs so the installed service bans repeat
        // abusers exactly like the foreground `serve` that installed it.
        (
            "DIG_RELAY_BAN_THRESHOLD".to_string(),
            config.ban_threshold.to_string(),
        ),
        (
            "DIG_RELAY_BAN_DURATION_SECS".to_string(),
            config.ban_duration.as_secs().to_string(),
        ),
        (
            "DIG_RELAY_BAN_STRIKE_WINDOW_SECS".to_string(),
            config.ban_strike_window.as_secs().to_string(),
        ),
    ];
    environment.extend(tls_environment_pairs(config));

    // The SCM-launched program must speak the Windows service protocol, so on Windows the installed
    // service runs the hidden `run-service` entrypoint; systemd/launchd exec `serve` directly.
    let entry_arg = if cfg!(windows) {
        "run-service"
    } else {
        "serve"
    };

    let plan = InstallPlan {
        program: program.clone(),
        args: vec![OsString::from(entry_arg)],
        environment,
        autostart: true,
    };

    // Only a platform WITH a second scope has anything to sweep; a scope whose manager cannot be
    // acquired holds no registration this binary could have made, so there is nothing to clear.
    let other = if PREFERS_USER_LEVEL {
        RelayServiceBackend::new(other_scope(resolved)).ok()
    } else {
        None
    };
    let migration = install_at_scope(
        &target,
        other.as_ref().map(|b| (b, other_scope(resolved))),
        &plan,
    )?;

    let scope_str = scope_label(resolved);
    let mut summary = format!(
        "dig-relay: installed as a {scope_str}-level service \"{SERVICE_LABEL}\"\n  \
         program: {}\n  relay:   ws://{}\n  health:  http://{}\n  \
         Start it now with: dig-relay start",
        program.display(),
        config.listen,
        config.health_listen,
    );
    // A cleared stale registration is news, and so is one that could not be cleared — the latter
    // leaves two registrations racing for the relay's ports, which is exactly what the sweep exists
    // to prevent, so it must never be invisible.
    if let Some(m) = &migration {
        if m.removed {
            summary.push_str(&format!(
                "\n  migrated: removed the previous {}-level registration",
                scope_label(m.scope)
            ));
        } else if m.found || m.indeterminate {
            summary.push_str(&format!(
                "\n  WARNING: a {}-level registration may still exist and could also bind these \
                 ports ({}). Remove it with: dig-relay uninstall --scope {}",
                scope_label(m.scope),
                m.error.as_deref().unwrap_or("removal did not take effect"),
                scope_label(m.scope),
            ));
        }
    }
    Ok(Outcome::new(
        summary,
        json!({
            "installed": true,
            "registered": true,
            "started": false,
            "label": SERVICE_LABEL,
            "scope": scope_str,
            "program": program.display().to_string(),
            "listen": config.listen.to_string(),
            "health_listen": config.health_listen.to_string(),
            "migration": migration.as_ref().map(ScopeRemoval::to_json),
        }),
    ))
}

/// The lowercase scope name used in `Outcome` summaries/JSON — matches dig-node's wording exactly
/// (dig_ecosystem#526) so tooling parsing either component's output sees one vocabulary.
fn scope_label(scope: ServiceScope) -> &'static str {
    match scope {
        ServiceScope::System => "system",
        ServiceScope::User => "user",
    }
}

/// Uninstall the relay service (best-effort stop first).
///
/// `Auto` removes the service at BOTH scopes — a stale registration silently left behind at the
/// other scope is the defect class of dig_ecosystem#1863 (it can still bind the relay's ports even
/// though `dig-relay status` looks clean). An explicit `System`/`User` choice removes only that one
/// scope, unconditionally; the swept second scope is probe-gated ([`RemovalMode`]).
///
/// **Fails loudly on anything less than a complete removal** ([`uninstall_outcome`]): found-but-not-
/// removed, or "cannot tell", is an `Err`, never a success envelope.
pub fn uninstall(scope: ScopeChoice) -> std::io::Result<Outcome> {
    if cfg!(windows) && !is_elevated() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "dig-relay: uninstalling a Windows service requires an elevated (Administrator) console.",
        ));
    }

    // The FIRST scope is the one the caller named (or that `Auto` resolved to) — removed
    // unconditionally; any further scope is a sweep, so it is probe-gated.
    let removals = uninstall_scopes(scope, PREFERS_USER_LEVEL, is_root())
        .into_iter()
        .enumerate()
        .map(|(index, s)| {
            let mode = if index == 0 {
                RemovalMode::Requested
            } else {
                RemovalMode::Swept
            };
            match RelayServiceBackend::new(s) {
                Ok(backend) => remove_registration(&backend, s, mode),
                Err(e) => ScopeRemoval::unreachable(s, mode, e.to_string()),
            }
        })
        .collect();
    uninstall_outcome(removals)
}

/// Start the installed service at the resolved scope.
pub fn start(scope: ScopeChoice) -> std::io::Result<Outcome> {
    let resolved = resolve_scope(scope, PREFERS_USER_LEVEL, is_root());
    let mgr = manager_at(resolved)?;
    mgr.start(ServiceStartCtx { label: label()? })?;
    Ok(Outcome::new(
        format!("dig-relay: start requested for \"{SERVICE_LABEL}\""),
        json!({ "started": true, "label": SERVICE_LABEL, "scope": scope_label(resolved) }),
    ))
}

/// Stop the running service at the resolved scope.
pub fn stop(scope: ScopeChoice) -> std::io::Result<Outcome> {
    let resolved = resolve_scope(scope, PREFERS_USER_LEVEL, is_root());
    let mgr = manager_at(resolved)?;
    mgr.stop(ServiceStopCtx { label: label()? })?;
    Ok(Outcome::new(
        format!("dig-relay: stop requested for \"{SERVICE_LABEL}\""),
        json!({ "stopped": true, "label": SERVICE_LABEL, "scope": scope_label(resolved) }),
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
    if let Some(a) = std::env::var("DIG_RELAY_DASHBOARD_LISTEN")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        config.dashboard_listen = a;
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
    if let Some(n) = std::env::var("DIG_RELAY_STUN_PER_IP_RPS")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        config.stun_per_ip_responses_per_sec = n;
    }
    if let Some(n) = std::env::var("DIG_RELAY_STUN_GLOBAL_RPS")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        config.stun_global_responses_per_sec = n;
    }
    if let Some(n) = std::env::var("DIG_RELAY_OUTBOUND_QUEUE_CAPACITY")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        config.outbound_queue_capacity = n;
    }
    if let Some(n) = std::env::var("DIG_RELAY_MAX_MESSAGE_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        config.max_message_bytes = n;
    }
    if let Some(s) = std::env::var("DIG_RELAY_REGISTER_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        config.register_timeout = std::time::Duration::from_secs(s);
    }
    // Health-sweep knobs (#1382 fold-in): these shipped with CLI flags but no env overrides; add
    // them here so an installed service can tune them the same way as every other knob.
    if let Some(s) = std::env::var("DIG_RELAY_HEALTH_CHECK_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        config.health_check_interval = std::time::Duration::from_secs(s);
    }
    if let Some(s) = std::env::var("DIG_RELAY_LIVENESS_DEADLINE_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        config.liveness_deadline = std::time::Duration::from_secs(s);
    }
    // App-level abuse limits (#1386).
    if let Some(n) = std::env::var("DIG_RELAY_MAX_CONNECTIONS_PER_IP")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        config.max_connections_per_ip = n;
    }
    if let Some(n) = std::env::var("DIG_RELAY_REGISTRATIONS_PER_IP_PER_SEC")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        config.registrations_per_ip_per_sec = n;
    }
    if let Some(n) = std::env::var("DIG_RELAY_MAX_REGISTRATIONS_PER_IP")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        config.max_registrations_per_ip = n;
    }
    if let Some(n) = std::env::var("DIG_RELAY_MESSAGES_PER_CONN_PER_SEC")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        config.messages_per_conn_per_sec = n;
    }
    if let Some(n) = std::env::var("DIG_RELAY_BYTES_PER_CONN_PER_SEC")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        config.bytes_per_conn_per_sec = n;
    }
    if let Some(n) = std::env::var("DIG_RELAY_MAX_RELAYED_BYTES_PER_CONN")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        config.max_relayed_bytes_per_conn = n;
    }
    if let Some(n) = std::env::var("DIG_RELAY_BAN_THRESHOLD")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        config.ban_threshold = n;
    }
    if let Some(s) = std::env::var("DIG_RELAY_BAN_DURATION_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        config.ban_duration = std::time::Duration::from_secs(s);
    }
    if let Some(s) = std::env::var("DIG_RELAY_BAN_STRIKE_WINDOW_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        config.ban_strike_window = std::time::Duration::from_secs(s);
    }
    if let Ok(p) = std::env::var("DIG_RELAY_TLS_CERT_PATH") {
        config.tls_cert_path = Some(std::path::PathBuf::from(p));
    }
    if let Ok(p) = std::env::var("DIG_RELAY_TLS_KEY_PATH") {
        config.tls_key_path = Some(std::path::PathBuf::from(p));
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
    const RELAY_ENV: [&str; 23] = [
        "DIG_RELAY_LISTEN",
        "DIG_RELAY_HEALTH_LISTEN",
        "DIG_RELAY_DASHBOARD_LISTEN",
        "DIG_RELAY_STUN_LISTEN",
        "DIG_RELAY_MAX_CONNECTIONS",
        "DIG_RELAY_STUN_PER_IP_RPS",
        "DIG_RELAY_STUN_GLOBAL_RPS",
        "DIG_RELAY_OUTBOUND_QUEUE_CAPACITY",
        "DIG_RELAY_MAX_MESSAGE_BYTES",
        "DIG_RELAY_REGISTER_TIMEOUT_SECS",
        "DIG_RELAY_HEALTH_CHECK_INTERVAL_SECS",
        "DIG_RELAY_LIVENESS_DEADLINE_SECS",
        "DIG_RELAY_MAX_CONNECTIONS_PER_IP",
        "DIG_RELAY_REGISTRATIONS_PER_IP_PER_SEC",
        "DIG_RELAY_MAX_REGISTRATIONS_PER_IP",
        "DIG_RELAY_MESSAGES_PER_CONN_PER_SEC",
        "DIG_RELAY_BYTES_PER_CONN_PER_SEC",
        "DIG_RELAY_MAX_RELAYED_BYTES_PER_CONN",
        "DIG_RELAY_BAN_THRESHOLD",
        "DIG_RELAY_BAN_DURATION_SECS",
        "DIG_RELAY_BAN_STRIKE_WINDOW_SECS",
        "DIG_RELAY_TLS_CERT_PATH",
        "DIG_RELAY_TLS_KEY_PATH",
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

    /// The full `(ScopeChoice x os_supports_user x is_root)` decision table — 12 rows, all runnable
    /// with no privileges on any host. This is the primary evidence for the scope-resolution
    /// contract (dig_ecosystem#526): explicit choices are always authoritative, `Auto` follows
    /// privilege except where the platform has no user-level manager at all.
    #[test]
    fn resolve_scope_covers_every_combination() {
        use ScopeChoice as C;
        use ServiceScope as S;
        let cases = [
            // (choice, os_supports_user, is_root) -> expected
            (C::Auto, true, true, S::System), // root on a user-capable OS -> system (reboot survival)
            (C::Auto, true, false, S::User), // unelevated on a user-capable OS -> user (unchanged default)
            (C::Auto, false, true, S::System), // Windows, root -> system
            (C::Auto, false, false, S::System), // Windows, unelevated -> system (no user-level SCM)
            (C::System, true, true, S::System),
            (C::System, true, false, S::System), // explicit System always wins, even unelevated
            (C::System, false, true, S::System),
            (C::System, false, false, S::System),
            (C::User, true, true, S::User), // explicit User always wins, even as root
            (C::User, true, false, S::User),
            // Windows has exactly ONE scope, so even an explicit `--scope user` resolves to system
            // rather than hard-failing — byte-identical to dig-node, so one installer argument form
            // behaves the same for both components (dig_ecosystem#526).
            (C::User, false, true, S::System),
            (C::User, false, false, S::System),
        ];
        for (choice, os_supports_user, is_root, expected) in cases {
            let actual = resolve_scope(choice, os_supports_user, is_root);
            assert_eq!(
                actual, expected,
                "resolve_scope({choice:?}, os_supports_user={os_supports_user}, is_root={is_root}) \
                 = {actual:?}, expected {expected:?}"
            );
        }
    }

    /// `Auto` sweeps BOTH scopes at EITHER privilege level — the resolved one first. The unelevated
    /// row is the load-bearing one: a plain `dig-relay uninstall` (no flag, no sudo — what an
    /// operator or an uninstall script actually runs) on a host the elevated dig-installer
    /// registered at SYSTEM scope must still address that system unit, rather than looking only at
    /// the user scope, finding nothing, and exiting 0 while the system unit keeps auto-starting at
    /// every boot and re-binding 9450/9451.
    #[test]
    fn uninstall_scopes_sweeps_both_for_auto_at_either_privilege() {
        assert_eq!(
            uninstall_scopes(ScopeChoice::Auto, true, true),
            vec![ServiceScope::System, ServiceScope::User],
            "auto + root must sweep both scopes, or a prior install at the other scope survives \
             uninstall (dig_ecosystem#1863)"
        );
        assert_eq!(
            uninstall_scopes(ScopeChoice::Auto, true, false),
            vec![ServiceScope::User, ServiceScope::System],
            "auto + unelevated must still sweep the SYSTEM scope an elevated installer would have \
             used — resolved scope first, then the sweep"
        );
        assert_eq!(
            uninstall_scopes(ScopeChoice::Auto, false, false),
            vec![ServiceScope::System],
            "a platform with only one scope has nothing to sweep"
        );
        assert_eq!(
            uninstall_scopes(ScopeChoice::System, true, true),
            vec![ServiceScope::System],
            "an explicit scope never widens to both, even under root"
        );
        assert_eq!(
            uninstall_scopes(ScopeChoice::User, true, true),
            vec![ServiceScope::User],
            "an explicit User choice removes only User, even under root"
        );
    }

    /// A system-scope registration an unelevated caller cannot make is refused — and refused as a
    /// PURE decision, so this runs on any host at any privilege level. Every other row is allowed:
    /// user scope needs nothing, root may do anything, and Windows (no user scope) has its own SCM
    /// elevation gate.
    #[test]
    fn ensure_privilege_for_scope_refuses_only_unprivileged_system() {
        let err = ensure_privilege_for_scope(ServiceScope::System, true, false).expect_err(
            "an unelevated system-scope install must be refused before any side effect",
        );
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            err.to_string().contains("--scope user"),
            "the refusal must say what to do instead: {err}"
        );
        assert!(ensure_privilege_for_scope(ServiceScope::System, true, true).is_ok());
        assert!(ensure_privilege_for_scope(ServiceScope::User, true, false).is_ok());
        assert!(ensure_privilege_for_scope(ServiceScope::System, false, false).is_ok());
    }

    /// A recording [`ServiceBackend`] double: it logs every operation into a SHARED log (so the
    /// relative ORDER of two backends' calls is observable), and each outcome is independently
    /// settable — a double that could only vary one field could not express "the probe saw it but
    /// the delete failed".
    struct MockBackend {
        name: &'static str,
        log: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
        installed: std::io::Result<bool>,
        delete_result: std::io::Result<()>,
        create_result: std::io::Result<()>,
    }

    impl MockBackend {
        fn new(name: &'static str, log: &std::rc::Rc<std::cell::RefCell<Vec<String>>>) -> Self {
            MockBackend {
                name,
                log: std::rc::Rc::clone(log),
                installed: Ok(false),
                delete_result: Ok(()),
                create_result: Ok(()),
            }
        }
        fn installed(mut self, installed: bool) -> Self {
            self.installed = Ok(installed);
            self
        }
        fn probe_fails(mut self) -> Self {
            self.installed = Err(std::io::Error::other("probe unavailable"));
            self
        }
        fn delete_fails(mut self) -> Self {
            self.delete_result = Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "access denied",
            ));
            self
        }
        fn record(&self, op: &str) {
            self.log.borrow_mut().push(format!("{}:{op}", self.name));
        }
    }

    /// Clone an `io::Error` shallowly enough for a mock to return it repeatedly.
    fn same_error(e: &std::io::Error) -> std::io::Error {
        std::io::Error::new(e.kind(), e.to_string())
    }

    impl ServiceBackend for MockBackend {
        fn is_installed(&self) -> std::io::Result<bool> {
            self.record("probe");
            match &self.installed {
                Ok(v) => Ok(*v),
                Err(e) => Err(same_error(e)),
            }
        }
        fn stop(&self) -> std::io::Result<()> {
            self.record("stop");
            Ok(())
        }
        fn delete(&self) -> std::io::Result<()> {
            self.record("delete");
            match &self.delete_result {
                Ok(()) => Ok(()),
                Err(e) => Err(same_error(e)),
            }
        }
        fn create(&self, _plan: &InstallPlan) -> std::io::Result<()> {
            self.record("create");
            match &self.create_result {
                Ok(()) => Ok(()),
                Err(e) => Err(same_error(e)),
            }
        }
    }

    fn test_plan() -> InstallPlan {
        InstallPlan {
            program: std::path::PathBuf::from("/usr/bin/dig-relay"),
            args: vec![OsString::from("serve")],
            environment: vec![("DIG_RELAY_LISTEN".into(), "[::]:9450".into())],
            autostart: true,
        }
    }

    /// The migration is a PLACEMENT fix, so it is proven by ORDER against a SECOND actor: the stale
    /// other-scope registration must be deleted BEFORE the new one is created. Asserting only "the
    /// new one exists" would pass just as happily if the sweep ran afterwards — and would then be
    /// deleting the registration it had just made.
    #[test]
    fn install_deregisters_the_other_scope_before_creating() {
        let log = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let target = MockBackend::new("target", &log);
        let stale = MockBackend::new("other", &log).installed(true);

        let migration = install_at_scope(&target, Some((&stale, ServiceScope::User)), &test_plan())
            .expect("the install itself succeeds")
            .expect("a migration was attempted");

        assert_eq!(
            log.borrow().as_slice(),
            ["other:probe", "other:stop", "other:delete", "target:create"],
            "the stale registration must be gone before the new one exists"
        );
        assert_eq!(migration.scope, ServiceScope::User);
        assert!(migration.found && migration.removed, "{migration:?}");
    }

    /// A sweep is PROBE-GATED: a scope the probe did not positively see must never be written to.
    #[test]
    fn install_sweep_does_not_touch_a_scope_holding_nothing() {
        let log = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let target = MockBackend::new("target", &log);
        let other = MockBackend::new("other", &log).installed(false);

        let migration = install_at_scope(&target, Some((&other, ServiceScope::User)), &test_plan())
            .unwrap()
            .expect("a migration was attempted");

        assert_eq!(
            log.borrow().as_slice(),
            ["other:probe", "target:create"],
            "a swept scope with nothing in it must be probed and then left alone"
        );
        assert!(!migration.found && !migration.removed);
    }

    /// A sweep that could not clear a stale registration is non-fatal but REPORTED — the install
    /// still succeeds, and the caller learns two registrations may now race for the relay's ports.
    #[test]
    fn install_reports_a_sweep_it_could_not_complete() {
        let log = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let target = MockBackend::new("target", &log);
        let stale = MockBackend::new("other", &log)
            .installed(true)
            .delete_fails();

        let migration =
            install_at_scope(&target, Some((&stale, ServiceScope::System)), &test_plan())
                .expect("a failed sweep must not fail the install")
                .expect("a migration was attempted");

        assert!(migration.found && !migration.removed, "{migration:?}");
        assert!(
            migration.error.is_some(),
            "the reason must reach the caller"
        );
        assert!(
            migration.indeterminate,
            "a registration we SAW and could not remove is unresolved"
        );
        assert!(log.borrow().contains(&"target:create".to_string()));
    }

    /// The scope the caller NAMED is deregistered unconditionally: the OS delete is the authority,
    /// so a probe false-negative (a `systemctl --user` issued from a root session cannot see the
    /// desktop user's units) can never silently turn the uninstall into a no-op.
    #[test]
    fn a_requested_scope_is_removed_even_when_the_probe_sees_nothing() {
        let log = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let backend = MockBackend::new("named", &log).installed(false);

        let removal = remove_registration(&backend, ServiceScope::System, RemovalMode::Requested);

        assert!(
            removal.removed,
            "the delete must run regardless of the probe: {removal:?}"
        );
        assert!(log.borrow().contains(&"named:delete".to_string()));
    }

    /// A probe that cannot ANSWER leaves a swept scope indeterminate — absence was never
    /// established, so it must not be reported as clean.
    #[test]
    fn a_swept_scope_with_an_unanswerable_probe_is_indeterminate() {
        let log = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let backend = MockBackend::new("swept", &log).probe_fails();

        let removal = remove_registration(&backend, ServiceScope::User, RemovalMode::Swept);

        assert!(removal.indeterminate && !removal.removed, "{removal:?}");
        assert!(
            !log.borrow().contains(&"swept:delete".to_string()),
            "an unreadable scope is still never written to"
        );
    }

    /// A complete removal is the ONLY success, and it reports `registered: false` — the field means
    /// "is it still registered", so a successful uninstall must answer `no`. (Inverting it would
    /// tell every machine consumer "still registered" exactly when removal WORKED.)
    #[test]
    fn uninstall_outcome_success_reports_not_registered() {
        let outcome = uninstall_outcome(vec![
            ScopeRemoval {
                scope: ServiceScope::System,
                found: true,
                removed: true,
                indeterminate: false,
                error: None,
            },
            ScopeRemoval {
                scope: ServiceScope::User,
                found: false,
                removed: false,
                indeterminate: false,
                error: None,
            },
        ])
        .expect("everything found was removed");
        assert_eq!(
            outcome.result["registered"],
            json!(false),
            "a successful uninstall leaves nothing registered"
        );
        assert_eq!(outcome.result["installed"], json!(false));
        assert_eq!(outcome.result["removed_scopes"], json!(["system"]));
    }

    /// The failure rows an uninstall must NOT report as success. Each varies ONE field away from the
    /// success case above, so each pins its own reason rather than a shared coincidence.
    #[test]
    fn uninstall_outcome_fails_on_anything_less_than_a_complete_removal() {
        let found_but_not_removed = uninstall_outcome(vec![ScopeRemoval {
            scope: ServiceScope::System,
            found: true,
            removed: false,
            indeterminate: false,
            error: Some("access denied".into()),
        }])
        .expect_err("a registration left behind is never a success");
        assert_eq!(
            found_but_not_removed.kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert!(found_but_not_removed.to_string().contains("access denied"));

        let indeterminate = uninstall_outcome(vec![ScopeRemoval {
            scope: ServiceScope::User,
            found: false,
            removed: false,
            indeterminate: true,
            error: None,
        }])
        .expect_err("\"cannot tell\" is never a success");
        assert_eq!(indeterminate.kind(), std::io::ErrorKind::PermissionDenied);

        let nothing_there = uninstall_outcome(vec![ScopeRemoval {
            scope: ServiceScope::User,
            found: false,
            removed: false,
            indeterminate: false,
            error: None,
        }])
        .expect_err("removing nothing is NotFound, not success");
        assert_eq!(nothing_there.kind(), std::io::ErrorKind::NotFound);

        // A partial sweep still succeeds when the scope that held something was cleared and the
        // other was provably empty — the control that keeps the three rows above from passing
        // merely because the function rejects everything.
        assert!(uninstall_outcome(vec![
            ScopeRemoval {
                scope: ServiceScope::User,
                found: true,
                removed: true,
                indeterminate: false,
                error: None,
            },
            ScopeRemoval {
                scope: ServiceScope::System,
                found: false,
                removed: false,
                indeterminate: false,
                error: None,
            },
        ])
        .is_ok());
    }

    /// A scope whose manager cannot be acquired: the caller ASKED for it, so the answer is unknown
    /// (an error), whereas a sweep of a scope this platform has no manager for is genuinely clean.
    #[test]
    fn an_unreachable_requested_scope_is_indeterminate_but_a_swept_one_is_not() {
        let requested =
            ScopeRemoval::unreachable(ServiceScope::User, RemovalMode::Requested, "no mgr".into());
        assert!(requested.indeterminate);
        assert!(uninstall_outcome(vec![requested]).is_err());

        let swept =
            ScopeRemoval::unreachable(ServiceScope::User, RemovalMode::Swept, "no mgr".into());
        assert!(!swept.indeterminate);
    }

    /// The systemd unit name `service-manager` actually registers is `to_script_name()`
    /// (`dignetwork-dig-relay`) — probing the reverse-DNS qualified name there looks for a unit that
    /// never exists, so the probe would always say "nothing here" and silently defeat every sweep.
    #[test]
    fn the_probe_uses_the_name_the_platform_actually_registers() {
        let l = label().unwrap();
        let expected = if cfg!(all(unix, not(target_os = "macos"))) {
            l.to_script_name()
        } else {
            l.to_qualified_name()
        };
        assert_eq!(os_native_service_name(&l), expected);
        assert_ne!(
            l.to_script_name(),
            l.to_qualified_name(),
            "the two names differ, which is why picking the wrong one is silent"
        );
    }

    #[test]
    fn other_scope_is_the_opposite() {
        assert_eq!(other_scope(ServiceScope::System), ServiceScope::User);
        assert_eq!(other_scope(ServiceScope::User), ServiceScope::System);
    }

    #[test]
    fn scope_label_matches_dig_node_wording() {
        assert_eq!(scope_label(ServiceScope::System), "system");
        assert_eq!(scope_label(ServiceScope::User), "user");
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
        std::env::set_var("DIG_RELAY_DASHBOARD_LISTEN", "127.0.0.1:7003");
        std::env::set_var("DIG_RELAY_STUN_LISTEN", "127.0.0.1:7002");
        std::env::set_var("DIG_RELAY_MAX_CONNECTIONS", "12");
        std::env::set_var("DIG_RELAY_STUN_PER_IP_RPS", "9");
        std::env::set_var("DIG_RELAY_STUN_GLOBAL_RPS", "321");
        std::env::set_var("DIG_RELAY_OUTBOUND_QUEUE_CAPACITY", "256");
        std::env::set_var("DIG_RELAY_MAX_MESSAGE_BYTES", "4096");
        std::env::set_var("DIG_RELAY_REGISTER_TIMEOUT_SECS", "3");
        std::env::set_var("DIG_RELAY_HEALTH_CHECK_INTERVAL_SECS", "20");
        std::env::set_var("DIG_RELAY_LIVENESS_DEADLINE_SECS", "50");
        std::env::set_var("DIG_RELAY_MAX_CONNECTIONS_PER_IP", "8");
        std::env::set_var("DIG_RELAY_REGISTRATIONS_PER_IP_PER_SEC", "3");
        std::env::set_var("DIG_RELAY_MAX_REGISTRATIONS_PER_IP", "16");
        std::env::set_var("DIG_RELAY_MESSAGES_PER_CONN_PER_SEC", "64");
        std::env::set_var("DIG_RELAY_BYTES_PER_CONN_PER_SEC", "2048");
        std::env::set_var("DIG_RELAY_MAX_RELAYED_BYTES_PER_CONN", "4096");
        std::env::set_var("DIG_RELAY_BAN_THRESHOLD", "7");
        std::env::set_var("DIG_RELAY_BAN_DURATION_SECS", "150");
        std::env::set_var("DIG_RELAY_BAN_STRIKE_WINDOW_SECS", "45");
        std::env::set_var("DIG_RELAY_TLS_CERT_PATH", "/etc/dig-relay/cert.pem");
        std::env::set_var("DIG_RELAY_TLS_KEY_PATH", "/etc/dig-relay/key.pem");
        let c = config_from_env();
        clear_relay_env();
        assert_eq!(c.listen, "127.0.0.1:7000".parse().unwrap());
        assert_eq!(c.health_listen, "127.0.0.1:7001".parse().unwrap());
        assert_eq!(c.dashboard_listen, "127.0.0.1:7003".parse().unwrap());
        assert_eq!(c.stun_listen, "127.0.0.1:7002".parse().unwrap());
        assert_eq!(c.max_connections, 12);
        assert_eq!(c.stun_per_ip_responses_per_sec, 9);
        assert_eq!(c.stun_global_responses_per_sec, 321);
        assert_eq!(c.outbound_queue_capacity, 256);
        assert_eq!(c.max_message_bytes, 4096);
        assert_eq!(c.register_timeout, std::time::Duration::from_secs(3));
        assert_eq!(c.health_check_interval, std::time::Duration::from_secs(20));
        assert_eq!(c.liveness_deadline, std::time::Duration::from_secs(50));
        assert_eq!(c.max_connections_per_ip, 8);
        assert_eq!(c.registrations_per_ip_per_sec, 3);
        assert_eq!(c.max_registrations_per_ip, 16);
        assert_eq!(c.messages_per_conn_per_sec, 64);
        assert_eq!(c.bytes_per_conn_per_sec, 2048);
        assert_eq!(c.max_relayed_bytes_per_conn, 4096);
        assert_eq!(c.ban_threshold, 7);
        assert_eq!(c.ban_duration, std::time::Duration::from_secs(150));
        assert_eq!(c.ban_strike_window, std::time::Duration::from_secs(45));
        assert_eq!(
            c.tls_cert_path,
            Some(std::path::PathBuf::from("/etc/dig-relay/cert.pem"))
        );
        assert_eq!(
            c.tls_key_path,
            Some(std::path::PathBuf::from("/etc/dig-relay/key.pem"))
        );
        // idle_timeout is not env-driven → stays default.
        assert_eq!(c.idle_timeout, RelayServerConfig::default().idle_timeout);
    }

    #[test]
    fn tls_environment_pairs_is_empty_when_tls_is_not_configured() {
        assert!(tls_environment_pairs(&RelayServerConfig::default()).is_empty());
    }

    #[test]
    fn tls_environment_pairs_carries_both_paths_when_configured() {
        let config = RelayServerConfig {
            tls_cert_path: Some(std::path::PathBuf::from("/etc/dig-relay/cert.pem")),
            tls_key_path: Some(std::path::PathBuf::from("/etc/dig-relay/key.pem")),
            ..Default::default()
        };
        let pairs = tls_environment_pairs(&config);
        assert_eq!(
            pairs,
            vec![
                (
                    "DIG_RELAY_TLS_CERT_PATH".to_string(),
                    "/etc/dig-relay/cert.pem".to_string()
                ),
                (
                    "DIG_RELAY_TLS_KEY_PATH".to_string(),
                    "/etc/dig-relay/key.pem".to_string()
                ),
            ]
        );
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
