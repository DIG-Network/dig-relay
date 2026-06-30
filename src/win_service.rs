//! Windows Service Control Protocol entrypoint (Windows only).
//!
//! A service-manager-registered service is not enough: the executable the SCM launches must itself
//! call `StartServiceCtrlDispatcher` and report `Running` within ~30s or the SCM kills it with
//! error 1053. This module is that connection: the installed service runs `dig-relay run-service`,
//! which calls [`run`] to become a real Windows service — registering a control handler, reporting
//! `Running`, serving until the SCM sends `Stop`, then reporting `Stopped`.

use std::ffi::OsString;
use std::sync::mpsc;
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use crate::service::{config_from_env, SERVICE_LABEL};

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// Hand control to the SCM dispatcher. Blocks until the service stops. Called by the `run-service`
/// subcommand. On a dispatcher error (e.g. invoked outside the SCM) returns an io::Error.
pub fn run() -> std::io::Result<()> {
    service_dispatcher::start(SERVICE_LABEL, ffi_service_main)
        .map_err(|e| std::io::Error::other(e.to_string()))
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        eprintln!("dig-relay service error: {e}");
    }
}

/// Register the control handler, report `Running`, serve until `Stop`, then report `Stopped`.
fn run_service() -> std::io::Result<()> {
    let config = config_from_env();
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_LABEL, event_handler)
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let set = |state: ServiceState, accept: ServiceControlAccept, exit: u32| ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    status_handle
        .set_service_status(set(ServiceState::Running, ServiceControlAccept::STOP, 0))
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(async move {
        let shutdown = async move {
            let _ = tokio::task::spawn_blocking(move || shutdown_rx.recv()).await;
        };
        crate::serve_with_shutdown(config, shutdown).await
    });

    let exit = if result.is_ok() { 0 } else { 1 };
    let _ = status_handle.set_service_status(set(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit,
    ));
    result
}
