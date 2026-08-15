//! Windows service hosting: registration, lifecycle, and shutdown.
//!
//! The agent runs as LocalSystem under the service control manager. That is the
//! whole reason the pipe carries a restrictive DACL and the caller check exists
//! — in this mode the process on the server side of that pipe is unrestricted.
//!
//! Stopping cleanly is the interesting part. The accept loop blocks inside
//! `ConnectNamedPipe`, which no flag can interrupt, so [`Shutdown::signal`]
//! raises the flag *and* opens a throwaway connection to the pipe. That unblocks
//! the accept, the loop sees the flag, and it returns without serving the poke.

use std::ffi::{OsStr, OsString};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use kam_core::{Error, Result, SERVICE_NAME};
use kam_ipc::pipe::PipeListener;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::dispatch::Context;
use crate::{server, Mode};

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
const DISPLAY_NAME: &str = "KAM Security Agent";
const DESCRIPTION: &str = "Performs the privileged half of KAM Security: scanning, \
     firewall rule management, and storage analysis. Every action it takes is \
     recorded in an audit log the user can read.";

/// How long the service control manager should wait for a pending transition.
const WAIT_HINT: Duration = Duration::from_secs(10);

fn service_error(error: windows_service::Error, context: &str) -> Error {
    Error::Privileged(format!("{context}: {error}"))
}

/// Cooperative stop signal for the accept loop.
///
/// Carries the pipe name rather than assuming the production one, so the loop a
/// test starts can be stopped the same way the service control manager stops
/// the real one.
#[derive(Clone, Debug)]
pub struct Shutdown {
    flag: Arc<AtomicBool>,
    pipe_name: Arc<str>,
}

impl Shutdown {
    pub fn new() -> Self {
        Self::for_pipe(kam_ipc::PIPE_NAME)
    }

    pub fn for_pipe(pipe_name: &str) -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
            pipe_name: Arc::from(pipe_name),
        }
    }

    pub fn is_signalled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Raise the flag and wake the accept loop.
    ///
    /// The flag alone is not enough: the loop is parked in `ConnectNamedPipe`
    /// and will not look at it until a connection arrives. Opening one here is
    /// what makes the stop prompt rather than eventual. The loop checks the flag
    /// before doing anything with the connection, so this poke is never served.
    pub fn signal(&self) {
        self.flag.store(true, Ordering::SeqCst);
        let _ = kam_ipc::pipe::connect(&self.pipe_name);
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

windows_service::define_windows_service!(ffi_service_main, service_main);

/// Hand control to the service control manager. Blocks until the service stops.
pub fn run_dispatcher() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|error| service_error(error, "could not start the service dispatcher"))
}

/// Called by the SCM on its own thread. There is no stdout here, so everything
/// worth knowing has to reach the log file configured before this point.
fn service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_service() {
        tracing::error!(%error, "the service failed");
    }
}

fn run_service() -> Result<()> {
    let shutdown = Shutdown::new();

    let handler_shutdown = shutdown.clone();
    let status_handle =
        service_control_handler::register(SERVICE_NAME, move |control| match control {
            // Always answer Interrogate, even though there is nothing to report:
            // the SCM treats silence as a hung service.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop | ServiceControl::Shutdown => {
                handler_shutdown.signal();
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        })
        .map_err(|error| service_error(error, "could not register the control handler"))?;

    let report = |state: ServiceState, accepted: ServiceControlAccept| ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted: accepted,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: WAIT_HINT,
        process_id: None,
    };

    status_handle
        .set_service_status(report(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ))
        .map_err(|error| service_error(error, "could not report the running state"))?;
    tracing::info!("service running");

    let outcome = serve_until_stopped(&shutdown);
    if let Err(error) = &outcome {
        tracing::error!(%error, "the accept loop ended in failure");
    }

    // Reported even when the loop failed. A service that does not reach Stopped
    // leaves the SCM believing it is still running.
    status_handle
        .set_service_status(report(ServiceState::Stopped, ServiceControlAccept::empty()))
        .map_err(|error| service_error(error, "could not report the stopped state"))?;
    tracing::info!("service stopped");

    outcome
}

fn serve_until_stopped(shutdown: &Shutdown) -> Result<()> {
    let context = Context {
        mode: Mode::Service,
        store: server::open_store(true)?,
    };
    let listener = PipeListener::new();
    tracing::info!(pipe = kam_ipc::PIPE_NAME, "listening");
    server::serve(&listener, &context, shutdown)
}

/// Register the agent with the service control manager. Requires elevation.
pub fn install() -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&OsStr>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|error| service_error(error, "could not open the service control manager"))?;

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: SERVICE_TYPE,
        // Manual until there is something worth running at boot. Auto-start is
        // a decision to make when the scheduler exists, not before.
        start_type: ServiceStartType::OnDemand,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe()?,
        // Explicit, so the ImagePath in the registry states plainly how this
        // process expects to be running.
        launch_arguments: vec![OsString::from("--service")],
        dependencies: vec![],
        // None means LocalSystem.
        account_name: None,
        account_password: None,
    };

    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG)
        .map_err(|error| service_error(error, "could not create the service"))?;
    service
        .set_description(DESCRIPTION)
        .map_err(|error| service_error(error, "could not set the service description"))?;

    println!("installed {SERVICE_NAME} ({DISPLAY_NAME})");
    println!("start it with:  sc start {SERVICE_NAME}");
    Ok(())
}

/// Stop the service if it is running, then remove it. Requires elevation.
pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&OsStr>, ServiceManagerAccess::CONNECT)
        .map_err(|error| service_error(error, "could not open the service control manager"))?;

    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .map_err(|error| service_error(error, "could not open the service"))?;

    let status = service
        .query_status()
        .map_err(|error| service_error(error, "could not query the service state"))?;
    if status.current_state != ServiceState::Stopped {
        service
            .stop()
            .map_err(|error| service_error(error, "could not stop the service"))?;
        println!("stop requested; the service control manager will complete it shortly");
    }

    service
        .delete()
        .map_err(|error| service_error(error, "could not delete the service"))?;
    println!("uninstalled {SERVICE_NAME}");
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_signal_is_not_set() {
        assert!(!Shutdown::new().is_signalled());
    }

    #[test]
    fn signalling_is_visible_through_a_clone() {
        // The control handler holds a clone while the accept loop reads the
        // original, so the two must observe the same flag.
        let shutdown = Shutdown::new();
        let handler_copy = shutdown.clone();
        handler_copy.signal();
        assert!(shutdown.is_signalled());
    }
}
