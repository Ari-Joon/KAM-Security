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
    ServiceAction, ServiceActionType, ServiceFailureActions, ServiceFailureResetPeriod,
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
    let context = Arc::new(Context {
        mode: Mode::Service,
        store: server::open_store(true)?,
        jobs: Default::default(),
        quarantine: server::open_quarantine(true)?,
    });
    let listener = PipeListener::new();
    tracing::info!(pipe = kam_ipc::PIPE_NAME, "listening");
    server::serve(&listener, &context, shutdown)
}

/// `ERROR_SERVICE_EXISTS`. Spelled out rather than pulling the whole `windows`
/// crate into the agent for one integer.
const ERROR_SERVICE_EXISTS: i32 = 1073;

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
        // Automatic, and this was wrong before.
        //
        // The original reasoning -- "manual until there is something worth
        // running at boot" -- was defensible while the agent only answered a
        // window nobody had opened yet. It stopped being true the moment
        // anything depended on the agent being there, and it failed exactly as
        // you would predict: a reboot left the service stopped, and opening
        // KAM Security showed "Cannot reach the agent" with a
        // file-not-found on the pipe. Nothing was broken; nothing had started.
        //
        // The boot cost of fixing it is nil. The agent blocks in
        // `ConnectNamedPipe` and does nothing until asked -- 1.4 MB of private
        // memory and no measurable CPU -- so there is nothing to defer. Delayed
        // auto-start was considered and rejected: it would put the same
        // confusing error in front of anyone who opens the app within a couple
        // of minutes of logging in.
        start_type: ServiceStartType::AutoStart,
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

    // Installing over an existing registration repairs it rather than failing.
    // A machine that already has the service is the common case when the start
    // type or image path needs correcting, and refusing there would mean
    // telling people to uninstall a security service to fix its configuration.
    let service = match manager.create_service(&info, ServiceAccess::CHANGE_CONFIG) {
        Ok(service) => service,
        Err(windows_service::Error::Winapi(error))
            if error.raw_os_error() == Some(ERROR_SERVICE_EXISTS) =>
        {
            let existing = manager
                .open_service(
                    SERVICE_NAME,
                    ServiceAccess::CHANGE_CONFIG | ServiceAccess::QUERY_CONFIG,
                )
                .map_err(|error| service_error(error, "could not open the existing service"))?;
            existing
                .change_config(&info)
                .map_err(|error| service_error(error, "could not update the service"))?;
            println!("updated the existing {SERVICE_NAME} registration");
            existing
        }
        Err(error) => return Err(service_error(error, "could not create the service")),
    };

    service
        .set_description(DESCRIPTION)
        .map_err(|error| service_error(error, "could not set the service description"))?;

    // Come back on its own if it ever falls over. A security service that
    // stays down after one crash is worse than useless: the interface reports
    // everything as unavailable and the machine looks unprotected when the
    // only thing wrong is a process that needs starting again.
    let restart = |after: Duration| ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: after,
    };
    if let Err(error) = service.update_failure_actions(ServiceFailureActions {
        // Two quick attempts, then a longer one, then leave it alone: a fault
        // that survives three restarts will not be fixed by a fourth, and a
        // service restarting forever is its own kind of problem.
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            restart(Duration::from_secs(5)),
            restart(Duration::from_secs(15)),
            restart(Duration::from_secs(60)),
        ]),
    }) {
        // Not fatal. The service is installed and will run; it simply will not
        // pick itself up automatically, which is worth saying rather than
        // failing the whole install over.
        println!("note: could not set restart-on-failure ({error})");
    }

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
        //
        // Named rather than Shutdown::new(): signalling opens a connection to
        // the pipe, and the default name is the production one -- running the
        // tests would poke a live service on the same machine.
        let shutdown = Shutdown::for_pipe(&format!("kam-test-clone-{}", std::process::id()));
        let handler_copy = shutdown.clone();
        handler_copy.signal();
        assert!(shutdown.is_signalled());
    }
}
