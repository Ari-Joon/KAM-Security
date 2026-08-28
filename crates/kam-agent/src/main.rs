//! The privileged half of KAM Security.
//!
//! Under the service control manager it runs as LocalSystem, which is what
//! makes the pipe's DACL and the caller check load-bearing rather than
//! decorative. `--console` runs the identical pipe, dispatch and trust check as
//! a foreground process, so development never has to reinstall a service or
//! debug something running as SYSTEM.
//!
//! `--probe` is the client. It is this same executable, so it sits in the
//! trusted directory and passes the check the shell will later have to pass —
//! ordinary development exercises that path instead of bypassing it.

mod check;
mod dispatch;
mod server;
mod service;

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use dispatch::Context;
use kam_ipc::pipe::PipeListener;
use service::Shutdown;

/// How the agent was started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Foreground process, for development.
    Console,
    /// Hosted by the service control manager as LocalSystem.
    Service,
    /// Client: talk to a running agent and exit.
    Probe,
    /// Register the service. Requires elevation.
    Install,
    /// Stop and remove the service. Requires elevation.
    Uninstall,
    /// Run the weekly check once and exit. What the scheduled task starts.
    Check,
}

const USAGE: &str = "\
usage: kam-agent <mode>

  --console     run in the foreground for development
  --service     run under the service control manager (set by --install)
  --probe       ask a running agent for its status and exit
  --install     register the service; requires elevation
  --uninstall   stop and remove the service; requires elevation
  --check       run the weekly check once and exit";

fn main() -> ExitCode {
    let mode = match parse_mode() {
        Ok(mode) => mode,
        Err(message) => {
            eprintln!("{message}\n\n{USAGE}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(error) = init_tracing(mode) {
        eprintln!("could not start logging: {error}");
        return ExitCode::FAILURE;
    }

    match run(mode) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "kam-agent failed");
            ExitCode::FAILURE
        }
    }
}

fn run(mode: Mode) -> kam_core::Result<()> {
    match mode {
        Mode::Probe => return server::probe(),
        Mode::Install => return service::install(),
        Mode::Uninstall => return service::uninstall(),
        Mode::Check => return run_check(),
        Mode::Console | Mode::Service => {}
    }

    tracing::info!(
        ?mode,
        version = env!("CARGO_PKG_VERSION"),
        "kam-agent starting"
    );

    if mode == Mode::Service {
        // Blocks until the control manager stops us.
        return service::run_dispatcher();
    }

    // Console runs have no control manager to signal them, so the flag exists
    // only to satisfy the shared accept loop; the process is stopped directly.
    let shutdown = Shutdown::new();
    let context = Arc::new(Context {
        mode,
        store: server::open_store(false)?,
        jobs: Default::default(),
        quarantine: server::open_quarantine(false)?,
    });
    let listener = PipeListener::new();
    tracing::info!(pipe = kam_ipc::PIPE_NAME, "listening");
    server::serve(&listener, &context, &shutdown)
}

/// One pass of the weekly check, started by the scheduled task.
///
/// It asks the running service to do the work rather than doing it here, and
/// that is the whole point of the mode. The first version ran the checks in
/// this process and failed on its first real run: the audit log lives under
/// `ProgramData` where only SYSTEM may write, so a task running as a person
/// could read it and not record anything, and every finding went to the log
/// file instead of to the place the window reads.
///
/// Going through the pipe fixes that and something better. The service is
/// already SYSTEM, so it writes; it already knows how to identify its caller,
/// so the per-user half of the check is about the right person; and it is
/// exactly the path the "Check now" button takes, so there is one code path
/// rather than two that can drift.
///
/// It also means the scheduled task needs no privileges at all. Adding
/// something to somebody's machine that runs as them, with their ordinary
/// rights, once a week, is a much smaller thing to ask than adding something
/// elevated.
fn run_check() -> kam_core::Result<()> {
    let reply = kam_ipc::client::call(&kam_ipc::Request::RunCheck)?;

    let findings = match reply {
        kam_ipc::Response::Checked { findings } => findings,
        kam_ipc::Response::Error { message } => {
            return Err(kam_core::Error::Refused(message));
        }
        other => {
            return Err(kam_core::Error::Protocol(format!(
                "the agent answered a check with {other:?}"
            )))
        }
    };

    if findings.is_empty() {
        println!("Checked. Nothing to report.");
        return Ok(());
    }
    for finding in &findings {
        println!(
            "{} {}",
            if finding.serious { "!" } else { "-" },
            finding.summary
        );
    }
    Ok(())
}

fn parse_mode() -> Result<Mode, String> {
    let mut mode = None;
    for argument in std::env::args().skip(1) {
        let parsed = match argument.as_str() {
            "--console" => Mode::Console,
            "--service" => Mode::Service,
            "--probe" => Mode::Probe,
            "--install" => Mode::Install,
            "--uninstall" => Mode::Uninstall,
            kam_schedule::CHECK_ARGUMENT => Mode::Check,
            other => return Err(format!("unrecognised argument: {other}")),
        };
        if mode.is_some_and(|existing| existing != parsed) {
            return Err("give exactly one mode".to_owned());
        }
        mode = Some(parsed);
    }
    // Deliberately not defaulting to --service. A service whose ImagePath says
    // what it is beats one that relies on the absence of arguments, and running
    // the binary by hand should explain itself rather than start a server.
    mode.ok_or_else(|| "no mode given".to_owned())
}

/// A log file shared by every tracing writer, guarded so concurrent writes do
/// not interleave mid-line.
#[derive(Clone)]
struct LogFile(Arc<Mutex<std::fs::File>>);

impl Write for LogFile {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        // A poisoned lock means another thread panicked while logging. Dropping
        // the line is better than panicking inside the logger and taking the
        // service down over a diagnostic.
        match self.0.lock() {
            Ok(mut file) => file.write(buffer),
            Err(_) => Ok(buffer.len()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.0.lock() {
            Ok(mut file) => file.flush(),
            Err(_) => Ok(()),
        }
    }
}

fn init_tracing(mode: Mode) -> kam_core::Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_env("KAM_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    if mode == Mode::Service {
        // There is no console under the service control manager, so anything
        // written to stdout is lost. Everything goes to a file next to the
        // store instead.
        let path = log_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        let writer = LogFile(Arc::new(Mutex::new(file)));
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(true)
            .init();
    }
    Ok(())
}

fn log_path() -> kam_core::Result<PathBuf> {
    let store = server::store_path(true)?;
    let directory = store
        .parent()
        .map(std::path::Path::to_path_buf)
        .ok_or_else(|| kam_core::Error::Privileged("the store has no directory".to_owned()))?;
    Ok(directory.join("logs").join("agent.log"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// Neither the rule engine nor the VirusTotal client may reach this
    /// binary.
    ///
    /// `kam-rules` carries a WebAssembly JIT. `kam-virustotal` makes outbound
    /// network requests and holds a credential. The argument for shipping
    /// either is that it runs in the unprivileged shell rather than here,
    /// where this process is LocalSystem: a JIT with a known unpatchable bug,
    /// and a socket to the public internet, are the last two things that
    /// belong in the most privileged process in a security product.
    ///
    /// That argument is a property of the dependency graph, and dependency
    /// graphs drift. Adding either to `kam-scanner` for something that seemed
    /// convenient would quietly undo it, with nothing to show that anything
    /// had changed — so it is asserted rather than trusted.
    #[test]
    fn the_rule_engine_never_reaches_the_privileged_agent() {
        let Some(crates) = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent() else {
            panic!("the agent crate should sit inside a crates directory");
        };

        // Everything the agent links, directly or through those.
        let linked = [
            "kam-agent",
            "kam-core",
            "kam-ipc",
            "kam-scanner",
            "kam-storage",
            "kam-quarantine",
            "kam-firewall",
        ];

        for name in linked {
            let manifest = crates.join(name).join("Cargo.toml");
            let Ok(text) = std::fs::read_to_string(&manifest) else {
                continue;
            };
            assert!(
                !text.contains("kam-rules"),
                "{name} depends on kam-rules, which would put a WebAssembly JIT \
                 inside the LocalSystem service. If this is deliberate, the \
                 reasoning in kam-rules and deny.toml no longer holds and both \
                 must be revisited."
            );
        }
    }

    #[test]
    fn the_service_log_sits_beside_the_service_store() {
        let log = log_path().unwrap();
        let store = server::store_path(true).unwrap();
        assert_eq!(log.parent().and_then(|p| p.parent()), store.parent());
        assert!(log.ends_with("logs/agent.log") || log.ends_with(r"logs\agent.log"));
    }
}
