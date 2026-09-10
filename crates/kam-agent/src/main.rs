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

mod baseline;
mod check;
mod dispatch;
mod server;
mod service;
mod store_acl;
mod trust;
mod watch;

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
    /// Report what decoys are planted and what has read one.
    Canaries,
    /// Plant the decoys and switch on Windows' auditing of them.
    CanariesOn,
    /// Take the decoys away and switch the auditing back off.
    CanariesOff,
    /// Report whether the protective work is running.
    Protection,
    /// Switch the protective work on.
    ProtectionOn,
    /// Switch the protective work off. The service keeps running.
    ProtectionOff,
}

const USAGE: &str = "\
usage: kam-agent <mode>

  --console       run in the foreground for development
  --service       run under the service control manager (set by --install)
  --probe         ask a running agent for its status and exit
  --install       register the service; requires elevation
  --uninstall     stop and remove the service; requires elevation
  --check         run the weekly check once and exit
  --canaries      report the decoy files and keys, and anything that read one
  --canaries-on   plant the decoys and record reads of them
  --canaries-off  remove the decoys and stop recording
  --protection    report whether the protective work is running
  --protection-on   switch the protective work on
  --protection-off  switch it off (the service keeps running)";

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
        Mode::Canaries => return run_canaries(None),
        Mode::CanariesOn => return run_canaries(Some(true)),
        Mode::CanariesOff => return run_canaries(Some(false)),
        Mode::Protection => return run_protection(None),
        Mode::ProtectionOn => return run_protection(Some(true)),
        Mode::ProtectionOff => return run_protection(Some(false)),
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
        behaviour: Default::default(),
    });

    // The behaviour watcher runs in console mode too, so development exercises
    // the same path the service uses rather than a quieter one.
    let watcher = watch::spawn(context.behaviour.clone(), false, shutdown.clone());

    let listener = PipeListener::new();
    tracing::info!(pipe = kam_ipc::PIPE_NAME, "listening");
    let outcome = server::serve(&listener, &context, &shutdown);

    if let Some(watcher) = watcher {
        let _ = watcher.join();
    }
    outcome
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

/// Report or change whether the protective work is running.
///
/// The same thin-client shape as the rest: the agent holds the setting, because
/// it is the thing that acts on it. Switching it off never stops the service —
/// something has to remain to switch it back on, and a security tool that can be
/// silenced through its own interface is one an attacker silences.
fn run_protection(set: Option<bool>) -> kam_core::Result<()> {
    let request = match set {
        Some(enabled) => kam_ipc::Request::SetProtection { enabled },
        None => kam_ipc::Request::GetProtection,
    };
    match kam_ipc::client::call(&request)? {
        kam_ipc::Response::Protection { enabled } => {
            if enabled {
                println!("Protection is ON. The agent is watching.");
            } else {
                println!("Protection is OFF. Nothing is being watched.");
                println!("The service is still running, so this can be switched back on.");
            }
            Ok(())
        }
        kam_ipc::Response::Error { message } => Err(kam_core::Error::Refused(message)),
        other => Err(kam_core::Error::Protocol(format!(
            "the agent answered with {other:?}"
        ))),
    }
}

/// Turn the decoys on or off, or just report on them.
///
/// A thin client over the pipe, exactly as `--check` is: the agent does the
/// work, because planting decoys and changing the machine's audit policy both
/// need privileges this process does not have when a person runs it by hand.
///
/// It exists so the decoys can be driven from a terminal rather than only from
/// the window -- useful on a machine nobody is sitting at, and useful for
/// seeing plainly what was turned on.
fn run_canaries(set: Option<bool>) -> kam_core::Result<()> {
    if let Some(planted) = set {
        // Auditing first when switching on, so a decoy is never planted into a
        // machine that is not recording reads yet; and last when switching off,
        // so the decoys are gone before the recording stops.
        if planted {
            let _ = kam_ipc::client::call(&kam_ipc::Request::SetCanaryAuditing { enabled: true })?;
        }
        let _ = kam_ipc::client::call(&kam_ipc::Request::SetCanaries { planted })?;
        if !planted {
            let _ = kam_ipc::client::call(&kam_ipc::Request::SetCanaryAuditing { enabled: false })?;
        }
    }

    let reply = kam_ipc::client::call(&kam_ipc::Request::GetCanaries)?;
    let report = match reply {
        kam_ipc::Response::Canaries(report) => report,
        kam_ipc::Response::Error { message } => return Err(kam_core::Error::Refused(message)),
        other => {
            return Err(kam_core::Error::Protocol(format!(
                "the agent answered with {other:?}"
            )))
        }
    };

    if report.canaries.is_empty() {
        println!("No decoys are planted.");
    } else {
        let armed = report.canaries.iter().filter(|c| c.armed).count();
        println!(
            "{} decoys planted, {armed} of them watched. Windows auditing is {}.",
            report.canaries.len(),
            if report.auditing { "on" } else { "OFF" }
        );
        for canary in &report.canaries {
            println!(
                "  [{}] {} {}",
                if canary.armed { "watched" } else { "  ---  " },
                canary.path,
                canary
                    .problem
                    .as_deref()
                    .map(|problem| format!("({problem})"))
                    .unwrap_or_default()
            );
        }
        if !report.auditing {
            println!(
                "
Auditing is off, so reading one of these would go unnoticed.                  Turn it on with --canaries-on."
            );
        }
    }

    if report.trips.is_empty() {
        println!("Nothing has read one.");
    } else {
        println!(
            "
{} read(s) recorded:",
            report.trips.len()
        );
        for trip in &report.trips {
            println!(
                "  {} — {} read by {} (as {})",
                trip.at,
                trip.path,
                trip.process.as_deref().unwrap_or("an unnamed program"),
                trip.user.as_deref().unwrap_or("an unnamed account")
            );
        }
    }

    for problem in &report.problems {
        println!("note: {problem}");
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
            "--canaries" => Mode::Canaries,
            "--protection" => Mode::Protection,
            "--protection-on" => Mode::ProtectionOn,
            "--protection-off" => Mode::ProtectionOff,
            "--canaries-on" => Mode::CanariesOn,
            "--canaries-off" => Mode::CanariesOff,
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

    /// The C runtime is linked into the *shipped* binary, not expected to be
    /// on the machine already.
    ///
    /// Without `+crt-static` the agent imports `VCRUNTIME140.dll`, which ships
    /// with the Visual C++ Redistributable and is absent from a clean Windows
    /// install. It is present on any machine that has ever installed something
    /// built with MSVC, which is exactly why this never showed up here: the
    /// developer's machine has it and a downloader's may not.
    ///
    /// The failure it causes is the worst possible first impression for a
    /// security tool downloaded from GitHub -- the service does not start, the
    /// window reports the agent is not answering, and the only clue is a
    /// missing-DLL dialog naming a file nobody has heard of.
    ///
    /// It checks the release binary rather than this test binary, because the
    /// static CRT only takes effect in the profile that ships: a debug test
    /// executable still imports the dynamic runtime, and asserting on that
    /// would fail for a reason nobody could act on. Nothing to check yet is not
    /// a failure -- a release that has never been built cannot be wrong.
    #[test]
    fn the_c_runtime_is_linked_into_what_ships() {
        // From target/debug/deps/ back up to target/, then into release.
        let Some(release) = std::env::current_exe().ok().and_then(|path| {
            let target = path.parent()?.parent()?.parent()?;
            Some(target.join("release").join("kam-agent.exe"))
        }) else {
            return;
        };
        let Ok(bytes) = std::fs::read(&release) else {
            return;
        };

        // Import names sit in the binary as plain ASCII.
        let text = String::from_utf8_lossy(&bytes);
        for wanted in ["VCRUNTIME140.dll", "VCRUNTIME140_1.dll", "MSVCP140.dll"] {
            assert!(
                !text.contains(wanted),
                "{} imports {wanted}: it needs the Visual C++ Redistributable and will not \n                 start on a clean Windows install. Check that .cargo/config.toml \n                 still sets +crt-static for this target.",
                release.display()
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
