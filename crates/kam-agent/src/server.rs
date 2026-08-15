//! The accept loop, and the policy deciding who is allowed to drive the agent.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use kam_core::audit::{AuditLog, Effect, Entry};
use kam_core::{Error, Result, Store};
use kam_ipc::frame::{read_frame, write_frame};
use kam_ipc::pipe::{PipeListener, PipeStream};
use kam_ipc::{Request, Response};

use crate::dispatch::{self, Context};
use crate::service::Shutdown;

/// Most connections served at once.
///
/// Only trusted clients get this far, so the cap is not the security boundary —
/// it is a guard against a buggy client opening connections in a loop and
/// spawning threads inside a SYSTEM process until something gives way.
const MAX_CONCURRENT_CONNECTIONS: usize = kam_ipc::MAX_PIPE_INSTANCES as usize;

/// Serve connections until `shutdown` is signalled.
///
/// Each connection is handled on its own thread. That was not true at first,
/// and sequential service was defensible while every request answered in
/// microseconds. A full-drive scan takes about a minute, and with one worker it
/// blocks the shell's status polling for that whole time — the UI would report
/// the agent as unreachable precisely while it was busiest.
pub fn serve(listener: &PipeListener, context: &Arc<Context>, shutdown: &Shutdown) -> Result<()> {
    let trusted_directory = Arc::new(trusted_directory()?);
    tracing::info!(directory = %trusted_directory.display(), "accepting clients from");
    let active = Arc::new(AtomicUsize::new(0));

    while !shutdown.is_signalled() {
        let mut stream = match listener.accept() {
            Ok(stream) => stream,
            Err(error) => {
                if shutdown.is_signalled() {
                    break;
                }
                // Backing off matters: an error here repeats immediately, and
                // without a pause the loop burns a core and writes thousands of
                // identical lines a second into the log.
                tracing::error!(%error, "could not accept a connection");
                std::thread::sleep(std::time::Duration::from_millis(200));
                continue;
            }
        };

        // The connection that woke us may be the shutdown poke rather than a
        // real client, so the flag is checked before the stream is touched.
        if shutdown.is_signalled() {
            break;
        }

        if active.load(Ordering::SeqCst) >= MAX_CONCURRENT_CONNECTIONS {
            tracing::warn!("connection limit reached; turning a client away");
            let _ = write_frame(
                &mut stream,
                &Response::Error {
                    message: "the agent is busy; try again shortly".to_owned(),
                },
            );
            continue;
        }

        active.fetch_add(1, Ordering::SeqCst);
        let context = Arc::clone(context);
        let trusted_directory = Arc::clone(&trusted_directory);
        let active_now = Arc::clone(&active);

        let spawned = std::thread::Builder::new()
            .name("kam-connection".to_owned())
            .spawn(move || {
                if let Err(error) = handle_connection(&mut stream, &context, &trusted_directory) {
                    // A bad peer must not stop the agent serving good ones.
                    tracing::warn!(%error, "dropping connection");
                }
                active_now.fetch_sub(1, Ordering::SeqCst);
            });

        if let Err(error) = spawned {
            tracing::error!(%error, "could not spawn a connection thread");
            active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    tracing::info!("accept loop stopped");
    Ok(())
}

fn handle_connection(
    stream: &mut PipeStream,
    context: &Context,
    trusted_directory: &Path,
) -> Result<()> {
    let image_path = stream.client_image_path()?;

    if !is_trusted_client(&image_path, trusted_directory) {
        // Refusals are recorded. Being able to open the pipe is not the same as
        // being trusted to drive it, and an attempt to cross that line is
        // exactly the kind of thing the audit log exists to preserve.
        context.audit(
            "agent",
            "reject_client",
            Effect::Refused,
            format!(
                "{} is not installed alongside the agent",
                image_path.display()
            ),
        );
        tracing::warn!(client = %image_path.display(), "refused an untrusted client");

        write_frame(
            stream,
            &Response::Error {
                message: "this program is not authorised to control the agent".to_owned(),
            },
        )?;
        return Ok(());
    }

    let request: Request = read_frame(stream)?;
    tracing::debug!(client = %image_path.display(), ?request, "serving request");
    let response = dispatch::handle(request, context);
    write_frame(stream, &response)
}

/// Directory the agent will accept clients from: its own.
///
/// The shell is installed next to the agent, so "same directory" is a check an
/// attacker cannot satisfy without already having write access to a privileged
/// install location -- at which point the pipe is not the weak point.
///
/// Authenticode verification of the client belongs here too, once releases are
/// signed. Until then this is the honest boundary, and it is stated as such.
fn trusted_directory() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    exe.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| Error::Privileged("the agent has no parent directory".to_owned()))
}

fn is_trusted_client(image_path: &Path, trusted_directory: &Path) -> bool {
    // Canonicalise both sides so `..`, short names, and symlinks cannot be used
    // to present an untrusted binary as though it sat in the trusted directory.
    let Ok(client_directory) = image_path
        .parent()
        .ok_or(())
        .and_then(|parent| parent.canonicalize().map_err(|_| ()))
    else {
        return false;
    };
    let Ok(trusted) = trusted_directory.canonicalize() else {
        return false;
    };
    client_directory == trusted
}

/// Connect to a running agent, ask for status, and print the reply.
///
/// A development aid, and the reason the trust check is exercised on every run:
/// the probe is this same executable, so it sits in the trusted directory and
/// passes the check the shell will later have to pass.
pub fn probe() -> Result<()> {
    let response = kam_ipc::client::call(&Request::GetSystemStatus)?;
    let rendered = serde_json::to_string_pretty(&response)
        .map_err(|error| Error::Protocol(format!("could not render the response: {error}")))?;
    println!("{rendered}");
    Ok(())
}

/// Where the agent keeps its store, which differs by how it was started.
pub fn store_path(running_as_service: bool) -> Result<PathBuf> {
    let base = if running_as_service {
        PathBuf::from(std::env::var_os("ProgramData").ok_or_else(|| {
            Error::Privileged("ProgramData is not set in the environment".to_owned())
        })?)
        .join("KAM Security")
    } else {
        // Development runs keep their state beside the build output rather than
        // touching the machine-wide location the service uses.
        std::env::current_exe()?
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| Error::Privileged("the agent has no parent directory".to_owned()))?
            .join("kam-dev-state")
    };
    Ok(base.join("kam.db"))
}

/// The quarantine store sits beside the audit database, so an item and the
/// record of why it was taken live or die together.
pub fn open_quarantine(running_as_service: bool) -> Result<kam_quarantine::Store> {
    let path = store_path(running_as_service)?
        .parent()
        .map(std::path::Path::to_path_buf)
        .ok_or_else(|| Error::Privileged("the store has no directory".to_owned()))?
        .join("quarantine");
    tracing::info!(path = %path.display(), "opening the quarantine store");
    kam_quarantine::Store::open(&path)
}

pub fn open_store(running_as_service: bool) -> Result<Store> {
    let path = store_path(running_as_service)?;
    tracing::info!(path = %path.display(), "opening the store");
    Store::open(&path)
}

/// Record an entry, logging rather than failing if the store rejects it.
///
/// A failed audit write must not silently swallow the fact that it failed, but
/// it also must not take down the agent mid-request.
pub fn record(store: &Store, entry: Entry) {
    if let Err(error) = store.record(entry) {
        tracing::error!(%error, "could not write an audit entry");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_client_in_the_trusted_directory_is_accepted() {
        let exe = std::env::current_exe().unwrap();
        let directory = exe.parent().unwrap();
        assert!(is_trusted_client(&exe, directory));
    }

    #[test]
    fn a_client_elsewhere_is_refused() {
        let exe = std::env::current_exe().unwrap();
        let elsewhere = std::env::temp_dir();
        assert!(!is_trusted_client(&exe, &elsewhere));
    }

    #[test]
    fn a_path_that_cannot_be_canonicalised_is_refused() {
        let missing = PathBuf::from(r"C:\this\path\does\not\exist\client.exe");
        let exe = std::env::current_exe().unwrap();
        assert!(!is_trusted_client(&missing, exe.parent().unwrap()));
    }

    #[test]
    fn signalling_shutdown_stops_a_loop_parked_in_accept() {
        // The subtlest part of the service lifecycle: accept() blocks inside
        // ConnectNamedPipe, which no flag can interrupt on its own. This asserts
        // that signal() actually unparks it, and that the poke connection is not
        // mistaken for a client and served.
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let name = format!("kam-test-shutdown-{}", std::process::id());
        let shutdown = crate::service::Shutdown::for_pipe(&name);
        let listener = PipeListener::with_name(name);

        let loop_shutdown = shutdown.clone();
        let (finished_tx, finished_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let quarantine_root =
                std::env::temp_dir().join(format!("kam-serve-test-{}", std::process::id()));
            let context = Arc::new(Context {
                mode: crate::Mode::Console,
                store: Store::open_in_memory().unwrap(),
                quarantine: kam_quarantine::Store::open(&quarantine_root).unwrap(),
            });
            let outcome = serve(&listener, &context, &loop_shutdown);
            let _ = finished_tx.send(());
            outcome
        });

        // Give the loop time to reach the blocking accept before stopping it.
        thread::sleep(Duration::from_millis(200));
        shutdown.signal();

        finished_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the accept loop did not stop when signalled");
        worker.join().unwrap().unwrap();
    }

    #[test]
    fn the_service_and_development_stores_are_different_files() {
        let service = store_path(true).unwrap();
        let development = store_path(false).unwrap();
        assert_ne!(service, development);
        assert!(development.to_string_lossy().contains("kam-dev-state"));
    }
}
