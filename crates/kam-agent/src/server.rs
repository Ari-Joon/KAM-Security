//! The accept loop, and the policy deciding who is allowed to drive the agent.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};

use kam_core::audit::{AuditLog, Effect, Entry};
use kam_core::{Error, Progress, Reporter, Result, Store};
use kam_ipc::frame::{read_frame, write_frame};
use kam_ipc::pipe::{PipeListener, PipeStream};
use kam_ipc::{Reply, Request, Response};

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
                &Reply::Done(Response::Error {
                    message: "the agent is busy; try again shortly".to_owned(),
                }),
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
    context: &Arc<Context>,
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
            &Reply::Done(Response::Error {
                message: "this program is not authorised to control the agent".to_owned(),
            }),
        )?;
        return Ok(());
    }

    // Who the work is for, resolved from the caller's own token.
    //
    // This process runs as LocalSystem, so its environment and its
    // `HKEY_CURRENT_USER` describe SYSTEM: a real account with a real profile
    // directory that nobody has ever installed anything into. Measuring
    // against it does not fail, it silently answers about the wrong person.
    // That is how the agent came to report no application data in any user
    // profile, no Steam install at all, and every program as never opened.
    //
    // Falling back to the agent's own account would reintroduce exactly that,
    // so a caller whose profile cannot be resolved is refused instead.
    let sid = stream.client_sid()?;
    let Some(user) = kam_core::UserContext::for_sid(&sid) else {
        tracing::warn!(%sid, "the caller has no profile on this machine");
        write_frame(
            stream,
            &Reply::Done(Response::Error {
                message: "the account you are signed in as has no profile on this machine"
                    .to_owned(),
            }),
        )?;
        return Ok(());
    };

    let request: Request = read_frame(stream)?;
    tracing::debug!(client = %image_path.display(), user = %user.profile(), ?request, "serving");

    // Machine-wide changes only for a caller Windows would let make them. See
    // `dispatch::needs_administrator` for which, and why.
    //
    // Checked here, before the request reaches any handler, so that no single
    // arm can forget it. A token whose elevation cannot be read is treated as
    // not elevated: the safe answer to "may this caller change a machine-wide
    // setting" when the question cannot be asked is no.
    if dispatch::needs_administrator(&request, &user)
        && !stream.client_is_elevated().unwrap_or(false)
    {
        context.audit(
            "agent",
            "refuse_unelevated",
            Effect::Refused,
            format!(
                "{} asked for a machine-wide change without administrator rights",
                user.profile()
            ),
        );
        write_frame(
            stream,
            &Reply::Done(Response::Error {
                message: dispatch::NEEDS_ADMINISTRATOR.to_owned(),
            }),
        )?;
        return Ok(());
    }
    // A file is checked only if the caller could open it themselves. The
    // handler hands back its fingerprint, signer and download address, so
    // without this the service would answer about files Windows would not let
    // the caller see. So the file is opened here, while acting as the caller,
    // on this thread, before any handler runs, and that one open handle is
    // what the check then reads from: asking as the caller and afterwards
    // reading by name as LocalSystem let the name lead somewhere else in
    // between. Network and device paths are refused first, because even
    // opening one reaches out over the network.
    if let Request::CheckDownload { path, job, copy_of } = &request {
        let copy_of = copy_of.as_deref();
        let opened = crate::downloads::plain_paths(path, copy_of).and_then(|()| {
            stream
                .as_client(|| crate::downloads::open_as_caller(path, copy_of))
                .unwrap_or_else(|error| Err(format!("{path} was not checked: {error}")))
        });
        let opened = match opened {
            Ok(opened) => opened,
            Err(message) => {
                context.audit("downloads", "check", Effect::Refused, message.clone());
                write_frame(stream, &Reply::Done(Response::Error { message }))?;
                return Ok(());
            }
        };
        let job = job.clone();
        let response = run_job(stream, context, move |context, reporter| {
            crate::downloads::check(opened, &job, context, reporter, &user)
        });
        // The answer to one check is cut to fit where it is built, and this
        // is the net behind that, as for every other answer.
        return send_final(stream, response);
    }

    let response = run_job(stream, context, move |context, reporter| {
        dispatch::handle(request, context, reporter, &user)
    });
    send_final(stream, response)
}

/// Send the answer to a request, or say why it could not be sent.
///
/// A frame that is too large is refused before a byte of it is written, and
/// that refusal used to end the connection. The work had been done by then: a
/// duplicate search could run for minutes, find too much to fit, and leave
/// the window showing "failed to fill whole buffer" with nothing to say what
/// had happened or that trying again would do the same.
///
/// The lists known to grow are cut to fit before they get here, and say what
/// they left out. This is for whatever is not: the caller is told, in words,
/// that there was an answer and it was too large to send.
fn send_final<W: std::io::Write>(writer: &mut W, response: Response) -> Result<()> {
    let reply = Reply::Done(response);
    match write_frame(writer, &reply) {
        // Refused whole, so nothing of it is on the wire and the connection
        // is still good for a frame that says so.
        Err(Error::Protocol(refusal)) => {
            tracing::warn!(%refusal, "an answer could not be sent");
            let megabytes = serde_json::to_vec(&reply)
                .map(|written| written.len().div_ceil(1024 * 1024))
                .ok();
            // Only what is known here. Whether the request changed anything,
            // and whether asking again would differ, depend on the request.
            let message = match megabytes {
                Some(megabytes) => format!(
                    "The work was done, but its answer was too large to send back \
                     ({megabytes} MB, and one reply carries at most {} MB), so it \
                     cannot be shown.",
                    kam_ipc::MAX_FRAME_BYTES / (1024 * 1024)
                ),
                None => "The work was done, but its answer could not be sent back, \
                         so it cannot be shown."
                    .to_owned(),
            };
            write_frame(writer, &Reply::Done(Response::Error { message }))
        }
        outcome => outcome,
    }
}

/// Run one piece of work, streaming its progress down the same connection.
///
/// The work happens on its own thread and reports through a channel, which
/// this thread drains onto the pipe. It has to be that way round: the reporter
/// is shared with scoped worker threads and so must be `Send + Sync`, while a
/// pipe handle is neither — and a job that wrote to the pipe directly from
/// four hashing threads would interleave frames into nonsense.
///
/// The channel closes when the last clone of the reporter is dropped, which
/// happens when the job returns. So draining until the channel is empty *is*
/// waiting for the job to finish, and there is no separate signal to get wrong.
fn run_job(
    stream: &mut PipeStream,
    context: &Arc<Context>,
    work: impl FnOnce(&Context, &Reporter) -> Response + Send + 'static,
) -> Response {
    let (sender, receiver) = mpsc::channel::<Progress>();
    let reporter = Reporter::new(move |progress| {
        // A failed send means the reader has gone: the client hung up. The job
        // itself is unaffected and will be stopped by the usual path.
        let _ = sender.send(progress);
    });

    let context = Arc::clone(context);
    let worker = std::thread::Builder::new()
        .name("kam-job".to_owned())
        .spawn(move || work(&context, &reporter));

    let worker = match worker {
        Ok(worker) => worker,
        Err(error) => {
            tracing::error!(%error, "could not spawn a worker thread");
            return Response::Error {
                message: "the agent could not start the job".to_owned(),
            };
        }
    };

    for progress in receiver {
        if write_frame(stream, &Reply::Progress(progress)).is_err() {
            // The client is gone. Stop writing, but let the job finish and be
            // joined rather than leaving a thread running inside a SYSTEM
            // process with nobody waiting on it.
            tracing::debug!("client stopped reading progress");
            break;
        }
    }

    match worker.join() {
        Ok(response) => response,
        Err(_) => {
            // A panicked job must not take the agent down with it.
            tracing::error!("a job panicked");
            Response::Error {
                message: "the job failed unexpectedly; see the agent log".to_owned(),
            }
        }
    }
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

    // Before the file is opened, not after.
    //
    // The database's own protections are real -- the audit log's triggers, the
    // baseline's integrity -- and every one of them is defeated by a
    // write-ahead log planted in the directory beside it, because SQLite
    // applies a WAL as raw pages beneath SQL. The window for planting one is
    // exactly the moment before this call, when the service is not running and
    // the sidecar does not exist. So the directory is closed first.
    //
    // Only when running as the service. A development run has its store beside
    // the build output, where locking a developer out of their own directory
    // would be officious rather than protective, and where nothing is trusted
    // anyway.
    if running_as_service {
        if let Some(directory) = path.parent() {
            match crate::store_acl::harden(directory) {
                Ok(()) => {
                    tracing::debug!(path = %directory.display(), "store directory secured")
                }
                // Loud, and not fatal. An agent that refuses to start leaves
                // the machine with no protection at all, which is worse than
                // one running with a store somebody could reach; and the
                // failure is worth a person's attention either way.
                Err(error) => tracing::error!(
                    %error,
                    path = %directory.display(),
                    "the store directory could not be secured; its audit log and                      baseline can be rewritten by anybody who can write there"
                ),
            }
        }
    }

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

    /// An answer too large for a frame is answered with words, not silence.
    ///
    /// The frame was refused before anything was written and the connection
    /// was then dropped, so after a search that had run to its end the window
    /// saw a read fail and showed "failed to fill whole buffer".
    #[test]
    fn an_answer_too_large_to_send_is_replaced_by_one_that_says_so() {
        let enormous = Response::RecentAudit {
            entries: (0..40_000)
                .map(|id| kam_core::audit::Record {
                    id,
                    at: "2026-11-18T12:00:00.000Z".to_owned(),
                    module: "storage".to_owned(),
                    action: "scan".to_owned(),
                    effect: Effect::Observed,
                    detail: "x".repeat(300),
                    undo_token: None,
                })
                .collect(),
        };

        // The premise: on its own, this frame is refused.
        assert!(
            write_frame(&mut Vec::new(), &Reply::Done(enormous.clone())).is_err(),
            "the test's answer is not large enough to show anything"
        );

        let mut wire = Vec::new();
        send_final(&mut wire, enormous).expect("something is always sent");

        let reply: Reply = read_frame(&mut std::io::Cursor::new(wire)).unwrap();
        let Reply::Done(Response::Error { message }) = reply else {
            panic!("expected the caller to be told, got {reply:?}");
        };
        assert!(
            message.contains("too large to send") && message.contains("MB"),
            "the message should say what happened and how large: {message}"
        );
    }

    #[test]
    fn an_ordinary_answer_is_sent_as_it_is() {
        let mut wire = Vec::new();
        send_final(&mut wire, Response::Acknowledged).unwrap();
        let reply: Reply = read_frame(&mut std::io::Cursor::new(wire)).unwrap();
        assert!(matches!(reply, Reply::Done(Response::Acknowledged)));
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
                jobs: Default::default(),
                quarantine: kam_quarantine::Store::open(&quarantine_root).unwrap(),
                behaviour: Default::default(),
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
    fn a_long_job_streams_progress_over_a_real_pipe() {
        // End to end, through the actual transport: a job's progress must
        // arrive as frames *before* its result, and the result must still
        // arrive intact afterwards.
        //
        // This is the test that would have caught the tagging collision that
        // made every reply undeserialisable, and it is here because progress
        // that silently never arrives looks exactly like a job with nothing to
        // say.
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let name = format!("kam-test-progress-{}", std::process::id());
        let shutdown = crate::service::Shutdown::for_pipe(&name);
        let listener = PipeListener::with_name(name.clone());

        let loop_shutdown = shutdown.clone();
        let server = thread::spawn(move || {
            let quarantine_root =
                std::env::temp_dir().join(format!("kam-progress-test-{}", std::process::id()));
            let context = Arc::new(Context {
                mode: crate::Mode::Console,
                store: Store::open_in_memory().unwrap(),
                jobs: Default::default(),
                quarantine: kam_quarantine::Store::open(&quarantine_root).unwrap(),
                behaviour: Default::default(),
            });
            let _ = serve(&listener, &context, &loop_shutdown);
        });

        thread::sleep(Duration::from_millis(200));

        let (tx, rx) = mpsc::channel();
        let response = kam_ipc::client::call_streaming_on(
            &name,
            &Request::SurveyProvenance {
                job: "test-job".to_owned(),
            },
            move |progress| {
                let _ = tx.send(progress);
            },
        );

        shutdown.signal();
        let _ = server.join();

        let response = response.expect("the streamed call should succeed");
        assert!(
            matches!(response, Response::Provenance(_)),
            "unexpected result: {response:?}"
        );

        let seen: Vec<_> = rx.into_iter().collect();
        assert!(
            !seen.is_empty(),
            "no progress arrived; the job reported nothing at all"
        );

        // The stages are named, and at least one of them counts towards a
        // total. Without that the interface has nothing to draw a bar from.
        let stages: std::collections::BTreeSet<&str> =
            seen.iter().map(|p| p.stage.as_str()).collect();
        assert!(stages.len() > 1, "expected several stages, got {stages:?}");
        assert!(
            seen.iter().any(|p| p.total.is_some() && p.done > 0),
            "no stage reported measurable progress"
        );
        println!("{} updates across stages {stages:?}", seen.len());
    }

    #[test]
    fn the_service_and_development_stores_are_different_files() {
        let service = store_path(true).unwrap();
        let development = store_path(false).unwrap();
        assert_ne!(service, development);
        assert!(development.to_string_lossy().contains("kam-dev-state"));
    }
}
