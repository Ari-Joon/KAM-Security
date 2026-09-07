//! The one thing the agent does without being asked: watch what newly starts
//! itself, and write down anything that appears in the shape unwanted software
//! uses to run unseen.
//!
//! # Why this is here at all
//!
//! Everything else in the agent answers a question the window asked. This does
//! not, and the reason is the incident this release was written after: a
//! credential stealer installed a hidden scheduled task that ran a script
//! through MSBuild, and nothing noticed until a person sat down and read the
//! task store by hand a day later. Defender never flagged it. The at-rest
//! provenance survey would have caught it — but only when someone next opened
//! the window and pressed a button. The gap was time: the thing to close is
//! "nobody looked for a day", and the way to close it is to look continuously.
//!
//! # What it costs, honestly
//!
//! The rest of this product makes a point of the agent doing no measurable work
//! while idle, and this spends a little of that. Every [`INTERVAL`] it reads the
//! Run keys, the Startup folders, the service list and the task store — the same
//! read the weekly check does, which is registry and small files, well under a
//! second and no disk to speak of. It is not a scan. But it is not nothing, and
//! it is written down here rather than hidden: a machine that watches itself
//! pays for it, and the price is one cheap snapshot a couple of times a minute.
//!
//! # Why a snapshot rather than an event stream
//!
//! The same reason the firewall watches by snapshot rather than ETW, recorded
//! in PLAN.md: a live event sink is a large amount of privileged surface, and
//! the thing being watched here is *persistence*, which by definition survives
//! to be seen at the next snapshot. A task that installs itself to run at every
//! logon does not need to be caught in the millisecond it is written; it needs
//! to be caught before the next logon, and a two-minute snapshot does that with
//! a fraction of the machinery.
//!
//! # What it does when it finds something
//!
//! It writes an audit entry, exactly as every other part of the agent does, and
//! keeps a copy in memory for the window to show in full. It does not delete,
//! quarantine, or block anything: the evidence is circumstantial, the product's
//! whole argument is that circumstantial evidence is presented and not acted on
//! automatically, and a watcher that killed things a second late on a guess
//! would be worse than the disease.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use kam_core::audit::{Effect, Entry};
use kam_core::Store;
use kam_scanner::behaviour::{self, Observation};
use kam_scanner::persistence;

use crate::server;
use crate::service::Shutdown;

/// How often to take a snapshot. Long enough that the cost is negligible, short
/// enough that something installed after you close the window is noticed the
/// same minute rather than the next time you happen to look.
const INTERVAL: Duration = Duration::from_secs(120);

/// How many observations to keep in memory for the window. The durable record
/// is the audit log; this is the rich copy, and a couple of hundred is far more
/// than a healthy machine will ever produce.
const KEEP: usize = 200;

/// The watcher's memory, shared between the watching thread and the request
/// that reads it. Cloning shares the same log rather than copying it.
#[derive(Clone, Debug, Default)]
pub struct Log {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug, Default)]
struct Inner {
    observations: VecDeque<Observation>,
    watching: bool,
    since: Option<String>,
}

impl Log {
    /// Record that watching has begun, so an empty list can be read as "nothing
    /// since then" rather than "not looking".
    fn begin(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.watching = true;
            inner.since = Some(kam_core::clock::now_utc_iso());
        }
    }

    fn stop(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.watching = false;
        }
    }

    fn push(&self, observation: Observation) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.observations.push_front(observation);
            while inner.observations.len() > KEEP {
                inner.observations.pop_back();
            }
        }
    }

    /// Whether the watch is currently live.
    pub fn is_watching(&self) -> bool {
        self.inner
            .lock()
            .map(|inner| inner.watching)
            .unwrap_or(false)
    }

    /// The observations recorded, newest first, and whether the watch is live.
    pub fn snapshot(&self) -> (Vec<Observation>, bool, Option<String>) {
        match self.inner.lock() {
            Ok(inner) => (
                inner.observations.iter().cloned().collect(),
                inner.watching,
                inner.since.clone(),
            ),
            Err(_) => (Vec::new(), false, None),
        }
    }
}

/// A stable key for one startup entry, so the same entry seen twice is not
/// reported twice. Location pins down where it lives; the command catches an
/// entry that keeps its name but changes what it runs.
fn key(entry: &persistence::Entry) -> String {
    format!(
        "{}\u{0}{}\u{0}{}",
        entry.location, entry.name, entry.command
    )
}

/// Take one snapshot, and report anything new that is worth a line.
///
/// Split out from the loop so it can be tested directly: given a baseline of
/// what was already there, it returns the observations for what has appeared
/// since. Pure but for the persistence read it does itself.
fn sweep(baseline: &mut HashSet<String>, first_pass: bool) -> Vec<Observation> {
    let survey = persistence::survey_for(&persistence::signed_in_users());
    let mut found = Vec::new();

    for entry in &survey.entries {
        let entry_key = key(entry);
        let already = !baseline.insert(entry_key);
        // On the first pass everything is "new", and reporting all of it would
        // be a list of the machine's entire startup at boot — noise, and not
        // what a watcher is for. The first pass only learns; it never reports.
        if already || first_pass {
            continue;
        }
        if let Some(observation) = behaviour::judge_entry(entry) {
            found.push(observation);
        }
    }
    found
}

/// Anything that has read a canary since the last look.
///
/// A canary read is the one signal in this product that is not circumstantial:
/// those files exist for no other purpose, nothing on the machine knows they are
/// there, and no legitimate program has a reason to open one. So it is reported
/// as strongly as this module reports anything, and with the process named.
fn canary_trips(seen: &mut HashSet<String>, first_pass: bool) -> Vec<Observation> {
    let mut found = Vec::new();

    for user in persistence::signed_in_users() {
        let report = kam_canary::status(&user);
        for trip in report.trips {
            // Windows keeps these events for as long as the Security log holds
            // them, so the first pass learns what is already there rather than
            // reporting a read from last week as though it just happened.
            let key = format!("{}\u{0}{}\u{0}{:?}", trip.at, trip.path, trip.process);
            if !seen.insert(key) || first_pass {
                continue;
            }

            let mut evidence = vec![
                "This file is a decoy. It was put there by KAM Security, nothing on this machine \
                 uses it, and no ordinary program has any reason to open it."
                    .to_owned(),
            ];
            if let Some(process) = &trip.process {
                evidence.push(format!("It was read by {process}."));
            }
            if let Some(user) = &trip.user {
                evidence.push(format!("The program was running as {user}."));
            }

            found.push(Observation {
                at: if trip.at.is_empty() {
                    kam_core::clock::now_utc_iso()
                } else {
                    trip.at.clone()
                },
                kind: behaviour::Kind::ProcessStart,
                concern: behaviour::Concern::Strong,
                summary: match &trip.process {
                    Some(process) => format!(
                        "{} read a decoy file",
                        std::path::Path::new(process)
                            .file_name()
                            .map(|name| name.to_string_lossy().into_owned())
                            .unwrap_or_else(|| process.clone())
                    ),
                    None => "Something read a decoy file".to_owned(),
                },
                evidence,
                subject: trip.path,
                command: trip.process.clone().unwrap_or_default(),
                pid: None,
            });
        }
    }

    found
}

/// Watch until told to stop. Runs on its own thread.
fn run(log: Log, running_as_service: bool, shutdown: Shutdown) {
    // The watcher writes to the audit log through its own connection to the same
    // database. SQLite in WAL mode handles several connections to one file, and
    // this keeps the watcher from having to share the Store the request handlers
    // hold.
    let store = match server::open_store(running_as_service) {
        Ok(store) => Some(store),
        Err(error) => {
            tracing::warn!(%error, "the watcher could not open the store; it will still keep an in-memory log");
            None
        }
    };

    // Deliberately not begun here. Whether the watch is live is decided by the
    // switch below, and saying "watching" before checking it meant an agent
    // started with the protection off still reported itself as watching — which
    // the window shows as "Watching since ...", a sentence that was not true.
    let mut baseline: HashSet<String> = HashSet::new();
    let mut canaries_seen: HashSet<String> = HashSet::new();
    let mut first_pass = true;
    tracing::info!("behaviour watcher started");

    loop {
        // Honour the switch. The service keeps running either way -- it has to,
        // or there would be nothing left to switch it back on -- but when the
        // protection is off it stops looking, and the baseline is dropped so
        // that turning it back on learns the machine as it is now rather than
        // reporting everything installed in the meantime as a fresh arrival.
        let protecting = store
            .as_ref()
            .is_none_or(|store| store.protection_enabled());
        if !protecting {
            // Keyed off what the log says rather than off the baseline, so the
            // state is right on the very first pass too.
            if log.is_watching() || !baseline.is_empty() {
                tracing::info!("protection is off; the watcher is standing down");
                baseline.clear();
                canaries_seen.clear();
                first_pass = true;
                log.stop();
            }
            if wait(&shutdown, store.as_ref(), false) {
                tracing::info!("behaviour watcher stopped");
                return;
            }
            continue;
        }
        if !log.is_watching() {
            log.begin();
            tracing::info!("protection is on; the watcher is looking again");
        }

        let mut observations = sweep(&mut baseline, first_pass);
        observations.extend(canary_trips(&mut canaries_seen, first_pass));
        first_pass = false;

        for observation in observations {
            tracing::info!(
                subject = %observation.subject,
                concern = ?observation.concern,
                "watcher: {}",
                observation.summary
            );
            if let Some(store) = &store {
                record(store, &observation);
            }
            log.push(observation);
        }

        if wait(&shutdown, store.as_ref(), true) {
            log.stop();
            tracing::info!("behaviour watcher stopped");
            return;
        }
    }
}

/// Sleep until the next sweep, a stop, or the switch being flipped.
///
/// Returns true when the caller should stop altogether.
///
/// Three things have to be able to interrupt the wait, and the reasons differ.
/// A stop must be prompt or `sc stop` appears to hang. The switch must be prompt
/// because the window says "nothing is being watched" the moment it is turned
/// off, and that sentence has to be true when it is written rather than up to
/// two minutes later. The interval itself is the ordinary case.
///
/// The setting is re-read every few seconds rather than every second: it is a
/// small indexed read, but this is a service that makes a point of costing
/// nothing while idle, and nobody can tell the difference between one second and
/// five when flicking a switch.
fn wait(shutdown: &Shutdown, store: Option<&Store>, protecting_now: bool) -> bool {
    const CHECK_EVERY: u64 = 5;

    for elapsed in 0..INTERVAL.as_secs() {
        if shutdown.is_signalled() {
            return true;
        }
        if elapsed % CHECK_EVERY == 0 {
            if let Some(store) = store {
                if store.protection_enabled() != protecting_now {
                    return false;
                }
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    false
}

/// Write one observation into the audit log.
///
/// A strong concern is recorded as `Refused` — the audit log's word for "this
/// state is wrong" — and a notable one as `Observed`, matching how the weekly
/// check already uses the two. The module is `behaviour`, so the window and a
/// person reading the log can tell watcher findings from everything else.
fn record(store: &Store, observation: &Observation) {
    server::record(
        store,
        Entry {
            module: "behaviour",
            action: observation.kind.action(),
            effect: if observation.concern.is_strong() {
                Effect::Refused
            } else {
                Effect::Observed
            },
            detail: format!("{} — {}", observation.summary, observation.subject),
            undo_token: None,
        },
    );
}

/// Start the watcher on its own thread and hand back its handle, so the caller
/// can join it when the service stops.
pub fn spawn(log: Log, running_as_service: bool, shutdown: Shutdown) -> Option<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("kam-behaviour-watcher".to_owned())
        .spawn(move || run(log, running_as_service, shutdown))
        .map_err(|error| {
            tracing::error!(%error, "could not start the behaviour watcher");
            error
        })
        .ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn the_first_pass_learns_without_reporting() {
        // A watcher that flagged everything already present at startup would
        // hand a person their whole startup as a list of alarms. The first pass
        // must be silent whatever it finds.
        let mut baseline = HashSet::new();
        let reported = sweep(&mut baseline, true);
        assert!(
            reported.is_empty(),
            "the first pass reported {} entries; it must only learn",
            reported.len()
        );
        assert!(
            !baseline.is_empty(),
            "the first pass learned nothing, so the readers are broken"
        );
    }

    #[test]
    fn a_second_pass_with_no_change_reports_nothing() {
        // The steady state on a machine nobody is installing anything on: quiet.
        let mut baseline = HashSet::new();
        sweep(&mut baseline, true);
        let again = sweep(&mut baseline, false);
        assert!(
            again.is_empty(),
            "nothing changed but the watcher reported {} things",
            again.len()
        );
    }

    #[test]
    fn the_log_keeps_newest_first_and_bounded() {
        let log = Log::default();
        for index in 0..(KEEP + 10) {
            log.push(Observation {
                at: format!("2026-09-06T14:{index:02}:00.000Z"),
                kind: kam_scanner::behaviour::Kind::ScheduledTask,
                concern: kam_scanner::behaviour::Concern::Notable,
                summary: format!("observation {index}"),
                evidence: vec!["because".to_owned()],
                subject: format!("thing-{index}.cmd"),
                command: "cmd".to_owned(),
                pid: None,
            });
        }
        let (observations, _, _) = log.snapshot();
        assert_eq!(observations.len(), KEEP, "the log must stay bounded");
        assert_eq!(
            observations[0].summary,
            format!("observation {}", KEEP + 9),
            "newest must be first"
        );
    }

    #[test]
    fn beginning_a_watch_is_visible() {
        let log = Log::default();
        let (_, watching, since) = log.snapshot();
        assert!(!watching);
        assert!(since.is_none());
        log.begin();
        let (_, watching, since) = log.snapshot();
        assert!(watching);
        assert!(since.is_some());
    }
}
