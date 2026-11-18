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
//!
//! # What it remembers, and for how long
//!
//! What it has already seen is kept in the store, not in this process, so a
//! restart of the service is not a fresh look. It used to be kept in memory,
//! with the first look after the service started taken as the one to learn
//! from. That look happens at boot, before anybody has signed in, so it held
//! nobody's own startup entries: they turned up on the second look and were
//! written down as new after every restart. And whatever was added while the
//! service was not running was learned at the next start without a word.
//!
//! The record is kept in parts, one for the machine's own entries and one for
//! each account's. The first look at a part learns it and reports nothing.
//! Every look after that, in whichever run of the service, reports what is
//! not on record. See [`fresh`].

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use kam_core::audit::{Effect, Entry};
use kam_core::db::Watched;
use kam_core::{Store, UserContext};
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

/// The part of the record the machine's own startup entries are held against.
const MACHINE: &str = "startup of the machine";

/// What marks a row of the record as a read of a decoy.
const DECOY_READ: &str = "decoy_read";

/// How an account is named in the record: by its SID, which is what stays
/// the same when the account is renamed. Its profile stands in for an account
/// with no SID to give, which is this process's own outside the service.
fn account(user: &UserContext) -> String {
    user.sid()
        .map(str::to_owned)
        .unwrap_or_else(|| user.profile().to_lowercase())
}

/// The part of the record one account's own startup entries are held against.
fn startup_of(user: &UserContext) -> String {
    format!("startup of {}", account(user))
}

/// The part of the record the reads of one account's decoys are held against.
fn decoy_reads_of(user: &UserContext) -> String {
    format!("decoy reads of {}", account(user))
}

/// One startup entry as the record holds it, so the same entry seen twice is
/// not reported twice. Location pins down where it lives; the command catches
/// an entry that keeps its name but changes what it runs.
///
/// So does the file the command comes to, which the command does not always
/// say. Every service inside svchost.exe has the same command, and what it
/// runs is a library named somewhere else: one swapped for another has to be
/// a different entry here, or it is never looked at.
///
/// The kind and the place are spelled as a sighting's are, which is what lets
/// a source that could not be read be asked whether it covers a row.
fn watched_as(entry: &persistence::Entry) -> Watched {
    Watched {
        kind: entry.anchor.kind().to_owned(),
        place: entry.location.to_lowercase(),
        what: format!(
            "{}\u{0}{}\u{0}{}",
            entry.name,
            entry.command,
            entry
                .target()
                .map(|target| target.to_string_lossy().into_owned())
                .unwrap_or_default()
        ),
    }
}

/// Hold what one look found in one part of the record against that part,
/// bring the record up to date, and hand back what was not on it.
///
/// # The first look is quiet, once
///
/// A part that has never been looked at is learned whole and nothing is
/// handed back: reporting it would be a list of everything that starts itself,
/// which is noise and not what a watcher is for. That is true of a new store,
/// of the first look after the update that brought this in, and of an account
/// signing in for the first time. It is not true of the first look after the
/// service starts. That one is held against the record like any other, so
/// what arrived while the service was not running is reported.
///
/// # What goes is forgotten, when it was seen to go
///
/// Something on record that this look did not find is taken off, so that it
/// is reported again if it comes back. `may_forget` is asked first, and
/// answers no for anything this look could have missed: a source that could
/// not be read must never make what is under it look gone, or it would be
/// reported as new the next time the source can be read.
///
/// # When the record cannot be read or written
///
/// Nothing is handed back. What was found is still not on record, so the
/// next look finds it again and reports it then. Saying it now as well would
/// say it at every look for as long as the store was in trouble.
fn fresh<T>(
    memory: &Store,
    part: &str,
    seen: Vec<(Watched, T)>,
    may_forget: impl Fn(&Watched) -> bool,
) -> Vec<T> {
    let known = match memory.watched(part) {
        Ok(known) => known,
        Err(error) => {
            tracing::warn!(%error, part, "the watcher could not read its record; nothing is reported from this look");
            return Vec::new();
        }
    };
    let Some(known) = known else {
        let all: Vec<Watched> = seen.into_iter().map(|(key, _)| key).collect();
        match memory.record_watched(part, &all, &[]) {
            Ok(()) => tracing::info!(part, learned = all.len(), "the watcher took its first look"),
            Err(error) => {
                tracing::warn!(%error, part, "the watcher could not write down its first look")
            }
        }
        return Vec::new();
    };

    let known: HashSet<Watched> = known.into_iter().collect();
    let present: HashSet<&Watched> = seen.iter().map(|(key, _)| key).collect();
    let gone: Vec<Watched> = known
        .iter()
        .filter(|one| !present.contains(one) && may_forget(one))
        .cloned()
        .collect();

    let mut taken: HashSet<Watched> = HashSet::new();
    let (appeared, found): (Vec<Watched>, Vec<T>) = seen
        .into_iter()
        .filter(|(key, _)| !known.contains(key) && taken.insert(key.clone()))
        .unzip();
    if appeared.is_empty() && gone.is_empty() {
        return found;
    }
    if let Err(error) = memory.record_watched(part, &appeared, &gone) {
        tracing::warn!(%error, part, "the watcher could not bring its record up to date; nothing is reported from this look");
        return Vec::new();
    }
    found
}

/// The startup entries in one part that are not on record for it.
///
/// Apart from the reading of the machine so that it can be tested with
/// surveys that were made up, across runs of the service that never happened.
fn appeared(memory: &Store, part: &str, survey: &persistence::Survey) -> Vec<persistence::Entry> {
    let seen = survey
        .entries
        .iter()
        .map(|entry| (watched_as(entry), entry.clone()))
        .collect();
    // Asked of each row, not of the look as a whole. One key that will not
    // read is all it would take to stop anything ever being forgotten, and
    // the survey already says exactly which places it could not vouch for.
    fresh(memory, part, seen, |known| {
        !survey
            .unreadable
            .iter()
            .any(|source| source.covers(&known.kind, &known.place))
    })
}

/// Take one snapshot, and report anything new that is worth a line.
///
/// The machine's own entries and each signed-in account's are read apart and
/// held against their own parts of the record. An account that is not signed
/// in is not read, and its part is left exactly as it was.
fn sweep(memory: &Store) -> Vec<Observation> {
    let mut looks = vec![(MACHINE.to_owned(), persistence::survey_of_machine())];
    for user in persistence::signed_in_users() {
        // Nothing back means the account signed out while it was being read,
        // which is the same as its not being signed in.
        if let Some(theirs) = persistence::survey_of_account(&user) {
            looks.push((startup_of(&user), theirs));
        }
    }
    looks
        .iter()
        .flat_map(|(part, survey)| appeared(memory, part, survey))
        .filter_map(|entry| behaviour::judge_entry(&entry))
        .collect()
}

/// One read of a decoy as the record holds it.
///
/// By the second it happened in, the file and the program, which is how the
/// reader of the log already folds the several events one read writes into
/// one. Any of those events is then the same read.
fn read_as(trip: &kam_canary::Trip) -> Watched {
    let second = trip.at.split('.').next().unwrap_or(&trip.at);
    Watched {
        kind: DECOY_READ.to_owned(),
        place: trip.path.to_lowercase(),
        what: format!(
            "{second}\u{0}{}",
            trip.process.as_deref().unwrap_or_default().to_lowercase()
        ),
    }
}

/// The reads of one account's decoys that are not on record.
///
/// # Why this is on record at all
///
/// Windows keeps these events for as long as the Security log holds them,
/// which is weeks. What had been seen was kept in memory and the first look
/// after the service started learned what was there, so a read from last week
/// was not reported as though it had just happened. But that look comes
/// before anybody has signed in, when no account's decoys are looked at. The
/// read from last week was first met on a later look, and reported again
/// after every restart, as strongly as this module reports anything.
///
/// # Why nothing is ever taken off it
///
/// The log is read back through a fixed number of events, in batches, and
/// this program's own reads of the decoys do not count towards that number.
/// So where the reading stops moves a little from one look to the next, and a
/// read near the edge can drop out of the list and come back. Forgetting it
/// when it dropped out would report it again when it came back. The record
/// only grows by reads that really happened, which is not many.
fn fresh_trips(memory: &Store, part: &str, trips: Vec<kam_canary::Trip>) -> Vec<kam_canary::Trip> {
    let seen = trips
        .into_iter()
        .map(|trip| (read_as(&trip), trip))
        .collect();
    fresh(memory, part, seen, |_| false)
}

/// Anything that has read a canary since the last look.
///
/// A canary read is the one signal in this product that is not circumstantial:
/// those files exist for no other purpose, nothing on the machine knows they are
/// there, and no legitimate program has a reason to open one. So it is reported
/// as strongly as this module reports anything, and with the process named.
fn canary_trips(memory: &Store, said: &mut HashSet<String>) -> Vec<Observation> {
    let mut found = Vec::new();

    for user in persistence::signed_in_users() {
        let report = kam_canary::status(&user);
        // A Security log that could not be read means a decoy could have been
        // read unseen. Said in the agent's own log when it starts and whenever
        // the reason changes, rather than on every pass.
        if let Some(reason) = &report.trips_unread {
            if said.insert(reason.clone()) {
                tracing::warn!(%reason, "reads of the decoys could not be checked");
            }
        }

        // The first look at an account's decoys has to be one that read the
        // log to the end. Learning from a look that could not would leave the
        // reads it missed to be reported as new by the first look that can.
        let part = decoy_reads_of(&user);
        if report.trips_unread.is_some() && !matches!(memory.watched(&part), Ok(Some(_))) {
            continue;
        }

        for trip in fresh_trips(memory, &part, report.trips) {
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

    // What has been seen is kept in the store, so that it outlasts this
    // process. Without a store there is nowhere lasting to keep it, and it is
    // kept for this run only, which is what the watcher did before it had a
    // record: better than not watching.
    let for_this_run;
    let memory: &Store = match &store {
        Some(store) => store,
        None => match Store::open_in_memory() {
            Ok(store) => {
                for_this_run = store;
                &for_this_run
            }
            Err(error) => {
                tracing::error!(%error, "the watcher has nowhere to keep what it has seen, so it is not watching");
                return;
            }
        },
    };

    // Deliberately not begun here. Whether the watch is live is decided by the
    // switch below, and saying "watching" before checking it meant an agent
    // started with the protection off still reported itself as watching — which
    // the window shows as "Watching since ...", a sentence that was not true.
    let mut said: HashSet<String> = HashSet::new();
    let mut stood_down = false;
    tracing::info!("behaviour watcher started");

    loop {
        // Honour the switch. The service keeps running either way -- it has to,
        // or there would be nothing left to switch it back on -- but when the
        // protection is off it stops looking, and the record is dropped so
        // that turning it back on learns the machine as it is now rather than
        // reporting everything installed in the meantime as a fresh arrival.
        let protecting = store
            .as_ref()
            .is_none_or(|store| store.protection_enabled());
        if !protecting {
            // Once for each spell of being off, the first pass after a start
            // included: the record is in the store now, and a switch flipped
            // in the last moments of the previous run has not been acted on.
            // Tried again at the next pass if the store would not take it.
            if !stood_down {
                tracing::info!("protection is off; the watcher is standing down");
                match memory.forget_watched() {
                    Ok(()) => stood_down = true,
                    Err(error) => {
                        tracing::warn!(%error, "the watcher could not drop its record")
                    }
                }
                said.clear();
                log.stop();
            }
            if wait(&shutdown, store.as_ref(), false) {
                tracing::info!("behaviour watcher stopped");
                return;
            }
            continue;
        }
        stood_down = false;
        if !log.is_watching() {
            log.begin();
            tracing::info!("protection is on; the watcher is looking again");
        }

        let mut observations = sweep(memory);
        observations.extend(canary_trips(memory, &mut said));

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
        // hand a person their whole startup as a list of alarms. The first look
        // at this machine must be silent whatever it finds.
        let memory = Store::open_in_memory().unwrap();
        let reported = sweep(&memory);
        assert!(
            reported.is_empty(),
            "the first pass reported {} entries; it must only learn",
            reported.len()
        );
        assert!(
            memory
                .watched(MACHINE)
                .unwrap()
                .is_some_and(|learned| !learned.is_empty()),
            "the first pass learned nothing, so the readers are broken"
        );
    }

    #[test]
    fn a_second_pass_with_no_change_reports_nothing() {
        // The steady state on a machine nobody is installing anything on: quiet.
        let memory = Store::open_in_memory().unwrap();
        sweep(&memory);
        let again = sweep(&memory);
        assert!(
            again.is_empty(),
            "nothing changed but the watcher reported {} things",
            again.len()
        );
    }

    /// A made-up startup entry. Where it is said to live decides whose it is,
    /// and nothing it names has to exist: what is tested here is which
    /// entries are taken for new, before any of them is judged.
    fn starts(
        anchor: persistence::Anchor,
        location: &str,
        name: &str,
        command: &str,
    ) -> persistence::Entry {
        persistence::Entry {
            name: name.to_owned(),
            anchor,
            location: location.to_owned(),
            command: command.to_owned(),
            executable: None,
            payload: None,
            host: None,
            hidden: false,
            machine_wide: location.starts_with("HKLM"),
            missing: None,
        }
    }

    fn looked(entries: &[&persistence::Entry]) -> persistence::Survey {
        persistence::Survey {
            entries: entries.iter().map(|entry| (*entry).clone()).collect(),
            unreadable: Vec::new(),
        }
    }

    fn names(entries: &[persistence::Entry]) -> Vec<&str> {
        entries.iter().map(|entry| entry.name.as_str()).collect()
    }

    const SERVICES: &str = r"HKLM\SYSTEM\CurrentControlSet\Services";
    const HER_RUN_KEY: &str =
        r"HKEY_USERS\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Run";
    const HERS: &str = "startup of S-1-5-21-1-2-3-1001";

    /// The fault as it was lived: the service starts at boot with nobody
    /// signed in, the person signs in, and their own startup entries, there
    /// for months, are written down as having just appeared.
    #[test]
    fn nobody_signed_in_and_then_somebody_reports_nothing_that_was_known() {
        let service = starts(
            persistence::Anchor::Service,
            &format!(r"{SERVICES}\Thing"),
            "Thing",
            "thing.exe",
        );
        let hers = starts(
            persistence::Anchor::RunKey,
            HER_RUN_KEY,
            "Shell",
            "kam-shell.exe",
        );

        // On a store that has never held anything: the machine is learned on
        // the first look, and her account on the look at which it first signs
        // in, each without a report.
        let memory = Store::open_in_memory().unwrap();
        assert!(appeared(&memory, MACHINE, &looked(&[&service])).is_empty());
        assert!(appeared(&memory, MACHINE, &looked(&[&service])).is_empty());
        assert!(appeared(&memory, HERS, &looked(&[&hers])).is_empty());

        // And at every start after that. The record is all that is carried
        // from one run of the service to the next, so a second run is the
        // same record met again: first with nobody signed in, then with her.
        for _restart in 0..3 {
            assert!(appeared(&memory, MACHINE, &looked(&[&service])).is_empty());
            let on_sign_in = appeared(&memory, HERS, &looked(&[&hers]));
            assert!(
                on_sign_in.is_empty(),
                "entries that were already known were reported at sign-in: {:?}",
                names(&on_sign_in)
            );
        }
    }

    /// What is added while the service is not running is reported by the
    /// first look of the next run. It used to be learned and never mentioned.
    ///
    /// Through a store on disk that is closed and opened again, which is what
    /// a restart is.
    #[test]
    fn an_entry_added_between_two_runs_is_reported_by_the_first_look_of_the_second() {
        let directory = std::env::temp_dir().join(format!(
            "kam-watch-restart-{}-{}",
            std::process::id(),
            kam_core::clock::now_utc_iso().replace(':', "")
        ));
        let path = directory.join("kam.db");
        let before = starts(
            persistence::Anchor::Service,
            &format!(r"{SERVICES}\Thing"),
            "Thing",
            "thing.exe",
        );
        let added = starts(
            persistence::Anchor::Service,
            &format!(r"{SERVICES}\Planted"),
            "Planted",
            "planted.exe",
        );

        {
            let first_run = Store::open(&path).unwrap();
            assert!(appeared(&first_run, MACHINE, &looked(&[&before])).is_empty());
        }
        let reported = {
            let second_run = Store::open(&path).unwrap();
            let reported = appeared(&second_run, MACHINE, &looked(&[&before, &added]));
            // And only once.
            assert!(appeared(&second_run, MACHINE, &looked(&[&before, &added])).is_empty());
            reported
        };
        std::fs::remove_dir_all(&directory).unwrap();

        assert_eq!(names(&reported), vec!["Planted"]);
    }

    /// Something that goes away is forgotten, so that it is reported again if
    /// it comes back.
    #[test]
    fn an_entry_that_leaves_and_returns_is_reported_again() {
        let stays = starts(
            persistence::Anchor::Service,
            &format!(r"{SERVICES}\Stays"),
            "Stays",
            "stays.exe",
        );
        let comes_and_goes = starts(
            persistence::Anchor::Service,
            &format!(r"{SERVICES}\Flits"),
            "Flits",
            "flits.exe",
        );
        let memory = Store::open_in_memory().unwrap();
        appeared(&memory, MACHINE, &looked(&[&stays, &comes_and_goes]));

        assert!(appeared(&memory, MACHINE, &looked(&[&stays])).is_empty());
        let back = appeared(&memory, MACHINE, &looked(&[&stays, &comes_and_goes]));
        assert_eq!(names(&back), vec!["Flits"]);
    }

    /// A look that could not read a place forgets nothing under it. What it
    /// did not find there may be there still, and forgetting it would report
    /// it as new the next time the place can be read.
    #[test]
    fn an_incomplete_read_forgets_nothing_it_could_have_missed() {
        let service = starts(
            persistence::Anchor::Service,
            &format!(r"{SERVICES}\Thing"),
            "Thing",
            "thing.exe",
        );
        let other = starts(
            persistence::Anchor::Service,
            &format!(r"{SERVICES}\Other"),
            "Other",
            "other.exe",
        );
        let task = starts(
            persistence::Anchor::ScheduledTask,
            r"C:\Windows\System32\Tasks\Backup",
            "Backup",
            "backup.exe",
        );
        let everything = looked(&[&service, &other, &task]);

        // The whole list of services could not be read.
        let memory = Store::open_in_memory().unwrap();
        appeared(&memory, MACHINE, &everything);
        let mut blind = looked(&[&task]);
        blind.unreadable.push(kam_core::changes::Unreadable::of(
            persistence::Anchor::Service.kind(),
            "the list of services could not be read",
        ));
        assert!(appeared(&memory, MACHINE, &blind).is_empty());
        let after = appeared(&memory, MACHINE, &everything);
        assert!(
            after.is_empty(),
            "services that were only unread were reported as new: {:?}",
            names(&after)
        );

        // One service's key could not be read. That says nothing about the
        // service beside it, which really has gone, and comes back.
        let memory = Store::open_in_memory().unwrap();
        appeared(&memory, MACHINE, &everything);
        let mut partly = looked(&[&task]);
        partly
            .unreadable
            .push(kam_core::changes::Unreadable::within(
                persistence::Anchor::Service.kind(),
                &format!(r"{SERVICES}\Thing"),
                "1 service(s) could not be read",
            ));
        assert!(appeared(&memory, MACHINE, &partly).is_empty());
        let after = appeared(&memory, MACHINE, &everything);
        assert_eq!(
            names(&after),
            vec!["Other"],
            "one unread key kept its neighbour from being forgotten, or was itself forgotten"
        );
    }

    /// An account met for the first time is learned without a report, and
    /// that takes nothing away from the machine, which is still compared.
    #[test]
    fn an_account_signing_in_for_the_first_time_is_learned_on_its_own() {
        let service = starts(
            persistence::Anchor::Service,
            &format!(r"{SERVICES}\Thing"),
            "Thing",
            "thing.exe",
        );
        let planted = starts(
            persistence::Anchor::Service,
            &format!(r"{SERVICES}\Planted"),
            "Planted",
            "planted.exe",
        );
        let hers = starts(
            persistence::Anchor::RunKey,
            HER_RUN_KEY,
            "Shell",
            "kam-shell.exe",
        );
        let later = starts(
            persistence::Anchor::RunKey,
            HER_RUN_KEY,
            "Updater",
            "upd.exe",
        );

        let memory = Store::open_in_memory().unwrap();
        appeared(&memory, MACHINE, &looked(&[&service]));

        let machine = appeared(&memory, MACHINE, &looked(&[&service, &planted]));
        let account = appeared(&memory, HERS, &looked(&[&hers]));
        assert_eq!(names(&machine), vec!["Planted"]);
        assert!(account.is_empty(), "{:?}", names(&account));

        // From then on her account is compared too.
        let account = appeared(&memory, HERS, &looked(&[&hers, &later]));
        assert_eq!(names(&account), vec!["Updater"]);
    }

    /// The same entry running something else is a different entry: the file
    /// its command comes to is part of what it is.
    #[test]
    fn an_entry_that_comes_to_run_something_else_is_new() {
        let host = r"C:\Windows\System32\svchost.exe -k netsvcs -p";
        let mut service = starts(
            persistence::Anchor::Service,
            &format!(r"{SERVICES}\Schedule"),
            "Task Scheduler",
            host,
        );
        service.executable = Some(std::path::PathBuf::from(r"C:\Windows\System32\svchost.exe"));
        service.host = Some("svchost.exe".to_owned());
        service.payload = Some(std::path::PathBuf::from(
            r"C:\Windows\System32\schedsvc.dll",
        ));
        let mut swapped = service.clone();
        swapped.payload = Some(std::path::PathBuf::from(r"C:\ProgramData\x\helper.dll"));

        let memory = Store::open_in_memory().unwrap();
        appeared(&memory, MACHINE, &looked(&[&service]));
        assert!(appeared(&memory, MACHINE, &looked(&[&service])).is_empty());
        let after = appeared(&memory, MACHINE, &looked(&[&swapped]));
        assert_eq!(after.len(), 1);
        assert_eq!(
            after[0].target(),
            Some(std::path::Path::new(r"C:\ProgramData\x\helper.dll"))
        );
    }

    /// Switching protection off drops the record, so that switching it back
    /// on learns the machine as it is then.
    #[test]
    fn a_dropped_record_is_learned_again_from_what_is_there() {
        let service = starts(
            persistence::Anchor::Service,
            &format!(r"{SERVICES}\Thing"),
            "Thing",
            "thing.exe",
        );
        let installed_meanwhile = starts(
            persistence::Anchor::Service,
            &format!(r"{SERVICES}\Meanwhile"),
            "Meanwhile",
            "meanwhile.exe",
        );
        let memory = Store::open_in_memory().unwrap();
        appeared(&memory, MACHINE, &looked(&[&service]));

        memory.forget_watched().unwrap();
        assert!(appeared(&memory, MACHINE, &looked(&[&service, &installed_meanwhile])).is_empty());
    }

    fn read(at: &str, process: &str) -> kam_canary::Trip {
        kam_canary::Trip {
            at: at.to_owned(),
            path: r"C:\Users\her\Documents\passwords.kdbx".to_owned(),
            process: Some(process.to_owned()),
            process_id: Some("0x1a2c".to_owned()),
            user: Some("her".to_owned()),
        }
    }

    /// A read of a decoy is reported once, whatever happens to the service.
    ///
    /// The reads were kept in memory, and the look that learned what was
    /// already in the log came before anybody had signed in. So a read from
    /// last week was first met on a later look and reported again after every
    /// restart, as the strongest thing this module ever says.
    #[test]
    fn a_read_of_a_decoy_is_reported_once_across_restarts() {
        let part = "decoy reads of S-1-5-21-1-2-3-1001";
        let old = read("2026-11-01T09:00:00.1234567Z", r"C:\Temp\thief.exe");
        let new = read("2026-11-18T14:00:00.7654321Z", r"C:\Temp\thief.exe");
        let memory = Store::open_in_memory().unwrap();

        // What is in the log when the account's decoys are first looked at
        // is learned: it was reported, or learned, before there was a record.
        assert!(fresh_trips(&memory, part, vec![old.clone()]).is_empty());

        // A new read is reported, and only that one.
        let reported = fresh_trips(&memory, part, vec![new.clone(), old.clone()]);
        assert_eq!(reported.len(), 1);
        assert_eq!(reported[0].at, new.at);

        // The record is all a restart keeps, and with it neither is new, at
        // any later look.
        assert!(fresh_trips(&memory, part, vec![new.clone(), old.clone()]).is_empty());

        // Dropping out of the stretch of the log that is read back, and
        // coming back into it, does not make a read new again. Nor does the
        // same read turning up as another of the events it wrote.
        assert!(fresh_trips(&memory, part, Vec::new()).is_empty());
        let again = read("2026-11-18T14:00:00.7000001Z", r"C:\TEMP\thief.exe");
        assert!(fresh_trips(&memory, part, vec![again, old]).is_empty());
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
