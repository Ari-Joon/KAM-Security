//! Long jobs a page starts, kept by the window's own half while they run and
//! after they end.
//!
//! A Storage scan, Applications' Measure, Cleanup's searches, a Defender scan
//! and the Scanner's examination each ran inside the page that started it:
//! the page asked the service and waited for the answer. Leaving the page did
//! not stop the service, which finished the work and sent its answer back to
//! nothing. The page came back empty, with its button ready to start the same
//! job again beside the one still running, and a job that had failed
//! meanwhile said nothing at all.
//!
//! Each now runs here, on a thread of its own, the way the check of everything
//! not checked yet on Active downloads already did (`downloads::check_backlog`).
//! The page starts it and from then on only reads: how far it has got, sent as
//! an event and kept for a page drawn later, and what it came to, with when.
//!
//! # One of each
//!
//! Each job has one place, named by its page ([`Asked::slot`]). Starting it
//! again while it runs is refused. When it ends, its place keeps what it came
//! to (an answer, a stop, or why it failed) until it is handed over or the
//! next run of the same job replaces it.
//!
//! # Who keeps the answer
//!
//! Storage, Applications and Cleanup keep their last completed results in the
//! person's own folder (`remembered`), shaped by the page and changed by it as
//! rows are acted on. What their jobs come to passes through here once: the
//! page takes it, keeps it there, and says it has ([`Jobs::taken`]), and this
//! lets it go. Holding it here as well would be a second record of the same
//! result, and a wrong one as soon as a row on the page was acted on. Until
//! the page has taken it, it waits here, so a job that ends while its page is
//! closed is not lost.
//!
//! The other jobs' answers are kept nowhere else, so each stays here until
//! the next run of the same job, for as long as the program runs.
//!
//! # Not tied to the window
//!
//! Closing the window destroys its page, and is not a press of Stop. A job
//! goes on, and what it came to is here when the window is opened again, for
//! as long as the program keeps running in the notification area. Quitting
//! the program ends that: a job the service is still doing then finishes
//! there, and its answer goes nowhere, as it always did.

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use kam_core::Progress;
use kam_scanner::defender_scan::ScanKind;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};

/// What a page asked for: which job, and what that job needs to be told.
///
/// The name of each is its place ([`Asked::slot`]), which the page that owns
/// it uses to find it again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "slot", rename_all = "kebab-case")]
pub enum Asked {
    /// Storage: measure a drive or folder.
    Storage { path: String },
    /// Applications: what each program on a drive really occupies.
    Applications { drive: String },
    /// Cleanup: leftovers, forgotten downloads and large old files, from one
    /// read of a drive.
    CleanupSurvey { drive: String },
    /// Cleanup: files that are identical byte for byte.
    CleanupDuplicates { drive: String },
    /// Cleanup: caches and scratch space.
    CleanupCaches,
    /// Cleanup: loose files with an obvious home.
    CleanupLoose { drive: String },
    /// Scanner: a scan by Microsoft Defender.
    DefenderScan { scan: ScanKind },
    /// Scanner: where the programs that start themselves came from, and the
    /// rules matched against them.
    Examine,
}

impl Asked {
    /// The job's one place. The first five are also the names `remembered`
    /// keeps those pages' results under.
    pub fn slot(&self) -> &'static str {
        match self {
            Self::Storage { .. } => "storage",
            Self::Applications { .. } => "applications",
            Self::CleanupSurvey { .. } => "cleanup-survey",
            Self::CleanupDuplicates { .. } => "cleanup-duplicates",
            Self::CleanupCaches => "cleanup-caches",
            Self::CleanupLoose { .. } => "cleanup-loose",
            Self::DefenderScan { .. } => "defender-scan",
            Self::Examine => "examine",
        }
    }

    /// Whether its page keeps what it came to, in `remembered`, so that this
    /// lets go of it once the page has it.
    pub fn kept_by_its_page(&self) -> bool {
        matches!(
            self,
            Self::Storage { .. }
                | Self::Applications { .. }
                | Self::CleanupSurvey { .. }
                | Self::CleanupDuplicates { .. }
                | Self::CleanupCaches
        )
    }

    /// Whether the service can be asked to stop it part way. Only the jobs it
    /// runs under a name of their own can be, and those are the ones that had
    /// a Stop before they ran here.
    pub fn stoppable(&self) -> bool {
        matches!(
            self,
            Self::CleanupDuplicates { .. } | Self::DefenderScan { .. } | Self::Examine
        )
    }
}

/// How a run ended. Each says when, in milliseconds since 1970 by this
/// computer's clock, which is what the page's own clock counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "how", rename_all = "snake_case")]
pub enum Ended {
    /// It came to an answer.
    Finished { at: i64 },
    /// Somebody pressed Stop, and it stopped before it had an answer.
    Stopped { at: i64 },
    /// It came to no answer, for the reason given: the service's own words,
    /// or why it could not be asked.
    Failed { at: i64, reason: String },
}

/// One run as a page draws it: what was asked, when, how far it has got and
/// how it ended. Small enough to send at every step. What it came to is not
/// in it: that is asked for once it has ended ([`Jobs::outcome`]).
#[derive(Debug, Clone, Serialize)]
pub struct View {
    /// This run's name, which tells it apart from the runs before and after.
    job: String,
    asked: Asked,
    /// Counts every change to any job, so of two views of the same place the
    /// one with the larger number is the newer. They reach the page by two
    /// roads, a command's reply and an event, and can arrive in either order.
    sequence: u64,
    /// When it started, in milliseconds since 1970.
    started_at: i64,
    stoppable: bool,
    /// The last thing the service said about how far it has got.
    progress: Option<Progress>,
    /// How it ended. `None` while it runs.
    ended: Option<Ended>,
}

/// What a run came to: the answer, written as the page reads it; `None` when
/// it was stopped; or why there was neither.
pub type Came = Result<Option<serde_json::Value>, String>;

/// A run that has ended, with what it came to.
#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    view: View,
    /// The answer, when it finished. `None` when it was stopped or failed.
    answer: Option<serde_json::Value>,
}

#[derive(Debug)]
struct Entry {
    view: View,
    answer: Option<serde_json::Value>,
}

/// Every page's long job, by place: the one running, or what the last one
/// came to.
#[derive(Debug, Default)]
pub struct Jobs {
    entries: Mutex<HashMap<&'static str, Entry>>,
}

/// The next number for [`View::sequence`]. Only ever taken while the lock on
/// the entries is held, so the numbers follow the order of the changes.
static SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn next_sequence() -> u64 {
    SEQUENCE.fetch_add(1, Ordering::SeqCst)
}

impl Jobs {
    fn entries(&self) -> MutexGuard<'_, HashMap<&'static str, Entry>> {
        // Every change made under this lock is a single assignment or insert,
        // so a lock poisoned by a panic elsewhere still guards whole entries.
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The running entry in `slot`, when it is the run named `job`.
    fn running<'a>(
        entries: &'a mut HashMap<&'static str, Entry>,
        slot: &str,
        job: &str,
    ) -> Option<&'a mut Entry> {
        entries
            .get_mut(slot)
            .filter(|entry| entry.view.job == job && entry.view.ended.is_none())
    }

    /// Take the job's place under a new name, as started at `now`.
    ///
    /// Refused while a run of the same job is going: a second would do the
    /// same work beside the first, and the page can follow only one. A run
    /// that has ended gives its place up, with what it came to.
    pub fn begin(&self, asked: Asked, now: i64) -> Result<View, String> {
        static RUNS: AtomicU64 = AtomicU64::new(0);
        let slot = asked.slot();
        let mut entries = self.entries();
        if entries
            .get(slot)
            .is_some_and(|entry| entry.view.ended.is_none())
        {
            return Err(
                "It is already running. What it comes to will be shown here when it ends."
                    .to_owned(),
            );
        }
        let view = View {
            job: format!(
                "{slot}-{}-{}",
                std::process::id(),
                RUNS.fetch_add(1, Ordering::SeqCst)
            ),
            stoppable: asked.stoppable(),
            asked,
            sequence: next_sequence(),
            started_at: now,
            progress: None,
            ended: None,
        };
        entries.insert(
            slot,
            Entry {
                view: view.clone(),
                answer: None,
            },
        );
        Ok(view)
    }

    /// Note how far a run has got. Answers with the run as it now stands, or
    /// `None` when it is no longer the one running in its place.
    pub fn progressed(&self, slot: &str, job: &str, progress: Progress) -> Option<View> {
        let mut entries = self.entries();
        let entry = Self::running(&mut entries, slot, job)?;
        entry.view.progress = Some(progress);
        entry.view.sequence = next_sequence();
        Some(entry.view.clone())
    }

    /// Record what a run came to, at `now`. Answers as [`Jobs::progressed`].
    pub fn ended(&self, slot: &str, job: &str, came: Came, now: i64) -> Option<View> {
        let mut entries = self.entries();
        let entry = Self::running(&mut entries, slot, job)?;
        let (ended, answer) = match came {
            Ok(Some(answer)) => (Ended::Finished { at: now }, Some(answer)),
            Ok(None) => (Ended::Stopped { at: now }, None),
            Err(reason) => (Ended::Failed { at: now, reason }, None),
        };
        entry.view.progress = None;
        entry.view.ended = Some(ended);
        entry.view.sequence = next_sequence();
        entry.answer = answer;
        Some(entry.view.clone())
    }

    /// The job in this place as it stands, if there is one.
    pub fn view(&self, slot: &str) -> Option<View> {
        self.entries().get(slot).map(|entry| entry.view.clone())
    }

    /// What the job in this place came to, once it has ended.
    ///
    /// Asking does not take it. A page left between asking and keeping the
    /// answer would otherwise lose it, so it stays until the page says it has
    /// it ([`Jobs::taken`]) or the next run replaces it.
    pub fn outcome(&self, slot: &str) -> Option<Outcome> {
        let entries = self.entries();
        let entry = entries
            .get(slot)
            .filter(|entry| entry.view.ended.is_some())?;
        Some(Outcome {
            view: entry.view.clone(),
            answer: entry.answer.clone(),
        })
    }

    /// The page has what the run named `job` came to. When the page keeps
    /// that itself, the place is emptied; otherwise it stays, for the page to
    /// show again the next time it is opened.
    pub fn taken(&self, slot: &str, job: &str) {
        let mut entries = self.entries();
        let handed_over = entries.get(slot).is_some_and(|entry| {
            entry.view.job == job
                && entry.view.ended.is_some()
                && entry.view.asked.kept_by_its_page()
        });
        if handed_over {
            entries.remove(slot);
        }
    }

    /// The service's name for the job a Stop on this place has to cancel:
    /// the run in it, while it is running and can be stopped.
    pub fn to_stop(&self, slot: &str) -> Option<String> {
        self.entries()
            .get(slot)
            .filter(|entry| entry.view.ended.is_none() && entry.view.stoppable)
            .map(|entry| entry.view.job.clone())
    }

    /// Give up a run's place as though it had never started, when the thread
    /// that was to do it could not be started.
    fn abandon(&self, slot: &str, job: &str) {
        let mut entries = self.entries();
        if entries.get(slot).is_some_and(|entry| entry.view.job == job) {
            entries.remove(slot);
        }
    }
}

/// The work of one job, given what was asked, the run's name and somewhere to
/// say how far it has got. In the program it asks the service; in a test it
/// is whatever the test needs.
pub type Work = fn(&Asked, &str, &mut dyn FnMut(Progress)) -> Came;

/// The event a page listens on for its job. Each carries the [`View`] after
/// a change.
pub fn event(slot: &str) -> String {
    format!("jobs://{slot}")
}

/// Milliseconds since 1970.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
        })
}

/// Do one run to its end on this thread, saying each change.
///
/// A job that panics ends as a failure that says so. Its place would
/// otherwise say it was running for as long as the program ran, refusing
/// both Stop and a fresh start.
fn run_through(jobs: &Jobs, view: &View, work: Work, changed: &dyn Fn(View)) {
    let slot = view.asked.slot();
    let mut report = |progress: Progress| {
        if let Some(next) = jobs.progressed(slot, &view.job, progress) {
            changed(next);
        }
    };
    let came = catch_unwind(AssertUnwindSafe(|| {
        work(&view.asked, &view.job, &mut report)
    }))
    .unwrap_or_else(|_| {
        Err("it stopped unexpectedly, before it could say what it came to".to_owned())
    });
    if let Some(next) = jobs.ended(slot, &view.job, came, now()) {
        changed(next);
    }
}

/// Start a job, and return once it is under way. The page follows it from
/// there, by its [`event`] and by reading it again.
pub fn start(app: &AppHandle, asked: Asked, work: Work) -> Result<View, String> {
    let jobs = app.state::<Jobs>();
    let view = jobs.begin(asked, now())?;
    let slot = view.asked.slot();

    let worker = app.clone();
    let running = view.clone();
    let spawned = std::thread::Builder::new()
        .name(format!("kam-job-{slot}"))
        .spawn(move || {
            let jobs = worker.state::<Jobs>();
            run_through(&jobs, &running, work, &|next| {
                // Nobody listening is not a reason to stop: a page that is not
                // open, or a window that is closed, reads the run when it is.
                let _ = worker.emit(&event(slot), next);
            });
        });
    match spawned {
        Ok(_) => {
            // Said only once there is a thread to do the work: said before,
            // a page would follow a run that never started. The thread may
            // have said more already, and the page keeps the newer view.
            let _ = app.emit(&event(slot), view.clone());
            Ok(view)
        }
        Err(error) => {
            jobs.abandon(slot, &view.job);
            Err(format!("it could not be started: {error}"))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn every_job() -> Vec<Asked> {
        vec![
            Asked::Storage {
                path: r"C:\".to_owned(),
            },
            Asked::Applications {
                drive: r"C:\".to_owned(),
            },
            Asked::CleanupSurvey {
                drive: r"C:\".to_owned(),
            },
            Asked::CleanupDuplicates {
                drive: r"C:\".to_owned(),
            },
            Asked::CleanupCaches,
            Asked::CleanupLoose {
                drive: r"C:\".to_owned(),
            },
            Asked::DefenderScan {
                scan: ScanKind::Quick,
            },
            Asked::Examine,
        ]
    }

    fn step(stage: &str) -> Progress {
        Progress {
            stage: stage.to_owned(),
            done: 1,
            total: Some(2),
            detail: None,
        }
    }

    fn answer(text: &str) -> Came {
        Ok(Some(serde_json::Value::String(text.to_owned())))
    }

    /// The name a page sends is the one the place is kept under, and every
    /// job has a place of its own.
    #[test]
    fn each_job_has_its_own_place_named_as_the_page_names_it() {
        let mut places = Vec::new();
        for asked in every_job() {
            let written = serde_json::to_value(&asked).unwrap();
            assert_eq!(written["slot"], asked.slot(), "{asked:?}");
            let read: Asked = serde_json::from_value(written).unwrap();
            assert_eq!(read, asked);
            places.push(asked.slot());
        }
        let mut distinct = places.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), places.len(), "two jobs share a place");
    }

    /// Exactly the results a page keeps in `remembered` are handed over to
    /// it, so nothing is kept in both places and nothing in neither.
    #[test]
    fn the_jobs_handed_over_are_exactly_the_ones_their_pages_keep() {
        let handed_over: Vec<&str> = every_job()
            .iter()
            .filter(|asked| asked.kept_by_its_page())
            .map(Asked::slot)
            .collect();
        assert_eq!(handed_over, crate::remembered::KINDS.to_vec());
    }

    /// A second start of a job beside a run of it is refused, and the run in
    /// hand is untouched. Once it has ended, the place is free again.
    #[test]
    fn a_job_runs_once_at_a_time_and_its_place_is_free_once_it_ends() {
        let jobs = Jobs::default();
        let first = jobs.begin(Asked::CleanupCaches, 10).unwrap();
        let refusal = jobs.begin(Asked::CleanupCaches, 11).unwrap_err();
        assert!(refusal.contains("already running"), "{refusal}");
        assert_eq!(jobs.view("cleanup-caches").unwrap().job, first.job);

        // Another job's place is its own.
        jobs.begin(Asked::Examine, 12).unwrap();

        jobs.ended("cleanup-caches", &first.job, answer("measured"), 20)
            .unwrap();
        let second = jobs.begin(Asked::CleanupCaches, 30).unwrap();
        assert_ne!(second.job, first.job);
        assert!(
            jobs.outcome("cleanup-caches").is_none(),
            "the old answer stayed"
        );
    }

    /// How far a run has got is kept for a page that is drawn later, and
    /// every change is newer than the one before it.
    #[test]
    fn progress_is_kept_and_each_change_is_newer_than_the_last() {
        let jobs = Jobs::default();
        let started = jobs
            .begin(
                Asked::CleanupDuplicates {
                    drive: r"D:\".to_owned(),
                },
                100,
            )
            .unwrap();
        assert!(started.stoppable);
        let moved = jobs
            .progressed("cleanup-duplicates", &started.job, step("Hashing"))
            .unwrap();
        assert!(moved.sequence > started.sequence);

        let drawn_later = jobs.view("cleanup-duplicates").unwrap();
        assert_eq!(drawn_later.started_at, 100);
        assert_eq!(drawn_later.progress.unwrap().stage, "Hashing");

        let ended = jobs
            .ended("cleanup-duplicates", &started.job, answer("sets"), 200)
            .unwrap();
        assert!(ended.sequence > moved.sequence);
        assert!(ended.progress.is_none());
        assert_eq!(ended.ended, Some(Ended::Finished { at: 200 }));

        // A run that has ended, or that is not the one in the place, moves
        // nothing.
        assert!(jobs
            .progressed("cleanup-duplicates", &started.job, step("late"))
            .is_none());
        assert!(jobs
            .progressed("cleanup-duplicates", "someone-else", step("stray"))
            .is_none());
    }

    /// A failure is kept with its reason and its time, and is never an
    /// answer. A stop is kept as a stop.
    #[test]
    fn a_failure_or_a_stop_is_kept_as_what_it_was_and_never_as_an_answer() {
        let jobs = Jobs::default();
        let failing = jobs
            .begin(
                Asked::Storage {
                    path: r"C:\".to_owned(),
                },
                1,
            )
            .unwrap();
        jobs.ended(
            "storage",
            &failing.job,
            Err("the service is not answering".to_owned()),
            5,
        );
        let failed = jobs.outcome("storage").unwrap();
        assert_eq!(
            failed.view.ended,
            Some(Ended::Failed {
                at: 5,
                reason: "the service is not answering".to_owned()
            })
        );
        assert!(failed.answer.is_none());

        let stopping = jobs
            .begin(
                Asked::DefenderScan {
                    scan: ScanKind::Full,
                },
                1,
            )
            .unwrap();
        jobs.ended("defender-scan", &stopping.job, Ok(None), 9);
        let stopped = jobs.outcome("defender-scan").unwrap();
        assert_eq!(stopped.view.ended, Some(Ended::Stopped { at: 9 }));
        assert!(stopped.answer.is_none());
    }

    /// A result its page keeps is handed over once: asking for it again
    /// before the page has it gives it again, and once the page says it has
    /// it, it is gone from here. Any other job's answer stays.
    #[test]
    fn an_answer_its_page_keeps_is_let_go_once_taken_and_any_other_stays() {
        let jobs = Jobs::default();
        let scan = jobs
            .begin(
                Asked::Storage {
                    path: r"C:\".to_owned(),
                },
                1,
            )
            .unwrap();
        jobs.ended("storage", &scan.job, answer("the scan"), 2);

        // Asked twice, as a page left and opened again would.
        for _ in 0..2 {
            let outcome = jobs.outcome("storage").unwrap();
            assert_eq!(outcome.answer, Some("the scan".into()));
        }
        // A page holding an older run's name does not take this one.
        jobs.taken("storage", "storage-0-0");
        assert!(jobs.outcome("storage").is_some());

        jobs.taken("storage", &scan.job);
        assert!(jobs.outcome("storage").is_none(), "kept twice");
        assert!(jobs.view("storage").is_none());

        let examined = jobs.begin(Asked::Examine, 1).unwrap();
        jobs.ended("examine", &examined.job, answer("the survey"), 2);
        jobs.taken("examine", &examined.job);
        assert_eq!(
            jobs.outcome("examine").unwrap().answer,
            Some("the survey".into()),
            "an answer kept nowhere else was let go"
        );
    }

    /// A run still going is not taken from under the page that follows it.
    #[test]
    fn a_run_still_going_is_never_taken() {
        let jobs = Jobs::default();
        let running = jobs.begin(Asked::CleanupCaches, 1).unwrap();
        assert!(jobs.outcome("cleanup-caches").is_none());
        jobs.taken("cleanup-caches", &running.job);
        assert!(jobs.view("cleanup-caches").is_some());
    }

    /// Stop reaches the service's job only for a run that is going and that
    /// the service can stop.
    #[test]
    fn stop_names_the_services_job_only_while_it_runs_and_can_be_stopped() {
        let jobs = Jobs::default();
        assert_eq!(jobs.to_stop("examine"), None);

        let examined = jobs.begin(Asked::Examine, 1).unwrap();
        assert_eq!(jobs.to_stop("examine"), Some(examined.job.clone()));
        jobs.ended("examine", &examined.job, Ok(None), 2);
        assert_eq!(jobs.to_stop("examine"), None);

        // A scan the service runs without a name of its own has no Stop.
        jobs.begin(
            Asked::Storage {
                path: r"C:\".to_owned(),
            },
            1,
        )
        .unwrap();
        assert_eq!(jobs.to_stop("storage"), None);
        assert_eq!(jobs.to_stop("not-a-job"), None);
    }

    fn finds(asked: &Asked, job: &str, report: &mut dyn FnMut(Progress)) -> Came {
        assert!(job.starts_with(asked.slot()), "{job}");
        report(step("Reading"));
        answer("found")
    }

    fn breaks(_: &Asked, _: &str, _: &mut dyn FnMut(Progress)) -> Came {
        panic!("a job that broke")
    }

    /// A run is followed from start to end, and its answer waits for its
    /// page.
    #[test]
    fn a_run_is_followed_to_its_end_and_its_answer_waits() {
        let jobs = Jobs::default();
        let view = jobs.begin(Asked::CleanupCaches, now()).unwrap();
        let seen = Mutex::new(Vec::new());
        run_through(&jobs, &view, finds, &|next| seen.lock().unwrap().push(next));

        let seen = seen.into_inner().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].progress.as_ref().unwrap().stage, "Reading");
        assert!(matches!(seen[1].ended, Some(Ended::Finished { .. })));
        assert_eq!(
            jobs.outcome("cleanup-caches").unwrap().answer,
            Some("found".into())
        );
    }

    /// A job that panics ends as a failure, so its place is free for the
    /// next run and its page says it failed.
    #[test]
    fn a_job_that_breaks_ends_as_a_failure_and_frees_its_place() {
        let jobs = Jobs::default();
        let view = jobs
            .begin(
                Asked::CleanupLoose {
                    drive: r"C:\".to_owned(),
                },
                now(),
            )
            .unwrap();
        run_through(&jobs, &view, breaks, &|_| {});
        let outcome = jobs.outcome("cleanup-loose").unwrap();
        let Some(Ended::Failed { reason, .. }) = outcome.view.ended else {
            panic!("not a failure: {:?}", outcome.view.ended);
        };
        assert!(reason.contains("stopped unexpectedly"), "{reason}");
        assert!(jobs
            .begin(
                Asked::CleanupLoose {
                    drive: r"C:\".to_owned(),
                },
                now(),
            )
            .is_ok());
    }
}
