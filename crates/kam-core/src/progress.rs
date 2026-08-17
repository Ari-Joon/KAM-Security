//! Saying what a long job is doing, and letting it be stopped.
//!
//! A scan that takes forty seconds behind a disabled button is
//! indistinguishable from one that has hung, and people reasonably conclude
//! the second. The remedy is not a spinner — a spinner says only that the
//! process is still running — but a count of what has been done out of what
//! there is to do, and a way to change your mind.
//!
//! # Why a reporter rather than a channel
//!
//! The work being reported on is spread across scoped threads: signature
//! verification and content hashing both fan out across cores. A [`Reporter`]
//! is cheap to clone, safe to share between those threads, and does its own
//! rate limiting, so a worker can call [`Reporter::advance`] on every one of
//! four hundred files without four hundred messages crossing a pipe.
//!
//! # Silence is a first-class case
//!
//! Most callers — every test, every short operation, the benchmark harness —
//! have nobody to report to. [`Reporter::silent`] costs an `Option` check per
//! call and needs no special handling anywhere else, so instrumented code
//! stays readable and nothing has to be written twice.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Shortest gap between two progress messages.
///
/// Hashing can retire hundreds of files a second. Without a floor here the
/// interface spends more time rendering counters than the agent spends
/// working, and the pipe carries thousands of frames nobody sees. At roughly
/// eight updates a second the number still looks alive.
const MIN_INTERVAL: Duration = Duration::from_millis(120);

/// One report of how far along something is.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Progress {
    /// What is happening, in words meant for a person: "Verifying signatures",
    /// not "phase 2".
    pub stage: String,
    pub done: u64,
    /// How many there are in total, when that is known before starting. Some
    /// stages genuinely do not know, and claiming a total there would produce
    /// a bar that jumps backwards.
    pub total: Option<u64>,
    /// The item currently being worked on, when naming it helps. Optional
    /// because for most stages it is noise.
    pub detail: Option<String>,
}

impl Progress {
    /// Fraction complete, when that is meaningful.
    pub fn fraction(&self) -> Option<f64> {
        let total = self.total.filter(|total| *total > 0)?;
        Some((self.done as f64 / total as f64).clamp(0.0, 1.0))
    }
}

/// Raised when a job stops because it was asked to.
///
/// Distinct from an error: nothing went wrong, and the interface should say
/// "stopped" rather than showing a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cancelled;

impl std::fmt::Display for Cancelled {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("stopped at your request")
    }
}

struct Inner {
    sink: Box<dyn Fn(Progress) + Send + Sync>,
    stage: Mutex<String>,
    done: AtomicU64,
    total: AtomicU64,
    /// Nanoseconds since this reporter was made, at the last emitted message.
    last_emit: AtomicU64,
    started: Instant,
}

/// Reports progress and carries the signal to stop.
///
/// Cloning shares one underlying counter, so workers on several threads
/// contribute to a single total.
#[derive(Clone)]
pub struct Reporter {
    inner: Option<Arc<Inner>>,
    /// Kept outside `Inner` so a silent reporter can still be cancelled, which
    /// matters for jobs that report nothing but must remain stoppable.
    cancel: Arc<AtomicBool>,
}

impl std::fmt::Debug for Reporter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Reporter")
            .field("reporting", &self.inner.is_some())
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

impl Default for Reporter {
    fn default() -> Self {
        Self::silent()
    }
}

impl Reporter {
    /// A reporter that says nothing and is never cancelled.
    pub fn silent() -> Self {
        Self {
            inner: None,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    /// A reporter that hands each message to `sink`.
    pub fn new(sink: impl Fn(Progress) + Send + Sync + 'static) -> Self {
        Self {
            inner: Some(Arc::new(Inner {
                sink: Box::new(sink),
                stage: Mutex::new(String::new()),
                done: AtomicU64::new(0),
                total: AtomicU64::new(0),
                last_emit: AtomicU64::new(0),
                started: Instant::now(),
            })),
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The flag this reporter watches, so whoever started the job can stop it.
    pub fn cancel_token(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancel)
    }

    /// Ask the job to stop at its next convenient point.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }

    /// `Err(Cancelled)` once someone has asked to stop, for use with `?`.
    pub fn check(&self) -> Result<(), Cancelled> {
        if self.is_cancelled() {
            Err(Cancelled)
        } else {
            Ok(())
        }
    }

    /// Begin a new stage, resetting the count.
    ///
    /// Always emits: a stage change is the one message worth showing
    /// immediately, since it is what tells someone the job moved on rather
    /// than stalled.
    pub fn stage(&self, stage: &str, total: Option<u64>) {
        let Some(inner) = &self.inner else {
            return;
        };
        if let Ok(mut current) = inner.stage.lock() {
            current.clear();
            current.push_str(stage);
        }
        inner.done.store(0, Ordering::SeqCst);
        inner.total.store(total.unwrap_or(0), Ordering::SeqCst);
        self.emit(None, true);
    }

    /// Record that `by` more items are finished.
    pub fn advance(&self, by: u64) {
        let Some(inner) = &self.inner else {
            return;
        };
        inner.done.fetch_add(by, Ordering::SeqCst);
        self.emit(None, false);
    }

    /// Record one more item, naming it.
    pub fn advance_with(&self, detail: &str) {
        let Some(inner) = &self.inner else {
            return;
        };
        inner.done.fetch_add(1, Ordering::SeqCst);
        self.emit(Some(detail), false);
    }

    /// Revise the total once it becomes known.
    ///
    /// Some stages can only count their work after starting — sweeping a
    /// folder tree, for instance. Better to show an honest count with no total
    /// and then fill it in than to guess one.
    pub fn set_total(&self, total: u64) {
        let Some(inner) = &self.inner else {
            return;
        };
        inner.total.store(total, Ordering::SeqCst);
        self.emit(None, true);
    }

    fn emit(&self, detail: Option<&str>, force: bool) {
        let Some(inner) = &self.inner else {
            return;
        };

        let elapsed = inner.started.elapsed().as_nanos() as u64;
        if !force {
            let last = inner.last_emit.load(Ordering::SeqCst);
            if elapsed.saturating_sub(last) < MIN_INTERVAL.as_nanos() as u64 {
                return;
            }
            // Claim the slot. If another thread got there first, it is already
            // sending an equivalent message and this one adds nothing.
            if inner
                .last_emit
                .compare_exchange(last, elapsed, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                return;
            }
        } else {
            inner.last_emit.store(elapsed, Ordering::SeqCst);
        }

        let total = inner.total.load(Ordering::SeqCst);
        let stage = inner
            .stage
            .lock()
            .map(|stage| stage.clone())
            .unwrap_or_default();

        (inner.sink)(Progress {
            stage,
            done: inner.done.load(Ordering::SeqCst),
            total: (total > 0).then_some(total),
            detail: detail.map(str::to_owned),
        });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn collector() -> (Reporter, Arc<Mutex<Vec<Progress>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let reporter = Reporter::new(move |progress| {
            sink.lock().unwrap().push(progress);
        });
        (reporter, seen)
    }

    #[test]
    fn a_silent_reporter_does_nothing_and_does_not_panic() {
        let reporter = Reporter::silent();
        reporter.stage("anything", Some(10));
        reporter.advance(1);
        reporter.advance_with("a file");
        reporter.set_total(5);
        assert!(!reporter.is_cancelled());
        assert!(reporter.check().is_ok());
    }

    #[test]
    fn a_stage_change_is_always_reported() {
        // Rate limiting must never swallow these: a stage change is what tells
        // someone the job moved on rather than stalled.
        let (reporter, seen) = collector();
        reporter.stage("first", Some(3));
        reporter.stage("second", Some(4));
        reporter.stage("third", None);

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[0].stage, "first");
        assert_eq!(seen[1].stage, "second");
        assert_eq!(seen[2].stage, "third");
        assert_eq!(seen[2].total, None);
    }

    #[test]
    fn rapid_advances_are_collapsed() {
        // The property that keeps a pipe from carrying thousands of frames
        // nobody will ever see.
        let (reporter, seen) = collector();
        reporter.stage("hashing", Some(1000));
        for _ in 0..1000 {
            reporter.advance(1);
        }

        let count = seen.lock().unwrap().len();
        assert!(
            count < 20,
            "a thousand advances produced {count} messages; rate limiting is not working"
        );
    }

    #[test]
    fn the_count_is_kept_even_when_the_message_is_not_sent() {
        // Collapsing messages must not lose work: the next message that does
        // go out has to carry the true total.
        let (reporter, seen) = collector();
        reporter.stage("hashing", Some(500));
        for _ in 0..500 {
            reporter.advance(1);
        }
        reporter.set_total(500); // forces an emit

        let seen = seen.lock().unwrap();
        let last = seen.last().unwrap();
        assert_eq!(last.done, 500);
    }

    #[test]
    fn counting_is_shared_across_threads() {
        let (reporter, seen) = collector();
        reporter.stage("examining", Some(400));

        std::thread::scope(|scope| {
            for _ in 0..4 {
                let reporter = reporter.clone();
                scope.spawn(move || {
                    for _ in 0..100 {
                        reporter.advance(1);
                    }
                });
            }
        });

        reporter.set_total(400);
        assert_eq!(seen.lock().unwrap().last().unwrap().done, 400);
    }

    #[test]
    fn cancelling_is_visible_to_every_clone() {
        let reporter = Reporter::silent();
        let worker = reporter.clone();
        assert!(worker.check().is_ok());
        reporter.cancel();
        assert!(worker.is_cancelled());
        assert_eq!(worker.check(), Err(Cancelled));
    }

    #[test]
    fn the_cancel_token_stops_the_job_it_came_from() {
        // This is how the agent stops a job it is already streaming: the token
        // is kept aside when the job starts, and a later request sets it.
        let reporter = Reporter::silent();
        let token = reporter.cancel_token();
        assert!(!reporter.is_cancelled());
        token.store(true, Ordering::SeqCst);
        assert!(reporter.is_cancelled());
    }

    #[test]
    fn a_fraction_needs_a_total() {
        let without = Progress {
            stage: "sweeping".to_owned(),
            done: 10,
            total: None,
            detail: None,
        };
        assert_eq!(without.fraction(), None);

        let with = Progress {
            total: Some(40),
            ..without.clone()
        };
        assert_eq!(with.fraction(), Some(0.25));
    }

    #[test]
    fn a_fraction_never_exceeds_one() {
        // Totals are sometimes revised downward mid-stage. A bar past its own
        // end looks broken.
        let overshot = Progress {
            stage: "examining".to_owned(),
            done: 90,
            total: Some(40),
            detail: None,
        };
        assert_eq!(overshot.fraction(), Some(1.0));
    }
}
