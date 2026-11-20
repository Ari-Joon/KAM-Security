//! Whether KAM Security's service is answering, as the window last found it.
//!
//! The window learnt that the service had stopped one page at a time: each
//! failed in its own words the next time it asked for something, or showed
//! nothing, while a notice written for a developer said the pipe was not
//! listening and how to start the service from a terminal. A service from a
//! different install had a second notice of its own.
//!
//! Now the window asks every few seconds while it is open and says what it
//! found in one place above every page: that the service is not answering and
//! since when, that it is from a different install, or that it turned the
//! window away, and then that it is answering again. When it answers, nothing
//! is said at all.
//!
//! # The question
//!
//! `GetSystemStatus`, the smallest request there is. The service answers it
//! from memory and does not record it in the Activity log. It is asked only
//! while the window is open: the window does the asking, and the icon in the
//! notification area asks nothing (see `tray`).
//!
//! One question at a time. While one is unanswered no other is sent, and one
//! still unanswered after [`PATIENCE`] counts as no answer. So a service that
//! has hung, taking the question and never replying, is reported within
//! seconds, and the questions do not pile up behind it.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{mpsc, Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use kam_ipc::{Response, SystemStatus};
use serde::Serialize;

/// How long after one answer the next question is asked.
pub const EVERY: Duration = Duration::from_secs(5);

/// How long a question waits for its answer before counting as none.
pub const PATIENCE: Duration = Duration::from_secs(5);

/// How long after being turned away the next question is asked. The service
/// writes every caller it turns away into the Activity log, so asking every
/// few seconds would write an entry every few seconds.
pub const AFTER_REFUSAL: Duration = Duration::from_secs(60);

/// How long "answering again" is said before it goes.
pub const AGAIN_FOR: Duration = Duration::from_secs(15);

/// The longest gap between the last answer and the first question without one
/// for the window to have been asking all along: one round of asking and
/// waiting, with room for a slow one. A longer gap means the window was
/// closed in between, and when the service stopped is not known.
const WATCHED: Duration = Duration::from_secs(15);

/// What one question came to.
#[derive(Debug, Clone)]
pub enum Heard {
    /// It answered.
    Answered(SystemStatus),
    /// It answered, and would not serve this window. Its own words.
    Refused(String),
    /// Something answered that this window cannot read: a service from a
    /// different install, speaking another version of the protocol.
    Unreadable(String),
    /// No answer: nothing is listening, the connection broke, or it took too
    /// long.
    Silent(String),
}

/// Sort a reply to `GetSystemStatus` by what it says about the service.
pub fn classify(reply: kam_core::Result<Response>) -> Heard {
    match reply {
        Ok(Response::SystemStatus(status)) => Heard::Answered(status),
        Ok(Response::Error { message }) => Heard::Refused(message),
        Ok(_) => Heard::Unreadable("it answered with something other than its status".to_owned()),
        // A frame this window could not read is still an answer, in a shape
        // this build does not know. Every other failure is no answer at all.
        Err(kam_core::Error::Protocol(reason)) => Heard::Unreadable(reason),
        Err(error) => Heard::Silent(error.to_string()),
    }
}

/// What the window says about the service, above every page. Times are
/// milliseconds since 1970, which is what the page's own clock counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Notice {
    /// Nothing: it answered the last time it was asked, or has not been asked
    /// yet. This is the ordinary state, and it has no words.
    Quiet,
    /// It is not answering.
    NotAnswering {
        /// The first question in a row that went unanswered.
        since: i64,
        /// The last question it did answer, if it has answered one.
        last_answered: Option<i64>,
        /// Whether the window was asking all along, so that the service
        /// stopped answering between `last_answered` and `since`.
        watched: bool,
        /// Why there was no answer, in Windows' words.
        reason: String,
    },
    /// It answered in a version of the protocol this window does not speak,
    /// or in a form it cannot read: the two are from different installs.
    OtherVersion {
        since: i64,
        window: u32,
        /// `None` when what it answered could not be read.
        service: Option<u32>,
        /// Why what it answered could not be read, when it could not.
        unreadable: Option<String>,
    },
    /// It answered, and would not serve this window.
    Refused { since: i64, message: String },
    /// It answered this window again at `at`, after not doing so since
    /// `from`.
    AnsweringAgain { at: i64, from: i64 },
}

/// What one check tells the window.
#[derive(Debug, Clone, Serialize)]
pub struct Checked {
    pub notice: Notice,
    /// What the service said about itself, while it is answering.
    pub status: Option<SystemStatus>,
    /// When to ask again.
    pub next_in_ms: u64,
}

/// What is wrong, while something is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Trouble {
    Silent {
        reason: String,
    },
    OtherVersion {
        service: Option<u32>,
        unreadable: Option<String>,
    },
    Refused {
        message: String,
    },
}

#[derive(Debug, Default)]
struct State {
    /// A question has been sent and its answer has not come back.
    asking: bool,
    last_answered: Option<i64>,
    status: Option<SystemStatus>,
    /// What is wrong now, and since when it has been that.
    trouble: Option<(Trouble, i64)>,
    /// When this spell of trouble began, whatever it has been since.
    down_since: Option<i64>,
    /// When it answered again, and since when it had not.
    again: Option<(i64, i64)>,
}

fn milliseconds(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

impl State {
    fn heard(&mut self, heard: Heard, now: i64) {
        match heard {
            Heard::Answered(status) if status.protocol_version == kam_ipc::PROTOCOL_VERSION => {
                if let Some(from) = self.down_since.take() {
                    self.again = Some((now, from));
                }
                self.trouble = None;
                self.last_answered = Some(now);
                self.status = Some(status);
            }
            Heard::Answered(status) => {
                self.in_trouble(
                    Trouble::OtherVersion {
                        service: Some(status.protocol_version),
                        unreadable: None,
                    },
                    now,
                );
                self.last_answered = Some(now);
                // What it said about itself could be read, so the pages may
                // still show it, under the notice.
                self.status = Some(status);
            }
            Heard::Unreadable(reason) => {
                self.in_trouble(
                    Trouble::OtherVersion {
                        service: None,
                        unreadable: Some(reason),
                    },
                    now,
                );
                self.status = None;
            }
            Heard::Refused(message) => {
                self.in_trouble(Trouble::Refused { message }, now);
                self.status = None;
            }
            Heard::Silent(reason) => {
                self.in_trouble(Trouble::Silent { reason }, now);
                self.status = None;
            }
        }
    }

    /// Something is wrong at `now`. The same kind of trouble as before keeps
    /// its first time, and its latest words.
    fn in_trouble(&mut self, trouble: Trouble, now: i64) {
        let since = match &self.trouble {
            Some((before, since))
                if std::mem::discriminant(before) == std::mem::discriminant(&trouble) =>
            {
                *since
            }
            _ => now,
        };
        self.trouble = Some((trouble, since));
        self.down_since.get_or_insert(now);
        self.again = None;
    }

    fn notice(&self, now: i64) -> Notice {
        if let Some((trouble, since)) = &self.trouble {
            let since = *since;
            return match trouble {
                Trouble::Silent { reason } => Notice::NotAnswering {
                    since,
                    last_answered: self.last_answered,
                    watched: self
                        .last_answered
                        .is_some_and(|last| since - last <= milliseconds(WATCHED)),
                    reason: reason.clone(),
                },
                Trouble::OtherVersion {
                    service,
                    unreadable,
                } => Notice::OtherVersion {
                    since,
                    window: kam_ipc::PROTOCOL_VERSION,
                    service: *service,
                    unreadable: unreadable.clone(),
                },
                Trouble::Refused { message } => Notice::Refused {
                    since,
                    message: message.clone(),
                },
            };
        }
        match self.again {
            Some((at, from)) if now - at < milliseconds(AGAIN_FOR) => {
                Notice::AnsweringAgain { at, from }
            }
            _ => Notice::Quiet,
        }
    }

    fn next_in(&self) -> Duration {
        match self.trouble {
            Some((Trouble::Refused { .. }, _)) => AFTER_REFUSAL,
            _ => EVERY,
        }
    }

    fn checked(&self, now: i64) -> Checked {
        Checked {
            notice: self.notice(now),
            status: self.status.clone(),
            next_in_ms: u64::try_from(self.next_in().as_millis()).unwrap_or(u64::MAX),
        }
    }
}

/// What the window knows about the service, between checks.
#[derive(Debug, Default)]
pub struct Watch {
    state: Mutex<State>,
}

impl Watch {
    fn state(&self) -> MutexGuard<'_, State> {
        // Every change made under this lock leaves the state whole, so a lock
        // poisoned by a panic elsewhere is still good to read.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Milliseconds since 1970.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
        })
}

/// Ask the service once, unless a question is already waiting for its
/// answer, and say what is known now.
///
/// `ask` runs on a thread of its own, so this returns within `patience`. A
/// question unanswered by then counts as no answer and stays out: its answer
/// is recorded whenever it comes, and until then no other question is sent.
pub fn check(
    watch: &Arc<Watch>,
    ask: impl FnOnce() -> Heard + Send + 'static,
    patience: Duration,
) -> Checked {
    {
        let mut state = watch.state();
        if state.asking {
            return state.checked(now());
        }
        state.asking = true;
    }

    let (answered, answer) = mpsc::channel();
    let asker = Arc::clone(watch);
    let spawned = std::thread::Builder::new()
        .name("kam-service-check".to_owned())
        .spawn(move || {
            // A question that broke is no answer. Left out, it would stop
            // every question after it from being asked.
            let heard = catch_unwind(AssertUnwindSafe(ask))
                .unwrap_or_else(|_| Heard::Silent("asking it failed unexpectedly".to_owned()));
            let mut state = asker.state();
            state.heard(heard, now());
            state.asking = false;
            drop(state);
            let _ = answered.send(());
        });
    if let Err(error) = spawned {
        let mut state = watch.state();
        state.asking = false;
        state.heard(
            Heard::Silent(format!("the window could not ask it: {error}")),
            now(),
        );
        return state.checked(now());
    }

    let waited = answer.recv_timeout(patience);
    let mut state = watch.state();
    if waited.is_err() && state.asking {
        state.heard(
            Heard::Silent(format!(
                "it did not answer within {} seconds",
                patience.as_secs()
            )),
            now(),
        );
    }
    state.checked(now())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn status(protocol_version: u32) -> SystemStatus {
        SystemStatus {
            protocol_version,
            agent_version: "0.6.0".to_owned(),
            running_as_service: true,
            hostname: "test-host".to_owned(),
        }
    }

    fn answered() -> Heard {
        Heard::Answered(status(kam_ipc::PROTOCOL_VERSION))
    }

    fn silent() -> Heard {
        Heard::Silent("could not connect to the agent".to_owned())
    }

    const SECOND: i64 = 1000;

    #[test]
    fn a_reply_is_sorted_by_what_it_says_about_the_service() {
        assert!(matches!(
            classify(Ok(Response::SystemStatus(status(7)))),
            Heard::Answered(found) if found.protocol_version == 7
        ));
        assert!(matches!(
            classify(Ok(Response::Error {
                message: "this program is not authorised to control the agent".to_owned()
            })),
            Heard::Refused(message) if message.contains("not authorised")
        ));
        assert!(matches!(
            classify(Err(kam_core::Error::Protocol(
                "could not deserialise frame".to_owned()
            ))),
            Heard::Unreadable(_)
        ));
        assert!(matches!(
            classify(Ok(Response::Acknowledged)),
            Heard::Unreadable(_)
        ));
        assert!(matches!(
            classify(Err(kam_core::Error::Privileged(
                "could not connect to the agent".to_owned()
            ))),
            Heard::Silent(reason) if reason.contains("could not connect")
        ));
        assert!(matches!(
            classify(Err(kam_core::Error::Io(std::io::Error::other(
                "the pipe has been ended"
            )))),
            Heard::Silent(_)
        ));
    }

    /// Answering is the ordinary state, and nothing is said about it: not
    /// before the first question, and not after an answer.
    #[test]
    fn nothing_is_said_while_it_answers() {
        let mut state = State::default();
        assert_eq!(state.notice(0), Notice::Quiet);
        state.heard(answered(), 10 * SECOND);
        assert_eq!(state.notice(11 * SECOND), Notice::Quiet);
        assert_eq!(state.checked(11 * SECOND).next_in_ms, 5000);
        assert!(state.checked(11 * SECOND).status.is_some());
    }

    /// Not answering is said with the first moment it was found, which a run
    /// of unanswered questions keeps, and with the latest reason.
    #[test]
    fn not_answering_keeps_its_first_time_and_says_it_was_watched() {
        let mut state = State::default();
        state.heard(answered(), 100 * SECOND);
        state.heard(silent(), 105 * SECOND);
        state.heard(
            Heard::Silent("it did not answer within 5 seconds".to_owned()),
            115 * SECOND,
        );
        assert_eq!(
            state.notice(116 * SECOND),
            Notice::NotAnswering {
                since: 105 * SECOND,
                last_answered: Some(100 * SECOND),
                watched: true,
                reason: "it did not answer within 5 seconds".to_owned(),
            }
        );
        assert!(state.checked(116 * SECOND).status.is_none());
    }

    /// When the window was closed in between, or it never answered, when it
    /// stopped is not known, and the notice does not claim it is.
    #[test]
    fn when_it_stopped_is_not_claimed_unless_the_window_was_asking_all_along() {
        let mut closed_meanwhile = State::default();
        closed_meanwhile.heard(answered(), 100 * SECOND);
        closed_meanwhile.heard(silent(), 4 * 3600 * SECOND);
        let Notice::NotAnswering { watched, .. } = closed_meanwhile.notice(4 * 3600 * SECOND)
        else {
            panic!("not the notice for no answer");
        };
        assert!(!watched);

        let mut never = State::default();
        never.heard(silent(), 100 * SECOND);
        assert_eq!(
            never.notice(100 * SECOND),
            Notice::NotAnswering {
                since: 100 * SECOND,
                last_answered: None,
                watched: false,
                reason: "could not connect to the agent".to_owned(),
            }
        );
    }

    /// When it answers again that is said, with when, and then goes away by
    /// itself.
    #[test]
    fn answering_again_is_said_and_then_goes() {
        let mut state = State::default();
        state.heard(answered(), 100 * SECOND);
        state.heard(silent(), 105 * SECOND);
        state.heard(silent(), 110 * SECOND);
        state.heard(answered(), 140 * SECOND);
        assert_eq!(
            state.notice(141 * SECOND),
            Notice::AnsweringAgain {
                at: 140 * SECOND,
                from: 105 * SECOND,
            }
        );
        // Still said on a later answer within the time, from the first one.
        state.heard(answered(), 145 * SECOND);
        assert_eq!(
            state.notice(146 * SECOND),
            Notice::AnsweringAgain {
                at: 140 * SECOND,
                from: 105 * SECOND,
            }
        );
        assert_eq!(state.notice(156 * SECOND), Notice::Quiet);
    }

    /// A service from a different install is its own sentence, not "not
    /// answering", whether its version could be read or not.
    #[test]
    fn a_different_install_is_not_the_same_as_no_answer() {
        let mut older = State::default();
        older.heard(Heard::Answered(status(21)), 10 * SECOND);
        assert_eq!(
            older.notice(10 * SECOND),
            Notice::OtherVersion {
                since: 10 * SECOND,
                window: kam_ipc::PROTOCOL_VERSION,
                service: Some(21),
                unreadable: None,
            }
        );
        // What it said about itself is still shown under the notice.
        assert_eq!(
            older.checked(10 * SECOND).status.unwrap().protocol_version,
            21
        );

        let mut unreadable = State::default();
        unreadable.heard(
            Heard::Unreadable("could not deserialise frame".to_owned()),
            10 * SECOND,
        );
        assert!(matches!(
            unreadable.notice(10 * SECOND),
            Notice::OtherVersion { service: None, unreadable: Some(why), .. }
                if why.contains("could not deserialise")
        ));

        // Once both are the same version again, it is answering again.
        older.heard(answered(), 70 * SECOND);
        assert_eq!(
            older.notice(70 * SECOND),
            Notice::AnsweringAgain {
                at: 70 * SECOND,
                from: 10 * SECOND,
            }
        );
    }

    /// Being turned away is said in the service's own words, and the window
    /// then asks far less often, because each refusal is an Activity entry.
    #[test]
    fn being_turned_away_is_said_and_asked_about_less_often() {
        let mut state = State::default();
        state.heard(
            Heard::Refused("this program is not authorised to control the agent".to_owned()),
            10 * SECOND,
        );
        assert_eq!(
            state.notice(10 * SECOND),
            Notice::Refused {
                since: 10 * SECOND,
                message: "this program is not authorised to control the agent".to_owned(),
            }
        );
        assert_eq!(state.checked(10 * SECOND).next_in_ms, 60_000);
    }

    /// A change of trouble starts its own time, and answering again counts
    /// from the start of the whole spell.
    #[test]
    fn a_new_kind_of_trouble_has_its_own_time() {
        let mut state = State::default();
        state.heard(silent(), 10 * SECOND);
        state.heard(Heard::Refused("busy".to_owned()), 20 * SECOND);
        assert!(matches!(
            state.notice(20 * SECOND),
            Notice::Refused { since, .. } if since == 20 * SECOND
        ));
        state.heard(answered(), 30 * SECOND);
        assert_eq!(
            state.notice(30 * SECOND),
            Notice::AnsweringAgain {
                at: 30 * SECOND,
                from: 10 * SECOND,
            }
        );
    }

    /// A question that is not answered in time counts as no answer, and no
    /// second question is sent while it is still out. Its answer, when it
    /// comes, is what the window then knows.
    #[test]
    fn questions_do_not_pile_up_behind_one_that_was_not_answered() {
        let watch = Arc::new(Watch::default());
        let asked = Arc::new(AtomicUsize::new(0));
        let (release, held) = mpsc::channel::<()>();

        let counted = Arc::clone(&asked);
        let first = check(
            &watch,
            move || {
                counted.fetch_add(1, Ordering::SeqCst);
                // Hangs, as a service that took the question and never
                // replied would, until the test lets it go.
                let _ = held.recv();
                answered()
            },
            Duration::from_millis(50),
        );
        let Notice::NotAnswering { reason, .. } = first.notice else {
            panic!("an unanswered question was not counted as no answer");
        };
        assert!(reason.contains("did not answer within"), "{reason}");

        for _ in 0..3 {
            let counted = Arc::clone(&asked);
            let again = check(
                &watch,
                move || {
                    counted.fetch_add(1, Ordering::SeqCst);
                    answered()
                },
                Duration::from_millis(50),
            );
            assert!(matches!(again.notice, Notice::NotAnswering { .. }));
        }
        assert_eq!(
            asked.load(Ordering::SeqCst),
            1,
            "a question was sent while another was still out"
        );

        // The late answer arrives, and is what the next check says.
        release.send(()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while watch.state().asking {
            assert!(
                std::time::Instant::now() < deadline,
                "the answer never landed"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let after = check(&watch, answered, Duration::from_secs(5));
        assert!(matches!(after.notice, Notice::AnsweringAgain { .. }));
        assert!(after.status.is_some());
    }

    /// A question that breaks counts as no answer, and the next one is still
    /// asked.
    #[test]
    fn a_question_that_breaks_does_not_stop_the_next() {
        let watch = Arc::new(Watch::default());
        let broken = check(
            &watch,
            || panic!("a question that broke"),
            Duration::from_secs(5),
        );
        assert!(matches!(broken.notice, Notice::NotAnswering { .. }));
        let next = check(&watch, answered, Duration::from_secs(5));
        assert!(matches!(next.notice, Notice::AnsweringAgain { .. }));
    }
}
