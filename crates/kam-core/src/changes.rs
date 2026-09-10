//! What changed on this machine since last time.
//!
//! # The question nothing else answers
//!
//! Everything else in this product reports what is true *now*: what is
//! installed, what is connected, what starts itself. That is useful and it is
//! not the question people have. The question is "is anything different", and
//! Windows will not tell them — there is no place to look that says a scheduled
//! task appeared last Tuesday, or that an administrator account was added, or
//! that the backup task somebody relied on is no longer there.
//!
//! # Compared with itself, never with a standard
//!
//! There is no score here and there will not be one. A score needs a notion of
//! a correct machine, which this software does not have and must not invent —
//! inventing it is the entire business model of the products this replaces. A
//! machine's own history needs nothing invented: fourteen changes this week
//! against one in each of the last six is a fact, and the person reading it
//! supplies the meaning.
//!
//! # The three things this gets right that a naive diff gets wrong
//!
//! **Names, not events.** A sighting is identified by what it is, not by how
//! many times it has been noticed. Measured on the development machine: 270
//! service-install events, 62 distinct names, one anti-cheat responsible for 125
//! of the events because it reinstalls itself on every game launch. A diff over
//! events reports that anti-cheat 125 times and buries the two a week that
//! matter.
//!
//! **Absence is not evidence of absence.** If a source cannot be read this
//! sweep, nothing under it may be concluded to have vanished. Otherwise one
//! permissions blip reports the entire startup surface as removed, the person
//! learns the panel cries wolf, and the feature is over. Sources that could not
//! be read are named, and their contents are left exactly as they were.
//!
//! **Things that come and go.** Something that has appeared and vanished
//! repeatedly is marked as doing that, once, rather than reported every cycle —
//! but it is never silently dropped, because a rule that hides flapping is a
//! rule an attacker can use by flapping.

use serde::{Deserialize, Serialize};

/// One thing that starts itself, or holds a privilege, as seen in a sweep.
///
/// Identity is `(kind, scope, name)`. `detail` is everything else worth
/// comparing — a command line, a path — so that a thing which is still present
/// but now does something different can be told apart from one that has not
/// moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sighting {
    /// What sort of thing it is: a service, a scheduled task, a Run key entry.
    pub kind: String,
    /// Where it lives, which separates one account's entries from another's.
    pub scope: String,
    /// What it calls itself.
    pub name: String,
    /// What it does, compared so a change in place can be noticed.
    pub detail: String,
}

/// What happened to one thing between two sweeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    /// Never seen before.
    Appeared,
    /// Still there, but doing something different.
    Altered,
    /// Was there, and is not now.
    ///
    /// Deliberately reported as loudly as an appearance. The intuitive threat
    /// model is that new things are the danger, but a protective thing being
    /// removed — an antivirus service, a backup task, this software's own agent
    /// — is at least as strong a signal and Windows reports it nowhere.
    Vanished,
    /// Has come and gone several times, so it is noted rather than announced.
    Recurring,
}

impl Change {
    pub fn label(self) -> &'static str {
        match self {
            Self::Appeared => "appeared",
            Self::Altered => "changed",
            Self::Vanished => "is gone",
            Self::Recurring => "comes and goes",
        }
    }
}

/// One difference between this sweep and the machine's own history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Difference {
    pub change: Change,
    pub kind: String,
    pub scope: String,
    pub name: String,
    pub detail: String,
    /// When this thing was first ever seen, so an appearance carries its date.
    pub first_seen: String,
    /// When it was last seen present.
    pub last_seen: String,
    pub times_seen: i64,
}

/// What one sweep found, and what it could not look at.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Sweep {
    /// Differences, most interesting first.
    pub differences: Vec<Difference>,
    /// Sources that could not be read, in plain words.
    ///
    /// Never empty-by-omission: a source that was skipped is said out loud,
    /// because a silently skipped source is a lie by omission in a product
    /// whose whole claim is that it says what it did.
    pub unreadable: Vec<String>,
    /// True when this was the first sweep, so there was nothing to compare to.
    ///
    /// A first sweep reports no differences at all. Claiming findings against
    /// an empty baseline is the false-verdict pattern in miniature.
    pub baseline: bool,
    /// When the previous sweep ran, so the interface can name a real date
    /// rather than saying "since last week" about eleven days ago.
    pub previous_at: Option<String>,
    pub at: String,
}

/// Appearances and disappearances are worth more attention than either a change
/// in place or something that flaps.
pub fn rank(change: Change) -> u8 {
    match change {
        Change::Vanished => 3,
        Change::Appeared => 2,
        Change::Altered => 1,
        Change::Recurring => 0,
    }
}

/// How many times something must come and go before it is called recurring.
///
/// Three, so a thing that has genuinely been installed, removed and reinstalled
/// once is still reported both times. Anti-cheat services on this machine cycle
/// far past this within a day.
pub const FLAPS_BEFORE_RECURRING: i64 = 3;
