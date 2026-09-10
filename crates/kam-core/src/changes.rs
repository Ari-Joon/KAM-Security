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
    /// Who vouches for the file this runs, as a short stable phrase.
    ///
    /// Compared like everything else, and it closes a hole `detail` cannot: an
    /// entry that still points at exactly the same path, whose file has been
    /// replaced. The path has not moved, so nothing else here would notice —
    /// but a binary that was signed by somebody yesterday and is unsigned today
    /// is the plainest statement of "this is not the thing it was" that this
    /// software can make.
    ///
    /// Stored in its own column rather than folded into `detail`, so that
    /// changing how it is phrased does not make every entry on every machine
    /// read as altered at once.
    pub trust: String,
}

/// A source that could not be read, and what may not be concluded from that.
///
/// # Why this is not just a sentence
///
/// It was a sentence. The rule "nothing under an unreadable source may be
/// reported as vanished" was enforced by testing whether the sentence contained
/// the kind of thing the source holds, as a substring. The kinds are stored
/// tokens — `scheduled_task`, `run_key` — and the only such sentence the
/// product actually produced was "Scheduled tasks could not be read without
/// administrator rights", which does not contain `scheduled_task`. So the guard
/// never fired on a real machine, while its test passed against a hand-written
/// sentence chosen to match.
///
/// A safety rule whose wiring depends on the wording of the message it guards
/// is not a safety rule. The kinds are stated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unreadable {
    /// The kinds of thing this source holds, as the tokens sightings are
    /// stored under. Nothing of these kinds may be concluded to have vanished.
    ///
    /// Empty means the gap is worth telling a person about but rules nothing
    /// out.
    pub kinds: Vec<String>,
    /// Which entries of those kinds this covers, as lowercase scope prefixes.
    ///
    /// # Why a whole kind is the wrong unit
    ///
    /// Empty means every entry of those kinds, and that turns out to be a
    /// switch rather than a safeguard. One unreadable corner suppressed the
    /// whole category, so:
    ///
    /// - An attacker with administrator rights creates one junk service key
    ///   with a DACL denying SYSTEM. It never runs and does nothing. From then
    ///   on no service on the machine can ever be reported as having gone, and
    ///   they can remove the antivirus, the backup agent and this software's
    ///   own service in silence.
    /// - No administrator rights needed for the same trick on tasks: the task
    ///   store grants Authenticated Users write, so any process can create
    ///   folders nested past the walk's depth limit and switch off vanish
    ///   reporting for every scheduled task on the machine.
    /// - And without any attacker at all, an ordinary two-account family
    ///   machine has one profile not signed in on nearly every sweep, which
    ///   suppressed run keys, run-once keys and Startup items — three of the
    ///   five kinds — permanently, including the machine-wide ones that were
    ///   read perfectly well.
    ///
    /// Naming the place shrinks each of those to the one key or folder it is
    /// actually about. Matched as a prefix because a scope is a path and the
    /// thing that could not be read is usually the folder above.
    pub scopes: Vec<String>,
    /// What to tell the person, in their words rather than the machine's.
    pub what: String,
}

impl Unreadable {
    /// Everything of one kind, everywhere. Use only when that is the truth:
    /// the enumeration that would have listed them all is the thing that
    /// failed, so nothing is known about any of them.
    pub fn of(kind: &str, what: impl Into<String>) -> Self {
        Self {
            kinds: vec![kind.to_owned()],
            scopes: Vec::new(),
            what: what.into(),
        }
    }

    /// One place that could not be read, and only what lives under it.
    pub fn within(kind: &str, scope: &str, what: impl Into<String>) -> Self {
        Self {
            kinds: vec![kind.to_owned()],
            scopes: vec![scope.to_lowercase()],
            what: what.into(),
        }
    }

    /// Several kinds, confined to the places named.
    pub fn covering(kinds: &[&str], scopes: &[String], what: impl Into<String>) -> Self {
        Self {
            kinds: kinds.iter().map(|kind| (*kind).to_string()).collect(),
            scopes: scopes.iter().map(|scope| scope.to_lowercase()).collect(),
            what: what.into(),
        }
    }

    /// Whether this source says anything about one particular sighting.
    pub fn covers(&self, kind: &str, scope: &str) -> bool {
        self.kinds.iter().any(|held| held == kind)
            && (self.scopes.is_empty()
                || self
                    .scopes
                    .iter()
                    .any(|prefix| scope.starts_with(prefix.as_str())))
    }
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
    /// The name this is stored under. Stable across versions: these go into the
    /// database, so renaming one would make old history unreadable.
    pub fn stored(self) -> &'static str {
        match self {
            Self::Appeared => "appeared",
            Self::Altered => "altered",
            Self::Vanished => "vanished",
            Self::Recurring => "recurring",
        }
    }

    /// Read one back. Anything unrecognised is treated as an alteration rather
    /// than dropped, so a row written by a newer version is still counted.
    pub fn from_stored(text: &str) -> Self {
        match text {
            "appeared" => Self::Appeared,
            "vanished" => Self::Vanished,
            "recurring" => Self::Recurring,
            _ => Self::Altered,
        }
    }

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
    /// When this was noticed, which is not when it happened.
    ///
    /// The distinction is worth keeping honest about: this software sees a
    /// difference between two sweeps, so all it can say is that the change was
    /// there by now and was not there before. Presenting a sweep time as the
    /// moment something was installed would be inventing a precision nobody
    /// has.
    pub at: String,
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
    /// Who vouches for it now, and who did before when that has changed.
    pub trust: String,
    /// Set only when the trust changed, holding what it used to be.
    pub was_trusted: Option<String>,
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
    /// Every difference from the last twelve weeks, newest first.
    ///
    /// Not the same thing as `differences`, which is only this sweep. This is
    /// what lets the machine be charted against itself: a bar per week whose
    /// height is how much changed, answering "is this week like my other
    /// weeks". That question needs history, and a table that only remembers
    /// the present cannot answer it.
    pub history: Vec<Difference>,
    /// Things that were already here when the baseline was first taken, and
    /// that nothing vouches for.
    ///
    /// Only ever populated on the first sweep, and it exists because of an
    /// unavoidable weakness: a baseline learns whatever is on the machine at
    /// the moment it is taken. Something unwanted that was already there is
    /// recorded as ordinary and never reported as having appeared, because it
    /// did not appear — it was always there.
    ///
    /// Nothing can be done about that in general. What can be done is to say
    /// so: on the first run, everything already present that carries no valid
    /// signature is listed, not as a finding but as the honest caveat on the
    /// baseline. "These were here before this software was watching, and
    /// nobody vouches for them" is a true sentence, and a person can act on it
    /// where the software cannot.
    pub unvouched: Vec<Difference>,
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

/// Whether a trust phrase means somebody stands behind the file.
///
/// Only a valid signature counts. "Not signed" and "could not be read" are both
/// *not vouched for*, and they are deliberately treated the same here — but they
/// are not the same claim, and the phrase itself keeps them apart so the
/// interface can say which one it is. Something unreadable is a gap in what this
/// software could see; something unsigned is a fact about the file.
pub fn vouched_for(trust: &str) -> bool {
    trust.starts_with(SIGNED_BY)
}

/// Whether the question of who vouches for this was ever a sensible one.
///
/// An administrator account is not a file. No signature is missing from it and
/// none could be, so recording it as unexamined and then listing it under a
/// heading about nobody vouching for it is a category error — and one that
/// reads as an accusation against the person whose name is on the account.
///
/// Kept separate from [`NOT_CHECKED`] rather than folded into it, because that
/// phrase means something real about a file that could not be opened, and that
/// gap should still be said.
pub fn is_a_file(trust: &str) -> bool {
    trust != NOT_A_FILE
}

/// The prefix a valid signature is recorded under, with the signer after it.
///
/// A constant because it is stored: changing the wording would make every
/// signed thing on every machine read as newly untrusted, which is the loudest
/// possible false alarm.
pub const SIGNED_BY: &str = "signed by ";

/// What is recorded for a file carrying no signature at all.
pub const NOT_SIGNED: &str = "not signed";

/// What is recorded for something that is not a file, so nothing could sign it.
///
/// An account, a group membership: things whose identity is not a thing on
/// disk. Distinct from [`NOT_CHECKED`] because that phrase is about a file
/// that exists and could not be read, which is a gap worth reporting, while
/// this is a question that was never applicable.
pub const NOT_A_FILE: &str = "not a file";

/// What is recorded when the file could not be examined.
///
/// Distinct from [`NOT_SIGNED`] on purpose: one is a property of the file, the
/// other a limit of the observer, and reporting the second as the first would
/// be inventing a finding out of a permissions failure.
pub const NOT_CHECKED: &str = "could not be checked";

/// How many times something must come and go before it is called recurring.
///
/// Three, so a thing that has genuinely been installed, removed and reinstalled
/// once is still reported both times. Anti-cheat services on this machine cycle
/// far past this within a day.
pub const FLAPS_BEFORE_RECURRING: i64 = 3;
