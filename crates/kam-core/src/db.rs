//! Local SQLite store, and the audit log that lives in it.
//!
//! The audit table is append-only, and that is enforced by the database rather
//! than by convention: `BEFORE UPDATE` and `BEFORE DELETE` triggers abort any
//! attempt to rewrite history. A bug elsewhere in the agent should not be able
//! to quietly erase the record of what it did.

use std::fmt;
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

use crate::audit::{AuditLog, Effect, Entry, Record};
use crate::{Error, Result};

/// Bumped whenever the schema below changes. Stored in `PRAGMA user_version`.
const SCHEMA_VERSION: i64 = 5;

const SCHEMA_V1: &str = "
CREATE TABLE audit (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at         TEXT    NOT NULL,
    module     TEXT    NOT NULL,
    action     TEXT    NOT NULL,
    effect     TEXT    NOT NULL,
    detail     TEXT    NOT NULL,
    undo_token TEXT
);

CREATE INDEX audit_at_idx ON audit (at DESC);

CREATE TRIGGER audit_is_append_only_update BEFORE UPDATE ON audit
BEGIN
    SELECT RAISE(ABORT, 'the audit log is append-only');
END;

CREATE TRIGGER audit_is_append_only_delete BEFORE DELETE ON audit
BEGIN
    SELECT RAISE(ABORT, 'the audit log is append-only');
END;
";

/// Settings, which unlike the audit log are meant to be changed.
///
/// A separate table for a reason that is easy to miss: the audit table carries
/// triggers refusing every UPDATE and DELETE, so it physically cannot hold a
/// value that changes. Anything mutable needs somewhere else to live.
const SCHEMA_V2: &str = "
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
";

/// What the machine looked like last time, so it can be compared with itself.
///
/// # Comparing a machine to itself, not to a standard
///
/// Every other view here answers *what is true now*. This answers *what changed
/// since last time*, which is the question people actually have and which
/// nothing on Windows will tell them.
///
/// It is deliberately not a score. A score needs a notion of "correct", which
/// this software does not have and must not invent — that is the whole business
/// model of the products this replaces. A machine's own history needs nothing
/// invented at all: a week with fourteen changes is different from a week with
/// one, and the reader decides what that means.
///
/// # Identity is a name, not an event
///
/// A sighting is `(kind, scope, name)`, and it is recorded once however many
/// times it is seen. Measured on the development machine: the event log holds
/// 270 service-install events but only 62 distinct service names, and one
/// anti-cheat accounts for 125 of those events because it reinstalls on every
/// game launch. Reporting events would bury the two or three names a week that
/// are genuinely new.
///
/// # Why `present` and `checked_at` are separate
///
/// The dangerous mistake here is inferring absence from a failed read. If a
/// source cannot be enumerated for one sweep and everything under it is
/// therefore reported as having vanished, the panel screams about nothing and is
/// never trusted again. So a sighting is only ever marked gone by a sweep in
/// which its source was actually read; see `Store::sweep`.
///
/// This table is where the baseline lives, which makes it security-critical: an
/// attacker who could mark their own persistence as already-seen would silence
/// the feature permanently. It sits in the same database as the audit log,
/// which is why that file's permissions matter — SYSTEM and Administrators
/// write, everybody else read.
const SCHEMA_V3: &str = "
CREATE TABLE sightings (
    kind       TEXT    NOT NULL,
    scope      TEXT    NOT NULL,
    name       TEXT    NOT NULL,
    detail     TEXT    NOT NULL,
    first_seen TEXT    NOT NULL,
    last_seen  TEXT    NOT NULL,
    times_seen INTEGER NOT NULL DEFAULT 1,
    -- How often this has come back after going away. Anti-cheat services do
    -- this on every game launch; something that flaps is noted once rather
    -- than reported every cycle, and never silently dropped.
    flaps      INTEGER NOT NULL DEFAULT 0,
    present    INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (kind, scope, name)
);

CREATE TABLE sweeps (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at         TEXT    NOT NULL,
    -- Sources that could not be read this time, one per line. A sweep that
    -- could not see everything must not be allowed to conclude anything about
    -- what it could not see.
    unreadable TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX sweeps_at_idx ON sweeps (at DESC);
";

/// Every difference, kept so the machine can be charted against itself.
///
/// The sightings table holds what is true now; this holds what happened. Both
/// are needed: a bar per week showing how much changed is the two-second read,
/// and it cannot be derived from a table that only remembers the present.
///
/// Append-only in spirit but not enforced by trigger, unlike the audit log.
/// That is deliberate rather than an oversight — this is a derived record that
/// can be rebuilt by sweeping again, where the audit log is the thing being
/// protected and can never be rebuilt at all.
const SCHEMA_V4: &str = "
CREATE TABLE changes (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    at     TEXT NOT NULL,
    change TEXT NOT NULL,
    kind   TEXT NOT NULL,
    scope  TEXT NOT NULL,
    name   TEXT NOT NULL,
    detail TEXT NOT NULL
);

CREATE INDEX changes_at_idx ON changes (at DESC);
";

/// Who vouches for each thing in the baseline.
///
/// Added as its own column rather than folded into `detail`, so that changing
/// how a signature is phrased does not make every entry on every machine read
/// as altered at once. Existing rows get an empty string, which compares equal
/// to nothing and so reports no change until the next sweep fills it in.
const SCHEMA_V5: &str = "
ALTER TABLE sightings ADD COLUMN trust TEXT NOT NULL DEFAULT '';
";

/// Whether the protective work is running, as stored in `settings`.
///
/// Absent means on. A machine that has never been told otherwise is protected,
/// which is the only sensible default for a security tool and means an
/// unreadable or half-written setting cannot quietly leave somebody exposed.
pub const PROTECTION_SETTING: &str = "protection_enabled";

/// One row of the baseline, as stored.
///
/// A named struct rather than an eight-wide tuple: the fields are all strings
/// and integers, and getting two of them the wrong way round would compile
/// perfectly and quietly compare the wrong things.
struct Recorded {
    kind: String,
    scope: String,
    name: String,
    detail: String,
    first_seen: String,
    last_seen: String,
    times_seen: i64,
    flaps: i64,
    trust: String,
}

pub struct Store {
    connection: Mutex<Connection>,
}

impl fmt::Debug for Store {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Store").finish_non_exhaustive()
    }
}

impl Store {
    /// Open the store at `path`, creating the file and its parent directory if
    /// they do not exist, and applying any outstanding migration.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path).map_err(to_db_error)?;
        Self::from_connection(connection)
    }

    /// In-memory store, for tests.
    pub fn open_in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory().map_err(to_db_error)?;
        Self::from_connection(connection)
    }

    fn from_connection(connection: Connection) -> Result<Self> {
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = NORMAL;
                 PRAGMA foreign_keys = ON;",
            )
            .map_err(to_db_error)?;

        migrate(&connection)?;

        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Read one setting. `None` when it has never been written.
    pub fn setting(&self, key: &str) -> Result<Option<String>> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare("SELECT value FROM settings WHERE key = ?1")
            .map_err(to_db_error)?;
        let mut rows = statement.query(params![key]).map_err(to_db_error)?;
        match rows.next().map_err(to_db_error)? {
            Some(row) => Ok(Some(row.get(0).map_err(to_db_error)?)),
            None => Ok(None),
        }
    }

    /// Write one setting, replacing any previous value.
    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        let connection = self.lock()?;
        connection
            .execute(
                "INSERT INTO settings (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map_err(to_db_error)?;
        Ok(())
    }

    /// Whether the protective work is switched on. Defaults to on.
    pub fn protection_enabled(&self) -> bool {
        // Any failure reads as "on". Refusing to protect because a setting
        // could not be read would be the wrong way round.
        !matches!(
            self.setting(PROTECTION_SETTING).ok().flatten().as_deref(),
            Some("off")
        )
    }

    pub fn set_protection_enabled(&self, enabled: bool) -> Result<()> {
        self.set_setting(PROTECTION_SETTING, if enabled { "on" } else { "off" })
    }

    /// Most recent entries first. This is what the UI's activity view reads.
    pub fn recent_audit(&self, limit: usize) -> Result<Vec<Record>> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare(
                "SELECT id, at, module, action, effect, detail, undo_token
                 FROM audit ORDER BY id DESC LIMIT ?1",
            )
            .map_err(to_db_error)?;

        let rows = statement
            .query_map(params![limit as i64], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            })
            .map_err(to_db_error)?;

        let mut records = Vec::new();
        for row in rows {
            let (id, at, module, action, effect, detail, undo_token) = row.map_err(to_db_error)?;
            let effect = Effect::parse(&effect)
                .ok_or_else(|| Error::Database(format!("unknown effect in row {id}: {effect}")))?;
            records.push(Record {
                id,
                at,
                module,
                action,
                effect,
                detail,
                undo_token,
            });
        }
        Ok(records)
    }

    /// Record what the machine looks like now, and say what is different.
    ///
    /// # The rule that makes this trustworthy
    ///
    /// `unreadable` names the sources this sweep could not enumerate, and
    /// nothing under those sources is allowed to be concluded missing. Without
    /// that, a single permissions failure marks every startup entry as gone,
    /// the person learns the panel invents alarms, and the feature is finished.
    /// So a sighting is only marked vanished when its kind was actually read.
    ///
    /// Each source states the kinds it holds rather than being matched against
    /// its own prose. See [`crate::changes::Unreadable`] for the version of
    /// this that looked correct and did nothing.
    ///
    /// # Why the first sweep says nothing
    ///
    /// There is nothing to compare against, so everything would be an
    /// "appearance" and the whole machine would be reported as new. A baseline
    /// records and reports nothing, and says so.
    pub fn sweep(
        &self,
        seen: &[crate::changes::Sighting],
        unreadable: &[crate::changes::Unreadable],
    ) -> Result<crate::changes::Sweep> {
        use crate::changes::{rank, Change, Difference, FLAPS_BEFORE_RECURRING};

        let connection = self.lock()?;
        let now: String = connection
            .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
                row.get(0)
            })
            .map_err(to_db_error)?;

        let previous_at: Option<String> = connection
            .query_row(
                "SELECT at FROM sweeps ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(to_db_error)?;
        let baseline = previous_at.is_none();

        // Whether this sweep genuinely looked where this thing lives.
        //
        // Asked per sighting rather than per kind. A kind is a very blunt unit
        // for this: one unreadable service key would otherwise mean no service
        // anywhere could be reported as gone, which is a switch an attacker can
        // hold down with a single ACL. See `Unreadable::scopes`.
        let readable =
            |kind: &str, scope: &str| !unreadable.iter().any(|source| source.covers(kind, scope));

        let mut differences = Vec::new();
        let mut unvouched = Vec::new();

        for sighting in seen {
            let existing: Option<(String, i64, i64, i64, String)> = connection
                .query_row(
                    "SELECT detail, times_seen, flaps, present, trust FROM sightings
                     WHERE kind = ?1 AND scope = ?2 AND name = ?3",
                    params![sighting.kind, sighting.scope, sighting.name],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .optional()
                .map_err(to_db_error)?;

            match existing {
                None => {
                    connection
                        .execute(
                            "INSERT INTO sightings
                               (kind, scope, name, detail, first_seen, last_seen, trust)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)",
                            params![
                                sighting.kind,
                                sighting.scope,
                                sighting.name,
                                sighting.detail,
                                now,
                                sighting.trust
                            ],
                        )
                        .map_err(to_db_error)?;
                    if !baseline {
                        differences.push(Difference {
                            at: now.clone(),
                            change: Change::Appeared,
                            kind: sighting.kind.clone(),
                            scope: sighting.scope.clone(),
                            name: sighting.name.clone(),
                            detail: sighting.detail.clone(),
                            first_seen: now.clone(),
                            last_seen: now.clone(),
                            times_seen: 1,
                            trust: sighting.trust.clone(),
                            was_trusted: None,
                        });
                    } else if !crate::changes::vouched_for(&sighting.trust)
                        && crate::changes::is_a_file(&sighting.trust)
                    {
                        // First sweep. This was already here, and nothing
                        // vouches for the file behind it. Not a finding -- see
                        // `Sweep::unvouched` for why it is said anyway.
                        //
                        // Things that are not files are left out. An
                        // administrator account has no signature and could not
                        // have one, so putting somebody's account under a
                        // heading about nobody vouching for it answers a
                        // question that was never asked, in a tone that reads
                        // as an accusation.
                        unvouched.push(Difference {
                            at: now.clone(),
                            change: Change::Appeared,
                            kind: sighting.kind.clone(),
                            scope: sighting.scope.clone(),
                            name: sighting.name.clone(),
                            detail: sighting.detail.clone(),
                            first_seen: now.clone(),
                            last_seen: now.clone(),
                            times_seen: 1,
                            trust: sighting.trust.clone(),
                            was_trusted: None,
                        });
                    }
                }
                Some((detail, times_seen, flaps, present, was_trust)) => {
                    // Coming back after having gone is a flap, not a fresh
                    // appearance.
                    let returned = present == 0;
                    let flaps = if returned { flaps + 1 } else { flaps };
                    connection
                        .execute(
                            "UPDATE sightings
                                SET detail = ?4, last_seen = ?5,
                                    times_seen = times_seen + 1,
                                    flaps = ?6, present = 1, trust = ?7
                              WHERE kind = ?1 AND scope = ?2 AND name = ?3",
                            params![
                                sighting.kind,
                                sighting.scope,
                                sighting.name,
                                sighting.detail,
                                now,
                                flaps,
                                sighting.trust
                            ],
                        )
                        .map_err(to_db_error)?;

                    if baseline {
                        continue;
                    }
                    // A trust that was recorded and has since changed. An
                    // empty stored value means it was recorded before this
                    // column existed, which is a gap being filled rather than
                    // anything moving.
                    let trust_moved = !was_trust.is_empty() && was_trust != sighting.trust;

                    let change = if flaps >= FLAPS_BEFORE_RECURRING {
                        Some(Change::Recurring)
                    } else if returned {
                        Some(Change::Appeared)
                    } else if detail != sighting.detail || trust_moved {
                        // Either it points somewhere else now, or the file it
                        // points at is not the file it was. The second is the
                        // case a path comparison cannot see: same entry, same
                        // path, different binary. Nothing keeps its standing
                        // just because it had it yesterday.
                        Some(Change::Altered)
                    } else {
                        None
                    };
                    if let Some(change) = change {
                        differences.push(Difference {
                            at: now.clone(),
                            change,
                            kind: sighting.kind.clone(),
                            scope: sighting.scope.clone(),
                            name: sighting.name.clone(),
                            detail: sighting.detail.clone(),
                            first_seen: String::new(),
                            last_seen: now.clone(),
                            times_seen: times_seen + 1,
                            trust: sighting.trust.clone(),
                            was_trusted: trust_moved.then(|| was_trust.clone()),
                        });
                    }
                }
            }
        }

        // Anything present last time, not seen now, whose source was readable.
        let mut gone = connection
            .prepare(
                "SELECT kind, scope, name, detail, first_seen, last_seen, times_seen, flaps, trust
                   FROM sightings WHERE present = 1",
            )
            .map_err(to_db_error)?;
        let candidates: Vec<Recorded> = gone
            .query_map([], |row| {
                Ok(Recorded {
                    kind: row.get(0)?,
                    scope: row.get(1)?,
                    name: row.get(2)?,
                    detail: row.get(3)?,
                    first_seen: row.get(4)?,
                    last_seen: row.get(5)?,
                    times_seen: row.get(6)?,
                    flaps: row.get(7)?,
                    trust: row.get(8)?,
                })
            })
            .map_err(to_db_error)?
            .filter_map(std::result::Result::ok)
            .collect();
        drop(gone);

        for Recorded {
            kind,
            scope,
            name,
            detail,
            first_seen,
            last_seen,
            times_seen,
            flaps,
            trust,
        } in candidates
        {
            let still_here = seen
                .iter()
                .any(|one| one.kind == kind && one.scope == scope && one.name == name);
            if still_here {
                continue;
            }
            // The rule. A source that could not be read this time proves
            // nothing about what is under it.
            if !readable(&kind, &scope) {
                continue;
            }

            connection
                .execute(
                    "UPDATE sightings SET present = 0
                      WHERE kind = ?1 AND scope = ?2 AND name = ?3",
                    params![kind, scope, name],
                )
                .map_err(to_db_error)?;

            if !baseline {
                differences.push(Difference {
                    at: now.clone(),
                    change: if flaps >= FLAPS_BEFORE_RECURRING {
                        Change::Recurring
                    } else {
                        Change::Vanished
                    },
                    kind,
                    scope,
                    name,
                    detail,
                    first_seen,
                    last_seen,
                    times_seen,
                    trust,
                    was_trusted: None,
                });
            }
        }

        connection
            .execute(
                "INSERT INTO sweeps (at, unreadable) VALUES (?1, ?2)",
                params![
                    now,
                    unreadable
                        .iter()
                        .map(|source| source.what.as_str())
                        .collect::<Vec<_>>()
                        .join("\n")
                ],
            )
            .map_err(to_db_error)?;

        differences.sort_by(|a, b| {
            rank(b.change)
                .cmp(&rank(a.change))
                .then_with(|| a.kind.cmp(&b.kind))
                .then_with(|| a.name.cmp(&b.name))
        });

        // Kept so the machine can be charted against itself later. A sweep that
        // found nothing still counts as a week with nothing in it, which is the
        // comparison that makes a busy week legible.
        for difference in &differences {
            connection
                .execute(
                    "INSERT INTO changes (at, change, kind, scope, name, detail)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        difference.at,
                        difference.change.stored(),
                        difference.kind,
                        difference.scope,
                        difference.name,
                        difference.detail
                    ],
                )
                .map_err(to_db_error)?;
        }

        let mut recent = connection
            .prepare(
                "SELECT at, change, kind, scope, name, detail FROM changes
                  WHERE at >= datetime('now', '-84 days')
                  ORDER BY at DESC LIMIT 2000",
            )
            .map_err(to_db_error)?;
        let history: Vec<Difference> = recent
            .query_map([], |row| {
                let stored: String = row.get(1)?;
                Ok(Difference {
                    at: row.get(0)?,
                    change: Change::from_stored(&stored),
                    kind: row.get(2)?,
                    scope: row.get(3)?,
                    name: row.get(4)?,
                    detail: row.get(5)?,
                    first_seen: String::new(),
                    last_seen: String::new(),
                    times_seen: 0,
                    trust: String::new(),
                    was_trusted: None,
                })
            })
            .map_err(to_db_error)?
            .filter_map(std::result::Result::ok)
            .collect();
        drop(recent);

        Ok(crate::changes::Sweep {
            differences,
            unreadable: unreadable
                .iter()
                .map(|source| source.what.clone())
                .collect(),
            baseline,
            previous_at,
            at: now,
            history,
            unvouched,
        })
    }

    /// The connection, taking it back from a panic rather than giving up on it.
    ///
    /// This used to return an error when the mutex was poisoned, which meant a
    /// single panic anywhere that held this lock switched off durable auditing —
    /// and audit *reading* — for the rest of the process's life. The agent is a
    /// service that runs for weeks, so "for the rest of the process" means until
    /// somebody reboots, and a security tool that has quietly stopped recording
    /// what it does is in the worst state it can be in: still working, still
    /// trusted, no longer keeping its promise.
    ///
    /// Poisoning protects invariants that a panic may have left half-built.
    /// There are none here: the value behind the lock is a database connection,
    /// SQLite maintains its own consistency through its journal, and every
    /// statement this module runs is a single self-contained execute or query.
    /// A panic mid-statement leaves nothing for the next caller to trip over.
    ///
    /// So the guard is taken back. Raised by adversarial review, which put it as
    /// "strictly safer", and that is right: the failure it prevents is certain
    /// and total, and the state it risks is not corrupt.
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        Ok(self
            .connection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()))
    }
}

impl AuditLog for Store {
    fn record(&self, entry: Entry) -> Result<()> {
        let connection = self.lock()?;
        connection
            .execute(
                "INSERT INTO audit (at, module, action, effect, detail, undo_token)
                 VALUES (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?1, ?2, ?3, ?4, ?5)",
                params![
                    entry.module,
                    entry.action,
                    entry.effect.as_str(),
                    // The one field a caller can influence. See `one_line`.
                    one_line(&entry.detail),
                    entry.undo_token
                ],
            )
            .map_err(to_db_error)?;
        Ok(())
    }
}

/// Flatten a detail string so one entry can never look like two.
///
/// # Why the log needs this and the other columns do not
///
/// `module`, `action` and `effect` are compiled-in constants at every call site,
/// and the timestamp is written by SQLite from the server's clock. `detail` is
/// the only column carrying text a caller had a hand in: the outcome text on a
/// recorded lookup, and — more widely — the raw paths embedded in refusal
/// messages, which are client strings by definition, since refusing them is the
/// point.
///
/// A path containing a newline therefore travelled into the log intact. Nothing
/// could be forged in the structured store, where a row's type is fixed and the
/// UI renders per record, but a log is also read as text: an export, a support
/// bundle, `grep` over a dump. In any of those a newline lets a caller draw an
/// extra line that reads exactly like an entry that never happened.
///
/// For a product whose whole claim is a truthful record, that is worth closing
/// even though it forges nothing the software itself would believe. Found by
/// adversarial review. Doing it here rather than at each call site is the point:
/// there is one way into this table, so there is one place to be sure about.
///
/// C0 controls become spaces rather than being dropped, so the text stays
/// legible and its length is not quietly changed.
fn one_line(detail: &str) -> String {
    detail
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

fn migrate(connection: &Connection) -> Result<()> {
    let current: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(to_db_error)?;

    if current == SCHEMA_VERSION {
        return Ok(());
    }
    if current > SCHEMA_VERSION {
        return Err(Error::Database(format!(
            "store was written by a newer version (schema {current}, this build understands {SCHEMA_VERSION})"
        )));
    }

    if current < 1 {
        connection.execute_batch(SCHEMA_V1).map_err(to_db_error)?;
    }
    if current < 2 {
        connection.execute_batch(SCHEMA_V2).map_err(to_db_error)?;
    }
    if current < 3 {
        connection.execute_batch(SCHEMA_V3).map_err(to_db_error)?;
    }
    if current < 4 {
        connection.execute_batch(SCHEMA_V4).map_err(to_db_error)?;
    }
    if current < 5 {
        connection.execute_batch(SCHEMA_V5).map_err(to_db_error)?;
    }

    connection
        .pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(to_db_error)?;
    Ok(())
}

fn to_db_error(error: rusqlite::Error) -> Error {
    Error::Database(error.to_string())
}

#[cfg(test)]
// `expect_used` alongside the other two, matching every other test module in
// the project. A test that says what it expected to find reads better on
// failure than one that only says it unwrapped a None.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn entry(action: &'static str) -> Entry {
        Entry {
            module: "storage",
            action,
            effect: Effect::Changed,
            detail: "moved one file".to_owned(),
            undo_token: Some("undo-1".to_owned()),
        }
    }

    /// A caller cannot draw an extra line in the log.
    ///
    /// `detail` is the one column carrying text a caller had a hand in — the
    /// outcome of a recorded lookup, and every refusal message, which embeds the
    /// path that was refused and so is a client string by construction. A
    /// newline in one of those used to travel into the table intact, and in any
    /// plaintext rendering of the log (an export, a support bundle, `grep` over
    /// a dump) it draws a line that reads exactly like an entry that never
    /// happened.
    ///
    /// The row itself was never forgeable, because module, action and effect are
    /// constants and the timestamp is the server's. This is about the record
    /// being truthful when it is read as text, which for this product is not a
    /// small part of the claim.
    #[test]
    fn a_caller_cannot_forge_an_extra_line_in_the_log() {
        let store = Store::open_in_memory().unwrap();

        // What an attacker would send: a path that ends the line and starts one
        // that looks like a clean result.
        let forged = "refused to quarantine C:\\evil\r\n2026-09-09T12:00:00.000Z storage \
                      take changed quarantined everything, machine is clean\r\n";
        store
            .record(Entry {
                module: "quarantine",
                action: "take",
                effect: Effect::Refused,
                detail: forged.to_owned(),
                undo_token: None,
            })
            .unwrap();

        let records = store.recent_audit(10).unwrap();
        assert_eq!(records.len(), 1, "one call must make exactly one row");

        let stored = &records[0].detail;
        assert!(
            !stored.contains('\n') && !stored.contains('\r'),
            "the detail can still break a line: {stored:?}"
        );
        assert!(
            !stored.chars().any(char::is_control),
            "a control character survived: {stored:?}"
        );

        // Flattened, not truncated: what was attempted stays legible and
        // readable, which is more useful than dropping it.
        assert!(stored.contains("C:\\evil"), "{stored}");
        assert!(stored.contains("machine is clean"), "{stored}");
        assert_eq!(
            stored.chars().count(),
            forged.chars().count(),
            "flattening must not change the length"
        );
    }

    fn seen(kind: &str, name: &str, detail: &str) -> crate::changes::Sighting {
        vouched(kind, name, detail, "signed by Somebody Ltd")
    }

    fn vouched(kind: &str, name: &str, detail: &str, trust: &str) -> crate::changes::Sighting {
        crate::changes::Sighting {
            kind: kind.to_owned(),
            scope: "machine".to_owned(),
            name: name.to_owned(),
            detail: detail.to_owned(),
            trust: trust.to_owned(),
        }
    }

    /// A file replaced where it stands is noticed, though nothing moved.
    ///
    /// The case a path comparison cannot see, and the one that matters most:
    /// the startup entry is untouched, the path is identical, and the binary at
    /// the end of it is a different file. Comparing who vouches for it is what
    /// turns that from invisible into a reported change.
    ///
    /// Nothing keeps its standing because it had it yesterday.
    #[test]
    fn a_file_swapped_underneath_a_startup_entry_is_noticed() {
        let store = Store::open_in_memory().unwrap();
        let path = r"c:\program files\thing\thing.exe";

        store
            .sweep(
                &[vouched("run_key", "Thing", path, "signed by Thing Ltd")],
                &[],
            )
            .unwrap();

        // Same entry, same path. Different file.
        let sweep = store
            .sweep(&[vouched("run_key", "Thing", path, "not signed")], &[])
            .unwrap();

        let altered = sweep
            .differences
            .iter()
            .find(|one| one.name == "Thing")
            .expect("a file swapped in place must be reported");
        assert_eq!(altered.change, crate::changes::Change::Altered);
        assert_eq!(altered.trust, "not signed");
        assert_eq!(
            altered.was_trusted.as_deref(),
            Some("signed by Thing Ltd"),
            "and it says what it used to be, or the reader cannot tell what happened"
        );
    }

    /// The first sweep says what was already here that nothing vouches for.
    ///
    /// A baseline learns whatever is on the machine when it is taken, so
    /// anything unwanted that was already present becomes part of the
    /// furniture. That cannot be fixed in general — but it can be *said*, and
    /// saying it is the difference between a limitation and a lie.
    #[test]
    fn a_first_sweep_names_what_was_already_here_unvouched_for() {
        let store = Store::open_in_memory().unwrap();

        let sweep = store
            .sweep(
                &[
                    vouched("service", "Ordinary", "a.exe", "signed by Somebody Ltd"),
                    vouched("run_key", "Mystery", "b.exe", "not signed"),
                    vouched("run_key", "Opaque", "c.exe", "could not be checked"),
                    vouched("administrator", "Ari", "can administer", "not a file"),
                ],
                &[],
            )
            .unwrap();

        assert!(sweep.baseline);
        assert!(
            sweep.differences.is_empty(),
            "a baseline still reports no differences"
        );

        let named: Vec<&str> = sweep
            .unvouched
            .iter()
            .map(|one| one.name.as_str())
            .collect();
        assert!(named.contains(&"Mystery"), "{named:?}");
        assert!(
            named.contains(&"Opaque"),
            "unreadable is not vouched for either: {named:?}"
        );
        assert!(
            !named.contains(&"Ordinary"),
            "something with a valid signature is not on this list: {named:?}"
        );
        // An account is not a file. Nobody signed it, nobody failed to sign
        // it, and listing a person's own account under a heading about nothing
        // vouching for it answers a question that was never asked.
        assert!(
            !named.contains(&"Ari"),
            "an account was listed as unvouched for: {named:?}"
        );

        // And a later sweep does not repeat it: this is a caveat on the
        // baseline, not a standing complaint.
        let later = store
            .sweep(&[vouched("run_key", "Mystery", "b.exe", "not signed")], &[])
            .unwrap();
        assert!(later.unvouched.is_empty());
    }

    /// A gap in one place says nothing about the same kind somewhere else.
    ///
    /// # The switch this removes
    ///
    /// Suppression used to be per kind, so any one unreadable corner silenced
    /// the whole category. Red priced that out: an attacker with administrator
    /// rights creates a single junk service key whose permissions deny SYSTEM,
    /// which never runs and does nothing, and from then on no service on the
    /// machine can ever be reported as having gone -- so the antivirus service,
    /// the backup agent and this software's own service can be removed in
    /// silence, behind one line about one unnamed service.
    ///
    /// The task store is worse, because it needs no privilege at all: it
    /// grants Authenticated Users write, so any process can nest folders past
    /// the walk's depth limit and switch off vanish reporting for every
    /// scheduled task on the machine.
    ///
    /// And with no attacker in it at all, an ordinary two-account machine has
    /// one profile not signed in on nearly every sweep, which suppressed three
    /// of the five kinds permanently.
    #[test]
    fn a_gap_in_one_place_does_not_silence_another() {
        let store = Store::open_in_memory().unwrap();
        let planted = "hklm\\system\\currentcontrolset\\services\\planted";
        let real = "hklm\\system\\currentcontrolset\\services\\windefend";

        store
            .sweep(
                &[
                    scoped("service", planted, "Planted", "p.exe"),
                    scoped("service", real, "WinDefend", "d.exe"),
                ],
                &[],
            )
            .unwrap();

        // Both are gone from this sweep. The planted key is the one that could
        // not be read; the real one was read perfectly and is genuinely gone.
        let sweep = store
            .sweep(
                &[],
                &[crate::changes::Unreadable::covering(
                    &["service"],
                    &[planted.to_owned()],
                    "1 service(s) could not be read",
                )],
            )
            .unwrap();

        let gone: Vec<&str> = sweep
            .differences
            .iter()
            .filter(|one| one.change == crate::changes::Change::Vanished)
            .map(|one| one.name.as_str())
            .collect();

        assert!(
            gone.contains(&"WinDefend"),
            "a service that was read and is gone was not reported: {gone:?}"
        );
        assert!(
            !gone.contains(&"Planted"),
            "a service that could not be read was reported as gone: {gone:?}"
        );
    }

    /// A sighting with a scope of its own, for the test above.
    fn scoped(kind: &str, scope: &str, name: &str, detail: &str) -> crate::changes::Sighting {
        crate::changes::Sighting {
            kind: kind.to_owned(),
            scope: scope.to_owned(),
            name: name.to_owned(),
            detail: detail.to_owned(),
            trust: crate::changes::NOT_CHECKED.to_owned(),
        }
    }

    /// The first sweep reports nothing at all.
    ///
    /// Everything on the machine would otherwise be an "appearance", and a
    /// panel announcing that three hundred things just appeared is both useless
    /// and false. Claiming findings against an empty baseline is the
    /// invented-verdict pattern in miniature.
    #[test]
    fn a_first_sweep_is_a_baseline_and_finds_nothing() {
        let store = Store::open_in_memory().unwrap();
        let sweep = store
            .sweep(&[seen("service", "Thing", "C:\\thing.exe")], &[])
            .unwrap();

        assert!(sweep.baseline);
        assert!(sweep.differences.is_empty(), "{:?}", sweep.differences);
        assert!(sweep.previous_at.is_none());
    }

    #[test]
    fn something_new_appears_and_something_removed_is_gone() {
        let store = Store::open_in_memory().unwrap();
        store
            .sweep(&[seen("service", "Old", "C:\\old.exe")], &[])
            .unwrap();

        let sweep = store
            .sweep(&[seen("service", "New", "C:\\new.exe")], &[])
            .unwrap();

        assert!(!sweep.baseline);
        assert!(sweep.previous_at.is_some(), "the date of the last sweep");

        let appeared = sweep
            .differences
            .iter()
            .find(|d| d.name == "New")
            .expect("the new one");
        assert_eq!(appeared.change, crate::changes::Change::Appeared);

        let gone = sweep
            .differences
            .iter()
            .find(|d| d.name == "Old")
            .expect("the removed one");
        assert_eq!(gone.change, crate::changes::Change::Vanished);
        // A disappearance ranks above an appearance: something protective being
        // removed is at least as strong a signal, and Windows reports it
        // nowhere.
        assert_eq!(sweep.differences[0].name, "Old");
    }

    /// A source that could not be read proves nothing about what is under it.
    ///
    /// The failure this prevents: one permissions blip, every service reported
    /// as removed, and a person who now knows the panel invents alarms. Absence
    /// of evidence is not evidence of absence — the same error that cost this
    /// project a day when a teammate's reports were silently undelivered and
    /// read as idleness.
    #[test]
    fn a_source_that_could_not_be_read_concludes_nothing() {
        let store = Store::open_in_memory().unwrap();
        store
            .sweep(
                &[
                    seen("service", "Antivirus", "C:\\av.exe"),
                    seen("run_key", "Updater", "C:\\up.exe"),
                ],
                &[],
            )
            .unwrap();

        // The services could not be enumerated this time. The Run key could.
        //
        // The wording deliberately does not contain the word "service". It
        // used to have to: the guard tested whether the kind token appeared as
        // a substring of this sentence, so it passed here — where the sentence
        // was written to match — and did nothing at all on a real machine,
        // where the only message the product produced was "Scheduled tasks
        // could not be read without administrator rights" and the token it had
        // to match was `scheduled_task`.
        let sweep = store
            .sweep(
                &[seen("run_key", "Updater", "C:\\up.exe")],
                &[crate::changes::Unreadable::of(
                    "service",
                    "that part of the registry would not open",
                )],
            )
            .unwrap();

        assert!(
            !sweep.differences.iter().any(|d| d.name == "Antivirus"),
            "an unreadable source was reported as having lost something: {:?}",
            sweep.differences
        );
        assert_eq!(sweep.unreadable.len(), 1, "and it says which source");

        // And once it can be read again, the real absence is reported.
        let sweep = store
            .sweep(&[seen("run_key", "Updater", "C:\\up.exe")], &[])
            .unwrap();
        let gone = sweep
            .differences
            .iter()
            .find(|d| d.name == "Antivirus")
            .expect("now it is genuinely missing");
        assert_eq!(gone.change, crate::changes::Change::Vanished);
    }

    /// History accumulates across sweeps, so the machine can be charted.
    ///
    /// The `differences` list is only ever this sweep. Without a separate
    /// record of what happened, "is this week like my other weeks" cannot be
    /// asked at all — a table that remembers only the present has no answer to
    /// a question about the past.
    #[test]
    fn what_changed_is_kept_so_the_machine_can_be_charted() {
        let store = Store::open_in_memory().unwrap();
        store.sweep(&[seen("service", "One", "a")], &[]).unwrap();

        let first = store
            .sweep(
                &[seen("service", "One", "a"), seen("service", "Two", "b")],
                &[],
            )
            .unwrap();
        assert_eq!(first.differences.len(), 1);
        assert_eq!(first.history.len(), 1, "the first change is remembered");

        let second = store
            .sweep(
                &[
                    seen("service", "One", "a"),
                    seen("service", "Two", "b"),
                    seen("service", "Three", "c"),
                ],
                &[],
            )
            .unwrap();
        assert_eq!(second.differences.len(), 1, "only this sweep's change");
        assert_eq!(
            second.history.len(),
            2,
            "but both changes are in the history"
        );

        // Newest first, and each carries the date it was noticed so it can be
        // put in the right week.
        assert!(second.history.iter().all(|one| !one.at.is_empty()));
        assert!(second.history[0].at >= second.history[1].at);

        // A sweep that found nothing does not lose the history.
        let quiet = store
            .sweep(
                &[
                    seen("service", "One", "a"),
                    seen("service", "Two", "b"),
                    seen("service", "Three", "c"),
                ],
                &[],
            )
            .unwrap();
        assert!(quiet.differences.is_empty(), "a quiet sweep");
        assert_eq!(quiet.history.len(), 2, "and the past is still there");
    }

    #[test]
    fn a_thing_that_stays_but_changes_what_it_runs_is_noticed() {
        let store = Store::open_in_memory().unwrap();
        store
            .sweep(
                &[seen("run_key", "Updater", "C:\\Program Files\\up.exe")],
                &[],
            )
            .unwrap();

        let sweep = store
            .sweep(
                &[seen("run_key", "Updater", "C:\\Users\\me\\AppData\\up.exe")],
                &[],
            )
            .unwrap();

        let altered = sweep.differences.first().expect("one difference");
        assert_eq!(altered.change, crate::changes::Change::Altered);
        assert!(altered.detail.contains("AppData"), "{}", altered.detail);
    }

    /// Something that comes and goes is noted once, not announced every cycle.
    ///
    /// Anti-cheat services reinstall on every game launch — 137 of 270 install
    /// events on the development machine were one product doing this. Reporting
    /// each cycle would bury everything else. It is never silently dropped,
    /// though: a rule that hides flapping is a rule an attacker can use by
    /// flapping.
    #[test]
    fn a_thing_that_comes_and_goes_is_marked_rather_than_repeated() {
        let store = Store::open_in_memory().unwrap();
        let present = [seen("service", "AntiCheat", "C:\\ac.exe")];

        store.sweep(&present, &[]).unwrap();
        // Three full cycles away and back.
        for _ in 0..3 {
            store.sweep(&[], &[]).unwrap();
            store.sweep(&present, &[]).unwrap();
        }

        let sweep = store.sweep(&present, &[]).unwrap();
        let note = sweep.differences.iter().find(|d| d.name == "AntiCheat");
        // Either it is quiet now, or it says it comes and goes. What it must
        // not do is keep announcing an appearance.
        if let Some(note) = note {
            assert_eq!(
                note.change,
                crate::changes::Change::Recurring,
                "a flapping service was announced as though it were new"
            );
        }
    }

    #[test]
    fn records_and_reads_back_newest_first() {
        let store = Store::open_in_memory().unwrap();
        store.record(entry("first")).unwrap();
        store.record(entry("second")).unwrap();

        let records = store.recent_audit(10).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].action, "second");
        assert_eq!(records[0].effect, Effect::Changed);
        assert_eq!(records[0].undo_token.as_deref(), Some("undo-1"));
        assert!(records[0].at.ends_with('Z'));
    }

    #[test]
    fn the_database_itself_refuses_to_rewrite_history() {
        let store = Store::open_in_memory().unwrap();
        store.record(entry("first")).unwrap();

        let connection = store.lock().unwrap();
        assert!(connection
            .execute("UPDATE audit SET detail = 'tampered'", [])
            .is_err());
        assert!(connection.execute("DELETE FROM audit", []).is_err());
    }

    #[test]
    fn protection_is_on_until_it_is_switched_off() {
        // The default matters more than most: a store that has never been
        // written, or one that cannot be read, must leave the machine protected.
        let store = Store::open_in_memory().unwrap();
        assert!(
            store.protection_enabled(),
            "a fresh store must be protected"
        );

        store.set_protection_enabled(false).unwrap();
        assert!(!store.protection_enabled());

        store.set_protection_enabled(true).unwrap();
        assert!(store.protection_enabled());
    }

    #[test]
    fn a_setting_can_be_rewritten_unlike_an_audit_row() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.setting("thing").unwrap(), None);
        store.set_setting("thing", "one").unwrap();
        store.set_setting("thing", "two").unwrap();
        assert_eq!(store.setting("thing").unwrap().as_deref(), Some("two"));
    }

    #[test]
    fn migrating_an_already_current_store_is_a_no_op() {
        let store = Store::open_in_memory().unwrap();
        let connection = store.lock().unwrap();
        migrate(&connection).unwrap();
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }
}
