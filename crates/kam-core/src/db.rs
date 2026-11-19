//! Local SQLite store, and the audit log that lives in it.
//!
//! The audit table is append-only, and that is enforced by the database rather
//! than by convention: `BEFORE UPDATE` and `BEFORE DELETE` triggers abort any
//! attempt to rewrite history. A bug elsewhere in the agent should not be able
//! to quietly erase the record of what it did.

use std::fmt;
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::audit::{AuditLog, Effect, Entry, Record};
use crate::{Error, Result};

/// Bumped whenever the schema below changes. Stored in `PRAGMA user_version`.
const SCHEMA_VERSION: i64 = 8;

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

/// Every download that has been checked, for whom, and what came of it.
///
/// # One row per person, path and content
///
/// The key is the caller's SID, the file's path and its SHA-256 together. The
/// same file checked twice is one row brought up to date; a different file
/// saved under the same name is a new row, because it is a different download
/// and its history is its own. Rows outlive the file: a download quarantined or
/// deleted last week is still something that happened.
///
/// # Not the audit log
///
/// Rows are rewritten as a file is checked again and as things are done to it,
/// so unlike the audit table this one carries no append-only triggers. The
/// audit log is still the record of each check and each action; this is the
/// page's memory of where each download stands.
///
/// The richer parts (where it came from, who signed it, Defender's answer, what
/// was done, what an archive held) are JSON written by the agent, because their
/// shapes belong to the crates that produce them and this one cannot depend on
/// those. `path` compares without regard to case, as Windows does.
const SCHEMA_V6: &str = "
CREATE TABLE downloads (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sid         TEXT    NOT NULL,
    path        TEXT    NOT NULL COLLATE NOCASE,
    sha256      TEXT    NOT NULL,
    name        TEXT    NOT NULL,
    bytes       INTEGER NOT NULL,
    arrived_at  TEXT,
    checked_at  TEXT    NOT NULL,
    origin      TEXT,
    signature   TEXT,
    outcome     TEXT    NOT NULL,
    actions     TEXT    NOT NULL DEFAULT '[]',
    dissection  TEXT,
    UNIQUE (sid, path, sha256)
);

CREATE INDEX downloads_caller_idx ON downloads (sid, checked_at DESC);
";

/// The way each kind of thing was read when it was last recorded.
///
/// See [`crate::changes::Reading`] for what the number is and why a sweep
/// needs it. One row per kind, written by the sweep that records the kind.
///
/// # Why the step fills it in
///
/// A store from before this table has recorded every kind there was, under
/// the only reading there was, and has nowhere said so. Left empty, the table
/// would have the first sweep after the update take each kind for one it had
/// never seen, and record it without comparing: every change made since the
/// last sweep, to anything, absorbed in silence. So a store that has been
/// swept is given the six kinds that every sweep before this looked at, at
/// their first reading. A store that has never been swept is given nothing,
/// because its first sweep compares nothing anyway.
const SCHEMA_V7: &str = "
CREATE TABLE readings (
    kind    TEXT    PRIMARY KEY,
    version INTEGER NOT NULL
);

INSERT INTO readings (kind, version)
SELECT kind, 1
  FROM (SELECT 'run_key' AS kind
        UNION ALL SELECT 'run_once_key'
        UNION ALL SELECT 'startup_item'
        UNION ALL SELECT 'service'
        UNION ALL SELECT 'scheduled_task'
        UNION ALL SELECT 'administrator')
 WHERE EXISTS (SELECT 1 FROM sweeps);
";

/// What the watcher has already seen, so that a restart is not a fresh look.
///
/// # Why the watcher needs a memory that lasts
///
/// It kept what it had seen in memory, and took the first look after the
/// service started as the one to learn from. The service starts with the
/// machine, before anybody has signed in, so that look held nobody's own
/// startup entries. They turned up on the second look and were written down
/// as having just appeared, after every restart: the same two entries four
/// times in a month on the machine this was found on. The other half was
/// worse. Anything added while the service was not running was learned at
/// the next start, and never reported at all.
///
/// # What a scope is
///
/// Something looked at as a whole, which either has been looked at before or
/// has not: the machine's own startup entries, one account's, the reads of
/// one account's decoys. `watched_scopes` holds the ones that have been,
/// because "looked at and found empty" and "never looked at" must not be the
/// same answer. The first look at a scope learns it and reports nothing.
/// Every later look, in any run of the service, reports what is not on
/// record.
///
/// # What a row is
///
/// `kind` and `place` are spelled as a sighting's kind and scope are, so that
/// the rule about sources that could not be read can be asked of a row before
/// it is taken off the record. `what` is everything else that makes the thing
/// itself and not another.
///
/// This is not the `sightings` table, though both remember what starts
/// itself. That one is compared when a person asks what changed, and what it
/// reports is theirs to read. The watcher looks every two minutes and must
/// not use their answer up.
const SCHEMA_V8: &str = "
CREATE TABLE watched (
    scope TEXT NOT NULL,
    kind  TEXT NOT NULL,
    place TEXT NOT NULL,
    what  TEXT NOT NULL,
    PRIMARY KEY (scope, kind, place, what)
);

CREATE TABLE watched_scopes (
    scope      TEXT PRIMARY KEY,
    learned_at TEXT NOT NULL
);
";

/// One thing the watcher has on record. See [`SCHEMA_V8`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Watched {
    /// What sort of thing, as the token a sighting of it would be filed under.
    pub kind: String,
    /// Where it lives, as a sighting's scope is spelled.
    pub place: String,
    /// Everything else that makes it this one and not another.
    pub what: String,
}

/// One checked download as the store keeps it. See [`SCHEMA_V6`].
///
/// The JSON columns are carried as text: this crate stores them and the agent
/// gives them their shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadRow {
    pub sid: String,
    pub path: String,
    pub sha256: String,
    pub name: String,
    pub bytes: u64,
    /// When the file was created where it is, in the store's ISO form.
    pub arrived_at: Option<String>,
    /// Written by the store's own clock when the row is recorded.
    pub checked_at: String,
    pub origin: Option<String>,
    pub signature: Option<String>,
    pub outcome: String,
    /// A JSON array, oldest first.
    pub actions: String,
    /// What the archive was found to hold. Written whole; read back without
    /// its list of members (see `DOWNLOAD_COLUMNS`).
    pub dissection: Option<String>,
}

/// The columns a download row is read back by, in [`download_row`]'s order.
///
/// The record of taking an archive apart is read without its list of members
/// and without the copy of Defender's answer it carries. Those are most of a
/// row: up to five thousand names for one archive. Nothing that reads a row
/// back needs them, and reading a thousand rows with them could come to
/// hundreds of megabytes, so they are left in the store by the query itself
/// and never loaded. A record that is not readable JSON comes back as none,
/// so one damaged row cannot fail the whole list.
const DOWNLOAD_COLUMNS: &str = "sid, path, sha256, name, bytes, arrived_at, checked_at,
    origin, signature, outcome, actions,
    CASE WHEN json_valid(dissection)
         THEN json_remove(dissection, '$.members', '$.scan', '$.whole_archive', '$.unmatched')
    END";

fn download_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DownloadRow> {
    Ok(DownloadRow {
        sid: row.get(0)?,
        path: row.get(1)?,
        sha256: row.get(2)?,
        name: row.get(3)?,
        bytes: row.get::<_, i64>(4)?.max(0) as u64,
        arrived_at: row.get(5)?,
        checked_at: row.get(6)?,
        origin: row.get(7)?,
        signature: row.get(8)?,
        outcome: row.get(9)?,
        actions: row.get(10)?,
        dissection: row.get(11)?,
    })
}

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
        // `recursive_triggers` is what makes the audit log's delete trigger
        // hold against `INSERT OR REPLACE`. A REPLACE removes the conflicting
        // row before inserting its own, and SQLite only fires delete triggers
        // for that removal when this is on. With it off, a REPLACE naming an
        // existing id rewrote that audit row in place, past both triggers.
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = NORMAL;
                 PRAGMA foreign_keys = ON;
                 PRAGMA recursive_triggers = ON;",
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

    /// Record that a download was checked, and say whether it is new.
    ///
    /// The row for this person, path and content is written if there is none,
    /// and brought up to date if there is: what was found, where it came from
    /// and when it was checked are replaced, while what was done to it and any
    /// record of taking it apart are kept, because those happened and a second
    /// look does not undo them. `checked_at` is the store's own clock, like the
    /// audit log's, whatever the row passed in says.
    ///
    /// Returns true the first time this person's file with this content is
    /// recorded, which is what decides whether a notice is worth sending.
    pub fn record_download_check(&self, row: &DownloadRow) -> Result<bool> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(to_db_error)?;
        let existing: Option<i64> = transaction
            .query_row(
                "SELECT id FROM downloads WHERE sid = ?1 AND path = ?2 AND sha256 = ?3",
                params![row.sid, row.path, row.sha256],
                |found| found.get(0),
            )
            .optional()
            .map_err(to_db_error)?;
        match existing {
            Some(id) => {
                transaction
                    .execute(
                        // A fact this check could not read keeps what an
                        // earlier one did: a private copy of an archive has
                        // no arrival time or origin of its own, and the
                        // original's should not be lost to it.
                        "UPDATE downloads SET
                             name = ?2, bytes = ?3,
                             arrived_at = COALESCE(?4, arrived_at),
                             checked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                             origin = COALESCE(?5, origin),
                             signature = COALESCE(?6, signature),
                             outcome = ?7
                         WHERE id = ?1",
                        params![
                            id,
                            row.name,
                            row.bytes as i64,
                            row.arrived_at,
                            row.origin,
                            row.signature,
                            row.outcome
                        ],
                    )
                    .map_err(to_db_error)?;
            }
            None => {
                transaction
                    .execute(
                        "INSERT INTO downloads
                             (sid, path, sha256, name, bytes, arrived_at, checked_at,
                              origin, signature, outcome, actions, dissection)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6,
                                 strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                                 ?7, ?8, ?9, '[]', NULL)",
                        params![
                            row.sid,
                            row.path,
                            row.sha256,
                            row.name,
                            row.bytes as i64,
                            row.arrived_at,
                            row.origin,
                            row.signature,
                            row.outcome
                        ],
                    )
                    .map_err(to_db_error)?;
            }
        }
        transaction.commit().map_err(to_db_error)?;
        Ok(existing.is_none())
    }

    /// One person's checked downloads, most recently checked first.
    ///
    /// Only theirs. The agent serves everybody signed in to the machine, and a
    /// list of what somebody downloaded is theirs to read and nobody else's.
    ///
    /// The record of taking an archive apart comes back without its list of
    /// members: see [`DOWNLOAD_COLUMNS`].
    pub fn downloads_for(&self, sid: &str, limit: usize) -> Result<Vec<DownloadRow>> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare(&format!(
                "SELECT {DOWNLOAD_COLUMNS} FROM downloads WHERE sid = ?1
                 ORDER BY checked_at DESC, id DESC LIMIT ?2"
            ))
            .map_err(to_db_error)?;
        let rows = statement
            .query_map(params![sid, limit as i64], download_row)
            .map_err(to_db_error)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(to_db_error)
    }

    /// One person's row for one path: the newest, or the one with this
    /// content when `sha256` is given. `None` when there is none.
    ///
    /// Asked for by name, so that finding one download does not mean reading
    /// every row, and so that a row older than the newest thousand can still
    /// be found.
    pub fn download_at(
        &self,
        sid: &str,
        path: &str,
        sha256: Option<&str>,
    ) -> Result<Option<DownloadRow>> {
        let connection = self.lock()?;
        connection
            .query_row(
                &format!(
                    "SELECT {DOWNLOAD_COLUMNS} FROM downloads
                     WHERE sid = ?1 AND path = ?2 AND (?3 IS NULL OR sha256 = ?3)
                     ORDER BY checked_at DESC, id DESC LIMIT 1"
                ),
                params![sid, path, sha256],
                download_row,
            )
            .optional()
            .map_err(to_db_error)
    }

    /// How many checked downloads one person has on record.
    pub fn download_count(&self, sid: &str) -> Result<u64> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT COUNT(*) FROM downloads WHERE sid = ?1",
                params![sid],
                |row| row.get::<_, i64>(0),
            )
            .map(|count| count.max(0) as u64)
            .map_err(to_db_error)
    }

    /// What each of one person's checks recorded after `since` came to: the
    /// stored answers and nothing else of the rows.
    ///
    /// For counting the results a person has not looked at yet. The answer
    /// is all a count needs, and its shape belongs to the crate that writes
    /// it, so it is handed back as it is stored for the agent to read.
    pub fn download_outcomes_since(&self, sid: &str, since: &str) -> Result<Vec<String>> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare("SELECT outcome FROM downloads WHERE sid = ?1 AND checked_at > ?2")
            .map_err(to_db_error)?;
        let rows = statement
            .query_map(params![sid, since], |row| row.get::<_, String>(0))
            .map_err(to_db_error)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(to_db_error)
    }

    /// Note something done to a download, on its most recent row.
    ///
    /// `sha256` narrows it to one content when the caller knows it; without it
    /// the newest row for the path is the one meant, which is the file that was
    /// there when the action was taken. `action` is one JSON value and is
    /// appended, so earlier actions are never rewritten.
    ///
    /// Returns false when there is no row to note it on, which is not an error:
    /// the audit log has the action either way.
    pub fn add_download_action(
        &self,
        sid: &str,
        path: &str,
        sha256: Option<&str>,
        action: &str,
    ) -> Result<bool> {
        let connection = self.lock()?;
        let changed = connection
            .execute(
                "UPDATE downloads SET actions = json_insert(actions, '$[#]', json(?4))
                 WHERE id = (
                     SELECT id FROM downloads
                     WHERE sid = ?1 AND path = ?2 AND (?3 IS NULL OR sha256 = ?3)
                     ORDER BY checked_at DESC, id DESC LIMIT 1
                 )",
                params![sid, path, sha256, action],
            )
            .map_err(to_db_error)?;
        Ok(changed > 0)
    }

    /// Keep what an archive was found to hold, on that archive's row.
    ///
    /// Replaces any earlier dissection of the same content: taking the same
    /// archive apart again produces the current answer, which is the one worth
    /// showing. Returns false when there is no such row.
    pub fn set_download_dissection(
        &self,
        sid: &str,
        path: &str,
        sha256: &str,
        dissection: &str,
    ) -> Result<bool> {
        let connection = self.lock()?;
        let changed = connection
            .execute(
                "UPDATE downloads SET dissection = ?4
                 WHERE sid = ?1 AND path = ?2 AND sha256 = ?3",
                params![sid, path, sha256, dissection],
            )
            .map_err(to_db_error)?;
        Ok(changed > 0)
    }

    /// Remove one person's record of one check, for good: the row for that
    /// path and that content. Returns how many rows went, one or none.
    ///
    /// Only theirs, like every other reading and writing of this table. The
    /// record is all that goes. The file is not this store's to touch, and
    /// the audit log keeps its own entry of the check, which nothing removes.
    pub fn remove_download(&self, sid: &str, path: &str, sha256: &str) -> Result<u64> {
        let connection = self.lock()?;
        connection
            .execute(
                "DELETE FROM downloads WHERE sid = ?1 AND path = ?2 AND sha256 = ?3",
                params![sid, path, sha256],
            )
            .map(|removed| removed as u64)
            .map_err(to_db_error)
    }

    /// Remove every record one person has that was last checked at or before
    /// `up_to`, for good. Returns how many rows went.
    ///
    /// Up to a time, and not simply all of them, so that clearing a list
    /// removes what was on it when the person decided. A check recorded a
    /// moment later is one they have never been shown, and it stays.
    pub fn clear_downloads(&self, sid: &str, up_to: &str) -> Result<u64> {
        let connection = self.lock()?;
        connection
            .execute(
                "DELETE FROM downloads WHERE sid = ?1 AND checked_at <= ?2",
                params![sid, up_to],
            )
            .map(|removed| removed as u64)
            .map_err(to_db_error)
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
    ///
    /// # All of it or none of it
    ///
    /// The sweep is one transaction. It used to be a run of separate writes,
    /// so an error partway through left new sightings inserted and `present`
    /// cleared for things that had gone, with no `changes` row and no sweep
    /// recorded. The next sweep then compared against that half-written
    /// baseline and found nothing: the appearances and disappearances the
    /// failed sweep had already absorbed were never reported to anybody.
    pub fn sweep(
        &self,
        seen: &[crate::changes::Sighting],
        unreadable: &[crate::changes::Unreadable],
    ) -> Result<crate::changes::Sweep> {
        self.sweep_read_as(seen, unreadable, &[])
    }

    /// The same, told how each kind of thing was read.
    ///
    /// # The first look is per kind
    ///
    /// A kind named in `readings` that this store has never recorded, or last
    /// recorded under a lower number, is recorded as it is and not compared:
    /// nothing of that kind is reported as appeared, changed or gone this
    /// time. See [`crate::changes::Reading`] for why, and for what it costs.
    /// The reading's note comes back in `afresh`.
    ///
    /// A kind that is not named keeps the old rule, under which only the very
    /// first sweep of a store goes uncompared. That is every kind when nothing
    /// is named, which is what [`Store::sweep`] asks for.
    ///
    /// A kind whose whole source could not be read this time is not written
    /// down as recorded. Its first look is the first sweep that can see it.
    pub fn sweep_read_as(
        &self,
        seen: &[crate::changes::Sighting],
        unreadable: &[crate::changes::Unreadable],
        readings: &[crate::changes::Reading],
    ) -> Result<crate::changes::Sweep> {
        use crate::changes::{rank, Change, Difference, Reading, FLAPS_BEFORE_RECURRING};

        let mut guard = self.lock()?;
        // Dropped without `commit` on any early return, which rolls back.
        let connection = guard
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(to_db_error)?;
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

        // The kinds being recorded without comparing, this sweep only.
        let recorded_under: std::collections::HashMap<String, i64> = {
            let mut stored = connection
                .prepare("SELECT kind, version FROM readings")
                .map_err(to_db_error)?;
            let rows = stored
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(to_db_error)?
                .collect::<std::result::Result<_, _>>()
                .map_err(to_db_error)?;
            rows
        };
        let afresh: Vec<&Reading> = readings
            .iter()
            .filter(|reading| {
                recorded_under
                    .get(&reading.kind)
                    .is_none_or(|under| *under < reading.version)
            })
            .collect();
        // Whether what this sweep makes of one kind is reported, or only
        // written down.
        let compared = |kind: &str| !baseline && !afresh.iter().any(|reading| reading.kind == kind);

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
            let existing: Option<(String, i64, i64, i64, String, String)> = connection
                .query_row(
                    "SELECT detail, times_seen, flaps, present, trust, first_seen FROM sightings
                     WHERE kind = ?1 AND scope = ?2 AND name = ?3",
                    params![sighting.kind, sighting.scope, sighting.name],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
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
                    if compared(&sighting.kind) {
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
                    } else if baseline
                        && !crate::changes::vouched_for(&sighting.trust)
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
                Some((detail, times_seen, flaps, present, was_trust, first_seen)) => {
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

                    if !compared(&sighting.kind) {
                        continue;
                    }
                    // A trust that was recorded and has since changed. An
                    // empty stored value means it was recorded before this
                    // column existed, which is a gap being filled rather than
                    // anything moving.
                    let trust_moved = !was_trust.is_empty() && was_trust != sighting.trust;
                    // Either it points somewhere else now, or the file it
                    // points at is not the file it was. The second is the case
                    // a path comparison cannot see: same entry, same path,
                    // different binary. Nothing keeps its standing just
                    // because it had it yesterday.
                    let altered = detail != sighting.detail || trust_moved;

                    // `Recurring` is said only on a sweep where the thing
                    // actually came back. It used to be said on every sweep
                    // once the flap count reached the threshold, whether or not
                    // anything had happened -- so a flapping service wrote a
                    // `changes` row each time the view was opened, and the
                    // weekly bars measured how often somebody looked. And it
                    // was checked before anything else, so an ImagePath
                    // hijack of a service that flaps read as "comes and goes".
                    // Coming and going is noted; it is not a licence.
                    let recurring = flaps >= FLAPS_BEFORE_RECURRING;
                    let change = match (returned, recurring, altered) {
                        // Back again, and nothing else about it is different.
                        (true, true, false) => Some(Change::Recurring),
                        // Back again before it has made a habit of it.
                        (true, false, _) => Some(Change::Appeared),
                        // Pointing somewhere else, whether or not it flaps.
                        (_, _, true) => Some(Change::Altered),
                        // Here last time and here now, unchanged: nothing to
                        // say, and nothing is written.
                        (false, _, false) => None,
                    };
                    if let Some(change) = change {
                        differences.push(Difference {
                            at: now.clone(),
                            change,
                            kind: sighting.kind.clone(),
                            scope: sighting.scope.clone(),
                            name: sighting.name.clone(),
                            detail: sighting.detail.clone(),
                            first_seen,
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
        // A row that would not read is an error rather than a row skipped: a
        // skipped row is one whose disappearance can never be reported.
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
            .collect::<std::result::Result<_, _>>()
            .map_err(to_db_error)?;
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

            if compared(&kind) {
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

        // What this sweep has to say about what it could not vouch for: the
        // sources it could not read, and apart from them the kinds it
        // recorded without comparing. Each kind that was recorded is written
        // down under the number it was read with, so that the next sweep
        // compares it.
        let said: Vec<String> = unreadable
            .iter()
            .map(|source| source.what.clone())
            .collect();
        let mut afresh_said: Vec<String> = Vec::new();
        for reading in readings {
            // The whole kind could not be read, so it has not been recorded
            // and nothing is written down: its first look is still to come.
            let unseen = unreadable
                .iter()
                .any(|source| source.scopes.is_empty() && source.kinds.contains(&reading.kind));
            if unseen {
                continue;
            }
            // The very first sweep compares nothing at all, and the
            // interface says so in its own words.
            let uncompared = afresh.iter().any(|one| one.kind == reading.kind);
            if uncompared && !baseline && !reading.note.is_empty() {
                afresh_said.push(reading.note.clone());
            }
            connection
                .execute(
                    "INSERT INTO readings (kind, version) VALUES (?1, ?2)
                     ON CONFLICT(kind) DO UPDATE
                        SET version = MAX(version, excluded.version)",
                    params![reading.kind, reading.version],
                )
                .map_err(to_db_error)?;
        }

        connection
            .execute(
                "INSERT INTO sweeps (at, unreadable) VALUES (?1, ?2)",
                params![
                    now,
                    said.iter()
                        .chain(&afresh_said)
                        .cloned()
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
        // found nothing writes nothing here; it still counts as a week with
        // nothing in it, because the sweep itself is recorded above and its
        // date comes back in `swept`. That is the comparison that makes a busy
        // week legible, and it is what tells a quiet week from one nobody
        // looked at.
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

        // When the machine was compared with itself, over the same window as
        // the history. Without these a week in which nothing was swept and a
        // week in which a sweep found nothing were the same empty bar, and the
        // chart called a week nobody looked at "nothing changed".
        //
        // The first sweep is left out. It took the baseline and compared
        // nothing, so a week holding only that sweep is not a week in which
        // nothing changed either.
        let mut dates = connection
            .prepare(
                "SELECT at FROM sweeps
                  WHERE id > (SELECT MIN(id) FROM sweeps)
                    AND at >= datetime('now', '-84 days')
                  ORDER BY id DESC",
            )
            .map_err(to_db_error)?;
        let swept: Vec<String> = dates
            .query_map([], |row| row.get(0))
            .map_err(to_db_error)?
            .collect::<std::result::Result<_, _>>()
            .map_err(to_db_error)?;
        drop(dates);

        connection.commit().map_err(to_db_error)?;

        Ok(crate::changes::Sweep {
            differences,
            unreadable: said,
            afresh: afresh_said,
            baseline,
            previous_at,
            at: now,
            history,
            swept,
            unvouched,
        })
    }

    /// What the watcher has on record for one scope.
    ///
    /// `None` when the scope has never been looked at, which is a different
    /// answer from having been looked at and found empty: the first is a
    /// scope to learn, the second a scope in which anything is new.
    pub fn watched(&self, scope: &str) -> Result<Option<Vec<Watched>>> {
        let connection = self.lock()?;
        let learned: Option<String> = connection
            .query_row(
                "SELECT learned_at FROM watched_scopes WHERE scope = ?1",
                params![scope],
                |row| row.get(0),
            )
            .optional()
            .map_err(to_db_error)?;
        if learned.is_none() {
            return Ok(None);
        }
        let mut statement = connection
            .prepare("SELECT kind, place, what FROM watched WHERE scope = ?1")
            .map_err(to_db_error)?;
        let rows = statement
            .query_map(params![scope], |row| {
                Ok(Watched {
                    kind: row.get(0)?,
                    place: row.get(1)?,
                    what: row.get(2)?,
                })
            })
            .map_err(to_db_error)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(to_db_error)?;
        Ok(Some(rows))
    }

    /// Bring one scope's record up to date: `appeared` is added to it, `gone`
    /// is taken off it, and the scope is marked as looked at if it was not.
    ///
    /// All of it or none of it, for the reason a sweep is. A record that took
    /// the additions and lost the mark would be learned again from nothing at
    /// the next look, and whatever arrived in between would never be
    /// reported.
    pub fn record_watched(
        &self,
        scope: &str,
        appeared: &[Watched],
        gone: &[Watched],
    ) -> Result<()> {
        let mut guard = self.lock()?;
        let transaction = guard
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(to_db_error)?;
        transaction
            .execute(
                "INSERT OR IGNORE INTO watched_scopes (scope, learned_at)
                 VALUES (?1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
                params![scope],
            )
            .map_err(to_db_error)?;
        for one in gone {
            transaction
                .execute(
                    "DELETE FROM watched
                      WHERE scope = ?1 AND kind = ?2 AND place = ?3 AND what = ?4",
                    params![scope, one.kind, one.place, one.what],
                )
                .map_err(to_db_error)?;
        }
        for one in appeared {
            transaction
                .execute(
                    "INSERT OR IGNORE INTO watched (scope, kind, place, what)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![scope, one.kind, one.place, one.what],
                )
                .map_err(to_db_error)?;
        }
        transaction.commit().map_err(to_db_error)
    }

    /// Forget everything the watcher has learned, in every scope, so that the
    /// next look at each is a first look.
    pub fn forget_watched(&self) -> Result<()> {
        let mut guard = self.lock()?;
        let transaction = guard
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(to_db_error)?;
        transaction
            .execute_batch("DELETE FROM watched; DELETE FROM watched_scopes;")
            .map_err(to_db_error)?;
        transaction.commit().map_err(to_db_error)
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
    /// write this module makes is either a single statement or, for a sweep,
    /// one transaction that rolls back when it is dropped uncommitted -- which
    /// unwinding does. A panic midway leaves nothing for the next caller to
    /// trip over.
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

/// Every schema step, with the version it brings the store to.
const MIGRATIONS: [(i64, &str); 8] = [
    (1, SCHEMA_V1),
    (2, SCHEMA_V2),
    (3, SCHEMA_V3),
    (4, SCHEMA_V4),
    (5, SCHEMA_V5),
    (6, SCHEMA_V6),
    (7, SCHEMA_V7),
    (8, SCHEMA_V8),
];

fn migrate(connection: &Connection) -> Result<()> {
    migrate_through(connection, &MIGRATIONS)
}

/// Apply each step the store has not had yet, each one whole or not at all.
///
/// # Why each step carries its own version bump
///
/// The steps and the final `user_version` write used to be separate
/// statements in no transaction. A service stopped partway through the v4 to
/// v5 upgrade -- after `ALTER TABLE ... ADD COLUMN trust`, before the version
/// was written -- left a store that said v4 and already had the column. Every
/// start after that ran the same `ALTER` again, failed with "duplicate column
/// name: trust", and the service would not start at all, on that machine,
/// for good.
///
/// So a step and the version it brings the store to commit together. An
/// interrupted step leaves the store exactly at the version before it, which
/// the next start simply runs again. The version is read again inside each
/// step's transaction, so a step another connection has already finished is
/// not applied twice either.
fn migrate_through(connection: &Connection, steps: &[(i64, &str)]) -> Result<()> {
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

    for &(version, schema) in steps {
        if current >= version {
            continue;
        }
        // `IMMEDIATE` takes the write lock before reading the version, so the
        // check below and the step it guards cannot be split by another
        // writer.
        connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(to_db_error)?;
        let applied = connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .and_then(|now| {
                if now >= version {
                    return Ok(());
                }
                connection.execute_batch(schema)?;
                connection.pragma_update(None, "user_version", version)
            });
        match applied {
            Ok(()) => connection.execute_batch("COMMIT").map_err(to_db_error)?,
            Err(error) => {
                // Whatever part of the step ran is undone, so the store is
                // left at the version it says it is.
                let _ = connection.execute_batch("ROLLBACK");
                return Err(Error::Database(format!(
                    "the store could not be brought up to schema {version}: {error}"
                )));
            }
        }
    }
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

    /// A change to something already known says when it was first seen.
    ///
    /// The row was read for everything but that, so the window was handed an
    /// empty date and printed "first seen" with nothing after it beside every
    /// entry that had changed, which is the one line where how long a thing
    /// has been here matters most.
    #[test]
    fn a_change_to_something_already_known_says_when_it_was_first_seen() {
        let store = Store::open_in_memory().unwrap();
        store
            .sweep(&[seen("service", "Thing", "C:\\one.exe")], &[])
            .unwrap();

        let sweep = store
            .sweep(&[seen("service", "Thing", "C:\\two.exe")], &[])
            .unwrap();

        let altered = sweep
            .differences
            .iter()
            .find(|d| d.name == "Thing")
            .expect("it points somewhere else now");
        assert_eq!(altered.change, crate::changes::Change::Altered);
        assert!(
            !altered.first_seen.is_empty(),
            "a changed entry was reported with no date it was first seen"
        );
        assert_eq!(altered.times_seen, 2);
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

    /// Something that comes and goes is noted when it comes or goes, and not
    /// on every sweep in between.
    ///
    /// Once the flap count reached the threshold, every later sweep reported
    /// it as `Recurring` whether or not anything had happened, and wrote a
    /// `changes` row each time -- so the weekly bars grew with how often the
    /// view was opened. And `Recurring` was decided before anything else, so
    /// pointing a flapping service at a different program read as "comes and
    /// goes" rather than as a change.
    #[test]
    fn a_thing_that_comes_and_goes_is_noted_only_when_it_comes_or_goes() {
        use crate::changes::Change;

        let store = Store::open_in_memory().unwrap();
        let present = [seen("service", "AntiCheat", "C:\\ac.exe")];

        store.sweep(&present, &[]).unwrap();
        for _ in 0..3 {
            store.sweep(&[], &[]).unwrap();
            store.sweep(&present, &[]).unwrap();
        }

        // Present last time and present now, unchanged: nothing to say, and
        // nothing written to the history.
        let before = store.sweep(&present, &[]).unwrap().history.len();
        let quiet = store.sweep(&present, &[]).unwrap();
        assert!(
            quiet.differences.is_empty(),
            "a sweep in which nothing happened reported {:?}",
            quiet.differences
        );
        assert_eq!(
            quiet.history.len(),
            before,
            "a sweep in which nothing happened wrote to the history"
        );

        // It goes, and that is noted as coming and going.
        let gone = store.sweep(&[], &[]).unwrap();
        assert_eq!(
            gone.differences
                .iter()
                .find(|d| d.name == "AntiCheat")
                .map(|d| d.change),
            Some(Change::Recurring)
        );

        // It comes back, and that is noted too.
        let back = store.sweep(&present, &[]).unwrap();
        assert_eq!(
            back.differences
                .iter()
                .find(|d| d.name == "AntiCheat")
                .map(|d| d.change),
            Some(Change::Recurring)
        );

        // And while it is here, it is hijacked: same service, another program.
        let hijacked = store
            .sweep(
                &[seen("service", "AntiCheat", "C:\\Users\\me\\evil.exe")],
                &[],
            )
            .unwrap();
        assert_eq!(
            hijacked
                .differences
                .iter()
                .find(|d| d.name == "AntiCheat")
                .map(|d| d.change),
            Some(Change::Altered),
            "a flapping service pointed elsewhere read as coming and going"
        );

        // A hijack that arrives with a return is a change too, not a flap.
        store.sweep(&[], &[]).unwrap();
        let returned_elsewhere = store
            .sweep(
                &[seen("service", "AntiCheat", "C:\\Users\\me\\worse.exe")],
                &[],
            )
            .unwrap();
        assert_eq!(
            returned_elsewhere
                .differences
                .iter()
                .find(|d| d.name == "AntiCheat")
                .map(|d| d.change),
            Some(Change::Altered)
        );
    }

    /// A sweep that fails partway leaves the baseline as it was.
    ///
    /// The sweep was a run of separate writes. A failure after the sightings
    /// had been written left the new one recorded as seen with no `changes`
    /// row, so the next sweep compared against it, found nothing new, and the
    /// appearance was never reported to anybody.
    #[test]
    fn a_sweep_that_fails_partway_leaves_nothing_behind() {
        let store = Store::open_in_memory().unwrap();
        store
            .sweep(&[seen("service", "Old", "C:\\old.exe")], &[])
            .unwrap();

        // Fail at the last write a sweep makes, after every sighting has been
        // inserted and every disappearance marked.
        store
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TEMP TRIGGER fail_the_sweep BEFORE INSERT ON sweeps
                 BEGIN SELECT RAISE(ABORT, 'interrupted'); END;",
            )
            .unwrap();
        let after = [seen("service", "New", "C:\\new.exe")];
        assert!(store.sweep(&after, &[]).is_err(), "the sweep should fail");
        store
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_the_sweep")
            .unwrap();

        let sweep = store.sweep(&after, &[]).unwrap();
        let change = |name: &str| {
            sweep
                .differences
                .iter()
                .find(|d| d.name == name)
                .map(|d| d.change)
        };
        assert_eq!(
            change("New"),
            Some(crate::changes::Change::Appeared),
            "the failed sweep swallowed an appearance: {:?}",
            sweep.differences
        );
        assert_eq!(
            change("Old"),
            Some(crate::changes::Change::Vanished),
            "the failed sweep swallowed a disappearance: {:?}",
            sweep.differences
        );
    }

    /// The history says when the machine was looked at, so a week nobody
    /// looked at is not drawn as a week in which nothing changed.
    #[test]
    fn the_dates_of_sweeps_come_back_with_the_history() {
        let store = Store::open_in_memory().unwrap();
        let things = [seen("service", "One", "a")];

        let first = store.sweep(&things, &[]).unwrap();
        assert!(
            first.swept.is_empty(),
            "the baseline compared nothing, so it is not a sweep that looked"
        );

        store.sweep(&things, &[]).unwrap();
        let third = store.sweep(&things, &[]).unwrap();
        assert!(third.differences.is_empty());
        assert!(third.history.is_empty(), "nothing changed");
        assert_eq!(
            third.swept.len(),
            2,
            "two sweeps compared the machine and found nothing: {:?}",
            third.swept
        );
        assert_eq!(third.swept[0], third.at, "newest first");
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

    /// `INSERT OR REPLACE` cannot rewrite an audit row.
    ///
    /// A REPLACE deletes the conflicting row and inserts its own, and SQLite
    /// fires delete triggers for that deletion only with `recursive_triggers`
    /// on. Without it, naming an existing id replaced that entry in place and
    /// both append-only triggers were walked straight past.
    #[test]
    fn replacing_an_audit_row_is_refused() {
        let store = Store::open_in_memory().unwrap();
        store.record(entry("first")).unwrap();
        let original = store.recent_audit(1).unwrap().remove(0);

        let connection = store.lock().unwrap();
        for statement in [
            "INSERT OR REPLACE INTO audit (id, at, module, action, effect, detail)
             VALUES (?1, '2000-01-01T00:00:00.000Z', 'storage', 'nothing', 'observed', 'tampered')",
            "REPLACE INTO audit (id, at, module, action, effect, detail)
             VALUES (?1, '2000-01-01T00:00:00.000Z', 'storage', 'nothing', 'observed', 'tampered')",
        ] {
            assert!(
                connection.execute(statement, params![original.id]).is_err(),
                "an audit row was replaced by: {statement}"
            );
        }
        drop(connection);

        let after = store.recent_audit(10).unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].action, original.action);
        assert_eq!(after[0].detail, original.detail);
        assert_eq!(after[0].at, original.at);
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

    /// An upgrade interrupted partway is finished by the next start, rather
    /// than failing it forever.
    ///
    /// The steps and the version bump were separate. A store left after
    /// `ADD COLUMN trust` and before `user_version = 5` said v4, already had
    /// the column, and failed every later start with "duplicate column name:
    /// trust" -- so the service would not start again on that machine.
    #[test]
    fn an_upgrade_interrupted_partway_is_finished_by_the_next_start() {
        let connection = Connection::open_in_memory().unwrap();
        migrate_through(&connection, &MIGRATIONS[..4]).unwrap();

        // The v5 step, failing after its `ALTER` has run.
        let interrupted = [(
            5,
            "ALTER TABLE sightings ADD COLUMN trust TEXT NOT NULL DEFAULT '';
             this is where the process was stopped;",
        )];
        assert!(migrate_through(&connection, &interrupted).is_err());

        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 4, "the store claims a version it does not have");

        migrate(&connection).expect("the next start should finish the upgrade");
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        connection
            .execute_batch("SELECT trust FROM sightings")
            .expect("the column the upgrade adds is there");
    }

    fn download(sid: &str, path: &str, sha256: &str, outcome: &str) -> DownloadRow {
        DownloadRow {
            sid: sid.to_owned(),
            path: path.to_owned(),
            sha256: sha256.to_owned(),
            name: "setup.exe".to_owned(),
            bytes: 4096,
            arrived_at: Some("2026-10-12T09:00:00.000Z".to_owned()),
            checked_at: String::new(),
            origin: Some(r#"{"zone":"internet"}"#.to_owned()),
            signature: None,
            outcome: outcome.to_owned(),
            actions: String::new(),
            dissection: None,
        }
    }

    /// A store from before downloads were recorded gains the table, keeps what
    /// it already held, and can then record a download.
    #[test]
    fn a_version_five_store_is_brought_up_to_six_and_keeps_its_history() {
        let connection = Connection::open_in_memory().unwrap();
        migrate_through(&connection, &MIGRATIONS[..5]).unwrap();
        connection
            .execute(
                "INSERT INTO audit (at, module, action, effect, detail)
                 VALUES ('2026-10-01T00:00:00.000Z', 'storage', 'scan', 'observed', 'before')",
                [],
            )
            .unwrap();
        assert!(
            connection
                .execute_batch("SELECT id FROM downloads")
                .is_err(),
            "the premise: a version five store has no downloads table"
        );

        migrate_through(&connection, &MIGRATIONS[..6]).expect("the upgrade to six should apply");
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 6);
        let kept: String = connection
            .query_row("SELECT detail FROM audit", [], |row| row.get(0))
            .unwrap();
        assert_eq!(kept, "before", "the audit log did not survive the upgrade");

        // And the upgraded store is a working one.
        let store = Store {
            connection: Mutex::new(connection),
        };
        assert!(store
            .record_download_check(&download("S-1-5-21-1", r"C:\D\a.exe", "aa", "{}"))
            .unwrap());
    }

    /// The v6 step, stopped partway, leaves the store at v5 and the next start
    /// finishes it rather than failing on a table that half exists.
    #[test]
    fn an_interrupted_upgrade_to_six_is_finished_by_the_next_start() {
        let connection = Connection::open_in_memory().unwrap();
        migrate_through(&connection, &MIGRATIONS[..5]).unwrap();
        let interrupted = [(
            6,
            "CREATE TABLE downloads (id INTEGER PRIMARY KEY);
             this is where the process was stopped;",
        )];
        assert!(migrate_through(&connection, &interrupted).is_err());
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 5);

        migrate(&connection).expect("the next start should finish the upgrade");
        connection
            .execute_batch("SELECT sid, path, sha256, actions, dissection FROM downloads")
            .expect("the table the upgrade adds is there, whole");
    }

    /// One row per person, path and content. A second check of the same file
    /// updates it and keeps what was done; new content is a new row.
    #[test]
    fn a_download_is_one_row_per_person_path_and_content() {
        let store = Store::open_in_memory().unwrap();
        let me = "S-1-5-21-1-1001";
        let path = r"C:\Users\me\Downloads\setup.exe";

        assert!(store
            .record_download_check(&download(me, path, "aa", r#"{"answer":"nothing_found"}"#))
            .unwrap());
        assert!(store
            .add_download_action(me, path, None, r#"{"what":"quarantined"}"#)
            .unwrap());
        // The same content again, spelled with other capitals: the same row,
        // brought up to date, with its action kept.
        let again = download(me, &path.to_uppercase(), "aa", r#"{"answer":"flagged"}"#);
        assert!(
            !store.record_download_check(&again).unwrap(),
            "a second check was taken for a first"
        );
        let rows = store.downloads_for(me, 50).unwrap();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].outcome, r#"{"answer":"flagged"}"#);
        assert_eq!(rows[0].actions, r#"[{"what":"quarantined"}]"#);
        assert!(
            rows[0].checked_at.ends_with('Z'),
            "the store's clock writes checked_at"
        );

        // Different content under the same name is a different download.
        assert!(store
            .record_download_check(&download(me, path, "bb", "{}"))
            .unwrap());
        assert_eq!(store.downloads_for(me, 50).unwrap().len(), 2);

        // A dissection lands on the row it describes and nowhere else.
        assert!(store
            .set_download_dissection(me, path, "bb", r#"{"members":[]}"#)
            .unwrap());
        assert!(!store.set_download_dissection(me, path, "cc", "{}").unwrap());
        let rows = store.downloads_for(me, 50).unwrap();
        let described: Vec<_> = rows.iter().filter(|row| row.dissection.is_some()).collect();
        assert_eq!(described.len(), 1);
        assert_eq!(described[0].sha256, "bb");
    }

    /// Somebody else's downloads are not in anybody's list but theirs.
    #[test]
    fn a_caller_sees_only_their_own_downloads() {
        let store = Store::open_in_memory().unwrap();
        store
            .record_download_check(&download(
                "S-1-5-21-1-1001",
                r"C:\Users\me\Downloads\a.exe",
                "aa",
                "{}",
            ))
            .unwrap();
        store
            .record_download_check(&download(
                "S-1-5-21-1-1002",
                r"C:\Users\them\Downloads\b.exe",
                "bb",
                "{}",
            ))
            .unwrap();

        let mine = store.downloads_for("S-1-5-21-1-1001", 50).unwrap();
        assert_eq!(mine.len(), 1);
        assert!(mine[0].path.contains(r"\me\"));
        assert!(
            !store
                .add_download_action(
                    "S-1-5-21-1-1001",
                    r"C:\Users\them\Downloads\b.exe",
                    None,
                    "{}"
                )
                .unwrap(),
            "an action landed on somebody else's row"
        );
    }

    /// A row comes back with the counts of what its archive held and without
    /// the list of members, which is most of the row and which nothing that
    /// reads a row back needs. A record that is not JSON reads as none and
    /// does not fail the list.
    #[test]
    fn a_row_is_read_back_without_the_members_of_its_archive() {
        let store = Store::open_in_memory().unwrap();
        let me = "S-1-5-21-1-1001";
        let member = format!(r#"{{"name":"{}","bytes":1}}"#, "x".repeat(200));
        let listed = vec![member; 5000].join(",");
        let dissection = format!(
            r#"{{"archive":"a","scan":{{"threats":["{}"]}},"members":[{listed}],"totals":{{"files":5000}},"offered":true,"whole_archive":["w"],"unmatched":["u"]}}"#,
            "y".repeat(5000)
        );
        assert!(dissection.len() > 1_000_000, "the premise: a large record");
        for (path, sha256, record) in [
            (r"C:\D\big.zip", "aa", dissection.as_str()),
            (r"C:\D\damaged.zip", "bb", "not json at all"),
        ] {
            store
                .record_download_check(&download(me, path, sha256, "{}"))
                .unwrap();
            assert!(store
                .set_download_dissection(me, path, sha256, record)
                .unwrap());
        }

        let rows = store.downloads_for(me, 50).unwrap();
        assert_eq!(rows.len(), 2, "a damaged record failed the whole list");
        let big = rows.iter().find(|row| row.sha256 == "aa").unwrap();
        let kept = big.dissection.as_deref().unwrap();
        assert!(
            kept.len() < 200,
            "the members came back: {} bytes",
            kept.len()
        );
        assert!(kept.contains(r#""totals":{"files":5000}"#), "{kept}");
        assert!(kept.contains(r#""offered":true"#), "{kept}");
        assert!(
            !kept.contains("members") && !kept.contains("scan"),
            "{kept}"
        );
        let damaged = rows.iter().find(|row| row.sha256 == "bb").unwrap();
        assert_eq!(damaged.dissection, None);

        // The one-row read is the same shape.
        let one = store
            .download_at(me, r"C:\D\big.zip", None)
            .unwrap()
            .unwrap();
        assert_eq!(one.dissection, big.dissection);
    }

    /// One download is found by its path, newest content first or by its
    /// content, without reading every row to look for it, and only among the
    /// caller's own.
    #[test]
    fn one_download_is_found_by_its_path() {
        let store = Store::open_in_memory().unwrap();
        let me = "S-1-5-21-1-1001";
        let path = r"C:\Users\me\Downloads\setup.exe";
        store
            .record_download_check(&download(me, path, "aa", "first"))
            .unwrap();
        store
            .record_download_check(&download(me, path, "bb", "second"))
            .unwrap();
        store
            .record_download_check(&download("S-1-5-21-1-1002", path, "cc", "theirs"))
            .unwrap();

        let newest = store.download_at(me, &path.to_uppercase(), None).unwrap();
        assert_eq!(newest.map(|row| row.outcome).as_deref(), Some("second"));
        let by_content = store.download_at(me, path, Some("aa")).unwrap();
        assert_eq!(by_content.map(|row| row.outcome).as_deref(), Some("first"));
        assert!(store.download_at(me, path, Some("cc")).unwrap().is_none());
        assert!(store
            .download_at(me, r"C:\Users\me\Downloads\other.exe", None)
            .unwrap()
            .is_none());
        assert_eq!(store.download_count(me).unwrap(), 2);
        assert_eq!(store.download_count("S-1-5-21-1-1003").unwrap(), 0);
    }

    /// A person can take a row off their own history, and only their own.
    /// The row is the one for that path and that content, and no other.
    #[test]
    fn a_download_record_is_removed_for_its_owner_alone() {
        let store = Store::open_in_memory().unwrap();
        let (me, them) = ("S-1-5-21-1-1001", "S-1-5-21-1-1002");
        let path = r"C:\Users\Public\Downloads\setup.exe";
        for (sid, sha256) in [(me, "aa"), (me, "bb"), (them, "aa")] {
            store
                .record_download_check(&download(sid, path, sha256, "{}"))
                .unwrap();
        }
        // A row for a download that went before it could be checked has no
        // fingerprint, and is its own row.
        store
            .record_download_check(&download(me, path, "", "{}"))
            .unwrap();

        assert_eq!(
            store
                .remove_download(me, &path.to_uppercase(), "aa")
                .unwrap(),
            1
        );
        let left: Vec<String> = store
            .downloads_for(me, 50)
            .unwrap()
            .into_iter()
            .map(|row| row.sha256)
            .collect();
        assert_eq!(left.len(), 2);
        assert!(left.contains(&"bb".to_owned()) && left.contains(&String::new()));
        assert_eq!(
            store.download_count(them).unwrap(),
            1,
            "somebody else's row went with it"
        );

        // Already gone is not an error, and removes nothing more.
        assert_eq!(store.remove_download(me, path, "aa").unwrap(), 0);
        assert_eq!(store.remove_download(me, path, "").unwrap(), 1);
        assert_eq!(store.download_count(me).unwrap(), 1);
    }

    /// Clearing removes what was on record when the person decided, for that
    /// person alone. A check recorded after that moment stays.
    #[test]
    fn clearing_a_history_removes_only_what_was_on_record_by_then() {
        let store = Store::open_in_memory().unwrap();
        let (me, them) = ("S-1-5-21-1-1001", "S-1-5-21-1-1002");
        let pause = || std::thread::sleep(std::time::Duration::from_millis(50));
        for name in ["a.exe", "b.exe"] {
            store
                .record_download_check(&download(me, &format!(r"C:\D\{name}"), "aa", "{}"))
                .unwrap();
        }
        store
            .record_download_check(&download(them, r"C:\D\a.exe", "aa", "{}"))
            .unwrap();
        pause();
        let decided = crate::clock::now_utc_iso();
        pause();
        store
            .record_download_check(&download(me, r"C:\D\later.exe", "aa", "{}"))
            .unwrap();

        assert_eq!(store.clear_downloads(me, &decided).unwrap(), 2);
        let left = store.downloads_for(me, 50).unwrap();
        assert_eq!(left.len(), 1, "a check recorded afterwards was removed");
        assert_eq!(left[0].path, r"C:\D\later.exe");
        assert_eq!(
            store.download_count(them).unwrap(),
            1,
            "somebody else's history was cleared"
        );
        assert_eq!(store.clear_downloads(me, &decided).unwrap(), 0);
    }

    /// The answers recorded since a moment are one person's, and only those
    /// recorded after it. A check made again counts from when it was made
    /// again.
    #[test]
    fn the_answers_since_a_moment_are_the_callers_and_only_the_later_ones() {
        let store = Store::open_in_memory().unwrap();
        let (me, them) = ("S-1-5-21-1-1001", "S-1-5-21-1-1002");
        let pause = || std::thread::sleep(std::time::Duration::from_millis(50));
        store
            .record_download_check(&download(me, r"C:\D\old.exe", "aa", "old"))
            .unwrap();
        store
            .record_download_check(&download(me, r"C:\D\again.exe", "aa", "before"))
            .unwrap();
        pause();
        let looked = crate::clock::now_utc_iso();
        pause();
        store
            .record_download_check(&download(me, r"C:\D\new.exe", "aa", "new"))
            .unwrap();
        store
            .record_download_check(&download(me, r"C:\D\again.exe", "aa", "after"))
            .unwrap();
        store
            .record_download_check(&download(them, r"C:\D\theirs.exe", "aa", "theirs"))
            .unwrap();

        let mut since = store.download_outcomes_since(me, &looked).unwrap();
        since.sort();
        assert_eq!(since, ["after", "new"]);
        pause();
        assert!(store
            .download_outcomes_since(me, &crate::clock::now_utc_iso())
            .unwrap()
            .is_empty());
    }

    /// A store from before readings were kept, as an update finds it: swept,
    /// with a service recorded the old way, a copy of a per-account service
    /// under the name it had that day, and a sign-in entry.
    fn a_swept_version_six_store() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        migrate_through(&connection, &MIGRATIONS[..6]).unwrap();
        connection
            .execute(
                "INSERT INTO sweeps (at) VALUES ('2026-10-12T09:00:00.000Z')",
                [],
            )
            .unwrap();
        for (kind, name, detail) in [
            ("service", "Task Scheduler", "svchost.exe"),
            ("service", "Clipboard User Service_a74e8", "svchost.exe"),
            ("run_key", "Updater", "up.exe"),
        ] {
            connection
                .execute(
                    "INSERT INTO sightings
                       (kind, scope, name, detail, first_seen, last_seen, trust)
                     VALUES (?1, 'machine', ?2, ?3, '2026-10-12T09:00:00.000Z',
                             '2026-10-12T09:00:00.000Z', 'signed by Somebody Ltd')",
                    params![kind, name, detail],
                )
                .unwrap();
        }
        connection
    }

    fn read_as(kind: &str, version: i64) -> crate::changes::Reading {
        crate::changes::Reading::of(kind, version, format!("{kind} was not compared"))
    }

    fn readings_in(connection: &Connection) -> Vec<(String, i64)> {
        let mut statement = connection
            .prepare("SELECT kind, version FROM readings ORDER BY kind")
            .unwrap();
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        rows
    }

    /// A store that has been swept is told, by the step that adds readings,
    /// that it has recorded every kind there was. Without that its next sweep
    /// would take each kind for one it had never seen and compare nothing.
    #[test]
    fn a_version_six_store_that_has_been_swept_is_given_its_readings() {
        let connection = a_swept_version_six_store();
        assert!(
            connection
                .execute_batch("SELECT kind FROM readings")
                .is_err(),
            "the premise: a version six store has no readings table"
        );

        migrate_through(&connection, &MIGRATIONS[..7]).expect("the upgrade to seven should apply");
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 7);

        let mut expected: Vec<(String, i64)> = crate::changes::KINDS_BEFORE_READINGS
            .iter()
            .map(|kind| ((*kind).to_owned(), 1))
            .collect();
        expected.sort();
        assert_eq!(readings_in(&connection), expected);

        let kept: i64 = connection
            .query_row("SELECT COUNT(*) FROM sightings", [], |row| row.get(0))
            .unwrap();
        assert_eq!(kept, 3, "the baseline did not survive the upgrade");
    }

    /// A store that was never swept has recorded nothing, and is told nothing.
    #[test]
    fn a_version_six_store_that_was_never_swept_is_given_no_readings() {
        let connection = Connection::open_in_memory().unwrap();
        migrate_through(&connection, &MIGRATIONS[..6]).unwrap();
        migrate_through(&connection, &MIGRATIONS[..7]).unwrap();
        assert!(readings_in(&connection).is_empty());
    }

    /// The step that adds readings, stopped partway, is finished by the next
    /// start and does not write the six kinds twice.
    #[test]
    fn an_interrupted_upgrade_to_seven_is_finished_by_the_next_start() {
        let connection = a_swept_version_six_store();
        let interrupted = [(
            7,
            "CREATE TABLE readings (kind TEXT PRIMARY KEY, version INTEGER NOT NULL);
             INSERT INTO readings (kind, version) VALUES ('service', 1);
             this is where the process was stopped;",
        )];
        assert!(migrate_through(&connection, &interrupted).is_err());
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 6);

        migrate_through(&connection, &MIGRATIONS[..7])
            .expect("the next start should finish the upgrade");
        assert_eq!(readings_in(&connection).len(), 6);
    }

    /// The first sweep after a kind starts being read in a new way updates
    /// what is stored and reports nothing of that kind.
    ///
    /// The case this was built for: services inside svchost.exe were recorded
    /// as svchost.exe and are now recorded as the file they load there, and
    /// the copies Windows makes of its per-account services stopped being
    /// recorded under a name that changes at every sign-in. Compared the
    /// ordinary way that is 58 services "changed" and a handful "gone" on the
    /// machine this was written on, none of which happened.
    #[test]
    fn a_kind_read_in_a_new_way_is_recorded_once_without_being_compared() {
        use crate::changes::Change;

        let connection = a_swept_version_six_store();
        migrate(&connection).unwrap();
        let store = Store {
            connection: Mutex::new(connection),
        };
        let how = [read_as("service", 2), read_as("run_key", 1)];

        let sweep = store
            .sweep_read_as(
                &[
                    // Recorded differently, though nothing about it changed.
                    seen("service", "Task Scheduler", "schedsvc.dll"),
                    // New under the new reading. The dated copy is not seen.
                    seen("service", "Clipboard User Service", "cbdhsvc.dll"),
                    seen("run_key", "Updater", "up.exe"),
                    // A different kind, read as it always was.
                    seen("run_key", "Arrived", "new.exe"),
                ],
                &[],
                &how,
            )
            .unwrap();

        assert!(!sweep.baseline, "this store already had a baseline");
        let reported: Vec<(&str, Change)> = sweep
            .differences
            .iter()
            .map(|one| (one.name.as_str(), one.change))
            .collect();
        assert_eq!(
            reported,
            vec![("Arrived", Change::Appeared)],
            "only the kind read as before is compared"
        );
        assert_eq!(
            sweep.afresh,
            vec!["service was not compared".to_owned()],
            "and the person is told which kind was not"
        );

        // What is stored is what was seen: the next sweep finds nothing to
        // say about any of it, and says nothing about not comparing.
        let again = store
            .sweep_read_as(
                &[
                    seen("service", "Task Scheduler", "schedsvc.dll"),
                    seen("service", "Clipboard User Service", "cbdhsvc.dll"),
                    seen("run_key", "Updater", "up.exe"),
                    seen("run_key", "Arrived", "new.exe"),
                ],
                &[],
                &how,
            )
            .unwrap();
        assert!(again.differences.is_empty(), "{:?}", again.differences);
        assert!(again.afresh.is_empty(), "{:?}", again.afresh);

        // And from then on the kind is compared like any other.
        let swapped = store
            .sweep_read_as(
                &[
                    seen("service", "Task Scheduler", "planted.dll"),
                    seen("run_key", "Updater", "up.exe"),
                    seen("run_key", "Arrived", "new.exe"),
                ],
                &[],
                &how,
            )
            .unwrap();
        let change = |name: &str| {
            swapped
                .differences
                .iter()
                .find(|one| one.name == name)
                .map(|one| one.change)
        };
        assert_eq!(change("Task Scheduler"), Some(Change::Altered));
        assert_eq!(change("Clipboard User Service"), Some(Change::Vanished));
    }

    /// A kind that is looked at for the first time on a store that already
    /// has a baseline is recorded, not reported as having appeared.
    ///
    /// The first look used to be decided once for the whole store, so adding
    /// a kind reported everything of that kind as new.
    #[test]
    fn a_kind_looked_at_for_the_first_time_is_recorded_without_a_report() {
        use crate::changes::Change;

        let store = Store::open_in_memory().unwrap();
        let old = [read_as("service", 1)];
        store
            .sweep_read_as(&[seen("service", "One", "a")], &[], &old)
            .unwrap();

        let both = [read_as("service", 1), read_as("certificate", 1)];
        let first = store
            .sweep_read_as(
                &[
                    seen("service", "One", "a"),
                    seen("certificate", "Root A", "aa"),
                    seen("certificate", "Root B", "bb"),
                ],
                &[],
                &both,
            )
            .unwrap();
        assert!(first.differences.is_empty(), "{:?}", first.differences);
        assert_eq!(
            first.afresh,
            vec!["certificate was not compared".to_owned()]
        );

        let second = store
            .sweep_read_as(
                &[
                    seen("service", "One", "a"),
                    seen("certificate", "Root A", "aa"),
                    seen("certificate", "Root B", "bb"),
                    seen("certificate", "Root C", "cc"),
                ],
                &[],
                &both,
            )
            .unwrap();
        assert_eq!(second.differences.len(), 1, "{:?}", second.differences);
        assert_eq!(second.differences[0].name, "Root C");
        assert_eq!(second.differences[0].change, Change::Appeared);
    }

    /// A kind that was looked at and had nothing in it has still been looked
    /// at. The first thing of that kind to turn up is an appearance, not a
    /// first look, or the commonest empty kind (run-once entries) would hand
    /// its first arrival a free pass.
    #[test]
    fn a_kind_with_nothing_in_it_has_still_been_looked_at() {
        let store = Store::open_in_memory().unwrap();
        let how = [read_as("service", 1), read_as("run_once_key", 1)];
        store
            .sweep_read_as(&[seen("service", "One", "a")], &[], &how)
            .unwrap();

        let sweep = store
            .sweep_read_as(
                &[
                    seen("service", "One", "a"),
                    seen("run_once_key", "Planted", "x.exe"),
                ],
                &[],
                &how,
            )
            .unwrap();
        assert_eq!(sweep.differences.len(), 1, "{:?}", sweep.differences);
        assert_eq!(sweep.differences[0].name, "Planted");
        assert!(sweep.afresh.is_empty(), "{:?}", sweep.afresh);
    }

    /// A kind whose whole source could not be read has not been looked at,
    /// so the first sweep that can read it is its first look.
    #[test]
    fn a_kind_that_could_not_be_read_at_all_keeps_its_first_look() {
        let store = Store::open_in_memory().unwrap();
        let how = [read_as("service", 1), read_as("administrator", 1)];
        let unread = [crate::changes::Unreadable::of(
            "administrator",
            "the group did not answer",
        )];
        store
            .sweep_read_as(&[seen("service", "One", "a")], &unread, &how)
            .unwrap();
        store
            .sweep_read_as(&[seen("service", "One", "a")], &unread, &how)
            .unwrap();

        let sweep = store
            .sweep_read_as(
                &[
                    seen("service", "One", "a"),
                    vouched("administrator", "Ari", "can administer", "not a file"),
                ],
                &[],
                &how,
            )
            .unwrap();
        assert!(
            sweep.differences.is_empty(),
            "an account that was there all along was reported as new: {:?}",
            sweep.differences
        );
        assert_eq!(
            sweep.afresh,
            vec!["administrator was not compared".to_owned()]
        );
    }

    /// What was recorded afresh is not said to have been unreadable.
    ///
    /// The note about a kind recorded without being compared was said among
    /// the sources that could not be read, so the page showed "services were
    /// recorded afresh" under the heading "could not be read this time", and
    /// the Activity line counted it as a source that could not be read. It
    /// was read; only the comparison was held back.
    #[test]
    fn what_was_recorded_afresh_is_said_apart_from_what_could_not_be_read() {
        let store = Store::open_in_memory().unwrap();
        store
            .sweep_read_as(
                &[seen("service", "One", "a")],
                &[],
                &[read_as("service", 1)],
            )
            .unwrap();

        let sweep = store
            .sweep_read_as(
                &[seen("service", "One", "a")],
                &[crate::changes::Unreadable::of(
                    "scheduled_task",
                    "the task store would not open",
                )],
                &[read_as("service", 2)],
            )
            .unwrap();
        assert_eq!(
            sweep.unreadable,
            vec!["the task store would not open".to_owned()],
            "a kind that was read was said to be unreadable"
        );
        assert_eq!(sweep.afresh, vec!["service was not compared".to_owned()]);
    }

    /// The number a kind was recorded under only goes up. A sweep that names a
    /// lower one compares as usual and leaves the store where it was.
    #[test]
    fn a_lower_reading_neither_skips_the_comparison_nor_is_written_down() {
        let store = Store::open_in_memory().unwrap();
        store
            .sweep_read_as(
                &[seen("service", "One", "a")],
                &[],
                &[read_as("service", 2)],
            )
            .unwrap();

        let sweep = store
            .sweep_read_as(
                &[seen("service", "One", "b")],
                &[],
                &[read_as("service", 1)],
            )
            .unwrap();
        assert_eq!(sweep.differences.len(), 1, "{:?}", sweep.differences);
        assert_eq!(
            readings_in(&store.lock().unwrap()),
            vec![("service".to_owned(), 2)]
        );
    }

    fn watched(kind: &str, place: &str, what: &str) -> Watched {
        Watched {
            kind: kind.to_owned(),
            place: place.to_owned(),
            what: what.to_owned(),
        }
    }

    /// A store from before the watcher kept anything gains its memory, keeps
    /// what it already held, and starts with no scope looked at.
    #[test]
    fn a_version_seven_store_is_brought_up_to_eight_and_keeps_what_it_held() {
        let connection = a_swept_version_six_store();
        migrate_through(&connection, &MIGRATIONS[..7]).unwrap();
        assert!(
            connection
                .execute_batch("SELECT scope FROM watched_scopes")
                .is_err(),
            "the premise: a version seven store has no memory for the watcher"
        );

        migrate_through(&connection, &MIGRATIONS[..8]).expect("the upgrade to eight should apply");
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 8);
        let kept: i64 = connection
            .query_row("SELECT COUNT(*) FROM sightings", [], |row| row.get(0))
            .unwrap();
        assert_eq!(kept, 3, "the baseline did not survive the upgrade");
        assert_eq!(readings_in(&connection).len(), 6);

        // And the upgraded store is a working one, in which nothing has been
        // looked at yet: the first look after the update is a first look.
        let store = Store {
            connection: Mutex::new(connection),
        };
        assert_eq!(store.watched("machine").unwrap(), None);
        store
            .record_watched("machine", &[watched("service", "a", "x")], &[])
            .unwrap();
        assert_eq!(
            store.watched("machine").unwrap(),
            Some(vec![watched("service", "a", "x")])
        );
    }

    /// The step that adds the watcher's memory, stopped partway, is finished
    /// by the next start.
    #[test]
    fn an_interrupted_upgrade_to_eight_is_finished_by_the_next_start() {
        let connection = Connection::open_in_memory().unwrap();
        migrate_through(&connection, &MIGRATIONS[..7]).unwrap();
        let interrupted = [(
            8,
            "CREATE TABLE watched (scope TEXT NOT NULL);
             this is where the process was stopped;",
        )];
        assert!(migrate_through(&connection, &interrupted).is_err());
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 7);

        migrate_through(&connection, &MIGRATIONS[..8])
            .expect("the next start should finish the upgrade");
        connection
            .execute_batch(
                "SELECT scope, kind, place, what FROM watched;
                 SELECT scope, learned_at FROM watched_scopes;",
            )
            .expect("the tables the upgrade adds are there, whole");
    }

    /// Never looked at and looked at and found empty are different answers.
    /// The first is a scope to learn; in the second, anything is new.
    #[test]
    fn a_scope_never_looked_at_is_not_a_scope_found_empty() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.watched("S-1-5-21-1-1001").unwrap(), None);

        store.record_watched("S-1-5-21-1-1001", &[], &[]).unwrap();
        assert_eq!(store.watched("S-1-5-21-1-1001").unwrap(), Some(Vec::new()));
        assert_eq!(
            store.watched("S-1-5-21-1-1002").unwrap(),
            None,
            "looking at one account is not looking at another"
        );
    }

    /// The record takes additions and removals, one scope at a time, and
    /// forgetting it puts every scope back to never looked at.
    #[test]
    fn the_watchers_record_is_kept_per_scope_and_can_be_forgotten() {
        let store = Store::open_in_memory().unwrap();
        let one = watched("run_key", "hklm\\run", "Updater\u{0}up.exe");
        let two = watched("service", "hklm\\services\\thing", "Thing\u{0}thing.exe");

        store
            .record_watched("machine", &[one.clone(), two.clone(), one.clone()], &[])
            .unwrap();
        store
            .record_watched("S-1-5-21-1-1001", std::slice::from_ref(&one), &[])
            .unwrap();
        let mut machine = store.watched("machine").unwrap().unwrap();
        machine.sort_by(|a, b| a.kind.cmp(&b.kind));
        assert_eq!(machine, vec![one.clone(), two.clone()], "written once each");

        // Taken off one scope, and still on the other.
        store
            .record_watched("machine", &[], std::slice::from_ref(&one))
            .unwrap();
        assert_eq!(store.watched("machine").unwrap(), Some(vec![two]));
        assert_eq!(store.watched("S-1-5-21-1-1001").unwrap(), Some(vec![one]));

        store.forget_watched().unwrap();
        assert_eq!(store.watched("machine").unwrap(), None);
        assert_eq!(store.watched("S-1-5-21-1-1001").unwrap(), None);
    }
}
