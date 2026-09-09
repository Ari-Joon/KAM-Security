//! Local SQLite store, and the audit log that lives in it.
//!
//! The audit table is append-only, and that is enforced by the database rather
//! than by convention: `BEFORE UPDATE` and `BEFORE DELETE` triggers abort any
//! attempt to rewrite history. A bug elsewhere in the agent should not be able
//! to quietly erase the record of what it did.

use std::fmt;
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection};

use crate::audit::{AuditLog, Effect, Entry, Record};
use crate::{Error, Result};

/// Bumped whenever the schema below changes. Stored in `PRAGMA user_version`.
const SCHEMA_VERSION: i64 = 2;

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

/// Whether the protective work is running, as stored in `settings`.
///
/// Absent means on. A machine that has never been told otherwise is protected,
/// which is the only sensible default for a security tool and means an
/// unreadable or half-written setting cannot quietly leave somebody exposed.
pub const PROTECTION_SETTING: &str = "protection_enabled";

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

    connection
        .pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(to_db_error)?;
    Ok(())
}

fn to_db_error(error: rusqlite::Error) -> Error {
    Error::Database(error.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
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
