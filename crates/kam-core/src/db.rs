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
const SCHEMA_VERSION: i64 = 1;

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

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| Error::Database("the store lock was poisoned by an earlier panic".into()))
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
                    entry.detail,
                    entry.undo_token
                ],
            )
            .map_err(to_db_error)?;
        Ok(())
    }
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
