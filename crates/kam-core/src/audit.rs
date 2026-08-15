//! Append-only record of everything the agent does with its privileges.
//!
//! Product rule: every privileged action is logged, and the user can read the
//! log. Phase 1 backs this with SQLite; the trait exists now so callers are
//! written against it from the first line of feature code.

use serde::Serialize;

/// Whether an entry describes something that changed the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Effect {
    /// Read-only: a scan, an enumeration, a status query.
    Observed,
    /// The system was changed, and the change can be undone.
    Changed,
    /// The agent declined to act. The reason belongs in `detail`.
    Refused,
}

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    /// Module that acted, e.g. `storage`, `firewall`, `scanner`.
    pub module: &'static str,
    /// Short action name, e.g. `quarantine_file`.
    pub action: &'static str,
    pub effect: Effect,
    /// Human-readable specifics, shown verbatim in the UI.
    pub detail: String,
    /// Identifier that reverses this entry, when one exists.
    pub undo_token: Option<String>,
}

pub trait AuditLog: Send + Sync {
    fn record(&self, entry: Entry) -> crate::Result<()>;
}
