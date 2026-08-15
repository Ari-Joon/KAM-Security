//! The one place anything is ever removed from, or moved within, the system.
//!
//! Product rule: nothing is deleted. Every module routes destructive intent
//! through this crate, which stages the item, records everything needed to put
//! it back exactly as it was, and keeps it for thirty days. Purging afterwards
//! requires explicit confirmation.
//!
//! Storage reorganisation uses the same journal, so an accepted batch of moves
//! is reversible as a single operation.

use serde::{Deserialize, Serialize};

/// Everything required to restore one item to its original state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Opaque identifier; also the undo token recorded in the audit log.
    pub id: String,
    pub original_path: String,
    /// Security descriptor in SDDL form, so ACLs survive the round trip.
    pub original_sddl: String,
    /// Created, modified and accessed times as Windows FILETIME values.
    pub original_times: [u64; 3],
    /// BLAKE3 content hash, verified again before any restore.
    pub content_hash: String,
    /// Which module staged it, and the finding that justified doing so.
    pub reason: String,
}
