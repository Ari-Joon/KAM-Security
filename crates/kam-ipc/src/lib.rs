//! The contract between the unprivileged shell and the SYSTEM agent.
//!
//! Transport is a named pipe carrying length-prefixed JSON. The pipe's DACL
//! restricts it to the interactive user and Administrators, and the agent
//! verifies the connecting process image before accepting any request.
//!
//! Keeping the surface small and explicitly enumerated is the point: the agent
//! runs as SYSTEM, so every variant added here is new attack surface.

pub mod client;
pub mod frame;
pub mod pipe;

use kam_core::audit::Record;
use kam_quarantine::{Manifest, MoveRecord};
use kam_scanner::provenance::Report as ProvenanceReport;
use kam_scanner::{DefenderStatus, Threat};
use kam_storage::{
    AppFootprint, Download, DownloadSummary, DuplicateGroup, DuplicateSummary, FootprintSummary,
    OrganiseSummary, Orphan, OrphanSummary, Proposal, Scan, Volume,
};
use serde::{Deserialize, Serialize};

/// Bumped whenever `Request` or `Response` changes shape. The shell refuses to
/// talk to an agent reporting a different version rather than guessing.
pub const PROTOCOL_VERSION: u32 = 1;

/// Pipe name. The `\\.\pipe\` prefix is added by the transport.
pub const PIPE_NAME: &str = "kam-security-agent";

/// Pipe instances the server keeps available.
///
/// This is not a nicety. `CreateNamedPipeW` refuses with `ERROR_PIPE_BUSY` once
/// this many instances exist, so a value of one means the accept loop cannot
/// create the next instance while a connection is still being served — it spins
/// on the error instead. The agent's own concurrency cap is kept in step with
/// it, so the limit is enforced deliberately rather than by a Win32 refusal.
pub const MAX_PIPE_INSTANCES: u32 = 16;

/// Maximum accepted frame size. Guards against a malformed length prefix
/// causing an enormous allocation in the SYSTEM process.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// Largest number of audit rows the agent will return in one response.
///
/// The store lives where only the agent can read it, so the shell has to ask
/// for history rather than opening the database. Capping the answer keeps a
/// careless caller from requesting the entire log in a single frame.
pub const MAX_AUDIT_ROWS: u32 = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Liveness and version handshake.
    GetSystemStatus,
    /// Most recent audit entries, newest first. `limit` is clamped to
    /// [`MAX_AUDIT_ROWS`] by the agent rather than rejected.
    GetRecentAudit { limit: u32 },
    /// Drives on the machine, with capacity and free space.
    ListVolumes,
    /// Measure everything beneath `path`. Seconds on a full drive, so callers
    /// should expect this one to take a while.
    ScanPath { path: String },
    /// What every installed application really occupies on `drive`, and which
    /// directories nothing installed accounts for. Needs the master file table,
    /// so the agent must be privileged.
    ListApplications { drive: String },
    /// Move a leftover directory into quarantine. The agent re-checks the path
    /// against its own fence before touching anything.
    QuarantinePath { path: String, reason: String },
    /// Everything currently held in quarantine.
    ListQuarantine,
    /// Put a quarantined item back where it came from.
    RestoreQuarantined { id: String },
    /// Find byte-for-byte duplicate files on `drive`.
    ///
    /// Separate from the survey because it reads file contents rather than the
    /// master file table, and takes tens of seconds rather than three.
    FindDuplicates { drive: String },
    /// Loose files that belong in a folder the user already keeps.
    FindOrganiseProposals { drive: String },
    /// Carry out one proposal. The agent re-checks the fence before moving.
    ApplyMove { from: String, to: String },
    /// Put a moved file back.
    UndoMove { id: String },
    /// Every move recorded, newest first.
    ListMoves,
    /// What Microsoft Defender is doing, read from Defender.
    GetDefenderStatus,
    /// Everything Defender has detected and still has a record of.
    GetDefenderThreats,
    /// Judge every executable that starts itself or arrived from outside.
    SurveyProvenance,
    /// Record that the shell launched an application's own uninstaller.
    ///
    /// The agent does not run it -- an uninstaller needs the user's desktop,
    /// which a service does not have -- but the audit log is the record of what
    /// happened on this machine, and this belongs in it.
    NoteUninstallLaunched { name: String, command: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    SystemStatus(SystemStatus),
    RecentAudit {
        entries: Vec<Record>,
    },
    Volumes {
        volumes: Vec<Volume>,
    },
    /// Boxed because a scan result dwarfs every other variant, and an enum is
    /// as large as its largest member wherever it is passed.
    Scan(Box<Scan>),
    Applications {
        apps: Vec<AppFootprint>,
        summary: FootprintSummary,
        orphans: Vec<Orphan>,
        orphan_summary: OrphanSummary,
        downloads: Vec<Download>,
        download_summary: DownloadSummary,
    },
    Duplicates {
        groups: Vec<DuplicateGroup>,
        summary: DuplicateSummary,
    },
    Organise {
        proposals: Vec<Proposal>,
        summary: OrganiseSummary,
    },
    Moved(MoveRecord),
    Defender {
        status: DefenderStatus,
        /// Phrased for a person, produced by the agent so the interface cannot
        /// invent a concern the data does not support.
        concerns: Vec<String>,
    },
    DefenderThreats {
        threats: Vec<Threat>,
    },
    Provenance(ProvenanceReport),
    Moves {
        records: Vec<MoveRecord>,
    },
    Quarantined(Manifest),
    /// Nothing to return beyond "recorded".
    Acknowledged,
    QuarantineList {
        items: Vec<Manifest>,
    },
    /// The agent declined or failed. `message` is safe to show to the user.
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    pub protocol_version: u32,
    pub agent_version: String,
    /// True when the agent is hosted by the service control manager rather
    /// than running as a foreground console process for development.
    pub running_as_service: bool,
    pub hostname: String,
}
