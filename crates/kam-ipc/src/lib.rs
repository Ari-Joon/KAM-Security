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
use kam_core::Progress;
use kam_firewall::connections::ConnectionReport;
use kam_firewall::policy::FirewallReport;
use kam_quarantine::{Manifest, MoveRecord};
use kam_scanner::behaviour::Observation;
use kam_scanner::provenance::Report as ProvenanceReport;
use kam_scanner::{DefenderStatus, Threat};
use kam_storage::apps::LocationKind;
use kam_storage::remnants::Remnants as RemnantReport;
use kam_storage::{
    AppFootprint, Cache, Cleared, Download, DownloadSummary, DuplicateGroup, DuplicateSummary,
    FootprintSummary, OrganiseSummary, Orphan, OrphanSummary, Proposal, Scan, Volume,
};
use serde::{Deserialize, Serialize};

/// Bumped whenever `Request` or `Response` changes shape. The shell refuses to
/// talk to an agent reporting a different version rather than guessing.
pub const PROTOCOL_VERSION: u32 = 10;

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

/// What the agent writes back.
///
/// A request used to be answered by exactly one frame. Long jobs may now send
/// any number of [`Reply::Progress`] frames first, and every exchange ends with
/// exactly one [`Reply::Done`] — so a client reads frames until it sees one,
/// and a client that does not care about progress can discard the rest.
///
/// Wrapping rather than adding a `Response::Progress` variant keeps the two
/// kinds of message distinguishable at the type level: a progress frame can
/// never be mistaken for a result, and forgetting to handle one is a
/// compile error rather than a hang.
///
/// Tagged *adjacently* — `{"kind": "done", "body": {…}}` — rather than
/// internally. An internal tag flattens the wrapped value into the same JSON
/// object, and `Response` carries its own `kind` field, so the two collided and
/// every reply failed to deserialise. Adjacent tagging nests the payload
/// instead, which cannot collide with anything the inner type does now or
/// later.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "body", rename_all = "snake_case")]
pub enum Reply {
    Progress(Progress),
    Done(Response),
}

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
    /// Delete a quarantined item permanently, now, because somebody asked.
    ///
    /// The thirty-day retention exists so a mistake has time to be noticed, and
    /// nothing here deletes anything on its own. This is the other case: the
    /// owner of the machine deciding about something they put here themselves.
    /// It cannot be undone, and the interface says so before sending it.
    DeleteQuarantined { id: String },
    /// Delete everything currently held. Same rules, once per item.
    EmptyQuarantine,
    /// Record that a file's hash was sent to VirusTotal.
    ///
    /// The lookup happens in the window, because the VirusTotal client is
    /// deliberately kept out of the privileged process. This is how the one
    /// action that sends anything off the machine still reaches the audit log.
    ///
    /// Carries a hash and a one-line outcome and nothing else: a client that
    /// could write free-form entries could write a plausible history of things
    /// that never happened.
    RecordLookup { sha256: String, outcome: String },
    /// Whether a weekly check is registered, and when it runs.
    GetSchedule,
    /// Register the weekly check, or take it away.
    ///
    /// The program the task starts and the account it runs as are both decided
    /// by the agent: this creates something that runs elevated on a timer, and
    /// a request that could name the program would be a request to run anything
    /// at all, on a schedule, as the person using the machine.
    SetSchedule {
        enabled: bool,
        day: String,
        hour: u8,
    },
    /// Run the check now, without waiting for the schedule.
    RunCheck,
    /// Every cache and scratch directory that currently holds anything.
    SurveyCaches,
    /// Empty one of them.
    ///
    /// `id` names an entry in the agent's own compiled-in catalogue. There is
    /// deliberately no variant that carries a path: this runs as LocalSystem,
    /// and a request that could name a directory to empty would be a request to
    /// empty any directory on the machine.
    ClearCache { id: String },
    /// Move one redundant copy of a duplicated file into quarantine.
    ///
    /// Separate from `QuarantinePath`, which fences to leftover directories
    /// directly inside a data root. This one fences to a *file* in a folder the
    /// person owns, and the agent re-derives that from the path rather than
    /// trusting the list the interface displayed.
    QuarantineCopy { path: String, reason: String },
    /// Find byte-for-byte duplicate files on `drive`.
    ///
    /// Separate from the survey because it reads file contents rather than the
    /// master file table, and takes tens of seconds rather than three.
    FindDuplicates { drive: String, job: String },
    /// Loose files that belong in a folder the user already keeps.
    FindOrganiseProposals { drive: String },
    /// Carry out one proposal. The agent re-checks the fence before moving.
    ApplyMove { from: String, to: String },
    /// Put a moved file back.
    UndoMove { id: String },
    /// Every move recorded, newest first.
    ListMoves,
    /// What an application left behind after its uninstaller ran.
    ///
    /// `paths` are the locations measured for it before the uninstall, which
    /// the agent re-checks and fences: anything outside the folders
    /// applications install into is refused and reported.
    FindRemnants {
        name: String,
        paths: Vec<String>,
        kinds: Vec<LocationKind>,
    },
    /// Windows Defender Firewall's profile state and every rule it holds.
    GetFirewall,
    /// Every open socket, joined to the program that owns it.
    GetConnections,
    /// Stop a program reaching the network, with an outbound block rule.
    BlockProgram { path: String },
    /// Remove a block rule this product created. Refuses anything else.
    UnblockProgram { rule: String },
    /// Ask a running job to stop. Answered on its own connection, because the
    /// one carrying the job is busy streaming its progress.
    ///
    /// Unknown ids are acknowledged rather than refused: by the time a person
    /// presses the button the job may already have finished, and that is not
    /// something to show them an error about.
    CancelJob { job: String },
    /// What Microsoft Defender is doing, read from Defender.
    GetDefenderStatus,
    /// Everything Defender has detected and still has a record of.
    GetDefenderThreats,
    /// Judge every executable that starts itself or arrived from outside.
    ///
    /// `job` names this run so it can be stopped; it is chosen by the caller
    /// and only has to be unique among jobs in flight.
    SurveyProvenance { job: String },
    /// Record that the shell launched an application's own uninstaller.
    ///
    /// The agent does not run it -- an uninstaller needs the user's desktop,
    /// which a service does not have -- but the audit log is the record of what
    /// happened on this machine, and this belongs in it.
    NoteUninstallLaunched { name: String, command: String },
    /// What the behaviour watcher has seen: startup entries that appeared while
    /// the agent was running and matched one of the shapes unwanted software
    /// uses to run unseen. Read-only, and never carries anything the agent acts
    /// on.
    GetBehaviourEvents,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
// Adjacently tagged, not internally tagged, and the difference is not
// cosmetic.
//
// With `tag = "kind"` alone, serde flattens a newtype variant's payload
// alongside the discriminant, so `Quarantined(Manifest)` serialised as
// `{"kind":"quarantined", ..., "kind":<ItemKind>, ...}` -- because `Manifest`
// has its own `kind` field. The shell then refused the frame with "duplicate
// field `kind`" and quarantine could not be used at all.
//
// Adding `content = "body"` nests the payload under its own key instead, so no
// field of any wrapped struct can ever collide with the discriminant again.
// Renaming `Manifest::kind` would have fixed the one case and left the trap
// armed for the next struct that happens to have a field called `kind`.
#[serde(tag = "kind", content = "body", rename_all = "snake_case")]
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
        /// How long each stage took. Shown, so "it feels slow" can become a
        /// number somebody can argue with.
        timings: kam_storage::apps::Timings,
    },
    Duplicates {
        groups: Vec<DuplicateGroup>,
        summary: DuplicateSummary,
    },
    Schedule(kam_schedule::Schedule),
    /// What a check found, most serious first. Empty means nothing to report,
    /// which is a result rather than a failure.
    Checked {
        findings: Vec<CheckFinding>,
    },
    Caches {
        caches: Vec<Cache>,
    },
    CacheCleared(Cleared),
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
    Remnants(Box<RemnantReport>),
    Firewall(Box<FirewallReport>),
    Connections(ConnectionReport),
    /// A firewall rule was created; the name is how it is undone.
    Blocked {
        rule: String,
    },
    /// The job stopped because it was asked to. Not an error, and the
    /// interface should not present it as one.
    Stopped,
    Moves {
        records: Vec<MoveRecord>,
    },
    Quarantined(Manifest),
    /// Items deleted for good, and what that freed.
    Deleted {
        items: usize,
        bytes_freed: u64,
        /// Anything that could not be removed, phrased for a person.
        refused: Vec<String>,
    },
    /// Nothing to return beyond "recorded".
    Acknowledged,
    QuarantineList {
        items: Vec<Manifest>,
    },
    /// What the behaviour watcher has recorded, newest first.
    BehaviourEvents {
        observations: Vec<Observation>,
        /// Whether the watcher is running at all. False means the list is a
        /// history, not a live view.
        watching: bool,
        /// When watching began, so "nothing seen" reads as "nothing since".
        since: Option<String>,
    },
    /// The agent declined or failed. `message` is safe to show to the user.
    Error {
        message: String,
    },
}

/// One thing a check thought was worth mentioning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckFinding {
    pub summary: String,
    /// True when this is a state to be corrected rather than a note.
    pub serious: bool,
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Every response has to survive the trip it is built for.
    ///
    /// This exists because one did not. `Response::Quarantined(Manifest)` could
    /// be sent and never received: internal tagging flattened the manifest's
    /// fields next to the discriminant, the manifest had its own `kind` field,
    /// and the shell rejected the frame with "duplicate field `kind`". Nothing
    /// caught it, because every test constructed values in memory and none of
    /// them went through serde and back.
    fn round_trip(response: Response) {
        let json = serde_json::to_string(&response).expect("should serialise");

        // Adjacent tagging keeps the payload in its own object, so the
        // discriminant can appear exactly once at the top level whatever the
        // payload contains.
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should be JSON");
        let object = parsed.as_object().expect("a response is an object");
        assert!(object.contains_key("kind"), "no discriminant in {json}");

        // The real assertion: it must come back. Serde rejects duplicate keys
        // on the way in, which is precisely how the original bug surfaced.
        serde_json::from_str::<Response>(&json)
            .unwrap_or_else(|error| panic!("could not read it back: {error}\n{json}"));
    }

    fn manifest() -> kam_quarantine::Manifest {
        kam_quarantine::Manifest {
            id: "abc123".to_owned(),
            original_path: r"C:\Users\someone\Downloads\thing.exe".to_owned(),
            // The field that collided with the discriminant.
            kind: kam_quarantine::ItemKind::File,
            bytes: 4096,
            quarantined_at: 1_700_000_000,
            reason: "leftover from software uninstalled long ago".to_owned(),
            restored: false,
        }
    }

    #[test]
    fn a_quarantine_manifest_survives_the_wire() {
        // The exact frame that could not be delivered.
        round_trip(Response::Quarantined(manifest()));
    }

    #[test]
    fn a_manifests_own_kind_does_not_collide_with_the_discriminant() {
        let json = serde_json::to_string(&Response::Quarantined(manifest())).unwrap();
        assert_eq!(
            json.matches("\"kind\"").count(),
            2,
            "expected the response discriminant and the manifest's own kind, \
             nested rather than flattened: {json}"
        );
        assert!(
            json.contains("\"body\""),
            "the payload should be nested under its own key: {json}"
        );
    }

    #[test]
    fn every_simple_response_survives_the_wire() {
        round_trip(Response::Acknowledged);
        round_trip(Response::Stopped);
        round_trip(Response::Error {
            message: "something went wrong".to_owned(),
        });
        round_trip(Response::Blocked {
            rule: "KAM Security: block thing.exe".to_owned(),
        });
        round_trip(Response::QuarantineList {
            items: vec![manifest()],
        });
        round_trip(Response::Connections(Default::default()));
        round_trip(Response::BehaviourEvents {
            observations: Vec::new(),
            watching: true,
            since: Some("2026-09-06T14:12:02.417Z".to_owned()),
        });
        round_trip(Response::SystemStatus(SystemStatus {
            protocol_version: PROTOCOL_VERSION,
            agent_version: "0.1.0".to_owned(),
            running_as_service: true,
            hostname: "machine".to_owned(),
        }));
    }

    #[test]
    fn a_progress_frame_is_never_mistaken_for_a_result() {
        // The two are distinguished at the type level so a client cannot read
        // one as the other; this checks the wire agrees.
        let progress = Reply::Progress(kam_core::Progress {
            stage: "Examining programs".to_owned(),
            done: 12,
            total: Some(400),
            detail: None,
        });
        let done = Reply::Done(Response::Acknowledged);

        let progress_json = serde_json::to_string(&progress).unwrap();
        let done_json = serde_json::to_string(&done).unwrap();

        assert!(progress_json.contains("\"progress\""));
        assert!(done_json.contains("\"done\""));

        for json in [&progress_json, &done_json] {
            serde_json::from_str::<Reply>(json)
                .unwrap_or_else(|error| panic!("could not read {json}: {error}"));
        }
    }
}
