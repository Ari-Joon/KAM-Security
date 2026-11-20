//! The shell's Rust half.
//!
//! The frontend is a web view and cannot open a named pipe, so every call to
//! the agent passes through a command here. That is deliberate rather than
//! incidental: it keeps the set of things the UI can ask for enumerated in one
//! reviewable place, mirroring `dispatch.rs` on the agent side.
//!
//! Nothing in this process is privileged. It runs as the desktop user and gets
//! served only because it is installed alongside the agent.

mod archive;
pub mod consent;
mod context_menu;
mod downloads;
mod notice;
mod recycle;
mod remembered;
mod seen;
mod startup;
mod uninstall;
mod update;
mod winget;

use kam_core::audit::Record;
use kam_ipc::{Request, Response, SystemStatus};
use kam_quarantine::{Manifest, MoveRecord};
use kam_scanner::provenance::Report as ProvenanceReport;
use kam_scanner::{DefenderStatus, Threat};
use kam_storage::{
    AppFootprint, Download, DownloadSummary, DuplicateGroup, DuplicateSummary, FootprintSummary,
    OrganiseSummary, Orphan, OrphanSummary, Proposal, Scan, Volume,
};
use tauri::{Emitter, Manager};

/// Turn a response into the value a command promised, or a message for the UI.
///
/// Agent-side errors arrive as `Response::Error` and are already phrased for a
/// person, so they pass through unchanged.
fn unexpected(response: &Response) -> String {
    format!("the agent replied with something unexpected: {response:?}")
}

/// Run a command's work off the window's thread.
///
/// A plain `fn` command runs inside the handler WebView2 calls on the window's
/// own thread, so for as long as it runs nothing on screen can move: not the
/// window, not other commands' replies, not progress events, not the tray menu.
/// A full-drive scan held it for a minute, and on 23 Sep 2026 Windows closed
/// the window as not responding. So every command that waits on the agent, the
/// disk or another program is `async` and does its work here, on Tauri's pool
/// for blocking work. The few left as plain `fn` answer from memory.
async fn off_the_window<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(work)
        .await
        .map_err(|error| format!("the work stopped before it finished: {error}"))?
}

#[tauri::command]
async fn agent_status() -> Result<SystemStatus, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::GetSystemStatus).map_err(|error| error.to_string())? {
            Response::SystemStatus(status) => Ok(status),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

#[tauri::command]
async fn recent_audit(limit: u32) -> Result<Vec<Record>, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::GetRecentAudit { limit })
            .map_err(|error| error.to_string())?
        {
            Response::RecentAudit { entries } => Ok(entries),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

#[tauri::command]
async fn list_volumes() -> Result<Vec<Volume>, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::ListVolumes).map_err(|error| error.to_string())? {
            Response::Volumes { volumes } => Ok(volumes),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

/// Measure a directory tree.
///
/// Takes about a minute on a full system drive. The agent serves each
/// connection on its own thread and this waits off the window's thread, so
/// the window stays responsive while it runs.
#[tauri::command]
async fn scan_path(path: String) -> Result<Scan, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::ScanPath { path })
            .map_err(|error| error.to_string())?
        {
            Response::Scan(scan) => Ok(*scan),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

/// Read one folder for the map, below where a scan of its drive stops.
///
/// What a click on a rectangle with nothing sent beneath it asks for. The
/// agent decides what may be asked about and finds the folder itself.
#[tauri::command]
async fn scan_folder(path: String) -> Result<kam_storage::FolderScan, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::ScanFolder { path })
            .map_err(|error| error.to_string())?
        {
            Response::Folder(folder) => Ok(*folder),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

/// The person's own summaries of their scans of a drive, and what grew and
/// shrank between two of them: `later`, or the newest, against `earlier`, or
/// the one kept before it. The agent reads only the caller's.
#[tauri::command]
async fn get_growth(
    drive: String,
    later: Option<i64>,
    earlier: Option<i64>,
) -> Result<kam_storage::growth::Growth, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::GetGrowth {
            drive,
            later,
            earlier,
        })
        .map_err(|error| error.to_string())?
        {
            Response::Growth(growth) => Ok(*growth),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

/// Keep a page's latest result for the next time the page is opened, in the
/// person's own Local AppData. See `remembered`.
#[tauri::command]
async fn remember_result(kind: String, result: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        remembered::remember_in(&remembered::folder(), &kind, &result)
    })
    .await
    .map_err(|error| format!("it did not finish: {error}"))?
}

/// A page's latest kept result, `None` when none is kept, or why the one that
/// is kept could not be read back.
#[tauri::command]
async fn remembered_result(kind: String) -> Result<Option<String>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        remembered::recall_in(&remembered::folder(), &kind)
    })
    .await
    .map_err(|error| format!("it did not finish: {error}"))?
}

/// What every installed application really occupies.
///
/// Needs a privileged agent, and takes a couple of seconds — it reads the whole
/// master file table to answer.
#[tauri::command]
async fn list_applications(drive: String) -> Result<ApplicationReport, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::ListApplications { drive })
            .map_err(|error| error.to_string())?
        {
            Response::Applications {
                apps,
                summary,
                orphans,
                orphan_summary,
                downloads,
                download_summary,
                old_files,
                old_file_summary,
                timings,
            } => Ok(ApplicationReport {
                apps,
                summary,
                orphans,
                orphan_summary,
                downloads,
                download_summary: *download_summary,
                old_files,
                old_file_summary: *old_file_summary,
                timings: *timings,
            }),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

/// Everything one read of the master file table produced, in one reply.
#[derive(serde::Serialize)]
struct ApplicationReport {
    apps: Vec<AppFootprint>,
    summary: FootprintSummary,
    orphans: Vec<Orphan>,
    orphan_summary: OrphanSummary,
    downloads: Vec<Download>,
    download_summary: DownloadSummary,
    old_files: Vec<kam_storage::OldFile>,
    old_file_summary: kam_storage::OldFileSummary,
    timings: kam_storage::apps::Timings,
}

/// Every application the registry knows, without reading the disk.
///
/// Answers in about a fifth of a second against a second and a half for the
/// measured list, because it reads the uninstall keys and Steam's manifests and
/// nothing else. Neither needs privileges, which is why this runs here rather
/// than in the agent, and why the window can show the list before the
/// measurement has started.
///
/// Every size in the result is the installer's own claim. Nothing has been
/// measured, and the interface says so rather than showing a zero.
#[tauri::command]
async fn list_applications_preview() -> Result<Vec<AppFootprint>, String> {
    off_the_window(move || {
        Ok(kam_storage::apps::registry_listing(
            &kam_core::UserContext::current(),
        ))
    })
    .await
}

/// Byte-for-byte duplicate files.
///
/// Its own command rather than part of the survey: this one reads file
/// contents, so it takes tens of seconds where everything else takes three.
/// That is also why it streams its progress.
#[tauri::command]
async fn find_duplicates(
    app: tauri::AppHandle,
    drive: String,
    job: String,
) -> Result<Option<DuplicateReport>, String> {
    stream_job(
        app,
        job.clone(),
        Request::FindDuplicates { drive, job },
        |response| match response {
            Response::Duplicates { groups, summary } => {
                Ok(Some(DuplicateReport { groups, summary }))
            }
            Response::Stopped => Ok(None),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        },
    )
    .await
}

#[derive(serde::Serialize)]
struct DuplicateReport {
    groups: Vec<DuplicateGroup>,
    summary: DuplicateSummary,
}

/// A set of identical files as it stands once one copy has gone, or nothing
/// when one file is all that is left of it.
///
/// Worked out here, by the code that judged the set to begin with, so the page
/// never does this arithmetic a second way. It answers from what it is given
/// and touches nothing, which is why it does not go to the agent.
#[tauri::command]
fn duplicate_set_without(group: DuplicateGroup, path: String) -> Option<DuplicateGroup> {
    kam_storage::duplicates::without(&group, &path)
}

/// Ask Windows Defender to scan, and bring back what it found.
///
/// Runs in the agent because `MpCmdRun` wants to be LocalSystem, and streams
/// like the duplicate search because a full scan runs for hours and has to be
/// stoppable from the window that started it.
///
/// Defender is asked to *report*, not to act — see the request's own note. So a
/// result carrying detections is a list of things still sitting where they were,
/// and the decision about them comes back here.
#[tauri::command]
async fn defender_scan(
    app: tauri::AppHandle,
    kind: kam_scanner::defender_scan::ScanKind,
    job: String,
) -> Result<Option<kam_scanner::defender_scan::ScanOutcome>, String> {
    stream_job(
        app,
        job.clone(),
        Request::DefenderScan { kind, job },
        |response| match response {
            Response::DefenderScanned(outcome) => Ok(Some(outcome)),
            Response::Stopped => Ok(None),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        },
    )
    .await
}

/// Compare the machine with what it looked like last time.
///
/// The only call here that answers what is *different* rather than what is
/// true. Runs in the agent because the baseline has to live where a non-admin
/// cannot edit it.
#[tauri::command]
async fn sweep_for_changes() -> Result<kam_core::changes::Sweep, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::SweepForChanges).map_err(|error| error.to_string())? {
            Response::Changes(sweep) => Ok(*sweep),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

/// Read one earlier comparison's list again, as it was shown. Takes no new
/// comparison.
#[tauri::command]
async fn read_comparison(id: i64) -> Result<kam_core::changes::Kept, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::ReadComparison { id })
            .map_err(|error| error.to_string())?
        {
            Response::Comparison(kept) => Ok(*kept),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

/// Whether one copy of a duplicated file is still byte for byte the same as
/// the copy being kept, asked before it is sent to the Recycle Bin.
///
/// The list it was chosen from may be days old (Cleanup keeps it), and a copy
/// edited since is no longer a spare. Asked here, as the person, because it is
/// the window that recycles, with the same rule the agent applies before it
/// quarantines one.
#[tauri::command]
async fn check_still_twins(remove: String, keep: String) -> Result<(), String> {
    off_the_window(move || {
        kam_storage::duplicates::check_still_twins(
            &remove,
            &keep,
            &kam_core::UserContext::current(),
        )
    })
    .await
}

/// Send one thing to the Recycle Bin.
///
/// Done here rather than through the agent, and that is the point rather than a
/// convenience: the Recycle Bin is per user, so a LocalSystem delete lands in
/// SYSTEM's bin where the person cannot see it or get it back. This process
/// runs as them. See `recycle` for the rest of the reasoning.
///
/// `in_bin` is false when the item is gone but did not reach the bin, which
/// Windows does silently for items too large for it. The window must say so
/// rather than repeating the reassurance.
#[tauri::command]
async fn recycle_item(path: String) -> Result<RecycleOutcome, String> {
    off_the_window(move || {
        let outcome = recycle::to_recycle_bin(std::path::Path::new(&path))?;

        // Recorded after the fact, and only after it worked.
        //
        // The agent no longer witnesses this act, so the log would otherwise hold
        // some removals and not others with nothing marking which. Asking it to
        // record the report closes that, and the entry it writes says the window
        // reported it rather than that the agent did it.
        //
        // The order matters: a record written first would claim something that had
        // not happened yet, and a failure between the two would leave a log saying
        // a file went to the bin when it is still on disk. This way the log can
        // only ever lag reality, never lead it.
        //
        // A failure to record is not a failure to recycle, and reporting it as one
        // would be a lie in the other direction. It is logged where the developer
        // can see it and the person is told what actually happened to their file.
        if let Err(error) = kam_ipc::client::call(&Request::RecordRecycle {
            path,
            in_bin: outcome.in_bin,
        }) {
            eprintln!("the recycle could not be recorded in the audit log: {error}");
        }

        Ok(RecycleOutcome {
            in_bin: outcome.in_bin,
            warning: outcome.warning,
        })
    })
    .await
}

/// Send one thing to the Recycle Bin, or leave it exactly where it is.
///
/// For the list of large old files, where a file too large for the bin is the
/// ordinary case and not the rare one. [`recycle_item`] reports afterwards
/// that Windows deleted such a file outright. This stops Windows before it
/// does and says why the file is still there: see
/// `recycle::to_recycle_bin_or_leave`. Recorded as [`recycle_item`] records,
/// after it worked and for the reasons given there.
#[tauri::command]
async fn recycle_or_leave(path: String) -> Result<RecycleOutcome, String> {
    off_the_window(move || {
        let outcome = recycle::to_recycle_bin_or_leave(std::path::Path::new(&path))?;
        if let Err(error) = kam_ipc::client::call(&Request::RecordRecycle {
            path,
            in_bin: outcome.in_bin,
        }) {
            eprintln!("the recycle could not be recorded in the audit log: {error}");
        }
        Ok(RecycleOutcome {
            in_bin: outcome.in_bin,
            warning: outcome.warning,
        })
    })
    .await
}

/// For each item, whether this account could remove it itself.
///
/// Lets the window offer recycling where it will work and quarantine where it
/// will not, instead of offering both everywhere and failing half the time.
/// Asked of each item rather than of its folder (see
/// `recycle::deletable_by_this_account`), all in one call, and off the
/// window's thread, so a slow or networked path cannot freeze the window.
#[tauri::command]
async fn can_recycle_all(paths: Vec<String>) -> Result<Vec<bool>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        paths
            .iter()
            .map(|path| recycle::deletable_by_this_account(std::path::Path::new(path)))
            .collect()
    })
    .await
    .map_err(|error| format!("the check did not finish: {error}"))
}

#[derive(serde::Serialize)]
struct RecycleOutcome {
    in_bin: bool,
    warning: Option<String>,
}

/// Delete one quarantined item for good.
///
/// There is no undo, which is why the interface asks first and why this is a
/// separate command rather than a flag on restore.
#[tauri::command]
async fn delete_quarantined(id: String) -> Result<Removal, String> {
    off_the_window(move || {
        finish_removal(kam_ipc::client::call(&Request::DeleteQuarantined { id }))
    })
    .await
}

/// Delete everything currently held.
#[tauri::command]
async fn empty_quarantine() -> Result<Removal, String> {
    off_the_window(move || finish_removal(kam_ipc::client::call(&Request::EmptyQuarantine))).await
}

#[derive(serde::Serialize)]
struct Removal {
    items: usize,
    bytes_freed: u64,
    refused: Vec<String>,
}

fn finish_removal(reply: kam_core::Result<Response>) -> Result<Removal, String> {
    match reply.map_err(|error| error.to_string())? {
        Response::Deleted {
            items,
            bytes_freed,
            refused,
        } => Ok(Removal {
            items,
            bytes_freed,
            refused,
        }),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

/// Whether a weekly check is registered, and when it runs.
#[tauri::command]
async fn schedule() -> Result<kam_schedule::Schedule, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::GetSchedule).map_err(|error| error.to_string())? {
            Response::Schedule(schedule) => Ok(schedule),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

/// Turn the weekly check on or off.
///
/// Only the day and the hour travel. What gets run, and as whom, are the
/// agent's decision, because this registers something that runs elevated on a
/// timer.
#[tauri::command]
async fn set_schedule(
    enabled: bool,
    day: String,
    hour: u8,
) -> Result<kam_schedule::Schedule, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::SetSchedule { enabled, day, hour })
            .map_err(|error| error.to_string())?
        {
            Response::Schedule(schedule) => Ok(schedule),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

/// Run the check now rather than waiting for the schedule.
#[tauri::command]
async fn run_check() -> Result<Vec<kam_ipc::CheckFinding>, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::RunCheck).map_err(|error| error.to_string())? {
            Response::Checked { findings } => Ok(findings),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

/// Every cache and scratch directory holding anything, largest first.
#[tauri::command]
async fn survey_caches() -> Result<Vec<kam_storage::Cache>, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::SurveyCaches).map_err(|error| error.to_string())? {
            Response::Caches { caches } => Ok(caches),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

/// Empty one of them.
///
/// Only the id travels. The agent holds the catalogue and resolves the paths
/// itself, so nothing this process is told can widen what gets deleted.
/// Run one machine-wide change off the window's thread, with consent.
///
/// The permission prompt can sit on screen for as long as the person takes to
/// answer it, and a command running on the window's own thread would freeze
/// the window for all of that time.
async fn with_consent(request: Request) -> Result<Response, String> {
    tauri::async_runtime::spawn_blocking(move || consent::call(request))
        .await
        .map_err(|error| format!("the change did not finish: {error}"))?
}

#[tauri::command]
async fn clear_cache(id: String) -> Result<kam_storage::Cleared, String> {
    // A person's own caches are theirs to clear without asking anyone, as in
    // Disk Cleanup. Only a clear that reaches outside their profile asks.
    let machine_wide = kam_storage::caches::is_machine_wide(&id, &kam_core::UserContext::current());
    let response = if machine_wide {
        with_consent(Request::ClearCache { id }).await?
    } else {
        tauri::async_runtime::spawn_blocking(move || {
            kam_ipc::client::call(&Request::ClearCache { id }).map_err(|error| error.to_string())
        })
        .await
        .map_err(|error| format!("the clear did not finish: {error}"))??
    };
    match response {
        Response::CacheCleared(cleared) => Ok(cleared),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

/// Hold one redundant copy of a duplicated file.
///
/// Quarantine rather than deletion: the whole point of the analysis is that
/// being wrong about a duplicate costs data, so being wrong here costs a press
/// of "put back" instead.
#[tauri::command]
async fn quarantine_copy(
    path: String,
    keep: String,
    reason: String,
    chosen: bool,
) -> Result<Manifest, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::QuarantineCopy {
            path,
            reason,
            chosen,
            keep,
        })
        .map_err(|error| error.to_string())?
        {
            Response::Quarantined(manifest) => Ok(manifest),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

/// Move a leftover directory into quarantine.
///
/// The agent re-checks the path against its own fence, so this is a request
/// rather than an instruction.
#[tauri::command]
async fn quarantine_path(path: String, reason: String) -> Result<Manifest, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::QuarantinePath { path, reason })
            .map_err(|error| error.to_string())?
        {
            Response::Quarantined(manifest) => Ok(manifest),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

#[tauri::command]
async fn list_quarantine() -> Result<Vec<Manifest>, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::ListQuarantine).map_err(|error| error.to_string())? {
            Response::QuarantineList { items } => Ok(items),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

#[tauri::command]
async fn restore_quarantined(id: String) -> Result<Manifest, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::RestoreQuarantined { id })
            .map_err(|error| error.to_string())?
        {
            Response::Quarantined(manifest) => Ok(manifest),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

/// Open Explorer with a file or folder selected.
///
/// Deliberately done here rather than through the agent. The agent runs as
/// LocalSystem, and a window it launched would be an Explorer running as SYSTEM
/// on the user's desktop -- a privilege boundary crossed for a convenience.
/// The shell already runs as the user, which is who should be looking at their
/// own files.
#[tauri::command]
async fn reveal_in_explorer(path: String) -> Result<(), String> {
    off_the_window(move || {
        use std::os::windows::process::CommandExt;

        let target = std::path::Path::new(&path);
        if !target.is_absolute() {
            return Err("only an absolute path can be revealed".to_owned());
        }
        // A quote in the path would end the argument early and let the rest be read
        // as further switches to explorer.
        if path.contains('"') {
            return Err("that path cannot be opened safely".to_owned());
        }
        if !target.exists() {
            return Err(format!("{path} is no longer there"));
        }

        // explorer.exe parses its own command line rather than using argv, so the
        // argument is passed raw with the quoting it expects.
        std::process::Command::new("explorer.exe")
            .raw_arg(format!("/select,\"{path}\""))
            .spawn()
            .map_err(|error| format!("could not open Explorer: {error}"))?;
        Ok(())
    })
    .await
}

/// Turn the pointers some names are stored as into the names they point at.
///
/// A Store application registers its firewall rules under a pointer into its
/// own resources, `@{Microsoft.WindowsAlarms_...?ms-resource://...}`, where an
/// ordinary program writes a name. Looking one up means asking the package,
/// and a package is installed per person.
///
/// So this is done here and not in the agent, for the reason that keeps coming
/// round in this program: the wrong principal. The agent is LocalSystem, for
/// whom no Store application is installed, so every lookup failed there and
/// the Firewall page showed a seventh of its rules as raw pointers. The window
/// runs as the person. Checked on the machine this was written on: 43 of 65
/// such names resolve here, and the rest belong to versions that have since
/// been replaced, which nobody can look up and which are shown as the
/// package's own name.
///
/// The answers come back in the order asked. Nothing here is acted on: the
/// raw name stays the rule's identity, and this is only what is drawn.
#[tauri::command]
async fn display_names(names: Vec<String>) -> Result<Vec<String>, String> {
    off_the_window(move || {
        Ok(names
            .iter()
            .map(|name| kam_core::mui::display(name))
            .collect())
    })
    .await
}

#[tauri::command]
async fn find_organise_proposals(drive: String) -> Result<OrganiseReport, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::FindOrganiseProposals { drive })
            .map_err(|error| error.to_string())?
        {
            Response::Organise { proposals, summary } => Ok(OrganiseReport { proposals, summary }),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

#[derive(serde::Serialize)]
struct OrganiseReport {
    proposals: Vec<Proposal>,
    summary: OrganiseSummary,
}

#[tauri::command]
async fn apply_move(from: String, to: String) -> Result<MoveRecord, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::ApplyMove { from, to })
            .map_err(|error| error.to_string())?
        {
            Response::Moved(record) => Ok(record),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

#[tauri::command]
async fn undo_move(id: String) -> Result<MoveRecord, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::UndoMove { id }).map_err(|error| error.to_string())? {
            Response::Moved(record) => Ok(record),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

#[tauri::command]
async fn list_moves() -> Result<Vec<MoveRecord>, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::ListMoves).map_err(|error| error.to_string())? {
            Response::Moves { records } => Ok(records),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

#[tauri::command]
async fn defender_status() -> Result<DefenderReport, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::GetDefenderStatus).map_err(|e| e.to_string())? {
            Response::Defender { status, concerns } => Ok(DefenderReport { status, concerns }),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

#[derive(serde::Serialize)]
struct DefenderReport {
    status: DefenderStatus,
    concerns: Vec<String>,
}

#[tauri::command]
async fn defender_threats() -> Result<Vec<Threat>, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::GetDefenderThreats).map_err(|e| e.to_string())? {
            Response::DefenderThreats { threats } => Ok(threats),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

#[derive(serde::Serialize)]
struct BehaviourReport {
    observations: Vec<kam_scanner::behaviour::Observation>,
    watching: bool,
    since: Option<String>,
}

/// What the behaviour watcher has seen since the agent started.
///
/// Read-only, like everything the watcher exposes: it reports what appeared and
/// why, and there is deliberately no command that acts on the result.
#[tauri::command]
async fn behaviour_events() -> Result<BehaviourReport, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::GetBehaviourEvents).map_err(|e| e.to_string())? {
            Response::BehaviourEvents {
                observations,
                watching,
                since,
            } => Ok(BehaviourReport {
                observations,
                watching,
                since,
            }),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

/// Every browser extension installed, and what each one may read.
#[tauri::command]
async fn browser_extensions() -> Result<kam_scanner::extensions::Report, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::GetExtensions).map_err(|e| e.to_string())? {
            Response::Extensions(report) => Ok(report),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

/// Which of Defender's free hardening rules are actually switched on.
#[tauri::command]
async fn hardening() -> Result<kam_scanner::hardening::Report, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::GetHardening).map_err(|e| e.to_string())? {
            Response::Hardening(report) => Ok(*report),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

/// Turn one hardening protection on, or off.
///
/// The agent validates the id against its own catalogue before anything runs,
/// and answers with a fresh survey rather than an acknowledgement, so what the
/// window draws afterwards is what Defender actually reports.
#[tauri::command]
async fn set_hardening(
    id: String,
    wanted: kam_scanner::hardening::Wanted,
) -> Result<kam_scanner::hardening::Report, String> {
    match with_consent(Request::SetHardening { id, wanted }).await? {
        Response::Hardening(report) => Ok(*report),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

/// Whether the protective work is running.
#[tauri::command]
async fn protection() -> Result<bool, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::GetProtection).map_err(|e| e.to_string())? {
            Response::Protection { enabled } => Ok(enabled),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

/// Turn the protective work on or off.
///
/// The service keeps running either way. That is the point: it has to still be
/// there to be switched back on, and a security tool that could be shut down
/// over its own interface is one an attacker shuts down.
#[tauri::command]
async fn set_protection(enabled: bool) -> Result<bool, String> {
    match with_consent(Request::SetProtection { enabled }).await? {
        Response::Protection { enabled } => Ok(enabled),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

/// What decoys are planted, and anything that has read one.
#[tauri::command]
async fn canaries() -> Result<kam_canary::Report, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::GetCanaries).map_err(|e| e.to_string())? {
            Response::Canaries(report) => Ok(*report),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

/// Plant the decoys, or take them away.
#[tauri::command]
async fn set_canaries(planted: bool) -> Result<kam_canary::Report, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::SetCanaries { planted }).map_err(|e| e.to_string())? {
            Response::Canaries(report) => Ok(*report),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

/// Turn Windows' file-access auditing on or off.
///
/// The one machine-wide setting this product changes. It is behind its own
/// deliberate action in the window, and the agent records it both ways.
#[tauri::command]
async fn set_canary_auditing(enabled: bool) -> Result<kam_canary::Report, String> {
    match with_consent(Request::SetCanaryAuditing { enabled }).await? {
        Response::Canaries(report) => Ok(*report),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

/// Judge every executable that starts itself or arrived from outside.
///
/// Read-only by construction: the agent gathers evidence and says what it
/// means, and there is deliberately no counterpart command that acts on the
/// result.
#[tauri::command]
async fn survey_provenance(
    app: tauri::AppHandle,
    job: String,
) -> Result<Option<ProvenanceReport>, String> {
    stream_job(
        app,
        job.clone(),
        Request::SurveyProvenance { job },
        |response| {
            match response {
                Response::Provenance(report) => Ok(Some(report)),
                // Stopping is not a failure, so it comes back as an absent result
                // rather than an error the interface would have to render in red.
                Response::Stopped => Ok(None),
                Response::Error { message } => Err(message),
                other => Err(unexpected(&other)),
            }
        },
    )
    .await
}

/// Run a request that reports progress, forwarding each update to the window.
///
/// Progress arrives on the pipe as frames and leaves as Tauri events named
/// `job://<id>`, so several jobs can run without their updates being confused
/// for one another.
async fn stream_job<T: Send + 'static>(
    app: tauri::AppHandle,
    job: String,
    request: Request,
    finish: impl FnOnce(Response) -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    let channel = format!("job://{job}");
    tauri::async_runtime::spawn_blocking(move || {
        let response = kam_ipc::client::call_streaming(&request, |progress| {
            // An interface that has navigated away is not an error worth
            // failing the job over.
            let _ = app.emit(&channel, progress);
        })
        .map_err(|error| error.to_string())?;
        finish(response)
    })
    .await
    .map_err(|error| format!("the job did not finish: {error}"))?
}

/// What an application left behind after its uninstaller ran.
///
/// The paths come from the footprint measured before the uninstall, because
/// afterwards the registry entry is gone and there is nothing left to measure
/// from. The agent fences them regardless of what is sent.
///
/// The folders are the agent's to measure. The shortcuts are judged here,
/// by this process, because it is the person: where a shortcut leads and
/// whether that is still there are answered by Windows for whoever asks, and
/// the agent asking as LocalSystem could be told that a working shortcut
/// points at nothing. See `kam_storage::shortcuts`.
#[tauri::command]
async fn find_remnants(
    name: String,
    paths: Vec<String>,
    kinds: Vec<kam_storage::apps::LocationKind>,
) -> Result<kam_storage::remnants::Remnants, String> {
    off_the_window(move || {
        let used = paths.clone();
        match kam_ipc::client::call(&Request::FindRemnants { name, paths, kinds })
            .map_err(|error| error.to_string())?
        {
            Response::Remnants(report) => {
                // Not looked for while the program is still installed: the
                // answer would be its own working shortcuts.
                let left = if report.still_installed {
                    None
                } else {
                    kam_storage::remnants::shortcuts_left(&used, &kam_core::UserContext::current())
                };
                Ok((*report).with_shortcuts(left))
            }
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

#[tauri::command]
async fn firewall() -> Result<kam_firewall::policy::FirewallReport, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::GetFirewall).map_err(|e| e.to_string())? {
            Response::Firewall(report) => Ok(*report),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

#[tauri::command]
async fn connections() -> Result<kam_firewall::connections::ConnectionReport, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::GetConnections).map_err(|e| e.to_string())? {
            Response::Connections(report) => Ok(report),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

/// Where this PC's traffic is sent: the hosts file, hand-set DNS servers and
/// proxies. The agent reads the account's proxy from that account's own hive.
#[tauri::command]
async fn traffic_settings() -> Result<kam_scanner::traffic::Report, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::GetTrafficSettings).map_err(|e| e.to_string())? {
            Response::TrafficSettings(report) => Ok(*report),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

/// The trusted root certificates by store, each looked up in Microsoft's list
/// as Windows last fetched it.
#[tauri::command]
async fn root_certificates() -> Result<kam_scanner::roots::Report, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::GetRootCertificates).map_err(|e| e.to_string())? {
            Response::RootCertificates(report) => Ok(*report),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

/// Stop a program reaching the network.
///
/// The first command in the product that changes the machine. The agent
/// re-derives everything that matters — that the path names a real program,
/// and that the rule it creates is tagged as ours — rather than trusting what
/// the interface sent. Returns the rule name, which is how it is undone.
#[tauri::command]
async fn block_program(path: String) -> Result<String, String> {
    match with_consent(Request::BlockProgram { path }).await? {
        Response::Blocked { rule } => Ok(rule),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

/// Remove a block this product created. The agent refuses anything else.
#[tauri::command]
async fn unblock_program(rule: String) -> Result<(), String> {
    match with_consent(Request::UnblockProgram { rule }).await? {
        Response::Acknowledged => Ok(()),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

/// Ask a running job to stop.
#[tauri::command]
async fn cancel_job(job: String) -> Result<(), String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::CancelJob { job }).map_err(|e| e.to_string())? {
            Response::Acknowledged => Ok(()),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

/// Match the bundled YARA rules against files the agent identified.
///
/// This is the one examination that happens in the shell rather than the agent,
/// and that is deliberate: the rule engine carries a WebAssembly JIT, which has
/// no business inside a LocalSystem service. It works here because privilege is
/// needed to *find* these files, not to read them — see `kam-rules`.
///
/// The paths come from a provenance survey the agent produced moments earlier.
/// Nothing is trusted about them beyond what this process could already do for
/// itself: it reads files as the signed-in user, which is exactly the authority
/// the shell already has.
#[tauri::command]
async fn scan_rules(paths: Vec<String>) -> Result<kam_rules::RuleReport, String> {
    // Compiling rules and reading several hundred files takes seconds, so it
    // runs off the interface thread rather than freezing the window.
    tauri::async_runtime::spawn_blocking(move || {
        let engine = kam_rules::Engine::load().map_err(|error| error.to_string())?;
        Ok(engine.scan(&paths))
    })
    .await
    .map_err(|error| format!("the rule scan did not finish: {error}"))?
}

/// Whether a VirusTotal key has been stored, without revealing it.
///
/// The key is never sent back to the interface. There is no command that
/// returns it, and there should not be: the interface only ever needs to know
/// whether to show the box.
#[tauri::command]
fn virustotal_key_present() -> bool {
    kam_virustotal::key::is_present()
}

/// Store, replace, or (with an empty string) forget the VirusTotal key.
#[tauri::command]
fn set_virustotal_key(key: String) -> Result<bool, String> {
    kam_virustotal::key::store(&key).map_err(|error| error.to_string())?;
    Ok(kam_virustotal::key::is_present())
}

/// Ask VirusTotal about one file.
///
/// One file, on an explicit request. Never in bulk and never automatically:
/// this reaches a third party, and a free key allows four lookups a minute in
/// any case.
///
/// What crosses the network is the file's SHA-256 and nothing else. The file
/// is not uploaded — there is no code in `kam-virustotal` that could upload it
/// — because publishing someone's file to a third party is irreversible and is
/// not a thing to do on their behalf.
#[tauri::command]
async fn virustotal_lookup(path: String) -> Result<kam_virustotal::Verdict, String> {
    // Hashing reads the whole file and the request waits on the network, so
    // neither belongs on the interface thread.
    tauri::async_runtime::spawn_blocking(move || {
        let verdict = kam_virustotal::look_up_file(&path).map_err(|error| error.to_string())?;

        // Asking the agent to write it down, because the lookup happens here
        // and the audit log lives there. This is the one action in the product
        // that sends anything off the machine, so it is the one most worth a
        // record; a failure to record it is not worth failing the lookup over,
        // but it is worth saying out loud.
        if let Err(error) = kam_ipc::client::call(&Request::RecordLookup {
            sha256: verdict.sha256.clone(),
            outcome: format!(
                "{:?}, {} of {} engines flagged it",
                verdict.standing, verdict.malicious, verdict.engines
            ),
        }) {
            eprintln!("the VirusTotal lookup was not recorded in the audit log: {error}");
        }

        Ok(verdict)
    })
    .await
    .map_err(|error| format!("the lookup did not finish: {error}"))?
}

/// Run an application's own uninstaller.
///
/// The command comes back from the agent, having been read out of the
/// uninstall key, and is shown to the user before this is called. It runs here
/// rather than in the agent because an uninstaller needs a desktop to put its
/// window on, and a LocalSystem service does not have one.
///
/// The audit entry is written first. If the launch then fails the log says an
/// uninstaller was started when it was not, which is a smaller lie than the
/// reverse -- an application removed with no record of who removed it.
#[tauri::command]
async fn run_uninstaller(name: String, command: String) -> Result<(), String> {
    off_the_window(move || {
        let noted = kam_ipc::client::call(&Request::NoteUninstallLaunched {
            name,
            command: command.clone(),
        });
        if let Err(error) = noted {
            // Not fatal. Refusing to uninstall because the log is unreachable
            // would be the audit trail holding the machine hostage.
            eprintln!("could not record the uninstall in the audit log: {error}");
        }
        uninstall::run(&command)
    })
    .await
}

/// Everything the Downloads page draws: the history from the agent, the files
/// in the folder with no check yet, and what the watcher is doing.
///
/// Off the window's thread: it asks the agent and lists a folder.
#[tauri::command]
async fn downloads_page(app: tauri::AppHandle) -> Result<downloads::Page, String> {
    off_the_window(move || Ok(downloads::page(&app.state::<downloads::Downloads>()))).await
}

/// Check one file the way a new download is checked.
///
/// Streams like a Defender scan and can be stopped. Defender is asked to
/// report, so nothing is moved or deleted by this.
#[tauri::command]
async fn check_download(
    app: tauri::AppHandle,
    path: String,
    job: String,
) -> Result<Option<kam_scanner::downloads::DownloadRecord>, String> {
    let asked = path.clone();
    let checked_app = app.clone();
    stream_job(
        app,
        job.clone(),
        Request::CheckDownload {
            path,
            job,
            copy_of: None,
        },
        move |response| match response {
            Response::DownloadChecked(record) => {
                // It has been checked now, so why it was not checked when it
                // arrived no longer has anything to say.
                let downloads = checked_app.state::<downloads::Downloads>();
                downloads.forget_failure(&asked);
                downloads.forget_failure(&record.check.path);
                Ok(Some(*record))
            }
            Response::Stopped => Ok(None),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        },
    )
    .await
}

/// Quarantine one download. The agent fences it to the Downloads folder.
#[tauri::command]
async fn quarantine_download(path: String) -> Result<Manifest, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::QuarantineDownload { path })
            .map_err(|error| error.to_string())?
        {
            Response::Quarantined(manifest) => Ok(manifest),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

/// Remove one row from this person's download history, for good. The record
/// goes and the file is not touched. Answers with how many rows went, which
/// is none when it had already gone.
#[tauri::command]
async fn remove_download_record(path: String, sha256: String) -> Result<u64, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::RemoveDownloadRecord { path, sha256 })
            .map_err(|error| error.to_string())?
        {
            Response::DownloadRecordsRemoved { removed } => Ok(removed),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

/// Remove every row this person's download history held when the page read
/// it, at `up_to`, for good. A check recorded since then is kept. Answers
/// with how many rows went.
#[tauri::command]
async fn clear_download_records(up_to: String) -> Result<u64, String> {
    off_the_window(move || {
        match kam_ipc::client::call(&Request::ClearDownloadRecords { up_to })
            .map_err(|error| error.to_string())?
        {
            Response::DownloadRecordsRemoved { removed } => Ok(removed),
            Response::Error { message } => Err(message),
            other => Err(unexpected(&other)),
        }
    })
    .await
}

/// Take a zip apart: a private copy, the original quarantined first when
/// Defender flagged it, and every member with Defender's answer. Nothing is
/// extracted until [`extract_clean`]. The answer says what became of the
/// original whether or not it was stopped first.
#[tauri::command]
async fn dissect_archive(
    app: tauri::AppHandle,
    path: String,
    job: String,
) -> Result<downloads::Dissected, String> {
    off_the_window(move || downloads::dissect(&app, &path, &job)).await
}

/// Stop taking an archive apart, whichever half is doing the work.
///
/// The agent is told, as for any job, and so is this program: copying the
/// archive and quarantining its original happen here, before the agent has
/// heard of the job, and a stop sent only to the agent was accepted and then
/// ignored until Defender was running.
#[tauri::command]
async fn stop_dissection(app: tauri::AppHandle, job: String) -> Result<(), String> {
    off_the_window(move || {
        app.state::<downloads::Downloads>().stop(&job);
        // The job may not have reached the agent yet, or may have finished.
        let _ = kam_ipc::client::call(&Request::CancelJob { job });
        Ok(())
    })
    .await
}

/// The archive that is open, for a page that was left and has come back.
#[tauri::command]
async fn open_dissection(
    app: tauri::AppHandle,
    token: String,
) -> Result<Option<downloads::DissectionView>, String> {
    off_the_window(move || Ok(app.state::<downloads::Downloads>().view(&token))).await
}

/// Extract what Defender found nothing in, because the person said go.
#[tauri::command]
async fn extract_clean(
    app: tauri::AppHandle,
    token: String,
) -> Result<kam_scanner::downloads::Extraction, String> {
    off_the_window(move || downloads::extract(&app.state::<downloads::Downloads>(), &token)).await
}

/// Close a taken-apart archive without extracting, deleting the private copy.
#[tauri::command]
async fn discard_dissection(app: tauri::AppHandle, token: String) -> Result<(), String> {
    off_the_window(move || {
        downloads::discard(&app.state::<downloads::Downloads>(), &token);
        Ok(())
    })
    .await
}

/// Check every file in Downloads that is not checked yet, one after another,
/// as one job. Returns once it is under way: the page follows it from there,
/// and it goes on if the page is left or the window is closed.
#[tauri::command]
async fn check_backlog(app: tauri::AppHandle) -> Result<(), String> {
    off_the_window(move || downloads::check_backlog(&app)).await
}

/// Stop that job: it ends before its next file, and the check it has in hand
/// is cancelled in the agent.
#[tauri::command]
async fn stop_backlog(app: tauri::AppHandle) -> Result<(), String> {
    off_the_window(move || {
        downloads::stop_backlog(&app.state::<downloads::Downloads>());
        Ok(())
    })
    .await
}

/// Let go of what that job came to, once it has been read.
#[tauri::command]
async fn close_backlog(app: tauri::AppHandle) -> Result<(), String> {
    off_the_window(move || {
        app.state::<downloads::Downloads>().close_backlog();
        Ok(())
    })
    .await
}

/// How many download results this person has not looked at yet: flagged by
/// Defender, and checks that did not finish, recorded since they last opened
/// Active downloads. When that cannot be told the answer says so, and why,
/// and is never a count of nothing. See `seen.rs`.
#[tauri::command]
async fn downloads_unseen() -> Result<seen::Unseen, String> {
    off_the_window(|| Ok(seen::unseen())).await
}

/// Put it on record that Active downloads is in front of the person now,
/// which is what clears that count. Answers with when it last was.
#[tauri::command]
async fn downloads_looked() -> Result<seen::Looked, String> {
    off_the_window(seen::looked).await
}

/// Add or remove the right-click entries.
#[tauri::command]
async fn set_context_menu(enabled: bool) -> Result<context_menu::MenuState, String> {
    off_the_window(move || context_menu::set(enabled)).await
}

/// The next file somebody asked about from outside the window, taken once.
/// `archive_free` is whether the page can open an archive now: a request to
/// take one apart waits while another is open.
#[tauri::command]
async fn take_launch(
    app: tauri::AppHandle,
    archive_free: bool,
) -> Result<Option<context_menu::Launch>, String> {
    off_the_window(move || {
        Ok(app
            .state::<downloads::Downloads>()
            .take_launch(archive_free))
    })
    .await
}

/// Whether such a request is waiting, so the window can open on Downloads.
#[tauri::command]
async fn launch_waiting(app: tauri::AppHandle) -> Result<bool, String> {
    off_the_window(move || Ok(app.state::<downloads::Downloads>().has_launch())).await
}

/// Which installed apps winget, Windows' own package tool, says have a newer
/// version. Runs winget as the person, only when asked, and installs nothing.
/// See `winget`.
#[tauri::command]
async fn newer_versions() -> Result<winget::Asked, String> {
    off_the_window(|| Ok(winget::ask())).await
}

/// Version of the protocol this build speaks, so the UI can say plainly when it
/// and the agent disagree rather than silently mis-rendering.
#[tauri::command]
fn protocol_version() -> u32 {
    kam_ipc::PROTOCOL_VERSION
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
/// Whether this launch turned starting at sign-in on by default.
struct FirstRun(bool);

/// Whether KAM Security starts when this person signs in.
#[tauri::command]
fn start_at_sign_in(first_run: tauri::State<'_, FirstRun>) -> startup::StartState {
    startup::state(first_run.0)
}

/// Turn starting at sign-in on or off.
#[tauri::command]
fn set_start_at_sign_in(enabled: bool) -> Result<startup::StartState, String> {
    startup::set(enabled)
}

/// Whether a newer release has been published. See `update.rs`.
///
/// Off the interface thread: it waits on the network for up to twenty seconds,
/// and every command that does not do this freezes the window for as long as
/// it runs.
#[tauri::command]
async fn check_for_update() -> Result<update::UpdateCheck, String> {
    tauri::async_runtime::spawn_blocking(|| update::check(env!("CARGO_PKG_VERSION")))
        .await
        .map_err(|error| format!("the update check did not finish: {error}"))
}

/// Open a release page in the person's browser.
///
/// Checked here rather than trusted from the window: the address came out of a
/// network response, and this is the only link the check is allowed to open.
#[tauri::command]
fn open_release_page(app: tauri::AppHandle, url: String) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;

    if !update::is_our_release_page(&url) {
        return Err(format!("{url} is not one of this program's release pages"));
    }
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|error| error.to_string())
}

mod taskbar_icon;
mod tray;

pub fn run() {
    // Before anything else, and before any window exists: the identity
    // Windows groups this program's windows, shortcuts and notifications
    // under. See `notice.rs`.
    notice::claim_identity();

    tauri::Builder::default()
        // Registered before anything else, deliberately. A second launch hands
        // its arguments to the instance already running and exits immediately,
        // so this has to be in place before that instance has spent anything on
        // a window or a tray icon.
        //
        // Without it a second launch is invisible: closing the window leaves
        // this program in the notification area, so clicking the shortcut again
        // looks like starting it fresh and is really starting it twice. The
        // taskbar shows one window, because the first instance has none, while
        // the notification area shows two icons — which is exactly how the bug
        // was reported. Two shells also means two pipe clients competing for
        // the agent's connection slots for no benefit whatever.
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            // "Check with KAM Security" or "Extract with KAM Security" from
            // Explorer: open on the Downloads page at that file.
            if let Some(launch) = context_menu::launch_from(&argv) {
                downloads::open_on(app, launch);
                return;
            }
            // A second start from the sign-in entry (after an update, say)
            // should not open the window; any other second start is somebody
            // clicking the shortcut, and should.
            if !argv.iter().any(|arg| arg == startup::BACKGROUND) {
                tray::show_window(app);
            }
        }))
        .setup(|app| {
            tray::install(app.handle())?;
            app.manage(FirstRun(startup::apply_first_run_default()));
            app.manage(downloads::Downloads::default());

            // The first copy can be started from the right-click menu too.
            let arguments: Vec<String> = std::env::args().collect();
            let launch = context_menu::launch_from(&arguments);
            let asked = launch.is_some();
            if let Some(launch) = launch {
                app.state::<downloads::Downloads>().set_launch(launch);
            }

            // Watching Downloads, on threads of its own. It waits on Windows
            // and costs nothing while nothing arrives.
            downloads::start_watching(app.handle().clone());

            // Registry and file work kept off the window's thread: the
            // right-click entries, where download results are counted from
            // on a first run, the Start menu shortcut notifications need,
            // and any working copy a previous run left behind.
            let _ = std::thread::Builder::new()
                .name("kam-first-run".to_owned())
                .spawn(|| {
                    context_menu::apply_at_start();
                    seen::start_counting();
                    if let Err(error) = notice::ensure_shortcut() {
                        eprintln!("{error}");
                    }
                    archive::discard_leftovers();
                });

            // Started at sign-in: the icon only, no window, which is what makes
            // being there from sign-in cost nothing. Otherwise open the window
            // as usual. It is not created from the configuration, so that a
            // background start never builds a WebView just to destroy it.
            let background = std::env::args().any(|arg| arg == startup::BACKGROUND);
            if !background || asked {
                tray::show_window(app.handle());
            }
            Ok(())
        })
        .on_window_event(tray::on_window_event)
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            agent_status,
            recent_audit,
            list_volumes,
            scan_path,
            scan_folder,
            get_growth,
            remember_result,
            remembered_result,
            list_applications,
            list_applications_preview,
            find_duplicates,
            duplicate_set_without,
            defender_scan,
            defender_status,
            defender_threats,
            behaviour_events,
            browser_extensions,
            hardening,
            set_hardening,
            protection,
            set_protection,
            canaries,
            set_canaries,
            set_canary_auditing,
            survey_provenance,
            cancel_job,
            find_remnants,
            firewall,
            connections,
            traffic_settings,
            root_certificates,
            block_program,
            unblock_program,
            scan_rules,
            virustotal_key_present,
            set_virustotal_key,
            virustotal_lookup,
            find_organise_proposals,
            apply_move,
            undo_move,
            list_moves,
            quarantine_path,
            quarantine_copy,
            check_still_twins,
            survey_caches,
            clear_cache,
            schedule,
            set_schedule,
            run_check,
            list_quarantine,
            restore_quarantined,
            delete_quarantined,
            empty_quarantine,
            sweep_for_changes,
            read_comparison,
            recycle_item,
            recycle_or_leave,
            can_recycle_all,
            reveal_in_explorer,
            display_names,
            run_uninstaller,
            protocol_version,
            check_for_update,
            open_release_page,
            start_at_sign_in,
            set_start_at_sign_in,
            downloads_page,
            check_download,
            quarantine_download,
            remove_download_record,
            clear_download_records,
            dissect_archive,
            stop_dissection,
            open_dissection,
            extract_clean,
            discard_dissection,
            check_backlog,
            stop_backlog,
            close_backlog,
            downloads_unseen,
            downloads_looked,
            set_context_menu,
            take_launch,
            launch_waiting,
            newer_versions
        ])
        .build(tauri::generate_context!())
        .unwrap_or_else(|error| {
            // Nothing can be shown to the user without a window, so failing
            // loudly on stderr is the best available.
            eprintln!("could not start the KAM Security shell: {error}");
            std::process::exit(1);
        })
        .run(|_app, event| {
            // Destroying the last window would normally end the program, which
            // would take the tray icon with it. Holding the loop open is what
            // makes "close to the notification area" mean anything.
            //
            // `code` distinguishes the two cases: `None` is Tauri noticing the
            // last window went away, `Some` is somebody actually choosing Quit.
            // Preventing both would make the program unquittable.
            if let tauri::RunEvent::ExitRequested { api, code, .. } = event {
                if code.is_none() {
                    api.prevent_exit();
                }
            }
        });
}
