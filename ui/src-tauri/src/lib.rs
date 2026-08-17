//! The shell's Rust half.
//!
//! The frontend is a web view and cannot open a named pipe, so every call to
//! the agent passes through a command here. That is deliberate rather than
//! incidental: it keeps the set of things the UI can ask for enumerated in one
//! reviewable place, mirroring `dispatch.rs` on the agent side.
//!
//! Nothing in this process is privileged. It runs as the desktop user and gets
//! served only because it is installed alongside the agent.

mod uninstall;

use kam_core::audit::Record;
use kam_ipc::{Request, Response, SystemStatus};
use kam_quarantine::{Manifest, MoveRecord};
use kam_scanner::{DefenderStatus, Threat};
use kam_storage::{
    AppFootprint, Download, DownloadSummary, DuplicateGroup, DuplicateSummary, FootprintSummary,
    OrganiseSummary, Orphan, OrphanSummary, Proposal, Scan, Volume,
};

/// Turn a response into the value a command promised, or a message for the UI.
///
/// Agent-side errors arrive as `Response::Error` and are already phrased for a
/// person, so they pass through unchanged.
fn unexpected(response: &Response) -> String {
    format!("the agent replied with something unexpected: {response:?}")
}

#[tauri::command]
fn agent_status() -> Result<SystemStatus, String> {
    match kam_ipc::client::call(&Request::GetSystemStatus).map_err(|error| error.to_string())? {
        Response::SystemStatus(status) => Ok(status),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

#[tauri::command]
fn recent_audit(limit: u32) -> Result<Vec<Record>, String> {
    match kam_ipc::client::call(&Request::GetRecentAudit { limit })
        .map_err(|error| error.to_string())?
    {
        Response::RecentAudit { entries } => Ok(entries),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

#[tauri::command]
fn list_volumes() -> Result<Vec<Volume>, String> {
    match kam_ipc::client::call(&Request::ListVolumes).map_err(|error| error.to_string())? {
        Response::Volumes { volumes } => Ok(volumes),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

/// Measure a directory tree.
///
/// Takes about a minute on a full system drive, and the agent serves each
/// connection on its own thread, so the shell stays responsive while this runs.
#[tauri::command]
fn scan_path(path: String) -> Result<Scan, String> {
    match kam_ipc::client::call(&Request::ScanPath { path }).map_err(|error| error.to_string())? {
        Response::Scan(scan) => Ok(*scan),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

/// What every installed application really occupies.
///
/// Needs a privileged agent, and takes a couple of seconds — it reads the whole
/// master file table to answer.
#[tauri::command]
fn list_applications(drive: String) -> Result<ApplicationReport, String> {
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
        } => Ok(ApplicationReport {
            apps,
            summary,
            orphans,
            orphan_summary,
            downloads,
            download_summary,
        }),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
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
}

/// Byte-for-byte duplicate files.
///
/// Its own command rather than part of the survey: this one reads file
/// contents, so it takes tens of seconds where everything else takes three.
#[tauri::command]
fn find_duplicates(drive: String) -> Result<DuplicateReport, String> {
    match kam_ipc::client::call(&Request::FindDuplicates { drive })
        .map_err(|error| error.to_string())?
    {
        Response::Duplicates { groups, summary } => Ok(DuplicateReport { groups, summary }),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

#[derive(serde::Serialize)]
struct DuplicateReport {
    groups: Vec<DuplicateGroup>,
    summary: DuplicateSummary,
}

/// Move a leftover directory into quarantine.
///
/// The agent re-checks the path against its own fence, so this is a request
/// rather than an instruction.
#[tauri::command]
fn quarantine_path(path: String, reason: String) -> Result<Manifest, String> {
    match kam_ipc::client::call(&Request::QuarantinePath { path, reason })
        .map_err(|error| error.to_string())?
    {
        Response::Quarantined(manifest) => Ok(manifest),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

#[tauri::command]
fn list_quarantine() -> Result<Vec<Manifest>, String> {
    match kam_ipc::client::call(&Request::ListQuarantine).map_err(|error| error.to_string())? {
        Response::QuarantineList { items } => Ok(items),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

#[tauri::command]
fn restore_quarantined(id: String) -> Result<Manifest, String> {
    match kam_ipc::client::call(&Request::RestoreQuarantined { id })
        .map_err(|error| error.to_string())?
    {
        Response::Quarantined(manifest) => Ok(manifest),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

/// Open Explorer with a file or folder selected.
///
/// Deliberately done here rather than through the agent. The agent runs as
/// LocalSystem, and a window it launched would be an Explorer running as SYSTEM
/// on the user's desktop -- a privilege boundary crossed for a convenience.
/// The shell already runs as the user, which is who should be looking at their
/// own files.
#[tauri::command]
fn reveal_in_explorer(path: String) -> Result<(), String> {
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
}

#[tauri::command]
fn find_organise_proposals(drive: String) -> Result<OrganiseReport, String> {
    match kam_ipc::client::call(&Request::FindOrganiseProposals { drive })
        .map_err(|error| error.to_string())?
    {
        Response::Organise { proposals, summary } => Ok(OrganiseReport { proposals, summary }),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

#[derive(serde::Serialize)]
struct OrganiseReport {
    proposals: Vec<Proposal>,
    summary: OrganiseSummary,
}

#[tauri::command]
fn apply_move(from: String, to: String) -> Result<MoveRecord, String> {
    match kam_ipc::client::call(&Request::ApplyMove { from, to })
        .map_err(|error| error.to_string())?
    {
        Response::Moved(record) => Ok(record),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

#[tauri::command]
fn undo_move(id: String) -> Result<MoveRecord, String> {
    match kam_ipc::client::call(&Request::UndoMove { id }).map_err(|error| error.to_string())? {
        Response::Moved(record) => Ok(record),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

#[tauri::command]
fn list_moves() -> Result<Vec<MoveRecord>, String> {
    match kam_ipc::client::call(&Request::ListMoves).map_err(|error| error.to_string())? {
        Response::Moves { records } => Ok(records),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

#[tauri::command]
fn defender_status() -> Result<DefenderReport, String> {
    match kam_ipc::client::call(&Request::GetDefenderStatus).map_err(|e| e.to_string())? {
        Response::Defender { status, concerns } => Ok(DefenderReport { status, concerns }),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

#[derive(serde::Serialize)]
struct DefenderReport {
    status: DefenderStatus,
    concerns: Vec<String>,
}

#[tauri::command]
fn defender_threats() -> Result<Vec<Threat>, String> {
    match kam_ipc::client::call(&Request::GetDefenderThreats).map_err(|e| e.to_string())? {
        Response::DefenderThreats { threats } => Ok(threats),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
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
fn run_uninstaller(name: String, command: String) -> Result<(), String> {
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
}

/// Version of the protocol this build speaks, so the UI can say plainly when it
/// and the agent disagree rather than silently mis-rendering.
#[tauri::command]
fn protocol_version() -> u32 {
    kam_ipc::PROTOCOL_VERSION
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            agent_status,
            recent_audit,
            list_volumes,
            scan_path,
            list_applications,
            find_duplicates,
            defender_status,
            defender_threats,
            find_organise_proposals,
            apply_move,
            undo_move,
            list_moves,
            quarantine_path,
            list_quarantine,
            restore_quarantined,
            reveal_in_explorer,
            run_uninstaller,
            protocol_version
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|error| {
            // Nothing can be shown to the user without a window, so failing
            // loudly on stderr is the best available.
            eprintln!("could not start the KAM Security shell: {error}");
            std::process::exit(1);
        });
}
