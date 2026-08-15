//! The shell's Rust half.
//!
//! The frontend is a web view and cannot open a named pipe, so every call to
//! the agent passes through a command here. That is deliberate rather than
//! incidental: it keeps the set of things the UI can ask for enumerated in one
//! reviewable place, mirroring `dispatch.rs` on the agent side.
//!
//! Nothing in this process is privileged. It runs as the desktop user and gets
//! served only because it is installed alongside the agent.

use kam_core::audit::Record;
use kam_ipc::{Request, Response, SystemStatus};
use kam_quarantine::Manifest;
use kam_storage::{AppFootprint, FootprintSummary, Orphan, OrphanSummary, Scan, Volume};

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
        } => Ok(ApplicationReport {
            apps,
            summary,
            orphans,
            orphan_summary,
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
            quarantine_path,
            list_quarantine,
            restore_quarantined,
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
