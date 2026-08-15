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
