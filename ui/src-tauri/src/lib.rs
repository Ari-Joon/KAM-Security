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
use kam_scanner::provenance::Report as ProvenanceReport;
use kam_scanner::{DefenderStatus, Threat};
use kam_storage::{
    AppFootprint, Download, DownloadSummary, DuplicateGroup, DuplicateSummary, FootprintSummary,
    OrganiseSummary, Orphan, OrphanSummary, Proposal, Scan, Volume,
};
use tauri::Emitter;

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

/// Every cache and scratch directory holding anything, largest first.
#[tauri::command]
fn survey_caches() -> Result<Vec<kam_storage::Cache>, String> {
    match kam_ipc::client::call(&Request::SurveyCaches).map_err(|error| error.to_string())? {
        Response::Caches { caches } => Ok(caches),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

/// Empty one of them.
///
/// Only the id travels. The agent holds the catalogue and resolves the paths
/// itself, so nothing this process is told can widen what gets deleted.
#[tauri::command]
fn clear_cache(id: String) -> Result<kam_storage::Cleared, String> {
    match kam_ipc::client::call(&Request::ClearCache { id }).map_err(|error| error.to_string())? {
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
fn quarantine_copy(path: String, reason: String) -> Result<Manifest, String> {
    match kam_ipc::client::call(&Request::QuarantineCopy { path, reason })
        .map_err(|error| error.to_string())?
    {
        Response::Quarantined(manifest) => Ok(manifest),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
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
#[tauri::command]
fn find_remnants(
    name: String,
    paths: Vec<String>,
    kinds: Vec<kam_storage::apps::LocationKind>,
) -> Result<kam_storage::remnants::Remnants, String> {
    match kam_ipc::client::call(&Request::FindRemnants { name, paths, kinds })
        .map_err(|error| error.to_string())?
    {
        Response::Remnants(report) => Ok(*report),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

#[tauri::command]
fn firewall() -> Result<kam_firewall::policy::FirewallReport, String> {
    match kam_ipc::client::call(&Request::GetFirewall).map_err(|e| e.to_string())? {
        Response::Firewall(report) => Ok(*report),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

#[tauri::command]
fn connections() -> Result<kam_firewall::connections::ConnectionReport, String> {
    match kam_ipc::client::call(&Request::GetConnections).map_err(|e| e.to_string())? {
        Response::Connections(report) => Ok(report),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

/// Stop a program reaching the network.
///
/// The first command in the product that changes the machine. The agent
/// re-derives everything that matters — that the path names a real program,
/// and that the rule it creates is tagged as ours — rather than trusting what
/// the interface sent. Returns the rule name, which is how it is undone.
#[tauri::command]
fn block_program(path: String) -> Result<String, String> {
    match kam_ipc::client::call(&Request::BlockProgram { path }).map_err(|e| e.to_string())? {
        Response::Blocked { rule } => Ok(rule),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

/// Remove a block this product created. The agent refuses anything else.
#[tauri::command]
fn unblock_program(rule: String) -> Result<(), String> {
    match kam_ipc::client::call(&Request::UnblockProgram { rule }).map_err(|e| e.to_string())? {
        Response::Acknowledged => Ok(()),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

/// Ask a running job to stop.
#[tauri::command]
fn cancel_job(job: String) -> Result<(), String> {
    match kam_ipc::client::call(&Request::CancelJob { job }).map_err(|e| e.to_string())? {
        Response::Acknowledged => Ok(()),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
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
        kam_virustotal::look_up_file(&path).map_err(|error| error.to_string())
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
mod tray;

pub fn run() {
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
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            tray::show_window(app);
        }))
        .setup(|app| {
            tray::install(app.handle())?;
            Ok(())
        })
        .on_window_event(tray::on_window_event)
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
            survey_provenance,
            cancel_job,
            find_remnants,
            firewall,
            connections,
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
            survey_caches,
            clear_cache,
            list_quarantine,
            restore_quarantined,
            reveal_in_explorer,
            run_uninstaller,
            protocol_version
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
