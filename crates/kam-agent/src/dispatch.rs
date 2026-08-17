//! Maps an incoming [`Request`] onto the module that serves it.
//!
//! Keeping dispatch in one file means the audit rule can be checked by reading
//! one file. That rule is narrower than "log everything":
//!
//! - Anything that **changes the system**, or is **refused**, is recorded.
//! - Anything the user **asked for deliberately** is recorded, even when it only
//!   reads — a full-drive scan belongs in the history of what happened.
//! - **Background chatter is not**: status polls and history reloads happen every
//!   few seconds on their own, and recording them would bury everything else.

use kam_core::audit::{Effect, Entry};
use kam_core::Store;
use kam_ipc::{Request, Response, SystemStatus};

use crate::server;
use crate::Mode;

/// Everything a handler is allowed to reach.
#[derive(Debug)]
pub struct Context {
    pub mode: Mode,
    pub store: Store,
    pub quarantine: kam_quarantine::Store,
}

impl Context {
    pub fn audit(
        &self,
        module: &'static str,
        action: &'static str,
        effect: Effect,
        detail: String,
    ) {
        server::record(
            &self.store,
            Entry {
                module,
                action,
                effect,
                detail,
                undo_token: None,
            },
        );
    }

    /// As [`Self::audit`], but recording how to undo what just happened.
    pub fn audit_with_token(
        &self,
        module: &'static str,
        action: &'static str,
        effect: Effect,
        detail: String,
        undo_token: Option<String>,
    ) {
        server::record(
            &self.store,
            Entry {
                module,
                action,
                effect,
                detail,
                undo_token,
            },
        );
    }

    fn running_as_service(&self) -> bool {
        self.mode == Mode::Service
    }
}

pub fn handle(request: Request, context: &Context) -> Response {
    match request {
        Request::GetSystemStatus => {
            let status = SystemStatus {
                protocol_version: kam_ipc::PROTOCOL_VERSION,
                agent_version: env!("CARGO_PKG_VERSION").to_owned(),
                running_as_service: context.running_as_service(),
                hostname: hostname(),
            };
            // Not audited. The shell polls this to keep its connection
            // indicator honest, so auditing it would add a row every few
            // seconds and bury the entries that describe real actions. The rule
            // is: the log records what the agent *does to the system*, and what
            // it refuses. Answering questions about itself is neither.
            Response::SystemStatus(status)
        }

        Request::GetRecentAudit { limit } => {
            // Clamped rather than refused: a caller asking for more history
            // than exists is not doing anything wrong, and an error here would
            // be a worse experience than a shorter list.
            let limit = limit.min(kam_ipc::MAX_AUDIT_ROWS);
            match context.store.recent_audit(limit as usize) {
                Ok(entries) => {
                    // Deliberately not audited. Reading the log is not an action
                    // on the system, and recording every read would bury the
                    // entries that matter under entries about looking at them.
                    Response::RecentAudit { entries }
                }
                Err(error) => {
                    tracing::error!(%error, "could not read the audit log");
                    Response::Error {
                        message: "the audit log could not be read".to_owned(),
                    }
                }
            }
        }

        Request::ListVolumes => match kam_storage::list_volumes() {
            Ok(volumes) => Response::Volumes { volumes },
            Err(error) => {
                tracing::error!(%error, "could not enumerate volumes");
                Response::Error {
                    message: "the drives on this machine could not be listed".to_owned(),
                }
            }
        },

        Request::ScanPath { path } => scan_path(&path, context),

        Request::ListApplications { drive } => {
            let Some(letter) = drive.chars().next().filter(|c| c.is_ascii_alphabetic()) else {
                return Response::Error {
                    message: "give a drive letter, such as C:".to_owned(),
                };
            };

            match kam_storage::apps::survey(letter.to_ascii_uppercase(), now_seconds()) {
                Ok(report) => {
                    context.audit(
                        "storage",
                        "survey",
                        Effect::Observed,
                        format!(
                            "surveyed {letter}: — {} applications using {}, {} leftover directories holding {}, {} downloads holding {}",
                            report.summary.applications,
                            human_bytes(report.summary.measured_bytes),
                            report.orphan_summary.found,
                            human_bytes(report.orphan_summary.total_bytes),
                            report.download_summary.found,
                            human_bytes(report.download_summary.total_bytes)
                        ),
                    );
                    Response::Applications {
                        apps: report.apps,
                        summary: report.summary,
                        orphans: report.orphans,
                        orphan_summary: report.orphan_summary,
                        downloads: report.downloads,
                        download_summary: report.download_summary,
                    }
                }
                Err(error) => {
                    tracing::info!(%error, "could not survey storage");
                    Response::Error {
                        message: format!(
                            "application sizes need the master file table, which the agent                              could not read: {error}"
                        ),
                    }
                }
            }
        }

        Request::QuarantinePath { path, reason } => quarantine_path(&path, &reason, context),

        Request::ListQuarantine => match context.quarantine.list() {
            Ok(items) => Response::QuarantineList { items },
            Err(error) => {
                tracing::error!(%error, "could not list quarantine");
                Response::Error {
                    message: "the quarantine store could not be read".to_owned(),
                }
            }
        },

        Request::RestoreQuarantined { id } => match context.quarantine.restore(&id) {
            Ok(manifest) => {
                context.audit_with_token(
                    "quarantine",
                    "restore",
                    Effect::Changed,
                    format!("restored {} to {}", manifest.id, manifest.original_path),
                    Some(manifest.id.clone()),
                );
                Response::Quarantined(manifest)
            }
            Err(error) => {
                context.audit(
                    "quarantine",
                    "restore",
                    Effect::Refused,
                    format!("could not restore {id}: {error}"),
                );
                Response::Error {
                    message: error.to_string(),
                }
            }
        },
    }
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// Move a leftover directory out of the way.
///
/// The path arrives as a string from a client. The agent runs as LocalSystem,
/// so it is re-checked against the fence here rather than trusted because the
/// UI only offered safe ones -- a different client need not be so polite.
fn quarantine_path(path: &str, reason: &str, context: &Context) -> Response {
    if let Err(refusal) = kam_storage::orphans::check_quarantinable(path) {
        context.audit(
            "quarantine",
            "take",
            Effect::Refused,
            format!("refused to quarantine {path}: {refusal}"),
        );
        return Response::Error { message: refusal };
    }

    let target = std::path::Path::new(path);
    let bytes = kam_storage::scan::walk_scan(target)
        .map(|scan| scan.total_bytes)
        .unwrap_or(0);

    match context.quarantine.take(target, bytes, reason) {
        Ok(manifest) => {
            context.audit_with_token(
                "quarantine",
                "take",
                Effect::Changed,
                format!(
                    "quarantined {} ({}) -- {reason}",
                    manifest.original_path,
                    human_bytes(manifest.bytes)
                ),
                Some(manifest.id.clone()),
            );
            Response::Quarantined(manifest)
        }
        Err(error) => {
            context.audit(
                "quarantine",
                "take",
                Effect::Refused,
                format!("could not quarantine {path}: {error}"),
            );
            Response::Error {
                message: error.to_string(),
            }
        }
    }
}

fn scan_path(path: &str, context: &Context) -> Response {
    let target = std::path::Path::new(path);

    // A relative path would be resolved against the agent's working directory,
    // which is meaningless to the caller and, running as SYSTEM, is not
    // somewhere a user asked to look.
    if !target.is_absolute() {
        context.audit(
            "storage",
            "scan",
            Effect::Refused,
            format!("refused to scan a relative path: {path}"),
        );
        return Response::Error {
            message: "give an absolute path to scan".to_owned(),
        };
    }

    match kam_storage::scan(target) {
        Ok(scan) => {
            // Audited: a scan is something the user asked for, so it belongs in
            // the record of what happened, even though it changes nothing.
            context.audit(
                "storage",
                "scan",
                Effect::Observed,
                format!(
                    "scanned {} — {} in {} files, {} unreadable, {} ms",
                    scan.root,
                    human_bytes(scan.total_bytes),
                    scan.file_count,
                    scan.unreadable,
                    scan.elapsed_ms
                ),
            );
            Response::Scan(Box::new(scan))
        }
        Err(error) => {
            tracing::error!(%error, path, "scan failed");
            Response::Error {
                message: format!("{path} could not be scanned"),
            }
        }
    }
}

/// Sizes appear in audit entries a person reads, so they are written the way a
/// person would say them rather than as a raw byte count.
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_owned())
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn context(mode: Mode) -> Context {
        // A scratch quarantine store per test, so nothing here can reach the
        // real one under %ProgramData%.
        let quarantine_root = std::env::temp_dir().join(format!(
            "kam-dispatch-test-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0)
        ));
        Context {
            mode,
            store: Store::open_in_memory().unwrap(),
            quarantine: kam_quarantine::Store::open(&quarantine_root).unwrap(),
        }
    }

    #[test]
    fn status_reports_the_current_protocol_version() {
        let context = context(Mode::Console);
        let Response::SystemStatus(status) = handle(Request::GetSystemStatus, &context) else {
            panic!("expected a status response");
        };
        assert_eq!(status.protocol_version, kam_ipc::PROTOCOL_VERSION);
        assert!(!status.running_as_service);
    }

    #[test]
    fn reads_are_not_audited() {
        // The shell polls status and reloads history continuously. If either
        // were audited the log would fill with entries about being looked at,
        // and the entries that matter would be unfindable.
        let context = context(Mode::Service);
        let _ = handle(Request::GetSystemStatus, &context);
        let _ = handle(Request::GetRecentAudit { limit: 10 }, &context);

        assert!(context.store.recent_audit(10).unwrap().is_empty());
    }

    #[test]
    fn a_relative_scan_path_is_refused_and_recorded() {
        let context = context(Mode::Service);
        let response = handle(
            Request::ScanPath {
                path: "..\\somewhere".to_owned(),
            },
            &context,
        );

        assert!(matches!(response, Response::Error { .. }));
        let records = context.store.recent_audit(10).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].effect, Effect::Refused);
        assert_eq!(records[0].module, "storage");
    }

    #[test]
    fn a_scan_is_audited_because_the_user_asked_for_it() {
        let context = context(Mode::Console);
        let directory = std::env::temp_dir();
        let response = handle(
            Request::ScanPath {
                path: directory.display().to_string(),
            },
            &context,
        );

        assert!(matches!(response, Response::Scan(_)));
        let records = context.store.recent_audit(10).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, "scan");
        assert_eq!(records[0].effect, Effect::Observed);
    }

    #[test]
    fn byte_counts_are_written_the_way_a_person_says_them() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KB");
        assert_eq!(human_bytes(1024 * 1024 * 3 / 2), "1.5 MB");
        assert_eq!(human_bytes(5 * 1024 * 1024 * 1024), "5.0 GB");
    }

    #[test]
    fn an_oversized_audit_request_is_clamped_rather_than_refused() {
        let context = context(Mode::Console);
        let response = handle(Request::GetRecentAudit { limit: u32::MAX }, &context);
        assert!(matches!(response, Response::RecentAudit { .. }));
    }
}
