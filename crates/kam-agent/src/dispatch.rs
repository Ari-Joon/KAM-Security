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

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use kam_core::audit::{Effect, Entry};
use kam_core::changes::TakenBy;
use kam_core::{Reporter, Store, UserContext};
use kam_ipc::{Request, Response, SystemStatus};

use crate::server;
use crate::Mode;

/// Everything a handler is allowed to reach.
#[derive(Debug)]
pub struct Context {
    pub mode: Mode,
    pub store: Store,
    pub quarantine: kam_quarantine::Store,
    /// Stop signals for jobs currently running, by the id their caller chose.
    ///
    /// A job streams its progress down the connection that started it, so that
    /// connection cannot also carry a request to stop. The token is left here
    /// instead, and a second connection sets it.
    pub jobs: Mutex<HashMap<String, Arc<AtomicBool>>>,
    /// What the behaviour watcher has seen. The watcher thread writes it; a
    /// `GetBehaviourEvents` request reads it. Default is an empty log that is
    /// not watching, which is the correct state when no watcher was started
    /// (the tests, `--probe`).
    pub behaviour: crate::watch::Log,
}

impl Context {
    /// Remember a job's stop signal for as long as it runs.
    pub fn register_job(&self, job: &str, token: Arc<AtomicBool>) {
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.insert(job.to_owned(), token);
        }
    }

    /// Forget a job that has finished, however it finished.
    pub fn finish_job(&self, job: &str) {
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.remove(job);
        }
    }

    /// Ask a running job to stop. False when there is no such job.
    pub fn stop_job(&self, job: &str) -> bool {
        let Ok(jobs) = self.jobs.lock() else {
            return false;
        };
        match jobs.get(job) {
            Some(token) => {
                token.store(true, std::sync::atomic::Ordering::SeqCst);
                true
            }
            None => false,
        }
    }
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

/// Whether a request changes something machine-wide, and so may be made only
/// for a caller running with administrator rights.
///
/// # The rule
///
/// The agent runs as LocalSystem, so it can make any change on this machine. A
/// request is only a request, though: the question is whether the *person
/// asking* could make that change themselves. For every request listed here,
/// Windows' own tools require an administrator — Windows Security prompts for
/// consent before a Defender protection is changed, and firewall rules and
/// audit policy are administrator-only everywhere. The agent must not be the
/// one place those same changes can be made without it.
///
/// So these run only when the caller's own token is elevated. A person who is
/// an administrator but opened the window normally is asked to open it as
/// administrator, which is the same consent Windows asks for.
///
/// # Every request is decided here, by hand
///
/// The match below has no catch-all arm on purpose. Adding a request to the
/// protocol does not compile until somebody has written down which group it
/// belongs to, so a new machine-wide change cannot arrive quietly in the
/// "anyone" group by default.
pub fn needs_administrator(request: &Request, user: &UserContext) -> bool {
    match request {
        // Machine-wide settings. Windows asks for an administrator before any
        // of these, so this does too.
        Request::SetHardening { .. }
        | Request::SetCanaryAuditing { .. }
        | Request::BlockProgram { .. }
        | Request::UnblockProgram { .. }
        | Request::SetProtection { .. } => true,

        // A cache clear is machine-wide exactly when it reaches outside the
        // caller's own profile: the Windows update cache, the shared temporary
        // folder, a previous installation of Windows. A person's own browser
        // cache and thumbnails are theirs to clear, as in Disk Cleanup.
        Request::ClearCache { id } => kam_storage::caches::is_machine_wide(id, user),

        // Acting on files and folders. Whether the caller may act on each path
        // is decided per path, in the handler, against that caller's own rights.
        Request::QuarantinePath { .. }
        | Request::QuarantineCopy { .. }
        | Request::RestoreQuarantined { .. }
        | Request::DeleteQuarantined { .. }
        | Request::EmptyQuarantine
        | Request::ApplyMove { .. }
        | Request::UndoMove { .. }
        | Request::QuarantineDownload { .. } => false,

        // The caller's own things: a schedule that runs as them, unelevated,
        // decoy files in their own profile, and the rows of their own
        // download history, which are removed for the caller alone.
        Request::SetSchedule { .. }
        | Request::SetCanaries { .. }
        | Request::RemoveDownloadRecord { .. }
        | Request::ClearDownloadRecords { .. } => false,

        // Recording what the window did, and stopping a job.
        Request::RecordLookup { .. }
        | Request::RecordRecycle { .. }
        | Request::NoteUninstallLaunched { .. }
        | Request::RecordDissection { .. }
        | Request::RecordExtraction { .. }
        | Request::NoteVanishedDownload { .. }
        | Request::CancelJob { .. } => false,

        // Reading, measuring and scanning. A Defender scan is something any
        // user may start from Windows Security.
        Request::GetSystemStatus
        | Request::GetRecentAudit { .. }
        | Request::ListVolumes
        | Request::ScanPath { .. }
        | Request::ScanFolder { .. }
        | Request::GetGrowth { .. }
        | Request::ListApplications { .. }
        | Request::ListQuarantine
        | Request::SweepForChanges
        | Request::ReadComparison { .. }
        | Request::DefenderScan { .. }
        | Request::GetSchedule
        | Request::RunCheck
        | Request::SurveyCaches
        | Request::FindDuplicates { .. }
        | Request::FindOrganiseProposals { .. }
        | Request::ListMoves
        | Request::FindRemnants { .. }
        | Request::GetFirewall
        | Request::GetConnections
        | Request::GetDefenderStatus
        | Request::GetDefenderThreats
        | Request::SurveyProvenance { .. }
        | Request::GetBehaviourEvents
        | Request::GetExtensions
        | Request::GetHardening
        | Request::GetCanaries
        | Request::GetProtection
        | Request::CheckDownload { .. }
        | Request::ListDownloads { .. }
        | Request::CountDownloadsSince { .. } => false,

        // Reading where traffic is sent and which certificates are trusted:
        // any account can read these from Windows' own settings.
        Request::GetTrafficSettings | Request::GetRootCertificates => false,
        // Whether there is a TPM and it is ready, and whether drive C: is
        // encrypted: Windows tells any account both, in Windows Security and
        // in Explorer. Its documented providers answer only an administrator,
        // which is the only reason the service is the one that asks them.
        Request::GetDeviceFacts => false,
    }
}

/// What a caller without administrator rights is told, in their terms.
pub const NEEDS_ADMINISTRATOR: &str = "Changing this needs administrator rights, the same as \
    changing it in Windows itself.";

pub fn handle(
    request: Request,
    context: &Context,
    reporter: &Reporter,
    user: &UserContext,
) -> Response {
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

        Request::ScanPath { path } => scan_path(&path, context, user),

        Request::ScanFolder { path } => scan_folder(&path, context),

        // A read of the caller's own notes, so not recorded: see the rule at
        // the top of this file.
        Request::GetGrowth {
            drive,
            later,
            earlier,
        } => crate::growth::answer(&drive, later, earlier, context, user),

        Request::ListApplications { drive } => {
            let Some(letter) = drive.chars().next().filter(|c| c.is_ascii_alphabetic()) else {
                return Response::Error {
                    message: "give a drive letter, such as C:".to_owned(),
                };
            };

            match kam_storage::apps::survey(letter.to_ascii_uppercase(), now_seconds(), user) {
                Ok(mut report) => {
                    report.downloads = sendable_downloads(
                        std::mem::take(&mut report.downloads),
                        &mut report.download_summary,
                    );
                    report.old_files = sendable_old_files(std::mem::take(&mut report.old_files));
                    context.audit(
                        "storage",
                        "survey",
                        Effect::Observed,
                        format!(
                            "surveyed {letter}: {} applications using {}, {} leftover directories holding {}, {} downloads holding {}, {} large files with no date in the last year holding {}, in {} ms (table {}, index {}, applications {}, leftovers {}, downloads {})",
                            report.summary.applications,
                            human_bytes(report.summary.measured_bytes),
                            report.orphan_summary.found,
                            human_bytes(report.orphan_summary.total_bytes),
                            report.download_summary.found,
                            human_bytes(report.download_summary.total_bytes),
                            report.old_file_summary.found,
                            human_bytes(report.old_file_summary.total_bytes),
                            report.timings.total,
                            report.timings.read_table,
                            report.timings.build_index,
                            report.timings.applications,
                            report.timings.orphans,
                            report.timings.downloads
                        ),
                    );
                    Response::Applications {
                        apps: report.apps,
                        summary: report.summary,
                        orphans: report.orphans,
                        orphan_summary: report.orphan_summary,
                        downloads: report.downloads,
                        download_summary: Box::new(report.download_summary),
                        old_files: report.old_files,
                        old_file_summary: Box::new(report.old_file_summary),
                        timings: Box::new(report.timings),
                    }
                }
                Err(error) => {
                    tracing::info!(%error, "could not survey storage");
                    Response::Error {
                        message: format!(
                            "application sizes need the master file table, which the agent \
                             could not read: {error}"
                        ),
                    }
                }
            }
        }

        Request::FindDuplicates { drive, job } => {
            let Some(letter) = drive.chars().next().filter(|c| c.is_ascii_alphabetic()) else {
                return Response::Error {
                    message: "give a drive letter, such as C:".to_owned(),
                };
            };

            context.register_job(&job, reporter.cancel_token());
            let outcome =
                kam_storage::duplicates::survey(letter.to_ascii_uppercase(), reporter, user);
            context.finish_job(&job);

            if reporter.is_cancelled() {
                tracing::info!(%job, "duplicate scan stopped");
                return Response::Stopped;
            }

            match outcome {
                Ok((groups, mut summary)) => {
                    summary.quarantine_only_on = quarantine_only_on(context, letter);
                    let (groups, summary) = sendable_duplicates(groups, summary);
                    context.audit(
                        "storage",
                        "find_duplicates",
                        Effect::Observed,
                        format!(
                            "found {} duplicate sets on {letter}: {} duplicated, {} of it \
                             reclaimable across {} sets, reading {} files in full{}",
                            summary.groups,
                            human_bytes(summary.wasted_bytes),
                            human_bytes(summary.reclaimable_bytes),
                            summary.actionable,
                            summary.fully_hashed,
                            if summary.unlisted.groups > 0 {
                                format!(
                                    "; the {} smallest were too many to send and were \
                                     left out of the list",
                                    summary.unlisted.groups
                                )
                            } else {
                                String::new()
                            }
                        ),
                    );
                    Response::Duplicates { groups, summary }
                }
                Err(error) => {
                    tracing::info!(%error, "could not look for duplicates");
                    Response::Error {
                        message: format!(
                            "duplicate detection needs the master file table, which the \
                             agent could not read: {error}"
                        ),
                    }
                }
            }
        }

        // A schedule that could not be read is an error, not "nothing is
        // registered": the window would otherwise offer to turn on a check
        // that may already be on.
        Request::GetSchedule => match kam_schedule::current() {
            Ok(schedule) => Response::Schedule(schedule),
            Err(error) => Response::Error {
                message: format!("whether a weekly check is registered could not be read: {error}"),
            },
        },

        Request::SetSchedule { enabled, day, hour } => {
            if !enabled {
                return match kam_schedule::disable() {
                    Ok(()) => {
                        context.audit(
                            "schedule",
                            "disable",
                            Effect::Changed,
                            "removed the weekly check".to_owned(),
                        );
                        match kam_schedule::current() {
                            Ok(schedule) => Response::Schedule(schedule),
                            Err(error) => Response::Error {
                                message: format!(
                                    "the weekly check was removed, but reading the schedule \
                                     back failed: {error}"
                                ),
                            },
                        }
                    }
                    Err(error) => {
                        context.audit(
                            "schedule",
                            "disable",
                            Effect::Refused,
                            format!("could not remove the weekly check: {error}"),
                        );
                        Response::Error {
                            message: error.to_string(),
                        }
                    }
                };
            }

            // The request is checked before anything is looked up, so a
            // malformed one is answered with what is wrong with it rather than
            // with whatever the first lookup happened to fail at. A silly hour
            // is a caller error, not something to clamp quietly: 25 o'clock
            // means the request was built wrong.
            if hour > 23 {
                return Response::Error {
                    message: "give an hour between 0 and 23".to_owned(),
                };
            }

            // The program is this executable and the account is the caller's,
            // both decided here. Neither travels over the pipe, because a
            // request that could name them would be a request to run anything
            // at all, elevated, on a timer.
            let Ok(program) = std::env::current_exe() else {
                return Response::Error {
                    message: "the agent could not find its own path".to_owned(),
                };
            };
            let Some(account) = user.sid().map(str::to_owned) else {
                return Response::Error {
                    message: "the caller could not be identified".to_owned(),
                };
            };

            match kam_schedule::enable(&program.to_string_lossy(), &account, &day, hour) {
                Ok(schedule) => {
                    context.audit(
                        "schedule",
                        "enable",
                        Effect::Changed,
                        format!(
                            "weekly check registered for {} at {}",
                            schedule.day.as_deref().unwrap_or(&day),
                            schedule.at.as_deref().unwrap_or("an unknown time")
                        ),
                    );
                    Response::Schedule(schedule)
                }
                Err(error) => {
                    context.audit(
                        "schedule",
                        "enable",
                        Effect::Refused,
                        format!("could not register the weekly check: {error}"),
                    );
                    Response::Error {
                        message: error.to_string(),
                    }
                }
            }
        }

        Request::RunCheck => {
            let findings = crate::check::run_and_record(&context.store, user);
            // The weekly check also takes the comparison What changed would
            // take, so that a week in which it ran is not drawn as a week
            // nobody looked at. That is all it adds: the comparison is not
            // one of its findings and changes none of them, and one that
            // could not be taken is written down on its own.
            if let Err(error) = take_comparison(context, TakenBy::WeeklyCheck) {
                tracing::error!(%error, "the weekly check could not compare the machine with its history");
                context.audit(
                    "changes",
                    "sweep",
                    Effect::Observed,
                    format!(
                        "the weekly check could not compare the machine with its history: {error}"
                    ),
                );
            }
            Response::Checked {
                findings: findings
                    .into_iter()
                    .map(|finding| kam_ipc::CheckFinding {
                        summary: finding.summary,
                        serious: finding.serious,
                    })
                    .collect(),
            }
        }

        Request::SurveyCaches => {
            let caches = kam_storage::caches::survey(user);
            // Two counts, because the survey now also measures what is only
            // explained, and "caches holding" must not take that in.
            let (explained, clearable): (Vec<_>, Vec<_>) = caches
                .iter()
                .partition(|cache| cache.safety == kam_storage::caches::Safety::Explained);
            let held = |list: &[&kam_storage::Cache]| -> u64 {
                list.iter().map(|cache| cache.bytes).sum()
            };
            context.audit(
                "storage",
                "survey_caches",
                Effect::Observed,
                format!(
                    "{} caches holding {}, and {} other places explained holding {}, for {}",
                    clearable.len(),
                    human_bytes(held(&clearable)),
                    explained.len(),
                    human_bytes(held(&explained)),
                    user.profile()
                ),
            );
            Response::Caches { caches }
        }

        Request::ClearCache { id } => match kam_storage::caches::clear(&id, user) {
            Ok(cleared) => {
                context.audit(
                    "storage",
                    "clear_cache",
                    Effect::Changed,
                    format!(
                        "cleared {id}: freed {} across {} files, {} still in use",
                        human_bytes(cleared.bytes_freed),
                        cleared.files_removed,
                        cleared.files_in_use
                    ),
                );
                Response::CacheCleared(cleared)
            }
            Err(refusal) => {
                // An id that is not in the catalogue is the shape a tampered
                // request takes, so it is recorded rather than shrugged off.
                context.audit(
                    "storage",
                    "clear_cache",
                    Effect::Refused,
                    format!("refused to clear {id}: {refusal}"),
                );
                Response::Error { message: refusal }
            }
        },

        Request::QuarantineCopy {
            path,
            reason,
            chosen,
            keep,
        } => quarantine_copy(&path, &keep, &reason, chosen, context, user),

        Request::FindOrganiseProposals { drive } => {
            let Some(letter) = drive.chars().next().filter(|c| c.is_ascii_alphabetic()) else {
                return Response::Error {
                    message: "give a drive letter, such as C:".to_owned(),
                };
            };
            match kam_storage::organise::survey(letter.to_ascii_uppercase(), user) {
                Ok((proposals, summary)) => Response::Organise { proposals, summary },
                Err(error) => {
                    tracing::info!(%error, "could not look for loose files");
                    Response::Error {
                        message: format!("loose files could not be looked for: {error}"),
                    }
                }
            }
        }

        Request::ApplyMove { from, to } => apply_move(&from, &to, context, user),

        Request::UndoMove { id } => match context.quarantine.undo_move(&id) {
            Ok(record) => {
                context.audit_with_token(
                    "storage",
                    "undo_move",
                    Effect::Changed,
                    format!("put {} back", record.from),
                    Some(record.id.clone()),
                );
                Response::Moved(record)
            }
            Err(error) => {
                context.audit(
                    "storage",
                    "undo_move",
                    Effect::Refused,
                    format!("could not undo {id}: {error}"),
                );
                Response::Error {
                    message: error.to_string(),
                }
            }
        },

        Request::ListMoves => match context.quarantine.moves() {
            Ok(records) => Response::Moves { records },
            Err(error) => {
                tracing::error!(%error, "could not list moves");
                Response::Error {
                    message: "the move journal could not be read".to_owned(),
                }
            }
        },

        Request::GetDefenderStatus => match kam_scanner::defender::status() {
            Ok(status) => {
                let concerns = status.concerns();
                Response::Defender { status, concerns }
            }
            Err(error) => {
                tracing::info!(%error, "could not read Defender status");
                Response::Error {
                    message: format!("Defender did not answer: {error}"),
                }
            }
        },

        Request::FindRemnants { name, paths, kinds } => {
            let report = kam_storage::remnants::of(&name, &paths, &kinds, user);
            tracing::info!(
                %name,
                still_installed = report.still_installed,
                locations = report.locations.len(),
                shortcuts = report.shortcuts.len(),
                refused = report.refused.len(),
                "looked for what {name} left behind"
            );
            Response::Remnants(Box::new(report))
        }

        Request::GetFirewall => match kam_firewall::policy::survey() {
            Ok(report) => Response::Firewall(Box::new(report)),
            Err(error) => {
                tracing::info!(%error, "could not read the firewall");
                Response::Error {
                    message: error.to_string(),
                }
            }
        },

        Request::GetConnections => Response::Connections(kam_firewall::connections::survey()),

        Request::BlockProgram { path } => match kam_firewall::policy::block_program(&path) {
            Ok(rule) => {
                // The first thing in this product that changes the machine, so
                // it is recorded with the handle that reverses it.
                context.audit_with_token(
                    "firewall",
                    "block_program",
                    Effect::Changed,
                    format!("blocked outgoing connections from {path}"),
                    Some(rule.clone()),
                );
                Response::Blocked { rule }
            }
            Err(error) => {
                context.audit(
                    "firewall",
                    "block_program",
                    Effect::Refused,
                    format!("could not block {path}: {error}"),
                );
                Response::Error {
                    message: error.to_string(),
                }
            }
        },

        Request::UnblockProgram { rule } => match kam_firewall::policy::remove_our_rule(&rule) {
            Ok(()) => {
                context.audit(
                    "firewall",
                    "unblock_program",
                    Effect::Changed,
                    format!("removed the block rule {rule}"),
                );
                Response::Acknowledged
            }
            Err(error) => {
                context.audit(
                    "firewall",
                    "unblock_program",
                    Effect::Refused,
                    format!("could not remove {rule}: {error}"),
                );
                Response::Error {
                    message: error.to_string(),
                }
            }
        },

        Request::CancelJob { job } => {
            // An unknown id is acknowledged rather than refused. By the time
            // someone presses the button the job may already have finished,
            // and an error about that would be noise.
            let stopped = context.stop_job(&job);
            tracing::info!(%job, stopped, "stop requested");
            Response::Acknowledged
        }

        Request::SurveyProvenance { job } => {
            context.register_job(&job, reporter.cancel_token());
            let outcome = kam_scanner::provenance::survey(reporter, user);
            context.finish_job(&job);

            match outcome {
                Ok(report) => {
                    // Recorded like everything else the agent does. This was
                    // the one privileged action that left no trace, in the
                    // half of the product whose whole argument is that it
                    // writes down what it looked at.
                    context.audit(
                        "scanner",
                        "survey_provenance",
                        Effect::Observed,
                        format!(
                            "examined {} programs that start themselves and {} files that \
                             arrived from outside; {} worth reading",
                            report.examined,
                            report.swept_files,
                            report.worth_reading().count()
                        ),
                    );
                    Response::Provenance(report)
                }
                Err(_) => {
                    context.audit(
                        "scanner",
                        "survey_provenance",
                        Effect::Observed,
                        "the survey was stopped before it finished".to_owned(),
                    );
                    Response::Stopped
                }
            }
        }

        Request::SweepForChanges => match take_comparison(context, TakenBy::Page) {
            Ok(sweep) => Response::Changes(Box::new(sweep)),
            Err(error) => {
                tracing::error!(%error, "could not compare the machine with its history");
                Response::Error {
                    message: format!("what changed could not be worked out: {error}"),
                }
            }
        },

        // Not audited, as reading the log is not: reading what an earlier
        // comparison found is reading history, and takes nothing and changes
        // nothing.
        Request::ReadComparison { id } => match context.store.comparison(id) {
            Ok(Some(kept)) => Response::Comparison(Box::new(kept)),
            Ok(None) => Response::Error {
                message: "no list is kept for that comparison".to_owned(),
            },
            Err(error) => {
                tracing::error!(%error, id, "could not read a kept comparison");
                Response::Error {
                    message: format!("that comparison's list could not be read: {error}"),
                }
            }
        },

        Request::RecordLookup { sha256, outcome } => {
            // The one thing in this product that sends anything off the
            // machine, and therefore the one thing most worth writing down.
            //
            // The lookup itself happens in the window, deliberately: the rule
            // engine and the VirusTotal client are kept out of the privileged
            // process entirely, and there is a test that fails if either ever
            // appears in its dependency tree. So the record has to be asked
            // for rather than produced where the work happened.
            //
            // The request carries a hash and a one-line outcome and nothing
            // else. A client that could write free-form audit entries could
            // write a plausible history of things that never happened.
            let digest: String = sha256
                .chars()
                .filter(|c| c.is_ascii_hexdigit())
                .take(64)
                .collect();
            if digest.len() != 64 {
                return Response::Error {
                    message: "a lookup record needs the file's SHA-256".to_owned(),
                };
            }
            let outcome: String = outcome.chars().take(120).collect();

            context.audit(
                "virustotal",
                "look_up",
                Effect::Changed,
                format!("sent the hash {digest} to VirusTotal: {outcome}"),
            );
            Response::Acknowledged
        }

        Request::RecordRecycle { path, in_bin } => {
            // The window did this one, not the agent, and the entry says so.
            //
            // Recycling happens in the window because the Recycle Bin is per
            // user and a LocalSystem delete lands in SYSTEM's, where nobody can
            // reach it. The cost is that the privileged process no longer
            // witnesses the act, so this is a report rather than a record of
            // something seen. Phrasing it as a report keeps the log honest
            // about which entries the agent stands behind.
            //
            // No fence is re-derived here, and there is deliberately nothing to
            // fence: this changes only the log. A client that lied would write a
            // false line about its own files, which it could do by recycling
            // them for real. The audit value is in the true reports, and there
            // is no privileged act to protect.
            //
            // The sentence is built here rather than accepted, so the only
            // caller-supplied part is the path, which `record` flattens.
            let detail = if in_bin {
                format!("the window reported sending {path} to the Recycle Bin")
            } else {
                format!(
                    "the window reported removing {path}, which did not reach \
                     the Recycle Bin and cannot be restored from it"
                )
            };
            context.audit("cleanup", "recycle", Effect::Changed, detail);
            Response::Acknowledged
        }

        Request::DefenderScan { kind, job } => {
            // Registered like any other long job so it can be stopped: a full
            // scan runs for hours, and an interface that offers no way out of
            // that is worse than not offering it.
            context.register_job(&job, reporter.cancel_token());
            let outcome = kam_scanner::defender_scan::run(&kind, &reporter.cancel_token());
            context.finish_job(&job);

            match outcome {
                Ok(outcome) => {
                    // Recorded either way, and the entry says whether it
                    // finished. A scan that was stopped early and found nothing
                    // has established nothing, and the log should not later read
                    // as though the machine came back clean.
                    context.audit(
                        "defender",
                        "scan",
                        Effect::Observed,
                        format!(
                            "{} {} in {} seconds; {} new {} recorded by Defender",
                            outcome.label,
                            if outcome.completed {
                                "finished"
                            } else {
                                "was stopped before finishing"
                            },
                            outcome.seconds,
                            outcome.found.len(),
                            if outcome.found.len() == 1 {
                                "detection"
                            } else {
                                "detections"
                            }
                        ),
                    );
                    Response::DefenderScanned(outcome)
                }
                Err(error) => {
                    context.audit(
                        "defender",
                        "scan",
                        Effect::Refused,
                        format!("could not run {}: {error}", kind.label()),
                    );
                    Response::Error {
                        message: error.to_string(),
                    }
                }
            }
        }

        Request::GetDefenderThreats => match kam_scanner::defender::threats() {
            Ok(threats) => Response::DefenderThreats { threats },
            Err(error) => {
                tracing::info!(%error, "could not read Defender threat history");
                Response::Error {
                    message: format!("Defender's threat history could not be read: {error}"),
                }
            }
        },

        Request::GetBehaviourEvents => {
            // Not audited. Reading what the watcher saw is not an action on the
            // system, and the window polls it; recording every read would bury
            // the watcher's own findings under entries about looking at them.
            let (observations, watching, since) = context.behaviour.snapshot();
            Response::BehaviourEvents {
                observations,
                watching,
                since,
            }
        }

        Request::GetExtensions => {
            let report = kam_scanner::extensions::survey(user);
            // Audited: this is a deliberate examination of somebody's browsers,
            // which belongs in the history of what was looked at.
            context.audit(
                "scanner",
                "survey_extensions",
                Effect::Observed,
                format!(
                    "read {} browser extensions across {}; {} worth reading",
                    report.extensions.len(),
                    report.examined.join(", "),
                    report.worth_reading().count()
                ),
            );
            Response::Extensions(report)
        }

        Request::GetHardening => {
            // Not audited. It reads registry state and changes nothing, and the
            // window shows it on every visit to the Scanner.
            Response::Hardening(Box::new(kam_scanner::hardening::survey()))
        }

        Request::SetHardening { id, wanted } => {
            match kam_scanner::hardening::request(&id, wanted) {
                Ok(report) => {
                    context.audit(
                        "scanner",
                        "set_hardening",
                        Effect::Changed,
                        format!("asked Defender to set {id} to {wanted:?}"),
                    );
                    Response::Hardening(Box::new(report))
                }
                Err(error) => {
                    // Defender refusing is a real answer and worth recording:
                    // Tamper Protection and group policy both decline here, and
                    // a person needs to know which.
                    context.audit(
                        "scanner",
                        "set_hardening",
                        Effect::Refused,
                        format!("could not set {id} to {wanted:?}: {error}"),
                    );
                    Response::Error {
                        message: error.to_string(),
                    }
                }
            }
        }

        Request::GetProtection => Response::Protection {
            enabled: context.store.protection_enabled(),
        },

        Request::SetProtection { enabled } => {
            match context.store.set_protection_enabled(enabled) {
                Ok(()) => {
                    // Recorded as a change, both ways. Somebody turning the
                    // protection off is exactly the entry a person reading this
                    // log later wants to find.
                    context.audit(
                        "protection",
                        if enabled { "enable" } else { "disable" },
                        Effect::Changed,
                        format!(
                            "the protective work was switched {}",
                            if enabled { "on" } else { "off" }
                        ),
                    );
                    Response::Protection { enabled }
                }
                Err(error) => {
                    tracing::error!(%error, "could not record the protection setting");
                    Response::Error {
                        message: "the setting could not be saved, so nothing was changed"
                            .to_owned(),
                    }
                }
            }
        }

        Request::GetCanaries => Response::Canaries(Box::new(kam_canary::status(user))),

        Request::SetCanaries { planted } => {
            if planted {
                let report = kam_canary::plant(user);
                // Effect::Changed: this writes files into somebody's Documents
                // and keys into their registry hive.
                context.audit(
                    "canary",
                    "plant",
                    Effect::Changed,
                    format!(
                        "planted {} decoys for {}; {} armed",
                        report.canaries.len(),
                        user.profile(),
                        report.canaries.iter().filter(|c| c.armed).count()
                    ),
                );
                Response::Canaries(Box::new(report))
            } else {
                let (removed, refused) = kam_canary::remove(user);
                context.audit(
                    "canary",
                    "remove",
                    Effect::Changed,
                    format!("removed {removed} decoys for {}", user.profile()),
                );
                let mut report = kam_canary::status(user);
                report.problems.extend(refused);
                Response::Canaries(Box::new(report))
            }
        }

        Request::SetCanaryAuditing { enabled } => {
            match kam_canary::set_auditing(enabled) {
                Ok(()) => {
                    // The one machine-wide setting this product changes, so it
                    // is recorded in both directions and in plain words.
                    context.audit(
                        "canary",
                        "set_auditing",
                        Effect::Changed,
                        format!(
                            "turned Windows file-access auditing {}",
                            if enabled { "on" } else { "off" }
                        ),
                    );
                    Response::Canaries(Box::new(kam_canary::status(user)))
                }
                Err(error) => {
                    context.audit(
                        "canary",
                        "set_auditing",
                        Effect::Refused,
                        format!("could not change the audit policy: {error}"),
                    );
                    Response::Error {
                        message: error.to_string(),
                    }
                }
            }
        }

        Request::NoteUninstallLaunched { name, command } => {
            // Effect::Changed, not Observed: the machine is about to change.
            // The wording says "launched" rather than "uninstalled" because
            // whether the user goes through with it is not knowable from here.
            context.audit(
                "applications",
                "launch_uninstaller",
                Effect::Changed,
                format!("launched the uninstaller for {name}: {command}"),
            );
            Response::Acknowledged
        }

        Request::QuarantinePath { path, reason } => quarantine_path(&path, &reason, context, user),

        // A download is checked when it lands and whenever somebody asks.
        // Audited either way: it reads a file as LocalSystem and records it.
        //
        // The service never comes this way. Its server opens the file while
        // acting as the caller and hands that one handle to
        // `downloads::check` itself (see `server::handle_connection`). An
        // open made here would be made as LocalSystem, which is the very
        // thing that open exists to prevent, so in the service this arm
        // refuses. What reaches it otherwise is a process asking about files
        // as itself: the tests.
        Request::CheckDownload { path, job, copy_of } => {
            let opened = if context.running_as_service() {
                Err(format!(
                    "{path} was not checked, because it was not opened as the account asking"
                ))
            } else {
                crate::downloads::open_as_caller(&path, copy_of.as_deref())
            };
            match opened {
                Ok(opened) => crate::downloads::check(opened, &job, context, reporter, user),
                Err(refusal) => {
                    context.audit("downloads", "check", Effect::Refused, refusal.clone());
                    Response::Error { message: refusal }
                }
            }
        }

        // Not audited. The page reads it whenever it is opened.
        Request::ListDownloads { paths, recent } => {
            crate::downloads::list(&paths, recent, context, user)
        }

        // Not audited either: the window asks whenever the list changes, to
        // keep the count beside the page's name true.
        Request::CountDownloadsSince { since } => {
            crate::downloads::count_since(&since, context, user)
        }

        Request::QuarantineDownload { path } => crate::downloads::quarantine(&path, context, user),

        Request::NoteVanishedDownload {
            path,
            bytes,
            arrived_at,
        } => crate::downloads::vanished(&path, bytes, arrived_at.as_deref(), context, user),

        Request::RecordDissection {
            path,
            sha256,
            dissection,
        } => crate::downloads::record_dissection(&path, &sha256, *dissection, context, user),

        Request::RecordExtraction {
            path,
            sha256,
            extraction,
        } => crate::downloads::record_extraction(&path, &sha256, &extraction, context, user),

        // Real, permanent removal of rows from the caller's own history, and
        // never of a file. Audited whatever comes of it.
        Request::RemoveDownloadRecord { path, sha256 } => {
            crate::downloads::remove_record(&path, &sha256, context, user)
        }

        Request::ClearDownloadRecords { up_to } => {
            crate::downloads::clear_records(&up_to, context, user)
        }

        Request::ListQuarantine => match context.quarantine.list() {
            Ok(items) => Response::QuarantineList { items },
            Err(error) => {
                tracing::error!(%error, "could not list quarantine");
                Response::Error {
                    message: "the quarantine store could not be read".to_owned(),
                }
            }
        },

        Request::DeleteQuarantined { id } => delete_quarantined(&[id], context),

        Request::EmptyQuarantine => {
            let held: Vec<String> = match context.quarantine.list() {
                Ok(items) => items.into_iter().map(|item| item.id).collect(),
                Err(error) => {
                    tracing::error!(%error, "could not list quarantine");
                    return Response::Error {
                        message: "the quarantine store could not be read".to_owned(),
                    };
                }
            };
            delete_quarantined(&held, context)
        }

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

        // Not audited, as the firewall's own state is not: the page reads it
        // on every visit and it changes nothing. The proxy shown is the
        // caller's own, read from their hive.
        Request::GetTrafficSettings => {
            Response::TrafficSettings(Box::new(kam_scanner::traffic::survey(user)))
        }

        // Not audited either, as the hardening state is not: the Scanner reads
        // it on every visit. The account's own stores are the caller's.
        Request::GetRootCertificates => {
            Response::RootCertificates(Box::new(kam_scanner::roots::survey(user)))
        }
        // Not audited, as the hardening state is not: a read of facts any
        // account can see, made on every visit to the Scanner.
        Request::GetDeviceFacts => Response::DeviceFacts(Box::new(kam_scanner::device::held())),
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
fn quarantine_path(path: &str, reason: &str, context: &Context, user: &UserContext) -> Response {
    if let Err(refusal) = kam_storage::orphans::check_quarantinable(path, user) {
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
                    "quarantined {} ({}): {reason}",
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

/// How much of a reply the list of duplicate sets may take, as JSON.
///
/// A reply is one frame, and a frame over [`kam_ipc::MAX_FRAME_BYTES`] is not
/// sent at all. Nothing bounded these two lists. A drive with around thirteen
/// thousand duplicate sets, which a photo archive kept twice reaches, or with
/// thousands of large downloads, ran its whole search and then lost the
/// answer: the frame was refused, the connection dropped, and the window
/// showed a pipe error, every time.
///
/// Half a frame holds several thousand sets, and the page draws forty.
const DUPLICATES_REPLY_BYTES: usize = kam_ipc::MAX_FRAME_BYTES / 2;

/// The same for the list of downloads, of which the page draws twenty-five.
/// Smaller, because it shares its reply with every application and leftover.
const DOWNLOADS_REPLY_BYTES: usize = kam_ipc::MAX_FRAME_BYTES / 4;

/// Split a list into the leading items that fit in `budget` bytes once
/// written as JSON, and the rest.
///
/// Both lists this is for arrive with the most useful first, so what is kept
/// is the largest and what is left out is the tail. The caller says what was
/// left out; nothing here is dropped without a count.
pub(crate) fn fitting<T: serde::Serialize>(mut items: Vec<T>, budget: usize) -> (Vec<T>, Vec<T>) {
    let mut used = 0_usize;
    let mut keep = items.len();
    for (position, item) in items.iter().enumerate() {
        // One more for the comma after it. An item that cannot be written at
        // all would fail the whole reply, so the list stops before it.
        let size = serde_json::to_vec(item)
            .map(|written| written.len() + 1)
            .unwrap_or(usize::MAX);
        if used.saturating_add(size) > budget {
            keep = position;
            break;
        }
        used += size;
    }
    let rest = items.split_off(keep);
    (items, rest)
}

/// A duplicate search, cut down to an answer that fits in one reply.
///
/// The summary goes on counting every set found. What is not in the list is
/// totalled into it, so the page can say how many were left out and what they
/// came to.
fn sendable_duplicates(
    groups: Vec<kam_storage::DuplicateGroup>,
    mut summary: kam_storage::DuplicateSummary,
) -> (
    Vec<kam_storage::DuplicateGroup>,
    kam_storage::DuplicateSummary,
) {
    let (groups, unlisted) = fitting(groups, DUPLICATES_REPLY_BYTES);
    summary.unlisted = kam_storage::duplicates::Unlisted::of(&unlisted);
    (groups, summary)
}

/// The same for the downloads a survey found.
fn sendable_downloads(
    downloads: Vec<kam_storage::Download>,
    summary: &mut kam_storage::DownloadSummary,
) -> Vec<kam_storage::Download> {
    let (downloads, unlisted) = fitting(downloads, DOWNLOADS_REPLY_BYTES);
    summary.unlisted = unlisted.len();
    downloads
}

/// How much of that same reply the list of large old files may take.
///
/// The list is two hundred rows at most, a few hundred bytes each, so this is
/// never reached by ordinary paths. It is here because a path can be very
/// long, and this list rides in the reply that already carries every
/// application, leftover and download.
const OLD_FILES_REPLY_BYTES: usize = kam_ipc::MAX_FRAME_BYTES / 8;

/// The large old files a survey found, cut to what fits.
///
/// Nothing needs counting here. The summary already holds how many were found
/// and what they hold in all, and the page works out what is not in the list
/// from those and the list it was sent, whatever shortened it.
fn sendable_old_files(files: Vec<kam_storage::OldFile>) -> Vec<kam_storage::OldFile> {
    fitting(files, OLD_FILES_REPLY_BYTES).0
}

/// The one drive quarantine holds things from, when `searched` is another.
///
/// The store moves an item in by renaming it, which only works within one
/// drive, and it refuses anything else on purpose. A duplicate search covers
/// one drive, so every copy it finds is either within reach or not, and the
/// answer goes back with the results: the page drew "Remove this one" beside
/// copies on a second drive, where pressing it could only produce the refusal.
///
/// Judged the way the store itself judges, by the first letter of each path.
fn quarantine_only_on(context: &Context, searched: char) -> Option<char> {
    let store = context
        .quarantine
        .root()
        .to_str()
        .and_then(|text| text.chars().next())
        .filter(char::is_ascii_alphabetic)?
        .to_ascii_uppercase();
    (store != searched.to_ascii_uppercase()).then_some(store)
}

/// Take one redundant copy of a duplicated file.
///
/// The fence is [`kam_storage::duplicates::check_removable`], and it is checked
/// here rather than trusted from the list the interface drew. Quarantine rather
/// than deletion, for the same reason as everywhere else: the copy is held, the
/// move is recorded, and it goes back with one press if this was wrong.
fn quarantine_copy(
    path: &str,
    keep: &str,
    reason: &str,
    chosen: bool,
    context: &Context,
    user: &UserContext,
) -> Response {
    let intent = if chosen {
        kam_storage::duplicates::Intent::Chosen
    } else {
        kam_storage::duplicates::Intent::Suggested
    };
    // Where it is decides whether it may go; whether it is still a spare
    // decides whether it should. The list it was chosen from may be days old.
    let allowed = kam_storage::duplicates::check_removable(path, user, intent)
        .and_then(|()| kam_storage::duplicates::check_still_twins(path, keep, user));
    if let Err(refusal) = allowed {
        context.audit(
            "quarantine",
            "take_copy",
            Effect::Refused,
            format!("refused to remove {path}: {refusal}"),
        );
        return Response::Error { message: refusal };
    }

    let target = std::path::Path::new(path);
    let bytes = std::fs::metadata(target)
        .map(|data| data.len())
        .unwrap_or(0);

    match context.quarantine.take(target, bytes, reason) {
        Ok(manifest) => {
            context.audit_with_token(
                "quarantine",
                "take_copy",
                Effect::Changed,
                format!(
                    "held a duplicate copy: {} ({})",
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
                "take_copy",
                Effect::Refused,
                format!("could not hold {path}: {error}"),
            );
            Response::Error {
                message: error.to_string(),
            }
        }
    }
}

/// Delete quarantined items for good.
///
/// One code path for one item and for all of them, because emptying the store
/// is the same decision repeated and should fail the same way per item: one
/// that cannot be removed is reported and the rest still go, rather than the
/// whole thing stopping half way with no way to tell what happened.
fn delete_quarantined(ids: &[String], context: &Context) -> Response {
    let mut items = 0_usize;
    let mut bytes_freed = 0_u64;
    let mut refused = Vec::new();

    for id in ids {
        match context.quarantine.delete_now(id) {
            Ok(bytes) => {
                items += 1;
                bytes_freed += bytes;
                // Recorded without an undo token, because there is no undo.
                context.audit(
                    "quarantine",
                    "delete",
                    Effect::Changed,
                    format!("deleted {id} for good, freeing {}", human_bytes(bytes)),
                );
            }
            Err(error) => {
                context.audit(
                    "quarantine",
                    "delete",
                    Effect::Refused,
                    format!("could not delete {id}: {error}"),
                );
                refused.push(error.to_string());
            }
        }
    }

    Response::Deleted {
        items,
        bytes_freed,
        refused,
    }
}

fn scan_path(path: &str, context: &Context, user: &UserContext) -> Response {
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
        Ok(mut scan) => {
            // A scan of a whole drive leaves a summary for the person who
            // asked, so the next one can say what grew.
            crate::growth::keep_summary(&mut scan, context, user);
            // Audited: a scan is something the user asked for, so it belongs in
            // the record of what happened, even though it changes nothing.
            context.audit(
                "storage",
                "scan",
                Effect::Observed,
                format!(
                    "scanned {}: {} in {} files, {} unreadable, {} ms",
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

/// Read one folder for the map, below where a scan of its drive stops.
///
/// What may be asked for, and how the folder is found, are decided in
/// [`kam_storage::scan::scan_folder`]. Here it is recorded: opening a folder
/// on the map is something a person asked for, like the scan it came from,
/// and a refusal is recorded like any other.
fn scan_folder(path: &str, context: &Context) -> Response {
    match kam_storage::scan::scan_folder(path) {
        Ok(folder) => {
            context.audit(
                "storage",
                "scan_folder",
                Effect::Observed,
                format!(
                    "read {}: {} {}, {} ms",
                    folder.path,
                    human_bytes(folder.tree.bytes),
                    match folder.method {
                        kam_storage::ScanMethod::MasterFileTable => "by the file table",
                        kam_storage::ScanMethod::DirectoryWalk => "by walking it",
                    },
                    folder.elapsed_ms
                ),
            );
            Response::Folder(Box::new(folder))
        }
        Err(error) => {
            // A refusal is already a sentence for the person. Anything else
            // is given the folder it was about.
            let message = match error {
                kam_core::Error::Refused(reason) => reason,
                other => format!("{path} could not be read: {other}"),
            };
            context.audit("storage", "scan_folder", Effect::Refused, message.clone());
            Response::Error { message }
        }
    }
}

/// Carry out one organisation proposal.
///
/// The fence is re-derived here rather than trusted. The proposal came from
/// this agent, but the paths come back as strings from a client, and a client
/// is not obliged to send back what it was given.
fn apply_move(from: &str, to: &str, context: &Context, user: &UserContext) -> Response {
    if let Err(refusal) = kam_storage::organise::check_movable(from, to, user) {
        context.audit(
            "storage",
            "move_file",
            Effect::Refused,
            format!("refused to move {from}: {refusal}"),
        );
        return Response::Error { message: refusal };
    }

    let source = std::path::Path::new(from);
    let bytes = std::fs::metadata(source)
        .map(|data| data.len())
        .unwrap_or(0);

    match context
        .quarantine
        .move_file(source, std::path::Path::new(to), bytes)
    {
        Ok(record) => {
            context.audit_with_token(
                "storage",
                "move_file",
                Effect::Changed,
                format!("moved {from} to {to} ({})", human_bytes(record.bytes)),
                Some(record.id.clone()),
            );
            Response::Moved(record)
        }
        Err(error) => {
            context.audit(
                "storage",
                "move_file",
                Effect::Refused,
                format!("could not move {from}: {error}"),
            );
            Response::Error {
                message: error.to_string(),
            }
        }
    }
}

/// Sizes appear in audit entries a person reads, so they are written the way a
/// person would say them rather than as a raw byte count.
pub(crate) fn human_bytes(bytes: u64) -> String {
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

/// Take one comparison of the machine with its history, and write it down.
///
/// The page and the weekly check both come here, so the comparison the weekly
/// check takes is the one the page would have taken: the machine and every
/// account signed in at the time, as `baseline::collect` reads them. Nothing
/// about who asked is passed in. The weekly check is started by Task
/// Scheduler as the person who switched it on, and the page by whoever opens
/// it, and neither can narrow what is compared to their own account.
///
/// Audited as an observation: a comparison is part of the history of what was
/// looked at, and the entry says what could not be checked as well as what
/// was found, so that one that saw less than it wanted to does not read later
/// as a clean bill of health.
fn take_comparison(context: &Context, by: TakenBy) -> kam_core::Result<kam_core::changes::Sweep> {
    let look = crate::baseline::collect();
    let readings = crate::baseline::readings();
    let sweep = context
        .store
        .compare(&look.seen, &look.unreadable, &readings, &look.parts, by)?;
    context.audit(
        "changes",
        "sweep",
        Effect::Observed,
        sweep_line(look.seen.len(), &sweep, by),
    );
    Ok(sweep)
}

/// The Activity line for one comparison: what took it, how much was compared,
/// what came of it, and what it could not vouch for.
///
/// What could not be read is counted, and apart from it what was recorded
/// afresh without being compared. The second was counted as the first, so a
/// comparison that had read everything said a source could not be read.
fn sweep_line(compared: usize, sweep: &kam_core::changes::Sweep, by: TakenBy) -> String {
    let found = sweep.differences.len();
    let mut line = format!(
        "{}compared {compared} things against the last sweep: {found} {}",
        match by {
            TakenBy::Page => "",
            TakenBy::WeeklyCheck => "the weekly check ",
        },
        if sweep.baseline {
            "differences (this was the first, so nothing was compared)"
        } else if found == 1 {
            "difference"
        } else {
            "differences"
        }
    );
    match sweep.unreadable.len() {
        0 => {}
        1 => line.push_str("; 1 source could not be read"),
        unread => line.push_str(&format!("; {unread} sources could not be read")),
    }
    match sweep.afresh.len() {
        0 => {}
        1 => line.push_str("; 1 part was recorded afresh, not compared"),
        afresh => line.push_str(&format!(
            "; {afresh} parts were recorded afresh, not compared"
        )),
    }
    line
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn someone() -> UserContext {
        UserContext::new(None, r"C:\Users\someone")
    }

    /// Changing a machine-wide setting needs an administrator, whichever way.
    ///
    /// Turning a protection on is included, not only turning one off. Windows
    /// asks for an administrator in both directions, and the rule this follows
    /// is "never a change the caller could not make themselves", which does not
    /// depend on whether the change looks like tightening.
    #[test]
    fn every_machine_wide_setting_needs_an_administrator() {
        let user = someone();
        let changes = [
            Request::SetHardening {
                id: "pua-protection".to_owned(),
                wanted: kam_scanner::hardening::Wanted::Block,
            },
            Request::SetHardening {
                id: "pua-protection".to_owned(),
                wanted: kam_scanner::hardening::Wanted::Off,
            },
            Request::SetCanaryAuditing { enabled: true },
            Request::SetCanaryAuditing { enabled: false },
            Request::BlockProgram {
                path: r"C:\Program Files\thing.exe".to_owned(),
            },
            Request::UnblockProgram {
                rule: "KAM Security: block thing.exe".to_owned(),
            },
            Request::SetProtection { enabled: true },
            Request::SetProtection { enabled: false },
        ];
        for request in &changes {
            assert!(
                needs_administrator(request, &user),
                "{request:?} was allowed without an administrator"
            );
        }
    }

    /// Reading and measuring are anyone's to ask for.
    #[test]
    fn reading_needs_nobody_special() {
        let user = someone();
        for request in [
            Request::GetSystemStatus,
            Request::GetRecentAudit { limit: 10 },
            Request::ListVolumes,
            Request::GetHardening,
            Request::GetFirewall,
            Request::GetProtection,
            Request::SurveyCaches,
            Request::ReadComparison { id: 1 },
            Request::GetDeviceFacts,
        ] {
            assert!(
                !needs_administrator(&request, &user),
                "{request:?} demanded an administrator for a read"
            );
        }
    }

    /// The TPM and drive C: are answered whatever the machine allows, each
    /// read or said not to have been, and asking is not written to the log:
    /// the Scanner asks on every visit.
    #[test]
    fn device_facts_are_answered_and_not_recorded() {
        let context = context(Mode::Console);
        let response = handle(
            Request::GetDeviceFacts,
            &context,
            &Reporter::silent(),
            &someone(),
        );
        assert!(
            matches!(response, Response::DeviceFacts(_)),
            "unexpected answer: {response:?}"
        );
        assert!(context.store.recent_audit(10).unwrap().is_empty());
    }

    /// A cache is the caller's to clear when it is in their profile, and the
    /// machine's otherwise, the same line Disk Cleanup draws.
    #[test]
    fn a_cache_clear_needs_an_administrator_only_beyond_the_callers_profile() {
        let user = someone();
        let clear = |id: &str| Request::ClearCache { id: id.to_owned() };

        for own in ["temp-user", "thumbnails"] {
            assert!(
                !needs_administrator(&clear(own), &user),
                "{own} lives in the caller's profile and still demanded an administrator"
            );
        }
        for machine in ["temp-system", "windows-update", "windows-old"] {
            assert!(
                needs_administrator(&clear(machine), &user),
                "{machine} reaches outside the caller's profile and was allowed without one"
            );
        }
        assert!(
            needs_administrator(&clear("not-a-real-cache"), &user),
            "an unknown cache was treated as the caller's own"
        );
    }

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
            jobs: Default::default(),
            quarantine: kam_quarantine::Store::open(&quarantine_root).unwrap(),
            behaviour: Default::default(),
        }
    }

    #[test]
    fn a_list_is_cut_where_it_stops_fitting_and_keeps_its_order() {
        // Each of these is 12 bytes as JSON, quotes included, and 13 with the
        // comma after it.
        let items: Vec<String> = (0..10).map(|n| format!("item-{n:05}")).collect();

        let (kept, rest) = fitting(items.clone(), 40);
        assert_eq!(kept, items[..3]);
        assert_eq!(rest, items[3..]);

        let (kept, rest) = fitting(items.clone(), usize::MAX);
        assert_eq!(kept.len(), 10);
        assert!(rest.is_empty());

        let (kept, rest) = fitting(items.clone(), 5);
        assert!(kept.is_empty(), "nothing fits, so nothing is sent");
        assert_eq!(rest.len(), 10);
    }

    /// Two identical files in a folder with a long name, as a photo archive
    /// kept twice is made of.
    fn duplicate_pair(number: usize) -> kam_storage::DuplicateGroup {
        use kam_storage::{FileCopy, Owner, Verdict};
        let copy = |side: &str| FileCopy {
            path: format!(
                r"C:\Users\someone\Pictures\{side}\{}\IMG_{number:06}.CR3",
                "holiday-album-with-a-long-name-".repeat(8)
            ),
            owner: Owner::Yours,
            removable: true,
        };
        kam_storage::DuplicateGroup {
            bytes: 30_000_000,
            wasted_bytes: 30_000_000,
            reclaimable_bytes: 30_000_000,
            copies: vec![copy("Archive"), copy("Archive (copy)")],
            verdict: Verdict::Choose,
            suggested_keep: Some(0),
            reasons: vec![
                "All 2 copies are in folders of yours, so keeping one and removing the \
                 rest loses nothing."
                    .to_owned(),
            ],
        }
    }

    fn summary_of(groups: &[kam_storage::DuplicateGroup]) -> kam_storage::DuplicateSummary {
        kam_storage::DuplicateSummary {
            groups: groups.len(),
            wasted_bytes: groups.iter().map(|group| group.wasted_bytes).sum(),
            reclaimable_bytes: groups.iter().map(|group| group.reclaimable_bytes).sum(),
            actionable: groups.len(),
            examined: groups.len() * 2,
            head_hashed: groups.len() * 2,
            fully_hashed: groups.len() * 2,
            elapsed_ms: 1,
            truncated: false,
            quarantine_only_on: None,
            unlisted: Default::default(),
        }
    }

    /// A search with more duplicate sets than one reply holds still answers.
    ///
    /// It used to run to the end and then lose everything: the frame was over
    /// the limit, the agent closed the connection instead of sending it, and
    /// the window showed a pipe error. Twenty thousand pairs is a photo
    /// archive that somebody copied once.
    #[test]
    fn a_duplicate_search_too_large_for_one_reply_is_cut_to_fit_and_says_what_was_left_out() {
        use kam_ipc::frame::write_frame;
        use kam_ipc::Reply;

        let found: Vec<kam_storage::DuplicateGroup> = (0..20_000).map(duplicate_pair).collect();
        let whole = summary_of(&found);

        // The premise: as found, this does not fit in a frame at all.
        let unbounded = Reply::Done(Response::Duplicates {
            groups: found.clone(),
            summary: whole.clone(),
        });
        assert!(
            write_frame(&mut Vec::new(), &unbounded).is_err(),
            "the test's answer is not large enough to show anything"
        );

        let (groups, summary) = sendable_duplicates(found.clone(), whole.clone());
        let listed = groups.len();
        assert!(listed > 0, "nothing at all was sent");
        assert!(listed < found.len(), "nothing was left out");
        // The head of the list, in the order it came: the most reclaimable.
        assert_eq!(groups[0].copies[0].path, found[0].copies[0].path);
        assert_eq!(
            groups[listed - 1].copies[0].path,
            found[listed - 1].copies[0].path
        );

        // The figures still count everything found, and what was left out is
        // said, set for set and byte for byte.
        assert_eq!(summary.groups, 20_000);
        assert_eq!(summary.wasted_bytes, whole.wasted_bytes);
        assert_eq!(summary.unlisted.groups, 20_000 - listed);
        assert_eq!(
            summary.unlisted.wasted_bytes,
            30_000_000 * (20_000 - listed) as u64
        );
        assert_eq!(
            summary.unlisted.reclaimable_bytes,
            summary.unlisted.wasted_bytes
        );
        assert_eq!(summary.unlisted.actionable, 20_000 - listed);

        let mut frame = Vec::new();
        write_frame(
            &mut frame,
            &Reply::Done(Response::Duplicates { groups, summary }),
        )
        .expect("the answer that is sent must fit in one frame");
        assert!(frame.len() <= kam_ipc::MAX_FRAME_BYTES + 4);
    }

    /// The same for a survey that finds thousands of large downloads.
    ///
    /// Download addresses are kept whole, and real ones carry signed tokens
    /// that run to kilobytes each.
    #[test]
    fn a_survey_with_too_many_downloads_for_one_reply_is_cut_to_fit_and_counts_the_rest() {
        use kam_ipc::frame::write_frame;
        use kam_ipc::Reply;
        use kam_storage::provenance::{AccessTimes, Zone};

        let token = "t".repeat(1_500);
        let found: Vec<kam_storage::Download> = (0..6_000_u64)
            .map(|number| kam_storage::Download {
                path: format!(r"C:\Users\someone\Downloads\installer-{number:05}.exe"),
                name: format!("installer-{number:05}.exe"),
                bytes: 4_000_000_000 - number,
                zone: Zone::Internet,
                host_url: Some(format!("https://cdn.example.com/get?signature={token}")),
                referrer_url: Some(format!("https://example.com/page?session={token}")),
                days_since_arrival: Some(40),
                days_since_access: Some(3),
            })
            .collect();
        let summary = kam_storage::DownloadSummary {
            found: found.len(),
            total_bytes: found.iter().map(|download| download.bytes).sum(),
            access_times: AccessTimes::Recorded,
            examined: 20_000,
            read_as_opened: 0,
            unlisted: 0,
        };
        let reply = |downloads: Vec<kam_storage::Download>,
                     download_summary: kam_storage::DownloadSummary| {
            Reply::Done(Response::Applications {
                apps: Vec::new(),
                summary: kam_storage::apps::summarise(&[]),
                orphans: Vec::new(),
                orphan_summary: kam_storage::orphans::summarise(&[]),
                downloads,
                download_summary: Box::new(download_summary),
                old_files: Vec::new(),
                old_file_summary: Box::new(no_old_files()),
                timings: Box::default(),
            })
        };

        // The premise: as found, this does not fit in a frame at all.
        assert!(
            write_frame(&mut Vec::new(), &reply(found.clone(), summary.clone())).is_err(),
            "the test's answer is not large enough to show anything"
        );

        let mut bounded = summary.clone();
        let downloads = sendable_downloads(found.clone(), &mut bounded);
        assert!(!downloads.is_empty() && downloads.len() < found.len());
        // Largest first, so it is the smallest that are left out.
        assert_eq!(downloads[0].path, found[0].path);
        assert_eq!(bounded.unlisted, found.len() - downloads.len());
        assert_eq!(bounded.found, 6_000, "the count is of everything found");
        assert_eq!(bounded.total_bytes, summary.total_bytes);

        write_frame(&mut Vec::new(), &reply(downloads, bounded))
            .expect("the answer that is sent must fit in one frame");
    }

    fn no_old_files() -> kam_storage::OldFileSummary {
        kam_storage::OldFileSummary {
            found: 0,
            total_bytes: 0,
            access_times: kam_storage::provenance::AccessTimes::Recorded,
            min_bytes: kam_storage::old_files::MIN_BYTES,
            older_than_days: kam_storage::old_files::OLDER_THAN_DAYS,
            left_out: Vec::new(),
            undated: 0,
            undated_bytes: 0,
            unplaced: 0,
        }
    }

    fn old_file(number: u64, folder: &str) -> kam_storage::OldFile {
        kam_storage::OldFile {
            path: format!(r"C:\Users\someone\Documents\{folder}\image-{number:04}.iso"),
            name: format!("image-{number:04}.iso"),
            bytes: 9_000_000_000 - number,
            created: Some(1_600_000_000),
            modified: Some(1_590_000_000),
            accessed: Some(1_610_000_000),
        }
    }

    /// The list of large old files is short and is sent whole, and it still
    /// cannot take the rest of a survey's answer down with it.
    ///
    /// Two hundred ordinary rows are a small part of a reply. Two hundred
    /// paths at the length Windows allows are not, and they share their reply
    /// with every application, leftover and download.
    #[test]
    fn the_list_of_large_old_files_is_sent_whole_unless_its_paths_are_too_long_to_fit() {
        let ordinary: Vec<kam_storage::OldFile> = (0..kam_storage::old_files::LISTED as u64)
            .map(|number| old_file(number, "disk images"))
            .collect();
        assert_eq!(sendable_old_files(ordinary.clone()), ordinary);

        let deep = "a-folder-with-a-long-name\\".repeat(1_200);
        let long: Vec<kam_storage::OldFile> = (0..kam_storage::old_files::LISTED as u64)
            .map(|number| old_file(number, &deep))
            .collect();
        let whole: usize = long
            .iter()
            .map(|file| serde_json::to_vec(file).unwrap().len())
            .sum();
        assert!(
            whole > OLD_FILES_REPLY_BYTES,
            "the test's list is not long enough to show anything"
        );

        let sent = sendable_old_files(long.clone());
        assert!(!sent.is_empty() && sent.len() < long.len());
        // Largest first, so it is the smallest that are not sent.
        assert_eq!(sent[..], long[..sent.len()]);
        let size: usize = sent
            .iter()
            .map(|file| serde_json::to_vec(file).unwrap().len() + 1)
            .sum();
        assert!(size <= OLD_FILES_REPLY_BYTES);
    }

    /// A duplicate search of another drive says quarantine cannot reach it.
    ///
    /// The store renames within its own drive and refuses anything else, and
    /// the page offered "Remove this one" on a second drive all the same.
    #[test]
    fn a_search_of_another_drive_names_the_only_drive_quarantine_holds_from() {
        let context = context(Mode::Console);
        let store = context
            .quarantine
            .root()
            .to_string_lossy()
            .chars()
            .next()
            .unwrap()
            .to_ascii_uppercase();
        let another = if store == 'Q' { 'R' } else { 'Q' };

        assert_eq!(quarantine_only_on(&context, store), None);
        assert_eq!(
            quarantine_only_on(&context, store.to_ascii_lowercase()),
            None,
            "the same drive in lower case is still the same drive"
        );
        assert_eq!(quarantine_only_on(&context, another), Some(store));
    }

    /// A scratch directory sitting directly inside a real data root.
    ///
    /// It has to be there rather than in the temp folder: the fence only
    /// allows a directory that sits *directly* inside `ProgramData`,
    /// `LocalAppData` or `Roaming`, which is exactly the shape of a leftover.
    /// Testing anywhere else would test something the product never does.
    struct Leftover {
        /// The throwaway profile the fence is told to confine itself to.
        root: std::path::PathBuf,
        /// The leftover directory itself, one level inside its Local AppData.
        path: std::path::PathBuf,
    }

    impl Leftover {
        /// A leftover inside a throwaway profile, with the caller to match.
        ///
        /// It used to be created in the tester's own `%LOCALAPPDATA%` and
        /// checked against `UserContext::current()`. That stopped working once
        /// the fence resolved paths before judging them, and the reason is
        /// worth recording: when the test suite runs inside a packaged
        /// application — the desktop app this project is developed in is one —
        /// Windows redirects newly created directories under Local AppData into
        /// the package's own store, so the leftover's real path came back as
        /// `...\AppData\Local\Packages\<package>\LocalCache\Local\<name>` and
        /// the fence correctly said it was nested too deep.
        ///
        /// The service is not packaged and sees no such redirection, so this
        /// was the test's environment leaking in rather than a fault in the
        /// fence. A scratch profile outside AppData removes the dependency on
        /// where the tests happen to run, which the storage tests needed for
        /// the same reason.
        fn new(tag: &str) -> Self {
            let home = std::env::var("USERPROFILE").expect("a user profile");
            let root = std::path::PathBuf::from(home)
                .join(format!("kam-quarantine-test-{}-{tag}", std::process::id()));
            let path = root.join("AppData").join("Local").join("DeadVendor");
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(path.join("cache")).unwrap();
            std::fs::create_dir_all(root.join("AppData").join("Roaming")).unwrap();
            std::fs::write(path.join("settings.cfg"), b"user settings worth keeping").unwrap();
            std::fs::write(path.join("cache").join("blob.bin"), vec![7_u8; 4096]).unwrap();
            Self { root, path }
        }

        /// The caller this leftover belongs to.
        fn user(&self) -> UserContext {
            UserContext::new(None, &self.root.to_string_lossy())
        }

        fn text(&self) -> String {
            std::fs::read_to_string(self.path.join("settings.cfg")).unwrap()
        }
    }

    impl Drop for Leftover {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// The schedule request carries a day and an hour, and nothing else.
    ///
    /// This registers something that runs elevated on a timer, so the program
    /// it starts and the account it runs as are decided by the agent. If a
    /// future change lets either of those in over the pipe, this is the test
    /// that should stop it.
    #[test]
    fn the_schedule_request_cannot_name_a_program_or_an_account() {
        let wire = serde_json::to_string(&Request::SetSchedule {
            enabled: true,
            day: "Sunday".to_owned(),
            hour: 3,
        })
        .unwrap();

        let fields: serde_json::Value = serde_json::from_str(&wire).unwrap();
        let object = fields.as_object().unwrap();
        let mut keys: Vec<&String> = object.keys().collect();
        keys.sort();
        assert_eq!(
            keys,
            vec!["day", "enabled", "hour", "op"],
            "the request grew a field: {wire}"
        );
    }

    #[test]
    fn an_hour_outside_the_clock_is_refused_rather_than_clamped() {
        let context = context(Mode::Service);
        let response = handle(
            Request::SetSchedule {
                enabled: true,
                day: "Sunday".to_owned(),
                hour: 25,
            },
            &context,
            &Reporter::silent(),
            &UserContext::current(),
        );
        let Response::Error { message } = &response else {
            panic!("25 o'clock was accepted: {response:?}");
        };
        assert!(message.contains("between 0 and 23"), "{message}");
    }

    #[test]
    fn asking_for_the_schedule_answers_whether_or_not_one_exists() {
        let context = context(Mode::Service);
        let response = handle(
            Request::GetSchedule,
            &context,
            &Reporter::silent(),
            &UserContext::current(),
        );
        let Response::Schedule(schedule) = &response else {
            panic!("expected a schedule, got {response:?}");
        };
        // Nothing is registered in a test run, and that is a real answer.
        if !schedule.enabled {
            assert!(schedule.command.is_none() || schedule.day.is_some());
        }

        // And it survives the wire, which is the check the last protocol
        // addition shipped without.
        let wire = serde_json::to_string(&kam_ipc::Reply::Done(response.clone())).unwrap();
        let back: kam_ipc::Reply = serde_json::from_str(&wire).unwrap();
        assert!(matches!(back, kam_ipc::Reply::Done(Response::Schedule(_))));
    }

    #[test]
    fn a_check_run_on_demand_answers_and_is_recorded() {
        let context = context(Mode::Service);
        let response = handle(
            Request::RunCheck,
            &context,
            &Reporter::silent(),
            &UserContext::current(),
        );
        let Response::Checked { findings } = &response else {
            panic!("expected findings, got {response:?}");
        };
        for finding in findings {
            assert!(!finding.summary.is_empty());
        }

        let recorded = context
            .store
            .recent_audit(200)
            .unwrap()
            .into_iter()
            .filter(|entry| entry.module == "check")
            .count();
        assert!(
            recorded > findings.len(),
            "the run itself should be recorded too"
        );
    }

    /// A comparison's list is read again through the pipe, and asking for one
    /// that is not kept is said, not answered with an empty list.
    #[test]
    fn a_kept_comparison_is_read_again_and_one_not_kept_is_said() {
        let context = context(Mode::Service);
        let thing = |detail: &str| kam_core::changes::Sighting {
            kind: "service".to_owned(),
            scope: "machine".to_owned(),
            name: "Thing".to_owned(),
            detail: detail.to_owned(),
            trust: "signed by Thing Ltd".to_owned(),
        };
        context.store.sweep(&[thing("a.exe")], &[]).unwrap();
        let shown = context.store.sweep(&[thing("b.exe")], &[]).unwrap();

        let response = handle(
            Request::ReadComparison { id: shown.id },
            &context,
            &Reporter::silent(),
            &someone(),
        );
        let Response::Comparison(kept) = response else {
            panic!("expected the list, got {response:?}");
        };
        assert_eq!(kept.differences.len(), 1);
        assert_eq!(kept.differences[0].detail, "b.exe");

        let response = handle(
            Request::ReadComparison { id: shown.id + 1 },
            &context,
            &Reporter::silent(),
            &someone(),
        );
        assert!(
            matches!(response, Response::Error { .. }),
            "a comparison that is not kept came back as {response:?}"
        );
    }

    /// The Activity line counts what could not be read, and apart from it
    /// what was recorded afresh. The second was counted as the first, so a
    /// comparison that had read everything said a source could not be read.
    #[test]
    fn the_activity_line_does_not_count_what_was_recorded_afresh_as_unreadable() {
        let afresh_only = kam_core::changes::Sweep {
            afresh: vec!["Services were recorded as they are, and not compared.".to_owned()],
            ..Default::default()
        };
        let line = sweep_line(312, &afresh_only, TakenBy::Page);
        assert!(!line.contains("could not be read"), "{line}");
        assert!(
            line.ends_with("; 1 part was recorded afresh, not compared"),
            "{line}"
        );

        let both = kam_core::changes::Sweep {
            unreadable: vec!["the task store would not open".to_owned()],
            afresh: vec!["one".to_owned(), "two".to_owned()],
            ..Default::default()
        };
        assert_eq!(
            sweep_line(312, &both, TakenBy::Page),
            "compared 312 things against the last sweep: 0 differences; 1 source could not \
             be read; 2 parts were recorded afresh, not compared"
        );
        assert_eq!(
            sweep_line(312, &kam_core::changes::Sweep::default(), TakenBy::Page),
            "compared 312 things against the last sweep: 0 differences"
        );
        // And one the weekly check took says so.
        assert_eq!(
            sweep_line(
                312,
                &kam_core::changes::Sweep::default(),
                TakenBy::WeeklyCheck
            ),
            "the weekly check compared 312 things against the last sweep: 0 differences"
        );
    }

    /// The weekly check takes a comparison, and it is the one the page would
    /// have taken, whoever started it.
    ///
    /// The page took the only comparisons, so a week in which nobody opened it
    /// was drawn as a week nobody looked at though the weekly check had run.
    /// The check is started by Task Scheduler as the person who switched it
    /// on, not through the window, so what it compares must not depend on who
    /// asked: here it is started by one caller and the page opened by another.
    /// The page's comparison then follows straight on from the check's, and
    /// meets no account for the first time, which it would if the check had
    /// looked at fewer accounts than the page does.
    #[test]
    fn the_weekly_check_takes_the_comparison_the_page_would() {
        let context = context(Mode::Service);
        let response = handle(Request::RunCheck, &context, &Reporter::silent(), &someone());
        assert!(
            matches!(response, Response::Checked { .. }),
            "the check itself still answers as it did: {response:?}"
        );
        let swept = context
            .store
            .recent_audit(200)
            .unwrap()
            .into_iter()
            .find(|entry| entry.module == "changes" && entry.action == "sweep")
            .expect("the weekly check's comparison is written down");
        assert!(
            swept.detail.starts_with("the weekly check compared"),
            "{}",
            swept.detail
        );

        let response = handle(
            Request::SweepForChanges,
            &context,
            &Reporter::silent(),
            &UserContext::current(),
        );
        let Response::Changes(sweep) = response else {
            panic!("expected a comparison, got {response:?}");
        };
        assert!(
            !sweep.baseline,
            "the weekly check took no comparison, so the page's was the first"
        );
        let takers: Vec<Option<TakenBy>> = sweep.kept.iter().map(|one| one.taken_by).collect();
        assert_eq!(
            takers,
            vec![Some(TakenBy::Page)],
            "the baseline is not offered"
        );
        assert!(
            sweep.afresh.is_empty(),
            "the page met something the weekly check had not looked at: {:?}",
            sweep.afresh
        );
    }

    /// A lookup record carries a hash and a line, and nothing a caller invents.
    ///
    /// The lookup itself happens in the window, so the record has to be asked
    /// for over the pipe. That makes it the one audit entry a client can cause,
    /// which is why its shape is checked rather than trusted.
    #[test]
    fn a_lookup_record_needs_a_real_hash_and_cannot_carry_a_story() {
        let context = context(Mode::Service);
        let user = UserContext::current();

        for bad in ["", "not-a-hash", "abc123", &"f".repeat(63)] {
            let response = handle(
                Request::RecordLookup {
                    sha256: bad.to_owned(),
                    outcome: "Clean".to_owned(),
                },
                &context,
                &Reporter::silent(),
                &user,
            );
            assert!(
                matches!(response, Response::Error { .. }),
                "{bad:?} was accepted as a hash"
            );
        }

        // A real one is recorded, and the free-text half is clipped so it
        // cannot be used to write paragraphs into the log.
        let digest = "a".repeat(64);
        let response = handle(
            Request::RecordLookup {
                sha256: digest.clone(),
                outcome: "x".repeat(500),
            },
            &context,
            &Reporter::silent(),
            &user,
        );
        assert!(matches!(response, Response::Acknowledged), "{response:?}");

        let recorded = context
            .store
            .recent_audit(10)
            .unwrap()
            .into_iter()
            .find(|entry| entry.module == "virustotal")
            .expect("the lookup was not recorded");
        assert!(recorded.detail.contains(&digest));
        assert!(
            recorded.detail.len() < 260,
            "the outcome was not clipped: {} chars",
            recorded.detail.len()
        );
    }

    /// The clear takes an id, and an id it does not know clears nothing.
    ///
    /// This is the whole security argument for the cache feature: the agent
    /// runs as LocalSystem, so if a request could name a directory to empty
    /// then anything that reached the pipe could empty any directory. It names
    /// an id instead, and these are the shapes an attempt to smuggle a path
    /// through one would take.
    #[test]
    fn a_cache_id_the_agent_does_not_know_clears_nothing() {
        let context = context(Mode::Service);
        let user = UserContext::current();

        for id in [
            r"C:\Windows",
            r"C:\Users\someone\Documents",
            "temp-user\\..\\..\\Windows",
            "../../Windows",
            "",
            "TEMP-USER",
        ] {
            let response = handle(
                Request::ClearCache { id: id.to_owned() },
                &context,
                &Reporter::silent(),
                &user,
            );
            assert!(
                matches!(response, Response::Error { .. }),
                "{id} was not refused: {response:?}"
            );
        }

        // And every refusal is on the record, because an id that is not in the
        // catalogue is the shape a tampered request takes.
        let refusals = context
            .store
            .recent_audit(50)
            .unwrap()
            .into_iter()
            .filter(|entry| entry.action == "clear_cache")
            .count();
        assert_eq!(refusals, 6, "every attempt should have been recorded");
    }

    /// Asked to clear something that is only explained, the agent refuses by
    /// name, for anybody, and writes the refusal down.
    ///
    /// The hibernation file, a browser's site data and the rest are measured
    /// and shown with no Clear button. A request for one is therefore not
    /// something the window sends, and is recorded as the refusal it is. It
    /// is not put to an administrator first: there is nothing a yes could do.
    #[test]
    fn something_that_is_only_explained_is_refused_and_the_refusal_recorded() {
        let context = context(Mode::Service);
        let user = someone();

        for id in [
            "hibernation-file",
            "website-storage",
            "visual-studio-packages",
        ] {
            let request = Request::ClearCache { id: id.to_owned() };
            assert!(
                !needs_administrator(&request, &user),
                "{id} would be answered with a request for administrator rights"
            );
            let response = handle(request, &context, &Reporter::silent(), &user);
            let Response::Error { message } = response else {
                panic!("{id} was not refused: {response:?}");
            };
            assert!(
                message.contains("nothing here clears it"),
                "{id}: the refusal should say why: {message}"
            );
        }

        let recorded: Vec<_> = context
            .store
            .recent_audit(50)
            .unwrap()
            .into_iter()
            .filter(|entry| entry.action == "clear_cache")
            .collect();
        assert_eq!(recorded.len(), 3, "every attempt should have been recorded");
        assert!(recorded.iter().all(|entry| entry.effect == Effect::Refused));
    }

    /// Only a copy in a folder of the caller's is ever removed.
    #[test]
    fn a_duplicate_copy_a_program_owns_is_refused() {
        let context = context(Mode::Service);
        let user = UserContext::current();

        for path in [
            r"C:\Windows\System32\kernel32.dll",
            r"C:\Program Files\Something\thing.dll",
            r"C:\ProgramData\Package Cache\x\setup.exe",
        ] {
            let response = handle(
                Request::QuarantineCopy {
                    path: path.to_owned(),
                    reason: "a test".to_owned(),
                    chosen: false,
                    keep: String::new(),
                },
                &context,
                &Reporter::silent(),
                &user,
            );
            let Response::Error { message } = &response else {
                panic!("{path} was not refused: {response:?}");
            };
            assert!(
                message.contains("folder of yours"),
                "the refusal should say why: {message}"
            );
        }

        // Nothing was touched.
        assert!(std::path::Path::new(r"C:\Windows\System32\kernel32.dll").exists());
    }

    /// A throwaway profile with a Downloads folder, a copy to keep and a
    /// redundant copy in it, and the caller it belongs to.
    ///
    /// The test below used to write its copy into the real Downloads folder of
    /// whoever ran it, where a running copy of the program saw it land and
    /// then go, and recorded it in their history every time.
    fn a_profile_with_two_copies(
        tag: &str,
        copy: &[u8],
        keep: &[u8],
    ) -> (std::path::PathBuf, UserContext, String, String) {
        let profile = std::env::temp_dir().join(format!(
            "kam-dispatch-copy-profile-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&profile);
        let downloads = profile.join("Downloads");
        std::fs::create_dir_all(&downloads).unwrap();
        std::fs::write(downloads.join("copy.bin"), copy).unwrap();
        std::fs::write(downloads.join("keep.bin"), keep).unwrap();
        let user = UserContext::new(
            Some("S-1-5-21-0-0-0-4007".to_owned()),
            &profile.to_string_lossy(),
        );
        let path = downloads.join("copy.bin").to_string_lossy().into_owned();
        let keep = downloads.join("keep.bin").to_string_lossy().into_owned();
        (profile, user, path, keep)
    }

    /// A real redundant copy is held, and comes back.
    #[test]
    fn a_copy_in_a_folder_of_yours_is_held_and_restored() {
        let context = context(Mode::Service);
        let (profile, user, path, keep) =
            a_profile_with_two_copies("held", &[9_u8; 2048], &[9_u8; 2048]);
        let copy = std::path::PathBuf::from(&path);

        let held = handle(
            Request::QuarantineCopy {
                path: path.clone(),
                reason: "a redundant copy".to_owned(),
                chosen: false,
                keep,
            },
            &context,
            &Reporter::silent(),
            &user,
        );
        let Response::Quarantined(manifest) = &held else {
            let _ = std::fs::remove_dir_all(&profile);
            panic!("expected the copy to be held, got {held:?}");
        };
        assert_eq!(manifest.bytes, 2048, "the size was not measured");
        assert!(!copy.exists(), "the copy is still where it was");

        // The whole reason this is quarantine rather than deletion.
        let back = handle(
            Request::RestoreQuarantined {
                id: manifest.id.clone(),
            },
            &context,
            &Reporter::silent(),
            &user,
        );
        assert!(matches!(back, Response::Quarantined(_)), "{back:?}");
        assert!(copy.exists(), "the copy did not come back");
        assert_eq!(std::fs::read(&copy).unwrap().len(), 2048);

        let _ = std::fs::remove_dir_all(&profile);
    }

    /// A copy that has changed since the search is not taken, and the refusal
    /// is on the record.
    ///
    /// Cleanup keeps its list of duplicates across restarts, so the copy a
    /// person removes may have been edited since. Quarantine deletes for good
    /// after thirty days, so taking it would have been a slow way of losing
    /// the only copy of what it now holds.
    #[test]
    fn a_copy_that_is_no_longer_the_same_as_the_one_kept_is_refused_and_recorded() {
        let context = context(Mode::Service);
        let (profile, user, path, keep) =
            a_profile_with_two_copies("changed", &[1_u8; 2048], &[2_u8; 2048]);

        let response = handle(
            Request::QuarantineCopy {
                path: path.clone(),
                reason: "a redundant copy".to_owned(),
                chosen: false,
                keep,
            },
            &context,
            &Reporter::silent(),
            &user,
        );
        let Response::Error { message } = &response else {
            let _ = std::fs::remove_dir_all(&profile);
            panic!("a copy that is no longer a twin was taken: {response:?}");
        };
        assert!(message.contains("no longer the same as"), "{message}");
        assert!(
            std::path::Path::new(&path).exists(),
            "the copy was moved although it was refused"
        );
        let refused = context
            .store
            .recent_audit(10)
            .unwrap()
            .into_iter()
            .any(|entry| entry.action == "take_copy" && entry.effect == Effect::Refused);
        assert!(refused, "the refusal was not recorded");
        let _ = std::fs::remove_dir_all(&profile);
    }

    /// The cache survey answers, and the reply survives the wire.
    ///
    /// The last protocol addition shipped broken because nothing ever put a
    /// `Response` through serde and back, so every new variant does that here.
    #[test]
    fn the_cache_survey_answers_and_survives_serialisation() {
        let context = context(Mode::Service);
        let response = handle(
            Request::SurveyCaches,
            &context,
            &Reporter::silent(),
            &UserContext::current(),
        );

        let Response::Caches { caches } = &response else {
            panic!("expected a cache list, got {response:?}");
        };
        for cache in caches {
            assert!(!cache.id.is_empty());
            assert!(cache.files > 0, "{} was listed while empty", cache.id);
        }

        let wire = serde_json::to_string(&kam_ipc::Reply::Done(response.clone())).unwrap();
        let back: kam_ipc::Reply = serde_json::from_str(&wire).unwrap();
        let kam_ipc::Reply::Done(Response::Caches { caches: returned }) = back else {
            panic!("the cache list did not survive the wire");
        };
        assert_eq!(returned.len(), caches.len());
    }

    /// Quarantine, list, restore, and check the contents came back.
    ///
    /// The store has its own tests; this exercises the whole agent path around
    /// it — the fence, the size measurement, the audit entry with its undo
    /// token, and the response as it actually travels. That last part is not
    /// incidental: this response could be produced and never delivered,
    /// because its payload was flattened into the frame alongside a field of
    /// the same name, and no test went through serde to notice.
    #[test]
    fn a_leftover_survives_being_quarantined_and_restored() {
        let context = context(Mode::Console);
        let leftover = Leftover::new("roundtrip");
        let original = leftover.path.display().to_string();

        // --- take ------------------------------------------------------
        let taken = handle(
            Request::QuarantinePath {
                path: original.clone(),
                reason: "left behind by a test".to_owned(),
            },
            &context,
            &Reporter::silent(),
            &leftover.user(),
        );

        let Response::Quarantined(manifest) = &taken else {
            panic!("expected the item to be quarantined, got {taken:?}");
        };
        assert_eq!(manifest.original_path, original);
        assert!(
            manifest.bytes >= 4096,
            "size was not measured: {}",
            manifest.bytes
        );
        assert!(!manifest.restored);
        assert!(
            !leftover.path.exists(),
            "the directory is still where it was after being quarantined"
        );

        // --- it has to survive the wire --------------------------------
        let json = serde_json::to_string(&taken).expect("should serialise");
        let returned: Response =
            serde_json::from_str(&json).expect("a quarantine response must be readable back");
        let Response::Quarantined(same) = returned else {
            panic!("the response changed shape crossing the wire");
        };
        assert_eq!(same.id, manifest.id);
        assert_eq!(same.kind, manifest.kind, "the manifest's own kind survived");

        // --- list ------------------------------------------------------
        let listed = handle(
            Request::ListQuarantine,
            &context,
            &Reporter::silent(),
            &UserContext::current(),
        );
        let Response::QuarantineList { items } = listed else {
            panic!("expected a quarantine listing");
        };
        assert!(
            items.iter().any(|item| item.id == manifest.id),
            "the item is not in the store's own listing"
        );

        // --- restore ---------------------------------------------------
        let restored = handle(
            Request::RestoreQuarantined {
                id: manifest.id.clone(),
            },
            &context,
            &Reporter::silent(),
            &UserContext::current(),
        );
        let Response::Quarantined(back) = &restored else {
            panic!("expected the item back, got {restored:?}");
        };
        assert!(back.restored, "the manifest should say it was restored");

        // --- and it is genuinely the same thing -------------------------
        assert!(leftover.path.exists(), "the directory did not come back");
        assert_eq!(
            leftover.text(),
            "user settings worth keeping",
            "the contents changed while it was away"
        );
        assert_eq!(
            std::fs::read(leftover.path.join("cache").join("blob.bin")).unwrap(),
            vec![7_u8; 4096],
            "the nested file did not survive byte for byte"
        );
    }

    /// Both halves are recorded, and the take carries the handle that undoes it.
    #[test]
    fn quarantining_is_written_to_the_audit_log_with_its_undo_token() {
        let context = context(Mode::Console);
        let leftover = Leftover::new("audit");

        let taken = handle(
            Request::QuarantinePath {
                path: leftover.path.display().to_string(),
                reason: "left behind by a test".to_owned(),
            },
            &context,
            &Reporter::silent(),
            &leftover.user(),
        );
        let Response::Quarantined(manifest) = &taken else {
            panic!("expected the item to be quarantined");
        };

        let entries = context.store.recent_audit(50).unwrap();
        let take = entries
            .iter()
            .find(|entry| entry.action == "take")
            .expect("the take was not recorded at all");

        assert_eq!(take.module, "quarantine");
        assert_eq!(
            take.undo_token.as_deref(),
            Some(manifest.id.as_str()),
            "the log records how to undo it"
        );
        // The reason follows a colon. It was joined on with a double hyphen,
        // which a person reading the Activity list sees as a dash.
        assert!(
            take.detail.ends_with("): left behind by a test"),
            "unexpected wording: {}",
            take.detail
        );

        handle(
            Request::RestoreQuarantined {
                id: manifest.id.clone(),
            },
            &context,
            &Reporter::silent(),
            &UserContext::current(),
        );
        let entries = context.store.recent_audit(50).unwrap();
        assert!(
            entries.iter().any(|entry| entry.action == "restore"),
            "the restore was not recorded"
        );
    }

    /// The fence, and that a refusal is recorded rather than passed over.
    #[test]
    fn the_dangerous_shapes_are_refused_and_the_refusal_is_logged() {
        let context = context(Mode::Console);
        let local = std::env::var("LOCALAPPDATA").unwrap();

        let refusals = [
            // A data root itself. Quarantining the whole of LocalAppData
            // would take the user's entire profile with it.
            local.clone(),
            // Nested below a root: only a directory directly inside one is a
            // leftover, anything deeper is part of something still installed.
            format!("{local}\\Microsoft\\Windows"),
            // Outside every root altogether.
            r"C:\Windows\System32".to_owned(),
        ];

        for path in refusals {
            let outcome = handle(
                Request::QuarantinePath {
                    path: path.clone(),
                    reason: "a test that should not succeed".to_owned(),
                },
                &context,
                &Reporter::silent(),
                &UserContext::current(),
            );
            assert!(
                matches!(outcome, Response::Error { .. }),
                "{path} was not refused: {outcome:?}"
            );
            assert!(
                std::path::Path::new(&path).exists(),
                "{path} was touched despite being refused"
            );
        }

        let entries = context.store.recent_audit(50).unwrap();
        let refused = entries
            .iter()
            .filter(|entry| entry.action == "take" && entry.effect == Effect::Refused)
            .count();
        assert_eq!(refused, 3, "every refusal should be in the log");
    }

    #[test]
    fn status_reports_the_current_protocol_version() {
        let context = context(Mode::Console);
        let Response::SystemStatus(status) = handle(
            Request::GetSystemStatus,
            &context,
            &Reporter::silent(),
            &UserContext::current(),
        ) else {
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
        let _ = handle(
            Request::GetSystemStatus,
            &context,
            &Reporter::silent(),
            &UserContext::current(),
        );
        let _ = handle(
            Request::GetRecentAudit { limit: 10 },
            &context,
            &Reporter::silent(),
            &UserContext::current(),
        );

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
            &Reporter::silent(),
            &UserContext::current(),
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
            &Reporter::silent(),
            &UserContext::current(),
        );

        assert!(matches!(response, Response::Scan(_)));
        let records = context.store.recent_audit(10).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, "scan");
        assert_eq!(records[0].effect, Effect::Observed);
        // A person reads this in the Activity list, so the figures follow the
        // path after a colon, not an em-dash or an en-dash.
        assert!(
            !records[0].detail.contains(['\u{2014}', '\u{2013}']),
            "a dash in what the person reads: {}",
            records[0].detail
        );
    }

    fn open_folder(path: &str, context: &Context) -> Response {
        handle(
            Request::ScanFolder {
                path: path.to_owned(),
            },
            context,
            &Reporter::silent(),
            &UserContext::current(),
        )
    }

    /// Opening a folder on the map reads, so anybody may ask. What may be
    /// asked about is a folder on a lettered drive, and anything else is
    /// refused before it is opened and is on the record.
    #[test]
    fn a_folder_that_is_not_on_a_lettered_drive_is_refused_and_recorded() {
        let context = context(Mode::Service);
        let asked = [
            r"\\server\share\folder",
            r"\\?\UNC\server\share\folder",
            r"\\.\C:\Users",
            r"C:\Users\..\Windows",
        ];
        for path in asked {
            assert!(!needs_administrator(
                &Request::ScanFolder {
                    path: path.to_owned()
                },
                &someone()
            ));
            let Response::Error { message } = open_folder(path, &context) else {
                panic!("{path} was read");
            };
            assert!(message.contains("was not read"), "{path}: {message}");
        }

        let records = context.store.recent_audit(10).unwrap();
        assert_eq!(records.len(), asked.len(), "every refusal is recorded");
        for record in &records {
            assert_eq!(
                (
                    record.module.as_str(),
                    record.action.as_str(),
                    record.effect
                ),
                ("storage", "scan_folder", Effect::Refused)
            );
        }
    }

    /// A folder that is not there is said to be gone, however the drive is
    /// read: by the file table where this runs with the rights for it, by
    /// walking where it does not.
    #[test]
    fn a_folder_that_is_not_there_is_said_to_be_gone_and_recorded() {
        let context = context(Mode::Console);
        let missing = std::env::temp_dir().join(format!(
            "kam-dispatch-no-such-folder-{}",
            std::process::id()
        ));
        let Response::Error { message } = open_folder(&missing.to_string_lossy(), &context) else {
            panic!("a folder that does not exist was read");
        };
        assert!(message.contains("there is no folder at"), "{message}");

        let records = context.store.recent_audit(10).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, "scan_folder");
        assert_eq!(records[0].effect, Effect::Refused);
    }

    /// Opening a folder is recorded, as the scan it was opened from is.
    ///
    /// Which way the folder is read depends on the rights the tests run with,
    /// and a folder made a moment ago need not be in the file table on disk
    /// yet. So this holds whichever happens: one answer, one entry, and where
    /// the folder was walked, the figure for what was written into it.
    #[test]
    fn opening_a_folder_is_recorded_because_the_person_asked_for_it() {
        let context = context(Mode::Console);
        let file = scratch_file("open-folder", &[7_u8; 4096]);
        let folder = file.parent().unwrap().to_string_lossy().into_owned();

        match open_folder(&folder, &context) {
            Response::Folder(read) => {
                if read.method == kam_storage::ScanMethod::DirectoryWalk {
                    assert_eq!(read.tree.bytes, 4096);
                    assert_eq!(read.unreadable, Some(0));
                    assert!(read.fallback_reason.is_some(), "a walk says why");
                }
            }
            Response::Error { message } => {
                assert!(message.contains("there is no folder at"), "{message}")
            }
            other => panic!("unexpected answer: {other:?}"),
        }

        let records = context.store.recent_audit(10).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].module, "storage");
        assert_eq!(records[0].action, "scan_folder");
        assert!(
            !records[0].detail.contains(['\u{2014}', '\u{2013}']),
            "a dash in what the person reads: {}",
            records[0].detail
        );
        let _ = std::fs::remove_dir_all(&folder);
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
        let response = handle(
            Request::GetRecentAudit { limit: u32::MAX },
            &context,
            &Reporter::silent(),
            &UserContext::current(),
        );
        assert!(matches!(response, Response::RecentAudit { .. }));
    }

    // --- downloads -------------------------------------------------------

    /// The person running the tests, identified by a made-up SID so their
    /// rows have a key, with their real profile so their files are theirs.
    fn identified(sid: &str) -> UserContext {
        UserContext::new(Some(sid.to_owned()), UserContext::current().profile())
    }

    fn scratch_file(tag: &str, contents: &[u8]) -> std::path::PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "kam-dispatch-download-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let file = directory.join("notes.txt");
        std::fs::write(&file, contents).unwrap();
        file
    }

    /// The history, as the page asks for it.
    fn everything() -> Request {
        Request::ListDownloads {
            paths: Vec::new(),
            recent: 1000,
        }
    }

    fn check(path: &str, user: &UserContext, context: &Context) -> Response {
        handle(
            Request::CheckDownload {
                path: path.to_owned(),
                job: "test-job".to_owned(),
                copy_of: None,
            },
            context,
            &Reporter::silent(),
            user,
        )
    }

    /// A check is recorded for the caller, audited, and the first one says so.
    #[test]
    fn a_checked_download_is_recorded_for_its_caller_alone() {
        let context = context(Mode::Console);
        let me = identified("S-1-5-21-0-0-0-4001");
        let them = identified("S-1-5-21-0-0-0-4002");
        let file = scratch_file("record", b"hello");
        let path = file.to_string_lossy().into_owned();

        let Response::DownloadChecked(first) = check(&path, &me, &context) else {
            panic!("the check did not come back as a record");
        };
        assert!(first.first_check);
        assert_eq!(first.check.bytes, 5);
        // Whether Defender can finish depends on the machine; a harmless
        // file is never flagged either way.
        assert_ne!(
            first.check.scan.answer,
            kam_scanner::defender_file::Answer::Flagged,
            "{:?}",
            first.check.scan
        );
        let Response::DownloadChecked(second) = check(&path, &me, &context) else {
            panic!("the second check did not come back as a record");
        };
        assert!(!second.first_check, "a second look was announced as new");

        let Response::Downloads { records, .. } =
            handle(everything(), &context, &Reporter::silent(), &me)
        else {
            panic!("no history came back");
        };
        assert_eq!(records.len(), 1);
        let Response::Downloads { records, .. } =
            handle(everything(), &context, &Reporter::silent(), &them)
        else {
            panic!("no history came back");
        };
        assert!(records.is_empty(), "somebody else's history was shown");

        let audited = context
            .store
            .recent_audit(20)
            .unwrap()
            .into_iter()
            .filter(|entry| entry.module == "downloads" && entry.action == "check")
            .count();
        assert_eq!(audited, 2, "each check is in the audit log");

        // The reply crosses the pipe intact.
        let wire = serde_json::to_string(&kam_ipc::Reply::Done(Response::DownloadChecked(second)))
            .unwrap();
        assert!(matches!(
            serde_json::from_str::<kam_ipc::Reply>(&wire).unwrap(),
            kam_ipc::Reply::Done(Response::DownloadChecked(_))
        ));
        let _ = std::fs::remove_dir_all(file.parent().unwrap());
    }

    /// In the service a download is opened as the caller, by the server,
    /// before any handler runs. A check that reached this handler without
    /// that would be opened as LocalSystem, so it is refused and recorded.
    #[test]
    fn the_service_never_opens_a_download_as_itself() {
        let context = context(Mode::Service);
        let me = identified("S-1-5-21-0-0-0-4005");
        let file = scratch_file("as-itself", b"hello");
        let response = check(&file.to_string_lossy(), &me, &context);
        let Response::Error { message } = &response else {
            panic!("the service opened a file itself: {response:?}");
        };
        assert!(
            message.contains("not opened as the account asking"),
            "{message}"
        );
        assert!(context
            .store
            .downloads_for("S-1-5-21-0-0-0-4005", 10)
            .unwrap()
            .is_empty());
        let refused = context
            .store
            .recent_audit(5)
            .unwrap()
            .into_iter()
            .any(|entry| entry.module == "downloads" && entry.effect == Effect::Refused);
        assert!(refused, "the refusal was not recorded");
        let _ = std::fs::remove_dir_all(file.parent().unwrap());
    }

    /// A working copy is only accepted from the caller's own work folder.
    #[test]
    fn a_working_copy_from_anywhere_else_is_refused() {
        let context = context(Mode::Console);
        let me = identified("S-1-5-21-0-0-0-4003");
        let file = scratch_file("copy", b"x");
        // The original is under the caller's own profile, so it is the
        // work-folder rule that refuses this. An original in somebody else's
        // profile is refused earlier, by its own test in `downloads`.
        let response = handle(
            Request::CheckDownload {
                path: file.to_string_lossy().into_owned(),
                job: "test-job".to_owned(),
                copy_of: Some(format!(r"{}\Downloads\a.zip", me.profile())),
            },
            &context,
            &Reporter::silent(),
            &me,
        );
        let Response::Error { message } = &response else {
            panic!("a working copy outside the work folder was accepted: {response:?}");
        };
        assert!(message.contains("work folder"), "{message}");
        let _ = std::fs::remove_dir_all(file.parent().unwrap());
    }

    /// Only a file inside the caller's own Downloads folder can be quarantined
    /// as a download, and every refusal is in the audit log.
    #[test]
    fn a_download_quarantine_outside_downloads_is_refused_and_recorded() {
        let context = context(Mode::Service);
        let me = UserContext::current();
        let elsewhere = scratch_file("fence", b"keep me");
        for path in [
            elsewhere.to_string_lossy().into_owned(),
            r"C:\Windows\System32\kernel32.dll".to_owned(),
            format!(
                r"{}\..\Desktop\x.txt",
                kam_storage::downloads::folder_for(&me)
            ),
        ] {
            let response = handle(
                Request::QuarantineDownload { path: path.clone() },
                &context,
                &Reporter::silent(),
                &me,
            );
            assert!(
                matches!(response, Response::Error { .. }),
                "{path} was quarantined: {response:?}"
            );
        }
        assert!(elsewhere.exists(), "a refused file was touched");
        let refused = context
            .store
            .recent_audit(20)
            .unwrap()
            .into_iter()
            .filter(|entry| entry.action == "quarantine" && entry.effect == Effect::Refused)
            .count();
        assert_eq!(refused, 3);
        let _ = std::fs::remove_dir_all(elsewhere.parent().unwrap());
    }

    /// A download in Downloads is held, the row says so, and it comes back.
    #[test]
    fn a_download_is_quarantined_noted_on_its_row_and_restored() {
        let context = context(Mode::Console);
        // A throwaway profile with a Downloads folder of its own. This used
        // to write its file into the real one, where a watching copy of the
        // program sees it land and then go, and would now record it as a
        // download that was gone before it could be checked.
        let profile = std::env::temp_dir().join(format!(
            "kam-dispatch-download-profile-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&profile);
        let me = UserContext::new(
            Some("S-1-5-21-0-0-0-4006".to_owned()),
            &profile.to_string_lossy(),
        );
        let downloads = std::path::PathBuf::from(kam_storage::downloads::folder_for(&me));
        assert!(downloads.starts_with(&profile), "{}", downloads.display());
        std::fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("download.bin");
        std::fs::write(&file, vec![3_u8; 1024]).unwrap();
        let path = file.to_string_lossy().into_owned();
        let Response::DownloadChecked(record) = check(&path, &me, &context) else {
            let _ = std::fs::remove_dir_all(&profile);
            panic!("the download could not be checked");
        };

        let held = handle(
            Request::QuarantineDownload { path: path.clone() },
            &context,
            &Reporter::silent(),
            &me,
        );
        let Response::Quarantined(manifest) = &held else {
            let _ = std::fs::remove_dir_all(&profile);
            panic!("the download was not quarantined: {held:?}");
        };
        assert!(!file.exists());
        let row = context
            .store
            .downloads_for("S-1-5-21-0-0-0-4006", 10)
            .unwrap()
            .remove(0);
        assert!(row.actions.contains(&manifest.id), "{}", row.actions);
        assert_eq!(row.sha256, record.check.sha256);
        // The Activity entry gives its reason after a colon, not a double
        // hyphen standing in for a dash.
        let taken = context
            .store
            .recent_audit(20)
            .unwrap()
            .into_iter()
            .find(|entry| entry.module == "downloads" && entry.action == "quarantine")
            .expect("the quarantine was not recorded");
        assert!(taken.detail.contains("): a download"), "{}", taken.detail);

        let back = handle(
            Request::RestoreQuarantined {
                id: manifest.id.clone(),
            },
            &context,
            &Reporter::silent(),
            &me,
        );
        assert!(matches!(back, Response::Quarantined(_)), "{back:?}");
        assert!(file.exists());
        let _ = std::fs::remove_dir_all(&profile);
    }

    /// What the window reports about an archive needs a check on record, and
    /// lands on that row.
    #[test]
    fn a_dissection_is_recorded_only_against_a_checked_archive() {
        let context = context(Mode::Console);
        let me = identified("S-1-5-21-0-0-0-4004");
        let file = scratch_file("dissect", b"not really a zip");
        let path = file.to_string_lossy().into_owned();
        let Response::DownloadChecked(record) = check(&path, &me, &context) else {
            panic!("the check failed");
        };
        let dissection = kam_scanner::downloads::dissect(
            &path,
            &record.check.sha256,
            record.check.scan.clone(),
            &[],
        );

        let unknown = handle(
            Request::RecordDissection {
                path: path.clone(),
                sha256: "0".repeat(64),
                dissection: Box::new(dissection.clone()),
            },
            &context,
            &Reporter::silent(),
            &me,
        );
        assert!(matches!(unknown, Response::Error { .. }), "{unknown:?}");

        let recorded = handle(
            Request::RecordDissection {
                path: record.check.path.clone(),
                sha256: record.check.sha256.clone(),
                dissection: Box::new(dissection),
            },
            &context,
            &Reporter::silent(),
            &me,
        );
        assert!(matches!(recorded, Response::Acknowledged), "{recorded:?}");
        let extracted = handle(
            Request::RecordExtraction {
                path: record.check.path.clone(),
                sha256: record.check.sha256.clone(),
                extraction: kam_scanner::downloads::Extraction {
                    destination: r"C:\Users\me\Downloads\a (checked by KAM)".to_owned(),
                    files: 2,
                    bytes: 10,
                    left_out: 1,
                    left_out_bytes: 68,
                    failed: Vec::new(),
                    removed: vec![kam_scanner::downloads::RemovedFile::new(
                        "tools/scan.exe".to_owned(),
                        Some("HackTool:Win32/Example".to_owned()),
                    )],
                    unmarked: vec!["docs/a.exe: Access is denied.".to_owned()],
                },
            },
            &context,
            &Reporter::silent(),
            &me,
        );
        assert!(matches!(extracted, Response::Acknowledged));

        let Response::Downloads { records, .. } =
            handle(everything(), &context, &Reporter::silent(), &me)
        else {
            panic!("no history");
        };
        assert!(records[0].dissection.is_some());
        let said = &records[0].actions[0].what;
        assert!(said.starts_with("Extracted 2 files"), "{said}");
        assert!(
            said.contains(
                "1 removed by Defender as it was written: tools/scan.exe (HackTool:Win32/Example)"
            ),
            "a file Defender took away was not said: {said}"
        );
        assert!(
            said.contains("1 of those written could not be given the mark Windows puts on"),
            "a file written without its download mark was not said: {said}"
        );
        let _ = std::fs::remove_dir_all(file.parent().unwrap());
    }

    /// A row put straight into the history, so that removing and counting
    /// rows can be tested without Defender having to check anything.
    fn recorded(context: &Context, sid: &str, path: &str, sha256: &str) {
        let nothing = kam_scanner::defender_file::parse_report(Some(0), "");
        recorded_as(
            context,
            sid,
            path,
            sha256,
            &serde_json::to_string(&nothing).unwrap(),
        );
    }

    /// The same, with the answer the row is to hold, as it is stored.
    fn recorded_as(context: &Context, sid: &str, path: &str, sha256: &str, outcome: &str) {
        context
            .store
            .record_download_check(&kam_core::db::DownloadRow {
                sid: sid.to_owned(),
                path: path.to_owned(),
                sha256: sha256.to_owned(),
                name: "a.bin".to_owned(),
                bytes: 5,
                arrived_at: None,
                checked_at: String::new(),
                origin: None,
                signature: None,
                outcome: outcome.to_owned(),
                actions: String::new(),
                dissection: None,
            })
            .unwrap();
    }

    fn removed(response: Response) -> u64 {
        match response {
            Response::DownloadRecordsRemoved { removed } => removed,
            other => panic!("nothing was said to have been removed: {other:?}"),
        }
    }

    /// How many entries of one action the audit log holds, by effect:
    /// changed, observed, refused.
    fn audited(context: &Context, action: &str) -> (usize, usize, usize) {
        let entries = context.store.recent_audit(50).unwrap();
        let count = |effect: Effect| {
            entries
                .iter()
                .filter(|entry| entry.action == action && entry.effect == effect)
                .count()
        };
        (
            count(Effect::Changed),
            count(Effect::Observed),
            count(Effect::Refused),
        )
    }

    /// "Remove from this list" removes the record of one check, for the
    /// person who asked and nobody else, and never the file. Every request
    /// is in the audit log, which keeps its own entry of the check besides.
    #[test]
    fn removing_a_download_record_removes_the_callers_row_and_never_the_file() {
        let context = context(Mode::Service);
        let (mine, theirs) = ("S-1-5-21-0-0-0-4010", "S-1-5-21-0-0-0-4011");
        let me = identified(mine);
        let file = scratch_file("remove", b"hello");
        let path = file.to_string_lossy().into_owned();
        let sha256 = "ab".repeat(32);
        recorded(&context, mine, &path, &sha256);
        recorded(&context, theirs, &path, &sha256);

        let remove = |sha256: &str| {
            removed(handle(
                Request::RemoveDownloadRecord {
                    path: path.clone(),
                    sha256: sha256.to_owned(),
                },
                &context,
                &Reporter::silent(),
                &me,
            ))
        };
        // Other content under that name would be another row, not this one.
        assert_eq!(remove(&"cd".repeat(32)), 0);
        assert_eq!(remove(&sha256.to_uppercase()), 1);
        assert_eq!(remove(&sha256), 0, "one row was removed twice");

        assert_eq!(context.store.download_count(mine).unwrap(), 0);
        assert_eq!(
            context.store.download_count(theirs).unwrap(),
            1,
            "somebody else's row was removed"
        );
        assert_eq!(
            std::fs::read(&file).unwrap(),
            b"hello",
            "the file was touched"
        );

        assert_eq!(audited(&context, "remove_record"), (1, 2, 0));
        let done = context
            .store
            .recent_audit(50)
            .unwrap()
            .into_iter()
            .find(|entry| entry.action == "remove_record" && entry.effect == Effect::Changed)
            .unwrap();
        assert!(
            done.detail.contains(&path)
                && done.detail.contains(me.profile())
                && done.detail.contains("The file itself was not touched"),
            "{}",
            done.detail
        );
        // A person's own rows, so no administrator is needed.
        assert!(!needs_administrator(
            &Request::RemoveDownloadRecord {
                path: path.clone(),
                sha256,
            },
            &me
        ));
        let _ = std::fs::remove_dir_all(file.parent().unwrap());
    }

    /// "Clear the list" removes every row the caller had on record when the
    /// list they were looking at was read. A check recorded after that stays,
    /// and so does everybody else's history. A request that does not say
    /// when is refused, and the refusal is recorded.
    #[test]
    fn clearing_the_download_history_keeps_what_was_recorded_afterwards() {
        let context = context(Mode::Service);
        let (mine, theirs) = ("S-1-5-21-0-0-0-4012", "S-1-5-21-0-0-0-4013");
        let me = identified(mine);
        let pause = || std::thread::sleep(std::time::Duration::from_millis(50));
        recorded(&context, mine, r"C:\D\a.bin", &"aa".repeat(32));
        recorded(&context, mine, r"C:\D\b.bin", &"bb".repeat(32));
        recorded(&context, theirs, r"C:\D\a.bin", &"aa".repeat(32));
        pause();
        let read_at = kam_core::clock::now_utc_iso();
        pause();
        recorded(&context, mine, r"C:\D\later.bin", &"cc".repeat(32));

        let clear = |up_to: &str| {
            handle(
                Request::ClearDownloadRecords {
                    up_to: up_to.to_owned(),
                },
                &context,
                &Reporter::silent(),
                &me,
            )
        };
        let not_times = [
            "",
            "everything",
            "2026-11-19",
            "2026-11-19 10:02:00.123Z",
            "2026-11-19T10:02:00.123Z' OR 1=1",
        ];
        for wrong in not_times {
            assert!(
                matches!(clear(wrong), Response::Error { .. }),
                "{wrong:?} was taken for a time"
            );
        }
        assert_eq!(
            context.store.download_count(mine).unwrap(),
            3,
            "a refused request removed something"
        );

        assert_eq!(removed(clear(&read_at)), 2);
        let left = context.store.downloads_for(mine, 10).unwrap();
        assert_eq!(left.len(), 1, "a check recorded afterwards was removed");
        assert_eq!(left[0].path, r"C:\D\later.bin");
        assert_eq!(
            context.store.download_count(theirs).unwrap(),
            1,
            "somebody else's history was cleared"
        );
        assert_eq!(removed(clear(&read_at)), 0);

        assert_eq!(audited(&context, "clear_records"), (1, 1, not_times.len()));
        let done = context
            .store
            .recent_audit(50)
            .unwrap()
            .into_iter()
            .find(|entry| entry.action == "clear_records" && entry.effect == Effect::Changed)
            .unwrap();
        assert!(
            done.detail.contains("2 records removed")
                && done.detail.contains("No file was touched"),
            "{}",
            done.detail
        );
        assert!(!needs_administrator(
            &Request::ClearDownloadRecords { up_to: read_at },
            &me
        ));
    }

    /// The count beside "Active downloads": the caller's own results,
    /// recorded since they last opened the page, that Defender flagged or
    /// whose check did not finish. Nobody else's, nothing older, and never a
    /// count of nothing for a question that could not be answered.
    #[test]
    fn results_not_looked_at_yet_are_counted_for_the_caller_alone() {
        use kam_scanner::defender_file::{parse_report, FileScan, Flagged};

        let context = context(Mode::Service);
        let (mine, theirs) = ("S-1-5-21-0-0-0-4014", "S-1-5-21-0-0-0-4015");
        let me = identified(mine);
        let pause = || std::thread::sleep(std::time::Duration::from_millis(50));
        let stored = |scan: &FileScan| serde_json::to_string(scan).unwrap();
        let nothing = stored(&parse_report(Some(0), ""));
        let flagged = stored(&parse_report(
            Some(2),
            "Scanning C:\\a.exe found 1 threats.\r\nThreat : Trojan:Win32/Example\r\n\
             Resources : 1 total\r\n    file : C:\\a.exe\r\n",
        ));
        let unfinished = stored(&parse_report(Some(2), ""));
        let gone_and_named = stored(&FileScan::gone_before_check(Ok(vec![(
            Flagged {
                name: "Trojan:Win32/Example".to_owned(),
                resources: Vec::new(),
            },
            "quarantined".to_owned(),
        )])));
        let gone_unexplained = stored(&FileScan::gone_before_check(Ok(Vec::new())));
        let sha256 = "ab".repeat(32);

        // Recorded before the page was last opened, so looked at already.
        recorded_as(&context, mine, r"C:\D\old.exe", &sha256, &flagged);
        pause();
        let looked = kam_core::clock::now_utc_iso();
        pause();
        for (name, sha256, outcome) in [
            ("a.exe", sha256.as_str(), &nothing),
            ("b.exe", sha256.as_str(), &flagged),
            ("c.exe", sha256.as_str(), &unfinished),
            ("d.exe", "", &gone_and_named),
            ("e.exe", "", &gone_unexplained),
            // A damaged row reads back as a check that did not finish.
            ("f.exe", sha256.as_str(), &"not an answer".to_owned()),
        ] {
            recorded_as(&context, mine, &format!(r"C:\D\{name}"), sha256, outcome);
        }
        recorded_as(&context, theirs, r"C:\D\g.exe", &sha256, &flagged);

        let count = |since: &str| {
            handle(
                Request::CountDownloadsSince {
                    since: since.to_owned(),
                },
                &context,
                &Reporter::silent(),
                &me,
            )
        };
        let counted = count(&looked);
        assert!(
            matches!(
                counted,
                Response::DownloadsSince {
                    flagged: 2,
                    unfinished: 3
                }
            ),
            "{counted:?}"
        );
        // Opening the page moves the moment, and nothing has come since.
        pause();
        let counted = count(&kam_core::clock::now_utc_iso());
        assert!(
            matches!(
                counted,
                Response::DownloadsSince {
                    flagged: 0,
                    unfinished: 0
                }
            ),
            "{counted:?}"
        );
        // A moment that is not a time is an error, never a count of nothing.
        assert!(matches!(count("yesterday"), Response::Error { .. }));

        // Asked whenever the list changes, so not in the audit log, and
        // anyone's to ask about their own rows.
        assert!(context.store.recent_audit(10).unwrap().is_empty());
        assert!(!needs_administrator(
            &Request::CountDownloadsSince { since: looked },
            &me
        ));
    }
}
