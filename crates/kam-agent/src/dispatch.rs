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

        Request::ScanPath { path } => scan_path(&path, context),

        Request::ListApplications { drive } => {
            let Some(letter) = drive.chars().next().filter(|c| c.is_ascii_alphabetic()) else {
                return Response::Error {
                    message: "give a drive letter, such as C:".to_owned(),
                };
            };

            match kam_storage::apps::survey(letter.to_ascii_uppercase(), now_seconds(), user) {
                Ok(report) => {
                    context.audit(
                        "storage",
                        "survey",
                        Effect::Observed,
                        format!(
                            "surveyed {letter}: — {} applications using {}, {} leftover directories holding {}, {} downloads holding {}, in {} ms (table {}, index {}, applications {}, leftovers {}, downloads {})",
                            report.summary.applications,
                            human_bytes(report.summary.measured_bytes),
                            report.orphan_summary.found,
                            human_bytes(report.orphan_summary.total_bytes),
                            report.download_summary.found,
                            human_bytes(report.download_summary.total_bytes),
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
                        download_summary: report.download_summary,
                        timings: report.timings,
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
                Ok((groups, summary)) => {
                    context.audit(
                        "storage",
                        "find_duplicates",
                        Effect::Observed,
                        format!(
                            "found {} duplicate sets on {letter}: {} duplicated, {} of it \
                             reclaimable across {} sets, reading {} files in full",
                            summary.groups,
                            human_bytes(summary.wasted_bytes),
                            human_bytes(summary.reclaimable_bytes),
                            summary.actionable,
                            summary.fully_hashed
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

        Request::GetSchedule => Response::Schedule(kam_schedule::current()),

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
                        Response::Schedule(kam_schedule::current())
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
            let total: u64 = caches.iter().map(|cache| cache.bytes).sum();
            context.audit(
                "storage",
                "survey_caches",
                Effect::Observed,
                format!(
                    "{} caches holding {} for {}",
                    caches.len(),
                    human_bytes(total),
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
        } => quarantine_copy(&path, &reason, chosen, context, user),

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
                // Effect::Changed: this writes files into somebody's Documents.
                context.audit(
                    "canary",
                    "plant",
                    Effect::Changed,
                    format!(
                        "planted {} decoy files for {}; {} armed",
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
                    format!("removed {removed} decoy files for {}", user.profile()),
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

        Request::DeletePath { path, reason } => {
            hold_then_delete(quarantine_path(&path, &reason, context, user), context)
        }

        Request::DeleteCopy {
            path,
            reason,
            chosen,
        } => hold_then_delete(
            quarantine_copy(&path, &reason, chosen, context, user),
            context,
        ),

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

/// Take one redundant copy of a duplicated file.
///
/// The fence is [`kam_storage::duplicates::check_removable`], and it is checked
/// here rather than trusted from the list the interface drew. Quarantine rather
/// than deletion, for the same reason as everywhere else: the copy is held, the
/// move is recorded, and it goes back with one press if this was wrong.
fn quarantine_copy(
    path: &str,
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
    if let Err(refusal) = kam_storage::duplicates::check_removable(path, user, intent) {
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

/// Finish a permanent removal that has already passed its fence.
///
/// Takes the reply from whichever quarantine path applied and, if the item was
/// really held, deletes it. Both halves reach the audit log — a `take` with its
/// undo token, then a `delete` without one — which is the honest record: for a
/// moment it *was* recoverable, and then the owner's instruction was carried
/// out.
///
/// If the first half refused, that reply is passed through untouched. It has
/// already been recorded and already says why, and re-wording it here would
/// only make the same refusal read differently depending on which button was
/// pressed.
///
/// If the second half fails, the item stays in quarantine and the reply carries
/// the reason in `refused`. That is the safe way round: the caller asked for it
/// gone and it is instead recoverable, which is a disappointment rather than a
/// loss.
fn hold_then_delete(held: Response, context: &Context) -> Response {
    let Response::Quarantined(manifest) = held else {
        return held;
    };
    delete_quarantined(&[manifest.id], context)
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
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
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
            jobs: Default::default(),
            quarantine: kam_quarantine::Store::open(&quarantine_root).unwrap(),
            behaviour: Default::default(),
        }
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

    /// A real redundant copy is held, and comes back.
    #[test]
    fn a_copy_in_a_folder_of_yours_is_held_and_restored() {
        let context = context(Mode::Service);
        let user = UserContext::current();

        let downloads = std::path::Path::new(user.profile()).join("Downloads");
        if !downloads.is_dir() {
            return;
        }
        let copy = downloads.join(format!("kam-copy-test-{}.bin", std::process::id()));
        std::fs::write(&copy, vec![9_u8; 2048]).unwrap();
        let path = copy.to_string_lossy().into_owned();

        let held = handle(
            Request::QuarantineCopy {
                path: path.clone(),
                reason: "a redundant copy".to_owned(),
                chosen: false,
            },
            &context,
            &Reporter::silent(),
            &user,
        );
        let Response::Quarantined(manifest) = &held else {
            let _ = std::fs::remove_file(&copy);
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

        std::fs::remove_file(&copy).unwrap();
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

    /// Deleting a leftover outright removes it and holds nothing.
    ///
    /// The point of the composition is that the fence is the quarantine fence,
    /// so this checks the outcome the person asked for rather than the
    /// mechanism: the directory is gone from disk, and it is *not* sitting in
    /// quarantine afterwards. A version that held it and quietly failed to
    /// delete it would look identical from the outside without the second
    /// assertion.
    #[test]
    fn deleting_a_leftover_removes_it_and_leaves_nothing_held() {
        let context = context(Mode::Console);
        let leftover = Leftover::new("delete-outright");

        let deleted = handle(
            Request::DeletePath {
                path: leftover.path.display().to_string(),
                reason: "the owner asked for it gone".to_owned(),
            },
            &context,
            &Reporter::silent(),
            &leftover.user(),
        );

        let Response::Deleted {
            items,
            bytes_freed,
            refused,
        } = &deleted
        else {
            panic!("expected a deletion, got {deleted:?}");
        };
        assert_eq!(*items, 1, "refused: {refused:?}");
        assert!(*bytes_freed >= 4096, "size was not measured: {bytes_freed}");
        assert!(refused.is_empty(), "{refused:?}");

        assert!(!leftover.path.exists(), "the directory is still on disk");
        assert!(
            context.quarantine.list().unwrap().is_empty(),
            "it was held rather than deleted"
        );

        // Both halves are recorded: for a moment it was recoverable, and then
        // the instruction was carried out.
        let entries = context.store.recent_audit(50).unwrap();
        assert!(
            entries
                .iter()
                .any(|entry| entry.action == "take" && entry.undo_token.is_some()),
            "the holding half was not recorded"
        );
        let removal = entries
            .iter()
            .find(|entry| entry.action == "delete")
            .expect("the deleting half was not recorded");
        assert!(
            removal.undo_token.is_none(),
            "a deletion must not offer an undo token"
        );
    }

    /// A path the fence refuses is refused, and nothing is deleted.
    ///
    /// The composition must not become a way around the fence it composes. A
    /// directory Windows owns is refused for `QuarantinePath`, so it is refused
    /// here for the same reason and by the same code.
    #[test]
    fn deleting_outright_still_obeys_the_quarantine_fence() {
        let context = context(Mode::Console);
        let leftover = Leftover::new("delete-fenced");

        // A name on the deny list, planted inside the same throwaway profile.
        let protected = leftover
            .root
            .join("AppData")
            .join("Local")
            .join("Microsoft");
        std::fs::create_dir_all(&protected).unwrap();
        std::fs::write(protected.join("keep.txt"), b"load bearing").unwrap();

        let reply = handle(
            Request::DeletePath {
                path: protected.display().to_string(),
                reason: "should never happen".to_owned(),
            },
            &context,
            &Reporter::silent(),
            &leftover.user(),
        );

        assert!(
            matches!(reply, Response::Error { .. }),
            "expected a refusal, got {reply:?}"
        );
        assert!(
            protected.join("keep.txt").exists(),
            "a directory Windows owns was deleted"
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
}
