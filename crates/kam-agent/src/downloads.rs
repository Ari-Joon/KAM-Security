//! The agent's half of the Downloads page: checking, history, quarantine, and
//! recording what the window reports about archives.
//!
//! # What the agent does here, and what it never does
//!
//! It reads and it asks Defender. It resolves each path it is sent, refuses
//! one inside another account's profile or its own store, fingerprints the
//! file, reads its origin and signer, runs a report-only scan, and records
//! the answer for the caller alone. It quarantines a download only through
//! the Downloads fence. It **never extracts anything and never writes into a
//! folder the person can write to**: taking an archive apart, the private
//! working copy and the extracted files all belong to the window, which runs
//! as the person. What the window did comes back here as a report, and the
//! audit log says it was reported rather than witnessed.

use std::path::Path;

use kam_core::audit::Effect;
use kam_core::db::DownloadRow;
use kam_core::{Reporter, UserContext};
use kam_ipc::Response;
use kam_scanner::defender_file::{Answer, FileScan};
use kam_scanner::downloads::{
    CheckError, Dissection, DownloadAction, DownloadCheck, DownloadRecord, Extraction,
};

use crate::dispatch::{human_bytes, Context};

/// How many history rows one answer carries.
const MAX_ROWS: usize = 1000;

/// How many members of an archive are kept in its record. The totals count
/// every member regardless.
const MAX_RECORDED_MEMBERS: usize = 5000;

/// The caller's key in the history. Every real caller is identified by SID;
/// an unidentified one (a test, a console run) gets the empty key, which no
/// real caller has.
fn caller(user: &UserContext) -> &str {
    user.sid().unwrap_or("")
}

/// The window's private folder for working copies of archives.
fn work_folder(user: &UserContext) -> String {
    format!(r"{}\{}\work", user.local_app_data(), kam_core::PRODUCT_NAME)
}

/// Decide whether a path may be checked for this caller, and where it leads.
///
/// Any file the person chose, on any lettered drive, except inside another
/// account's profile or Recycle Bin, or this product's own store: the agent
/// would be reading it as LocalSystem and handing back its fingerprint and
/// download address, which for somebody else's file is not the caller's to
/// ask. A private working copy must be inside the caller's own work folder.
fn checkable(path: &str, copy_of: Option<&str>, user: &UserContext) -> Result<String, String> {
    let target = Path::new(path);
    if !target.is_absolute() {
        return Err(format!("{path} is not a full path, so it was not checked"));
    }
    let real = std::fs::canonicalize(target)
        .map_err(|error| format!("{path} could not be found ({error}), so it was not checked"))?;
    let text = real.to_string_lossy().into_owned();
    let resolved = text.strip_prefix(r"\\?\").unwrap_or(&text).to_owned();

    if let Some(refusal) = kam_storage::duplicates::reach_refusal(&resolved, path, user) {
        return Err(format!(
            "{path} was not checked. {}",
            refusal.replace(
                "move another account's files",
                "read another account's files"
            )
        ));
    }

    if copy_of.is_some() {
        let folder = work_folder(user);
        let inside = std::fs::canonicalize(&folder)
            .is_ok_and(|work| kam_storage::downloads::lies_within(&real, &work));
        if !inside {
            return Err(format!(
                "{path} is not in your private KAM Security work folder, so it was not checked \
                 as a copy of another file"
            ));
        }
    }
    Ok(resolved)
}

/// Check one file, record it, and answer with its row.
pub fn check(
    path: &str,
    job: &str,
    copy_of: Option<&str>,
    context: &Context,
    reporter: &Reporter,
    user: &UserContext,
) -> Response {
    let resolved = match checkable(path, copy_of, user) {
        Ok(resolved) => resolved,
        Err(refusal) => {
            context.audit("downloads", "check", Effect::Refused, refusal.clone());
            return Response::Error { message: refusal };
        }
    };
    // The original's path is what the history is kept under. It may already
    // be in quarantine, so it is taken as written rather than resolved.
    let original = copy_of
        .map(str::trim)
        .filter(|original| Path::new(original).is_absolute());
    if copy_of.is_some() && original.is_none() {
        return Response::Error {
            message: "the original of a working copy has to be a full path".to_owned(),
        };
    }

    context.register_job(job, reporter.cancel_token());
    let outcome = kam_scanner::downloads::check(&resolved, reporter);
    context.finish_job(job);

    let mut checked = match outcome {
        Ok(checked) => checked,
        Err(CheckError::Stopped) => {
            context.audit(
                "downloads",
                "check",
                Effect::Observed,
                format!("the check of {resolved} was stopped before it finished"),
            );
            return Response::Stopped;
        }
        Err(CheckError::Failed(reason)) => {
            context.audit(
                "downloads",
                "check",
                Effect::Refused,
                format!("could not check {resolved}: {reason}"),
            );
            return Response::Error { message: reason };
        }
    };

    if let Some(original) = original {
        // A private copy carries none of the original's history: its own
        // creation time is a moment ago. What the original's row already has
        // is kept by the store.
        checked.path = original.to_owned();
        checked.name = Path::new(original)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| original.to_owned());
        checked.arrived_at = std::fs::metadata(original)
            .and_then(|metadata| metadata.created())
            .ok()
            .and_then(|created| created.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|since| kam_core::clock::iso_from_unix_millis(since.as_millis() as u64));
        checked.origin = kam_storage::provenance::origin_of(original);
    }

    let row = DownloadRow {
        sid: caller(user).to_owned(),
        path: checked.path.clone(),
        sha256: checked.sha256.clone(),
        name: checked.name.clone(),
        bytes: checked.bytes,
        arrived_at: checked.arrived_at.clone(),
        checked_at: String::new(),
        origin: checked
            .origin
            .as_ref()
            .and_then(|origin| serde_json::to_string(origin).ok()),
        signature: checked
            .signature
            .as_ref()
            .and_then(|signature| serde_json::to_string(signature).ok()),
        outcome: serde_json::to_string(&checked.scan).unwrap_or_default(),
        actions: String::new(),
        dissection: None,
    };
    let first = match context.store.record_download_check(&row) {
        Ok(first) => first,
        Err(error) => {
            tracing::error!(%error, "could not record a download check");
            // The answer is still true; it is the history that failed.
            false
        }
    };

    context.audit(
        "downloads",
        "check",
        Effect::Observed,
        format!(
            "checked {}{} ({}, SHA-256 {}): {}{}",
            if original.is_some() {
                "a private copy of "
            } else {
                ""
            },
            checked.path,
            human_bytes(checked.bytes),
            checked.sha256,
            checked.scan.sentence(),
            checked
                .scan
                .caveat
                .as_deref()
                .map(|caveat| format!(". {caveat}"))
                .unwrap_or_default()
        ),
    );

    let mut record =
        current_record(context, user, &checked.path, &checked.sha256).unwrap_or_else(|| {
            DownloadRecord {
                check: checked,
                checked_at: kam_core::clock::now_utc_iso(),
                actions: Vec::new(),
                dissection: None,
                first_check: false,
            }
        });
    record.first_check = first;
    Response::DownloadChecked(Box::new(record))
}

/// The stored row for one path and content, as a record.
fn current_record(
    context: &Context,
    user: &UserContext,
    path: &str,
    sha256: &str,
) -> Option<DownloadRecord> {
    context
        .store
        .downloads_for(caller(user), MAX_ROWS)
        .ok()?
        .into_iter()
        .find(|row| row.sha256 == sha256 && row.path.eq_ignore_ascii_case(path))
        .map(record_from_row)
}

/// A stored row, read back into the shape the window draws.
///
/// A part that cannot be read back is said to be unreadable rather than
/// dropped: Defender's answer in particular never reads as nothing found
/// because its record was damaged.
fn record_from_row(row: DownloadRow) -> DownloadRecord {
    let scan: FileScan = serde_json::from_str(&row.outcome).unwrap_or_else(|_| FileScan {
        answer: Answer::NotFinished,
        completed: false,
        exit_code: None,
        seconds: 0,
        threats: Vec::new(),
        listing_consistent: false,
        caveat: Some("The stored answer for this check could not be read back.".to_owned()),
        definitions: None,
        notes: Vec::new(),
    });
    DownloadRecord {
        check: DownloadCheck {
            path: row.path,
            name: row.name,
            bytes: row.bytes,
            sha256: row.sha256,
            arrived_at: row.arrived_at,
            origin: row
                .origin
                .as_deref()
                .and_then(|origin| serde_json::from_str(origin).ok()),
            signature: row
                .signature
                .as_deref()
                .and_then(|signature| serde_json::from_str(signature).ok()),
            scan,
        },
        checked_at: row.checked_at,
        actions: serde_json::from_str(&row.actions).unwrap_or_default(),
        dissection: row
            .dissection
            .as_deref()
            .and_then(|dissection| serde_json::from_str(dissection).ok()),
        first_check: false,
    }
}

/// The caller's own history, newest first. A read, so not audited.
pub fn list(context: &Context, user: &UserContext) -> Response {
    match context.store.downloads_for(caller(user), MAX_ROWS) {
        Ok(rows) => Response::Downloads {
            records: rows.into_iter().map(record_from_row).collect(),
        },
        Err(error) => {
            tracing::error!(%error, "could not read the download history");
            Response::Error {
                message: "the download history could not be read".to_owned(),
            }
        }
    }
}

/// Note something done to a download on its row. A missing row is not an
/// error: the audit log has the action either way.
fn note(
    context: &Context,
    user: &UserContext,
    path: &str,
    sha256: Option<&str>,
    action: &DownloadAction,
) {
    let Ok(json) = serde_json::to_string(action) else {
        return;
    };
    if let Err(error) = context
        .store
        .add_download_action(caller(user), path, sha256, &json)
    {
        tracing::error!(%error, "could not note an action on a download");
    }
}

/// Move one download into quarantine, through the Downloads fence.
pub fn quarantine(path: &str, context: &Context, user: &UserContext) -> Response {
    let resolved = match kam_storage::downloads::check_quarantinable(path, user) {
        Ok(resolved) => resolved,
        Err(refusal) => {
            context.audit(
                "downloads",
                "quarantine",
                Effect::Refused,
                format!("refused to quarantine {path}: {refusal}"),
            );
            return Response::Error { message: refusal };
        }
    };
    let text = resolved.to_string_lossy().into_owned();
    // The limits every chosen quarantine has, on top of the Downloads fence:
    // a Downloads folder can be pointed anywhere, including somewhere these
    // refuse.
    if let Err(refusal) = kam_storage::duplicates::check_removable(
        &text,
        user,
        kam_storage::duplicates::Intent::Chosen,
    ) {
        context.audit(
            "downloads",
            "quarantine",
            Effect::Refused,
            format!("refused to quarantine {path}: {refusal}"),
        );
        return Response::Error { message: refusal };
    }

    let latest = context
        .store
        .downloads_for(caller(user), MAX_ROWS)
        .ok()
        .and_then(|rows| {
            rows.into_iter()
                .find(|row| row.path.eq_ignore_ascii_case(&text))
        })
        .map(record_from_row);
    let reason = match &latest {
        Some(record) if record.check.scan.answer == Answer::Flagged => format!(
            "a download {}",
            record
                .check
                .scan
                .sentence()
                .replacen("Defender flagged", "Defender flagged as", 1)
        ),
        _ => "a download you chose to quarantine".to_owned(),
    };
    let bytes = std::fs::metadata(&resolved)
        .map(|metadata| metadata.len())
        .unwrap_or(0);

    match context.quarantine.take(&resolved, bytes, &reason) {
        Ok(manifest) => {
            context.audit_with_token(
                "downloads",
                "quarantine",
                Effect::Changed,
                format!(
                    "quarantined the download {} ({}) -- {reason}",
                    manifest.original_path,
                    human_bytes(manifest.bytes)
                ),
                Some(manifest.id.clone()),
            );
            note(
                context,
                user,
                &text,
                latest.as_ref().map(|record| record.check.sha256.as_str()),
                &DownloadAction {
                    at: kam_core::clock::now_utc_iso(),
                    what: "Quarantined. It can be put back from Cleanup for thirty days."
                        .to_owned(),
                    undo: Some(manifest.id.clone()),
                },
            );
            Response::Quarantined(manifest)
        }
        Err(error) => {
            context.audit(
                "downloads",
                "quarantine",
                Effect::Refused,
                format!("could not quarantine {path}: {error}"),
            );
            Response::Error {
                message: error.to_string(),
            }
        }
    }
}

/// A SHA-256 as the window sent it, if it is one.
fn digest(sha256: &str) -> Option<String> {
    let lower = sha256.trim().to_ascii_lowercase();
    (lower.len() == 64 && lower.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(lower)
}

/// Text from the window, cut to a length that cannot fill the store.
fn clipped(text: &str, most: usize) -> String {
    let flat: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if flat.chars().count() <= most {
        flat
    } else {
        let mut cut: String = flat.chars().take(most).collect();
        cut.push('…');
        cut
    }
}

/// Keep what an archive was found to hold, as the window reported it.
pub fn record_dissection(
    path: &str,
    sha256: &str,
    dissection: Dissection,
    context: &Context,
    user: &UserContext,
) -> Response {
    let Some(sha256) = digest(sha256) else {
        return Response::Error {
            message: "a record of an archive needs its SHA-256".to_owned(),
        };
    };
    let mut kept = dissection.for_record(MAX_RECORDED_MEMBERS);
    kept.archive = path.to_owned();
    kept.sha256 = sha256.clone();
    for member in &mut kept.members {
        member.name = clipped(&member.name, 1024);
        if let kam_scanner::downloads::MemberStatus::LeftOut { reason } = &mut member.status {
            *reason = clipped(reason, 300);
        }
    }
    kept.whole_archive.truncate(100);
    kept.unmatched.truncate(100);
    for name in kept
        .unmatched
        .iter_mut()
        .chain(kept.whole_archive.iter_mut())
    {
        *name = clipped(name, 1024);
    }
    if let Some(reason) = kept.not_offered.as_mut() {
        *reason = clipped(reason, 500);
    }

    let Ok(json) = serde_json::to_string(&kept) else {
        return Response::Error {
            message: "what the archive holds could not be recorded".to_owned(),
        };
    };
    match context
        .store
        .set_download_dissection(caller(user), path, &sha256, &json)
    {
        Ok(true) => {}
        Ok(false) => {
            return Response::Error {
                message: "there is no check of that archive on record, so what it holds was \
                          not recorded"
                    .to_owned(),
            }
        }
        Err(error) => {
            tracing::error!(%error, "could not record a dissection");
            return Response::Error {
                message: "what the archive holds could not be recorded".to_owned(),
            };
        }
    }

    let totals = &kept.totals;
    let names = kept.scan.threat_names();
    context.audit(
        "downloads",
        "dissect",
        Effect::Observed,
        format!(
            "the window reported taking apart {path} (SHA-256 {sha256}): {} files ({}); {} \
             flagged by Defender{}; {} left out for another reason ({}); {} Defender found \
             nothing in ({}); {}",
            totals.files,
            human_bytes(totals.bytes),
            totals.flagged,
            if names.is_empty() {
                String::new()
            } else {
                format!(" as {}", clipped(&names.join(", "), 300))
            },
            totals.left_out,
            human_bytes(totals.left_out_bytes),
            totals.clean,
            human_bytes(totals.clean_bytes),
            if kept.offered {
                "those were offered for extraction".to_owned()
            } else {
                format!(
                    "nothing was offered: {}",
                    kept.not_offered.as_deref().unwrap_or("no reason given")
                )
            }
        ),
    );
    Response::Acknowledged
}

/// Record that the window extracted the clean parts of an archive.
pub fn record_extraction(
    path: &str,
    sha256: &str,
    extraction: &Extraction,
    context: &Context,
    user: &UserContext,
) -> Response {
    let Some(sha256) = digest(sha256) else {
        return Response::Error {
            message: "a record of an extraction needs the archive's SHA-256".to_owned(),
        };
    };
    let destination = clipped(&extraction.destination, 1024);
    let removed = if extraction.removed.is_empty() {
        String::new()
    } else {
        let named: Vec<String> = extraction
            .removed
            .iter()
            .take(20)
            .map(|removal| match &removal.threat {
                Some(threat) => {
                    format!("{} ({})", clipped(&removal.name, 200), clipped(threat, 200))
                }
                None => clipped(&removal.name, 200),
            })
            .collect();
        format!(
            "; {} removed by Defender as {} written: {}",
            extraction.removed.len(),
            if extraction.removed.len() == 1 {
                "it was"
            } else {
                "they were"
            },
            named.join(", ")
        )
    };
    let sentence = format!(
        "Extracted {} {} ({}) that Defender did not flag into {destination}; {} {} ({}) left \
         out{}{removed}.",
        extraction.files,
        if extraction.files == 1 {
            "file"
        } else {
            "files"
        },
        human_bytes(extraction.bytes),
        extraction.left_out,
        if extraction.left_out == 1 {
            "file"
        } else {
            "files"
        },
        human_bytes(extraction.left_out_bytes),
        if extraction.failed.is_empty() {
            String::new()
        } else {
            format!("; {} could not be written", extraction.failed.len())
        }
    );
    note(
        context,
        user,
        path,
        Some(&sha256),
        &DownloadAction {
            at: kam_core::clock::now_utc_iso(),
            what: sentence.clone(),
            undo: None,
        },
    );
    context.audit(
        "downloads",
        "extract",
        Effect::Changed,
        format!("the window reported extracting from {path} (SHA-256 {sha256}): {sentence}"),
    );
    Response::Acknowledged
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_digest_must_be_sixty_four_hex_characters() {
        assert!(digest(&"A".repeat(64)).is_some());
        assert!(digest(&"g".repeat(64)).is_none());
        assert!(digest("abc").is_none());
    }

    #[test]
    fn text_from_the_window_is_flattened_and_cut() {
        assert_eq!(clipped("a\nb", 10), "a b");
        assert_eq!(clipped(&"x".repeat(20), 5), "xxxxx…");
    }

    #[test]
    fn a_damaged_row_reads_as_unfinished_never_as_nothing_found() {
        let row = DownloadRow {
            sid: "s".to_owned(),
            path: r"C:\D\a.exe".to_owned(),
            sha256: "ab".to_owned(),
            name: "a.exe".to_owned(),
            bytes: 1,
            arrived_at: None,
            checked_at: "2026-10-12T00:00:00.000Z".to_owned(),
            origin: Some("not json".to_owned()),
            signature: None,
            outcome: "not json either".to_owned(),
            actions: "[]".to_owned(),
            dissection: None,
        };
        let record = record_from_row(row);
        assert_eq!(record.check.scan.answer, Answer::NotFinished);
        assert!(record.check.scan.caveat.is_some());
        assert!(record.check.origin.is_none());
    }
}
