//! The agent's half of the Downloads page: checking, history, quarantine, and
//! recording what the window reports about archives.
//!
//! # What the agent does here, and what it never does
//!
//! It reads and it asks Defender. Each file it is sent is opened once, as the
//! caller, and kept open: where that handle leads is what is judged (nothing
//! inside another account's profile or the product's own store), and that
//! handle is what is fingerprinted. It reads the file's origin and signer,
//! runs a report-only scan, and records the answer for the caller alone. It
//! quarantines a download only through
//! the Downloads fence. It **never extracts anything and never writes into a
//! folder the person can write to**: taking an archive apart, the private
//! working copy and the extracted files all belong to the window, which runs
//! as the person. What the window did comes back here as a report, and the
//! audit log says it was reported rather than witnessed.

use std::collections::HashSet;
use std::path::Path;

use kam_core::audit::Effect;
use kam_core::db::DownloadRow;
use kam_core::{Reporter, UserContext};
use kam_ipc::Response;
use kam_scanner::defender_file::{Answer, FileScan, Flagged};
use kam_scanner::downloads::{
    CheckError, Dissection, DownloadAction, DownloadCheck, DownloadRecord, Extraction, Held,
};

use crate::dispatch::{human_bytes, Context};

/// How many of the most recent history rows one answer carries.
const MAX_ROWS: usize = 1000;

/// How many files one request may ask after by name.
const MAX_PATHS: usize = 5000;

/// How large the history in one answer may be, as the JSON it is sent as:
/// half of what a frame may hold, so the rest of the frame is never in doubt.
const LIST_BUDGET: usize = kam_ipc::MAX_FRAME_BYTES / 2;

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

/// Whether a path is a plain path on a lettered drive: `C:\...`, or the same
/// with the `\\?\` prefix.
///
/// Checked before anything is resolved. Resolving `\\server\share\x` is a
/// network connection made as LocalSystem: it can hold the agent for as long
/// as Windows waits on a host that never answers, and to one that does it
/// signs in as this machine's own account. Device paths (`\\.\`) and
/// `\\?\UNC\` are not files a person downloaded either.
fn on_a_drive(path: &str) -> bool {
    let text = path.strip_prefix(r"\\?\").unwrap_or(path);
    let bytes = text.as_bytes();
    bytes.len() > 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\'
}

/// Refuse anything but a plain drive path, for the file and for the original
/// it is a copy of. See [`on_a_drive`].
pub fn plain_paths(path: &str, copy_of: Option<&str>) -> Result<(), String> {
    for candidate in std::iter::once(path).chain(copy_of) {
        if !on_a_drive(candidate.trim()) {
            return Err(format!(
                "{candidate} is not a file on one of this PC's drives, so it was not checked"
            ));
        }
    }
    Ok(())
}

/// The original a private working copy was made from, and what was read of
/// it. All of it is read once, as the caller, when the request arrives.
#[derive(Debug)]
struct Original {
    /// As the window wrote it. The history is kept under this.
    path: String,
    /// Where it really is, when it was there to be opened. An original
    /// already in quarantine is not, and then nothing of it was read.
    real: Option<String>,
    arrived_at: Option<String>,
    origin: Option<kam_storage::provenance::Origin>,
}

/// A file opened for checking, with everything that has to be read as the
/// caller already read. See [`open_as_caller`].
#[derive(Debug)]
pub struct Opened {
    /// What the caller asked about, as they wrote it, for messages.
    asked: String,
    held: Held,
    original: Option<Original>,
}

/// Open the file a check is about, as the caller, and keep it open.
///
/// # Why the opening and the reading are one step
///
/// The handler hands back a file's fingerprint, size, signer and download
/// address, and for a file the person could not open each of those is
/// something this service would be telling them that Windows would not. A
/// list of forbidden folders always misses one; asking Windows on the
/// person's behalf cannot. So the file is opened while acting as the caller
/// (`PipeStream::as_client`).
///
/// It used to be opened, closed, and then found again by name and read with
/// the system's rights, and a name can lead somewhere else the second time.
/// The handle opened here is the one the whole check reads from (see
/// [`Held`]), so what the caller was allowed to open is what is read.
///
/// The original of a working copy is read here too, and nowhere else: its
/// creation time and its download mark, as the caller, through one open. It
/// may already be in quarantine, where it is simply not found, and then
/// nothing of it is read. It used to be read by name after Defender had
/// finished, seconds later, whatever that name had come to lead to by then.
/// Found and refused is a refusal.
pub fn open_as_caller(path: &str, copy_of: Option<&str>) -> Result<Opened, String> {
    // Before anything is opened: see `on_a_drive`.
    plain_paths(path, copy_of)?;
    if !Path::new(path).is_absolute() {
        return Err(format!("{path} is not a full path, so it was not checked"));
    }
    let held = Held::open(path)?;

    let original = match copy_of.map(str::trim) {
        None => None,
        Some(original) if !Path::new(original).is_absolute() => {
            return Err("the original of a working copy has to be a full path".to_owned())
        }
        Some(original) => Some(match std::fs::File::open(original) {
            Ok(file) => {
                let real = kam_scanner::downloads::real_path(&file).ok_or_else(|| {
                    format!("{original} is not on a lettered drive, so it was not read")
                })?;
                Original {
                    path: original.to_owned(),
                    arrived_at: file
                        .metadata()
                        .ok()
                        .and_then(|metadata| kam_scanner::downloads::created_iso(&metadata)),
                    origin: kam_storage::provenance::origin_of(&real),
                    real: Some(real),
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Original {
                path: original.to_owned(),
                real: None,
                arrived_at: None,
                origin: None,
            },
            Err(error) => {
                return Err(format!(
                    "{original} was not read, because your account cannot open it ({error})"
                ))
            }
        }),
    };
    Ok(Opened {
        asked: path.to_owned(),
        held,
        original,
    })
}

/// Decide whether a file that has been opened may be checked for this caller.
///
/// Any file the person chose, on any lettered drive, except inside another
/// account's profile or Recycle Bin, or this product's own store: the agent
/// reads it and hands back its fingerprint and download address, which for
/// somebody else's file is not the caller's to ask, whatever Windows would
/// let an administrator open. A private working copy must be inside the
/// caller's own work folder.
///
/// Judged on where the open handles really lead, never on the text that
/// arrived. Only an original that was not there is judged as written, and
/// nothing was read of that one.
fn permitted(opened: &Opened, user: &UserContext) -> Result<(), String> {
    let reach = |real: &str, asked: &str, verb: &str| match kam_storage::duplicates::reach_refusal(
        real, asked, user,
    ) {
        Some(refusal) => Err(format!(
            "{asked} was not {verb}. {}",
            refusal.replace(
                "move another account's files",
                "read another account's files"
            )
        )),
        None => Ok(()),
    };

    // The original was the one thing nothing fenced: a copy in the caller's
    // own work folder could name another account's download as its original.
    if let Some(original) = &opened.original {
        reach(
            original.real.as_deref().unwrap_or(&original.path),
            &original.path,
            "read",
        )?;
    }
    reach(opened.held.real(), &opened.asked, "checked")?;

    if opened.original.is_some() {
        let inside = std::fs::canonicalize(work_folder(user)).is_ok_and(|work| {
            kam_storage::downloads::lies_within(Path::new(opened.held.real()), &work)
        });
        if !inside {
            return Err(format!(
                "{} is not in your private KAM Security work folder, so it was not checked as a \
                 copy of another file",
                opened.asked
            ));
        }
    }
    Ok(())
}

/// Check one file that was opened as the caller, record it, and answer with
/// its row. The file stays open, and so cannot be changed or replaced, until
/// this returns.
pub fn check(
    opened: Opened,
    job: &str,
    context: &Context,
    reporter: &Reporter,
    user: &UserContext,
) -> Response {
    if let Err(refusal) = permitted(&opened, user) {
        context.audit("downloads", "check", Effect::Refused, refusal.clone());
        return Response::Error { message: refusal };
    }
    let resolved = opened.held.real().to_owned();
    let original = opened.original.as_ref();

    context.register_job(job, reporter.cancel_token());
    let outcome = kam_scanner::downloads::check(&opened.held, reporter);
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
        // creation time is a moment ago. What was read of the original when
        // the request arrived is used, and the original is not touched again
        // from here. What its row already has is kept by the store.
        checked.path = original.path.clone();
        checked.name = Path::new(&original.path)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| original.path.clone());
        checked.arrived_at = original.arrived_at.clone();
        checked.origin = original.origin.clone();
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
        // The row keeps Defender's names and one resource for each. The whole
        // list goes back in the reply below, which is where taking an archive
        // apart reads it; kept in every row it made the history too large to
        // send.
        outcome: serde_json::to_string(&checked.scan.for_record()).unwrap_or_default(),
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

    // What the row already has (what was done to it, what taking it apart
    // came to) with this check's own answer, whole.
    let stored = context
        .store
        .download_at(caller(user), &checked.path, Some(&checked.sha256))
        .ok()
        .flatten()
        .map(record_from_row);
    let record = DownloadRecord {
        checked_at: stored
            .as_ref()
            .map(|stored| stored.checked_at.clone())
            .unwrap_or_else(kam_core::clock::now_utc_iso),
        actions: stored
            .as_ref()
            .map(|stored| stored.actions.clone())
            .unwrap_or_default(),
        dissection: stored.and_then(|stored| stored.dissection),
        check: checked,
        first_check: first,
    };
    Response::DownloadChecked(Box::new(record))
}

/// A stored row, read back into the shape the window draws.
///
/// A part that cannot be read back is said to be unreadable rather than
/// dropped: Defender's answer in particular never reads as nothing found
/// because its record was damaged.
fn record_from_row(row: DownloadRow) -> DownloadRecord {
    let scan = serde_json::from_str::<FileScan>(&row.outcome)
        // A row written before rows were kept small still holds Defender's
        // whole list. It is read back in the same short form as the rest.
        .map(|scan| scan.for_record())
        .unwrap_or_else(|_| FileScan {
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

/// The caller's own history: the newest row for each file they name, then
/// the most recently checked, newest first. A read, so not audited.
///
/// # Bounded three ways
///
/// By how many recent rows (`MAX_ROWS`), by how many named files
/// (`MAX_PATHS`), and by the size of the answer (`LIST_BUDGET`), measured as
/// it is built. The last is the one that cannot be argued with: a frame over
/// 8 MiB is not sent at all, and before this the page's whole history went
/// in one frame with every archive's member list in it. A dozen large
/// archives were enough, and from then on the page could never be sent its
/// list again. Rows are small now, and should they ever not be, the answer
/// stops short of the limit and says how many rows there are in all.
pub fn list(paths: &[String], recent: u32, context: &Context, user: &UserContext) -> Response {
    let sid = caller(user);
    let unreadable = |error: kam_core::Error| {
        tracing::error!(%error, "could not read the download history");
        Response::Error {
            message: "the download history could not be read".to_owned(),
        }
    };
    let recent = match context
        .store
        .downloads_for(sid, (recent as usize).min(MAX_ROWS))
    {
        Ok(rows) => rows,
        Err(error) => return unreadable(error),
    };
    let on_record = match context.store.download_count(sid) {
        Ok(count) => count,
        Err(error) => return unreadable(error),
    };

    // Compared the way the store compares paths: ASCII case folded.
    let mut seen: HashSet<String> = recent
        .iter()
        .map(|row| row.path.to_ascii_lowercase())
        .collect();
    let mut rows = Vec::new();
    for path in paths.iter().take(MAX_PATHS) {
        if !seen.insert(path.to_ascii_lowercase()) {
            continue;
        }
        match context.store.download_at(sid, path, None) {
            Ok(Some(row)) => rows.push(row),
            Ok(None) => {}
            Err(error) => return unreadable(error),
        }
    }
    // The named files first: they are the ones in the folder now, and a row
    // left out for one of them shows it as never checked.
    rows.extend(recent);

    let mut records = Vec::new();
    let mut size = 0_usize;
    for row in rows {
        let record = record_from_row(row);
        size =
            size.saturating_add(serde_json::to_vec(&record).map_or(usize::MAX, |json| json.len()));
        if size > LIST_BUDGET {
            break;
        }
        records.push(record);
    }
    Response::Downloads { records, on_record }
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

/// How far back a detection in Defender's history is taken to be about a
/// file that has just gone. A file of the same name flagged last month is
/// not the one that vanished a moment ago.
const RECENT_DETECTION_MILLIS: u64 = 60 * 60 * 1000;

/// `2026-11-18T17:51:37` from WMI's `20261118175137.853000+000`, when it is
/// that shape and in UTC, which is how Defender writes its detection times.
fn detection_time(cim: &str) -> Option<String> {
    let digits = cim.get(..14)?;
    let utc = cim.ends_with("+000") || cim.ends_with("-000");
    if !digits.bytes().all(|byte| byte.is_ascii_digit()) || !utc {
        return None;
    }
    Some(format!(
        "{}-{}-{}T{}:{}:{}",
        &digits[..4],
        &digits[4..6],
        &digits[6..8],
        &digits[8..10],
        &digits[10..12],
        &digits[12..14]
    ))
}

/// Record a download that arrived and was gone before it could be checked.
///
/// The window saw it arrive and go. What Defender did is read here, from
/// Defender's own history, and not taken from the window.
pub fn vanished(
    path: &str,
    bytes: u64,
    arrived_at: Option<&str>,
    context: &Context,
    user: &UserContext,
) -> Response {
    let history = kam_scanner::defender::threats().map_err(|error| error.to_string());
    vanished_with(path, bytes, arrived_at, history, context, user)
}

/// [`vanished`] against a history given rather than read, so it can be tested
/// without Defender having detected anything.
fn vanished_with(
    path: &str,
    bytes: u64,
    arrived_at: Option<&str>,
    history: Result<Vec<kam_scanner::Threat>, String>,
    context: &Context,
    user: &UserContext,
) -> Response {
    let path = path.trim();
    let fenced = plain_paths(path, None)
        .and_then(|()| {
            if path.chars().any(char::is_control) {
                Err("a name with a control character in it was not recorded".to_owned())
            } else {
                Ok(())
            }
        })
        .and_then(|()| kam_storage::downloads::check_gone_from(path, user));
    if let Err(refusal) = fenced {
        context.audit("downloads", "vanished", Effect::Refused, refusal.clone());
        return Response::Error { message: refusal };
    }

    // The detections that name this very path, and are recent enough to be
    // about the file that has just gone.
    let names_it = |resource: &String| {
        kam_scanner::defender_file::parse_resource(resource).is_some_and(|named| {
            named
                .path
                .strip_prefix(r"\\?\")
                .unwrap_or(&named.path)
                .eq_ignore_ascii_case(path)
        })
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_millis() as u64);
    let earliest =
        kam_core::clock::iso_from_unix_millis(now.saturating_sub(RECENT_DETECTION_MILLIS));
    let found = history.map(|threats| {
        threats
            .into_iter()
            .filter(|threat| threat.resources.iter().any(names_it))
            .filter_map(|threat| {
                let when = threat.detected_at.as_deref().and_then(detection_time);
                // A time that cannot be read does not rule a detection out;
                // it is said to be unread, and the reader can judge.
                if when
                    .as_deref()
                    .is_some_and(|when| when < earliest.get(..19).unwrap_or_default())
                {
                    return None;
                }
                let status = match when {
                    Some(when) => format!(
                        "{}, recorded {} UTC",
                        threat.status_text,
                        when.replace('T', " ")
                    ),
                    None => format!("{}, at a time that could not be read", threat.status_text),
                };
                Some((
                    Flagged {
                        resources: threat
                            .resources
                            .iter()
                            .filter(|resource| names_it(resource))
                            .take(1)
                            .map(|resource| clipped(resource, 1024))
                            .collect(),
                        name: clipped(&threat.name, 200),
                    },
                    status,
                ))
            })
            .collect::<Vec<_>>()
    });
    let scan = FileScan::gone_before_check(found);

    let name = Path::new(path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_owned());
    // What the window says it saw, kept only if it is the shape of a time.
    let arrived_at = arrived_at.filter(|at| {
        at.len() <= 32
            && at
                .bytes()
                .all(|byte| byte.is_ascii_digit() || b"-:.TZ".contains(&byte))
    });
    let row = DownloadRow {
        sid: caller(user).to_owned(),
        path: path.to_owned(),
        // There was never anything to fingerprint. Every other row has one,
        // so the empty one is this path's "gone before it was checked" row.
        sha256: String::new(),
        name: name.clone(),
        bytes,
        arrived_at: arrived_at.map(str::to_owned),
        checked_at: String::new(),
        origin: None,
        signature: None,
        outcome: serde_json::to_string(&scan).unwrap_or_default(),
        actions: String::new(),
        dissection: None,
    };
    let first = match context.store.record_download_check(&row) {
        Ok(first) => first,
        Err(error) => {
            tracing::error!(%error, "could not record a download that went missing");
            false
        }
    };
    context.audit(
        "downloads",
        "vanished",
        Effect::Observed,
        format!(
            "the window reported that {path} arrived and was gone before it could be checked. \
             {}",
            scan.caveat.as_deref().unwrap_or_default()
        ),
    );

    Response::DownloadChecked(Box::new(DownloadRecord {
        check: DownloadCheck {
            path: path.to_owned(),
            name,
            bytes,
            sha256: String::new(),
            arrived_at: arrived_at.map(str::to_owned),
            origin: None,
            signature: None,
            scan,
        },
        checked_at: kam_core::clock::now_utc_iso(),
        actions: Vec::new(),
        dissection: None,
        first_check: first,
    }))
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
        .download_at(caller(user), &text, None)
        .ok()
        .flatten()
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
                    "quarantined the download {} ({}): {reason}",
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
    let mut kept = dissection.for_record(kam_scanner::downloads::RECORDED_MEMBERS);
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

/// Record that the window extracted what Defender did not flag in an archive.
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
    // Said on the row and in the log, because it decides whether Windows
    // warns before one of these files is run.
    let unmarked = match extraction.unmarked.len() {
        0 => String::new(),
        1 => "; 1 of those written could not be given the mark Windows puts on downloaded \
              files, so SmartScreen will not check it"
            .to_owned(),
        several => format!(
            "; {several} of those written could not be given the mark Windows puts on \
             downloaded files, so SmartScreen will not check them"
        ),
    };
    let sentence = format!(
        "Extracted {} {} ({}) that Defender did not flag into {destination}; {} {} ({}) left \
         out{}{removed}{unmarked}.",
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
    fn only_plain_drive_paths_are_checked() {
        // Network shares, device paths and relative names are refused before
        // anything is resolved, for the file and for its original alike.
        for refused in [
            r"\\server\share\x.zip",
            r"\\?\UNC\server\share\x.zip",
            r"\\.\pipe\kam",
            r"\\?\GLOBALROOT\Device\HarddiskVolume3\x.zip",
            "x.zip",
            "",
        ] {
            assert!(
                plain_paths(refused, None).is_err(),
                "{refused:?} was accepted"
            );
            assert!(
                plain_paths(r"C:\Users\x\Downloads\a.zip", Some(refused)).is_err(),
                "{refused:?} was accepted as the original"
            );
        }
        assert!(plain_paths(r"C:\Users\x\Downloads\a.zip", None).is_ok());
        assert!(plain_paths(r"\\?\D:\a.zip", Some(r"C:\a.zip")).is_ok());
    }

    #[test]
    fn a_network_path_is_refused_without_being_resolved() {
        // Red review: resolving this would make LocalSystem wait on the
        // network, or sign in as the machine to whatever answered. The address
        // is reserved for documentation and never routes.
        let started = std::time::Instant::now();
        let refusal = open_as_caller(r"\\192.0.2.1\share\x.zip", None).unwrap_err();
        assert!(
            refusal.contains("not a file on one of this PC's drives"),
            "{refusal}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "the network path was resolved before it was refused"
        );
    }

    /// A throwaway profile with a work folder and a Downloads folder, and the
    /// caller it belongs to, so nothing here touches the real ones.
    fn scratch_profile(tag: &str) -> (std::path::PathBuf, UserContext) {
        let root = std::env::temp_dir().join(format!(
            "kam-downloads-profile-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("Downloads")).unwrap();
        let user = UserContext::new(
            Some("S-1-5-21-0-0-0-4100".to_owned()),
            &root.to_string_lossy(),
        );
        std::fs::create_dir_all(work_folder(&user)).unwrap();
        (root, user)
    }

    fn context() -> Context {
        let quarantine = std::env::temp_dir().join(format!(
            "kam-downloads-test-quarantine-{}",
            std::process::id()
        ));
        Context {
            mode: crate::Mode::Console,
            store: kam_core::Store::open_in_memory().unwrap(),
            jobs: Default::default(),
            quarantine: kam_quarantine::Store::open(&quarantine).unwrap(),
            behaviour: Default::default(),
        }
    }

    const MARK: &[u8] =
        b"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.test/private?token=1\r\n";

    fn mark(file: &Path) {
        std::fs::write(format!("{}:Zone.Identifier", file.display()), MARK).unwrap();
    }

    #[test]
    fn the_original_of_a_copy_cannot_be_another_accounts_file() {
        // Red review: a copy in the caller's own work folder could name
        // another account's download as its original, and the agent read that
        // file's download address and creation time as LocalSystem.
        let (root, user) = scratch_profile("fence");
        let copy = Path::new(&work_folder(&user)).join("copy.zip");
        std::fs::write(&copy, b"a private copy").unwrap();
        let opened = open_as_caller(
            &copy.to_string_lossy(),
            Some(r"C:\Users\Default\Downloads\secret.zip"),
        )
        .unwrap();
        let refusal = permitted(&opened, &user).unwrap_err();
        assert!(refusal.contains("was not read"), "{refusal}");
        drop(opened);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Red review: the original of a working copy was accepted when it was
    /// not there, and then read by name with the system's rights once
    /// Defender had finished, seconds later, with no second look. Whatever
    /// that name had come to lead to by then was read, and its download
    /// address was handed back and stored.
    #[test]
    fn the_original_of_a_copy_is_read_when_the_request_arrives_and_never_again() {
        let (root, user) = scratch_profile("original");
        let copy = Path::new(&work_folder(&user)).join("copy.zip");
        std::fs::write(&copy, b"a private copy").unwrap();
        let original = root.join("Downloads").join("a.zip");
        let asked = original.to_string_lossy().into_owned();

        // Not there when the request arrives, as when it is in quarantine.
        let opened = open_as_caller(&copy.to_string_lossy(), Some(&asked)).unwrap();
        // The name comes to lead to a file while the check is under way.
        std::fs::write(&original, b"not the caller's to ask about").unwrap();
        mark(&original);

        let response = check(opened, "test-job", &context(), &Reporter::silent(), &user);
        let Response::DownloadChecked(record) = response else {
            panic!("the copy was not checked: {response:?}");
        };
        assert_eq!(
            record.check.path, asked,
            "the row is kept under the original"
        );
        assert!(
            record.check.origin.is_none(),
            "the original was read after the request had been let in: {:?}",
            record.check.origin
        );
        assert!(record.check.arrived_at.is_none());

        // An original that is there when the request arrives is read then.
        let opened = open_as_caller(&copy.to_string_lossy(), Some(&asked)).unwrap();
        let response = check(opened, "test-job", &context(), &Reporter::silent(), &user);
        let Response::DownloadChecked(record) = response else {
            panic!("the copy was not checked: {response:?}");
        };
        assert!(record.check.origin.is_some() && record.check.arrived_at.is_some());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_file_the_caller_cannot_open_is_refused_and_one_they_can_is_not() {
        let scratch =
            std::env::temp_dir().join(format!("kam-unreadable-{}.bin", std::process::id()));
        std::fs::write(&scratch, b"private").unwrap();
        let path = scratch.to_string_lossy().into_owned();
        assert!(
            open_as_caller(&path, None).is_ok(),
            "a readable file was refused"
        );
        // An original already moved into quarantine is simply not found.
        assert!(open_as_caller(&path, Some(r"C:\nowhere\gone.zip")).is_ok());
        let caller_can_read = |path: &str, copy_of: Option<&str>| open_as_caller(path, copy_of);

        let me = format!(
            "{}\\{}",
            std::env::var("USERDOMAIN").unwrap(),
            std::env::var("USERNAME").unwrap()
        );
        let icacls = Path::new(&std::env::var("SystemRoot").unwrap())
            .join("System32")
            .join("icacls.exe");
        let denied = std::process::Command::new(&icacls)
            .arg(&scratch)
            .args(["/deny", &format!("{me}:(R)")])
            .output()
            .unwrap();
        let readable = scratch.with_extension("copy");
        std::fs::write(&readable, b"a copy").unwrap();
        let refused = caller_can_read(&path, None);
        let refused_as_original = caller_can_read(&readable.to_string_lossy(), Some(&path));

        // Undo before asserting, so a failure leaves nothing locked behind.
        let _ = std::process::Command::new(&icacls)
            .arg(&scratch)
            .args(["/remove:d", &me])
            .output();
        let _ = std::fs::remove_file(&scratch);
        let _ = std::fs::remove_file(&readable);

        assert!(
            denied.status.success(),
            "could not deny the read: {denied:?}"
        );
        assert!(
            refused.is_err(),
            "a file the caller cannot open was accepted"
        );
        assert!(
            refused_as_original.is_err(),
            "an original the caller cannot open was accepted"
        );
    }

    fn stored(path: &str, sha256: &str, outcome: &FileScan) -> DownloadRow {
        DownloadRow {
            sid: "S-1-5-21-0-0-0-4100".to_owned(),
            path: path.to_owned(),
            sha256: sha256.to_owned(),
            name: "a.zip".to_owned(),
            bytes: 1,
            arrived_at: None,
            checked_at: String::new(),
            origin: None,
            signature: None,
            outcome: serde_json::to_string(outcome).unwrap(),
            actions: String::new(),
            dissection: None,
        }
    }

    fn fits_in_a_frame(response: Response) -> bool {
        kam_ipc::frame::write_frame(&mut Vec::new(), &kam_ipc::Reply::Done(response)).is_ok()
    }

    /// Red review: the history went to the page in one frame, every row
    /// carrying its archive's member list and Defender's whole answer. Past
    /// 8 MiB the frame was refused, and the page could never be sent its
    /// history again. Rows written that way are still in real stores, so
    /// this builds them as they were.
    #[test]
    fn a_history_of_large_archives_is_still_sent_and_says_how_much_there_is() {
        let context = context();
        let (root, user) = scratch_profile("history");
        let flagged = kam_scanner::defender_file::parse_report(
            Some(2),
            &format!(
                "Scanning C:\\a.zip found 1 threats.\r\nThreat : Trojan:Win32/Example\r\n\
                 Resources : 3000 total\r\n{}",
                (0..3000)
                    .map(|number| format!("    file : C:\\a.zip->tools/{number}.exe\r\n"))
                    .collect::<String>()
            ),
        );
        let entries: Vec<kam_scanner::downloads::Entry> = (0..5000)
            .map(|number| kam_scanner::downloads::Entry {
                name: format!("a/rather/long/folder/name/for/file-number-{number}.dat"),
                bytes: 10,
                packed: 5,
                is_dir: false,
                encrypted: false,
                link: false,
                unsupported: None,
            })
            .collect();
        for number in 0..40 {
            let path = format!(r"C:\D\{number}.zip");
            let sha256 = format!("{number:064x}");
            context
                .store
                .record_download_check(&stored(&path, &sha256, &flagged))
                .unwrap();
            let dissection =
                kam_scanner::downloads::dissect(&path, &sha256, flagged.clone(), &entries);
            context
                .store
                .set_download_dissection(
                    caller(&user),
                    &path,
                    &sha256,
                    &serde_json::to_string(&dissection).unwrap(),
                )
                .unwrap();
        }

        let response = list(&[], 1000, &context, &user);
        let Response::Downloads { records, on_record } = &response else {
            panic!("the history was not listed: {response:?}");
        };
        assert_eq!((records.len(), *on_record), (40, 40));
        let row = &records[0];
        assert_eq!(row.check.scan.answer, Answer::Flagged);
        assert_eq!(row.check.scan.threats[0].resources.len(), 1);
        assert_eq!(row.dissection.as_ref().unwrap().totals.files, 5000);
        assert!(fits_in_a_frame(response), "the history no longer fits");

        // And should rows ever be large all the same, the answer stops short
        // of what a frame can carry and says how many rows there are.
        let action = serde_json::to_string(&DownloadAction {
            at: "2026-11-18T00:00:00.000Z".to_owned(),
            what: "x".repeat(300_000),
            undo: None,
        })
        .unwrap();
        for number in 0..40 {
            context
                .store
                .add_download_action(caller(&user), &format!(r"C:\D\{number}.zip"), None, &action)
                .unwrap();
        }
        let response = list(&[], 1000, &context, &user);
        let Response::Downloads { records, on_record } = &response else {
            panic!("the history was not listed: {response:?}");
        };
        assert_eq!(*on_record, 40);
        assert!(
            !records.is_empty() && records.len() < 40,
            "{} rows of 300 KB each were all sent",
            records.len()
        );
        assert!(fits_in_a_frame(response), "the answer was not cut to fit");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The window names the files in Downloads now, and gets the newest row
    /// for each however old it is, so a file checked long ago does not read
    /// as never checked once the history is longer than one answer.
    #[test]
    fn a_file_the_window_names_is_found_however_old_its_row() {
        let context = context();
        let (root, user) = scratch_profile("named");
        let nothing = kam_scanner::defender_file::parse_report(Some(0), "");
        for (number, path) in [r"C:\D\old.zip", r"C:\D\middle.zip", r"C:\D\new.zip"]
            .iter()
            .enumerate()
        {
            context
                .store
                .record_download_check(&stored(path, &format!("{number:064x}"), &nothing))
                .unwrap();
        }
        let asked = [r"c:\d\OLD.zip".to_owned(), r"C:\D\never.zip".to_owned()];
        let Response::Downloads { records, on_record } = list(&asked, 1, &context, &user) else {
            panic!("the history was not listed");
        };
        let paths: Vec<&str> = records
            .iter()
            .map(|record| record.check.path.as_str())
            .collect();
        assert_eq!(paths, [r"C:\D\old.zip", r"C:\D\new.zip"]);
        assert_eq!(on_record, 3);

        // The reply to a check carries Defender's whole list, cut to a size
        // that can be sent.
        let long = kam_scanner::defender_file::parse_report(
            Some(2),
            &format!(
                "Scanning C:\\a.zip found 1 threats.\r\nThreat : Trojan:Win32/Example\r\n\
                 Resources : 60000 total\r\n{}",
                (0..60_000)
                    .map(|number| format!(
                        "    file : C:\\a.zip->{}\u{1}{number}.exe\r\n",
                        r"a\b\".repeat(30)
                    ))
                    .collect::<String>()
            ),
        )
        .bounded(kam_scanner::defender_file::MAX_ANSWER_BYTES);
        let mut record = record_from_row(stored(r"C:\D\a.zip", &"0".repeat(64), &nothing));
        record.check.scan = long;
        assert!(fits_in_a_frame(Response::DownloadChecked(Box::new(record))));
        let _ = std::fs::remove_dir_all(&root);
    }

    fn detection(name: &str, path: &str, when: &str, status: &str) -> kam_scanner::Threat {
        kam_scanner::Threat {
            name: name.to_owned(),
            severity: Some(5),
            category: None,
            action: None,
            status: None,
            resources: vec![format!("file:_{path}")],
            detected_at: Some(when.to_owned()),
            status_text: status.to_owned(),
            needs_attention: false,
        }
    }

    /// A download Defender removes before it can be checked used to leave no
    /// trace on the page at all. It is recorded now, with what Defender's own
    /// history says about that path, read by the agent and not taken from
    /// the window.
    #[test]
    fn a_download_gone_before_it_was_checked_is_recorded_with_what_defender_did() {
        let context = context();
        let (root, user) = scratch_profile("vanished");
        let path = root.join("Downloads").join("taken.exe");
        let asked = path.to_string_lossy().into_owned();
        // Now, as WMI writes a time.
        let now: String = kam_core::clock::now_utc_iso()
            .chars()
            .filter(char::is_ascii_digit)
            .take(14)
            .collect();
        let history = vec![
            detection(
                "Trojan:Win32/Example",
                &asked,
                &format!("{now}.000000+000"),
                "quarantined",
            ),
            // The same name, flagged long ago: not the file that has just gone.
            detection(
                "Old:Win32/Stale",
                &asked,
                "20200101000000.000000+000",
                "removed",
            ),
            // Another file altogether.
            detection(
                "Other:Win32/Elsewhere",
                &root.join("Downloads").join("b.exe").to_string_lossy(),
                &format!("{now}.000000+000"),
                "quarantined",
            ),
        ];

        let response = vanished_with(
            &asked,
            4096,
            Some("2026-11-18T10:02:00.000Z"),
            Ok(history),
            &context,
            &user,
        );
        let Response::DownloadChecked(record) = &response else {
            panic!("it was not recorded: {response:?}");
        };
        assert!(record.first_check, "nobody is told about it");
        assert_eq!(record.check.scan.answer, Answer::GoneBeforeCheck);
        assert_eq!(record.check.scan.threat_names(), ["Trojan:Win32/Example"]);
        let caveat = record.check.scan.caveat.as_deref().unwrap_or_default();
        assert!(
            caveat.contains("Trojan:Win32/Example (quarantined, recorded "),
            "{caveat}"
        );
        assert_eq!(record.check.bytes, 4096);
        assert_eq!(
            record.check.arrived_at.as_deref(),
            Some("2026-11-18T10:02:00.000Z")
        );

        // It is on the page's list, once, however often it is reported.
        let again = vanished_with(&asked, 4096, None, Ok(Vec::new()), &context, &user);
        let Response::DownloadChecked(again) = again else {
            panic!("the second report was refused");
        };
        assert!(!again.first_check);
        assert!(again.check.scan.threats.is_empty());
        assert!(again
            .check
            .scan
            .caveat
            .as_deref()
            .unwrap_or_default()
            .contains("what removed it is not known"));
        let Response::Downloads { records, .. } = list(&[], 10, &context, &user) else {
            panic!("the history was not listed");
        };
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].check.scan.answer, Answer::GoneBeforeCheck);
        assert_eq!(records[0].check.path, asked);

        // A history that could not be read is said, not taken for empty.
        let unread = vanished_with(
            &asked,
            0,
            None,
            Err("no access".to_owned()),
            &context,
            &user,
        );
        let Response::DownloadChecked(unread) = unread else {
            panic!("the report was refused");
        };
        assert!(unread
            .check
            .scan
            .caveat
            .as_deref()
            .unwrap_or_default()
            .contains("could not be read (no access)"));

        // Only a missing name directly inside the caller's own Downloads.
        std::fs::write(&path, b"here after all").unwrap();
        for refused in [asked.clone(), r"C:\Windows\System32\taken.dll".to_owned()] {
            let response = vanished_with(&refused, 0, None, Ok(Vec::new()), &context, &user);
            assert!(
                matches!(response, Response::Error { .. }),
                "{refused} was recorded as gone: {response:?}"
            );
        }
        let audited = context.store.recent_audit(20).unwrap();
        let count = |effect: Effect| {
            audited
                .iter()
                .filter(|entry| entry.action == "vanished" && entry.effect == effect)
                .count()
        };
        assert_eq!((count(Effect::Observed), count(Effect::Refused)), (3, 2));
        let _ = std::fs::remove_dir_all(&root);
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
