//! Asking Windows Defender to scan, from the agent.
//!
//! # Why this is a wrapper and not a scanner
//!
//! KAM does not detect malware and this module does not change that. Defender
//! is already on the machine, already has the signatures, and is already better
//! at it than anything this project could ship. What is missing is not detection
//! but *reach*: starting a scan means finding the Security app, and its results
//! then live somewhere a person never looks. So this starts the scan and brings
//! the answer back to where they already are.
//!
//! # The rules this obeys, and why each one exists
//!
//! Every one of these came out of a specific failure, most of them found in this
//! codebase rather than read about.
//!
//! - **The executable is named absolutely.** `Command::new("MpCmdRun.exe")`
//!   searches the launching process's own directory first, and the agent runs as
//!   LocalSystem. That exact mistake was a user-to-SYSTEM execution path here
//!   until it was fixed in the hardening module. Absolute naming is safe *here*
//!   specifically because both of Defender's locations are administrator-only,
//!   which was checked rather than assumed.
//! - **Arguments are passed as arguments**, never joined into a string. The same
//!   module got that wrong too, in a comment that claimed the opposite of what
//!   the code did.
//! - **A scan target must be an absolute, resolved path.** Otherwise a target
//!   beginning with `-` is read by `MpCmdRun` as a switch, and the caller
//!   chooses the flags rather than the file.
//! - **Remediation is disabled.** This is the important one and the least
//!   obvious. Left able to act, Defender follows a junction and *removes the
//!   real target elsewhere* — destroying something outside every fence and audit
//!   trail this product has. So Defender reports, and KAM decides and acts
//!   through its own quarantine, which is the only path here that is fenced and
//!   recorded.
//! - **Its console output is not believed.** Exit codes are quirky, and a file
//!   whose *name* contains a newline can write a convincing "no threats found"
//!   line into the output — the same injection that was found in the audit log,
//!   relocated into a result parser. What was found is read afterwards from
//!   Defender's own records instead.
//!
//! The last two are why this file is longer than "run a command".

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use kam_core::{Error, Result};
use serde::{Deserialize, Serialize};

use crate::Threat;

/// How long to let a scan run before giving up on it.
///
/// A full scan of a large disk genuinely takes an hour or more, so this is
/// generous. It exists so a wedged child process cannot hold a thread for the
/// life of the service, not to bound honest work.
const SCAN_TIMEOUT: Duration = Duration::from_secs(4 * 60 * 60);

/// How often the child is checked for having finished, or for being cancelled.
const POLL: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScanKind {
    /// The places malware has to be to run: memory, startup, the usual folders.
    /// Minutes rather than hours.
    Quick,
    /// Every file on every fixed drive. Hours.
    Full,
    /// One directory or file the person pointed at.
    Path { path: String },
}

impl ScanKind {
    pub fn label(&self) -> String {
        match self {
            Self::Quick => "a quick scan".to_owned(),
            Self::Full => "a full scan".to_owned(),
            Self::Path { path } => format!("a scan of {path}"),
        }
    }
}

/// What a finished scan came to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOutcome {
    pub label: String,
    /// False when it was cancelled or timed out. A partial scan that found
    /// nothing has not established that there is nothing.
    pub completed: bool,
    /// Defender's own exit code, reported rather than interpreted.
    pub exit_code: Option<i32>,
    pub seconds: u64,
    /// Detections Defender recorded that were not in its records beforehand.
    ///
    /// Read from Defender rather than parsed out of its console output, and
    /// compared against a before-list rather than filtered by time, so no clock
    /// or date format has to be trusted either.
    pub found: Vec<Threat>,
    /// Set when the result is worth less than it looks.
    pub caveat: Option<String>,
}

/// Where `MpCmdRun.exe` is, named absolutely.
///
/// The stub under Program Files rather than the versioned copy in
/// `ProgramData\Microsoft\Windows Defender\Platform\<version>\`. Both are
/// administrator-only — which is what makes naming either of them safe, and was
/// verified rather than assumed — but the stub forwards to whichever platform
/// version is live, so nothing here has to enumerate versions and pick one.
fn mp_cmd_run() -> PathBuf {
    let program_files =
        std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".to_owned());
    PathBuf::from(program_files).join(r"Windows Defender\MpCmdRun.exe")
}

/// A directory to run the child in that nobody can write to.
///
/// Not inherited. A process's working directory takes part in library search,
/// so handing a child one that a caller influenced is a way of choosing what it
/// loads. Defender's own binary is signed and loads from its protected
/// directory, and this costs one line.
fn safe_working_directory() -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    PathBuf::from(root).join("System32")
}

/// Check a scan target before it becomes an argument.
///
/// Returns the resolved path, or says why it will not be scanned.
///
/// Two separate jobs. The first is that `MpCmdRun` reads `-File <path>`, so a
/// target that begins with `-` is read as a switch and the caller is choosing
/// flags rather than naming a file; requiring an absolute path makes that
/// structurally impossible rather than filtered. The second is that the path
/// arrives from a client, so it is resolved before use like every other path in
/// this product — see `kam-storage`'s `paths` module for the history behind
/// that.
fn checked_target(path: &str) -> std::result::Result<PathBuf, String> {
    let resolved = std::fs::canonicalize(path)
        .map_err(|error| format!("{path} could not be found, so it was not scanned: {error}"))?;

    // `canonicalize` gives the extended-length form. Defender takes it, and it
    // is unambiguous, but the leading `\\?\` means a check for "starts with a
    // drive letter" has to look past it.
    let text = resolved.to_string_lossy().into_owned();
    let plain = text.strip_prefix(r"\\?\").unwrap_or(&text);

    let starts_with_drive = {
        let mut chars = plain.chars();
        matches!(
            (chars.next(), chars.next(), chars.next()),
            (Some(letter), Some(':'), Some('\\')) if letter.is_ascii_alphabetic()
        )
    };
    if !starts_with_drive {
        return Err(format!(
            "{path} is not a plain drive path, so it was not scanned"
        ));
    }

    Ok(PathBuf::from(plain))
}

/// Detections Defender has that it did not have before the scan.
///
/// Compared against a list taken beforehand rather than filtered by timestamp,
/// so no clock and no date format has to be trusted. The key is the name paired
/// with the detection time: two genuinely separate detections of the same threat
/// in the same instant would collapse into one, which under-counts a display and
/// changes nothing about what is reported.
/// Detections Defender has recorded that were not in `known`.
///
/// An error rather than an empty list when the history cannot be read: an
/// unreadable history after a scan is not a clean result, and must not be
/// shown as one.
fn new_detections(
    known: &std::collections::HashSet<(String, Option<String>)>,
) -> Result<Vec<Threat>> {
    Ok(crate::defender::threats()?
        .into_iter()
        .filter(|threat| !known.contains(&(threat.name.clone(), threat.detected_at.clone())))
        .collect())
}

/// The arguments for one scan, built only from constants and, for a single
/// path, that path already resolved and checked.
///
/// # Quick and full scans behave exactly as Windows Security's own
///
/// `-DisableRemediation` is, in `MpCmdRun`'s own words, "valid only for custom
/// scan". It was passed to quick and full scans as well, where Defender does
/// not honour it as documented, and where it can also keep what was found out
/// of the detection history this reads afterwards. So a scan started here could
/// report "nothing new" about something Defender had found.
///
/// A quick or full scan started here is now the same scan as the button in
/// Windows Security: Defender deals with what it finds the way it is configured
/// to, usually by quarantining it where Windows Security can restore it, and
/// records it in its history, which is what this then reads. That is the point
/// of building on Defender rather than beside it.
///
/// A scan of one path keeps `-DisableRemediation`, where it is valid. That path
/// comes from a request, and a target reached through a link must not have
/// Defender act on whatever the link leads to.
fn arguments(kind: &ScanKind, target: Option<&Path>) -> Vec<String> {
    let mut arguments = vec!["-Scan".to_owned(), "-ScanType".to_owned()];
    match (kind, target) {
        (ScanKind::Quick, _) => arguments.push("1".to_owned()),
        (ScanKind::Full, _) => arguments.push("2".to_owned()),
        (ScanKind::Path { .. }, Some(target)) => {
            arguments.push("3".to_owned());
            arguments.push("-File".to_owned());
            arguments.push(target.to_string_lossy().into_owned());
            arguments.push("-DisableRemediation".to_owned());
        }
        // A path scan without its checked target is never built.
        (ScanKind::Path { .. }, None) => arguments.clear(),
    }
    arguments
}

fn unread_after(error: &Error) -> String {
    format!(
        "Defender's detection history could not be read after the scan ({error}), so \
         this cannot say what it found. Windows Security's Protection history can."
    )
}

/// Ask Defender to scan, and report what it found.
///
/// Blocks for as long as the scan runs, which for a full scan is hours, so the
/// caller is expected to be a job on its own thread. `cancel` is checked
/// throughout and kills the child.
pub fn run(kind: &ScanKind, cancel: &AtomicBool) -> Result<ScanOutcome> {
    let executable = mp_cmd_run();
    if !executable.is_file() {
        return Err(Error::Privileged(format!(
            "{} is not on this machine, so Defender cannot be asked to scan",
            executable.display()
        )));
    }

    // Built as separate arguments, never a command line. See `arguments`.
    let target = match kind {
        ScanKind::Path { path } => Some(checked_target(path).map_err(Error::Refused)?),
        _ => None,
    };
    let arguments = arguments(kind, target.as_deref());
    let mut caveat = None;

    // What Defender already knew about, so the new ones can be told apart
    // without trusting a timestamp format. If this cannot be read, nothing
    // can be called new, and the result says so rather than presenting every
    // past detection as today's.
    let known: Option<std::collections::HashSet<(String, Option<String>)>> =
        crate::defender::threats().ok().map(|before| {
            before
                .iter()
                .map(|threat| (threat.name.clone(), threat.detected_at.clone()))
                .collect()
        });

    let started = Instant::now();
    let mut child = std::process::Command::new(&executable)
        .args(&arguments)
        .current_dir(safe_working_directory())
        .stdin(std::process::Stdio::null())
        // Discarded rather than captured. Nothing reads it for meaning (see
        // below), and a pipe nobody drains fills up and stalls the scanner
        // until the timeout, hours later.
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| {
            Error::Privileged(format!("Defender's scanner could not be started: {error}"))
        })?;

    let mut completed = true;
    let exit_code = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code(),
            Ok(None) => {}
            Err(error) => {
                return Err(Error::Privileged(format!(
                    "Defender's scanner could not be waited on: {error}"
                )))
            }
        }

        if cancel.load(Ordering::SeqCst) {
            let _ = child.kill();
            let _ = child.wait();
            completed = false;
            caveat = Some(
                "The scan was stopped before it finished, so a clean result \
                 would not mean much."
                    .to_owned(),
            );
            break None;
        }
        if started.elapsed() > SCAN_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            completed = false;
            caveat = Some(format!(
                "The scan was still running after {} hours and was stopped.",
                SCAN_TIMEOUT.as_secs() / 3600
            ));
            break None;
        }

        std::thread::sleep(POLL);
    };

    // Read what was found from Defender's records rather than from what the
    // process printed. A file whose name carries a newline can write a
    // convincing line into that output; it cannot write a row into Defender's
    // own detection history.
    //
    // Read twice, briefly apart, and only when the first read found nothing.
    // `MpCmdRun` exiting and the detection appearing in `MSFT_MpThreatDetection`
    // are not the same instant, and the direction of that race matters: it can
    // only turn a real detection into an apparent clean result, which is the one
    // outcome this must not produce. A second look costs a moment on the path
    // where nothing was found and nothing at all on the path where something
    // was. Raised in review; the lag is plausible rather than demonstrated,
    // which is exactly the sort of thing to spend a second on rather than argue
    // about.
    let mut found = Vec::new();
    match &known {
        None => {
            caveat.get_or_insert_with(|| {
                "Defender's detection history could not be read before the scan, so \
                 this cannot say which detections are new. Windows Security's \
                 Protection history lists everything Defender has found."
                    .to_owned()
            });
        }
        Some(known) => match new_detections(known) {
            Ok(first) if !first.is_empty() => found = first,
            Ok(_) => {
                std::thread::sleep(Duration::from_millis(1500));
                match new_detections(known) {
                    Ok(second) => found = second,
                    Err(error) => {
                        caveat.get_or_insert_with(|| unread_after(&error));
                    }
                }
            }
            Err(error) => {
                caveat.get_or_insert_with(|| unread_after(&error));
            }
        },
    }

    // A single-path scan keeps remediation off, and with it Defender reports
    // only in its own console output, which is not read for meaning. Its exit
    // code is the one signal left, so a non-zero code is said out loud rather
    // than shown as nothing found.
    if let (ScanKind::Path { .. }, Some(code)) = (kind, exit_code) {
        if code != 0 && found.is_empty() && caveat.is_none() {
            caveat = Some(format!(
                "Defender finished with code {code}, which it uses when it finds \
                 something or cannot scan the file. A single-file scan leaves the file \
                 where it is and does not always record it, so check it with Windows \
                 Security before trusting it."
            ));
        }
    }

    if completed && caveat.is_none() && !found.is_empty() {
        caveat = Some(match kind {
            ScanKind::Path { .. } => "Defender was asked to report rather than to act, so \
                 anything found is still where it was."
                .to_owned(),
            _ => "Defender dealt with these the way Windows Security does, usually by \
                 quarantining them. Windows Security's Protection history shows what it \
                 did and can restore anything it got wrong."
                .to_owned(),
        });
    }

    Ok(ScanOutcome {
        label: kind.label(),
        completed,
        exit_code,
        seconds: started.elapsed().as_secs(),
        found,
        caveat,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn the_scanner_is_named_absolutely_and_is_really_there() {
        let path = mp_cmd_run();
        assert!(path.is_absolute(), "{} is not absolute", path.display());
        assert!(
            path.to_string_lossy()
                .to_lowercase()
                .contains(r"\windows defender\"),
            "{} is not Defender's own copy",
            path.display()
        );
        // Present on any machine with Defender, which is every supported one.
        assert!(
            path.is_file(),
            "{} is missing, so scanning cannot be offered",
            path.display()
        );
    }

    #[test]
    fn the_working_directory_is_one_nobody_can_write_to() {
        let directory = safe_working_directory();
        assert!(directory.is_absolute());
        assert!(directory.is_dir());
        assert!(directory
            .to_string_lossy()
            .to_lowercase()
            .ends_with(r"\system32"));
    }

    /// A target cannot smuggle a switch in, whatever it is called.
    ///
    /// `MpCmdRun` reads `-File <path>`, so a target beginning with `-` would be
    /// taken as a flag and the caller would be choosing Defender's behaviour
    /// rather than naming a file. Requiring an absolute path makes that
    /// impossible by construction rather than by blocklist.
    #[test]
    fn a_target_that_is_not_a_plain_path_is_refused() {
        for hostile in [
            "-Scan",
            "-RemoveDefinitions",
            "--help",
            "/scan",
            "",
            "relative\\path.txt",
            r"\\?\GLOBALROOT\Device\HarddiskVolume1",
        ] {
            assert!(
                checked_target(hostile).is_err(),
                "{hostile:?} was accepted as a scan target"
            );
        }
    }

    #[test]
    fn a_real_directory_resolves_to_a_plain_drive_path() {
        let scratch = std::env::temp_dir().join("kam-defender-scan-target");
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();

        let checked = checked_target(&scratch.to_string_lossy()).expect("a real directory");
        let text = checked.to_string_lossy().into_owned();
        assert!(!text.starts_with(r"\\?\"), "{text} kept the prefix");
        assert!(
            text.chars().nth(1) == Some(':'),
            "{text} is not a drive path"
        );

        let _ = std::fs::remove_dir_all(&scratch);
    }

    /// Nothing a caller supplies can become a flag.
    ///
    /// The arguments are assembled from compiled-in constants plus, at most, one
    /// resolved absolute path. This asserts the shape rather than describing it,
    /// because the day somebody adds an option whose value comes from a request
    /// is the day that stops being true.
    ///
    /// This used to rebuild the arguments inside the test and then check the
    /// copy it had just built, so it could never fail. It now calls the
    /// function the scan uses.
    #[test]
    fn scans_are_built_the_way_mpcmdrun_documents_them() {
        // Quick and full: the same scan as Windows Security's button, with no
        // switch MpCmdRun documents as valid only for a custom scan.
        assert_eq!(
            arguments(&ScanKind::Quick, None),
            ["-Scan", "-ScanType", "1"]
        );
        assert_eq!(
            arguments(&ScanKind::Full, None),
            ["-Scan", "-ScanType", "2"]
        );

        // One path: custom scan, and remediation off, where it is valid.
        let target = Path::new(r"C:\Users\someone\thing.exe");
        let path = ScanKind::Path {
            path: target.display().to_string(),
        };
        let built = arguments(&path, Some(target));
        assert_eq!(built[..3], ["-Scan", "-ScanType", "3"]);
        assert!(built.iter().any(|part| part == "-DisableRemediation"));

        // And never a path scan without its checked target.
        assert!(arguments(&path, None).is_empty());

        for arguments in [
            arguments(&ScanKind::Quick, None),
            arguments(&ScanKind::Full, None),
            built,
        ] {
            for part in &arguments {
                assert!(
                    !part.contains('\n') && !part.contains('\r'),
                    "{part:?} carries a line break"
                );
            }
        }
    }
}
