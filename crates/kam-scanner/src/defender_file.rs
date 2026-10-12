//! Asking Defender about one file, report-only, and reading its answer.
//!
//! # Why this reads Defender's console output, when the full scan does not
//!
//! [`crate::defender_scan`] deliberately ignores what `MpCmdRun` prints and
//! reads detections from Defender's own history instead, because a file whose
//! name carries a newline can print a convincing line of its own. That is the
//! right rule for a quick or full scan, which Defender records.
//!
//! It cannot be the rule here. A scan of one file with `-DisableRemediation`
//! records **nothing**: verified on 12 Oct 2026 against the EICAR test archive,
//! `MpCmdRun` printed the threat and both resources and exited 2, while
//! `MSFT_MpThreatDetection` and the Defender Operational event log gained no
//! entry at all. Letting Defender remediate so that it records would let it act
//! on a path in a folder the person can write to, which is the junction hazard
//! `defender_scan` describes. So the console is the only place the answer to a
//! report-only scan exists, and it is read here, under rules that make a
//! forged line unable to make anything look cleaner than it is:
//!
//! - **The exit code decides whether anything was found**, and a file name
//!   cannot change an exit code. 0 is nothing found. 2 is either "found
//!   something" or "failed", and the two are told apart by Defender's own
//!   summary line, which comes before any name it prints.
//! - **The text only says which, and by what name.** Defender states how many
//!   threats it found and how many resources each has. When the list that
//!   follows does not add up to those counts, the listing is marked
//!   inconsistent and nothing is offered on the strength of it.
//! - **Anything the listing names that cannot be matched fails closed.** See
//!   [`attribute`]: a member Defender named and the archive does not list, or a
//!   threat on the archive as a whole, means nothing is offered for extraction.
//! - **Names carrying control characters are never trusted**, as targets here
//!   and as archive members in the window.

use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use kam_core::{Error, Result};
use serde::{Deserialize, Serialize};

use crate::defender_scan::{
    checked_target, mp_cmd_run, safe_working_directory, POLL, SCAN_TIMEOUT,
};

/// Most of `MpCmdRun`'s output kept. A few lines in the ordinary case; this
/// only bounds an archive with an absurd number of detections, and a listing
/// cut short is marked inconsistent rather than read as complete.
const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

/// What Defender said, in the three cases that differ for a person.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Answer {
    /// Defender scanned it and reported nothing.
    NothingFound,
    /// Defender flagged something, named in `threats`.
    Flagged,
    /// Defender did not finish, failed, or was stopped. Not a clean result.
    NotFinished,
}

/// One threat Defender flagged, with the resources it named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flagged {
    /// Defender's own name for it, such as `Virus:DOS/EICAR_Test_File`.
    pub name: String,
    /// What it named, as it printed them: `file : C:\...\a.zip->tools/x.exe`.
    pub resources: Vec<String>,
}

/// The answer to a report-only scan of one file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileScan {
    pub answer: Answer,
    /// False when Defender did not finish. Kept beside `answer` because a
    /// record read years later should not need the enum to say it.
    pub completed: bool,
    /// Defender's own exit code: 0 nothing found, 2 found something or failed.
    pub exit_code: Option<i32>,
    pub seconds: u64,
    pub threats: Vec<Flagged>,
    /// Whether the list of threats added up to Defender's own counts. When it
    /// does not, that Defender flagged something stands, and which files it
    /// named is not relied on.
    pub listing_consistent: bool,
    /// Set when the answer is worth less than it looks, or needs saying.
    pub caveat: Option<String>,
    /// The definitions Defender looked with, when it said.
    #[serde(default)]
    pub definitions: Option<String>,
}

impl FileScan {
    /// The names Defender gave, without repeats, in the order it gave them.
    pub fn threat_names(&self) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        for threat in &self.threats {
            if !names.contains(&threat.name) {
                names.push(threat.name.clone());
            }
        }
        names
    }

    /// One plain sentence: what Defender said.
    pub fn sentence(&self) -> String {
        match self.answer {
            Answer::NothingFound => "Defender found nothing".to_owned(),
            Answer::Flagged => {
                let names = self.threat_names();
                if names.is_empty() {
                    "Defender flagged something it did not name".to_owned()
                } else {
                    format!("Defender flagged {}", names.join(", "))
                }
            }
            Answer::NotFinished => "Defender could not finish checking it".to_owned(),
        }
    }
}

/// Ask Defender about one file and report what it said, changing nothing.
///
/// Blocks for as long as the scan runs, normally a few seconds. `cancel` is
/// checked throughout and kills the child; a stopped check comes back as
/// [`Answer::NotFinished`], never as nothing found.
pub fn check_file(path: &str, cancel: &AtomicBool) -> Result<FileScan> {
    let executable = mp_cmd_run();
    if !executable.is_file() {
        return Err(Error::Privileged(format!(
            "{} is not on this machine, so Defender cannot be asked to check anything",
            executable.display()
        )));
    }
    let target = checked_target(path).map_err(Error::Refused)?;
    let text = target.to_string_lossy().into_owned();
    if text.chars().any(char::is_control) {
        return Err(Error::Refused(format!(
            "{} has a control character in its name, so Defender's answer about it could not \
             be read safely",
            text.escape_debug()
        )));
    }

    // What it is looking with, read first so a slow read cannot be mistaken
    // for a slow scan. Optional: not knowing the version does not change the
    // answer, only how it is dated.
    let definitions = crate::defender::status()
        .ok()
        .and_then(|status| status.antivirus_signature_version);

    let started = Instant::now();
    let mut child = std::process::Command::new(&executable)
        .args([
            "-Scan",
            "-ScanType",
            "3",
            "-File",
            &text,
            "-DisableRemediation",
        ])
        .current_dir(safe_working_directory())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| {
            Error::Privileged(format!("Defender's scanner could not be started: {error}"))
        })?;

    // Drained on its own thread for as long as the child runs. A pipe nobody
    // reads fills up and stalls the scanner until the timeout.
    let reader = child.stdout.take().map(|mut stdout| {
        std::thread::spawn(move || {
            let mut kept = Vec::new();
            let mut chunk = [0_u8; 8192];
            let mut overflowed = false;
            loop {
                match stdout.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        if kept.len() + read <= MAX_OUTPUT_BYTES {
                            kept.extend_from_slice(&chunk[..read]);
                        } else {
                            overflowed = true;
                        }
                    }
                }
            }
            (kept, overflowed)
        })
    });

    let mut stopped: Option<String> = None;
    let exit_code = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code(),
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                return Err(Error::Privileged(format!(
                    "Defender's scanner could not be waited on: {error}"
                )));
            }
        }
        if cancel.load(Ordering::SeqCst) {
            let _ = child.kill();
            let _ = child.wait();
            stopped = Some(
                "The check was stopped before Defender finished, so it says nothing either way."
                    .to_owned(),
            );
            break None;
        }
        if started.elapsed() > SCAN_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            stopped = Some(format!(
                "Defender was still checking it after {} hours and was stopped.",
                SCAN_TIMEOUT.as_secs() / 3600
            ));
            break None;
        }
        std::thread::sleep(POLL);
    };

    let (bytes, overflowed) = reader
        .and_then(|reader| reader.join().ok())
        .unwrap_or_default();
    let output = decode_console(&bytes);

    let mut scan = match stopped {
        Some(reason) => FileScan {
            answer: Answer::NotFinished,
            completed: false,
            exit_code: None,
            seconds: 0,
            threats: Vec::new(),
            listing_consistent: false,
            caveat: Some(reason),
            definitions: None,
        },
        None => parse_report(exit_code, &output),
    };
    scan.seconds = started.elapsed().as_secs();
    scan.definitions = definitions;
    if overflowed && scan.answer == Answer::Flagged {
        scan.listing_consistent = false;
        scan.caveat.get_or_insert_with(|| {
            "Defender's list of what it flagged was too long to read whole.".to_owned()
        });
    }
    if scan.completed && !Path::new(&text).exists() {
        scan.caveat = Some(
            "The file was no longer there when the check finished. Windows Security's \
             Protection history says whether Defender removed it."
                .to_owned(),
        );
    }
    Ok(scan)
}

/// Turn what `MpCmdRun` printed into text.
///
/// Measured: it writes in the system's ANSI code page when its output is a
/// pipe. A file called `prøbe-é中.zip` came back as `pr\xF8be-\xE9?.zip` on a
/// Western European system, the character outside the code page replaced by
/// `?`. So this decodes with that code page, and the matching in [`attribute`]
/// treats every character outside ASCII as unknown on both sides. Should a
/// future version write UTF-16, that is recognised by its zero bytes.
fn decode_console(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let odd_zeros = bytes
        .iter()
        .skip(1)
        .step_by(2)
        .filter(|byte| **byte == 0)
        .count();
    if bytes.len() >= 4 && odd_zeros * 2 >= bytes.len() / 2 {
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        return String::from_utf16_lossy(&units);
    }

    use windows::Win32::Globalization::{
        MultiByteToWideChar, CP_ACP, MULTI_BYTE_TO_WIDE_CHAR_FLAGS,
    };
    let Ok(length) = i32::try_from(bytes.len()) else {
        return String::from_utf8_lossy(bytes).into_owned();
    };
    let needed =
        unsafe { MultiByteToWideChar(CP_ACP, MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0), bytes, None) };
    if needed <= 0 || needed > length.saturating_mul(2) {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let mut wide = vec![0_u16; needed as usize];
    let written = unsafe {
        MultiByteToWideChar(
            CP_ACP,
            MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0),
            bytes,
            Some(&mut wide),
        )
    };
    if written <= 0 {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    wide.truncate(written as usize);
    String::from_utf16_lossy(&wide)
}

/// Read `MpCmdRun`'s report of a one-file scan. See the module notes for why
/// each rule is what it is.
pub fn parse_report(exit_code: Option<i32>, output: &str) -> FileScan {
    let lines: Vec<&str> = output.lines().collect();
    // Defender's summary is printed before any name it lists, so the first
    // one is Defender's and not something a member's name wrote.
    let summary = lines
        .iter()
        .position(|line| line.trim_start().starts_with("Scanning ") && line.contains(" found "));
    let found = summary.and_then(|at| summary_count(lines[at]));
    let failure = lines
        .iter()
        .find(|line| line.contains("Failed with hr"))
        .and_then(|line| failure_code(line));

    let unfinished = |reason: String| FileScan {
        answer: Answer::NotFinished,
        completed: false,
        exit_code,
        seconds: 0,
        threats: Vec::new(),
        listing_consistent: false,
        caveat: Some(reason),
        definitions: None,
    };

    match exit_code {
        Some(0) => FileScan {
            answer: Answer::NothingFound,
            completed: true,
            exit_code,
            seconds: 0,
            threats: Vec::new(),
            listing_consistent: true,
            caveat: None,
            definitions: None,
        },
        Some(2) => match (summary, found) {
            (Some(at), Some(count)) if count > 0 => {
                let (threats, consistent) = threat_blocks(&lines[at + 1..], count);
                FileScan {
                    answer: Answer::Flagged,
                    completed: true,
                    exit_code,
                    seconds: 0,
                    listing_consistent: consistent,
                    caveat: (!consistent).then(|| {
                        "Defender's list of what it flagged did not add up to its own count, so \
                         which files it named is not relied on."
                            .to_owned()
                    }),
                    threats,
                    definitions: None,
                }
            }
            (Some(_), Some(_)) => unfinished(
                "Defender ended with code 2, which it uses for a failure, while saying it found \
                 nothing. That is not a clean result."
                    .to_owned(),
            ),
            _ => unfinished(match failure {
                Some(code) => format!("Defender could not check it (error {code})."),
                None => "Defender ended with code 2 without saying what it found, so this is not \
                         a clean result."
                    .to_owned(),
            }),
        },
        Some(code) => unfinished(match failure {
            Some(hr) => format!("Defender could not check it (code {code}, error {hr})."),
            None => format!("Defender ended with code {code}, so this is not a clean result."),
        }),
        None => unfinished("Defender did not report how the check ended.".to_owned()),
    }
}

/// `Scanning C:\x.zip found 1 threats.` gives 1; `found no threats.` gives 0.
///
/// Read from the end of the line, because the path before it is a file name
/// and can say anything.
fn summary_count(line: &str) -> Option<usize> {
    let (_, tail) = line.rsplit_once(" found ")?;
    let first = tail.split_whitespace().next()?;
    if first.eq_ignore_ascii_case("no") {
        return Some(0);
    }
    first.parse().ok()
}

/// The `0x80070002` in `CmdTool: Failed with hr = 0x80070002. Check ...`.
fn failure_code(line: &str) -> Option<String> {
    let (_, rest) = line.split_once("hr =")?;
    let code: String = rest
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect();
    (!code.is_empty()).then_some(code)
}

/// The threats listed after the summary line, and whether they add up.
fn threat_blocks(lines: &[&str], expected_threats: usize) -> (Vec<Flagged>, bool) {
    let mut threats: Vec<Flagged> = Vec::new();
    let mut declared: Vec<Option<usize>> = Vec::new();

    for line in lines {
        let indented = line.starts_with(' ') || line.starts_with('\t');
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('-') || trimmed.starts_with('<') {
            continue;
        }
        if !indented {
            if let Some(name) = labelled(trimmed, "Threat") {
                threats.push(Flagged {
                    name: name.to_owned(),
                    resources: Vec::new(),
                });
                declared.push(None);
                continue;
            }
            if let Some(count) = labelled(trimmed, "Resources") {
                if let Some(last) = declared.last_mut() {
                    *last = count.split_whitespace().next().and_then(|n| n.parse().ok());
                }
                continue;
            }
        }
        if indented && trimmed.contains(':') {
            if let Some(threat) = threats.last_mut() {
                threat.resources.push(trimmed.to_owned());
            }
        }
    }

    let consistent = threats.len() == expected_threats
        && threats
            .iter()
            .zip(&declared)
            .all(|(threat, declared)| *declared == Some(threat.resources.len()));
    (threats, consistent)
}

/// `Threat                  : Virus:DOS/EICAR_Test_File` gives the name.
fn labelled<'a>(line: &'a str, label: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(label)?;
    let rest = rest.trim_start().strip_prefix(':')?;
    let value = rest.trim();
    (!value.is_empty()).then_some(value)
}

/// What kind of thing a resource names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceKind {
    /// A file, possibly a member of an archive.
    File,
    /// The archive a flagged member was found in.
    Container,
    /// Anything else Defender names: a registry key, a process.
    Other(String),
}

/// One resource, taken apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resource {
    pub kind: ResourceKind,
    /// The file on disk: the archive, for a member.
    pub path: String,
    /// The member inside it, everything after the first `->`. A further `->`
    /// is a member of an archive inside the archive.
    pub member: Option<String>,
}

/// Take one resource apart, in either form Defender writes it.
///
/// The console prints `file                : C:\a.zip->tools/x.com`; its
/// detection records hold `file:_C:\a.zip->tools/x.com`. Both are read, and
/// so are the variants without the underscore.
///
/// The archive and its member are split at the *first* `->`. A Windows path
/// cannot contain `>`, so that arrow is never part of the archive's own path,
/// while a member's name can contain anything at all.
pub fn parse_resource(text: &str) -> Option<Resource> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }

    // A kind is a word of two letters or more, then a colon. A bare path
    // starts with one letter and a colon, which is a drive, not a kind.
    let word: String = text.chars().take_while(char::is_ascii_alphabetic).collect();
    let after_word = &text[word.len()..];
    let labelled = word.len() >= 2 && after_word.trim_start().starts_with(':');
    let (kind, value) = if labelled {
        let rest = after_word
            .trim_start()
            .strip_prefix(':')
            .unwrap_or_default();
        let rest = rest.strip_prefix('_').unwrap_or(rest).trim();
        let kind = match word.to_ascii_lowercase().as_str() {
            "file" => ResourceKind::File,
            "containerfile" => ResourceKind::Container,
            other => ResourceKind::Other(other.to_owned()),
        };
        (kind, rest)
    } else {
        (ResourceKind::File, text)
    };
    if value.is_empty() {
        return None;
    }

    let (path, member) = match value.split_once("->") {
        Some((path, member)) => (path.trim_end(), Some(member.to_owned())),
        None => (value, None),
    };
    Some(Resource {
        kind,
        path: path.to_owned(),
        member,
    })
}

/// Which members of an archive Defender's answer names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attribution {
    /// For each member, in the order given, the threats Defender attached.
    pub by_member: Vec<Vec<String>>,
    /// Threats Defender attached to the archive as a whole, naming no member.
    pub whole: Vec<String>,
    /// Members Defender named that match nothing in the listing.
    pub unmatched: Vec<String>,
}

impl Attribution {
    /// Whether every flag Defender raised landed on a member that can be left
    /// out by itself. When not, nothing is offered for extraction.
    pub fn complete(&self) -> bool {
        self.whole.is_empty() && self.unmatched.is_empty()
    }
}

/// A member's name, reduced to what Defender's printed form can be compared
/// on: one kind of separator, no leading one, ASCII case folded, and every
/// character outside ASCII replaced by `?`, because the console's code page
/// cannot be trusted to have kept it.
fn comparable_member(name: &str) -> String {
    name.replace('\\', "/")
        .trim_start_matches('/')
        .chars()
        .map(|c| {
            if c.is_ascii() {
                c.to_ascii_lowercase()
            } else {
                '?'
            }
        })
        .collect()
}

/// Match what Defender flagged against an archive's own list of members.
///
/// A member is flagged when Defender named it exactly, or named something
/// inside it (`inner.zip->tools/x.com` flags `inner.zip`, which is then left
/// out whole). Matching is deliberately loose in one direction: characters the
/// console may have mangled match each other, so an ambiguous name can flag
/// two members, and never flags none.
///
/// The other direction fails closed. A flagged name that matches no member,
/// or a threat on the archive with no member named, goes into `unmatched` or
/// `whole`, and [`Attribution::complete`] is then false.
pub fn attribute(threats: &[Flagged], members: &[&str]) -> Attribution {
    let comparable: Vec<String> = members.iter().map(|name| comparable_member(name)).collect();
    let mut attribution = Attribution {
        by_member: vec![Vec::new(); members.len()],
        ..Attribution::default()
    };

    for threat in threats {
        let mut named_a_file = false;
        for resource in threat
            .resources
            .iter()
            .filter_map(|text| parse_resource(text))
        {
            if resource.kind != ResourceKind::File {
                continue;
            }
            named_a_file = true;
            let Some(member) = resource.member else {
                // The archive itself, not anything in it.
                if !attribution.whole.contains(&threat.name) {
                    attribution.whole.push(threat.name.clone());
                }
                continue;
            };
            let flagged = comparable_member(&member);
            let mut matched = false;
            for (index, candidate) in comparable.iter().enumerate() {
                if candidate.is_empty() {
                    continue;
                }
                let exact = flagged == *candidate;
                let inside = flagged.starts_with(&format!("{candidate}->"));
                if exact || inside {
                    matched = true;
                    if !attribution.by_member[index].contains(&threat.name) {
                        attribution.by_member[index].push(threat.name.clone());
                    }
                }
            }
            if !matched {
                attribution.unmatched.push(member);
            }
        }
        // A threat that named only the container, or nothing at all, is a
        // threat on the archive.
        if !named_a_file && !attribution.whole.contains(&threat.name) {
            attribution.whole.push(threat.name.clone());
        }
    }
    attribution
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const ZIP: &str = r"C:\Users\someone\Downloads\kam-eicar-test.zip";

    /// What `MpCmdRun` printed for the EICAR test archive on 12 Oct 2026, with
    /// the path changed. Line for line otherwise, including its own spacing.
    fn eicar_output(zip: &str) -> String {
        format!(
            "Scan starting...\r\nScan finished.\r\nScanning {zip} found 1 threats.\r\n\r\n\
             <===========================LIST OF DETECTED THREATS==========================>\r\n\
             ----------------------------- Threat information ------------------------------\r\n\
             Threat                  : Virus:DOS/EICAR_Test_File\r\n\
             Resources               : 2 total\r\n\
             \x20   file                : {zip}->tools/eicar.com\r\n\
             \x20   containerfile       : {zip}\r\n\
             -------------------------------------------------------------------------------\r\n"
        )
    }

    // --- resources ------------------------------------------------------

    #[test]
    fn the_eicar_resources_read_the_same_in_every_form_defender_writes() {
        for text in [
            format!("file : {ZIP}->tools/eicar.com"),
            format!("    file                : {ZIP}->tools/eicar.com"),
            format!("file:_{ZIP}->tools/eicar.com"),
            format!("file:{ZIP}->tools/eicar.com"),
        ] {
            let resource = parse_resource(&text).unwrap_or_else(|| panic!("{text} did not parse"));
            assert_eq!(resource.kind, ResourceKind::File, "{text}");
            assert_eq!(resource.path, ZIP, "{text}");
            assert_eq!(
                resource.member.as_deref(),
                Some("tools/eicar.com"),
                "{text}"
            );
        }
        for text in [
            format!("containerfile : {ZIP}"),
            format!("containerfile:_{ZIP}"),
        ] {
            let resource = parse_resource(&text).unwrap();
            assert_eq!(resource.kind, ResourceKind::Container, "{text}");
            assert_eq!(resource.path, ZIP);
            assert_eq!(resource.member, None);
        }
    }

    #[test]
    fn a_member_of_an_archive_inside_the_archive_keeps_its_whole_chain() {
        let resource = parse_resource(&format!("file:_{ZIP}->inner.zip->tools/eicar.com")).unwrap();
        assert_eq!(resource.path, ZIP);
        assert_eq!(
            resource.member.as_deref(),
            Some("inner.zip->tools/eicar.com")
        );
    }

    #[test]
    fn a_bare_path_is_a_file_and_other_kinds_are_kept_apart() {
        let bare = parse_resource(r"C:\Users\someone\Downloads\setup.exe").unwrap();
        assert_eq!(bare.kind, ResourceKind::File);
        assert_eq!(bare.path, r"C:\Users\someone\Downloads\setup.exe");
        let key = parse_resource(r"regkey:_HKLM\Software\Thing").unwrap();
        assert_eq!(key.kind, ResourceKind::Other("regkey".to_owned()));
        assert!(parse_resource("   ").is_none());
        assert!(parse_resource("file:_").is_none());
    }

    // --- the whole report -----------------------------------------------

    #[test]
    fn the_eicar_report_is_read_as_flagged_with_its_member() {
        let scan = parse_report(Some(2), &eicar_output(ZIP));
        assert_eq!(scan.answer, Answer::Flagged);
        assert!(scan.completed);
        assert!(scan.listing_consistent, "{scan:?}");
        assert_eq!(scan.threats.len(), 1);
        assert_eq!(scan.threats[0].name, "Virus:DOS/EICAR_Test_File");
        assert_eq!(scan.threats[0].resources.len(), 2);
        assert_eq!(
            scan.sentence(),
            "Defender flagged Virus:DOS/EICAR_Test_File"
        );
    }

    #[test]
    fn nothing_found_is_exit_code_zero_and_nothing_else() {
        let output =
            format!("Scan starting...\r\nScan finished.\r\nScanning {ZIP} found no threats.\r\n");
        let scan = parse_report(Some(0), &output);
        assert_eq!(scan.answer, Answer::NothingFound);
        assert!(scan.completed && scan.caveat.is_none());
    }

    /// Exit code 2 is also what `MpCmdRun` uses when it cannot scan at all,
    /// measured against a file that was not there. That must never read as a
    /// clean result, or as a detection.
    #[test]
    fn a_failed_scan_is_not_finished_rather_than_clean_or_flagged() {
        let missing = r"CmdTool: Failed with hr = 0x80070002. Check C:\Users\someone\AppData\Local\Temp\MpCmdRun.log for more information";
        let scan = parse_report(Some(2), missing);
        assert_eq!(scan.answer, Answer::NotFinished);
        assert!(!scan.completed);
        assert!(scan
            .caveat
            .as_deref()
            .unwrap_or_default()
            .contains("0x80070002"));

        for (code, output) in [
            (Some(2), String::new()),
            (Some(2), format!("Scanning {ZIP} found no threats.\r\n")),
            (Some(5), String::new()),
            (None, eicar_output(ZIP)),
        ] {
            let scan = parse_report(code, &output);
            assert_eq!(scan.answer, Answer::NotFinished, "{code:?} {output:?}");
            assert!(scan.caveat.is_some());
        }
    }

    /// A member's name can carry a newline and print lines of its own. It
    /// cannot change the exit code or Defender's counts, so extra lines show up
    /// as a listing that does not add up.
    #[test]
    fn a_name_that_writes_its_own_lines_makes_the_listing_inconsistent() {
        let forged = format!(
            "Scanning {ZIP} found 1 threats.\r\n\
             Threat                  : Virus:DOS/EICAR_Test_File\r\n\
             Resources               : 2 total\r\n\
             \x20   file                : {ZIP}->a.txt\r\n\
             \x20   file                : {ZIP}->b.txt\r\n\
             \x20   containerfile       : {ZIP}\r\n"
        );
        let scan = parse_report(Some(2), &forged);
        assert_eq!(scan.answer, Answer::Flagged, "the flag itself stands");
        assert!(!scan.listing_consistent);
        assert!(scan.caveat.is_some());

        let extra_threat = format!(
            "{}Threat                  : Harmless:Nothing\r\nResources               : 0 total\r\n",
            eicar_output(ZIP)
        );
        assert!(!parse_report(Some(2), &extra_threat).listing_consistent);
    }

    #[test]
    fn the_count_is_read_from_the_end_of_the_summary_line() {
        assert_eq!(
            summary_count(r"Scanning C:\x found 3 threats\a.zip found 1 threats."),
            Some(1)
        );
        assert_eq!(
            summary_count(r"Scanning C:\a.zip found no threats."),
            Some(0)
        );
        assert_eq!(summary_count("Scanning nothing"), None);
    }

    // --- which members ---------------------------------------------------

    #[test]
    fn the_eicar_member_is_flagged_and_its_neighbour_is_not() {
        let scan = parse_report(Some(2), &eicar_output(ZIP));
        let members = ["readme.txt", "tools/", "tools/eicar.com"];
        let attribution = attribute(&scan.threats, &members);
        assert!(attribution.complete(), "{attribution:?}");
        assert!(attribution.by_member[0].is_empty());
        assert!(
            attribution.by_member[1].is_empty(),
            "a folder entry is not the file in it"
        );
        assert_eq!(
            attribution.by_member[2],
            vec!["Virus:DOS/EICAR_Test_File".to_owned()]
        );
    }

    /// Measured the same day: an archive holding that archive printed
    /// `outer.zip->inner.zip->tools/eicar.com`. The whole inner archive is
    /// what gets left out.
    #[test]
    fn a_flagged_file_inside_an_inner_archive_flags_the_inner_archive_whole() {
        let threats = [Flagged {
            name: "Virus:DOS/EICAR_Test_File".to_owned(),
            resources: vec![
                format!("file                : {ZIP}->inner.zip->tools/eicar.com"),
                format!("containerfile       : {ZIP}"),
            ],
        }];
        let attribution = attribute(&threats, &["inner.zip", "notes.txt", "inner.zip.txt"]);
        assert!(attribution.complete());
        assert_eq!(attribution.by_member[0].len(), 1);
        assert!(attribution.by_member[1].is_empty());
        assert!(
            attribution.by_member[2].is_empty(),
            "a name that only begins the same is another file"
        );
    }

    #[test]
    fn a_member_name_containing_an_arrow_is_still_matched() {
        let threats = [Flagged {
            name: "Trojan:Win32/Example".to_owned(),
            resources: vec![format!("file:_{ZIP}->a->b.exe")],
        }];
        let attribution = attribute(&threats, &["a->b.exe", "a"]);
        assert!(attribution.complete());
        assert_eq!(
            attribution.by_member[0].len(),
            1,
            "the member really called a->b.exe"
        );
        assert_eq!(
            attribution.by_member[1].len(),
            1,
            "and, to be safe, anything it could be inside"
        );
    }

    /// The console's code page replaces what it cannot show with `?`. Both
    /// sides are compared that way, so the member is still found.
    #[test]
    fn a_name_the_console_mangled_still_finds_its_member() {
        let threats = [Flagged {
            name: "Virus:DOS/EICAR_Test_File".to_owned(),
            resources: vec![format!("file : {ZIP}->pr?be-é?.com")],
        }];
        let attribution = attribute(&threats, &["prøbe-é中.com", "probe.com"]);
        assert!(attribution.complete(), "{attribution:?}");
        assert_eq!(attribution.by_member[0].len(), 1);
        assert!(attribution.by_member[1].is_empty());
    }

    #[test]
    fn a_flag_that_lands_on_no_member_or_on_the_archive_fails_closed() {
        let nowhere = [Flagged {
            name: "Virus:DOS/EICAR_Test_File".to_owned(),
            resources: vec![format!("file : {ZIP}->not/in/the/listing.exe")],
        }];
        let attribution = attribute(&nowhere, &["readme.txt"]);
        assert!(!attribution.complete());
        assert_eq!(
            attribution.unmatched,
            vec!["not/in/the/listing.exe".to_owned()]
        );

        let whole = [Flagged {
            name: "Exploit:Win32/ZipBomb".to_owned(),
            resources: vec![format!("file:_{ZIP}")],
        }];
        let attribution = attribute(&whole, &["readme.txt"]);
        assert!(!attribution.complete());
        assert_eq!(attribution.whole, vec!["Exploit:Win32/ZipBomb".to_owned()]);

        let container_only = [Flagged {
            name: "Virus:DOS/EICAR_Test_File".to_owned(),
            resources: vec![format!("containerfile:_{ZIP}")],
        }];
        assert!(!attribute(&container_only, &["readme.txt"]).complete());
    }

    #[test]
    fn ansi_output_is_decoded_and_utf16_is_recognised() {
        assert_eq!(
            decode_console(b"Scanning C:\\a.zip found no threats."),
            "Scanning C:\\a.zip found no threats."
        );
        let wide: Vec<u8> = "Scan finished."
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(decode_console(&wide), "Scan finished.");
        assert_eq!(decode_console(&[]), "");
    }

    /// Defender really answers, report-only, about a harmless file. Nothing is
    /// flagged and nothing is changed; the file is still there afterwards.
    #[test]
    fn defender_answers_about_a_harmless_file_and_leaves_it_alone() {
        let scratch =
            std::env::temp_dir().join(format!("kam-defender-file-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let file = scratch.join("harmless.txt");
        std::fs::write(&file, b"nothing to see here").unwrap();

        let scan = check_file(&file.to_string_lossy(), &AtomicBool::new(false)).unwrap();
        assert_eq!(scan.answer, Answer::NothingFound, "{scan:?}");
        assert!(file.exists(), "a report-only check removed the file");

        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn a_target_that_is_not_a_plain_path_is_refused_before_defender_runs() {
        for hostile in ["-Scan", "", "relative.txt"] {
            assert!(
                check_file(hostile, &AtomicBool::new(false)).is_err(),
                "{hostile:?}"
            );
        }
    }

    /// The real thing, end to end, against a copy of the EICAR test archive.
    ///
    /// Ignored because it needs that archive, which is not kept in the
    /// repository: antivirus on a contributor's machine or a CI runner would
    /// rightly quarantine it. Run it with `KAM_EICAR_ZIP` naming a copy, and
    /// `--ignored`. The copy is left where it was; Defender only reports.
    #[test]
    #[ignore = "needs a copy of the EICAR test archive named by KAM_EICAR_ZIP"]
    fn the_eicar_archive_is_flagged_member_by_member_and_left_in_place() {
        let Ok(path) = std::env::var("KAM_EICAR_ZIP") else {
            panic!("set KAM_EICAR_ZIP to a copy of the EICAR test archive");
        };
        let scan = check_file(&path, &AtomicBool::new(false)).unwrap();
        println!("{scan:#?}");
        assert_eq!(scan.answer, Answer::Flagged);
        assert!(scan.listing_consistent);
        let attribution = attribute(&scan.threats, &["readme.txt", "tools/eicar.com"]);
        assert!(attribution.complete(), "{attribution:?}");
        assert!(attribution.by_member[0].is_empty());
        assert_eq!(
            attribution.by_member[1],
            vec!["Virus:DOS/EICAR_Test_File".to_owned()]
        );
        assert!(
            Path::new(&path).exists(),
            "a report-only check moved the archive"
        );
    }
}
