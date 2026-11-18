//! Checking a download as it arrives, and what an archive turned out to hold.
//!
//! # What a check is
//!
//! Size, a SHA-256 fingerprint, where the file came from (its
//! `Zone.Identifier` stream), who signed it when it is a program, and
//! Defender's answer to a report-only scan of it. Nothing here judges the file:
//! Defender decides what is flagged, and every other fact is evidence shown
//! beside that answer, never added up into a score.
//!
//! # What taking an archive apart is
//!
//! Defender looks inside a zip and names each member it flags. [`dissect`]
//! lines those names up against the archive's own list, and says for every
//! member whether Defender flagged it, found nothing, or why it is left out
//! regardless. Reading the archive and writing anything out happen in the
//! window, as the person; this is the part both sides need to agree on.

use std::io::Read;
use std::path::Path;

use kam_core::Reporter;
use kam_storage::provenance::Origin;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::defender_file::{attribute, Answer, FileScan};
use crate::signature::Signature;

/// Everything one check found out about one file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadCheck {
    /// Where the file really is, after links and short names.
    pub path: String,
    pub name: String,
    pub bytes: u64,
    /// Lower-case hex.
    pub sha256: String,
    /// When the file was created where it is, which for a download is when it
    /// arrived.
    pub arrived_at: Option<String>,
    /// From the file's own `Zone.Identifier`. Absent means nothing was
    /// recorded, not that it is local.
    pub origin: Option<Origin>,
    /// Read for programs and installers only.
    pub signature: Option<Signature>,
    pub scan: FileScan,
}

/// Something done to a download, as the agent wrote it down.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadAction {
    pub at: String,
    /// A sentence written by the agent, never by the window.
    pub what: String,
    /// The quarantine id, when the action can be undone from quarantine.
    #[serde(default)]
    pub undo: Option<String>,
}

/// One row of the download history, as it travels to the window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadRecord {
    #[serde(flatten)]
    pub check: DownloadCheck,
    pub checked_at: String,
    #[serde(default)]
    pub actions: Vec<DownloadAction>,
    #[serde(default)]
    pub dissection: Option<Dissection>,
    /// Set only in the reply to a check: true the first time this file, with
    /// this content, was recorded for this person. A notice is sent then and
    /// not on a second look.
    #[serde(default)]
    pub first_check: bool,
}

/// Why a check did not produce an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckError {
    /// Somebody asked it to stop.
    Stopped,
    /// It could not be done, in a sentence for the person.
    Failed(String),
}

/// How much of a file is read at a time for its fingerprint.
const CHUNK: usize = 1024 * 1024;

/// Check one file. See the module notes for what that means.
///
/// `path` must already be one the caller may have checked; this resolves it
/// again and refuses anything that is not a plain file on a lettered drive.
pub fn check(path: &str, reporter: &Reporter) -> Result<DownloadCheck, CheckError> {
    let real = std::fs::canonicalize(path).map_err(|error| {
        CheckError::Failed(format!(
            "{path} could not be found ({error}), so it was not checked"
        ))
    })?;
    let real = plain_drive_path(&real).ok_or_else(|| {
        CheckError::Failed(format!(
            "{path} is not on a lettered drive, so it was not checked"
        ))
    })?;
    if real.chars().any(char::is_control) {
        return Err(CheckError::Failed(format!(
            "{} has a control character in its name, so it was not checked",
            real.escape_debug()
        )));
    }
    let metadata = std::fs::metadata(&real)
        .map_err(|error| CheckError::Failed(format!("{real} could not be read: {error}")))?;
    if !metadata.is_file() {
        return Err(CheckError::Failed(format!("{real} is not a file")));
    }
    let name = Path::new(&real)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| real.clone());
    let bytes = metadata.len();
    let arrived_at = metadata.created().ok().and_then(|created| {
        created
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|since| kam_core::clock::iso_from_unix_millis(since.as_millis() as u64))
    });

    let sha256 = fingerprint(&real, bytes, reporter)?;

    let origin = kam_storage::provenance::origin_of(&real);
    let signature = kam_storage::downloads::is_program(&name).then(|| {
        reporter.stage("Reading who signed it", None);
        crate::signature::of(Path::new(&real))
    });

    reporter.stage("Asking Microsoft Defender", None);
    let scan = crate::defender_file::check_file(&real, &reporter.cancel_token())
        .map_err(|error| CheckError::Failed(plain_error(&error)))?;
    if reporter.is_cancelled() {
        return Err(CheckError::Stopped);
    }

    Ok(DownloadCheck {
        path: real,
        name,
        bytes,
        sha256,
        arrived_at,
        origin,
        signature,
        scan,
    })
}

/// A `kam_core` error without its category prefix, which is for logs.
fn plain_error(error: &kam_core::Error) -> String {
    match error {
        kam_core::Error::Refused(message) | kam_core::Error::Privileged(message) => message.clone(),
        other => other.to_string(),
    }
}

/// `C:\...` from `\\?\C:\...`; `None` for anything that is not a drive path.
fn plain_drive_path(path: &Path) -> Option<String> {
    let text = path.to_string_lossy();
    let text = text.strip_prefix(r"\\?\").unwrap_or(&text);
    let bytes = text.as_bytes();
    let drive =
        bytes.len() > 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';
    drive.then(|| text.to_owned())
}

/// The file's SHA-256, read a megabyte at a time so a large download shows
/// its progress and can be stopped.
fn fingerprint(path: &str, bytes: u64, reporter: &Reporter) -> Result<String, CheckError> {
    let megabytes = bytes.div_ceil(1024 * 1024);
    reporter.stage(
        "Reading it to take its fingerprint (MB)",
        (megabytes > 1).then_some(megabytes),
    );
    let mut file = std::fs::File::open(path).map_err(|error| {
        CheckError::Failed(format!("{path} could not be opened to read it: {error}"))
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; CHUNK];
    loop {
        if reporter.is_cancelled() {
            return Err(CheckError::Stopped);
        }
        let read = file.read(&mut buffer).map_err(|error| {
            CheckError::Failed(format!("{path} could not be read to the end: {error}"))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        reporter.advance(1);
    }
    Ok(hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// One member of an archive, as the archive itself lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub bytes: u64,
    pub packed: u64,
    pub is_dir: bool,
    /// Password-protected: Defender cannot look inside it.
    pub encrypted: bool,
    /// Stored as a link rather than a file.
    pub link: bool,
    /// Compressed with a method this cannot unpack, named.
    pub unsupported: Option<String>,
}

/// What became of one member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum MemberStatus {
    /// Defender looked and found nothing. Offered for extraction.
    NothingFound,
    /// Defender flagged it, by these names. Never extracted.
    Flagged { threats: Vec<String> },
    /// Not extracted, whatever Defender said, for this reason.
    LeftOut { reason: String },
    /// A folder entry: created as needed, never counted as a file.
    Folder,
}

/// One member and what became of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub name: String,
    pub bytes: u64,
    pub packed: u64,
    pub status: MemberStatus,
}

/// Counts and sizes, so the page can say "3 of 47 files left out, 2.1 MB of
/// 380 MB" rather than anything that sounds like a grade.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totals {
    pub files: u64,
    pub bytes: u64,
    pub flagged: u64,
    pub flagged_bytes: u64,
    pub left_out: u64,
    pub left_out_bytes: u64,
    pub clean: u64,
    pub clean_bytes: u64,
}

/// What happened to the original archive before it was taken apart.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OriginalFate {
    /// The quarantine id, when it was quarantined.
    pub quarantined: Option<String>,
    /// Why it could not be, in a sentence, when that was tried and failed.
    pub refused: Option<String>,
}

/// An archive taken apart: every member with Defender's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dissection {
    /// The original's path, which the history row is keyed on.
    pub archive: String,
    pub sha256: String,
    /// Defender's answer about the private working copy that was examined.
    pub scan: FileScan,
    pub members: Vec<Member>,
    /// Members left off `members` when it was recorded, so a record of a vast
    /// archive stays a reasonable size. The totals still count every one.
    #[serde(default)]
    pub members_omitted: u64,
    pub totals: Totals,
    /// Threats Defender put on the archive as a whole.
    #[serde(default)]
    pub whole_archive: Vec<String>,
    /// Members Defender named that the archive's own list does not have.
    #[serde(default)]
    pub unmatched: Vec<String>,
    /// Whether the members Defender found nothing in may be extracted.
    pub offered: bool,
    /// Why not, when they may not, in a sentence.
    #[serde(default)]
    pub not_offered: Option<String>,
    #[serde(default)]
    pub original: OriginalFate,
}

/// What a person agreed to extract, and what came of it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extraction {
    /// The new folder everything went into.
    pub destination: String,
    pub files: u64,
    pub bytes: u64,
    pub left_out: u64,
    pub left_out_bytes: u64,
    /// Members that were offered and could not be written, with why.
    #[serde(default)]
    pub failed: Vec<String>,
    /// Members that were written and then were not there, or not whole, when
    /// looked at again: Defender's real-time protection removing them as they
    /// landed. Never counted in `files`.
    #[serde(default)]
    pub removed: Vec<RemovedFile>,
}

/// A file that was written and then taken away as it landed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemovedFile {
    /// The member's name in the archive.
    pub name: String,
    /// The detection that names it, when Defender's history has one.
    pub threat: Option<String>,
    /// What that detection's name means. This is the case that matters most
    /// in practice: an open-source tool Defender classes as a hacking tool,
    /// deleted as it is written, where keeping it is the person's decision.
    #[serde(default)]
    pub note: Option<crate::defender_file::ThreatNote>,
}

impl RemovedFile {
    /// A removed file, with the note for the detection that names it.
    pub fn new(name: String, threat: Option<String>) -> Self {
        let note = threat.as_deref().map(crate::defender_file::note_for);
        Self { name, threat, note }
    }
}

/// Line Defender's answer up against the archive's own list of members.
///
/// The rules, each one fail-closed:
///
/// - A member Defender flagged is never extracted, and a member inside an
///   archive inside this one flags that inner archive whole.
/// - When the name Defender printed fits more than one member, none of them
///   is extracted: which it meant cannot be told.
/// - A member is left out for its name (see
///   [`kam_storage::downloads::safe_relative`]), for being a link, for being
///   password-protected (Defender could not look inside, which is not the same
///   as finding nothing) or for a compression method this cannot unpack.
/// - Nothing at all is offered when Defender did not finish, when its listing
///   did not add up, or when it flagged something that cannot be pinned to one
///   member.
pub fn dissect(archive: &str, sha256: &str, scan: FileScan, entries: &[Entry]) -> Dissection {
    let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
    let attribution = attribute(&scan.threats, &names);

    // When Defender's answer cannot be pinned to members, nothing is known
    // about a member just because it was not named, so none is shown as one
    // Defender found nothing in. The first sentence is for the archive, the
    // second for each member. None of them calls a file clean: that would be
    // this product's verdict, and it does not give one.
    let untrusted: Option<(String, &str)> = if scan.answer == Answer::NotFinished {
        Some((
            "Defender did not finish checking the archive, so nothing in it is offered for \
             extraction."
                .to_owned(),
            "Defender did not finish checking the archive, so nothing is known about this file \
             either way.",
        ))
    } else if scan.answer == Answer::Flagged && !scan.listing_consistent {
        Some((
            "Defender flagged something in this archive, and its list of what did not add up, \
             so nothing in it is offered for extraction."
                .to_owned(),
            "Defender's list of what it flagged did not add up, so nothing is known about this \
             file either way.",
        ))
    } else if !attribution.whole.is_empty() {
        Some((
            "Defender flagged the archive as a whole, not a file inside it, so no part of it \
             can be told apart from the rest."
                .to_owned(),
            "Defender flagged the archive as a whole, so nothing is known about this file \
             either way.",
        ))
    } else if !attribution.unmatched.is_empty() {
        Some((
            "Defender flagged a file this archive's own list does not show by that name, so \
             which file it meant cannot be told and nothing is offered for extraction."
                .to_owned(),
            "Defender flagged a file it could not be matched to, so nothing is known about this \
             file either way.",
        ))
    } else {
        None
    };

    let mut totals = Totals::default();
    let members: Vec<Member> = entries
        .iter()
        .zip(attribution.by_member.iter().zip(&attribution.either))
        .map(|(entry, (threats, either))| {
            let status = if entry.is_dir && threats.is_empty() && either.is_empty() {
                MemberStatus::Folder
            } else if !threats.is_empty() {
                MemberStatus::Flagged {
                    threats: threats.clone(),
                }
            } else if !either.is_empty() {
                // Said as what it is. Calling it flagged would put Defender's
                // name on a file Defender may not have meant.
                MemberStatus::LeftOut {
                    reason: format!(
                        "Defender flagged a file as {} under a name that fits this file and at \
                         least one other in the archive, so which it meant cannot be told and \
                         none of them is extracted.",
                        either.join(", ")
                    ),
                }
            } else if let Err(refusal) = kam_storage::downloads::safe_relative(&entry.name) {
                MemberStatus::LeftOut {
                    reason: refusal.sentence(),
                }
            } else if entry.link {
                MemberStatus::LeftOut {
                    reason: "It is a link, and links are never created.".to_owned(),
                }
            } else if entry.encrypted {
                MemberStatus::LeftOut {
                    reason: "It is password-protected, so Defender could not look inside it."
                        .to_owned(),
                }
            } else if let Some(method) = &entry.unsupported {
                MemberStatus::LeftOut {
                    reason: format!("It is compressed with {method}, which this cannot unpack."),
                }
            } else if let Some((_, reason)) = &untrusted {
                MemberStatus::LeftOut {
                    reason: (*reason).to_owned(),
                }
            } else {
                MemberStatus::NothingFound
            };

            if status != MemberStatus::Folder {
                totals.files += 1;
                totals.bytes += entry.bytes;
                match &status {
                    MemberStatus::Flagged { .. } => {
                        totals.flagged += 1;
                        totals.flagged_bytes += entry.bytes;
                    }
                    MemberStatus::LeftOut { .. } => {
                        totals.left_out += 1;
                        totals.left_out_bytes += entry.bytes;
                    }
                    MemberStatus::NothingFound => {
                        totals.clean += 1;
                        totals.clean_bytes += entry.bytes;
                    }
                    MemberStatus::Folder => {}
                }
            }
            Member {
                name: entry.name.clone(),
                bytes: entry.bytes,
                packed: entry.packed,
                status,
            }
        })
        .collect();

    let not_offered = if let Some((sentence, _)) = untrusted {
        Some(sentence)
    } else if totals.clean == 0 {
        Some(
            "Every file in this archive was flagged or left out, so there is nothing to extract."
                .to_owned(),
        )
    } else {
        None
    };

    Dissection {
        archive: archive.to_owned(),
        sha256: sha256.to_owned(),
        scan,
        members,
        members_omitted: 0,
        totals,
        whole_archive: attribution.whole,
        unmatched: attribution.unmatched,
        offered: not_offered.is_none(),
        not_offered,
        original: OriginalFate::default(),
    }
}

impl Dissection {
    /// A copy small enough to record: every flagged and left-out member, and
    /// the first of the rest up to `keep` in all. The totals are untouched.
    pub fn for_record(&self, keep: usize) -> Self {
        let mut copy = self.clone();
        if copy.members.len() <= keep {
            return copy;
        }
        let (notable, clean): (Vec<Member>, Vec<Member>) =
            copy.members.into_iter().partition(|member| {
                matches!(
                    member.status,
                    MemberStatus::Flagged { .. } | MemberStatus::LeftOut { .. }
                )
            });
        let mut kept: Vec<Member> = notable.into_iter().take(keep).collect();
        let room = keep.saturating_sub(kept.len());
        kept.extend(clean.into_iter().take(room));
        copy.members_omitted = (self.members.len() - kept.len()) as u64;
        copy.members = kept;
        copy
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::defender_file::{parse_report, Flagged};

    fn entry(name: &str, bytes: u64) -> Entry {
        Entry {
            name: name.to_owned(),
            bytes,
            packed: bytes / 2,
            is_dir: name.ends_with('/'),
            encrypted: false,
            link: false,
            unsupported: None,
        }
    }

    fn flagged(resources: &[&str]) -> FileScan {
        FileScan {
            answer: Answer::Flagged,
            completed: true,
            exit_code: Some(2),
            seconds: 1,
            threats: vec![Flagged {
                name: "Virus:DOS/EICAR_Test_File".to_owned(),
                resources: resources.iter().map(|text| (*text).to_owned()).collect(),
            }],
            listing_consistent: true,
            caveat: None,
            definitions: None,
            notes: Vec::new(),
        }
    }

    fn clean() -> FileScan {
        parse_report(Some(0), "Scanning C:\\w.zip found no threats.")
    }

    #[test]
    fn the_eicar_archive_comes_apart_into_one_flagged_file_and_one_clean_one() {
        let scan = flagged(&[
            r"file : C:\w.zip->tools/eicar.com",
            r"containerfile : C:\w.zip",
        ]);
        let entries = [
            entry("readme.txt", 120),
            entry("tools/", 0),
            entry("tools/eicar.com", 68),
        ];
        let dissection = dissect(r"C:\Users\me\Downloads\x.zip", "ab", scan, &entries);

        assert!(dissection.offered, "{dissection:?}");
        assert_eq!(dissection.members[0].status, MemberStatus::NothingFound);
        assert_eq!(dissection.members[1].status, MemberStatus::Folder);
        assert!(matches!(
            dissection.members[2].status,
            MemberStatus::Flagged { .. }
        ));
        assert_eq!(
            dissection.totals,
            Totals {
                files: 2,
                bytes: 188,
                flagged: 1,
                flagged_bytes: 68,
                left_out: 0,
                left_out_bytes: 0,
                clean: 1,
                clean_bytes: 120,
            }
        );
    }

    #[test]
    fn a_member_defender_could_not_read_or_should_not_be_written_is_left_out() {
        let mut locked = entry("secret.docx", 10);
        locked.encrypted = true;
        let mut link = entry("shortcut", 10);
        link.link = true;
        let mut odd = entry("old.bin", 10);
        odd.unsupported = Some("Implode".to_owned());
        let entries = [
            entry("../../evil.exe", 10),
            entry("C:/Windows/evil.dll", 10),
            locked,
            link,
            odd,
            entry("fine.txt", 10),
        ];
        let dissection = dissect(r"C:\D\x.zip", "ab", clean(), &entries);
        for member in &dissection.members[..5] {
            assert!(
                matches!(member.status, MemberStatus::LeftOut { .. }),
                "{} was not left out: {:?}",
                member.name,
                member.status
            );
        }
        assert_eq!(dissection.members[5].status, MemberStatus::NothingFound);
        assert!(dissection.offered);
        assert_eq!(dissection.totals.left_out, 5);
        assert_eq!(dissection.totals.clean, 1);
    }

    #[test]
    fn nothing_is_offered_when_the_answer_cannot_be_pinned_to_members() {
        let entries = [entry("readme.txt", 1)];

        let unfinished = parse_report(Some(2), "CmdTool: Failed with hr = 0x80070005.");
        assert!(!dissect("a", "b", unfinished, &entries).offered);

        let mut inconsistent = flagged(&[r"file : C:\w.zip->readme.txt"]);
        inconsistent.listing_consistent = false;
        assert!(!dissect("a", "b", inconsistent, &entries).offered);

        let elsewhere = flagged(&[r"file : C:\w.zip->not-listed.exe"]);
        let dissection = dissect("a", "b", elsewhere, &entries);
        assert!(!dissection.offered);
        assert_eq!(dissection.unmatched, vec!["not-listed.exe".to_owned()]);

        let whole = flagged(&[r"file:_C:\w.zip"]);
        assert!(!dissect("a", "b", whole, &entries).offered);
    }

    /// Every sentence this writes about an archive and its members says what
    /// Defender did or did not do. None calls a file clean, which would be
    /// this product's own verdict.
    #[test]
    fn no_sentence_about_an_archive_calls_a_file_clean() {
        let entries = [entry("readme.txt", 1), entry("tool.exe", 2)];
        let mut inconsistent = flagged(&[r"file : C:\w.zip->readme.txt"]);
        inconsistent.listing_consistent = false;
        let mut locked = entry("secret.docx", 3);
        locked.encrypted = true;
        let cases = [
            dissect(
                "a",
                "b",
                parse_report(Some(2), "CmdTool: Failed with hr = 0x80070005."),
                &entries,
            ),
            dissect("a", "b", inconsistent, &entries),
            dissect("a", "b", flagged(&[r"file:_C:\w.zip"]), &entries),
            dissect(
                "a",
                "b",
                flagged(&[r"file : C:\w.zip->not-listed.exe"]),
                &entries,
            ),
            dissect(
                "a",
                "b",
                flagged(&[r"file : C:\w.zip->readme.txt"]),
                &entries[..1],
            ),
            dissect("a", "b", clean(), &[locked]),
        ];
        for dissection in &cases {
            assert!(!dissection.offered, "{dissection:?}");
            let mut said = vec![dissection.not_offered.clone().unwrap_or_default()];
            for member in &dissection.members {
                if let MemberStatus::LeftOut { reason } = &member.status {
                    said.push(reason.clone());
                }
            }
            for sentence in said {
                assert!(
                    !sentence.to_lowercase().contains("clean"),
                    "this calls a file clean, or not clean: {sentence}"
                );
            }
        }
    }

    /// The real case from this machine's own history: an ML detection whose
    /// only resource is the zip itself. Nothing is known about a member just
    /// because none was named, so none is shown as one Defender found nothing
    /// in and none is offered.
    #[test]
    fn an_archive_flagged_as_a_whole_has_no_parts_to_tell_apart() {
        let mut scan = flagged(&[r"file:_C:\Users\me\Downloads\WindWakerHD.zip"]);
        scan.threats[0].name = "Trojan:Script/Wacatac.H!ml".to_owned();
        let entries = [entry("readme.txt", 10), entry("game.exe", 20)];
        let dissection = dissect(
            r"C:\Users\me\Downloads\WindWakerHD.zip",
            "ab",
            scan,
            &entries,
        );

        assert!(!dissection.offered);
        assert_eq!(
            dissection.not_offered.as_deref(),
            Some(
                "Defender flagged the archive as a whole, not a file inside it, so no part of \
                 it can be told apart from the rest."
            )
        );
        assert_eq!(
            dissection.whole_archive,
            vec!["Trojan:Script/Wacatac.H!ml".to_owned()]
        );
        assert_eq!(
            dissection.totals.clean, 0,
            "a file was shown as one Defender found nothing in: {:?}",
            dissection.members
        );
        assert_eq!(dissection.totals.left_out, 2);
        for member in &dissection.members {
            assert!(
                matches!(member.status, MemberStatus::LeftOut { .. }),
                "{member:?}"
            );
        }
    }

    /// Red review: a harmless member with the plain spelling took the flag,
    /// and the member Defender named, whose name ends in a no-break space,
    /// was shown as nothing found and offered for extraction.
    #[test]
    fn a_member_whose_name_only_looks_like_the_flagged_one_is_not_extracted_either() {
        let scan = flagged(&["file : C:\\w.zip->tool.exe\u{a0}"]);
        let entries = [
            entry("tool.exe", 10),
            entry("tool.exe\u{a0}", 20),
            entry("readme.txt", 5),
        ];
        let dissection = dissect(r"C:\D\x.zip", "ab", scan, &entries);
        for member in &dissection.members[..2] {
            let MemberStatus::LeftOut { reason } = &member.status else {
                panic!("{:?} could be extracted: {:?}", member.name, member.status);
            };
            assert!(reason.contains("which it meant cannot be told"), "{reason}");
        }
        assert_eq!(dissection.members[2].status, MemberStatus::NothingFound);
        assert!(dissection.offered, "the unrelated file is still offered");
        assert_eq!(dissection.totals.clean, 1);
        assert_eq!(dissection.totals.left_out, 2);
    }

    #[test]
    fn a_record_of_a_vast_archive_keeps_every_notable_member_and_every_total() {
        let mut entries: Vec<Entry> = (0..50).map(|n| entry(&format!("f{n}.txt"), 1)).collect();
        entries.push(entry("../evil.exe", 1));
        let dissection = dissect("a", "b", clean(), &entries);
        let small = dissection.for_record(10);
        assert_eq!(small.members.len(), 10);
        assert_eq!(small.members_omitted, 41);
        assert!(small
            .members
            .iter()
            .any(|member| member.name == "../evil.exe"));
        assert_eq!(small.totals, dissection.totals);
    }

    #[test]
    fn a_record_survives_the_wire_with_its_check_flattened() {
        let record = DownloadRecord {
            check: DownloadCheck {
                path: r"C:\Users\me\Downloads\x.zip".to_owned(),
                name: "x.zip".to_owned(),
                bytes: 10,
                sha256: "ab".to_owned(),
                arrived_at: None,
                origin: None,
                signature: Some(Signature::Unsigned),
                scan: clean(),
            },
            checked_at: "2026-10-12T00:00:00.000Z".to_owned(),
            actions: vec![DownloadAction {
                at: "2026-10-12T00:00:01.000Z".to_owned(),
                what: "quarantined".to_owned(),
                undo: Some("1-0001".to_owned()),
            }],
            dissection: None,
            first_check: true,
        };
        let json = serde_json::to_string(&record).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value["name"], "x.zip",
            "the check's fields sit at the top level"
        );
        assert_eq!(value["scan"]["answer"], "nothing_found");
        let back: DownloadRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn a_file_is_fingerprinted_and_checked() {
        let scratch =
            std::env::temp_dir().join(format!("kam-download-check-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let file = scratch.join("hello.txt");
        std::fs::write(&file, b"hello").unwrap();

        let checked = check(&file.to_string_lossy(), &Reporter::silent()).unwrap();
        assert_eq!(
            checked.sha256,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(checked.bytes, 5);
        assert_eq!(checked.name, "hello.txt");
        assert!(
            checked.signature.is_none(),
            "a text file has no signature to read"
        );
        // Whether Defender can finish depends on the machine; a harmless file
        // is never flagged either way.
        assert_ne!(checked.scan.answer, Answer::Flagged, "{:?}", checked.scan);
        assert!(!checked.path.starts_with(r"\\?\"));

        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn a_check_that_is_asked_to_stop_says_it_stopped() {
        let scratch =
            std::env::temp_dir().join(format!("kam-download-stop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let file = scratch.join("a.bin");
        std::fs::write(&file, vec![0_u8; 4096]).unwrap();

        let reporter = Reporter::silent();
        reporter.cancel();
        assert_eq!(
            check(&file.to_string_lossy(), &reporter),
            Err(CheckError::Stopped)
        );

        let _ = std::fs::remove_dir_all(&scratch);
    }
}
