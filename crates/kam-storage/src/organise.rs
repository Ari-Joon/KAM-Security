//! Loose files that belong somewhere you already keep that kind of file.
//!
//! A download lands in `Downloads` and stays there. Months later there are two
//! hundred of them, and the folder they belonged in — `Documents\Invoices`,
//! `Videos\Recordings` — has existed the whole time. This finds those pairings
//! by looking at what each folder already holds, and proposes them.
//!
//! Nothing is moved by this module. It produces suggestions with their
//! reasoning attached; moving is a separate, journalled, reversible act.
//!
//! # A contradiction in the plan, resolved toward caution
//!
//! PLAN.md listed "media, documents, archives, **installers**" as safe to move,
//! and in the next breath listed "**executables**" as never. Installers are
//! executables. The two rules cannot both hold, and installers are the single
//! most common thing cluttering a downloads folder, so the temptation is to
//! read the permissive one.
//!
//! Executables win. A `.exe` or `.msi` sitting in `Downloads` may be referenced
//! by a shortcut, a scheduled task, or an installer that expects to find its own
//! payload beside it, and none of that is visible from here. The cost of being
//! wrong about a PDF is a confused user; about an executable it is something
//! that silently stops working. So the allowlist below has no executable in it,
//! and the folder stays untidy.
//!
//! # The rest of the fence
//!
//! A file is only ever a candidate when it is a plain file, in a user folder,
//! with an allowed extension, and outside every place software lives. A
//! destination must be a real folder that already holds several files of the
//! same kind — this never invents a folder, because a folder the user did not
//! choose is not somewhere they will look.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::index::VolumeIndex;

/// Extensions considered inert: opening one runs nothing.
///
/// Deliberately a list rather than a rule. "Not executable" is not a property
/// of a file extension in general, and an allowlist fails closed.
const MOVABLE: &[&str] = &[
    // Documents
    "pdf", "doc", "docx", "odt", "rtf", "txt", "md", "csv", "xls", "xlsx", "ods", "ppt", "pptx",
    "odp", "epub", "mobi", // Images
    "jpg", "jpeg", "png", "gif", "bmp", "webp", "tif", "tiff", "svg", "heic", "raw", "cr2", "nef",
    // Audio and video
    "mp3", "flac", "wav", "aac", "ogg", "m4a", "mp4", "mkv", "mov", "avi", "webm", "wmv", "m4v",
    // Archives and images of media
    "zip", "7z", "rar", "tar", "gz", "bz2", "xz", "iso",
];

/// Places a loose file is worth noticing. Anywhere else is either somewhere the
/// user filed it deliberately or somewhere software lives.
const SOURCE_FOLDERS: &[&str] = &["Downloads", "Desktop"];

/// Never a source and never a destination, wherever they appear in a path.
const OFF_LIMITS: &[&str] = &[
    "appdata",
    "programdata",
    "program files",
    "program files (x86)",
    "windows",
    "$recycle.bin",
    "system volume information",
    "onedrivetemp",
    "node_modules",
    ".git",
    ".venv",
    "venv",
    "target",
    "__pycache__",
];

/// Smallest file worth proposing a home for.
const MIN_SIZE: u64 = 1024 * 1024;

/// A destination must already hold at least this many files of the same kind,
/// or it is not established enough to be "where those go".
const MIN_ESTABLISHED: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strength {
    /// The extension matches a folder that holds mostly that kind of file.
    Reasonable,
    /// That, and the names agree too.
    Strong,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub from: String,
    pub to: String,
    pub name: String,
    pub bytes: u64,
    pub strength: Strength,
    /// Why this destination, in the words the user should see.
    pub reason: String,
    /// The destination is inside a synced folder, so moving a file there
    /// uploads it. Not a reason to refuse — it is where the user keeps those
    /// files — but not something to do to someone's connection silently.
    #[serde(default)]
    pub destination_syncs: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganiseSummary {
    pub proposals: usize,
    pub bytes: u64,
    /// Loose files considered before matching.
    pub examined: usize,
}

fn extension_of(name: &str) -> Option<String> {
    let (_, extension) = name.rsplit_once('.')?;
    let extension = extension.to_lowercase();
    (!extension.is_empty() && extension.len() <= 5).then_some(extension)
}

fn is_movable(name: &str) -> bool {
    extension_of(name).is_some_and(|extension| MOVABLE.contains(&extension.as_str()))
}

/// Whether any component of a path is somewhere this must not touch.
fn is_off_limits(path: &str) -> bool {
    let lowered = path.to_lowercase();
    OFF_LIMITS
        .iter()
        .any(|forbidden| lowered.split(['\\', '/']).any(|part| part == *forbidden))
}

/// Whether a path lives inside a folder a sync client mirrors to the cloud.
fn is_synced(path: &str) -> bool {
    let lowered = path.to_lowercase();
    lowered
        .split(['\\', '/'])
        .any(|part| part.starts_with("onedrive") || part == "dropbox" || part == "google drive")
}

/// Reduce a name for comparison: lower case, letters and digits only.
fn normalise(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

/// A folder that already holds several files of one kind.
#[derive(Debug)]
struct Destination {
    path: String,
    name: String,
    /// Files of the dominant extension.
    matching: usize,
    /// Every file directly inside.
    total: usize,
}

/// Walk the user's folders looking for established homes.
fn destinations(index: &VolumeIndex, profile: &str) -> HashMap<String, Vec<Destination>> {
    let mut by_extension: HashMap<String, Vec<Destination>> = HashMap::new();

    let Some(profile_record) = index.resolve(profile) else {
        return by_extension;
    };

    // Breadth-first through the profile, bounded: a home five levels down is
    // not somewhere anyone is filing things by hand.
    let mut queue = vec![(profile_record, profile.to_owned(), 0_usize)];
    while let Some((record, path, depth)) = queue.pop() {
        if depth > 3 || is_off_limits(&path) {
            continue;
        }

        let mut counts: HashMap<String, usize> = HashMap::new();
        let mut total = 0_usize;
        for child in index.children_of(record) {
            let Some(entry) = index.entry(*child) else {
                continue;
            };
            if entry.is_directory {
                queue.push((*child, format!("{path}\\{}", entry.name), depth + 1));
                continue;
            }
            total += 1;
            if let Some(extension) = extension_of(&entry.name) {
                *counts.entry(extension).or_default() += 1;
            }
        }

        // The source folders are where the mess is, not where it goes.
        let name = path.rsplit(['\\', '/']).next().unwrap_or(&path).to_owned();
        if depth == 0
            || SOURCE_FOLDERS
                .iter()
                .any(|folder| name.eq_ignore_ascii_case(folder))
        {
            continue;
        }

        for (extension, matching) in counts {
            if matching >= MIN_ESTABLISHED {
                by_extension
                    .entry(extension)
                    .or_default()
                    .push(Destination {
                        path: path.clone(),
                        name: name.clone(),
                        matching,
                        total,
                    });
            }
        }
    }

    by_extension
}

/// Propose homes for loose files under the user's profile.
pub fn find(index: &VolumeIndex, profile: &str) -> (Vec<Proposal>, OrganiseSummary) {
    let homes = destinations(index, profile);
    let mut proposals = Vec::new();
    let mut examined = 0_usize;

    for folder in SOURCE_FOLDERS {
        let source = format!("{profile}\\{folder}");
        let Some(record) = index.resolve(&source) else {
            continue;
        };

        for child in index.children_of(record) {
            let Some(entry) = index.entry(*child) else {
                continue;
            };
            if entry.is_directory || entry.bytes < MIN_SIZE || !is_movable(&entry.name) {
                continue;
            }
            let from = format!("{source}\\{}", entry.name);
            if is_off_limits(&from) {
                continue;
            }
            examined += 1;

            let Some(extension) = extension_of(&entry.name) else {
                continue;
            };
            let Some(candidates) = homes.get(&extension) else {
                continue;
            };

            let stem = normalise(entry.name.rsplit_once('.').map_or(&*entry.name, |(s, _)| s));

            // Best destination: the one whose name the file echoes, else the
            // one most dominated by this kind of file.
            let mut best: Option<(&Destination, Strength, String)> = None;
            for destination in candidates {
                let folder_key = normalise(&destination.name);
                let named = folder_key.len() >= 4
                    && (stem.contains(&folder_key) || folder_key.contains(&stem));

                let share = destination.matching as f64 / destination.total.max(1) as f64;
                let strength = if named {
                    Strength::Strong
                } else if share >= 0.6 {
                    Strength::Reasonable
                } else {
                    continue;
                };

                let reason = if named {
                    format!(
                        "the name matches the folder, which already holds {} .{extension} files",
                        destination.matching
                    )
                } else {
                    format!(
                        "{} of the {} files in that folder are .{extension}",
                        destination.matching, destination.total
                    )
                };

                let better = match &best {
                    None => true,
                    Some((current, current_strength, _)) => {
                        strength > *current_strength
                            || (strength == *current_strength
                                && destination.matching > current.matching)
                    }
                };
                if better {
                    best = Some((destination, strength, reason));
                }
            }

            if let Some((destination, strength, reason)) = best {
                let to = format!("{}\\{}", destination.path, entry.name);
                proposals.push(Proposal {
                    destination_syncs: is_synced(&to),
                    to,
                    from,
                    name: entry.name.clone(),
                    bytes: entry.bytes,
                    strength,
                    reason,
                });
            }
        }
    }

    proposals.sort_by(|a, b| b.strength.cmp(&a.strength).then(b.bytes.cmp(&a.bytes)));

    let summary = OrganiseSummary {
        proposals: proposals.len(),
        bytes: proposals.iter().map(|proposal| proposal.bytes).sum(),
        examined,
    };
    (proposals, summary)
}

/// Read the volume's table, then look for loose files on it.
pub fn survey(drive_letter: char) -> kam_core::Result<(Vec<Proposal>, OrganiseSummary)> {
    let profile = std::env::var("USERPROFILE")
        .map_err(|_| kam_core::Error::Privileged("USERPROFILE is not set".to_owned()))?;
    let snapshot = crate::mft::read(drive_letter)?;
    let index = VolumeIndex::build(snapshot);
    Ok(find(&index, profile.trim_end_matches(['\\', '/'])))
}

/// Decide whether a move may happen at all, from first principles.
///
/// The agent re-derives this rather than trusting the proposal it sent, for the
/// same reason quarantine does: the paths come back as strings from a client,
/// and the agent is LocalSystem.
pub fn check_movable(from: &str, to: &str) -> std::result::Result<(), String> {
    let profile = std::env::var("USERPROFILE").map_err(|_| "no user profile".to_owned())?;
    let profile_key = profile.to_lowercase();

    for path in [from, to] {
        if !path.to_lowercase().starts_with(&profile_key) {
            return Err(format!(
                "{path} is outside your user folder, which is the only place this moves files"
            ));
        }
        if is_off_limits(path) {
            return Err(format!(
                "{path} is somewhere software lives, not a document"
            ));
        }
    }

    let name = from.rsplit(['\\', '/']).next().unwrap_or_default();
    if !is_movable(name) {
        return Err(format!(
            "{name} is not a kind of file this will move — executables and \
             anything that runs are excluded on purpose"
        ));
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn documents_and_media_are_movable() {
        assert!(is_movable("invoice.pdf"));
        assert!(is_movable("HOLIDAY.JPG"));
        assert!(is_movable("album.flac"));
        assert!(is_movable("backup.zip"));
    }

    #[test]
    fn nothing_that_runs_is_movable() {
        // The resolution of the plan's contradiction, asserted so it cannot be
        // loosened by accident.
        for name in [
            "setup.exe",
            "installer.msi",
            "script.bat",
            "run.cmd",
            "tool.ps1",
            "library.dll",
            "thing.scr",
        ] {
            assert!(!is_movable(name), "{name} should never be movable");
        }
    }

    #[test]
    fn a_file_with_no_extension_is_not_movable() {
        assert!(!is_movable("README"));
        assert!(!is_movable(""));
    }

    #[test]
    fn software_directories_are_off_limits_at_any_depth() {
        assert!(is_off_limits(r"C:\Users\me\AppData\Local\Thing\file.pdf"));
        assert!(is_off_limits(
            r"C:\Users\me\Projects\app\node_modules\x.zip"
        ));
        assert!(is_off_limits(r"C:\Users\me\code\repo\.git\thing.pdf"));
        assert!(is_off_limits(r"C:\Program Files\Thing\manual.pdf"));
        assert!(!is_off_limits(r"C:\Users\me\Documents\Invoices\bill.pdf"));
    }

    #[test]
    fn a_folder_named_like_a_forbidden_one_is_still_allowed() {
        // Component-wise, not substring: "Windows Photos" is not "windows".
        assert!(!is_off_limits(r"C:\Users\me\Pictures\Windows Photos\a.jpg"));
        assert!(!is_off_limits(r"C:\Users\me\Documents\targeting\plan.pdf"));
    }

    #[test]
    fn the_fence_refuses_anything_outside_the_user_folder() {
        let profile = std::env::var("USERPROFILE").unwrap();
        assert!(
            check_movable(&format!(r"{profile}\Downloads\a.pdf"), r"C:\Windows\a.pdf").is_err()
        );
        assert!(check_movable(
            r"C:\Program Files\Thing\a.pdf",
            &format!(r"{profile}\Documents\a.pdf")
        )
        .is_err());
    }

    #[test]
    fn the_fence_refuses_executables_even_inside_the_user_folder() {
        let profile = std::env::var("USERPROFILE").unwrap();
        assert!(check_movable(
            &format!(r"{profile}\Downloads\setup.exe"),
            &format!(r"{profile}\Documents\setup.exe")
        )
        .is_err());
    }

    #[test]
    fn the_fence_allows_a_document_between_user_folders() {
        let profile = std::env::var("USERPROFILE").unwrap();
        assert!(check_movable(
            &format!(r"{profile}\Downloads\invoice.pdf"),
            &format!(r"{profile}\Documents\Invoices\invoice.pdf")
        )
        .is_ok());
    }

    #[test]
    fn synced_folders_are_recognised() {
        assert!(is_synced(r"C:\Users\me\OneDrive\Pictures\a.png"));
        assert!(is_synced(r"C:\Users\me\OneDrive - Company\Docs\a.pdf"));
        assert!(is_synced(r"C:\Users\me\Dropbox\a.pdf"));
        assert!(!is_synced(r"C:\Users\me\Pictures\a.png"));
    }

    #[test]
    fn a_named_match_outranks_a_merely_typical_folder() {
        assert!(Strength::Strong > Strength::Reasonable);
    }
}
