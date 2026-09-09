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

use kam_core::UserContext;
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
///
/// # A trap for anyone testing the fence
///
/// `appdata` is on the list, and on Windows the temp directory lives *inside*
/// AppData. So a test that builds its fixture in `std::env::temp_dir()` — which
/// is the obvious place, and where cargo and most harnesses put things — cannot
/// ever get a move permitted, because the fixture's own location is off limits.
///
/// That is this function being right rather than wrong, so the fixture is what
/// has to move: somewhere with no off-limits component, such as a folder beside
/// the tester's own profile or under `C:\Users\Public`. It is written here
/// because two people hit it independently on the same day, each spending a
/// while assuming the fence was broken before noticing where they were standing.
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
///
/// The profile comes from the caller's [`UserContext`], not from the
/// environment. Inside the service the environment's `USERPROFILE` is
/// LocalSystem's own — `C:\Windows\system32\config\systemprofile` — which is a
/// real directory that no loose file of anyone's is ever under, so this feature
/// silently proposed nothing at all for as long as it read that variable.
pub fn survey(
    drive_letter: char,
    user: &UserContext,
) -> kam_core::Result<(Vec<Proposal>, OrganiseSummary)> {
    let profile = user.profile().trim_end_matches(['\\', '/']);
    if profile.is_empty() {
        return Err(kam_core::Error::Privileged(
            "there is no user profile to look in".to_owned(),
        ));
    }
    let snapshot = crate::mft::read(drive_letter)?;
    let index = VolumeIndex::build(snapshot);
    Ok(find(&index, profile))
}

/// Decide whether a move may happen at all, from first principles.
///
/// The agent re-derives this rather than trusting the proposal it sent, for the
/// same reason quarantine does: the paths come back as strings from a client,
/// and the agent is LocalSystem.
///
/// # Whose user folder
///
/// The caller's, taken from [`UserContext`]. This read `USERPROFILE` from the
/// environment, which inside the service is LocalSystem's profile and not the
/// profile of the person who asked — the same wrong-principal mistake that made
/// the agent measure the wrong account's disk everywhere else. Here it failed
/// closed rather than open: every legitimate move was refused, so the feature
/// simply did not work under the service.
///
/// # Why it resolves before comparing
///
/// A confinement rule written against the text is not a confinement rule.
/// `C:\Users\someone\Downloads\..\..\..\Windows\System32\driver.pdf` starts with
/// the profile and ends up in `System32`; a junction anywhere in the middle does
/// the same thing without any punctuation to notice. Both paths are resolved
/// first, and every rule below — the fence, the off-limits check — is applied to
/// what came back rather than to what was sent.
///
/// The destination usually does not exist yet, which is the point of moving
/// something there, so it is resolved as far as it goes; see
/// [`crate::paths::resolved`].
pub fn check_movable(from: &str, to: &str, user: &UserContext) -> std::result::Result<(), String> {
    // Resolved against resolved: see `paths::resolved_root`. A profile reached
    // through a junction — ordinary where folders are redirected — otherwise
    // never matches the resolved paths below, and every move is refused.
    let Some(profile) = crate::paths::resolved_root(user.profile()) else {
        return Err("there is no user folder to confine this to".to_owned());
    };
    let profile = profile.trim_end_matches(['\\', '/']);
    if profile.is_empty() {
        return Err("there is no user folder to confine this to".to_owned());
    }
    // The trailing separator is load-bearing: without it `C:\Users\ann` is a
    // prefix of `C:\Users\annette`, and the fence lets one account move the
    // other's files.
    let fence = format!("{profile}\\");

    for path in [from, to] {
        if crate::paths::has_relative_step(path) {
            return Err(format!("{path} is not a plain path"));
        }
        let Some(real) = crate::paths::resolved_plain(path) else {
            return Err(format!(
                "{path} could not be resolved, so it was left alone"
            ));
        };
        if !real.starts_with(&fence) {
            return Err(format!(
                "{path} is outside your user folder, which is the only place this moves files"
            ));
        }
        if is_off_limits(&real) {
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

    /// A throwaway user folder, with the shape the fence expects.
    ///
    /// The fence resolves paths on disk, so it cannot be exercised against
    /// names that are not there — and testing it against the *tester's* real
    /// profile is what let the wrong-principal bug hide, since under `cargo
    /// test` the environment's profile and the caller's are the same person.
    /// They are only different inside the service, which is the one place the
    /// old tests could not reach.
    struct Home {
        root: std::path::PathBuf,
    }

    impl Home {
        fn new(tag: &str) -> Self {
            // Not the temp directory: on Windows that lives under AppData,
            // which `is_off_limits` refuses — correctly, which is why the
            // fixture has to move rather than the rule. A folder beside the
            // tester's own is somewhere the fence has no opinion about.
            let home = std::env::var("USERPROFILE").unwrap();
            let root = std::path::PathBuf::from(home).join(format!("kam-organise-{tag}"));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("Downloads")).unwrap();
            std::fs::create_dir_all(root.join("Documents")).unwrap();
            Self { root }
        }

        fn root(&self) -> String {
            self.root.to_string_lossy().into_owned()
        }

        fn user(&self) -> UserContext {
            UserContext::new(None, &self.root())
        }

        /// A path inside this profile, which need not exist.
        fn path(&self, relative: &str) -> String {
            self.root.join(relative).to_string_lossy().into_owned()
        }

        /// The same, but the file is really there.
        fn file(&self, relative: &str) -> String {
            let path = self.root.join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&path, b"a document").unwrap();
            path.to_string_lossy().into_owned()
        }
    }

    impl Drop for Home {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

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
        let home = Home::new("outside");
        assert!(check_movable(
            &home.file("Downloads\\a.pdf"),
            r"C:\Windows\a.pdf",
            &home.user()
        )
        .is_err());
        assert!(check_movable(
            r"C:\Program Files\Thing\a.pdf",
            &home.path("Documents\\a.pdf"),
            &home.user()
        )
        .is_err());
    }

    #[test]
    fn the_fence_refuses_executables_even_inside_the_user_folder() {
        let home = Home::new("executables");
        assert!(check_movable(
            &home.file("Downloads\\setup.exe"),
            &home.path("Documents\\setup.exe"),
            &home.user()
        )
        .is_err());
    }

    #[test]
    fn the_fence_allows_a_document_between_user_folders() {
        let home = Home::new("allows");
        assert!(check_movable(
            &home.file("Downloads\\invoice.pdf"),
            &home.path("Documents\\Invoices\\invoice.pdf"),
            &home.user()
        )
        .is_ok());
    }

    /// The fence confines the *caller*, not whoever the service happens to run
    /// as.
    ///
    /// This read `USERPROFILE` from the environment. Inside the service that is
    /// `C:\Windows\system32\config\systemprofile`, so the fence confined moves
    /// to LocalSystem's own profile and refused every real one — the feature
    /// was inert under the service and nobody noticed, because a fence that
    /// refuses everything looks exactly like a fence that is working.
    ///
    /// A `UserContext` for somebody else must therefore refuse the same paths
    /// this user's context allows.
    #[test]
    fn the_fence_confines_the_caller_and_not_the_running_account() {
        let home = Home::new("principal");
        let from = home.file("Downloads\\invoice.pdf");
        let to = home.path("Documents\\invoice.pdf");

        assert!(check_movable(&from, &to, &home.user()).is_ok());

        // The account the service actually runs as.
        let system = UserContext::new(None, r"C:\Windows\system32\config\systemprofile");
        assert!(
            check_movable(&from, &to, &system).is_err(),
            "another account's profile was allowed to confine this move"
        );
    }

    /// One profile is not a prefix of another.
    ///
    /// `C:\Users\ann` is a text prefix of `C:\Users\annette`, so a fence that
    /// compares with a bare `starts_with` lets one account move the other's
    /// files. The separator is what makes it a folder rather than a spelling.
    #[test]
    fn a_profile_name_that_starts_with_another_is_still_a_different_person() {
        let ann = Home::new("ann");
        let annette = Home::new("annette");

        let theirs = annette.file("Downloads\\private.pdf");
        assert!(
            check_movable(
                &theirs,
                &annette.path("Documents\\private.pdf"),
                &ann.user()
            )
            .is_err(),
            "one profile reached into another that merely shares its opening letters"
        );
    }

    /// A path that starts inside the profile need not stay inside it.
    ///
    /// Every rule here used to be applied to the string as sent, and a string
    /// that begins with the profile can still land anywhere on the disk. The
    /// escape below goes to a *neighbouring* folder rather than to `Windows`,
    /// deliberately: a path with `windows` in it is refused by the off-limits
    /// component check whether anything resolves or not, so aiming there would
    /// prove nothing about this fence. Nothing on the way to the neighbour is
    /// off-limits, so the confinement rule is the only thing standing between
    /// the caller and somebody else's files — which is what it is for.
    #[test]
    fn the_fence_refuses_a_path_that_walks_out_of_the_user_folder() {
        let home = Home::new("traversal");
        let neighbour = Home::new("traversal-neighbour");
        let secret = neighbour.file("Documents\\private.pdf");
        let inside = home.file("Downloads\\a.pdf");

        // Begins with the profile, ends in the neighbour's folder.
        let escape = format!(
            "{}\\Downloads\\..\\..\\kam-organise-traversal-neighbour\\Documents\\private.pdf",
            home.root()
        );
        assert!(
            escape
                .to_lowercase()
                .starts_with(&home.root().to_lowercase()),
            "the test input has to look confined, or it proves nothing"
        );

        assert!(
            check_movable(&escape, &home.path("Documents\\a.pdf"), &home.user()).is_err(),
            "a walk out of the user folder was accepted as a source"
        );
        assert!(
            check_movable(&inside, &escape, &home.user()).is_err(),
            "a walk out of the user folder was accepted as a destination"
        );
        assert!(std::path::Path::new(&secret).exists());
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
