//! Files that are byte-for-byte copies of one another.
//!
//! # Three passes, cheapest first
//!
//! Hashing a terabyte to find duplicates would take longer than the scan that
//! found them, so almost everything is eliminated before a byte is read.
//!
//! 1. **Size.** Two files of different lengths cannot be identical, and the
//!    master file table already knows every length. This is free, and it
//!    discards the overwhelming majority.
//! 2. **The first 64 KB.** Files that merely happen to share a size — and
//!    installers, padded archives and disk images share sizes constantly — nearly
//!    always differ in their opening bytes. One small read each settles it.
//! 3. **The whole file.** Only for what survives both, which is close to the set
//!    of genuine duplicates. This is the expensive pass and it runs on the least
//!    data.
//!
//! # Why the full read happens at all
//!
//! A head hash plus a size is persuasive but not proof, and this list exists to
//! tell someone they can delete something. Two files that agree on length and
//! opening block but differ deep inside are exactly the case a shortcut would
//! get wrong, and the cost of being wrong is data. So the last pass is a full
//! comparison, and the word "duplicate" means it.
//!
//! # Why it is not part of the ordinary survey
//!
//! Everything else here answers in about three seconds because it reads the
//! master file table and nothing else. This reads file contents, and on a
//! terabyte of games that is tens of gigabytes however well the earlier passes
//! filter. Folding it into the survey would have turned every application
//! measurement into a minute-long wait for something the user did not ask for,
//! so it is a separate action with its own button.
//!
//! The reads are spread across threads: hashing is CPU work sitting on top of
//! IO, and both parallelise.
//!
//! # Hard links are not duplicates
//!
//! Two names for one file share their bytes, so deleting one frees nothing.
//! They never appear here, because the index is keyed by record number and a
//! hard link is one record with several names.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use kam_core::{Cancelled, Reporter, UserContext};
use serde::{Deserialize, Serialize};

use crate::index::VolumeIndex;

/// Below this, duplicates are not worth a row. A list of matching 40 KB icons
/// buries the pair of 3 GB installers.
const MIN_SIZE: u64 = 8 * 1024 * 1024;

/// How much of a file the second pass reads.
const HEAD_BYTES: usize = 64 * 1024;

/// Ceiling on the third pass. A pathological volume could otherwise spend
/// minutes reading; stopping and saying so beats an unbounded wait.
const MAX_FULL_HASH_BYTES: u64 = 192 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateGroup {
    /// Size of one copy.
    pub bytes: u64,
    /// Arithmetic: what every copy beyond the first occupies. Says nothing
    /// about whether any of it can be reclaimed, which is what
    /// `reclaimable_bytes` is for.
    pub wasted_bytes: u64,
    /// What could actually be freed without breaking anything -- often zero
    /// even for a large group, and the number worth showing.
    pub reclaimable_bytes: u64,
    /// Every copy, best keeper first.
    pub copies: Vec<FileCopy>,
    pub verdict: Verdict,
    /// Index into `copies` of the one to keep, when there is something to
    /// choose between.
    pub suggested_keep: Option<usize>,
    /// Why, in the order somebody would want to read it.
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateSummary {
    pub groups: usize,
    /// Total held by every copy after the first, whether or not it can go.
    pub wasted_bytes: u64,
    /// The part of that which could actually be removed safely.
    pub reclaimable_bytes: u64,
    /// Groups where there is in fact a choice to make.
    pub actionable: usize,
    /// Files that reached the size test.
    pub examined: usize,
    /// Files whose opening block was read.
    pub head_hashed: usize,
    /// Files read in full.
    pub fully_hashed: usize,
    pub elapsed_ms: u64,
    /// True when the read ceiling stopped the search early.
    pub truncated: bool,
}

/// Who put a copy where it is.
///
/// This is the whole point of the analysis. "Byte-for-byte identical" is a fact
/// about content and says nothing about whether a copy can go: Windows keeps
/// several copies of the same library on purpose, every installer keeps a
/// second copy of itself so it can repair later, and two programs that both
/// ship the same runtime each look for it beside themselves. Deleting the
/// "redundant" one in any of those cases breaks something.
///
/// So each copy is judged by where it lives, and only the ones somebody put
/// somewhere personal are ever offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Owner {
    /// Inside `C:\Windows`. Windows' own files.
    Windows,
    /// Component store, driver store, installer cache, update cache. Windows
    /// keeps duplicates here deliberately, and servicing puts back anything
    /// removed — usually while breaking an update on the way through.
    Servicing,
    /// An installed program's own folder, including game libraries.
    Program,
    /// A program's data, under `ProgramData` or an `AppData` root.
    ProgramData,
    /// A folder belonging to the person using the machine: the desktop,
    /// downloads, documents, pictures, video, music, or a cloud folder.
    Yours,
    /// Already deleted, sitting in the recycle bin.
    Deleted,
    /// Somewhere this does not recognise. Not offered — being unable to say who
    /// owns something is a reason for caution, not for a recommendation.
    Elsewhere,
}

impl Owner {
    /// Whether a copy here may be offered for removal.
    fn removable(self) -> bool {
        matches!(self, Owner::Yours | Owner::Deleted)
    }

    fn describes(self) -> &'static str {
        match self {
            Owner::Windows => "one of Windows' own files",
            Owner::Servicing => "held by Windows servicing or an installer",
            Owner::Program => "inside a program's install folder",
            Owner::ProgramData => "in a program's data folder",
            Owner::Yours => "in a folder of yours",
            Owner::Deleted => "already in the recycle bin",
            Owner::Elsewhere => "somewhere this cannot attribute",
        }
    }
}

/// Folders that belong to the person rather than to any program.
const PERSONAL: &[&str] = &[
    "desktop",
    "documents",
    "downloads",
    "music",
    "pictures",
    "videos",
    "saved games",
];

/// Fragments that mean an installer or Windows keeps this copy on purpose.
const SERVICING: &[&str] = &[
    r"\windows\winsxs\",
    r"\windows\servicing\",
    r"\windows\installer\",
    r"\windows\softwaredistribution\",
    r"\windows\assembly\",
    r"\driverstore\",
    r"\$patchcache$\",
    r"\packagecache\",
    r"\package cache\",
    r"\downloaded installations\",
];

/// Fragments that mean a program owns the folder.
const PROGRAM: &[&str] = &[
    r"\program files\",
    r"\program files (x86)\",
    r"\windowsapps\",
    r"\steamapps\",
    r"\epic games\",
    r"\gog galaxy\",
    r"\ea games\",
    r"\ubisoft\",
    r"\battle.net\",
    r"\riot games\",
];

/// Work out who owns a copy, from its path alone.
///
/// Path-only on purpose. This runs against the master file table on a whole
/// volume, so anything that opened files to decide would cost another pass over
/// the disk, and every rule here is one a person could check by reading the
/// path themselves — which matters for a list whose whole job is to be trusted.
pub fn owner_of(path: &str, user: &UserContext) -> Owner {
    let lowered = path.to_lowercase().replace('/', "\\");

    if lowered.contains(r"\$recycle.bin\") {
        return Owner::Deleted;
    }
    if SERVICING.iter().any(|marker| lowered.contains(marker)) {
        return Owner::Servicing;
    }
    // Checked after servicing, since most of what servicing holds is also
    // inside the Windows directory.
    if lowered
        .get(1..)
        .is_some_and(|rest| rest.starts_with(r":\windows\"))
    {
        return Owner::Windows;
    }
    if PROGRAM.iter().any(|marker| lowered.contains(marker)) {
        return Owner::Program;
    }

    let profile = user.profile().to_lowercase();
    if !profile.is_empty() {
        if let Some(rest) = lowered.strip_prefix(&format!("{profile}\\")) {
            let top = rest.split('\\').next().unwrap_or_default();
            // A cloud folder is named for its provider — OneDrive, "OneDrive -
            // Contoso", Dropbox — so it is matched by prefix rather than listed.
            if PERSONAL.contains(&top)
                || top.starts_with("onedrive")
                || top.starts_with("dropbox")
                || top.starts_with("google drive")
            {
                return Owner::Yours;
            }
            if top == "appdata" {
                return Owner::ProgramData;
            }
        }
    }

    if lowered.contains(r"\appdata\") || lowered.contains(r"\programdata\") {
        return Owner::ProgramData;
    }

    Owner::Elsewhere
}

/// One copy, with the judgement attached to it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileCopy {
    pub path: String,
    pub owner: Owner,
    /// True when removing *this* copy is a choice rather than a hazard.
    pub removable: bool,
}

/// What the group as a whole means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Windows keeps these. Nothing to do, and removing one causes trouble.
    Keep,
    /// Programs shipped their own copies. Normal, and not waste in any sense
    /// that can be acted on.
    Deliberate,
    /// At least one copy is somewhere personal and another would survive it.
    Choose,
    /// Identical, in places this cannot attribute. Shown without a suggestion.
    Unclear,
}

/// Rank a copy by how much it looks like the one to keep. Lower is better.
fn keep_rank(copy: &FileCopy) -> (u8, usize) {
    let owner_rank = match copy.owner {
        // Anything a program or Windows holds is surviving regardless, so it is
        // the natural keeper.
        Owner::Windows | Owner::Servicing => 0,
        Owner::Program | Owner::ProgramData => 1,
        Owner::Elsewhere => 2,
        Owner::Yours => 3,
        // Already deleted: never the copy to keep.
        Owner::Deleted => 9,
    };

    let lowered = copy.path.to_lowercase();
    let name = lowered.rsplit('\\').next().unwrap_or_default();
    // "report (1).pdf" and "report - Copy.pdf" are what Windows names the
    // second one, so they are the second one.
    let looks_like_a_copy =
        name.contains(" - copy") || name.contains(" (1)") || name.contains(" (2)");
    let in_downloads = lowered.contains(r"\downloads\");

    let mut penalty = owner_rank * 4;
    if looks_like_a_copy {
        penalty += 2;
    }
    if in_downloads {
        penalty += 1;
    }
    // Shortest path breaks any remaining tie, which favours the tidier home.
    (penalty, copy.path.len())
}

/// Judge a set of identical files.
fn judge(bytes: u64, paths: Vec<String>, user: &UserContext) -> DuplicateGroup {
    let mut copies: Vec<FileCopy> = paths
        .into_iter()
        .map(|path| {
            let owner = owner_of(&path, user);
            FileCopy {
                path,
                owner,
                removable: owner.removable(),
            }
        })
        .collect();
    copies.sort_by_key(keep_rank);

    let total = copies.len();
    let removable = copies.iter().filter(|copy| copy.removable).count();

    // One copy always stays, whatever the owners say. A set where every copy is
    // yours still reclaims one copy less than it holds.
    let spare = removable.min(total.saturating_sub(1));
    let reclaimable_bytes = bytes * spare as u64;

    let verdict = if spare > 0 {
        Verdict::Choose
    } else if copies
        .iter()
        .any(|copy| matches!(copy.owner, Owner::Windows | Owner::Servicing))
    {
        Verdict::Keep
    } else if copies
        .iter()
        .any(|copy| matches!(copy.owner, Owner::Program | Owner::ProgramData))
    {
        Verdict::Deliberate
    } else {
        Verdict::Unclear
    };

    DuplicateGroup {
        bytes,
        wasted_bytes: bytes * (total as u64 - 1),
        reclaimable_bytes,
        reasons: explain(&copies, verdict, spare),
        // The best keeper sorts first, so it is the one at index zero.
        suggested_keep: (verdict == Verdict::Choose).then_some(0),
        verdict,
        copies,
    }
}

/// Say why, in the order somebody would want to read it.
fn explain(copies: &[FileCopy], verdict: Verdict, spare: usize) -> Vec<String> {
    let mut reasons = Vec::new();

    let names: HashSet<String> = copies
        .iter()
        .filter_map(|copy| copy.path.rsplit('\\').next())
        .map(str::to_lowercase)
        .collect();

    match verdict {
        Verdict::Keep => {
            reasons.push(
                "Windows keeps these copies deliberately. Servicing puts back anything \
                 removed from here, and usually breaks an update doing it."
                    .to_owned(),
            );
        }
        Verdict::Deliberate => {
            reasons.push(
                "Each copy sits inside a program's own folder. Programs ship their own \
                 libraries so they do not depend on each other's versions; removing one \
                 breaks that program rather than saving anything."
                    .to_owned(),
            );
        }
        Verdict::Unclear => {
            reasons.push(
                "These are outside every folder this recognises, so it cannot tell whether \
                 something needs them. Nothing is suggested."
                    .to_owned(),
            );
        }
        Verdict::Choose => {
            let where_it_stays = copies
                .first()
                .map(|copy| copy.owner)
                .unwrap_or(Owner::Elsewhere);
            reasons.push(if where_it_stays.removable() {
                format!(
                    "All {} copies are in folders of yours, so keeping one and removing the \
                     rest loses nothing.",
                    copies.len()
                )
            } else {
                format!(
                    "{} of these is {}, and would still be there. The rest are in folders \
                     of yours.",
                    if spare + 1 == copies.len() {
                        "One"
                    } else {
                        "Some"
                    },
                    where_it_stays.describes()
                )
            });

            if names.len() == 1 {
                reasons.push(
                    "Same name in both places, which usually means one was copied rather \
                     than saved twice."
                        .to_owned(),
                );
            } else {
                reasons.push(
                    "The names differ, so this is the same file saved under two names — \
                     identical content regardless."
                        .to_owned(),
                );
            }
        }
    }

    if copies.iter().any(|copy| copy.owner == Owner::Deleted) {
        reasons.push(
            "One copy is already in the recycle bin and is still taking up the space until \
             the bin is emptied."
                .to_owned(),
        );
    }

    let executable = copies.iter().any(|copy| {
        let lowered = copy.path.to_lowercase();
        [".exe", ".dll", ".sys", ".msi", ".pyd"]
            .iter()
            .any(|suffix| lowered.ends_with(suffix))
    });
    if executable && verdict == Verdict::Choose {
        reasons.push(
            "These are program files. If one of them is a portable application you run from \
             that folder, it is not spare."
                .to_owned(),
        );
    }

    reasons
}

/// Decide whether one copy may be removed at all.
///
/// The agent's fence, and it re-derives the answer rather than trusting the
/// list the shell was shown. Same shape as the leftover fence: the interface
/// produces a suggestion from data, and the path that comes back over the pipe
/// is a string from a client that a LocalSystem process is about to act on.
pub fn check_removable(path: &str, user: &UserContext) -> std::result::Result<(), String> {
    let owner = owner_of(path, user);
    if !owner.removable() {
        return Err(format!(
            "{path} is {} -- only a copy in a folder of yours may be removed this way",
            owner.describes()
        ));
    }

    let target = std::path::Path::new(path);
    let metadata = std::fs::symlink_metadata(target)
        .map_err(|error| format!("{path} could not be read: {error}"))?;
    if metadata.is_dir() {
        return Err(format!("{path} is a directory, not a copy of a file"));
    }
    // A link shares its target's bytes, so removing it frees nothing and may
    // take the real file with it.
    if metadata.is_symlink() {
        return Err(format!("{path} is a link rather than a file"));
    }
    Ok(())
}

/// Hash the first [`HEAD_BYTES`] of a file, or the whole thing if it is smaller.
fn head_hash(path: &str) -> Option<[u8; 32]> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut buffer = vec![0_u8; HEAD_BYTES];
    let mut filled = 0;
    // A single read may return less than asked for without being at the end.
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(_) => return None,
        }
    }
    Some(*blake3::hash(&buffer[..filled]).as_bytes())
}

fn full_hash(path: &str) -> Option<[u8; 32]> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                hasher.update(&buffer[..read]);
            }
            Err(_) => return None,
        }
    }
    Some(*hasher.finalize().as_bytes())
}

/// Group values by a key, keeping only the groups with more than one member.
fn keep_collisions<K: std::hash::Hash + Eq, V>(pairs: Vec<(K, V)>) -> Vec<Vec<V>> {
    let mut grouped: HashMap<K, Vec<V>> = HashMap::new();
    for (key, value) in pairs {
        grouped.entry(key).or_default().push(value);
    }
    grouped
        .into_values()
        .filter(|group| group.len() > 1)
        .collect()
}

/// Counters shared across the hashing threads.
#[derive(Debug, Default)]
struct Counters {
    head_hashed: AtomicUsize,
    fully_hashed: AtomicUsize,
    hashed_bytes: AtomicU64,
    truncated: AtomicUsize,
}

/// Resolve, head-hash and where necessary fully hash one size group.
fn resolve_group(
    records: &[u32],
    index: &VolumeIndex,
    drive_root: &str,
    counters: &Counters,
    user: &UserContext,
) -> Vec<DuplicateGroup> {
    let Some(size) = records
        .first()
        .and_then(|record| index.entry(*record))
        .map(|entry| entry.bytes)
    else {
        return Vec::new();
    };

    let heads: Vec<([u8; 32], String)> = records
        .iter()
        .filter_map(|record| {
            let path = index.path_of(*record, drive_root)?;
            let hash = head_hash(&path)?;
            Some((hash, path))
        })
        .collect();
    counters
        .head_hashed
        .fetch_add(heads.len(), Ordering::Relaxed);

    let mut groups = Vec::new();
    for candidates in keep_collisions(heads) {
        let wanted = size * candidates.len() as u64;
        // Reserve the budget before reading, so threads cannot collectively
        // overshoot the ceiling by racing past it.
        let before = counters.hashed_bytes.fetch_add(wanted, Ordering::Relaxed);
        if before + wanted > MAX_FULL_HASH_BYTES {
            counters.truncated.fetch_add(1, Ordering::Relaxed);
            continue;
        }

        let full: Vec<([u8; 32], String)> = candidates
            .into_iter()
            .filter_map(|path| Some((full_hash(&path)?, path)))
            .collect();
        counters
            .fully_hashed
            .fetch_add(full.len(), Ordering::Relaxed);

        for identical in keep_collisions(full) {
            groups.push(judge(size, identical, user));
        }
    }
    groups
}

/// Find duplicate files on an indexed volume.
pub fn find(
    index: &VolumeIndex,
    drive_root: &str,
    reporter: &Reporter,
    user: &UserContext,
) -> Result<(Vec<DuplicateGroup>, DuplicateSummary), Cancelled> {
    let started = Instant::now();

    // Pass one: identical length, straight from the table. No disk access.
    let by_size: Vec<(u64, u32)> = index
        .entries()
        .iter()
        .filter(|(_, entry)| !entry.is_directory && entry.bytes >= MIN_SIZE)
        .map(|(record, entry)| (entry.bytes, *record))
        .collect();
    let examined = by_size.len();
    let size_groups = keep_collisions(by_size);
    reporter.check()?;

    // Only the second pass is worth a bar. The first is a scan of a table
    // already in memory and is over before anything could be drawn; the
    // second reads file contents off the disk, and is where the time goes.
    reporter.stage(
        "Comparing files of equal size",
        Some(size_groups.len() as u64),
    );

    let counters = Counters::default();
    let threads = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(4);
    let chunk = size_groups.len().div_ceil(threads.max(1)).max(1);

    let mut groups: Vec<DuplicateGroup> = std::thread::scope(|scope| {
        let handles: Vec<_> = size_groups
            .chunks(chunk)
            .map(|slice| {
                let counters = &counters;
                let reporter = reporter.clone();
                scope.spawn(move || {
                    let mut found = Vec::new();
                    for records in slice {
                        if reporter.is_cancelled() {
                            break;
                        }
                        found.extend(resolve_group(records, index, drive_root, counters, user));
                        reporter.advance(1);
                    }
                    found
                })
            })
            .collect();

        handles
            .into_iter()
            .filter_map(|handle| handle.join().ok())
            .flatten()
            .collect()
    });

    reporter.check()?;
    // What can be acted on first, then what is merely large. A 40 GB set of
    // Windows component-store copies is not more useful to see than a 2 GB
    // video somebody saved twice.
    groups.sort_by_key(|group| {
        (
            std::cmp::Reverse(group.reclaimable_bytes),
            std::cmp::Reverse(group.wasted_bytes),
        )
    });

    let summary = DuplicateSummary {
        groups: groups.len(),
        wasted_bytes: groups.iter().map(|group| group.wasted_bytes).sum(),
        reclaimable_bytes: groups.iter().map(|group| group.reclaimable_bytes).sum(),
        actionable: groups
            .iter()
            .filter(|group| group.verdict == Verdict::Choose)
            .count(),
        examined,
        head_hashed: counters.head_hashed.load(Ordering::Relaxed),
        fully_hashed: counters.fully_hashed.load(Ordering::Relaxed),
        elapsed_ms: started.elapsed().as_millis() as u64,
        truncated: counters.truncated.load(Ordering::Relaxed) > 0,
    };
    Ok((groups, summary))
}

/// Read the volume's table, then look for duplicates on it.
pub fn survey(
    drive_letter: char,
    reporter: &Reporter,
    user: &UserContext,
) -> kam_core::Result<(Vec<DuplicateGroup>, DuplicateSummary)> {
    reporter.stage("Reading the file table", None);
    let snapshot = crate::mft::read(drive_letter)?;
    let index = VolumeIndex::build(snapshot);
    find(&index, &format!("{drive_letter}:"), reporter, user)
        .map_err(|_| kam_core::Error::Refused("stopped at your request".to_owned()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A user whose profile is fixed, so path judgements are checkable rather
    /// than dependent on whoever runs the tests.
    fn someone() -> UserContext {
        UserContext::new(None, r"C:\Users\someone")
    }

    fn judged(bytes: u64, paths: &[&str]) -> DuplicateGroup {
        judge(
            bytes,
            paths.iter().map(|path| (*path).to_owned()).collect(),
            &someone(),
        )
    }

    #[test]
    fn windows_own_files_are_attributed_to_windows() {
        let user = someone();
        assert_eq!(
            owner_of(r"C:\Windows\System32\kernel32.dll", &user),
            Owner::Windows
        );
        assert_eq!(
            owner_of(r"C:\Windows\WinSxS\amd64_something\file.dll", &user),
            Owner::Servicing
        );
        assert_eq!(
            owner_of(r"C:\Windows\Installer\1a2b3c.msi", &user),
            Owner::Servicing
        );
        assert_eq!(
            owner_of(r"C:\ProgramData\Package Cache\{guid}\setup.exe", &user),
            Owner::Servicing
        );
    }

    #[test]
    fn a_game_in_any_library_belongs_to_the_program_that_installed_it() {
        let user = someone();
        assert_eq!(
            owner_of(
                r"D:\SteamLibrary\steamapps\common\Elden Ring\data.pak",
                &user
            ),
            Owner::Program
        );
        assert_eq!(
            owner_of(r"C:\Program Files (x86)\Steam\steam.dll", &user),
            Owner::Program
        );
    }

    #[test]
    fn only_a_personal_folder_counts_as_yours() {
        let user = someone();
        assert_eq!(
            owner_of(r"C:\Users\someone\Downloads\holiday.mp4", &user),
            Owner::Yours
        );
        assert_eq!(
            owner_of(r"C:\Users\someone\OneDrive - Work\report.pdf", &user),
            Owner::Yours
        );
        // AppData sits inside the profile and is emphatically not personal.
        assert_eq!(
            owner_of(r"C:\Users\someone\AppData\Local\Slack\app.asar", &user),
            Owner::ProgramData
        );
        // Somebody else's profile is not yours either.
        assert_ne!(
            owner_of(r"C:\Users\otherperson\Downloads\holiday.mp4", &user),
            Owner::Yours
        );
    }

    #[test]
    fn an_unrecognised_location_is_never_called_yours() {
        // The case the whole classification exists for: a folder off the root
        // of a second drive could be a media library or an unpacked game, and
        // guessing wrong deletes somebody's game.
        assert_eq!(
            owner_of(r"D:\Games\SomethingUnknown\data.bin", &someone()),
            Owner::Elsewhere
        );
    }

    #[test]
    fn copies_windows_keeps_are_never_offered() {
        let group = judged(
            500_000_000,
            &[
                r"C:\Windows\WinSxS\one\payload.dll",
                r"C:\Windows\System32\payload.dll",
            ],
        );
        assert_eq!(group.verdict, Verdict::Keep);
        assert_eq!(group.reclaimable_bytes, 0);
        assert!(group.suggested_keep.is_none());
        // The raw arithmetic is still reported, because it is still true.
        assert_eq!(group.wasted_bytes, 500_000_000);
    }

    #[test]
    fn two_programs_shipping_the_same_library_is_deliberate_not_waste() {
        let group = judged(
            40_000_000,
            &[
                r"C:\Program Files\Alpha\vcruntime140.dll",
                r"C:\Program Files\Beta\vcruntime140.dll",
            ],
        );
        assert_eq!(group.verdict, Verdict::Deliberate);
        assert_eq!(group.reclaimable_bytes, 0);
        assert!(
            group.reasons[0].contains("their own"),
            "unhelpful reason: {}",
            group.reasons[0]
        );
    }

    #[test]
    fn one_copy_always_survives_even_when_every_copy_is_yours() {
        let group = judged(
            1_000_000_000,
            &[
                r"C:\Users\someone\Videos\wedding.mp4",
                r"C:\Users\someone\Downloads\wedding.mp4",
                r"C:\Users\someone\Desktop\wedding.mp4",
            ],
        );
        assert_eq!(group.verdict, Verdict::Choose);
        // Three copies, two removable -- never three.
        assert_eq!(group.reclaimable_bytes, 2_000_000_000);
        assert_eq!(group.copies.iter().filter(|c| c.removable).count(), 3);
    }

    #[test]
    fn the_copy_to_keep_is_the_one_in_a_proper_folder() {
        let group = judged(
            1_000_000,
            &[
                r"C:\Users\someone\Downloads\report (1).pdf",
                r"C:\Users\someone\Documents\report.pdf",
            ],
        );
        let keep = group.suggested_keep.expect("something should be kept");
        assert_eq!(
            group.copies[keep].path,
            r"C:\Users\someone\Documents\report.pdf"
        );
    }

    #[test]
    fn a_copy_a_program_holds_is_the_one_that_survives() {
        let group = judged(
            80_000_000,
            &[
                r"C:\Users\someone\Downloads\installer.exe",
                r"C:\Program Files\Thing\installer.exe",
            ],
        );
        assert_eq!(group.verdict, Verdict::Choose);
        assert_eq!(group.reclaimable_bytes, 80_000_000);
        let keep = group.suggested_keep.expect("something should be kept");
        assert!(!group.copies[keep].removable, "the keeper is the safe one");
        assert!(
            group
                .reasons
                .iter()
                .any(|why| why.contains("program files")),
            "an executable pair should carry the warning: {:?}",
            group.reasons
        );
    }

    #[test]
    fn nothing_recognisable_produces_no_recommendation() {
        let group = judged(
            9_000_000_000,
            &[r"D:\Archive\one\blob.bin", r"E:\Vault\blob.bin"],
        );
        assert_eq!(group.verdict, Verdict::Unclear);
        assert_eq!(group.reclaimable_bytes, 0);
        assert!(group.suggested_keep.is_none());
    }

    #[test]
    fn the_fence_refuses_anything_a_program_or_windows_owns() {
        let user = someone();
        for path in [
            r"C:\Windows\System32\kernel32.dll",
            r"C:\Program Files\Thing\thing.exe",
            r"C:\ProgramData\Package Cache\x\setup.exe",
            r"D:\Games\Unknown\data.bin",
        ] {
            assert!(
                check_removable(path, &user).is_err(),
                "{path} should have been refused"
            );
        }
    }

    #[test]
    fn the_fence_accepts_a_real_file_in_a_folder_of_yours() {
        // Built against the account running the test, since the file has to
        // exist for the fence to check it.
        let user = UserContext::current();
        let downloads = std::path::Path::new(user.profile()).join("Downloads");
        if !downloads.is_dir() {
            return;
        }

        let file = downloads.join(format!("kam-dup-fence-{}.tmp", std::process::id()));
        std::fs::write(&file, b"content").unwrap();
        let path = file.to_string_lossy().into_owned();

        assert!(
            check_removable(&path, &user).is_ok(),
            "a real file was refused"
        );
        // The folder holding it is not itself a copy of anything.
        assert!(check_removable(&downloads.to_string_lossy(), &user).is_err());

        std::fs::remove_file(&file).unwrap();
        // And once it is gone there is nothing to remove.
        assert!(check_removable(&path, &user).is_err());
    }

    #[test]
    fn a_group_reports_what_can_go_separately_from_what_is_merely_duplicated() {
        // The distinction the whole analysis turns on: 3 GB is duplicated and
        // none of it can be reclaimed.
        let group = judged(
            1_500_000_000,
            &[
                r"C:\Windows\WinSxS\a\payload.bin",
                r"C:\Windows\WinSxS\b\payload.bin",
                r"C:\Windows\System32\payload.bin",
            ],
        );
        assert_eq!(group.wasted_bytes, 3_000_000_000);
        assert_eq!(group.reclaimable_bytes, 0);
    }

    #[test]
    fn grouping_keeps_only_keys_seen_more_than_once() {
        let groups = keep_collisions(vec![(1, "a"), (2, "b"), (1, "c"), (3, "d")]);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].len(), 2);
    }

    #[test]
    fn a_key_seen_once_is_not_a_group() {
        assert!(keep_collisions(vec![(1, "a"), (2, "b")]).is_empty());
    }

    #[test]
    fn identical_content_hashes_identically_and_different_content_does_not() {
        let directory = std::env::temp_dir().join(format!("kam-dup-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();

        let same_a = directory.join("a.bin");
        let same_b = directory.join("b.bin");
        let other = directory.join("c.bin");
        // Same length as the others, differing only well past the head, which
        // is the case a head-only shortcut would call a duplicate.
        let mut content = vec![7_u8; 200_000];
        std::fs::write(&same_a, &content).unwrap();
        std::fs::write(&same_b, &content).unwrap();
        content[199_999] = 8;
        std::fs::write(&other, &content).unwrap();

        let a = full_hash(same_a.to_str().unwrap()).unwrap();
        let b = full_hash(same_b.to_str().unwrap()).unwrap();
        let c = full_hash(other.to_str().unwrap()).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c, "a difference past the head must still be caught");

        // The heads match for all three, which is exactly why the third pass
        // exists rather than stopping at the second.
        let head_a = head_hash(same_a.to_str().unwrap()).unwrap();
        let head_c = head_hash(other.to_str().unwrap()).unwrap();
        assert_eq!(head_a, head_c);

        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn a_missing_file_hashes_to_nothing_rather_than_panicking() {
        assert!(head_hash(r"C:\this\is\not\here.bin").is_none());
        assert!(full_hash(r"C:\this\is\not\here.bin").is_none());
    }
}
