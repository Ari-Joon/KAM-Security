//! What grew since last time.
//!
//! The drive went from 855 GB used in September to 994 GB in November, and
//! nothing could say where the 139 GB went, because nothing remembered the
//! scan before. A small summary of each scan of a whole drive does: when,
//! which drive, the volume's serial number, how it was read, the total, and a
//! row for every folder holding 100 MB or more. Two of them, compared, say
//! what grew and what shrank.
//!
//! # What a summary holds
//!
//! A folder's total includes everything beneath it, so the rows agree with
//! each other at every level: when a folder is listed, so is every folder
//! above it, because each of those holds at least as much. That is what lets
//! a page open what grew one level at a time from a flat list.
//!
//! # What a comparison may say
//!
//! - A folder missing from the older summary held less than its floor then.
//!   It is "under 100 MB then", never "new": it may have been there for
//!   years. A folder missing from the newer one is "under 100 MB now", which
//!   includes gone, and is never said to have been deleted. What such a
//!   folder grew or shrank by is known only to be at least its distance from
//!   the floor, and is given as that.
//! - A table read and a walk are never compared. A walk counts a file with
//!   several names once for each name and the table counts it once, so on a
//!   Windows drive the two can differ by gigabytes with nothing changed.
//! - A different serial number is a different drive, whatever its letter.
//! - "Grew" and "shrank" are facts about sizes. Nothing here says whether a
//!   change was expected, or is unusual, or is a problem.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::index::VolumeIndex;
use crate::scan::{Node, ScanMethod};

/// Smallest folder a summary keeps a row for.
pub const FOLDER_FLOOR: u64 = 100 * 1024 * 1024;

/// One folder, as a summary keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderTotal {
    pub path: String,
    /// What it holds, everything beneath it included.
    pub bytes: u64,
    /// Files anywhere beneath it.
    pub files: u64,
}

/// Every folder of a drive holding `floor` bytes or more, largest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderList {
    /// Every folder holding this much or more is listed, so a folder that is
    /// not listed held less. [`FOLDER_FLOOR`], unless the list was cut to fit
    /// in one reply, when it is higher: see [`fit`].
    pub floor: u64,
    pub folders: Vec<FolderTotal>,
    /// Folders of the floor or more that sit too many folders deep for their
    /// path to be rebuilt, so they could not be named.
    #[serde(default)]
    pub unplaced: u64,
}

/// Every folder on an indexed drive holding [`FOLDER_FLOOR`] or more.
pub fn from_index(index: &VolumeIndex, root_label: &str) -> FolderList {
    let files = files_beneath(index);
    let mut folders = Vec::new();
    let mut unplaced = 0;
    for (record, entry) in index.entries() {
        if !entry.is_directory || *record == index.root() {
            continue;
        }
        let bytes = index.total_of(*record);
        if bytes < FOLDER_FLOOR {
            continue;
        }
        let Some(path) = index.path_of(*record, root_label) else {
            unplaced += 1;
            continue;
        };
        folders.push(FolderTotal {
            path,
            bytes,
            files: files.get(record).copied().unwrap_or(0),
        });
    }
    largest_first(&mut folders);
    FolderList {
        floor: FOLDER_FLOOR,
        folders,
        unplaced,
    }
}

/// How many files sit anywhere beneath each folder.
///
/// Bottom-up and without recursion, for the reason the index totals sizes
/// that way: a damaged table can hold a very deep chain of folders, and this
/// runs inside the service.
fn files_beneath(index: &VolumeIndex) -> HashMap<u32, u64> {
    let mut beneath: HashMap<u32, u64> = HashMap::new();
    let mut visited: HashSet<u32> = HashSet::new();
    let mut stack = vec![(index.root(), false)];
    visited.insert(index.root());
    while let Some((record, expanded)) = stack.pop() {
        if expanded {
            let below: u64 = index
                .directories_in(record)
                .iter()
                .map(|child| beneath.get(child).copied().unwrap_or(0))
                .sum();
            beneath.insert(record, index.direct_files_in(record) + below);
            continue;
        }
        stack.push((record, true));
        for child in index.directories_in(record) {
            if visited.insert(*child) {
                stack.push((*child, false));
            }
        }
    }
    beneath
}

/// Every folder in a walked tree holding [`FOLDER_FLOOR`] or more.
///
/// The tree must be the whole walk, before it is cut down to be sent: a
/// folder below where the map stops is still a folder that grew.
pub fn from_tree(root: &Node) -> FolderList {
    let mut folders = Vec::new();
    // A folder, how many of its folders have been finished, and the files
    // counted beneath it so far.
    let mut frames: Vec<(&Node, usize, u64)> = vec![(root, 0, root.files)];
    while let Some(frame) = frames.last_mut() {
        let (node, next) = (frame.0, frame.1);
        if let Some(child) = node.children.get(next) {
            frame.1 += 1;
            frames.push((child, 0, child.files));
            continue;
        }
        let Some((node, _, files)) = frames.pop() else {
            break;
        };
        if let Some(parent) = frames.last_mut() {
            parent.2 += files;
        }
        let is_root = frames.is_empty();
        if !is_root && !node.is_aggregate && node.bytes >= FOLDER_FLOOR {
            folders.push(FolderTotal {
                path: node.path.clone(),
                bytes: node.bytes,
                files,
            });
        }
    }
    largest_first(&mut folders);
    FolderList {
        floor: FOLDER_FLOOR,
        folders,
        unplaced: 0,
    }
}

/// Largest first, and by path between equals, so that the same drive gives
/// the same list twice.
fn largest_first(folders: &mut [FolderTotal]) {
    folders.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.path.cmp(&b.path)));
}

/// The list cut to what fits in `budget`, as `measure` counts a row, keeping
/// the largest folders.
///
/// The floor rises to match. Every folder the same size as the first one
/// left out goes too, so that the rule a summary keeps still holds: every
/// folder holding the floor or more is listed, and a folder that is not
/// listed held less than the floor. A comparison then knows what it can say
/// about a folder missing from a cut list, which a list that had simply lost
/// its tail would not let it.
pub fn fit(list: FolderList, budget: usize, measure: impl Fn(&FolderTotal) -> usize) -> FolderList {
    let mut used = 0_usize;
    let first_left_out = list.folders.iter().position(|folder| {
        used = used.saturating_add(measure(folder));
        used > budget
    });
    let Some(cut) = first_left_out.and_then(|index| list.folders.get(index)) else {
        return list;
    };
    let floor = cut.bytes.saturating_add(1);
    FolderList {
        floor,
        folders: list
            .folders
            .into_iter()
            .filter(|folder| folder.bytes >= floor)
            .collect(),
        unplaced: list.unplaced,
    }
}

/// One summary as it is listed to choose from, without its rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryHeader {
    pub id: i64,
    /// When it was kept, by the store's clock, as UTC in ISO form.
    pub taken_at: String,
    /// `C:`.
    pub drive: String,
    /// The volume's serial number, when it could be read.
    pub serial: Option<u32>,
    pub method: ScanMethod,
    pub total_bytes: u64,
    pub file_count: u64,
}

/// What became of the summary of a scan of a whole drive. Set by the agent,
/// which keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SummaryKept {
    Kept {
        id: i64,
        taken_at: String,
    },
    /// The scan stands, and this summary of it could not be kept, so it
    /// cannot be compared with later.
    NotKept {
        why: String,
    },
}

/// One folder that grew or shrank.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    pub path: String,
    /// What it held then. `None`: less than the floor.
    pub before: Option<u64>,
    /// What it holds now. `None`: less than the floor, gone included.
    pub after: Option<u64>,
    pub files_before: Option<u64>,
    pub files_after: Option<u64>,
    /// How much it grew or shrank by. Exact where both sizes are known.
    /// Where one side is under the floor, the least it can be, counted from
    /// one byte under the floor.
    pub by: u64,
    pub exact: bool,
}

/// What grew and what shrank between two summaries that can be compared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Differences {
    /// Folders are compared from this size up: the higher of the two floors.
    pub floor: u64,
    /// The later total less the earlier. Negative when the drive holds less.
    pub total_change: i64,
    /// Largest growth first.
    pub grew: Vec<Change>,
    /// Largest shrinkage first.
    pub shrank: Vec<Change>,
    /// The smallest changes, left out of the lists to fit one reply.
    #[serde(default)]
    pub grew_left_out: u64,
    #[serde(default)]
    pub shrank_left_out: u64,
    /// Folders of the floor or more, in either summary, that sat too deep to
    /// be named and so are not compared.
    #[serde(default)]
    pub unplaced: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Comparison {
    /// No summary of this drive is kept for this person.
    NothingKept,
    /// One is, and there is nothing earlier to compare it with.
    NothingEarlier,
    /// There is, and it cannot be compared with this one, for this reason.
    NotComparable {
        why: String,
    },
    Compared(Differences),
}

/// What a person is sent about the summaries of one drive kept for them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Growth {
    pub drive: String,
    /// Every summary of the drive kept for this person, newest first.
    pub summaries: Vec<SummaryHeader>,
    /// The summary compared to.
    pub later: Option<SummaryHeader>,
    /// The summary compared with.
    pub earlier: Option<SummaryHeader>,
    pub comparison: Comparison,
}

/// The serial number as Windows prints it: `1A2B-3C4D`.
pub fn serial_text(serial: u32) -> String {
    format!("{:04X}-{:04X}", serial >> 16, serial & 0xFFFF)
}

/// Why two summaries cannot be compared, or `None` when they can.
pub fn incomparable(earlier: &SummaryHeader, later: &SummaryHeader) -> Option<String> {
    if !earlier.drive.eq_ignore_ascii_case(&later.drive) {
        return Some(format!(
            "The two are of different drives, {} and {}, so they are not compared.",
            earlier.drive, later.drive
        ));
    }
    match (earlier.serial, later.serial) {
        (Some(then), Some(now)) if then != now => {
            return Some(format!(
                "The drive in {} had a different serial number at the earlier scan \
                 ({} then, {} now). A drive that has been replaced or formatted is a \
                 different drive, so the two are not compared.",
                later.drive,
                serial_text(then),
                serial_text(now)
            ));
        }
        (Some(_), Some(_)) => {}
        _ => {
            return Some(
                "The drive's serial number could not be read at one of the two scans, so \
                 whether they are of the same drive cannot be told, and they are not \
                 compared."
                    .to_owned(),
            );
        }
    }
    if earlier.method != later.method {
        return Some(
            "One of the two scans read the drive's file table and the other walked its \
             folders. A walk counts a file with several names once for each name and the \
             file table counts it once, so the two can differ with nothing having \
             changed. They are not compared."
                .to_owned(),
        );
    }
    None
}

/// What grew and what shrank from `earlier` to `later`.
pub fn compare(
    earlier: (&SummaryHeader, &FolderList),
    later: (&SummaryHeader, &FolderList),
) -> Comparison {
    if let Some(why) = incomparable(earlier.0, later.0) {
        return Comparison::NotComparable { why };
    }
    let floor = earlier.1.floor.max(later.1.floor);
    let keyed = |list: &FolderList| -> HashMap<String, FolderTotal> {
        list.folders
            .iter()
            .filter(|folder| folder.bytes >= floor)
            .map(|folder| (folder.path.to_lowercase(), folder.clone()))
            .collect()
    };
    let before = keyed(earlier.1);
    let after = keyed(later.1);
    // What a folder under the floor can have held, at most.
    let under = floor.saturating_sub(1);

    let mut grew = Vec::new();
    let mut shrank = Vec::new();
    for (key, now) in &after {
        match before.get(key) {
            Some(then) if now.bytes > then.bytes => {
                grew.push(change(Some(then), Some(now), now.bytes - then.bytes, true));
            }
            Some(then) if now.bytes < then.bytes => {
                shrank.push(change(Some(then), Some(now), then.bytes - now.bytes, true));
            }
            Some(_) => {}
            None => grew.push(change(None, Some(now), now.bytes - under, false)),
        }
    }
    for (key, then) in &before {
        if !after.contains_key(key) {
            shrank.push(change(Some(then), None, then.bytes - under, false));
        }
    }
    let by_size = |a: &Change, b: &Change| b.by.cmp(&a.by).then_with(|| a.path.cmp(&b.path));
    grew.sort_by(by_size);
    shrank.sort_by(by_size);

    let total = |bytes: u64| i64::try_from(bytes).unwrap_or(i64::MAX);
    Comparison::Compared(Differences {
        floor,
        total_change: total(later.0.total_bytes) - total(earlier.0.total_bytes),
        grew,
        shrank,
        grew_left_out: 0,
        shrank_left_out: 0,
        unplaced: earlier.1.unplaced + later.1.unplaced,
    })
}

fn change(then: Option<&FolderTotal>, now: Option<&FolderTotal>, by: u64, exact: bool) -> Change {
    Change {
        // As the drive spells it now, or as it was spelled when it was last
        // seen holding the floor or more.
        path: now
            .or(then)
            .map(|folder| folder.path.clone())
            .unwrap_or_default(),
        before: then.map(|folder| folder.bytes),
        after: now.map(|folder| folder.bytes),
        files_before: then.map(|folder| folder.files),
        files_after: now.map(|folder| folder.files),
        by,
        exact,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::index::testing::Drive;

    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * MB;

    fn row(path: &str, bytes: u64, files: u64) -> FolderTotal {
        FolderTotal {
            path: path.to_owned(),
            bytes,
            files,
        }
    }

    fn header(id: i64, method: ScanMethod, serial: Option<u32>, total: u64) -> SummaryHeader {
        SummaryHeader {
            id,
            taken_at: format!("2026-11-{:02}T12:00:00.000Z", id),
            drive: "C:".to_owned(),
            serial,
            method,
            total_bytes: total,
            file_count: 1_000,
        }
    }

    fn list(folders: Vec<FolderTotal>) -> FolderList {
        FolderList {
            floor: FOLDER_FLOOR,
            folders,
            unplaced: 0,
        }
    }

    fn compared(comparison: Comparison) -> Differences {
        match comparison {
            Comparison::Compared(differences) => differences,
            other => panic!("not compared: {other:?}"),
        }
    }

    const TABLE: ScanMethod = ScanMethod::MasterFileTable;
    const WALK: ScanMethod = ScanMethod::DirectoryWalk;

    /// A made-up drive with large folders at every depth, the deepest well
    /// below where the map stops, and small ones beside them.
    fn drive() -> VolumeIndex {
        let mut drive = Drive::new();
        let cache = r"Users\someone\AppData\Local\NVIDIA\DXCache";
        drive.file(&format!(r"{cache}\a.bin"), 300 * MB, 0);
        drive.file(&format!(r"{cache}\b.bin"), 200 * MB, 0);
        drive.file(r"Users\someone\AppData\Local\NVIDIA\note.txt", 10, 0);
        drive.file(r"Users\someone\AppData\Local\tiny\x.bin", 50 * MB, 0);
        drive.file(r"Users\someone\Documents\small.txt", 1_000, 0);
        drive.file(r"Windows\big.bin", 150 * MB, 0);
        drive.file(r"Windows\System32\under.dll", 99 * MB, 0);
        drive.index()
    }

    /// Every folder of the floor or more is kept, at any depth, with what it
    /// holds and how many files are beneath it, and nothing smaller is.
    #[test]
    fn every_folder_of_the_floor_or_more_is_kept_with_the_files_beneath_it() {
        let index = drive();
        let list = from_index(&index, r"C:\");
        let rows: Vec<(&str, u64, u64)> = list
            .folders
            .iter()
            .map(|folder| (folder.path.as_str(), folder.bytes / MB, folder.files))
            .collect();
        // Largest first, and by path between folders of the same size. The
        // tiny folder, Documents and System32 are under the floor.
        assert_eq!(
            rows,
            vec![
                (r"C:\Users", 550, 5),
                (r"C:\Users\someone", 550, 5),
                (r"C:\Users\someone\AppData", 550, 4),
                (r"C:\Users\someone\AppData\Local", 550, 4),
                (r"C:\Users\someone\AppData\Local\NVIDIA", 500, 3),
                (r"C:\Users\someone\AppData\Local\NVIDIA\DXCache", 500, 2),
                (r"C:\Windows", 249, 2),
            ]
        );
        assert_eq!(list.floor, FOLDER_FLOOR);
        assert_eq!(list.unplaced, 0);
        // The drive itself is the summary's total, not a row of it.
        assert!(list.folders.iter().all(|folder| folder.path != r"C:\"));
        // Every folder above a listed one is listed: each holds at least as
        // much.
        for folder in &list.folders {
            if let Some((parent, _)) = folder.path.rsplit_once('\\') {
                if parent.len() > 2 {
                    assert!(
                        list.folders.iter().any(|other| other.path == parent),
                        "{} is listed and {parent} is not",
                        folder.path
                    );
                }
            }
        }
    }

    fn folder(name: &str, path: &str, bytes: u64, files: u64, children: Vec<Node>) -> Node {
        Node {
            name: name.to_owned(),
            path: path.to_owned(),
            bytes,
            files,
            children,
            is_aggregate: false,
            folded: false,
        }
    }

    /// A drive that had to be walked gives its rows from the whole walk, the
    /// folders below where the map stops included.
    #[test]
    fn a_walked_drive_gives_every_folder_of_the_floor_or_more_from_the_whole_walk() {
        let deep = folder(r"e", r"C:\a\b\c\d\e", 400 * MB, 4, Vec::new());
        let d = folder("d", r"C:\a\b\c\d", 400 * MB, 0, vec![deep]);
        let c = folder("c", r"C:\a\b\c", 400 * MB, 1, vec![d]);
        let small = folder("small", r"C:\a\small", 5 * MB, 7, Vec::new());
        let b = folder("b", r"C:\a\b", 400 * MB, 0, vec![c]);
        let a = folder("a", r"C:\a", 405 * MB, 2, vec![b, small]);
        let root = folder(r"C:\", r"C:\", 405 * MB, 1, vec![a]);

        let list = from_tree(&root);
        let rows: Vec<(&str, u64)> = list
            .folders
            .iter()
            .map(|folder| (folder.path.as_str(), folder.files))
            .collect();
        assert_eq!(
            rows,
            vec![
                (r"C:\a", 14),
                (r"C:\a\b", 5),
                (r"C:\a\b\c", 5),
                (r"C:\a\b\c\d", 4),
                (r"C:\a\b\c\d\e", 4),
            ]
        );
    }

    /// A list cut to fit keeps its largest folders and raises its floor, so
    /// that a folder it does not list still held less than its floor.
    #[test]
    fn a_list_cut_to_fit_raises_its_floor_so_a_folder_not_listed_was_still_under_it() {
        let whole = list(vec![
            row(r"C:\a", 900 * MB, 1),
            row(r"C:\b", 800 * MB, 1),
            row(r"C:\c", 700 * MB, 1),
            row(r"C:\d", 700 * MB, 1),
            row(r"C:\e", 600 * MB, 1),
        ]);
        // Every row counts ten, so three fit in thirty.
        let cut = fit(whole.clone(), 30, |_| 10);
        assert_eq!(cut.floor, 700 * MB + 1);
        let kept: Vec<&str> = cut
            .folders
            .iter()
            .map(|folder| folder.path.as_str())
            .collect();
        // C:\c would have fitted. It goes with C:\d, which is the same size,
        // or C:\d would be "under the floor" at the size of a listed folder.
        assert_eq!(kept, vec![r"C:\a", r"C:\b"]);

        assert_eq!(fit(whole.clone(), 50, |_| 10), whole, "it all fits");
    }

    /// A folder missing from the older summary was under the floor then. It
    /// is not new, and what it grew by is the least it can have grown by.
    #[test]
    fn a_folder_missing_from_the_older_summary_was_under_the_floor_then_and_is_not_new() {
        let earlier = list(vec![row(r"C:\Users", 10 * GB, 100)]);
        let later = list(vec![
            row(r"C:\Users", 15 * GB, 140),
            row(r"C:\Users\someone\models", 5 * GB, 40),
        ]);
        let differences = compared(compare(
            (&header(1, TABLE, Some(7), 20 * GB), &earlier),
            (&header(2, TABLE, Some(7), 25 * GB), &later),
        ));

        let models = differences
            .grew
            .iter()
            .find(|change| change.path.ends_with("models"))
            .unwrap();
        assert_eq!(models.before, None, "under the floor then, not zero");
        assert_eq!(models.after, Some(5 * GB));
        assert!(!models.exact);
        assert_eq!(models.by, 5 * GB - (FOLDER_FLOOR - 1));
    }

    /// A folder missing from the newer summary is under the floor now, which
    /// is all that is known: not that it was deleted.
    #[test]
    fn a_folder_missing_from_the_newer_summary_is_under_the_floor_now_and_not_said_to_be_deleted() {
        let earlier = list(vec![row(r"C:\Games\Old", 30 * GB, 900)]);
        let later = list(Vec::new());
        let differences = compared(compare(
            (&header(1, TABLE, Some(7), 100 * GB), &earlier),
            (&header(2, TABLE, Some(7), 70 * GB), &later),
        ));
        assert!(differences.grew.is_empty());
        let gone = &differences.shrank[0];
        assert_eq!((gone.before, gone.after), (Some(30 * GB), None));
        assert_eq!(gone.files_after, None);
        assert_eq!(gone.by, 30 * GB - (FOLDER_FLOOR - 1));
        assert!(!gone.exact);
    }

    /// Where both sizes are known, what a folder grew or shrank by is exact,
    /// a folder that did not change is in neither list, and the total's
    /// change keeps its sign.
    #[test]
    fn growth_and_shrinkage_are_exact_where_both_sizes_are_known() {
        let earlier = list(vec![
            row(r"C:\Users", 50 * GB, 1_000),
            row(r"C:\Windows", 30 * GB, 9_000),
            row(r"C:\Program Files", 20 * GB, 4_000),
        ]);
        let later = list(vec![
            row(r"C:\Users", 89 * GB, 1_500),
            row(r"C:\Windows", 30 * GB, 9_000),
            row(r"C:\Program Files", 12 * GB, 3_000),
        ]);
        let differences = compared(compare(
            (&header(1, TABLE, Some(7), 855 * GB), &earlier),
            (&header(2, TABLE, Some(7), 994 * GB), &later),
        ));
        assert_eq!(differences.total_change, (139 * GB) as i64);
        assert_eq!(differences.floor, FOLDER_FLOOR);

        assert_eq!(differences.grew.len(), 1);
        let users = &differences.grew[0];
        assert_eq!(users.path, r"C:\Users");
        assert_eq!((users.by, users.exact), (39 * GB, true));
        assert_eq!(
            (users.files_before, users.files_after),
            (Some(1_000), Some(1_500))
        );

        assert_eq!(differences.shrank.len(), 1);
        assert_eq!(differences.shrank[0].by, 8 * GB);

        let back = compared(compare(
            (&header(2, TABLE, Some(7), 994 * GB), &later),
            (&header(3, TABLE, Some(7), 855 * GB), &earlier),
        ));
        assert_eq!(back.total_change, -((139 * GB) as i64));
    }

    /// A summary compared with itself has nothing to say.
    #[test]
    fn a_summary_compared_with_one_of_the_same_drive_as_it_was_shows_no_change() {
        let same = list(vec![row(r"C:\Users", 50 * GB, 1_000)]);
        let differences = compared(compare(
            (&header(1, TABLE, Some(7), 80 * GB), &same),
            (&header(2, TABLE, Some(7), 80 * GB), &same),
        ));
        assert!(differences.grew.is_empty() && differences.shrank.is_empty());
        assert_eq!(differences.total_change, 0);
    }

    /// The same folder is the same folder however it is spelled: Windows
    /// does not tell names apart by case.
    #[test]
    fn folders_are_matched_without_regard_to_case() {
        let earlier = list(vec![row(r"C:\Users\Someone", 10 * GB, 10)]);
        let later = list(vec![row(r"C:\users\someone", 12 * GB, 12)]);
        let differences = compared(compare(
            (&header(1, TABLE, Some(7), 10 * GB), &earlier),
            (&header(2, TABLE, Some(7), 12 * GB), &later),
        ));
        assert_eq!(differences.grew.len(), 1);
        assert!(differences.grew[0].exact);
        assert!(differences.shrank.is_empty());
    }

    /// A table read and a walk count a file with several names differently,
    /// so they are never compared, and the reason is said.
    #[test]
    fn a_table_read_and_a_walk_are_never_compared() {
        let rows = list(vec![row(r"C:\Windows", 30 * GB, 9_000)]);
        for (then, now) in [(TABLE, WALK), (WALK, TABLE)] {
            let Comparison::NotComparable { why } = compare(
                (&header(1, then, Some(7), 80 * GB), &rows),
                (&header(2, now, Some(7), 95 * GB), &rows),
            ) else {
                panic!("a table read was compared with a walk");
            };
            assert!(why.contains("several names"), "{why}");
        }
        // Two walks are compared.
        assert!(matches!(
            compare(
                (&header(1, WALK, Some(7), 80 * GB), &rows),
                (&header(2, WALK, Some(7), 95 * GB), &rows),
            ),
            Comparison::Compared(_)
        ));
    }

    /// A different serial number is a different drive, whatever its letter,
    /// and a serial number that could not be read is not taken for the same.
    #[test]
    fn a_different_serial_number_is_a_different_drive_and_an_unknown_one_is_not_the_same() {
        let rows = list(vec![row(r"C:\Windows", 30 * GB, 9_000)]);
        let Comparison::NotComparable { why } = compare(
            (&header(1, TABLE, Some(0x1A2B_3C4D), 80 * GB), &rows),
            (&header(2, TABLE, Some(0x5E6F_7A8B), 95 * GB), &rows),
        ) else {
            panic!("two drives were compared");
        };
        assert!(why.contains("1A2B-3C4D then, 5E6F-7A8B now"), "{why}");

        for (then, now) in [(None, Some(7)), (Some(7), None), (None, None)] {
            let Comparison::NotComparable { why } = compare(
                (&header(1, TABLE, then, 80 * GB), &rows),
                (&header(2, TABLE, now, 95 * GB), &rows),
            ) else {
                panic!("an unknown serial number was taken for the same drive");
            };
            assert!(why.contains("could not be read"), "{why}");
        }
    }

    /// Two summaries with different floors are compared from the higher, so
    /// that a folder missing from either still says something true.
    #[test]
    fn summaries_with_different_floors_are_compared_from_the_higher_one() {
        // The earlier list was cut: it lists 300 MB and up.
        let earlier = FolderList {
            floor: 300 * MB,
            folders: vec![row(r"C:\Big", 2 * GB, 10)],
            unplaced: 0,
        };
        // 200 MB now, and anything up to 300 MB then: it may have shrunk.
        let later = list(vec![
            row(r"C:\Big", 3 * GB, 12),
            row(r"C:\Middling", 200 * MB, 3),
        ]);
        let differences = compared(compare(
            (&header(1, TABLE, Some(7), 10 * GB), &earlier),
            (&header(2, TABLE, Some(7), 11 * GB), &later),
        ));
        assert_eq!(differences.floor, 300 * MB);
        assert_eq!(differences.grew.len(), 1, "{:?}", differences.grew);
        assert_eq!(differences.grew[0].path, r"C:\Big");
        assert!(differences.shrank.is_empty(), "{:?}", differences.shrank);
    }

    /// The reasons given are a person's to read: plain words, no dashes, and
    /// nothing that judges a change.
    #[test]
    fn what_a_comparison_says_is_plain_and_judges_nothing() {
        let a = header(1, TABLE, Some(1), 1);
        let reasons = [
            incomparable(&a, &header(2, WALK, Some(1), 1)),
            incomparable(&a, &header(2, TABLE, Some(2), 1)),
            incomparable(&a, &header(2, TABLE, None, 1)),
            incomparable(
                &a,
                &SummaryHeader {
                    drive: "D:".to_owned(),
                    ..header(2, TABLE, Some(1), 1)
                },
            ),
        ];
        for why in reasons {
            let why = why.expect("a reason");
            assert!(!why.contains(['\u{2014}', '\u{2013}']), "a dash: {why}");
            for word in ["unusual", "suspicious", "safe", "problem"] {
                assert!(!why.to_lowercase().contains(word), "{word}: {why}");
            }
        }
        assert_eq!(serial_text(0x0000_00FF), "0000-00FF");
    }
}
