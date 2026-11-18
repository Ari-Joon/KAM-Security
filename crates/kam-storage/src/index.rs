//! A queryable view over a master file table snapshot.
//!
//! The raw snapshot is a flat map of record numbers. Almost every question
//! worth asking of it — how big is this folder, what is inside it — needs the
//! parent/child structure reassembled and every directory totalled first. Doing
//! that once and sharing it means a scan and an application footprint cost one
//! read of the volume between them rather than one each.

use std::collections::{HashMap, HashSet};

use crate::mft::{MftEntry, MftSnapshot};

#[derive(Debug)]
pub struct VolumeIndex {
    snapshot: MftSnapshot,
    /// Record numbers of the directories inside each directory.
    directories: HashMap<u32, Vec<u32>>,
    /// Every child, directories and files alike.
    children: HashMap<u32, Vec<u32>>,
    /// Total bytes beneath each directory, including all descendants.
    totals: HashMap<u32, u64>,
    /// Files sitting directly in each directory.
    direct_files: HashMap<u32, u64>,
    /// The newest last-write time anywhere beneath each directory, its own
    /// included, as a Windows FILETIME.
    newest_writes: HashMap<u32, u64>,
    file_count: u64,
    directory_count: u64,
    total_bytes: u64,
}

impl VolumeIndex {
    pub fn build(snapshot: MftSnapshot) -> Self {
        let mut children: HashMap<u32, Vec<u32>> =
            HashMap::with_capacity(snapshot.entries.len() / 4);
        let mut directories: HashMap<u32, Vec<u32>> = HashMap::new();
        let mut file_count = 0_u64;
        let mut directory_count = 0_u64;
        let mut total_bytes = 0_u64;

        for (index, entry) in &snapshot.entries {
            if entry.is_directory {
                directory_count += 1;
            } else {
                file_count += 1;
                total_bytes += entry.bytes;
            }
            // The root names itself as its parent; recording that edge would
            // make the tree contain itself.
            if *index != snapshot.root {
                children.entry(entry.parent).or_default().push(*index);
                if entry.is_directory {
                    directories.entry(entry.parent).or_default().push(*index);
                }
            }
        }

        let Totalled {
            totals,
            direct_files,
            newest_writes,
        } = total_directories(&snapshot, &children);

        Self {
            snapshot,
            directories,
            children,
            totals,
            direct_files,
            newest_writes,
            file_count,
            directory_count,
            total_bytes,
        }
    }

    pub fn root(&self) -> u32 {
        self.snapshot.root
    }

    /// The drive this index describes, as an upper-case letter.
    pub fn drive(&self) -> char {
        self.snapshot.drive
    }

    /// Whether a path is on the drive this index describes.
    ///
    /// A question about the path's spelling only. Whether anything is there
    /// is what [`Self::resolve`] answers.
    pub fn covers(&self, path: &str) -> bool {
        components_on(self.snapshot.drive, path).is_some()
    }

    pub fn entries(&self) -> &HashMap<u32, MftEntry> {
        &self.snapshot.entries
    }

    pub fn entry(&self, index: u32) -> Option<&MftEntry> {
        self.snapshot.entries.get(&index)
    }

    pub fn children_of(&self, index: u32) -> &[u32] {
        self.children.get(&index).map_or(&[], Vec::as_slice)
    }

    pub fn directories_in(&self, index: u32) -> &[u32] {
        self.directories.get(&index).map_or(&[], Vec::as_slice)
    }

    pub fn total_of(&self, index: u32) -> u64 {
        self.totals.get(&index).copied().unwrap_or(0)
    }

    pub fn direct_files_in(&self, index: u32) -> u64 {
        self.direct_files.get(&index).copied().unwrap_or(0)
    }

    /// When anything in a directory was last written, as a Windows FILETIME:
    /// the newest last-write time of the directory and of every file and
    /// folder beneath it. Zero when none of them carries one.
    ///
    /// # Why not the directory's own time
    ///
    /// Windows moves a folder's own last-write time only when something
    /// directly inside it is added, removed or renamed. A program that keeps
    /// writing to the same files several levels down leaves its top folder
    /// looking untouched for years. Measured on the development machine: of 99
    /// top-level data folders with an own date over 180 days old, 13 held a
    /// file written in the last 30 days.
    ///
    /// Every folder's own time is counted as well as every file's, because a
    /// file that arrives carrying an old date (unpacked from an archive, or
    /// copied) still moves the time of the folder it lands in.
    ///
    /// The table read already holds all of these, so this costs one more
    /// comparison per record in the pass that totals sizes, and one number
    /// kept per folder.
    pub fn newest_write_in(&self, index: u32) -> u64 {
        self.newest_writes.get(&index).copied().unwrap_or(0)
    }

    pub fn file_count(&self) -> u64 {
        self.file_count
    }

    pub fn directory_count(&self) -> u64 {
        self.directory_count
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub fn skipped(&self) -> u64 {
        self.snapshot.skipped
    }

    /// Find the record for a path, which may name a file or a directory.
    ///
    /// Matching is case-insensitive because NTFS is.
    ///
    /// # Only a path on this drive has an answer
    ///
    /// This used to drop the drive letter, on the reasoning that an index only
    /// ever covers one volume. The paths it is asked about do not: the caller's
    /// ProgramData and AppData, and every install location in the registry,
    /// name the drive they are really on. So measuring `D:` looked up
    /// `C:\ProgramData` and `C:\Users\someone\AppData` by name on `D:`, and on
    /// a second disk that still holds an earlier Windows those folders exist.
    /// Their sizes and dates were then shown against the `C:` paths, a leftover
    /// read "nothing has written to it in 2.5 years" on the strength of the old
    /// disk, and Quarantine acted on the folder of that name on `C:`, which
    /// was in use.
    ///
    /// A path on another drive, a network path, and a path that does not say
    /// which drive it is on all resolve to nothing.
    pub fn resolve(&self, path: &str) -> Option<u32> {
        let mut current = self.snapshot.root;
        for component in components_on(self.snapshot.drive, path)? {
            let wanted = component.to_lowercase();
            let next = self
                .children_of(current)
                .iter()
                .find(|index| {
                    self.snapshot
                        .entries
                        .get(index)
                        .is_some_and(|entry| entry.name.to_lowercase() == wanted)
                })
                .copied()?;
            current = next;
        }
        Some(current)
    }

    /// Rebuild the full path of a record by walking parent references.
    ///
    /// Bounded: a corrupted parent chain could otherwise loop forever, and this
    /// runs inside a privileged process.
    pub fn path_of(&self, index: u32, root_label: &str) -> Option<String> {
        let mut parts: Vec<&str> = Vec::new();
        let mut current = index;
        for _ in 0..64 {
            if current == self.snapshot.root {
                let mut path = root_label.trim_end_matches(['\\', '/']).to_owned();
                for part in parts.iter().rev() {
                    path.push('\\');
                    path.push_str(part);
                }
                return Some(path);
            }
            let entry = self.entry(current)?;
            parts.push(&entry.name);
            current = entry.parent;
        }
        None
    }

    /// Total bytes beneath a path, or the file's own size.
    pub fn size_of(&self, path: &str) -> Option<u64> {
        let index = self.resolve(path)?;
        let entry = self.entry(index)?;
        Some(if entry.is_directory {
            self.total_of(index)
        } else {
            entry.bytes
        })
    }
}

/// What one bottom-up pass over the tree works out for every directory.
struct Totalled {
    totals: HashMap<u32, u64>,
    direct_files: HashMap<u32, u64>,
    newest_writes: HashMap<u32, u64>,
}

/// Total every directory bottom-up.
///
/// Iterative rather than recursive: a corrupted parent reference can produce a
/// cycle or a very deep chain, and neither should be able to blow the stack of
/// a process running as SYSTEM.
fn total_directories(snapshot: &MftSnapshot, children: &HashMap<u32, Vec<u32>>) -> Totalled {
    let mut totals: HashMap<u32, u64> = HashMap::new();
    let mut direct_files: HashMap<u32, u64> = HashMap::new();
    let mut newest_writes: HashMap<u32, u64> = HashMap::new();
    let mut visited: HashSet<u32> = HashSet::with_capacity(snapshot.entries.len());
    let mut stack: Vec<(u32, bool)> = vec![(snapshot.root, false)];
    visited.insert(snapshot.root);

    while let Some((index, expanded)) = stack.pop() {
        if expanded {
            let mut sum = 0_u64;
            let mut files_here = 0_u64;
            let mut newest = snapshot
                .entries
                .get(&index)
                .map_or(0, |entry| entry.modified);
            for child in children.get(&index).map_or(&[][..], Vec::as_slice) {
                match snapshot.entries.get(child) {
                    Some(entry) if entry.is_directory => {
                        sum += totals.get(child).copied().unwrap_or(0);
                        newest = newest.max(newest_writes.get(child).copied().unwrap_or(0));
                    }
                    Some(entry) => {
                        sum += entry.bytes;
                        files_here += 1;
                        newest = newest.max(entry.modified);
                    }
                    None => {}
                }
            }
            totals.insert(index, sum);
            direct_files.insert(index, files_here);
            newest_writes.insert(index, newest);
            continue;
        }

        stack.push((index, true));
        for child in children.get(&index).map_or(&[][..], Vec::as_slice) {
            let is_directory = snapshot
                .entries
                .get(child)
                .is_some_and(|entry| entry.is_directory);
            if is_directory && visited.insert(*child) {
                stack.push((*child, false));
            }
        }
    }

    Totalled {
        totals,
        direct_files,
        newest_writes,
    }
}

/// The names along `path`, below the root of drive `drive`.
///
/// `None` unless the path is absolute and on that drive. That leaves out a
/// path on another drive, a network path (`\\server\share`, with or without
/// the extended-length prefix), and `C:folder`, which Windows reads against
/// whatever the current directory on `C:` happens to be.
fn components_on(drive: char, path: &str) -> Option<impl Iterator<Item = &str>> {
    let text = [r"\\?\", r"\??\"]
        .iter()
        .find_map(|prefix| path.strip_prefix(prefix))
        .unwrap_or(path);

    let mut characters = text.chars();
    let letter = characters.next()?;
    if !letter.is_ascii_alphabetic() || characters.next() != Some(':') {
        return None;
    }
    if !letter.eq_ignore_ascii_case(&drive) {
        return None;
    }
    // Both were ASCII, so the rest starts two bytes in.
    let rest = text.get(2..)?;
    if !(rest.is_empty() || rest.starts_with(['\\', '/'])) {
        return None;
    }
    Some(rest.split(['\\', '/']).filter(|part| !part.is_empty()))
}

/// A made-up drive, for tests that need an index without a disk to read.
///
/// Built by path, so a test says what is on the drive the way a person would
/// and the record numbers and parent references take care of themselves.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub(crate) mod testing {
    use super::*;

    /// Seconds between 1601 and 1970, for turning a date into a FILETIME.
    const FILETIME_EPOCH_OFFSET: u64 = 11_644_473_600;

    /// The moment the made-up drive is looked at, in Unix seconds.
    pub(crate) const NOW: u64 = 1_800_000_000;

    /// The FILETIME of a moment some whole days before [`NOW`].
    pub(crate) fn days_ago(days: u64) -> u64 {
        (NOW - days * 86_400 + FILETIME_EPOCH_OFFSET) * 10_000_000
    }

    pub(crate) struct Drive {
        letter: char,
        entries: HashMap<u32, MftEntry>,
        next: u32,
    }

    impl Drive {
        /// A made-up `C:`.
        pub(crate) fn new() -> Self {
            Self::lettered('C')
        }

        /// A made-up drive with a letter of its own, for what goes wrong when
        /// there is more than one.
        pub(crate) fn lettered(letter: char) -> Self {
            let mut entries = HashMap::new();
            entries.insert(5, entry(".", 5, true, 0, 0));
            Self {
                letter,
                entries,
                next: 100,
            }
        }

        fn child(&self, parent: u32, name: &str) -> Option<u32> {
            self.entries
                .iter()
                .find(|(record, entry)| {
                    **record != 5 && entry.parent == parent && entry.name == name
                })
                .map(|(record, _)| *record)
        }

        fn add(&mut self, parent: u32, name: &str, is_directory: bool, bytes: u64) -> u32 {
            let record = self.next;
            self.next += 1;
            self.entries
                .insert(record, entry(name, parent, is_directory, bytes, 0));
            record
        }

        /// The folder at `path`, made along with any folder above it that is
        /// not there yet. `path` has no drive letter: `Users\someone`.
        pub(crate) fn folder(&mut self, path: &str) -> u32 {
            let mut current = 5;
            for name in path.split('\\').filter(|part| !part.is_empty()) {
                current = match self.child(current, name) {
                    Some(record) => record,
                    None => self.add(current, name, true, 0),
                };
            }
            current
        }

        /// A folder whose own last-write time is `modified`.
        pub(crate) fn folder_written(&mut self, path: &str, modified: u64) -> u32 {
            let record = self.folder(path);
            self.entries.get_mut(&record).unwrap().modified = modified;
            record
        }

        /// A file of `bytes` at `path`, last written at `modified`.
        pub(crate) fn file(&mut self, path: &str, bytes: u64, modified: u64) -> u32 {
            let (folder, name) = path.rsplit_once('\\').unwrap_or(("", path));
            let parent = self.folder(folder);
            let record = self.add(parent, name, false, bytes);
            self.entries.get_mut(&record).unwrap().modified = modified;
            record
        }

        pub(crate) fn index(self) -> VolumeIndex {
            VolumeIndex::build(MftSnapshot {
                drive: self.letter,
                entries: self.entries,
                root: 5,
                skipped: 0,
                stats: Default::default(),
            })
        }
    }

    fn entry(name: &str, parent: u32, is_directory: bool, bytes: u64, modified: u64) -> MftEntry {
        MftEntry {
            parent,
            name: name.to_owned(),
            is_directory,
            bytes,
            modified,
            created: 0,
            accessed: 0,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn snapshot() -> MftSnapshot {
        // root(5)
        //   Windows(6)      [dir]
        //     notepad.exe(7)  1000
        //   Users(8)        [dir]
        //     akcar(9)      [dir]
        //       big.bin(10)  5000
        let mut entries = HashMap::new();
        let directory = |name: &str, parent: u32| MftEntry {
            parent,
            name: name.to_owned(),
            is_directory: true,
            bytes: 0,
            modified: 0,
            created: 0,
            accessed: 0,
        };
        let file = |name: &str, parent: u32, bytes: u64| MftEntry {
            parent,
            name: name.to_owned(),
            is_directory: false,
            bytes,
            modified: 0,
            created: 0,
            accessed: 0,
        };
        entries.insert(5, directory(".", 5));
        entries.insert(6, directory("Windows", 5));
        entries.insert(7, file("notepad.exe", 6, 1000));
        entries.insert(8, directory("Users", 5));
        entries.insert(9, directory("akcar", 8));
        entries.insert(10, file("big.bin", 9, 5000));

        MftSnapshot {
            drive: 'C',
            entries,
            root: 5,
            skipped: 0,
            stats: Default::default(),
        }
    }

    /// A folder on one drive is not the folder of that name on another.
    ///
    /// The test that was missing. The index dropped the drive letter, so on an
    /// index of `C:` the path `D:\Users` found `C:\Users`, and the other way
    /// round: measuring a second drive showed its folders' sizes and dates
    /// against `C:` paths, and Quarantine then acted on the `C:` path.
    #[test]
    fn a_path_on_another_drive_resolves_to_nothing() {
        let index = VolumeIndex::build(snapshot());
        assert_eq!(index.drive(), 'C');
        assert_eq!(index.size_of(r"C:\Users"), Some(5000));

        assert_eq!(index.size_of(r"D:\Users"), None);
        assert_eq!(index.size_of(r"d:\users\akcar"), None);
        assert_eq!(index.resolve(r"D:\"), None);
        assert!(!index.covers(r"D:\Users"));
        assert!(index.covers(r"C:\Nope"), "on the drive, though not there");
    }

    #[test]
    fn a_network_path_or_one_with_no_drive_resolves_to_nothing() {
        let index = VolumeIndex::build(snapshot());
        for path in [
            r"\\server\share\Users",
            r"\\?\UNC\server\share\Users",
            r"Users\akcar",
            r"\Users\akcar",
            // Drive-relative: Windows reads this against the current directory
            // on C:, whatever that is.
            r"C:Users",
            "",
        ] {
            assert_eq!(index.resolve(path), None, "{path} was given an answer");
            assert!(!index.covers(path), "{path} was taken as on this drive");
        }
    }

    #[test]
    fn the_extended_length_form_names_the_same_folder() {
        // It used to resolve to nothing: the prefix was stripped and the drive
        // letter was then looked for in the string that still had it.
        let index = VolumeIndex::build(snapshot());
        assert_eq!(index.size_of(r"\\?\C:\Users\akcar"), Some(5000));
        assert_eq!(index.size_of(r"\\?\D:\Users\akcar"), None);
        assert_eq!(index.resolve(r"C:\"), Some(index.root()));
        assert_eq!(index.resolve("C:"), Some(index.root()));
    }

    #[test]
    fn totals_roll_up_through_every_level() {
        let index = VolumeIndex::build(snapshot());
        assert_eq!(index.total_of(index.root()), 6000);
        assert_eq!(index.size_of(r"C:\Users").unwrap(), 5000);
        assert_eq!(index.size_of(r"C:\Users\akcar").unwrap(), 5000);
        assert_eq!(index.size_of(r"C:\Windows").unwrap(), 1000);
    }

    #[test]
    fn paths_resolve_regardless_of_case_or_separator() {
        let index = VolumeIndex::build(snapshot());
        assert_eq!(index.size_of(r"c:\users\AKCAR").unwrap(), 5000);
        assert_eq!(index.size_of("C:/Users/akcar").unwrap(), 5000);
        assert_eq!(index.size_of(r"C:\Users\akcar\").unwrap(), 5000);
    }

    #[test]
    fn a_file_reports_its_own_size_not_a_subtree() {
        let index = VolumeIndex::build(snapshot());
        assert_eq!(index.size_of(r"C:\Windows\notepad.exe").unwrap(), 1000);
    }

    #[test]
    fn a_path_that_is_not_there_is_none_rather_than_zero() {
        // Zero would read as "this application uses no space", which is a very
        // different claim from "this folder does not exist".
        let index = VolumeIndex::build(snapshot());
        assert!(index.size_of(r"C:\Nope").is_none());
        assert!(index.size_of(r"C:\Users\someone-else").is_none());
    }

    /// A folder is dated by the newest thing in it, however deep.
    ///
    /// `Users` here was itself last written at 100. One file two levels down
    /// was written at 900 and a folder between them at 300, and the question
    /// "when was anything in Users last written" has one answer: 900.
    #[test]
    fn the_newest_write_beneath_a_folder_is_found_at_any_depth() {
        let mut snapshot = snapshot();
        let mut dated = |record: u32, modified: u64| {
            snapshot.entries.get_mut(&record).unwrap().modified = modified;
        };
        dated(8, 100); // Users
        dated(9, 300); // Users\akcar
        dated(10, 900); // Users\akcar\big.bin
        dated(6, 500); // Windows
        dated(7, 200); // Windows\notepad.exe

        let index = VolumeIndex::build(snapshot);
        assert_eq!(index.newest_write_in(8), 900);
        assert_eq!(index.newest_write_in(9), 900);
        // A folder newer than everything in it answers with its own time: a
        // file arriving with an old date still moves the folder it lands in.
        assert_eq!(index.newest_write_in(6), 500);
        assert_eq!(index.newest_write_in(index.root()), 900);
    }

    #[test]
    fn a_folder_with_no_readable_times_has_no_newest_write() {
        // Zero is "not known" throughout, never 1601.
        let index = VolumeIndex::build(snapshot());
        assert_eq!(index.newest_write_in(8), 0);
        assert_eq!(index.newest_write_in(404), 0);
    }

    #[test]
    fn counts_separate_files_from_directories() {
        let index = VolumeIndex::build(snapshot());
        assert_eq!(index.file_count(), 2);
        // The root counts as a directory too.
        assert_eq!(index.directory_count(), 4);
        assert_eq!(index.total_bytes(), 6000);
    }
}
