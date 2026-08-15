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

        let (totals, direct_files) = total_directories(&snapshot, &children);

        Self {
            snapshot,
            directories,
            children,
            totals,
            direct_files,
            file_count,
            directory_count,
            total_bytes,
        }
    }

    pub fn root(&self) -> u32 {
        self.snapshot.root
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
    /// The drive letter is dropped: an index only ever covers one volume, and
    /// matching is case-insensitive because NTFS is.
    pub fn resolve(&self, path: &str) -> Option<u32> {
        let mut current = self.snapshot.root;
        for component in split_path(path) {
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

/// Total every directory bottom-up.
///
/// Iterative rather than recursive: a corrupted parent reference can produce a
/// cycle or a very deep chain, and neither should be able to blow the stack of
/// a process running as SYSTEM.
fn total_directories(
    snapshot: &MftSnapshot,
    children: &HashMap<u32, Vec<u32>>,
) -> (HashMap<u32, u64>, HashMap<u32, u64>) {
    let mut totals: HashMap<u32, u64> = HashMap::new();
    let mut direct_files: HashMap<u32, u64> = HashMap::new();
    let mut visited: HashSet<u32> = HashSet::with_capacity(snapshot.entries.len());
    let mut stack: Vec<(u32, bool)> = vec![(snapshot.root, false)];
    visited.insert(snapshot.root);

    while let Some((index, expanded)) = stack.pop() {
        if expanded {
            let mut sum = 0_u64;
            let mut files_here = 0_u64;
            for child in children.get(&index).map_or(&[][..], Vec::as_slice) {
                match snapshot.entries.get(child) {
                    Some(entry) if entry.is_directory => {
                        sum += totals.get(child).copied().unwrap_or(0);
                    }
                    Some(entry) => {
                        sum += entry.bytes;
                        files_here += 1;
                    }
                    None => {}
                }
            }
            totals.insert(index, sum);
            direct_files.insert(index, files_here);
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

    (totals, direct_files)
}

/// Split a path into components, dropping the drive letter and any separators.
fn split_path(path: &str) -> impl Iterator<Item = &str> {
    let trimmed = path
        .strip_prefix(r"\\?\")
        .unwrap_or(path)
        .trim_start_matches(|c: char| c.is_ascii_alphabetic() && path.get(1..2) == Some(":"));
    trimmed
        .split(['\\', '/'])
        .filter(|part| !part.is_empty() && *part != ":")
        .map(|part| part.trim_end_matches(':'))
        .filter(|part| !part.is_empty())
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
            entries,
            root: 5,
            skipped: 0,
            stats: Default::default(),
        }
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

    #[test]
    fn counts_separate_files_from_directories() {
        let index = VolumeIndex::build(snapshot());
        assert_eq!(index.file_count(), 2);
        // The root counts as a directory too.
        assert_eq!(index.directory_count(), 4);
        assert_eq!(index.total_bytes(), 6000);
    }
}
