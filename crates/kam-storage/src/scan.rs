//! Measuring where the space went, by either of two routes.
//!
//! [`scan`] picks between them. A whole NTFS volume is read from the master
//! file table by [`crate::mft`]; anything else — a subdirectory, a non-NTFS
//! volume, or a volume the process lacks the rights to open raw — is walked
//! directory by directory. Both produce the same [`Scan`], so nothing above
//! here has to care which ran.
//!
//! Measured on a 1 TB system drive with 1.4 million files:
//!
//! | | Master file table | Directory walk |
//! |---|---|---|
//! | Cold cache | 2.4 s | 57.8 s |
//! | Warm cache | 2.4 s | 15.2 s |
//! | Measured against the 1036.3 GB Windows reports | 99.6% | 97.6% |
//! | Needs elevation | yes | no |
//!
//! The walk benefits enormously from a warm filesystem cache and the table
//! barely notices one, because it is a single sequential read either way. The
//! fair comparison is the warm figure — still six times slower, and the cold
//! figure is what a user actually meets on the first scan after a reboot.
//!
//! The walk is slower *and* less accurate: it cannot open every directory, and
//! it counts a hard-linked file once per link, which on a Windows volume means
//! counting much of `WinSxS` several times over.
//!
//! # Correctness notes for the walk
//!
//! Reparse points are skipped. Windows is full of junctions that point back up
//! the tree — `C:\Documents and Settings` to `C:\Users`, `Application Data` to
//! itself — and following them both double-counts and loops forever.

use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use kam_core::Result;
use serde::{Deserialize, Serialize};

/// Levels of the tree returned to the caller. Deeper nodes are still measured;
/// they are just folded into their ancestor's total rather than transmitted.
pub const DEFAULT_MAX_DEPTH: usize = 4;
/// Largest children kept per level. The tail is summarised as one "other" node
/// so the totals still add up.
pub const DEFAULT_MAX_CHILDREN: usize = 14;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    /// Display name — the final path component, or the root itself at the top.
    pub name: String,
    pub path: String,
    /// Total size of this subtree.
    pub bytes: u64,
    /// Files directly in this directory, not including subdirectories.
    pub files: u64,
    pub children: Vec<Node>,
    /// True for the synthetic node standing in for the trimmed tail.
    #[serde(default)]
    pub is_aggregate: bool,
}

/// How a scan got its numbers. Shown in the UI, because a two-second answer and
/// a one-minute answer are different enough that the user should know which
/// they are looking at — and why, when the fast path was unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanMethod {
    /// Read straight out of the NTFS master file table.
    MasterFileTable,
    /// Walked directory by directory. Slower, but needs no privileges.
    DirectoryWalk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scan {
    pub root: String,
    pub method: ScanMethod,
    /// Why the fast path was not used, when it was not.
    #[serde(default)]
    pub fallback_reason: Option<String>,
    pub total_bytes: u64,
    pub file_count: u64,
    pub directory_count: u64,
    /// Directories that could not be opened. Normal on a system drive: parts of
    /// `System Volume Information` are closed even to SYSTEM.
    pub unreadable: u64,
    pub elapsed_ms: u64,
    pub tree: Node,
    /// Largest individual files found, newest measurement first.
    pub largest_files: Vec<FileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub bytes: u64,
}

#[derive(Debug, Default)]
struct Counters {
    bytes: AtomicU64,
    files: AtomicU64,
    directories: AtomicU64,
    unreadable: AtomicU64,
}

/// How many largest files to keep while walking.
const LARGEST_FILES_KEPT: usize = 25;

/// Depth below which subdirectories are handed to worker threads. Deeper than
/// this the per-thread overhead outweighs the win.
const PARALLEL_DEPTH: usize = 2;

/// Measure everything beneath `root`, by the fastest route available.
///
/// A whole NTFS volume is read from the master file table. Anything else — a
/// subdirectory, a non-NTFS volume, or a volume we lack the rights to open
/// raw — is walked. The two produce the same shape, so callers do not branch.
pub fn scan(root: &Path) -> Result<Scan> {
    if let Some(letter) = volume_letter(root) {
        let started = Instant::now();
        match crate::mft::read(letter) {
            Ok(snapshot) => {
                tracing::info!(
                    drive = %letter,
                    records = snapshot.entries.len(),
                    "read the master file table"
                );
                return Ok(from_master_file_table(
                    snapshot,
                    root,
                    started.elapsed().as_millis() as u64,
                ));
            }
            Err(error) => {
                // Not fatal: falling back is the designed behaviour for an
                // unprivileged agent, and the reason travels to the UI so the
                // slow answer is explained rather than mysterious.
                tracing::info!(%error, "master file table unavailable; walking instead");
                let mut scan = walk_scan(root)?;
                scan.fallback_reason = Some(error.to_string());
                return Ok(scan);
            }
        }
    }
    walk_scan(root)
}

/// `C:\` yes; `C:\Users` no. Only a whole volume can come from its table.
fn volume_letter(path: &Path) -> Option<char> {
    let text = path.to_str()?;
    let bytes = text.as_bytes();
    let looks_like_root = matches!(text.len(), 2 | 3)
        && bytes.get(1) == Some(&b':')
        && bytes.first().is_some_and(|c| c.is_ascii_alphabetic())
        && bytes.get(2).is_none_or(|c| *c == b'\\' || *c == b'/');
    looks_like_root.then(|| bytes[0].to_ascii_uppercase() as char)
}

/// Walk `root` and measure everything beneath it.
pub fn walk_scan(root: &Path) -> Result<Scan> {
    let started = Instant::now();
    let counters = Counters::default();

    let threads = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(4);

    let mut walked = walk(root, 0, threads, &counters);
    walked.node.name = root.display().to_string();

    // Every subtree merged its candidates upward, so the root holds them all.
    let mut largest: Vec<FileEntry> = walked
        .big
        .iter()
        .map(|big| FileEntry {
            path: big.path.clone(),
            bytes: big.bytes,
        })
        .collect();
    largest.sort_by_key(|entry| Reverse(entry.bytes));
    largest.truncate(LARGEST_FILES_KEPT);

    let tree = prune(walked.node, 0, DEFAULT_MAX_DEPTH, DEFAULT_MAX_CHILDREN);

    Ok(Scan {
        root: root.display().to_string(),
        method: ScanMethod::DirectoryWalk,
        fallback_reason: None,
        total_bytes: counters.bytes.load(Ordering::Relaxed),
        file_count: counters.files.load(Ordering::Relaxed),
        directory_count: counters.directories.load(Ordering::Relaxed),
        unreadable: counters.unreadable.load(Ordering::Relaxed),
        elapsed_ms: started.elapsed().as_millis() as u64,
        tree,
        largest_files: largest,
    })
}

/// Turn a table snapshot into the same tree a directory walk produces.
///
/// Done in two passes. The first totals every directory bottom-up, because a
/// folder's size is only known once its children are. The second builds the
/// transmittable tree from the top, keeping directories only — files are
/// already counted in their parent's total.
fn from_master_file_table(snapshot: crate::mft::MftSnapshot, root: &Path, elapsed_ms: u64) -> Scan {
    let entries = &snapshot.entries;

    let mut children: HashMap<u32, Vec<u32>> = HashMap::with_capacity(entries.len() / 4);
    let mut file_count = 0_u64;
    let mut directory_count = 0_u64;
    let mut total_bytes = 0_u64;

    for (index, entry) in entries {
        if entry.is_directory {
            directory_count += 1;
        } else {
            file_count += 1;
            total_bytes += entry.bytes;
        }
        // The root is its own parent; recording that edge would make the tree
        // contain itself.
        if *index != snapshot.root {
            children.entry(entry.parent).or_default().push(*index);
        }
    }

    // Bottom-up totals, iteratively. A recursive walk would risk the stack on a
    // pathological tree, and a corrupted parent reference could make one.
    let mut totals: HashMap<u32, u64> = HashMap::with_capacity(directory_count as usize + 1);
    let mut direct_files: HashMap<u32, u64> = HashMap::with_capacity(directory_count as usize + 1);
    let mut visited: HashSet<u32> = HashSet::with_capacity(entries.len());
    let mut stack: Vec<(u32, bool)> = vec![(snapshot.root, false)];
    visited.insert(snapshot.root);

    while let Some((index, expanded)) = stack.pop() {
        if expanded {
            let mut sum = 0_u64;
            let mut files_here = 0_u64;
            if let Some(list) = children.get(&index) {
                for child in list {
                    match entries.get(child) {
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
            }
            totals.insert(index, sum);
            direct_files.insert(index, files_here);
            continue;
        }

        stack.push((index, true));
        if let Some(list) = children.get(&index) {
            for child in list {
                let is_directory = entries.get(child).is_some_and(|e| e.is_directory);
                // Only directories need expanding, and only once: a cycle from
                // a bad parent reference would otherwise never terminate.
                if is_directory && visited.insert(*child) {
                    stack.push((*child, false));
                }
            }
        }
    }

    let root_label = root.display().to_string();
    let tree = build_branch(
        snapshot.root,
        &root_label,
        &root_label,
        entries,
        &children,
        &totals,
        &direct_files,
        0,
    );

    let mut largest = largest_files(entries, &children, snapshot.root, &root_label);
    largest.sort_by_key(|entry| Reverse(entry.bytes));
    largest.truncate(LARGEST_FILES_KEPT);

    Scan {
        root: root_label,
        method: ScanMethod::MasterFileTable,
        fallback_reason: None,
        total_bytes,
        file_count,
        directory_count,
        unreadable: snapshot.skipped,
        elapsed_ms,
        tree: prune(tree, 0, DEFAULT_MAX_DEPTH, DEFAULT_MAX_CHILDREN),
        largest_files: largest,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_branch(
    index: u32,
    name: &str,
    path: &str,
    entries: &HashMap<u32, crate::mft::MftEntry>,
    children: &HashMap<u32, Vec<u32>>,
    totals: &HashMap<u32, u64>,
    direct_files: &HashMap<u32, u64>,
    depth: usize,
) -> Node {
    let mut node = Node {
        name: name.to_owned(),
        path: path.to_owned(),
        bytes: totals.get(&index).copied().unwrap_or(0),
        files: direct_files.get(&index).copied().unwrap_or(0),
        children: Vec::new(),
        is_aggregate: false,
    };

    // One level deeper than the tree is pruned to, so pruning has a tail to
    // fold rather than silently losing it.
    if depth > DEFAULT_MAX_DEPTH {
        return node;
    }

    if let Some(list) = children.get(&index) {
        for child in list {
            let Some(entry) = entries.get(child) else {
                continue;
            };
            if !entry.is_directory {
                continue;
            }
            let child_path = join(path, &entry.name);
            node.children.push(build_branch(
                *child,
                &entry.name,
                &child_path,
                entries,
                children,
                totals,
                direct_files,
                depth + 1,
            ));
        }
    }

    node
}

/// Find the biggest files and reconstruct paths for just those.
///
/// Building a path for all 1.7 million entries would cost more than the read
/// did; only the handful that get displayed are worth resolving.
fn largest_files(
    entries: &HashMap<u32, crate::mft::MftEntry>,
    children: &HashMap<u32, Vec<u32>>,
    root: u32,
    root_label: &str,
) -> Vec<FileEntry> {
    let mut candidates: Vec<(u32, u64)> = entries
        .iter()
        .filter(|(_, entry)| !entry.is_directory && entry.bytes >= 64 * 1024 * 1024)
        .map(|(index, entry)| (*index, entry.bytes))
        .collect();
    candidates.sort_by_key(|(_, bytes)| Reverse(*bytes));
    candidates.truncate(LARGEST_FILES_KEPT);

    let _ = children;
    candidates
        .into_iter()
        .filter_map(|(index, bytes)| {
            let path = resolve_path(index, entries, root, root_label)?;
            Some(FileEntry { path, bytes })
        })
        .collect()
}

/// Walk parent references up to the root, assembling a path.
fn resolve_path(
    index: u32,
    entries: &HashMap<u32, crate::mft::MftEntry>,
    root: u32,
    root_label: &str,
) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    let mut current = index;
    // Bounded so a cycle in the parent chain cannot hang the caller.
    for _ in 0..64 {
        if current == root {
            let mut path = root_label.trim_end_matches(['\\', '/']).to_owned();
            for part in parts.iter().rev() {
                path.push('\\');
                path.push_str(part);
            }
            return Some(path);
        }
        let entry = entries.get(&current)?;
        parts.push(&entry.name);
        current = entry.parent;
    }
    None
}

fn join(parent: &str, name: &str) -> String {
    if parent.ends_with('\\') || parent.ends_with('/') {
        format!("{parent}{name}")
    } else {
        format!("{parent}\\{name}")
    }
}

/// Files big enough to be worth naming individually, carried up the tree.
#[derive(Debug, Clone)]
struct Big {
    path: String,
    bytes: u64,
}

fn walk(directory: &Path, depth: usize, threads: usize, counters: &Counters) -> NodeWithBig {
    let mut node = NodeWithBig {
        node: Node {
            name: file_name(directory),
            path: directory.display().to_string(),
            bytes: 0,
            files: 0,
            children: Vec::new(),
            is_aggregate: false,
        },
        big: Vec::new(),
    };

    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(_) => {
            counters.unreadable.fetch_add(1, Ordering::Relaxed);
            return node;
        }
    };

    let mut subdirectories = Vec::new();
    for entry in entries.flatten() {
        // On Windows this is served from the directory listing already in hand,
        // so it costs no extra system call, and it describes the link itself
        // rather than its target.
        let Ok(metadata) = entry.metadata() else {
            counters.unreadable.fetch_add(1, Ordering::Relaxed);
            continue;
        };

        if metadata.file_type().is_symlink() {
            // Junction or symlink: whatever is behind it belongs to wherever it
            // really lives, and is counted there.
            continue;
        }

        if metadata.is_dir() {
            subdirectories.push(entry.path());
        } else {
            let bytes = metadata.len();
            node.node.bytes += bytes;
            node.node.files += 1;
            counters.bytes.fetch_add(bytes, Ordering::Relaxed);
            counters.files.fetch_add(1, Ordering::Relaxed);
            if bytes >= 64 * 1024 * 1024 {
                node.big.push(Big {
                    path: entry.path().display().to_string(),
                    bytes,
                });
            }
        }
    }

    counters
        .directories
        .fetch_add(subdirectories.len() as u64, Ordering::Relaxed);

    let children: Vec<NodeWithBig> = if depth < PARALLEL_DEPTH && subdirectories.len() > 1 {
        walk_in_parallel(&subdirectories, depth, threads, counters)
    } else {
        subdirectories
            .iter()
            .map(|path| walk(path, depth + 1, threads, counters))
            .collect()
    };

    for child in children {
        node.node.bytes += child.node.bytes;
        node.big.extend(child.big);
        node.node.children.push(child.node);
    }

    // Keep the carried list bounded; anything trimmed here was smaller than 25
    // other files in the same subtree and cannot reach the final table.
    if node.big.len() > LARGEST_FILES_KEPT {
        node.big.sort_by_key(|big| Reverse(big.bytes));
        node.big.truncate(LARGEST_FILES_KEPT);
    }

    node
}

/// Split the work into one chunk per thread rather than one thread per
/// directory: `C:\` alone would otherwise spawn hundreds two levels down.
fn walk_in_parallel(
    subdirectories: &[PathBuf],
    depth: usize,
    threads: usize,
    counters: &Counters,
) -> Vec<NodeWithBig> {
    let chunk_size = subdirectories.len().div_ceil(threads.max(1)).max(1);

    std::thread::scope(|scope| {
        let handles: Vec<_> = subdirectories
            .chunks(chunk_size)
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .iter()
                        .map(|path| walk(path, depth + 1, threads, counters))
                        .collect::<Vec<_>>()
                })
            })
            .collect();

        handles
            .into_iter()
            .filter_map(|handle| handle.join().ok())
            .flatten()
            .collect()
    })
}

struct NodeWithBig {
    node: Node,
    big: Vec<Big>,
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// Trim the tree for transport, keeping the largest children at each level and
/// folding the rest into a single node so the numbers still reconcile.
fn prune(mut node: Node, depth: usize, max_depth: usize, max_children: usize) -> Node {
    if depth >= max_depth || node.children.is_empty() {
        node.children = Vec::new();
        return node;
    }

    node.children.sort_by_key(|child| Reverse(child.bytes));

    if node.children.len() > max_children {
        let tail: Vec<Node> = node.children.split_off(max_children);
        let bytes: u64 = tail.iter().map(|child| child.bytes).sum();
        let files: u64 = tail.iter().map(|child| child.files).sum();
        if bytes > 0 {
            node.children.push(Node {
                name: format!("{} more", tail.len()),
                path: node.path.clone(),
                bytes,
                files,
                children: Vec::new(),
                is_aggregate: true,
            });
        }
    }

    node.children = node
        .children
        .into_iter()
        .map(|child| prune(child, depth + 1, max_depth, max_children))
        .collect();
    node
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("kam-scan-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn write(path: &Path, bytes: usize) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, vec![0_u8; bytes]).unwrap();
    }

    #[test]
    fn totals_match_what_was_written() {
        let root = scratch("totals");
        write(&root.join("a.bin"), 1000);
        write(&root.join("nested/b.bin"), 2000);
        write(&root.join("nested/deeper/c.bin"), 3000);

        let scan = scan(&root).unwrap();
        assert_eq!(scan.total_bytes, 6000);
        assert_eq!(scan.file_count, 3);
        assert_eq!(scan.directory_count, 2);
        assert_eq!(scan.tree.bytes, 6000);

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_subtree_total_includes_its_descendants() {
        let root = scratch("subtree");
        write(&root.join("nested/deeper/c.bin"), 4096);

        let scan = scan(&root).unwrap();
        let nested = scan
            .tree
            .children
            .iter()
            .find(|child| child.name == "nested")
            .expect("nested directory missing from the tree");
        assert_eq!(nested.bytes, 4096);

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn pruning_folds_the_tail_without_losing_bytes() {
        let mut children: Vec<Node> = (0..30)
            .map(|index| Node {
                name: format!("child{index}"),
                path: format!("root/child{index}"),
                bytes: (index + 1) * 100,
                files: 1,
                children: Vec::new(),
                is_aggregate: false,
            })
            .collect();
        let expected: u64 = children.iter().map(|child| child.bytes).sum();
        children.reverse();

        let root = Node {
            name: "root".to_owned(),
            path: "root".to_owned(),
            bytes: expected,
            files: 0,
            children,
            is_aggregate: false,
        };

        let pruned = prune(root, 0, 4, 14);
        assert_eq!(pruned.children.len(), 15, "14 kept plus one aggregate");
        let total: u64 = pruned.children.iter().map(|child| child.bytes).sum();
        assert_eq!(total, expected, "pruning must not lose bytes");
        assert!(pruned.children.last().unwrap().is_aggregate);
    }

    /// Not part of the normal run — it walks a whole drive. Invoke deliberately:
    /// `cargo test -p kam-storage -- --ignored --nocapture measure_the_system_drive`
    #[test]
    #[ignore = "walks the entire system drive"]
    fn measure_the_system_drive() {
        let scan = scan(Path::new("C:\\")).unwrap();
        println!(
            "method: {:?}{}",
            scan.method,
            scan.fallback_reason
                .as_deref()
                .map(|reason| format!("  (fell back: {reason})"))
                .unwrap_or_default()
        );
        println!(
            "C:\\  {:.1} GB  {} files  {} dirs  {} unreadable  {} ms",
            scan.total_bytes as f64 / 1024.0 / 1024.0 / 1024.0,
            scan.file_count,
            scan.directory_count,
            scan.unreadable,
            scan.elapsed_ms
        );
        println!("largest: {:?}", scan.largest_files.first());
        if scan.method == ScanMethod::MasterFileTable {
            let snapshot = crate::mft::read('C').unwrap();
            println!("stats: {:?}", snapshot.stats);
        }
        for child in scan.tree.children.iter().take(8) {
            println!(
                "   {:>8.1} GB  {}",
                child.bytes as f64 / 1024.0 / 1024.0 / 1024.0,
                child.name
            );
        }
        assert!(scan.total_bytes > 0);
    }

    #[test]
    fn an_unreadable_root_reports_rather_than_failing() {
        let missing = std::env::temp_dir().join("kam-scan-definitely-not-here");
        let scan = scan(&missing).unwrap();
        assert_eq!(scan.total_bytes, 0);
        assert_eq!(scan.unreadable, 1);
    }
}
