//! Directory scanning: where the space actually went.
//!
//! # Why this is not the master-file-table reader
//!
//! PLAN.md promised a whole-volume map in about two seconds by reading the NTFS
//! master file table. That still stands, but with a correction found while
//! building it: `FSCTL_ENUM_USN_DATA`, the documented enumeration path, returns
//! names, parents and attributes — and no sizes. A treemap without sizes is not
//! a treemap. Getting sizes that way means locating `$MFT` on the raw volume and
//! parsing record headers, attribute lists and non-resident data runs by hand,
//! which is a substantial piece of work and needs elevation.
//!
//! So this is the honest intermediate: a parallel directory walk that needs no
//! special privileges and produces the same tree, in seconds rather than
//! milliseconds. The master-file-table reader replaces the traversal underneath
//! without changing anything above it.
//!
//! # Correctness notes
//!
//! Reparse points are skipped. Windows is full of junctions that point back up
//! the tree — `C:\Documents and Settings` to `C:\Users`, `Application Data` to
//! itself — and following them both double-counts and loops forever.

use std::cmp::Reverse;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scan {
    pub root: String,
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

/// Walk `root` and measure everything beneath it.
pub fn scan(root: &Path) -> Result<Scan> {
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
        total_bytes: counters.bytes.load(Ordering::Relaxed),
        file_count: counters.files.load(Ordering::Relaxed),
        directory_count: counters.directories.load(Ordering::Relaxed),
        unreadable: counters.unreadable.load(Ordering::Relaxed),
        elapsed_ms: started.elapsed().as_millis() as u64,
        tree,
        largest_files: largest,
    })
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
            "C:\\  {:.1} GB  {} files  {} dirs  {} unreadable  {} ms",
            scan.total_bytes as f64 / 1024.0 / 1024.0 / 1024.0,
            scan.file_count,
            scan.directory_count,
            scan.unreadable,
            scan.elapsed_ms
        );
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
