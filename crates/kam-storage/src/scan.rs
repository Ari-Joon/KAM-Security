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
//!
//! # One folder on its own
//!
//! The tree that is sent stops [`DEFAULT_MAX_DEPTH`] folders down, and the
//! things worth finding are below that: everything inside `AppData\Local`, and
//! every game inside a Steam library. [`scan_folder`] reads one such folder
//! and sends its own tree, cut the same way, so the map can be followed down
//! as far as the drive goes.
//!
//! It reads the file table again, where the drive allows it, and builds the
//! folder's tree with the function that builds the drive's. That is what makes
//! a folder's figure the figure on the rectangle it was opened from: a walk of
//! the same folder counts a hard-linked file once per name and can disagree.

use std::cmp::Reverse;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use kam_core::{Error, Result};
use serde::{Deserialize, Serialize};

use crate::index::VolumeIndex;

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
    /// True when this folder has folders inside it that were measured and not
    /// sent, because the tree stops here. An empty `children` cannot say so by
    /// itself: a folder with no folders in it looks the same. This is what
    /// tells the map that [`scan_folder`] has something to show for it.
    #[serde(default)]
    pub folded: bool,
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
    /// Every folder of the drive holding [`crate::growth::FOLDER_FLOOR`] or
    /// more, when the scan was of a whole drive: what a summary of it keeps,
    /// to be compared with later. It is sent as well as kept, so that a
    /// summary holds nothing the person who asked for the scan was not sent.
    #[serde(default)]
    pub folders: Option<crate::growth::FolderList>,
    /// What became of that summary. Set by the agent, which keeps it.
    #[serde(default)]
    pub summary: Option<crate::growth::SummaryKept>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub bytes: u64,
}

/// One folder of a drive, read on its own. See [`scan_folder`].
///
/// It carries folders and nothing else, built by the code that builds the map
/// of a whole drive and cut the same way. So it says no more about a folder
/// than a scan of the drive says about the drive, and it names no file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderScan {
    /// The folder, as the drive itself spells it.
    pub path: String,
    pub method: ScanMethod,
    /// Why the file table was not used, when it was not.
    #[serde(default)]
    pub fallback_reason: Option<String>,
    /// Folders beneath it that could not be opened, when that can be told.
    /// Only a walk can tell: the file table counts the records it could not
    /// parse for the drive as a whole, and none of them can be placed in one
    /// folder.
    #[serde(default)]
    pub unreadable: Option<u64>,
    pub elapsed_ms: u64,
    pub tree: Node,
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
                let mut scan = walk_scan_with(root, true)?;
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
    walk_scan_with(root, false)
}

/// [`walk_scan`], keeping every large folder for a summary when `root` is a
/// whole drive. Taken from the whole walk, before it is cut down to be sent.
fn walk_scan_with(root: &Path, keep_folders: bool) -> Result<Scan> {
    let started = Instant::now();
    let counters = Counters::default();

    let threads = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(4);

    let mut walked = walk(root, 0, threads, &counters);
    walked.node.name = root.display().to_string();
    let folders = keep_folders.then(|| crate::growth::from_tree(&walked.node));

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
        folders,
        summary: None,
    })
}

/// Turn a table snapshot into the same tree a directory walk produces.
fn from_master_file_table(snapshot: crate::mft::MftSnapshot, root: &Path, elapsed_ms: u64) -> Scan {
    from_index(&VolumeIndex::build(snapshot), root, elapsed_ms)
}

/// The map of a whole drive, from its index.
///
/// The index has already totalled every folder bottom-up, because a folder's
/// size is only known once its children are. This builds the tree that is sent
/// from the top, keeping directories only: files are already counted in their
/// parent's total.
///
/// This used to total the folders with a loop of its own, a copy of the one
/// in the index. A folder read on its own is answered from the index, so with
/// two loops a folder's figure and the figure on the rectangle it was opened
/// from would have come from different code.
fn from_index(index: &VolumeIndex, root: &Path, elapsed_ms: u64) -> Scan {
    let root_label = root.display().to_string();
    let tree = branch(index, index.root(), &root_label, &root_label, 0);

    Scan {
        root: root_label.clone(),
        method: ScanMethod::MasterFileTable,
        fallback_reason: None,
        total_bytes: index.total_bytes(),
        file_count: index.file_count(),
        directory_count: index.directory_count(),
        unreadable: index.skipped(),
        elapsed_ms,
        tree: prune(tree, 0, DEFAULT_MAX_DEPTH, DEFAULT_MAX_CHILDREN),
        largest_files: largest_files(index, &root_label),
        // Only ever a whole drive: a table is read for nothing smaller.
        folders: Some(crate::growth::from_index(index, &root_label)),
        summary: None,
    }
}

/// A folder and the folders beneath it, as far down as the tree is sent.
///
/// The one place a tree is built from the table, whether it starts at the top
/// of the drive or at a folder somebody opened.
fn branch(index: &VolumeIndex, record: u32, name: &str, path: &str, depth: usize) -> Node {
    let mut node = Node {
        name: name.to_owned(),
        path: path.to_owned(),
        bytes: index.total_of(record),
        files: index.direct_files_in(record),
        children: Vec::new(),
        is_aggregate: false,
        folded: false,
    };

    // One level deeper than the tree is pruned to, so pruning has a tail to
    // fold rather than silently losing it, and can tell a folder it cut short
    // from a folder with no folders in it.
    if depth > DEFAULT_MAX_DEPTH {
        return node;
    }

    for child in index.directories_in(record) {
        let Some(entry) = index.entry(*child) else {
            continue;
        };
        let child_path = join(path, &entry.name);
        node.children
            .push(branch(index, *child, &entry.name, &child_path, depth + 1));
    }

    node
}

/// Find the biggest files and reconstruct paths for just those.
///
/// Building a path for all 1.7 million entries would cost more than the read
/// did; only the handful that get displayed are worth resolving.
fn largest_files(index: &VolumeIndex, root_label: &str) -> Vec<FileEntry> {
    let mut candidates: Vec<(u32, u64)> = index
        .entries()
        .iter()
        .filter(|(_, entry)| !entry.is_directory && entry.bytes >= 64 * 1024 * 1024)
        .map(|(record, entry)| (*record, entry.bytes))
        .collect();
    candidates.sort_by_key(|(_, bytes)| Reverse(*bytes));
    candidates.truncate(LARGEST_FILES_KEPT);

    candidates
        .into_iter()
        .filter_map(|(record, bytes)| {
            let path = index.path_of(record, root_label)?;
            Some(FileEntry { path, bytes })
        })
        .collect()
}

/// Read one folder of a drive, by the file table where the drive allows it.
///
/// # Why the table again
///
/// The folder was a rectangle on a map, and where that map came from the file
/// table it counted a file with several names once. A walk counts it once per
/// name, so a walked answer can disagree with the rectangle it was opened
/// from. Reading the table again and starting from the folder's own record
/// gives a figure worked out the way the rectangle's was. Only where the table
/// cannot be read is the folder walked, and the reason goes back with the
/// answer so that a difference can be explained.
///
/// # What is refused, and when
///
/// The path is a string from a client, and this runs as LocalSystem. Only a
/// folder on a lettered drive is looked for, and that much is decided from the
/// spelling, before anything is opened: resolving a network path is itself a
/// connection, made as this machine's own account.
///
/// After that the spelling decides nothing. The table route finds the folder
/// by following names through the table, where a link has nothing beneath it
/// to follow. The walk route checks every name on the way down for being a
/// link, then asks Windows where the folder really is and judges that.
pub fn scan_folder(path: &str) -> Result<FolderScan> {
    let (letter, asked) = lettered_folder(path)?;
    let started = Instant::now();

    match crate::mft::read(letter) {
        Ok(snapshot) => {
            let index = VolumeIndex::build(snapshot);
            let mut folder = folder_from_index(&index, &asked)?;
            folder.elapsed_ms = started.elapsed().as_millis() as u64;
            Ok(folder)
        }
        Err(error) => {
            tracing::info!(%error, "master file table unavailable; walking the folder instead");
            let mut folder = walk_folder(&asked)?;
            folder.fallback_reason = Some(error.to_string());
            folder.elapsed_ms = started.elapsed().as_millis() as u64;
            Ok(folder)
        }
    }
}

/// What a folder that is not there is answered with.
///
/// Gone is the ordinary reason: the map it was clicked on is a picture of the
/// drive as it was, and folders are deleted and renamed.
fn no_such_folder(path: &str) -> Error {
    Error::Refused(format!("there is no folder at {path} now"))
}

/// The drive a path is on, and the path in its plain spelling, or why it is
/// not a folder this will look for.
///
/// Text only, and on purpose: this is the judgement made before anything is
/// opened, and its whole job is to decide whether opening is allowed. A
/// network path, a device path and a path with no drive are refused here.
/// What the path leads to is decided afterwards, by the route that reads it.
fn lettered_folder(path: &str) -> Result<(char, String)> {
    let refused = |why: &str| Error::Refused(format!("{path} was not read: {why}"));

    // The extended-length form of an ordinary path names the same folder.
    // Stripped once: what is left of `\\?\UNC\server` or `\\?\Volume{...}`
    // does not start with a drive letter, and is refused below.
    let text = path
        .strip_prefix(r"\\?\")
        .unwrap_or(path)
        .replace('/', "\\");
    let bytes = text.as_bytes();
    let lettered =
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';
    if !lettered {
        return Err(refused(
            "only a folder on a lettered drive is read, never a network path or a device",
        ));
    }
    // Past the drive's own colon, a colon names a stream. A folder's index
    // stream opens as the folder does, and is not what a map was clicked on.
    if text[2..].contains(':') {
        return Err(refused("a folder's name has no colon in it"));
    }
    if text[3..]
        .split('\\')
        .any(|part| part == "." || part == "..")
    {
        return Err(refused("it does not say plainly which folder it means"));
    }

    let letter = bytes[0].to_ascii_uppercase() as char;
    // The separator after the colon stays: `C:` by itself means wherever the
    // current directory on that drive happens to be.
    let plain = format!("{}{}", &text[..3], text[3..].trim_end_matches('\\'));
    Ok((letter, plain))
}

/// One folder's tree, from the index of the drive it is on.
fn folder_from_index(index: &VolumeIndex, path: &str) -> Result<FolderScan> {
    let record = index.resolve(path).ok_or_else(|| no_such_folder(path))?;
    let entry = index.entry(record).ok_or_else(|| no_such_folder(path))?;
    if !entry.is_directory {
        return Err(Error::Refused(format!("{path} is a file, not a folder")));
    }

    // Spelled from the table's own names, not from what was asked: the table
    // matched without regard to case, and the answer should say what is there.
    let drive = format!("{}:", index.drive());
    let (name, spelled) = if record == index.root() {
        let root = format!("{drive}\\");
        (root.clone(), root)
    } else {
        let spelled = index
            .path_of(record, &drive)
            .ok_or_else(|| no_such_folder(path))?;
        (entry.name.clone(), spelled)
    };

    let tree = branch(index, record, &name, &spelled, 0);
    Ok(FolderScan {
        path: spelled,
        method: ScanMethod::MasterFileTable,
        fallback_reason: None,
        unreadable: None,
        elapsed_ms: 0,
        tree: prune(tree, 0, DEFAULT_MAX_DEPTH, DEFAULT_MAX_CHILDREN),
    })
}

/// One folder's tree, by walking it. For a drive whose table cannot be read.
fn walk_folder(path: &str) -> Result<FolderScan> {
    let real = real_folder(path)?;
    let scan = walk_scan(Path::new(&real))?;

    let mut tree = scan.tree;
    // A walk names its root by the whole path, which is right at the top of a
    // drive. This is one folder among others on a map.
    tree.name = file_name(Path::new(&real));
    Ok(FolderScan {
        path: real,
        method: ScanMethod::DirectoryWalk,
        fallback_reason: None,
        unreadable: Some(scan.unreadable),
        elapsed_ms: scan.elapsed_ms,
        tree,
    })
}

/// Where a folder really is, or why it will not be walked.
///
/// # Every name on the way down
///
/// A walk starts by listing its root, and Windows follows any link in the
/// path to get there. So a folder reached through a link is somewhere else,
/// possibly on another drive or another machine, and walking it would report
/// that other place under this path. Each name from the drive down is looked
/// at without following it, and a link anywhere among them is a refusal. What
/// is behind a link is counted where it really lives.
///
/// Then Windows is asked where the folder is, and that answer is judged
/// again, because it is the one that will be walked.
///
/// # It answers about the moment it looks
///
/// Nothing here holds the folder open, so a name could be swapped for a link
/// between the look and the walk. That is accepted for measuring, which
/// destroys nothing: the walk would report another folder's sizes, as a scan
/// of wherever that folder is would. The cache clear holds its folder open,
/// because it deletes.
fn real_folder(path: &str) -> Result<String> {
    let unreadable =
        |error: std::io::Error| Error::Refused(format!("{path} could not be opened: {error}"));

    let mut prefix = PathBuf::new();
    for component in Path::new(path).components() {
        prefix.push(component);
        // The drive and its root are not names anybody could have swapped.
        if !matches!(component, std::path::Component::Normal(_)) {
            continue;
        }
        let data = match std::fs::symlink_metadata(&prefix) {
            Ok(data) => data,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(no_such_folder(path));
            }
            Err(error) => return Err(unreadable(error)),
        };
        if data.file_type().is_symlink() {
            return Err(Error::Refused(format!(
                "{path} was not read: {} is a link to somewhere else, and what is behind \
                 a link is measured where it really is",
                prefix.display()
            )));
        }
        if !data.is_dir() {
            return Err(Error::Refused(format!(
                "{} is a file, not a folder",
                prefix.display()
            )));
        }
    }

    let resolved = std::fs::canonicalize(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            no_such_folder(path)
        } else {
            unreadable(error)
        }
    })?;
    let (_, real) = lettered_folder(&resolved.to_string_lossy())?;

    // A folder that cannot be listed would walk to a total of nothing, which
    // reads as an empty folder. It is said instead.
    std::fs::read_dir(&real).map_err(unreadable)?;
    Ok(real)
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
            folded: false,
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
///
/// A folder whose own folders are cut off here is marked as folded, so that
/// whoever draws it knows there is more to ask for.
fn prune(mut node: Node, depth: usize, max_depth: usize, max_children: usize) -> Node {
    if depth >= max_depth || node.children.is_empty() {
        node.folded = !node.children.is_empty();
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
                folded: false,
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
                folded: false,
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
            folded: false,
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

    // --- one folder on its own -------------------------------------------

    use crate::index::testing::Drive;

    /// A made-up drive whose largest things sit below where the map stops:
    /// a shader cache and a package cache inside `AppData\Local`, which is
    /// four folders down.
    fn drive_with_things_below_the_floor() -> VolumeIndex {
        let mut drive = Drive::new();
        drive.file(
            r"Users\someone\AppData\Local\NVIDIA\DXCache\a.bin",
            5_000,
            0,
        );
        drive.file(
            r"Users\someone\AppData\Local\NVIDIA\DXCache\b.bin",
            3_000,
            0,
        );
        drive.file(r"Users\someone\AppData\Local\NVIDIA\readme.txt", 10, 0);
        drive.file(
            r"Users\someone\AppData\Local\pip\Cache\http\wheel.whl",
            700,
            0,
        );
        drive.file(r"Users\someone\AppData\Roaming\notes.txt", 50, 0);
        drive.file(r"Windows\notepad.exe", 1_000, 0);
        drive.index()
    }

    fn child<'a>(node: &'a Node, name: &str) -> &'a Node {
        node.children
            .iter()
            .find(|child| child.name == name)
            .unwrap_or_else(|| panic!("{name} is not inside {}", node.path))
    }

    /// A scan of a whole drive carries every folder of 100 MB or more for
    /// its summary, those below where the map stops included. A scan of
    /// anything smaller than a drive carries none.
    #[test]
    fn a_scan_of_a_whole_drive_carries_its_large_folders_and_a_smaller_one_carries_none() {
        let mut drive = Drive::new();
        drive.file(r"a\b\c\d\e\f\deep.bin", 300 * 1024 * 1024, 0);
        drive.file(r"a\small.bin", 1_000, 0);
        let scan = from_index(&drive.index(), Path::new(r"C:\"), 0);
        let folders = scan.folders.expect("a whole drive keeps its large folders");
        let paths: Vec<&str> = folders
            .folders
            .iter()
            .map(|folder| folder.path.as_str())
            .collect();
        assert_eq!(
            paths,
            vec![
                r"C:\a",
                r"C:\a\b",
                r"C:\a\b\c",
                r"C:\a\b\c\d",
                r"C:\a\b\c\d\e",
                r"C:\a\b\c\d\e\f"
            ]
        );
        assert_eq!(scan.summary, None, "a summary is the agent's to keep");

        let root = real_scratch("no-summary");
        write(&Path::new(&root).join("x.bin"), 10);
        assert!(walk_scan(Path::new(&root)).unwrap().folders.is_none());
        // The drive's own route, given a folder to try it on.
        let walked = walk_scan_with(Path::new(&root), true).unwrap();
        assert_eq!(walked.folders.map(|list| list.folders.len()), Some(0));
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A file of `bytes` that takes no room on the drive: marked sparse
    /// before it is lengthened, so its length is a number and nothing more.
    fn sparse(path: &Path, bytes: u64) {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::IO::DeviceIoControl;
        const FSCTL_SET_SPARSE: u32 = 0x0009_00C4;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let file = std::fs::File::create(path).unwrap();
        let mut returned = 0_u32;
        unsafe {
            DeviceIoControl(
                HANDLE(file.as_raw_handle()),
                FSCTL_SET_SPARSE,
                None,
                0,
                None,
                0,
                Some(&mut returned),
                None,
            )
        }
        .expect("the temporary folder's drive should make a sparse file");
        file.set_len(bytes).unwrap();
    }

    /// The large folders of a walked drive come from the whole walk, not from
    /// the tree cut down to be sent: a folder six deep is one of them.
    #[test]
    fn a_walked_drive_keeps_its_large_folders_from_below_where_the_map_stops() {
        let root = real_scratch("walk-summary");
        let base = Path::new(&root);
        sparse(&base.join(r"a\b\c\d\e\f\big.bin"), 300 * 1024 * 1024);

        let scan = walk_scan_with(base, true).unwrap();
        let folders = scan
            .folders
            .expect("the drive's route keeps its large folders");
        let deepest = format!(r"{root}\a\b\c\d\e\f");
        assert!(
            folders.folders.iter().any(|folder| folder.path == deepest),
            "the folder six down is missing: {:?}",
            folders.folders
        );
        // The tree that is sent still stops four folders down.
        let floor = child(child(child(child(&scan.tree, "a"), "b"), "c"), "d");
        assert!(floor.children.is_empty() && floor.folded);

        std::fs::remove_dir_all(base).unwrap();
    }

    /// The map says which of its rectangles have more beneath them.
    ///
    /// A rectangle at the floor of the map and a folder with no folders in it
    /// both arrive with no children. Only the first has anything to open, and
    /// the page asks the service about a folder only when it is marked.
    #[test]
    fn the_map_of_a_drive_marks_the_folders_it_stopped_at() {
        let index = drive_with_things_below_the_floor();
        let scan = from_index(&index, Path::new(r"C:\"), 0);

        let app_data = child(child(child(&scan.tree, "Users"), "someone"), "AppData");
        let local = child(app_data, "Local");
        assert!(local.children.is_empty(), "the map goes four folders down");
        assert!(
            local.folded,
            "Local has folders beneath it that were not sent"
        );
        assert_eq!(local.bytes, 8_710);

        let roaming = child(app_data, "Roaming");
        assert!(roaming.children.is_empty());
        assert!(
            !roaming.folded,
            "Roaming has no folders in it, so there is nothing more to ask for"
        );
        assert!(!child(&scan.tree, "Windows").folded);
        assert!(!app_data.folded, "its folders were sent");
    }

    /// Opening a rectangle at the floor of the map gives that folder's own
    /// tree, and its figure is the figure that was on the rectangle.
    #[test]
    fn a_folder_at_the_floor_of_the_map_opens_with_the_figure_on_its_rectangle() {
        let index = drive_with_things_below_the_floor();
        let scan = from_index(&index, Path::new(r"C:\"), 0);
        let rectangle = child(
            child(child(child(&scan.tree, "Users"), "someone"), "AppData"),
            "Local",
        );

        let folder = folder_from_index(&index, &rectangle.path).unwrap();
        assert_eq!(folder.path, r"C:\Users\someone\AppData\Local");
        assert_eq!(folder.method, ScanMethod::MasterFileTable);
        assert_eq!(folder.unreadable, None);
        assert_eq!(folder.tree.name, "Local");
        assert_eq!(folder.tree.path, rectangle.path);
        assert_eq!(
            folder.tree.bytes, rectangle.bytes,
            "the folder disagrees with the rectangle it was opened from"
        );

        let nvidia = child(&folder.tree, "NVIDIA");
        assert_eq!(nvidia.bytes, 8_010);
        assert_eq!(nvidia.files, 1, "the readme sits directly in it");
        let cache = child(nvidia, "DXCache");
        assert_eq!(cache.path, r"C:\Users\someone\AppData\Local\NVIDIA\DXCache");
        assert_eq!((cache.bytes, cache.files), (8_000, 2));
        assert_eq!(child(&folder.tree, "pip").bytes, 700);
        // Largest first, as the top of the map is.
        assert_eq!(folder.tree.children[0].name, "NVIDIA");
    }

    /// The person can keep going down: a folder's own tree stops four folders
    /// down too, says where, and those open in turn.
    #[test]
    fn a_folder_opened_from_the_map_can_be_opened_further_down_in_turn() {
        let mut drive = Drive::new();
        drive.file(r"a\b\c\d\e\f\g\h\i\j\deep.bin", 4_096, 0);
        drive.file(r"a\b\c\d\e\beside.bin", 100, 0);
        let index = drive.index();

        let scan = from_index(&index, Path::new(r"C:\"), 0);
        let mut current = scan.tree;
        let mut opened = 0;
        loop {
            // A folder with nothing beneath it that still says it has more
            // would be opened for ever: fail instead of hanging the run.
            assert!(
                opened <= 10,
                "still offered something to open at {}",
                current.path
            );
            // Down the only chain there is, as far as this tree was sent.
            let mut floor = &current;
            while let Some(next) = floor.children.first() {
                floor = next;
            }
            if !floor.folded {
                assert_eq!(
                    floor.name, "j",
                    "the walk down stopped short at {}",
                    floor.path
                );
                assert_eq!((floor.bytes, floor.files), (4_096, 1));
                break;
            }
            let folder = folder_from_index(&index, &floor.path).unwrap();
            assert_eq!(folder.tree.bytes, floor.bytes);
            current = folder.tree;
            opened += 1;
        }
        assert_eq!(opened, 2, "ten folders down is two openings below the map");
    }

    #[test]
    fn a_folder_is_answered_with_the_drives_own_spelling_of_it() {
        let index = drive_with_things_below_the_floor();
        let folder = folder_from_index(&index, r"c:\users\SOMEONE\appdata\local\nvidia").unwrap();
        assert_eq!(folder.path, r"C:\Users\someone\AppData\Local\NVIDIA");
        assert_eq!(folder.tree.name, "NVIDIA");

        let top = folder_from_index(&index, r"C:\").unwrap();
        assert_eq!(
            (top.path.as_str(), top.tree.name.as_str()),
            (r"C:\", r"C:\")
        );
        assert_eq!(top.tree.bytes, index.total_bytes());
    }

    /// A folder that has gone since the map was drawn says so. It is not
    /// answered with an empty folder, which would read as "nothing in it".
    #[test]
    fn a_folder_that_is_no_longer_there_is_said_to_be_gone_and_a_file_is_not_a_folder() {
        let index = drive_with_things_below_the_floor();

        let gone = folder_from_index(&index, r"C:\Users\someone\AppData\Local\Removed")
            .expect_err("a folder that is not in the table was answered");
        assert_eq!(
            gone.to_string(),
            r"refused: there is no folder at C:\Users\someone\AppData\Local\Removed now"
        );

        let file = folder_from_index(&index, r"C:\Windows\notepad.exe")
            .expect_err("a file was opened as a folder");
        assert!(
            file.to_string().contains("is a file, not a folder"),
            "{file}"
        );
    }

    /// What may be looked for at all is decided from the spelling, before
    /// anything is opened: resolving a network path is already a connection.
    #[test]
    fn only_a_folder_on_a_lettered_drive_is_looked_for() {
        for path in [
            r"\\server\share\folder",
            r"\\?\UNC\server\share\folder",
            r"\\?\Volume{4c1b02c1-d990-11dc-99ae-806e6f6e6963}\folder",
            r"\\.\C:\Users",
            r"\\.\PhysicalDrive0",
            r"\??\C:\Users",
            r"\\?\\\?\C:\Users",
            // Drive-relative: wherever the current directory on C: is.
            r"C:Users",
            "C:",
            r"Users\someone",
            r"\Users\someone",
            "",
            // A stream of the folder, which opens as the folder does.
            r"C:\Users\someone::$INDEX_ALLOCATION",
            r"C:\Users\..\Windows",
            r"C:\Users\.\someone",
        ] {
            let refusal = lettered_folder(path).expect_err(path);
            assert!(
                refusal.to_string().contains("was not read"),
                "{path}: {refusal}"
            );
            // And the whole request refuses the same way, having opened
            // nothing: none of these reaches a drive to be read from.
            assert_eq!(
                scan_folder(path).unwrap_err().to_string(),
                refusal.to_string()
            );
        }

        assert_eq!(
            lettered_folder(r"c:\Users\someone\").unwrap(),
            ('C', r"c:\Users\someone".to_owned())
        );
        assert_eq!(
            lettered_folder(r"\\?\D:\Games").unwrap(),
            ('D', r"D:\Games".to_owned())
        );
        assert_eq!(
            lettered_folder("C:/Users/someone").unwrap(),
            ('C', r"C:\Users\someone".to_owned())
        );
        // The top of a drive keeps its separator.
        assert_eq!(lettered_folder(r"E:\").unwrap(), ('E', r"E:\".to_owned()));
        // A name that only contains dots is a name.
        assert!(lettered_folder(r"C:\Users\someone\..config").is_ok());
    }

    /// A scratch folder, by the path Windows itself gives for it, so that
    /// nothing in the path to it is a link or a short name.
    fn real_scratch(name: &str) -> String {
        let (_, real) = lettered_folder(
            &std::fs::canonicalize(scratch(name))
                .unwrap()
                .to_string_lossy(),
        )
        .expect("the temporary folder is on a lettered drive");
        real
    }

    /// Where the table cannot be read the folder is walked, and the answer is
    /// the same shape: its own name at the top, cut four folders down, and
    /// marked where it was cut.
    #[test]
    fn a_folder_that_has_to_be_walked_comes_back_in_the_same_shape() {
        let root = real_scratch("folder-walk");
        let base = Path::new(&root);
        write(&base.join("direct.bin"), 300);
        write(&base.join("games/one/data.bin"), 4_000);
        write(&base.join("a/b/c/d/e/deep.bin"), 2_000);

        let folder = walk_folder(&root).unwrap();
        assert_eq!(folder.method, ScanMethod::DirectoryWalk);
        assert_eq!(folder.unreadable, Some(0));
        assert_eq!(folder.path, root);
        assert_eq!(
            folder.tree.name,
            base.file_name().unwrap().to_string_lossy(),
            "one folder among others on a map is named by its own name"
        );
        assert_eq!((folder.tree.bytes, folder.tree.files), (6_300, 1));
        assert_eq!(child(&folder.tree, "games").bytes, 4_000);

        let floor = child(child(child(child(&folder.tree, "a"), "b"), "c"), "d");
        assert!(floor.children.is_empty() && floor.folded);
        let below = walk_folder(&floor.path).unwrap();
        assert_eq!(below.tree.bytes, floor.bytes);
        assert_eq!(child(&below.tree, "e").files, 1);

        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn a_walked_folder_that_is_gone_or_is_a_file_says_so() {
        let root = real_scratch("folder-walk-gone");
        let base = Path::new(&root);
        write(&base.join("kept/file.bin"), 10);

        let gone = walk_folder(&format!(r"{root}\removed\deeper")).unwrap_err();
        assert!(gone.to_string().contains("there is no folder at"), "{gone}");
        let file = walk_folder(&format!(r"{root}\kept\file.bin")).unwrap_err();
        assert!(
            file.to_string().contains("is a file, not a folder"),
            "{file}"
        );

        std::fs::remove_dir_all(base).unwrap();
    }

    fn junction(link: &Path, target: &Path) -> bool {
        std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    }

    /// A folder reached through a link is somewhere else, and is not walked
    /// under the name it was asked for.
    ///
    /// The walk lists its root by path, and Windows follows any link in a
    /// path. Without the look at every name on the way down, a link in the
    /// middle had another folder measured and shown under this one's path.
    #[test]
    fn a_folder_reached_through_a_link_is_not_walked() {
        let root = real_scratch("folder-walk-link");
        let base = Path::new(&root);
        let elsewhere = real_scratch("folder-walk-link-target");
        write(&Path::new(&elsewhere).join("inner/secret.bin"), 5_000);
        if !junction(&base.join("link"), Path::new(&elsewhere)) {
            // Nothing to show where a junction cannot be made.
            let _ = std::fs::remove_dir_all(base);
            let _ = std::fs::remove_dir_all(&elsewhere);
            return;
        }
        // The premise: by path, the link leads straight into the other folder.
        assert!(std::fs::read_dir(base.join("link").join("inner")).is_ok());

        for path in [format!(r"{root}\link"), format!(r"{root}\link\inner")] {
            let refusal = walk_folder(&path)
                .map(|folder| folder.tree.bytes)
                .expect_err("a folder behind a link was walked under the link's name");
            assert!(
                refusal.to_string().contains("is a link to somewhere else"),
                "{refusal}"
            );
        }
        // The folder itself, asked for where it really is, is still read.
        assert_eq!(walk_folder(&elsewhere).unwrap().tree.bytes, 5_000);

        // The link first, as a link, so the other folder is not emptied
        // through it.
        std::fs::remove_dir(base.join("link")).unwrap();
        std::fs::remove_dir_all(base).unwrap();
        std::fs::remove_dir_all(&elsewhere).unwrap();
    }
}
