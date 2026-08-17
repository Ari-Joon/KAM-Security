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

use std::collections::HashMap;
use std::io::Read;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use kam_core::{Cancelled, Reporter};
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
    /// What keeping every copy but one costs.
    pub wasted_bytes: u64,
    /// Every copy found, largest directory tree first is not meaningful here so
    /// they are left in the order the table produced.
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateSummary {
    pub groups: usize,
    /// Total reclaimable if every group were reduced to a single copy.
    pub wasted_bytes: u64,
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
            groups.push(DuplicateGroup {
                bytes: size,
                wasted_bytes: size * (identical.len() as u64 - 1),
                paths: identical,
            });
        }
    }
    groups
}

/// Find duplicate files on an indexed volume.
pub fn find(
    index: &VolumeIndex,
    drive_root: &str,
    reporter: &Reporter,
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
    reporter.stage("Comparing files of equal size", Some(size_groups.len() as u64));

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
                        found.extend(resolve_group(records, index, drive_root, counters));
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
    groups.sort_by_key(|group| std::cmp::Reverse(group.wasted_bytes));

    let summary = DuplicateSummary {
        groups: groups.len(),
        wasted_bytes: groups.iter().map(|group| group.wasted_bytes).sum(),
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
) -> kam_core::Result<(Vec<DuplicateGroup>, DuplicateSummary)> {
    reporter.stage("Reading the file table", None);
    let snapshot = crate::mft::read(drive_letter)?;
    let index = VolumeIndex::build(snapshot);
    find(&index, &format!("{drive_letter}:"), reporter)
        .map_err(|_| kam_core::Error::Refused("stopped at your request".to_owned()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

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

    #[test]
    fn wasted_bytes_is_what_keeping_one_copy_would_save() {
        // Three copies of a 1 GB file waste 2 GB, not 3.
        let group = DuplicateGroup {
            bytes: 1_000_000_000,
            wasted_bytes: 2_000_000_000,
            paths: vec!["a".into(), "b".into(), "c".into()],
        };
        assert_eq!(
            group.bytes * (group.paths.len() as u64 - 1),
            group.wasted_bytes
        );
    }
}
