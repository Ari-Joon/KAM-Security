//! Reading the NTFS master file table directly.
//!
//! Walking directories asks the filesystem about one folder at a time and pays
//! a round trip for each. NTFS already holds every answer in one place: the
//! `$MFT`, a flat array of fixed-size records, one per file and directory,
//! each carrying its own size and its parent's reference. Reading it end to end
//! and reassembling the tree in memory turns a minute of traversal into a
//! sequential read of a couple of gigabytes.
//!
//! This is the path `FSCTL_ENUM_USN_DATA` cannot provide, because that call
//! reports names and parents but no sizes.
//!
//! # What this costs
//!
//! Opening `\\.\C:` requires administrative rights. The agent has them when it
//! runs as a service; a console-mode agent started by an ordinary user does
//! not, and [`super::scan`] falls back to walking directories.
//!
//! # Where its numbers differ from a directory walk
//!
//! - **Alternate data streams are not counted.** Only the unnamed `$DATA`
//!   attribute is measured, which is the size Explorer reports.
//! - **Hard links are counted once**, against the first Win32 name found.
//!   A directory walk counts the bytes once per link.
//! - **Resident files** — small enough to live inside their own MFT record —
//!   are measured from the attribute value rather than a cluster count.
//!
//! # The two traps that make sizes wrong
//!
//! Both were live bugs here before the numbers were checked against Windows.
//!
//! 1. **Fragmented files spill into extension records.** When a file's runlist
//!    outgrows one record, NTFS allocates more and points at them. The base
//!    record can end up with no `$DATA` at all, so a naive reader reports a
//!    138 GB game archive as 0 bytes. Extension records are collected and
//!    merged back into the base they name.
//! 2. **Only the fragment at VCN 0 knows the size.** A file split across
//!    several `$DATA` attributes repeats the attribute once per run, and only
//!    the one starting at virtual cluster 0 carries the real length; the rest
//!    hold zero. Taking whichever comes first loses the file.
//!
//! Together these accounted for 270 GB on a 1 TB volume — the difference
//! between 73.6% and 99.6% agreement with the figure Windows reports.

use std::collections::HashMap;

use kam_core::{Error, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, SetFilePointerEx, FILE_ATTRIBUTE_NORMAL, FILE_BEGIN, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};

/// Record 5 is always the root directory.
const ROOT_RECORD: u64 = 5;

const ATTR_STANDARD_INFORMATION: u32 = 0x10;
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_DATA: u32 = 0x80;
const ATTR_END: u32 = 0xFFFF_FFFF;

const FLAG_IN_USE: u16 = 0x0001;
const FLAG_DIRECTORY: u16 = 0x0002;

/// Namespace values in `$FILE_NAME`. DOS-only names are 8.3 aliases of a name
/// we already have, so taking one would rename half the tree to `PROGRA~1`.
const NAMESPACE_DOS: u8 = 2;

/// Bytes pulled from the volume per read. Large enough that the read is
/// sequential rather than a series of seeks.
const CHUNK_BYTES: usize = 4 * 1024 * 1024;

/// One file or directory, as the table describes it.
#[derive(Debug, Clone)]
pub struct MftEntry {
    pub parent: u32,
    pub name: String,
    pub is_directory: bool,
    /// Unnamed `$DATA` size. Zero for directories.
    pub bytes: u64,
    /// Last write, as a Windows FILETIME: 100-nanosecond ticks since 1601.
    /// Zero when `$STANDARD_INFORMATION` was missing or unreadable.
    pub modified: u64,
}

/// Everything the table yielded, indexed by record number.
#[derive(Debug)]
pub struct MftSnapshot {
    pub entries: HashMap<u32, MftEntry>,
    pub root: u32,
    /// Records that were allocated but could not be parsed.
    pub skipped: u64,
    pub stats: MftStats,
}

/// Counts kept while reading, so a total that looks wrong can be traced to the
/// stage that lost it rather than guessed at.
#[derive(Debug, Default, Clone, Copy)]
pub struct MftStats {
    /// Records carrying the `FILE` signature.
    pub records_seen: u64,
    /// Of those, records marked in use.
    pub in_use: u64,
    /// In-use base records with no usable `$FILE_NAME`.
    pub nameless: u64,
    /// Records that hold attributes on behalf of another record.
    pub extensions: u64,
    /// Files whose size was recovered from an extension record.
    pub sizes_from_extensions: u64,
    /// Files left at zero bytes because no `$DATA` was found anywhere.
    pub sizeless_files: u64,
}

struct Volume(HANDLE);

impl Drop for Volume {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn win32(context: &str) -> Error {
    Error::Privileged(format!(
        "{context}: {}",
        windows::core::Error::from_thread()
    ))
}

fn read_u16(buffer: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(buffer.get(at..at + 2)?.try_into().ok()?))
}

fn read_u32(buffer: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(buffer.get(at..at + 4)?.try_into().ok()?))
}

fn read_u64(buffer: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(buffer.get(at..at + 8)?.try_into().ok()?))
}

/// Geometry read out of the NTFS boot sector.
#[derive(Debug, Clone, Copy)]
struct Geometry {
    bytes_per_sector: u64,
    bytes_per_cluster: u64,
    record_bytes: u64,
    mft_start_cluster: u64,
}

fn parse_boot_sector(boot: &[u8]) -> Result<Geometry> {
    if boot.get(3..11) != Some(b"NTFS    ") {
        return Err(Error::Refused("this volume is not NTFS".to_owned()));
    }

    let bytes_per_sector = read_u16(boot, 0x0B)
        .ok_or_else(|| Error::Refused("truncated boot sector".to_owned()))?
        as u64;
    let sectors_per_cluster_raw = *boot
        .get(0x0D)
        .ok_or_else(|| Error::Refused("truncated boot sector".to_owned()))?;

    // Values above 0x80 are a signed power of two rather than a count, which is
    // how volumes with clusters larger than 64 KB describe themselves.
    let sectors_per_cluster = if sectors_per_cluster_raw <= 0x80 {
        sectors_per_cluster_raw as u64
    } else {
        1_u64 << (256 - sectors_per_cluster_raw as u32)
    };

    let mft_start_cluster =
        read_u64(boot, 0x30).ok_or_else(|| Error::Refused("truncated boot sector".to_owned()))?;

    let clusters_per_record = *boot
        .get(0x40)
        .ok_or_else(|| Error::Refused("truncated boot sector".to_owned()))?
        as i8;

    let bytes_per_cluster = bytes_per_sector * sectors_per_cluster;

    // Positive means a cluster count; negative means 2^-n bytes directly, which
    // is what every modern volume uses (-10, for 1024-byte records).
    let record_bytes = if clusters_per_record > 0 {
        clusters_per_record as u64 * bytes_per_cluster
    } else {
        1_u64 << (-clusters_per_record) as u32
    };

    if bytes_per_sector == 0 || bytes_per_cluster == 0 || record_bytes == 0 {
        return Err(Error::Refused(
            "the boot sector describes an unusable geometry".to_owned(),
        ));
    }

    Ok(Geometry {
        bytes_per_sector,
        bytes_per_cluster,
        record_bytes,
        mft_start_cluster,
    })
}

impl Volume {
    fn open(drive_letter: char) -> Result<Self> {
        // The `\\.\C:` form addresses the volume itself rather than its root
        // directory, and is what allows reads at arbitrary byte offsets.
        let path: Vec<u16> = format!(r"\\.\{drive_letter}:")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe {
            CreateFileW(
                PCWSTR(path.as_ptr()),
                GENERIC_READ.0,
                // The volume is mounted and in use; without sharing both ways
                // the open fails outright.
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        }
        .map_err(|error| {
            Error::Privileged(format!(
                "could not open volume {drive_letter}: for raw reading \
                 (this needs administrative rights): {error}"
            ))
        })?;

        Ok(Self(handle))
    }

    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        unsafe {
            SetFilePointerEx(self.0, offset as i64, None, FILE_BEGIN)
                .map_err(|_| win32("could not seek on the volume"))?;
        }
        let mut read = 0_u32;
        unsafe { ReadFile(self.0, Some(buffer), Some(&mut read), None) }
            .map_err(|_| win32("could not read from the volume"))?;
        Ok(read as usize)
    }
}

/// A contiguous stretch of clusters belonging to one attribute.
#[derive(Debug, Clone, Copy)]
struct Run {
    start_cluster: u64,
    clusters: u64,
}

/// Decode the mapping pairs that describe where a non-resident attribute lives.
///
/// Each pair is a header byte splitting into two nibbles — how many bytes hold
/// the run's length, and how many hold its starting offset. The offset is
/// *signed* and *relative to the previous run*, so a fragmented file can point
/// backwards on the disk.
fn parse_runs(mapping: &[u8]) -> Vec<Run> {
    let mut runs = Vec::new();
    let mut cursor = 0_usize;
    let mut previous_lcn = 0_i64;

    while cursor < mapping.len() {
        let header = mapping[cursor];
        if header == 0 {
            break;
        }
        cursor += 1;

        let length_bytes = (header & 0x0F) as usize;
        let offset_bytes = (header >> 4) as usize;
        if length_bytes == 0 || cursor + length_bytes + offset_bytes > mapping.len() {
            break;
        }

        let mut clusters = 0_u64;
        for index in 0..length_bytes {
            clusters |= (mapping[cursor + index] as u64) << (index * 8);
        }
        cursor += length_bytes;

        if offset_bytes == 0 {
            // A sparse run: it occupies virtual space but no clusters.
            cursor += offset_bytes;
            previous_lcn += 0;
            continue;
        }

        // Sign-extend from the top byte of the offset field.
        let mut offset = 0_i64;
        for index in 0..offset_bytes {
            offset |= (mapping[cursor + index] as i64) << (index * 8);
        }
        let sign_bit = 1_i64 << (offset_bytes * 8 - 1);
        if offset & sign_bit != 0 {
            offset -= 1_i64 << (offset_bytes * 8);
        }
        cursor += offset_bytes;

        previous_lcn += offset;
        if previous_lcn >= 0 && clusters > 0 {
            runs.push(Run {
                start_cluster: previous_lcn as u64,
                clusters,
            });
        }
    }

    runs
}

/// Undo the update sequence protection applied to a multi-sector structure.
///
/// NTFS overwrites the last two bytes of every sector in a record with a shared
/// sequence number, keeping the originals in an array in the header. It is how
/// a torn write is detected. Skipping this step corrupts any attribute that
/// happens to straddle a sector boundary, which on a 1 KB record over 512-byte
/// sectors is most of them.
fn apply_fixups(record: &mut [u8], bytes_per_sector: u64) -> Option<()> {
    let offset = read_u16(record, 0x04)? as usize;
    let count = read_u16(record, 0x06)? as usize;
    if count == 0 {
        return None;
    }

    let signature = read_u16(record, offset)?;
    let sector_size = bytes_per_sector as usize;

    for sector in 0..count - 1 {
        let tail = (sector + 1) * sector_size;
        if tail < 2 || tail > record.len() {
            return None;
        }
        // Every protected sector must carry the signature; if one does not, the
        // record was torn and cannot be trusted.
        if read_u16(record, tail - 2)? != signature {
            return None;
        }
        let replacement = read_u16(record, offset + 2 + sector * 2)?;
        record[tail - 2..tail].copy_from_slice(&replacement.to_le_bytes());
    }

    Some(())
}

/// One record, decoded but not yet placed in the tree.
struct RawRecord {
    in_use: bool,
    is_directory: bool,
    /// Record this one holds attributes for. `None` when it is itself a base.
    base: Option<u32>,
    /// Namespace, name, parent index.
    name: Option<(u8, String, u32)>,
    /// Unnamed `$DATA` size, taken only from the fragment that starts at VCN 0.
    data: Option<u64>,
    /// Last write from `$STANDARD_INFORMATION`.
    modified: u64,
}

/// Pull the name, parent and size out of one MFT record.
fn parse_record(record: &[u8]) -> Option<RawRecord> {
    if record.get(0..4)? != b"FILE" {
        return None;
    }

    let flags = read_u16(record, 0x16)?;
    let in_use = flags & FLAG_IN_USE != 0;
    let is_directory = flags & FLAG_DIRECTORY != 0;

    // A record whose base reference is set is an extension: NTFS spilled this
    // file's attributes here because they would not fit in one record. Large
    // fragmented files do this routinely, and their $DATA — with it, their
    // size — lives out here rather than in the base record.
    let base_reference = read_u64(record, 0x20)?;
    let base = match (base_reference & 0x0000_FFFF_FFFF_FFFF) as u32 {
        0 => None,
        index => Some(index),
    };

    let mut cursor = read_u16(record, 0x14)? as usize;
    let used = read_u32(record, 0x18)? as usize;
    let limit = used.min(record.len());

    let mut best_name: Option<(u8, String, u32)> = None;
    let mut data_size: Option<u64> = None;
    let mut modified = 0_u64;

    while cursor + 8 <= limit {
        let attribute_type = read_u32(record, cursor)?;
        if attribute_type == ATTR_END {
            break;
        }
        let length = read_u32(record, cursor + 4)? as usize;
        if length < 8 || cursor + length > limit {
            break;
        }
        let non_resident = *record.get(cursor + 0x08)? != 0;

        match attribute_type {
            ATTR_STANDARD_INFORMATION if !non_resident => {
                // Creation, modification, MFT-change and access times, in that
                // order. The modification time is the one a person means by
                // "last touched", and drives the orphan confidence scoring.
                let value_offset = read_u16(record, cursor + 0x14)? as usize;
                modified = read_u64(record, cursor + value_offset + 0x08).unwrap_or(0);
            }
            ATTR_FILE_NAME if !non_resident => {
                let value_offset = read_u16(record, cursor + 0x14)? as usize;
                let value = cursor + value_offset;
                let parent_reference = read_u64(record, value)?;
                // The upper 16 bits are a reuse counter, not part of the index.
                let parent = (parent_reference & 0x0000_FFFF_FFFF_FFFF) as u32;
                let name_length = *record.get(value + 0x40)? as usize;
                let namespace = *record.get(value + 0x41)?;

                let start = value + 0x42;
                let units: Vec<u16> = (0..name_length)
                    .filter_map(|index| read_u16(record, start + index * 2))
                    .collect();
                let name = String::from_utf16_lossy(&units);

                // Prefer a real name over its 8.3 alias, and take the first
                // otherwise. A file can carry several names via hard links.
                let better = match &best_name {
                    None => true,
                    Some((existing, _, _)) => {
                        *existing == NAMESPACE_DOS && namespace != NAMESPACE_DOS
                    }
                };
                if better {
                    best_name = Some((namespace, name, parent));
                }
            }
            ATTR_DATA => {
                // Only the unnamed stream counts; a named one is an alternate
                // data stream and is not what Explorer shows as the file size.
                let name_length = *record.get(cursor + 0x09)?;
                if name_length != 0 {
                    cursor += length;
                    continue;
                }
                if non_resident {
                    // A fragmented file has several $DATA attributes, one per
                    // run of VCNs. Only the fragment beginning at VCN 0 carries
                    // the true size; the others hold zero there, and reading
                    // one of those is how a 40 GB file becomes a 0 GB file.
                    let lowest_vcn = read_u64(record, cursor + 0x10)?;
                    if lowest_vcn == 0 && data_size.is_none() {
                        data_size = Some(read_u64(record, cursor + 0x30)?);
                    }
                } else if data_size.is_none() {
                    data_size = Some(read_u32(record, cursor + 0x10)? as u64);
                }
            }
            _ => {}
        }

        cursor += length;
    }

    Some(RawRecord {
        in_use,
        is_directory,
        base,
        name: best_name,
        data: data_size,
        modified,
    })
}

/// Read the whole master file table for one drive letter.
pub fn read(drive_letter: char) -> Result<MftSnapshot> {
    let volume = Volume::open(drive_letter)?;

    let mut boot = vec![0_u8; 512];
    volume.read_at(0, &mut boot)?;
    let geometry = parse_boot_sector(&boot)?;

    // Record 0 describes the $MFT itself, including where the rest of it lives.
    let mut first = vec![0_u8; geometry.record_bytes as usize];
    volume.read_at(
        geometry.mft_start_cluster * geometry.bytes_per_cluster,
        &mut first,
    )?;
    apply_fixups(&mut first, geometry.bytes_per_sector)
        .ok_or_else(|| Error::Refused("the $MFT record failed its fixup check".to_owned()))?;

    let runs = mft_runs(&first)?;
    if runs.is_empty() {
        return Err(Error::Refused("the $MFT reported no data runs".to_owned()));
    }

    let mut entries: HashMap<u32, MftEntry> = HashMap::with_capacity(1 << 18);
    // Sizes found in extension records, keyed by the base they belong to. An
    // extension can be read before or after its base, so they are collected
    // separately and merged at the end.
    let mut extension_sizes: HashMap<u32, u64> = HashMap::new();
    let mut stats = MftStats::default();
    let mut skipped = 0_u64;
    let record_bytes = geometry.record_bytes as usize;

    // Records are parsed out of a rolling buffer rather than assuming they sit
    // neatly inside a run: with 512-byte clusters a run can end mid-record.
    let mut carry: Vec<u8> = Vec::new();
    let mut record_index: u32 = 0;
    let mut chunk = vec![0_u8; CHUNK_BYTES];

    for run in &runs {
        let mut remaining = run.clusters * geometry.bytes_per_cluster;
        let mut offset = run.start_cluster * geometry.bytes_per_cluster;

        while remaining > 0 {
            let want = remaining.min(CHUNK_BYTES as u64) as usize;
            let read = volume.read_at(offset, &mut chunk[..want])?;
            if read == 0 {
                break;
            }
            offset += read as u64;
            remaining -= read as u64;

            carry.extend_from_slice(&chunk[..read]);

            let whole = carry.len() / record_bytes;
            for index in 0..whole {
                let start = index * record_bytes;
                let record = &mut carry[start..start + record_bytes];
                let is_file_record = record.get(0..4) == Some(b"FILE");
                if is_file_record {
                    stats.records_seen += 1;
                }

                if apply_fixups(record, geometry.bytes_per_sector).is_some() {
                    if let Some(raw) = parse_record(record) {
                        if raw.in_use {
                            stats.in_use += 1;
                            match raw.base {
                                Some(base) => {
                                    stats.extensions += 1;
                                    if let Some(bytes) = raw.data {
                                        extension_sizes.insert(base, bytes);
                                    }
                                }
                                None => match raw.name {
                                    Some((_, name, parent)) => {
                                        entries.insert(
                                            record_index,
                                            MftEntry {
                                                parent,
                                                name,
                                                is_directory: raw.is_directory,
                                                bytes: if raw.is_directory {
                                                    0
                                                } else {
                                                    raw.data.unwrap_or(0)
                                                },
                                                modified: raw.modified,
                                            },
                                        );
                                    }
                                    None => stats.nameless += 1,
                                },
                            }
                        }
                    }
                } else if is_file_record {
                    skipped += 1;
                }
                record_index = record_index.saturating_add(1);
            }
            carry.drain(..whole * record_bytes);
        }
    }

    // Give every base record that came up empty the size its extension holds.
    for (index, entry) in entries.iter_mut() {
        if entry.is_directory || entry.bytes != 0 {
            continue;
        }
        match extension_sizes.get(index) {
            Some(bytes) => {
                entry.bytes = *bytes;
                stats.sizes_from_extensions += 1;
            }
            // Genuinely empty files exist, so this is only a signal in bulk.
            None => stats.sizeless_files += 1,
        }
    }

    Ok(MftSnapshot {
        entries,
        root: ROOT_RECORD as u32,
        skipped,
        stats,
    })
}

/// Find the `$DATA` runs inside the `$MFT`'s own record.
fn mft_runs(record: &[u8]) -> Result<Vec<Run>> {
    let malformed = || Error::Refused("the $MFT record could not be parsed".to_owned());

    let mut cursor = read_u16(record, 0x14).ok_or_else(malformed)? as usize;
    let used = read_u32(record, 0x18).ok_or_else(malformed)? as usize;
    let limit = used.min(record.len());

    while cursor + 8 <= limit {
        let attribute_type = read_u32(record, cursor).ok_or_else(malformed)?;
        if attribute_type == ATTR_END {
            break;
        }
        let length = read_u32(record, cursor + 4).ok_or_else(malformed)? as usize;
        if length < 8 || cursor + length > limit {
            break;
        }

        if attribute_type == ATTR_DATA && *record.get(cursor + 0x08).ok_or_else(malformed)? != 0 {
            let mapping_offset = read_u16(record, cursor + 0x20).ok_or_else(malformed)? as usize;
            let mapping = record
                .get(cursor + mapping_offset..cursor + length)
                .ok_or_else(malformed)?;
            return Ok(parse_runs(mapping));
        }

        cursor += length;
    }

    Err(malformed())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn boot_sector(sectors_per_cluster: u8, clusters_per_record: i8) -> Vec<u8> {
        let mut boot = vec![0_u8; 512];
        boot[3..11].copy_from_slice(b"NTFS    ");
        boot[0x0B..0x0D].copy_from_slice(&512_u16.to_le_bytes());
        boot[0x0D] = sectors_per_cluster;
        boot[0x30..0x38].copy_from_slice(&786_432_u64.to_le_bytes());
        boot[0x40] = clusters_per_record as u8;
        boot
    }

    #[test]
    fn typical_geometry_is_read_correctly() {
        // 8 sectors per cluster, records described as 2^10 bytes.
        let geometry = parse_boot_sector(&boot_sector(8, -10)).unwrap();
        assert_eq!(geometry.bytes_per_sector, 512);
        assert_eq!(geometry.bytes_per_cluster, 4096);
        assert_eq!(geometry.record_bytes, 1024);
        assert_eq!(geometry.mft_start_cluster, 786_432);
    }

    #[test]
    fn a_positive_record_size_means_clusters_not_bytes() {
        let geometry = parse_boot_sector(&boot_sector(1, 2)).unwrap();
        assert_eq!(geometry.bytes_per_cluster, 512);
        assert_eq!(geometry.record_bytes, 1024);
    }

    #[test]
    fn a_non_ntfs_volume_is_rejected_rather_than_misread() {
        let mut boot = boot_sector(8, -10);
        boot[3..11].copy_from_slice(b"MSDOS5.0");
        assert!(matches!(parse_boot_sector(&boot), Err(Error::Refused(_))));
    }

    #[test]
    fn runs_decode_lengths_and_relative_offsets() {
        // 0x21: one length byte, two offset bytes. Length 0x18, offset 0x0233.
        // 0x11: one and one. Length 0x08, offset +0x20 from the previous start.
        let mapping = [0x21, 0x18, 0x33, 0x02, 0x11, 0x08, 0x20, 0x00];
        let runs = parse_runs(&mapping);
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].clusters, 0x18);
        assert_eq!(runs[0].start_cluster, 0x0233);
        assert_eq!(runs[1].clusters, 0x08);
        assert_eq!(runs[1].start_cluster, 0x0233 + 0x20);
    }

    #[test]
    fn a_negative_offset_moves_backwards_on_the_disk() {
        // Second run starts 0x10 clusters *before* the first: fragmentation
        // does not have to run forwards.
        let mapping = [0x11, 0x10, 0x40, 0x11, 0x08, 0xF0, 0x00];
        let runs = parse_runs(&mapping);
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].start_cluster, 0x40);
        assert_eq!(runs[1].start_cluster, 0x40 - 0x10);
    }

    #[test]
    fn fixups_restore_the_bytes_the_sequence_number_replaced() {
        let mut record = vec![0_u8; 1024];
        record[0..4].copy_from_slice(b"FILE");
        record[0x04..0x06].copy_from_slice(&48_u16.to_le_bytes()); // array offset
        record[0x06..0x08].copy_from_slice(&3_u16.to_le_bytes()); // signature + 2
        record[48..50].copy_from_slice(&0xBEEF_u16.to_le_bytes());
        record[50..52].copy_from_slice(&0x1111_u16.to_le_bytes());
        record[52..54].copy_from_slice(&0x2222_u16.to_le_bytes());
        // Each protected sector currently ends with the signature.
        record[510..512].copy_from_slice(&0xBEEF_u16.to_le_bytes());
        record[1022..1024].copy_from_slice(&0xBEEF_u16.to_le_bytes());

        assert!(apply_fixups(&mut record, 512).is_some());
        assert_eq!(read_u16(&record, 510).unwrap(), 0x1111);
        assert_eq!(read_u16(&record, 1022).unwrap(), 0x2222);
    }

    #[test]
    fn a_torn_record_is_rejected() {
        let mut record = vec![0_u8; 1024];
        record[0..4].copy_from_slice(b"FILE");
        record[0x04..0x06].copy_from_slice(&48_u16.to_le_bytes());
        record[0x06..0x08].copy_from_slice(&3_u16.to_le_bytes());
        record[48..50].copy_from_slice(&0xBEEF_u16.to_le_bytes());
        // Second sector carries the wrong signature: the write was torn.
        record[510..512].copy_from_slice(&0xBEEF_u16.to_le_bytes());
        record[1022..1024].copy_from_slice(&0xDEAD_u16.to_le_bytes());

        assert!(apply_fixups(&mut record, 512).is_none());
    }
}
