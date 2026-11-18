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

/// Bytes read to see the boot sector.
///
/// A raw read from a volume has to be a whole number of the disk's sectors.
/// The boot sector's contents fit in 512 bytes and this used to ask for
/// exactly that, which is not a whole sector on a disk whose sectors are 4096
/// bytes: the read failed, and the reader never worked on such a disk at all.
/// 4096 is a whole number of sectors for both sizes.
const BOOT_READ_BYTES: usize = 4096;

/// How far apart NTFS puts the bytes it protects in a record.
///
/// Always 512, whatever the disk's own sector size. The boot sector's
/// "bytes per sector" is the disk's, and on a disk with 4096-byte sectors it
/// is a different number: stepping through a record by it lands past the end
/// of the record at the second step, so every record on such a disk failed
/// its check.
const FIXUP_STRIDE: usize = 512;

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
    /// When the file was created here. For a download this is when it arrived.
    pub created: u64,
    /// Last read. Whether Windows keeps this up to date is a setting that
    /// differs by machine, so it cannot be trusted without checking; see
    /// [`crate::provenance::access_times`]. Where it is kept, any program that
    /// reads the file moves it, and Windows writes it down to within an hour.
    pub accessed: u64,
}

/// Everything the table yielded, indexed by record number.
#[derive(Debug)]
pub struct MftSnapshot {
    /// The drive this table was read from, as an upper-case letter. A table
    /// describes one drive and nothing in it says which, so it is carried
    /// here: the same folder names exist on more than one drive, and a size
    /// read from one must never be shown against a path on another.
    pub drive: char,
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
    /// Milliseconds spent inside the reads themselves.
    ///
    /// Kept beside the counters because "the table read is slow" has two very
    /// different causes with two very different fixes, and guessing which costs
    /// an afternoon. Everything else in the read is parsing.
    pub io_millis: u64,
    /// Bytes pulled off the volume.
    pub bytes_read: u64,
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
///
/// The disk's own sector size is read on the way to the cluster size and not
/// kept. Nothing after the boot sector is measured in it: records are
/// protected every 512 bytes whatever the disk ([`FIXUP_STRIDE`]), and every
/// read here is of whole clusters or whole records.
#[derive(Debug, Clone, Copy)]
struct Geometry {
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
}

/// Somewhere a volume's bytes can be read from, at any offset.
///
/// The real one is a handle on the volume, which needs administrative rights
/// and a disk of the right kind to exercise. Reading through this instead
/// means the whole reader can be run against a volume made up in memory, with
/// whatever sector size and whatever layout a test needs.
trait RawVolume {
    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize>;
}

impl RawVolume for Volume {
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
/// NTFS overwrites the last two bytes of every 512 bytes in a record with a
/// shared sequence number, keeping the originals in an array in the header. It
/// is how a torn write is detected. Skipping this step corrupts any attribute
/// that happens to straddle one of those boundaries, which in a 1 KB record is
/// most of them.
fn apply_fixups(record: &mut [u8]) -> Option<()> {
    let offset = read_u16(record, 0x04)? as usize;
    let count = read_u16(record, 0x06)? as usize;
    if count == 0 {
        return None;
    }

    let signature = read_u16(record, offset)?;

    for sector in 0..count - 1 {
        let tail = (sector + 1) * FIXUP_STRIDE;
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
    /// Timestamps from `$STANDARD_INFORMATION`.
    modified: u64,
    created: u64,
    accessed: u64,
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
    let mut created = 0_u64;
    let mut accessed = 0_u64;

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
                // Creation, modification, MFT-change and access, at +0x00,
                // +0x08, +0x10 and +0x18. Modification is what a person means
                // by "last touched"; creation is when a download arrived.
                let value_offset = read_u16(record, cursor + 0x14)? as usize;
                let value = cursor + value_offset;
                created = read_u64(record, value).unwrap_or(0);
                modified = read_u64(record, value + 0x08).unwrap_or(0);
                accessed = read_u64(record, value + 0x18).unwrap_or(0);
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
        created,
        accessed,
    })
}

/// One run of whole records, handed to a parser thread.
///
/// The framing stays on the reading thread. Deciding where a record begins is
/// the part that has to happen in order — a run can end mid-record, so the
/// remainder carries into the next read — and it is also the cheap part. What
/// gets handed out is always a whole number of records, with the index of the
/// first, so a worker can label its results without knowing what came before.
struct Block {
    /// Position in the stream, so results merge in the order they were read.
    sequence: usize,
    first_record: u32,
    bytes: Vec<u8>,
}

/// What one block yielded.
#[derive(Default)]
struct Parsed {
    entries: Vec<(u32, MftEntry)>,
    extension_sizes: Vec<(u32, u64)>,
    stats: MftStats,
    skipped: u64,
}

/// Parse every record in one block.
///
/// This is the same work the reader used to do inline, moved somewhere it can
/// happen several times at once. On this machine the table holds 1.9 million
/// records: reading them off an NVMe disk takes about half a second and parsing
/// them took nearly two, so the disk was idle for three quarters of the wait.
fn parse_block(block: &mut Block, record_bytes: usize) -> Parsed {
    let mut parsed = Parsed::default();
    let mut record_index = block.first_record;

    for start in (0..block.bytes.len()).step_by(record_bytes) {
        let record = &mut block.bytes[start..start + record_bytes];
        let is_file_record = record.get(0..4) == Some(b"FILE");
        if is_file_record {
            parsed.stats.records_seen += 1;
        }

        if apply_fixups(record).is_some() {
            if let Some(raw) = parse_record(record) {
                if raw.in_use {
                    parsed.stats.in_use += 1;
                    match raw.base {
                        Some(base) => {
                            parsed.stats.extensions += 1;
                            if let Some(bytes) = raw.data {
                                parsed.extension_sizes.push((base, bytes));
                            }
                        }
                        None => match raw.name {
                            Some((_, name, parent)) => parsed.entries.push((
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
                                    created: raw.created,
                                    accessed: raw.accessed,
                                },
                            )),
                            None => parsed.stats.nameless += 1,
                        },
                    }
                }
            }
        } else if is_file_record {
            parsed.skipped += 1;
        }

        record_index = record_index.saturating_add(1);
    }

    parsed
}

/// Read buffers, waiting to be used again.
///
/// A survey reads about two gigabytes of table in four-megabyte pieces, and a
/// fresh `Vec` for each one is two gigabytes of zeroing that nothing ever looks
/// at before the disk overwrites it. Handing the buffers back means the memory
/// is written once by the disk instead of twice.
///
/// The pool is capped, so the memory in flight stays bounded by the number of
/// parsers rather than by the size of the volume.
struct BufferPool {
    spare: std::sync::Mutex<Vec<Vec<u8>>>,
    limit: usize,
}

impl BufferPool {
    fn new(limit: usize) -> Self {
        Self {
            spare: std::sync::Mutex::new(Vec::with_capacity(limit)),
            limit,
        }
    }

    /// A buffer of exactly `want` bytes, recycled where possible.
    ///
    /// Growing a recycled buffer only zeroes the few bytes it was short by,
    /// because it comes back holding whole records and goes out holding the
    /// same chunk size.
    fn take(&self, want: usize) -> Vec<u8> {
        let mut buffer = match self.spare.lock() {
            Ok(mut spare) => spare.pop().unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        buffer.clear();
        buffer.resize(want, 0);
        buffer
    }

    fn give_back(&self, buffer: Vec<u8>) {
        if let Ok(mut spare) = self.spare.lock() {
            if spare.len() < self.limit {
                spare.push(buffer);
            }
        }
    }
}

/// Read the whole master file table for one drive letter.
pub fn read(drive_letter: char) -> Result<MftSnapshot> {
    let volume = Volume::open(drive_letter)?;
    read_from(&volume, drive_letter)
}

/// Read the whole master file table of a volume that is already open.
fn read_from(volume: &impl RawVolume, drive_letter: char) -> Result<MftSnapshot> {
    let mut boot = vec![0_u8; BOOT_READ_BYTES];
    let read = volume.read_at(0, &mut boot)?;
    // A read that came back short is not an NTFS volume failing to be one,
    // and is not reported as that.
    if read < 512 {
        return Err(Error::Refused(
            "the start of the volume could not be read".to_owned(),
        ));
    }
    boot.truncate(read);
    let geometry = parse_boot_sector(&boot)?;

    // Record 0 describes the $MFT itself, including where the rest of it lives.
    let mut first = vec![0_u8; geometry.record_bytes as usize];
    volume.read_at(
        geometry.mft_start_cluster * geometry.bytes_per_cluster,
        &mut first,
    )?;
    apply_fixups(&mut first)
        .ok_or_else(|| Error::Refused("the $MFT record failed its fixup check".to_owned()))?;

    let runs = mft_runs(&first, geometry.bytes_per_cluster)?;
    if runs.is_empty() {
        return Err(Error::Refused("the $MFT reported no data runs".to_owned()));
    }

    let mut io_millis = 0_u64;
    let mut bytes_read = 0_u64;

    let record_bytes = geometry.record_bytes as usize;

    // One thread reads, the rest parse.
    //
    // The reading is nearly free and the parsing is not: 1.9 million records
    // came off this machine's disk in about half a second and took nearly two
    // to interpret, so for three quarters of the wait the disk sat idle and one
    // core did arithmetic. The queue is deliberately short -- a few blocks in
    // flight, not the whole table -- so the memory this costs stays in the tens
    // of megabytes rather than the size of the volume's table.
    let threads = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(4)
        .clamp(1, 8);
    let (sender, receiver) = std::sync::mpsc::sync_channel::<Block>(threads + 1);
    let receiver = std::sync::Mutex::new(receiver);
    let pool = BufferPool::new(threads + 2);

    let mut read_error: Option<Error> = None;
    let mut blocks_sent = 0_usize;
    let mut blocks: Vec<(usize, Parsed)> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                let receiver = &receiver;
                let pool = &pool;
                scope.spawn(move || {
                    let mut mine = Vec::new();
                    loop {
                        // The lock is held only long enough to take one block,
                        // never while parsing it.
                        let taken = match receiver.lock() {
                            Ok(queue) => queue.recv(),
                            Err(_) => break,
                        };
                        let Ok(mut block) = taken else { break };
                        let parsed = parse_block(&mut block, record_bytes);
                        mine.push((block.sequence, parsed));
                        pool.give_back(block.bytes);
                    }
                    mine
                })
            })
            .collect();

        // Reading happens here, on the thread that already owns the volume
        // handle, and the queue's depth is what stops it running ahead.
        //
        // Records are framed out of a rolling remainder rather than assumed to
        // sit neatly inside a run: with 512-byte clusters a run can end
        // mid-record, and the tail has to join the front of the next read.
        let mut carry: Vec<u8> = Vec::new();
        let mut record_index: u32 = 0;
        let mut sequence = 0_usize;

        'reading: for run in &runs {
            let mut remaining = run.clusters * geometry.bytes_per_cluster;
            let mut offset = run.start_cluster * geometry.bytes_per_cluster;

            while remaining > 0 {
                let want = remaining.min(CHUNK_BYTES as u64) as usize;
                // Handed away to a parser, and handed back when it is done.
                let mut buffer = pool.take(want);

                let waited = std::time::Instant::now();
                let read = match volume.read_at(offset, &mut buffer) {
                    Ok(read) => read,
                    Err(error) => {
                        read_error = Some(error);
                        break 'reading;
                    }
                };
                io_millis += waited.elapsed().as_millis() as u64;
                bytes_read += read as u64;
                if read == 0 {
                    break;
                }
                offset += read as u64;
                remaining -= read as u64;
                buffer.truncate(read);

                // Only happens at a run boundary, where the previous read
                // stopped part-way through a record.
                if !carry.is_empty() {
                    let mut joined = Vec::with_capacity(carry.len() + buffer.len());
                    joined.extend_from_slice(&carry);
                    joined.extend_from_slice(&buffer);
                    carry.clear();
                    buffer = joined;
                }

                let whole = buffer.len() / record_bytes;
                if whole == 0 {
                    carry = buffer;
                    continue;
                }
                let take = whole * record_bytes;
                carry.extend_from_slice(&buffer[take..]);
                buffer.truncate(take);

                if sender
                    .send(Block {
                        sequence,
                        first_record: record_index,
                        bytes: buffer,
                    })
                    .is_err()
                {
                    // Every parser has gone, which cannot happen while this
                    // thread holds the only sender -- but there is nothing to
                    // read for if it does.
                    break 'reading;
                }
                sequence += 1;
                record_index = record_index.saturating_add(whole as u32);
            }
        }

        // Closing the queue is what tells the parsers there is no more.
        drop(sender);
        blocks_sent = sequence;

        let mut all = Vec::new();
        for worker in workers {
            if let Ok(mine) = worker.join() {
                all.extend(mine);
            }
        }
        all
    });

    if let Some(error) = read_error {
        return Err(error);
    }

    // A table read in part is not a table, and is never returned as one.
    //
    // Two ways it could be, both of which used to pass without a word. A read
    // that came back short ended that piece of the table and went on to the
    // next, which lost the records in between and numbered every later one
    // wrongly, so parents pointed at the wrong folders. And a parser thread
    // that died took the blocks it had finished with it. Either way the result
    // was a smaller drive than the real one, presented as the whole of it.
    let listed_bytes = runs.iter().fold(0_u64, |total, run| {
        total.saturating_add(run.clusters.saturating_mul(geometry.bytes_per_cluster))
    });
    if bytes_read < listed_bytes {
        return Err(Error::Refused(format!(
            "the file table on this drive could only be read in part ({} of {}), so \
             it was not used",
            megabytes(bytes_read),
            megabytes(listed_bytes)
        )));
    }
    if blocks.len() != blocks_sent {
        return Err(Error::Refused(format!(
            "part of the file table on this drive was read and then lost before it \
             could be interpreted ({} of {blocks_sent} blocks were), so it was not used",
            blocks.len()
        )));
    }

    // Merged in the order the blocks were read, so the result does not depend
    // on which thread happened to finish first.
    blocks.sort_by_key(|(sequence, _)| *sequence);

    let mut entries: HashMap<u32, MftEntry> = HashMap::with_capacity(1 << 18);
    // Sizes found in extension records, keyed by the base they belong to. An
    // extension can be read before or after its base, so they are collected
    // separately and merged at the end.
    let mut extension_sizes: HashMap<u32, u64> = HashMap::new();
    let mut stats = MftStats::default();
    let mut skipped = 0_u64;

    for (_, parsed) in blocks {
        entries.extend(parsed.entries);
        extension_sizes.extend(parsed.extension_sizes);
        skipped += parsed.skipped;
        stats.records_seen += parsed.stats.records_seen;
        stats.in_use += parsed.stats.in_use;
        stats.nameless += parsed.stats.nameless;
        stats.extensions += parsed.stats.extensions;
    }
    stats.io_millis = io_millis;
    stats.bytes_read = bytes_read;

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
        drive: drive_letter.to_ascii_uppercase(),
        entries,
        root: ROOT_RECORD as u32,
        skipped,
        stats,
    })
}

/// A size the way a person would say it, for a refusal somebody will read.
fn megabytes(bytes: u64) -> String {
    format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
}

/// Find the `$DATA` runs inside the `$MFT`'s own record.
///
/// # The list can run on past this record
///
/// A table that has grown in a great many pieces, as on an old and nearly full
/// hard disk, has more pieces than one record holds. NTFS then continues the
/// list in other records, and this reads only the first. It used to return
/// that part as though it were all of it: the reader read the first stretch of
/// the table, found the files recorded there, and reported a drive that
/// looked half empty, with nothing to say so.
///
/// The record states how long the table is, so the two are compared. A list
/// that covers less than the table holds is refused, with both figures. Scan
/// then walks the folders and gives this as its reason, and the pages with no
/// other route show it. Following the continuation is not done here.
fn mft_runs(record: &[u8], bytes_per_cluster: u64) -> Result<Vec<Run>> {
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
            let runs = parse_runs(mapping);

            // The table's length in bytes, which only this first piece of the
            // attribute carries. Measured against what holds records rather
            // than against what is set aside for the table to grow into: a
            // list that reaches every record is whole for this purpose.
            let table_bytes = read_u64(record, cursor + 0x30).ok_or_else(malformed)?;
            let listed_bytes = runs.iter().fold(0_u64, |total, run| {
                total.saturating_add(run.clusters.saturating_mul(bytes_per_cluster))
            });
            if listed_bytes < table_bytes {
                return Err(Error::Refused(format!(
                    "the file table on this drive is in too many pieces to read directly: \
                     its first record lists {} of {}, and reading only that much would \
                     leave files out",
                    megabytes(listed_bytes),
                    megabytes(table_bytes)
                )));
            }
            return Ok(runs);
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

        assert!(apply_fixups(&mut record).is_some());
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

        assert!(apply_fixups(&mut record).is_none());
    }

    // What follows reads whole volumes made up in memory. The real reader
    // needs administrative rights and a disk of the kind being tested, and the
    // two kinds it got wrong are ones the development machine does not have.
    // These are built from the layout NTFS documents, by somebody reading that
    // layout, so they show that the reader does what the layout asks. They are
    // not a real disk of either kind.

    fn put(buffer: &mut [u8], at: usize, bytes: &[u8]) {
        buffer[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn rounded_to_eight(length: usize) -> usize {
        (length + 7) & !7
    }

    /// An attribute whose value sits inside the record.
    fn resident(kind: u32, value: &[u8]) -> Vec<u8> {
        const HEADER: usize = 0x18;
        let mut attribute = vec![0_u8; rounded_to_eight(HEADER + value.len())];
        let length = attribute.len() as u32;
        put(&mut attribute, 0x00, &kind.to_le_bytes());
        put(&mut attribute, 0x04, &length.to_le_bytes());
        put(&mut attribute, 0x10, &(value.len() as u32).to_le_bytes());
        put(&mut attribute, 0x14, &(HEADER as u16).to_le_bytes());
        put(&mut attribute, HEADER, value);
        attribute
    }

    fn standard_information(modified: u64) -> Vec<u8> {
        let mut value = vec![0_u8; 0x30];
        put(&mut value, 0x08, &modified.to_le_bytes());
        resident(ATTR_STANDARD_INFORMATION, &value)
    }

    fn file_name(parent: u32, name: &str) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut value = vec![0_u8; 0x42 + units.len() * 2];
        put(&mut value, 0x00, &(parent as u64).to_le_bytes());
        value[0x40] = units.len() as u8;
        // The Win32 namespace: an ordinary long name.
        value[0x41] = 1;
        for (position, unit) in units.iter().enumerate() {
            put(&mut value, 0x42 + position * 2, &unit.to_le_bytes());
        }
        resident(ATTR_FILE_NAME, &value)
    }

    /// An unnamed `$DATA` whose contents live in clusters, as a list of
    /// (clusters, first cluster) pieces. `bytes` is the length it states.
    fn data_in_clusters(pieces: &[(u8, u16)], bytes: u64) -> Vec<u8> {
        const HEADER: usize = 0x40;
        let mut mapping = Vec::new();
        let mut previous = 0_i32;
        for (clusters, first) in pieces {
            // One byte of length, two of offset from the piece before.
            let step = (*first as i32 - previous) as i16;
            mapping.push(0x21);
            mapping.push(*clusters);
            mapping.extend_from_slice(&step.to_le_bytes());
            previous = *first as i32;
        }
        mapping.push(0);

        let mut attribute = vec![0_u8; rounded_to_eight(HEADER + mapping.len())];
        let length = attribute.len() as u32;
        put(&mut attribute, 0x00, &ATTR_DATA.to_le_bytes());
        put(&mut attribute, 0x04, &length.to_le_bytes());
        attribute[0x08] = 1;
        put(&mut attribute, 0x20, &(HEADER as u16).to_le_bytes());
        put(&mut attribute, 0x28, &bytes.to_le_bytes());
        put(&mut attribute, 0x30, &bytes.to_le_bytes());
        put(&mut attribute, 0x38, &bytes.to_le_bytes());
        put(&mut attribute, HEADER, &mapping);
        attribute
    }

    const IN_USE: u16 = FLAG_IN_USE;
    const IN_USE_DIRECTORY: u16 = FLAG_IN_USE | FLAG_DIRECTORY;

    /// One record of `size` bytes, protected the way NTFS protects it: the
    /// last two bytes of every 512 moved into the header, and a sequence
    /// number left in their place.
    fn file_record(size: usize, flags: u16, attributes: &[Vec<u8>]) -> Vec<u8> {
        const ARRAY: usize = 0x30;
        const SEQUENCE: u16 = 0x0C0A;
        let strides = size / 512;
        let first_attribute = rounded_to_eight(ARRAY + 2 * (strides + 1));

        let mut record = vec![0_u8; size];
        put(&mut record, 0x00, b"FILE");
        put(&mut record, 0x04, &(ARRAY as u16).to_le_bytes());
        put(&mut record, 0x06, &((strides + 1) as u16).to_le_bytes());
        put(&mut record, 0x14, &(first_attribute as u16).to_le_bytes());
        put(&mut record, 0x16, &flags.to_le_bytes());

        let mut cursor = first_attribute;
        for attribute in attributes {
            put(&mut record, cursor, attribute);
            cursor += attribute.len();
        }
        put(&mut record, cursor, &ATTR_END.to_le_bytes());
        cursor += 8;
        put(&mut record, 0x18, &(cursor as u32).to_le_bytes());
        put(&mut record, 0x1C, &(size as u32).to_le_bytes());

        put(&mut record, ARRAY, &SEQUENCE.to_le_bytes());
        for stride in 0..strides {
            let tail = (stride + 1) * 512;
            let original = [record[tail - 2], record[tail - 1]];
            put(&mut record, ARRAY + 2 + stride * 2, &original);
            put(&mut record, tail - 2, &SEQUENCE.to_le_bytes());
        }
        record
    }

    /// A volume in memory, which refuses what a real volume refuses: a read
    /// that is not a whole number of its sectors, or does not start on one.
    struct Image {
        bytes: Vec<u8>,
        sector: usize,
    }

    impl RawVolume for Image {
        fn read_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
            let offset = offset as usize;
            let whole_sectors =
                buffer.len().is_multiple_of(self.sector) && offset.is_multiple_of(self.sector);
            if !whole_sectors {
                return Err(Error::Privileged(
                    "could not read from the volume: the parameter is incorrect".to_owned(),
                ));
            }
            let start = offset.min(self.bytes.len());
            let end = (start + buffer.len()).min(self.bytes.len());
            buffer[..end - start].copy_from_slice(&self.bytes[start..end]);
            Ok(end - start)
        }
    }

    /// Where the made-up table starts, in clusters.
    const TABLE_AT: u16 = 4;
    /// How many records it holds: the table's own, four unused, the root, one
    /// folder and one file.
    const RECORDS: usize = 8;

    /// A small volume: a root, `Users` inside it, and `big.bin` of 5000 bytes
    /// inside that.
    ///
    /// `listed` is how many clusters of the table its own record lists, and
    /// `stated` how many bytes it says the table is. On a healthy volume the
    /// first covers the second.
    fn volume(sector: usize, cluster: usize, record: usize, listed: u8, stated: u64) -> Image {
        let mut boot = vec![0_u8; sector.max(512)];
        put(&mut boot, 3, b"NTFS    ");
        put(&mut boot, 0x0B, &(sector as u16).to_le_bytes());
        boot[0x0D] = (cluster / sector) as u8;
        put(&mut boot, 0x30, &(TABLE_AT as u64).to_le_bytes());
        // Negative means two to that power, in bytes.
        boot[0x40] = (-(record.trailing_zeros() as i8)) as u8;

        let mut records = vec![vec![0_u8; record]; RECORDS];
        records[0] = file_record(
            record,
            IN_USE,
            &[
                file_name(5, "$MFT"),
                data_in_clusters(&[(listed, TABLE_AT)], stated),
            ],
        );
        records[5] = file_record(record, IN_USE_DIRECTORY, &[file_name(5, ".")]);
        records[6] = file_record(
            record,
            IN_USE_DIRECTORY,
            &[standard_information(777), file_name(5, "Users")],
        );
        records[7] = file_record(
            record,
            IN_USE,
            &[
                standard_information(999),
                file_name(6, "big.bin"),
                data_in_clusters(&[(2, 40)], 5000),
            ],
        );

        let mut bytes = vec![0_u8; TABLE_AT as usize * cluster];
        put(&mut bytes, 0, &boot);
        for record in records {
            bytes.extend_from_slice(&record);
        }
        // Whole clusters to the end, as a volume is.
        bytes.resize(bytes.len().next_multiple_of(cluster), 0);
        Image { bytes, sector }
    }

    /// The table in whole clusters, and in bytes.
    fn table_size(cluster: usize, record: usize) -> (u8, u64) {
        let bytes = RECORDS * record;
        (bytes.div_ceil(cluster) as u8, bytes as u64)
    }

    fn assert_the_small_volume_was_read(snapshot: &MftSnapshot) {
        assert_eq!(snapshot.drive, 'K');
        assert_eq!(snapshot.skipped, 0);
        assert_eq!(snapshot.stats.records_seen, 4);

        let users = snapshot.entries.get(&6).expect("the folder was not found");
        assert!(users.is_directory);
        assert_eq!((users.name.as_str(), users.parent), ("Users", 5));
        assert_eq!(users.modified, 777);

        let file = snapshot.entries.get(&7).expect("the file was not found");
        assert!(!file.is_directory);
        assert_eq!((file.name.as_str(), file.parent), ("big.bin", 6));
        assert_eq!(file.bytes, 5000);
        assert_eq!(file.modified, 999);
    }

    #[test]
    fn a_table_on_an_ordinary_disk_is_read_through_the_same_path() {
        // The control for the tests below: 512-byte sectors and 1 KB records,
        // which is what the development machine's drive has.
        let (clusters, bytes) = table_size(4096, 1024);
        let image = volume(512, 4096, 1024, clusters, bytes);
        let snapshot = read_from(&image, 'k').unwrap();
        assert_the_small_volume_was_read(&snapshot);
    }

    /// A disk whose sectors are 4096 bytes is read like any other.
    ///
    /// It never was. The boot sector was asked for as 512 bytes, which such a
    /// disk refuses because it is not a whole sector; and had that read worked,
    /// every record would then have failed its check, because the check
    /// stepped through the record by the disk's sector size where NTFS always
    /// steps by 512. Storage fell back to walking the folders and said the
    /// fast route "needs administrative rights"; the other pages had no
    /// fallback and could not work on such a disk at all.
    #[test]
    fn a_table_on_a_disk_with_4096_byte_sectors_is_read() {
        let (clusters, bytes) = table_size(4096, 4096);
        let image = volume(4096, 4096, 4096, clusters, bytes);
        let snapshot = read_from(&image, 'k').unwrap();
        assert_the_small_volume_was_read(&snapshot);
    }

    #[test]
    fn a_4096_byte_record_is_checked_every_512_bytes() {
        // Eight protected stretches, so nine entries in the array: the
        // sequence number and the eight pairs of bytes it stands in for.
        let mut record = file_record(4096, IN_USE, &[file_name(5, "thing.bin")]);
        assert_eq!(read_u16(&record, 0x06).unwrap(), 9);
        assert_eq!(read_u16(&record, 4094).unwrap(), 0x0C0A);

        assert!(apply_fixups(&mut record).is_some());
        assert_eq!(
            read_u16(&record, 4094).unwrap(),
            0,
            "the bytes were not put back"
        );
        let parsed = parse_record(&record).expect("the record should parse");
        assert_eq!(
            parsed.name.map(|(_, name, _)| name).as_deref(),
            Some("thing.bin")
        );
    }

    /// A table in more pieces than its first record lists is not read in part.
    ///
    /// The record here says the table is four times as long as the pieces it
    /// lists, which is what a table that has outgrown one record's list looks
    /// like from that record. This used to read what was listed and return it
    /// as the whole drive.
    #[test]
    fn a_table_whose_first_record_lists_only_part_of_it_is_refused_and_says_so() {
        let (clusters, bytes) = table_size(4096, 1024);
        let image = volume(512, 4096, 1024, clusters, bytes * 4);

        let refusal = read_from(&image, 'k').map(|_| ()).unwrap_err();
        assert!(matches!(refusal, Error::Refused(_)), "{refusal}");
        let text = refusal.to_string();
        assert!(
            text.contains("too many pieces") && text.contains("leave files out"),
            "the refusal should say why: {text}"
        );
    }

    /// A read that comes back short is not the end of the table.
    ///
    /// The table's record lists more clusters than the volume gives back, as
    /// when a read fails part-way. This used to stop reading that piece
    /// without a word and return what it had.
    #[test]
    fn a_table_that_could_only_be_read_in_part_is_refused_and_says_so() {
        let (clusters, bytes) = table_size(4096, 1024);
        let image = volume(512, 4096, 1024, clusters + 2, bytes);
        // The premise: the volume ends where the records do, two clusters
        // short of what the list says belongs to the table.
        assert_eq!(
            image.bytes.len(),
            (TABLE_AT as usize + clusters as usize) * 4096
        );

        let refusal = read_from(&image, 'k').map(|_| ()).unwrap_err();
        let text = refusal.to_string();
        assert!(
            text.contains("only be read in part"),
            "the refusal should say the read was partial: {text}"
        );
    }
}
