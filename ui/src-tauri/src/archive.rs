//! Taking a zip apart, as the person, and writing out only what Defender did
//! not flag.
//!
//! # Why here and not in the agent
//!
//! An archive member's name is chosen by whoever made the archive. Writing
//! files under names like that is exactly how a zip-slip turns into a file
//! written anywhere, and in a LocalSystem process "anywhere" includes
//! System32. So the agent never extracts anything, and there is a test in it
//! that fails if an archive reader ever reaches it. This process runs as the
//! person, so the worst a hostile archive could do here is what that person
//! could do in Explorer, and the rules below stop even that.
//!
//! # The rules
//!
//! - The archive is read from a private working copy, never in place.
//! - Only members Defender found nothing in are written. Flagged, password
//!   protected, linked, unsupported and dangerously named members never are.
//! - Every name is reduced to plain parts by
//!   [`kam_storage::downloads::safe_relative`] and joined one part at a time.
//! - Folders are created one at a time, and an existing one is used only when
//!   it is a real folder, never a link. Files are created new, never opened
//!   over something already there.
//! - Every folder before a file is written, and every file after, is resolved
//!   and must still lie inside the new folder. Anything that does not is
//!   removed and reported.
//! - A member that unpacks to more than it declared is cut off and reported.
//! - The mark Windows puts on downloaded files is carried over, so an
//!   extracted program gets the same SmartScreen warning it would have had
//!   from Explorer's own extraction.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use kam_scanner::downloads::{Dissection, Entry, Extraction, MemberStatus, RemovedFile};
use kam_storage::downloads::{extraction_folder_name, lies_within, safe_relative};

/// Most members read from one archive. Past this it is not an archive anybody
/// downloaded to use, and listing it would cost the window its memory.
const MAX_MEMBERS: usize = 200_000;

/// The window's private folder for working copies:
/// `%LOCALAPPDATA%\KAM Security\work`, as the agent derives it from the
/// person's profile, so the two agree on where it is.
pub fn work_folder() -> PathBuf {
    PathBuf::from(kam_core::UserContext::current().local_app_data())
        .join(kam_core::PRODUCT_NAME)
        .join("work")
}

/// A name for a working copy nobody else will choose.
fn fresh_name() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_nanos())
        .unwrap_or(0);
    format!(
        "{}-{nanos}-{}.zip",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    )
}

/// Deletes one file when it is let go. Permanent, and meant to be: it is only
/// ever a private duplicate this program made, not anybody's file.
#[derive(Debug)]
struct Remove(PathBuf);

impl Drop for Remove {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A private working copy of an archive, held open, and deleted when let go.
///
/// # Why it is held open
///
/// The copy sits in a folder the person's own account can write to, between
/// Defender's look at it and the press of Extract. It used to be found again
/// by name each time: to list it, and again to extract from it. Anything
/// running as the person could have changed it in between, and this would
/// then have written out content Defender never saw and recorded it as files
/// Defender did not flag. Red review found it.
///
/// So the copy is opened once, as soon as it is written, in a way that lets
/// others read (the agent and Defender have to) and nobody write, rename or
/// delete. Everything this program then does with it (taking its
/// fingerprint, listing it, extracting from it) goes through that one
/// handle, for as long as the archive is open here.
#[derive(Debug)]
pub struct WorkingCopy {
    // Declared before `remove`, so the handle is closed before the file it
    // holds is deleted: fields are let go in this order.
    file: File,
    remove: Remove,
}

impl WorkingCopy {
    /// The one handle everything is read through.
    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn path(&self) -> &Path {
        &self.remove.0
    }

    /// Whether this copy is the file Defender was asked about: its
    /// fingerprint, read through the handle everything else is read through,
    /// against the one the check came back with.
    ///
    /// The agent fingerprints the file it has Defender look at, through one
    /// open handle of its own. This handle has been open since before that,
    /// with writers shut out, so equal fingerprints mean what is listed and
    /// extracted here is what Defender saw.
    pub fn is_the_file_checked(&self, sha256: &str) -> Result<(), String> {
        let here = kam_scanner::downloads::fingerprint(&self.file, &kam_core::Reporter::silent())
            .map_err(|error| match error {
            kam_scanner::downloads::CheckError::Failed(reason) => {
                format!("the private copy could not be read back: {reason}")
            }
            kam_scanner::downloads::CheckError::Stopped => {
                "reading the private copy back was stopped".to_owned()
            }
        })?;
        if here.eq_ignore_ascii_case(sha256.trim()) {
            Ok(())
        } else {
            Err(
                "The private copy is not the file Defender was asked about: it changed after \
                 it was made. Nothing in it is offered for extraction."
                    .to_owned(),
            )
        }
    }
}

/// How much of an archive is copied between looks at whether to go on.
const COPY_CHUNK: usize = 1024 * 1024;

/// Make the private working copy of an archive. `None` when `keep_going`
/// said to stop before it was finished, and then nothing is left behind.
///
/// Created new, in a folder that must be a real folder rather than a link,
/// and read from the original with other writers shut out, so what is copied
/// is one consistent file.
pub fn working_copy(
    original: &Path,
    keep_going: &dyn Fn() -> bool,
) -> Result<Option<WorkingCopy>, String> {
    working_copy_in(original, &work_folder(), keep_going)
}

fn working_copy_in(
    original: &Path,
    folder: &Path,
    keep_going: &dyn Fn() -> bool,
) -> Result<Option<WorkingCopy>, String> {
    use std::os::windows::fs::OpenOptionsExt;

    std::fs::create_dir_all(folder)
        .map_err(|error| format!("the private work folder could not be made: {error}"))?;
    let metadata = std::fs::symlink_metadata(folder)
        .map_err(|error| format!("the private work folder could not be read: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "{} is not a plain folder, so no working copy was made in it",
            folder.display()
        ));
    }

    let mut source = open_shut_to_writers(original).map_err(|error| {
        format!(
            "{} could not be opened to copy it, perhaps because it is still being written: {error}",
            original.display()
        )
    })?;
    let copy = folder.join(fresh_name());
    // Others may read it while it is written; nobody may write or delete.
    let created = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ)
        .open(&copy)
        .map_err(|error| format!("the working copy could not be created: {error}"))?;
    // From here every way out deletes what was made. Named after `remove` so
    // that it is closed first: the file cannot be deleted while it is open.
    let remove = Remove(copy.clone());
    let mut target = created;

    let mut buffer = vec![0_u8; COPY_CHUNK];
    loop {
        if !keep_going() {
            drop(target);
            return Ok(None);
        }
        let read = source
            .read(&mut buffer)
            .map_err(|error| format!("the archive could not be copied: {error}"))?;
        if read == 0 {
            break;
        }
        target
            .write_all(&buffer[..read])
            .map_err(|error| format!("the archive could not be copied: {error}"))?;
    }
    target
        .flush()
        .map_err(|error| format!("the archive could not be copied: {error}"))?;
    drop(target);

    let file = open_shut_to_writers(&copy).map_err(|error| {
        format!("the working copy could not be opened again once it was written: {error}")
    })?;
    Ok(Some(WorkingCopy { file, remove }))
}

const FILE_SHARE_READ: u32 = 0x1;

/// Open a file for reading while nobody else may write to it, rename it or
/// delete it.
///
/// Also the watcher's test for "finished": a browser still writing a download
/// holds it open for writing, and this open then fails.
pub fn open_shut_to_writers(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
}

/// The start of every working copy's name that this run of the program made.
fn own_prefix() -> String {
    format!("{}-", std::process::id())
}

/// Delete working copies a previous run left behind. Only plain files
/// directly in the work folder; nothing is followed.
///
/// A copy this run made is never one of them, and is recognised by its name.
/// This runs on its own thread at start-up, and a first start from "Extract
/// with KAM Security" could otherwise have had its fresh copy deleted from
/// under it.
pub fn discard_leftovers() {
    discard_leftovers_in(&work_folder());
}

fn discard_leftovers_in(folder: &Path) {
    let Ok(listing) = std::fs::read_dir(folder) else {
        return;
    };
    let ours = own_prefix();
    for item in listing.flatten() {
        let made_now = item.file_name().to_string_lossy().starts_with(&ours);
        if !made_now && item.file_type().is_ok_and(|kind| kind.is_file()) {
            let _ = std::fs::remove_file(item.path());
        }
    }
}

/// Every member of a zip, as the zip itself lists it.
pub fn entries(archive: &File) -> Result<Vec<Entry>, String> {
    let mut zip = zip::ZipArchive::new(archive)
        .map_err(|error| format!("it could not be read as a zip archive ({error})"))?;
    if zip.len() > MAX_MEMBERS {
        return Err(format!(
            "it lists {} members, more than this will take apart",
            zip.len()
        ));
    }
    let mut listed = Vec::with_capacity(zip.len());
    for index in 0..zip.len() {
        let member = zip
            .by_index_raw(index)
            .map_err(|error| format!("member {index} could not be read ({error})"))?;
        let name = member
            .name()
            .map(|name| name.into_owned())
            .unwrap_or_else(|_| String::from_utf8_lossy(member.name_raw()).into_owned());
        let method = member.compression();
        listed.push(Entry {
            bytes: member.size(),
            packed: member.compressed_size(),
            is_dir: member.is_dir(),
            encrypted: member.encrypted(),
            link: member.is_symlink(),
            unsupported: (!zip::SUPPORTED_COMPRESSION_METHODS.contains(&method))
                .then(|| method.to_string()),
            name,
        });
    }
    Ok(listed)
}

/// Write out what Defender found nothing in, into a new folder in `parent`.
///
/// `copy` is the working copy's own handle, held since before Defender was
/// asked about it, so what is unpacked is what was checked. `parent` is the
/// person's Downloads folder. `zone` is the original's `Zone.Identifier`,
/// written beside every extracted file when there was one.
///
/// An error means nothing was written: every refusal comes before the first
/// file, so the same archive can simply be tried again.
pub fn extract(
    copy: &File,
    dissection: &Dissection,
    parent: &Path,
    archive_name: &str,
    zone: Option<&[u8]>,
) -> Result<Extraction, String> {
    extract_with(copy, dissection, parent, archive_name, zone, &stamp)
}

/// The mark Windows puts on a downloaded file, as it was on an archive.
///
/// `None` only when the archive carries no mark. Any other failure to read
/// it is an error and is said: it used to count as "no mark", and the files
/// extracted then went without one in silence. A file without the mark is a
/// file SmartScreen does not check before it runs.
pub fn read_mark(archive: &Path) -> Result<Option<Vec<u8>>, String> {
    let mut stream = archive.as_os_str().to_owned();
    stream.push(":Zone.Identifier");
    match std::fs::read(PathBuf::from(stream)) {
        Ok(mark) => Ok(Some(mark)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

/// Put the mark on one extracted file.
fn stamp(target: &Path, zone: &[u8]) -> std::io::Result<()> {
    let mut stream = target.as_os_str().to_owned();
    stream.push(":Zone.Identifier");
    std::fs::write(PathBuf::from(stream), zone)
}

/// [`extract`] with the marking given rather than done, so that a mark that
/// cannot be written can be tested on a drive where it always can.
fn extract_with(
    copy: &File,
    dissection: &Dissection,
    parent: &Path,
    archive_name: &str,
    zone: Option<&[u8]>,
    stamp: &dyn Fn(&Path, &[u8]) -> std::io::Result<()>,
) -> Result<Extraction, String> {
    if !dissection.offered {
        return Err(dissection
            .not_offered
            .clone()
            .unwrap_or_else(|| "Nothing in this archive is offered for extraction.".to_owned()));
    }
    let parent_real = std::fs::canonicalize(parent)
        .map_err(|error| format!("{} could not be found: {error}", parent.display()))?;

    let wanted: u64 = dissection.totals.clean_bytes;
    if let Some(free) = free_space(&parent_real) {
        if wanted > free {
            return Err(format!(
                "the files Defender found nothing in come to {} and {} has {} free, so nothing \
                 was extracted",
                human_bytes(wanted),
                parent.display(),
                human_bytes(free)
            ));
        }
    }

    // Read before the folder is made, so that failing here leaves nothing.
    let mut zip = zip::ZipArchive::new(copy)
        .map_err(|error| format!("the working copy could not be read as a zip ({error})"))?;

    let name = extraction_folder_name(archive_name, |candidate| {
        std::fs::symlink_metadata(parent_real.join(candidate)).is_ok()
    });
    let destination = parent_real.join(&name);
    std::fs::create_dir(&destination).map_err(|error| {
        format!(
            "the folder {} could not be made: {error}",
            destination.display()
        )
    })?;
    let destination_real = std::fs::canonicalize(&destination)
        .map_err(|error| format!("the new folder could not be found again: {error}"))?;
    if !lies_within(&destination_real, &parent_real) {
        let _ = std::fs::remove_dir(&destination);
        return Err(format!(
            "{} does not lead where it was made, so nothing was extracted into it",
            destination.display()
        ));
    }

    let mut outcome = Extraction {
        destination: plain_text(&destination_real),
        left_out: dissection.totals.flagged + dissection.totals.left_out,
        left_out_bytes: dissection.totals.flagged_bytes + dissection.totals.left_out_bytes,
        ..Extraction::default()
    };

    let mut written: Vec<(String, PathBuf, u64)> = Vec::new();
    let mut removed: Vec<(String, PathBuf)> = Vec::new();
    let mut unmarked: Vec<(String, String)> = Vec::new();
    for (index, member) in dissection.members.iter().enumerate() {
        if member.status != MemberStatus::NothingFound {
            continue;
        }
        match write_member(
            &mut zip,
            index,
            &member.name,
            member.bytes,
            &destination_real,
        ) {
            Ok((path, size)) => {
                // A failure is not an absence: the file is there, and it
                // lacks the mark it should carry, so it is listed.
                if let Some(zone) = zone {
                    if let Err(error) = stamp(&path, zone) {
                        unmarked.push((member.name.clone(), error.to_string()));
                    }
                }
                written.push((member.name.clone(), path, size));
            }
            Err(Unwritten::Removed(path)) => removed.push((member.name.clone(), path)),
            Err(Unwritten::Failed(reason)) => {
                outcome.failed.push(format!("{}: {reason}", member.name));
            }
        }
    }

    // A failure is not an absence: a file that was written is only counted
    // once it has been looked at again and is still there, whole. Defender's
    // real-time protection acts on a file as it lands, a moment after it is
    // closed, so the second look waits for that moment.
    if !written.is_empty() {
        std::thread::sleep(SETTLE_AFTER_WRITING);
    }
    let (files, bytes, gone) = second_look(written);
    outcome.files = files;
    outcome.bytes = bytes;
    // A file that is gone is reported as gone, not as lacking a mark.
    outcome.unmarked = unmarked
        .into_iter()
        .filter(|(name, _)| !gone.iter().any(|(taken, _)| taken == name))
        .map(|(name, reason)| format!("{name}: {reason}"))
        .collect();
    removed.extend(gone);
    if !removed.is_empty() {
        outcome.removed = name_removals(removed);
    }
    Ok(outcome)
}

/// Look again at every file written: how many are still there and whole, how
/// many bytes they hold, and which are gone or changed.
fn second_look(written: Vec<(String, PathBuf, u64)>) -> (u64, u64, Vec<(String, PathBuf)>) {
    let mut files = 0;
    let mut bytes = 0;
    let mut gone = Vec::new();
    for (name, path, size) in written {
        let whole = std::fs::metadata(&path).is_ok_and(|metadata| metadata.len() == size);
        if whole {
            files += 1;
            bytes += size;
        } else {
            gone.push((name, path));
        }
    }
    (files, bytes, gone)
}

/// How long to wait after writing before looking again. Defender scans a file
/// when it is closed and removes it moments later.
const SETTLE_AFTER_WRITING: std::time::Duration = std::time::Duration::from_millis(1500);

/// Why a member is not among the files extracted.
enum Unwritten {
    /// Written, or being written, and then taken away: Windows refused it as
    /// containing a threat, or it was gone the moment it was closed.
    Removed(PathBuf),
    /// Never written, for this reason.
    Failed(String),
}

impl From<String> for Unwritten {
    fn from(reason: String) -> Self {
        Self::Failed(reason)
    }
}

/// Windows' own errors for a file its antivirus refused or deleted.
fn refused_by_antivirus(error: &std::io::Error) -> bool {
    // ERROR_VIRUS_INFECTED and ERROR_VIRUS_DELETED.
    matches!(error.raw_os_error(), Some(225 | 226))
}

/// Put the detection that took each file away beside it, when Defender's
/// history names that file. Read as the person, which Defender allows.
fn name_removals(removed: Vec<(String, PathBuf)>) -> Vec<RemovedFile> {
    let detections = kam_scanner::defender::threats().unwrap_or_default();
    removed
        .into_iter()
        .map(|(name, path)| {
            let wanted = plain_text(&path);
            let threat = detections
                .iter()
                .find(|threat| {
                    threat.resources.iter().any(|resource| {
                        kam_scanner::defender_file::parse_resource(resource).is_some_and(|named| {
                            let named = named
                                .path
                                .strip_prefix(r"\\?\")
                                .unwrap_or(&named.path)
                                .to_owned();
                            named.eq_ignore_ascii_case(&wanted)
                        })
                    })
                })
                .map(|threat| threat.name.clone());
            RemovedFile::new(name, threat)
        })
        .collect()
}

/// Write one member, under every rule in the module notes. Answers where it
/// went and how big it was.
fn write_member(
    zip: &mut zip::ZipArchive<&File>,
    index: usize,
    name: &str,
    declared: u64,
    destination: &Path,
) -> Result<(PathBuf, u64), Unwritten> {
    let parts = safe_relative(name).map_err(|refusal| refusal.sentence())?;
    let Some((file_name, folders)) = parts.split_last() else {
        return Err(Unwritten::Failed("It has no name.".to_owned()));
    };

    let mut folder = destination.to_path_buf();
    for part in folders {
        folder.push(part);
        match std::fs::symlink_metadata(&folder) {
            Ok(existing) if existing.is_dir() && !existing.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(Unwritten::Failed(format!(
                    "{} is in the way and is not a plain folder.",
                    folder.display()
                )))
            }
            Err(_) => std::fs::create_dir(&folder)
                .map_err(|error| format!("its folder could not be made: {error}"))?,
        }
    }
    let folder_real = std::fs::canonicalize(&folder)
        .map_err(|error| format!("its folder could not be found again: {error}"))?;
    if folder_real != destination && !lies_within(&folder_real, destination) {
        return Err(Unwritten::Failed(
            "Its folder leads outside the new folder, so it was not written.".to_owned(),
        ));
    }

    let target = folder_real.join(file_name);
    let mut member = zip
        .by_index(index)
        .map_err(|error| format!("it could not be unpacked ({error})"))?;
    let listed = member
        .name()
        .map(|listed| listed.into_owned())
        .unwrap_or_else(|_| String::from_utf8_lossy(member.name_raw()).into_owned());
    if listed != name {
        return Err(Unwritten::Failed(
            "The archive changed while it was being read.".to_owned(),
        ));
    }
    let mut out = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)
    {
        Ok(out) => out,
        Err(error) if refused_by_antivirus(&error) => return Err(Unwritten::Removed(target)),
        Err(error) => {
            return Err(Unwritten::Failed(format!(
                "it could not be created: {error}"
            )))
        }
    };

    // One byte more than declared is read, so a member that keeps going is
    // noticed rather than written in full.
    let mut limited = (&mut member).take(declared.saturating_add(1));
    let copied = std::io::copy(&mut limited, &mut out).and_then(|copied| {
        out.flush()?;
        Ok(copied)
    });
    drop(out);
    let copied = match copied {
        Ok(copied) => copied,
        Err(error) if refused_by_antivirus(&error) => {
            let _ = std::fs::remove_file(&target);
            return Err(Unwritten::Removed(target));
        }
        Err(error) => {
            let _ = std::fs::remove_file(&target);
            return Err(Unwritten::Failed(format!(
                "it could not be unpacked ({error})"
            )));
        }
    };
    if copied > declared {
        let _ = std::fs::remove_file(&target);
        return Err(Unwritten::Failed(
            "It unpacked to more than it declared, so it was not kept.".to_owned(),
        ));
    }

    // Gone the moment it was closed: taken away as it landed, which is not the
    // same as written.
    let real = match std::fs::canonicalize(&target) {
        Ok(real) => real,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(Unwritten::Removed(target))
        }
        Err(error) => {
            let _ = std::fs::remove_file(&target);
            return Err(Unwritten::Failed(format!(
                "it was written and could not be found again ({error})"
            )));
        }
    };
    if !lies_within(&real, destination) {
        let _ = std::fs::remove_file(&target);
        return Err(Unwritten::Failed(
            "It would have landed outside the new folder, so it was removed.".to_owned(),
        ));
    }

    Ok((target, copied))
}

/// Free space where the files would go, when Windows says.
fn free_space(folder: &Path) -> Option<u64> {
    use windows::core::HSTRING;
    use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let mut free = 0_u64;
    unsafe {
        GetDiskFreeSpaceExW(
            &HSTRING::from(folder.as_os_str()),
            Some(&mut free),
            None,
            None,
        )
    }
    .ok()
    .map(|()| free)
}

fn plain_text(path: &Path) -> String {
    let text = path.to_string_lossy();
    text.strip_prefix(r"\\?\").unwrap_or(&text).to_owned()
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use kam_scanner::defender_file::{parse_report, Answer, FileScan, Flagged};
    use kam_scanner::downloads::dissect;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("kam-archive-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("Downloads")).unwrap();
            std::fs::create_dir_all(root.join("work")).unwrap();
            Self(root)
        }
        fn downloads(&self) -> PathBuf {
            self.0.join("Downloads")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A zip holding a harmless file, a folder, a file in it, and the classic
    /// zip-slip names.
    fn hostile_zip(at: &Path) {
        let mut writer = zip::ZipWriter::new(File::create(at).unwrap());
        let options = zip::write::SimpleFileOptions::default();
        for (name, body) in [
            ("readme.txt", b"hello".as_slice()),
            ("docs/guide.txt", b"a guide".as_slice()),
            ("../escaped.txt", b"out".as_slice()),
            ("docs/../../escaped-too.txt", b"out".as_slice()),
            ("C:/Users/Public/escaped.txt", b"out".as_slice()),
            ("tools/eicar.com", b"pretend".as_slice()),
        ] {
            writer.start_file(name, options).unwrap();
            writer.write_all(body).unwrap();
        }
        writer.add_directory("empty/", options).unwrap();
        writer.finish().unwrap();
    }

    fn clean() -> FileScan {
        parse_report(Some(0), "Scanning C:\\w.zip found no threats.")
    }

    fn opened(path: &Path) -> File {
        File::open(path).unwrap()
    }

    #[test]
    fn every_member_is_listed_as_the_archive_lists_it() {
        let scratch = Scratch::new("list");
        let zip_path = scratch.0.join("a.zip");
        hostile_zip(&zip_path);
        let listed = entries(&opened(&zip_path)).unwrap();
        let names: Vec<&str> = listed.iter().map(|entry| entry.name.as_str()).collect();
        assert!(names.contains(&"../escaped.txt"), "{names:?}");
        assert!(names.contains(&"empty/"));
        let readme = listed
            .iter()
            .find(|entry| entry.name == "readme.txt")
            .unwrap();
        assert_eq!(readme.bytes, 5);
        assert!(!readme.encrypted && !readme.link && readme.unsupported.is_none());
        assert!(
            listed
                .iter()
                .find(|entry| entry.name == "empty/")
                .unwrap()
                .is_dir
        );
    }

    #[test]
    fn something_that_is_not_a_zip_says_so() {
        let scratch = Scratch::new("notzip");
        let fake = scratch.0.join("fake.zip");
        std::fs::write(&fake, b"not a zip at all").unwrap();
        assert!(entries(&opened(&fake)).unwrap_err().contains("zip"));
    }

    /// The zip-slip test: only what Defender found nothing in is written, and
    /// nothing is written outside the new folder whatever its name says.
    #[test]
    fn only_clean_members_are_written_and_nothing_lands_outside_the_new_folder() {
        let scratch = Scratch::new("extract");
        let zip_path = scratch.0.join("work").join("copy.zip");
        hostile_zip(&zip_path);
        let scan = FileScan {
            answer: Answer::Flagged,
            completed: true,
            exit_code: Some(2),
            seconds: 0,
            threats: vec![Flagged {
                name: "Virus:DOS/EICAR_Test_File".to_owned(),
                resources: vec![r"file : C:\w.zip->tools/eicar.com".to_owned()],
            }],
            listing_consistent: true,
            caveat: None,
            definitions: None,
            notes: Vec::new(),
        };
        let dissection = dissect(
            "Photos.zip",
            "ab",
            scan,
            &entries(&opened(&zip_path)).unwrap(),
        );
        assert!(dissection.offered, "{dissection:?}");
        assert_eq!(dissection.totals.clean, 2, "{:?}", dissection.totals);
        assert_eq!(dissection.totals.flagged, 1);
        assert_eq!(dissection.totals.left_out, 3);

        let zone = b"[ZoneTransfer]\r\nZoneId=3\r\n";
        let done = extract(
            &opened(&zip_path),
            &dissection,
            &scratch.downloads(),
            "Photos.zip",
            Some(zone),
        )
        .unwrap();
        assert_eq!(done.files, 2, "{done:?}");
        assert!(done.failed.is_empty(), "{:?}", done.failed);
        assert!(
            done.destination.ends_with("Photos (checked by KAM)"),
            "{}",
            done.destination
        );

        let folder = scratch.downloads().join("Photos (checked by KAM)");
        assert_eq!(std::fs::read(folder.join("readme.txt")).unwrap(), b"hello");
        assert_eq!(
            std::fs::read(folder.join("docs").join("guide.txt")).unwrap(),
            b"a guide"
        );
        assert!(
            !folder.join("tools").join("eicar.com").exists(),
            "a flagged member was written"
        );
        for escaped in [
            scratch.downloads().join("escaped.txt"),
            scratch.0.join("escaped.txt"),
            scratch.0.join("escaped-too.txt"),
            scratch.downloads().join("escaped-too.txt"),
            PathBuf::from(r"C:\Users\Public\escaped.txt"),
        ] {
            assert!(!escaped.exists(), "{} was written", escaped.display());
        }
        // The mark of the web came along.
        let mut stream = folder.join("readme.txt").into_os_string();
        stream.push(":Zone.Identifier");
        assert_eq!(std::fs::read(PathBuf::from(stream)).unwrap(), zone);

        // A second extraction never reuses the first folder.
        let again = extract(
            &opened(&zip_path),
            &dissection,
            &scratch.downloads(),
            "Photos.zip",
            None,
        )
        .unwrap();
        assert!(
            again.destination.ends_with("Photos (checked by KAM) (2)"),
            "{}",
            again.destination
        );
    }

    #[test]
    fn nothing_is_written_when_nothing_is_offered() {
        let scratch = Scratch::new("refused");
        let zip_path = scratch.0.join("work").join("copy.zip");
        hostile_zip(&zip_path);
        let unfinished = parse_report(Some(2), "CmdTool: Failed with hr = 0x80070005.");
        let dissection = dissect(
            "x.zip",
            "ab",
            unfinished,
            &entries(&opened(&zip_path)).unwrap(),
        );
        assert!(extract(
            &opened(&zip_path),
            &dissection,
            &scratch.downloads(),
            "x.zip",
            None
        )
        .is_err());
        assert_eq!(std::fs::read_dir(scratch.downloads()).unwrap().count(), 0);
        let _ = clean();
    }

    #[test]
    fn a_working_copy_is_private_new_and_identical() {
        let scratch = Scratch::new("copy");
        let original = scratch.downloads().join("a.zip");
        hostile_zip(&original);
        let copy = working_copy_in(&original, &scratch.0.join("work"), &|| true)
            .unwrap()
            .expect("nobody asked it to stop");
        assert_ne!(copy.path(), original);
        assert_eq!(
            std::fs::read(copy.path()).unwrap(),
            std::fs::read(&original).unwrap()
        );
        assert!(original.exists(), "the original was moved");
    }

    /// Red review: the copy was found again by name to list it and to
    /// extract from it, and never compared with what Defender had checked.
    /// It is held open now, so that nothing can change it in between, and
    /// its fingerprint through that same handle has to be the one Defender's
    /// check came back with.
    #[test]
    fn a_working_copy_cannot_be_changed_and_must_be_the_file_that_was_checked() {
        let scratch = Scratch::new("pinned");
        let original = scratch.downloads().join("a.zip");
        hostile_zip(&original);
        let copy = working_copy_in(&original, &scratch.0.join("work"), &|| true)
            .unwrap()
            .unwrap();
        let path = copy.path().to_path_buf();

        assert!(
            OpenOptions::new().append(true).open(&path).is_err(),
            "the copy could be written to while it was open here"
        );
        assert!(
            std::fs::rename(&path, path.with_extension("moved")).is_err(),
            "the copy could be swapped for another while it was open here"
        );
        assert!(
            std::fs::remove_file(&path).is_err(),
            "the copy could be deleted while it was open here"
        );
        // Others can still read it, which the agent and Defender have to.
        assert!(open_shut_to_writers(&path).is_ok());

        let reporter = kam_core::Reporter::silent();
        let checked = kam_scanner::downloads::fingerprint(&opened(&original), &reporter).unwrap();
        assert!(copy.is_the_file_checked(&checked).is_ok());
        // Listing it afterwards reads the same handle from its start.
        assert!(entries(copy.file()).is_ok());
        let refusal = copy
            .is_the_file_checked(&"0".repeat(64))
            .expect_err("a copy that is not the file Defender checked was accepted");
        assert!(
            refusal.contains("not the file Defender was asked about"),
            "{refusal}"
        );

        drop(copy);
        assert!(!path.exists(), "the private copy was left behind");
    }

    #[test]
    fn a_copy_that_is_stopped_part_way_leaves_nothing_behind() {
        let scratch = Scratch::new("stopped");
        let original = scratch.downloads().join("a.zip");
        hostile_zip(&original);
        let work = scratch.0.join("work");
        assert!(working_copy_in(&original, &work, &|| false)
            .unwrap()
            .is_none());
        assert_eq!(std::fs::read_dir(&work).unwrap().count(), 0);
    }

    /// Red review: a mark that could not be read from the archive counted as
    /// no mark, and a mark that could not be written onto an extracted file
    /// was thrown away. Either way a file went without the mark that makes
    /// SmartScreen check it, and nothing said so.
    #[test]
    fn a_mark_that_cannot_be_read_or_written_is_said_and_not_passed_over() {
        let scratch = Scratch::new("mark");
        let zip_path = scratch.0.join("work").join("copy.zip");
        hostile_zip(&zip_path);
        let zone = b"[ZoneTransfer]\r\nZoneId=3\r\n";

        // Reading: no mark is no mark, and a mark that is there is read.
        assert_eq!(read_mark(&zip_path), Ok(None));
        stamp(&zip_path, zone).unwrap();
        assert_eq!(read_mark(&zip_path), Ok(Some(zone.to_vec())));
        // Anything else that goes wrong is an error, not "none". A name
        // Windows will not take fails in a way that is not "not found".
        let unreadable = scratch.0.join("work").join("what?.zip");
        assert!(
            read_mark(&unreadable).is_err(),
            "a mark that could not be read was taken for no mark"
        );

        // Writing: the files are written, counted, and listed as unmarked.
        let dissection = dissect(
            "Photos.zip",
            "ab",
            clean(),
            &entries(&opened(&zip_path)).unwrap(),
        );
        let refuses = |_: &Path, _: &[u8]| -> std::io::Result<()> {
            Err(std::io::Error::from_raw_os_error(5))
        };
        let done = extract_with(
            &opened(&zip_path),
            &dissection,
            &scratch.downloads(),
            "Photos.zip",
            Some(zone),
            &refuses,
        )
        .unwrap();
        assert_eq!(done.files, 3, "{done:?}");
        assert_eq!(done.unmarked.len(), 3, "{:?}", done.unmarked);
        assert!(
            done.unmarked
                .iter()
                .any(|entry| entry.starts_with("readme.txt: ")),
            "{:?}",
            done.unmarked
        );

        // With no mark on the archive there is none to add, and nothing to say.
        let done = extract_with(
            &opened(&zip_path),
            &dissection,
            &scratch.downloads(),
            "Photos.zip",
            None,
            &refuses,
        )
        .unwrap();
        assert!(done.unmarked.is_empty());
    }

    /// What a previous run left is cleared at start. What this run made is
    /// not, whether or not it happens to be open at that moment.
    #[test]
    fn leftovers_are_cleared_but_never_a_copy_this_run_made() {
        let scratch = Scratch::new("leftovers");
        let work = scratch.0.join("work");
        let old = work.join("1-123-0.zip");
        let mine = work.join(format!("{}9", fresh_name()));
        std::fs::write(&old, b"left by another run").unwrap();
        std::fs::write(&mine, b"made by this one").unwrap();
        discard_leftovers_in(&work);
        assert!(!old.exists(), "a leftover was kept");
        assert!(mine.exists(), "a copy this run made was deleted");
    }

    #[test]
    fn a_file_still_being_written_cannot_be_opened_shut_to_writers() {
        let scratch = Scratch::new("busy");
        let path = scratch.downloads().join("arriving.bin");
        let writer = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        assert!(
            open_shut_to_writers(&path).is_err(),
            "a file open for writing looked finished"
        );
        drop(writer);
        assert!(open_shut_to_writers(&path).is_ok());
    }

    /// A file taken away, or cut short, after it was written is never counted
    /// as extracted. This is what Defender's real-time protection does to a
    /// file it objects to as it lands; here the taking away is done by hand.
    #[test]
    fn a_file_gone_or_changed_after_writing_is_not_counted_as_extracted() {
        let scratch = Scratch::new("second-look");
        let kept = scratch.downloads().join("kept.txt");
        let taken = scratch.downloads().join("taken.exe");
        let cut = scratch.downloads().join("cut.dll");
        for path in [&kept, &taken, &cut] {
            std::fs::write(path, b"0123456789").unwrap();
        }
        std::fs::remove_file(&taken).unwrap();
        std::fs::write(&cut, b"0").unwrap();

        let (files, bytes, gone) = second_look(vec![
            ("kept.txt".to_owned(), kept, 10),
            ("taken.exe".to_owned(), taken, 10),
            ("cut.dll".to_owned(), cut, 10),
        ]);
        assert_eq!((files, bytes), (1, 10));
        let names: Vec<&str> = gone.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["taken.exe", "cut.dll"]);

        // And without a detection naming them, they are still reported, just
        // without a name for what took them.
        let named = name_removals(gone);
        assert_eq!(named.len(), 2);
        assert!(named.iter().all(|removal| removal.threat.is_none()));
    }

    #[test]
    fn windows_own_antivirus_refusals_are_recognised() {
        assert!(refused_by_antivirus(&std::io::Error::from_raw_os_error(
            225
        )));
        assert!(refused_by_antivirus(&std::io::Error::from_raw_os_error(
            226
        )));
        assert!(!refused_by_antivirus(&std::io::Error::from_raw_os_error(5)));
    }
}
