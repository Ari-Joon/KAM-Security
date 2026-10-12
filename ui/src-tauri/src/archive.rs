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

use kam_scanner::downloads::{Dissection, Entry, Extraction, MemberStatus};
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

/// Make the private working copy of an archive.
///
/// Created new, in a folder that must be a real folder rather than a link,
/// and read from the original with other writers shut out, so what is copied
/// is one consistent file.
pub fn working_copy(original: &Path) -> Result<PathBuf, String> {
    working_copy_in(original, &work_folder())
}

fn working_copy_in(original: &Path, folder: &Path) -> Result<PathBuf, String> {
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
    let mut target = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&copy)
        .map_err(|error| format!("the working copy could not be created: {error}"))?;
    if let Err(error) = std::io::copy(&mut source, &mut target).and_then(|_| target.flush()) {
        drop(target);
        let _ = std::fs::remove_file(&copy);
        return Err(format!("the archive could not be copied: {error}"));
    }
    Ok(copy)
}

/// Open a file for reading while nobody else may write to it.
///
/// Also the watcher's test for "finished": a browser still writing a download
/// holds it open for writing, and this open then fails.
pub fn open_shut_to_writers(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 0x1;
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
}

/// Delete a working copy, which belongs to this program alone. Permanent, and
/// meant to be: it is a private duplicate, not anybody's file.
pub fn discard(copy: &Path) {
    if copy.parent().is_some_and(|parent| parent == work_folder()) {
        let _ = std::fs::remove_file(copy);
    }
}

/// Delete working copies a previous run left behind. Only plain files
/// directly in the work folder; nothing is followed.
pub fn discard_leftovers() {
    let Ok(listing) = std::fs::read_dir(work_folder()) else {
        return;
    };
    for item in listing.flatten() {
        if item.file_type().is_ok_and(|kind| kind.is_file()) {
            let _ = std::fs::remove_file(item.path());
        }
    }
}

/// Every member of a zip, as the zip itself lists it.
pub fn entries(archive: &Path) -> Result<Vec<Entry>, String> {
    let file = File::open(archive)
        .map_err(|error| format!("the working copy could not be opened: {error}"))?;
    let mut zip = zip::ZipArchive::new(file)
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
/// `parent` is the person's Downloads folder. `zone` is the original's
/// `Zone.Identifier`, written beside every extracted file when there was one.
pub fn extract(
    copy: &Path,
    dissection: &Dissection,
    parent: &Path,
    archive_name: &str,
    zone: Option<&[u8]>,
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
        return Err(format!(
            "{} does not lead where it was made, so nothing was extracted into it",
            destination.display()
        ));
    }

    let file = File::open(copy)
        .map_err(|error| format!("the working copy could not be opened: {error}"))?;
    let mut zip = zip::ZipArchive::new(file)
        .map_err(|error| format!("the working copy could not be read as a zip ({error})"))?;

    let mut outcome = Extraction {
        destination: plain_text(&destination_real),
        left_out: dissection.totals.flagged + dissection.totals.left_out,
        left_out_bytes: dissection.totals.flagged_bytes + dissection.totals.left_out_bytes,
        ..Extraction::default()
    };

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
            zone,
        ) {
            Ok(written) => {
                outcome.files += 1;
                outcome.bytes += written;
            }
            Err(reason) => outcome.failed.push(format!("{}: {reason}", member.name)),
        }
    }
    Ok(outcome)
}

/// Write one member, under every rule in the module notes.
fn write_member(
    zip: &mut zip::ZipArchive<File>,
    index: usize,
    name: &str,
    declared: u64,
    destination: &Path,
    zone: Option<&[u8]>,
) -> Result<u64, String> {
    let parts = safe_relative(name).map_err(|refusal| refusal.sentence())?;
    let Some((file_name, folders)) = parts.split_last() else {
        return Err("It has no name.".to_owned());
    };

    let mut folder = destination.to_path_buf();
    for part in folders {
        folder.push(part);
        match std::fs::symlink_metadata(&folder) {
            Ok(existing) if existing.is_dir() && !existing.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(format!(
                    "{} is in the way and is not a plain folder.",
                    folder.display()
                ))
            }
            Err(_) => std::fs::create_dir(&folder)
                .map_err(|error| format!("its folder could not be made: {error}"))?,
        }
    }
    let folder_real = std::fs::canonicalize(&folder)
        .map_err(|error| format!("its folder could not be found again: {error}"))?;
    if folder_real != destination && !lies_within(&folder_real, destination) {
        return Err("Its folder leads outside the new folder, so it was not written.".to_owned());
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
        return Err("The archive changed while it was being read.".to_owned());
    }
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)
        .map_err(|error| format!("it could not be created: {error}"))?;

    // One byte more than declared is read, so a member that keeps going is
    // noticed rather than written in full.
    let mut limited = (&mut member).take(declared.saturating_add(1));
    let copied = std::io::copy(&mut limited, &mut out).and_then(|copied| {
        out.flush()?;
        Ok(copied)
    });
    drop(out);
    let failure = match copied {
        Ok(copied) if copied > declared => {
            Some("It unpacked to more than it declared, so it was not kept.".to_owned())
        }
        Ok(_) => None,
        Err(error) => Some(format!("it could not be unpacked ({error})")),
    };
    let escaped =
        std::fs::canonicalize(&target).map_or(true, |real| !lies_within(&real, destination));
    if failure.is_some() || escaped {
        let _ = std::fs::remove_file(&target);
        return Err(failure.unwrap_or_else(|| {
            "It would have landed outside the new folder, so it was removed.".to_owned()
        }));
    }

    if let Some(zone) = zone {
        let mut stream = target.clone().into_os_string();
        stream.push(":Zone.Identifier");
        let _ = std::fs::write(PathBuf::from(stream), zone);
    }
    std::fs::metadata(&target)
        .map(|metadata| metadata.len())
        .map_err(|error| format!("it was written and could not be read back: {error}"))
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

    #[test]
    fn every_member_is_listed_as_the_archive_lists_it() {
        let scratch = Scratch::new("list");
        let zip_path = scratch.0.join("a.zip");
        hostile_zip(&zip_path);
        let listed = entries(&zip_path).unwrap();
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
        assert!(entries(&fake).unwrap_err().contains("zip"));
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
        };
        let dissection = dissect("Photos.zip", "ab", scan, &entries(&zip_path).unwrap());
        assert!(dissection.offered, "{dissection:?}");
        assert_eq!(dissection.totals.clean, 2, "{:?}", dissection.totals);
        assert_eq!(dissection.totals.flagged, 1);
        assert_eq!(dissection.totals.left_out, 3);

        let zone = b"[ZoneTransfer]\r\nZoneId=3\r\n";
        let done = extract(
            &zip_path,
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
            &zip_path,
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
        let dissection = dissect("x.zip", "ab", unfinished, &entries(&zip_path).unwrap());
        assert!(extract(&zip_path, &dissection, &scratch.downloads(), "x.zip", None).is_err());
        assert_eq!(std::fs::read_dir(scratch.downloads()).unwrap().count(), 0);
        let _ = clean();
    }

    #[test]
    fn a_working_copy_is_private_new_and_identical() {
        let scratch = Scratch::new("copy");
        let original = scratch.downloads().join("a.zip");
        hostile_zip(&original);
        let copy = working_copy_in(&original, &scratch.0.join("work")).unwrap();
        assert_ne!(copy, original);
        assert_eq!(
            std::fs::read(&copy).unwrap(),
            std::fs::read(&original).unwrap()
        );
        assert!(original.exists(), "the original was moved");
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
}
