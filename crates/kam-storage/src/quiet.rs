//! Reading a file without Windows counting it as opened.
//!
//! NTFS keeps a last-access time for every file. Where Windows maintains it
//! (see [`crate::provenance::access_times`]), any read moves it, and that
//! includes a read of nothing but a small stream beside the file. The November
//! 2026 review showed it in a scratch folder, and the tests below show it
//! again wherever Windows keeps the time: three files with their last-access
//! time set three days back, one read whole, one whose `Zone.Identifier`
//! stream alone was read, one only listed. The first two came back stamped
//! with the moment of the read.
//!
//! A survey that reads thousands of files in order to describe them therefore
//! stamps every one of them as opened just now. The one piece of evidence that
//! answers "have I used this since I downloaded it" becomes a record of the
//! survey, and the next survey reports it as though the person had done it.
//!
//! Windows has a documented way to read without that: `SetFileTime` with a
//! last-access value of all ones, made on a handle before anything is read
//! through it, tells the file system not to count what that handle does.

use std::fs::File;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;

use windows::Win32::Foundation::{FILETIME, GENERIC_READ, HANDLE};
use windows::Win32::Storage::FileSystem::{SetFileTime, FILE_WRITE_ATTRIBUTES};

/// A file open for reading.
#[derive(Debug)]
pub struct Reader {
    pub file: File,
    /// False when reading through this handle counts as opening the file, so
    /// its last-access time will show this read. A caller that reports that
    /// time to anybody has to say so.
    pub quiet: bool,
}

/// Open `path` for reading, quietly wherever Windows allows it.
///
/// Asking a handle not to count needs the right to write the file's
/// attributes, which the reader does not always have: Windows' own files grant
/// even LocalSystem nothing but read. Those are opened the ordinary way and
/// marked as such, because refusing to read them would drop every one of them
/// from a comparison that has always included them.
///
/// A file that is not there is reported at once, without the second attempt.
/// The download survey asks for a stream that most files do not have, twenty
/// thousand times over, and that is the common answer rather than a failure.
pub fn open(path: &str) -> std::io::Result<Reader> {
    let quietly = std::fs::OpenOptions::new()
        .access_mode(GENERIC_READ.0 | FILE_WRITE_ATTRIBUTES.0)
        .open(path);

    match quietly {
        Ok(file) => {
            let quiet = leave_last_access_alone(&file);
            Ok(Reader { file, quiet })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(error),
        Err(_) => File::open(path).map(|file| Reader { file, quiet: false }),
    }
}

/// Tell the file system that this handle's reads are not to move the file's
/// last-access time. False when it would not take the instruction.
fn leave_last_access_alone(file: &File) -> bool {
    // All ones in both halves is the value Windows documents for this, and it
    // is an instruction about the handle rather than a time: nothing on disk
    // changes.
    let untouched = FILETIME {
        dwLowDateTime: u32::MAX,
        dwHighDateTime: u32::MAX,
    };
    // SAFETY: the handle is this file's own and stays open for the call, and
    // the pointer is to a value that outlives it.
    unsafe { SetFileTime(HANDLE(file.as_raw_handle()), None, Some(&untouched), None) }.is_ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::time::{Duration, SystemTime};

    fn scratch(tag: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("kam-quiet-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    const DAY: Duration = Duration::from_secs(86_400);

    /// A file whose last-access time is three days old, with a download record
    /// beside it. `None` where the scratch folder cannot hold one: a stream
    /// beside a file needs NTFS.
    fn aged(folder: &std::path::Path, name: &str) -> Option<(String, SystemTime)> {
        let path = folder.join(name);
        std::fs::write(&path, vec![7_u8; 4096]).unwrap();
        let text = path.to_string_lossy().into_owned();
        std::fs::write(
            format!("{text}:Zone.Identifier"),
            b"[ZoneTransfer]\r\nZoneId=3\r\n",
        )
        .ok()?;

        let then = SystemTime::now() - 3 * DAY;
        let handle = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        handle
            .set_times(std::fs::FileTimes::new().set_accessed(then))
            .unwrap();
        drop(handle);

        let recorded = last_access(&text);
        // The premise of everything below: the file really does look as though
        // nothing has opened it for days.
        let age = SystemTime::now().duration_since(recorded).ok()?;
        (age > 2 * DAY).then_some((text, recorded))
    }

    fn last_access(path: &str) -> SystemTime {
        std::fs::metadata(path).unwrap().accessed().unwrap()
    }

    /// Whether an ordinary read moves a file's last-access time here.
    ///
    /// It did where these tests were written and need not elsewhere: the setting
    /// differs by machine, and where Windows is not recording opens there is
    /// nothing for a quiet read to protect and nothing these tests can show.
    /// So each test asks first, and says nothing either way when the answer is
    /// no, rather than passing for a reason that has nothing to do with it.
    fn this_machine_counts_reads(folder: &std::path::Path) -> bool {
        let Some((path, before)) = aged(folder, "control.bin") else {
            return false;
        };
        let _ = std::fs::read(format!("{path}:Zone.Identifier")).unwrap();
        last_access(&path)
            .duration_since(before)
            .is_ok_and(|moved| moved > DAY)
    }

    #[test]
    fn reading_a_files_download_record_quietly_leaves_its_last_access_time_alone() {
        let folder = scratch("stream");
        if !this_machine_counts_reads(&folder) {
            let _ = std::fs::remove_dir_all(&folder);
            return;
        }

        let (path, before) = aged(&folder, "download.bin").unwrap();
        let mut reader = open(&format!("{path}:Zone.Identifier")).unwrap();
        assert!(reader.quiet, "a file of our own should open quietly");
        let mut text = String::new();
        reader.file.read_to_string(&mut text).unwrap();
        drop(reader);

        assert!(text.contains("ZoneId=3"), "the record was not read: {text}");
        assert_eq!(
            last_access(&path),
            before,
            "reading the download record stamped the file as opened just now"
        );

        std::fs::remove_dir_all(&folder).unwrap();
    }

    #[test]
    fn reading_a_whole_file_quietly_leaves_its_last_access_time_alone() {
        let folder = scratch("whole");
        if !this_machine_counts_reads(&folder) {
            let _ = std::fs::remove_dir_all(&folder);
            return;
        }

        let (path, before) = aged(&folder, "copy.bin").unwrap();
        let mut reader = open(&path).unwrap();
        assert!(reader.quiet);
        let mut bytes = Vec::new();
        reader.file.read_to_end(&mut bytes).unwrap();
        drop(reader);

        assert_eq!(bytes.len(), 4096);
        assert_eq!(
            last_access(&path),
            before,
            "reading the file stamped it as opened just now"
        );

        std::fs::remove_dir_all(&folder).unwrap();
    }

    #[test]
    fn a_file_that_is_not_there_is_an_error_and_not_a_second_attempt() {
        let folder = scratch("absent");
        let path = folder.join("never-written.bin");
        let outcome = open(&path.to_string_lossy());
        assert_eq!(
            outcome.map(|_| ()).map_err(|error| error.kind()),
            Err(std::io::ErrorKind::NotFound)
        );
        std::fs::remove_dir_all(&folder).unwrap();
    }
}
