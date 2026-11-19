//! Where a file came from, according to Windows itself.
//!
//! Every browser, mail client and archive tool marks what it writes with a
//! `Zone.Identifier` alternate data stream — a few lines of INI hidden beside
//! the file, naming the security zone it came from and usually the URL it was
//! fetched from. It is what makes Windows show the "this file came from another
//! computer" checkbox. Nothing surfaces it to the user, and it survives for
//! years.
//!
//! Reading it turns "you have a 16 GB file in Documents" into "you downloaded a
//! 16 GB file from example.com in March 2024 and have not opened it since".
//!
//! # A correction to the plan
//!
//! PLAN.md said the USN journal would tell us *which process* wrote a file. It
//! does not. USN records carry file references and reason codes — created,
//! extended, renamed — and no process identity at all. Attributing a write to a
//! program needs ETW or a filesystem minifilter, and neither is in scope. So
//! provenance here is: which zone, from what URL, when it arrived, and how long
//! since anything touched it.
//!
//! # On "never opened"
//!
//! Whether Windows keeps a file's last-access time up to date is a setting,
//! and it differs by machine. Where it is off the time means nothing, so
//! [`access_times`] is checked and reported rather than letting the UI draw a
//! confident conclusion from a number the filesystem stopped maintaining.
//!
//! This module used to read that setting backwards. It took every value but 0
//! to mean "off", including the 2 that current Windows sets by itself, and 2
//! means the times are kept. So on an ordinary machine the page said there was
//! no way to tell which downloads had ever been opened, while Windows was
//! recording exactly that.
//!
//! Where the time is kept, any read moves it, this module's own included. The
//! record beside each file is therefore read through [`crate::quiet`], which
//! asks Windows not to count the read. The two corrections belong together:
//! reporting a time this survey had just overwritten would be reporting itself.

use std::io::Read;

use serde::{Deserialize, Serialize};
use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;

use crate::index::VolumeIndex;
use crate::registry::{Key, View};

/// Smallest file worth asking about. Reading the stream costs an open per file,
/// and a 2 MB download is not what anyone is hunting for.
const MIN_DOWNLOAD_BYTES: u64 = 32 * 1024 * 1024;

/// Largest number of files to interrogate, biggest first. A bound rather than a
/// filter: without it a volume full of large files turns this into a long job.
const MAX_CANDIDATES: usize = 20_000;

/// Windows security zones, as written into the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Zone {
    LocalMachine,
    Intranet,
    Trusted,
    /// The ordinary case for anything downloaded from the web.
    Internet,
    /// A site the user or policy marked as restricted.
    Restricted,
    Other(u32),
}

impl Zone {
    fn from_id(id: u32) -> Self {
        match id {
            0 => Self::LocalMachine,
            1 => Self::Intranet,
            2 => Self::Trusted,
            3 => Self::Internet,
            4 => Self::Restricted,
            other => Self::Other(other),
        }
    }

    /// Whether the file came from outside this machine.
    pub fn is_external(self) -> bool {
        matches!(self, Self::Internet | Self::Restricted)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::LocalMachine => "this machine",
            Self::Intranet => "the local network",
            Self::Trusted => "a trusted site",
            Self::Internet => "the internet",
            Self::Restricted => "a restricted site",
            Self::Other(_) => "an unrecognised zone",
        }
    }
}

/// Where a single file came from, as its own stream records it.
///
/// [`find`] answers "what large downloads are on this volume"; this answers
/// "where did this one file come from", which is the question the scanner asks
/// about a binary it already has reason to care about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Origin {
    pub zone: Zone,
    /// Kept whole because it is evidence. Download URLs routinely carry tokens
    /// and account identifiers, so the interface shows only the host.
    pub host_url: Option<String>,
    pub referrer_url: Option<String>,
}

impl Origin {
    /// Just the host, which is what is safe to put on screen.
    pub fn host(&self) -> Option<&str> {
        let url = self.host_url.as_deref()?;
        let rest = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
        let host = rest.split(['/', '?', '#']).next()?;
        // Strip any credentials, which have no business on screen either.
        let host = host.rsplit('@').next()?;
        (!host.is_empty()).then_some(host)
    }
}

/// Read one file's recorded origin.
///
/// Most files have no such stream, and that is not an error: it means nothing
/// was recorded, not that the file is local.
pub fn origin_of(path: &str) -> Option<Origin> {
    let (zone, host_url, referrer_url) = parse_stream(&read_stream(path)?.text)?;
    Some(Origin {
        zone,
        host_url,
        referrer_url,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Download {
    pub path: String,
    /// Final component, which is what a person recognises.
    pub name: String,
    pub bytes: u64,
    pub zone: Zone,
    /// The site the file itself came from.
    ///
    /// Kept whole because it is evidence, but the interface shows only the host.
    /// Real download URLs routinely carry signed tokens, account identifiers and
    /// session keys in their query strings, and a screenshot of this list would
    /// otherwise publish them.
    pub host_url: Option<String>,
    /// The page that linked to it, when the downloader recorded one.
    pub referrer_url: Option<String>,
    pub days_since_arrival: Option<u64>,
    /// Meaningless unless [`DownloadSummary::access_times`] says Windows is
    /// recording them. Any program that reads the file moves it, so an old
    /// figure is evidence that nothing has and a recent one only that
    /// something did.
    pub days_since_access: Option<u64>,
}

/// Whether Windows keeps last-access times up to date on this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessTimes {
    /// A read moves a file's last-access time.
    Recorded,
    /// It does not, and the time on a file is whatever it last happened to be.
    NotRecorded,
    /// The setting could not be read. Not the same as either answer, and the
    /// interface shows no last-opened dates on the strength of it.
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadSummary {
    pub found: usize,
    pub total_bytes: u64,
    /// Whether this machine maintains last-access times. Unless it does, the
    /// access figures are not evidence of anything.
    pub access_times: AccessTimes,
    /// How many files were interrogated to produce the list.
    pub examined: usize,
    /// Listed files whose record could only be read in a way Windows counts as
    /// opening them, so their last-access time now shows this survey. Zero in
    /// the ordinary case; see [`crate::quiet`] for when it is not.
    #[serde(default)]
    pub read_as_opened: usize,
    /// Downloads that were found and are counted in `found` and `total_bytes`
    /// but are not in the list sent with them, because the answer would not
    /// have fitted in one reply. The list is largest first, so these are the
    /// smallest. Zero in the ordinary case.
    #[serde(default)]
    pub unlisted: usize,
}

/// Parse the `Zone.Identifier` stream.
///
/// The format is a tiny INI: a `[ZoneTransfer]` header then `Key=Value` lines.
/// Written by many different programs, so it is read leniently — unknown keys
/// ignored, a missing zone treated as absent rather than as zero.
fn parse_stream(text: &str) -> Option<(Zone, Option<String>, Option<String>)> {
    let mut zone = None;
    let mut host = None;
    let mut referrer = None;

    for line in text.lines() {
        let line = line.trim();
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key.trim().to_ascii_lowercase().as_str() {
            "zoneid" => zone = value.parse::<u32>().ok().map(Zone::from_id),
            "hosturl" => host = Some(value.to_owned()),
            "referrerurl" => referrer = Some(value.to_owned()),
            _ => {}
        }
    }

    zone.map(|zone| (zone, host, referrer))
}

/// The record beside a file, and whether reading it left the file looking
/// unopened.
struct Stream {
    text: String,
    /// False when Windows counted the read as opening the file.
    quiet: bool,
}

/// Read the stream beside a file, if it has one.
///
/// The `path:stream` form is how Windows addresses an alternate data stream, and
/// ordinary file reads understand it. Most files have none, so a failure here is
/// the normal case rather than an error worth reporting.
fn read_stream(path: &str) -> Option<Stream> {
    let mut reader = crate::quiet::open(&format!("{path}:Zone.Identifier")).ok()?;
    let mut bytes = Vec::new();
    reader.file.read_to_end(&mut bytes).ok()?;
    let quiet = reader.quiet;
    // Usually ASCII, occasionally UTF-16 with a byte order mark from an older
    // writer. Lossy either way: only three keys are being looked for.
    let text = if bytes.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(&bytes).into_owned()
    };
    Some(Stream { text, quiet })
}

/// Whether this machine keeps last-access times up to date.
pub fn access_times() -> AccessTimes {
    let Some(key) = Key::open(
        HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\FileSystem",
        View::Native,
    ) else {
        return AccessTimes::Unknown;
    };
    access_times_from(key.dword("NtfsDisableLastAccessUpdate"))
}

/// What `NtfsDisableLastAccessUpdate` says.
///
/// The lowest bit is the answer: 0 and 2 mean the times are kept, 1 and 3 that
/// they are not. The next bit only says who chose, the person (0 and 1) or
/// Windows (2 and 3), and current Windows also sets the highest bit, so the
/// value on an untouched machine is `0x80000002` and Windows' own tool reports
/// it as "System Managed, Last Access Time Updates ENABLED".
///
/// A value that is not there, or could not be read, is its own answer.
fn access_times_from(setting: Option<u32>) -> AccessTimes {
    match setting {
        None => AccessTimes::Unknown,
        Some(value) if value & 1 == 0 => AccessTimes::Recorded,
        Some(_) => AccessTimes::NotRecorded,
    }
}

const FILETIME_EPOCH_OFFSET: u64 = 11_644_473_600;

fn days_since(filetime: u64, now: u64) -> Option<u64> {
    if filetime == 0 {
        return None;
    }
    let seconds = (filetime / 10_000_000).checked_sub(FILETIME_EPOCH_OFFSET)?;
    Some(now.saturating_sub(seconds) / 86_400)
}

/// Find large files that came from outside this machine.
pub fn find(
    index: &VolumeIndex,
    drive_root: &str,
    now_unix: u64,
) -> (Vec<Download>, DownloadSummary) {
    // Candidates come from the table, which already knows every size, so only
    // the few thousand worth asking about are touched on disk.
    let mut candidates: Vec<(u32, u64)> = index
        .entries()
        .iter()
        .filter(|(_, entry)| !entry.is_directory && entry.bytes >= MIN_DOWNLOAD_BYTES)
        .map(|(record, entry)| (*record, entry.bytes))
        .collect();
    candidates.sort_by_key(|(_, bytes)| std::cmp::Reverse(*bytes));
    candidates.truncate(MAX_CANDIDATES);

    let examined = candidates.len();
    let mut downloads = Vec::new();
    let mut read_as_opened = 0_usize;

    for (record, bytes) in candidates {
        let Some(path) = index.path_of(record, drive_root) else {
            continue;
        };
        let Some(stream) = read_stream(&path) else {
            continue;
        };
        let Some((zone, host_url, referrer_url)) = parse_stream(&stream.text) else {
            continue;
        };
        if !zone.is_external() {
            continue;
        }
        if !stream.quiet {
            read_as_opened += 1;
        }

        let entry = index.entry(record);
        downloads.push(Download {
            name: entry
                .map(|entry| entry.name.clone())
                .unwrap_or_else(|| path.clone()),
            days_since_arrival: entry.and_then(|entry| days_since(entry.created, now_unix)),
            days_since_access: entry.and_then(|entry| days_since(entry.accessed, now_unix)),
            path,
            bytes,
            zone,
            host_url,
            referrer_url,
        });
    }

    downloads.sort_by_key(|download| std::cmp::Reverse(download.bytes));
    let summary = DownloadSummary {
        found: downloads.len(),
        total_bytes: downloads.iter().map(|download| download.bytes).sum(),
        access_times: access_times(),
        examined,
        read_as_opened,
        unlisted: 0,
    };
    (downloads, summary)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const CHROME: &str = "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.com/page\r\nHostUrl=https://cdn.example.com/big.iso\r\n";

    #[test]
    fn a_browser_stream_yields_zone_and_both_urls() {
        let (zone, host, referrer) = parse_stream(CHROME).unwrap();
        assert_eq!(zone, Zone::Internet);
        assert_eq!(host.as_deref(), Some("https://cdn.example.com/big.iso"));
        assert_eq!(referrer.as_deref(), Some("https://example.com/page"));
    }

    #[test]
    fn a_stream_with_only_a_zone_still_parses() {
        // Plenty of writers record nothing but the zone.
        let (zone, host, referrer) = parse_stream("[ZoneTransfer]\nZoneId=3\n").unwrap();
        assert_eq!(zone, Zone::Internet);
        assert!(host.is_none());
        assert!(referrer.is_none());
    }

    #[test]
    fn keys_are_matched_regardless_of_case() {
        let (zone, host, _) =
            parse_stream("[ZoneTransfer]\nzoneid=4\nHOSTURL=https://x.test/f\n").unwrap();
        assert_eq!(zone, Zone::Restricted);
        assert_eq!(host.as_deref(), Some("https://x.test/f"));
    }

    #[test]
    fn a_stream_without_a_zone_is_not_a_download() {
        // Absent rather than zero: treating a missing ZoneId as LocalMachine
        // would quietly file real downloads under "came from this machine".
        assert!(parse_stream("[ZoneTransfer]\nHostUrl=https://x.test/f\n").is_none());
        assert!(parse_stream("").is_none());
    }

    #[test]
    fn empty_values_are_ignored_rather_than_stored() {
        let (_, host, referrer) =
            parse_stream("[ZoneTransfer]\nZoneId=3\nHostUrl=\nReferrerUrl=  \n").unwrap();
        assert!(host.is_none(), "an empty HostUrl is not a URL");
        assert!(referrer.is_none());
    }

    #[test]
    fn only_external_zones_count_as_downloads() {
        assert!(Zone::Internet.is_external());
        assert!(Zone::Restricted.is_external());
        // A file copied off a local disk or a trusted intranet share is not a
        // download, and listing it would bury the ones that are.
        assert!(!Zone::LocalMachine.is_external());
        assert!(!Zone::Intranet.is_external());
        assert!(!Zone::Trusted.is_external());
    }

    #[test]
    fn unknown_zone_numbers_are_preserved_rather_than_guessed() {
        assert_eq!(Zone::from_id(9), Zone::Other(9));
        assert!(!Zone::Other(9).is_external());
    }

    #[test]
    fn a_zero_timestamp_is_unknown() {
        assert_eq!(days_since(0, 1_700_000_000), None);
    }

    #[test]
    fn arrival_is_counted_in_whole_days() {
        let now = 1_704_067_200_u64;
        let three_days_ago = ((now - 3 * 86_400) + FILETIME_EPOCH_OFFSET) * 10_000_000;
        assert_eq!(days_since(three_days_ago, now), Some(3));
    }

    /// The setting is read by its lowest bit, whoever chose it.
    ///
    /// This is the regression test for reading it backwards. The value read
    /// on the development machine, from a session's own shell, is
    /// `0x80000002`, which Windows' own tool there reports as "System Managed,
    /// Last Access Time Updates ENABLED", and the old reading (anything but 0
    /// means off) called that not recorded. Current Windows
    /// always sets the high bit, so the old reading could no longer answer
    /// "recorded" on any up-to-date machine.
    #[test]
    fn the_last_access_setting_is_read_by_its_lowest_bit() {
        for kept in [0, 2, 0x8000_0000, 0x8000_0002] {
            assert_eq!(
                access_times_from(Some(kept)),
                AccessTimes::Recorded,
                "{kept:#x} means Windows is keeping last-access times"
            );
        }
        for stopped in [1, 3, 0x8000_0001, 0x8000_0003] {
            assert_eq!(
                access_times_from(Some(stopped)),
                AccessTimes::NotRecorded,
                "{stopped:#x} means Windows is not keeping last-access times"
            );
        }
    }

    #[test]
    fn a_setting_that_could_not_be_read_is_neither_answer() {
        assert_eq!(access_times_from(None), AccessTimes::Unknown);
    }

    #[test]
    fn the_machine_reports_whether_it_keeps_last_access_times() {
        // Informational: the setting differs by machine, and the UI must know
        // it before it says anything about when a file was last opened.
        println!("last-access times here: {:?}", access_times());
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("kam-provenance-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    /// Asking where a file came from must not make it look freshly opened.
    ///
    /// The survey asks this of every large file on the drive, and the answer
    /// it then shows beside each download is when that file was last opened.
    /// Read the ordinary way, the question overwrote the answer.
    #[test]
    fn asking_where_a_file_came_from_does_not_stamp_it_as_opened() {
        use std::time::{Duration, SystemTime};

        let folder = scratch("origin");
        let aged = |name: &str| -> Option<(String, SystemTime)> {
            let path = folder.join(name).to_string_lossy().into_owned();
            std::fs::write(&path, b"payload").unwrap();
            std::fs::write(format!("{path}:Zone.Identifier"), CHROME).ok()?;
            let handle = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            let then = SystemTime::now() - Duration::from_secs(3 * 86_400);
            handle
                .set_times(std::fs::FileTimes::new().set_accessed(then))
                .unwrap();
            drop(handle);
            let recorded = std::fs::metadata(&path).unwrap().accessed().unwrap();
            Some((path, recorded))
        };
        let last_access = |path: &str| std::fs::metadata(path).unwrap().accessed().unwrap();

        // The premise, checked on a file of its own: here, an ordinary read of
        // the record does move the time. Where it does not (the setting is
        // off, or the folder cannot hold a stream) there is nothing to show.
        let Some((control, before)) = aged("control.iso") else {
            let _ = std::fs::remove_dir_all(&folder);
            return;
        };
        let _ = std::fs::read(format!("{control}:Zone.Identifier")).unwrap();
        if last_access(&control) == before {
            let _ = std::fs::remove_dir_all(&folder);
            return;
        }

        let (path, before) = aged("big.iso").unwrap();
        let origin = origin_of(&path).expect("the record should be read");
        assert_eq!(origin.zone, Zone::Internet);
        assert_eq!(origin.host(), Some("cdn.example.com"));
        assert_eq!(
            last_access(&path),
            before,
            "reading the download record stamped the file as opened just now"
        );

        std::fs::remove_dir_all(&folder).unwrap();
    }
}
