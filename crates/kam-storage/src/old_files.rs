//! Large files whose dates are all more than a year old.
//!
//! The download list in [`crate::provenance`] answers "what did I fetch and
//! forget". This answers a wider question from the same read of the file
//! table: which large files, however they got here, carry no date from the
//! last year.
//!
//! # Dates and sizes, and nothing else
//!
//! This is a list of facts Windows recorded. It does not say a file is unused,
//! or spare, or safe to remove, and nothing built on it may: a year-old date
//! on a file says when something last happened to it, not whether anybody
//! needs it. A disk image kept for the day a machine has to be rebuilt looks
//! exactly like one that was forgotten.
//!
//! # The three dates, and what each is worth
//!
//! - **Created** is when this copy arrived on this drive. A copy resets it; a
//!   move within the drive keeps it.
//! - **Last written** is when the contents last changed. A download often
//!   carries its server's or its archive's date, so this can be older than
//!   created.
//! - **Last opened** is kept only where Windows is recording opens, which is
//!   a setting ([`crate::provenance::access_times`]). Any program that reads
//!   the file moves it, antivirus and backup included, so it is evidence in
//!   one direction only: an old date means nothing has read the file since.
//!
//! A file is listed only when every date the list is built from was recorded
//! and is more than a year old. Where Windows is not recording opens, or that
//! could not be told, the last-opened date is not used and not sent: the
//! number in the table is whatever it last happened to be. The list is then
//! built from the other two, and the summary says so.
//!
//! # A date that was not recorded
//!
//! A date of zero is "not recorded", never the year 1601. A file with such a
//! date cannot be said to have every date more than a year old, so it is not
//! listed. It is counted, because leaving a file out without a word reads as
//! the file not being there.
//!
//! # Only the caller's own folders
//!
//! Most large old files on a drive are Windows' own, or a program's, or in
//! another account's profile, and none of those is this caller's to act on.
//! [`crate::duplicates::owner_of`] already draws that line for the duplicate
//! search, and it is used here unchanged: a file is listed only where it
//! answers [`Owner::Yours`]. What is left out for where it sits is counted by
//! where that is, so the page can say what the list does not cover.

use kam_core::UserContext;
use serde::{Deserialize, Serialize};

use crate::duplicates::{owner_of, Owner};
use crate::index::VolumeIndex;
use crate::provenance::AccessTimes;

/// Smallest file listed.
pub const MIN_BYTES: u64 = 100 * 1024 * 1024;

/// How old every date has to be, in days.
pub const OLDER_THAN_DAYS: u64 = 365;

/// How many files are listed, largest first. The summary counts the rest.
pub const LISTED: usize = 200;

/// Seconds between 1601, where Windows counts from, and 1970.
const FILETIME_EPOCH_OFFSET: u64 = 11_644_473_600;

/// One large file, with the dates Windows recorded for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OldFile {
    pub path: String,
    /// Final component, which is what a person recognises.
    pub name: String,
    pub bytes: u64,
    /// When this copy arrived on this drive, in seconds since 1970.
    pub created: Option<u64>,
    /// When its contents last changed.
    pub modified: Option<u64>,
    /// When anything last opened it. `None` whenever
    /// [`OldFileSummary::access_times`] is not [`AccessTimes::Recorded`]: the
    /// date was not used to build the list and is not sent.
    pub accessed: Option<u64>,
}

/// Files that met the size and the dates and are not listed because of where
/// they are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeftOut {
    /// Where, as the duplicate search judges it. Never [`Owner::Yours`].
    pub owner: Owner,
    pub files: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OldFileSummary {
    /// Every file that met the rule in the caller's own folders. The list
    /// sent with this holds the largest of them and may hold fewer.
    pub found: usize,
    /// What all of those hold together, listed or not.
    pub total_bytes: u64,
    /// Whether Windows keeps last-opened dates on this machine. Anything but
    /// `Recorded` means the list was built from created and last written
    /// alone.
    pub access_times: AccessTimes,
    /// The rule the list was built by, so that the page states this one and
    /// not a figure of its own.
    pub min_bytes: u64,
    pub older_than_days: u64,
    /// Files that met the rule somewhere that is not the caller's own, by
    /// where. Most by bytes first.
    pub left_out: Vec<LeftOut>,
    /// Files of the size in the caller's own folders with a date Windows did
    /// not record, and no recorded date from the last year. They could not be
    /// said to meet the rule, so they are not listed.
    pub undated: u64,
    pub undated_bytes: u64,
    /// Files of the size that sit too many folders deep for their path to be
    /// rebuilt, so they could not be named or placed at all.
    pub unplaced: u64,
}

/// A FILETIME as seconds since 1970, or `None` when it was not recorded.
///
/// Zero is how a missing date arrives. A value from before 1970 is not a date
/// anything on this drive happened either, and is read the same way.
fn seconds(filetime: u64) -> Option<u64> {
    if filetime == 0 {
        return None;
    }
    (filetime / 10_000_000).checked_sub(FILETIME_EPOCH_OFFSET)
}

/// Find the large files with no date from the last year.
pub fn find(
    index: &VolumeIndex,
    drive_root: &str,
    now_unix: u64,
    user: &UserContext,
) -> (Vec<OldFile>, OldFileSummary) {
    find_as(
        index,
        drive_root,
        now_unix,
        user,
        crate::provenance::access_times(),
    )
}

/// [`find`], told whether Windows is recording opens instead of asking.
pub(crate) fn find_as(
    index: &VolumeIndex,
    drive_root: &str,
    now_unix: u64,
    user: &UserContext,
    access_times: AccessTimes,
) -> (Vec<OldFile>, OldFileSummary) {
    let horizon = now_unix.saturating_sub(OLDER_THAN_DAYS * 86_400);
    // "Could not be read" is not "recorded": a date nobody can vouch for is
    // not one to build a list on.
    let opens_recorded = access_times == AccessTimes::Recorded;

    let mut files: Vec<OldFile> = Vec::new();
    let mut left_out: Vec<LeftOut> = Vec::new();
    let mut undated = 0_u64;
    let mut undated_bytes = 0_u64;
    let mut unplaced = 0_u64;

    for (record, entry) in index.entries() {
        if entry.is_directory || entry.bytes < MIN_BYTES {
            continue;
        }

        let created = seconds(entry.created);
        let modified = seconds(entry.modified);
        let accessed = if opens_recorded {
            seconds(entry.accessed)
        } else {
            None
        };
        let relied_on: &[Option<u64>] = if opens_recorded {
            &[created, modified, accessed]
        } else {
            &[created, modified]
        };

        // One date from the last year settles it, whatever else is missing.
        // A date in the future is not older than a year either.
        if relied_on.iter().flatten().any(|date| *date >= horizon) {
            continue;
        }
        let every_date_recorded = relied_on.iter().all(Option::is_some);

        let Some(path) = index.path_of(*record, drive_root) else {
            unplaced += 1;
            continue;
        };
        let owner = owner_of(&path, user);
        if owner != Owner::Yours {
            // Only what would otherwise have been listed: this is the count
            // of files the list does not cover, not of everything large.
            if every_date_recorded {
                match left_out.iter_mut().find(|group| group.owner == owner) {
                    Some(group) => {
                        group.files += 1;
                        group.bytes += entry.bytes;
                    }
                    None => left_out.push(LeftOut {
                        owner,
                        files: 1,
                        bytes: entry.bytes,
                    }),
                }
            }
            continue;
        }
        if !every_date_recorded {
            undated += 1;
            undated_bytes += entry.bytes;
            continue;
        }

        files.push(OldFile {
            name: entry.name.clone(),
            path,
            bytes: entry.bytes,
            created,
            modified,
            accessed,
        });
    }

    // Largest first, and by path between equals so that the same drive gives
    // the same list twice: the table is walked in no particular order.
    files.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.path.cmp(&b.path)));
    left_out.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| b.files.cmp(&a.files)));

    let summary = OldFileSummary {
        found: files.len(),
        total_bytes: files.iter().map(|file| file.bytes).sum(),
        access_times,
        min_bytes: MIN_BYTES,
        older_than_days: OLDER_THAN_DAYS,
        left_out,
        undated,
        undated_bytes,
        unplaced,
    };
    files.truncate(LISTED);
    (files, summary)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::index::testing::{days_ago, Drive, NOW};

    const MB: u64 = 1024 * 1024;

    fn someone() -> UserContext {
        UserContext::new(None, r"C:\Users\someone")
    }

    fn listed(files: &[OldFile]) -> Vec<&str> {
        files.iter().map(|file| file.name.as_str()).collect()
    }

    /// The rule, one date at a time: a file is listed only when all three of
    /// its dates are more than a year old.
    ///
    /// Each of the files that is not listed differs from the one that is in
    /// one date only, so a rule that forgot a date would let that one in.
    #[test]
    fn a_file_is_listed_only_when_all_three_of_its_dates_are_more_than_a_year_old() {
        let mut drive = Drive::new();
        let old = days_ago(400);
        let recent = days_ago(30);
        let folder = r"Users\someone\Documents";
        drive.file_dated(&format!(r"{folder}\all-old.iso"), 700 * MB, old, old, old);
        drive.file_dated(&format!(r"{folder}\opened.iso"), 700 * MB, old, old, recent);
        drive.file_dated(
            &format!(r"{folder}\written.iso"),
            700 * MB,
            old,
            recent,
            old,
        );
        drive.file_dated(
            &format!(r"{folder}\arrived.iso"),
            700 * MB,
            recent,
            old,
            old,
        );
        // A year to the day is not more than a year.
        let edge = days_ago(OLDER_THAN_DAYS);
        drive.file_dated(&format!(r"{folder}\edge.iso"), 700 * MB, old, old, edge);
        // Old in every date, and under the size.
        drive.file_dated(&format!(r"{folder}\small.iso"), 99 * MB, old, old, old);
        let index = drive.index();

        let (files, summary) = find_as(&index, "C:", NOW, &someone(), AccessTimes::Recorded);
        assert_eq!(listed(&files), vec!["all-old.iso"]);
        assert_eq!(summary.found, 1);
        assert_eq!(summary.total_bytes, 700 * MB);
        assert_eq!(summary.access_times, AccessTimes::Recorded);
        assert_eq!(
            (summary.min_bytes, summary.older_than_days),
            (100 * MB, 365)
        );

        let file = &files[0];
        assert_eq!(file.path, r"C:\Users\someone\Documents\all-old.iso");
        let expected = NOW - 400 * 86_400;
        assert_eq!(
            (file.created, file.modified, file.accessed),
            (Some(expected), Some(expected), Some(expected))
        );
    }

    /// Where Windows is not recording opens, the last-opened date is not
    /// used and not sent, and the list is built from the other two.
    ///
    /// The number is still in the table there. It is whatever it last
    /// happened to be, and a list built on it, or a column showing it, would
    /// present it as a record of something.
    #[test]
    fn where_opens_are_not_recorded_the_list_is_built_from_the_other_two_dates() {
        let mut drive = Drive::new();
        let old = days_ago(500);
        let recent = days_ago(5);
        let folder = r"Users\someone\Videos";
        // A last-opened number from last week, on a machine not keeping them.
        drive.file_dated(&format!(r"{folder}\film.mkv"), 900 * MB, old, old, recent);
        drive.file_dated(&format!(r"{folder}\edited.mkv"), 900 * MB, old, recent, old);
        let index = drive.index();

        for access in [AccessTimes::NotRecorded, AccessTimes::Unknown] {
            let (files, summary) = find_as(&index, "C:", NOW, &someone(), access);
            assert_eq!(listed(&files), vec!["film.mkv"], "{access:?}");
            assert_eq!(
                files[0].accessed, None,
                "a last-opened date was sent that Windows is not keeping ({access:?})"
            );
            assert!(files[0].created.is_some() && files[0].modified.is_some());
            assert_eq!(summary.access_times, access);
        }

        // The same drive where opens are recorded: that file was opened last
        // week, and is not listed.
        let (files, _) = find_as(&index, "C:", NOW, &someone(), AccessTimes::Recorded);
        assert!(files.is_empty(), "{:?}", listed(&files));
    }

    /// Only the caller's own folders are listed, and what is left out for
    /// where it sits is counted by where that is.
    #[test]
    fn only_files_in_the_callers_own_folders_are_listed_and_the_rest_are_counted() {
        let mut drive = Drive::new();
        let old = days_ago(800);
        let mut add = |path: &str, megabytes: u64| {
            drive.file_dated(path, megabytes * MB, old, old, old);
        };
        add(r"Users\someone\Downloads\mine.zip", 300);
        add(r"Users\someone\OneDrive\archive.7z", 200);
        add(r"Windows\System32\big.dll", 150);
        add(r"Windows\WinSxS\component.cab", 160);
        add(r"Program Files\Game\data.pak", 4_000);
        add(r"Program Files\Game\more.pak", 1_000);
        add(r"ProgramData\Vendor\cache.bin", 500);
        add(r"Users\someone\AppData\Local\Vendor\model.bin", 600);
        add(r"Users\another\Documents\theirs.iso", 2_000);
        add(r"Backups\old.vhdx", 2_500);
        add(r"$Recycle.Bin\S-1-5-21-1-2-3-1001\$R1.iso", 700);
        let index = drive.index();

        let (files, summary) = find_as(&index, "C:", NOW, &someone(), AccessTimes::Recorded);
        assert_eq!(listed(&files), vec!["mine.zip", "archive.7z"]);
        assert_eq!(summary.found, 2);
        assert_eq!(summary.total_bytes, 500 * MB);

        let group = |owner: Owner| {
            summary
                .left_out
                .iter()
                .find(|group| group.owner == owner)
                .map(|group| (group.files, group.bytes / MB))
        };
        assert_eq!(group(Owner::Yours), None, "what is listed is not left out");
        assert_eq!(group(Owner::Windows), Some((1, 150)));
        assert_eq!(group(Owner::Servicing), Some((1, 160)));
        assert_eq!(group(Owner::Program), Some((2, 5_000)));
        assert_eq!(group(Owner::ProgramData), Some((2, 1_100)));
        assert_eq!(group(Owner::Deleted), Some((1, 700)));
        // Another account's profile and a folder nobody can be told to own.
        assert_eq!(group(Owner::Elsewhere), Some((2, 4_500)));
        // Most by bytes first.
        assert_eq!(summary.left_out[0].owner, Owner::Program);
        assert_eq!(summary.left_out[1].owner, Owner::Elsewhere);
        // Every file on the drive is in the list or in a count.
        let counted: u64 = summary.left_out.iter().map(|group| group.files).sum();
        assert_eq!(counted + summary.found as u64, 11);
    }

    /// A date that was not recorded is not an old date.
    ///
    /// Zero would otherwise read as the year 1601, which is more than a year
    /// ago, and every file missing a date would be listed on the strength of
    /// it. Such a file is counted instead, unless a date it does have is from
    /// the last year, when it was never going to be listed.
    #[test]
    fn a_file_with_a_date_that_was_not_recorded_is_counted_and_not_listed() {
        let mut drive = Drive::new();
        let old = days_ago(600);
        let recent = days_ago(3);
        let folder = r"Users\someone\Documents";
        drive.file_dated(&format!(r"{folder}\dated.iso"), 400 * MB, old, old, old);
        drive.file_dated(&format!(r"{folder}\no-opened.iso"), 500 * MB, old, old, 0);
        drive.file_dated(&format!(r"{folder}\no-created.iso"), 600 * MB, 0, old, old);
        drive.file_dated(&format!(r"{folder}\no-dates.iso"), 700 * MB, 0, 0, 0);
        drive.file_dated(&format!(r"{folder}\recent.iso"), 800 * MB, 0, recent, old);
        // Not the caller's, and missing a date: it would not have been
        // listed, so it is not among the files the list leaves out either.
        drive.file_dated(r"Program Files\Thing\undated.pak", 900 * MB, old, old, 0);
        let index = drive.index();

        let (files, summary) = find_as(&index, "C:", NOW, &someone(), AccessTimes::Recorded);
        assert_eq!(listed(&files), vec!["dated.iso"]);
        assert_eq!(summary.undated, 3);
        assert_eq!(summary.undated_bytes, 1_800 * MB);
        assert!(summary.left_out.is_empty(), "{:?}", summary.left_out);

        // Where opens are not recorded that date is not relied on, so its
        // absence stops nothing.
        let (files, summary) = find_as(&index, "C:", NOW, &someone(), AccessTimes::NotRecorded);
        assert_eq!(listed(&files), vec!["no-opened.iso", "dated.iso"]);
        assert_eq!(summary.undated, 2, "no-created and no-dates");
    }

    /// The list is the largest two hundred, and the summary still counts
    /// every file found, so the page can say how many more there are and
    /// what they hold.
    #[test]
    fn the_largest_two_hundred_are_listed_and_the_summary_counts_the_rest() {
        let mut drive = Drive::new();
        let old = days_ago(1_000);
        for number in 0..230_u64 {
            drive.file_dated(
                &format!(r"Users\someone\Pictures\raw\shot-{number:03}.dng"),
                (100 + number) * MB,
                old,
                old,
                old,
            );
        }
        let index = drive.index();

        let (files, summary) = find_as(&index, "C:", NOW, &someone(), AccessTimes::Recorded);
        assert_eq!(files.len(), LISTED);
        assert_eq!(summary.found, 230);
        assert_eq!(files[0].name, "shot-229.dng", "largest first");
        assert_eq!(files[LISTED - 1].name, "shot-030.dng");

        let listed_bytes: u64 = files.iter().map(|file| file.bytes).sum();
        let every: u64 = (0..230_u64).map(|number| (100 + number) * MB).sum();
        assert_eq!(summary.total_bytes, every);
        // What the thirty not listed hold together.
        let rest: u64 = (0..30_u64).map(|number| (100 + number) * MB).sum();
        assert_eq!(summary.total_bytes - listed_bytes, rest);
    }

    #[test]
    fn a_date_from_before_1970_or_in_the_future_is_not_an_old_date() {
        // 1601 plus a day: a number, and not a date anything happened here.
        assert_eq!(seconds(86_400 * 10_000_000), None);
        assert_eq!(seconds(0), None);
        assert_eq!(seconds(days_ago(0)), Some(NOW));

        let mut drive = Drive::new();
        let old = days_ago(700);
        // A clock that was wrong when the file was written.
        let future = (NOW + 90 * 86_400 + FILETIME_EPOCH_OFFSET) * 10_000_000;
        drive.file_dated(
            r"Users\someone\Documents\future.iso",
            300 * MB,
            old,
            future,
            old,
        );
        let (files, summary) =
            find_as(&drive.index(), "C:", NOW, &someone(), AccessTimes::Recorded);
        assert!(files.is_empty());
        assert_eq!(
            summary.undated, 0,
            "it has all its dates, and one is not old"
        );
    }
}
