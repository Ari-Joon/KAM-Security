//! Summaries of a person's scans of a drive, and what grew between two.
//!
//! What a summary holds and what a comparison may say are decided in
//! [`kam_storage::growth`]. This keeps them: one after each scan of a whole
//! drive, for the account that asked, and read back for that account alone.
//!
//! # Only what the person was sent
//!
//! The folders a summary keeps are the ones the scan's answer carries, cut to
//! fit that answer before either is done. So the store never holds anything
//! about the drive that the person who asked was not sent, and what a later
//! comparison tells them was theirs already.

use kam_core::db::ScanSummaryRow;
use kam_core::UserContext;
use kam_ipc::Response;
use kam_storage::growth::{self, Comparison, FolderList, Growth, SummaryHeader, SummaryKept};
use kam_storage::{Scan, ScanMethod};

use crate::dispatch::{fitting, Context};

/// How much of a scan's answer its list of large folders may take, as JSON.
/// The tree beside it is the rest, and is far smaller than this leaves.
const FOLDERS_REPLY_BYTES: usize = kam_ipc::MAX_FRAME_BYTES / 4;

/// How much of a comparison's answer each of its two lists may take.
const CHANGES_REPLY_BYTES: usize = kam_ipc::MAX_FRAME_BYTES / 4;

/// The caller's key for their summaries. Every real caller is identified by
/// SID; an unidentified one (a test, a console run) gets the empty key, which
/// no real caller has, as with the download history.
fn caller(user: &UserContext) -> &str {
    user.sid().unwrap_or("")
}

fn method_name(method: ScanMethod) -> &'static str {
    match method {
        ScanMethod::MasterFileTable => "master_file_table",
        ScanMethod::DirectoryWalk => "directory_walk",
    }
}

fn method_of(name: &str) -> Option<ScanMethod> {
    match name {
        "master_file_table" => Some(ScanMethod::MasterFileTable),
        "directory_walk" => Some(ScanMethod::DirectoryWalk),
        _ => None,
    }
}

/// Keep a summary of a scan of a whole drive for the person who asked, and
/// say on the scan what became of it.
///
/// A scan of anything smaller than a drive carries no folders and is left as
/// it is. The folders are cut to fit the answer first, so that what is kept
/// is exactly what is sent.
pub fn keep_summary(scan: &mut Scan, context: &Context, user: &UserContext) {
    let Some(folders) = scan.folders.take() else {
        return;
    };
    let folders = growth::fit(folders, FOLDERS_REPLY_BYTES, |folder| {
        serde_json::to_vec(folder).map_or(usize::MAX, |written| written.len() + 1)
    });
    let kept = scan
        .root
        .chars()
        .next()
        .filter(char::is_ascii_alphabetic)
        .ok_or_else(|| format!("{} is not on a lettered drive", scan.root))
        .and_then(|letter| {
            let letter = letter.to_ascii_uppercase();
            let written = serde_json::to_string(&folders)
                .map_err(|error| format!("it could not be written down: {error}"))?;
            let row = ScanSummaryRow {
                id: 0,
                taken_at: String::new(),
                drive: format!("{letter}:"),
                serial: kam_storage::volumes::serial_number(letter),
                method: method_name(scan.method).to_owned(),
                total_bytes: scan.total_bytes,
                file_count: scan.file_count,
                folders: written,
            };
            context
                .store
                .record_scan_summary(caller(user), &row)
                .map_err(|error| format!("the store could not keep it: {error}"))
        });
    scan.summary = Some(match kept {
        Ok((id, taken_at)) => SummaryKept::Kept { id, taken_at },
        Err(why) => {
            tracing::warn!(%why, "a summary of a scan could not be kept");
            SummaryKept::NotKept { why }
        }
    });
    scan.folders = Some(folders);
}

fn header(row: &ScanSummaryRow) -> Result<SummaryHeader, String> {
    let method = method_of(&row.method).ok_or_else(|| {
        format!(
            "the summary kept at {} says it was read by \"{}\", which this version does not know",
            row.taken_at, row.method
        )
    })?;
    Ok(SummaryHeader {
        id: row.id,
        taken_at: row.taken_at.clone(),
        drive: row.drive.clone(),
        serial: row.serial,
        method,
        total_bytes: row.total_bytes,
        file_count: row.file_count,
    })
}

/// One of the caller's summaries with its folders, or why it could not be
/// read back. Never an empty list in place of one that would not read.
fn folders_of(
    context: &Context,
    user: &UserContext,
    wanted: &SummaryHeader,
) -> Result<FolderList, String> {
    let unreadable = |why: String| {
        format!(
            "The summary of the scan kept at {} could not be read back: {why}",
            wanted.taken_at
        )
    };
    let row = context
        .store
        .scan_summary(caller(user), wanted.id)
        .map_err(|error| unreadable(error.to_string()))?
        .ok_or_else(|| unreadable("it is no longer kept".to_owned()))?;
    serde_json::from_str(&row.folders).map_err(|error| unreadable(error.to_string()))
}

/// The caller's summaries of a drive, and what grew and shrank between two.
///
/// Only the caller's own: a summary kept for somebody else is not found by
/// its number either, and is answered as one that is not there.
pub fn answer(
    drive: &str,
    later: Option<i64>,
    earlier: Option<i64>,
    context: &Context,
    user: &UserContext,
) -> Response {
    match compare(drive, later, earlier, context, user) {
        Ok(growth) => Response::Growth(Box::new(growth)),
        Err(message) => Response::Error { message },
    }
}

fn compare(
    drive: &str,
    later: Option<i64>,
    earlier: Option<i64>,
    context: &Context,
    user: &UserContext,
) -> Result<Growth, String> {
    let letter = drive
        .chars()
        .next()
        .filter(char::is_ascii_alphabetic)
        .ok_or_else(|| "give a drive letter, such as C:".to_owned())?;
    let drive = format!("{}:", letter.to_ascii_uppercase());

    let rows = context
        .store
        .scan_summaries(caller(user), &drive)
        .map_err(|error| {
            format!("The summaries of earlier scans of {drive} could not be read: {error}")
        })?;
    let summaries = rows.iter().map(header).collect::<Result<Vec<_>, _>>()?;
    // A summary asked for by number is one of the caller's or is not there,
    // whatever else the answer would have been.
    let named = |id: Option<i64>| -> Result<Option<SummaryHeader>, String> {
        let Some(id) = id else {
            return Ok(None);
        };
        summaries
            .iter()
            .find(|summary| summary.id == id)
            .cloned()
            .map(Some)
            .ok_or_else(|| format!("There is no summary {id} of a scan of {drive} kept for you."))
    };
    let earlier = named(earlier)?;
    let later = named(later)?.or_else(|| summaries.first().cloned());
    let Some(later) = later else {
        return Ok(Growth {
            drive,
            summaries,
            later: None,
            earlier: None,
            comparison: Comparison::NothingKept,
        });
    };
    // Newest first, so the first one older than `later` is the one kept just
    // before it.
    let earlier = earlier.or_else(|| {
        summaries
            .iter()
            .find(|summary| summary.id < later.id)
            .cloned()
    });
    let Some(earlier) = earlier else {
        return Ok(Growth {
            drive,
            summaries,
            later: Some(later),
            earlier: None,
            comparison: Comparison::NothingEarlier,
        });
    };

    let comparison = match growth::incomparable(&earlier, &later) {
        // Not even read back: there is nothing to compare.
        Some(why) => Comparison::NotComparable { why },
        None => {
            let before = folders_of(context, user, &earlier)?;
            let after = folders_of(context, user, &later)?;
            match growth::compare((&earlier, &before), (&later, &after)) {
                Comparison::Compared(mut differences) => {
                    let (grew, left) = fitting(differences.grew, CHANGES_REPLY_BYTES);
                    differences.grew = grew;
                    differences.grew_left_out = left.len() as u64;
                    let (shrank, left) = fitting(differences.shrank, CHANGES_REPLY_BYTES);
                    differences.shrank = shrank;
                    differences.shrank_left_out = left.len() as u64;
                    Comparison::Compared(differences)
                }
                other => other,
            }
        }
    };
    Ok(Growth {
        drive,
        summaries,
        later: Some(later),
        earlier: Some(earlier),
        comparison,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use kam_core::{Reporter, Store};
    use kam_ipc::Request;
    use kam_storage::growth::{FolderTotal, FOLDER_FLOOR};
    use kam_storage::scan::Node;

    const GB: u64 = 1024 * 1024 * 1024;
    const MINE: &str = "S-1-5-21-1-2-3-1001";
    const THEIRS: &str = "S-1-5-21-1-2-3-1002";

    /// A context with an empty store, and the scratch folder its quarantine
    /// store was given, to be removed afterwards.
    fn context() -> (Context, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "kam-growth-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0)
        ));
        let context = Context {
            mode: crate::Mode::Console,
            store: Store::open_in_memory().unwrap(),
            jobs: Default::default(),
            quarantine: kam_quarantine::Store::open(&root).unwrap(),
            behaviour: Default::default(),
        };
        (context, root)
    }

    fn person(sid: &str) -> UserContext {
        UserContext::new(Some(sid.to_owned()), r"C:\Users\someone")
    }

    fn folder(path: &str, bytes: u64) -> FolderTotal {
        FolderTotal {
            path: path.to_owned(),
            bytes,
            files: 10,
        }
    }

    /// A scan of all of C:, as the storage crate hands it over.
    fn drive_scan(method: ScanMethod, total: u64, folders: Vec<FolderTotal>) -> Scan {
        Scan {
            root: r"C:\".to_owned(),
            method,
            fallback_reason: None,
            total_bytes: total,
            file_count: 1_000,
            directory_count: 100,
            unreadable: 0,
            elapsed_ms: 2_400,
            tree: Node {
                name: r"C:\".to_owned(),
                path: r"C:\".to_owned(),
                bytes: total,
                files: 0,
                children: Vec::new(),
                is_aggregate: false,
                folded: false,
            },
            largest_files: Vec::new(),
            folders: Some(FolderList {
                floor: FOLDER_FLOOR,
                folders,
                unplaced: 0,
            }),
            summary: None,
        }
    }

    fn kept(scan: &Scan) -> i64 {
        match &scan.summary {
            Some(SummaryKept::Kept { id, .. }) => *id,
            other => panic!("no summary was kept: {other:?}"),
        }
    }

    fn growth_of(response: Response) -> Growth {
        match response {
            Response::Growth(growth) => *growth,
            other => panic!("not an answer about growth: {other:?}"),
        }
    }

    /// A scan of a whole drive leaves a summary for the person who asked,
    /// and what it holds is exactly what the scan sent them.
    #[test]
    fn a_scan_of_a_whole_drive_leaves_a_summary_holding_exactly_what_was_sent() {
        let (context, root) = context();
        let mut scan = drive_scan(
            ScanMethod::MasterFileTable,
            900 * GB,
            vec![
                folder(r"C:\Users", 500 * GB),
                folder(r"C:\Windows", 40 * GB),
            ],
        );
        keep_summary(&mut scan, &context, &person(MINE));

        let id = kept(&scan);
        let row = context.store.scan_summary(MINE, id).unwrap().unwrap();
        let sent = serde_json::to_string(scan.folders.as_ref().unwrap()).unwrap();
        assert_eq!(
            row.folders, sent,
            "the summary holds something that was not sent"
        );
        assert_eq!(
            (row.drive.as_str(), row.method.as_str(), row.total_bytes),
            ("C:", "master_file_table", 900 * GB)
        );
        assert_eq!(
            context.store.scan_summary(THEIRS, id).unwrap(),
            None,
            "somebody else was given this person's summary"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// A scan of something smaller than a drive leaves no summary.
    #[test]
    fn a_scan_of_a_folder_leaves_no_summary() {
        let (context, root) = context();
        let mut scan = drive_scan(ScanMethod::DirectoryWalk, GB, Vec::new());
        scan.folders = None;
        keep_summary(&mut scan, &context, &person(MINE));
        assert_eq!(scan.summary, None);
        assert!(context.store.scan_summaries(MINE, "C:").unwrap().is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    /// Folders that will not fit in the answer are cut before anything is
    /// kept, so what is kept and what is sent are still the same, and the
    /// summary's floor says how far the cut went.
    #[test]
    fn a_list_too_long_for_one_answer_is_cut_before_it_is_kept() {
        let (context, root) = context();
        let deep = "a-folder-with-a-long-name\\".repeat(48);
        let folders: Vec<FolderTotal> = (0..2_000_u64)
            .map(|number| {
                folder(
                    &format!(r"C:\{deep}{number:04}"),
                    200 * GB - number * GB / 100,
                )
            })
            .collect();
        let mut scan = drive_scan(ScanMethod::MasterFileTable, 900 * GB, folders);
        keep_summary(&mut scan, &context, &person(MINE));

        let sent = scan.folders.as_ref().unwrap();
        assert!(sent.floor > FOLDER_FLOOR, "the list was not cut");
        assert!(sent.folders.len() < 2_000);
        let written = serde_json::to_string(sent).unwrap();
        assert!(written.len() <= FOLDERS_REPLY_BYTES + 64);
        let row = context
            .store
            .scan_summary(MINE, kept(&scan))
            .unwrap()
            .unwrap();
        assert!(
            row.folders == written,
            "what was kept ({} bytes) is not what was sent ({} bytes)",
            row.folders.len(),
            written.len()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// Before anything is kept there is nothing; after the first scan there
    /// is nothing earlier; after the second, the two are compared.
    #[test]
    fn the_first_scan_has_nothing_to_compare_with_and_the_second_is_compared_with_it() {
        let (context, root) = context();
        let me = person(MINE);
        let ask = |later: Option<i64>, earlier: Option<i64>| {
            growth_of(answer("c", later, earlier, &context, &me))
        };
        assert_eq!(ask(None, None).comparison, Comparison::NothingKept);

        let mut first = drive_scan(
            ScanMethod::MasterFileTable,
            855 * GB,
            vec![folder(r"C:\Users", 500 * GB)],
        );
        keep_summary(&mut first, &context, &me);
        let growth = ask(None, None);
        assert_eq!(growth.drive, "C:");
        assert_eq!(growth.comparison, Comparison::NothingEarlier);
        assert_eq!(growth.later.map(|later| later.id), Some(kept(&first)));

        let mut second = drive_scan(
            ScanMethod::MasterFileTable,
            994 * GB,
            vec![folder(r"C:\Users", 639 * GB)],
        );
        keep_summary(&mut second, &context, &me);
        let growth = ask(Some(kept(&second)), None);
        assert_eq!(growth.summaries.len(), 2);
        assert_eq!(
            growth.earlier.as_ref().map(|earlier| earlier.id),
            Some(kept(&first))
        );
        let Comparison::Compared(differences) = growth.comparison else {
            panic!("two scans of one drive, read the same way, were not compared");
        };
        assert_eq!(differences.total_change, (139 * GB) as i64);
        assert_eq!(differences.grew.len(), 1);
        assert_eq!(differences.grew[0].by, 139 * GB);

        // Asked about the first, there is nothing before it.
        assert_eq!(
            ask(Some(kept(&first)), None).comparison,
            Comparison::NothingEarlier
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// A walk and a table read are listed, and not compared.
    #[test]
    fn a_walk_is_not_compared_with_a_table_read_and_says_why() {
        let (context, root) = context();
        let me = person(MINE);
        let mut table = drive_scan(ScanMethod::MasterFileTable, 900 * GB, Vec::new());
        keep_summary(&mut table, &context, &me);
        let mut walk = drive_scan(ScanMethod::DirectoryWalk, 950 * GB, Vec::new());
        keep_summary(&mut walk, &context, &me);

        let growth = growth_of(answer("C:", None, None, &context, &me));
        let Comparison::NotComparable { why } = growth.comparison else {
            panic!("a walk was compared with a table read");
        };
        assert!(why.contains("several names"), "{why}");
        let _ = std::fs::remove_dir_all(root);
    }

    /// One person's summaries are never read for another, by number or not.
    #[test]
    fn a_summary_kept_for_somebody_else_is_not_there_for_the_caller() {
        let (context, root) = context();
        let mut theirs = drive_scan(ScanMethod::MasterFileTable, 900 * GB, Vec::new());
        keep_summary(&mut theirs, &context, &person(THEIRS));

        let me = person(MINE);
        let growth = growth_of(answer("C:", None, None, &context, &me));
        assert!(growth.summaries.is_empty());
        assert_eq!(growth.comparison, Comparison::NothingKept);

        for (later, earlier) in [(Some(kept(&theirs)), None), (None, Some(kept(&theirs)))] {
            let Response::Error { message } = answer("C:", later, earlier, &context, &me) else {
                panic!("somebody else's summary was answered for");
            };
            assert!(message.contains("no summary"), "{message}");
        }
        let _ = std::fs::remove_dir_all(root);
    }

    /// A summary that will not read back is said not to, never compared as
    /// though it held no folders.
    #[test]
    fn a_summary_that_cannot_be_read_back_says_so() {
        let (context, root) = context();
        let me = person(MINE);
        let serial = kam_storage::volumes::serial_number('C');
        let damaged = ScanSummaryRow {
            id: 0,
            taken_at: String::new(),
            drive: "C:".to_owned(),
            serial,
            method: "master_file_table".to_owned(),
            total_bytes: 900 * GB,
            file_count: 1,
            folders: "{\"floor\": 104857600, \"folders\": [".to_owned(),
        };
        context.store.record_scan_summary(MINE, &damaged).unwrap();
        let mut scan = drive_scan(ScanMethod::MasterFileTable, 950 * GB, Vec::new());
        keep_summary(&mut scan, &context, &me);

        let Response::Error { message } = answer("C:", None, None, &context, &me) else {
            panic!("a summary that did not read back was compared");
        };
        assert!(message.contains("could not be read back"), "{message}");
        let _ = std::fs::remove_dir_all(root);
    }

    /// The request reaches this through the dispatcher, and anybody may ask
    /// it: it reads nothing but the caller's own notes.
    #[test]
    fn asking_what_grew_is_a_read_anybody_may_make() {
        let (context, root) = context();
        let request = Request::GetGrowth {
            drive: "C:".to_owned(),
            later: None,
            earlier: None,
        };
        assert!(!crate::dispatch::needs_administrator(
            &request,
            &person(MINE)
        ));
        let growth = growth_of(crate::dispatch::handle(
            request,
            &context,
            &Reporter::silent(),
            &person(MINE),
        ));
        assert_eq!(growth.comparison, Comparison::NothingKept);
        assert!(
            context.store.recent_audit(10).unwrap().is_empty(),
            "a read was recorded"
        );

        let Response::Error { message } = answer("", None, None, &context, &person(MINE)) else {
            panic!("a request with no drive was answered");
        };
        assert!(message.contains("drive letter"), "{message}");
        let _ = std::fs::remove_dir_all(root);
    }
}
