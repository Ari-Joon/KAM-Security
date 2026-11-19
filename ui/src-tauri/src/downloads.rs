//! The Downloads page's half that runs in the window's process, as the person.
//!
//! # Watching, without polling
//!
//! One thread waits inside `ReadDirectoryChangesW` on the person's Downloads
//! folder (wherever it has been moved to) and does nothing at all until
//! Windows says something there changed. A second thread waits on a channel
//! for those names; only while a download is still settling does it wake,
//! every two seconds, to look again. A file is taken as finished when its
//! size and time have not moved between two looks two seconds apart and it
//! opens with other writers shut out. Names browsers give a download still in
//! progress are never looked at. A third thread asks the agent to check each
//! finished file, one at a time, and sends a notification the first time a
//! file is recorded.
//!
//! Nothing here moves or deletes anything. A check is a report.
//!
//! # Taking an archive apart
//!
//! [`dissect`] makes a private working copy, quarantines the original when
//! Defender has flagged it (before anything is taken apart, as asked), has the
//! agent check the copy, and lines up Defender's answer with the archive's own
//! list. [`extract`] writes out only what Defender found nothing in, when the
//! person says so, and deletes the working copy.
//!
//! # Everything not checked yet, at one press
//!
//! Files that were in Downloads before this program first ran, or that
//! arrived while it was closed, are listed as not checked and are only ever
//! checked when somebody asks. [`check_backlog`] is one press for all of
//! them: a thread of its own asks the agent about each in turn, exactly as
//! "Check now" does, and keeps what came of it for the page to say. It lives
//! here and not in the page so that leaving the page, or closing the window,
//! does not lose it. See [`work_through`] for its rules.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use kam_core::Progress;
use kam_ipc::{Request, Response};
use kam_scanner::defender_file::{Answer, Counted};
use kam_scanner::downloads::{Dissection, DownloadRecord, Extraction, OriginalFate};
use kam_storage::downloads::{archive_kind, is_partial, ArchiveKind};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};

use crate::context_menu::{Launch, MenuState};

/// How long a file's size has to hold still before it counts as arrived.
const SETTLE: Duration = Duration::from_secs(2);

/// The event the page listens for to reload.
pub const CHANGED_EVENT: &str = "downloads://changed";

/// The event that brings the window to the Downloads page.
pub const LAUNCH_EVENT: &str = "kam://launch";

/// What the watcher is doing, for the page to say.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum WatchStatus {
    Starting,
    Watching { folder: String },
    NotWatching { reason: String },
}

/// A file's size and when it was last written: enough to tell that it is the
/// file that was looked at before.
type FileStamp = (u64, Option<SystemTime>);

/// An archive taken apart and waiting for the person to decide.
///
/// It holds the private copy, and letting it go deletes that copy. So an
/// archive is open for exactly as long as something holds this: the slot in
/// [`Downloads`], and an extraction for as long as it runs.
#[derive(Debug)]
struct Session {
    copy: crate::archive::WorkingCopy,
    name: String,
    sha256: String,
    zone: Option<Vec<u8>>,
    view: DissectionView,
    /// Set while it is being extracted from, so a second press of the button
    /// does not start a second extraction beside the first.
    extracting: AtomicBool,
}

/// Everything the Downloads half keeps between calls.
pub struct Downloads {
    watch: Mutex<WatchStatus>,
    /// Why an automatic check of a file did not happen, by path.
    failures: Mutex<HashMap<String, String>>,
    /// Files somebody asked about from outside the window, waiting for the
    /// page to pick them up, in the order they were asked.
    pending: Mutex<VecDeque<Launch>>,
    /// What each zip's own list said, by path, with the size and time the
    /// file had when it was read.
    looks: Mutex<HashMap<String, (FileStamp, crate::archive::Inside)>>,
    /// The archive that is open, if one is. One at a time: taking another
    /// apart closes it, and so does closing the window.
    open: Mutex<Option<Arc<Session>>>,
    /// Jobs somebody asked to stop while the work was this program's own and
    /// not yet the agent's: copying an archive, or quarantining its original.
    stopped: Mutex<HashSet<String>>,
    /// Where each arriving file has got to. Shared with the watcher's
    /// threads, which write it.
    board: Arc<Mutex<Board>>,
    /// The check of everything not checked yet: the one that is running, or
    /// the last one, kept until the page has said what it came to.
    backlog: Mutex<Option<Backlog>>,
}

impl Default for Downloads {
    fn default() -> Self {
        Self {
            watch: Mutex::new(WatchStatus::Starting),
            failures: Mutex::new(HashMap::new()),
            pending: Mutex::new(VecDeque::new()),
            looks: Mutex::new(HashMap::new()),
            open: Mutex::new(None),
            stopped: Mutex::new(HashSet::new()),
            board: Arc::new(Mutex::new(Board::default())),
            backlog: Mutex::new(None),
        }
    }
}

impl Downloads {
    fn set_watch(&self, status: WatchStatus) {
        if let Ok(mut watch) = self.watch.lock() {
            *watch = status;
        }
    }

    /// Close whatever archive is open, deleting its private copy.
    ///
    /// Called when the window is closed. Closing destroys the window, so the
    /// page's own clean-up never runs, and a complete copy of an archive
    /// Defender had flagged used to stay in the work folder until the program
    /// was next started. It starts at sign-in and lives in the notification
    /// area, so that could be days.
    pub fn close_all(&self) {
        if let Ok(mut open) = self.open.lock() {
            *open = None;
        }
    }

    /// Close one archive, if it is the one that is open.
    fn close(&self, token: &str) {
        if let Ok(mut open) = self.open.lock() {
            if open
                .as_ref()
                .is_some_and(|session| session.view.token == token)
            {
                *open = None;
            }
        }
    }

    /// Open an archive, closing any that was open before.
    fn open(&self, session: Session) {
        if let Ok(mut open) = self.open.lock() {
            *open = Some(Arc::new(session));
        }
    }

    /// The open archive, when `token` names it.
    fn session(&self, token: &str) -> Option<Arc<Session>> {
        self.open
            .lock()
            .ok()?
            .as_ref()
            .filter(|session| session.view.token == token)
            .cloned()
    }

    /// What the page draws for the open archive, when `token` names it.
    pub fn view(&self, token: &str) -> Option<DissectionView> {
        self.session(token).map(|session| session.view.clone())
    }

    /// Ask for a job to stop. See [`Downloads::stopped`].
    pub fn stop(&self, job: &str) {
        if let Ok(mut stopped) = self.stopped.lock() {
            stopped.insert(job.to_owned());
        }
    }

    fn is_stopped(&self, job: &str) -> bool {
        self.stopped
            .lock()
            .is_ok_and(|stopped| stopped.contains(job))
    }

    fn forget_stop(&self, job: &str) {
        if let Ok(mut stopped) = self.stopped.lock() {
            stopped.remove(job);
        }
    }

    /// Forget why an automatic check of a file did not happen, once a check
    /// of it has. The note used to stay until a later automatic check
    /// succeeded, and could reappear under a file checked by hand long since.
    pub fn forget_failure(&self, path: &str) {
        if let Ok(mut failures) = self.failures.lock() {
            failures.retain(|noted, _| !noted.eq_ignore_ascii_case(path));
        }
    }

    /// Say under a file why it was not checked, until a check of it happens.
    fn note_failure(&self, path: &str, message: String) {
        if let Ok(mut failures) = self.failures.lock() {
            failures.insert(path.to_owned(), message);
        }
    }

    /// The check of everything not checked yet, as it stands.
    fn backlog(&self) -> Option<Backlog> {
        self.backlog.lock().ok().and_then(|backlog| backlog.clone())
    }

    /// How far it has got, without what it has come to.
    fn backlog_step(&self) -> Option<BacklogStep> {
        let slot = self.backlog.lock().ok()?;
        slot.as_ref().map(|backlog| BacklogStep {
            job: backlog.job.clone(),
            done: backlog.done,
            total: backlog.total,
            current: backlog.current.clone(),
            progress: backlog.progress.clone(),
        })
    }

    /// Change the run named `job`, if it is still the one on record.
    fn in_backlog(&self, job: &str, change: impl FnOnce(&mut Backlog)) {
        if let Ok(mut slot) = self.backlog.lock() {
            if let Some(backlog) = slot.as_mut().filter(|backlog| backlog.job == job) {
                change(backlog);
            }
        }
    }

    /// Take the one place there is for such a run, under a new name.
    ///
    /// Refused while one is running: a second press would otherwise start a
    /// second run through the same files beside the first. A run that has
    /// ended gives its place up, and with it what it came to.
    fn begin_backlog(&self) -> Result<String, String> {
        static RUNS: AtomicU64 = AtomicU64::new(0);
        let mut slot = self
            .backlog
            .lock()
            .map_err(|_| "the list of files to check could not be kept".to_owned())?;
        if slot.as_ref().is_some_and(|backlog| backlog.ended.is_none()) {
            return Err("Everything not checked yet is already being checked.".to_owned());
        }
        let job = format!(
            "backlog-{}-{}",
            std::process::id(),
            RUNS.fetch_add(1, Ordering::SeqCst)
        );
        *slot = Some(Backlog::new(&job));
        Ok(job)
    }

    /// Ask the run in hand to stop, and say which of the agent's jobs is the
    /// check it has in hand, if it has one. `None` when nothing is running.
    ///
    /// The run is this program's own work and is told here. The check of the
    /// file in hand is the agent's, and whoever calls this tells the agent.
    fn ask_backlog_to_stop(&self) -> Option<Option<String>> {
        let (job, in_hand) = self.backlog.lock().ok().and_then(|slot| {
            slot.as_ref()
                .filter(|backlog| backlog.ended.is_none())
                .map(|backlog| (backlog.job.clone(), backlog.current_job.clone()))
        })?;
        self.stop(&job);
        Some(in_hand)
    }

    /// Let go of a run that has ended, once the page has said what it came
    /// to. One that is still running is left alone.
    pub fn close_backlog(&self) {
        if let Ok(mut slot) = self.backlog.lock() {
            if slot.as_ref().is_some_and(|backlog| backlog.ended.is_some()) {
                *slot = None;
            }
        }
    }

    /// Where a file has got to on its way to being checked, if the watcher
    /// has it. An empty name with a partial download beside it is still
    /// arriving whether or not the watcher saw it start.
    fn in_flight(&self, path: &Path) -> Option<InFlight> {
        self.board
            .lock()
            .ok()
            .and_then(|board| board.state_of(path))
            .or_else(|| kam_storage::downloads::is_placeholder(path).then_some(InFlight::Arriving))
    }

    /// What a zip's own list says about how much of it Defender could look
    /// inside, read once for each state of the file and remembered.
    fn inside(&self, path: &str, metadata: &std::fs::Metadata) -> crate::archive::Inside {
        let key = path.to_ascii_lowercase();
        let stamp = (metadata.len(), metadata.modified().ok());
        if let Ok(looks) = self.looks.lock() {
            if let Some((seen, inside)) = looks.get(&key) {
                if *seen == stamp {
                    return inside.clone();
                }
            }
        }
        let inside = crate::archive::look_inside(Path::new(path));
        if let Ok(mut looks) = self.looks.lock() {
            looks.insert(key, (stamp, inside.clone()));
        }
        inside
    }

    /// Remember a file somebody asked about from outside the window.
    ///
    /// Each one waits its turn. There was room for one, and each new request
    /// replaced the last: with several files selected in Explorer, Windows
    /// starts this program once for each, and all but one were dropped
    /// without a word.
    pub fn set_launch(&self, launch: Launch) {
        if let Ok(mut pending) = self.pending.lock() {
            if !pending.contains(&launch) {
                pending.push_back(launch);
            }
        }
    }

    /// The next waiting request, once.
    ///
    /// `archive_free` says whether the page can open an archive now. While
    /// one is open, a request to take another apart stays where it is: only
    /// one can be open, and replacing it would quarantine the next archive's
    /// original while nobody was looking at it.
    pub fn take_launch(&self, archive_free: bool) -> Option<Launch> {
        let mut pending = self.pending.lock().ok()?;
        if !archive_free && pending.front().is_some_and(|next| next.action == "extract") {
            return None;
        }
        pending.pop_front()
    }

    /// How many requests are waiting.
    pub fn launches_waiting(&self) -> usize {
        self.pending.lock().map_or(0, |pending| pending.len())
    }

    /// Whether a request is waiting, without taking it.
    pub fn has_launch(&self) -> bool {
        self.launches_waiting() > 0
    }
}

/// The person's Downloads folder, from Windows' own record of it.
pub fn known_folder() -> Result<PathBuf, String> {
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{FOLDERID_Downloads, SHGetKnownFolderPath, KF_FLAG_DEFAULT};
    unsafe {
        let raw =
            SHGetKnownFolderPath(&FOLDERID_Downloads, KF_FLAG_DEFAULT, None).map_err(|error| {
                format!("Windows did not say where your Downloads folder is: {error}")
            })?;
        let text = raw.to_string();
        CoTaskMemFree(Some(raw.0 as _));
        text.map(PathBuf::from)
            .map_err(|error| format!("your Downloads folder's name could not be read: {error}"))
    }
}

/// When a file was created, as the store writes times.
fn created_iso(metadata: &std::fs::Metadata) -> Option<String> {
    metadata
        .created()
        .ok()
        .and_then(|created| created.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|since| kam_core::clock::iso_from_unix_millis(since.as_millis() as u64))
}

fn archive_label(name: &str) -> Option<&'static str> {
    match archive_kind(name)? {
        ArchiveKind::Zip => Some("zip"),
        ArchiveKind::Other => Some("other"),
    }
}

/// A checked download, with what the page needs to draw its buttons.
#[derive(Debug, Serialize)]
pub struct PageRecord {
    #[serde(flatten)]
    record: DownloadRecord,
    /// Whether the file is still where it was checked.
    present: bool,
    archive: Option<&'static str>,
    /// The quarantine item this file can be put back from, when it is not
    /// where it was because it is being held there. This is what stops a row
    /// being a dead end: a file quarantined from here, or by taking it apart,
    /// can always be put back from its own row.
    held: Option<String>,
    /// A file is at that path, and it is not the one this row is about.
    replaced: bool,
    /// Whether it is in the Downloads folder, which is the only place a
    /// download can be quarantined from here. Elsewhere the button could
    /// only ever be refused, so it is not offered.
    in_downloads: bool,
    /// For a zip Defender found nothing in: what its own list says about how
    /// much of it Defender could look inside.
    inside: Option<crate::archive::Inside>,
    /// Whether this is a result a person is told about, and as which kind:
    /// flagged, or a check that did not finish. The agent counts by the same
    /// rule, so the page and the count beside its name cannot disagree.
    counted_as: Option<Counted>,
}

/// The archive that is open, for a page that has just been drawn again.
#[derive(Debug, Serialize)]
pub struct OpenArchive {
    token: String,
    archive: String,
}

/// A file in Downloads with no check on record yet.
#[derive(Debug, Serialize)]
pub struct LooseFile {
    path: String,
    name: String,
    bytes: u64,
    arrived_at: Option<String>,
    archive: Option<&'static str>,
    /// True when a check of this name is on record but the file has changed
    /// size since, so that check is not about this file.
    changed_since_checked: bool,
    /// Where it has got to, when it is on its way to being checked and not
    /// simply unchecked.
    in_flight: Option<InFlight>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Failure {
    path: String,
    message: String,
}

/// Everything the page draws, in one answer.
#[derive(Debug, Serialize)]
pub struct Page {
    folder: Option<String>,
    folder_error: Option<String>,
    watch: WatchStatus,
    records: Vec<PageRecord>,
    /// How many checks are on record in all, which can be more than
    /// `records` holds: the page says so when it is.
    on_record: u64,
    /// When the history was asked for. "Clear the list" removes what was on
    /// record by then, so that a check recorded while the person is reading
    /// the question is not removed before they have been shown it.
    read_at: String,
    history_error: Option<String>,
    unchecked: Vec<LooseFile>,
    failures: Vec<Failure>,
    /// The archive that was taken apart and is still open, so that leaving
    /// the page and coming back finds it again.
    open: Option<OpenArchive>,
    /// Why it could not be told which quarantined downloads can be put back.
    quarantine_error: Option<String>,
    /// How many files asked about from Explorer are still waiting their turn.
    waiting: usize,
    menu: MenuState,
    protection: Option<bool>,
    /// Why notices about new downloads will not be seen, when Windows says
    /// they will not, or cannot say.
    notifications: Option<String>,
    /// The check of everything not checked yet, while it runs and until what
    /// it came to has been closed, so that a page drawn again finds it.
    backlog: Option<Backlog>,
}

/// How many of the most recent checks the page asks for. The agent has its
/// own cap, and the page says when there are more on record than it shows.
const RECENT_ROWS: u32 = 1000;

/// The newest row on record for each of `paths`, and the `recent` most
/// recently checked, with how many rows there are in all.
fn history(paths: Vec<String>, recent: u32) -> Result<(Vec<DownloadRecord>, u64), String> {
    match kam_ipc::client::call(&Request::ListDownloads { paths, recent }) {
        Ok(Response::Downloads { records, on_record }) => Ok((records, on_record)),
        Ok(Response::Error { message }) => Err(message),
        Ok(other) => Err(format!(
            "the agent answered something unexpected: {other:?}"
        )),
        Err(error) => Err(error.to_string()),
    }
}

/// One file directly inside Downloads: its path, its name, and what the
/// folder's own listing says of it.
type Present = (String, String, std::fs::Metadata);

/// The files directly inside `folder`, leaving out the names a browser gives
/// a download still in progress.
fn files_in(folder: &Path) -> Result<Vec<Present>, String> {
    let listing = std::fs::read_dir(folder)
        .map_err(|error| format!("your Downloads folder could not be read: {error}"))?;
    let mut present = Vec::new();
    for item in listing.flatten() {
        let Ok(metadata) = item.metadata() else {
            continue;
        };
        let name = item.file_name().to_string_lossy().into_owned();
        if metadata.is_file() && !is_partial(&name) {
            present.push((item.path().to_string_lossy().into_owned(), name, metadata));
        }
    }
    Ok(present)
}

/// The files among `present` with no check on record that is about them as
/// they are now, most recently arrived first. One on its way to being checked
/// is among them, and says where it has got to.
fn not_checked(
    state: &Downloads,
    present: Vec<Present>,
    records: &[DownloadRecord],
) -> Vec<LooseFile> {
    let mut unchecked = Vec::new();
    for (path, name, metadata) in present {
        // A row for a file that was gone before it could be checked is not a
        // check of whatever is there under that name now.
        let latest = records.iter().find(|record| {
            record.check.scan.answer != Answer::GoneBeforeCheck
                && record.check.path.eq_ignore_ascii_case(&path)
        });
        let in_flight = state.in_flight(Path::new(&path));
        if in_flight.is_none() && latest.is_some_and(|record| still_the_file(record, &metadata)) {
            continue;
        }
        unchecked.push(LooseFile {
            archive: archive_label(&name),
            arrived_at: created_iso(&metadata),
            bytes: metadata.len(),
            changed_since_checked: latest.is_some(),
            in_flight,
            name,
            path,
        });
    }
    unchecked.sort_by(|a, b| b.arrived_at.cmp(&a.arrived_at));
    unchecked
}

/// Gather the page: the folder as it is now, and the history from the agent.
pub fn page(state: &Downloads) -> Page {
    let folder = known_folder();
    let (present, folder_error) = match folder.as_deref().map(files_in) {
        Ok(Ok(present)) => (present, None),
        Ok(Err(error)) => (Vec::new(), Some(error)),
        Err(_) => (Vec::new(), None),
    };

    // The files in the folder are named in the request, so each one's row
    // comes back however long ago it was checked. Asked for only by recency,
    // a file checked before the newest thousand read as never checked.
    let named = present.iter().map(|(path, _, _)| path.clone()).collect();
    // Taken before asking, so that nothing recorded later can be older.
    let read_at = kam_core::clock::now_utc_iso();
    let (records, on_record, history_error) = match history(named, RECENT_ROWS) {
        Ok((records, on_record)) => (records, on_record, None),
        Err(reason) => (Vec::new(), 0, Some(reason)),
    };
    let protection = match kam_ipc::client::call(&Request::GetProtection) {
        Ok(Response::Protection { enabled }) => Some(enabled),
        _ => None,
    };

    let unchecked = not_checked(state, present, &records);

    // What is being held in quarantine, asked for only when a row could be
    // about one of them. A failure to read it is said, not taken for "none".
    let quarantined = records
        .iter()
        .any(|record| record.actions.iter().any(|action| action.undo.is_some()));
    let (held, quarantine_error) = if quarantined {
        match kam_ipc::client::call(&Request::ListQuarantine) {
            Ok(Response::QuarantineList { items }) => (items, None),
            Ok(Response::Error { message }) => (Vec::new(), Some(message)),
            Ok(other) => (
                Vec::new(),
                Some(format!(
                    "the agent answered something unexpected: {other:?}"
                )),
            ),
            Err(error) => (Vec::new(), Some(error.to_string())),
        }
    } else {
        (Vec::new(), None)
    };

    let downloads_folder = folder.as_ref().ok().cloned();
    // Rows come newest first, so the first one seen for a path is the newest.
    let mut newest: HashSet<String> = HashSet::new();
    let records = records
        .into_iter()
        .map(|record| {
            let path = Path::new(&record.check.path);
            let metadata = std::fs::metadata(path).ok().filter(|found| found.is_file());
            // The row's buttons act on the file at its path, so they are only
            // offered when that file is the one the row is about: the newest
            // row for the path, with the size it was checked at, not written
            // to since. A row counted as "still there" by its path alone, and
            // an old row then offered to quarantine whatever had replaced it.
            // A file that went before it could be checked is not there,
            // whatever has since been saved under its name.
            let is_newest = newest.insert(record.check.path.to_ascii_lowercase());
            let present = record.check.scan.answer != Answer::GoneBeforeCheck
                && is_newest
                && metadata
                    .as_ref()
                    .is_some_and(|found| still_the_file(&record, found));
            let archive = archive_label(&record.check.name);
            PageRecord {
                held: (!present).then(|| held_as(&record, &held)).flatten(),
                replaced: !present && metadata.is_some(),
                in_downloads: downloads_folder
                    .as_deref()
                    .is_some_and(|folder| kam_storage::downloads::lies_within(path, folder)),
                // Only where the answer could be read as "nothing in it":
                // which of a zip's files Defender could not look inside.
                inside: (present
                    && archive == Some("zip")
                    && record.check.scan.answer == Answer::NothingFound)
                    .then(|| {
                        metadata
                            .as_ref()
                            .map(|found| state.inside(&record.check.path, found))
                    })
                    .flatten(),
                counted_as: record.check.scan.counted_as(),
                present,
                archive,
                record,
            }
        })
        .collect();
    let open = state.open.lock().ok().and_then(|open| {
        open.as_ref().map(|session| OpenArchive {
            token: session.view.token.clone(),
            archive: session.view.dissection.archive.clone(),
        })
    });
    let failures = state
        .failures
        .lock()
        .map(|failures| {
            failures
                .iter()
                .map(|(path, message)| Failure {
                    path: path.clone(),
                    message: message.clone(),
                })
                .collect()
        })
        .unwrap_or_default();

    Page {
        folder: folder
            .as_ref()
            .ok()
            .map(|folder| folder.to_string_lossy().into_owned()),
        folder_error: folder.err().or(folder_error),
        watch: state
            .watch
            .lock()
            .map(|watch| watch.clone())
            .unwrap_or(WatchStatus::Starting),
        records,
        on_record,
        read_at,
        history_error,
        unchecked,
        failures,
        open,
        quarantine_error,
        waiting: state.launches_waiting(),
        menu: crate::context_menu::state(),
        protection,
        notifications: crate::notice::delivery_problem(),
        backlog: state.backlog(),
    }
}

/// Whether the file at a row's path is still the file that row is about: the
/// size it was checked at, and not written to since.
///
/// Size alone let an edit that kept the size pass for the file that was
/// checked. A time of writing later than now says nothing, and is not taken
/// to mean the file changed, or such a file could never read as checked.
fn still_the_file(record: &DownloadRecord, metadata: &std::fs::Metadata) -> bool {
    let written = metadata
        .modified()
        .ok()
        .and_then(|at| at.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|since| kam_core::clock::iso_from_unix_millis(since.as_millis() as u64));
    let written_since = written.is_some_and(|written| {
        written.as_str() > record.checked_at.as_str() && written <= kam_core::clock::now_utc_iso()
    });
    metadata.len() == record.check.bytes && !written_since
}

/// The quarantine item a download that is no longer where it was can be put
/// back from: the newest one its row names that is still held, and that came
/// from that very path.
fn held_as(record: &DownloadRecord, held: &[kam_quarantine::Manifest]) -> Option<String> {
    record
        .actions
        .iter()
        .rev()
        .filter_map(|action| action.undo.as_deref())
        .find(|id| {
            held.iter().any(|item| {
                item.id == *id
                    && !item.restored
                    && item.original_path.eq_ignore_ascii_case(&record.check.path)
            })
        })
        .map(str::to_owned)
}

// --- watching ----------------------------------------------------------

/// What the folder watcher passes on.
enum Seen {
    /// A name appeared. `renamed` when it was renamed into place, which is
    /// how a browser finishes a download and never how it starts one.
    Arrived { path: PathBuf, renamed: bool },
    /// A name already there was written to.
    Changed(PathBuf),
    /// A name was given another name in the folder. The file is still
    /// there, and arrives again under the new one.
    Renamed(PathBuf),
    /// Windows lost count of what changed; look at everything recent.
    Overflowed,
}

/// What the settling thread hands on, to be dealt with one at a time.
#[derive(Debug, PartialEq, Eq)]
enum Arrival {
    /// It has stopped changing and nobody is still writing it: check it.
    Settled(Sighting),
    /// It arrived and was gone before it could be checked.
    Vanished(Sighting),
}

/// One file as it was last seen while arriving.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sighting {
    path: PathBuf,
    bytes: u64,
    arrived_at: Option<String>,
}

/// Where each file the watcher knows about has got to, so that the page can
/// say "being checked now" where it used to say "Not checked yet" for as long
/// as the check took.
#[derive(Debug, Default)]
pub struct Board {
    /// Seen arriving, and not yet still.
    arriving: HashSet<PathBuf>,
    /// Arrived, and waiting their turn, in order.
    waiting: Vec<PathBuf>,
    /// The one being checked now.
    checking: Option<Checking>,
}

#[derive(Debug)]
struct Checking {
    path: PathBuf,
    job: String,
    since: Instant,
}

/// Where one file has got to on its way to being checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum InFlight {
    /// Still arriving: changing, held open by whatever is writing it, or an
    /// empty name waiting to be filled in.
    Arriving,
    /// Arrived, and waiting behind this many others.
    Waiting { ahead: usize },
    /// Being checked now, under this job, for this long so far.
    Checking { job: String, seconds: u64 },
}

impl Board {
    fn state_of(&self, path: &Path) -> Option<InFlight> {
        let same = |other: &PathBuf| {
            other
                .to_string_lossy()
                .eq_ignore_ascii_case(&path.to_string_lossy())
        };
        if let Some(checking) = self.checking.as_ref().filter(|now| same(&now.path)) {
            return Some(InFlight::Checking {
                job: checking.job.clone(),
                seconds: checking.since.elapsed().as_secs(),
            });
        }
        if let Some(position) = self.waiting.iter().position(same) {
            return Some(InFlight::Waiting {
                ahead: position + usize::from(self.checking.is_some()),
            });
        }
        self.arriving.iter().any(same).then_some(InFlight::Arriving)
    }
}

/// The event that carries the progress of an automatic check to the page.
pub const PROGRESS_EVENT: &str = "downloads://progress";

/// How far an automatic check has got, for the row it is about.
#[derive(Debug, Clone, Serialize)]
struct ArrivalProgress {
    path: String,
    job: String,
    progress: Progress,
}

/// How long one automatic check may keep other downloads waiting behind it.
///
/// Checks of arriving files run one at a time, and Defender is given up to
/// four hours on one file before it is given up on, so one file it stalled
/// on held every later download unchecked for as long. Past this, and only
/// while something is waiting, the check is stopped and says so; the file
/// can still be checked from the page, where a check runs until it finishes
/// or is stopped. With nothing waiting it holds nobody up and is left to run.
const ARRIVAL_PATIENCE: Duration = Duration::from_secs(10 * 60);

/// Start watching the Downloads folder. Returns at once; the work happens on
/// threads of its own and never on the window's.
pub fn start_watching(app: AppHandle) {
    let (seen_tx, seen_rx) = mpsc::channel::<Seen>();
    let (ready_tx, ready_rx) = mpsc::channel::<Arrival>();

    let watcher_app = app.clone();
    let spawned = std::thread::Builder::new()
        .name("kam-downloads-watch".to_owned())
        .spawn(move || watch(&watcher_app, &seen_tx));
    if let Err(error) = spawned {
        app.state::<Downloads>()
            .set_watch(WatchStatus::NotWatching {
                reason: format!("the watcher could not be started: {error}"),
            });
        return;
    }
    let board = Arc::clone(&app.state::<Downloads>().board);
    let settle_app = app.clone();
    let _ = std::thread::Builder::new()
        .name("kam-downloads-settle".to_owned())
        .spawn(move || {
            settle(&seen_rx, &ready_tx, &board, &|| {
                let _ = settle_app.emit(CHANGED_EVENT, ());
            })
        });
    let _ = std::thread::Builder::new()
        .name("kam-downloads-check".to_owned())
        .spawn(move || check_arrivals(&app, &ready_rx));
}

/// Wait on the folder for as long as the program runs.
fn watch(app: &AppHandle, seen: &Sender<Seen>) {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, ReadDirectoryChangesW, FILE_FLAG_BACKUP_SEMANTICS, FILE_LIST_DIRECTORY,
        FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let state = app.state::<Downloads>();
    let folder = match known_folder() {
        Ok(folder) => folder,
        Err(reason) => {
            state.set_watch(WatchStatus::NotWatching { reason });
            return;
        }
    };
    let handle = unsafe {
        CreateFileW(
            &HSTRING::from(folder.as_os_str()),
            FILE_LIST_DIRECTORY.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    };
    let handle = match handle {
        Ok(handle) => handle,
        Err(error) => {
            state.set_watch(WatchStatus::NotWatching {
                reason: format!("{} could not be watched: {error}", folder.display()),
            });
            return;
        }
    };
    state.set_watch(WatchStatus::Watching {
        folder: folder.to_string_lossy().into_owned(),
    });

    // DWORD-aligned, as Windows requires, and large enough for a burst.
    let mut buffer = vec![0_u32; 16 * 1024];
    loop {
        let mut returned = 0_u32;
        let outcome = unsafe {
            ReadDirectoryChangesW(
                handle,
                buffer.as_mut_ptr().cast(),
                (buffer.len() * 4) as u32,
                false,
                FILE_NOTIFY_CHANGE_FILE_NAME
                    | FILE_NOTIFY_CHANGE_SIZE
                    | FILE_NOTIFY_CHANGE_LAST_WRITE,
                Some(&mut returned),
                None,
                None,
            )
        };
        if let Err(error) = outcome {
            state.set_watch(WatchStatus::NotWatching {
                reason: format!("watching {} stopped: {error}", folder.display()),
            });
            let _ = app.emit(CHANGED_EVENT, ());
            break;
        }
        let bytes: Vec<u8> = buffer
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .take(returned as usize)
            .collect();
        let events = if returned == 0 {
            vec![Seen::Overflowed]
        } else {
            parse_notifications(&bytes, &folder)
        };
        for event in events {
            if seen.send(event).is_err() {
                break;
            }
        }
    }
    unsafe {
        let _ = CloseHandle(handle);
    }
}

/// Read `FILE_NOTIFY_INFORMATION` records from what Windows wrote, by their
/// documented layout, without trusting any offset to stay in bounds.
fn parse_notifications(bytes: &[u8], folder: &Path) -> Vec<Seen> {
    let word = |at: usize| -> Option<u32> {
        bytes
            .get(at..at + 4)
            .map(|four| u32::from_le_bytes([four[0], four[1], four[2], four[3]]))
    };
    let mut events = Vec::new();
    let mut offset = 0_usize;
    while let (Some(next), Some(action), Some(length)) =
        (word(offset), word(offset + 4), word(offset + 8))
    {
        let start = offset + 12;
        let Some(raw) = bytes.get(start..start + length as usize) else {
            break;
        };
        let units: Vec<u16> = raw
            .chunks(2)
            .filter_map(|pair| Some(u16::from_le_bytes([pair[0], *pair.get(1)?])))
            .collect();
        let name = String::from_utf16_lossy(&units);
        // Top level only: a name with a separator is inside a subfolder.
        if !name.is_empty() && !name.contains('\\') && !is_partial(&name) {
            let path = folder.join(&name);
            match action {
                // Added, or renamed into this name.
                1 | 5 => events.push(Seen::Arrived {
                    path,
                    renamed: action == 5,
                }),
                3 => events.push(Seen::Changed(path)),
                // Renamed away from this name. Removal (2) is not passed on:
                // the next look finds the file gone, and waits a moment
                // before believing it.
                4 => events.push(Seen::Renamed(path)),
                _ => {}
            }
        }
        if next == 0 {
            break;
        }
        offset += next as usize;
    }
    events
}

/// A file seen arriving, not yet known to have finished.
struct Settling {
    size: Option<u64>,
    written: Option<SystemTime>,
    looked: Instant,
    /// Whether it was ever a download and not just a name: it has been seen
    /// holding something, or it was renamed into place. Only such a file is
    /// recorded as gone if it goes; an empty name that comes and goes is not.
    was_something: bool,
    /// The most it has been seen to hold, and when it was created, for the
    /// record of it should it go before it can be checked.
    bytes: u64,
    arrived_at: Option<String>,
    /// When it was first found missing. A program that saves by deleting and
    /// renaming has the name missing for a moment, so it is looked for once
    /// more before it is called gone.
    missing: Option<Instant>,
}

impl Settling {
    /// Not looked at yet: the first look only records the size.
    fn fresh() -> Self {
        Self {
            size: None,
            written: None,
            looked: Instant::now()
                .checked_sub(SETTLE)
                .unwrap_or_else(Instant::now),
            was_something: false,
            bytes: 0,
            arrived_at: None,
            missing: None,
        }
    }

    /// Start settling again, keeping what is already known of the file.
    fn again(&mut self) {
        let fresh = Self::fresh();
        self.size = fresh.size;
        self.written = fresh.written;
        self.looked = fresh.looked;
        self.missing = None;
    }

    fn sighting(&self, path: &Path) -> Sighting {
        Sighting {
            path: path.to_path_buf(),
            bytes: self.bytes,
            arrived_at: self.arrived_at.clone(),
        }
    }
}

/// Hold each arriving file until it stops changing, then pass it on.
///
/// Waits on the channel with no timeout while nothing is settling, so it
/// costs nothing when nothing is arriving.
///
/// Two things are not passed on as arrived. An empty name with a partial
/// download of the same name beside it is a placeholder (see
/// `kam_storage::downloads::is_placeholder`): it waits, without being looked
/// at, until Windows says it changed. And a file that goes before it has
/// settled is passed on as gone, if it ever held anything, so that a
/// download Defender takes away as it lands leaves a record.
///
/// `board` is told where each file has got to, and `changed` is called when
/// that moves, so the page can say so.
fn settle(
    seen: &Receiver<Seen>,
    ready: &Sender<Arrival>,
    board: &Mutex<Board>,
    changed: &dyn Fn(),
) {
    let mut settling: HashMap<PathBuf, Settling> = HashMap::new();
    let mut placeholders: HashSet<PathBuf> = HashSet::new();
    loop {
        let event = if settling.is_empty() {
            seen.recv().map_err(|_| RecvTimeoutError::Disconnected)
        } else {
            seen.recv_timeout(SETTLE / 2)
        };
        match event {
            Ok(Seen::Arrived { path, renamed }) => {
                placeholders.remove(&path);
                let entry = settling.entry(path).or_insert_with(Settling::fresh);
                entry.again();
                entry.was_something |= renamed;
            }
            Ok(Seen::Changed(path)) => {
                if let Some(entry) = settling.get_mut(&path) {
                    entry.again();
                } else if placeholders.remove(&path) {
                    settling.insert(path, Settling::fresh());
                }
            }
            Ok(Seen::Renamed(path)) => {
                settling.remove(&path);
                placeholders.remove(&path);
            }
            Ok(Seen::Overflowed) => {
                for path in recent_files(Duration::from_secs(600)) {
                    settling.entry(path).or_insert_with(Settling::fresh);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }

        // A placeholder that has since been filled in, or whose partial
        // download has gone, settles like any other file. One that is gone
        // itself is forgotten.
        let mut filled = Vec::new();
        placeholders.retain(|path| {
            let still = kam_storage::downloads::is_placeholder(path);
            if !still && path.is_file() {
                filled.push(path.clone());
            }
            still
        });
        for path in filled {
            settling.entry(path).or_insert_with(Settling::fresh);
        }

        let mut passed_on: Vec<Arrival> = Vec::new();
        let mut dropped = Vec::new();
        for (path, entry) in &mut settling {
            if entry.looked.elapsed() < SETTLE {
                continue;
            }
            match std::fs::symlink_metadata(path) {
                Ok(metadata) if metadata.is_file() => {
                    entry.missing = None;
                    let size = metadata.len();
                    if size > 0 {
                        entry.was_something = true;
                        entry.bytes = size;
                    }
                    if entry.arrived_at.is_none() {
                        entry.arrived_at = created_iso(&metadata);
                    }
                    if kam_storage::downloads::is_placeholder(path) {
                        placeholders.insert(path.clone());
                        dropped.push(path.clone());
                        continue;
                    }
                    let written = metadata.modified().ok();
                    let steady = entry.size == Some(size) && entry.written == written;
                    if steady && crate::archive::open_shut_to_writers(path).is_ok() {
                        passed_on.push(Arrival::Settled(entry.sighting(path)));
                    } else {
                        entry.size = Some(size);
                        entry.written = written;
                        entry.looked = Instant::now();
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => match entry.missing {
                    None => {
                        entry.missing = Some(Instant::now());
                        entry.looked = Instant::now();
                    }
                    Some(since) if since.elapsed() >= SETTLE => {
                        if entry.was_something {
                            passed_on.push(Arrival::Vanished(entry.sighting(path)));
                        } else {
                            dropped.push(path.clone());
                        }
                    }
                    Some(_) => entry.looked = Instant::now(),
                },
                // A folder, a link, or something that cannot be read: not a
                // download to check.
                _ => dropped.push(path.clone()),
            }
        }
        for path in dropped {
            settling.remove(&path);
        }
        for arrival in &passed_on {
            let (Arrival::Settled(sighting) | Arrival::Vanished(sighting)) = arrival;
            settling.remove(&sighting.path);
        }

        // Said before anything is handed on, so that a file is never between
        // "arriving" and "waiting" with the page told neither.
        let mut moved = false;
        if let Ok(mut board) = board.lock() {
            let arriving: HashSet<PathBuf> = settling
                .keys()
                .chain(placeholders.iter())
                .cloned()
                .collect();
            moved = board.arriving != arriving || !passed_on.is_empty();
            board.arriving = arriving;
            for arrival in &passed_on {
                if let Arrival::Settled(sighting) = arrival {
                    board.waiting.push(sighting.path.clone());
                }
            }
        }
        if moved {
            changed();
        }
        for arrival in passed_on {
            if ready.send(arrival).is_err() {
                return;
            }
        }
    }
}

/// Files in Downloads created within `window`, for when Windows lost count.
fn recent_files(window: Duration) -> Vec<PathBuf> {
    let Ok(folder) = known_folder() else {
        return Vec::new();
    };
    let Ok(listing) = std::fs::read_dir(folder) else {
        return Vec::new();
    };
    listing
        .flatten()
        .filter(|item| !is_partial(&item.file_name().to_string_lossy()))
        .filter(|item| {
            item.metadata().is_ok_and(|metadata| {
                metadata.is_file()
                    && metadata
                        .created()
                        .ok()
                        .and_then(|created| created.elapsed().ok())
                        .is_some_and(|age| age <= window)
            })
        })
        .map(|item| item.path())
        .collect()
}

/// Deal with each file the settling thread hands on, one at a time: ask the
/// agent about one that has arrived, and record one that went first.
fn check_arrivals(app: &AppHandle, ready: &Receiver<Arrival>) {
    // Windows' notification interfaces want the thread set up for COM.
    unsafe {
        let _ = windows::Win32::System::Com::CoInitializeEx(
            None,
            windows::Win32::System::Com::COINIT_MULTITHREADED,
        );
    }
    let state = app.state::<Downloads>();
    let on_board = |change: &dyn Fn(&mut Board)| {
        if let Ok(mut board) = state.board.lock() {
            change(&mut board);
        }
        let _ = app.emit(CHANGED_EVENT, ());
    };
    let mut done: HashSet<(PathBuf, u64, Option<SystemTime>)> = HashSet::new();
    let mut counter = 0_u64;
    while let Ok(arrival) = ready.recv() {
        let sighting = match arrival {
            Arrival::Vanished(sighting) => {
                note_vanished(app, &sighting);
                continue;
            }
            Arrival::Settled(sighting) => sighting,
        };
        let path = sighting.path.clone();
        let Ok(metadata) = std::fs::metadata(&path) else {
            // Gone between settling and its turn.
            on_board(&|board| board.waiting.retain(|waiting| *waiting != path));
            note_vanished(app, &sighting);
            continue;
        };
        // The same file, unchanged, is not checked twice in one run.
        if !done.insert((path.clone(), metadata.len(), metadata.modified().ok())) {
            on_board(&|board| board.waiting.retain(|waiting| *waiting != path));
            continue;
        }
        counter += 1;
        let job = format!("arrival-{}-{counter}", std::process::id());
        on_board(&|board| {
            board.waiting.retain(|waiting| *waiting != path);
            board.checking = Some(Checking {
                path: path.clone(),
                job: job.clone(),
                since: Instant::now(),
            });
        });
        check_one(app, &sighting, &job);
        on_board(&|board| board.checking = None);
    }
}

/// Run `work`. If it is still running after `patience`, and for as long as
/// `others_waiting` says something is, ask it once to `give_way`. Answers
/// with what the work came to and whether it was asked.
///
/// The asking is all this does: the work has to be something that stops when
/// asked, as a check does when its job is cancelled.
fn with_patience<T>(
    patience: Duration,
    others_waiting: &(dyn Fn() -> bool + Sync),
    give_way: &(dyn Fn() + Sync),
    work: impl FnOnce() -> T,
) -> (T, bool) {
    let asked = AtomicBool::new(false);
    let asked_here = &asked;
    // Dropped when the work ends, which wakes the watching thread at once.
    let (finished, wait) = mpsc::channel::<()>();
    let look_every = patience
        .min(Duration::from_secs(1))
        .max(Duration::from_millis(10));
    let result = std::thread::scope(|scope| {
        scope.spawn(move || {
            let started = Instant::now();
            while let Err(RecvTimeoutError::Timeout) = wait.recv_timeout(look_every) {
                if started.elapsed() >= patience && others_waiting() {
                    asked_here.store(true, Ordering::SeqCst);
                    give_way();
                    break;
                }
            }
        });
        let result = work();
        drop(finished);
        result
    });
    (result, asked.load(Ordering::SeqCst))
}

/// What is said under a file whose automatic check was stopped so that the
/// downloads behind it were not kept waiting.
fn gave_way_sentence() -> String {
    format!(
        "The automatic check of this file was stopped after {} minutes, because other downloads \
         were waiting behind it. It can be checked from here, where a check runs until it \
         finishes or you stop it.",
        ARRIVAL_PATIENCE.as_secs() / 60
    )
}

/// Record a download that arrived and was gone before it could be checked,
/// and say so in a notice the first time.
fn note_vanished(app: &AppHandle, sighting: &Sighting) {
    let request = Request::NoteVanishedDownload {
        path: sighting.path.to_string_lossy().into_owned(),
        bytes: sighting.bytes,
        arrived_at: sighting.arrived_at.clone(),
    };
    match kam_ipc::client::call(&request) {
        Ok(Response::DownloadChecked(record)) => {
            if record.first_check {
                announce(app, &record);
            }
        }
        // Refused (it is there again, say) or the service did not answer.
        // There is no row to say it on, and nothing was shown as checked.
        Ok(other) => eprintln!("a download that went missing was not recorded: {other:?}"),
        Err(error) => eprintln!("a download that went missing was not recorded: {error}"),
    }
    let _ = app.emit(CHANGED_EVENT, ());
}

fn check_one(app: &AppHandle, sighting: &Sighting, job: &str) {
    let state = app.state::<Downloads>();
    let path = sighting.path.as_path();
    let key = path.to_string_lossy().into_owned();
    let note = |message: Option<String>| {
        if let Ok(mut failures) = state.failures.lock() {
            match message {
                Some(message) => {
                    failures.insert(key.clone(), message);
                }
                None => {
                    failures.remove(&key);
                }
            }
        }
    };

    // The protection switch stops the watching work, this included.
    if let Ok(Response::Protection { enabled: false }) =
        kam_ipc::client::call(&Request::GetProtection)
    {
        note(Some(
            "Not checked when it arrived, because KAM Security's protection was switched off."
                .to_owned(),
        ));
        let _ = app.emit(CHANGED_EVENT, ());
        return;
    }

    let request = Request::CheckDownload {
        path: key.clone(),
        job: job.to_owned(),
        copy_of: None,
    };
    // Its progress goes to the page, on the row it is about. And it is not
    // left to keep later downloads waiting for as long as it likes: see
    // `ARRIVAL_PATIENCE`.
    let others_waiting = || {
        state
            .board
            .lock()
            .is_ok_and(|board| !board.waiting.is_empty())
    };
    let give_way = || {
        let _ = kam_ipc::client::call(&Request::CancelJob {
            job: job.to_owned(),
        });
    };
    let (response, gave_way) = with_patience(ARRIVAL_PATIENCE, &others_waiting, &give_way, || {
        kam_ipc::client::call_streaming(&request, |progress| {
            let _ = app.emit(
                PROGRESS_EVENT,
                ArrivalProgress {
                    path: key.clone(),
                    job: job.to_owned(),
                    progress,
                },
            );
        })
    });
    match response {
        Ok(Response::DownloadChecked(record)) => {
            note(None);
            if record.first_check {
                announce(app, &record);
            }
        }
        // It went while it was being checked, or just before: that is a
        // download that was gone before it could be checked, and is recorded
        // as one. The reason used to be kept for a row that no longer existed.
        Ok(Response::Error { .. }) if std::fs::symlink_metadata(path).is_err() => {
            note(None);
            note_vanished(app, sighting);
        }
        Ok(Response::Error { message }) => {
            note(Some(format!("Not checked when it arrived: {message}")))
        }
        Ok(Response::Stopped) if gave_way => note(Some(gave_way_sentence())),
        Ok(Response::Stopped) => note(Some("The check was stopped before it finished.".to_owned())),
        Ok(other) => note(Some(format!(
            "The agent answered something unexpected: {other:?}"
        ))),
        Err(error) => note(Some(format!(
            "Not checked when it arrived, because the KAM Security service did not answer: {error}"
        ))),
    }
    let _ = app.emit(CHANGED_EVENT, ());
}

/// Send the notification for a newly recorded download.
fn announce(app: &AppHandle, record: &DownloadRecord) {
    // "Defender found nothing" about a zip it could not look inside is not
    // what the notice should say, so the zip's own list is read first.
    let path = Path::new(&record.check.path);
    let inside = (record.check.scan.answer == Answer::NothingFound
        && archive_kind(&record.check.name) == Some(ArchiveKind::Zip))
    .then(|| std::fs::metadata(path).ok())
    .flatten()
    .map(|metadata| {
        app.state::<Downloads>()
            .inside(&record.check.path, &metadata)
    });
    let (title, body) = crate::notice::sentence(
        &record.check.name,
        &record.check.scan,
        archive_kind(&record.check.name).is_some(),
        inside.as_ref(),
    );
    let clicked_app = app.clone();
    let path = record.check.path.clone();
    let shown = crate::notice::show(crate::notice::APP_ID, &title, &body, move || {
        open_on(
            &clicked_app,
            Launch {
                action: "show".to_owned(),
                path: path.clone(),
            },
        );
    });
    if let Err(error) = shown {
        eprintln!("the notification could not be shown: {error}");
    }
}

/// Open the window on the Downloads page for one file.
pub fn open_on(app: &AppHandle, launch: Launch) {
    app.state::<Downloads>().set_launch(launch);
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        crate::tray::show_window(&handle);
        let _ = handle.emit(LAUNCH_EVENT, ());
    });
}

// --- everything not checked yet -------------------------------------------

/// The event that says how far the check of everything not checked yet has
/// got: which file it is on, and the stage the check of that file is at.
pub const BACKLOG_EVENT: &str = "downloads://backlog";

/// How a run through everything not checked yet ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "how", rename_all = "snake_case")]
pub enum Ended {
    /// Every file was dealt with.
    Finished,
    /// Somebody pressed Stop. `abandoned` is the file whose check was in
    /// hand and was given up, when one was: nothing is recorded for it. The
    /// files after it were never started.
    Stopped { abandoned: Option<String> },
    /// The service stopped answering. Every file left would have failed the
    /// same way, for a reason that has nothing to do with the file.
    NoAnswer { reason: String },
}

/// One press of "Check everything not checked yet": how far it has got, and
/// what it has come to so far. Files are named by their full paths.
#[derive(Debug, Clone, Serialize)]
pub struct Backlog {
    job: String,
    /// How many files it set out to deal with.
    total: usize,
    /// How many it has dealt with: checked, found impossible to check, or
    /// left alone.
    done: usize,
    /// The file in hand.
    current: Option<String>,
    /// The agent's name for the check of the file in hand, which is the job
    /// a Stop has to cancel.
    #[serde(skip)]
    current_job: Option<String>,
    /// The stage that check is at.
    progress: Option<Progress>,
    /// Files Defender was asked about and answered for, whatever the answer.
    /// Each has its row.
    checked: usize,
    /// Of those, the ones Defender flagged.
    flagged: Vec<String>,
    /// Of those, the ones Defender could not finish checking.
    unfinished: Vec<String>,
    /// Files that could not be checked, each with why, in a sentence that
    /// opens with the file's name.
    failed: Vec<Failure>,
    /// Files left alone because they are stored only online.
    online_only: Vec<String>,
    /// How it ended. `None` while it runs.
    ended: Option<Ended>,
}

impl Backlog {
    fn new(job: &str) -> Self {
        Self {
            job: job.to_owned(),
            total: 0,
            done: 0,
            current: None,
            current_job: None,
            progress: None,
            checked: 0,
            flagged: Vec::new(),
            unfinished: Vec::new(),
            failed: Vec::new(),
            online_only: Vec::new(),
            ended: None,
        }
    }
}

/// How far a run has got, for the page to draw between two readings of the
/// whole of it: small enough to send at every step of every check.
#[derive(Debug, Clone, Serialize)]
struct BacklogStep {
    job: String,
    done: usize,
    total: usize,
    current: Option<String>,
    progress: Option<Progress>,
}

/// What has just moved in a run, for whoever is drawing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Moved {
    /// The file in hand, or the stage its check is at.
    Step,
    /// A file has been dealt with, or the run has ended, so the list of
    /// downloads is no longer what it was.
    List,
}

/// What became of one file in a run.
#[derive(Debug)]
enum Dealt {
    Checked(Box<DownloadRecord>),
    /// Not checked. `said` is the sentence for the page's list, opening with
    /// the file's name. `note` goes under the file, when it is still there
    /// to have one.
    Failed {
        said: String,
        note: Option<String>,
    },
    OnlineOnly,
}

/// Whether a file's contents are somewhere else, so that reading it would
/// fetch them: a OneDrive file that is not kept on this PC, say. The three
/// attributes Windows has for that are offline, recall on open, and recall on
/// data access.
fn stored_only_online(attributes: u32) -> bool {
    const ELSEWHERE: u32 = 0x0000_1000 | 0x0004_0000 | 0x0040_0000;
    attributes & ELSEWHERE != 0
}

/// A file's attributes, as its folder's listing gives them.
///
/// Asked of the folder and not of the file, because that opens nothing: it
/// is the one way to be sure that finding out whether a file is stored only
/// online does not itself fetch it. Recall on open is also only ever
/// reported this way.
fn listed_attributes(path: &Path) -> std::io::Result<u32> {
    use windows::core::HSTRING;
    use windows::Win32::Storage::FileSystem::{FindClose, FindFirstFileW, WIN32_FIND_DATAW};

    let mut found = WIN32_FIND_DATAW::default();
    let search = unsafe { FindFirstFileW(&HSTRING::from(path.as_os_str()), &mut found) }
        // The low half of the code is Windows' own error number, which is
        // what tells "not there" from every other reason.
        .map_err(|error| std::io::Error::from_raw_os_error(error.code().0 & 0xFFFF))?;
    unsafe {
        let _ = FindClose(search);
    }
    Ok(found.dwFileAttributes)
}

/// The agent's sentence about a file, opening with the file's name where it
/// opened with the whole path: in a list of files from one folder the path
/// is the same every time and the name is what tells them apart.
fn about(name: &str, path: &str, message: &str) -> String {
    match message.get(..path.len()) {
        Some(start) if start.eq_ignore_ascii_case(path) => {
            format!("{name}{}", &message[path.len()..])
        }
        _ => format!("{name}: {message}"),
    }
}

/// What asking about one file came to: the agent's answer, or why there was
/// none.
type Asked = Result<Response, String>;

/// Whoever is asked about each file: given the file, a name for that one
/// check, and somewhere to report its stages.
type Ask<'a> = dyn Fn(&str, &str, &mut dyn FnMut(Progress)) -> Asked + 'a;

/// Ask the agent to check one file, as a press of "Check now" does.
fn ask_the_agent(path: &str, job: &str, stage: &mut dyn FnMut(Progress)) -> Asked {
    kam_ipc::client::call_streaming(
        &Request::CheckDownload {
            path: path.to_owned(),
            job: job.to_owned(),
            copy_of: None,
        },
        stage,
    )
    .map_err(|error| error.to_string())
}

/// Work through `files`, one after another, as the one job named `job`.
///
/// # The rules
///
/// - Each file is asked about exactly as a press of "Check now" asks, so it
///   is the same check, recorded the same way. In the program `ask` is the
///   agent, and in a test it is whatever the test needs.
/// - A file stored only online is left alone and named. Reading it would
///   download it, and nobody asked for that by pressing one button for a
///   whole folder. Whether it is one is asked of the folder's listing, which
///   opens nothing.
/// - A file that cannot be checked (gone, open in a program that can still
///   change it, refused) is named with the reason, and the run goes on.
/// - Stop ends the run before the next file. The check in hand is cancelled
///   by whoever asked for the stop. If the agent answers that it stopped,
///   that file is named as abandoned and nothing is recorded for it; a check
///   that finished all the same is kept.
/// - A service that stops answering ends the run too. Every file left would
///   fail the same way, and a hundred identical failures say less than one
///   sentence does.
/// - No notification is raised for any file: this is not given the handle
///   one needs. What the run came to is said once, on the page.
fn work_through(
    state: &Downloads,
    job: &str,
    files: &[PathBuf],
    ask: &Ask<'_>,
    moved: &dyn Fn(Moved),
) {
    let end = |how: Ended| {
        state.in_backlog(job, |backlog| {
            backlog.current = None;
            backlog.current_job = None;
            backlog.progress = None;
            backlog.ended = Some(how);
        });
        state.forget_stop(job);
        moved(Moved::List);
    };

    for (number, file) in files.iter().enumerate() {
        if state.is_stopped(job) {
            end(Ended::Stopped { abandoned: None });
            return;
        }
        let path = file.to_string_lossy().into_owned();
        let name = file
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.clone());
        let check = format!("{job}-{}", number + 1);
        state.in_backlog(job, |backlog| {
            backlog.current = Some(path.clone());
            backlog.current_job = Some(check.clone());
            backlog.progress = None;
        });
        moved(Moved::Step);

        let dealt = match listed_attributes(file) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Dealt::Failed {
                said: format!("{name} is no longer in Downloads."),
                note: None,
            },
            // Not checked, in case it is one that reading would fetch.
            Err(error) => {
                let why = format!(
                    "its entry in the folder could not be read ({error}), so whether it is \
                     stored only online could not be told"
                );
                Dealt::Failed {
                    said: format!("{name} was not checked: {why}."),
                    note: Some(format!("Not checked: {why}.")),
                }
            }
            Ok(attributes) if stored_only_online(attributes) => Dealt::OnlineOnly,
            Ok(_) => {
                let mut stage = |progress: Progress| {
                    state.in_backlog(job, |backlog| backlog.progress = Some(progress));
                    moved(Moved::Step);
                };
                match ask(&path, &check, &mut stage) {
                    Ok(Response::DownloadChecked(record)) => Dealt::Checked(record),
                    Ok(Response::Stopped) if state.is_stopped(job) => {
                        end(Ended::Stopped {
                            abandoned: Some(path),
                        });
                        return;
                    }
                    Ok(Response::Stopped) => Dealt::Failed {
                        said: format!("{name}: the check was stopped before it finished."),
                        note: Some("The check was stopped before it finished.".to_owned()),
                    },
                    Ok(Response::Error { message }) => Dealt::Failed {
                        said: about(&name, &path, &message),
                        note: Some(format!("Not checked: {message}")),
                    },
                    Ok(other) => {
                        let message = format!("the agent answered something unexpected: {other:?}");
                        Dealt::Failed {
                            said: format!("{name}: {message}"),
                            note: Some(format!("Not checked: {message}")),
                        }
                    }
                    Err(reason) => {
                        end(Ended::NoAnswer { reason });
                        return;
                    }
                }
            }
        };

        match &dealt {
            // It has been checked now, so why it was not checked before no
            // longer has anything to say.
            Dealt::Checked(record) => {
                state.forget_failure(&path);
                state.forget_failure(&record.check.path);
            }
            Dealt::Failed { note, .. } => {
                if let Some(note) = note {
                    state.note_failure(&path, note.clone());
                }
            }
            Dealt::OnlineOnly => state.note_failure(
                &path,
                "Not checked with the rest, because it is stored only online and checking it \
                 would download it."
                    .to_owned(),
            ),
        }
        state.in_backlog(job, |backlog| {
            backlog.done += 1;
            match dealt {
                Dealt::Checked(record) => {
                    backlog.checked += 1;
                    match record.check.scan.answer {
                        Answer::Flagged => backlog.flagged.push(path),
                        Answer::NotFinished => backlog.unfinished.push(path),
                        Answer::NothingFound | Answer::GoneBeforeCheck => {}
                    }
                }
                Dealt::Failed { said, .. } => backlog.failed.push(Failure {
                    path,
                    message: said,
                }),
                Dealt::OnlineOnly => backlog.online_only.push(path),
            }
        });
        moved(Moved::List);
    }
    end(Ended::Finished);
}

/// The files a press of "Check everything not checked yet" is about: the
/// ones the page shows as not checked, worked out the way the page works
/// them out, without those already on their way to being checked.
///
/// A history that cannot be read is a refusal, not an empty one. Without it
/// every file in the folder reads as not checked, and the run would check
/// again everything that already has an answer.
fn backlog_files(state: &Downloads) -> Result<Vec<PathBuf>, String> {
    let folder = known_folder()?;
    let present = files_in(&folder)?;
    let named = present.iter().map(|(path, _, _)| path.clone()).collect();
    let (records, _) = history(named, RECENT_ROWS).map_err(|reason| {
        format!(
            "The history of checked downloads could not be read ({reason}), so which files \
             are not checked yet is not known, and none was checked."
        )
    })?;
    Ok(not_checked(state, present, &records)
        .into_iter()
        .filter(|file| file.in_flight.is_none())
        .map(|file| PathBuf::from(file.path))
        .collect())
}

/// Start checking everything not checked yet. Returns once it is under way;
/// the work is on a thread of its own, and the page follows it through
/// [`BACKLOG_EVENT`] and by reading the page again.
///
/// It is not tied to the window. Closing the window is not a press of Stop,
/// so the run goes on, and what it came to is there when the page is next
/// opened, for as long as this program keeps running.
pub fn check_backlog(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<Downloads>();
    let job = state.begin_backlog()?;
    let give_up = |reason: String| {
        if let Ok(mut slot) = state.backlog.lock() {
            *slot = None;
        }
        Err(reason)
    };
    let files = match backlog_files(&state) {
        Ok(files) if files.is_empty() => {
            return give_up("Nothing in Downloads is waiting to be checked.".to_owned())
        }
        Ok(files) => files,
        Err(reason) => return give_up(reason),
    };
    state.in_backlog(&job, |backlog| backlog.total = files.len());

    let worker = app.clone();
    let name = job.clone();
    let spawned = std::thread::Builder::new()
        .name("kam-downloads-backlog".to_owned())
        .spawn(move || {
            let state = worker.state::<Downloads>();
            work_through(
                &state,
                &name,
                &files,
                &ask_the_agent,
                &|moved| match moved {
                    Moved::Step => {
                        if let Some(step) = state.backlog_step() {
                            let _ = worker.emit(BACKLOG_EVENT, step);
                        }
                    }
                    Moved::List => {
                        let _ = worker.emit(CHANGED_EVENT, ());
                    }
                },
            );
        });
    match spawned {
        Ok(_) => Ok(()),
        Err(error) => give_up(format!("the check could not be started: {error}")),
    }
}

/// Stop checking everything not checked yet: the run here, and the check it
/// has in hand in the agent.
pub fn stop_backlog(state: &Downloads) {
    if let Some(Some(check)) = state.ask_backlog_to_stop() {
        // It may not have reached the agent yet, or may have just finished.
        // Either way the run ends before the next file.
        let _ = kam_ipc::client::call(&Request::CancelJob { job: check });
    }
}

// --- taking archives apart ------------------------------------------------

/// What the page draws for an archive that has been taken apart.
#[derive(Debug, Clone, Serialize)]
pub struct DissectionView {
    token: String,
    dissection: Dissection,
    /// The folder the files would be extracted into, as it stands now. The
    /// one really made is named in the result, should this be taken by then.
    destination: String,
    /// Why the files extracted from this archive will not carry the mark
    /// Windows puts on downloaded files, when the archive's own could not be
    /// read.
    mark_problem: Option<String>,
    /// Why what the archive holds is not on its row, when recording it
    /// failed. It used to be missing without a word.
    record_problem: Option<String>,
}

/// What came of asking for an archive to be taken apart.
#[derive(Debug, Serialize)]
pub struct Dissected {
    /// The archive, open. Absent when it was stopped first.
    view: Option<DissectionView>,
    /// What had happened to the original by then. A flagged original is
    /// quarantined before anything else, so "stopped" does not always mean
    /// "nothing was changed", and the page says which it was.
    original: OriginalFate,
}

/// A sentence about something that went wrong, with what had already
/// happened to the original by then. Every way out of [`dissect`] after the
/// original may have been quarantined goes through this, so that no message
/// reads as if nothing had been changed when something had.
fn and_the_original(message: &str, fate: &OriginalFate) -> String {
    let message = message.trim_end();
    let stop = if message.ends_with(['.', '!', '?', ')']) {
        ""
    } else {
        "."
    };
    if fate.quarantined.is_some() {
        format!(
            "{message}{stop} The original had already been quarantined, because Defender \
             flagged it. It can be put back from its row here, or from Cleanup, for thirty days."
        )
    } else if let Some(refused) = &fate.refused {
        format!(
            "{message}{stop} The original is still where it was: quarantining it was tried and \
             did not work ({refused})."
        )
    } else {
        message.to_owned()
    }
}

fn emit_stage(app: &AppHandle, job: &str, stage: &str) {
    let _ = app.emit(
        &format!("job://{job}"),
        Progress {
            stage: stage.to_owned(),
            done: 0,
            total: None,
            detail: None,
        },
    );
}

/// Quarantine the original, saying how that went.
fn quarantine_original(original: &str) -> OriginalFate {
    match kam_ipc::client::call(&Request::QuarantineDownload {
        path: original.to_owned(),
    }) {
        Ok(Response::Quarantined(manifest)) => OriginalFate {
            quarantined: Some(manifest.id),
            refused: None,
        },
        Ok(Response::Error { message }) => OriginalFate {
            quarantined: None,
            refused: Some(message),
        },
        Ok(other) => OriginalFate {
            quarantined: None,
            refused: Some(format!(
                "the agent answered something unexpected: {other:?}"
            )),
        },
        Err(error) => OriginalFate {
            quarantined: None,
            refused: Some(error.to_string()),
        },
    }
}

/// What is said about an archive of a kind this cannot take apart. It says
/// what was done, and does not call anything clean: that word would be this
/// product's own verdict on a file.
const NOT_A_ZIP: &str = "Only zip archives can be taken apart here. Defender was asked about \
     this one as a single file.";

/// Take a zip apart. See the module notes.
pub fn dissect(app: &AppHandle, path: &str, job: &str) -> Result<Dissected, String> {
    let state = app.state::<Downloads>();
    let outcome = dissect_for(app, &state, path, job);
    state.forget_stop(job);
    // The window may have been closed while this ran, and then nobody is
    // left to close the archive it opened.
    if app.get_webview_window("main").is_none() {
        state.close_all();
    }
    outcome
}

fn dissect_for(
    app: &AppHandle,
    state: &Downloads,
    path: &str,
    job: &str,
) -> Result<Dissected, String> {
    let stopped = |original: OriginalFate| {
        Ok(Dissected {
            view: None,
            original,
        })
    };
    let given = Path::new(path);
    let name = given
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    match archive_kind(&name) {
        Some(ArchiveKind::Zip) => {}
        Some(ArchiveKind::Other) => return Err(NOT_A_ZIP.to_owned()),
        None => return Err("This is not an archive, so there is nothing to take apart.".to_owned()),
    }
    let real = std::fs::canonicalize(given)
        .map_err(|error| format!("{path} could not be found: {error}"))?;
    let real_text = real.to_string_lossy();
    let original = real_text
        .strip_prefix(r"\\?\")
        .unwrap_or(&real_text)
        .to_owned();

    // What Defender said about the original when it arrived, if anything.
    let earlier = history(vec![original.clone()], 0)
        .ok()
        .and_then(|(records, _)| records.into_iter().next());
    let known_flagged = earlier
        .as_ref()
        .is_some_and(|record| record.check.scan.answer == Answer::Flagged);

    // Read before the original can be quarantined. A mark that could not be
    // read is not the same as no mark: the files extracted will go without
    // one, which is said beside the button that extracts them.
    let (zone, mark_problem) = match crate::archive::read_mark(&real) {
        Ok(zone) => (zone, None),
        Err(error) => (
            None,
            Some(format!(
                "The mark Windows puts on downloaded files could not be read from this archive \
                 ({error}). Files extracted from it will not carry the mark, so SmartScreen \
                 will not check them before they are run."
            )),
        ),
    };

    emit_stage(app, job, "Making a private copy to take apart");
    // Held open from here until the archive is closed or extracted, and
    // deleted when it is let go, on every way out of this function.
    //
    // Stop is honoured here and before the original is quarantined. It used
    // to be accepted and ignored until Defender was running, because only
    // the agent was ever told about it.
    let Some(copy) = crate::archive::working_copy(&real, &|| !state.is_stopped(job))? else {
        return stopped(OriginalFate::default());
    };
    if state.is_stopped(job) {
        return stopped(OriginalFate::default());
    }

    // Quarantined first, as asked, when Defender has already flagged it.
    // From here on something may have been changed, so every way out says
    // what became of the original.
    let mut fate = OriginalFate::default();
    let mut tried = false;
    if known_flagged {
        emit_stage(app, job, "Quarantining the original");
        fate = quarantine_original(&original);
        tried = true;
    }
    if state.is_stopped(job) {
        return stopped(fate);
    }

    let channel = format!("job://{job}");
    let checked = kam_ipc::client::call_streaming(
        &Request::CheckDownload {
            path: copy.path().to_string_lossy().into_owned(),
            job: job.to_owned(),
            copy_of: Some(original.clone()),
        },
        |progress| {
            let _ = app.emit(&channel, progress);
        },
    );
    let record = match checked {
        Ok(Response::DownloadChecked(record)) => record,
        Ok(Response::Stopped) => return stopped(fate),
        Ok(Response::Error { message }) => return Err(and_the_original(&message, &fate)),
        Ok(other) => {
            return Err(and_the_original(
                &format!("the agent answered something unexpected: {other:?}"),
                &fate,
            ))
        }
        Err(error) => return Err(and_the_original(&error.to_string(), &fate)),
    };

    // Flagged only now: quarantined before anything is taken apart.
    if record.check.scan.answer == Answer::Flagged && !tried {
        emit_stage(app, job, "Quarantining the original");
        fate = quarantine_original(&original);
    }

    // The copy held here has to be the file Defender was asked about, or
    // nothing in it is listed, let alone extracted.
    emit_stage(
        app,
        job,
        "Making sure the copy is the file Defender looked at",
    );
    copy.is_the_file_checked(&record.check.sha256)
        .map_err(|refusal| and_the_original(&refusal, &fate))?;

    emit_stage(app, job, "Reading the archive's list of files");
    let entries = crate::archive::entries(copy.file()).map_err(|reason| {
        and_the_original(&format!("{name} could not be taken apart: {reason}"), &fate)
    })?;
    let mut dissection = kam_scanner::downloads::dissect(
        &original,
        &record.check.sha256,
        record.check.scan.clone(),
        &entries,
    );
    dissection.original = fate;

    let recorded = kam_ipc::client::call(&Request::RecordDissection {
        path: original.clone(),
        sha256: record.check.sha256.clone(),
        // Cut to what a record keeps before it is sent. Whole, the list of a
        // vast archive is larger than one frame of the pipe, and the record
        // of it was then silently never made.
        dissection: Box::new(dissection.for_record(kam_scanner::downloads::RECORDED_MEMBERS)),
    });
    let record_problem = match recorded {
        Ok(Response::Error { message }) => Some(message),
        Err(error) => Some(error.to_string()),
        Ok(_) => None,
    }
    .map(|reason| format!("What this archive holds could not be recorded on its row ({reason})."));

    let destination = known_folder()
        .map(|folder| {
            kam_storage::downloads::extraction_folder_name(&name, |candidate| {
                std::fs::symlink_metadata(folder.join(candidate)).is_ok()
            })
        })
        .unwrap_or_default();
    let view = DissectionView {
        token: format!(
            "{job}-{}",
            record.check.sha256.get(..12).unwrap_or_default()
        ),
        dissection,
        destination,
        mark_problem,
        record_problem,
    };
    state.open(Session {
        copy,
        name,
        sha256: record.check.sha256.clone(),
        zone,
        view: view.clone(),
        extracting: AtomicBool::new(false),
    });
    Ok(Dissected {
        original: view.dissection.original.clone(),
        view: Some(view),
    })
}

/// Extract what Defender found nothing in, record it, and close the archive.
pub fn extract(state: &Downloads, token: &str) -> Result<Extraction, String> {
    let (session, extraction) = extract_into(state, token, &known_folder()?)?;
    if let Err(error) = kam_ipc::client::call(&Request::RecordExtraction {
        path: session.view.dissection.archive.clone(),
        sha256: session.sha256.clone(),
        extraction: extraction.clone(),
    }) {
        eprintln!("the extraction could not be recorded: {error}");
    }
    Ok(extraction)
}

/// Extract from the open archive into a new folder in `parent`.
///
/// The archive is closed, and its private copy deleted, only once files have
/// been written. A refusal comes before the first file (see
/// `archive::extract`), so the archive stays open and the button can simply
/// be pressed again. It used to be closed whatever happened, and after a
/// refusal for want of free space the only way back to an archive whose
/// original was in quarantine was to restore it from another page.
fn extract_into(
    state: &Downloads,
    token: &str,
    parent: &Path,
) -> Result<(Arc<Session>, Extraction), String> {
    let session = state
        .session(token)
        .ok_or("That archive is no longer open here. Take it apart again to extract from it.")?;
    if session.extracting.swap(true, Ordering::SeqCst) {
        return Err("This archive is already being extracted.".to_owned());
    }
    // Through the handle held since the copy was made.
    let outcome = crate::archive::extract(
        session.copy.file(),
        &session.view.dissection,
        parent,
        &session.name,
        session.zone.as_deref(),
    );
    session.extracting.store(false, Ordering::SeqCst);
    let extraction = outcome?;
    state.close(token);
    Ok((session, extraction))
}

/// Close an archive without extracting, deleting the private copy.
pub fn discard(state: &Downloads, token: &str) {
    state.close(token);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn record(action: u32, name: &str, next: u32) -> Vec<u8> {
        let units: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&next.to_le_bytes());
        bytes.extend_from_slice(&action.to_le_bytes());
        bytes.extend_from_slice(&(units.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&units);
        while bytes.len() % 4 != 0 {
            bytes.push(0);
        }
        bytes
    }

    #[test]
    fn windows_change_records_are_read_and_partial_names_ignored() {
        let mut first = record(1, "setup.exe.crdownload", 0);
        let length = first.len() as u32;
        first[..4].copy_from_slice(&length.to_le_bytes());
        let mut second = record(5, "setup.exe", 0);
        let second_length = second.len() as u32;
        second[..4].copy_from_slice(&second_length.to_le_bytes());
        let mut third = record(3, "notes.txt", 0);
        let third_length = third.len() as u32;
        third[..4].copy_from_slice(&third_length.to_le_bytes());
        let mut fourth = record(4, "old name.txt", 0);
        let fourth_length = fourth.len() as u32;
        fourth[..4].copy_from_slice(&fourth_length.to_le_bytes());
        let mut fifth = record(1, "new.txt", 0);
        let fifth_length = fifth.len() as u32;
        fifth[..4].copy_from_slice(&fifth_length.to_le_bytes());
        // Removed: found by looking, not passed on.
        let sixth = record(2, "deleted.txt", 0);
        let bytes = [first, second, third, fourth, fifth, sixth].concat();

        let events = parse_notifications(&bytes, Path::new(r"C:\Users\me\Downloads"));
        assert_eq!(events.len(), 4, "the partial name should be ignored");
        assert!(matches!(
            &events[0],
            Seen::Arrived { path, renamed: true } if path.ends_with("setup.exe")
        ));
        assert!(matches!(&events[1], Seen::Changed(path) if path.ends_with("notes.txt")));
        assert!(matches!(&events[2], Seen::Renamed(path) if path.ends_with("old name.txt")));
        assert!(matches!(
            &events[3],
            Seen::Arrived { path, renamed: false } if path.ends_with("new.txt")
        ));
    }

    #[test]
    fn a_truncated_record_ends_the_reading_rather_than_overrunning() {
        let mut bytes = record(1, "a.exe", 400);
        bytes.truncate(16);
        let events = parse_notifications(&bytes, Path::new(r"C:\D"));
        assert!(events.is_empty());
        assert!(parse_notifications(&[1, 2, 3], Path::new(r"C:\D")).is_empty());
    }

    /// A file still being written is held back, and let through once it has
    /// stopped changing and nobody holds it open for writing.
    #[test]
    fn a_download_is_passed_on_only_once_it_has_settled() {
        use std::io::Write;
        let folder = std::env::temp_dir().join(format!("kam-settle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&folder);
        std::fs::create_dir_all(&folder).unwrap();
        let path = folder.join("big.bin");
        let mut writer = std::fs::File::create(&path).unwrap();

        let (seen_tx, ready_rx, board, settler) = settling();
        seen_tx.send(arrived(&path, false)).unwrap();

        // Still growing, and held open for writing: nothing comes out.
        for _ in 0..3 {
            writer.write_all(&[0_u8; 1024]).unwrap();
            writer.flush().unwrap();
            assert!(ready_rx.recv_timeout(Duration::from_millis(1500)).is_err());
        }
        assert_eq!(
            board.lock().unwrap().state_of(&path),
            Some(InFlight::Arriving),
            "the page was not told it is still arriving"
        );
        drop(writer);
        let finished = ready_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("it never settled");
        let Arrival::Settled(sighting) = finished else {
            panic!("it was passed on as gone: {finished:?}");
        };
        assert_eq!(
            (sighting.path.clone(), sighting.bytes),
            (path.clone(), 3072)
        );
        assert_eq!(
            board.lock().unwrap().state_of(&path),
            Some(InFlight::Waiting { ahead: 0 }),
            "the page was not told it is waiting its turn"
        );

        drop(seen_tx);
        settler.join().unwrap();
        let _ = std::fs::remove_dir_all(&folder);
    }

    type Settler = (
        Sender<Seen>,
        Receiver<Arrival>,
        Arc<Mutex<Board>>,
        std::thread::JoinHandle<()>,
    );

    /// The settling thread, on channels and a board of its own.
    fn settling() -> Settler {
        let (seen_tx, seen_rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel();
        let board = Arc::new(Mutex::new(Board::default()));
        let shared = Arc::clone(&board);
        let settler = std::thread::spawn(move || settle(&seen_rx, &ready_tx, &shared, &|| {}));
        (seen_tx, ready_rx, board, settler)
    }

    fn arrived(path: &Path, renamed: bool) -> Seen {
        Seen::Arrived {
            path: path.to_path_buf(),
            renamed,
        }
    }

    /// Firefox makes the final name, empty, when a download starts. It sat
    /// still, so it was checked and announced as "Defender found nothing"
    /// while the real file was still arriving in the partial one beside it.
    #[test]
    fn an_empty_name_made_for_a_download_still_arriving_is_not_passed_on() {
        let scratch = Scratch::new("placeholder");
        let name = scratch.0.join("Downloads").join("big.iso");
        let part = scratch.0.join("Downloads").join("big.iso.part");
        std::fs::write(&name, b"").unwrap();
        std::fs::write(&part, b"the first megabyte").unwrap();

        let (seen_tx, ready_rx, board, settler) = settling();
        seen_tx.send(arrived(&name, false)).unwrap();
        let early = ready_rx.recv_timeout(Duration::from_secs(6));
        assert!(
            early.is_err(),
            "an empty placeholder was passed on as a finished download: {early:?}"
        );
        // Something else arriving wakes the thread, which tells the page.
        let other = scratch.0.join("Downloads").join("other.txt");
        std::fs::write(&other, b"x").unwrap();
        seen_tx.send(arrived(&other, false)).unwrap();
        assert!(matches!(
            ready_rx.recv_timeout(Duration::from_secs(10)),
            Ok(Arrival::Settled(sighting)) if sighting.path == other
        ));
        assert_eq!(
            board.lock().unwrap().state_of(&name),
            Some(InFlight::Arriving)
        );

        // The browser finishes: the partial file is renamed over the name.
        std::fs::remove_file(&name).unwrap();
        std::fs::rename(&part, &name).unwrap();
        seen_tx.send(arrived(&name, true)).unwrap();
        let finished = ready_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the finished download never settled");
        assert!(
            matches!(&finished, Arrival::Settled(sighting) if sighting.path == name && sighting.bytes == 18),
            "{finished:?}"
        );

        drop(seen_tx);
        settler.join().unwrap();
    }

    /// A download that Defender takes away as it lands used to leave no
    /// trace: it was dropped without a word when it was found missing. It is
    /// passed on as gone now, to be recorded. A name that never held
    /// anything, or was only renamed, is not.
    #[test]
    fn a_download_that_goes_before_it_settles_is_passed_on_as_gone() {
        let scratch = Scratch::new("vanish");
        let folder = scratch.0.join("Downloads");
        let (seen_tx, ready_rx, _, settler) = settling();

        let taken = folder.join("taken.exe");
        std::fs::write(&taken, b"0123456789").unwrap();
        seen_tx.send(arrived(&taken, true)).unwrap();
        std::thread::sleep(Duration::from_millis(500));
        std::fs::remove_file(&taken).unwrap();
        let gone = ready_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("a download that went was dropped without a word");
        let Arrival::Vanished(sighting) = gone else {
            panic!("it was passed on to be checked: {gone:?}");
        };
        assert_eq!((sighting.path, sighting.bytes), (taken, 10));
        assert!(sighting.arrived_at.is_some());

        // An empty name that comes and goes, and a file that was renamed.
        let empty = folder.join("New Text Document.txt");
        std::fs::write(&empty, b"").unwrap();
        seen_tx.send(arrived(&empty, false)).unwrap();
        let renamed = folder.join("a.txt");
        std::fs::write(&renamed, b"kept").unwrap();
        seen_tx.send(arrived(&renamed, false)).unwrap();
        std::thread::sleep(Duration::from_millis(500));
        std::fs::remove_file(&empty).unwrap();
        std::fs::rename(&renamed, folder.join("b.txt")).unwrap();
        seen_tx.send(Seen::Renamed(renamed)).unwrap();
        let nothing = ready_rx.recv_timeout(Duration::from_secs(7));
        assert!(nothing.is_err(), "{nothing:?} was passed on");

        drop(seen_tx);
        settler.join().unwrap();
    }

    /// The page is told where each file has got to, so one that is being
    /// checked no longer reads "Not checked yet".
    #[test]
    fn the_board_says_where_each_file_has_got_to() {
        let path = |name: &str| PathBuf::from(format!(r"C:\Users\me\Downloads\{name}"));
        let mut board = Board::default();
        board.arriving.insert(path("arriving.iso"));
        board.waiting = vec![path("second.exe"), path("third.exe")];
        assert_eq!(
            board.state_of(&path("ARRIVING.iso")),
            Some(InFlight::Arriving)
        );
        assert_eq!(
            board.state_of(&path("third.exe")),
            Some(InFlight::Waiting { ahead: 1 })
        );
        assert_eq!(board.state_of(&path("unknown.txt")), None);

        board.checking = Some(Checking {
            path: path("first.exe"),
            job: "arrival-1-1".to_owned(),
            since: Instant::now(),
        });
        assert!(matches!(
            board.state_of(&path("first.exe")),
            Some(InFlight::Checking { job, .. }) if job == "arrival-1-1"
        ));
        // The one being checked is ahead of everything waiting.
        assert_eq!(
            board.state_of(&path("second.exe")),
            Some(InFlight::Waiting { ahead: 1 })
        );
    }

    /// One file Defender stalls on used to hold every later download
    /// unchecked, for up to four hours. A check that has had its time is
    /// asked to give way, but only when something is waiting behind it.
    #[test]
    fn a_check_gives_way_only_when_it_has_had_its_time_and_others_are_waiting() {
        // A check that runs for ten seconds unless it is asked to stop.
        let stopped = AtomicBool::new(false);
        let started = Instant::now();
        let long = || {
            while !stopped.load(Ordering::SeqCst) && started.elapsed() < Duration::from_secs(10) {
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        let ((), gave_way) = with_patience(
            Duration::from_millis(100),
            &|| true,
            &|| stopped.store(true, Ordering::SeqCst),
            long,
        );
        assert!(gave_way, "it was never asked to give way");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "it held the others up for its whole length"
        );

        // With nothing waiting it holds nobody up, and is left to finish.
        let asked = AtomicBool::new(false);
        let (finished, gave_way) = with_patience(
            Duration::from_millis(50),
            &|| false,
            &|| asked.store(true, Ordering::SeqCst),
            || {
                std::thread::sleep(Duration::from_millis(400));
                "finished"
            },
        );
        assert_eq!((finished, gave_way), ("finished", false));
        assert!(!asked.load(Ordering::SeqCst));

        // One that finishes inside its time is never asked, and is not waited on.
        let quick = Instant::now();
        let ((), gave_way) = with_patience(Duration::from_secs(600), &|| true, &|| {}, || ());
        assert!(!gave_way && quick.elapsed() < Duration::from_secs(1));
        assert!(gave_way_sentence().contains("after 10 minutes"));
    }

    /// Product rule: no "clean" in this product's own voice. The page said
    /// "Extract the clean parts", "Clean extraction is available" and "get a
    /// clean copy". Read from the page's own source, because that is where
    /// the words a person reads are. What it may still say is what a result
    /// is not, and that nothing unread is ever shown as clean.
    #[test]
    fn nothing_the_page_or_the_window_says_calls_a_file_clean() {
        let allowed = ["not a clean result", "never shown as clean"];
        let standalone = |line: &str| {
            let lower = line.to_lowercase();
            lower.match_indices("clean").any(|(at, word)| {
                let before = lower[..at].chars().next_back();
                let after = lower[at + word.len()..].chars().next();
                let part_of_a_name = |c: Option<char>| {
                    c.is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '('))
                };
                !part_of_a_name(before) && !part_of_a_name(after)
            }) && !allowed.iter().any(|phrase| lower.contains(phrase))
        };
        let page = include_str!("../../src/views/Downloads.tsx");
        for (number, line) in page.lines().enumerate() {
            assert!(!standalone(line), "the page, line {}: {line}", number + 1);
        }
        assert!(!standalone(NOT_A_ZIP), "{NOT_A_ZIP}");
        // The check itself: it catches the three sentences it was written for.
        for wrong in [
            "Extract the clean parts",
            "Clean extraction is available for zip archives.",
            "get a clean copy from its publisher",
        ] {
            assert!(standalone(wrong), "{wrong} was let through");
        }
    }

    /// Removing a row is real and permanent, so what it does and does not
    /// do is said beside the buttons, in the words the owner asked for, and
    /// the one that clears the whole list says so again before it does.
    /// Read from the page's own source, where the words a person reads are.
    #[test]
    fn the_page_says_what_removing_a_row_does_and_does_not_do() {
        let page: String = include_str!("../../src/views/Downloads.tsx")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        for said in [
            "\"Remove from this list\" on a row, and \"Clear the list\" above, delete KAM \
             Security's record of a check for good.",
            "The file itself is not touched",
            "A file still in Downloads goes back to \"Not checked yet\".",
            "The Activity log keeps its own entry of each check.",
            // The question "Clear the list" asks, once.
            "No file is touched.",
            "This cannot be undone.",
            // Searching a list that is not the whole of it says so.
            "Searching, filtering and sorting cover only the rows shown here.",
        ] {
            assert!(page.contains(said), "the page no longer says: {said}");
        }
    }

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("kam-downloads-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("Downloads")).unwrap();
            Self(root)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Take a harmless zip apart into `state`, as `dissect` leaves it, and
    /// say where its private copy is.
    fn open_archive(state: &Downloads, scratch: &Scratch, token: &str) -> PathBuf {
        use std::io::Write;
        let original = scratch.0.join("a.zip");
        let mut writer = zip::ZipWriter::new(std::fs::File::create(&original).unwrap());
        writer
            .start_file("readme.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"hello").unwrap();
        writer.finish().unwrap();

        let copy = crate::archive::working_copy_in(&original, &scratch.0.join("work"), &|| true)
            .unwrap()
            .unwrap();
        let path = copy.path().to_path_buf();
        let nothing = kam_scanner::defender_file::parse_report(Some(0), "");
        let dissection = kam_scanner::downloads::dissect(
            "a.zip",
            "ab",
            nothing,
            &crate::archive::entries(copy.file()).unwrap(),
        );
        state.open(Session {
            copy,
            name: "a.zip".to_owned(),
            sha256: "ab".to_owned(),
            zone: None,
            view: DissectionView {
                token: token.to_owned(),
                dissection,
                destination: String::new(),
                mark_problem: None,
                record_problem: None,
            },
            extracting: AtomicBool::new(false),
        });
        path
    }

    /// Red review: closing the window destroys it, so the page's own
    /// clean-up never ran, and the private copy of an archive stayed in the
    /// work folder until the program was next started.
    #[test]
    fn closing_the_window_deletes_the_private_copy_of_an_open_archive() {
        let scratch = Scratch::new("close");
        let state = Downloads::default();
        let copy = open_archive(&state, &scratch, "one");
        assert!(copy.exists() && state.view("one").is_some());

        // Taking another archive apart closes the first.
        let second = open_archive(&state, &scratch, "two");
        assert!(!copy.exists(), "the first archive's copy was left behind");
        assert!(state.view("one").is_none());

        state.close_all();
        assert!(!second.exists(), "the copy outlived the window");
        assert!(state.view("two").is_none());
    }

    /// An extraction that is refused wrote nothing, so the archive stays
    /// open and the button can be pressed again. It used to be closed
    /// whatever happened, which left a row with nothing to press.
    #[test]
    fn a_refused_extraction_leaves_the_archive_open_to_try_again() {
        let scratch = Scratch::new("retry");
        let state = Downloads::default();
        let copy = open_archive(&state, &scratch, "one");

        let nowhere = scratch.0.join("no-such-folder");
        assert!(extract_into(&state, "one", &nowhere).is_err());
        assert!(
            state.view("one").is_some() && copy.exists(),
            "a refused extraction closed the archive"
        );

        let (_, done) = extract_into(&state, "one", &scratch.0.join("Downloads")).unwrap();
        assert_eq!(done.files, 1, "{done:?}");
        assert!(state.view("one").is_none(), "it stayed open once extracted");
        assert!(extract_into(&state, "one", &nowhere)
            .unwrap_err()
            .contains("no longer open"));
        // The copy goes when the last holder lets go, which is this test.
        assert!(!copy.exists(), "the private copy outlived the extraction");
    }

    /// "Taking it apart was stopped, so nothing was changed" was said when
    /// the original had already been quarantined. Every message after that
    /// point now says what became of the original.
    #[test]
    fn what_went_wrong_says_what_had_already_happened_to_the_original() {
        let untouched = OriginalFate::default();
        assert_eq!(and_the_original("It failed", &untouched), "It failed");

        let quarantined = OriginalFate {
            quarantined: Some("1-0001".to_owned()),
            refused: None,
        };
        let said = and_the_original("a.zip could not be taken apart: not a zip", &quarantined);
        assert!(
            said.starts_with("a.zip could not be taken apart: not a zip. The original had already")
                && said.contains("can be put back"),
            "{said}"
        );
        assert!(and_the_original("It failed.", &quarantined).starts_with("It failed. The"));

        let refused = OriginalFate {
            quarantined: None,
            refused: Some("it is in use".to_owned()),
        };
        let said = and_the_original("It failed", &refused);
        assert!(
            said.contains("still where it was") && said.contains("it is in use"),
            "{said}"
        );
    }

    /// With several files selected, Windows starts this program once for
    /// each. There was room for one request, so each replaced the last and
    /// all but one were dropped without a word.
    #[test]
    fn several_files_asked_about_from_explorer_each_wait_their_turn() {
        let state = Downloads::default();
        let asked = |action: &str, name: &str| Launch {
            action: action.to_owned(),
            path: format!(r"C:\Users\me\Downloads\{name}"),
        };
        state.set_launch(asked("check", "a.exe"));
        state.set_launch(asked("extract", "b.zip"));
        state.set_launch(asked("check", "c.exe"));
        // The same request twice is one request.
        state.set_launch(asked("check", "c.exe"));
        assert_eq!(state.launches_waiting(), 3);
        assert!(state.has_launch());

        assert_eq!(state.take_launch(true), Some(asked("check", "a.exe")));
        // An archive is open: the next one to take apart waits where it is.
        assert_eq!(state.take_launch(false), None);
        assert_eq!(state.launches_waiting(), 2);
        assert_eq!(state.take_launch(true), Some(asked("extract", "b.zip")));
        // A check does not need the archive to be closed.
        assert_eq!(state.take_launch(false), Some(asked("check", "c.exe")));
        assert_eq!(state.take_launch(true), None);
        assert!(!state.has_launch());
    }

    /// A row's buttons act on the file at its path, so the file has to be
    /// the one the row is about. It counted as "still there" by its path
    /// alone, and as unchanged by its size alone.
    #[test]
    fn a_row_is_only_about_the_file_that_was_checked() {
        let scratch = Scratch::new("same-file");
        let file = scratch.0.join("Downloads").join("a.bin");
        std::fs::write(&file, b"0123456789").unwrap();
        let metadata = std::fs::metadata(&file).unwrap();
        let row = |bytes: u64, checked_at: &str| DownloadRecord {
            check: kam_scanner::downloads::DownloadCheck {
                path: file.to_string_lossy().into_owned(),
                name: "a.bin".to_owned(),
                bytes,
                sha256: "ab".to_owned(),
                arrived_at: None,
                origin: None,
                signature: None,
                scan: kam_scanner::defender_file::parse_report(Some(0), ""),
            },
            checked_at: checked_at.to_owned(),
            actions: Vec::new(),
            dissection: None,
            first_check: false,
        };
        let later = kam_core::clock::iso_from_unix_millis(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
                + 60_000,
        );
        assert!(still_the_file(&row(10, &later), &metadata));
        assert!(
            !still_the_file(&row(11, &later), &metadata),
            "another size is another file"
        );
        assert!(
            !still_the_file(&row(10, "2000-01-01T00:00:00.000Z"), &metadata),
            "written to since it was checked, at the same size"
        );
    }

    /// A row whose file is in quarantine names the item it can be put back
    /// from: the newest one still held that came from that very path.
    #[test]
    fn a_quarantined_download_can_be_put_back_from_its_own_row() {
        let path = r"C:\Users\me\Downloads\a.zip";
        let action = |undo: &str| kam_scanner::downloads::DownloadAction {
            at: String::new(),
            what: "Quarantined.".to_owned(),
            undo: Some(undo.to_owned()),
        };
        let record = DownloadRecord {
            check: kam_scanner::downloads::DownloadCheck {
                path: path.to_owned(),
                name: "a.zip".to_owned(),
                bytes: 1,
                sha256: "ab".to_owned(),
                arrived_at: None,
                origin: None,
                signature: None,
                scan: kam_scanner::defender_file::parse_report(Some(0), ""),
            },
            checked_at: String::new(),
            actions: vec![action("1-0001"), action("2-0002"), action("3-0003")],
            dissection: None,
            first_check: false,
        };
        let item = |id: &str, from: &str, restored: bool| kam_quarantine::Manifest {
            id: id.to_owned(),
            original_path: from.to_owned(),
            kind: kam_quarantine::ItemKind::File,
            bytes: 1,
            quarantined_at: 0,
            reason: String::new(),
            restored,
        };

        let held = [
            item("1-0001", path, false),
            item("2-0002", &path.to_uppercase(), false),
            item("3-0003", path, true),
        ];
        assert_eq!(held_as(&record, &held).as_deref(), Some("2-0002"));
        // Put back already, deleted since, or somebody else's file.
        assert_eq!(held_as(&record, &[item("3-0003", path, true)]), None);
        assert_eq!(held_as(&record, &[]), None);
        assert_eq!(
            held_as(
                &record,
                &[item("1-0001", r"C:\Users\me\Downloads\b.zip", false)]
            ),
            None
        );
    }

    #[test]
    fn the_downloads_folder_is_known() {
        let folder = known_folder().unwrap();
        assert!(folder.is_absolute(), "{}", folder.display());
    }

    // --- everything not checked yet ----------------------------------------

    /// The agent's answer to a check of `path` that came to `scan`.
    fn answer(path: &str, scan: kam_scanner::defender_file::FileScan) -> Response {
        Response::DownloadChecked(Box::new(DownloadRecord {
            check: kam_scanner::downloads::DownloadCheck {
                path: path.to_owned(),
                name: Path::new(path)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                bytes: 1,
                sha256: "ab".to_owned(),
                arrived_at: None,
                origin: None,
                signature: None,
                scan,
            },
            checked_at: String::new(),
            actions: Vec::new(),
            dissection: None,
            first_check: true,
        }))
    }

    fn nothing_found() -> kam_scanner::defender_file::FileScan {
        kam_scanner::defender_file::parse_report(Some(0), "")
    }

    /// Mark a scratch file the way Windows marks one whose contents are kept
    /// somewhere else. Offline is the one of the three attributes an
    /// ordinary program is allowed to set.
    fn mark_online_only(path: &Path) {
        use windows::core::HSTRING;
        use windows::Win32::Storage::FileSystem::{SetFileAttributesW, FILE_ATTRIBUTE_OFFLINE};
        unsafe { SetFileAttributesW(&HSTRING::from(path.as_os_str()), FILE_ATTRIBUTE_OFFLINE) }
            .unwrap();
    }

    /// Scratch files in a scratch Downloads folder, one for each name.
    fn scratch_files(scratch: &Scratch, names: &[&str]) -> Vec<PathBuf> {
        names
            .iter()
            .map(|name| {
                let path = scratch.0.join("Downloads").join(name);
                std::fs::write(&path, b"x").unwrap();
                path
            })
            .collect()
    }

    /// One run over `files`, with `agent` standing in for the service. Says
    /// which files it was asked about, in order.
    fn run_backlog(
        state: &Downloads,
        files: &[PathBuf],
        agent: &dyn Fn(&str) -> Asked,
    ) -> Vec<String> {
        let job = state.begin_backlog().unwrap();
        state.in_backlog(&job, |backlog| backlog.total = files.len());
        let asked = Mutex::new(Vec::new());
        work_through(
            state,
            &job,
            files,
            &|path, _, stage| {
                asked.lock().unwrap().push(path.to_owned());
                stage(Progress {
                    stage: "Asking Microsoft Defender".to_owned(),
                    done: 0,
                    total: None,
                    detail: None,
                });
                agent(path)
            },
            &|_| {},
        );
        asked.into_inner().unwrap()
    }

    /// One press for everything not checked yet. Each file is asked about
    /// as "Check now" asks. One that cannot be checked is named with why
    /// and the run goes on, and one stored only online is never read.
    #[test]
    fn everything_not_checked_is_worked_through_and_each_outcome_is_kept() {
        let scratch = Scratch::new("backlog");
        let files = scratch_files(
            &scratch,
            &["a.txt", "b.exe", "online.bin", "c.iso", "d.docx", "e.zip"],
        );
        mark_online_only(&files[2]);
        // Gone by the time its turn comes.
        std::fs::remove_file(&files[5]).unwrap();
        let text = |at: usize| files[at].to_string_lossy().into_owned();

        let state = Downloads::default();
        state.note_failure(
            &text(0),
            "Not checked when it arrived: the service did not answer".to_owned(),
        );
        let flagged = kam_scanner::defender_file::parse_report(
            Some(2),
            "Scanning C:\\b.exe found 1 threats.\r\nThreat : Trojan:Win32/Example\r\n\
             Resources : 1 total\r\n    file : C:\\b.exe\r\n",
        );
        let unfinished = kam_scanner::defender_file::parse_report(Some(2), "");
        assert_eq!(
            (flagged.answer, unfinished.answer),
            (Answer::Flagged, Answer::NotFinished)
        );

        let asked = run_backlog(&state, &files, &|path| match Path::new(path)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
        {
            "a.txt" => Ok(answer(path, nothing_found())),
            "b.exe" => Ok(answer(path, flagged.clone())),
            "c.iso" => Ok(answer(path, unfinished.clone())),
            "d.docx" => Ok(Response::Error {
                message: format!(
                    "{path} is open in another program that can still change it, so it was \
                         not checked."
                ),
            }),
            other => panic!("{other} should never have been read"),
        });
        assert_eq!(
            asked,
            [text(0), text(1), text(3), text(4)],
            "the file stored only online, or the one that had gone, was asked about"
        );

        let backlog = state.backlog().unwrap();
        assert_eq!(backlog.ended, Some(Ended::Finished));
        assert_eq!((backlog.total, backlog.done, backlog.checked), (6, 6, 3));
        assert_eq!(backlog.flagged, [text(1)]);
        assert_eq!(backlog.unfinished, [text(3)]);
        assert_eq!(backlog.online_only, [text(2)]);
        assert_eq!(
            backlog.failed,
            [
                Failure {
                    path: text(4),
                    message: "d.docx is open in another program that can still change it, so it \
                              was not checked."
                        .to_owned(),
                },
                Failure {
                    path: text(5),
                    message: "e.zip is no longer in Downloads.".to_owned(),
                },
            ]
        );
        assert!(backlog.current.is_none() && backlog.progress.is_none());

        // Under each file that is still there and still not checked: why.
        let failures = state.failures.lock().unwrap();
        assert!(
            !failures.contains_key(&text(0)),
            "a file that has now been checked still says why it was not"
        );
        assert!(failures[&text(2)].contains("stored only online"));
        assert!(failures[&text(4)].starts_with("Not checked: "));
        assert!(!failures.contains_key(&text(5)));
    }

    /// Stop ends the run with the file in hand, whose check is given up, and
    /// starts none of the files after it.
    #[test]
    fn stopping_abandons_the_file_in_hand_and_starts_no_other() {
        let scratch = Scratch::new("backlog-stop");
        let files = scratch_files(&scratch, &["a.txt", "b.txt", "c.txt", "d.txt"]);
        let text = |at: usize| files[at].to_string_lossy().into_owned();
        let state = Downloads::default();

        let asked = run_backlog(&state, &files, &|path| {
            if !path.ends_with("b.txt") {
                return Ok(answer(path, nothing_found()));
            }
            // Stop is pressed while this file is being checked. The check in
            // hand is named, so that the agent can be told to cancel it, and
            // the agent then answers that it stopped.
            let in_hand = state.ask_backlog_to_stop();
            assert!(
                matches!(&in_hand, Some(Some(check)) if check.ends_with("-2")),
                "{in_hand:?}"
            );
            Ok(Response::Stopped)
        });
        assert_eq!(asked, [text(0), text(1)], "a file after the stop was read");
        let backlog = state.backlog().unwrap();
        assert_eq!(
            backlog.ended,
            Some(Ended::Stopped {
                abandoned: Some(text(1))
            })
        );
        assert_eq!((backlog.total, backlog.done, backlog.checked), (4, 1, 1));
        assert!(!state.is_stopped(&backlog.job), "the stop outlived the run");
        assert_eq!(state.ask_backlog_to_stop(), None, "nothing is running now");

        // A check that finished before the stop reached it is kept, and the
        // run still ends there.
        state.close_backlog();
        assert!(state.backlog().is_none());
        let asked = run_backlog(&state, &files, &|path| {
            if path.ends_with("b.txt") {
                state.ask_backlog_to_stop();
            }
            Ok(answer(path, nothing_found()))
        });
        assert_eq!(asked.len(), 2);
        let backlog = state.backlog().unwrap();
        assert_eq!(backlog.ended, Some(Ended::Stopped { abandoned: None }));
        assert_eq!((backlog.done, backlog.checked), (2, 2));
    }

    /// A service that stops answering ends the run, in one sentence, and the
    /// files left are not each failed in turn. While a run is going a second
    /// press starts no second run, and what it has come to cannot be closed.
    #[test]
    fn a_service_that_stops_answering_ends_the_run_and_only_one_run_goes_at_a_time() {
        let scratch = Scratch::new("backlog-gone");
        let files = scratch_files(&scratch, &["a.txt", "b.txt", "c.txt"]);
        let state = Downloads::default();

        let asked = run_backlog(&state, &files, &|path| {
            assert!(
                state.begin_backlog().is_err(),
                "a second run was started beside the first"
            );
            state.close_backlog();
            assert!(state.backlog().is_some(), "a run in hand was closed away");
            if path.ends_with("b.txt") {
                Err("the pipe is not there".to_owned())
            } else {
                Ok(answer(path, nothing_found()))
            }
        });
        assert_eq!(asked.len(), 2, "the files left were each tried");
        let backlog = state.backlog().unwrap();
        assert_eq!(
            backlog.ended,
            Some(Ended::NoAnswer {
                reason: "the pipe is not there".to_owned()
            })
        );
        assert_eq!((backlog.total, backlog.done), (3, 1));
        assert!(backlog.failed.is_empty());

        state.close_backlog();
        assert!(state.backlog().is_none());
    }

    /// Whether a file is stored only online is read from its folder's
    /// listing, so that finding out cannot itself download it.
    #[test]
    fn a_file_stored_only_online_is_told_from_its_folders_listing() {
        // What OneDrive puts on a file it keeps online: archive, sparse,
        // reparse point, offline, unpinned, recall on data access.
        assert!(stored_only_online(0x0050_1620));
        for one in [0x1000, 0x4_0000, 0x40_0000] {
            assert!(stored_only_online(one | 0x20), "{one:#x}");
        }
        // Kept on this PC: plain, read-only, hidden, compressed, and pinned
        // ("Always keep on this device").
        for kept in [0x20, 0x21, 0x22, 0x820, 0x8_0020] {
            assert!(!stored_only_online(kept), "{kept:#x}");
        }

        let scratch = Scratch::new("online-only");
        let files = scratch_files(&scratch, &["here.bin"]);
        assert!(!stored_only_online(listed_attributes(&files[0]).unwrap()));
        mark_online_only(&files[0]);
        assert!(stored_only_online(listed_attributes(&files[0]).unwrap()));
        assert_eq!(
            listed_attributes(&scratch.0.join("Downloads").join("never.bin"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotFound
        );
    }

    /// The button is about the files the page shows as not checked: those
    /// with no check on record, or changed since the one there is.
    #[test]
    fn the_files_not_checked_are_those_with_no_check_that_is_still_about_them() {
        let scratch = Scratch::new("not-checked");
        let files = scratch_files(
            &scratch,
            &["checked.bin", "changed.bin", "never.bin", "half.crdownload"],
        );
        let later = kam_core::clock::iso_from_unix_millis(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
                + 60_000,
        );
        let row = |file: &Path, bytes: u64| {
            let Response::DownloadChecked(mut record) =
                answer(&file.to_string_lossy(), nothing_found())
            else {
                unreachable!()
            };
            record.check.bytes = bytes;
            record.checked_at = later.clone();
            *record
        };
        let records = [row(&files[0], 1), row(&files[1], 500)];

        let present = files_in(&scratch.0.join("Downloads")).unwrap();
        assert_eq!(present.len(), 3, "a download still in progress was listed");
        let mut loose: Vec<(String, bool)> = not_checked(&Downloads::default(), present, &records)
            .into_iter()
            .map(|file| (file.name, file.changed_since_checked))
            .collect();
        loose.sort();
        assert_eq!(
            loose,
            [
                ("changed.bin".to_owned(), true),
                ("never.bin".to_owned(), false)
            ]
        );
    }

    #[test]
    fn a_sentence_about_a_file_opens_with_its_name() {
        let path = r"C:\Users\me\Downloads\a.exe";
        assert_eq!(
            about("a.exe", path, &format!("{path} could not be found")),
            "a.exe could not be found"
        );
        assert_eq!(
            about("a.exe", path, "Defender's scanner could not be started"),
            "a.exe: Defender's scanner could not be started"
        );
    }
}
