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

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use kam_core::Progress;
use kam_ipc::{Request, Response};
use kam_scanner::defender_file::Answer;
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
    /// A file somebody asked about from outside the window, waiting for the
    /// page to pick it up.
    pending: Mutex<Option<Launch>>,
    /// The archive that is open, if one is. One at a time: taking another
    /// apart closes it, and so does closing the window.
    open: Mutex<Option<Arc<Session>>>,
    /// Jobs somebody asked to stop while the work was this program's own and
    /// not yet the agent's: copying an archive, or quarantining its original.
    stopped: Mutex<HashSet<String>>,
}

impl Default for Downloads {
    fn default() -> Self {
        Self {
            watch: Mutex::new(WatchStatus::Starting),
            failures: Mutex::new(HashMap::new()),
            pending: Mutex::new(None),
            open: Mutex::new(None),
            stopped: Mutex::new(HashSet::new()),
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

    /// Remember a file somebody asked about from outside the window.
    pub fn set_launch(&self, launch: Launch) {
        if let Ok(mut pending) = self.pending.lock() {
            *pending = Some(launch);
        }
    }

    /// The waiting request, once.
    pub fn take_launch(&self) -> Option<Launch> {
        self.pending
            .lock()
            .ok()
            .and_then(|mut pending| pending.take())
    }

    /// Whether a request is waiting, without taking it.
    pub fn has_launch(&self) -> bool {
        self.pending.lock().is_ok_and(|pending| pending.is_some())
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
}

#[derive(Debug, Serialize)]
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
    history_error: Option<String>,
    unchecked: Vec<LooseFile>,
    failures: Vec<Failure>,
    /// The archive that was taken apart and is still open, so that leaving
    /// the page and coming back finds it again.
    open: Option<OpenArchive>,
    /// Why it could not be told which quarantined downloads can be put back.
    quarantine_error: Option<String>,
    menu: MenuState,
    protection: Option<bool>,
    /// Why notices about new downloads will not be seen, when Windows says
    /// they will not, or cannot say.
    notifications: Option<String>,
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

/// Gather the page: the folder as it is now, and the history from the agent.
pub fn page(state: &Downloads) -> Page {
    let folder = known_folder();
    let mut present: Vec<(String, String, std::fs::Metadata)> = Vec::new();
    let mut folder_error = None;
    if let Ok(folder) = &folder {
        match std::fs::read_dir(folder) {
            Ok(listing) => {
                for item in listing.flatten() {
                    let Ok(metadata) = item.metadata() else {
                        continue;
                    };
                    let name = item.file_name().to_string_lossy().into_owned();
                    if metadata.is_file() && !is_partial(&name) {
                        present.push((item.path().to_string_lossy().into_owned(), name, metadata));
                    }
                }
            }
            Err(error) => {
                folder_error = Some(format!("your Downloads folder could not be read: {error}"))
            }
        }
    }

    // The files in the folder are named in the request, so each one's row
    // comes back however long ago it was checked. Asked for only by recency,
    // a file checked before the newest thousand read as never checked.
    let named = present.iter().map(|(path, _, _)| path.clone()).collect();
    let (records, on_record, history_error) = match history(named, RECENT_ROWS) {
        Ok((records, on_record)) => (records, on_record, None),
        Err(reason) => (Vec::new(), 0, Some(reason)),
    };
    let protection = match kam_ipc::client::call(&Request::GetProtection) {
        Ok(Response::Protection { enabled }) => Some(enabled),
        _ => None,
    };

    let mut unchecked = Vec::new();
    for (path, name, metadata) in present {
        let latest = records
            .iter()
            .find(|record| record.check.path.eq_ignore_ascii_case(&path));
        if latest.is_some_and(|record| record.check.bytes == metadata.len()) {
            continue;
        }
        unchecked.push(LooseFile {
            archive: archive_label(&name),
            arrived_at: created_iso(&metadata),
            bytes: metadata.len(),
            changed_since_checked: latest.is_some(),
            name,
            path,
        });
    }
    unchecked.sort_by(|a, b| b.arrived_at.cmp(&a.arrived_at));

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

    let records = records
        .into_iter()
        .map(|record| {
            let present = Path::new(&record.check.path).is_file();
            PageRecord {
                held: (!present).then(|| held_as(&record, &held)).flatten(),
                present,
                archive: archive_label(&record.check.name),
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
        history_error,
        unchecked,
        failures,
        open,
        quarantine_error,
        menu: crate::context_menu::state(),
        protection,
        notifications: crate::notice::delivery_problem(),
    }
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
    /// A name appeared, or was renamed into place.
    Arrived(PathBuf),
    /// A name already there was written to.
    Changed(PathBuf),
    /// Windows lost count of what changed; look at everything recent.
    Overflowed,
}

/// Start watching the Downloads folder. Returns at once; the work happens on
/// threads of its own and never on the window's.
pub fn start_watching(app: AppHandle) {
    let (seen_tx, seen_rx) = mpsc::channel::<Seen>();
    let (ready_tx, ready_rx) = mpsc::channel::<PathBuf>();

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
    let _ = std::thread::Builder::new()
        .name("kam-downloads-settle".to_owned())
        .spawn(move || settle(&seen_rx, &ready_tx));
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
                1 | 5 => events.push(Seen::Arrived(path)),
                3 => events.push(Seen::Changed(path)),
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
}

/// Hold each arriving file until it stops changing, then pass it on.
///
/// Waits on the channel with no timeout while nothing is settling, so it
/// costs nothing when nothing is arriving.
fn settle(seen: &Receiver<Seen>, ready: &Sender<PathBuf>) {
    let mut settling: HashMap<PathBuf, Settling> = HashMap::new();
    loop {
        let event = if settling.is_empty() {
            seen.recv().map_err(|_| RecvTimeoutError::Disconnected)
        } else {
            seen.recv_timeout(SETTLE / 2)
        };
        match event {
            Ok(Seen::Arrived(path)) => {
                settling.insert(path, fresh());
            }
            Ok(Seen::Changed(path)) => {
                if let Some(entry) = settling.get_mut(&path) {
                    *entry = fresh();
                }
            }
            Ok(Seen::Overflowed) => {
                for path in recent_files(Duration::from_secs(600)) {
                    settling.entry(path).or_insert_with(fresh);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }

        let mut finished = Vec::new();
        let mut gone = Vec::new();
        for (path, entry) in &mut settling {
            if entry.looked.elapsed() < SETTLE {
                continue;
            }
            match std::fs::symlink_metadata(path) {
                Ok(metadata) if metadata.is_file() => {
                    let size = Some(metadata.len());
                    let written = metadata.modified().ok();
                    let steady = entry.size == size && entry.written == written;
                    if steady && crate::archive::open_shut_to_writers(path).is_ok() {
                        finished.push(path.clone());
                    } else {
                        entry.size = size;
                        entry.written = written;
                        entry.looked = Instant::now();
                    }
                }
                // Gone, a folder, or a link: not a download to check.
                _ => gone.push(path.clone()),
            }
        }
        for path in gone {
            settling.remove(&path);
        }
        for path in finished {
            settling.remove(&path);
            if ready.send(path).is_err() {
                return;
            }
        }
    }
}

/// Not looked at yet: the first look only records the size.
fn fresh() -> Settling {
    Settling {
        size: None,
        written: None,
        looked: Instant::now()
            .checked_sub(SETTLE)
            .unwrap_or_else(Instant::now),
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

/// Ask the agent about each finished file, one at a time.
fn check_arrivals(app: &AppHandle, ready: &Receiver<PathBuf>) {
    // Windows' notification interfaces want the thread set up for COM.
    unsafe {
        let _ = windows::Win32::System::Com::CoInitializeEx(
            None,
            windows::Win32::System::Com::COINIT_MULTITHREADED,
        );
    }
    let mut done: HashSet<(PathBuf, u64, Option<SystemTime>)> = HashSet::new();
    let mut counter = 0_u64;
    while let Ok(path) = ready.recv() {
        let Ok(metadata) = std::fs::metadata(&path) else {
            continue;
        };
        // The same file, unchanged, is not checked twice in one run.
        if !done.insert((path.clone(), metadata.len(), metadata.modified().ok())) {
            continue;
        }
        counter += 1;
        check_one(
            app,
            &path,
            &format!("arrival-{}-{counter}", std::process::id()),
        );
    }
}

fn check_one(app: &AppHandle, path: &Path, job: &str) {
    let state = app.state::<Downloads>();
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
    match kam_ipc::client::call(&request) {
        Ok(Response::DownloadChecked(record)) => {
            note(None);
            if record.first_check {
                announce(app, &record);
            }
        }
        Ok(Response::Error { message }) => {
            note(Some(format!("Not checked when it arrived: {message}")))
        }
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
    let (title, body) = crate::notice::sentence(&record.check.name, &record.check.scan);
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
        let third = record(3, "notes.txt", 0);
        let bytes = [first, second, third].concat();

        let events = parse_notifications(&bytes, Path::new(r"C:\Users\me\Downloads"));
        assert_eq!(events.len(), 2, "the partial name should be ignored");
        assert!(matches!(&events[0], Seen::Arrived(path) if path.ends_with("setup.exe")));
        assert!(matches!(&events[1], Seen::Changed(path) if path.ends_with("notes.txt")));
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

        let (seen_tx, seen_rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel();
        let settler = std::thread::spawn(move || settle(&seen_rx, &ready_tx));
        seen_tx.send(Seen::Arrived(path.clone())).unwrap();

        // Still growing, and held open for writing: nothing comes out.
        for _ in 0..3 {
            writer.write_all(&[0_u8; 1024]).unwrap();
            writer.flush().unwrap();
            assert!(ready_rx.recv_timeout(Duration::from_millis(1500)).is_err());
        }
        drop(writer);
        let finished = ready_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("it never settled");
        assert_eq!(finished, path);

        drop(seen_tx);
        settler.join().unwrap();
        let _ = std::fs::remove_dir_all(&folder);
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
}
