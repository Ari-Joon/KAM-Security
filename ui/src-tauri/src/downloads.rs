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
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::Mutex;
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
struct Session {
    copy: PathBuf,
    name: String,
    sha256: String,
    zone: Option<Vec<u8>>,
    dissection: Dissection,
}

/// Everything the Downloads half keeps between calls.
pub struct Downloads {
    watch: Mutex<WatchStatus>,
    /// Why an automatic check of a file did not happen, by path.
    failures: Mutex<HashMap<String, String>>,
    /// A file somebody asked about from outside the window, waiting for the
    /// page to pick it up.
    pending: Mutex<Option<Launch>>,
    sessions: Mutex<HashMap<String, Session>>,
}

impl Default for Downloads {
    fn default() -> Self {
        Self {
            watch: Mutex::new(WatchStatus::Starting),
            failures: Mutex::new(HashMap::new()),
            pending: Mutex::new(None),
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

impl Downloads {
    fn set_watch(&self, status: WatchStatus) {
        if let Ok(mut watch) = self.watch.lock() {
            *watch = status;
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
    history_error: Option<String>,
    unchecked: Vec<LooseFile>,
    failures: Vec<Failure>,
    menu: MenuState,
    protection: Option<bool>,
    /// Why notices about new downloads will not be seen, when Windows says
    /// they will not, or cannot say.
    notifications: Option<String>,
}

/// Gather the page: the history from the agent, and the folder as it is now.
pub fn page(state: &Downloads) -> Page {
    let (records, history_error) = match kam_ipc::client::call(&Request::ListDownloads) {
        Ok(Response::Downloads { records }) => (records, None),
        Ok(Response::Error { message }) => (Vec::new(), Some(message)),
        Ok(other) => (
            Vec::new(),
            Some(format!(
                "the agent answered something unexpected: {other:?}"
            )),
        ),
        Err(error) => (Vec::new(), Some(error.to_string())),
    };
    let protection = match kam_ipc::client::call(&Request::GetProtection) {
        Ok(Response::Protection { enabled }) => Some(enabled),
        _ => None,
    };

    let folder = known_folder();
    let mut unchecked = Vec::new();
    let mut folder_error = None;
    if let Ok(folder) = &folder {
        match std::fs::read_dir(folder) {
            Ok(listing) => {
                for item in listing.flatten() {
                    let Ok(metadata) = item.metadata() else {
                        continue;
                    };
                    if !metadata.is_file() {
                        continue;
                    }
                    let name = item.file_name().to_string_lossy().into_owned();
                    if is_partial(&name) {
                        continue;
                    }
                    let path = item.path().to_string_lossy().into_owned();
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
            }
            Err(error) => {
                folder_error = Some(format!("your Downloads folder could not be read: {error}"))
            }
        }
    }
    unchecked.sort_by(|a, b| b.arrived_at.cmp(&a.arrived_at));

    let records = records
        .into_iter()
        .map(|record| PageRecord {
            present: Path::new(&record.check.path).is_file(),
            archive: archive_label(&record.check.name),
            record,
        })
        .collect();
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
        history_error,
        unchecked,
        failures,
        menu: crate::context_menu::state(),
        protection,
        notifications: crate::notice::delivery_problem(),
    }
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

/// What the page gets back from taking an archive apart.
#[derive(Debug, Serialize)]
pub struct DissectionView {
    token: String,
    dissection: Dissection,
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

/// Take a zip apart. `None` when it was stopped. See the module notes.
pub fn dissect(app: &AppHandle, path: &str, job: &str) -> Result<Option<DissectionView>, String> {
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
    let earlier = match kam_ipc::client::call(&Request::ListDownloads) {
        Ok(Response::Downloads { records }) => records
            .into_iter()
            .find(|record| record.check.path.eq_ignore_ascii_case(&original)),
        _ => None,
    };
    let known_flagged = earlier
        .as_ref()
        .is_some_and(|record| record.check.scan.answer == Answer::Flagged);

    let mut zone_stream = real.clone().into_os_string();
    zone_stream.push(":Zone.Identifier");
    let zone = std::fs::read(PathBuf::from(zone_stream)).ok();

    emit_stage(app, job, "Making a private copy to take apart");
    let copy = crate::archive::working_copy(&real)?;

    // Quarantined first, as asked, when Defender has already flagged it.
    let mut fate = OriginalFate::default();
    let mut tried = false;
    if known_flagged {
        emit_stage(app, job, "Quarantining the original");
        fate = quarantine_original(&original);
        tried = true;
    }

    let channel = format!("job://{job}");
    let checked = kam_ipc::client::call_streaming(
        &Request::CheckDownload {
            path: copy.to_string_lossy().into_owned(),
            job: job.to_owned(),
            copy_of: Some(original.clone()),
        },
        |progress| {
            let _ = app.emit(&channel, progress);
        },
    );
    let record = match checked {
        Ok(Response::DownloadChecked(record)) => record,
        Ok(Response::Stopped) => {
            crate::archive::discard(&copy);
            return Ok(None);
        }
        Ok(Response::Error { message }) => {
            crate::archive::discard(&copy);
            return Err(message);
        }
        Ok(other) => {
            crate::archive::discard(&copy);
            return Err(format!(
                "the agent answered something unexpected: {other:?}"
            ));
        }
        Err(error) => {
            crate::archive::discard(&copy);
            return Err(error.to_string());
        }
    };

    // Flagged only now: quarantined before anything is taken apart.
    if record.check.scan.answer == Answer::Flagged && !tried {
        emit_stage(app, job, "Quarantining the original");
        fate = quarantine_original(&original);
    }

    emit_stage(app, job, "Reading the archive's list of files");
    let entries = match crate::archive::entries(&copy) {
        Ok(entries) => entries,
        Err(reason) => {
            crate::archive::discard(&copy);
            return Err(format!("{name} could not be taken apart: {reason}"));
        }
    };
    let mut dissection = kam_scanner::downloads::dissect(
        &original,
        &record.check.sha256,
        record.check.scan.clone(),
        &entries,
    );
    dissection.original = fate;

    if let Err(error) = kam_ipc::client::call(&Request::RecordDissection {
        path: original.clone(),
        sha256: record.check.sha256.clone(),
        dissection: Box::new(dissection.clone()),
    }) {
        eprintln!("what the archive holds could not be recorded: {error}");
    }

    let token = format!(
        "{job}-{}",
        record.check.sha256.get(..12).unwrap_or_default()
    );
    let view = DissectionView {
        token: token.clone(),
        dissection: dissection.clone(),
    };
    if let Ok(mut sessions) = app.state::<Downloads>().sessions.lock() {
        sessions.insert(
            token,
            Session {
                copy,
                name,
                sha256: record.check.sha256.clone(),
                zone,
                dissection,
            },
        );
    }
    Ok(Some(view))
}

/// Extract what Defender found nothing in, record it, and delete the copy.
pub fn extract(state: &Downloads, token: &str) -> Result<Extraction, String> {
    let session = state
        .sessions
        .lock()
        .ok()
        .and_then(|mut sessions| sessions.remove(token))
        .ok_or("That archive is no longer open here. Take it apart again to extract from it.")?;
    let parent = known_folder()?;
    let outcome = crate::archive::extract(
        &session.copy,
        &session.dissection,
        &parent,
        &session.name,
        session.zone.as_deref(),
    );
    crate::archive::discard(&session.copy);
    let extraction = outcome?;
    if let Err(error) = kam_ipc::client::call(&Request::RecordExtraction {
        path: session.dissection.archive.clone(),
        sha256: session.sha256.clone(),
        extraction: extraction.clone(),
    }) {
        eprintln!("the extraction could not be recorded: {error}");
    }
    Ok(extraction)
}

/// Close an archive without extracting, deleting the private copy.
pub fn discard(state: &Downloads, token: &str) {
    if let Some(session) = state
        .sessions
        .lock()
        .ok()
        .and_then(|mut sessions| sessions.remove(token))
    {
        crate::archive::discard(&session.copy);
    }
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

    #[test]
    fn the_downloads_folder_is_known() {
        let folder = known_folder().unwrap();
        assert!(folder.is_absolute(), "{}", folder.display());
    }
}
