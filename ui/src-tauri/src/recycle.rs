//! Sending things to the Recycle Bin, from the window rather than the service.
//!
//! # Why this is here and not in the agent
//!
//! The Recycle Bin is per user. Every volume has a `$Recycle.Bin` with one
//! folder per SID inside it, and a delete performed by LocalSystem lands in
//! SYSTEM's folder — a real place, genuinely recoverable, that the person
//! sitting at the machine cannot see in Explorer and cannot restore from. That
//! is the same wrong-principal trap that has bitten this project in the
//! registry, in the disk survey and in the move fence: the privileged process
//! doing the work on the wrong account's behalf.
//!
//! So the window does it. The window runs as the person, which means the item
//! goes to *their* bin and comes back with a right-click in a program they
//! already know. It also means this needs no privilege whatsoever: anything
//! offered here is something they could have deleted in Explorer themselves,
//! and routing it through a LocalSystem service to achieve the same end would
//! be adding a privileged path for no reason.
//!
//! Quarantine still exists, and still goes through the agent, for the cases
//! that genuinely need it: paths a person cannot write, and anything where the
//! product wants to guarantee reversibility rather than rely on a bin the user
//! may empty. Permanent deletion is narrower still — see the quarantine view.
//!
//! # Never claim something is recoverable when it is not
//!
//! Windows permanently deletes rather than recycles when an item will not fit
//! in the bin, and with confirmations suppressed it does so silently. Telling
//! somebody their 12 GB folder is "in the Recycle Bin" when it has actually
//! been destroyed would be the worst thing this module could do, so the bin is
//! counted before and after and the answer says which really happened.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use windows::core::{implement, Ref, HRESULT, PCWSTR};
use windows::Win32::Foundation::E_ABORT;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_ALL, COINIT_APARTMENTTHREADED,
};
use windows::Win32::UI::Shell::{
    FileOperation, IFileOperation, IFileOperationProgressSink, IFileOperationProgressSink_Impl,
    IShellItem, SHCreateItemFromParsingName, SHQueryRecycleBinW, SHQUERYRBINFO,
    TSF_DELETE_RECYCLE_IF_POSSIBLE,
};

/// Suppress the confirmation prompt. The window has already asked.
const FOF_NOCONFIRMATION: u32 = 0x0010;
/// No progress dialog of Windows' own.
const FOF_SILENT: u32 = 0x0004;
/// No error dialog either; failures come back as values and are shown in place.
const FOF_NOERRORUI: u32 = 0x0400;
/// Recycle rather than delete. Documented to apply regardless of `FOF_ALLOWUNDO`.
const FOFX_RECYCLEONDELETE: u32 = 0x0008_0000;

/// What actually happened to an item.
///
/// Three outcomes, carried in two fields so the command that returns this
/// needs no change to pass them on:
///
/// - `in_bin` and no `warning`: the bin was counted before and after, and it
///   gained the item.
/// - not `in_bin`, with a `warning`: the bin was counted both times and did not
///   gain it, so Windows deleted it outright.
/// - `in_bin` with a `warning`: it was sent to the bin, but the bin could not be
///   counted, so whether it arrived is not known. The warning says so.
pub struct Recycled {
    /// False only when the bin was counted and did not gain the item.
    pub in_bin: bool,
    /// Present whenever the item is gone and arriving in the bin was not
    /// confirmed, whichever way that went.
    pub warning: Option<String>,
}

/// Whether an item reached the bin, as far as counting the bin can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arrival {
    /// The bin gained an item.
    Arrived,
    /// The bin was counted both times and did not grow.
    Missed,
    /// The bin could not be counted, before or after, so nothing is known.
    Unconfirmed,
}

/// Read the two counts. Not knowing is its own answer, never a yes.
fn arrival(before: Option<i64>, after: Option<i64>) -> Arrival {
    match (before, after) {
        (Some(before), Some(after)) if after > before => Arrival::Arrived,
        (Some(_), Some(_)) => Arrival::Missed,
        _ => Arrival::Unconfirmed,
    }
}

fn wide(text: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// How many items the bin holds, across all volumes it can be asked about.
///
/// `None` when it cannot be counted, which is treated as "cannot verify"
/// rather than as a failure: the count is a check on the claim, not the claim.
fn bin_count() -> Option<i64> {
    let mut info = SHQUERYRBINFO {
        cbSize: std::mem::size_of::<SHQUERYRBINFO>() as u32,
        ..Default::default()
    };
    // A null root asks about every volume, which is what we want: the item may
    // be on any of them.
    unsafe { SHQueryRecycleBinW(PCWSTR::null(), &mut info) }.ok()?;
    Some(info.i64NumItems)
}

/// COM, initialised for this call and left as it was found.
struct Com {
    uninitialise: bool,
}

impl Com {
    fn enter() -> Self {
        // A Tauri command runs on a pool thread that may or may not already
        // have COM up. Asking again is legal; `RPC_E_CHANGED_MODE` means
        // somebody else set a different model, in which case theirs stands and
        // this must not tear it down.
        let result = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        Self {
            uninitialise: result.is_ok(),
        }
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        if self.uninitialise {
            unsafe { CoUninitialize() };
        }
    }
}

/// Send one path to the Recycle Bin.
///
/// Fails rather than falling back to a permanent delete. If the item is gone
/// but the bin did not gain anything, that is reported in `warning` rather than
/// being quietly presented as a recycle.
pub fn to_recycle_bin(path: &Path) -> Result<Recycled, String> {
    send(path, None)
}

/// Send one path to the Recycle Bin, or leave it exactly where it is.
///
/// # Why there is a second way to do this
///
/// [`to_recycle_bin`] asks Windows to recycle and then counts the bin to see
/// whether it did. When an item is larger than the bin on its drive is set to
/// hold, or the bin is switched off for that drive, Windows deletes the item
/// outright, and with its own question suppressed it does so without a word.
/// The count then says so, afterwards. That is an honest report of something
/// that cannot be taken back.
///
/// For the leftovers and duplicate copies that function serves, the item is
/// usually small and the report has been judged enough. The list of large old
/// files is the opposite case in both respects: every row is large, which is
/// exactly when the bin cannot take it, and the list promises a Recycle Bin
/// button and no permanent delete. So that list uses this.
///
/// Windows tells whoever is watching a delete, before each item goes, whether
/// it is about to be recycled. [`RecycleOrStop`] watches, and stops the delete
/// when the answer is no. The file is then still there, and the person is
/// told why.
pub fn to_recycle_bin_or_leave(path: &Path) -> Result<Recycled, String> {
    let stopped = Arc::new(AtomicBool::new(false));
    let watcher: IFileOperationProgressSink = RecycleOrStop {
        stopped: Arc::clone(&stopped),
    }
    .into();

    let outcome = send(path, Some(&watcher));
    if !stopped.load(Ordering::SeqCst) {
        return outcome;
    }
    if path.exists() {
        return Err(format!(
            "{} was left where it is. Windows was not going to put it in the Recycle \
             Bin, and would have deleted it outright: that happens when a file is \
             larger than the Recycle Bin on its drive is set to hold, or when the bin \
             is switched off for that drive",
            path.display()
        ));
    }
    // Stopped, and gone all the same. Not expected, and not to be reported as
    // anything but what it is.
    Ok(Recycled {
        in_bin: false,
        warning: Some(format!(
            "{} was removed and did not reach the Recycle Bin, although Windows was \
             told to leave it. It cannot be restored from there.",
            path.display()
        )),
    })
}

/// Whether the flags Windows hands a watcher before a delete say the item is
/// about to be recycled.
///
/// The delete is asked for with "recycle if possible". Windows clears that
/// flag for an item it has decided it cannot recycle, and what it does next
/// to such an item is delete it.
fn will_be_recycled(flags: u32) -> bool {
    flags & (TSF_DELETE_RECYCLE_IF_POSSIBLE.0 as u32) != 0
}

/// Watches one delete, and stops it if the item is about to be destroyed
/// instead of recycled. See [`to_recycle_bin_or_leave`].
#[implement(IFileOperationProgressSink)]
struct RecycleOrStop {
    stopped: Arc<AtomicBool>,
}

// Windows calls every one of these as the operation goes along. Only the
// moment before a delete is of interest; the rest answer "carry on".
#[allow(non_snake_case)]
impl IFileOperationProgressSink_Impl for RecycleOrStop_Impl {
    fn PreDeleteItem(&self, dwflags: u32, _psiitem: Ref<IShellItem>) -> windows::core::Result<()> {
        if will_be_recycled(dwflags) {
            return Ok(());
        }
        self.stopped.store(true, Ordering::SeqCst);
        Err(E_ABORT.into())
    }

    fn StartOperations(&self) -> windows::core::Result<()> {
        Ok(())
    }

    fn FinishOperations(&self, _hrresult: HRESULT) -> windows::core::Result<()> {
        Ok(())
    }

    fn PreRenameItem(
        &self,
        _dwflags: u32,
        _psiitem: Ref<IShellItem>,
        _psznewname: &PCWSTR,
    ) -> windows::core::Result<()> {
        Ok(())
    }

    fn PostRenameItem(
        &self,
        _dwflags: u32,
        _psiitem: Ref<IShellItem>,
        _psznewname: &PCWSTR,
        _hrrename: HRESULT,
        _psinewlycreated: Ref<IShellItem>,
    ) -> windows::core::Result<()> {
        Ok(())
    }

    fn PreMoveItem(
        &self,
        _dwflags: u32,
        _psiitem: Ref<IShellItem>,
        _psidestinationfolder: Ref<IShellItem>,
        _psznewname: &PCWSTR,
    ) -> windows::core::Result<()> {
        Ok(())
    }

    fn PostMoveItem(
        &self,
        _dwflags: u32,
        _psiitem: Ref<IShellItem>,
        _psidestinationfolder: Ref<IShellItem>,
        _psznewname: &PCWSTR,
        _hrmove: HRESULT,
        _psinewlycreated: Ref<IShellItem>,
    ) -> windows::core::Result<()> {
        Ok(())
    }

    fn PreCopyItem(
        &self,
        _dwflags: u32,
        _psiitem: Ref<IShellItem>,
        _psidestinationfolder: Ref<IShellItem>,
        _psznewname: &PCWSTR,
    ) -> windows::core::Result<()> {
        Ok(())
    }

    fn PostCopyItem(
        &self,
        _dwflags: u32,
        _psiitem: Ref<IShellItem>,
        _psidestinationfolder: Ref<IShellItem>,
        _psznewname: &PCWSTR,
        _hrcopy: HRESULT,
        _psinewlycreated: Ref<IShellItem>,
    ) -> windows::core::Result<()> {
        Ok(())
    }

    fn PostDeleteItem(
        &self,
        _dwflags: u32,
        _psiitem: Ref<IShellItem>,
        _hrdelete: HRESULT,
        _psinewlycreated: Ref<IShellItem>,
    ) -> windows::core::Result<()> {
        Ok(())
    }

    fn PreNewItem(
        &self,
        _dwflags: u32,
        _psidestinationfolder: Ref<IShellItem>,
        _psznewname: &PCWSTR,
    ) -> windows::core::Result<()> {
        Ok(())
    }

    fn PostNewItem(
        &self,
        _dwflags: u32,
        _psidestinationfolder: Ref<IShellItem>,
        _psznewname: &PCWSTR,
        _psztemplatename: &PCWSTR,
        _dwfileattributes: u32,
        _hrnew: HRESULT,
        _psinewitem: Ref<IShellItem>,
    ) -> windows::core::Result<()> {
        Ok(())
    }

    fn UpdateProgress(&self, _iworktotal: u32, _iworksofar: u32) -> windows::core::Result<()> {
        Ok(())
    }

    fn ResetTimer(&self) -> windows::core::Result<()> {
        Ok(())
    }

    fn PauseTimer(&self) -> windows::core::Result<()> {
        Ok(())
    }

    fn ResumeTimer(&self) -> windows::core::Result<()> {
        Ok(())
    }
}

/// Ask Windows to recycle one path, with or without somebody watching.
fn send(path: &Path, watcher: Option<&IFileOperationProgressSink>) -> Result<Recycled, String> {
    if !path.exists() {
        return Err(format!("{} is not there", path.display()));
    }

    let _com = Com::enter();
    let text = wide(&path.to_string_lossy());
    let before = bin_count();

    unsafe {
        let operation: IFileOperation = CoCreateInstance(&FileOperation, None, CLSCTX_ALL)
            .map_err(|error| format!("the shell could not be asked to delete it: {error}"))?;

        operation
            .SetOperationFlags(windows::Win32::UI::Shell::FILEOPERATION_FLAGS(
                FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI | FOFX_RECYCLEONDELETE,
            ))
            .map_err(|error| format!("the delete could not be set up: {error}"))?;

        let item: IShellItem = SHCreateItemFromParsingName(PCWSTR(text.as_ptr()), None)
            .map_err(|error| format!("{} could not be opened: {error}", path.display()))?;

        operation
            .DeleteItem(&item, watcher)
            .map_err(|error| format!("{} could not be queued: {error}", path.display()))?;

        operation.PerformOperations().map_err(|error| {
            format!(
                "{} could not be moved to the Recycle Bin: {error}",
                path.display()
            )
        })?;

        if operation
            .GetAnyOperationsAborted()
            .unwrap_or_default()
            .as_bool()
        {
            return Err(format!("{} was not fully removed", path.display()));
        }
    }

    // Did it actually arrive? See the module note: the one thing this must not
    // do is call something recoverable when it is not.
    //
    // A bin that could not be counted used to come back as plainly "in the
    // bin", with nothing said. That is a guess presented as a check, so it is
    // now its own outcome, and the window says it could not confirm.
    Ok(match arrival(before, bin_count()) {
        Arrival::Arrived => Recycled {
            in_bin: true,
            warning: None,
        },
        Arrival::Missed => Recycled {
            in_bin: false,
            warning: Some(format!(
                "{} was removed, but it did not reach the Recycle Bin: Windows \
                 does that when an item is too large for it. It cannot be \
                 restored from there.",
                path.display()
            )),
        },
        Arrival::Unconfirmed => Recycled {
            in_bin: true,
            warning: Some(format!(
                "{} was sent to the Recycle Bin, but whether it arrived could not \
                 be confirmed, because the bin could not be counted. Look in the \
                 Recycle Bin before relying on getting it back.",
                path.display()
            )),
        },
    })
}

/// Whether the current account can delete this item without help.
///
/// Used to decide what to offer rather than to enforce anything: if the answer
/// is no, the window offers quarantine, which goes through the agent and its
/// fences. Getting it wrong costs a clear error message and nothing else.
///
/// It opens the item itself asking for delete access and nothing else, so
/// nothing is written and nothing is left behind. Windows grants that when the
/// item allows deleting it or its folder allows deleting what it holds, which
/// is the same decision it makes when the item is actually sent to the bin.
///
/// This replaced a probe that created and deleted a file of its own in the
/// folder above, and that asked the wrong question twice. The window passed it
/// the folder, and it then looked at the folder's parent. And adding a file of
/// your own is not the permission to delete one somebody else put there: most
/// shared folders, `ProgramData` among them, allow the first and not the
/// second, so the button was offered for leftovers it could not remove.
pub fn deletable_by_this_account(path: &Path) -> bool {
    use std::os::windows::fs::OpenOptionsExt;

    const DELETE: u32 = 0x0001_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    // A folder cannot be opened at all without backup semantics, and a link
    // is asked about as the link, which is what recycling it would remove.
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    std::fs::OpenOptions::new()
        .access_mode(DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .is_ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_file_goes_to_the_bin_and_can_be_found_there() {
        let scratch = std::env::temp_dir().join(format!("kam-recycle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let victim = scratch.join("throwaway.txt");
        std::fs::write(&victim, b"this can go").unwrap();

        let before = bin_count();
        let result = to_recycle_bin(&victim).expect("a small file should recycle");

        assert!(!victim.exists(), "the file is still on disk");
        assert!(
            result.in_bin,
            "a small file must reach the bin: {:?}",
            result.warning
        );
        assert!(result.warning.is_none());

        if let (Some(before), Some(after)) = (before, bin_count()) {
            assert!(after > before, "the bin did not gain an item");
        }

        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn the_flags_before_a_delete_say_whether_the_item_will_be_recycled() {
        let recycle = TSF_DELETE_RECYCLE_IF_POSSIBLE.0 as u32;
        assert!(will_be_recycled(recycle));
        assert!(will_be_recycled(recycle | 0x40 | 0x8));
        assert!(!will_be_recycled(0));
        // Other flags being set says nothing about the bin.
        assert!(!will_be_recycled(0x40 | 0x8));
    }

    /// The watcher lets a delete that is going to the bin go ahead, and stops
    /// one that is not, when called the way Windows calls it.
    ///
    /// A real delete that Windows would refuse to recycle cannot be arranged
    /// here without changing how the Recycle Bin on this machine is set up,
    /// which a test must not do. So the watcher is handed the flags Windows
    /// would hand it, through the same interface.
    #[test]
    fn the_watcher_stops_a_delete_that_would_destroy_the_item_and_no_other() {
        let stopped = Arc::new(AtomicBool::new(false));
        let watcher: IFileOperationProgressSink = RecycleOrStop {
            stopped: Arc::clone(&stopped),
        }
        .into();
        let recycle = TSF_DELETE_RECYCLE_IF_POSSIBLE.0 as u32;

        unsafe { watcher.PreDeleteItem(recycle, None) }
            .expect("a delete that is going to the bin was stopped");
        assert!(!stopped.load(Ordering::SeqCst));

        let refusal = unsafe { watcher.PreDeleteItem(0, None) }
            .expect_err("a delete that would destroy the item was let through");
        assert_eq!(refusal.code(), E_ABORT);
        assert!(stopped.load(Ordering::SeqCst));
    }

    /// Being watched changes nothing for a file the bin can take: it goes to
    /// the bin as before. This is also what shows, on the machine the tests
    /// run on, that Windows does hand the watcher "recycle if possible" for a
    /// file it is going to recycle. If it did not, every use of this would
    /// leave the file where it was.
    #[test]
    fn a_file_the_bin_can_take_still_goes_to_it_when_the_delete_is_watched() {
        let scratch =
            std::env::temp_dir().join(format!("kam-recycle-watched-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let victim = scratch.join("throwaway.txt");
        std::fs::write(&victim, b"this can go").unwrap();

        let result = to_recycle_bin_or_leave(&victim).expect("a small file should recycle");
        assert!(!victim.exists(), "the file is still on disk");
        assert!(
            result.in_bin,
            "a small file must reach the bin: {:?}",
            result.warning
        );

        let _ = std::fs::remove_dir_all(&scratch);
    }

    /// A bin that cannot be counted is neither a yes nor a no.
    ///
    /// It was read as a yes, so the window said "Sent to the Recycle Bin"
    /// without having checked.
    #[test]
    fn an_uncountable_bin_is_its_own_answer() {
        assert_eq!(arrival(Some(3), Some(4)), Arrival::Arrived);
        assert_eq!(arrival(Some(3), Some(3)), Arrival::Missed);
        assert_eq!(arrival(Some(3), Some(2)), Arrival::Missed);
        assert_eq!(arrival(None, Some(4)), Arrival::Unconfirmed);
        assert_eq!(arrival(Some(3), None), Arrival::Unconfirmed);
        assert_eq!(arrival(None, None), Arrival::Unconfirmed);
    }

    #[test]
    fn a_path_that_is_not_there_is_refused_rather_than_reported_as_recycled() {
        let absent = std::env::temp_dir().join("kam-recycle-never-existed");
        let _ = std::fs::remove_file(&absent);
        assert!(to_recycle_bin(&absent).is_err());
    }

    /// Both answers, without asking whether Windows is feeling permissive.
    ///
    /// This used to assert that `C:\Windows\System32\kernel32.dll` was not
    /// deletable, which is true for the account a person actually runs as and
    /// false on a build agent, where the account is an administrator and can
    /// genuinely write there. That assertion was about Windows' permissions
    /// rather than about this function, and it broke the build for a day.
    ///
    /// The negative case is a path that does not exist, which no privilege can
    /// delete: a property of the function rather than of whoever runs it.
    #[test]
    fn an_item_of_ones_own_is_deletable_and_a_missing_one_is_not() {
        let scratch = std::env::temp_dir().join(format!("kam-writable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let mine = scratch.join("thing.txt");
        std::fs::write(&mine, b"x").unwrap();

        assert!(deletable_by_this_account(&mine), "a file of one's own");
        assert!(deletable_by_this_account(&scratch), "a folder of one's own");
        assert!(!deletable_by_this_account(
            &scratch.join("no-such-thing.txt")
        ));
        assert!(!deletable_by_this_account(Path::new("")));

        // Asking wrote nothing: the folder holds exactly what the test put
        // there. The probe this replaced created a file of its own, and left
        // it behind if it was interrupted.
        let entries = std::fs::read_dir(&scratch).unwrap().count();
        assert_eq!(entries, 1, "checking left something behind");

        let _ = std::fs::remove_dir_all(&scratch);
    }

    /// Being allowed to add a file is not being allowed to delete one.
    ///
    /// The shape of `ProgramData` and most shared folders, rebuilt in a scratch
    /// folder with deny entries, which bind an administrator too, so the answer
    /// is the same on a build agent: this account may create a file there and
    /// delete that file, but may not delete the one already present. The probe
    /// this function replaced said yes to it, and the window offered the
    /// Recycle Bin for a leftover it could not remove.
    #[test]
    fn adding_a_file_somewhere_is_not_permission_to_delete_what_is_there() {
        fn icacls(args: &[&str]) {
            let output = std::process::Command::new("icacls")
                .args(args)
                .output()
                .expect("icacls runs");
            assert!(output.status.success(), "icacls {args:?} failed");
        }

        /// Takes the deny entries off again, however the test ends, so the
        /// folder can be removed.
        struct Undeny<'a> {
            folder: &'a str,
            item: &'a str,
        }
        impl Drop for Undeny<'_> {
            fn drop(&mut self) {
                for path in [self.item, self.folder] {
                    let _ = std::process::Command::new("icacls")
                        .args([path, "/remove:d", "*S-1-1-0"])
                        .output();
                }
                let _ = std::fs::remove_dir_all(self.folder);
            }
        }

        let scratch = std::env::temp_dir().join(format!("kam-shared-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let theirs = scratch.join("put-here-by-someone-else.txt");
        std::fs::write(&theirs, b"x").unwrap();

        let folder = scratch.to_str().unwrap();
        let item = theirs.to_str().unwrap();
        let _undeny = Undeny { folder, item };
        // Everyone is denied deleting the item (DE, delete and nothing else)
        // and deleting what the folder holds (DC). Adding to the folder is
        // untouched.
        icacls(&[item, "/deny", "*S-1-1-0:(DE)"]);
        icacls(&[folder, "/deny", "*S-1-1-0:(DC)"]);

        // The case is real: a file of one's own can still be added and deleted.
        let mine = scratch.join("mine.txt");
        std::fs::write(&mine, b"x").expect("adding a file is still allowed");
        std::fs::remove_file(&mine).expect("and deleting one's own file");

        assert!(
            !deletable_by_this_account(&theirs),
            "offered to delete a file this account may not delete"
        );
    }
}
