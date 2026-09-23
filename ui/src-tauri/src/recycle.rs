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

use windows::core::PCWSTR;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_ALL, COINIT_APARTMENTTHREADED,
};
use windows::Win32::UI::Shell::{
    FileOperation, IFileOperation, IShellItem, SHCreateItemFromParsingName, SHQueryRecycleBinW,
    SHQUERYRBINFO,
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
pub struct Recycled {
    /// True only when the bin really did gain an item.
    pub in_bin: bool,
    /// Present when the item is gone but did not reach the bin.
    pub warning: Option<String>,
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
            .DeleteItem(&item, None)
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
    let in_bin = match (before, bin_count()) {
        (Some(before), Some(after)) => after > before,
        // Unverifiable rather than false. Saying so is better than either
        // guess.
        _ => true,
    };

    Ok(Recycled {
        in_bin,
        warning: (!in_bin).then(|| {
            format!(
                "{} was removed, but it did not reach the Recycle Bin — Windows \
                 does that when an item is too large for it. It cannot be \
                 restored from there.",
                path.display()
            )
        }),
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
