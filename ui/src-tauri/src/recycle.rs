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
//! been destroyed would be the worst thing this module could do.
//!
//! Counting the bin before and after only found that out once it was too late.
//! So Windows is now asked to warn before destroying anything
//! (`FOF_WANTNUKEWARNING`, which exists for exactly this and overrides the
//! suppressed confirmation for this one case): an item too large for the bin
//! brings up Windows' own "delete permanently?" question, and saying no leaves
//! it where it was. A drive with no Recycle Bin at all is refused before
//! anything is attempted. The count before and after stays, as a check on the
//! claim rather than as the only thing standing between a person and a
//! permanent delete.

use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::{
    GetDriveTypeW, GetVolumePathNameW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
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
/// Warn before destroying something that cannot be recycled, even with the
/// confirmation otherwise suppressed. See the module note.
const FOF_WANTNUKEWARNING: u32 = 0x4000;

/// `GetDriveTypeW`'s answer for a fixed disk, the only kind with a Recycle Bin
/// that belongs to the person. Removable drives and network shares delete
/// outright.
const DRIVE_FIXED: u32 = 3;

/// Delete access, asked for on its own.
const DELETE: u32 = 0x0001_0000;

/// The flags every recycle is performed with, in one place so a test can hold
/// them to it.
fn operation_flags() -> u32 {
    FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI | FOFX_RECYCLEONDELETE | FOF_WANTNUKEWARNING
}

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
    if !drive_has_a_bin(path) {
        return Err(format!(
            "{} is on a drive with no Recycle Bin, so this would delete it permanently. \
             Quarantine can move it aside instead.",
            path.display()
        ));
    }

    let _com = Com::enter();
    let text = wide(&path.to_string_lossy());
    let before = bin_count();

    unsafe {
        let operation: IFileOperation = CoCreateInstance(&FileOperation, None, CLSCTX_ALL)
            .map_err(|error| format!("the shell could not be asked to delete it: {error}"))?;

        operation
            .SetOperationFlags(windows::Win32::UI::Shell::FILEOPERATION_FLAGS(
                operation_flags(),
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
            // Usually the answer to Windows' "delete permanently?" question,
            // for an item too large for the bin.
            return Err(if path.exists() {
                format!(
                    "{} was not deleted. Windows could not put it in the Recycle Bin, \
                     probably because it is too large for it, and would only have \
                     deleted it permanently. Quarantine can move it aside instead.",
                    path.display()
                )
            } else {
                format!(
                    "{} was only partly removed before Windows stopped.",
                    path.display()
                )
            });
        }
    }

    // Did it actually arrive? See the module note: the one thing this must not
    // do is call something recoverable when it is not.
    let (in_bin, warning) = match (before, bin_count()) {
        (Some(before), Some(after)) if after > before => (true, None),
        (Some(_), Some(_)) => (
            false,
            Some(format!(
                "{} was removed, but the Recycle Bin did not gain it, so it cannot be \
                 restored from there.",
                path.display()
            )),
        ),
        // Unverifiable. Windows was told to recycle it and to warn before
        // destroying it, so it most likely arrived, but "most likely" is said
        // as such rather than as a fact.
        _ => (
            true,
            Some(
                "It was sent to the Recycle Bin, but the bin could not be checked \
                 afterwards to confirm it arrived."
                    .to_owned(),
            ),
        ),
    };

    Ok(Recycled { in_bin, warning })
}

/// Whether the drive holding `path` has a Recycle Bin of the person's own.
fn drive_has_a_bin(path: &Path) -> bool {
    let text = wide(&path.to_string_lossy());
    let mut root = [0_u16; 261];
    if unsafe { GetVolumePathNameW(PCWSTR(text.as_ptr()), &mut root) }.is_err() {
        return false;
    }
    unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) == DRIVE_FIXED }
}

/// Whether this account could send this item to its Recycle Bin.
///
/// Used to decide whether to offer the button at all. Both halves matter: the
/// drive has to have a bin, and this account has to be allowed to delete the
/// item, which is asked of Windows directly (see `can_delete`).
pub fn can_recycle(path: &Path) -> bool {
    drive_has_a_bin(path) && can_delete(path)
}

/// Whether Windows would let this account delete this item.
///
/// Opens the item itself asking for delete access and nothing else, so no file
/// is written and nothing is left behind. Windows grants that when the item
/// allows deleting it or its folder allows deleting what it holds, which is
/// the same decision it makes when the item is actually removed.
///
/// This replaced a probe that created and deleted a file of its own in the
/// folder above. That asked a different question: most shared folders let an
/// ordinary account add a file and delete that file, while not letting it
/// delete anything anybody else put there. So the button was offered for
/// things it could not remove.
fn can_delete(path: &Path) -> bool {
    std::fs::OpenOptions::new()
        .access_mode(DELETE)
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
        // Opens a folder as well as a file, and a link as the link itself.
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
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
    /// An earlier version asserted that `kernel32.dll` was not deletable, which
    /// is true for a person's own account and false on a build agent running as
    /// an administrator; it broke the build for a day. The negative case is a
    /// path that does not exist, which no privilege can delete.
    #[test]
    fn an_item_of_ones_own_can_be_recycled_and_a_missing_one_cannot() {
        let scratch = std::env::temp_dir().join(format!("kam-writable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let mine = scratch.join("thing.txt");
        std::fs::write(&mine, b"x").unwrap();

        assert!(
            can_recycle(&mine),
            "a file of one's own in temp could not be recycled"
        );
        assert!(
            can_recycle(&scratch),
            "a folder of one's own could not be recycled"
        );
        assert!(!can_recycle(&scratch.join("no-such-thing.txt")));

        // Checking wrote nothing: the folder holds exactly what the test put
        // there. The probe this replaced left a file of its own behind if it
        // was interrupted.
        let entries = std::fs::read_dir(&scratch).unwrap().count();
        assert_eq!(entries, 1, "checking left something behind");

        let _ = std::fs::remove_dir_all(&scratch);
    }

    /// The flags that stand between a person and a permanent delete.
    #[test]
    fn every_recycle_asks_windows_to_warn_before_destroying() {
        let flags = operation_flags();
        assert_ne!(
            flags & FOF_WANTNUKEWARNING,
            0,
            "the permanent-delete warning is off"
        );
        assert_ne!(flags & FOFX_RECYCLEONDELETE, 0, "recycling is off");
    }

    /// The temporary folder is on the system drive, which is a fixed disk.
    #[test]
    fn the_system_drive_has_a_bin() {
        assert!(drive_has_a_bin(&std::env::temp_dir()));
    }
}
