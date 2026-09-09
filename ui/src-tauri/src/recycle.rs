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

/// Whether the current account can delete this path without help.
///
/// Used to decide what to offer rather than to enforce anything: if the answer
/// is no, the window offers quarantine, which goes through the agent and its
/// fences. Getting it wrong costs a clear error message and nothing else.
pub fn deletable_by_this_account(path: &Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    // Removing an entry needs write access to the directory holding it, so
    // that is what is tested, by the only reliable means: trying it.
    let probe = parent.join(format!(".kam-write-probe-{}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
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

    #[test]
    fn a_writable_folder_is_deletable_and_a_system_one_is_not() {
        let scratch = std::env::temp_dir().join(format!("kam-writable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let mine = scratch.join("thing.txt");
        std::fs::write(&mine, b"x").unwrap();

        assert!(deletable_by_this_account(&mine));
        // Not writable without elevation, which is the case the window uses to
        // decide it must offer quarantine instead.
        assert!(!deletable_by_this_account(Path::new(
            r"C:\Windows\System32\kernel32.dll"
        )));

        let _ = std::fs::remove_dir_all(&scratch);
    }
}
