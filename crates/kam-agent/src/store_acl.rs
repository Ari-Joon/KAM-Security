//! Locking the directory the store lives in.
//!
//! # The hole this closes, which was not the one anybody was watching
//!
//! The audit log is append-only, and that is enforced by the database: `BEFORE
//! UPDATE` and `BEFORE DELETE` triggers abort any attempt to rewrite history.
//! The baseline of what the machine looks like lives in the same file, and its
//! whole value is that an attacker cannot mark their own persistence as
//! already-seen.
//!
//! Both of those protections were checked at the level of the *file*, and both
//! were correct there: `kam.db` and its two sidecars are readable by everybody
//! and writable by nobody but SYSTEM and administrators. What nobody checked
//! was the *directory*, which granted `BUILTIN\Users` create-file.
//!
//! That is enough, because of how SQLite works. In WAL mode the write-ahead log
//! lives beside the database as `kam.db-wal`, and it is **deleted on a clean
//! close** — so between the service stopping and starting again, at every boot,
//! every update and every crash, that file does not exist and an ordinary user
//! can create it. SQLite applies a WAL as raw page images, underneath SQL
//! entirely: a planted one rewrites rows without a statement ever running, so
//! the triggers protecting the audit log never fire and never could. The
//! database is also world-readable, so an attacker has the exact bytes needed
//! to build a consistent one.
//!
//! Adversarial review demonstrated the applying half against scratch databases:
//! `DELETE` and `UPDATE` refused by the triggers as designed, then a WAL dropped
//! beside a pristine copy rewrote the append-only row, added a forged one, and
//! removed the triggers on reopen.
//!
//! The lesson is worth more than the fix. Every protection here was real and
//! each was verified on the object it named. The gap was between them, in the
//! container, and it took somebody checking the two files nobody had thought
//! to name.
//!
//! # The agent's own log is inside this, deliberately
//!
//! Locking the store means an ordinary account can no longer read
//! `logs\agent.log`, which is a real cost: the owner of the machine cannot look
//! at their own security tool's diagnostics without an elevated prompt, and
//! cannot casually send the file to anybody.
//!
//! It stays locked anyway, and the reason is specific rather than a general
//! preference for tightness. The log names decoy keys when planting one fails,
//! and decoys are the one thing in this product that is not circumstantial —
//! their entire value is that nothing on the machine knows they exist. An
//! attacker who can read this file learns which files and keys to leave alone,
//! and the canaries stop working without anybody noticing they have.
//!
//! So do not carve out a read for `logs` to make support easier. Reading it
//! needs administrator rights, which is a nuisance with a reason behind it.
//!
//! # Do not try to detect this instead
//!
//! The obvious cheaper fix is to delete an unexpected `kam.db-wal` on open. It
//! is wrong, and wrong in a way that loses data: an unclean shutdown — a crash,
//! a power cut — legitimately leaves a write-ahead log that SQLite must replay
//! to recover committed transactions. A planted one and a crash one are both
//! just a valid WAL sitting beside the database, and nothing about the file
//! says which it is. Deleting on sight throws away real work; deleting only
//! "suspicious" ones is a guess an attacker writes around.
//!
//! Permissions are the defence precisely because they stop the file being
//! created at all, which is a question that has an answer.
//!
//! # Why the agent does it rather than the installer
//!
//! The installer does it too, and should. But the agent runs as LocalSystem
//! every time the machine starts, so doing it here makes the protection
//! self-healing: a restore from backup, a copied profile, or an installer that
//! somebody ran the wrong way cannot leave the store sitting open. It costs one
//! call at startup.

use std::path::Path;

use kam_core::{Error, Result};
use windows::core::PCWSTR;
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};

/// Who may touch the store, and nobody else.
///
/// - `D:P` — protected, so nothing inherited from `ProgramData` applies. That
///   inheritance is exactly where the `Users` create-file right came from.
/// - `(A;OICI;FA;;;SY)` — LocalSystem, full, inherited by everything inside.
///   This is the agent.
/// - `(A;OICI;FA;;;BA)` — Administrators, full. Somebody has to be able to
///   remove it.
///
/// `Users` appears nowhere, deliberately, and they lose the read they had. The
/// unprivileged window never opens this database — it asks the agent over the
/// pipe — so nothing legitimate needs it, and a world-readable database is what
/// gave an attacker the bytes to forge a consistent write-ahead log.
const STORE_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

fn wide(text: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Put the store's directory beyond the reach of ordinary accounts.
///
/// Returns an error rather than failing quietly: a store this could not secure
/// is one whose audit log can be rewritten and whose baseline can be poisoned,
/// and the caller decides what to do about that.
pub fn harden(directory: &Path) -> Result<()> {
    let path = wide(&directory.to_string_lossy());
    let sddl = wide(STORE_SDDL);

    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(|error| {
        Error::Privileged(format!(
            "the store's permissions could not be built: {error}"
        ))
    })?;

    // Freed however this returns.
    let _owned = OwnedDescriptor(descriptor);

    let mut present = windows::core::BOOL(0);
    let mut acl: *mut ACL = std::ptr::null_mut();
    let mut defaulted = windows::core::BOOL(0);
    unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) }
        .map_err(|error| {
            Error::Privileged(format!(
                "the store's permissions could not be read: {error}"
            ))
        })?;

    if !present.as_bool() || acl.is_null() {
        return Err(Error::Privileged(
            "the store's permissions came back empty".to_owned(),
        ));
    }

    // PROTECTED as well as DACL: without it the inherited entries from
    // ProgramData are merged back in, which is where the create-file right for
    // ordinary users came from in the first place.
    let status = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(path.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(acl),
            None,
        )
    };
    if status.is_err() {
        return Err(Error::Privileged(format!(
            "{} could not be secured: {status:?}",
            directory.display()
        )));
    }

    Ok(())
}

/// A security descriptor that frees itself.
struct OwnedDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for OwnedDescriptor {
    fn drop(&mut self) {
        if !self.0 .0.is_null() {
            unsafe {
                let _ = windows::Win32::Foundation::LocalFree(Some(
                    windows::Win32::Foundation::HLOCAL(self.0 .0),
                ));
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The descriptor is well formed, whatever the machine allows.
    ///
    /// Applying it needs rights the test runner may not have, so this asserts
    /// what can be asserted anywhere: that the rule this product intends to
    /// impose parses, and names SYSTEM and Administrators and nobody else.
    #[test]
    fn the_rule_is_well_formed_and_names_only_two_principals() {
        let sddl = wide(STORE_SDDL);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .expect("the descriptor must parse, or nothing is ever secured");
        let _owned = OwnedDescriptor(descriptor);

        // Protected, or ProgramData's inherited create-file for Users comes
        // straight back and the whole exercise is undone.
        assert!(STORE_SDDL.starts_with("D:P"), "{STORE_SDDL}");
        assert!(STORE_SDDL.contains(";SY)"), "SYSTEM must keep full access");
        assert!(STORE_SDDL.contains(";BA)"), "administrators must too");
        // The two that must not appear. `Users` is what could create the
        // write-ahead log; `WD` is world.
        assert!(
            !STORE_SDDL.contains(";BU)"),
            "ordinary users must not appear"
        );
        assert!(!STORE_SDDL.contains(";WD)"), "everyone must not appear");
    }

    /// Applying it to a real directory works, when the test can do it at all.
    #[test]
    fn a_directory_can_be_secured() {
        let scratch = std::env::temp_dir().join(format!("kam-store-acl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();

        match harden(&scratch) {
            Ok(()) => {
                // It applied. The directory should now refuse an ordinary
                // account, but this test may itself be running as one of the
                // two that are allowed, so the only safe assertion is that
                // nothing broke.
                assert!(scratch.is_dir());
            }
            Err(error) => {
                // Changing an owner's ACL needs WRITE_DAC, which the runner
                // has for a directory it created; a failure here is worth
                // seeing rather than swallowing.
                panic!("a scratch directory could not be secured: {error}");
            }
        }

        let _ = std::fs::remove_dir_all(&scratch);
    }
}
