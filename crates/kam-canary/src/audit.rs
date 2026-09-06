//! Asking Windows to record who reads a file.
//!
//! Two separate things have to be true before a canary reports anything, and
//! they are easy to confuse:
//!
//! 1. The **file** must carry a SACL — a system access control list — saying
//!    "write an event when anyone reads this". That is per-file, and set here.
//! 2. The **machine** must have the File System audit subcategory switched on.
//!    That is machine-wide policy, and without it the SACL is ignored and no
//!    event is ever written.
//!
//! Both need the `SeSecurityPrivilege`, which LocalSystem holds but does not
//! have enabled by default, so it is turned on in the process token first.
//!
//! # Why the machine-wide half is narrow in practice
//!
//! Switching on File System auditing sounds like it would fill the Security log
//! with every file operation on the machine. It does not: an event is only
//! written for an object that carries a SACL, and essentially nothing on a normal
//! Windows installation does. A handful of canaries produce a handful of events.

use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, LUID};
use windows::Win32::Security::Authentication::Identity::{
    AuditSetSystemPolicy, AUDIT_POLICY_INFORMATION, POLICY_AUDIT_EVENT_NONE,
    POLICY_AUDIT_EVENT_SUCCESS,
};
use windows::Win32::Security::Authorization::{SetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows::Win32::Security::{
    AddAuditAccessAceEx, AdjustTokenPrivileges, CreateWellKnownSid, GetLengthSid,
    GetSecurityDescriptorSacl, InitializeAcl, LookupPrivilegeValueW, WinWorldSid, ACL,
    ACL_REVISION, LUID_AND_ATTRIBUTES, PSECURITY_DESCRIPTOR, PSID, SACL_SECURITY_INFORMATION,
    SE_PRIVILEGE_ENABLED, SUCCESSFUL_ACCESS_ACE_FLAG, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
    TOKEN_QUERY,
};
use windows::Win32::Storage::FileSystem::FILE_GENERIC_READ;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use kam_core::{Error, Result};

/// The File System subcategory of Object Access, as Windows identifies it.
///
/// Spelled out rather than looked up: the identifiers are fixed, documented, and
/// the same on every installation.
const AUDIT_SUBCATEGORY_FILE_SYSTEM: windows::core::GUID =
    windows::core::GUID::from_u128(0x0cce921d_69ae_11d9_bed3_505054503030);

/// Enable `SeSecurityPrivilege` in this process.
///
/// LocalSystem holds it, but a privilege being held is not the same as it being
/// enabled — every one of these calls fails with "a required privilege is not
/// held by the client" until this runs.
fn enable_security_privilege() -> Result<()> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .map_err(|error| Error::Privileged(format!("could not open the process token: {error}")))?;

        let mut luid = LUID::default();
        let name: Vec<u16> = "SeSecurityPrivilege"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let looked_up = LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(name.as_ptr()), &mut luid);

        let outcome = looked_up.and_then(|()| {
            let privileges = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            AdjustTokenPrivileges(token, false, Some(&privileges), 0, None, None)
        });

        // AdjustTokenPrivileges reports success even when it changed nothing,
        // so the real answer is in the last error rather than the return value.
        let assigned = windows::Win32::Foundation::GetLastError() == ERROR_SUCCESS;
        let _ = CloseHandle(token);

        outcome.map_err(|error| {
            Error::Privileged(format!("could not enable SeSecurityPrivilege: {error}"))
        })?;

        if !assigned {
            return Err(Error::Privileged(
                "this process does not hold SeSecurityPrivilege, which is needed to watch a file. \
                 The agent must be running as a service for canaries to work."
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

/// Build the Everyone SID on the stack.
///
/// Everyone rather than a specific account on purpose: the question a canary
/// answers is "did *anything* read this", and narrowing it to one user would
/// miss a service, a scheduled task, or a process running as somebody else —
/// which is exactly the case worth catching.
fn everyone(buffer: &mut [u8]) -> Result<PSID> {
    let mut size = buffer.len() as u32;
    let sid = PSID(buffer.as_mut_ptr().cast());
    unsafe {
        CreateWellKnownSid(WinWorldSid, None, Some(sid), &mut size).map_err(|error| {
            Error::Privileged(format!("could not build the Everyone SID: {error}"))
        })?;
    }
    Ok(sid)
}

/// Put an audit rule on one file: record every successful read, by anyone.
pub fn watch_file(path: &Path) -> Result<()> {
    enable_security_privilege()?;

    let mut sid_buffer = [0_u8; 68];
    let sid = everyone(&mut sid_buffer)?;

    // One ACE holding one SID. Sized generously rather than exactly; the ACL is
    // discarded as soon as Windows has copied it.
    let mut acl_buffer = vec![0_u8; 256 + unsafe { GetLengthSid(sid) } as usize];
    let acl = acl_buffer.as_mut_ptr().cast::<ACL>();

    unsafe {
        InitializeAcl(acl, acl_buffer.len() as u32, ACL_REVISION).map_err(|error| {
            Error::Privileged(format!("could not build an audit list: {error}"))
        })?;

        AddAuditAccessAceEx(
            acl,
            ACL_REVISION,
            SUCCESSFUL_ACCESS_ACE_FLAG,
            FILE_GENERIC_READ.0,
            sid,
            // Successful reads only. Failures are noise here: a program denied
            // access never saw the contents, and the question is who read it.
            true,
            false,
        )
        .map_err(|error| Error::Privileged(format!("could not add the audit rule: {error}")))?;

        let path = wide(path);
        let status = SetNamedSecurityInfoW(
            PCWSTR(path.as_ptr()),
            SE_FILE_OBJECT,
            SACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            Some(acl),
        );
        if status != ERROR_SUCCESS {
            return Err(Error::Privileged(format!(
                "Windows refused the audit rule (error {})",
                status.0
            )));
        }
    }
    Ok(())
}

/// Whether a file already carries an audit rule.
pub fn is_watched(path: &Path) -> Result<bool> {
    use windows::Win32::Security::Authorization::GetNamedSecurityInfoW;

    enable_security_privilege()?;
    let wide_path = wide(path);
    let mut sacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();

    unsafe {
        let status = GetNamedSecurityInfoW(
            PCWSTR(wide_path.as_ptr()),
            SE_FILE_OBJECT,
            SACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            Some(&mut sacl),
            &mut descriptor,
        );
        if status != ERROR_SUCCESS {
            return Err(Error::Privileged(format!(
                "the audit rule could not be read (error {})",
                status.0
            )));
        }

        let mut present = windows::core::BOOL::default();
        let mut defaulted = windows::core::BOOL::default();
        let mut found: *mut ACL = std::ptr::null_mut();
        let readable =
            GetSecurityDescriptorSacl(descriptor, &mut present, &mut found, &mut defaulted).is_ok();

        let watched = readable && present.as_bool() && !found.is_null() && (*found).AceCount > 0;

        // The descriptor came from LocalAlloc inside GetNamedSecurityInfoW.
        let _ = windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
            descriptor.0,
        )));

        Ok(watched)
    }
}

/// Whether the machine is recording file access at all.
///
/// Read by asking for the current policy rather than assuming: a canary that
/// silently reports nothing because the subcategory is off would be worse than
/// no canary, since it looks like an all-clear.
pub fn auditing_enabled() -> bool {
    use windows::Win32::Security::Authentication::Identity::AuditQuerySystemPolicy;

    if enable_security_privilege().is_err() {
        return false;
    }
    unsafe {
        let mut policy: *mut AUDIT_POLICY_INFORMATION = std::ptr::null_mut();
        let subcategories = [AUDIT_SUBCATEGORY_FILE_SYSTEM];
        if !AuditQuerySystemPolicy(&subcategories, &mut policy) || policy.is_null() {
            return false;
        }
        let enabled = ((*policy).AuditingInformation & POLICY_AUDIT_EVENT_SUCCESS as u32) != 0;
        windows::Win32::Security::Authentication::Identity::AuditFree(policy.cast());
        enabled
    }
}

/// Turn recording of file access on or off, machine-wide.
///
/// This is the one setting this product changes on the machine, and it is only
/// ever reached from a deliberate action in the window. Turning it off is the
/// exact inverse, so nothing is left behind that the user did not ask for.
pub fn set_auditing(on: bool) -> Result<()> {
    enable_security_privilege()?;
    let policy = AUDIT_POLICY_INFORMATION {
        AuditSubCategoryGuid: AUDIT_SUBCATEGORY_FILE_SYSTEM,
        AuditingInformation: if on {
            POLICY_AUDIT_EVENT_SUCCESS as u32
        } else {
            POLICY_AUDIT_EVENT_NONE as u32
        },
        AuditCategoryGuid: windows::core::GUID::zeroed(),
    };

    unsafe {
        if !AuditSetSystemPolicy(&[policy]) {
            return Err(Error::Privileged(
                "Windows refused to change the audit policy. This needs the agent to be running \
                 as a service."
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn the_file_system_subcategory_is_the_documented_one() {
        // A wrong GUID here would switch on the wrong kind of auditing, or
        // silently switch on nothing at all.
        assert_eq!(
            format!("{:?}", AUDIT_SUBCATEGORY_FILE_SYSTEM).to_lowercase(),
            "0cce921d-69ae-11d9-bed3-505054503030"
        );
    }

    #[test]
    fn the_everyone_sid_can_be_built() {
        // No privilege needed for this one, so it runs everywhere.
        let mut buffer = [0_u8; 68];
        let sid = everyone(&mut buffer).expect("the Everyone SID is well known");
        assert!(unsafe { GetLengthSid(sid) } > 0);
    }

    #[test]
    fn reading_the_audit_policy_never_panics() {
        // Unprivileged, this answers false rather than failing, which is what
        // the interface relies on to say "not watching" honestly.
        let _ = auditing_enabled();
    }

    #[test]
    fn watching_a_file_without_privilege_fails_with_a_readable_reason() {
        // The tests do not run as SYSTEM, so this must refuse in a way a person
        // could act on rather than panicking or silently succeeding.
        let path = std::env::temp_dir().join(format!("kam-canary-acl-{}", std::process::id()));
        std::fs::write(&path, "decoy").unwrap();
        match watch_file(&path) {
            Ok(()) => println!("running privileged; the audit rule was set"),
            Err(error) => {
                let message = error.to_string();
                assert!(!message.is_empty());
                println!("refused as expected: {message}");
            }
        }
        std::fs::remove_file(&path).ok();
    }
}
