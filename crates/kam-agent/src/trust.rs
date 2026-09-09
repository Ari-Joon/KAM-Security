//! Whether the directory the agent trusts can be trusted.
//!
//! # The assumption this checks
//!
//! The agent serves any client whose executable sits in the agent's own
//! directory. That check is sound in itself — the path is canonicalised, so
//! `..`, short names and symlinks cannot present an outside binary as an inside
//! one — but it reduces the whole trust decision to a single predicate: *the
//! caller lives here*. There is no signature check and no fixed identity. The
//! security of the pipe is therefore exactly the security of that directory's
//! access control list, and nothing in the product was checking it.
//!
//! On the machine this was written on it was wrong. `dist\` carried
//! `NT AUTHORITY\Authenticated Users:(I)(M)` — Modify — inherited from the
//! default access control list at the root of `C:` and carried along by a
//! same-volume move. Any user could drop an executable into the trusted
//! directory and drive a LocalSystem service with it, and could replace the
//! agent's own binary for a straight escalation the next time the service
//! started. Both were confirmed by writing a file there as a non-administrator.
//!
//! This is not an exotic misconfiguration. Anybody who unzips a release into
//! their Downloads folder, or into a folder they made off the root of `C:`,
//! inherits exactly the same thing. It is the default outcome of the obvious
//! action, which is the worst kind of trap for a security tool to leave.
//!
//! # What is done about it
//!
//! Installation refuses. Not a warning printed above a success message that
//! nobody reads: a refusal, naming the principals that can write and what to do
//! instead. A service that guards a machine has no business installing itself
//! into a location where any user can replace it.

use std::path::Path;

use kam_core::{Error, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
};

/// Rights that would let somebody replace what lives in a directory.
///
/// Not "write" in the abstract. These are specifically the ways to put a
/// different file where a trusted one was: add a file, write over one, delete
/// one, or rewrite the access control list so as to be able to.
/// The numbers matter and are easy to get wrong: `DELETE` is `0x0001_0000`
/// and `READ_CONTROL` is `0x0002_0000`. Using the second by mistake matches
/// every read-only entry there is, which made this report Program Files as
/// world-writable — caught by the test below, which is why that test exists.
const DANGEROUS: u32 = 0x0000_0002 // FILE_ADD_FILE / FILE_WRITE_DATA
    | 0x0000_0004 // FILE_ADD_SUBDIRECTORY
    | 0x0000_0040 // FILE_DELETE_CHILD
    | 0x0001_0000 // DELETE, which allows the folder to be replaced wholesale
    | 0x0004_0000 // WRITE_DAC, which allows granting the rest
    | 0x0008_0000 // WRITE_OWNER
    | 0x1000_0000 // GENERIC_ALL
    | 0x4000_0000; // GENERIC_WRITE

/// Accounts that are *supposed* to be able to write here.
///
/// Anything running as one of these can already replace the agent by other
/// means, so their access is not a weakness. Everything else is.
fn is_expected(sid: &str) -> bool {
    matches!(
        sid,
        "S-1-5-18"        // LocalSystem
            | "S-1-5-32-544"  // Builtin Administrators
            | "S-1-3-0"       // Creator Owner, which only ever applies to new items
            | "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" // TrustedInstaller
    )
}

/// Principals that can replace files in `path`, by SID.
///
/// Empty means the directory is safe to trust. Any entry means it is not, and
/// the caller should say so rather than continue.
pub fn writers_of(path: &Path) -> Result<Vec<String>> {
    let wide: Vec<u16> = path
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();

    // The descriptor owns the ACL, so it is freed once and the ACL pointer is
    // only valid until then.
    let status = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut descriptor,
        )
    };
    if status.is_err() {
        return Err(Error::Privileged(format!(
            "could not read the access control list of {}: {status:?}",
            path.display()
        )));
    }

    let mut found = Vec::new();

    // A null DACL is not an empty one: it grants everyone everything.
    if dacl.is_null() {
        found.push("Everyone (this folder has no access control list at all)".to_owned());
        unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
        return Ok(found);
    }

    let count = unsafe { (*dacl).AceCount } as u32;
    for index in 0..count {
        let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
        if unsafe { windows::Win32::Security::GetAce(dacl, index, &mut ace) }.is_err() {
            continue;
        }

        let header = unsafe { *(ace as *const ACE_HEADER) };
        // Only allow entries grant anything; deny entries are handled by
        // Windows before any of this matters.
        if header.AceType != 0 {
            continue;
        }

        let allowed = unsafe { &*(ace as *const ACCESS_ALLOWED_ACE) };
        if allowed.Mask & DANGEROUS == 0 {
            continue;
        }

        // The SID follows the fixed part of the structure, in the same
        // allocation, which is why the pointer is taken from its address.
        let sid = PSID(std::ptr::addr_of!(allowed.SidStart) as *mut core::ffi::c_void);
        let mut text = windows::core::PWSTR::null();
        if unsafe { ConvertSidToStringSidW(sid, &mut text) }.is_err() {
            continue;
        }
        let sid_text = unsafe { text.to_string() }.unwrap_or_default();
        unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };

        if !is_expected(&sid_text) && !found.contains(&sid_text) {
            found.push(sid_text);
        }
    }

    unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    Ok(found)
}

/// Turn a SID into something a person can act on.
pub fn describe(sid: &str) -> String {
    match sid {
        "S-1-1-0" => "Everyone".to_owned(),
        "S-1-5-11" => "Authenticated Users (every account that can sign in)".to_owned(),
        "S-1-5-32-545" => "Users (every ordinary account on this machine)".to_owned(),
        "S-1-5-32-547" => "Power Users".to_owned(),
        "S-1-5-4" => "Interactive (anyone signed in at the keyboard)".to_owned(),
        other => other.to_owned(),
    }
}

/// The whole check, phrased for somebody about to install.
///
/// `Ok(())` means the directory is safe to trust. The error is written to be
/// read by a person at a terminal, because that is exactly where it appears.
pub fn check_install_directory(path: &Path) -> Result<()> {
    let writers = writers_of(path)?;
    if writers.is_empty() {
        return Ok(());
    }

    let named: Vec<String> = writers.iter().map(|sid| describe(sid)).collect();
    Err(Error::Refused(format!(
        "{} can be written to by: {}.\n\n\
         The agent serves any program that sits in its own directory, so a folder \
         other people can write to is a folder where anyone can drop a program that \
         drives this service as LocalSystem — or replace the agent itself.\n\n\
         Move the whole folder somewhere only administrators can write, such as \
         C:\\Program Files\\KAM Security, and install from there.",
        path.display(),
        named.join(", ")
    )))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "reads the access control list of wherever this is installed"]
    fn show_this_installation() {
        let here = std::env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(Path::to_path_buf))
            .expect("a test binary has a directory");

        // Wherever this build is, plus wherever the agent was deployed to,
        // because they are usually different and both matter.
        let deployed = std::env::var("KAM_DIST").ok().map(std::path::PathBuf::from);

        for candidate in [Some(here), deployed].into_iter().flatten() {
            if !candidate.is_dir() {
                continue;
            }
            println!("\n{}", candidate.display());
            match writers_of(&candidate) {
                Ok(writers) if writers.is_empty() => {
                    println!("  safe: only administrators and the system can write here")
                }
                Ok(writers) => {
                    for sid in &writers {
                        println!("  CAN REPLACE FILES HERE: {}", describe(sid));
                    }
                }
                Err(error) => println!("  could not read: {error}"),
            }
        }
    }

    #[test]
    fn program_files_is_safe_to_trust() {
        // The place the installer should be recommending. If this ever reports
        // writers, either the machine is misconfigured or the check is wrong,
        // and both are worth knowing.
        let program_files = std::env::var("ProgramFiles").unwrap_or_default();
        if program_files.is_empty() {
            return;
        }
        let writers = writers_of(Path::new(&program_files)).unwrap();
        assert!(
            writers.is_empty(),
            "Program Files reports writers, which should not happen: {writers:?}"
        );
    }

    #[test]
    fn a_folder_in_the_users_own_profile_is_not() {
        // The counterpart, and the reason the check exists: a folder somebody
        // made themselves is writable by them, which is exactly the trap
        // somebody unzipping a release into Downloads falls into.
        let scratch = std::env::temp_dir().join(format!("kam-trust-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();

        let writers = writers_of(&scratch).unwrap();
        assert!(
            !writers.is_empty(),
            "a folder inside the user's own profile reported no writers"
        );
        assert!(check_install_directory(&scratch).is_err());

        std::fs::remove_dir_all(&scratch).unwrap();
    }

    #[test]
    fn the_refusal_says_what_to_do_about_it() {
        let scratch = std::env::temp_dir().join(format!("kam-trust-msg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();

        let message = check_install_directory(&scratch).unwrap_err().to_string();
        assert!(
            message.contains("Program Files"),
            "no remedy offered: {message}"
        );
        assert!(
            message.contains("LocalSystem"),
            "no stakes given: {message}"
        );

        std::fs::remove_dir_all(&scratch).unwrap();
    }

    #[test]
    fn the_accounts_that_may_write_are_named_rather_than_shown_as_numbers() {
        assert_eq!(describe("S-1-1-0"), "Everyone");
        assert!(describe("S-1-5-11").starts_with("Authenticated Users"));
        // An unknown one is passed through rather than guessed at.
        assert_eq!(describe("S-1-5-21-1-2-3-1001"), "S-1-5-21-1-2-3-1001");
    }

    #[test]
    fn administrators_and_the_system_are_not_counted_as_a_problem() {
        assert!(is_expected("S-1-5-18"));
        assert!(is_expected("S-1-5-32-544"));
        assert!(!is_expected("S-1-5-11"));
        assert!(!is_expected("S-1-1-0"));
    }
}
