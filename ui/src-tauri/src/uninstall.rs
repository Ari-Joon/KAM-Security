//! Running an application's own uninstaller.
//!
//! # Why the shell and not the agent
//!
//! Uninstallers show windows. The agent runs as LocalSystem in session 0, where
//! a window has no desktop to appear on — the process would sit forever waiting
//! for a click nobody can give it. The shell already runs as the user, in the
//! user's session, which is where an uninstaller belongs. If it needs elevation
//! it asks for it through its own manifest, and Windows shows the prompt.
//!
//! # Why the command line is parsed rather than shelled out
//!
//! `UninstallString` is a command line written by whoever made the installer:
//!
//! ```text
//! "C:\Program Files\Thing\uninst.exe" /S
//! MsiExec.exe /X{2A5B...}
//! C:\Windows\SysWOW64\rundll32.exe advpack.dll,LaunchINFSection thing.inf,Uninstall
//! ```
//!
//! Handing that to `cmd /c` would let any `&`, `|` or `>` inside it run as a
//! second command, and these strings come from any installer that ever touched
//! the machine. Splitting on spaces is worse: it breaks the first example.
//!
//! So the string is given to `CommandLineToArgvW`, the same parser Windows uses
//! on a process's own command line, and the resulting argv is spawned directly.
//! No shell is involved, so there is nothing for a metacharacter to mean.

use std::path::Path;

use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::LocalFree;
use windows::Win32::Foundation::HLOCAL;
use windows::Win32::UI::Shell::{CommandLineToArgvW, ShellExecuteW};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

/// Split a command line the way Windows itself would.
fn split_command_line(command: &str) -> Result<Vec<String>, String> {
    let wide = HSTRING::from(command);
    let mut count = 0_i32;
    let argv = unsafe { CommandLineToArgvW(PCWSTR(wide.as_ptr()), &mut count) };
    if argv.is_null() || count <= 0 {
        return Err(format!("could not read the uninstall command: {command}"));
    }

    let mut parts = Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        // Each entry is a null-terminated wide string owned by the block below.
        let pointer = unsafe { *argv.add(index) };
        parts.push(unsafe { pointer.to_string() }.unwrap_or_default());
    }
    // CommandLineToArgvW allocates one block for the whole array.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(argv as *mut _)));
    }

    if parts.is_empty() {
        return Err(format!("the uninstall command is empty: {command}"));
    }
    Ok(parts)
}

/// A protocol handler rather than a program — `steam://uninstall/730`.
fn is_uri(command: &str) -> bool {
    // Deliberately narrow. A general "has a scheme" test would treat
    // `C:\...` as the `c:` scheme, and anything with a colon would qualify.
    command.split_once("://").is_some_and(|(scheme, _)| {
        !scheme.is_empty()
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
    })
}

/// Launch what the registry says removes this application.
///
/// Returns once the uninstaller has *started*. Whether it finishes, and whether
/// the user goes through with it, is not knowable from here — so nothing in the
/// interface claims the application was removed, only that its uninstaller ran.
pub fn run(command: &str) -> Result<(), String> {
    let command = command.trim();
    if command.is_empty() {
        return Err("this application does not publish an uninstall command".to_owned());
    }

    if is_uri(command) {
        // Handed to the shell so the registered protocol handler picks it up.
        // There is no command line here to parse, and nothing to inject into.
        let target = HSTRING::from(command);
        let result = unsafe {
            ShellExecuteW(
                None,
                PCWSTR::null(),
                PCWSTR(target.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            )
        };
        // ShellExecuteW reports failure as a value of 32 or less.
        if result.0 as usize <= 32 {
            return Err(format!("nothing is registered to handle {command}"));
        }
        return Ok(());
    }

    let parts = split_command_line(command)?;
    let program = &parts[0];

    // A bare name like MsiExec.exe is resolved through PATH by the system, so
    // only a path that names a file is checked here.
    if program.contains(['\\', '/']) && !Path::new(program).exists() {
        return Err(format!(
            "{program} is not there any more; the application may already have \
             been removed, leaving its registry entry behind"
        ));
    }

    std::process::Command::new(program)
        .args(&parts[1..])
        .spawn()
        .map_err(|error| format!("could not start the uninstaller: {error}"))?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_quoted_path_with_spaces_stays_one_argument() {
        // The case that naive splitting breaks, and the most common form.
        let parts = split_command_line(r#""C:\Program Files\Thing\uninst.exe" /S"#).unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], r"C:\Program Files\Thing\uninst.exe");
        assert_eq!(parts[1], "/S");
    }

    #[test]
    fn an_msi_command_splits_into_program_and_product() {
        let parts =
            split_command_line("MsiExec.exe /X{2A5B1234-0000-0000-0000-000000000000}").unwrap();
        assert_eq!(parts[0], "MsiExec.exe");
        assert_eq!(parts[1], "/X{2A5B1234-0000-0000-0000-000000000000}");
    }

    #[test]
    fn shell_metacharacters_stay_inside_one_argument() {
        // The reason nothing is handed to cmd: through a shell this would run
        // a second command. As argv it is one meaningless argument.
        let parts = split_command_line(r#""C:\a\b.exe" /S & calc.exe"#).unwrap();
        assert_eq!(parts[0], r"C:\a\b.exe");
        assert!(parts.contains(&"&".to_owned()));
        assert!(
            parts.iter().all(|part| !part.contains("b.exe /S")),
            "the arguments should not have been recombined"
        );
    }

    #[test]
    fn a_steam_uri_is_recognised() {
        assert!(is_uri("steam://uninstall/730"));
        assert!(is_uri("ms-windows-store://pdp/?productid=9WZ"));
    }

    #[test]
    fn a_windows_path_is_not_mistaken_for_a_uri() {
        // `c:` would otherwise look like a scheme and be handed to the shell.
        assert!(!is_uri(r"C:\Program Files\Thing\uninst.exe"));
        assert!(!is_uri(r"MsiExec.exe /X{2A5B}"));
        assert!(!is_uri(r#""C:\a b\uninst.exe" /S"#));
    }

    #[test]
    fn an_empty_command_is_refused_rather_than_spawned() {
        assert!(run("").is_err());
        assert!(run("   ").is_err());
    }

    #[test]
    fn a_missing_uninstaller_is_reported_not_launched() {
        let outcome = run(r#""C:\this\does\not\exist\uninst.exe" /S"#);
        assert!(outcome.is_err());
        assert!(
            outcome.unwrap_err().contains("not there any more"),
            "the message should explain why nothing happened"
        );
    }
}
