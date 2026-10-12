//! Where a path is, decided one folder name at a time.
//!
//! # The bug this exists to stop
//!
//! Locations were checked with `starts_with` on the text of the path. Text is
//! not folders: `C:\WindowsUpdate\x.exe` starts with `C:\Windows`, and
//! `C:\Program FilesX\x.exe` starts with `C:\Program Files`, so a program in a
//! folder anybody can create at the root of the drive was described as living
//! in the protected Windows folder or as an installed program. A check worded
//! as `contains` had the opposite weakness: any writable folder could be given
//! a path that merely *contained* Defender's folder name and so be waved
//! through as Defender's own.
//!
//! Every check here compares whole folder names, without regard to case, and
//! is anchored to where the folder really is on this machine.
//!
//! # Not everything inside Windows is protected
//!
//! A handful of folders under `C:\Windows` let an ordinary account create
//! files in them, so a program there was put there by something that needed no
//! administrator rights at all. [`WRITABLE_INSIDE_WINDOWS`] lists them, and
//! each one was checked on a real machine by opening it for adding a file from
//! an ordinary, unelevated account (which creates nothing) rather than taken
//! from a list on the internet.

/// Folders inside the Windows folder an ordinary account can create files in.
///
/// Relative to `%SystemRoot%`. Checked from an unelevated account by asking
/// for `FILE_ADD_FILE` on each: every one of these granted it, and `Windows`,
/// `System32` and `Program Files` themselves refused it.
pub const WRITABLE_INSIDE_WINDOWS: &[&str] = &[
    "Temp",
    "Tasks",
    "tracing",
    r"System32\Tasks",
    r"SysWOW64\Tasks",
    r"System32\spool\drivers\color",
    r"System32\Com\dmp",
    r"SysWOW64\Com\dmp",
    r"System32\Microsoft\Crypto\RSA\MachineKeys",
    r"Registration\CRMLog",
];

/// A path in the one spelling every comparison here uses: lower case,
/// backslashes, no extended-length prefix and no trailing separator.
pub fn normalise(path: &str) -> String {
    let lower = path.trim().to_lowercase().replace('/', "\\");
    let plain = if let Some(rest) = lower.strip_prefix(r"\\?\unc\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = lower.strip_prefix(r"\\?\") {
        rest.to_owned()
    } else {
        lower
    };
    plain.trim_end_matches('\\').to_owned()
}

/// Whether `path` is `root` itself or somewhere inside it.
///
/// Compared folder by folder: `C:\WindowsUpdate` is not inside `C:\Windows`.
/// An empty root contains nothing, so a variable that is not set can never
/// make every path match.
pub fn within(path: &str, root: &str) -> bool {
    let root = normalise(root);
    if root.is_empty() {
        return false;
    }
    let path = normalise(path);
    path == root
        || path
            .strip_prefix(&root)
            .is_some_and(|rest| rest.starts_with('\\'))
}

/// A machine-wide folder named by an environment variable, such as
/// `SystemRoot` or `ProgramFiles`. These are the same for every account, so
/// reading them from this process is right even inside the agent.
pub fn machine_folder(variable: &str) -> Option<String> {
    std::env::var(variable)
        .ok()
        .map(|value| normalise(&value))
        .filter(|value| !value.is_empty())
}

/// Whether a path is in one of the folders inside Windows that an ordinary
/// account can write to.
pub fn writable_inside_windows(path: &str) -> bool {
    let Some(root) = machine_folder("SystemRoot") else {
        return false;
    };
    WRITABLE_INSIDE_WINDOWS
        .iter()
        .any(|tail| within(path, &format!(r"{root}\{tail}")))
}

/// Whether a path is inside Defender's own folder under `ProgramData`, where
/// its engine and its updates live and which only administrators can write.
pub fn in_defenders_own_folder(path: &str) -> bool {
    machine_folder("ProgramData")
        .is_some_and(|root| within(path, &format!(r"{root}\Microsoft\Windows Defender")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_folder_that_merely_starts_with_the_same_letters_is_not_inside() {
        assert!(!within(r"C:\WindowsUpdate\x.exe", r"C:\Windows"));
        assert!(!within(r"C:\Program FilesX\x.exe", r"C:\Program Files"));
        assert!(within(r"C:\Windows\System32\x.exe", r"C:\Windows"));
        assert!(within(r"c:/windows/system32/x.exe", r"C:\WINDOWS\"));
        assert!(within(r"\\?\C:\Windows\x.exe", r"C:\Windows"));
        assert!(within(r"C:\Windows", r"C:\Windows"));
    }

    #[test]
    fn an_empty_root_contains_nothing() {
        assert!(!within(r"C:\anything", ""));
        assert!(!within(r"C:\anything", "  "));
    }

    #[test]
    fn the_writable_folders_inside_windows_are_recognised() {
        let root = std::env::var("SystemRoot").unwrap();
        for tail in WRITABLE_INSIDE_WINDOWS {
            assert!(
                writable_inside_windows(&format!(r"{root}\{tail}\thing.exe")),
                "{tail}"
            );
        }
        assert!(!writable_inside_windows(&format!(
            r"{root}\System32\notepad.exe"
        )));
        // Named like one, but not one.
        assert!(!writable_inside_windows(&format!(
            r"{root}\TempStuff\x.exe"
        )));
        assert!(!writable_inside_windows(r"D:\Windows\Temp\x.exe"));
    }

    #[test]
    fn only_defenders_real_folder_is_defenders() {
        let data = std::env::var("ProgramData").unwrap();
        assert!(in_defenders_own_folder(&format!(
            r"{data}\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe"
        )));
        // A writable folder can contain the same names. It is not Defender's.
        assert!(!in_defenders_own_folder(
            r"C:\Users\me\AppData\Local\Temp\ProgramData\Microsoft\Windows Defender\x.cmd"
        ));
        assert!(!in_defenders_own_folder(&format!(
            r"{data}\Microsoft\Windows Defender Evil\x.cmd"
        )));
    }
}
