//! "Check with KAM Security" and "Extract with KAM Security" in Explorer's
//! right-click menu.
//!
//! # What it writes, and where
//!
//! Two verbs in the person's own hive, under `HKCU\Software\Classes`, written
//! by this unelevated process as them: one for every file, one for zip files
//! only. Each starts this program with `--check` or `--extract` and the file,
//! and the running copy picks that up (see the single-instance handler in
//! `lib.rs`). Nothing is written machine-wide and nothing else is changed.
//! On Windows 11 they appear under "Show more options", which is where Windows
//! puts every verb registered this way.
//!
//! # On by default, said out loud, and switchable
//!
//! Turned on the first time the program runs, like the sign-in entry, and the
//! Downloads page says so beside the switch that removes them. A choice already
//! made is kept. While they are on, they are pointed at this copy of the
//! program each time it starts, so moving the folder does not leave a menu
//! entry that starts nothing.

use std::os::windows::ffi::OsStrExt;

use serde::Serialize;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegGetValueW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_SET_VALUE, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ, RRF_RT_REG_DWORD,
    RRF_RT_REG_SZ,
};

/// The verb on every file.
pub const CHECK_KEY: &str = r"Software\Classes\*\shell\KAMSecurity.Check";
/// The verb on zip files.
pub const EXTRACT_KEY: &str =
    r"Software\Classes\SystemFileAssociations\.zip\shell\KAMSecurity.Extract";

/// Where the person's choice is kept, beside the sign-in entry's.
const CHOICE_KEY: &str = r"Software\KAM Security";
const CHOICE_VALUE: &str = "ContextMenu";

/// The arguments the verbs pass.
pub const CHECK_ARG: &str = "--check";
pub const EXTRACT_ARG: &str = "--extract";

#[derive(Debug, Clone, Serialize)]
pub struct MenuState {
    /// Both entries are there and start this copy of the program.
    pub enabled: bool,
    /// An entry is there but starts something else.
    pub points_elsewhere: bool,
}

/// One verb: its key, its label and the argument it passes.
struct Verb {
    key: &'static str,
    label: &'static str,
    argument: &'static str,
}

const VERBS: [Verb; 2] = [
    Verb {
        key: CHECK_KEY,
        label: "Check with KAM Security",
        argument: CHECK_ARG,
    },
    Verb {
        key: EXTRACT_KEY,
        label: "Extract with KAM Security",
        argument: EXTRACT_ARG,
    },
];

/// The command a verb runs: this program, quoted, then the argument and the
/// file, quoted, because both paths routinely contain spaces.
fn command_for(exe: &str, argument: &str) -> String {
    format!("\"{exe}\" {argument} \"%1\"")
}

fn this_program() -> Option<String> {
    std::env::current_exe()
        .ok()
        .map(|exe| exe.to_string_lossy().into_owned())
}

/// Read the current state.
pub fn state() -> MenuState {
    let Some(exe) = this_program() else {
        return MenuState {
            enabled: false,
            points_elsewhere: false,
        };
    };
    let mut ours = 0;
    let mut elsewhere = false;
    for verb in &VERBS {
        match read_string(&format!(r"{}\command", verb.key), "") {
            Some(existing) if existing.eq_ignore_ascii_case(&command_for(&exe, verb.argument)) => {
                ours += 1
            }
            Some(_) => elsewhere = true,
            None => {}
        }
    }
    MenuState {
        enabled: ours == VERBS.len(),
        points_elsewhere: elsewhere,
    }
}

/// Add both entries, pointing here, or remove both, and remember the choice.
pub fn set(enabled: bool) -> Result<MenuState, String> {
    if enabled {
        let exe = this_program().ok_or("could not work out where this program is")?;
        for verb in &VERBS {
            write_string(verb.key, "", verb.label)?;
            write_string(verb.key, "Icon", &format!("{exe},0"))?;
            write_string(
                &format!(r"{}\command", verb.key),
                "",
                &command_for(&exe, verb.argument),
            )?;
        }
    } else {
        for verb in &VERBS {
            remove_tree(verb.key)?;
        }
    }
    write_dword(CHOICE_KEY, CHOICE_VALUE, u32::from(enabled))?;
    Ok(state())
}

/// At start-up: on the first run turn the entries on, and on later runs keep
/// them pointing here if they are on. A choice to have them off is kept.
pub fn apply_at_start() {
    let outcome = match read_dword(CHOICE_KEY, CHOICE_VALUE) {
        None => set(true).map(|_| ()),
        Some(0) => Ok(()),
        Some(_) if state().enabled => Ok(()),
        Some(_) => set(true).map(|_| ()),
    };
    if let Err(error) = outcome {
        eprintln!("the right-click entries could not be put in place: {error}");
    }
}

fn wide(text: &str) -> Vec<u16> {
    std::ffi::OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn read_string(key: &str, value: &str) -> Option<String> {
    let key = wide(key);
    let value = wide(value);
    let mut size = 0_u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            PCWSTR(key.as_ptr()),
            PCWSTR(value.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            None,
            Some(&mut size),
        )
    };
    if status != ERROR_SUCCESS || size == 0 {
        return None;
    }
    let mut buffer = vec![0_u16; (size as usize).div_ceil(2)];
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            PCWSTR(key.as_ptr()),
            PCWSTR(value.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buffer.as_mut_ptr().cast()),
            Some(&mut size),
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    let end = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    Some(String::from_utf16_lossy(&buffer[..end]))
}

fn read_dword(key: &str, value: &str) -> Option<u32> {
    let key = wide(key);
    let value = wide(value);
    let mut data = 0_u32;
    let mut size = std::mem::size_of::<u32>() as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            PCWSTR(key.as_ptr()),
            PCWSTR(value.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some((&raw mut data).cast()),
            Some(&mut size),
        )
    };
    (status == ERROR_SUCCESS).then_some(data)
}

fn open_for_writing(key: &str) -> Result<HKEY, String> {
    let key_wide = wide(key);
    let mut handle = HKEY::default();
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(key_wide.as_ptr()),
            None,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut handle,
            None,
        )
    };
    if status == ERROR_SUCCESS {
        Ok(handle)
    } else {
        Err(format!("could not open {key}: Windows error {}", status.0))
    }
}

fn finish(status: WIN32_ERROR, what: &str) -> Result<(), String> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(format!(
            "could not write {what}: Windows error {}",
            status.0
        ))
    }
}

fn write_string(key: &str, value: &str, data: &str) -> Result<(), String> {
    let handle = open_for_writing(key)?;
    let name = wide(value);
    let bytes: Vec<u8> = wide(data)
        .iter()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    let status =
        unsafe { RegSetValueExW(handle, PCWSTR(name.as_ptr()), None, REG_SZ, Some(&bytes)) };
    unsafe {
        let _ = RegCloseKey(handle);
    }
    finish(status, key)
}

fn write_dword(key: &str, value: &str, data: u32) -> Result<(), String> {
    let handle = open_for_writing(key)?;
    let name = wide(value);
    let status = unsafe {
        RegSetValueExW(
            handle,
            PCWSTR(name.as_ptr()),
            None,
            REG_DWORD,
            Some(&data.to_le_bytes()),
        )
    };
    unsafe {
        let _ = RegCloseKey(handle);
    }
    finish(status, value)
}

/// Remove one of this program's own keys and everything under it. Only ever
/// called with the two constants above.
fn remove_tree(key: &str) -> Result<(), String> {
    let key_wide = wide(key);
    let status = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(key_wide.as_ptr())) };
    if status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND {
        Ok(())
    } else {
        Err(format!(
            "could not remove {key}: Windows error {}",
            status.0
        ))
    }
}

/// The file a launch asks about: `--check <path>` or `--extract <path>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Launch {
    /// "check", "extract", or "show" for a notification that was clicked.
    pub action: String,
    pub path: String,
}

/// Read a launch request out of a command line. Only an absolute path is
/// taken, and only the first request.
pub fn launch_from(arguments: &[String]) -> Option<Launch> {
    let mut iter = arguments.iter();
    while let Some(argument) = iter.next() {
        let action = match argument.as_str() {
            CHECK_ARG => "check",
            EXTRACT_ARG => "extract",
            _ => continue,
        };
        let path = iter.next()?;
        if !std::path::Path::new(path).is_absolute() || path.chars().any(char::is_control) {
            return None;
        }
        return Some(Launch {
            action: action.to_owned(),
            path: path.clone(),
        });
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn the_verbs_quote_the_program_and_the_file() {
        let command = command_for(r"C:\Program Files\KAM Security\kam-shell.exe", CHECK_ARG);
        assert_eq!(
            command,
            r#""C:\Program Files\KAM Security\kam-shell.exe" --check "%1""#
        );
        assert!(CHECK_KEY.starts_with(r"Software\Classes\*\shell\"));
        assert!(EXTRACT_KEY.contains(r"SystemFileAssociations\.zip\shell\"));
    }

    #[test]
    fn a_launch_is_read_from_the_command_line_and_only_with_a_full_path() {
        let args = |list: &[&str]| list.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            launch_from(&args(&[
                "kam-shell.exe",
                "--check",
                r"C:\Users\me\Downloads\a b.exe"
            ])),
            Some(Launch {
                action: "check".to_owned(),
                path: r"C:\Users\me\Downloads\a b.exe".to_owned()
            })
        );
        assert_eq!(
            launch_from(&args(&["kam-shell.exe", "--extract", r"D:\x.zip"]))
                .map(|launch| launch.action),
            Some("extract".to_owned())
        );
        assert_eq!(
            launch_from(&args(&["kam-shell.exe", "--check", "relative.exe"])),
            None
        );
        assert_eq!(launch_from(&args(&["kam-shell.exe", "--check"])), None);
        assert_eq!(launch_from(&args(&["kam-shell.exe", "--background"])), None);
    }

    /// A round trip through a scratch key in the person's own hive, never the
    /// real verbs: tests must not change Explorer's menu.
    #[test]
    fn a_value_written_reads_back_and_a_tree_is_removed_whole() {
        let key = format!(r"Software\KAM Security\test-menu-{}", std::process::id());
        write_string(&format!(r"{key}\command"), "", "hello").unwrap();
        assert_eq!(
            read_string(&format!(r"{key}\command"), "").as_deref(),
            Some("hello")
        );
        remove_tree(&key).unwrap();
        assert_eq!(read_string(&format!(r"{key}\command"), ""), None);
        remove_tree(&key).unwrap();
    }
}
