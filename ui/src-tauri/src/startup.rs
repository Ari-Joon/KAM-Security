//! Starting with Windows, so KAM Security is there from the moment you sign in.
//!
//! # What it does
//!
//! It adds one value, named "KAM Security", to the person's own `Run` key. It
//! starts this program in the notification area without opening a window, so
//! the icon is there from sign-in and costs nothing until someone opens it.
//! The protection itself does not depend on this: that is the service, which
//! Windows starts at boot before anyone signs in. This makes the protection
//! visible, and makes the window one click away.
//!
//! # On by default, and never quietly
//!
//! This product reports on everything that starts itself, so adding itself to
//! that list silently would be the one thing it cannot do. It is turned on the
//! first time the program runs, and the Overview says so in plain words beside
//! the switch that turns it off. The entry also appears in this program's own
//! list of what starts itself, named as KAM Security itself.
//!
//! It lives in the person's own hive, written by this unelevated process as
//! them. Another account on the same machine decides for itself.

use std::os::windows::ffi::OsStrExt;

use serde::Serialize;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteKeyValueW, RegGetValueW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_SET_VALUE, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ, RRF_RT_REG_DWORD,
    RRF_RT_REG_SZ,
};

const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const NAME: &str = "KAM Security";

/// Where the person's choice is remembered, so the default is applied once.
const CHOICE_KEY: &str = r"Software\KAM Security";
const CHOICE_VALUE: &str = "StartAtSignIn";

/// Passed by the `Run` entry, so a sign-in start opens no window.
pub const BACKGROUND: &str = "--background";

#[derive(Debug, Clone, Serialize)]
pub struct StartState {
    /// True when the `Run` entry exists and starts this program.
    pub enabled: bool,
    /// True when an entry named "KAM Security" exists but starts something
    /// else, for instance an older copy in another folder. Reported rather than
    /// silently overwritten or silently counted as on.
    pub points_elsewhere: bool,
    /// True when this launch is the one that turned it on by default, so the
    /// window can say so once.
    pub turned_on_now: bool,
}

/// Read the current state.
pub fn state(turned_on_now: bool) -> StartState {
    let wanted = command();
    match read_string(RUN, NAME) {
        Some(existing) => {
            let ours = wanted
                .as_deref()
                .is_some_and(|wanted| existing.eq_ignore_ascii_case(wanted));
            StartState {
                enabled: ours,
                points_elsewhere: !ours,
                turned_on_now,
            }
        }
        None => StartState {
            enabled: false,
            points_elsewhere: false,
            turned_on_now,
        },
    }
}

/// Turn starting at sign-in on or off, and remember that the person chose.
pub fn set(enabled: bool) -> Result<StartState, String> {
    if enabled {
        let command = command().ok_or("could not work out where this program is")?;
        write_string(RUN, NAME, &command)?;
    } else {
        remove(RUN, NAME)?;
    }
    write_dword(CHOICE_KEY, CHOICE_VALUE, u32::from(enabled))?;
    Ok(state(false))
}

/// On a first run, turn it on and say so. Returns whether it did.
///
/// A choice already recorded, either way, is left alone: somebody who turned it
/// off stays off across updates and reinstalls.
pub fn apply_first_run_default() -> bool {
    if read_dword(CHOICE_KEY, CHOICE_VALUE).is_some() {
        return false;
    }
    set(true).is_ok()
}

/// The command the `Run` entry holds: this program, quoted, started in the
/// background.
fn command() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    Some(format!("\"{}\" {BACKGROUND}", exe.display()))
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

/// Open a key under the person's own hive for writing, creating it if needed.
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
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(format!(
            "could not write {value}: Windows error {}",
            status.0
        ))
    }
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
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(format!(
            "could not write {value}: Windows error {}",
            status.0
        ))
    }
}

fn remove(key: &str, value: &str) -> Result<(), String> {
    let key_wide = wide(key);
    let name = wide(value);
    let status = unsafe {
        RegDeleteKeyValueW(
            HKEY_CURRENT_USER,
            PCWSTR(key_wide.as_ptr()),
            PCWSTR(name.as_ptr()),
        )
    };
    // Already absent is the state that was asked for.
    if status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND {
        Ok(())
    } else {
        Err(format!(
            "could not remove {value}: Windows error {}",
            status.0
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The entry names this program, quoted, and starts it in the background.
    ///
    /// Quoted because the install path contains spaces, and an unquoted path
    /// with spaces in a `Run` value is resolved by trying each prefix in turn.
    #[test]
    fn the_command_is_quoted_and_starts_in_the_background() {
        let command = command().unwrap();
        assert!(command.starts_with('"'), "{command}");
        assert!(command.ends_with(&format!("\" {BACKGROUND}")), "{command}");
    }

    /// Round trip through a scratch value in the person's own hive, never the
    /// real `Run` key: tests must not change what starts at sign-in.
    #[test]
    fn a_value_written_reads_back_and_removal_is_final() {
        let key = format!(r"Software\KAM Security\test-startup-{}", std::process::id());
        write_string(&key, "probe", "hello").unwrap();
        assert_eq!(read_string(&key, "probe").as_deref(), Some("hello"));
        remove(&key, "probe").unwrap();
        assert_eq!(read_string(&key, "probe"), None);
        // Removing what is already gone is not an error.
        remove(&key, "probe").unwrap();
        let _ = unsafe {
            windows::Win32::System::Registry::RegDeleteKeyW(
                HKEY_CURRENT_USER,
                PCWSTR(wide(&key).as_ptr()),
            )
        };
    }
}
