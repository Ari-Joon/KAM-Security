//! The little bit of registry reading this project needs.
//!
//! Open a key, list its subkeys, read string and DWORD values. Deliberately not
//! a general registry library.
//!
//! It lives in the shared crate because two modules now need it for unrelated
//! reasons: storage reads the uninstall keys to find what is installed, and the
//! scanner reads the Run keys to find what starts itself.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS,
    ERROR_PATH_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, RegQueryValueExW, HKEY, KEY_READ,
    KEY_WOW64_32KEY, KEY_WOW64_64KEY, REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_SAM_FLAGS, REG_SZ,
    REG_VALUE_TYPE,
};

/// Which of the two registry views to read.
///
/// A 32-bit application on 64-bit Windows registers itself under
/// `WOW6432Node`, and the two views list entirely different software. Reading
/// only one misses roughly half of what is installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Native,
    Wow6432,
}

impl View {
    fn flag(self) -> REG_SAM_FLAGS {
        match self {
            Self::Native => KEY_WOW64_64KEY,
            Self::Wow6432 => KEY_WOW64_32KEY,
        }
    }
}

/// An open registry key that closes itself.
#[derive(Debug)]
pub struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide(buffer: &[u16]) -> String {
    let end = buffer.iter().position(|c| *c == 0).unwrap_or(buffer.len());
    OsString::from_wide(&buffer[..end])
        .to_string_lossy()
        .into_owned()
}

/// Why a key could not be opened.
///
/// The distinction is the whole point. A key that is not there and a key this
/// account may not read look identical to a caller that only gets `None`, and
/// they mean opposite things: the first is a fact about the machine, the second
/// is a limit on the observer. Software that reports the second as the first is
/// claiming to have looked when it did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unopened {
    /// Not there. Ordinary — plenty of machines have no `WOW6432Node`
    /// uninstall key, and `RunOnce` is absent as often as not.
    Absent,
    /// There, and this account may not read it.
    Denied,
    /// Something else went wrong. The code is kept so it can be named rather
    /// than folded into a shrug.
    Failed(u32),
}

impl Unopened {
    fn from(status: WIN32_ERROR) -> Self {
        match status {
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Self::Absent,
            ERROR_ACCESS_DENIED => Self::Denied,
            other => Self::Failed(other.0),
        }
    }

    /// How to describe this to a person, with `what` naming the key.
    pub fn describe(self, what: &str) -> String {
        match self {
            Self::Absent => format!("{what} is not present on this machine"),
            Self::Denied => format!("{what} could not be read by this account"),
            Self::Failed(code) => format!("{what} could not be read (Windows error {code})"),
        }
    }
}

/// What one enumeration of a key returned, and whether it is the whole of it.
///
/// A list that stopped early and a list that ended are the same `Vec` and mean
/// different things, so they are not allowed to be the same value. The caller
/// that needs to say "and there may be more" can; the caller that only wants
/// names still gets names.
#[derive(Debug, Clone, Default)]
pub struct Listing {
    pub names: Vec<String>,
    /// False when enumeration stopped before Windows said there was no more.
    ///
    /// This is not hypothetical. Value names run to 16383 characters and the
    /// buffer here is smaller, so before the retry below, one value with a
    /// long name ended the enumeration where it stood and everything after it
    /// vanished from the survey — plantable by anyone who can write a Run key,
    /// and silent.
    pub whole: bool,
}

impl Key {
    /// Open a subkey for reading. `None` when it could not be opened for any
    /// reason. Use [`Key::look`] where the reason matters, which is anywhere
    /// the absence of results will be reported to a person.
    pub fn open(root: HKEY, path: &str, view: View) -> Option<Self> {
        Self::look(root, path, view).ok()
    }

    /// Open a subkey, saying why if it could not be opened.
    pub fn look(root: HKEY, path: &str, view: View) -> std::result::Result<Self, Unopened> {
        let mut handle = HKEY::default();
        let path = wide(path);
        let status = unsafe {
            RegOpenKeyExW(
                root,
                PCWSTR(path.as_ptr()),
                None,
                KEY_READ | view.flag(),
                &mut handle,
            )
        };
        if status == ERROR_SUCCESS {
            Ok(Self(handle))
        } else {
            Err(Unopened::from(status))
        }
    }

    fn open_child(&self, name: &str) -> Option<Self> {
        self.look_child(name).ok()
    }

    /// Open a subkey of this one, saying why if it could not be opened.
    pub fn look_child(&self, name: &str) -> std::result::Result<Self, Unopened> {
        let mut handle = HKEY::default();
        let name = wide(name);
        let status =
            unsafe { RegOpenKeyExW(self.0, PCWSTR(name.as_ptr()), None, KEY_READ, &mut handle) };
        if status == ERROR_SUCCESS {
            Ok(Self(handle))
        } else {
            Err(Unopened::from(status))
        }
    }

    /// Names of every subkey.
    pub fn subkey_names(&self) -> Vec<String> {
        self.subkeys().names
    }

    /// Names of every subkey, and whether the enumeration ran to the end.
    pub fn subkeys(&self) -> Listing {
        let mut names = Vec::new();
        let mut index = 0_u32;
        loop {
            // Key names are capped at 255 characters by the registry itself,
            // so the buffer cannot be too small — but the failure is handled
            // the same way regardless, because "cannot happen" is how the
            // value-name truncation below got in.
            let mut buffer = [0_u16; 256];
            let mut length = buffer.len() as u32;
            let status: WIN32_ERROR = unsafe {
                RegEnumKeyExW(
                    self.0,
                    index,
                    Some(windows::core::PWSTR(buffer.as_mut_ptr())),
                    &mut length,
                    None,
                    None,
                    None,
                    None,
                )
            };
            match status {
                ERROR_SUCCESS => {
                    names.push(from_wide(&buffer));
                    index += 1;
                }
                ERROR_NO_MORE_ITEMS => return Listing { names, whole: true },
                _ => {
                    return Listing {
                        names,
                        whole: false,
                    }
                }
            }
        }
    }

    /// Names of every value directly under this key.
    ///
    /// The counterpart to `subkey_names`, and what the auto-start keys need:
    /// there the interesting information is the values, not the subkeys.
    pub fn value_names(&self) -> Vec<String> {
        self.values().names
    }

    /// Names of every value, and whether the enumeration ran to the end.
    ///
    /// # The buffer that was an exploit
    ///
    /// This read into a fixed 1024-character buffer and stopped on any status
    /// that was not success, with a comment reasoning that no person writes a
    /// name that long. People do not; the thing this software is looking for
    /// is not a person. A value name over 1023 characters makes Windows return
    /// `ERROR_MORE_DATA` without advancing the index, so the old loop ended
    /// there — and every value after it disappeared from the survey silently.
    ///
    /// That is plantable by anything that can write a Run key, and it is worse
    /// than a blind spot: the entries that vanish from the survey were in the
    /// baseline, so the next sweep reports the machine's *legitimate* startup
    /// entries as removed while hiding the one that did it.
    ///
    /// So a name too long for the buffer is read again with a buffer big
    /// enough for the largest name the registry permits, and a failure that is
    /// still not the end of the list is reported as a partial read rather than
    /// passed off as the whole.
    pub fn values(&self) -> Listing {
        // The registry's own cap on a value name, plus the terminator.
        const LONGEST: usize = 16384;

        let mut names = Vec::new();
        let mut index = 0_u32;
        loop {
            // Small buffer first, since essentially every real name fits it
            // and this runs once per value on keys with many.
            let mut buffer = vec![0_u16; 1024];
            let mut status = self.enumerate_value(index, &mut buffer);
            if status == ERROR_MORE_DATA {
                buffer = vec![0_u16; LONGEST];
                status = self.enumerate_value(index, &mut buffer);
            }
            match status {
                ERROR_SUCCESS => {
                    names.push(from_wide(&buffer));
                    index += 1;
                }
                ERROR_NO_MORE_ITEMS => return Listing { names, whole: true },
                _ => {
                    return Listing {
                        names,
                        whole: false,
                    }
                }
            }
        }
    }

    /// One `RegEnumValueW` call, so the retry above reads as a retry.
    fn enumerate_value(&self, index: u32, buffer: &mut [u16]) -> WIN32_ERROR {
        let mut length = buffer.len() as u32;
        unsafe {
            RegEnumValueW(
                self.0,
                index,
                Some(windows::core::PWSTR(buffer.as_mut_ptr())),
                &mut length,
                None,
                None,
                None,
                None,
            )
        }
    }

    pub fn child(&self, name: &str) -> Option<Self> {
        self.open_child(name)
    }

    /// Read a string value. Empty strings come back as `None`, since an empty
    /// `InstallLocation` is as useless as an absent one.
    pub fn string(&self, value: &str) -> Option<String> {
        let name = wide(value);
        let mut kind = REG_VALUE_TYPE::default();
        let mut size = 0_u32;

        let status = unsafe {
            RegQueryValueExW(
                self.0,
                PCWSTR(name.as_ptr()),
                None,
                Some(&mut kind),
                None,
                Some(&mut size),
            )
        };
        if status != ERROR_SUCCESS || (kind != REG_SZ && kind != REG_EXPAND_SZ) || size == 0 {
            return None;
        }

        let mut data = vec![0_u8; size as usize];
        let status = unsafe {
            RegQueryValueExW(
                self.0,
                PCWSTR(name.as_ptr()),
                None,
                None,
                Some(data.as_mut_ptr()),
                Some(&mut size),
            )
        };
        if status != ERROR_SUCCESS {
            return None;
        }

        let units: Vec<u16> = data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        let text = from_wide(&units).trim().to_owned();
        (!text.is_empty()).then_some(text)
    }

    /// Read a raw binary value.
    ///
    /// Windows keeps a surprising amount in `REG_BINARY` blobs whose layout is
    /// documented nowhere official — the run counts and last-run times under
    /// `UserAssist` among them. Handing back the bytes keeps the decoding with
    /// the code that understands the layout, rather than teaching this module
    /// about every structure Windows invents.
    pub fn binary(&self, value: &str) -> Option<Vec<u8>> {
        let name = wide(value);
        let mut kind = REG_VALUE_TYPE::default();
        let mut size = 0_u32;

        let status = unsafe {
            RegQueryValueExW(
                self.0,
                PCWSTR(name.as_ptr()),
                None,
                Some(&mut kind),
                None,
                Some(&mut size),
            )
        };
        if status != ERROR_SUCCESS || kind != REG_BINARY || size == 0 {
            return None;
        }

        let mut data = vec![0_u8; size as usize];
        let status = unsafe {
            RegQueryValueExW(
                self.0,
                PCWSTR(name.as_ptr()),
                None,
                None,
                Some(data.as_mut_ptr()),
                Some(&mut size),
            )
        };
        (status == ERROR_SUCCESS).then(|| {
            data.truncate(size as usize);
            data
        })
    }

    pub fn dword(&self, value: &str) -> Option<u32> {
        let name = wide(value);
        let mut kind = REG_VALUE_TYPE::default();
        let mut data = 0_u32;
        let mut size = std::mem::size_of::<u32>() as u32;

        let status = unsafe {
            RegQueryValueExW(
                self.0,
                PCWSTR(name.as_ptr()),
                None,
                Some(&mut kind),
                Some(&mut data as *mut u32 as *mut u8),
                Some(&mut size),
            )
        };
        (status == ERROR_SUCCESS && kind == REG_DWORD).then_some(data)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

    #[test]
    fn a_well_known_key_opens_and_reads() {
        let key = Key::open(
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            View::Native,
        )
        .expect("the CurrentVersion key should exist on every Windows install");

        let product = key
            .string("ProductName")
            .expect("ProductName should be set");
        assert!(
            product.to_lowercase().contains("windows"),
            "unexpected ProductName: {product}"
        );
    }

    #[test]
    fn a_missing_key_is_none_rather_than_a_panic() {
        assert!(Key::open(
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\This\Does\Not\Exist\Anywhere",
            View::Native
        )
        .is_none());
    }

    #[test]
    fn a_key_that_exists_but_is_refused_is_not_reported_as_absent() {
        // The SAM hive is present on every Windows machine and readable by
        // SYSTEM alone, so an ordinary account gets a refusal rather than a
        // "not there". Under an elevated test runner it opens, and the point
        // being made is only that the two are told apart -- so both outcomes
        // are accepted and the one that must not happen is `Absent`.
        match Key::look(HKEY_LOCAL_MACHINE, r"SAM\SAM", View::Native) {
            Ok(_) => {}
            Err(Unopened::Denied) | Err(Unopened::Failed(_)) => {}
            Err(Unopened::Absent) => {
                panic!("a key that exists was reported as not existing")
            }
        }
    }

    /// A long value name must not end the enumeration where it stands.
    ///
    /// # Why this is written against the real registry
    ///
    /// The code this replaces had a comment reasoning that nobody writes a
    /// value name a thousand characters long. Nobody does. The thing this
    /// software looks for is not a person, and anything that can write a Run
    /// key can write one -- after which `RegEnumValueW` returns
    /// `ERROR_MORE_DATA` without advancing, the old loop stopped, and every
    /// value after it was invisible.
    ///
    /// The consequence was worse than a blind spot. Those values were in the
    /// baseline, so the next sweep would report the machine's legitimate
    /// startup entries as removed while saying nothing about the entry that
    /// did it: a false alarm and a hiding place from the same two lines.
    ///
    /// Asserting that reasoning against a mock would prove nothing. This
    /// writes the name Windows actually has to enumerate.
    #[test]
    fn a_value_name_too_long_for_the_buffer_does_not_end_the_list() {
        let where_it_goes = r"Software\KAM Security\enumeration test";
        let long_name = "n".repeat(2000);

        let planted = std::process::Command::new("reg.exe")
            .args([
                "add",
                &format!(r"HKCU\{where_it_goes}"),
                "/v",
                &long_name,
                "/t",
                "REG_SZ",
                "/d",
                "long",
                "/f",
            ])
            .output();
        let Ok(planted) = planted else {
            eprintln!("reg.exe would not run; nothing proved");
            return;
        };
        if !planted.status.success() {
            eprintln!("could not plant the long name; nothing proved");
            return;
        }

        let _ = std::process::Command::new("reg.exe")
            .args([
                "add",
                &format!(r"HKCU\{where_it_goes}"),
                "/v",
                "after",
                "/t",
                "REG_SZ",
                "/d",
                "short",
                "/f",
            ])
            .output();

        let listing = Key::open(HKEY_CURRENT_USER, where_it_goes, View::Native)
            .expect("the key just written should open")
            .values();

        // Tidy up before asserting, so a failure does not leave the key behind.
        let _ = std::process::Command::new("reg.exe")
            .args(["delete", &format!(r"HKCU\{where_it_goes}"), "/f"])
            .output();

        assert!(
            listing.whole,
            "the enumeration stopped early and said it was complete"
        );
        assert!(
            listing.names.iter().any(|name| name == "after"),
            "a value after a long-named one was not listed: {:?}",
            listing.names
        );
        assert!(
            listing.names.iter().any(|name| name.len() == 2000),
            "the long name itself was not listed: {:?}",
            listing
                .names
                .iter()
                .map(std::string::String::len)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_uninstall_key_lists_subkeys() {
        let key = Key::open(
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            View::Native,
        )
        .expect("the uninstall key should exist");
        assert!(
            !key.subkey_names().is_empty(),
            "no installed software found at all, which cannot be right"
        );
    }
}
