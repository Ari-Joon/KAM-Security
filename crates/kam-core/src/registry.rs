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
use windows::Win32::Foundation::{ERROR_SUCCESS, WIN32_ERROR};
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

impl Key {
    /// Open a subkey for reading. `None` when it does not exist, which is
    /// normal — plenty of machines have no `WOW6432Node` uninstall key.
    pub fn open(root: HKEY, path: &str, view: View) -> Option<Self> {
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
        (status == ERROR_SUCCESS).then_some(Self(handle))
    }

    fn open_child(&self, name: &str) -> Option<Self> {
        let mut handle = HKEY::default();
        let name = wide(name);
        let status =
            unsafe { RegOpenKeyExW(self.0, PCWSTR(name.as_ptr()), None, KEY_READ, &mut handle) };
        (status == ERROR_SUCCESS).then_some(Self(handle))
    }

    /// Names of every subkey.
    pub fn subkey_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        let mut index = 0_u32;
        loop {
            // Key names are capped at 255 characters by the registry itself.
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
            if status != ERROR_SUCCESS {
                break;
            }
            names.push(from_wide(&buffer));
            index += 1;
        }
        names
    }

    /// Names of every value directly under this key.
    ///
    /// The counterpart to `subkey_names`, and what the auto-start keys need:
    /// there the interesting information is the values, not the subkeys.
    pub fn value_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        let mut index = 0_u32;
        loop {
            // Value names are capped at 16383 characters, but anything that
            // long is not a name a person wrote. A generous fixed buffer keeps
            // this a single call per value.
            let mut buffer = [0_u16; 1024];
            let mut length = buffer.len() as u32;
            let status: WIN32_ERROR = unsafe {
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
            };
            if status != ERROR_SUCCESS {
                break;
            }
            names.push(from_wide(&buffer));
            index += 1;
        }
        names
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
    use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;

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
