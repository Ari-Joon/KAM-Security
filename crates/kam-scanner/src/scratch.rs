//! A made-up registry key for tests, under this account's own hive.
//!
//! Readers that take where to read from are pointed at one of these in place
//! of the machine's real keys, so what a setting of some shape reads as can be
//! tested without the machine having that setting, and without writing
//! anywhere the product itself reads. Removed, with everything under it, when
//! dropped.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegDeleteTreeW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_DWORD, REG_EXPAND_SZ, REG_OPTION_NON_VOLATILE,
    REG_SZ, REG_VALUE_TYPE,
};

pub(crate) struct ScratchKey {
    /// Where it is, under `HKEY_CURRENT_USER`.
    pub path: String,
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Text as a string value holds it: UTF-16 with its terminator.
pub(crate) fn wide_bytes(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

impl ScratchKey {
    pub fn new(tag: &str) -> Self {
        let key = Self {
            path: format!(
                r"Software\KAM Security\test {tag} {} {}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|since| since.as_nanos())
                    .unwrap_or(0)
            ),
        };
        key.make("");
        key
    }

    /// The full path of a key under this one, as it would be opened.
    pub fn under(&self, key: &str) -> String {
        if key.is_empty() {
            self.path.clone()
        } else {
            format!(r"{}\{key}", self.path)
        }
    }

    /// Make a key, and everything above it, if it is not there.
    pub fn make(&self, key: &str) -> HKEY {
        let path = self.under(key);
        let wide_path = wide(&path);
        let mut handle = HKEY::default();
        let made = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(wide_path.as_ptr()),
                None,
                PWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_READ | KEY_WRITE,
                None,
                &mut handle,
                None,
            )
        };
        assert_eq!(made, ERROR_SUCCESS, "could not create {path}");
        handle
    }

    /// Write one value, making the key it lives in if it is not there.
    pub fn put(&self, key: &str, name: &str, kind: REG_VALUE_TYPE, data: &[u8]) {
        let handle = self.make(key);
        let wide_name = wide(name);
        let set =
            unsafe { RegSetValueExW(handle, PCWSTR(wide_name.as_ptr()), None, kind, Some(data)) };
        unsafe {
            let _ = RegCloseKey(handle);
        }
        assert_eq!(set, ERROR_SUCCESS, "could not write {name} in {key}");
    }

    pub fn text(&self, key: &str, name: &str, value: &str) {
        self.put(key, name, REG_SZ, &wide_bytes(value));
    }

    /// Text with its variables left in, as Windows stores paths.
    pub fn expandable(&self, key: &str, name: &str, value: &str) {
        self.put(key, name, REG_EXPAND_SZ, &wide_bytes(value));
    }

    pub fn number(&self, key: &str, name: &str, value: u32) {
        self.put(key, name, REG_DWORD, &value.to_le_bytes());
    }
}

impl Drop for ScratchKey {
    fn drop(&mut self) {
        let path = wide(&self.path);
        unsafe {
            let _ = RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(path.as_ptr()));
            let _ = RegDeleteKeyW(HKEY_CURRENT_USER, PCWSTR(path.as_ptr()));
        }
    }
}
