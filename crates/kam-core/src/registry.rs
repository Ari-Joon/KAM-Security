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
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_PATH_NOT_FOUND,
    ERROR_SUCCESS, WIN32_ERROR,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, RegQueryInfoKeyW, RegQueryValueExW,
    HKEY, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY, REG_BINARY, REG_DWORD, REG_EXPAND_SZ,
    REG_SAM_FLAGS, REG_SZ, REG_VALUE_TYPE,
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

/// Decode an enumerated name using the length Windows reported.
///
/// # A name that hides inside another name
///
/// [`from_wide`] stops at the first NUL, which is right for a value read back
/// as text and wrong for a name that came out of an enumeration. `NtSetValueKey`
/// and `NtCreateKey` take counted strings rather than NUL-terminated ones, so a
/// name may contain a NUL — and needs no privilege at all on `HKCU`. It is the
/// Poweliks technique, aimed at the very key the startup reader walks.
///
/// Decoded to the first NUL, `Updater` and `Updater␀evil` are the same string.
/// Two values collapse to one name, the count still agrees, and the walk
/// reports `whole: true` — an affirmative claim to have read the key to the
/// end, covering the entry it did not report. Reading the returned length keeps
/// them apart, after which the name simply cannot be looked up through the
/// NUL-terminated Win32 entry points, and the caller has to say so rather than
/// treat it as a value that is not there.
fn exactly(buffer: &[u16], length: u32) -> String {
    let end = (length as usize).min(buffer.len());
    OsString::from_wide(&buffer[..end])
        .to_string_lossy()
        .into_owned()
}

/// Whether a name holds a character that hides it from Registry Editor.
///
/// Worth telling a person in as many words: no installer produces one, and
/// nothing in Windows' own interface will show it to them.
pub fn is_hidden_name(name: &str) -> bool {
    name.contains('\0')
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
///
/// `whole` defaults to false, so a `Listing` that nothing filled in claims
/// nothing. That is the right way round: the cost of wrongly saying "there may
/// be more" is a line of text, and the cost of wrongly saying "that was all of
/// them" is reporting things as removed that were never looked at.
#[derive(Debug, Clone, Default)]
pub struct Listing {
    pub names: Vec<String>,
    /// True only when as many entries came back as Windows said there were.
    ///
    /// Not "the loop ended tidily". A key can be written to while it is being
    /// walked, and index-based enumeration is not a snapshot — deleting an
    /// entry mid-walk makes the following one skip, and the walk still ends
    /// normally. Counting is what tells those apart.
    pub whole: bool,
}

/// How much Windows says a key holds, asked before walking it.
#[derive(Debug, Clone, Copy)]
struct Shape {
    subkeys: u32,
    longest_subkey: u32,
    values: u32,
    longest_value: u32,
}

/// How many times a walk is repeated while the count disagrees.
///
/// Small on purpose. This is not about being sure, it is about not letting one
/// concurrent write -- from an installer, or from something that would like the
/// enumeration to stay incomplete -- decide what the sweep may report.
const RETRIES: usize = 3;

impl Shape {
    /// Finish a walk, claiming completeness only if the count agrees.
    fn finish(self, names: Vec<String>, expected: u32) -> Listing {
        let whole = names.len() == expected as usize;
        Listing { names, whole }
    }
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

    /// Names of every subkey, and whether that is all of them.
    ///
    /// Retried while the count disagrees, because a key written to during the
    /// walk is usually an installer rather than an adversary -- and because a
    /// single lost race would otherwise be as good as an attack. A resident
    /// process that adds and removes a service key during every sweep would
    /// hold the enumeration permanently incomplete, and an incomplete
    /// enumeration is the one gap that has to cover the whole kind, since
    /// there is no telling which entry was missed. Three tries turns "win once"
    /// into "win three times in a row, every sweep, forever".
    pub fn subkeys(&self) -> Listing {
        for _ in 0..RETRIES {
            let listing = self.walk_subkeys();
            if listing.whole {
                return listing;
            }
        }
        self.walk_subkeys()
    }

    fn walk_subkeys(&self) -> Listing {
        let Some(shape) = self.shape() else {
            // Nothing is known about how many there should be, so nothing may
            // be claimed about having got them all.
            return Listing::default();
        };

        let mut names = Vec::new();
        let mut index = 0_u32;
        loop {
            // Sized from what Windows just said the longest name is, so there
            // is no buffer to be too small and no reasoning about what length
            // a name "realistically" has.
            let mut buffer = vec![0_u16; shape.longest_subkey as usize + 1];
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
                    names.push(exactly(&buffer, length));
                    index += 1;
                }
                _ => return shape.finish(names, shape.subkeys),
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

    /// Names of every value, and whether that is all of them.
    ///
    /// # Two ways this lied, and why counting fixes both
    ///
    /// It read into a fixed 1024-character buffer and stopped on any status
    /// that was not success, reasoning that no person writes a value name that
    /// long. People do not; the thing this software looks for is not a person.
    /// A name over 1023 characters returns `ERROR_MORE_DATA` without advancing
    /// the index, so the loop ended there and every value after it disappeared
    /// from the survey while the list reported itself complete.
    ///
    /// Then, with that fixed by retrying on a bigger buffer, Red demonstrated
    /// the deeper one: index-based enumeration is not a snapshot. Delete the
    /// value just read at index 0 and continue at index 1, and the value that
    /// *was* at index 1 is never returned — the list still ends on
    /// `ERROR_NO_MORE_ITEMS` and still called itself whole. Anything running as
    /// the user can write its own `Run` key, so anything running as the user
    /// could make the machine's real startup entries flap on demand: three
    /// flaps and they are downgraded to `Recurring`, which is a quiet bucket
    /// an attacker can then park their own entry in.
    ///
    /// Asking Windows how many values there are, and comparing, answers both.
    /// A name cannot be too long for a buffer sized from the reported maximum,
    /// and a key mutated underneath the walk comes back with the wrong count
    /// and says so. The retry, the guessed buffer size and the constant for
    /// the registry's own limit all stop being needed.
    pub fn values(&self) -> Listing {
        for _ in 0..RETRIES {
            let listing = self.walk_values();
            if listing.whole {
                return listing;
            }
        }
        self.walk_values()
    }

    fn walk_values(&self) -> Listing {
        let Some(shape) = self.shape() else {
            return Listing::default();
        };

        let mut names = Vec::new();
        let mut index = 0_u32;
        loop {
            let mut buffer = vec![0_u16; shape.longest_value as usize + 1];
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
            match status {
                ERROR_SUCCESS => {
                    names.push(exactly(&buffer, length));
                    index += 1;
                }
                _ => return shape.finish(names, shape.values),
            }
        }
    }

    /// What Windows says this key holds, asked before walking it.
    ///
    /// `None` when the question could not be answered, which is the only
    /// honest response to "did you get them all" in that case.
    fn shape(&self) -> Option<Shape> {
        let mut subkeys = 0_u32;
        let mut longest_subkey = 0_u32;
        let mut values = 0_u32;
        let mut longest_value = 0_u32;
        let status = unsafe {
            RegQueryInfoKeyW(
                self.0,
                None,
                None,
                None,
                Some(&mut subkeys),
                Some(&mut longest_subkey),
                None,
                Some(&mut values),
                Some(&mut longest_value),
                None,
                None,
                None,
            )
        };
        (status == ERROR_SUCCESS).then_some(Shape {
            subkeys,
            // Both maxima are in characters and exclude the terminator, which
            // the buffers above add back. The `cb` in the parameter names is
            // misleading; for the wide entry points these are character counts.
            longest_subkey,
            values,
            longest_value,
        })
    }

    pub fn child(&self, name: &str) -> Option<Self> {
        self.open_child(name)
    }

    /// Read a string value. Empty strings come back as `None`, since an empty
    /// `InstallLocation` is as useless as an absent one.
    pub fn string(&self, value: &str) -> Option<String> {
        self.read_string(value).ok().flatten()
    }

    /// The same, keeping a failed read apart from a value that is not there.
    ///
    /// Both came back as `None`, and the caller in the startup reader treats
    /// `None` as "nothing to record" -- so a value that could not be read left
    /// the survey silently and was reported as removed on the next sweep. The
    /// reader is looking at the `Run` keys, where the writer of the value is
    /// whoever is being looked for: alternating one between a short and a long
    /// string makes a legitimate startup entry come and go on demand.
    pub fn read_string(&self, value: &str) -> std::result::Result<Option<String>, Unopened> {
        // Two calls, one for the size and one for the data, so a value that
        // grows in between returns ERROR_MORE_DATA. Retried rather than
        // treated as absent, and a retry that keeps losing is a failure that
        // gets said out loud.
        for _ in 0..4 {
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
            if status == ERROR_FILE_NOT_FOUND {
                return Ok(None);
            }
            if status != ERROR_SUCCESS {
                return Err(Unopened::from(status));
            }
            // Not a string, which is a fact about the value rather than a
            // failure to read it.
            if (kind != REG_SZ && kind != REG_EXPAND_SZ) || size == 0 {
                return Ok(None);
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
            if status == ERROR_MORE_DATA {
                continue;
            }
            if status != ERROR_SUCCESS {
                return Err(Unopened::from(status));
            }

            return Ok(Self::text_of(&data));
        }
        Err(Unopened::Failed(ERROR_MORE_DATA.0))
    }

    /// Decode what a string value's bytes hold.
    fn text_of(data: &[u8]) -> Option<String> {
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
        self.read_dword(value).ok().flatten()
    }

    /// The same, keeping a failed read apart from a value that is not there.
    ///
    /// The two are not close in meaning and are very different in frequency.
    /// Most keys under `Services` are not services at all -- performance
    /// counter registrations, protocol stubs, driver placeholders -- and have
    /// no `Start` value whatsoever. On this machine 55 of them, so treating a
    /// missing value as a failed read named 55 perfectly ordinary keys as gaps
    /// and suppressed vanish reporting across all of them. Absence here is the
    /// common case and says nothing; only a refusal is worth reporting.
    pub fn read_dword(&self, value: &str) -> std::result::Result<Option<u32>, Unopened> {
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
        match status {
            ERROR_SUCCESS if kind == REG_DWORD => Ok(Some(data)),
            // There, and not a number. A fact about the value.
            ERROR_SUCCESS => Ok(None),
            ERROR_FILE_NOT_FOUND => Ok(None),
            other => Err(Unopened::from(other)),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use windows::core::PWSTR;
    // Write entry points, used only to plant what these tests then read. The
    // module itself stays read-only on purpose.
    use windows::Win32::System::Registry::{
        RegCreateKeyExW, RegDeleteKeyW, RegSetValueExW, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
        KEY_WRITE, REG_OPTION_NON_VOLATILE,
    };

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

    /// A name with a NUL in it is not the name up to the NUL.
    ///
    /// `NtSetValueKey` takes a counted string, so a value name may contain a
    /// NUL, and writing one to `HKCU` needs no privilege at all. Decoded to the
    /// first NUL, `Updater` and `Updater` followed by NUL and `evil` are the
    /// same string: two values collapse to one name, the count still agrees,
    /// and the walk reports `whole: true` -- an affirmative claim to have read
    /// the whole key, covering the entry it did not report.
    ///
    /// Tested at the decode rather than by planting one, because the decode is
    /// what was wrong, and a test needing `ntdll` to set itself up is a test
    /// that quietly stops running.
    #[test]
    fn a_name_holding_a_nul_is_not_truncated_at_it() {
        // As `RegEnumValueW` fills a buffer: the characters, then whatever was
        // already in it.
        let mut buffer = vec![0_u16; 32];
        for (slot, unit) in buffer.iter_mut().zip("Updater\0evil".encode_utf16()) {
            *slot = unit;
        }

        assert_eq!(exactly(&buffer, 12), "Updater\0evil");
        assert_ne!(
            exactly(&buffer, 12),
            "Updater",
            "the hidden half of the name was dropped"
        );
        assert!(is_hidden_name(&exactly(&buffer, 12)));

        // An ordinary name is unaffected.
        assert_eq!(exactly(&buffer, 7), "Updater");
        assert!(!is_hidden_name("Updater"));
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

    /// A scratch key under HKCU that removes itself, for planting into.
    ///
    /// Written through the API rather than by shelling out to `reg.exe`. The
    /// first version of these tests ran `reg.exe` and *returned early* when it
    /// could not, which is a pass -- so on a runner without System32 on PATH,
    /// or with the registry-tools policy set, the test proved nothing and
    /// still went green. A test whose premise cannot be established has
    /// failed; it has not succeeded.
    struct Scratch {
        path: String,
        // Kept open for writing. Reopening through `Key::look` would hand back
        // a read-only handle, since that is all this module ever asks for.
        handle: HKEY,
    }

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = format!(r"Software\KAM Security\test {name} {}", std::process::id());
            let wide_path = wide(&path);
            let mut handle = HKEY::default();
            let status = unsafe {
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
            assert_eq!(status, ERROR_SUCCESS, "could not create {path}");
            Self { path, handle }
        }

        fn put(&self, name: &str, data: &str) {
            let wide_name = wide(name);
            let bytes: Vec<u8> = wide(data)
                .iter()
                .flat_map(|unit| unit.to_le_bytes())
                .collect();
            let status = unsafe {
                RegSetValueExW(
                    self.handle,
                    PCWSTR(wide_name.as_ptr()),
                    None,
                    REG_SZ,
                    Some(&bytes),
                )
            };
            assert_eq!(
                status,
                ERROR_SUCCESS,
                "could not write a value of {} chars",
                name.len()
            );
        }

        fn read(&self) -> Listing {
            Key::look(HKEY_CURRENT_USER, &self.path, View::Native)
                .expect("the scratch key should open")
                .values()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            // Runs even when an assertion fails, so a red test does not leave
            // keys behind for the next one to trip over.
            let path = wide(&self.path);
            unsafe {
                let _ = RegCloseKey(self.handle);
                let _ = RegDeleteKeyW(HKEY_CURRENT_USER, PCWSTR(path.as_ptr()));
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
        let scratch = Scratch::new("long name");
        let long_name = "n".repeat(2000);
        scratch.put(&long_name, "long");
        scratch.put("after", "short");

        let listing = scratch.read();

        assert!(
            listing.whole,
            "the enumeration stopped early and said it was complete: {:?}",
            listing.names.len()
        );
        assert!(
            listing.names.iter().any(|name| name == "after"),
            "a value after a long-named one was not listed: {:?}",
            listing.names
        );
        assert!(
            listing
                .names
                .iter()
                .any(|name| name.chars().count() == 2000),
            "the long name itself was not listed: {:?}",
            listing
                .names
                .iter()
                .map(|name| name.chars().count())
                .collect::<Vec<_>>()
        );
    }

    /// A key written to while it is being walked does not call itself whole.
    ///
    /// Red demonstrated the hole this closes: index-based enumeration is not a
    /// snapshot, so deleting the entry just read makes the next one skip while
    /// the walk still ends on `ERROR_NO_MORE_ITEMS`. Anything running as the
    /// user can write its own `Run` key, so anything running as the user could
    /// make the machine's real startup entries appear to come and go.
    ///
    /// This cannot reproduce the race deterministically from one thread, so it
    /// tests the property that makes the race safe: the count Windows reports
    /// is what completeness is judged against, and a list short of it is not
    /// whole.
    #[test]
    fn a_short_read_is_not_reported_as_the_whole_list() {
        let scratch = Scratch::new("counting");
        for index in 0..4 {
            scratch.put(&format!("value{index}"), "x");
        }

        let listing = scratch.read();
        assert!(listing.whole, "an undisturbed key should read whole");
        assert_eq!(listing.names.len(), 4);

        // What a skipped entry looks like to the code that decides.
        let short = Shape {
            subkeys: 0,
            longest_subkey: 0,
            values: 4,
            longest_value: 16,
        }
        .finish(vec!["value0".to_owned(), "value2".to_owned()], 4);
        assert!(
            !short.whole,
            "a list two short of the reported count called itself complete"
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
