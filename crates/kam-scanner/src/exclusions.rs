//! What Defender has been told to skip: the paths, file extensions, processes
//! and IP addresses it does not look at.
//!
//! # Shown only to an administrator, as Windows shows them
//!
//! Windows hides this list from anyone who is not an administrator, on
//! purpose: knowing it tells an attacker where to hide. The service can read
//! it, and so must not tell a caller that Windows would not, which is why the
//! request for it needs an administrator (`needs_administrator` in the agent)
//! and the window asks through Windows' own permission prompt.
//!
//! # Read from the registry, as the service
//!
//! Every way an ordinary account has of asking is refused, and one of them,
//! `Get-MpPreference`, does not fail: it returns the sentence "N/A: Must be an
//! administrator to view exclusions" in each list, which a careless reader
//! shows as an exclusion. Nothing here runs a program or asks PowerShell.
//! The lists are the names of the values under Defender's own key, and under
//! the policy key where an organisation's policy sets them.

use kam_core::registry::{is_hidden_name, Key, Unopened, View};
use serde::{Deserialize, Serialize};
use windows::Win32::System::Registry::{HKEY, HKEY_LOCAL_MACHINE};

/// Where Defender keeps the lists it was given locally.
const LOCAL: &str = r"SOFTWARE\Microsoft\Windows Defender\Exclusions";

/// Where a policy puts the lists it sets.
const POLICY: &str = r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions";

/// What a list holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Kind {
    Paths,
    Extensions,
    Processes,
    IpAddresses,
    /// Another list Defender keeps beside those four, by its own name.
    Other {
        name: String,
    },
}

/// The four lists Defender documents, by the key each is kept under.
const KINDS: [(&str, Kind); 4] = [
    ("Paths", Kind::Paths),
    ("Extensions", Kind::Extensions),
    ("Processes", Kind::Processes),
    ("IpAddresses", Kind::IpAddresses),
];

/// One thing Defender skips, as Defender holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub value: String,
    /// False when the name holds something that hides part of it, so what is
    /// shown is not exactly what Defender holds.
    pub exact: bool,
}

/// One list, from Defender's own settings or from a policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct List {
    pub kind: Kind,
    /// Set by a policy, under `HKLM\SOFTWARE\Policies`, rather than in
    /// Windows Security or with `Add-MpPreference`.
    pub by_policy: bool,
    pub entries: Vec<Entry>,
    /// False when the list changed while it was read, so it may not be all
    /// of it.
    pub whole: bool,
}

/// Everything Defender has been told to skip.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exclusions {
    pub lists: Vec<List>,
    /// What could not be read, in plain words. Never an empty list instead.
    pub unread: Vec<String>,
}

impl Exclusions {
    /// How many entries there are of one kind, over both places.
    pub fn count(&self, kind: &Kind) -> usize {
        self.lists
            .iter()
            .filter(|list| &list.kind == kind)
            .map(|list| list.entries.len())
            .sum()
    }

    pub fn total(&self) -> usize {
        self.lists.iter().map(|list| list.entries.len()).sum()
    }

    pub fn by_policy(&self) -> usize {
        self.lists
            .iter()
            .filter(|list| list.by_policy)
            .map(|list| list.entries.len())
            .sum()
    }

    /// The lists other than the four Defender documents.
    pub fn others(&self) -> usize {
        self.lists
            .iter()
            .filter(|list| matches!(list.kind, Kind::Other { .. }))
            .map(|list| list.entries.len())
            .sum()
    }
}

/// Read Defender's exclusions. For the service, and only for a caller with
/// administrator rights.
pub fn read() -> Exclusions {
    read_from(HKEY_LOCAL_MACHINE, LOCAL, POLICY)
}

/// Read the lists under `local` and `policy` in `root`. The tests point this
/// at scratch keys laid out the same way, never at Defender's.
fn read_from(root: HKEY, local: &str, policy: &str) -> Exclusions {
    let mut found = Exclusions::default();
    for (base, by_policy) in [(local, false), (policy, true)] {
        let place = if by_policy {
            "The exclusions a policy sets"
        } else {
            "Defender's exclusions"
        };
        let key = match Key::look(root, base, View::Native) {
            Ok(key) => key,
            // Nothing recorded there, which is a fact and not a failure.
            Err(Unopened::Absent) => continue,
            Err(why) => {
                found.unread.push(why.describe(place));
                continue;
            }
        };

        let listed = key.subkeys();
        if !listed.whole {
            found.unread.push(format!(
                "{place} changed while they were listed, so a list may be missing"
            ));
        }
        // The four Defender documents, in a fixed order, then anything else
        // kept beside them, by its own name: a list this has not heard of is
        // still a list.
        let mut names: Vec<String> = KINDS.iter().map(|(name, _)| (*name).to_owned()).collect();
        for name in listed.names {
            if !KINDS
                .iter()
                .any(|(known, _)| known.eq_ignore_ascii_case(&name))
            {
                names.push(name);
            }
        }

        for name in names {
            if is_hidden_name(&name) {
                found.unread.push(format!(
                    "{place} include a list whose name hides part of itself ({}), so it was not \
                     read",
                    name.escape_debug()
                ));
                continue;
            }
            let kind = KINDS
                .iter()
                .find(|(known, _)| known.eq_ignore_ascii_case(&name))
                .map(|(_, kind)| kind.clone())
                .unwrap_or_else(|| Kind::Other { name: name.clone() });
            match key.look_child(&name) {
                Ok(list) => {
                    let values = list.strings();
                    found.lists.push(List {
                        kind,
                        by_policy,
                        entries: values
                            .values
                            .into_iter()
                            .filter(|value| !value.name.is_empty())
                            .map(|value| Entry {
                                value: value.name,
                                exact: value.exact,
                            })
                            .collect(),
                        whole: values.whole,
                    });
                }
                Err(Unopened::Absent) => {}
                Err(why) => found
                    .unread
                    .push(why.describe(&format!("{place}' list of {name}"))),
            }
        }
    }
    found
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegDeleteTreeW, RegSetValueExW,
        HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ,
        REG_VALUE_TYPE,
    };

    /// Keys laid out as Defender's and a policy's are, under this account's
    /// own hive, removed when dropped. Never Defender's own key.
    struct Scratch {
        path: String,
    }

    impl Scratch {
        fn new(tag: &str) -> Self {
            Self {
                path: format!(
                    r"Software\KAM Security\test exclusions {tag} {}",
                    std::process::id()
                ),
            }
        }

        fn local(&self) -> String {
            format!(r"{}\Defender", self.path)
        }

        fn policy(&self) -> String {
            format!(r"{}\Policy", self.path)
        }

        /// Write one value, making the key it lives in if it is not there.
        fn put(&self, key: &str, name: &str, kind: REG_VALUE_TYPE, data: &[u8]) {
            let wide_path: Vec<u16> = key.encode_utf16().chain(std::iter::once(0)).collect();
            let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
            let mut handle = HKEY::default();
            unsafe {
                let made = RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    PCWSTR(wide_path.as_ptr()),
                    None,
                    PWSTR::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_READ | KEY_WRITE,
                    None,
                    &mut handle,
                    None,
                );
                assert_eq!(made, ERROR_SUCCESS, "could not create {key}");
                let set =
                    RegSetValueExW(handle, PCWSTR(wide_name.as_ptr()), None, kind, Some(data));
                let _ = RegCloseKey(handle);
                assert_eq!(set, ERROR_SUCCESS, "could not write {name} in {key}");
            }
        }

        /// An entry as Defender writes one locally: the value's name, holding 0.
        fn local_entry(&self, list: &str, entry: &str) {
            self.put(
                &format!(r"{}\{list}", self.local()),
                entry,
                REG_DWORD,
                &0_u32.to_le_bytes(),
            );
        }

        /// An entry as a policy writes one: the value's name, holding "0".
        fn policy_entry(&self, list: &str, entry: &str) {
            let zero: Vec<u8> = "0\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
            self.put(&format!(r"{}\{list}", self.policy()), entry, REG_SZ, &zero);
        }

        fn read(&self) -> Exclusions {
            read_from(HKEY_CURRENT_USER, &self.local(), &self.policy())
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let path: Vec<u16> = self.path.encode_utf16().chain(std::iter::once(0)).collect();
            unsafe {
                let _ = RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(path.as_ptr()));
                let _ = RegDeleteKeyW(HKEY_CURRENT_USER, PCWSTR(path.as_ptr()));
            }
        }
    }

    fn values(found: &Exclusions, kind: &Kind, by_policy: bool) -> Vec<String> {
        let mut values: Vec<String> = found
            .lists
            .iter()
            .filter(|list| &list.kind == kind && list.by_policy == by_policy)
            .flat_map(|list| list.entries.iter().map(|entry| entry.value.clone()))
            .collect();
        values.sort();
        values
    }

    /// Each list is read as Defender holds it, and the ones a policy set
    /// are told apart from the ones set on this PC.
    #[test]
    fn each_list_is_read_as_defender_holds_it_and_policy_is_told_apart() {
        let scratch = Scratch::new("lists");
        scratch.local_entry("Paths", r"C:\Games");
        scratch.local_entry("Paths", r"D:\Builds\cache");
        scratch.local_entry("Extensions", ".iso");
        scratch.local_entry("Processes", "node.exe");
        scratch.local_entry("IpAddresses", "192.168.1.20");
        scratch.policy_entry("Paths", r"C:\Program Files\Company Agent");

        let found = scratch.read();
        assert!(found.unread.is_empty(), "{:?}", found.unread);
        assert_eq!(
            values(&found, &Kind::Paths, false),
            vec![r"C:\Games".to_owned(), r"D:\Builds\cache".to_owned()]
        );
        assert_eq!(values(&found, &Kind::Extensions, false), vec![".iso"]);
        assert_eq!(values(&found, &Kind::Processes, false), vec!["node.exe"]);
        assert_eq!(
            values(&found, &Kind::IpAddresses, false),
            vec!["192.168.1.20"]
        );
        assert_eq!(
            values(&found, &Kind::Paths, true),
            vec![r"C:\Program Files\Company Agent".to_owned()]
        );
        assert_eq!(found.total(), 6);
        assert_eq!(found.by_policy(), 1);
        assert_eq!(found.count(&Kind::Paths), 3);
        assert!(found.lists.iter().all(|list| list.whole));
    }

    /// A list beside the four Defender documents is still read, by its own
    /// name, rather than left out.
    #[test]
    fn a_list_this_has_not_heard_of_is_read_by_its_own_name() {
        let scratch = Scratch::new("other");
        scratch.local_entry("TemporaryPaths", r"C:\Windows\Temp\setup");

        let found = scratch.read();
        let other = Kind::Other {
            name: "TemporaryPaths".to_owned(),
        };
        assert_eq!(
            values(&found, &other, false),
            vec![r"C:\Windows\Temp\setup"]
        );
        assert_eq!(found.others(), 1);
    }

    /// No key at all is nothing recorded, which is a fact: no lists, and
    /// nothing said to be unread.
    #[test]
    fn nothing_recorded_is_no_lists_and_nothing_unread() {
        let scratch = Scratch::new("none");
        let found = scratch.read();
        assert_eq!(found.total(), 0);
        assert!(found.unread.is_empty(), "{:?}", found.unread);
    }
}
