//! Registry keys that exist only to be read.
//!
//! # Why the registry needs its own decoys
//!
//! The file canaries cover documents. They do not cover the other place an
//! infostealer looks, which is the registry — because several programs people
//! rely on keep connection details, usernames and in one case an encrypted
//! password there, under well-known paths that every stealer enumerates.
//!
//! PuTTY keeps its saved sessions under `SimonTatham\PuTTY\Sessions`, complete
//! with hostnames and usernames. WinSCP keeps its under
//! `Martin Prikryl\WinSCP 2\Sessions`, and stores a password with them. The
//! Terminal Services client keeps the servers you have connected to, and the
//! account you used. None of that is secret from the user, and all of it is
//! exactly what somebody wants when they are deciding what else of yours they
//! can reach.
//!
//! # Why a decoy here is safe
//!
//! A decoy session is a subkey alongside any real ones. It is not a value
//! inside somebody's own session, it does not modify anything already there, and
//! it is named so that a person who finds it in PuTTY's session list can see at
//! once what it is. Anything enumerating that path — which is what a stealer
//! does, rather than opening one session by name — reads it.
//!
//! # How a read is detected
//!
//! Exactly as for files: a SACL on the key asks Windows to record reads, and the
//! **Registry** audit subcategory has to be on for those events to be written.
//! That is a different subcategory from File System, so turning canaries on
//! switches on both.
//!
//! One difference matters when reading the events back. Windows names a
//! registry object in the kernel's own namespace —
//! `\REGISTRY\USER\S-1-5-21-…\SOFTWARE\…` — not in the form anything types. The
//! matching in `events` accounts for that.

use kam_core::{Error, Result, UserContext};
use windows::core::PCWSTR;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    HKEY, KEY_READ, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ,
};

use crate::MARKER;

/// The value every decoy key carries, so removal can recognise its own work.
const MARKER_VALUE: &str = "KAMSecurityCanary";

/// One decoy registry key.
#[derive(Debug, Clone, Copy)]
pub struct RegistryDecoy {
    pub id: &'static str,
    pub name: &'static str,
    /// Under the user's own hive, without a leading separator.
    pub relative: &'static str,
    pub bait: &'static str,
    /// Values written inside, chosen to look like the real thing.
    pub values: &'static [(&'static str, &'static str)],
}

/// The decoys, and why each path is the one a thief reads.
///
/// The subkey names say what they are. A stealer enumerates every session under
/// these paths rather than opening one by name, so a decoy does not have to
/// pretend convincingly to be found — and a person who sees it in their own
/// PuTTY session list should be able to tell immediately that it is not theirs.
pub const REGISTRY_DECOYS: &[RegistryDecoy] = &[
    RegistryDecoy {
        id: "putty-session",
        name: "A saved PuTTY session",
        relative: r"Software\SimonTatham\PuTTY\Sessions\KAM-Security-decoy-do-not-use",
        bait: "PuTTY keeps every saved session here, with the hostname and username in plain text. It is one of the first registry paths an infostealer enumerates, because it maps out what else you can reach.",
        values: &[
            ("HostName", "backup-db.internal.example"),
            ("UserName", "svc-backup"),
            ("PortNumber", "22"),
            ("Protocol", "ssh"),
        ],
    },
    RegistryDecoy {
        id: "winscp-session",
        name: "A saved WinSCP session",
        relative: r"Software\Martin Prikryl\WinSCP 2\Sessions\KAM-Security-decoy-do-not-use",
        bait: "WinSCP stores its saved sessions here together with a password. The encryption is reversible without a master password, so this path is worth more to a thief than most files on the disk.",
        values: &[
            ("HostName", "files.internal.example"),
            ("UserName", "transfer"),
            ("Password", "A35C4F00000000000000000000000000"),
            ("PortNumber", "22"),
        ],
    },
    RegistryDecoy {
        id: "rdp-server",
        name: "A saved Remote Desktop connection",
        relative: r"Software\Microsoft\Terminal Server Client\Servers\kam-security-decoy.example",
        bait: "The Remote Desktop client records every machine you have connected to and the account you used. It tells somebody which machines are worth trying next, with a username already supplied.",
        values: &[("UsernameHint", "DOMAIN\\svc-remote")],
    },
];

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The caller's hive root and the prefix their keys hang from.
///
/// Always `HKEY_USERS\<sid>` rather than `HKEY_CURRENT_USER` when a SID is
/// known, for the reason the whole product does this: inside a LocalSystem
/// service, `HKEY_CURRENT_USER` is SYSTEM's own hive, and writing a decoy there
/// would put it somewhere nobody will ever look.
fn hive(user: &UserContext) -> (HKEY, String) {
    user.hive()
}

/// The full path of one decoy, as `SetNamedSecurityInfoW` wants it named.
///
/// For a registry object that is `USERS\<sid>\…`, or `CURRENT_USER\…` when the
/// caller is this process.
pub fn object_name(user: &UserContext, decoy: &RegistryDecoy) -> String {
    match user.sid() {
        Some(sid) => format!(r"USERS\{sid}\{}", decoy.relative),
        None => format!(r"CURRENT_USER\{}", decoy.relative),
    }
}

/// A readable path for the window, in the form a person would type.
pub fn display_name(user: &UserContext, decoy: &RegistryDecoy) -> String {
    match user.sid() {
        Some(sid) => format!(r"HKEY_USERS\{sid}\{}", decoy.relative),
        None => format!(r"HKEY_CURRENT_USER\{}", decoy.relative),
    }
}

/// Whether a decoy key exists and carries our marker.
///
/// The same rule as the files: nothing is removed on the strength of its path
/// alone, because these paths belong to other people's software.
pub fn is_ours(user: &UserContext, decoy: &RegistryDecoy) -> bool {
    let (root, prefix) = hive(user);
    let path = wide(&format!("{prefix}{}", decoy.relative));
    unsafe {
        let mut key = HKEY::default();
        if RegOpenKeyExW(root, PCWSTR(path.as_ptr()), None, KEY_READ, &mut key) != ERROR_SUCCESS {
            return false;
        }
        let name = wide(MARKER_VALUE);
        let mut kind = windows::Win32::System::Registry::REG_VALUE_TYPE::default();
        let mut size = 0_u32;
        let status = RegQueryValueExW(
            key,
            PCWSTR(name.as_ptr()),
            None,
            Some(&mut kind),
            None,
            Some(&mut size),
        );
        let _ = RegCloseKey(key);
        status == ERROR_SUCCESS
    }
}

/// Whether anything at all exists at a decoy's path.
pub fn exists(user: &UserContext, decoy: &RegistryDecoy) -> bool {
    let (root, prefix) = hive(user);
    let path = wide(&format!("{prefix}{}", decoy.relative));
    unsafe {
        let mut key = HKEY::default();
        if RegOpenKeyExW(root, PCWSTR(path.as_ptr()), None, KEY_READ, &mut key) == ERROR_SUCCESS {
            let _ = RegCloseKey(key);
            return true;
        }
    }
    false
}

/// Create one decoy key, with its values and its marker.
pub fn plant(user: &UserContext, decoy: &RegistryDecoy) -> Result<()> {
    let (root, prefix) = hive(user);
    let path = wide(&format!("{prefix}{}", decoy.relative));

    unsafe {
        let mut key = HKEY::default();
        let status = RegCreateKeyExW(
            root,
            PCWSTR(path.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_READ | KEY_WRITE,
            None,
            &mut key,
            None,
        );
        if status != ERROR_SUCCESS {
            return Err(Error::Privileged(format!(
                "{} could not be created (error {})",
                display_name(user, decoy),
                status.0
            )));
        }

        let write = |name: &str, value: &str| {
            let name = wide(name);
            // REG_SZ wants the terminator included, counted in bytes.
            let data: Vec<u8> = wide(value)
                .iter()
                .flat_map(|unit| unit.to_le_bytes())
                .collect();
            RegSetValueExW(key, PCWSTR(name.as_ptr()), None, REG_SZ, Some(&data))
        };

        for (name, value) in decoy.values {
            let _ = write(name, value);
        }
        // Written last, so a key that exists without it was not finished by us
        // and will not be removed by us either.
        let marker = format!(
            "{MARKER}. This key is a decoy created by KAM Security. Nothing in it is real and \
             nothing uses it. It exists so that a program going through the registry looking for \
             saved credentials reads something it should not. Safe to delete."
        );
        let status = write(MARKER_VALUE, &marker);
        let _ = RegCloseKey(key);

        if status != ERROR_SUCCESS {
            return Err(Error::Privileged(format!(
                "{} was created but could not be marked (error {})",
                display_name(user, decoy),
                status.0
            )));
        }
    }
    Ok(())
}

/// Remove one decoy key, and only if it is ours.
pub fn remove(user: &UserContext, decoy: &RegistryDecoy) -> Result<()> {
    if !is_ours(user, decoy) {
        return Err(Error::Refused(format!(
            "{} was left alone: it is not one of ours.",
            display_name(user, decoy)
        )));
    }
    let (root, prefix) = hive(user);
    let path = wide(&format!("{prefix}{}", decoy.relative));
    unsafe {
        let status = RegDeleteTreeW(root, PCWSTR(path.as_ptr()));
        if status != ERROR_SUCCESS {
            return Err(Error::Privileged(format!(
                "{} could not be removed (error {})",
                display_name(user, decoy),
                status.0
            )));
        }
    }
    Ok(())
}

/// Serialises the tests that touch the real registry hive.
///
/// The decoy paths are global: a scratch profile gives a test its own
/// directory, but there is no scratch registry, so every test that plants or
/// removes a decoy key contends with every other one. Running them in parallel
/// produced exactly the failure you would expect — one test removing a key
/// while another asserted it was gone.
#[cfg(test)]
pub(crate) static HIVE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take the lock, surviving a previous test that panicked while holding it.
#[cfg(test)]
pub(crate) fn hive_guard() -> std::sync::MutexGuard<'static, ()> {
    HIVE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn every_decoy_is_distinct_and_lives_under_the_user_hive() {
        let mut seen = std::collections::BTreeSet::new();
        for decoy in REGISTRY_DECOYS {
            assert!(seen.insert(decoy.id), "{} appears twice", decoy.id);
            assert!(
                decoy.relative.starts_with(r"Software\"),
                "{} is not under Software",
                decoy.id
            );
            assert!(!decoy.relative.contains(".."), "{} escapes", decoy.id);
            assert!(!decoy.bait.is_empty());
            assert!(!decoy.values.is_empty(), "{} has nothing in it", decoy.id);
        }
    }

    #[test]
    fn a_decoy_names_itself_so_a_person_finding_it_can_tell() {
        // These sit alongside somebody's real PuTTY and WinSCP sessions. A
        // person who opens that list has to be able to see at a glance that
        // this one is not theirs.
        for decoy in REGISTRY_DECOYS {
            let leaf = decoy.relative.rsplit('\\').next().unwrap_or_default();
            assert!(
                leaf.to_lowercase().contains("kam-security-decoy"),
                "{} does not name itself: {leaf}",
                decoy.id
            );
        }
    }

    #[test]
    fn the_object_names_are_shaped_the_way_each_api_wants_them() {
        let user = UserContext::new(Some("S-1-5-21-1-2-3-1001".to_owned()), r"C:\Users\them");
        let decoy = &REGISTRY_DECOYS[0];

        // SetNamedSecurityInfoW wants USERS\<sid>\...
        assert!(object_name(&user, decoy).starts_with(r"USERS\S-1-5-21-1-2-3-1001\Software\"));
        // And a person reads HKEY_USERS.
        assert!(display_name(&user, decoy).starts_with(r"HKEY_USERS\"));

        // With no SID this is the running account, and the current-user forms
        // are correct instead.
        let mine = UserContext::new(None, r"C:\Users\me");
        assert!(object_name(&mine, decoy).starts_with(r"CURRENT_USER\"));
        assert!(display_name(&mine, decoy).starts_with(r"HKEY_CURRENT_USER\"));

        // Whichever form Windows writes into the event, the decoy's own name is
        // in the tail — which is what the trip matching keys on, because the
        // hive prefix depends on who is asking and is not always knowable.
        assert!(decoy
            .relative
            .to_lowercase()
            .ends_with("kam-security-decoy-do-not-use"));
    }

    #[test]
    fn planting_and_removing_a_real_key_round_trips() {
        let _guard = hive_guard();
        // Writes to this account's own hive under a decoy path, then removes
        // it. No privilege needed for HKCU, so this runs everywhere.
        let user = UserContext::current();
        let decoy = &REGISTRY_DECOYS[0];

        // Never run against a path somebody already has something at.
        if exists(&user, decoy) && !is_ours(&user, decoy) {
            println!(
                "something is already at {}; skipping",
                display_name(&user, decoy)
            );
            return;
        }

        plant(&user, decoy).expect("a key in our own hive should be creatable");
        assert!(exists(&user, decoy));
        assert!(is_ours(&user, decoy), "the marker was not written");

        remove(&user, decoy).expect("our own key should be removable");
        assert!(!exists(&user, decoy), "the key survived removal");
    }

    #[test]
    fn a_key_without_our_marker_is_never_removed() {
        let _guard = hive_guard();
        // The rule that matters: these paths belong to other people's software,
        // and a real saved session must survive this program entirely.
        let user = UserContext::current();
        let decoy = &REGISTRY_DECOYS[2];
        if exists(&user, decoy) {
            println!("something is already there; skipping");
            return;
        }

        // Create the key with values but no marker, as another program would.
        let (root, prefix) = hive(&user);
        let path = wide(&format!("{prefix}{}", decoy.relative));
        unsafe {
            let mut key = HKEY::default();
            let status = RegCreateKeyExW(
                root,
                PCWSTR(path.as_ptr()),
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_READ | KEY_WRITE,
                None,
                &mut key,
                None,
            );
            assert_eq!(status, ERROR_SUCCESS);
            let _ = RegCloseKey(key);
        }

        assert!(
            !is_ours(&user, decoy),
            "an unmarked key was claimed as ours"
        );
        assert!(remove(&user, decoy).is_err(), "an unmarked key was removed");
        assert!(exists(&user, decoy), "an unmarked key was destroyed");

        // Clean up the key this test made, directly rather than through remove.
        unsafe {
            let _ = RegDeleteTreeW(root, PCWSTR(path.as_ptr()));
        }
    }
}
