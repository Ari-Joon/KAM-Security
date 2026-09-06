//! Files that exist only to be stolen.
//!
//! # The idea, and where it comes from
//!
//! A canary token is something with no legitimate reason to be touched. Nobody
//! opens it, no program reads it, no backup job cares about it. So the moment
//! anything *does* read it, that is not evidence to be weighed against other
//! evidence — it is close to proof that something is going through your files
//! looking for credentials. The idea is borrowed from canarytokens.org, which
//! does it with URLs and documents that phone home; this does it locally, with
//! files and Windows' own auditing, so nothing ever leaves the machine.
//!
//! # Why this product needed it
//!
//! Everything else here judges evidence that is circumstantial by construction.
//! An unsigned program in AppData *might* be a problem. A hidden scheduled task
//! *might* be a problem. The behaviour watcher closes the gap on persistence,
//! but it still works by snapshot: it finds what an infection left behind, some
//! minutes after it ran.
//!
//! None of that catches the theft itself. The infection this product was
//! hardened after did its work in about three minutes — read the browser
//! credential stores, took the cookies, and left. By the time anything took a
//! snapshot, the damage was finished and only the launcher remained.
//!
//! A canary catches the act. If something reads
//! `Documents\Backups\Chrome\Login Data`, there is no innocent explanation to
//! weigh: that file was put there by this program, for exactly this purpose, and
//! nothing else on the machine knows it exists.
//!
//! # How the reading is detected
//!
//! Windows can audit access to a specific object. Each canary gets a **SACL** —
//! a system access control list — asking for an event whenever anyone reads it,
//! and the File System audit subcategory is switched on so those events are
//! actually written. Windows then records event 4663 in the Security log naming
//! the file, the process, and the account. That is the whole mechanism: no
//! driver, no hooking, no third party, nothing on the network.
//!
//! The audit policy is machine-wide, and turning it on is the one thing here
//! that changes a Windows setting, so it is opt-in and reversible and says so.
//! It is also narrower than it sounds: the subcategory only produces events for
//! objects that carry a SACL, and almost nothing on a normal machine does. Ten
//! canaries do not make a noisy Security log.
//!
//! # The rules this module holds itself to
//!
//! - **Never overwrite anything.** A canary is only ever created where no file
//!   exists. If something is already there, it is left alone and reported.
//! - **Never plant inside another program's data.** Every decoy lives somewhere
//!   no real software reads, so a canary cannot break a browser or a wallet.
//! - **Never delete anything it did not create.** Removal reads the marker
//!   inside the file first, and refuses anything without it.
//! - **Contain nothing worth stealing.** The contents are obviously fake and say
//!   what they are, so a person who opens one is not misled and an attacker who
//!   takes one gains nothing.

use std::path::{Path, PathBuf};

use kam_core::UserContext;
use serde::{Deserialize, Serialize};

mod audit;
mod events;

pub use audit::{auditing_enabled, set_auditing};
pub use events::Trip;

/// Written inside every canary. Removal refuses to delete a file without it,
/// which is what stops this ever removing something of the user's.
pub const MARKER: &str = "KAM-SECURITY-CANARY";

/// One kind of decoy: where it goes, and what it pretends to be.
#[derive(Debug, Clone, Copy)]
struct Decoy {
    id: &'static str,
    name: &'static str,
    /// Relative to the user's profile.
    relative: &'static str,
    /// What a thief would think it was, in words for the person reading.
    bait: &'static str,
    /// Plausible-looking filler. Deliberately, obviously fake.
    body: &'static str,
}

/// The decoys planted, and why each one is shaped the way it is.
///
/// Every path here is somewhere no real program reads. A decoy inside a live
/// browser profile would be more tempting, and would also risk confusing the
/// browser — so instead they sit where a person might plausibly have kept a
/// backup, which is exactly the sort of place a thief's recursive search finds.
const DECOYS: &[Decoy] = &[
    Decoy {
        id: "browser-logins",
        name: "A saved browser password database",
        relative: r"Documents\Backups\Chrome\Login Data",
        bait: "Named exactly what Chrome calls its saved-password store, in a folder that looks like a backup of one. This is the first thing an infostealer goes looking for.",
        body: "SQLite format 3\u{0}-- not a real database. See the notice below.\n",
    },
    Decoy {
        id: "password-vault",
        name: "A password manager vault",
        relative: r"Documents\passwords.kdbx",
        bait: "Shaped like a KeePass vault. A thief that cannot break it will still take it, because it can be attacked later at leisure.",
        body: "\u{3}\u{d9}\u{a2}\u{9a}-- not a real vault. See the notice below.\n",
    },
    Decoy {
        id: "wallet",
        name: "A cryptocurrency wallet",
        relative: r"Documents\Backups\wallet.dat",
        bait: "The filename Bitcoin Core and several other wallets use. Wallet files are taken by almost every infostealer, because they can be emptied without needing any account.",
        body: "-- not a real wallet. See the notice below.\n",
    },
    Decoy {
        id: "seed-phrase",
        name: "A wallet recovery phrase",
        relative: r"Documents\seed phrase.txt",
        bait: "A recovery phrase in a text file is the single most valuable thing on a machine, and people really do keep them this way. Anything reading your documents for the word 'seed' finds this.",
        body: "-- not a real recovery phrase. See the notice below.\n",
    },
    Decoy {
        id: "ssh-key",
        name: "A private SSH key",
        relative: r"Documents\Backups\id_rsa",
        bait: "A private key opens servers and code repositories without a password. Deliberately not placed in your real .ssh folder, where it could confuse the tools that read it.",
        body: "-----BEGIN OPENSSH PRIVATE KEY-----\nbm90IGEgcmVhbCBrZXkuIFNlZSB0aGUgbm90aWNlIGJlbG93Lg==\n-----END OPENSSH PRIVATE KEY-----\n",
    },
];

/// The notice every canary carries, so nobody is ever misled by one.
fn notice(name: &str) -> String {
    format!(
        "\n\n{MARKER}\n\
         =====================================================================\n\
         This file is a decoy, created by KAM Security. It pretends to be:\n\
         {name}\n\
         \n\
         It contains nothing real. No password, key, wallet or phrase in this\n\
         file works, and none of it came from you.\n\
         \n\
         Its only purpose is to be read by something it should not be. Windows\n\
         is set to record any read of this file, so if a program goes looking\n\
         through your documents for credentials, opening this is what gives it\n\
         away.\n\
         \n\
         You can delete it safely at any time, or remove all of them from the\n\
         Scanner tab. Nothing depends on it.\n\
         =====================================================================\n"
    )
}

/// One planted canary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Canary {
    pub id: String,
    pub name: String,
    pub path: String,
    /// What it is pretending to be, and why that is the bait.
    pub bait: String,
    /// True when Windows is actually set to record reads of it.
    pub armed: bool,
    /// Why it is not armed, when it is not.
    pub problem: Option<String>,
}

/// What is planted, whether it is watched, and anything that has touched it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub canaries: Vec<Canary>,
    /// Reads recorded against a canary, newest first.
    pub trips: Vec<Trip>,
    /// Whether Windows is recording file access at all. Without this the
    /// canaries are inert, and the interface must say so rather than implying
    /// they are watching.
    pub auditing: bool,
    /// Anything that stopped this doing its job, in plain words.
    pub problems: Vec<String>,
}

impl Report {
    /// True when there is at least one canary and Windows is set to watch it.
    pub fn watching(&self) -> bool {
        self.auditing && self.canaries.iter().any(|canary| canary.armed)
    }
}

fn path_for(user: &UserContext, decoy: &Decoy) -> PathBuf {
    PathBuf::from(user.profile()).join(decoy.relative)
}

/// Ask Windows Search not to index a file.
///
/// `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED` is the supported way to say "do not
/// read this for the index". It keeps the indexer from generating a read that
/// would otherwise look, to the canary, exactly like a program going through
/// the documents.
fn exclude_from_indexing(path: &Path) -> std::io::Result<()> {
    use windows::Win32::Storage::FileSystem::{
        GetFileAttributesW, SetFileAttributesW, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
        FILE_FLAGS_AND_ATTRIBUTES, INVALID_FILE_ATTRIBUTES,
    };

    let wide: Vec<u16> = path
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let current = GetFileAttributesW(windows::core::PCWSTR(wide.as_ptr()));
        if current == INVALID_FILE_ATTRIBUTES {
            return Err(std::io::Error::last_os_error());
        }
        SetFileAttributesW(
            windows::core::PCWSTR(wide.as_ptr()),
            FILE_FLAGS_AND_ATTRIBUTES(current | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED.0),
        )
        .map_err(|error| std::io::Error::other(error.to_string()))
    }
}

/// Whether a file is one of ours, judged by the marker inside it.
///
/// Read rather than assumed, because the alternative is deleting a file on the
/// strength of its path — and the paths are chosen to look like things people
/// really keep.
fn is_ours(path: &Path) -> bool {
    std::fs::read_to_string(path).is_ok_and(|text| text.contains(MARKER))
}

/// Plant every canary that is not already there, and ask Windows to watch it.
///
/// Returns what is now planted. A decoy whose path is already occupied by
/// something else is skipped and reported — never overwritten.
pub fn plant(user: &UserContext) -> Report {
    let mut report = Report {
        auditing: audit::auditing_enabled(),
        ..Default::default()
    };

    for decoy in DECOYS {
        let path = path_for(user, decoy);

        if path.exists() && !is_ours(&path) {
            report.problems.push(format!(
                "{} was left alone: something else is already at {}.",
                decoy.name,
                path.display()
            ));
            continue;
        }

        if !path.exists() {
            if let Some(parent) = path.parent() {
                if let Err(error) = std::fs::create_dir_all(parent) {
                    report
                        .problems
                        .push(format!("{} could not be created: {error}", path.display()));
                    continue;
                }
            }
            let contents = format!("{}{}", decoy.body, notice(decoy.name));
            if let Err(error) = std::fs::write(&path, contents) {
                report
                    .problems
                    .push(format!("{} could not be written: {error}", path.display()));
                continue;
            }
            // Tell Windows Search to leave it alone.
            //
            // Found by testing rather than by reasoning: the first end-to-end
            // run caught `SearchProtocolHost.exe` reading a decoy within
            // seconds, because the indexer reads everything new in Documents.
            // That is a perfectly legitimate read, and left alone it would have
            // made every canary cry wolf on the day it was planted — which is
            // the exact failure this whole product is meant to avoid.
            if let Err(error) = exclude_from_indexing(&path) {
                report.problems.push(format!(
                    "{} could not be hidden from Windows Search, so the indexer may read it: {error}",
                    path.display()
                ));
            }
        }

        // Ask Windows to record reads of it. This is the part that needs
        // privilege, and the part that makes a decoy into a canary.
        let (armed, problem) = match audit::watch_file(&path) {
            Ok(()) => (true, None),
            Err(error) => (false, Some(error.to_string())),
        };

        report.canaries.push(Canary {
            id: decoy.id.to_owned(),
            name: decoy.name.to_owned(),
            path: path.display().to_string(),
            bait: decoy.bait.to_owned(),
            armed,
            problem,
        });
    }

    report.trips = events::trips(&paths(user));
    report
}

/// Remove every canary this program planted.
///
/// Only files carrying the marker are removed. Anything else at one of those
/// paths is somebody's own file and is left exactly where it is.
pub fn remove(user: &UserContext) -> (usize, Vec<String>) {
    let mut removed = 0;
    let mut refused = Vec::new();

    for decoy in DECOYS {
        let path = path_for(user, decoy);
        if !path.exists() {
            continue;
        }
        if !is_ours(&path) {
            refused.push(format!(
                "{} was left alone: it is not one of ours.",
                path.display()
            ));
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => removed += 1,
            Err(error) => refused.push(format!("{} could not be removed: {error}", path.display())),
        }
    }

    // Tidy the folder this program made, but only when it is empty — anything
    // else in there is the user's.
    if let Ok(backups) =
        std::fs::read_dir(PathBuf::from(user.profile()).join(r"Documents\Backups\Chrome"))
    {
        if backups.count() == 0 {
            let _ = std::fs::remove_dir(
                PathBuf::from(user.profile()).join(r"Documents\Backups\Chrome"),
            );
        }
    }

    (removed, refused)
}

/// Every canary path, whether or not it is currently planted.
fn paths(user: &UserContext) -> Vec<String> {
    DECOYS
        .iter()
        .map(|decoy| path_for(user, decoy).display().to_string())
        .collect()
}

/// What is planted now, and what has touched it.
pub fn status(user: &UserContext) -> Report {
    let mut report = Report {
        auditing: audit::auditing_enabled(),
        ..Default::default()
    };

    for decoy in DECOYS {
        let path = path_for(user, decoy);
        if !path.exists() || !is_ours(&path) {
            continue;
        }
        let (armed, problem) = match audit::is_watched(&path) {
            Ok(watched) => (watched, None),
            Err(error) => (false, Some(error.to_string())),
        };
        report.canaries.push(Canary {
            id: decoy.id.to_owned(),
            name: decoy.name.to_owned(),
            path: path.display().to_string(),
            bait: decoy.bait.to_owned(),
            armed,
            problem,
        });
    }

    report.trips = events::trips(&paths(user));
    report
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn scratch_user() -> (UserContext, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "kam-canary-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&root).unwrap();
        (UserContext::new(None, &root.display().to_string()), root)
    }

    #[test]
    fn every_decoy_carries_the_marker_and_says_it_is_fake() {
        // The one property that makes removal safe, and the one that stops a
        // person being misled by their own decoy.
        for decoy in DECOYS {
            let contents = format!("{}{}", decoy.body, notice(decoy.name));
            assert!(contents.contains(MARKER), "{} has no marker", decoy.id);
            assert!(
                contents.contains("nothing real"),
                "{} does not say it is fake",
                decoy.id
            );
            assert!(!decoy.bait.is_empty());
        }
    }

    #[test]
    fn no_decoy_is_listed_twice_or_points_outside_the_profile() {
        let mut seen = std::collections::BTreeSet::new();
        for decoy in DECOYS {
            assert!(seen.insert(decoy.id), "{} appears twice", decoy.id);
            assert!(
                !decoy.relative.contains(".."),
                "{} escapes the profile",
                decoy.id
            );
            assert!(
                !decoy.relative.starts_with('\\') && !decoy.relative.contains(':'),
                "{} is not a relative path",
                decoy.id
            );
        }
    }

    #[test]
    fn planting_creates_files_that_can_be_recognised_and_removed() {
        let (user, root) = scratch_user();
        let report = plant(&user);
        // Arming needs privilege the tests do not have; the files must still be
        // written, and that is what is checked here.
        assert_eq!(
            report.canaries.len(),
            DECOYS.len(),
            "problems: {:?}",
            report.problems
        );
        for canary in &report.canaries {
            let path = Path::new(&canary.path);
            assert!(path.is_file(), "{} was not written", canary.path);
            assert!(is_ours(path), "{} is not recognisable as ours", canary.path);
        }

        let (removed, refused) = remove(&user);
        assert_eq!(removed, DECOYS.len(), "refused: {refused:?}");
        for canary in &report.canaries {
            assert!(
                !Path::new(&canary.path).exists(),
                "{} survived",
                canary.path
            );
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_file_that_is_not_ours_is_never_overwritten_or_removed() {
        // The rule that matters most. These paths are chosen to look like
        // things people really keep, so being wrong here would destroy
        // somebody's actual password vault.
        let (user, root) = scratch_user();
        let victim = path_for(&user, &DECOYS[1]);
        std::fs::create_dir_all(victim.parent().unwrap()).unwrap();
        std::fs::write(&victim, "a real vault, belonging to somebody").unwrap();

        let report = plant(&user);
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "a real vault, belonging to somebody",
            "an existing file was overwritten"
        );
        assert!(
            report.problems.iter().any(|p| p.contains("already at")),
            "the skip was not reported: {:?}",
            report.problems
        );

        let (_, refused) = remove(&user);
        assert!(victim.is_file(), "an existing file was deleted");
        assert!(refused.iter().any(|r| r.contains("not one of ours")));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn planting_twice_is_harmless() {
        let (user, root) = scratch_user();
        let first = plant(&user);
        let second = plant(&user);
        assert_eq!(first.canaries.len(), second.canaries.len());
        assert!(second.problems.is_empty(), "{:?}", second.problems);
        remove(&user);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    #[ignore = "changes the machine's audit policy and writes into the real profile"]
    fn a_read_of_a_real_canary_is_caught_and_names_the_reader() {
        // The whole mechanism, end to end, on this machine: plant, arm, switch
        // on auditing, read one, and see it come back with the process named.
        //
        // Ignored by default because it changes a machine-wide Windows setting
        // and writes into the real Documents folder, in the same spirit as the
        // firewall test that creates a real rule. It restores both.
        //
        // Needs to run as a user holding SeSecurityPrivilege — an elevated
        // shell, or the service account.
        let user = UserContext::current();
        let was_auditing = auditing_enabled();

        let planted = plant(&user);
        println!("planted {} decoys", planted.canaries.len());
        for canary in &planted.canaries {
            println!(
                "  {} armed={} {:?}",
                canary.path, canary.armed, canary.problem
            );
        }
        assert!(
            planted.canaries.iter().all(|canary| canary.armed),
            "not every decoy could be armed; run this elevated. problems: {:?}",
            planted.problems
        );

        set_auditing(true).expect("auditing should be switchable on when privileged");
        assert!(auditing_enabled(), "auditing did not come on");

        // Read one, exactly as something rifling through the documents would.
        let target = planted.canaries[0].path.clone();
        let contents = std::fs::read_to_string(&target).expect("the decoy should be readable");
        assert!(contents.contains(MARKER));

        // Windows writes the event asynchronously; give it a moment.
        let mut trips = Vec::new();
        for _ in 0..20 {
            std::thread::sleep(std::time::Duration::from_millis(500));
            trips = status(&user).trips;
            if trips
                .iter()
                .any(|trip| trip.path.eq_ignore_ascii_case(&target))
            {
                break;
            }
        }

        let caught = trips
            .iter()
            .find(|trip| trip.path.eq_ignore_ascii_case(&target));
        println!("caught: {caught:#?}");

        // Put the machine back before asserting, so a failure does not leave
        // auditing switched on behind it.
        let (removed, refused) = remove(&user);
        if !was_auditing {
            let _ = set_auditing(false);
        }
        println!("removed {removed} decoys, refused {refused:?}");

        let caught = caught.expect("the read was not recorded; is the Security log readable?");
        assert!(
            caught.process.is_some(),
            "the event did not name the process that read it"
        );
    }

    #[test]
    fn status_reports_nothing_when_nothing_is_planted() {
        let (user, root) = scratch_user();
        let report = status(&user);
        assert!(report.canaries.is_empty());
        assert!(!report.watching());
        std::fs::remove_dir_all(&root).ok();
    }
}
