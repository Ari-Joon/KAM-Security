//! Turning what is on the machine into something that can be compared with
//! last time.
//!
//! The diff itself lives in `kam-core`, deliberately, so it can be tested
//! against invented sightings with no machine involved. This is the other half:
//! reading the real sources and expressing them as the identity that diff
//! compares — `(kind, scope, name)` plus whatever else is worth noticing a
//! change in.
//!
//! # Which sources, and why not more
//!
//! Chosen from measured churn on a real machine rather than from a list of
//! everything readable. The rule was: does a change here mean something, or does
//! this turn over on its own?
//!
//! - **Services, Run keys, Startup folder items, scheduled tasks.** All of them
//!   things that start themselves, which is the property that makes a change
//!   worth a person's attention.
//! - **Local administrators.** The most stable thing on the machine and the
//!   highest-consequence change on it. Two accounts on the development machine,
//!   unchanged in the whole history available.
//!
//! Deliberately left out: installed applications, because they churn with every
//! update and an uninstall is not a security event; files anywhere, for the
//! same reason many times over; and firewall rules, which are genuinely
//! interesting but whose rate of change nobody has measured yet, and a source
//! whose churn is unknown is a source that cannot be diffed honestly.
//!
//! Microsoft's own scheduled tasks are read and recorded like everything else:
//! one of them *disappearing* matters, and Defender's own tasks being removed is
//! a documented step in several ransomware families. Keeping them out of the
//! itemised list is a display decision and is made in the interface, which is
//! the only place that knows how much room there is.
//!
//! The reason it is a display decision: 233 of them on
//! the development machine with 22 changing in a month, which is Windows Update
//! doing its job. Itemising it produces two dozen rows a month of guaranteed
//! noise, and a panel that cries wolf monthly is a panel nobody opens.

use std::collections::HashMap;
use std::path::PathBuf;

use kam_core::changes::{Sighting, Unreadable};
use kam_scanner::persistence::{self, Anchor, Entry};

/// The name a sighting is filed under for each kind of thing.
///
/// Delegates to [`Anchor::kind`] rather than repeating the strings. They were
/// repeated, and the two copies were what let a reader report a source
/// unreadable under a name the diff never looked up.
fn kind_of(anchor: Anchor) -> &'static str {
    anchor.kind()
}

/// The kind an account holding administrator rights is filed under.
///
/// A constant for the same reason the others are: it is written when the list
/// of administrators is read and looked up when a failure to read that list is
/// reported, and those two spellings agreeing is the only thing standing
/// between a permissions failure and a claim that every administrator has been
/// removed.
const ADMINISTRATOR: &str = "administrator";

/// Who vouches for one file, as a phrase that can be stored and compared.
///
/// Cached by the caller: a machine with three hundred startup entries has far
/// fewer distinct executables behind them, and verifying a signature means
/// opening and hashing the file.
fn trust_in(path: Option<&std::path::Path>) -> String {
    use kam_core::changes::{NOT_CHECKED, NOT_SIGNED, SIGNED_BY};

    let Some(path) = path else {
        return NOT_CHECKED.to_owned();
    };
    match kam_scanner::signature::of(path) {
        kam_scanner::signature::Signature::Valid { signer, .. } => format!("{SIGNED_BY}{signer}"),
        // A signature that does not verify is not a signature. The name is
        // still worth carrying, because "claimed to be Microsoft and does not
        // verify" is a much more interesting sentence than "not signed".
        kam_scanner::signature::Signature::Invalid { signer, .. } => match signer {
            Some(signer) => format!("{NOT_SIGNED}, but claims to be {signer}"),
            None => NOT_SIGNED.to_owned(),
        },
        kam_scanner::signature::Signature::Unsigned => NOT_SIGNED.to_owned(),
        // Not the same as unsigned, and kept apart deliberately: this is a
        // limit of what could be seen, not a property of the file.
        kam_scanner::signature::Signature::Unknown { .. } => NOT_CHECKED.to_owned(),
    }
}

/// What one entry is, as something comparable.
fn sighting_of(entry: &Entry, trust: &mut HashMap<PathBuf, String>) -> Sighting {
    let target = entry.target().map(std::path::Path::to_path_buf);

    Sighting {
        kind: kind_of(entry.anchor).to_owned(),
        // The location separates one account's Run key from another's, and one
        // task folder from another, so two things with the same name in
        // different places are two things.
        scope: entry.location.to_lowercase(),
        name: entry.name.clone(),
        // What it actually runs. A thing still present but now pointing
        // somewhere else is the case a name-only comparison misses entirely,
        // and is exactly what hijacking a legitimate entry looks like.
        detail: target
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_else(|| entry.command.clone()),
        // And who vouches for the file at that path, which closes the case the
        // path alone cannot see: the entry has not moved, but the file it
        // points at has been replaced. Nothing keeps its standing because it
        // had it yesterday.
        trust: match target {
            Some(path) => trust
                .entry(path.clone())
                .or_insert_with(|| trust_in(Some(&path)))
                .clone(),
            None => trust_in(None),
        },
    }
}

/// Everything on this machine worth comparing with last time.
///
/// Returns the sightings and, separately, the sources that could not be read.
/// The second is not an afterthought: `kam-core`'s diff refuses to conclude
/// anything about a source it was told failed, so getting this wrong in the
/// optimistic direction is how a panel starts inventing alarms.
pub fn collect() -> (Vec<Sighting>, Vec<Unreadable>) {
    // A known blind spot, named here rather than left to be discovered.
    //
    // `signed_in_users` enumerates the subkeys of `HKEY_USERS`, and a profile
    // only has one while its hive is loaded — that is, while somebody is signed
    // in as them. An account nobody is using at sweep time is therefore not
    // examined at all, which is worse than a missed comparison: its persistence
    // never enters the baseline, so its *appearance* can never be a difference
    // either. It is invisible permanently rather than late.
    //
    // Closing it means enumerating every profile from `ProfileList` and loading
    // each absent hive read-only to read it, then unloading it on every path
    // including the failing ones. That is a careful operation as LocalSystem
    // and has not been done yet.
    //
    // Until it is, this is reported as an unreadable source below rather than
    // silently omitted, because a source nobody looked at must not read later
    // as a source with nothing in it.
    let users = persistence::signed_in_users();
    let survey = persistence::survey_for(&users);
    // Signatures are verified once per distinct executable, not once per
    // entry: three hundred entries sit behind far fewer files.
    let mut trust: HashMap<PathBuf, String> = HashMap::new();
    let mut sightings: Vec<Sighting> = survey
        .entries
        .iter()
        .map(|entry| sighting_of(entry, &mut trust))
        .collect();

    let mut unreadable = survey.unreadable;

    match administrators() {
        Ok(accounts) => sightings.extend(accounts),
        Err(why) => {
            // Named rather than swallowed, so nothing concludes an
            // administrator was removed when the truth is nobody looked.
            //
            // This used to `return` here, which skipped the account check
            // below -- so a failure to read one source switched off the gap
            // note for three other kinds, on a sweep that had examined only
            // the account that happened to be signed in. Every Run entry,
            // RunOnce entry and Startup item belonging to anyone else was then
            // reported as gone. No source may be silenced by another source
            // failing, so nothing returns early any more.
            unreadable.push(Unreadable::of(
                ADMINISTRATOR,
                format!("the list of local administrators: {why}"),
            ));
        }
    }

    // Say which accounts were not examined. See the note at the top of this
    // function: an account whose hive is not loaded is not looked at, and the
    // honest thing is to say so rather than let its absence read as emptiness.
    if let Some(missing) = profiles_not_examined(&users) {
        // Covers every per-account kind, confined to the accounts in question.
        //
        // Confining it is the whole point. Without the scopes this suppressed
        // three of the five kinds machine-wide, including `HKLM` and
        // `ProgramData` which were read perfectly — and since the ordinary
        // two-account family machine has one profile not signed in on nearly
        // every sweep, that was not an edge case but the common one. Half the
        // feature, switched off for the life of the machine, behind one polite
        // sentence.
        unreadable.push(Unreadable::covering(
            &per_account_kinds(),
            &missing.places,
            missing.what,
        ));
    }

    (sightings, unreadable)
}

/// The kinds that live inside one person's account rather than the machine's.
///
/// Derived from the anchors rather than typed out, so that adding a per-user
/// source cannot silently miss the place that decides what an unexamined
/// account is allowed to say nothing about.
fn per_account_kinds() -> Vec<&'static str> {
    [
        Anchor::RunKey,
        Anchor::RunOnceKey,
        Anchor::StartupFolder,
        Anchor::Service,
        Anchor::ScheduledTask,
    ]
    .into_iter()
    .filter(|anchor| {
        match anchor {
            Anchor::RunKey | Anchor::RunOnceKey | Anchor::StartupFolder => true,
            // A service lives in `HKLM` and a task in a machine-wide file
            // store, so neither is hidden by a hive nobody loaded.
            Anchor::Service | Anchor::ScheduledTask => false,
        }
    })
    .map(Anchor::kind)
    .collect()
}

/// An account this sweep did not look at, and where its things would live.
struct NotExamined {
    what: String,
    /// Scope prefixes: the account's hive, and its profile directory.
    places: Vec<String>,
}

/// Accounts on this machine that this sweep did not look at.
///
/// `None` when every profile was covered. The comparison is by SID, since a
/// profile directory's name is not reliably the account's.
fn profiles_not_examined(examined: &[kam_core::UserContext]) -> Option<NotExamined> {
    use kam_core::registry::{Key, View};
    use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;

    // A failure to read this is reported, not treated as nothing missing.
    //
    // The first version returned `None` here, which the caller reads as "every
    // account was examined" — a claim nobody had earned. That is precisely the
    // mistake this whole feature is built to avoid, committed inside the
    // function written to avoid it: an unreadable source concluding that its
    // contents are empty.
    let Some(root) = Key::open(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
        View::Native,
    ) else {
        return Some(NotExamined {
            what: "the list of accounts on this machine could not be read, so whether \
                   every account was examined is not known"
                .to_owned(),
            // Nothing is known about which accounts were missed, so nothing may
            // be ruled out: no scopes means every entry of those kinds.
            places: Vec::new(),
        });
    };

    let looked_at: std::collections::HashSet<&str> = examined
        .iter()
        .filter_map(kam_core::UserContext::sid)
        .collect();

    let listing = root.subkeys();

    let missed: Vec<String> = listing
        .names
        .iter()
        // Real accounts, not the service profiles.
        .filter(|sid| sid.starts_with("S-1-5-21-"))
        // And not the wreckage of a profile that would not load. When one
        // fails, Windows renames the key to `<SID>.bak` and leaves both in
        // place indefinitely -- the "signed in with a temporary profile"
        // state. A real SID never contains a dot, and the `.bak` twin usually
        // points at the same directory as the live profile, so counting it as
        // an unexamined account produced a gap covering the *signed-in* user's
        // Startup folder: their entries could then never be reported as gone,
        // permanently, on the account most worth watching.
        .filter(|sid| !sid.contains('.'))
        .filter(|sid| !looked_at.contains(sid.as_str()))
        .cloned()
        .collect();

    if !listing.whole {
        // The list of accounts was cut short, so which ones were missed is not
        // known and none of the per-account kinds may be ruled on.
        return Some(NotExamined {
            what: "the list of accounts on this machine could not be read in full, \
                   so whether every account was examined is not known"
                .to_owned(),
            places: Vec::new(),
        });
    }

    if missed.is_empty() {
        return None;
    }

    // Where each unexamined account's things would live: its own hive, and its
    // own profile directory. Both are prefixes of the scopes those sightings
    // are filed under, so this gap says nothing about anybody else's.
    //
    // The profile path comes from `UserContext::for_sid` rather than being
    // read here, because reading it here got it wrong twice: `ProfileImagePath`
    // is `REG_EXPAND_SZ` and routinely holds `%SystemDrive%\Users\Name` on an
    // imaged machine, and it sometimes carries a trailing separator. Either one
    // makes the prefix match nothing -- so the gap covers nothing, and the
    // account's Startup items are reported as gone, which is the failure this
    // whole mechanism exists to prevent. `for_sid` already expands and trims,
    // and one value read by two functions in two ways is how that happened.
    let examined_places: std::collections::HashSet<String> = examined
        .iter()
        .map(|user| user.profile().to_lowercase())
        .collect();

    let mut places = Vec::new();
    for sid in &missed {
        places.push(format!("HKEY_USERS\\{sid}\\"));
        let Some(account) = kam_core::UserContext::for_sid(sid) else {
            continue;
        };
        // Never name a directory this sweep read successfully. A profile
        // shared with an examined account -- which the `.bak` twins above make
        // real -- would otherwise silence the account that was examined.
        if examined_places.contains(&account.profile().to_lowercase()) {
            continue;
        }
        places.push(format!("{}\\", account.profile()));
    }

    let how_many = missed.len();
    Some(NotExamined {
        what: format!(
            "{how_many} account{} on this machine {} not signed in, so what starts \
             itself under {} was not examined",
            if how_many == 1 { "" } else { "s" },
            if how_many == 1 { "was" } else { "were" },
            if how_many == 1 { "it" } else { "them" }
        ),
        places,
    })
}

/// Who can administer this machine.
///
/// Cheapest signal in the whole feature and the highest consequence: an account
/// gaining administrator rights is the change that makes every other change
/// possible, and Windows will not tell anybody it happened.
fn administrators() -> Result<Vec<Sighting>, String> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    let powershell =
        std::path::PathBuf::from(root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");

    // Named absolutely, and the command is a compiled-in constant: the same two
    // rules the hardening module learned the hard way when a bare name was a
    // user-to-SYSTEM execution path. The working directory is set explicitly for
    // the same reason it is for Defender's scanner — a child's working directory
    // takes part in library search and is not a thing to inherit.
    let mut child = std::process::Command::new(&powershell)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            // `$ErrorActionPreference = 'Stop'` because the exit code is
            // otherwise a lie. `powershell.exe -Command` returns 0 after a
            // non-terminating cmdlet error, and `Get-LocalGroupMember` has a
            // well-known one on this exact group: a member SID that cannot be
            // resolved to a principal -- a deleted domain account, an Azure AD
            // account on a hybrid-joined machine, a stale SID from a
            // decommissioned controller -- writes to the error stream and puts
            // nothing on stdout. Exit 0, empty output, and every administrator
            // on the machine reported as gone.
            "$ErrorActionPreference = 'Stop'; \
             Get-LocalGroupMember -SID S-1-5-32-544 | ForEach-Object { $_.Name }",
        ])
        .current_dir(
            std::path::PathBuf::from(
                std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned()),
            )
            .join("System32"),
        )
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| error.to_string())?;

    // Bounded, because this call can block indefinitely.
    //
    // `Get-LocalGroupMember` resolves every member, and a member that is a
    // domain principal sends it to a domain controller. On a machine whose
    // domain is unreachable — a laptop away from the office, a VPN that is
    // down — that wait is long and the sweep is holding a thread throughout.
    // Raised in review; the failure it prevents is the whole feature appearing
    // to hang rather than anything unsafe.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) => return Err("the group could not be read".to_owned()),
            Ok(None) => {}
            Err(error) => return Err(error.to_string()),
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            // Reported as unreadable, never as an empty list. An empty list
            // would mark every administrator as having vanished.
            return Err("the group did not answer in time".to_owned());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    let output = child
        .wait_with_output()
        .map_err(|error| error.to_string())?;

    let accounts: Vec<Sighting> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|account| Sighting {
            kind: ADMINISTRATOR.to_owned(),
            scope: "machine".to_owned(),
            name: account.to_owned(),
            detail: "can administer this machine".to_owned(),
            // An account is not a file, so nothing signs it and nothing
            // failed to. Recorded as neither signed nor unexamined: those are
            // both statements about a file, and applying either here is a
            // category error that the caveat list would then repeat back to
            // somebody about their own account.
            trust: kam_core::changes::NOT_A_FILE.to_owned(),
        })
        .collect();

    // The belt to the exit code's braces. Every Windows machine has at least
    // one member of the Administrators group -- it cannot be emptied, and
    // Windows refuses to remove the last one -- so nobody in it is not a fact
    // about the machine, it is a failed read wearing the costume of one.
    //
    // The invariant was written down in a test rather than in the function,
    // and a test only knows about the machine it runs on. It belongs here,
    // where the empty list would otherwise be returned as an answer and every
    // administrator reported as having vanished: the highest-consequence kind
    // recorded, ranked at the top of the panel, on a machine where nothing
    // happened at all.
    if accounts.is_empty() {
        return Err("the group answered with nobody in it".to_owned());
    }

    Ok(accounts)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn this_machine_has_a_baseline_worth_comparing() {
        let (sightings, unreadable) = collect();

        assert!(
            !sightings.is_empty(),
            "nothing at all was found to compare, which cannot be right on a \
             running machine (unreadable: {unreadable:?})"
        );

        // How many things a first run would have to caveat. Printed rather
        // than asserted: the number is the point, because the panel that lists
        // them is only worth having if a person can read it. A machine where
        // most of the startup surface is unsigned would need that panel
        // designed differently, and nobody would find that out from a green
        // test.
        let mut unvouched = 0;
        let mut unchecked = 0;
        let mut signed = 0;
        for sighting in &sightings {
            if kam_core::changes::vouched_for(&sighting.trust) {
                signed += 1;
            } else if sighting.trust == kam_core::changes::NOT_CHECKED {
                unchecked += 1;
            } else if kam_core::changes::is_a_file(&sighting.trust) {
                unvouched += 1;
            }
        }
        println!(
            "{} sightings: {signed} signed, {unvouched} unsigned, {unchecked} unreadable",
            sightings.len()
        );
        println!("unreadable sources: {:?}", unreadable);

        // The identity has to be complete, or two different things collapse
        // into one and a change between them is invisible.
        for sighting in &sightings {
            assert!(!sighting.kind.is_empty());
            assert!(!sighting.name.is_empty(), "{sighting:?}");
        }
    }

    #[test]
    fn every_kind_has_a_stable_name() {
        // Stored and compared across versions: if these ever change, every
        // machine's whole baseline reads as new at once.
        assert_eq!(kind_of(Anchor::RunKey), "run_key");
        assert_eq!(kind_of(Anchor::Service), "service");
        assert_eq!(kind_of(Anchor::ScheduledTask), "scheduled_task");
        assert_eq!(kind_of(Anchor::StartupFolder), "startup_item");
        assert_eq!(kind_of(Anchor::RunOnceKey), "run_once_key");
    }

    /// An account nobody is signed in as is named, not silently skipped.
    ///
    /// This is the blind spot, and the rule that makes it survivable is the
    /// same one the whole feature rests on: a source nobody looked at must not
    /// read later as a source with nothing in it. If the machine has a second
    /// account, the sweep says it did not examine it.
    #[test]
    fn accounts_that_were_not_examined_are_named() {
        let examined = persistence::signed_in_users();
        let (_, unreadable) = collect();

        match profiles_not_examined(&examined) {
            Some(note) => {
                assert!(
                    unreadable.iter().any(|source| source.what == note.what),
                    "an unexamined account was not reported: {unreadable:?}"
                );
                assert!(note.what.contains("not signed in"), "{}", note.what);

                // And it says nothing about anybody else's entries. Without
                // this the note suppressed run keys, run-once keys and Startup
                // items machine-wide -- on the ordinary two-account machine,
                // permanently, including the ones that were read.
                let source = unreadable
                    .iter()
                    .find(|source| source.what == note.what)
                    .expect("just asserted present");
                assert!(
                    !source.covers("run_key", r"hklm\\software\\microsoft"),
                    "an unexamined account silenced the machine-wide run keys"
                );
                assert!(
                    !source.covers("service", "anything"),
                    "an unexamined account silenced services, which live in HKLM"
                );
            }
            None => {
                // Every profile was covered, which is the ordinary case on a
                // single-account machine. Nothing to claim either way.
                assert!(
                    !unreadable
                        .iter()
                        .any(|source| source.what.contains("not signed in")),
                    "nothing was missed, so nothing should say it was"
                );
            }
        }
    }

    /// Administrators are read, or the failure is reported as a failure.
    ///
    /// The one outcome that must not happen is an empty list read as "there are
    /// no administrators", which would report every administrator as having
    /// vanished the moment the command failed.
    #[test]
    fn administrators_are_either_listed_or_the_failure_is_named() {
        match administrators() {
            Ok(accounts) => {
                assert!(
                    !accounts.is_empty(),
                    "a successful read returned nobody, which no Windows machine can be"
                );
                for account in &accounts {
                    assert_eq!(account.kind, "administrator");
                    assert!(!account.name.is_empty());
                }
            }
            Err(why) => assert!(!why.is_empty(), "a failure has to say something"),
        }
    }
}
