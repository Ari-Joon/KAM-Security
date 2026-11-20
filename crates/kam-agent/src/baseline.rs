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

use kam_core::changes::{Part, Reading, Sighting, Unreadable, NOT_A_FILE};
use kam_scanner::persistence::{self, Anchor, Entry};
use kam_scanner::{extensions, quiet, roots, traffic};

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

/// What one look at the machine found, ready to be compared with last time.
pub struct Look {
    pub seen: Vec<Sighting>,
    /// The sources that could not be read. Not an afterthought: `kam-core`'s
    /// diff refuses to conclude anything about a source it was told failed,
    /// so getting this wrong in the optimistic direction is how a panel
    /// starts inventing alarms.
    pub unreadable: Vec<Unreadable>,
    /// Each account that was looked at, as a part with a first look of its
    /// own. See [`Part`].
    pub parts: Vec<Part>,
}

/// Everything on this machine worth comparing with last time.
///
/// The machine, and every account signed in at the time, whoever is asking:
/// nothing here depends on the caller.
pub fn collect() -> Look {
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
    // The quieter places, for the machine and the same accounts, with the
    // COM classes the tasks just read hand their work to.
    let quiet = quiet::survey_for(&users, &persistence::com_handlers(&survey));
    // Signatures are verified once per distinct executable, not once per
    // entry: three hundred entries sit behind far fewer files.
    let mut trust: HashMap<PathBuf, String> = HashMap::new();
    let mut sightings: Vec<Sighting> = survey
        .entries
        .iter()
        .chain(&quiet.entries)
        .map(|entry| sighting_of(entry, &mut trust))
        .collect();

    let mut unreadable = survey.unreadable;
    unreadable.extend(quiet.unreadable);
    settings(&users, &mut sightings, &mut unreadable);

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
            &account_kinds(),
            &missing.places,
            missing.what,
        ));
    }

    Look {
        seen: sightings,
        unreadable,
        parts: users
            .iter()
            .flat_map(|user| [part_of(user), later_part_of(user)])
            .collect(),
    }
}

/// Where this PC's traffic is sent, which root certificates it trusts and
/// which extensions its browsers run, for the machine and each account
/// signed in, as sightings.
///
/// None of these is a file, so none has a signature to vouch for it, and
/// each is recorded as not a file, as an administrator is: the list of what
/// nobody vouched for on a first look is about files.
fn settings(
    users: &[kam_core::UserContext],
    seen: &mut Vec<Sighting>,
    unreadable: &mut Vec<Unreadable>,
) {
    if let Some(hosts) = traffic::hosts(unreadable) {
        seen.extend(hosts.entries.iter().map(|entry| Sighting {
            kind: traffic::HOSTS_ENTRY.to_owned(),
            scope: hosts.path.to_lowercase(),
            // Names are not told apart by case, by Windows or by DNS.
            name: entry.name.to_lowercase(),
            detail: entry.addresses.join(", "),
            trust: NOT_A_FILE.to_owned(),
        }));
    }
    let (dns, _) = traffic::hand_set_dns(unreadable);
    seen.extend(dns.iter().map(|set| Sighting {
        kind: traffic::DNS_SERVERS.to_owned(),
        scope: set.location.to_lowercase(),
        name: format!("{} ({})", set.adapter, set.family.label()),
        detail: set.servers.join(", "),
        trust: NOT_A_FILE.to_owned(),
    }));
    if let Some(windows) = traffic::windows_proxy(unreadable) {
        seen.extend(proxy_sightings(&windows));
    }

    let list = roots::MicrosoftList::read();
    for store in roots::machine_stores(&list, unreadable) {
        seen.extend(certificate_sightings(&store));
    }

    for user in users {
        match traffic::proxy_of(user, unreadable) {
            Some(proxy) => seen.extend(proxy_sightings(&proxy)),
            // Gone while it was read, so its proxy is not known. A key that
            // would not read has already said so.
            None if persistence::hive_gone(user) => {
                unreadable.push(signed_out(user, &[traffic::PROXY], "proxy"))
            }
            None => {}
        }
        match roots::account_stores(user, &list, unreadable) {
            Some(stores) => {
                for store in &stores {
                    seen.extend(certificate_sightings(store));
                }
            }
            None => unreadable.push(signed_out(
                user,
                &[roots::ROOT_CERTIFICATE],
                "own root certificates",
            )),
        }
        // Read from the profile folder, which is there whether or not
        // anybody is signed in, so this has no hive to lose.
        let browsers = extensions::survey(user);
        seen.extend(browsers.extensions.iter().map(|extension| Sighting {
            kind: extensions::BROWSER_EXTENSION.to_owned(),
            // The profile folder, which names the account, the browser and
            // the profile all at once.
            scope: extension.profile_folder.to_lowercase(),
            name: extension.id.clone(),
            detail: match extension.source {
                extensions::Source::Folder => format!(
                    "{}, loaded from a folder on this PC: {}",
                    extension.name, extension.path
                ),
                source => format!("{}, {}", extension.name, source.label()),
            },
            trust: NOT_A_FILE.to_owned(),
        }));
        unreadable.extend(browsers.unreadable);
    }
}

/// A proxy as sightings: one for the server it sends requests through, and
/// one for a configuration script, each only while it is set. Switching one
/// on is an appearance, changing its address a change, switching it off a
/// disappearance.
fn proxy_sightings(proxy: &traffic::Proxy) -> Vec<Sighting> {
    let mut found = Vec::new();
    let scope = proxy.location.to_lowercase();
    if let Some(server) = &proxy.server {
        found.push(Sighting {
            kind: traffic::PROXY.to_owned(),
            scope: scope.clone(),
            name: "proxy server".to_owned(),
            detail: match &proxy.bypass {
                Some(bypass) => format!("{server}, not used for {bypass}"),
                None => server.clone(),
            },
            trust: NOT_A_FILE.to_owned(),
        });
    }
    if let Some(script) = &proxy.script {
        found.push(Sighting {
            kind: traffic::PROXY.to_owned(),
            scope,
            name: "automatic configuration script".to_owned(),
            detail: script.clone(),
            trust: NOT_A_FILE.to_owned(),
        });
    }
    found
}

/// One store's certificates as sightings: known by thumbprint, in the store
/// as their scope. What else is recorded is the certificate's own and cannot
/// change without the thumbprint changing, so a certificate is never
/// reported as changed in place.
fn certificate_sightings(store: &roots::Store) -> impl Iterator<Item = Sighting> + '_ {
    store.certificates.iter().map(|certificate| Sighting {
        kind: roots::ROOT_CERTIFICATE.to_owned(),
        scope: store.location.to_lowercase(),
        name: certificate.thumbprint.clone(),
        detail: format!(
            "{} (valid to {})",
            certificate.name,
            certificate
                .expires
                .as_deref()
                .and_then(|expires| expires.get(..10))
                .unwrap_or("a date that could not be read")
        ),
        trust: NOT_A_FILE.to_owned(),
    })
}

/// An account that signed out while one of its own settings was read, as a
/// gap confined to its own hive, so nothing of its is concluded to have gone.
fn signed_out(user: &kam_core::UserContext, kinds: &[&str], what: &str) -> Unreadable {
    let (_, hive) = account_of(user);
    Unreadable::covering(
        kinds,
        &[hive],
        format!(
            "the account at {} signed out while its {what} was being read, so it is not shown",
            user.profile()
        ),
    )
}

/// How an account is named in the store's record, and its hive as a place.
///
/// By SID, as the watcher names the same account, and its hive as the prefix
/// its entries are filed under.
fn account_of(user: &kam_core::UserContext) -> (String, String) {
    match user.sid() {
        Some(sid) => (sid.to_owned(), format!("HKEY_USERS\\{sid}\\")),
        None => (user.profile().to_lowercase(), "HKCU\\".to_owned()),
    }
}

/// One account's own startup places, as a part of what is compared.
///
/// Named by SID, as the watcher names the same part of its record. Its places
/// are the prefixes its entries are filed under, its hive and its profile
/// folder, the same two a gap for an account nobody is signed in as names.
fn part_of(user: &kam_core::UserContext) -> Part {
    let (name, hive) = account_of(user);
    Part::new(
        format!("startup of {name}"),
        &per_account_kinds(),
        &[hive, format!("{}\\", user.profile())],
        format!(
            "The account at {} had not been looked at before, so what starts itself under it \
             was recorded as it is this time and not compared with anything.",
            user.profile()
        ),
    )
}

/// One account's own proxy, root certificates, browser extensions and quieter
/// startup places, as a part of what is compared.
///
/// A part of their own, not added to the account's startup part. That part is
/// on record for every account a comparison has already met, so these kinds,
/// which came after it, would be compared under it straight away: an account
/// nobody was signed in as at the first comparison after this update would
/// have its proxy, certificates and extensions reported as having appeared
/// the first time it signed in again, though they had been there all along.
/// A part not on record gives each account the first look its kinds had.
fn later_part_of(user: &kam_core::UserContext) -> Part {
    let (name, hive) = account_of(user);
    Part::new(
        format!("proxy, certificates, extensions and quiet places of {name}"),
        &later_account_kinds(),
        &[hive, format!("{}\\", user.profile())],
        format!(
            "The proxy, trusted root certificates, browser extensions and quieter startup \
             places of the account at {} had not been looked at before, so they were recorded \
             as they are this time and not compared with anything.",
            user.profile()
        ),
    )
}

/// The kinds the later part holds: those that live inside one person's
/// account and came after the account's startup part.
fn later_account_kinds() -> Vec<&'static str> {
    let mut kinds = vec![
        traffic::PROXY,
        roots::ROOT_CERTIFICATE,
        extensions::BROWSER_EXTENSION,
    ];
    kinds.extend(quiet::PER_ACCOUNT.map(Anchor::kind));
    kinds
}

/// Every kind that lives inside one person's account, which is what an
/// account nobody was signed in as rules nothing out about.
fn account_kinds() -> Vec<&'static str> {
    let mut kinds = per_account_kinds();
    kinds.extend(later_account_kinds());
    kinds
}

/// How each kind this module files anything under is read, for the store to
/// hold against how it was read last time. See [`Reading`] for why it asks.
///
/// Every kind is named, whether or not the way it is read has ever changed. A
/// kind that is named is written down as looked at even by a sweep that finds
/// none of it, which is what makes the first one to turn up an appearance and
/// not a first look.
pub fn readings() -> Vec<Reading> {
    let never_before = |what: &str| {
        format!(
            "{what} had not been recorded before, so this time they were recorded as \
             they are and not compared with anything."
        )
    };
    let mut readings = vec![
        Reading::of(
            kind_of(Anchor::RunKey),
            1,
            never_before("Sign-in entries in the registry"),
        ),
        Reading::of(
            kind_of(Anchor::RunOnceKey),
            1,
            never_before("Run-once entries in the registry"),
        ),
        // 2: a shortcut kept relative to one of a person's own folders is read
        // for that person. It was read as the service, which placed it under
        // the service's own folders, so what it runs could not be told and
        // its item was recorded by the shortcut's own path.
        Reading::of(
            kind_of(Anchor::StartupFolder),
            2,
            "Startup folder items are read more closely from this version on: a shortcut kept \
             relative to one of a person's own folders, such as their Desktop, is read for that \
             person, where before what it runs often could not be told. So this time Startup \
             folder items were recorded as they are, and not compared with last time.",
        ),
        // 2: a service that runs inside svchost.exe is recorded as the file
        // it loads there. It was recorded as svchost.exe.
        // 3: the copies Windows makes of a per-account service at each
        // sign-in are recorded as that one service. Each was recorded under
        // the name it had that day.
        Reading::of(
            kind_of(Anchor::Service),
            3,
            "Services are looked at more closely from this version on: for one that runs \
             inside svchost.exe, what is recorded is the file it loads there, and the copies \
             Windows makes of its per-account services at each sign-in are recorded as the \
             one service they are copies of. So this time services were recorded as they \
             are, and not compared with last time.",
        ),
        Reading::of(
            kind_of(Anchor::ScheduledTask),
            1,
            never_before("Scheduled tasks"),
        ),
        Reading::of(ADMINISTRATOR, 1, never_before("The local administrators")),
    ];
    // The kinds that came in together, after the store kept a number for
    // each, so their first look is their own: nothing recorded them before.
    // Each group shares one sentence, which the store says once.
    let traffic_note = "Where this PC's traffic is sent (the hosts file, DNS servers set by hand \
                        and proxies) had not been recorded before, so this time it was recorded \
                        as it is and not compared with anything.";
    let quiet_note = "The quieter places a program can be started from (the Windows sign-in \
                      programs, debugger redirections, programs set to start when another \
                      closes, sign-in scripts, AppInit libraries, WMI event subscriptions and \
                      accounts' own registrations of the COM classes scheduled tasks use) had \
                      not been recorded before, so this time they were recorded as they are \
                      and not compared with anything.";
    readings.extend([
        Reading::of(traffic::HOSTS_ENTRY, 1, traffic_note),
        Reading::of(traffic::DNS_SERVERS, 1, traffic_note),
        Reading::of(traffic::PROXY, 1, traffic_note),
        Reading::of(
            roots::ROOT_CERTIFICATE,
            1,
            never_before("Trusted root certificates"),
        ),
        Reading::of(
            extensions::BROWSER_EXTENSION,
            1,
            never_before("Browser extensions"),
        ),
    ]);
    readings.extend(
        quiet::PLACES
            .iter()
            .map(|(_, anchor)| Reading::of(kind_of(*anchor), 1, quiet_note)),
    );
    readings
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
            // The quieter places are read apart, by `kam_scanner::quiet`, and
            // are not among the anchors above.
            Anchor::Winlogon
            | Anchor::Debugger
            | Anchor::ExitMonitor
            | Anchor::LogonScript
            | Anchor::AppInit
            | Anchor::WmiSubscription
            | Anchor::ComOverride => false,
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
        let Look {
            seen: sightings,
            unreadable,
            ..
        } = collect();

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
        assert_eq!(kind_of(Anchor::Winlogon), "winlogon");
        assert_eq!(kind_of(Anchor::Debugger), "image_debugger");
        assert_eq!(kind_of(Anchor::ExitMonitor), "exit_monitor");
        assert_eq!(kind_of(Anchor::LogonScript), "logon_script");
        assert_eq!(kind_of(Anchor::AppInit), "appinit_dll");
        assert_eq!(kind_of(Anchor::WmiSubscription), "wmi_subscription");
        assert_eq!(kind_of(Anchor::ComOverride), "com_override");
        assert_eq!(traffic::HOSTS_ENTRY, "hosts_entry");
        assert_eq!(traffic::DNS_SERVERS, "dns_servers");
        assert_eq!(traffic::PROXY, "proxy");
        assert_eq!(roots::ROOT_CERTIFICATE, "root_certificate");
        assert_eq!(extensions::BROWSER_EXTENSION, "browser_extension");
    }

    /// The kinds that came after the store kept a number for each: where
    /// traffic is sent, root certificates, browser extensions and the quieter
    /// startup places.
    fn later_kinds() -> Vec<&'static str> {
        let mut kinds = vec![
            traffic::HOSTS_ENTRY,
            traffic::DNS_SERVERS,
            traffic::PROXY,
            roots::ROOT_CERTIFICATE,
            extensions::BROWSER_EXTENSION,
        ];
        kinds.extend(quiet::PLACES.iter().map(|(_, anchor)| anchor.kind()));
        kinds
    }

    /// Every kind is told to the store, and under the token the store was
    /// given for it when it first started keeping count.
    ///
    /// Three spellings have to agree: what a sighting is filed under, what
    /// the sweep is told was read, and what the step that brought an older
    /// store up to date wrote down as already looked at. A kind missing from
    /// the second loses its own first look. A kind missing from the third is
    /// taken for new on a store that has held it for months, and everything
    /// that changed in it since the last sweep goes unreported.
    ///
    /// The kinds that came later are told too, and are not among those the
    /// step wrote down: nothing recorded them before, so their first look,
    /// recorded and not reported, is their own.
    #[test]
    fn every_kind_is_told_to_the_store_under_the_token_it_knows() {
        let mut told: Vec<String> = readings().into_iter().map(|one| one.kind).collect();
        told.sort();
        let mut known: Vec<String> = kam_core::changes::KINDS_BEFORE_READINGS
            .iter()
            .chain(later_kinds().iter())
            .map(|kind| (*kind).to_owned())
            .collect();
        known.sort();
        assert_eq!(told, known);
        for later in later_kinds() {
            assert!(
                !kam_core::changes::KINDS_BEFORE_READINGS.contains(&later),
                "{later} would be taken for already looked at, and lose its first look"
            );
        }

        for reading in readings() {
            assert!(reading.version >= 1, "{reading:?}");
            assert!(
                reading.note.ends_with('.'),
                "the note is shown to a person as a sentence: {reading:?}"
            );
        }
    }

    /// The first comparison after this update does not report a Startup item
    /// as changed because its shortcut can now be read.
    ///
    /// A shortcut kept relative to one of a person's folders was read as the
    /// service, what it ran could not be told, and its item was recorded by
    /// the shortcut's own path. Read for its person, the same item is
    /// recorded by what it runs. Nothing on the machine changed, so nothing is
    /// reported, and the person is told Startup items were recorded afresh.
    #[test]
    fn a_startup_item_read_for_its_person_is_not_reported_as_changed_after_the_update() {
        let store = kam_core::Store::open_in_memory().unwrap();
        let item = |detail: &str, trust: &str| Sighting {
            kind: kind_of(Anchor::StartupFolder).to_owned(),
            scope: r"c:\users\her\appdata\roaming\microsoft\windows\start menu\programs\startup"
                .to_owned(),
            name: "Clear Voice".to_owned(),
            detail: detail.to_owned(),
            trust: trust.to_owned(),
        };
        let lnk = r"C:\Users\her\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Clear Voice.lnk";
        // How the version before read: Startup items under their first number.
        let before: Vec<Reading> = readings()
            .into_iter()
            .map(|reading| {
                if reading.kind == kind_of(Anchor::StartupFolder) {
                    Reading {
                        version: 1,
                        ..reading
                    }
                } else {
                    reading
                }
            })
            .collect();
        for _ in 0..2 {
            store
                .sweep_read_as(&[item(lnk, kam_core::changes::NOT_CHECKED)], &[], &before)
                .unwrap();
        }

        let after = store
            .sweep_read_as(
                &[item(
                    r"C:\Users\her\Desktop\Projects\Clear Voice\.venv\Scripts\pythonw.exe",
                    "signed by Python Software Foundation",
                )],
                &[],
                &readings(),
            )
            .unwrap();
        assert!(
            after.differences.is_empty(),
            "a Startup item that can now be read was reported: {:?}",
            after.differences
        );
        assert_eq!(after.afresh.len(), 1, "{:?}", after.afresh);
    }

    /// The readings as the version before this one told them: the kinds the
    /// store has held all along, at the numbers they have now.
    fn readings_before_the_later_kinds() -> Vec<Reading> {
        readings()
            .into_iter()
            .filter(|reading| {
                kam_core::changes::KINDS_BEFORE_READINGS.contains(&reading.kind.as_str())
            })
            .collect()
    }

    fn found(kind: &str, scope: &str, name: &str, detail: &str) -> Sighting {
        Sighting {
            kind: kind.to_owned(),
            scope: scope.to_lowercase(),
            name: name.to_owned(),
            detail: detail.to_owned(),
            trust: NOT_A_FILE.to_owned(),
        }
    }

    /// What the later kinds find for the machine on one shaped like the
    /// development machine, with one of each where it has none, spelled as
    /// the readers file them.
    fn machine_found() -> Vec<Sighting> {
        vec![
            found(
                traffic::HOSTS_ENTRY,
                r"C:\Windows\System32\drivers\etc\hosts",
                "onlineconfigservice.ubi.com",
                "192.168.1.155",
            ),
            found(
                traffic::DNS_SERVERS,
                r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{11111111-2222-3333-4444-555555555555}",
                "VPN (IPv4)",
                "10.7.0.2",
            ),
            found(
                traffic::PROXY,
                traffic::WINHTTP_LOCATION,
                "proxy server",
                "proxy.corp.example:3128",
            ),
            found(
                roots::ROOT_CERTIFICATE,
                r"HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT",
                "5CF9D43A01717303FBAC4B3F04D12338D303F7C6",
                "Blizzard Battle.net Local Cert (valid to 2036-02-17)",
            ),
            found(
                roots::ROOT_CERTIFICATE,
                r"HKLM\SOFTWARE\Microsoft\SystemCertificates\AuthRoot",
                "D4DE20D05E66FC53FE1A50882C78DB2852CAE474",
                "Baltimore CyberTrust Root (valid to 2025-05-12)",
            ),
            found(
                kind_of(Anchor::Debugger),
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe",
                "taskmgr.exe",
                r"C:\Tools\procexp64.exe",
            ),
            found(
                kind_of(Anchor::WmiSubscription),
                r#"ROOT\subscription:CommandLineEventConsumer.Name="Vendor""#,
                "Vendor",
                r"C:\Program Files\Vendor\agent.exe",
            ),
        ]
    }

    /// What the later kinds find in one account, spelled as the readers file
    /// them: under its hive, or under its profile folder.
    fn account_found(user: &kam_core::UserContext) -> Vec<Sighting> {
        let (_, hive) = account_of(user);
        let chrome = format!(
            r"{}\AppData\Local\Google\Chrome\User Data\Default",
            user.profile()
        );
        vec![
            found(
                traffic::PROXY,
                &format!(r"{hive}Software\Microsoft\Windows\CurrentVersion\Internet Settings"),
                "proxy server",
                "127.0.0.1:8080",
            ),
            found(
                roots::ROOT_CERTIFICATE,
                &format!(r"{hive}Software\Microsoft\SystemCertificates\Root"),
                "4503EADFFC69CBDC85BF4B77D1BD5E62B9AD4B89",
                "A Developer's Own Root (valid to 2036-02-17)",
            ),
            found(
                extensions::BROWSER_EXTENSION,
                &chrome,
                "jghecgabfgfdldnmbfkhmffcabddioke",
                &format!(
                    r"Volume Booster for Chrome, loaded from a folder on this PC: {}\Desktop\Projects\Volume Booster for Chrome",
                    user.profile()
                ),
            ),
            found(
                extensions::BROWSER_EXTENSION,
                &chrome,
                "nmmhkkegccagdldgiimedpiccmgmieda",
                "Google Docs Offline, installed from a store",
            ),
            found(
                kind_of(Anchor::LogonScript),
                &format!(r"{hive}Environment"),
                "UserInitMprLogonScript",
                &format!(r"{}\logon.cmd", user.profile()),
            ),
        ]
    }

    fn signed_in_entry(user: &kam_core::UserContext, name: &str) -> Sighting {
        let (_, hive) = account_of(user);
        Sighting {
            kind: kind_of(Anchor::RunKey).to_owned(),
            scope: format!(r"{hive}Software\Microsoft\Windows\CurrentVersion\Run").to_lowercase(),
            name: name.to_owned(),
            detail: format!(r"{}\AppData\Local\{name}\{name}.exe", user.profile()),
            trust: "signed by Somebody Ltd".to_owned(),
        }
    }

    /// The first comparison after this update reports none of what the
    /// later kinds find as having appeared, for the machine or for any
    /// account, including one nobody was signed in as that day.
    ///
    /// Without a first look of their own, a store that already held a
    /// baseline would meet every hosts entry, certificate and extension for
    /// the first time and report the lot: 57 certificates on the development
    /// machine alone. And an account the store already knew, signing in again
    /// after the update, would have its proxy, certificates and extensions
    /// reported the same way, because its startup part is on record.
    #[test]
    fn the_first_comparison_after_the_update_reports_none_of_the_later_kinds() {
        use kam_core::changes::{Change, TakenBy};

        let store = kam_core::Store::open_in_memory().unwrap();
        let her =
            kam_core::UserContext::new(Some("S-1-5-21-1-2-3-1001".to_owned()), r"C:\Users\her");
        let him =
            kam_core::UserContext::new(Some("S-1-5-21-1-2-3-1002".to_owned()), r"C:\Users\him");
        let service = Sighting {
            kind: kind_of(Anchor::Service).to_owned(),
            scope: r"hklm\system\currentcontrolset\services\thing".to_owned(),
            name: "Thing".to_owned(),
            detail: r"C:\Program Files\Thing\thing.exe".to_owned(),
            trust: "signed by Thing Ltd".to_owned(),
        };

        // Before the update, with both of them signed in.
        let before = vec![
            service.clone(),
            signed_in_entry(&her, "Helper"),
            signed_in_entry(&him, "Sync"),
        ];
        for _ in 0..2 {
            store
                .compare(
                    &before,
                    &[],
                    &readings_before_the_later_kinds(),
                    &[part_of(&her), part_of(&him)],
                    TakenBy::Page,
                )
                .unwrap();
        }

        // The first comparison after it. She is signed in and he is not.
        let mut first_seen = vec![service.clone(), signed_in_entry(&her, "Helper")];
        first_seen.extend(machine_found());
        first_seen.extend(account_found(&her));
        let his_absence = Unreadable::covering(
            &account_kinds(),
            &[
                r"HKEY_USERS\S-1-5-21-1-2-3-1002\".to_owned(),
                r"C:\Users\him\".to_owned(),
            ],
            "1 account on this machine was not signed in",
        );
        let first = store
            .compare(
                &first_seen,
                &[his_absence],
                &readings(),
                &[part_of(&her), later_part_of(&her)],
                TakenBy::Page,
            )
            .unwrap();
        assert!(
            first.differences.is_empty(),
            "what the later kinds found was reported on their first look: {:#?}",
            first.differences
        );
        // One sentence for each group of kinds, and none again for her.
        assert_eq!(first.afresh.len(), 4, "{:#?}", first.afresh);

        // He signs in again. What is his was there all along and is
        // recorded for his own first look, not reported.
        let mut second_seen = first_seen.clone();
        second_seen.push(signed_in_entry(&him, "Sync"));
        second_seen.extend(account_found(&him));
        let everyone = [
            part_of(&her),
            later_part_of(&her),
            part_of(&him),
            later_part_of(&him),
        ];
        let second = store
            .compare(&second_seen, &[], &readings(), &everyone, TakenBy::Page)
            .unwrap();
        assert!(
            second.differences.is_empty(),
            "his own, there all along, were reported as new when he signed in: {:#?}",
            second.differences
        );
        assert_eq!(second.afresh, vec![later_part_of(&him).note]);

        // From then on his are compared like anything else.
        let mut third_seen = second_seen.clone();
        third_seen.push(found(
            extensions::BROWSER_EXTENSION,
            r"C:\Users\him\AppData\Local\Google\Chrome\User Data\Default",
            "aapocclcgogkmnckokdopfmhonfmgoek",
            "Google Slides, installed from a store",
        ));
        let third = store
            .compare(&third_seen, &[], &readings(), &everyone, TakenBy::Page)
            .unwrap();
        let reported: Vec<(&str, Change)> = third
            .differences
            .iter()
            .map(|one| (one.name.as_str(), one.change))
            .collect();
        assert_eq!(
            reported,
            vec![("aapocclcgogkmnckokdopfmhonfmgoek", Change::Appeared)]
        );
    }

    /// An account's later part holds its own proxy, certificates, extensions
    /// and quieter startup places, and nothing of the machine's, nor anything
    /// of its startup part's.
    #[test]
    fn the_later_part_holds_the_accounts_own_settings_and_nothing_else() {
        let her =
            kam_core::UserContext::new(Some("S-1-5-21-1-2-3-1001".to_owned()), r"C:\Users\her");
        let part = later_part_of(&her);
        for sighting in account_found(&her) {
            assert!(
                part.holds(&sighting.kind, &sighting.scope),
                "the account's own is not in its part: {sighting:?}"
            );
        }
        for sighting in machine_found() {
            assert!(
                !part.holds(&sighting.kind, &sighting.scope),
                "one of the machine's is in an account's part: {sighting:?}"
            );
        }
        let entry = signed_in_entry(&her, "Helper");
        assert!(
            !part.holds(&entry.kind, &entry.scope),
            "a sign-in entry is the startup part's"
        );
        assert!(!part_of(&her).holds(
            extensions::BROWSER_EXTENSION,
            r"c:\users\her\appdata\local\google\chrome\user data\default"
        ));
        assert_ne!(part.name, part_of(&her).name);
        assert!(part.note.ends_with('.'), "{}", part.note);
    }

    /// What is compared for a service inside svchost.exe is the file it
    /// loads there, so one swapped for another is a change.
    #[test]
    fn a_service_inside_svchost_is_compared_by_the_file_it_loads() {
        let root = std::env::var("SystemRoot").unwrap();
        let host = PathBuf::from(&root).join(r"System32\svchost.exe");
        let hosted = |library: &str| Entry {
            name: "Task Scheduler".to_owned(),
            anchor: Anchor::Service,
            location: r"HKLM\SYSTEM\CurrentControlSet\Services\Schedule".to_owned(),
            command: format!("{} -k netsvcs -p", host.display()),
            executable: Some(host.clone()),
            payload: Some(PathBuf::from(&root).join("System32").join(library)),
            host: Some("svchost.exe".to_owned()),
            hidden: false,
            machine_wide: true,
            missing: None,
        };

        let mut trust = HashMap::new();
        let before = sighting_of(&hosted("schedsvc.dll"), &mut trust);
        let after = sighting_of(&hosted("kernel32.dll"), &mut trust);
        assert!(before.detail.to_lowercase().ends_with("schedsvc.dll"));
        assert_eq!(
            (&before.kind, &before.scope, &before.name),
            (&after.kind, &after.scope, &after.name),
            "the same service"
        );
        assert_ne!(before.detail, after.detail, "running something else");
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
        let unreadable = collect().unreadable;

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

    /// An account is a part that holds its own entries, as the reader really
    /// files them, and nothing of the machine's or anybody else's.
    ///
    /// The part and the sightings are spelled in two places, and the first
    /// look per account is only as good as their agreeing: a part that held
    /// nothing would leave the account's first look to report everything in
    /// it as new, and one that held the machine's entries would pass over
    /// whatever changed in those.
    #[test]
    fn an_account_is_a_part_holding_its_own_entries_and_nothing_else() {
        let mine = kam_core::UserContext::current();
        let part = part_of(&mine);
        let own = persistence::survey_of_account(&mine).expect("the account running the tests");
        let mut trust = HashMap::new();
        for entry in &own.entries {
            let sighting = sighting_of(entry, &mut trust);
            assert!(
                part.holds(&sighting.kind, &sighting.scope),
                "the account's own entry is not in its part: {sighting:?}"
            );
        }
        for entry in &persistence::survey_of_machine().entries {
            let sighting = sighting_of(entry, &mut trust);
            assert!(
                !part.holds(&sighting.kind, &sighting.scope),
                "one of the machine's entries is in an account's part: {sighting:?}"
            );
        }

        let hers = part_of(&kam_core::UserContext::new(
            Some("S-1-5-21-1-2-3-1001".to_owned()),
            r"C:\Users\her",
        ));
        let run = r"hkey_users\s-1-5-21-1-2-3-1001\software\microsoft\windows\currentversion\run";
        assert!(hers.holds("run_key", run));
        assert!(hers.holds(
            "startup_item",
            r"c:\users\her\appdata\roaming\microsoft\windows\start menu\programs\startup"
        ));
        assert!(!hers.holds(
            "startup_item",
            r"c:\users\herself\appdata\roaming\microsoft\windows\start menu\programs\startup"
        ));
        assert!(!hers.holds("service", run), "a service is the machine's");
        assert!(hers.note.ends_with('.'), "{}", hers.note);
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
