//! Judging an executable by where it came from rather than what it contains.
//!
//! Defender already answers "is this a known bad file" better than anything
//! this project could build. It does not answer the question people actually
//! have about their own machine, which is nearer to: *what is this, how did it
//! get here, and why does it start itself?*
//!
//! Those are answerable from evidence Windows already keeps and nobody
//! surfaces together:
//!
//! - **who signed it** — and whether Windows still accepts that signature
//! - **when it arrived** — from the filesystem's creation time
//! - **where it came from** — the `Zone.Identifier` stream a browser writes
//! - **how it holds on** — Run keys, services, tasks, Startup folders
//! - **where it lives** — a folder any program can write to, or a protected one
//!
//! No single one of these means anything. Unsigned software is often
//! legitimate; downloaded software is normally how software arrives; plenty of
//! good programs start at boot. It is the *combination* that is legible: an
//! unsigned binary that arrived last week from a website, sits in AppData, and
//! quietly installed a service is a different object from an unsigned build
//! tool in a projects folder, and no antivirus verdict distinguishes them.
//!
//! # This does not detect malware
//!
//! It cannot and does not claim to. Everything here is circumstantial by
//! construction, and the interface says so. The output is an ordered list of
//! things worth a person's attention with the reasons attached, not a verdict —
//! which is why nothing in this module deletes, blocks, or quarantines
//! anything. Presenting circumstantial evidence as a verdict is precisely the
//! behaviour that makes the "PC optimiser" industry worthless, and the value
//! here depends entirely on not doing it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use kam_core::{Cancelled, Reporter};
use kam_storage::provenance::{origin_of, Origin};
use serde::{Deserialize, Serialize};

use kam_core::UserContext;

use crate::persistence::{self, Anchor, Entry};
use crate::places;
use crate::signature::{self, Signature};

/// How much of the disk to sweep for downloaded executables that are not
/// anchored anywhere. A bound, not a filter: the folders below are where
/// downloads land, and walking the whole volume would take minutes to add
/// almost nothing.
const MAX_LOOSE_CANDIDATES: usize = 4_000;

/// How deep to walk each of those folders.
const MAX_DEPTH: usize = 6;

/// Extensions that run. `.dll` is deliberately absent: a library does not start
/// itself, and including them would multiply the list without adding a single
/// thing a person can act on.
const EXECUTABLE: &[&str] = &["exe", "com", "scr", "bat", "cmd", "ps1", "vbs", "js", "jar"];

/// What kind of place a file lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Location {
    /// Under `Windows`. Writing here needs administrator rights, apart from
    /// the few folders inside it that do not, which are [`UserWritable`].
    ///
    /// [`UserWritable`]: Location::UserWritable
    System,
    /// Under `Program Files`. Also protected, and where installers belong.
    Installed,
    /// Under `ProgramData`. Machine-wide application data, and where a great
    /// deal of legitimate software genuinely lives — Defender's own engine
    /// among it. A program can create a folder here, but not modify one
    /// another program owns, so treating it as freely writable produces
    /// exactly the confident false alarm this module exists to avoid.
    Shared,
    /// `AppData`, `Temp`, `Downloads`, `Desktop` — anywhere a program can
    /// write without asking anyone. Perfectly normal for lots of legitimate
    /// software, and also the only place software that was never granted
    /// administrator rights can put itself. Includes `C:\Windows\Temp` and the
    /// other folders inside Windows that are open to everyone; see
    /// [`crate::places::WRITABLE_INSIDE_WINDOWS`].
    UserWritable,
    /// Somewhere else entirely: another drive, a game library, a projects
    /// folder.
    Elsewhere,
}

impl Location {
    /// Decided by whole folder names. A plain text prefix described
    /// `C:\WindowsUpdate\x.exe` as the protected Windows folder and
    /// `C:\Program FilesX\x.exe` as an installed program, and described
    /// `C:\Windows\Temp`, which anyone can write to, as protected.
    ///
    /// The person's own folders come from `user`, the account the survey is
    /// for. They came from this process's environment, which inside the agent
    /// is LocalSystem's: a program in the person's AppData was described as
    /// being outside the usual program folders.
    fn of(path: &Path, user: &UserContext) -> Self {
        let text = path.to_string_lossy();
        let under = |variable: &str| {
            places::machine_folder(variable).is_some_and(|root| places::within(&text, &root))
        };

        // Before the Windows folder, which these are inside of.
        if places::writable_inside_windows(&text) {
            return Self::UserWritable;
        }
        if under("SystemRoot") {
            return Self::System;
        }
        if under("ProgramFiles") || under("ProgramFiles(x86)") || under("ProgramW6432") {
            return Self::Installed;
        }
        if under("ProgramData") {
            return Self::Shared;
        }
        if personal_folders(user)
            .iter()
            .any(|root| places::within(&text, root))
        {
            return Self::UserWritable;
        }
        Self::Elsewhere
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::System => "a protected Windows folder",
            Self::Installed => "an installed program folder",
            Self::Shared => "a shared application folder",
            Self::UserWritable => "a folder any program can write to",
            Self::Elsewhere => "outside the usual program folders",
        }
    }
}

/// The folders that belong to the person a survey is for.
///
/// For the running account (no SID) the environment is that person's own, and
/// its `%TEMP%` is added, because it can be spelled differently from the one
/// derived from the profile. For anybody else everything comes from their
/// profile, never from this process.
fn personal_folders(user: &UserContext) -> Vec<String> {
    if user.profile().is_empty() {
        return Vec::new();
    }
    let mut folders = vec![
        user.local_app_data(),
        user.roaming_app_data(),
        user.temp(),
        user.profile().to_owned(),
    ];
    if user.sid().is_none() {
        if let Ok(temp) = std::env::var("TEMP") {
            folders.push(temp);
        }
    }
    folders
}

/// How much attention something warrants. Three levels, because a scale with
/// more gradations than the evidence supports is a way of sounding precise
/// without being it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Attention {
    /// Nothing stands out. The overwhelming majority of every machine.
    Ordinary,
    /// One or two things are unusual. Probably fine; worth knowing.
    Notable,
    /// Several unusual things at once. Still not a verdict — but this is the
    /// short list a person should actually read.
    Unusual,
}

impl Attention {
    fn from_weight(weight: u32) -> Self {
        match weight {
            0..=2 => Self::Ordinary,
            3..=5 => Self::Notable,
            _ => Self::Unusual,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Ordinary => "nothing unusual",
            Self::Notable => "worth knowing",
            Self::Unusual => "worth a look",
        }
    }
}

/// Everything known about one executable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub path: String,
    /// Final component, which is what a person recognises.
    pub name: String,
    pub bytes: u64,
    pub signature: Signature,
    /// Where the file came from, when its own stream recorded it.
    pub origin: Option<Origin>,
    /// Just the host, safe to display. Full URLs carry tokens.
    pub origin_host: Option<String>,
    pub arrived_days_ago: Option<u64>,
    /// Every way this file starts itself.
    pub persistence: Vec<Entry>,
    pub location: Location,
    pub attention: Attention,
    /// The reasoning, in plain words, in the order it was arrived at. This is
    /// the actual product: a rank with no reasons attached is an accusation.
    pub reasons: Vec<String>,
    /// True when this file is part of this program.
    ///
    /// Every clause of the worst unsigned case is true of this program's own
    /// agent: nobody signed it, it runs as a service, and on anything but a
    /// proper install it sits in a folder the user can write to. So it ranked
    /// itself at the top of the list of programs worth looking at, which is
    /// funny once and corrosive afterwards -- a security tool that accuses
    /// itself is teaching the reader that its list is mechanical rather than
    /// considered.
    ///
    /// Marked rather than removed. The facts stay, and are shown as this
    /// program disclosing its own position; what stops is ranking itself
    /// against other people's software. See [`kam_core::ourselves`] for why
    /// exempting yourself from your own checks is otherwise indefensible.
    #[serde(default)]
    pub ours: bool,
}

impl Finding {
    /// Whether this starts itself at all.
    pub fn persists(&self) -> bool {
        !self.persistence.is_empty()
    }
}

/// The whole picture, with its own limits attached.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    /// Everything examined, most interesting first.
    pub findings: Vec<Finding>,
    /// How many executables were judged: everything that starts itself, plus
    /// everything that arrived from outside.
    pub examined: usize,
    /// How many files the sweep passed over to find those. Reported separately
    /// so "examined" stays an honest count of real work rather than a number
    /// inflated by files that were looked at and immediately dismissed.
    pub swept_files: usize,
    /// Everything that could not be looked at, in plain sentences: sources the
    /// persistence survey could not read, download folders that would not
    /// open, and files that could not be examined. Empty only when the whole
    /// picture was read.
    pub unreadable: Vec<String>,
    /// Folders swept for downloaded executables, so the reader knows what was
    /// and was not covered.
    pub swept: Vec<String>,
}

impl Report {
    /// The findings actually worth putting in front of someone.
    pub fn worth_reading(&self) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(|finding| finding.attention != Attention::Ordinary)
    }
}

fn canonical(path: &Path) -> String {
    path.to_string_lossy()
        .to_lowercase()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_owned()
}

fn is_executable(path: &Path) -> bool {
    path.extension().is_some_and(|extension| {
        let extension = extension.to_string_lossy().to_lowercase();
        EXECUTABLE.contains(&extension.as_str())
    })
}

/// Days since the file was created, from the filesystem's own record.
fn arrival(metadata: &std::fs::Metadata, now: u64) -> Option<u64> {
    let created = metadata.created().ok()?;
    let seconds = created.duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(now.saturating_sub(seconds) / 86_400)
}

/// Weigh the evidence and say why.
///
/// The weights are not a probability of anything and are not presented as one.
/// They order a list. Every one of them adds a sentence to `reasons`, so a
/// reader can disagree with the ordering on the evidence rather than having to
/// take it on faith.
fn weigh(finding: &mut Finding) {
    let mut weight = 0_u32;
    let mut reasons = Vec::new();

    if finding.ours {
        // Said in full, and said first. An unsigned service running as
        // LocalSystem out of a directory somebody can write to is a real
        // weakness of this install -- anyone who can write there owns the
        // machine -- and it would be absurd for the one program on the machine
        // whose job is to say such things to leave its own out.
        //
        // What it does not do is compete with the rest of the list for the
        // reader's attention, because "this is the software you are currently
        // looking at" is not a finding.
        finding
            .reasons
            .push("This is part of KAM Security itself.".to_owned());
        match &finding.signature {
            Signature::Valid { signer, .. } => finding.reasons.push(format!("Signed by {signer}.")),
            _ => finding.reasons.push(
                "It is not signed, which is worth knowing about a program \
                       that runs as the system account."
                    .to_owned(),
            ),
        }
        if finding.location == Location::UserWritable {
            finding.reasons.push(
                "It is installed in a folder that programs running as you can write to, \
                 so anything running as you could replace it. Installing under \
                 Program Files is what stops that."
                    .to_owned(),
            );
        }
        finding.attention = Attention::Ordinary;
        return;
    }

    let persists = finding.persists();
    let external = finding
        .origin
        .as_ref()
        .is_some_and(|origin| origin.zone.is_external());
    let exposed =
        finding.location == Location::UserWritable || finding.location == Location::Elsewhere;

    // --- the signature ---------------------------------------------------
    match &finding.signature {
        Signature::Invalid { signer, reason } => {
            // The strongest single signal available here. A broken signature is
            // not ambiguous the way an absent one is: something was signed and
            // no longer verifies.
            weight += 4;
            reasons.push(match signer {
                Some(name) => format!("Signed by {name}, but {reason}."),
                None => format!("It carries a signature, but {reason}."),
            });
        }
        Signature::Unsigned => {
            // On its own this means very little — so on its own it scores
            // nothing, and only counts alongside something else.
            if persists && exposed {
                weight += 3;
                reasons.push(
                    "Nobody signed it, and it starts itself from a folder any program can write to."
                        .to_owned(),
                );
            } else if persists {
                weight += 2;
                reasons.push("Nobody signed it, and it starts itself.".to_owned());
            } else {
                reasons.push("Nobody signed it.".to_owned());
            }
        }
        Signature::Valid { signer, catalogue } => {
            if catalogue.is_some() {
                reasons.push(format!("Part of Windows, signed by {signer}."));
            } else {
                reasons.push(format!("Signed by {signer}, and Windows accepts it."));
            }
        }
        Signature::Unknown { reason } => {
            reasons.push(format!("The signature could not be checked: {reason}."));
        }
    }

    // --- where it came from ----------------------------------------------
    if let Some(origin) = &finding.origin {
        let host = finding.origin_host.as_deref();
        if external && persists {
            weight += 3;
            reasons.push(match host {
                Some(host) => format!("Downloaded from {host}, and it starts itself."),
                None => "Downloaded from the internet, and it starts itself.".to_owned(),
            });
        } else if external {
            reasons.push(match host {
                Some(host) => format!("Downloaded from {host}."),
                None => "Downloaded from the internet.".to_owned(),
            });
        } else {
            reasons.push(format!("Recorded as coming from {}.", origin.zone.label()));
        }
    }

    // --- how it holds on --------------------------------------------------
    if persists {
        let mut anchors: Vec<&str> = finding
            .persistence
            .iter()
            .map(|entry| entry.anchor.label())
            .collect();
        anchors.sort_unstable();
        anchors.dedup();

        // Holding on several ways at once is the behaviour of something that
        // does not want to be removed by accident. Ordinary software does it
        // too — updaters especially — but it is worth pointing out.
        if anchors.len() > 1 {
            weight += 2;
            reasons.push(format!(
                "It holds on in {} different ways: {}.",
                anchors.len(),
                anchors.join(", ")
            ));
        } else if let Some(anchor) = anchors.first() {
            reasons.push(format!("It is {anchor}."));
        }

        if finding
            .persistence
            .iter()
            .any(|entry| entry.anchor == Anchor::Service)
            && exposed
        {
            // Installing a service requires administrator rights; running from
            // a user-writable folder does not. Together they are an odd pair.
            weight += 2;
            reasons.push(
                "It installed a Windows service that runs from a folder any program can write to."
                    .to_owned(),
            );
        }

        // A hidden scheduled task.
        //
        // Hiding on its own says nothing, and assuming otherwise was a real
        // mistake: Windows marks a great many of its own maintenance tasks
        // hidden, and a stock installation flagged eighteen of fifty-nine
        // programs on that basis alone. Every one of those runs a
        // catalogue-signed Microsoft binary from a protected folder, which is
        // exactly what distinguishes them. So hiding counts when it is hiding
        // *something*: an unsigned or unverifiable target, or one in a folder
        // any program can write to.
        if finding.persistence.iter().any(|entry| entry.hidden) {
            let vouched_for = finding.signature.is_valid();
            if !vouched_for || exposed {
                weight += 3;
                reasons.push(
                    "It starts from a scheduled task that is marked hidden, so it does not show in Task Scheduler."
                        .to_owned(),
                );
            }
        }

        // Started through a launcher: cmd, PowerShell, MSBuild, rundll32. This
        // is how something arranges to run while the thing Task Manager shows is
        // a trusted Microsoft program.
        //
        // Only counted in a writable folder, and for the same reason as above:
        // Windows starts plenty of its own signed work through rundll32 and
        // cmd, and scoring that would be scoring Windows for being Windows.
        if let Some(host) = finding
            .persistence
            .iter()
            .find_map(|entry| entry.host.as_deref())
        {
            if exposed {
                weight += 3;
                reasons.push(format!(
                    "It does not run directly: {host} is told to run it, which is how something keeps the program Task Manager shows looking like part of Windows."
                ));
            } else if !finding.signature.is_valid() {
                weight += 1;
                reasons.push(format!("It is run by {host} rather than started directly."));
            }
        }
    }

    // --- where it lives ---------------------------------------------------
    if persists && finding.location == Location::UserWritable {
        weight += 1;
    }

    // --- when it arrived --------------------------------------------------
    if let Some(days) = finding.arrived_days_ago {
        if days <= 14 && persists {
            weight += 1;
            reasons.push(match days {
                0 => "It arrived today and already starts itself.".to_owned(),
                1 => "It arrived yesterday and already starts itself.".to_owned(),
                days => format!("It arrived {days} days ago and already starts itself."),
            });
        }
    }

    finding.attention = Attention::from_weight(weight);
    finding.reasons = reasons;
}

/// Examine one file.
///
/// An error says why it could not be, so a file that could not be read is
/// named rather than dropped from the list as though it had never been found.
fn examine(
    path: &Path,
    anchored: &[Entry],
    now: u64,
    user: &UserContext,
) -> Result<Finding, String> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("{} could not be read ({error})", path.display()))?;
    let text = path.to_string_lossy().into_owned();
    let origin = origin_of(&text);

    let mut finding = Finding {
        name: path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| text.clone()),
        origin_host: origin
            .as_ref()
            .and_then(|origin| origin.host().map(str::to_owned)),
        origin,
        bytes: metadata.len(),
        arrived_days_ago: arrival(&metadata, now),
        signature: signature::of(path),
        location: Location::of(path, user),
        persistence: anchored.to_vec(),
        ours: kam_core::ourselves::is_ours(path),
        path: text,
        attention: Attention::Ordinary,
        reasons: Vec::new(),
    };

    weigh(&mut finding);
    Ok(finding)
}

/// Whether everything in a folder is worth judging, or only what can be shown
/// to have come from outside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sweep {
    /// Downloads and the Desktop: places a person deliberately puts things.
    /// Everything here is judged, because the absence of a `Zone.Identifier`
    /// proves nothing — extracting an archive, moving a file across a
    /// filesystem, or copying it from a USB stick all strip the stream while
    /// leaving the file exactly as suspicious as it was.
    Everything,
    /// Temp and the per-user program folders: hundreds of build artefacts,
    /// installer leftovers and `node_modules` scripts. Judging all of them
    /// would bury the real rows, so here a file must carry a recorded origin.
    OnlyIfItCameFromOutside,
}

/// Where Explorer records a person's Desktop and Downloads, which can be moved
/// away from the profile (OneDrive moves the Desktop, for one).
const SHELL_FOLDERS: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";

/// The value naming the Downloads folder. It has no friendly name.
const DOWNLOADS_VALUE: &str = "{374DE290-123F-4565-9164-39C4925E467B}";

/// One of the person's own shell folders, wherever they have put it.
fn shell_folder(user: &UserContext, value: &str, default: &str) -> PathBuf {
    user.open_key(SHELL_FOLDERS, kam_core::registry::View::Native)
        .and_then(|key| key.string(value))
        .map(|stored| kam_core::env::expand_for(&stored, user))
        .filter(|path| !path.trim().is_empty() && !path.contains('%'))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(user.folder(default)))
}

/// The folders where downloaded executables land, for the person the survey
/// is for.
///
/// These came from this process's own `USERPROFILE` and `LOCALAPPDATA`, which
/// inside the agent are LocalSystem's. So the agent swept SYSTEM's empty
/// profile, and the person's real Downloads and Desktop were never looked at.
fn sweep_folders(user: &UserContext) -> Vec<(PathBuf, Sweep)> {
    if user.profile().is_empty() {
        return Vec::new();
    }
    let local = PathBuf::from(user.local_app_data());
    vec![
        (
            shell_folder(user, DOWNLOADS_VALUE, "Downloads"),
            Sweep::Everything,
        ),
        (shell_folder(user, "Desktop", "Desktop"), Sweep::Everything),
        (PathBuf::from(user.temp()), Sweep::OnlyIfItCameFromOutside),
        (local.join("Programs"), Sweep::OnlyIfItCameFromOutside),
    ]
}

/// What one folder's walk found, and what it could not look at.
#[derive(Debug, Default)]
struct Walked {
    found: Vec<PathBuf>,
    /// Folders below the top that would not open.
    unread: usize,
    /// The first of those, with its error, to name in the sentence.
    first_unread: Option<String>,
    /// Whether the walk stopped at its cap with more left to look at.
    capped: bool,
}

fn walk(folder: &Path, depth: usize, walked: &mut Walked) {
    if depth > MAX_DEPTH {
        return;
    }
    if walked.found.len() >= MAX_LOOSE_CANDIDATES {
        walked.capped = true;
        return;
    }
    let listing = match std::fs::read_dir(folder) {
        Ok(listing) => listing,
        // Gone between being listed and being opened, which is a fact about
        // a Temp folder rather than a gap in what was read.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            walked.unread += 1;
            walked
                .first_unread
                .get_or_insert_with(|| format!("{} ({error})", folder.display()));
            return;
        }
    };
    for item in listing {
        if walked.found.len() >= MAX_LOOSE_CANDIDATES {
            walked.capped = true;
            return;
        }
        let item = match item {
            Ok(item) => item,
            Err(error) => {
                walked.unread += 1;
                walked
                    .first_unread
                    .get_or_insert_with(|| format!("{} ({error})", folder.display()));
                break;
            }
        };
        let path = item.path();
        match item.file_type() {
            // Not following links: a junction pointing upwards would make this
            // walk forever, and nothing here needs to cross one.
            Ok(kind) if kind.is_symlink() => continue,
            Ok(kind) if kind.is_dir() => walk(&path, depth + 1, walked),
            Ok(_) if is_executable(&path) => walked.found.push(path),
            _ => {}
        }
    }
}

/// Sweep one of the download folders, saying what could not be read.
///
/// A folder that is simply not there has nothing in it to miss. A folder that
/// is there and would not open is a different answer, and returning nothing
/// for it made "nothing downloaded" and "could not look" the same sentence.
fn sweep(folder: &Path, gaps: &mut Vec<String>) -> Option<Vec<PathBuf>> {
    if let Err(error) = std::fs::read_dir(folder) {
        if error.kind() != std::io::ErrorKind::NotFound {
            gaps.push(format!(
                "{} could not be read ({error}), so programs in it were not examined.",
                folder.display()
            ));
        }
        return None;
    }
    let mut walked = Walked::default();
    walk(folder, 0, &mut walked);
    if walked.unread > 0 {
        gaps.push(format!(
            "{} folder(s) inside {} could not be read, so programs in them were not \
             examined. The first was {}.",
            walked.unread,
            folder.display(),
            walked.first_unread.unwrap_or_default()
        ));
    }
    if walked.capped {
        gaps.push(format!(
            "The sweep of {} stopped after {MAX_LOOSE_CANDIDATES} programs, so any \
             beyond those were not examined.",
            folder.display()
        ));
    }
    Some(walked.found)
}

/// Examine everything on this machine that starts itself, plus executables
/// that arrived from outside and are sitting where downloads land.
pub fn survey(reporter: &Reporter, user: &UserContext) -> Result<Report, Cancelled> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or_default();

    // Three stages, and they are named rather than numbered because the
    // useful thing to know while waiting is what is being done, not how far
    // through an opaque sequence it is.
    reporter.stage("Reading what starts itself", None);
    let persistence = persistence::survey(user);
    reporter.check()?;

    // One file, many anchors: svchost hosts dozens of services, and an updater
    // typically holds on two or three ways. Grouping first means each binary is
    // verified once and presented once, with all its anchors together.
    let mut anchored: BTreeMap<String, (PathBuf, Vec<Entry>)> = BTreeMap::new();
    for entry in &persistence.entries {
        // The thing worth judging is what actually runs. For most entries that
        // is the executable; for one started through a launcher — `cmd.exe /c
        // script`, `MSBuild.exe project` — it is the payload, and judging the
        // launcher instead would rate a credential stealer as "signed by
        // Microsoft, lives in System32" because that describes cmd.exe.
        if let Some(target) = entry.target() {
            let target = target.to_path_buf();
            anchored
                .entry(canonical(&target))
                .or_insert_with(|| (target, Vec::new()))
                .1
                .push(entry.clone());
        }
    }

    // Loose executables in the download folders, minus anything already
    // accounted for above.
    reporter.stage("Sweeping the download folders", None);
    let mut unreadable = persistence.reasons();
    // Something that starts itself and names nothing that could be found
    // left the grouping above without a word, so it was in no list at all.
    for entry in &persistence.entries {
        if let Some(note) = entry.unresolved() {
            unreadable.push(format!("{note} It was not examined."));
        }
    }
    let mut swept = Vec::new();
    let mut loose: Vec<(PathBuf, Sweep)> = Vec::new();
    for (folder, policy) in sweep_folders(user) {
        if let Some(found) = sweep(&folder, &mut unreadable) {
            swept.push(folder.display().to_string());
            reporter.advance(found.len() as u64);
            loose.extend(found.into_iter().map(|path| (path, policy)));
        }
        reporter.check()?;
    }

    let mut candidates: Vec<(PathBuf, Vec<Entry>)> = anchored.into_values().collect();
    let known: std::collections::HashSet<String> =
        candidates.iter().map(|(path, _)| canonical(path)).collect();

    let swept_files = loose.len();
    for (path, policy) in loose {
        if known.contains(&canonical(&path)) {
            continue;
        }
        let keep = policy == Sweep::Everything || origin_of(&path.to_string_lossy()).is_some();
        if keep {
            candidates.push((path, Vec::new()));
        }
    }

    reporter.check()?;

    // The only stage with a total worth showing: the candidate list is known
    // before the expensive part starts, and this is where the seconds go.
    reporter.stage("Examining programs", Some(candidates.len() as u64));

    // Signature verification is the slow part — each call may open a catalogue
    // and walk a certificate chain — and it is entirely independent per file.
    let threads = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(4);
    let chunk = candidates.len().div_ceil(threads.max(1)).max(1);

    let (mut findings, failed): (Vec<Finding>, Vec<String>) = std::thread::scope(|scope| {
        let handles: Vec<_> = candidates
            .chunks(chunk)
            .map(|batch| {
                let reporter = reporter.clone();
                scope.spawn(move || {
                    let mut found = Vec::new();
                    let mut failed = Vec::new();
                    for (path, anchors) in batch {
                        // Checked per file rather than per batch: with the work
                        // split across cores a batch is a quarter of the job,
                        // and stopping should feel immediate.
                        if reporter.is_cancelled() {
                            break;
                        }
                        let name = path
                            .file_name()
                            .map(|name| name.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        match examine(path, anchors, now, user) {
                            Ok(finding) => found.push(finding),
                            Err(why) => failed.push(why),
                        }
                        reporter.advance_with(&name);
                    }
                    (found, failed)
                })
            })
            .collect();

        let mut findings = Vec::new();
        let mut failed = Vec::new();
        for (found, missed) in handles.into_iter().filter_map(|handle| handle.join().ok()) {
            findings.extend(found);
            failed.extend(missed);
        }
        (findings, failed)
    });
    for why in failed {
        unreadable.push(format!("{why}, so it was not examined."));
    }

    // Most interesting first, then largest, then by name so the order does not
    // shuffle between runs.
    findings.sort_by(|a, b| {
        b.attention
            .cmp(&a.attention)
            .then_with(|| b.bytes.cmp(&a.bytes))
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });

    reporter.check()?;

    Ok(Report {
        examined: findings.len(),
        swept_files,
        findings,
        unreadable,
        swept,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn finding(signature: Signature, location: Location, persistence: Vec<Entry>) -> Finding {
        let mut finding = Finding {
            path: r"C:\somewhere\thing.exe".to_owned(),
            name: "thing.exe".to_owned(),
            bytes: 1024,
            signature,
            origin: None,
            origin_host: None,
            arrived_days_ago: None,
            persistence,
            location,
            attention: Attention::Ordinary,
            reasons: Vec::new(),
            ours: false,
        };
        weigh(&mut finding);
        finding
    }

    fn anchor(anchor: Anchor) -> Entry {
        Entry {
            name: "Thing".to_owned(),
            anchor,
            location: "somewhere".to_owned(),
            command: r"C:\somewhere\thing.exe".to_owned(),
            executable: Some(PathBuf::from(r"C:\somewhere\thing.exe")),
            payload: None,
            host: None,
            hidden: false,
            machine_wide: false,
        }
    }

    /// A hidden scheduled task that runs a script through a launcher, the
    /// resting shape of the infection this release was written after.
    fn hidden_launcher(target: &str) -> Entry {
        Entry {
            name: "SettingsSync".to_owned(),
            anchor: Anchor::ScheduledTask,
            location: r"C:\Windows\System32\Tasks\SettingsSync".to_owned(),
            command: format!(r#"cmd.exe /c "{target}""#),
            executable: Some(PathBuf::from(r"C:\Windows\System32\cmd.exe")),
            payload: Some(PathBuf::from(target)),
            host: Some("cmd.exe".to_owned()),
            hidden: true,
            machine_wide: true,
        }
    }

    #[test]
    fn windows_own_hidden_maintenance_tasks_stay_ordinary() {
        // The false positive that failed CI on a stock Windows image: a great
        // many of Windows' own scheduled tasks are marked hidden, and scoring
        // that alone flagged eighteen of fifty-nine programs. What separates
        // them from something worth reading is that they run a catalogue-signed
        // binary from a protected folder, so that is what has to be checked.
        let mut entry = hidden_launcher(r"C:\Windows\System32\some-maintenance.exe");
        entry.host = None;
        entry.payload = None;
        let finding = finding(
            Signature::Valid {
                signer: "Microsoft Windows".to_owned(),
                catalogue: Some(r"C:\Windows\...\thing.cat".to_owned()),
            },
            Location::System,
            vec![entry],
        );
        assert_eq!(
            finding.attention,
            Attention::Ordinary,
            "hiding is only worth saying when it hides something: {:?}",
            finding.reasons
        );
    }

    #[test]
    fn windows_running_its_own_signed_work_through_a_launcher_stays_ordinary() {
        // Windows starts plenty of its own tasks through rundll32 and cmd.
        // Scoring that would be scoring Windows for being Windows.
        let finding = finding(
            Signature::Valid {
                signer: "Microsoft Windows".to_owned(),
                catalogue: Some(r"C:\Windows\...\thing.cat".to_owned()),
            },
            Location::System,
            vec![Entry {
                name: "SomeTask".to_owned(),
                anchor: Anchor::ScheduledTask,
                location: r"C:\Windows\System32\Tasks\SomeTask".to_owned(),
                command: r"rundll32.exe C:\Windows\System32\thing.dll,Entry".to_owned(),
                executable: Some(PathBuf::from(r"C:\Windows\System32\rundll32.exe")),
                payload: Some(PathBuf::from(r"C:\Windows\System32\thing.dll")),
                host: Some("rundll32.exe".to_owned()),
                hidden: false,
                machine_wide: true,
            }],
        );
        assert_eq!(
            finding.attention,
            Attention::Ordinary,
            "{:?}",
            finding.reasons
        );
    }

    #[test]
    fn a_hidden_task_launching_a_script_from_appdata_stands_out() {
        let finding = finding(
            Signature::Unsigned,
            Location::UserWritable,
            vec![hidden_launcher(
                r"C:\Users\me\AppData\Local\Microsoft\Windows\Caches\x\launch.cmd",
            )],
        );
        assert_eq!(
            finding.attention,
            Attention::Unusual,
            "hidden task + launcher + unsigned + writable must be the top of the list: {:?}",
            finding.reasons
        );
        assert!(finding
            .reasons
            .iter()
            .any(|reason| reason.contains("hidden")));
        assert!(finding
            .reasons
            .iter()
            .any(|reason| reason.contains("cmd.exe")));
    }

    /// Locations are folders, not text.
    ///
    /// `C:\WindowsUpdate` starts with the same letters as `C:\Windows` and is
    /// a folder anyone can create at the root of the drive; `C:\Windows\Temp`
    /// is inside Windows and anyone can write to it. The prefix check called
    /// the first protected and the second protected too.
    #[test]
    fn a_location_is_decided_by_whole_folder_names() {
        let windows = std::env::var("SystemRoot").unwrap();
        let program_files = std::env::var("ProgramFiles").unwrap();
        let user = UserContext::current();
        let of = |path: String| Location::of(Path::new(&path), &user);

        assert_eq!(
            of(format!(r"{windows}\System32\notepad.exe")),
            Location::System
        );
        assert_ne!(of(format!(r"{windows}Update\x.exe")), Location::System);
        assert_eq!(
            of(format!(r"{program_files}\App\app.exe")),
            Location::Installed
        );
        assert_ne!(
            of(format!(r"{program_files}X\app.exe")),
            Location::Installed
        );
        for writable in [
            r"Temp\x.exe",
            r"Tasks\x.exe",
            r"tracing\x.exe",
            r"System32\Tasks\x.exe",
            r"System32\spool\drivers\color\x.exe",
        ] {
            assert_eq!(
                of(format!(r"{windows}\{writable}")),
                Location::UserWritable,
                "{writable} is open to everyone and must not read as protected"
            );
        }
    }

    /// The person's own folders are theirs, not the agent's.
    ///
    /// Inside the LocalSystem agent `%LOCALAPPDATA%` is SYSTEM's, so a program
    /// in the person's AppData read as outside the usual program folders and
    /// their Downloads and Desktop were never swept.
    #[test]
    fn a_named_persons_folders_come_from_their_profile() {
        let them = UserContext::new(
            Some("S-1-5-21-1-2-3-1001".to_owned()),
            r"C:\Users\kam-test-them",
        );
        assert_eq!(
            Location::of(
                Path::new(r"C:\Users\kam-test-them\AppData\Local\Updater\u.exe"),
                &them
            ),
            Location::UserWritable
        );
        assert_eq!(
            Location::of(Path::new(r"C:\Users\kam-test-themx\u.exe"), &them),
            Location::Elsewhere
        );

        let folders: Vec<PathBuf> = sweep_folders(&them)
            .into_iter()
            .map(|(folder, _)| folder)
            .collect();
        // Nobody of that SID is signed in, so there is no hive to say where
        // the folders were moved to, and the profile's own are used.
        for expected in [
            r"C:\Users\kam-test-them\Downloads",
            r"C:\Users\kam-test-them\Desktop",
            r"C:\Users\kam-test-them\AppData\Local\Temp",
            r"C:\Users\kam-test-them\AppData\Local\Programs",
        ] {
            assert!(
                folders.contains(&PathBuf::from(expected)),
                "{expected} not swept: {folders:?}"
            );
        }
    }

    /// A download folder that is there and would not open is said out loud.
    #[test]
    fn a_folder_that_will_not_open_is_named_rather_than_skipped() {
        // A file where a folder should be will not list, and is certain to
        // exist; an access-denied folder would need an ACL changed.
        let not_a_folder =
            std::env::temp_dir().join(format!("kam-sweep-file-{}", std::process::id()));
        std::fs::write(&not_a_folder, b"x").unwrap();
        let mut gaps = Vec::new();
        let found = sweep(&not_a_folder, &mut gaps);
        std::fs::remove_file(&not_a_folder).unwrap();
        assert!(found.is_none());
        assert_eq!(gaps.len(), 1, "{gaps:?}");
        assert!(gaps[0].contains("could not be read"), "{gaps:?}");

        // Simply absent is not a gap: there is nothing in it to miss.
        let mut gaps = Vec::new();
        assert!(sweep(Path::new(r"C:\kam-definitely-absent-folder"), &mut gaps).is_none());
        assert!(gaps.is_empty(), "{gaps:?}");
    }

    #[test]
    fn an_unsigned_file_that_does_nothing_is_ordinary() {
        // The single most important property. Unsigned software is everywhere
        // and flagging it alone would make the list useless.
        let finding = finding(Signature::Unsigned, Location::Elsewhere, Vec::new());
        assert_eq!(finding.attention, Attention::Ordinary);
    }

    #[test]
    fn a_signed_windows_component_is_ordinary_even_as_a_service() {
        let finding = finding(
            Signature::Valid {
                signer: "Microsoft Windows".to_owned(),
                catalogue: Some(r"C:\Windows\...\thing.cat".to_owned()),
            },
            Location::System,
            vec![anchor(Anchor::Service)],
        );
        assert_eq!(
            finding.attention,
            Attention::Ordinary,
            "signed Windows services must not fill the list: {:?}",
            finding.reasons
        );
    }

    #[test]
    fn a_broken_signature_is_always_worth_a_look() {
        // Distinct from unsigned, and the one case that stands alone: something
        // was signed and no longer verifies.
        let finding = finding(
            Signature::Invalid {
                signer: Some("Some Publisher".to_owned()),
                reason: "the file has been altered since it was signed".to_owned(),
            },
            Location::Installed,
            Vec::new(),
        );
        assert_eq!(finding.attention, Attention::Notable);
        assert!(finding.reasons[0].contains("altered"));
    }

    #[test]
    fn the_combination_is_what_stands_out() {
        // None of these alone is much. Together they are the thing this whole
        // module exists to surface.
        let mut finding = finding(
            Signature::Unsigned,
            Location::UserWritable,
            vec![anchor(Anchor::Service), anchor(Anchor::RunKey)],
        );
        finding.origin = Some(Origin {
            zone: kam_storage::provenance::Zone::Internet,
            host_url: Some("https://downloads.example.com/a?token=secret".to_owned()),
            referrer_url: None,
        });
        finding.origin_host = finding
            .origin
            .as_ref()
            .and_then(|origin| origin.host().map(str::to_owned));
        finding.arrived_days_ago = Some(2);
        weigh(&mut finding);

        assert_eq!(finding.attention, Attention::Unusual);
        assert!(finding.reasons.len() >= 4, "{:?}", finding.reasons);
    }

    #[test]
    fn a_download_url_never_reaches_the_screen_whole() {
        // Real download URLs carry signed tokens and account identifiers, and a
        // screenshot of this list would otherwise publish them.
        let origin = Origin {
            zone: kam_storage::provenance::Zone::Internet,
            host_url: Some("https://cdn.example.com/path/file.exe?token=abc123&user=me".to_owned()),
            referrer_url: None,
        };
        assert_eq!(origin.host(), Some("cdn.example.com"));
    }

    #[test]
    fn credentials_are_stripped_from_the_host() {
        let origin = Origin {
            zone: kam_storage::provenance::Zone::Internet,
            host_url: Some("https://user:password@example.com/file.exe".to_owned()),
            referrer_url: None,
        };
        assert_eq!(origin.host(), Some("example.com"));
    }

    #[test]
    fn every_finding_carries_its_reasoning() {
        // A rank with no reasons attached is an accusation, so this is a
        // structural guarantee rather than a nicety.
        for signature in [
            Signature::Unsigned,
            Signature::Valid {
                signer: "X".to_owned(),
                catalogue: None,
            },
            Signature::Invalid {
                signer: None,
                reason: "expired".to_owned(),
            },
            Signature::Unknown {
                reason: "unreadable".to_owned(),
            },
        ] {
            let finding = finding(signature, Location::Elsewhere, vec![anchor(Anchor::RunKey)]);
            assert!(
                !finding.reasons.is_empty(),
                "a finding with no reasons: {finding:?}"
            );
        }
    }

    #[test]
    fn this_machine_produces_a_readable_report() {
        let started = std::time::Instant::now();
        let report = survey(&Reporter::silent(), &UserContext::current()).unwrap();
        let elapsed = started.elapsed();

        println!(
            "judged {} executables (swept {} files) in {:.1}s",
            report.examined,
            report.swept_files,
            elapsed.as_secs_f64()
        );
        println!("swept: {:?}", report.swept);
        println!("unreadable: {:?}", report.unreadable);

        assert!(report.examined > 0, "nothing was examined");

        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        let mut signatures: BTreeMap<&str, usize> = BTreeMap::new();
        let mut places: BTreeMap<&str, usize> = BTreeMap::new();
        for finding in &report.findings {
            *counts.entry(finding.attention.label()).or_default() += 1;
            *places.entry(finding.location.label()).or_default() += 1;
            *signatures
                .entry(match &finding.signature {
                    Signature::Valid {
                        catalogue: Some(_), ..
                    } => "signed (catalogue)",
                    Signature::Valid { .. } => "signed",
                    Signature::Invalid { .. } => "signature rejected",
                    Signature::Unsigned => "unsigned",
                    Signature::Unknown { .. } => "could not check",
                })
                .or_default() += 1;
        }
        println!("attention: {counts:?}");
        println!("signatures: {signatures:?}");
        println!("locations: {places:?}");
        println!(
            "persisting: {}, unsigned and persisting: {}, downloaded: {}",
            report.findings.iter().filter(|f| f.persists()).count(),
            report
                .findings
                .iter()
                .filter(|f| f.persists() && matches!(f.signature, Signature::Unsigned))
                .count(),
            report
                .findings
                .iter()
                .filter(|f| f.origin.is_some())
                .count(),
        );

        // The claim this module makes is that the list is short enough to read.
        // If most of the machine is "worth a look", the weighting is wrong and
        // the whole thing is just another scareware scanner.
        let flagged = report.worth_reading().count();
        assert!(
            flagged * 4 <= report.examined.max(4),
            "{flagged} of {} flagged — the weighting is too eager to be useful",
            report.examined
        );

        for finding in report.worth_reading().take(10) {
            println!("\n[{}] {}", finding.attention.label(), finding.path);
            for reason in &finding.reasons {
                println!("    - {reason}");
            }
        }
    }
}
