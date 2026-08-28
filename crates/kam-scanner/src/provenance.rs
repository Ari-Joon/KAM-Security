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
    /// Under `Windows`. Writing here needs administrator rights.
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
    /// administrator rights can put itself.
    UserWritable,
    /// Somewhere else entirely: another drive, a game library, a projects
    /// folder.
    Elsewhere,
}

impl Location {
    fn of(path: &Path) -> Self {
        let text = path.to_string_lossy().to_lowercase().replace('/', "\\");
        let windows = folder("SystemRoot");
        let program_files = folder("ProgramFiles");
        let program_files_x86 = folder("ProgramFiles(x86)");

        if windows.is_some_and(|root| text.starts_with(&root)) {
            return Self::System;
        }
        if program_files.is_some_and(|root| text.starts_with(&root))
            || program_files_x86.is_some_and(|root| text.starts_with(&root))
        {
            return Self::Installed;
        }
        if folder("ProgramData").is_some_and(|root| text.starts_with(&root)) {
            return Self::Shared;
        }
        for variable in ["LOCALAPPDATA", "APPDATA", "TEMP", "USERPROFILE"] {
            if folder(variable).is_some_and(|root| text.starts_with(&root)) {
                return Self::UserWritable;
            }
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

fn folder(variable: &str) -> Option<String> {
    std::env::var(variable)
        .ok()
        .map(|value| value.to_lowercase().replace('/', "\\"))
        .filter(|value| !value.is_empty())
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
    /// Sources that could not be read, carried up from the persistence survey.
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
fn examine(path: &Path, anchored: &[Entry], now: u64) -> Option<Finding> {
    let metadata = std::fs::metadata(path).ok()?;
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
        location: Location::of(path),
        persistence: anchored.to_vec(),
        path: text,
        attention: Attention::Ordinary,
        reasons: Vec::new(),
    };

    weigh(&mut finding);
    Some(finding)
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

/// The folders where downloaded executables land.
fn sweep_folders() -> Vec<(PathBuf, Sweep)> {
    let mut folders = Vec::new();
    if let Ok(profile) = std::env::var("USERPROFILE") {
        let profile = PathBuf::from(profile);
        folders.push((profile.join("Downloads"), Sweep::Everything));
        folders.push((profile.join("Desktop"), Sweep::Everything));
    }
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        let local = PathBuf::from(local);
        folders.push((local.join("Temp"), Sweep::OnlyIfItCameFromOutside));
        folders.push((local.join("Programs"), Sweep::OnlyIfItCameFromOutside));
    }
    folders.retain(|(folder, _)| folder.is_dir());
    folders
}

fn walk(folder: &Path, depth: usize, found: &mut Vec<PathBuf>) {
    if depth > MAX_DEPTH || found.len() >= MAX_LOOSE_CANDIDATES {
        return;
    }
    let Ok(listing) = std::fs::read_dir(folder) else {
        return;
    };
    for item in listing.flatten() {
        if found.len() >= MAX_LOOSE_CANDIDATES {
            return;
        }
        let path = item.path();
        match item.file_type() {
            // Not following links: a junction pointing upwards would make this
            // walk forever, and nothing here needs to cross one.
            Ok(kind) if kind.is_symlink() => continue,
            Ok(kind) if kind.is_dir() => walk(&path, depth + 1, found),
            Ok(_) if is_executable(&path) => found.push(path),
            _ => {}
        }
    }
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
        if let Some(executable) = &entry.executable {
            anchored
                .entry(canonical(executable))
                .or_insert_with(|| (executable.clone(), Vec::new()))
                .1
                .push(entry.clone());
        }
    }

    // Loose executables in the download folders, minus anything already
    // accounted for above.
    reporter.stage("Sweeping the download folders", None);
    let folders = sweep_folders();
    let mut loose: Vec<(PathBuf, Sweep)> = Vec::new();
    for (folder, policy) in &folders {
        let mut found = Vec::new();
        walk(folder, 0, &mut found);
        reporter.advance(found.len() as u64);
        loose.extend(found.into_iter().map(|path| (path, *policy)));
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

    let mut findings: Vec<Finding> = std::thread::scope(|scope| {
        let handles: Vec<_> = candidates
            .chunks(chunk)
            .map(|batch| {
                let reporter = reporter.clone();
                scope.spawn(move || {
                    let mut found = Vec::new();
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
                        if let Some(finding) = examine(path, anchors, now) {
                            found.push(finding);
                        }
                        reporter.advance_with(&name);
                    }
                    found
                })
            })
            .collect();

        handles
            .into_iter()
            .filter_map(|handle| handle.join().ok())
            .flatten()
            .collect()
    });

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
        unreadable: persistence.unreadable,
        swept: folders
            .iter()
            .map(|(folder, _)| folder.display().to_string())
            .collect(),
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
            machine_wide: false,
        }
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
