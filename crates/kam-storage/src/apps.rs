//! What an installed application actually occupies.
//!
//! Control Panel's size column is `EstimatedSize`, a value the installer writes
//! about itself into its own uninstall key. It is frequently missing, sometimes
//! stale by years, and — even when honest — counts only the install directory.
//! Everything an application accumulates afterwards in `ProgramData` and the
//! three `AppData` roots is invisible there.
//!
//! This measures the real thing by looking up each candidate directory in the
//! master file table index, which already knows every folder's total.
//!
//! # Why attribution is conservative
//!
//! A vendor directory like `%LOCALAPPDATA%\Microsoft` is shared by dozens of
//! products. Charging the whole of it to whichever one happens to be named
//! "Microsoft ..." would produce impressive, wrong numbers, and the same bytes
//! would be counted once per application.
//!
//! So a directory is only attributed when it matches the *application's* name,
//! or sits at `<vendor>\<application>`. A bare vendor folder is never claimed.
//! The result understates rather than overstates, and says which directories it
//! found so the number can be checked.

use std::collections::HashMap;

use kam_core::Result;
use kam_core::UserContext;
use serde::{Deserialize, Serialize};
use windows::Win32::System::Registry::{HKEY, HKEY_LOCAL_MACHINE};

use crate::index::VolumeIndex;
use crate::registry::{Key, View};

const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocationKind {
    /// The directory the uninstall key points at.
    Install,
    /// Machine-wide data under `%ProgramData%`.
    ProgramData,
    /// Per-user data under `%LOCALAPPDATA%`.
    LocalData,
    /// Per-user data under `%APPDATA%`, which roams with the profile.
    RoamingData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub path: String,
    pub bytes: u64,
    pub kind: LocationKind,
    /// How many *other* applications also matched this directory. Anything
    /// above zero is excluded from the total — see [`footprints`].
    #[serde(default)]
    pub shared_with: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppFootprint {
    pub name: String,
    pub publisher: String,
    pub version: String,
    /// `EstimatedSize` as Control Panel would show it. `None` when the
    /// installer never wrote one — which is itself worth showing.
    pub reported_bytes: Option<u64>,
    /// What the directories this application alone owns actually hold.
    pub actual_bytes: u64,
    /// Bytes in directories shared with other applications. Reported so the
    /// number is visible, never added to `actual_bytes`.
    pub shared_bytes: u64,
    pub locations: Vec<Location>,
    /// Exactly what Windows would run to remove this, verbatim from the
    /// uninstall key. `None` when the entry has none, which is common for
    /// store apps and things installed by a package manager.
    ///
    /// Shown to the user before it runs. It is a command line out of the
    /// registry, and the only honest way to present that is literally.
    pub uninstall_command: Option<String>,
    /// When the installer says it was installed, as `YYYY-MM-DD`.
    ///
    /// From `InstallDate`, which installers write inconsistently and often not
    /// at all, so this is absent more than it is present. Shown as unknown
    /// rather than guessed at from a directory timestamp, which would be a
    /// different fact wearing this one's label.
    pub installed_on: Option<String>,
    /// Seconds since the Unix epoch when this account last launched anything
    /// inside the install directory.
    ///
    /// `None` means Explorer has no record of you launching it — which is not
    /// the same as never run, and the interface says so. Something started by
    /// a service, a terminal or another account leaves no trace here.
    pub last_used: Option<u64>,
    /// How many times this account has launched it, by the same record.
    pub launches: Option<u32>,
}

impl AppFootprint {
    /// How much larger the truth is than the claim, as a multiple.
    ///
    /// `None` when there is nothing to compare against.
    pub fn understatement(&self) -> Option<f64> {
        match self.reported_bytes {
            Some(reported) if reported > 0 => Some(self.actual_bytes as f64 / reported as f64),
            _ => None,
        }
    }
}

/// One uninstall key, before its size is worked out.
#[derive(Debug, Clone)]
struct Installed {
    name: String,
    publisher: String,
    version: String,
    install_location: Option<String>,
    estimated_kilobytes: Option<u32>,
    uninstall_command: Option<String>,
    installed_on: Option<String>,
    /// Set only for Steam titles, which keep their own record of it.
    last_played: Option<u64>,
}

/// Make sense of `InstallDate`, which is written three different ways.
///
/// Most installers write `YYYYMMDD`. Some write a locale-formatted date, which
/// cannot be read without knowing the locale that produced it and is therefore
/// not read at all. A wrong date is worse than no date on a screen people use
/// to decide what to delete.
fn install_date(raw: &str) -> Option<String> {
    let digits: String = raw.chars().filter(char::is_ascii_digit).collect();
    if digits.len() != 8 {
        return None;
    }

    let year: u32 = digits[0..4].parse().ok()?;
    let month: u32 = digits[4..6].parse().ok()?;
    let day: u32 = digits[6..8].parse().ok()?;

    // Windows did not exist before 1985 and this is not a calendar.
    if !(1985..=2100).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some(format!("{year:04}-{month:02}-{day:02}"))
}

/// Read every uninstall key across both registry views and both hives.
///
/// The third source is the *user's* hive, not the running process's. Anything
/// installed just for one person — which on a modern machine is most of what
/// somebody chose to install themselves — is registered only there.
fn installed(user: &UserContext) -> Vec<Installed> {
    let (user_hive, user_prefix) = user.hive();
    let sources: [(HKEY, String, View); 3] = [
        (HKEY_LOCAL_MACHINE, String::new(), View::Native),
        // 32-bit software on 64-bit Windows lives in a separate view, and it is
        // roughly half of what is installed on a typical machine.
        (HKEY_LOCAL_MACHINE, String::new(), View::Wow6432),
        (user_hive, user_prefix, View::Native),
    ];

    let mut found: Vec<Installed> = Vec::new();
    let mut seen: Vec<String> = Vec::new();

    for (root, prefix, view) in sources {
        let Some(key) = Key::open(root, &format!("{prefix}{UNINSTALL}"), view) else {
            continue;
        };
        for subkey in key.subkey_names() {
            let Some(entry) = key.child(&subkey) else {
                continue;
            };
            let Some(name) = entry.string("DisplayName") else {
                // No display name means Control Panel would not list it either.
                continue;
            };

            // Windows updates and driver packages register here too. They are
            // components of something else, not separate installations.
            if entry.dword("SystemComponent") == Some(1) {
                continue;
            }
            if entry.string("ParentKeyName").is_some()
                || entry.string("ParentDisplayName").is_some()
            {
                continue;
            }
            if entry.string("ReleaseType").is_some_and(|kind| {
                let kind = kind.to_lowercase();
                kind.contains("update") || kind.contains("hotfix") || kind.contains("security")
            }) {
                continue;
            }

            // The same product appears in several views; keep the first.
            let key_name = name.to_lowercase();
            if seen.contains(&key_name) {
                continue;
            }
            seen.push(key_name);

            found.push(Installed {
                publisher: entry.string("Publisher").unwrap_or_default(),
                version: entry.string("DisplayVersion").unwrap_or_default(),
                install_location: entry.string("InstallLocation"),
                estimated_kilobytes: entry.dword("EstimatedSize"),
                // The quiet form where an installer offers one: same program,
                // same arguments, minus the wizard.
                uninstall_command: entry
                    .string("QuietUninstallString")
                    .or_else(|| entry.string("UninstallString")),
                installed_on: entry
                    .string("InstallDate")
                    .and_then(|raw| install_date(&raw)),
                last_played: None,
                name,
            });
        }
    }

    found
}

/// Add Steam games the registry never mentioned.
///
/// Steam does not create an uninstall entry for every title it installs, and
/// Control Panel therefore never lists them — which is why a 40 GB game can be
/// entirely absent from a list of installed software. The manifests know about
/// them regardless, so anything Steam has and the registry does not is added
/// here, marked as coming from Steam rather than from an installer.
///
/// Nothing is replaced: a game with a real uninstall entry keeps it, along with
/// whatever size that entry claims.
fn with_steam_games(mut apps: Vec<Installed>, steam: &[crate::steam::SteamApp]) -> Vec<Installed> {
    let known: Vec<String> = apps.iter().map(|app| normalise(&app.name)).collect();

    for game in steam {
        let wanted = normalise(&game.name);
        if wanted.is_empty() || known.contains(&wanted) {
            continue;
        }
        apps.push(Installed {
            name: game.name.clone(),
            publisher: "Steam".to_owned(),
            version: String::new(),
            install_location: Some(game.path.clone()),
            // Steam owns the install, so removal goes through Steam.
            uninstall_command: Some(format!("steam://uninstall/{}", game.app_id)),
            // Steam records a SizeOnDisk, but it is the same kind of claim as
            // EstimatedSize: written by the installer about itself. Left absent
            // so the measured figure stands on its own.
            estimated_kilobytes: None,
            installed_on: None,
            // Steam's own record, and the only one there is for a game. The
            // comment that used to sit here said the launch history covered
            // this; it does not, because Steam is what starts the game, and
            // every title on the machine read as never opened.
            last_played: game.last_played,
        });
    }

    apps
}

/// Reduce a name to something comparable: lower case, letters and digits only.
///
/// Vendors are wildly inconsistent between the registry and the folder they
/// create — "Path of Exile 2" against `PathOfExile2`, "Mozilla Firefox"
/// against `Mozilla\Firefox`.
pub(crate) fn normalise(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

/// Match a launch recorded under an application's name to the application.
///
/// Deliberately the last resort. It compares only stripped-down letters and
/// digits, requires the record's name to be *contained in* the program's or the
/// other way round, and refuses anything short enough to collide -- "Code" or
/// "App" would otherwise match half the machine. Getting this wrong puts a
/// wrong date on a screen people use to decide what to delete, so it errs
/// towards saying nothing.
fn match_by_name(
    unattributed: &[crate::usage::Usage],
    name: &str,
    publisher: Option<&str>,
) -> Option<crate::usage::Usage> {
    let wanted = normalise(name);
    if wanted.len() < 6 {
        return None;
    }
    let with_publisher = publisher.map(|publisher| format!("{}{wanted}", normalise(publisher)));

    unattributed
        .iter()
        .filter(|usage| usage.last_run.is_some())
        .filter(|usage| {
            let Some(id) = usage.app_id.as_deref() else {
                return false;
            };
            // An id is a dotted name: `Microsoft.VisualStudioCode`. Stripping
            // the punctuation is what makes it comparable at all.
            let id = normalise(id);
            if id.len() < 6 {
                return false;
            }
            id.contains(&wanted)
                || wanted.contains(&id)
                || with_publisher
                    .as_deref()
                    .is_some_and(|both| id.contains(both) || both.contains(&id))
        })
        .max_by_key(|usage| usage.last_run)
        .cloned()
}

/// Directories that plausibly belong to this application, and their sizes.
fn locate(
    app: &Installed,
    index: &VolumeIndex,
    roots: &[(LocationKind, String)],
    steam: &[crate::steam::SteamApp],
    drive_root: &str,
) -> Vec<Location> {
    let mut locations = Vec::new();

    // Steam first, because it is a lookup rather than a guess. Its uninstall
    // entries often have no InstallLocation and its folder names rarely match
    // the store name, so without this a games machine measures as nearly empty.
    let wanted = normalise(&app.name);
    for game in steam {
        if normalise(&game.name) != wanted {
            continue;
        }
        let Some(record) = index.resolve(&game.path) else {
            continue;
        };
        // Steam stores its root lower-cased with forward slashes. The table
        // holds the real on-disk names, so the path is rebuilt from there and
        // displayed the way Explorer would show it.
        let path = index
            .path_of(record, drive_root)
            .unwrap_or_else(|| game.path.clone());
        push_unique(
            &mut locations,
            Location {
                path,
                bytes: index.total_of(record),
                kind: LocationKind::Install,
                shared_with: 0,
            },
        );
    }

    if let Some(path) = &app.install_location {
        let trimmed = path.trim_end_matches(['\\', '/']);
        if let Some(bytes) = index.size_of(trimmed) {
            push_unique(
                &mut locations,
                Location {
                    path: trimmed.to_owned(),
                    bytes,
                    kind: LocationKind::Install,
                    shared_with: 0,
                },
            );
        }
    }

    let wanted_name = wanted;
    let wanted_publisher = normalise(&app.publisher);
    if wanted_name.is_empty() {
        return locations;
    }

    for (kind, root) in roots {
        let Some(root_index) = index.resolve(root) else {
            continue;
        };

        for child in index.directories_in(root_index) {
            let Some(entry) = index.entry(*child) else {
                continue;
            };
            let folder = normalise(&entry.name);
            if folder.is_empty() {
                continue;
            }

            // Directly named after the application.
            if names_match(&folder, &wanted_name) {
                push_unique(
                    &mut locations,
                    Location {
                        path: format!("{root}\\{}", entry.name),
                        bytes: index.total_of(*child),
                        kind: *kind,
                        shared_with: 0,
                    },
                );
                continue;
            }

            // Or `<vendor>\<application>`. The vendor folder itself is never
            // claimed: it is shared, and charging it here would count the same
            // bytes against every product that vendor ships.
            if !wanted_publisher.is_empty() && names_match(&folder, &wanted_publisher) {
                for grandchild in index.directories_in(*child) {
                    let Some(inner) = index.entry(*grandchild) else {
                        continue;
                    };
                    if names_match(&normalise(&inner.name), &wanted_name) {
                        push_unique(
                            &mut locations,
                            Location {
                                path: format!("{root}\\{}\\{}", entry.name, inner.name),
                                bytes: index.total_of(*grandchild),
                                kind: *kind,
                                shared_with: 0,
                            },
                        );
                    }
                }
            }
        }
    }

    locations
}

/// Names match when one contains the other, with a length floor.
///
/// Exact equality misses "Firefox" against "Mozilla Firefox". Containment alone
/// would match "7" against everything, so anything under four characters has to
/// match exactly.
fn names_match(folder: &str, wanted: &str) -> bool {
    if folder == wanted {
        return true;
    }
    if folder.len() < 4 || wanted.len() < 4 {
        return false;
    }
    folder.contains(wanted) || wanted.contains(folder)
}

/// One spelling of a path, for comparison only.
///
/// The same directory arrives written several ways: the registry gives
/// `C:\Program Files (x86)\Steam\...`, Steam's own config gives
/// `c:/program files (x86)/steam/...`, and either may carry a trailing
/// separator. Comparing them literally counts one folder twice, which is how a
/// 66 GB game briefly became a 133 GB one.
pub(crate) fn canonical(path: &str) -> String {
    path.replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase()
}

/// Guard against listing a directory twice when several rules find it.
fn push_unique(locations: &mut Vec<Location>, candidate: Location) {
    let wanted = canonical(&candidate.path);
    if locations
        .iter()
        .any(|existing| canonical(&existing.path) == wanted)
    {
        return;
    }
    locations.push(candidate);
}

/// Where per-user and machine-wide application data lives on this machine.
pub(crate) fn data_roots(user: &UserContext) -> Vec<(LocationKind, String)> {
    let mut roots = Vec::new();
    // Machine-wide, and so the same whoever is asking.
    if let Some(value) = std::env::var_os("ProgramData") {
        roots.push((
            LocationKind::ProgramData,
            value.to_string_lossy().into_owned(),
        ));
    }
    // These two are not. Taken from the environment they would be the
    // *running account's* AppData, which inside a LocalSystem service is
    // `C:\Windows\system32\config\systemprofile\AppData` -- a real
    // directory containing nothing anybody installed.
    roots.push((LocationKind::LocalData, user.local_app_data()));
    roots.push((LocationKind::RoamingData, user.roaming_app_data()));
    roots
}

/// Drop any location that contains another location of the same application.
///
/// `C:\Vendor` and `C:\Vendor\App` can both match, and the first already
/// includes the second — adding them counts the inner folder twice inside a
/// single total. The more specific path is the better attribution, so the
/// ancestor goes.
fn drop_ancestors(locations: &mut Vec<Location>) {
    let paths: Vec<String> = locations
        .iter()
        .map(|location| canonical(&location.path))
        .collect();

    let mut keep = vec![true; locations.len()];
    for (outer, outer_path) in paths.iter().enumerate() {
        for (inner, inner_path) in paths.iter().enumerate() {
            if outer == inner {
                continue;
            }
            let prefix = format!("{outer_path}\\");
            if inner_path.starts_with(&prefix) {
                keep[outer] = false;
                break;
            }
        }
    }

    let mut index = 0;
    locations.retain(|_| {
        let kept = keep[index];
        index += 1;
        kept
    });
}

/// Measure every installed application against a volume index.
///
/// Applications installed on another drive contribute only the directories that
/// live on the indexed one, which is why a footprint can legitimately come back
/// smaller than the reported size.
///
/// # Shared directories
///
/// Name matching alone attributes `%LOCALAPPDATA%\NVIDIA` to every one of the
/// six NVIDIA entries in the uninstall keys, and `%ProgramData%\Microsoft` to
/// both Office and VS Code. The same bytes then appear in half a dozen totals
/// and the numbers stop meaning anything.
///
/// So attribution runs in two passes. Candidates are gathered first, then any
/// directory claimed by more than one application is marked shared and left out
/// of every total. It is still listed, with a count, because "45 GB in a folder
/// six NVIDIA packages share" is a useful thing to be told — it is just not a
/// fact about any one of them.
pub fn footprints(
    index: &VolumeIndex,
    drive_root: &str,
    user: &UserContext,
) -> Result<Vec<AppFootprint>> {
    let roots = data_roots(user);
    let steam = crate::steam::installed_games(user);

    // Read once for the whole run: the registry is cheap but there are several
    // hundred applications and reopening the key per application would be
    // several hundred opens for one answer.
    // One read, both halves. Reading it twice meant resolving every shortcut
    // on the machine through COM twice, for one answer.
    let history = crate::usage::history(user);
    let usage = history.by_path;
    let unattributed = history.unattributed;

    let candidates: Vec<(Installed, Vec<Location>)> = with_steam_games(installed(user), &steam)
        .into_iter()
        .map(|app| {
            let mut locations = locate(&app, index, &roots, &steam, drive_root);
            drop_ancestors(&mut locations);
            (app, locations)
        })
        .collect();

    let mut claims: HashMap<String, usize> = HashMap::new();
    for (_, locations) in &candidates {
        for location in locations {
            *claims.entry(canonical(&location.path)).or_default() += 1;
        }
    }

    let mut results: Vec<AppFootprint> = candidates
        .into_iter()
        .map(|(app, locations)| {
            let locations: Vec<Location> = locations
                .into_iter()
                .map(|mut location| {
                    let claimed = claims.get(&canonical(&location.path)).copied().unwrap_or(1);
                    location.shared_with = claimed.saturating_sub(1);
                    location
                })
                .collect();

            let actual_bytes = locations
                .iter()
                .filter(|location| location.shared_with == 0)
                .map(|location| location.bytes)
                .sum();
            let shared_bytes = locations
                .iter()
                .filter(|location| location.shared_with > 0)
                .map(|location| location.bytes)
                .sum();

            // When did anything in this application's own directories last
            // run. Only the install location counts: a launch out of AppData
            // is usually an updater doing its own thing rather than the person
            // opening the program.
            let launched = locations
                .iter()
                .filter(|location| location.kind == LocationKind::Install)
                .filter_map(|location| crate::usage::latest_under(&usage, &location.path))
                .max_by_key(|found| (found.last_run, found.runs))
                // Nothing under its own folder. Some programs tell Windows
                // their own name at startup instead of declaring it in a
                // shortcut, and the launch is then recorded under that name and
                // no path at all -- Visual Studio Code among them. Matching by
                // name is weaker than matching by path, so it is only ever
                // reached when the path told us nothing.
                .or_else(|| match_by_name(&unattributed, &app.name, Some(app.publisher.as_str())));

            AppFootprint {
                name: app.name,
                publisher: app.publisher,
                version: app.version,
                // The registry stores kilobytes.
                reported_bytes: app.estimated_kilobytes.map(|kb| kb as u64 * 1024),
                actual_bytes,
                shared_bytes,
                locations,
                uninstall_command: app.uninstall_command,
                installed_on: app.installed_on,
                // Steam's figure wins where there is one: it is written by
                // the thing that actually starts the game, rather than
                // inferred from what Explorer happened to see.
                last_used: app
                    .last_played
                    .or_else(|| launched.as_ref().and_then(|found| found.last_run)),
                launches: launched.as_ref().map(|found| found.runs),
            }
        })
        .collect();

    results.sort_by_key(|app| std::cmp::Reverse(app.actual_bytes));
    Ok(results)
}

/// Everything one read of the table can answer at once.
///
/// Footprints and orphans are two views of the same question — which
/// directories belong to what — so they are produced together rather than
/// costing a read of the volume each.
#[derive(Debug)]
pub struct StorageReport {
    pub apps: Vec<AppFootprint>,
    pub summary: FootprintSummary,
    pub orphans: Vec<crate::orphans::Orphan>,
    pub orphan_summary: crate::orphans::OrphanSummary,
    pub downloads: Vec<crate::provenance::Download>,
    pub download_summary: crate::provenance::DownloadSummary,
    pub timings: Timings,
}

/// How long each stage of a survey took, in milliseconds.
///
/// Reported rather than logged. "It feels slow" is not something anybody can
/// act on, and the answer to it is almost never where people assume: on this
/// machine the file table is most of it and always was, so the interesting
/// number is how much of the rest is avoidable.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Timings {
    /// Reading the master file table off the volume.
    pub read_table: u64,
    /// Of that, the part spent waiting on the disk rather than parsing.
    pub read_table_io: u64,
    /// File records the table held.
    pub records: u64,
    /// Turning that into a directory tree with sizes.
    pub build_index: u64,
    /// Registry, launch history, and matching applications to directories.
    pub applications: u64,
    /// Looking for directories no installed application accounts for.
    pub orphans: u64,
    /// Looking for large files that arrived from the internet.
    pub downloads: u64,
    pub total: u64,
}

/// Everything the registry knows, without reading the disk at all.
///
/// The point of this product is the gap between what an installer claims and
/// what it occupies, and the two halves cost wildly different amounts to
/// answer. The claim is a registry read: every name, publisher, version,
/// install date and `EstimatedSize` on the machine, in about fifty
/// milliseconds. The truth needs the whole master file table, which is over a
/// second and a half.
///
/// So they are separated, and the interface shows the claims immediately and
/// replaces them as the measurements arrive. Sorting by name, publisher or
/// install date works on the first set; only the sizes have to wait.
///
/// Needs no privileges: the uninstall keys and Steam's manifests are both
/// readable by the person they belong to. That is why this runs in the window
/// rather than in the agent, and why it costs nothing to call.
pub fn registry_listing(user: &UserContext) -> Vec<AppFootprint> {
    let steam = crate::steam::installed_games(user);
    let history = crate::usage::history(user);

    let mut listing: Vec<AppFootprint> = with_steam_games(installed(user), &steam)
        .into_iter()
        .map(|app| {
            // Where the launch history can be joined without the file table:
            // by the install directory the registry already names.
            let launched = app
                .install_location
                .as_deref()
                .and_then(|path| crate::usage::latest_under(&history.by_path, path));

            AppFootprint {
                reported_bytes: app.estimated_kilobytes.map(|kb| kb as u64 * 1024),
                // Nothing has been measured yet, and nothing here pretends
                // otherwise: the interface shows these rows as unmeasured
                // rather than as zero bytes.
                actual_bytes: 0,
                shared_bytes: 0,
                locations: Vec::new(),
                last_used: app
                    .last_played
                    .or_else(|| launched.as_ref().and_then(|found| found.last_run))
                    .or_else(|| {
                        match_by_name(&history.unattributed, &app.name, Some(&app.publisher))
                            .and_then(|found| found.last_run)
                    }),
                launches: launched.as_ref().map(|found| found.runs),
                name: app.name,
                publisher: app.publisher,
                version: app.version,
                uninstall_command: app.uninstall_command,
                installed_on: app.installed_on,
            }
        })
        .collect();

    // The same order the measured list will arrive in for everything that has
    // no claimed size, so the rows move as little as possible when the real
    // figures land.
    listing.sort_by(|a, b| {
        b.reported_bytes
            .unwrap_or(0)
            .cmp(&a.reported_bytes.unwrap_or(0))
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    listing
}

/// Read the volume's table, then measure applications and find leftovers.
pub fn survey(drive_letter: char, now_unix: u64, user: &UserContext) -> Result<StorageReport> {
    let whole = std::time::Instant::now();
    let mut timings = Timings::default();

    let step = std::time::Instant::now();
    let snapshot = crate::mft::read(drive_letter)?;
    timings.read_table = step.elapsed().as_millis() as u64;
    timings.read_table_io = snapshot.stats.io_millis;
    timings.records = snapshot.stats.records_seen;

    let step = std::time::Instant::now();
    let index = VolumeIndex::build(snapshot);
    timings.build_index = step.elapsed().as_millis() as u64;

    let root = format!("{drive_letter}:");

    let step = std::time::Instant::now();
    let apps = footprints(&index, &root, user)?;
    timings.applications = step.elapsed().as_millis() as u64;
    let summary = summarise(&apps);

    let step = std::time::Instant::now();
    let orphans = crate::orphans::find(&index, &apps, now_unix, user);
    let orphan_summary = crate::orphans::summarise(&orphans);
    timings.orphans = step.elapsed().as_millis() as u64;

    let step = std::time::Instant::now();
    let (downloads, download_summary) = crate::provenance::find(&index, &root, now_unix);
    timings.downloads = step.elapsed().as_millis() as u64;

    timings.total = whole.elapsed().as_millis() as u64;
    Ok(StorageReport {
        apps,
        summary,
        orphans,
        orphan_summary,
        downloads,
        download_summary,
        timings,
    })
}

/// Read the volume's table and measure every installed application against it.
///
/// Needs administrative rights, because the master file table does. There is no
/// directory-walking fallback: the candidate directories add up to most of the
/// disk, so walking them would cost more than reading the whole table and give
/// a worse answer.
pub fn measure(
    drive_letter: char,
    user: &UserContext,
) -> Result<(Vec<AppFootprint>, FootprintSummary)> {
    let snapshot = crate::mft::read(drive_letter)?;
    let index = VolumeIndex::build(snapshot);
    let apps = footprints(&index, &format!("{drive_letter}:"), user)?;
    let summary = summarise(&apps);
    Ok((apps, summary))
}

/// Summary counts for the header of the applications view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FootprintSummary {
    pub applications: usize,
    pub measured_bytes: u64,
    pub reported_bytes: u64,
    /// Applications whose installer wrote no size at all.
    pub without_reported_size: usize,
}

pub fn summarise(apps: &[AppFootprint]) -> FootprintSummary {
    let mut summary = FootprintSummary {
        applications: apps.len(),
        measured_bytes: 0,
        reported_bytes: 0,
        without_reported_size: 0,
    };
    let mut counted: HashMap<&str, ()> = HashMap::new();
    for app in apps {
        summary.measured_bytes += app.actual_bytes;
        match app.reported_bytes {
            Some(bytes) => summary.reported_bytes += bytes,
            None => summary.without_reported_size += 1,
        }
        counted.insert(app.name.as_str(), ());
    }
    summary
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn the_registry_listing_costs_nothing_and_claims_nothing_it_has_not_read() {
        let started = std::time::Instant::now();
        let listing = registry_listing(&kam_core::UserContext::current());
        let elapsed = started.elapsed();

        // The whole reason it exists: it must be fast enough to show before
        // anybody notices, or the measured list may as well be the only one.
        assert!(
            elapsed < std::time::Duration::from_millis(1500),
            "the registry listing took {elapsed:?}, which is no longer worth showing first"
        );

        for app in &listing {
            assert!(!app.name.is_empty());
            // Nothing has been measured, and nothing pretends it has.
            assert_eq!(app.actual_bytes, 0, "{} claims a measured size", app.name);
            assert_eq!(app.shared_bytes, 0);
            assert!(app.locations.is_empty(), "{} claims a location", app.name);
        }

        // Largest claim first, then by name, so the rows move as little as
        // possible when the real figures replace them.
        for pair in listing.windows(2) {
            let (a, b) = (
                pair[0].reported_bytes.unwrap_or(0),
                pair[1].reported_bytes.unwrap_or(0),
            );
            assert!(a >= b, "the listing is not ordered by claimed size");
        }
    }

    #[test]
    #[ignore = "compares against this machine's real registry"]
    fn the_listing_names_the_same_applications_the_measurement_does() {
        let user = kam_core::UserContext::current();
        let listing = registry_listing(&user);
        println!(
            "
{} applications from the registry alone",
            listing.len()
        );
        for app in listing.iter().take(10) {
            println!(
                "  {:<44} claimed {:>10}  last used {:?}",
                app.name,
                app.reported_bytes
                    .map(|b| format!("{} MB", b / 1_000_000))
                    .unwrap_or_else(|| "none".to_owned()),
                app.last_used
            );
        }
    }

    fn recorded(id: &str, at: u64) -> crate::usage::Usage {
        crate::usage::Usage {
            path: String::new(),
            app_id: Some(id.to_owned()),
            runs: 0,
            last_run: Some(at),
        }
    }

    #[test]
    fn a_launch_recorded_under_a_name_finds_its_application() {
        // The real case: Explorer records this launch as
        // `Microsoft.VisualStudioCode`, which appears nowhere on disk, while
        // the uninstall entry calls it "Microsoft Visual Studio Code (User)".
        let records = vec![
            recorded("Microsoft.VisualStudioCode", 1_787_389_214),
            recorded("com.squirrel.Discord.Discord", 1_787_907_537),
        ];
        let found = match_by_name(
            &records,
            "Microsoft Visual Studio Code (User)",
            Some("Microsoft Corporation"),
        );
        assert_eq!(found.and_then(|usage| usage.last_run), Some(1_787_389_214));
    }

    #[test]
    fn a_name_short_enough_to_collide_matches_nothing() {
        // "Code" would otherwise match Visual Studio Code, VS Code Insiders,
        // and anything else with those four letters in its id.
        let records = vec![recorded("Microsoft.VisualStudioCode", 1_787_389_214)];
        assert!(match_by_name(&records, "Code", None).is_none());
        assert!(match_by_name(&records, "App", None).is_none());
    }

    #[test]
    fn an_unrelated_application_is_not_given_somebody_elses_date() {
        let records = vec![recorded("Valve.Steam.Client", 1_787_770_031)];
        assert!(match_by_name(&records, "Mozilla Firefox", Some("Mozilla")).is_none());
        assert!(match_by_name(&records, "Notepad++", Some("Don Ho")).is_none());
    }

    #[test]
    fn a_record_with_no_time_is_not_worth_matching() {
        let mut record = recorded("Microsoft.VisualStudioCode", 0);
        record.last_run = None;
        assert!(match_by_name(&[record], "Microsoft Visual Studio Code", None).is_none());
    }

    use kam_core::Reporter;

    #[test]
    fn normalising_ignores_case_spacing_and_punctuation() {
        assert_eq!(normalise("Path of Exile 2"), "pathofexile2");
        assert_eq!(normalise("PathOfExile2"), "pathofexile2");
        assert_eq!(
            normalise("Mozilla Firefox (x64 en-GB)"),
            "mozillafirefoxx64engb"
        );
    }

    #[test]
    fn short_names_must_match_exactly() {
        // Otherwise "7" matches "7-Zip", "Windows 7 Codecs", and half the disk.
        assert!(!names_match("7zip", "7"));
        assert!(names_match("7z", "7z"));
    }

    #[test]
    fn longer_names_match_by_containment_either_way() {
        assert!(names_match("mozillafirefox", "firefox"));
        assert!(names_match("firefox", "mozillafirefox"));
        assert!(!names_match("firefox", "chrome"));
    }

    fn location(path: &str, bytes: u64) -> Location {
        Location {
            path: path.to_owned(),
            bytes,
            kind: LocationKind::ProgramData,
            shared_with: 0,
        }
    }

    #[test]
    fn a_steam_title_takes_its_date_from_steam_rather_than_from_explorer() {
        // The bug this pins: Steam starts the game, so Explorer's launch
        // history records Steam and nothing else, and every title on the
        // machine showed "no record of you opening it" -- including ones
        // played that week.
        let steam = vec![crate::steam::SteamApp {
            name: "ELDEN RING".to_owned(),
            path: r"C:\Steam\steamapps\common\ELDEN RING".to_owned(),
            app_id: "1245620".to_owned(),
            last_played: Some(1_784_058_206),
        }];
        let merged = with_steam_games(Vec::new(), &steam);
        assert_eq!(merged[0].last_played, Some(1_784_058_206));
    }

    #[test]
    fn a_game_installed_and_never_started_has_no_date_rather_than_1970() {
        // Steam writes a zero there, which read as a date would be the first
        // of January 1970 in a column of real ones.
        let steam = vec![crate::steam::SteamApp {
            name: "SWORN".to_owned(),
            path: r"C:\Steam\steamapps\common\SWORN".to_owned(),
            app_id: "1763250".to_owned(),
            last_played: None,
        }];
        assert_eq!(with_steam_games(Vec::new(), &steam)[0].last_played, None);
    }

    #[test]
    fn steam_games_missing_from_the_registry_are_added() {
        // Steam does not register every title, so without this a 40 GB game can
        // be absent from the list of installed software entirely.
        let registry = vec![Installed {
            name: "Warframe".to_owned(),
            publisher: "Digital Extremes".to_owned(),
            version: String::new(),
            install_location: None,
            estimated_kilobytes: None,
            uninstall_command: None,
            installed_on: None,
            last_played: None,
        }];
        let steam = vec![
            crate::steam::SteamApp {
                name: "Warframe".to_owned(),
                path: r"C:\Steam\steamapps\common\Warframe".to_owned(),
                app_id: "230410".to_owned(),
                last_played: Some(1_780_000_000),
            },
            crate::steam::SteamApp {
                name: "Deep Rock Galactic".to_owned(),
                path: r"C:\Steam\steamapps\common\Deep Rock Galactic".to_owned(),
                app_id: "548430".to_owned(),
                last_played: None,
            },
        ];

        let merged = with_steam_games(registry, &steam);
        assert_eq!(merged.len(), 2, "the unregistered game should be added");

        let existing = merged.iter().find(|app| app.name == "Warframe").unwrap();
        assert_eq!(
            existing.publisher, "Digital Extremes",
            "a registered game keeps its own details"
        );
        let added = merged
            .iter()
            .find(|app| app.name == "Deep Rock Galactic")
            .unwrap();
        assert_eq!(added.publisher, "Steam");
        assert!(added.install_location.is_some());
        assert_eq!(
            added.uninstall_command.as_deref(),
            Some("steam://uninstall/548430"),
            "a Steam title is removed through Steam"
        );
    }

    #[test]
    fn the_same_directory_spelled_differently_is_one_directory() {
        // The registry, Steam's config and a trailing separator all name the
        // same folder differently. Treating them as three cost a 66 GB game an
        // extra 66 GB before this existed.
        let steam_style = r"c:/program files (x86)/steam/steamapps/common/Warframe";
        let registry_style = r"C:\Program Files (x86)\Steam\steamapps\common\Warframe";
        let trailing = r"C:\Program Files (x86)\Steam\steamapps\common\Warframe";
        assert_eq!(canonical(steam_style), canonical(registry_style));
        assert_eq!(canonical(registry_style), canonical(trailing));

        let mut locations = Vec::new();
        push_unique(&mut locations, location(steam_style, 50));
        push_unique(&mut locations, location(registry_style, 50));
        push_unique(&mut locations, location(trailing, 50));
        assert_eq!(locations.len(), 1, "one folder counted more than once");
    }

    #[test]
    fn different_directories_are_still_different() {
        assert_ne!(
            canonical(r"C:\Games\Warframe"),
            canonical(r"C:\Games\Warframe2")
        );
    }

    #[test]
    fn a_directory_found_twice_is_only_counted_once() {
        let mut locations = Vec::new();
        push_unique(&mut locations, location(r"C:\ProgramData\Thing", 10));
        // Same directory, different case, as the registry often gives.
        push_unique(&mut locations, location(r"C:\programdata\thing", 10));
        assert_eq!(locations.len(), 1);
    }

    #[test]
    fn a_parent_directory_is_dropped_when_its_child_is_also_claimed() {
        // Keeping both would count the inner folder twice inside one total.
        let mut locations = vec![
            location(r"C:\ProgramData\Vendor", 900),
            location(r"C:\ProgramData\Vendor\App", 100),
            location(r"C:\Program Files\App", 50),
        ];
        drop_ancestors(&mut locations);

        let kept: Vec<&str> = locations.iter().map(|l| l.path.as_str()).collect();
        assert_eq!(
            kept,
            vec![r"C:\ProgramData\Vendor\App", r"C:\Program Files\App"]
        );
    }

    #[test]
    fn a_sibling_with_a_shared_prefix_is_not_mistaken_for_a_child() {
        // "Vendor" must not swallow "VendorTools": string prefixes are not
        // path prefixes without the separator.
        let mut locations = vec![
            location(r"C:\ProgramData\Vendor", 900),
            location(r"C:\ProgramData\VendorTools", 100),
        ];
        drop_ancestors(&mut locations);
        assert_eq!(locations.len(), 2);
    }

    #[test]
    fn understatement_needs_something_to_compare_against() {
        let mut app = AppFootprint {
            name: "Thing".to_owned(),
            publisher: String::new(),
            version: String::new(),
            reported_bytes: None,
            actual_bytes: 4096,
            shared_bytes: 0,
            locations: Vec::new(),
            uninstall_command: None,
            installed_on: None,
            last_used: None,
            launches: None,
        };
        assert!(app.understatement().is_none());

        app.reported_bytes = Some(0);
        assert!(app.understatement().is_none(), "must not divide by zero");

        app.reported_bytes = Some(1024);
        assert_eq!(app.understatement(), Some(4.0));
    }

    #[test]
    fn this_machine_has_installed_software_with_names() {
        let apps = installed(&kam_core::UserContext::current());
        assert!(!apps.is_empty(), "no installed applications found at all");
        assert!(apps.iter().all(|app| !app.name.trim().is_empty()));
    }

    /// Needs administrator rights, and reads the whole table. Run deliberately:
    /// `cargo test -p kam-storage --release -- --ignored --nocapture measure_installed`
    #[test]
    #[ignore = "reads the whole master file table and needs elevation"]
    fn measure_installed_applications() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);
        let snapshot = crate::mft::read('C').unwrap();
        let index = VolumeIndex::build(snapshot);
        let apps = footprints(&index, "C:", &kam_core::UserContext::current()).unwrap();
        let summary = summarise(&apps);

        let gb = |bytes: u64| bytes as f64 / 1024.0 / 1024.0 / 1024.0;

        // What the depth work added: when each was installed, and when this
        // account last actually launched it.
        let dated = apps.iter().filter(|a| a.installed_on.is_some()).count();
        let used = apps.iter().filter(|a| a.last_used.is_some()).count();
        println!(
            "
DEPTH: {} applications, {dated} with an install date, {used} with a launch record",
            apps.len()
        );
        for app in apps.iter().take(14) {
            let age = app
                .last_used
                .map(|last| format!("{}d ago", now.saturating_sub(last) / 86_400))
                .unwrap_or_else(|| "no record".to_owned());
            println!(
                "  {:>8.1} GB  installed {:<11} used {:<11} {}",
                gb(app.actual_bytes),
                app.installed_on.as_deref().unwrap_or("unknown"),
                age,
                app.name
            );
        }

        let profile = std::env::var("USERPROFILE").unwrap();
        let (proposals, osum) = crate::organise::find(&index, profile.trim_end_matches('\\'));
        println!(
            "
ORGANISE: {} proposals from {} loose files, {:.1} GB",
            osum.proposals,
            osum.examined,
            gb(osum.bytes)
        );
        for proposal in proposals.iter().take(12) {
            println!(
                "  {:?}  {}\n       -> {}\n       because {}",
                proposal.strength, proposal.name, proposal.to, proposal.reason
            );
        }

        let user = kam_core::UserContext::current();
        let (dupes, dsum) =
            crate::duplicates::find(&index, "C:", &Reporter::silent(), &user).unwrap();
        println!(
            "
DUPLICATES: {} sets holding {:.1} GB of copies, {:.1} GB of it reclaimable across {} sets | {} files sized, {} heads read, {} read whole | {} ms{}",
            dsum.groups,
            gb(dsum.wasted_bytes),
            gb(dsum.reclaimable_bytes),
            dsum.actionable,
            dsum.examined,
            dsum.head_hashed,
            dsum.fully_hashed,
            dsum.elapsed_ms,
            if dsum.truncated {
                " (hit the read ceiling)"
            } else {
                ""
            }
        );
        for group in dupes.iter().take(10) {
            println!(
                "  {:?}: {} copies of {:.2} GB, {:.2} GB reclaimable",
                group.verdict,
                group.copies.len(),
                gb(group.bytes),
                gb(group.reclaimable_bytes)
            );
            for why in &group.reasons {
                println!("       {why}");
            }
            for (n, copy) in group.copies.iter().take(4).enumerate() {
                let mark = if group.suggested_keep == Some(n) {
                    "keep"
                } else if copy.removable {
                    "spare"
                } else {
                    "    "
                };
                println!("       [{mark}] {:?}  {}", copy.owner, copy.path);
            }
        }

        let (downloads, download_summary) = crate::provenance::find(&index, "C:", now);
        println!(
            "\nDOWNLOADS: {} of {} large files carry a download record, {:.1} GB (last-access tracked: {})",
            download_summary.found,
            download_summary.examined,
            gb(download_summary.total_bytes),
            download_summary.last_access_tracked
        );
        for download in downloads.iter().take(10) {
            println!(
                "  {:>7.2} GB  {}  <- {}  ({} days ago)",
                gb(download.bytes),
                download.name,
                // Host only: these URLs carry tokens and account identifiers.
                download
                    .host_url
                    .as_deref()
                    .and_then(|url| url.split('/').nth(2))
                    .unwrap_or("source not recorded"),
                download
                    .days_since_arrival
                    .map(|days| days.to_string())
                    .unwrap_or_else(|| "?".to_owned())
            );
        }
        println!(
            "\nSTEAM: {} games located from manifests",
            crate::steam::installed_games(&kam_core::UserContext::current()).len()
        );

        let orphans = crate::orphans::find(&index, &apps, now, &kam_core::UserContext::current());
        let orphan_summary = crate::orphans::summarise(&orphans);
        println!(
            "\nLEFTOVERS: {} directories holding {:.1} GB, of which {:.1} GB is high confidence",
            orphan_summary.found,
            orphan_summary.total_bytes as f64 / 1024.0 / 1024.0 / 1024.0,
            orphan_summary.confident_bytes as f64 / 1024.0 / 1024.0 / 1024.0
        );
        for orphan in orphans.iter().take(12) {
            println!(
                "  {:>8.2} GB  {:?}  {}  ({})",
                orphan.bytes as f64 / 1024.0 / 1024.0 / 1024.0,
                orphan.confidence,
                orphan.path,
                orphan.reasons.join("; ")
            );
        }
        println!();

        let gb = |bytes: u64| bytes as f64 / 1024.0 / 1024.0 / 1024.0;
        println!(
            "{} applications | measured {:.1} GB | Control Panel claims {:.1} GB | {} report no size at all",
            summary.applications,
            gb(summary.measured_bytes),
            gb(summary.reported_bytes),
            summary.without_reported_size
        );

        println!("\n   ACTUAL   REPORTED   RATIO  APPLICATION");
        for app in apps.iter().take(15) {
            let reported = app
                .reported_bytes
                .map(|bytes| format!("{:.1} GB", gb(bytes)))
                .unwrap_or_else(|| "none".to_owned());
            let ratio = app
                .understatement()
                .map(|value| format!("{value:.1}x"))
                .unwrap_or_else(|| "-".to_owned());
            println!(
                "{:>9}  {:>9}  {:>6}  {}",
                format!("{:.1} GB", gb(app.actual_bytes)),
                reported,
                ratio,
                app.name
            );
            for location in &app.locations {
                let note = if location.shared_with > 0 {
                    format!(
                        "  [shared with {} others, not counted]",
                        location.shared_with
                    )
                } else {
                    String::new()
                };
                println!(
                    "             {:>9}  {}{note}",
                    format!("{:.1} GB", gb(location.bytes)),
                    location.path
                );
            }
        }
    }
}
