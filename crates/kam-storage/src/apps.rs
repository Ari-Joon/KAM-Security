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
use serde::{Deserialize, Serialize};
use windows::Win32::System::Registry::{HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

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
}

/// Read every uninstall key across both registry views and both hives.
fn installed() -> Vec<Installed> {
    let sources: [(HKEY, View); 3] = [
        (HKEY_LOCAL_MACHINE, View::Native),
        // 32-bit software on 64-bit Windows lives in a separate view, and it is
        // roughly half of what is installed on a typical machine.
        (HKEY_LOCAL_MACHINE, View::Wow6432),
        (HKEY_CURRENT_USER, View::Native),
    ];

    let mut found: Vec<Installed> = Vec::new();
    let mut seen: Vec<String> = Vec::new();

    for (root, view) in sources {
        let Some(key) = Key::open(root, UNINSTALL, view) else {
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
pub(crate) fn data_roots() -> Vec<(LocationKind, String)> {
    let mut roots = Vec::new();
    if let Some(value) = std::env::var_os("ProgramData") {
        roots.push((
            LocationKind::ProgramData,
            value.to_string_lossy().into_owned(),
        ));
    }
    if let Some(value) = std::env::var_os("LOCALAPPDATA") {
        roots.push((
            LocationKind::LocalData,
            value.to_string_lossy().into_owned(),
        ));
    }
    if let Some(value) = std::env::var_os("APPDATA") {
        roots.push((
            LocationKind::RoamingData,
            value.to_string_lossy().into_owned(),
        ));
    }
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
pub fn footprints(index: &VolumeIndex, drive_root: &str) -> Result<Vec<AppFootprint>> {
    let roots = data_roots();
    let steam = crate::steam::installed_games();

    let candidates: Vec<(Installed, Vec<Location>)> = with_steam_games(installed(), &steam)
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
}

/// Read the volume's table, then measure applications and find leftovers.
pub fn survey(drive_letter: char, now_unix: u64) -> Result<StorageReport> {
    let snapshot = crate::mft::read(drive_letter)?;
    let index = VolumeIndex::build(snapshot);
    let root = format!("{drive_letter}:");
    let apps = footprints(&index, &root)?;
    let summary = summarise(&apps);
    let orphans = crate::orphans::find(&index, &apps, now_unix);
    let orphan_summary = crate::orphans::summarise(&orphans);
    let (downloads, download_summary) = crate::provenance::find(&index, &root, now_unix);
    Ok(StorageReport {
        apps,
        summary,
        orphans,
        orphan_summary,
        downloads,
        download_summary,
    })
}

/// Read the volume's table and measure every installed application against it.
///
/// Needs administrative rights, because the master file table does. There is no
/// directory-walking fallback: the candidate directories add up to most of the
/// disk, so walking them would cost more than reading the whole table and give
/// a worse answer.
pub fn measure(drive_letter: char) -> Result<(Vec<AppFootprint>, FootprintSummary)> {
    let snapshot = crate::mft::read(drive_letter)?;
    let index = VolumeIndex::build(snapshot);
    let apps = footprints(&index, &format!("{drive_letter}:"))?;
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
        }];
        let steam = vec![
            crate::steam::SteamApp {
                name: "Warframe".to_owned(),
                path: r"C:\Steam\steamapps\common\Warframe".to_owned(),
                app_id: "230410".to_owned(),
            },
            crate::steam::SteamApp {
                name: "Deep Rock Galactic".to_owned(),
                path: r"C:\Steam\steamapps\common\Deep Rock Galactic".to_owned(),
                app_id: "548430".to_owned(),
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
        };
        assert!(app.understatement().is_none());

        app.reported_bytes = Some(0);
        assert!(app.understatement().is_none(), "must not divide by zero");

        app.reported_bytes = Some(1024);
        assert_eq!(app.understatement(), Some(4.0));
    }

    #[test]
    fn this_machine_has_installed_software_with_names() {
        let apps = installed();
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
        let apps = footprints(&index, "C:").unwrap();
        let summary = summarise(&apps);

        let gb = |bytes: u64| bytes as f64 / 1024.0 / 1024.0 / 1024.0;

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

        let (dupes, dsum) = crate::duplicates::find(&index, "C:", &Reporter::silent()).unwrap();
        println!(
            "
DUPLICATES: {} sets wasting {:.1} GB | {} files sized, {} heads read, {} read whole | {} ms{}",
            dsum.groups,
            gb(dsum.wasted_bytes),
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
        for group in dupes.iter().take(8) {
            println!(
                "  {:>7.2} GB wasted, {} copies of {:.2} GB:",
                gb(group.wasted_bytes),
                group.paths.len(),
                gb(group.bytes)
            );
            for path in group.paths.iter().take(3) {
                println!("       {path}");
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
            crate::steam::installed_games().len()
        );

        let orphans = crate::orphans::find(&index, &apps, now);
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
