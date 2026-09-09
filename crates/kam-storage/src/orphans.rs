//! Directories left behind by software that is no longer installed.
//!
//! Uninstallers routinely remove their program files and leave everything under
//! `ProgramData` and the `AppData` roots exactly where it was. Years later it is
//! still there, and nothing in Windows will ever mention it.
//!
//! # This is the first thing here that can lose data
//!
//! Every other module measures. This one produces a list a user may act on, and
//! acting means moving a directory. So the rules are deliberately timid:
//!
//! - **Only the three data roots.** `Program Files` is not examined. Plenty of
//!   uninstall entries have no `InstallLocation`, so a perfectly live
//!   application's folder can look unclaimed, and being wrong there is much
//!   worse than missing a few gigabytes.
//! - **Windows' own directories are never candidates**, by name.
//! - **Anything matching an installed application or its publisher is skipped**,
//!   using the same matching the footprint attribution uses.
//! - **Recently modified directories are never high confidence**, whatever else
//!   is true of them. Something wrote to it; something still uses it.
//! - **Nothing under a size floor is reported at all**, because a list of
//!   400 KB leftovers buries the 12 GB one.
//!
//! The output is a suggestion with its reasoning attached, never an instruction.

use std::collections::HashSet;

use kam_core::UserContext;

use serde::{Deserialize, Serialize};

use crate::apps::{normalise, LocationKind};
use crate::index::VolumeIndex;

/// Below this a leftover is not worth a row in a list.
const SIZE_FLOOR: u64 = 64 * 1024 * 1024;

/// Untouched for longer than this, and it is very unlikely to be in use.
const STALE_DAYS: f64 = 365.0;
/// Touched more recently than this, and something is still writing to it.
const ACTIVE_DAYS: f64 = 90.0;

/// Directories that belong to Windows, or are shared infrastructure no single
/// application owns. Never reported, regardless of anything else.
const NEVER_ORPHANS: &[&str] = &[
    "microsoft",
    "windows",
    "windowsapps",
    "packages",
    "packagecache",
    "package cache",
    "temp",
    "tmp",
    "crashdumps",
    "connecteddevicesplatform",
    "comms",
    "d3dscache",
    "elevateddiagnostics",
    "virtualstore",
    "placeholdertilelogofolder",
    "softwaredistribution",
    "usoprivate",
    "usoshared",
    "ssh",
    "applicationdata",
    "application data",
    "desktop",
    "documents",
    "downloads",
    "favorites",
    "startmenu",
    "start menu",
    "templates",
    "history",
    "inetcache",
    "iconcache",
    "programs",
    "publisher",
    "systemdata",
    "defender",
    "windowsdefender",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Something wrote to it recently, or it is small. Shown, not recommended.
    Low,
    /// Unclaimed and sizeable, but touched within the last year.
    Medium,
    /// Unclaimed, sizeable, and untouched for over a year.
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Orphan {
    pub path: String,
    pub name: String,
    pub bytes: u64,
    pub kind: LocationKind,
    pub confidence: Confidence,
    /// Days since anything in the directory was written, when known.
    pub days_since_modified: Option<u64>,
    /// Why it is on the list, in the order a person would want to read it.
    pub reasons: Vec<String>,
}

/// Windows FILETIME ticks between 1601 and the Unix epoch.
const FILETIME_EPOCH_OFFSET: u64 = 11_644_473_600;

fn filetime_to_unix(filetime: u64) -> Option<u64> {
    if filetime == 0 {
        return None;
    }
    (filetime / 10_000_000).checked_sub(FILETIME_EPOCH_OFFSET)
}

fn days_since(filetime: u64, now: u64) -> Option<u64> {
    let seconds = filetime_to_unix(filetime)?;
    Some(now.saturating_sub(seconds) / 86_400)
}

/// Names claimed by something currently installed.
fn claimed_names(apps: &[crate::apps::AppFootprint]) -> HashSet<String> {
    let mut claimed = HashSet::new();
    for app in apps {
        let name = normalise(&app.name);
        if !name.is_empty() {
            claimed.insert(name);
        }
        let publisher = normalise(&app.publisher);
        if !publisher.is_empty() {
            claimed.insert(publisher);
        }
    }
    claimed
}

/// A folder is claimed when any installed name matches it the same way the
/// footprint attribution matches, so the two views cannot disagree.
fn is_claimed(folder: &str, claimed: &HashSet<String>) -> bool {
    if claimed.contains(folder) {
        return true;
    }
    claimed.iter().any(|name| {
        if folder.len() < 4 || name.len() < 4 {
            false
        } else {
            folder.contains(name) || name.contains(folder)
        }
    })
}

/// Find leftover directories on an indexed volume.
///
/// `apps` comes from [`crate::apps::footprints`] against the same index, so the
/// two share one read of the table.
pub fn find(
    index: &VolumeIndex,
    apps: &[crate::apps::AppFootprint],
    now_unix: u64,
    user: &UserContext,
) -> Vec<Orphan> {
    let claimed = claimed_names(apps);
    let mut orphans = Vec::new();

    for (kind, root) in crate::apps::data_roots(user) {
        let Some(root_index) = index.resolve(&root) else {
            continue;
        };

        for child in index.directories_in(root_index) {
            let Some(entry) = index.entry(*child) else {
                continue;
            };
            let folder = normalise(&entry.name);
            let lowered = entry.name.to_lowercase();

            if folder.is_empty()
                || NEVER_ORPHANS.contains(&lowered.as_str())
                || NEVER_ORPHANS.contains(&folder.as_str())
            {
                continue;
            }
            if is_claimed(&folder, &claimed) {
                continue;
            }

            let bytes = index.total_of(*child);
            if bytes < SIZE_FLOOR {
                continue;
            }

            let days = days_since(entry.modified, now_unix);
            let mut reasons = vec![format!(
                "no installed application matches the name \"{}\"",
                entry.name
            )];

            let confidence = match days {
                Some(days) if (days as f64) > STALE_DAYS => {
                    reasons.push(format!(
                        "nothing has written to it in {:.1} years",
                        days as f64 / 365.0
                    ));
                    Confidence::High
                }
                Some(days) if (days as f64) < ACTIVE_DAYS => {
                    reasons.push(format!(
                        "but something wrote to it {days} days ago, so it is probably still in use"
                    ));
                    Confidence::Low
                }
                Some(days) => {
                    reasons.push(format!("last written to {days} days ago"));
                    Confidence::Medium
                }
                None => {
                    reasons.push("its last-write time could not be read".to_owned());
                    Confidence::Low
                }
            };

            orphans.push(Orphan {
                path: format!("{root}\\{}", entry.name),
                name: entry.name.clone(),
                bytes,
                kind,
                confidence,
                days_since_modified: days,
                reasons,
            });
        }
    }

    // Most confident first, then largest, so the top of the list is both the
    // safest to act on and the most worth acting on.
    orphans.sort_by(|a, b| b.confidence.cmp(&a.confidence).then(b.bytes.cmp(&a.bytes)));
    orphans
}

/// Decide whether a path may be quarantined at all.
///
/// This is the fence, and it lives on the agent's side of the pipe. The list of
/// orphans the UI shows is a suggestion produced from data; the path that comes
/// back is just a string from a client, and the agent runs as LocalSystem. It
/// gets re-derived from first principles here rather than trusted.
///
/// The rule is narrow on purpose: exactly one level below one of the three data
/// roots, and not a name Windows owns. `C:\Windows`, `C:\ProgramData` itself,
/// and anything nested deeper are all refused.
///
/// # Why it resolves the path before judging it
///
/// It used to compare the string it was given, and that was a hole. Windows
/// will open and rename a directory through its own index stream, so
/// `%LOCALAPPDATA%\Microsoft::$INDEX_ALLOCATION` names the same object as
/// `%LOCALAPPDATA%\Microsoft` — but as text it matches neither `microsoft` nor,
/// once stripped to letters, anything else on the list. Both checks missed it,
/// the fence returned `Ok`, and `symlink_metadata` reported an ordinary
/// directory so the reparse-point guard downstream stayed silent. Adversarial
/// review demonstrated the rename: the real directory moved.
///
/// Rejecting that one spelling would have closed that one hole. The 8.3 short
/// name `MICROS~1` is the same trick with different syntax, and whether it
/// exists is a per-volume setting on a machine this is meant to run on
/// unmodified — so the string was never the thing to reason about. Asking the
/// filesystem what the path points at closes the spellings nobody here has
/// thought of yet, which is the only version of this that stays closed.
///
/// A path that cannot be resolved is refused rather than judged as text.
/// Something that cannot be located is not something to move as LocalSystem,
/// and a directory that is not there cannot be a leftover worth reclaiming.
pub fn check_quarantinable(path: &str, user: &UserContext) -> std::result::Result<(), String> {
    let Some(real) = crate::paths::existing_plain(path) else {
        return Err(format!(
            "{path} could not be found on disk, so it will not be touched"
        ));
    };
    let real = real.trim_end_matches(['\\', '/']).to_owned();

    for (_, root) in crate::apps::data_roots(user) {
        // Resolved against resolved: see `paths::resolved_root` for why
        // comparing a resolved path to a root's own spelling is wrong. A root
        // that is not there cannot contain anything, so it is skipped.
        let Some(root) = crate::paths::resolved_root(&root) else {
            continue;
        };
        if real == root {
            return Err(format!("{path} is a data root itself"));
        }

        let Some(remainder) = real.strip_prefix(&format!("{root}\\")) else {
            continue;
        };
        if remainder.contains('\\') {
            return Err(format!(
                "{path} is nested below a data root; only a directory directly \
                 inside one may be quarantined"
            ));
        }
        // Resolving should have removed any stream syntax, and a directory name
        // legitimately never carries a colon. Refusing rather than trusting that
        // means the day it does get through, the answer is a refusal and not a
        // rename.
        if remainder.contains(':') {
            return Err(format!("{path} is not a plain directory name"));
        }
        if NEVER_ORPHANS.contains(&remainder)
            || NEVER_ORPHANS.contains(&normalise(remainder).as_str())
        {
            return Err(format!("{path} is a directory Windows owns"));
        }
        return Ok(());
    }

    Err(format!(
        "{path} is not inside ProgramData, Local AppData or Roaming AppData, \
         which are the only places this will touch"
    ))
}

/// Totals for the header of the cleanup view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrphanSummary {
    pub found: usize,
    pub total_bytes: u64,
    /// Bytes in the high-confidence entries only — what could be reclaimed
    /// without much thought.
    pub confident_bytes: u64,
}

pub fn summarise(orphans: &[Orphan]) -> OrphanSummary {
    OrphanSummary {
        found: orphans.len(),
        total_bytes: orphans.iter().map(|o| o.bytes).sum(),
        confident_bytes: orphans
            .iter()
            .filter(|o| o.confidence == Confidence::High)
            .map(|o| o.bytes)
            .sum(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::fs;

    fn claimed_set(names: &[&str]) -> HashSet<String> {
        names.iter().map(|name| normalise(name)).collect()
    }

    #[test]
    fn a_folder_matching_an_installed_application_is_claimed() {
        let claimed = claimed_set(&["Mozilla Firefox", "Steam"]);
        assert!(is_claimed(&normalise("Mozilla"), &claimed));
        assert!(is_claimed(&normalise("Firefox"), &claimed));
        assert!(is_claimed(&normalise("Steam"), &claimed));
    }

    #[test]
    fn an_unrelated_folder_is_not_claimed() {
        let claimed = claimed_set(&["Mozilla Firefox"]);
        assert!(!is_claimed(&normalise("SomeDeadVendor"), &claimed));
    }

    #[test]
    fn short_names_do_not_claim_everything() {
        // "7" must not mark every folder as belonging to something installed.
        let claimed = claimed_set(&["7"]);
        assert!(!is_claimed(&normalise("SomeVendor"), &claimed));
    }

    #[test]
    fn windows_own_directories_are_on_the_never_list() {
        for name in ["microsoft", "windows", "packages", "temp"] {
            assert!(NEVER_ORPHANS.contains(&name), "{name} should be excluded");
        }
    }

    #[test]
    fn filetime_converts_to_a_sane_epoch() {
        // 2024-01-01T00:00:00Z as a Windows FILETIME.
        let filetime = (1_704_067_200_u64 + FILETIME_EPOCH_OFFSET) * 10_000_000;
        assert_eq!(filetime_to_unix(filetime), Some(1_704_067_200));
    }

    #[test]
    fn a_zero_timestamp_is_unknown_rather_than_1601() {
        // Otherwise every unreadable timestamp reads as "424 years untouched"
        // and everything becomes high confidence.
        assert_eq!(filetime_to_unix(0), None);
        assert_eq!(days_since(0, 1_704_067_200), None);
    }

    #[test]
    fn days_since_counts_forwards_from_the_timestamp() {
        let now = 1_704_067_200_u64;
        let ten_days_ago = ((now - 10 * 86_400) + FILETIME_EPOCH_OFFSET) * 10_000_000;
        assert_eq!(days_since(ten_days_ago, now), Some(10));
    }

    #[test]
    fn confidence_orders_high_above_low() {
        // The sort depends on this ordering, so it is asserted rather than
        // assumed from the declaration order.
        assert!(Confidence::High > Confidence::Medium);
        assert!(Confidence::Medium > Confidence::Low);
    }

    /// A throwaway profile, so the fence can be tested against real directories
    /// without creating anything in the tester's own AppData.
    ///
    /// The fence resolves paths on disk now, so it cannot be exercised with
    /// names that are not there. That is a better test than the one it replaced
    /// — the old version asserted the fence's opinion of a string, which is
    /// precisely the thing that turned out not to be worth much.
    struct Profile {
        root: std::path::PathBuf,
    }

    impl Profile {
        fn new(tag: &str) -> Self {
            let root = std::env::temp_dir().join(format!("kam-orphans-{tag}"));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(root.join("AppData").join("Local")).unwrap();
            fs::create_dir_all(root.join("AppData").join("Roaming")).unwrap();
            Self { root }
        }

        fn user(&self) -> UserContext {
            UserContext::new(None, &self.root.to_string_lossy())
        }

        fn local(&self) -> std::path::PathBuf {
            self.root.join("AppData").join("Local")
        }

        /// Create a directory under Local AppData and return its path.
        fn make(&self, relative: &str) -> String {
            let path = self.local().join(relative);
            fs::create_dir_all(&path).unwrap();
            path.to_string_lossy().into_owned()
        }
    }

    impl Drop for Profile {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn the_fence_allows_a_directory_directly_inside_a_data_root() {
        let profile = Profile::new("allows");
        let vendor = profile.make("SomeDeadVendor");

        assert!(check_quarantinable(&vendor, &profile.user()).is_ok());
        // The same directory spelled differently is still the same directory.
        assert!(check_quarantinable(&format!("{vendor}\\"), &profile.user()).is_ok());
        assert!(
            check_quarantinable(&vendor.replace('\\', "/"), &profile.user()).is_ok(),
            "forward slashes are separators too"
        );
        assert!(
            check_quarantinable(&format!("\\\\?\\{vendor}"), &profile.user()).is_ok(),
            "the extended-length form names the same directory"
        );
    }

    #[test]
    fn the_fence_refuses_a_data_root_itself() {
        let profile = Profile::new("root-itself");
        let root = profile.local().to_string_lossy().into_owned();

        assert!(check_quarantinable(&root, &profile.user()).is_err());
        assert!(check_quarantinable(&format!("{root}\\"), &profile.user()).is_err());
    }

    #[test]
    fn the_fence_refuses_anything_nested_deeper() {
        // One level only. Deeper paths are where a mistake stops being a
        // leftover folder and starts being someone's saved games.
        let profile = Profile::new("nested");
        let inner = profile.make("Vendor\\Inner");

        assert!(check_quarantinable(&inner, &profile.user()).is_err());
    }

    #[test]
    fn the_fence_refuses_directories_windows_owns() {
        let profile = Profile::new("owned");

        for name in ["Microsoft", "Temp", "Packages"] {
            let path = profile.make(name);
            assert!(
                check_quarantinable(&path, &profile.user()).is_err(),
                "{name} should have been refused"
            );
        }
    }

    /// The deny list is checked against what the path *points at*.
    ///
    /// `Microsoft::$INDEX_ALLOCATION` is the directory's own index stream:
    /// Windows opens it, `symlink_metadata` calls it an ordinary directory, and
    /// `fs::rename` moves it — but as text it matches nothing on the list, and
    /// stripping it to letters gives `microsoftindexallocation`, which matches
    /// nothing either. Both checks missed, and adversarial review moved a real
    /// directory through it as LocalSystem.
    ///
    /// This is the regression test for that. It fails if the fence ever goes
    /// back to judging the string it was handed.
    #[test]
    fn the_fence_sees_through_a_stream_spelling_of_a_protected_name() {
        let profile = Profile::new("stream-spelling");
        profile.make("Microsoft");

        let local = profile.local();
        for spelling in [
            "Microsoft::$INDEX_ALLOCATION",
            "microsoft::$index_allocation",
            "Microsoft::$iNdEx_AlLoCaTiOn",
        ] {
            let path = local.join(spelling).to_string_lossy().into_owned();

            // The premise: Windows really does accept this as the directory. If
            // this ever stops being true the test below proves nothing, so it is
            // asserted rather than assumed.
            assert!(
                fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_dir()),
                "{spelling} no longer opens the directory; revisit this test"
            );

            assert!(
                check_quarantinable(&path, &profile.user()).is_err(),
                "{spelling} got past the deny list"
            );
        }
    }

    /// The fence judges where a name points, not what it is called.
    ///
    /// This is the test with teeth for the resolving step specifically. The
    /// stream spelling above is also caught by the colon check, so it cannot
    /// show that resolving does any work; a junction can, because its name
    /// carries no punctuation to notice and no deny-list entry to match.
    ///
    /// `DeadVendor` looks like exactly the sort of leftover this feature exists
    /// to offer, and points at the directory the deny list is protecting.
    /// Creating one needs no elevation, which is what makes it worth testing:
    /// anybody who can write a data root can plant it.
    #[test]
    fn the_fence_judges_where_a_link_points_and_not_what_it_is_called() {
        let profile = Profile::new("junction");
        let real = profile.make("Microsoft");
        let link = profile.local().join("DeadVendor");

        let made = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&real)
            .output();
        if !made.map(|out| out.status.success()).unwrap_or(false) {
            // Junctions are unavailable here; the property is untested rather
            // than disproved, so say nothing either way.
            return;
        }

        // The premise, which is the whole trap: by name and by `is_dir` this is
        // an ordinary directory called DeadVendor.
        assert!(link.is_dir());
        let name = link.to_string_lossy().into_owned();
        assert!(
            !name[2..].contains(':'),
            "the point of this one is a name with no stream syntax to spot"
        );

        assert!(
            check_quarantinable(&name, &profile.user()).is_err(),
            "a junction pointing at a protected directory was accepted under its own name"
        );
    }

    /// And the protected directory is still there afterwards.
    ///
    /// The test above is about the fence; this is about the consequence, which
    /// is what review actually demonstrated.
    #[test]
    fn a_protected_directory_survives_being_named_through_its_index_stream() {
        let profile = Profile::new("stream-consequence");
        let real = profile.make("Microsoft");
        fs::write(std::path::Path::new(&real).join("keep.txt"), b"load bearing").unwrap();

        let sneaky = profile
            .local()
            .join("Microsoft::$INDEX_ALLOCATION")
            .to_string_lossy()
            .into_owned();

        assert!(check_quarantinable(&sneaky, &profile.user()).is_err());
        assert!(
            std::path::Path::new(&real).join("keep.txt").exists(),
            "the protected directory was reached"
        );
    }

    #[test]
    fn the_fence_refuses_everything_outside_the_data_roots() {
        for path in [
            r"C:\Windows",
            r"C:\Windows\System32",
            r"C:\",
            r"C:\Program Files\Something",
            r"C:\Users\someone\Documents",
        ] {
            assert!(
                check_quarantinable(path, &kam_core::UserContext::current()).is_err(),
                "{path} should have been refused"
            );
        }
    }

    #[test]
    fn the_fence_refuses_a_directory_that_is_not_there() {
        // Nothing to reclaim, and nothing whose real identity can be checked.
        let profile = Profile::new("absent");
        let absent = profile
            .local()
            .join("NeverExisted")
            .to_string_lossy()
            .into_owned();

        assert!(check_quarantinable(&absent, &profile.user()).is_err());
    }

    #[test]
    fn summarising_separates_confident_bytes_from_the_total() {
        let orphan = |bytes, confidence| Orphan {
            path: String::new(),
            name: String::new(),
            bytes,
            kind: LocationKind::LocalData,
            confidence,
            days_since_modified: None,
            reasons: Vec::new(),
        };
        let summary = summarise(&[
            orphan(1000, Confidence::High),
            orphan(500, Confidence::Medium),
            orphan(200, Confidence::Low),
        ]);
        assert_eq!(summary.found, 3);
        assert_eq!(summary.total_bytes, 1700);
        assert_eq!(summary.confident_bytes, 1000);
    }
}
