//! What an uninstaller leaves behind.
//!
//! An application's own uninstaller clears its install directory and, as a
//! rule, nothing else. The data under `ProgramData` and `AppData` stays, the
//! Start Menu folder stays, the desktop icon stays. Logitech G HUB on the
//! development machine is the perfect specimen: its install directory is gone,
//! its registry entry remains, its shortcuts point at a binary that no longer
//! exists, and 2.7 GB sits in `ProgramData` doing nothing.
//!
//! Control Panel cannot show any of this, because it never knew the footprint
//! in the first place. This product measures it *before* the uninstaller runs,
//! so afterwards it can say exactly what survived.
//!
//! # Nothing here removes anything
//!
//! This reports. Removal goes through quarantine like every other destructive
//! path in the product: one item at a time, on an explicit choice, reversible
//! for thirty days. Keeping them apart is the point — a mistake in *measuring*
//! must never become a mistake in *deleting*.

use serde::{Deserialize, Serialize};

use kam_core::UserContext;

use crate::apps::LocationKind;

use crate::shortcuts::{self, Shortcut};

/// Largest number of files to add up before answering with a floor.
///
/// A leftover directory is usually a cache holding a great many small files.
/// Counting every one is not worth making somebody wait for, and "at least
/// this much" is enough to decide by.
const MAX_FILES_COUNTED: usize = 200_000;

/// One directory an application left behind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remnant {
    pub path: String,
    pub bytes: u64,
    pub kind: LocationKind,
    /// True when the count hit the ceiling, so `bytes` is a floor rather than
    /// a total. Said plainly rather than quietly rounded.
    pub partial: bool,
    pub files: usize,
    /// Whether quarantine would take this, decided by the same fence the agent
    /// applies when it is asked to. False unless that fence said yes, so an
    /// answer from an agent that never asked reads as "no" rather than "yes".
    #[serde(default)]
    pub quarantinable: bool,
    /// The fence's own reason when it would not.
    #[serde(default)]
    pub quarantine_refusal: Option<String>,
}

/// A shortcut an application left behind, with the same answer attached.
///
/// Leftover shortcuts sit in the Start Menu, on the desktop or on the taskbar,
/// and the quarantine fence only takes a directory directly inside a data root,
/// so as things stand it refuses every one of them. The list says so per item
/// rather than offering a box that can only produce a refusal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeftoverShortcut {
    #[serde(flatten)]
    pub shortcut: Shortcut,
    #[serde(default)]
    pub quarantinable: bool,
    #[serde(default)]
    pub quarantine_refusal: Option<String>,
}

/// Everything still on disk for an application that has been removed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Remnants {
    pub name: String,

    /// Directories that still exist. Ones the uninstaller did clear are simply
    /// absent, so this is a list of what is left rather than what there was.
    pub locations: Vec<Remnant>,

    /// Shortcuts pointing into those directories, or at a target now gone.
    pub shortcuts: Vec<LeftoverShortcut>,

    pub total_bytes: u64,

    /// Paths asked about that this would not look at: outside the folders it
    /// will look in, or present but impossible to resolve. Reported rather
    /// than silently dropped.
    pub refused: Vec<String>,
}

impl Remnants {
    pub fn is_empty(&self) -> bool {
        self.locations.is_empty() && self.shortcuts.is_empty()
    }
}

/// Roots this is willing to measure inside, as their own spelling.
///
/// The caller supplies the paths, and the caller is the interface. A path is
/// only looked at if it sits under a folder applications actually install
/// into, so a malformed or mischievous request cannot turn the privileged
/// agent into a general-purpose disk reader.
///
/// # Whose AppData
///
/// The caller's, from `user`, and never this process's environment. These
/// were read from `%LOCALAPPDATA%` and `%APPDATA%`, which inside the agent are
/// LocalSystem's own, under `C:\Windows\system32\config\systemprofile`. Every
/// leftover in the person's AppData was then outside the fence and landed in
/// `refused`, and the window told them the application had left nothing
/// behind. `apps::data_roots` made the same move for the same reason.
/// Program Files and ProgramData are machine-wide, so the environment is
/// right for those.
fn allowed_roots(user: &UserContext) -> Vec<String> {
    let mut roots: Vec<String> = ["ProgramFiles", "ProgramFiles(x86)", "ProgramData"]
        .iter()
        .filter_map(|name| std::env::var(name).ok())
        .collect();
    roots.push(user.local_app_data());
    roots.push(user.roaming_app_data());
    roots
        .iter()
        .map(|root| canonical(root))
        .filter(|root| !root.is_empty())
        .collect()
}

/// The same roots, resolved, for judging a path that is really there.
///
/// Both sides or neither: see `paths::resolved_root`. A root that is not on
/// this machine cannot contain anything, so it is left out.
fn resolved_roots(roots: &[String]) -> Vec<String> {
    roots
        .iter()
        .filter_map(|root| crate::paths::resolved_root(root))
        .map(|root| canonical(&root))
        .collect()
}

fn canonical(path: &str) -> String {
    crate::paths::plain(path).trim_end_matches('\\').to_owned()
}

/// Whether `path` is strictly inside `root`, compared a component at a time.
///
/// Both are expected in [`canonical`] form. Comparing components rather than
/// text is what stops `C:\Program Files Evil` passing as inside
/// `C:\Program Files`, and an empty component (a doubled separator) is
/// refused rather than skipped.
fn strictly_inside(path: &str, root: &str) -> bool {
    let mut path_parts = path.split('\\');
    for root_part in root.split('\\') {
        if path_parts.next() != Some(root_part) {
            return false;
        }
    }
    let rest: Vec<&str> = path_parts.collect();
    // Must be *inside* a root, never the root itself: offering to quarantine
    // the whole of ProgramData is not a feature.
    !rest.is_empty() && rest.iter().all(|part| !part.is_empty())
}

/// What the fence makes of one path a caller asked about.
#[derive(Debug, PartialEq, Eq)]
enum Judged {
    /// Inside a root and really there.
    Inside,
    /// Inside a root by name, and not there: the uninstaller cleared it.
    Absent,
    /// Outside every root, or there but impossible to locate.
    Refused,
}

/// Resolve first, then judge, as every other fence in this crate does.
///
/// A path that exists is judged by what it really is, against roots that are
/// resolved the same way, so `..`, a junction part-way along, an 8.3 short
/// name and the extended-length prefix all land where they really point. Only
/// a path that is not there is judged by its text, because there is nothing
/// to resolve; it is reported absent, never measured.
fn judge(path: &str, roots: &[String], resolved: &[String]) -> Judged {
    // Legitimate paths come from the measurement, which never produces a
    // relative step. Refusing them is stricter than working out where they
    // would land, and costs nothing.
    if crate::paths::has_relative_step(path) {
        return Judged::Refused;
    }

    match crate::paths::existing_plain(path) {
        Some(real) => {
            let real = canonical(&real);
            if resolved.iter().any(|root| strictly_inside(&real, root)) {
                Judged::Inside
            } else {
                Judged::Refused
            }
        }
        None => {
            let text = canonical(path);
            if !roots.iter().any(|root| strictly_inside(&text, root)) {
                return Judged::Refused;
            }
            // Not resolvable. Gone is the good outcome; there but unreadable
            // is not, and must not be reported as cleared.
            match std::fs::symlink_metadata(path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Judged::Absent,
                _ => Judged::Refused,
            }
        }
    }
}

/// Ask the quarantine fence about one path, without moving anything.
fn quarantine_answer(path: &str, user: &UserContext) -> (bool, Option<String>) {
    match crate::orphans::check_quarantinable(path, user) {
        Ok(()) => (true, None),
        Err(refusal) => (false, Some(refusal)),
    }
}

/// Add up a directory, stopping at a sane ceiling.
fn measure(path: &std::path::Path) -> (u64, usize, bool) {
    let mut bytes = 0_u64;
    let mut files = 0_usize;
    let mut stack = vec![path.to_path_buf()];

    while let Some(folder) = stack.pop() {
        if files >= MAX_FILES_COUNTED {
            return (bytes, files, true);
        }
        let Ok(listing) = std::fs::read_dir(&folder) else {
            continue;
        };
        for item in listing.flatten() {
            match item.file_type() {
                // Following a junction could walk the whole disk and count
                // things that are not this application's at all.
                Ok(kind) if kind.is_symlink() => continue,
                Ok(kind) if kind.is_dir() => stack.push(item.path()),
                Ok(_) => {
                    if let Ok(data) = item.metadata() {
                        bytes += data.len();
                        files += 1;
                    }
                }
                Err(_) => {}
            }
        }
    }
    (bytes, files, false)
}

/// What is still on disk for `name`, given the locations measured for it
/// before its uninstaller ran.
pub fn of(name: &str, paths: &[String], kinds: &[LocationKind], user: &UserContext) -> Remnants {
    let roots = allowed_roots(user);
    let resolved = resolved_roots(&roots);
    let mut remnants = Remnants {
        name: name.to_owned(),
        ..Default::default()
    };

    for (index, path) in paths.iter().enumerate() {
        match judge(path, &roots, &resolved) {
            Judged::Refused => {
                remnants.refused.push(path.clone());
                continue;
            }
            // Cleared by the uninstaller, which is the good outcome.
            Judged::Absent => continue,
            Judged::Inside => {}
        }

        let on_disk = std::path::Path::new(path);
        if !on_disk.is_dir() {
            continue;
        }

        let (bytes, files, partial) = measure(on_disk);
        let (quarantinable, quarantine_refusal) = quarantine_answer(path, user);
        remnants.total_bytes += bytes;
        remnants.locations.push(Remnant {
            path: path.clone(),
            bytes,
            files,
            partial,
            kind: kinds.get(index).copied().unwrap_or(LocationKind::Install),
            quarantinable,
            quarantine_refusal,
        });
    }

    // Shortcuts pointing into any of those directories, plus any pointing at a
    // target that is simply gone — the install-directory case, where the
    // folder went but the icon did not.
    let mut found = shortcuts::pointing_into(paths, user);
    let known: std::collections::HashSet<String> = found
        .iter()
        .map(|shortcut| canonical(&shortcut.path))
        .collect();

    for shortcut in shortcuts::all(user) {
        if !shortcut.broken || known.contains(&canonical(&shortcut.path)) {
            continue;
        }
        // Only ones whose dead target sat inside a directory this application
        // owned. Matching on the shortcut's *name* would sweep up anything
        // with a similar title.
        let Some(target) = shortcut.target.as_deref() else {
            continue;
        };
        let target = canonical(target);
        if paths.iter().any(|path| {
            let root = canonical(path);
            target.starts_with(&format!("{root}\\"))
        }) {
            found.push(shortcut);
        }
    }

    found.sort_by_key(|shortcut| shortcut.path.to_lowercase());
    found.dedup_by(|a, b| canonical(&a.path) == canonical(&b.path));
    remnants.shortcuts = found
        .into_iter()
        .map(|shortcut| {
            let (quarantinable, quarantine_refusal) = quarantine_answer(&shortcut.path, user);
            LeftoverShortcut {
                shortcut,
                quarantinable,
                quarantine_refusal,
            }
        })
        .collect();
    remnants
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {

    use super::*;

    #[test]
    #[ignore = "machine specific"]
    fn the_logitech_leftover_is_found() {
        let program_data = std::env::var("ProgramData").unwrap();
        let local = std::env::var("LOCALAPPDATA").unwrap();
        let paths = vec![
            r"C:\Program Files\LGHUB".to_owned(),
            format!("{program_data}\\LGHUB"),
            format!("{local}\\LGHUB"),
        ];
        let kinds = vec![
            LocationKind::Install,
            LocationKind::ProgramData,
            LocationKind::LocalData,
        ];
        let outcome = of(
            "Logitech G HUB",
            &paths,
            &kinds,
            &kam_core::UserContext::current(),
        );
        println!(
            "total {} MB across {} locations",
            outcome.total_bytes / 1_048_576,
            outcome.locations.len()
        );
        for item in &outcome.locations {
            println!(
                "  {} -> {} MB, {} files",
                item.path,
                item.bytes / 1_048_576,
                item.files
            );
        }
        for leftover in &outcome.shortcuts {
            let s = &leftover.shortcut;
            println!(
                "  shortcut: {} [{}] broken={} quarantinable={}",
                s.name,
                s.place.label(),
                s.broken,
                leftover.quarantinable
            );
        }
        println!("refused: {:?}", outcome.refused);
    }

    #[test]
    fn a_path_outside_the_allowed_roots_is_refused() {
        // The fence that stops the privileged agent being asked to measure
        // anything at all on the disk.
        let outcome = of(
            "thing",
            &[r"C:\Windows\System32".to_owned()],
            &[],
            &kam_core::UserContext::current(),
        );
        assert!(outcome.locations.is_empty());
        assert_eq!(outcome.refused.len(), 1);
    }

    #[test]
    fn a_root_itself_is_refused() {
        // Offering to quarantine the whole of ProgramData is not a feature.
        let program_data = std::env::var("ProgramData").unwrap();
        let outcome = of(
            "thing",
            std::slice::from_ref(&program_data),
            &[],
            &kam_core::UserContext::current(),
        );
        assert!(
            outcome.locations.is_empty(),
            "the root itself must never be offered"
        );
        assert_eq!(outcome.refused, vec![program_data]);
    }

    #[test]
    fn a_directory_the_uninstaller_cleared_is_simply_absent() {
        let gone = format!(
            "{}\\kam-does-not-exist-{}",
            std::env::var("ProgramData").unwrap(),
            std::process::id()
        );
        let outcome = of("thing", &[gone], &[], &kam_core::UserContext::current());
        assert!(outcome.locations.is_empty());
        assert!(
            outcome.refused.is_empty(),
            "a missing path is not a refusal"
        );
    }

    /// A throwaway profile belonging to somebody who is not running the tests.
    ///
    /// It sits directly in the tester's profile rather than in the temp folder,
    /// because the temp folder is inside the tester's own Local AppData: a
    /// fixture there is inside the service-environment root the old fence
    /// used, so it would pass whichever root the fence consulted and could not
    /// tell the two apart.
    struct Profile {
        root: std::path::PathBuf,
    }

    impl Profile {
        fn new(tag: &str) -> Self {
            let home = std::env::var("USERPROFILE").expect("a user profile");
            let root = std::path::PathBuf::from(home)
                .join(format!("kam-remnants-test-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("AppData").join("Local")).unwrap();
            std::fs::create_dir_all(root.join("AppData").join("Roaming")).unwrap();
            Self { root }
        }

        fn user(&self) -> UserContext {
            UserContext::new(None, &self.root.to_string_lossy())
        }

        fn local(&self) -> std::path::PathBuf {
            self.root.join("AppData").join("Local")
        }

        fn roaming(&self) -> std::path::PathBuf {
            self.root.join("AppData").join("Roaming")
        }
    }

    impl Drop for Profile {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn text(path: &std::path::Path) -> String {
        path.to_string_lossy().into_owned()
    }

    /// The bug this fix is for: the caller's AppData is where leftovers are.
    ///
    /// The fence used to take its AppData roots from the process environment,
    /// which in the agent is LocalSystem's profile. Every one of these was
    /// refused, and the window said the application had left nothing behind.
    #[test]
    fn a_leftover_in_the_callers_appdata_is_measured_whoever_runs_the_check() {
        let profile = Profile::new("callers");
        let local = profile.local().join("DeadVendor");
        let roaming = profile.roaming().join("DeadVendor").join("Settings");
        std::fs::create_dir_all(local.join("nested")).unwrap();
        std::fs::create_dir_all(&roaming).unwrap();
        std::fs::write(local.join("a.bin"), vec![0_u8; 2048]).unwrap();
        std::fs::write(local.join("nested").join("b.bin"), vec![0_u8; 1024]).unwrap();
        std::fs::write(roaming.join("c.bin"), vec![0_u8; 512]).unwrap();

        let outcome = of(
            "thing",
            &[text(&local), text(&roaming)],
            &[LocationKind::LocalData, LocationKind::RoamingData],
            &profile.user(),
        );
        assert!(
            outcome.refused.is_empty(),
            "the caller's own AppData was refused: {:?}",
            outcome.refused
        );
        assert_eq!(outcome.locations.len(), 2);
        assert_eq!(outcome.locations[0].files, 2, "both files counted");
        assert_eq!(outcome.locations[0].bytes, 3072);
        assert_eq!(outcome.total_bytes, 3584);
        assert!(!outcome.locations[0].partial);

        // And each says whether quarantine would take it, from the fence that
        // decides: directly inside a data root yes, nested below one no.
        assert!(outcome.locations[0].quarantinable);
        assert!(outcome.locations[0].quarantine_refusal.is_none());
        assert!(!outcome.locations[1].quarantinable);
        let why = outcome.locations[1].quarantine_refusal.as_deref().unwrap();
        assert!(why.contains("nested"), "unhelpful reason: {why}");
    }

    /// The other half of the same bug: the service's environment is not a root.
    #[test]
    fn the_services_own_appdata_is_not_the_callers() {
        let profile = Profile::new("not-mine");
        let elsewhere = format!(
            "{}\\kam-not-the-callers-{}",
            std::env::var("LOCALAPPDATA").unwrap(),
            std::process::id()
        );
        let outcome = of(
            "thing",
            std::slice::from_ref(&elsewhere),
            &[],
            &profile.user(),
        );
        assert_eq!(
            outcome.refused,
            vec![elsewhere],
            "a folder outside the caller's AppData was treated as theirs"
        );
    }

    /// The fence judges where a name points, not what it is called.
    ///
    /// `DeadVendor` sits in the caller's Local AppData by name and points
    /// outside every root. Measuring it would have the agent read whatever it
    /// points at.
    #[test]
    fn a_junction_out_of_a_root_is_judged_by_where_it_points() {
        let profile = Profile::new("junction");
        let outside = profile.root.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("private.bin"), vec![0_u8; 4096]).unwrap();
        let link = profile.local().join("DeadVendor");

        let made = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .output();
        if !made.map(|out| out.status.success()).unwrap_or(false) {
            // Junctions are unavailable here; untested rather than disproved.
            return;
        }
        assert!(link.is_dir(), "the premise: by name, an ordinary directory");

        let outcome = of(
            "thing",
            &[text(&link)],
            &[LocationKind::LocalData],
            &profile.user(),
        );
        assert!(
            outcome.locations.is_empty(),
            "a junction out of the root was measured as a leftover"
        );
        assert_eq!(outcome.refused, vec![text(&link)]);
    }

    #[test]
    fn a_relative_step_out_of_a_root_is_refused() {
        let profile = Profile::new("relative");
        std::fs::create_dir_all(profile.root.join("outside")).unwrap();
        let climbing = format!("{}\\..\\..\\outside", profile.local().display());

        let outcome = of(
            "thing",
            std::slice::from_ref(&climbing),
            &[],
            &profile.user(),
        );
        assert!(outcome.locations.is_empty());
        assert_eq!(outcome.refused, vec![climbing]);
    }

    /// Text that merely begins with a root's name is not inside it.
    #[test]
    fn a_root_is_compared_a_component_at_a_time() {
        let root = r"c:\program files";
        assert!(strictly_inside(r"c:\program files\vendor", root));
        assert!(strictly_inside(r"c:\program files\vendor\app", root));
        assert!(!strictly_inside(r"c:\program files evil\vendor", root));
        assert!(!strictly_inside(r"c:\program filesx", root));
        assert!(!strictly_inside(root, root), "the root itself");
        assert!(!strictly_inside(r"c:\program files\\vendor", root));
    }

    /// An 8.3 short name lands on the folder it names.
    ///
    /// Whether short names exist is a per-volume setting, so this only runs
    /// where `PROGRA~1` really is Program Files.
    #[test]
    fn a_short_name_is_judged_by_the_folder_it_names() {
        let Ok(program_files) = std::env::var("ProgramFiles") else {
            return;
        };
        let short = r"C:\PROGRA~1\Common Files";
        let long = format!("{program_files}\\Common Files");
        let (Ok(a), Ok(b)) = (std::fs::canonicalize(short), std::fs::canonicalize(&long)) else {
            return;
        };
        if a != b {
            return;
        }
        let roots = allowed_roots(&UserContext::current());
        let resolved = resolved_roots(&roots);
        assert_eq!(judge(short, &roots, &resolved), Judged::Inside);
    }

    #[test]
    fn nothing_is_offered_for_an_application_with_no_paths() {
        let outcome = of("thing", &[], &[], &kam_core::UserContext::current());
        assert!(outcome.is_empty());
        assert_eq!(outcome.total_bytes, 0);
    }
}
