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

}



/// Everything still on disk for an application that has been removed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Remnants {

    pub name: String,

    /// Directories that still exist. Ones the uninstaller did clear are simply
    /// absent, so this is a list of what is left rather than what there was.
    pub locations: Vec<Remnant>,

    /// Shortcuts pointing into those directories, or at a target now gone.
    pub shortcuts: Vec<Shortcut>,

    pub total_bytes: u64,

    /// Paths asked about that sit outside the folders this will look in.
    /// Reported rather than silently dropped.
    pub refused: Vec<String>,

}



impl Remnants {

    pub fn is_empty(&self) -> bool {

        self.locations.is_empty() && self.shortcuts.is_empty()

    }

}



/// Roots this is willing to measure inside.
///
/// The caller supplies the paths, and the caller is the interface. A path is
/// only looked at if it sits under a folder applications actually install
/// into, so a malformed or mischievous request cannot turn the privileged
/// agent into a general-purpose disk reader.
fn allowed_roots() -> Vec<String> {

    [

        "ProgramFiles",

        "ProgramFiles(x86)",

        "ProgramData",

        "LOCALAPPDATA",

        "APPDATA",

    ]

    .iter()

    .filter_map(|name| std::env::var(name).ok())

    .map(|value| canonical(&value))

    .filter(|value| !value.is_empty())

    .collect()

}



fn canonical(path: &str) -> String {

    path.to_lowercase()

        .replace('/', "\\")

        .trim_end_matches('\\')

        .to_owned()

}



fn is_allowed(path: &str, roots: &[String]) -> bool {

    let path = canonical(path);

    roots.iter().any(|root| {

        // Must be *inside* a root, never the root itself: offering to

        // quarantine the whole of ProgramData is not a feature.

        path.starts_with(&format!("{root}\\")) && path.len() > root.len() + 1

    })

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
pub fn of(name: &str, paths: &[String], kinds: &[LocationKind]) -> Remnants {

    let roots = allowed_roots();

    let mut remnants = Remnants {

        name: name.to_owned(),

        ..Default::default()

    };



    for (index, path) in paths.iter().enumerate() {

        if !is_allowed(path, &roots) {

            remnants.refused.push(path.clone());

            continue;

        }



        let on_disk = std::path::Path::new(path);

        if !on_disk.is_dir() {

            // Cleared by the uninstaller, which is the good outcome.

            continue;

        }



        let (bytes, files, partial) = measure(on_disk);

        remnants.total_bytes += bytes;

        remnants.locations.push(Remnant {

            path: path.clone(),

            bytes,

            files,

            partial,

            kind: kinds.get(index).copied().unwrap_or(LocationKind::Install),

        });

    }



    // Shortcuts pointing into any of those directories, plus any pointing at a

    // target that is simply gone — the install-directory case, where the

    // folder went but the icon did not.

    let mut found = shortcuts::pointing_into(paths);

    let known: std::collections::HashSet<String> = found

        .iter()

        .map(|shortcut| canonical(&shortcut.path))

        .collect();



    for shortcut in shortcuts::all() {

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

    remnants.shortcuts = found;

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

        let outcome = of("Logitech G HUB", &paths, &kinds);

        println!(

            "total {} MB across {} locations",

            outcome.total_bytes / 1_048_576,

            outcome.locations.len()

        );

        for item in &outcome.locations {

            println!("  {} -> {} MB, {} files", item.path, item.bytes / 1_048_576, item.files);

        }

        for s in &outcome.shortcuts {

            println!("  shortcut: {} [{}] broken={}", s.name, s.place.label(), s.broken);

        }

        println!("refused: {:?}", outcome.refused);

    }



    #[test]
    fn a_path_outside_the_allowed_roots_is_refused() {

        // The fence that stops the privileged agent being asked to measure

        // anything at all on the disk.

        let outcome = of("thing", &[r"C:\Windows\System32".to_owned()], &[]);

        assert!(outcome.locations.is_empty());

        assert_eq!(outcome.refused.len(), 1);

    }



    #[test]
    fn a_root_itself_is_refused() {

        // Offering to quarantine the whole of ProgramData is not a feature.

        let program_data = std::env::var("ProgramData").unwrap();

        let outcome = of("thing", std::slice::from_ref(&program_data), &[]);

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

        let outcome = of("thing", &[gone], &[]);

        assert!(outcome.locations.is_empty());

        assert!(outcome.refused.is_empty(), "a missing path is not a refusal");

    }



    #[test]
    fn a_real_leftover_directory_is_measured() {

        let base = std::env::var("LOCALAPPDATA").unwrap();

        let folder =

            std::path::PathBuf::from(&base).join(format!("kam-remnant-{}", std::process::id()));

        std::fs::create_dir_all(folder.join("nested")).unwrap();

        std::fs::write(folder.join("a.bin"), vec![0_u8; 2048]).unwrap();

        std::fs::write(folder.join("nested").join("b.bin"), vec![0_u8; 1024]).unwrap();



        let outcome = of(

            "thing",

            &[folder.display().to_string()],

            &[LocationKind::LocalData],

        );

        assert_eq!(outcome.locations.len(), 1);

        assert_eq!(outcome.locations[0].files, 2, "should have counted both files");

        assert_eq!(outcome.locations[0].bytes, 3072);

        assert_eq!(outcome.total_bytes, 3072);

        assert!(!outcome.locations[0].partial);



        std::fs::remove_dir_all(&folder).unwrap();

    }



    #[test]
    fn nothing_is_offered_for_an_application_with_no_paths() {

        let outcome = of("thing", &[], &[]);

        assert!(outcome.is_empty());

        assert_eq!(outcome.total_bytes, 0);

    }

}

