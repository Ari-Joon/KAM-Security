//! Caches and scratch space, and clearing them.
//!
//! # What this is not
//!
//! It is not a registry cleaner, and it does not have a "PC health score". Both
//! of those are how this category of software makes money and neither has ever
//! made a machine faster. What is here is the small, real list: places Windows
//! and a few programs write data they can regenerate, which nothing ever
//! deletes on their behalf.
//!
//! # The list is compiled in, and that is the security design
//!
//! Clearing runs in the agent, as LocalSystem. If the shell could name a
//! directory to empty, then anything that could impersonate the shell could
//! empty any directory on the machine. So the shell names an **id** from this
//! catalogue and nothing else; the paths are resolved here, from constants and
//! the calling user's own profile. There is no request shape that carries a
//! path to delete.
//!
//! Within a location, only the *contents* go. The folder itself stays, because
//! several of these are recreated by Windows only at boot and their absence is
//! a much stranger state than their emptiness.
//!
//! # What is deliberately absent
//!
//! - **Prefetch.** Clearing it is folklore. Windows uses it to make programs
//!   start faster, and emptying it makes the next launch of everything slower
//!   in exchange for a few megabytes.
//! - **The registry.** Nothing in it is large enough to matter and everything
//!   in it is load-bearing for something.
//! - **`WinSxS` / the component store.** It looks enormous and is mostly hard
//!   links to files that are in use. Windows has its own tool for it and using
//!   anything else corrupts servicing.
//! - **Anything not currently on disk.** A cache with nothing in it is not
//!   listed at all, rather than shown as a zero somebody has to read past.

use std::path::{Path, PathBuf};

use kam_core::UserContext;
use serde::{Deserialize, Serialize};

/// Stop measuring one location after this many files. A temp directory with a
/// million entries in it should not turn a survey into a disk walk.
const MAX_FILES_COUNTED: u64 = 400_000;

/// How much thought clearing one of these deserves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Safety {
    /// Regenerates by itself and costs nothing but the space it reclaims.
    Routine,
    /// Safe, but you give something up: a slower first launch, a re-download,
    /// or a door closing behind you.
    Considered,
}

/// One place on disk belonging to a cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheLocation {
    pub path: String,
    pub bytes: u64,
    pub files: u64,
    /// True when measuring stopped at the ceiling, so the size is a floor.
    pub partial: bool,
}

/// A cache, as offered to somebody.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cache {
    /// Stable identifier. This, and never a path, is what a client sends back.
    pub id: String,
    pub name: String,
    /// What it holds.
    pub what: String,
    /// What clearing it costs. Empty when the honest answer is "nothing".
    pub cost: String,
    pub safety: Safety,
    pub locations: Vec<CacheLocation>,
    pub bytes: u64,
    pub files: u64,
}

/// The result of clearing one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cleared {
    pub id: String,
    pub bytes_freed: u64,
    pub files_removed: u64,
    /// Files something else had open. Normal, not an error: a browser's cache
    /// is held open by the browser, and Windows holds its own log files.
    pub files_in_use: u64,
    /// Anything that failed for a reason worth reading.
    pub refused: Vec<String>,
}

/// An entry in the compiled-in catalogue.
struct Entry {
    id: &'static str,
    name: &'static str,
    what: &'static str,
    cost: &'static str,
    safety: Safety,
    /// Resolved against the calling user. Returning several paths is normal:
    /// one cache often lives in more than one place.
    locate: fn(&UserContext) -> Vec<PathBuf>,
}

fn windir() -> PathBuf {
    PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned()))
}

fn program_data() -> PathBuf {
    PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_owned()))
}

fn system_drive() -> PathBuf {
    // `%SystemDrive%` is "C:" with no separator, and joining onto that produces
    // a *drive-relative* path -- `C:Windows.old`, meaning "Windows.old inside
    // whatever the current directory on C: happens to be". The guard test below
    // caught this, which is the only reason it is not still here.
    let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_owned());
    PathBuf::from(format!("{}\\", drive.trim_end_matches('\\')))
}

/// Every profile directory of a browser family, since people have several.
fn browser_profiles(base: &Path, subdirectories: &[&str]) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(listing) = std::fs::read_dir(base) else {
        return found;
    };
    for item in listing.flatten() {
        if !item.path().is_dir() {
            continue;
        }
        for sub in subdirectories {
            let candidate = item.path().join(sub);
            if candidate.is_dir() {
                found.push(candidate);
            }
        }
    }
    found
}

/// Chromium keeps its caches per profile, under names it chooses.
fn chromium_caches(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(listing) = std::fs::read_dir(root) else {
        return found;
    };
    for item in listing.flatten() {
        let name = item.file_name().to_string_lossy().to_lowercase();
        // "Default", "Profile 1", "Profile 2", and the shared system profile.
        if !(name == "default" || name.starts_with("profile ") || name == "guest profile") {
            continue;
        }
        for sub in [
            "Cache",
            "Code Cache",
            "GPUCache",
            "Service Worker\\CacheStorage",
        ] {
            let candidate = item.path().join(sub);
            if candidate.is_dir() {
                found.push(candidate);
            }
        }
    }
    found
}

/// The catalogue.
const CATALOGUE: &[Entry] = &[
    Entry {
        id: "temp-user",
        name: "Your temporary files",
        what: "Where installers unpack, programs write scratch files, and almost none of \
               them tidy up afterwards. The oldest thing in here is usually years old.",
        cost: "",
        safety: Safety::Routine,
        locate: |user| vec![PathBuf::from(user.local_app_data()).join("Temp")],
    },
    Entry {
        id: "temp-system",
        name: "The system temporary folder",
        what: "The same thing for anything running as a service, plus what Windows setup \
               leaves behind.",
        cost: "",
        safety: Safety::Routine,
        locate: |_| vec![windir().join("Temp")],
    },
    Entry {
        id: "windows-update",
        name: "Windows Update downloads",
        what: "Update packages Windows has already installed. It keeps them, and nothing \
               removes them on its own.",
        cost: "An update part-way through downloading starts again.",
        safety: Safety::Routine,
        locate: |_| {
            let root = windir().join("SoftwareDistribution");
            vec![root.join("Download"), root.join("DeliveryOptimization")]
        },
    },
    Entry {
        id: "crash-dumps",
        name: "Crash dumps",
        what: "Memory written out when a program or the machine stopped. Individually \
               enormous, and useful only to whoever was debugging it at the time.",
        cost: "",
        safety: Safety::Routine,
        locate: |user| {
            vec![
                PathBuf::from(user.local_app_data()).join("CrashDumps"),
                windir().join("Minidump"),
                windir().join("LiveKernelReports"),
            ]
        },
    },
    Entry {
        id: "error-reports",
        name: "Error reports queued for Microsoft",
        what: "Reports about crashes, waiting to be sent or already sent and kept.",
        cost: "",
        safety: Safety::Routine,
        locate: |_| {
            let wer = program_data().join(r"Microsoft\Windows\WER");
            vec![
                wer.join("ReportQueue"),
                wer.join("ReportArchive"),
                wer.join("Temp"),
            ]
        },
    },
    Entry {
        id: "thumbnails",
        name: "Thumbnail and icon cache",
        what: "Explorer's stored previews. It rebuilds them as you browse.",
        cost: "Folders of photos redraw their previews the first time you open them.",
        safety: Safety::Routine,
        locate: |user| {
            vec![PathBuf::from(user.local_app_data()).join(r"Microsoft\Windows\Explorer")]
        },
    },
    Entry {
        id: "shader-cache",
        name: "Graphics shader cache",
        what: "Compiled shaders, kept by Windows and by the graphics driver so games do \
               not recompile them every time.",
        cost: "The first few minutes of a game may stutter while it rebuilds them.",
        safety: Safety::Considered,
        locate: |user| {
            let local = PathBuf::from(user.local_app_data());
            [
                r"D3DSCache",
                r"NVIDIA\DXCache",
                r"NVIDIA\GLCache",
                r"AMD\DxCache",
                r"AMD\DxcCache",
                r"Intel\ShaderCache",
            ]
            .iter()
            .map(|sub| local.join(sub))
            .collect()
        },
    },
    Entry {
        id: "browser-cache",
        name: "Browser caches",
        what: "Pages, images and scripts your browsers keep so sites load faster. Every \
               profile of every Chromium browser and Firefox found on this account.",
        cost: "Sites reload from the network once. Nothing is signed out and no history \
               or passwords are touched.",
        safety: Safety::Routine,
        locate: |user| {
            let local = PathBuf::from(user.local_app_data());
            let roaming = PathBuf::from(user.roaming_app_data());
            let mut found = Vec::new();
            for chromium in [
                r"Google\Chrome\User Data",
                r"Microsoft\Edge\User Data",
                r"BraveSoftware\Brave-Browser\User Data",
                r"Vivaldi\User Data",
                r"Opera Software\Opera Stable",
            ] {
                found.extend(chromium_caches(&local.join(chromium)));
            }
            // Firefox splits its cache out of the profile entirely.
            found.extend(browser_profiles(
                &local.join(r"Mozilla\Firefox\Profiles"),
                &["cache2", "startupCache"],
            ));
            found.extend(browser_profiles(
                &roaming.join(r"Mozilla\Firefox\Profiles"),
                &["cache2"],
            ));
            found
        },
    },
    Entry {
        id: "package-caches",
        name: "Developer package caches",
        what: "Downloaded packages kept by npm, pip, NuGet and Cargo so they do not have \
               to be fetched again. They grow without limit and nothing prunes them.",
        cost: "The next build of anything that used them downloads again, and an offline \
               build will fail until it has.",
        safety: Safety::Considered,
        locate: |user| {
            let local = PathBuf::from(user.local_app_data());
            let profile = PathBuf::from(user.profile());
            vec![
                local.join(r"npm-cache\_cacache"),
                local.join(r"pip\Cache"),
                local.join(r"NuGet\v3-cache"),
                profile.join(r".cargo\registry\cache"),
                profile.join(r".nuget\packages"),
            ]
        },
    },
    Entry {
        id: "steam-downloads",
        name: "Steam download scratch",
        what: "Part-finished downloads and Steam's own shader cache, in every library \
               folder it knows about.",
        cost: "A paused download restarts from the beginning.",
        safety: Safety::Considered,
        locate: |user| {
            crate::steam::library_roots(user)
                .into_iter()
                .flat_map(|library| {
                    ["downloading", "temp", "shadercache"]
                        .iter()
                        .map(|sub| library.join("steamapps").join(sub))
                        .collect::<Vec<_>>()
                })
                .collect()
        },
    },
    Entry {
        id: "windows-old",
        name: "The previous Windows installation",
        what: "A complete copy of the Windows you upgraded from. Windows removes it by \
               itself after ten days, and if it is still here, it did not.",
        cost: "You can no longer roll back to the previous version of Windows.",
        safety: Safety::Considered,
        locate: |_| vec![system_drive().join("Windows.old")],
    },
];

/// Add up one directory, without following links out of it.
fn measure(path: &Path) -> (u64, u64, bool) {
    let mut bytes = 0_u64;
    let mut files = 0_u64;
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
                // A junction here would take the walk somewhere nobody asked
                // for, and count files that are not part of this cache.
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

fn build(entry: &Entry, user: &UserContext) -> Option<Cache> {
    let mut locations = Vec::new();
    for path in (entry.locate)(user) {
        if !ours_to_empty(&path) {
            continue;
        }
        let (bytes, files, partial) = measure(&path);
        if files == 0 {
            continue;
        }
        locations.push(CacheLocation {
            path: path.to_string_lossy().into_owned(),
            bytes,
            files,
            partial,
        });
    }

    if locations.is_empty() {
        return None;
    }

    Some(Cache {
        id: entry.id.to_owned(),
        name: entry.name.to_owned(),
        what: entry.what.to_owned(),
        cost: entry.cost.to_owned(),
        safety: entry.safety,
        bytes: locations.iter().map(|location| location.bytes).sum(),
        files: locations.iter().map(|location| location.files).sum(),
        locations,
    })
}

/// Measure every cache that is actually present, largest first.
pub fn survey(user: &UserContext) -> Vec<Cache> {
    let mut caches: Vec<Cache> = CATALOGUE
        .iter()
        .filter_map(|entry| build(entry, user))
        .collect();
    caches.sort_by_key(|cache| std::cmp::Reverse(cache.bytes));
    caches
}

/// Whether a path is a real directory of ours, rather than a link to one.
///
/// `Path::is_dir` follows reparse points, so it answers "yes" for a junction
/// pointing anywhere at all. Every root in the catalogue is checked with this
/// instead, because several of them sit in user-writable space: deleting
/// `%LOCALAPPDATA%\Temp` or a browser cache while it is unlocked and
/// recreating it as a junction needs no elevation, and the next clear would
/// have had a LocalSystem service delete whatever it pointed at. Permanently:
/// this is the path that removes rather than quarantines.
///
/// The guard inside `empty` never covered this. It checks the *children* of a
/// directory, so it protected against a junction planted inside a cache and
/// not against a cache that was itself one.
fn ours_to_empty(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|data| data.is_dir() && !data.file_type().is_symlink())
        .unwrap_or(false)
}

/// Empty one catalogue root, having checked it is really ours.
fn empty_root(path: &Path, result: &mut Cleared) {
    if !ours_to_empty(path) {
        // Said out loud rather than skipped silently: a cache root that has
        // become a link is not a tidy no-op, it is somebody having put it
        // there.
        result.refused.push(format!(
            "{} is a link rather than a real folder, so it was left alone",
            path.display()
        ));
        return;
    }
    empty(path, result);
}

/// Empty one directory's contents, leaving the directory itself.
fn empty(path: &Path, result: &mut Cleared) {
    let Ok(listing) = std::fs::read_dir(path) else {
        result
            .refused
            .push(format!("{} could not be opened", path.display()));
        return;
    };

    for item in listing.flatten() {
        let target = item.path();
        let Ok(kind) = item.file_type() else { continue };

        // A junction is removed as a link, never followed: deleting through one
        // would delete somebody's real files somewhere else entirely.
        if kind.is_symlink() {
            let _ = if kind.is_dir() {
                std::fs::remove_dir(&target)
            } else {
                std::fs::remove_file(&target)
            };
            continue;
        }

        if kind.is_dir() {
            // Measure before removing: afterwards there is nothing to ask.
            let (bytes, files, _) = measure(&target);
            match std::fs::remove_dir_all(&target) {
                Ok(()) => {
                    result.bytes_freed += bytes;
                    result.files_removed += files;
                }
                Err(error) => {
                    // Partly removed is the common outcome when one file inside
                    // is open, so what actually went is measured again rather
                    // than assumed either way.
                    let (left_bytes, left_files, _) = measure(&target);
                    result.bytes_freed += bytes.saturating_sub(left_bytes);
                    result.files_removed += files.saturating_sub(left_files);
                    result.files_in_use += left_files;
                    if left_files == 0 {
                        result
                            .refused
                            .push(format!("{}: {error}", target.display()));
                    }
                }
            }
            continue;
        }

        let size = item.metadata().map(|data| data.len()).unwrap_or(0);
        match std::fs::remove_file(&target) {
            Ok(()) => {
                result.bytes_freed += size;
                result.files_removed += 1;
            }
            // Almost always "in use by another process", which for a cache is
            // the expected state rather than a failure.
            Err(_) => result.files_in_use += 1,
        }
    }
}

/// Clear one cache, named by its id.
///
/// The id is looked up in the catalogue above; an unknown one is refused
/// without touching anything. No caller supplies a path.
pub fn clear(id: &str, user: &UserContext) -> std::result::Result<Cleared, String> {
    let Some(entry) = CATALOGUE.iter().find(|entry| entry.id == id) else {
        return Err(format!("{id} is not something this knows how to clear"));
    };

    let mut result = Cleared {
        id: id.to_owned(),
        bytes_freed: 0,
        files_removed: 0,
        files_in_use: 0,
        refused: Vec::new(),
    };

    for path in (entry.locate)(user) {
        // Not `is_dir`: that follows a reparse point, which is the whole hole.
        // A root that exists at all is judged; one that does not is simply not
        // there and needs no comment.
        if std::fs::symlink_metadata(&path).is_ok() {
            empty_root(&path, &mut result);
        }
    }
    Ok(result)
}

/// Every id the catalogue defines, for anything that needs to check one.
pub fn known_ids() -> Vec<&'static str> {
    CATALOGUE.iter().map(|entry| entry.id).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("kam-cache-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    /// Nothing in the catalogue can reach outside the places it names.
    ///
    /// The clear takes an id and resolves paths here, so this is the whole
    /// fence. Every location has to sit under a root this product is entitled
    /// to empty; a typo in one entry would otherwise be a LocalSystem process
    /// deleting somebody's documents.
    #[test]
    fn no_cache_resolves_outside_the_roots_it_is_allowed_to_touch() {
        let user = UserContext::current();
        let allowed: Vec<String> = [
            windir().join("Temp").to_string_lossy().into_owned(),
            windir()
                .join("SoftwareDistribution")
                .to_string_lossy()
                .into_owned(),
            windir().join("Minidump").to_string_lossy().into_owned(),
            windir()
                .join("LiveKernelReports")
                .to_string_lossy()
                .into_owned(),
            program_data()
                .join(r"Microsoft\Windows\WER")
                .to_string_lossy()
                .into_owned(),
            user.local_app_data(),
            user.roaming_app_data(),
            PathBuf::from(user.profile())
                .join(".cargo")
                .to_string_lossy()
                .into_owned(),
            PathBuf::from(user.profile())
                .join(".nuget")
                .to_string_lossy()
                .into_owned(),
            system_drive()
                .join("Windows.old")
                .to_string_lossy()
                .into_owned(),
        ]
        .iter()
        .map(|root| root.to_lowercase())
        .collect();

        // Steam libraries are wherever Steam says, so they are allowed by
        // shape rather than by prefix.
        for entry in CATALOGUE {
            for path in (entry.locate)(&user) {
                let text = path.to_string_lossy().to_lowercase();
                let steam = text.contains(r"\steamapps\");
                let known = allowed.iter().any(|root| text.starts_with(root));
                assert!(
                    known || steam,
                    "{} resolves to {text}, which is outside every root it may touch",
                    entry.id
                );
            }
        }
    }

    /// A cache entry may never name a whole profile or data root.
    ///
    /// Emptying `AppData\Local` would take every program's settings with it.
    /// The entries are all supposed to be a folder *inside* one.
    #[test]
    fn no_cache_is_a_root_itself() {
        let user = UserContext::current();
        let roots: Vec<String> = [
            user.profile().to_owned(),
            user.local_app_data(),
            user.roaming_app_data(),
            program_data().to_string_lossy().into_owned(),
            windir().to_string_lossy().into_owned(),
        ]
        .iter()
        .map(|root| root.to_lowercase())
        .collect();

        for entry in CATALOGUE {
            for path in (entry.locate)(&user) {
                let text = path.to_string_lossy().to_lowercase();
                assert!(
                    !roots.contains(&text),
                    "{} would empty {text} itself",
                    entry.id
                );
            }
        }
    }

    /// A cache root that is a junction is not ours to empty.
    ///
    /// Found by adversarial review, and it was a real hole. `clear` gated on
    /// `Path::is_dir`, which *follows* a reparse point, and `empty` then
    /// `read_dir`s the same path — which follows it too — and deletes the
    /// target's children. Those children are ordinary files, so the
    /// `is_symlink` guard inside `empty` never fired: it only ever protected
    /// against a junction *inside* a cache, never against a cache root that
    /// was itself one.
    ///
    /// Several catalogue roots sit in user-writable space -- `%LOCALAPPDATA%    /// Temp` and every browser cache. Deleting one while it is unlocked and
    /// recreating it as a junction needs no elevation at all, and the next
    /// press of "clear" would have had a LocalSystem service permanently
    /// delete whatever it pointed at. This is the delete path, so there is no
    /// quarantine to undo it from.
    #[test]
    fn a_cache_root_that_is_a_junction_is_refused_rather_than_followed() {
        let root = scratch("root-junction");
        let victim = scratch("root-junction-target");
        std::fs::write(victim.join("precious.txt"), b"do not delete me").unwrap();
        std::fs::create_dir(victim.join("nested")).unwrap();
        std::fs::write(victim.join("nested").join("also.txt"), b"nor me").unwrap();

        // The root has to *be* the junction, so the real directory goes first.
        let link = root.join("cache");
        let made = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&victim)
            .output();
        if !made.map(|out| out.status.success()).unwrap_or(false) {
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&victim);
            return;
        }

        // What the old code trusted, and why it was wrong: this is true.
        assert!(
            link.is_dir(),
            "is_dir follows the junction, which is the trap"
        );
        assert!(
            !ours_to_empty(&link),
            "a junction must not be treated as ours"
        );

        let mut result = Cleared {
            id: "test".to_owned(),
            bytes_freed: 0,
            files_removed: 0,
            files_in_use: 0,
            refused: Vec::new(),
        };
        empty_root(&link, &mut result);

        assert!(
            victim.join("precious.txt").exists(),
            "the clear followed a junction and deleted through it"
        );
        assert!(victim.join("nested").join("also.txt").exists());
        assert_eq!(result.files_removed, 0);
        assert!(
            result.refused.iter().any(|why| why.contains("link")),
            "it should say why it refused: {:?}",
            result.refused
        );

        let _ = std::fs::remove_dir_all(&root);
        std::fs::remove_dir_all(&victim).unwrap();
    }

    /// The clear never follows a link out of the folder it was given.
    ///
    /// A junction inside a cache pointing at somebody's documents would
    /// otherwise mean emptying the cache emptied the documents.
    #[test]
    fn a_link_is_removed_as_a_link_rather_than_followed() {
        let root = scratch("junction");
        let outside = scratch("junction-target");
        std::fs::write(outside.join("precious.txt"), b"do not delete me").unwrap();

        // Creating a junction needs no special rights; a symlink would.
        let made = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(root.join("link"))
            .arg(&outside)
            .output();
        let linked = made.map(|out| out.status.success()).unwrap_or(false);
        if !linked {
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&outside);
            return;
        }

        let mut result = Cleared {
            id: "test".to_owned(),
            bytes_freed: 0,
            files_removed: 0,
            files_in_use: 0,
            refused: Vec::new(),
        };
        empty(&root, &mut result);

        assert!(
            outside.join("precious.txt").exists(),
            "the clear followed a junction and deleted through it"
        );
        assert_eq!(
            result.files_removed, 0,
            "nothing on the other side was ours"
        );

        let _ = std::fs::remove_dir_all(&root);
        std::fs::remove_dir_all(&outside).unwrap();
    }

    /// Measuring does not follow one either, or the sizes would be nonsense.
    #[test]
    fn measuring_stops_at_a_link() {
        let root = scratch("measure-junction");
        let outside = scratch("measure-target");
        std::fs::write(outside.join("big.bin"), vec![0_u8; 50_000]).unwrap();

        let made = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(root.join("link"))
            .arg(&outside)
            .output();
        if !made.map(|out| out.status.success()).unwrap_or(false) {
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&outside);
            return;
        }

        let (bytes, files, _) = measure(&root);
        assert_eq!((bytes, files), (0, 0), "the walk went through the junction");

        let _ = std::fs::remove_dir_all(&root);
        std::fs::remove_dir_all(&outside).unwrap();
    }

    #[test]
    fn every_id_is_unique_because_it_is_the_only_thing_a_caller_sends() {
        let mut ids = known_ids();
        let before = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), before, "two entries share an id");
    }

    #[test]
    fn an_unknown_id_clears_nothing() {
        let user = UserContext::current();
        assert!(clear("temp-user; rm -rf", &user).is_err());
        assert!(clear(r"C:\Windows", &user).is_err());
        assert!(clear("", &user).is_err());
    }

    #[test]
    fn no_entry_resolves_to_a_root_that_would_take_everything_with_it() {
        // The failure this guards against is a `join` against an empty variable
        // producing `C:\` and the clear emptying the drive.
        let user = UserContext::current();
        for entry in CATALOGUE {
            for path in (entry.locate)(&user) {
                let text = path.to_string_lossy().to_lowercase();
                assert!(
                    path.is_absolute(),
                    "{}: {text} is not an absolute path",
                    entry.id
                );
                assert!(
                    path.components().count() > 2,
                    "{}: {text} is too near the root to empty",
                    entry.id
                );
                assert!(
                    !text.ends_with(r":\") && text != r"c:\windows" && text != r"c:\users",
                    "{}: refuses to be pointed at {text}",
                    entry.id
                );
            }
        }
    }

    #[test]
    fn a_cache_with_nothing_in_it_is_not_listed() {
        let empty_dir = scratch("empty");
        let (bytes, files, partial) = measure(&empty_dir);
        assert_eq!((bytes, files, partial), (0, 0, false));
        std::fs::remove_dir_all(&empty_dir).unwrap();
    }

    #[test]
    fn clearing_removes_the_contents_and_keeps_the_folder() {
        let root = scratch("clear");
        std::fs::write(root.join("a.tmp"), vec![1_u8; 1000]).unwrap();
        std::fs::create_dir(root.join("nested")).unwrap();
        std::fs::write(root.join("nested").join("b.tmp"), vec![2_u8; 2000]).unwrap();

        let (bytes, files, _) = measure(&root);
        assert_eq!((bytes, files), (3000, 2));

        let mut result = Cleared {
            id: "test".to_owned(),
            bytes_freed: 0,
            files_removed: 0,
            files_in_use: 0,
            refused: Vec::new(),
        };
        empty(&root, &mut result);

        assert_eq!(result.bytes_freed, 3000);
        assert_eq!(result.files_removed, 2);
        assert!(result.refused.is_empty(), "{:?}", result.refused);
        assert!(root.is_dir(), "the folder itself must survive");
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_file_something_else_has_open_is_counted_not_reported_as_an_error() {
        let root = scratch("locked");
        let held = root.join("held.tmp");
        std::fs::write(&held, vec![3_u8; 500]).unwrap();

        // Windows refuses to delete a file opened without FILE_SHARE_DELETE,
        // which is what every program holding a cache open does. Rust's own
        // `File::open` shares deletion, so it has to be asked for explicitly.
        use std::os::windows::fs::OpenOptionsExt;
        let handle = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&held)
            .unwrap();

        let mut result = Cleared {
            id: "test".to_owned(),
            bytes_freed: 0,
            files_removed: 0,
            files_in_use: 0,
            refused: Vec::new(),
        };
        empty(&root, &mut result);

        assert_eq!(result.files_in_use, 1, "an open file should be counted");
        assert_eq!(result.files_removed, 0);
        assert!(
            result.refused.is_empty(),
            "an open file is expected, not an error: {:?}",
            result.refused
        );

        drop(handle);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_survey_only_lists_what_is_really_there() {
        let user = UserContext::current();
        let caches = survey(&user);
        for cache in &caches {
            assert!(!cache.locations.is_empty(), "{} has no locations", cache.id);
            assert!(cache.files > 0, "{} was listed while empty", cache.id);
            assert_eq!(
                cache.bytes,
                cache.locations.iter().map(|l| l.bytes).sum::<u64>()
            );
        }
        // Largest first.
        for pair in caches.windows(2) {
            assert!(pair[0].bytes >= pair[1].bytes);
        }
    }

    #[test]
    #[ignore = "prints what is really on this machine"]
    fn show_what_is_here() {
        let caches = survey(&UserContext::current());
        let total: u64 = caches.iter().map(|cache| cache.bytes).sum();
        println!(
            "\n{} caches, {:.2} GB total",
            caches.len(),
            total as f64 / 1e9
        );
        for cache in &caches {
            println!(
                "  {:>8.2} GB  {:<34} {:?}  ({} files)",
                cache.bytes as f64 / 1e9,
                cache.name,
                cache.safety,
                cache.files
            );
            for location in &cache.locations {
                println!(
                    "        {:>8.2} GB  {}{}",
                    location.bytes as f64 / 1e9,
                    location.path,
                    if location.partial {
                        "  (at the ceiling)"
                    } else {
                        ""
                    }
                );
            }
        }
    }
}
