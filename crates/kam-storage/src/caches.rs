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
//!
//! And these, which the November 2026 review suggested and which are left out
//! on purpose, each for a reason that would survive being asked again:
//!
//! - **Visual Studio's package folder**, `Packages` under
//!   `ProgramData\Microsoft\VisualStudio`. The installer's packages are a
//!   cache. The same folder also holds `_Instances`, the records Visual Studio
//!   and the Build Tools are found by, and emptying it would leave them
//!   installed and impossible to find.
//! - **A folder at the top of a drive named only for a vendor or by an
//!   abbreviation**: `C:\AMD`, `C:\ESD`. Installers do unpack there, and
//!   anybody may have a folder of that name for their own reasons. A name
//!   that loose is not enough to empty a folder on.
//! - **Maven's repository** (`.m2\repository`). It also holds whatever
//!   `mvn install` built on this machine, which nothing downloads again.
//! - **Playwright's browsers.** Nothing fetches them again by itself: the next
//!   test run fails until somebody installs them.
//! - **A game launcher's web cache.** Clearing one can sign the person out,
//!   and nothing here touches a session. Their logs are listed.
//! - **Spotify's cache.** Where it keeps songs saved for listening offline was
//!   not established, and those are not a cache.
//! - **A single file**, such as a memory dump. This empties folders.

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
    /// Not a cache, and never cleared from here. Measured and shown so that
    /// the space is accounted for, with what it is for and which of Windows'
    /// or the program's own settings controls it. See [`EXPLAINED`].
    Explained,
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
    /// For something explained and not cleared: what decides how large it is,
    /// and where that is changed. Empty for a cache.
    #[serde(default)]
    pub managed_by: String,
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

/// Space that is large, looks as though it could go, and is not a cache.
///
/// A list of what can be cleared says nothing about the rest, and the rest is
/// where a person goes looking next: a 25 GB file at the top of the drive, 20
/// GB inside a browser's folder that the cache entry did not touch. Leaving
/// those unexplained invites deleting them by hand. So each is measured and
/// shown with what it is for and what controls its size, and that is all.
///
/// These are kept in a list of their own so that the list of what `clear`
/// will empty is the one above and nothing else. Nothing here is ever looked
/// up to be cleared, and asking is refused by name.
struct Explanation {
    id: &'static str,
    name: &'static str,
    /// What the space is for, and what goes wrong without it.
    what: &'static str,
    /// What decides how large it is, and where the person changes that. A
    /// fact about Windows or the program, never advice.
    managed_by: &'static str,
    /// Folders, or single files: several of these are one file.
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

fn program_files_x86() -> PathBuf {
    PathBuf::from(
        std::env::var("ProgramFiles(x86)").unwrap_or_else(|_| r"C:\Program Files (x86)".to_owned()),
    )
}

fn program_files() -> PathBuf {
    PathBuf::from(std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".to_owned()))
}

/// `AppData\LocalLow`, where programs running with reduced rights keep what
/// others keep in Local AppData. Some graphics drivers write their caches here.
fn local_low(user: &UserContext) -> PathBuf {
    PathBuf::from(user.profile()).join(r"AppData\LocalLow")
}

/// Where each Chromium browser keeps its profiles, below Local AppData.
const CHROMIUM_BROWSERS: &[&str] = &[
    r"Google\Chrome\User Data",
    r"Microsoft\Edge\User Data",
    r"BraveSoftware\Brave-Browser\User Data",
    r"Vivaldi\User Data",
    r"Opera Software\Opera Stable",
    r"Opera Software\Opera GX Stable",
];

/// What websites themselves stored in a Chromium browser, per profile.
///
/// Beside the caches and under other names, and not a cache: a site's own
/// files and databases, which only that site can make again, if it can.
fn chromium_site_storage(root: &Path) -> Vec<PathBuf> {
    browser_profiles(root, &["File System", "IndexedDB"])
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

/// Chromium keeps its caches per profile, under names it chooses, and a few
/// more beside the profiles that every profile shares.
///
/// Every name here is a cache by Chromium's own account: fetched pages,
/// compiled scripts, compiled graphics shaders, and downloaded copies of its
/// own components. A profile's history, cookies, passwords and saved site data
/// sit beside these under other names, and none of those names is here.
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
            "Service Worker\\ScriptCache",
            "DawnGraphiteCache",
            "DawnWebGPUCache",
        ] {
            let candidate = item.path().join(sub);
            if candidate.is_dir() {
                found.push(candidate);
            }
        }
    }
    for shared in [
        "GrShaderCache",
        "ShaderCache",
        "GraphiteDawnCache",
        "component_crx_cache",
    ] {
        let candidate = root.join(shared);
        if candidate.is_dir() {
            found.push(candidate);
        }
    }
    found
}

/// Several named folders inside one, for an entry that takes some of what a
/// program keeps and must leave the rest: the names are the whole of what is
/// taken, and anything beside them stays.
fn inside(folder: &Path, names: &[&str]) -> Vec<PathBuf> {
    names.iter().map(|name| folder.join(name)).collect()
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
        what: "Update packages Windows has already installed, and the copies it keeps to \
               pass on to other PCs. It keeps them, and nothing removes them on its own.",
        cost: "An update part-way through downloading starts again, and other PCs on your \
               network can no longer fetch these update files from this one.",
        safety: Safety::Routine,
        locate: |_| {
            let root = windir().join("SoftwareDistribution");
            vec![
                root.join("Download"),
                // Where older Windows kept the files it shares with other PCs,
                // and where current Windows keeps them.
                root.join("DeliveryOptimization"),
                windir().join(
                    r"ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache",
                ),
            ]
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
            let mut found = inside(
                &local,
                &[
                    r"D3DSCache",
                    r"NVIDIA\DXCache",
                    r"NVIDIA\GLCache",
                    r"NVIDIA\OptixCache",
                    r"AMD\DxCache",
                    r"AMD\DxcCache",
                    r"AMD\VkCache",
                    r"AMD\OglCache",
                    r"AMD\DX9Cache",
                    r"Intel\ShaderCache",
                ],
            );
            // The drivers also write under LocalLow, for programs that run
            // with reduced rights, and which folder depends on the driver's
            // version.
            found.extend(inside(
                &local_low(user),
                &[
                    r"NVIDIA\DXCache",
                    r"NVIDIA\PerDriverVersion\DXCache",
                    r"NVIDIA\PerDriverVersion\GLCache",
                    r"Intel\ShaderCache",
                ],
            ));
            found
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
            for chromium in CHROMIUM_BROWSERS {
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
        what: "Downloaded packages kept by npm, pip, NuGet, Cargo, Yarn, Gradle, Go, uv and \
               Electron so they do not have to be fetched again. They grow without limit \
               and nothing prunes them.",
        cost: "The next build of anything that used them downloads again, and an offline \
               build will fail until it has.",
        safety: Safety::Considered,
        locate: |user| {
            let local = PathBuf::from(user.local_app_data());
            let profile = PathBuf::from(user.profile());
            let mut found = inside(
                &local,
                &[
                    r"npm-cache\_cacache",
                    r"pip\Cache",
                    r"NuGet\v3-cache",
                    r"Yarn\Cache",
                    r"Yarn\Berry\cache",
                    r"go-build",
                    r"uv\cache",
                    r"electron\Cache",
                ],
            );
            found.extend(inside(
                &profile,
                &[
                    r".cargo\registry\cache",
                    // Cargo's unpacked copies of the same packages, and of
                    // the ones it fetched with git.
                    r".cargo\registry\src",
                    r".cargo\git\checkouts",
                    r".nuget\packages",
                    r".gradle\caches",
                    r".gradle\wrapper\dists",
                    r"go\pkg\mod",
                ],
            ));
            found
        },
    },
    Entry {
        id: "steam-downloads",
        name: "Steam download scratch",
        what: "Part-finished downloads and Steam's own shader cache, in every library \
               folder it knows about.",
        cost: "A paused download restarts from the beginning, and each game rebuilds its \
               shaders the next time it starts.",
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
    // What follows was added from the November 2026 review, which set this
    // list beside what is commonly large on a gaming and development PC. Each
    // was taken only where three things hold: the program that made it makes
    // it again by itself, nothing in it is a session, a password or history,
    // and the folder is named so that it can only be that program's. The ones
    // the review suggested that fail one of those are listed, with which one,
    // at the top of this file.
    Entry {
        id: "nvidia-driver-downloads",
        name: "NVIDIA driver downloads",
        what: "Driver installers the NVIDIA App, or GeForce Experience before it, \
               downloaded and kept after installing them, and the copies they unpacked.",
        cost: "The NVIDIA App downloads the driver package again if you repair or \
               reinstall the driver from inside the app.",
        safety: Safety::Considered,
        locate: |_| {
            let nvidia = program_data().join("NVIDIA Corporation");
            vec![
                nvidia.join(r"NVIDIA App\UpdateFramework\ota-artifacts"),
                nvidia.join("Downloader"),
                system_drive().join(r"NVIDIA\DisplayDriver"),
            ]
        },
    },
    Entry {
        id: "nvidia-app-logs",
        name: "NVIDIA App logs",
        what: "What the NVIDIA App writes down as it runs. Read only by somebody working \
               out why it misbehaved.",
        cost: "",
        safety: Safety::Routine,
        locate: |_| vec![program_data().join(r"NVIDIA Corporation\NVIDIA App\Logs")],
    },
    Entry {
        id: "chrome-on-device-model",
        name: "Chrome's on-device AI model",
        what: "A language model Chrome downloads for its built-in AI features, such as \
               help with writing. It is several gigabytes.",
        cost: "Chrome downloads the model again, several gigabytes, the next time one of \
               its built-in AI features is used.",
        safety: Safety::Considered,
        locate: |user| {
            vec![PathBuf::from(user.local_app_data())
                .join(r"Google\Chrome\User Data\OptGuideOnDeviceModel")]
        },
    },
    Entry {
        id: "steam-web-cache",
        name: "Steam's web cache",
        what: "Store and library pages Steam's built-in browser keeps so they open faster.",
        cost: "Steam loads its store and library pages from the network again.",
        safety: Safety::Considered,
        locate: |user| {
            // The cache folders by name, and not the folder that holds them:
            // the built-in browser keeps its cookies there too, and nothing
            // in this list touches a session.
            inside(
                &PathBuf::from(user.local_app_data()).join(r"Steam\htmlcache"),
                &[
                    "Cache",
                    "Code Cache",
                    "GPUCache",
                    r"Default\Cache",
                    r"Default\Code Cache",
                    r"Default\GPUCache",
                ],
            )
        },
    },
    Entry {
        id: "chat-caches",
        name: "Chat program caches",
        what: "Pictures, videos and files Discord, Slack and Teams keep after showing \
               them, so that a chat opens without fetching them again.",
        cost: "Pictures, videos and files in chats load from the network again. You stay \
               signed in.",
        safety: Safety::Considered,
        locate: |user| {
            let roaming = PathBuf::from(user.roaming_app_data());
            let mut found = inside(
                &roaming.join("discord"),
                &["Cache", "Code Cache", "GPUCache"],
            );
            found.extend(inside(
                &roaming.join("Slack"),
                &[
                    "Cache",
                    "Code Cache",
                    "GPUCache",
                    r"Service Worker\CacheStorage",
                ],
            ));
            found.extend(chromium_caches(&PathBuf::from(user.local_app_data()).join(
                r"Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView",
            )));
            found
        },
    },
    Entry {
        id: "vscode-cache",
        name: "Visual Studio Code caches",
        what: "Compiled copies of VS Code's own scripts, the packages of extensions it has \
               already installed, and its logs.",
        cost: "VS Code starts a little slower once.",
        safety: Safety::Considered,
        locate: |user| {
            inside(
                &PathBuf::from(user.roaming_app_data()).join("Code"),
                &[
                    "Cache",
                    "CachedData",
                    "CachedExtensionVSIXs",
                    "Code Cache",
                    "GPUCache",
                    "logs",
                ],
            )
        },
    },
    Entry {
        id: "game-engine-caches",
        name: "Unreal and Unity caches",
        what: "Shaders and other data the Unreal and Unity editors work out from a \
               project's files and keep, so that a project opens without doing it again.",
        cost: "The editor rebuilds shaders and derived data the next time each project is \
               opened, which can take from minutes to hours.",
        safety: Safety::Considered,
        locate: |user| {
            let local = PathBuf::from(user.local_app_data());
            let mut found = vec![
                local.join(r"Unity\cache"),
                local_low(user).join(r"Unity\Caches\GiCache"),
            ];
            // Unreal keeps one shared cache and one for each engine version.
            if let Ok(listing) = std::fs::read_dir(local.join("UnrealEngine")) {
                for item in listing.flatten() {
                    found.push(item.path().join("DerivedDataCache"));
                }
            }
            found
        },
    },
    Entry {
        id: "adobe-media-cache",
        name: "Adobe media cache",
        what: "Previews and audio that Premiere Pro and After Effects work out from your \
               footage and keep. Your footage and your projects are elsewhere.",
        cost: "Premiere Pro and After Effects rebuild their previews the next time each \
               project opens, a few minutes per project.",
        safety: Safety::Considered,
        locate: |user| {
            inside(
                &PathBuf::from(user.roaming_app_data()).join(r"Adobe\Common"),
                &["Media Cache Files", "Media Cache"],
            )
        },
    },
    Entry {
        id: "windows-upgrade-files",
        name: "Windows upgrade files",
        what: "What Windows downloads and unpacks to install a new version of itself, in \
               hidden folders at the top of the system drive. They are normally removed \
               when the upgrade is over.",
        cost: "A Windows upgrade that was downloading or waiting to install starts again. \
               If one was installed in the last ten days, it may no longer be possible to \
               go back to the version before it.",
        safety: Safety::Considered,
        locate: |_| {
            ["$WINDOWS.~BT", "$WINDOWS.~WS", "$GetCurrent"]
                .iter()
                .map(|name| system_drive().join(name))
                .collect()
        },
    },
    Entry {
        id: "windows-servicing-logs",
        name: "Windows servicing logs",
        what: "The record Windows keeps of installing updates and checking its own files. \
               It grows for years and is read only when an update has gone wrong.",
        cost: "",
        safety: Safety::Routine,
        locate: |_| vec![windir().join(r"Logs\CBS")],
    },
    Entry {
        id: "edge-update-downloads",
        name: "Microsoft Edge update downloads",
        what: "Installers that Edge's updater downloaded and has already used.",
        cost: "",
        safety: Safety::Routine,
        locate: |_| vec![program_files_x86().join(r"Microsoft\EdgeUpdate\Download")],
    },
    Entry {
        id: "launcher-logs",
        name: "Game launcher logs",
        what: "What the Epic Games Launcher, the EA app and VALORANT write down as they \
               run. Read only by somebody working out why one misbehaved.",
        cost: "",
        safety: Safety::Routine,
        locate: |user| {
            inside(
                &PathBuf::from(user.local_app_data()),
                &[
                    r"EpicGamesLauncher\Saved\Logs",
                    r"Electronic Arts\EA Desktop\Logs",
                    r"VALORANT\Saved\Logs",
                ],
            )
        },
    },
];

/// What is explained and never cleared. See [`Explanation`].
///
/// Every sentence here says what a thing is for and what controls it. None
/// says what to do about it: whether 25 GB is worth hibernation is the
/// person's to weigh, and this is not a list of recommendations.
const EXPLAINED: &[Explanation] = &[
    Explanation {
        id: "hibernation-file",
        name: "The hibernation file",
        what: "Windows writes the contents of memory here so the PC can hibernate, and \
               uses it to start quickly after a shut-down. It is sized from the memory \
               this PC has, not from what is in use.",
        managed_by: "Turning hibernation off removes the file, and Fast Startup with it: \
                     powercfg /h off, run as administrator. powercfg /h on brings both back.",
        locate: |_| vec![system_drive().join("hiberfil.sys")],
    },
    Explanation {
        id: "page-file",
        name: "The page file",
        what: "Windows moves memory that is not being used here when programs ask for \
               more than the PC has. The smaller file beside it does the same for apps \
               from the Store.",
        managed_by: "Its size is set in System Properties, Advanced, Performance, Virtual \
                     memory. Left to Windows, it grows and shrinks by itself.",
        locate: |_| {
            vec![
                system_drive().join("pagefile.sys"),
                system_drive().join("swapfile.sys"),
            ]
        },
    },
    Explanation {
        id: "restore-points",
        name: "Restore points and earlier versions of files",
        what: "Windows' own folder at the top of the drive. Most of what is in it is \
               restore points and earlier versions of files, kept so that the system, or \
               one file, can be put back as it was on an earlier day.",
        managed_by: "System Properties, System Protection, Configure sets how much of the \
                     drive they may use, and deletes them.",
        locate: |_| vec![system_drive().join("System Volume Information")],
    },
    Explanation {
        id: "website-storage",
        name: "Data that websites saved in a browser",
        what: "Files and databases that websites themselves stored on this PC through \
               the browser: offline copies of documents and mail, a web app's own storage. \
               It is not a cache. The browser cannot fetch it again, and removing it can \
               lose work that was only saved here.",
        managed_by: "Each browser lists it by site, largest first, and deletes it one site \
                     at a time. In Chrome: Settings, Privacy and security, Third-party \
                     cookies, See all site data and permissions.",
        locate: |user| {
            let local = PathBuf::from(user.local_app_data());
            CHROMIUM_BROWSERS
                .iter()
                .flat_map(|browser| chromium_site_storage(&local.join(browser)))
                .collect()
        },
    },
    Explanation {
        id: "ai-models",
        name: "Downloaded AI models",
        what: "Models fetched by tools such as the Hugging Face libraries, Whisper and \
               Ollama. Each is a file of up to several gigabytes, downloaded the first \
               time a program asked for it.",
        managed_by: "The tool that downloaded a model removes it: huggingface-cli \
                     delete-cache for Hugging Face, and ollama rm followed by the model's \
                     name for Ollama. A model that has been removed is downloaded again \
                     the next time something asks for it.",
        locate: |user| {
            inside(
                &PathBuf::from(user.profile()),
                &[r".cache\huggingface", r".cache\whisper", r".ollama\models"],
            )
        },
    },
    Explanation {
        id: "windows-installer-cache",
        name: "Windows Installer's copies",
        what: "The installer packages of programs installed on this PC, kept by Windows \
               in its Installer folder. Windows needs each one to repair, update or \
               uninstall the program it belongs to.",
        managed_by: "Windows adds one when a program is installed and removes it when \
                     that program is uninstalled. Removing one by hand breaks that \
                     program's uninstaller.",
        locate: |_| vec![windir().join("Installer")],
    },
    Explanation {
        id: "setup-package-cache",
        name: "Setup programs' package cache",
        what: "Installer packages kept in the Package Cache folder by setup programs \
               that install several parts at once, such as Visual C++ and .NET. They are \
               needed to repair, change or uninstall what they installed.",
        managed_by: "Each is removed when the program it belongs to is uninstalled. \
                     Removing one by hand breaks that program's uninstaller.",
        locate: |_| vec![program_data().join("Package Cache")],
    },
    Explanation {
        id: "visual-studio-packages",
        name: "Visual Studio's installer packages",
        what: "Packages the Visual Studio Installer keeps so that Visual Studio or the \
               Build Tools can be repaired or changed without downloading them again. \
               The same folder holds the records both are found by, which is why it is \
               not emptied from here.",
        managed_by: "Whether packages are kept is the Visual Studio Installer's own \
                     setting. Microsoft's documentation calls it the package cache and \
                     describes how to switch it off or move it.",
        locate: |_| vec![program_data().join(r"Microsoft\VisualStudio\Packages")],
    },
    Explanation {
        id: "driver-packages",
        name: "Driver packages and graphics driver files",
        what: "Windows' store of the driver packages installed on this PC, the graphics \
               driver's own repair data, and the models games load for upscaling.",
        managed_by: "Windows keeps a driver package for as long as a device might need it. \
                     An old one is removed with pnputil /delete-driver, run as \
                     administrator, which refuses a package that is in use.",
        locate: |_| {
            vec![
                windir().join(r"System32\DriverStore\FileRepository"),
                program_files().join(r"NVIDIA Corporation\Installer2"),
                program_data().join(r"NVIDIA\NGX"),
            ]
        },
    },
    Explanation {
        id: "defender-records",
        name: "Microsoft Defender's own records",
        what: "Defender's history of what it scanned and found, and the definitions it \
               has downloaded.",
        managed_by: "Defender removes old entries itself. Tamper Protection stops other \
                     programs changing these folders.",
        locate: |_| {
            inside(
                &program_data().join(r"Microsoft\Windows Defender"),
                &["Scans", "Definition Updates"],
            )
        },
    },
    Explanation {
        id: "device-backups",
        name: "iPhone and iPad backups",
        what: "Each folder is a complete backup of one device, made by iTunes or by \
               Apple Devices.",
        managed_by: "A backup is deleted from inside iTunes or Apple Devices, under Edit, \
                     Preferences, Devices, which shows the device and the date of each.",
        locate: |user| {
            vec![
                PathBuf::from(user.roaming_app_data()).join(r"Apple Computer\MobileSync\Backup"),
                PathBuf::from(user.profile()).join(r"Apple\MobileSync\Backup"),
            ]
        },
    },
    Explanation {
        id: "outlook-mailboxes",
        name: "Outlook mailbox files",
        what: "Mail that Outlook keeps on this PC. An .ost file is Outlook's offline copy \
               of a mailbox and is rebuilt from the server. A .pst file may be the only \
               copy of the mail inside it.",
        managed_by: "Outlook's account settings decide how much mail is kept offline, and \
                     a .pst file is opened and closed from inside Outlook.",
        locate: |user| {
            let local = PathBuf::from(user.local_app_data());
            vec![
                local.join(r"Microsoft\Outlook"),
                local.join(r"Microsoft\Olk"),
                PathBuf::from(user.profile()).join(r"Documents\Outlook Files"),
            ]
        },
    },
    Explanation {
        id: "virtual-disks",
        name: "Docker and Linux virtual disks",
        what: "Each file is a whole virtual disk, used by Docker or by a Linux system \
               running under Windows. It grows as things are stored inside it and does \
               not shrink when they are deleted inside it.",
        managed_by: "Docker Desktop frees its disk under Troubleshoot, Clean / Purge data. \
                     A Linux disk is made smaller by stopping it with wsl --shutdown and \
                     then compacting the disk file.",
        locate: |user| {
            let local = PathBuf::from(user.local_app_data());
            let mut found = vec![local.join(r"Docker\wsl"), local.join("wsl")];
            // A distribution from the Store keeps its disk in its own package.
            if let Ok(packages) = std::fs::read_dir(local.join("Packages")) {
                for package in packages.flatten() {
                    found.push(package.path().join(r"LocalState\ext4.vhdx"));
                }
            }
            found
        },
    },
    Explanation {
        id: "android-emulators",
        name: "Android emulators",
        what: "Each folder is a whole virtual phone with its own data, or the system \
               image one is made from.",
        managed_by: "Android Studio's Device Manager lists the virtual devices and \
                     deletes them, and its SDK Manager removes system images.",
        locate: |user| {
            vec![
                PathBuf::from(user.profile()).join(r".android\avd"),
                PathBuf::from(user.local_app_data()).join(r"Android\Sdk\system-images"),
            ]
        },
    },
    Explanation {
        id: "pnpm-store",
        name: "pnpm's package store",
        what: "Every package pnpm has installed for any project, kept once. Projects \
               link into this store instead of holding copies of their own.",
        managed_by: "pnpm store prune removes what no project still uses. Removing the \
                     folder by hand breaks the projects that link into it until they are \
                     installed again.",
        locate: |user| vec![PathBuf::from(user.local_app_data()).join(r"pnpm\store")],
    },
    Explanation {
        id: "amd-installer-files",
        name: "Files AMD's installers unpacked",
        what: "AMD's driver and chipset installers unpack themselves into a folder named \
               AMD at the top of the system drive and leave the files there. The drivers \
               themselves are installed elsewhere.",
        managed_by: "Nothing removes these by itself. The folder can be deleted in \
                     Explorer, which sends it to the Recycle Bin. It is not emptied from \
                     here because a folder of that name may hold something else as well.",
        locate: |_| vec![system_drive().join("AMD")],
    },
    Explanation {
        id: "memory-dump",
        name: "The memory dump from the last crash",
        what: "The whole of memory, written to one file when Windows last stopped with a \
               blue screen. It is of use to somebody working out why.",
        managed_by: "Windows overwrites it at the next such stop, and its own Disk Cleanup \
                     removes it under System error memory dump files.",
        locate: |_| vec![windir().join("MEMORY.DMP")],
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

/// The folders every catalogue location starts from, as spelled and as they
/// really are.
///
/// # Why a location is checked against where it starts
///
/// A location is one of these followed by names the catalogue spells out:
/// the caller's profile, then `AppData\Roaming\discord\Cache`. Only the last
/// of those names used to be checked for being a link. Any folder above it
/// that the caller can replace could be made a junction, and the clear then
/// went through it: as LocalSystem, into whatever folder of that last name
/// the junction led to. `%USERPROFILE%\.nuget` pointed at
/// `C:\ProgramData\Microsoft\VisualStudio` would have emptied the folder
/// Visual Studio is found by, for a caller with no rights over it, and every
/// entry added to this list adds names that could be reached the same way.
///
/// So a location is only cleared, or measured, when the folder it really is
/// turns out to be the starting place followed by exactly those names. The
/// starting place itself may be reached through a link, because a profile
/// moved to another drive is: nothing the caller can swap sits above it.
struct Anchors(Vec<(String, String)>);

impl Anchors {
    fn of(user: &UserContext) -> Self {
        let mut folders = vec![
            PathBuf::from(user.profile()),
            program_data(),
            windir(),
            program_files_x86(),
            system_drive(),
        ];
        // Wherever Steam says its libraries are.
        folders.extend(crate::steam::library_roots(user));
        Self::from_folders(&folders)
    }

    fn from_folders(folders: &[PathBuf]) -> Self {
        Self(
            folders
                .iter()
                .filter_map(|folder| {
                    let spelled = folder.to_string_lossy();
                    // One that is not there has nothing inside it to clear.
                    let real = crate::paths::existing_plain(&spelled)?;
                    Some((
                        crate::paths::plain(&spelled)
                            .trim_end_matches('\\')
                            .to_owned(),
                        real.trim_end_matches('\\').to_owned(),
                    ))
                })
                .collect(),
        )
    }

    /// Where `path` is if every name below its starting place is a real
    /// folder, in plain form. `None` when it starts from none of them.
    fn where_spelled(&self, path: &Path) -> Option<String> {
        let spelled = crate::paths::plain(&path.to_string_lossy());
        self.0
            .iter()
            .filter_map(|(anchor, real)| {
                let below = crate::paths::below(&spelled, anchor)?;
                let mut expected = real.clone();
                for name in below {
                    expected.push('\\');
                    expected.push_str(name);
                }
                Some((anchor.len(), expected))
            })
            // The deepest starting place it is under: the profile rather than
            // the drive the profile is on.
            .max_by_key(|(depth, _)| *depth)
            .map(|(_, expected)| expected)
    }

    /// Whether `path`, as it resolves now, is where it is spelled.
    ///
    /// For listing only, like [`ours_to_empty`]: it answers about this moment.
    /// The clear asks the same question of the folder it is holding open.
    fn holds(&self, path: &Path) -> bool {
        let real = crate::paths::existing_plain(&path.to_string_lossy());
        real.is_some_and(|real| {
            self.where_spelled(path).as_deref() == Some(real.trim_end_matches('\\'))
        })
    }
}

fn build(entry: &Entry, user: &UserContext, anchors: &Anchors) -> Option<Cache> {
    let mut locations = Vec::new();
    for path in (entry.locate)(user) {
        if !ours_to_empty(&path) || !anchors.holds(&path) {
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
        managed_by: String::new(),
        bytes: locations.iter().map(|location| location.bytes).sum(),
        files: locations.iter().map(|location| location.files).sum(),
        locations,
    })
}

/// Measure one explained place, which may be a folder or a single file.
///
/// A link is not measured, as everywhere else here. A file is measured by the
/// length Windows records for it, which is all that can be asked of the
/// hibernation and page files: nothing may open them while Windows runs.
fn sized(path: &Path) -> Option<CacheLocation> {
    let data = std::fs::symlink_metadata(path).ok()?;
    if data.file_type().is_symlink() {
        return None;
    }
    let (bytes, files, partial) = if data.is_dir() {
        measure(path)
    } else {
        (data.len(), 1, false)
    };
    (files > 0).then(|| CacheLocation {
        path: path.to_string_lossy().into_owned(),
        bytes,
        files,
        partial,
    })
}

fn explain(explanation: &Explanation, user: &UserContext) -> Option<Cache> {
    let locations: Vec<CacheLocation> = (explanation.locate)(user)
        .iter()
        .filter_map(|path| sized(path))
        .collect();
    if locations.is_empty() {
        return None;
    }

    Some(Cache {
        id: explanation.id.to_owned(),
        name: explanation.name.to_owned(),
        what: explanation.what.to_owned(),
        // Nothing is cleared, so there is no cost of clearing to state.
        cost: String::new(),
        safety: Safety::Explained,
        managed_by: explanation.managed_by.to_owned(),
        bytes: locations.iter().map(|location| location.bytes).sum(),
        files: locations.iter().map(|location| location.files).sum(),
        locations,
    })
}

/// Measure every cache that is actually present, and everything explained
/// beside them, largest first. [`Cache::safety`] tells the two apart.
pub fn survey(user: &UserContext) -> Vec<Cache> {
    let anchors = Anchors::of(user);
    let mut caches: Vec<Cache> = CATALOGUE
        .iter()
        .filter_map(|entry| build(entry, user, &anchors))
        .collect();
    caches.extend(
        EXPLAINED
            .iter()
            .filter_map(|explanation| explain(explanation, user)),
    );
    caches.sort_by_key(|cache| std::cmp::Reverse(cache.bytes));
    caches
}

/// Whether a path looks like a real directory rather than a link to one.
///
/// `Path::is_dir` follows reparse points, so it answers "yes" for a junction
/// pointing anywhere at all, and the survey would then list somebody else's
/// files as a cache and offer their size for reclaiming.
///
/// # Not a safety guard
///
/// This is for *listing*, and nothing more. It resolves the path once and
/// answers about that moment, which is worth nothing to the code that deletes:
/// by the time deleting happened the answer could be stale, and adversarial
/// review demonstrated exactly that. [`HeldRoot`] is what stands between a
/// name and a deletion. Do not reach for this one there.
fn ours_to_empty(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|data| data.is_dir() && !data.file_type().is_symlink())
        .unwrap_or(false)
}

/// A cache root, held open so it cannot become something else.
///
/// # Why a handle and not another check
///
/// The obvious guard is to ask whether the path is a real directory and then
/// empty it, and that is what this did. Asking and acting are two separate
/// resolutions of the same name, and between them the name can be made to mean
/// something else: several catalogue roots sit in user-writable space, so
/// renaming `%LOCALAPPDATA%\Temp` aside and dropping a junction in its place
/// needs no elevation at all. Adversarial review demonstrated the payload —
/// with the swap landing in that window, `read_dir` follows the junction and
/// the walk deletes the target's real contents, as LocalSystem, permanently,
/// because this is the path that removes rather than quarantines.
///
/// A narrower window would not have fixed it. The check is retryable, the
/// attacker controls the location, and losing a race that can be re-run costs
/// nothing. So the second resolution is removed instead: the root is opened
/// once, and the handle is held for as long as the walk runs.
///
/// Two flags carry the weight:
///
/// - `FILE_FLAG_OPEN_REPARSE_POINT` opens the reparse point itself rather than
///   following it, so a root that is *already* a junction is seen as one.
/// - The share mode omits `FILE_SHARE_DELETE`, which is what makes this a lock
///   rather than a faster check. Renaming or deleting a directory needs DELETE
///   access, and that cannot be granted while a handle without delete sharing
///   is open. For as long as this value lives, the root cannot be swapped.
///
/// # Why enumerating by path below is nonetheless safe
///
/// The obvious objection is that only the root is pinned, and `read_dir` is
/// still by path: rename a *parent*, rebuild the chain through a junction, and
/// the same path resolves somewhere else. That was written here as an open
/// limitation until adversarial review went and tried it, and it does not work.
///
/// Windows refuses to move a directory whose subtree contains an open handle.
/// Holding this one therefore pins every ancestor too, not just the root —
/// measured at three levels up, each rename refused, and the full attack
/// (rename the parent away, rebuild it with the root as a junction to a victim)
/// refused at its first step. The enforcement is in the filesystem rather than
/// in `MoveFileExW`, so going below `std` to `NtSetInformationFile` meets the
/// same sharing violation.
///
/// So from the moment this handle is acquired until it is dropped, the whole
/// path is stable: the root cannot already be a link, because that was checked
/// on the handle itself, and no part of the path above it can be moved to
/// redirect it. That is what makes by-path enumeration below correct, and it is
/// why this does not need the handle-relative enumeration `std` cannot do.
struct HeldRoot {
    _handle: std::fs::File,
}

impl HeldRoot {
    /// Open a catalogue root, or explain why it will not be touched.
    fn open(path: &Path) -> std::result::Result<Self, String> {
        use std::os::windows::fs::OpenOptionsExt;

        // Opening a directory at all needs backup semantics; the rest is
        // described above.
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_SHARE_WRITE: u32 = 0x0000_0002;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

        let handle = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|error| format!("{} could not be opened: {error}", path.display()))?;

        let attributes = {
            use std::os::windows::fs::MetadataExt;
            handle
                .metadata()
                .map_err(|error| format!("{} could not be read: {error}", path.display()))?
                .file_attributes()
        };

        // Any reparse tag is refused, not only the redirecting ones. A cache
        // root is an ordinary directory this product created or Windows did,
        // and something that has become a reparse point of any kind is not a
        // thing to empty as LocalSystem on the strength of its name.
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(format!(
                "{} is a link rather than a real folder, so it was left alone",
                path.display()
            ));
        }
        if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(format!(
                "{} is not a folder, so it was left alone",
                path.display()
            ));
        }

        Ok(Self { _handle: handle })
    }

    /// Where the folder being held really is, in plain form.
    ///
    /// Asked of the handle and not of the path. The path can be made to lead
    /// somewhere else between one look and the next; the handle is already on
    /// whatever folder it reached, and stays there.
    fn real_path(&self) -> Option<String> {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Storage::FileSystem::{
            GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED,
        };

        let mut buffer = vec![0_u16; 1024];
        // Twice at most: once to learn the length a long path needs.
        for _ in 0..2 {
            // SAFETY: the handle is this value's own and stays open for the
            // call, and the buffer is as long as it is said to be.
            let length = unsafe {
                GetFinalPathNameByHandleW(
                    HANDLE(self._handle.as_raw_handle()),
                    &mut buffer,
                    FILE_NAME_NORMALIZED,
                )
            } as usize;
            if length == 0 {
                return None;
            }
            if length < buffer.len() {
                let text = String::from_utf16_lossy(&buffer[..length]);
                return Some(crate::paths::plain(&text).trim_end_matches('\\').to_owned());
            }
            buffer.resize(length + 1, 0);
        }
        None
    }
}

/// Empty one catalogue root, holding it open for the whole walk.
fn empty_root(path: &Path, anchors: &Anchors, result: &mut Cleared) {
    // Said out loud rather than skipped silently: a cache root that has become
    // a link is not a tidy no-op, it is somebody having put it there.
    let held = match HeldRoot::open(path) {
        Ok(held) => held,
        Err(refusal) => {
            result.refused.push(refusal);
            return;
        }
    };

    // The root is no link, and from here nothing above it can be swapped. What
    // is left to settle is whether a folder above it was a link already, so
    // that what is held is somebody else's folder of the same name. See
    // [`Anchors`]. Checked on the handle: if what is held is where the path
    // spells, then it is that path's own folders the handle is pinning, and
    // walking by path below is walking this folder.
    match (held.real_path(), anchors.where_spelled(path)) {
        (Some(real), Some(spelled)) if real == spelled => {}
        (Some(real), _) => {
            result.refused.push(format!(
                "{} leads to {real}, which is somewhere else, so it was left alone",
                path.display()
            ));
            return;
        }
        (None, _) => {
            result.refused.push(format!(
                "where {} really is could not be read, so it was left alone",
                path.display()
            ));
            return;
        }
    }

    empty(path, result);

    // Explicit, because the whole point is *when* it is released. Dropping it
    // early would restore the race this exists to remove, and a lint that
    // "helpfully" moved it would do exactly that.
    drop(held);
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
            // `remove_dir_all` will not traverse a reparse point, which matters
            // more than it looks: a child swapped for a junction *after* the
            // listing above cached it as a directory arrives here, and what
            // gets removed is the link rather than whatever it points at.
            //
            // That is a property of the standard library since 1.58, when
            // CVE-2022-21658 was fixed, and not of anything written here. The
            // workspace pins a far newer toolchain so it holds today; it is
            // written down because reimplementing this walk by hand, or an
            // MSRV that somehow went backwards, would lose it silently.
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
    // Asked by name and refused by name. An explained entry is not in the
    // catalogue, so it could not be cleared whatever happened here. It is
    // answered first so that the refusal says what the thing is and what does
    // control it, where "not something this knows how to clear" would read as
    // a fault.
    if let Some(explanation) = EXPLAINED.iter().find(|entry| entry.id == id) {
        return Err(format!(
            "{} is listed so that the space is explained. It is not a cache, and \
             nothing here clears it. {}",
            explanation.name, explanation.managed_by
        ));
    }

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

    let anchors = Anchors::of(user);
    for path in (entry.locate)(user) {
        // Not `is_dir`: that follows a reparse point, which is the whole hole.
        // A root that exists at all is judged; one that does not is simply not
        // there and needs no comment.
        if std::fs::symlink_metadata(&path).is_ok() {
            empty_root(&path, &anchors, &mut result);
        }
    }
    Ok(result)
}

/// Every id the catalogue defines, for anything that needs to check one.
/// Whether clearing this cache reaches beyond the caller's own profile.
///
/// That is the line Windows draws itself: Disk Cleanup clears a person's own
/// temporary files and caches without asking, and asks for administrator
/// rights before touching the Windows update cache, the machine-wide temporary
/// folder or a previous installation of Windows. A clear that reaches outside
/// the caller's profile is a machine-wide change and is only made for a caller
/// who could make it themselves.
///
/// An id this does not know is treated as machine-wide. `clear` refuses it
/// anyway; answering "needs an administrator" costs nothing, and answering the
/// other way would be a guess in the permissive direction.
pub fn is_machine_wide(id: &str, user: &UserContext) -> bool {
    // An explained entry is never cleared, so there is no change here for an
    // administrator to agree to. Answering "no" lets the request reach
    // `clear`, which refuses it by name and has the refusal recorded, where
    // "this needs administrator rights" would promise something that a yes
    // could not deliver.
    if EXPLAINED.iter().any(|entry| entry.id == id) {
        return false;
    }
    let Some(entry) = CATALOGUE.iter().find(|entry| entry.id == id) else {
        return true;
    };
    let profile = user.profile().to_lowercase().replace('/', "\\");
    let profile = profile.trim_end_matches('\\');
    (entry.locate)(user).iter().any(|location| {
        let location = location.to_string_lossy().to_lowercase().replace('/', "\\");
        // Inside means the profile itself or below it on a component boundary,
        // so `C:\Users\Ari` does not claim `C:\Users\Arianna`.
        !(location == profile
            || location
                .strip_prefix(profile)
                .is_some_and(|rest| rest.starts_with('\\')))
    })
}

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
        .chain(
            // The roots of the entries added in November 2026.
            [
                local_low(&user),
                PathBuf::from(user.profile()).join(".gradle"),
                PathBuf::from(user.profile()).join(r"go\pkg\mod"),
                program_data().join("NVIDIA Corporation"),
                system_drive().join(r"NVIDIA\DisplayDriver"),
                system_drive().join("$WINDOWS.~BT"),
                system_drive().join("$WINDOWS.~WS"),
                system_drive().join("$GetCurrent"),
                windir().join(r"Logs\CBS"),
                windir().join(
                    r"ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization",
                ),
                program_files_x86().join(r"Microsoft\EdgeUpdate\Download"),
            ]
            .iter()
            .map(|root| root.to_string_lossy().to_lowercase()),
        )
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
        empty_root(&link, &Anchors::of(&UserContext::current()), &mut result);

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

    /// While a root is held, it cannot be swapped for anything else.
    ///
    /// The test above proves a root that is *already* a junction is refused.
    /// This proves the harder half: that checking and acting are no longer two
    /// resolutions with a gap between them.
    ///
    /// Adversarial review demonstrated the payload. Verify the root is a real
    /// directory, swap it for a junction before the walk reads it, and the walk
    /// deletes the junction target's contents as LocalSystem, permanently. The
    /// window was microseconds, but the attacker owns the location, the clear
    /// is user-triggered and retryable, and losing a race you can re-run costs
    /// nothing.
    ///
    /// So the fix is not a smaller window. `HeldRoot` opens the directory
    /// without sharing delete, and renaming or removing a directory needs
    /// DELETE access, which cannot be granted while such a handle is open. The
    /// swap does not lose a race here; it fails.
    #[test]
    fn a_held_root_cannot_be_renamed_out_from_under_the_walk() {
        let root = scratch("held-root");
        let cache = root.join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(cache.join("junk.tmp"), vec![0_u8; 32]).unwrap();

        let held = HeldRoot::open(&cache).expect("a real directory opens");

        // The swap the attack depends on: move the real root aside so a
        // junction can take its name. Both halves are refused while it is held.
        let aside = root.join("cache-aside");
        assert!(
            std::fs::rename(&cache, &aside).is_err(),
            "the held root was renamed, so the swap is still possible"
        );
        assert!(
            std::fs::remove_dir_all(&cache).is_err(),
            "the held root was removed, so the swap is still possible"
        );

        // And releasing it gives the rights back, so this is a lock held for a
        // reason and not an unrelated failure.
        drop(held);
        assert!(
            std::fs::rename(&cache, &aside).is_ok(),
            "the block outlived the handle, which would be a different bug"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Holding the root pins every directory above it too.
    ///
    /// This is the property that makes enumerating by path safe, and it is a
    /// behaviour of Windows rather than of anything written here: a directory
    /// whose subtree contains an open handle cannot be moved. Without it, the
    /// obvious attack on `HeldRoot` would be to leave the pinned root alone and
    /// rename a *parent*, rebuilding the chain through a junction so the same
    /// path resolves somewhere else.
    ///
    /// It is asserted rather than described because the comment on `HeldRoot`
    /// now depends on it. If a future Windows relaxed this, the code would
    /// still look correct and would silently stop being so, and this is the
    /// only thing that would say otherwise.
    #[test]
    fn holding_a_root_also_blocks_renaming_its_ancestors() {
        let base = scratch("held-ancestors");
        let cache = base.join("a").join("b").join("c").join("cache");
        std::fs::create_dir_all(&cache).unwrap();

        let held = HeldRoot::open(&cache).expect("a real directory opens");

        // Every level between the handle and the scratch root.
        for ancestor in ["a", r"a\b", r"a\b\c"] {
            let from = base.join(ancestor);
            let to = base.join(format!("{}-moved", ancestor.replace('\\', "-")));
            assert!(
                std::fs::rename(&from, &to).is_err(),
                "{} was renamed while a descendant handle was open, so the \
                 path above a held root is not pinned after all",
                from.display()
            );
        }

        // And the pin is the handle's doing, not something else about the tree.
        drop(held);
        assert!(
            std::fs::rename(base.join("a"), base.join("a-moved")).is_ok(),
            "the block outlived the handle, which would be a different bug"
        );

        let _ = std::fs::remove_dir_all(&base);
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

    /// A scratch folder spelled by its real, long path.
    ///
    /// The temporary folder is often named through a short name such as
    /// `RUNNER~1`, and the tests below are about a path being exactly where it
    /// is spelled.
    fn long_scratch(tag: &str) -> PathBuf {
        let real = std::fs::canonicalize(scratch(tag)).unwrap();
        let text = real.to_string_lossy();
        PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text))
    }

    fn nothing_cleared() -> Cleared {
        Cleared {
            id: "test".to_owned(),
            bytes_freed: 0,
            files_removed: 0,
            files_in_use: 0,
            refused: Vec::new(),
        }
    }

    fn junction(link: &Path, target: &Path) -> bool {
        std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    }

    /// A link above a cache is not followed to somebody else's folder.
    ///
    /// Only the last name of a location was checked for being a link. Here the
    /// caller's own `vendor` folder is a junction to a folder that is not
    /// theirs, which happens to hold a folder named `Cache`. By name and by
    /// every check there was, `vendor\Cache` is an ordinary folder, and the
    /// clear, running as LocalSystem, emptied the other one.
    #[test]
    fn a_cache_reached_through_a_link_above_it_is_refused_rather_than_followed() {
        let base = long_scratch("link-above");
        let victim = long_scratch("link-above-victim");
        std::fs::create_dir_all(victim.join("Cache")).unwrap();
        std::fs::write(victim.join("Cache").join("precious.txt"), b"not a cache").unwrap();
        if !junction(&base.join("vendor"), &victim) {
            let _ = std::fs::remove_dir_all(&base);
            let _ = std::fs::remove_dir_all(&victim);
            return;
        }
        let location = base.join("vendor").join("Cache");

        // The premise, which is the whole trap.
        assert!(
            ours_to_empty(&location),
            "by its own name this is an ordinary folder"
        );

        let anchors = Anchors::from_folders(std::slice::from_ref(&base));
        assert!(
            !anchors.holds(&location),
            "a folder reached through a link was taken for the caller's own"
        );

        let mut result = nothing_cleared();
        empty_root(&location, &anchors, &mut result);
        assert!(
            victim.join("Cache").join("precious.txt").exists(),
            "the clear went through a link above the cache and emptied somebody else's folder"
        );
        assert_eq!(result.files_removed, 0);
        assert!(
            result
                .refused
                .iter()
                .any(|why| why.contains("somewhere else")),
            "it should say why it refused: {:?}",
            result.refused
        );

        let _ = std::fs::remove_dir_all(&base);
        std::fs::remove_dir_all(&victim).unwrap();
    }

    #[test]
    fn a_cache_that_is_where_its_path_says_is_emptied() {
        // The control for the test above: the same shape with no link in it.
        let base = long_scratch("no-link");
        let location = base.join("vendor").join("Cache");
        std::fs::create_dir_all(&location).unwrap();
        std::fs::write(location.join("old.tmp"), vec![1_u8; 700]).unwrap();

        let anchors = Anchors::from_folders(std::slice::from_ref(&base));
        assert!(anchors.holds(&location));

        let mut result = nothing_cleared();
        empty_root(&location, &anchors, &mut result);
        assert_eq!(result.files_removed, 1, "{:?}", result.refused);
        assert_eq!(result.bytes_freed, 700);
        assert!(location.is_dir(), "the folder itself must survive");

        std::fs::remove_dir_all(&base).unwrap();
    }

    /// The place a location starts from may itself be reached through a link.
    ///
    /// A profile moved to another drive is, and nothing the caller can swap
    /// sits above it. Only what comes below it has to be real.
    #[test]
    fn a_starting_place_reached_through_a_link_is_still_a_starting_place() {
        let base = long_scratch("moved-profile");
        let moved = long_scratch("moved-profile-target");
        let location = moved.join("AppData").join("Cache");
        std::fs::create_dir_all(&location).unwrap();
        std::fs::write(location.join("old.tmp"), vec![1_u8; 300]).unwrap();
        let profile = base.join("profile");
        if !junction(&profile, &moved) {
            let _ = std::fs::remove_dir_all(&base);
            let _ = std::fs::remove_dir_all(&moved);
            return;
        }

        let spelled = profile.join("AppData").join("Cache");
        let anchors = Anchors::from_folders(std::slice::from_ref(&profile));
        assert!(anchors.holds(&spelled));

        let mut result = nothing_cleared();
        empty_root(&spelled, &anchors, &mut result);
        assert_eq!(result.files_removed, 1, "{:?}", result.refused);

        let _ = std::fs::remove_dir_all(&base);
        std::fs::remove_dir_all(&moved).unwrap();
    }

    #[test]
    fn a_location_that_starts_from_nowhere_known_is_not_ours() {
        let base = long_scratch("unanchored");
        let location = base.join("Cache");
        std::fs::create_dir_all(&location).unwrap();
        std::fs::write(location.join("keep.txt"), b"keep").unwrap();

        // Starting places that do not include the folder this is in.
        let anchors = Anchors::from_folders(&[base.join("somewhere-else")]);
        assert!(!anchors.holds(&location));
        let mut result = nothing_cleared();
        empty_root(&location, &anchors, &mut result);
        assert!(location.join("keep.txt").exists());
        assert_eq!(result.refused.len(), 1);

        std::fs::remove_dir_all(&base).unwrap();
    }

    /// A made-up person, for asking where an entry reaches without touching
    /// anybody's real folders.
    fn someone() -> UserContext {
        UserContext::new(None, r"C:\Users\someone")
    }

    fn located(id: &str, user: &UserContext) -> Vec<String> {
        let entry = CATALOGUE
            .iter()
            .find(|entry| entry.id == id)
            .unwrap_or_else(|| panic!("{id} is not in the catalogue"));
        (entry.locate)(user)
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect()
    }

    /// Each added entry is the caller's own to clear, or needs an
    /// administrator, by where it reaches.
    #[test]
    fn the_added_entries_are_classed_by_where_they_reach() {
        let user = someone();
        for own in [
            "chrome-on-device-model",
            "steam-web-cache",
            "chat-caches",
            "vscode-cache",
            "game-engine-caches",
            "adobe-media-cache",
            "launcher-logs",
        ] {
            assert!(
                !is_machine_wide(own, &user),
                "{own} is inside the caller's profile and was classed as machine-wide"
            );
        }
        for machine in [
            "nvidia-driver-downloads",
            "nvidia-app-logs",
            "windows-upgrade-files",
            "windows-servicing-logs",
            "edge-update-downloads",
        ] {
            assert!(
                is_machine_wide(machine, &user),
                "{machine} reaches outside the caller's profile and was classed as theirs"
            );
        }
    }

    /// The additions to entries that were already there stay where those were.
    #[test]
    fn the_additions_to_existing_entries_keep_their_class() {
        let user = someone();
        assert!(!is_machine_wide("shader-cache", &user));
        assert!(!is_machine_wide("browser-cache", &user));
        assert!(!is_machine_wide("package-caches", &user));
        assert!(is_machine_wide("windows-update", &user));

        let shaders = located("shader-cache", &user);
        assert!(shaders.contains(&r"C:\Users\someone\AppData\LocalLow\NVIDIA\DXCache".to_owned()));
        let packages = located("package-caches", &user);
        assert!(packages.contains(&r"C:\Users\someone\.cargo\registry\src".to_owned()));
        assert!(packages.contains(&r"C:\Users\someone\.gradle\caches".to_owned()));
    }

    /// Steam's web cache is taken by the names of its cache folders, never as
    /// the folder that holds them, because that folder holds cookies too.
    #[test]
    fn the_steam_web_cache_does_not_reach_the_browsers_cookies() {
        let holder = r"c:\users\someone\appdata\local\steam\htmlcache";
        let locations = located("steam-web-cache", &someone());
        assert!(!locations.is_empty());
        for location in locations {
            let lowered = location.to_lowercase();
            assert_ne!(lowered, holder, "the whole folder would be emptied");
            let last = lowered.rsplit('\\').next().unwrap();
            assert!(
                ["cache", "code cache", "gpucache"].contains(&last),
                "{location} is not one of the cache folders"
            );
        }
    }

    /// A new entry, from the list to an empty folder, in a made-up profile.
    ///
    /// Discord keeps its sign-in beside its cache. The cache goes, the folder
    /// it was in stays, and what sits beside it is not touched.
    #[test]
    fn clearing_the_chat_caches_takes_the_cache_and_leaves_the_session() {
        let profile = long_scratch("chat");
        let discord = profile.join("AppData").join("Roaming").join("discord");
        std::fs::create_dir_all(discord.join("Cache").join("Cache_Data")).unwrap();
        std::fs::create_dir_all(discord.join("Local Storage")).unwrap();
        std::fs::write(
            discord.join("Cache").join("Cache_Data").join("f_0001"),
            vec![9_u8; 4096],
        )
        .unwrap();
        std::fs::write(
            discord.join("Local Storage").join("session.db"),
            b"signed in",
        )
        .unwrap();
        let user = UserContext::new(None, &profile.to_string_lossy());

        let listed = survey(&user);
        let chat = listed
            .iter()
            .find(|cache| cache.id == "chat-caches")
            .expect("the cache has a file in it and should be listed");
        assert_eq!(chat.bytes, 4096);
        assert_eq!(chat.locations.len(), 1);

        let cleared = clear("chat-caches", &user).unwrap();
        assert_eq!(cleared.files_removed, 1, "{:?}", cleared.refused);
        assert_eq!(cleared.bytes_freed, 4096);
        assert!(
            discord.join("Cache").is_dir(),
            "the folder itself must survive"
        );
        assert!(
            discord.join("Local Storage").join("session.db").exists(),
            "what keeps the person signed in was removed"
        );

        std::fs::remove_dir_all(&profile).unwrap();
    }

    /// "Costs nothing" is said only of an entry that states no cost.
    ///
    /// The page labels a routine entry "Costs nothing" and clears it on one
    /// press. Of the entries added in November 2026, the ones that give
    /// something up, however small, say what and ask first.
    #[test]
    fn an_added_entry_that_states_a_cost_is_not_called_free() {
        let added = [
            "nvidia-driver-downloads",
            "nvidia-app-logs",
            "chrome-on-device-model",
            "steam-web-cache",
            "chat-caches",
            "vscode-cache",
            "game-engine-caches",
            "adobe-media-cache",
            "windows-upgrade-files",
            "windows-servicing-logs",
            "edge-update-downloads",
            "launcher-logs",
        ];
        for id in added {
            let entry = CATALOGUE
                .iter()
                .find(|entry| entry.id == id)
                .unwrap_or_else(|| panic!("{id} is not in the catalogue"));
            assert_eq!(
                entry.safety == Safety::Routine,
                entry.cost.is_empty(),
                "{id} is called free and states a cost, or the other way round"
            );
        }
    }

    /// Nothing a person reads from this list carries a dash, and every entry
    /// says what it holds.
    #[test]
    fn every_entry_is_described_in_plain_sentences() {
        for entry in CATALOGUE {
            for text in [entry.name, entry.what, entry.cost] {
                assert!(
                    !text.contains('\u{2014}') && !text.contains('\u{2013}'),
                    "{} has a dash in: {text}",
                    entry.id
                );
            }
            assert!(
                !entry.name.is_empty() && !entry.what.is_empty(),
                "{}",
                entry.id
            );
        }
    }

    /// Something explained is refused by name, whoever asks and however.
    ///
    /// It is not in the list `clear` empties, so nothing could be removed
    /// either way. What this pins is that the refusal says what the thing is
    /// and what does control it, and that asking never becomes a question of
    /// administrator rights, which would suggest that a yes could clear it.
    #[test]
    fn something_explained_is_never_cleared_and_says_what_controls_it() {
        let user = someone();
        for explanation in EXPLAINED {
            let refusal = clear(explanation.id, &user).expect_err(explanation.id);
            assert!(
                refusal.contains("nothing here clears it")
                    && refusal.contains(explanation.managed_by),
                "{}: the refusal should say what controls it: {refusal}",
                explanation.id
            );
            assert!(
                !is_machine_wide(explanation.id, &user),
                "{} would be put to an administrator, as if consent could clear it",
                explanation.id
            );
            assert!(
                CATALOGUE.iter().all(|entry| entry.id != explanation.id),
                "{} is also in the list that is emptied",
                explanation.id
            );
        }
    }

    /// A made-up person's AI models are measured, explained, and left alone.
    #[test]
    fn something_explained_is_measured_and_survives_being_asked_to_clear() {
        let profile = long_scratch("explained");
        let models = profile.join(".ollama").join("models");
        std::fs::create_dir_all(models.join("blobs")).unwrap();
        std::fs::write(models.join("blobs").join("sha256-0001"), vec![3_u8; 8192]).unwrap();
        let user = UserContext::new(None, &profile.to_string_lossy());

        let listed = survey(&user);
        let found = listed
            .iter()
            .find(|cache| cache.id == "ai-models")
            .expect("the models are there and should be listed");
        assert_eq!(found.safety, Safety::Explained);
        assert_eq!(found.bytes, 8192);
        assert!(found.cost.is_empty());
        assert!(
            found.managed_by.contains("ollama rm"),
            "{}",
            found.managed_by
        );

        assert!(clear("ai-models", &user).is_err());
        assert!(
            models.join("blobs").join("sha256-0001").exists(),
            "something that is only explained was removed"
        );

        std::fs::remove_dir_all(&profile).unwrap();
    }

    #[test]
    fn a_single_file_is_measured_as_the_one_file_it_is() {
        // The hibernation file, the page file and a memory dump are each one
        // file, and the list could only hold folders.
        let folder = long_scratch("single-file");
        let file = folder.join("hiberfil.sys");
        std::fs::write(&file, vec![0_u8; 5000]).unwrap();

        let measured = sized(&file).expect("a file that is there is measured");
        assert_eq!((measured.bytes, measured.files), (5000, 1));
        assert!(!measured.partial);

        assert!(sized(&folder.join("not-there.sys")).is_none());
        // An empty folder holds nothing to explain.
        std::fs::create_dir(folder.join("empty")).unwrap();
        assert!(sized(&folder.join("empty")).is_none());

        std::fs::remove_dir_all(&folder).unwrap();
    }

    /// What is explained is described, and never advised on.
    #[test]
    fn every_explanation_states_facts_and_gives_no_advice() {
        let mut ids: Vec<&str> = CATALOGUE.iter().map(|entry| entry.id).collect();
        ids.extend(EXPLAINED.iter().map(|explanation| explanation.id));
        let before = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), before, "two entries share an id");

        for explanation in EXPLAINED {
            for text in [explanation.name, explanation.what, explanation.managed_by] {
                assert!(
                    !text.is_empty(),
                    "{} leaves something unsaid",
                    explanation.id
                );
                assert!(
                    !text.contains('\u{2014}') && !text.contains('\u{2013}'),
                    "{} has a dash in: {text}",
                    explanation.id
                );
                let lowered = text.to_lowercase();
                for advice in ["you should", "we recommend", "safe to", "it is safe"] {
                    assert!(
                        !lowered.contains(advice),
                        "{} gives advice (\"{advice}\"): {text}",
                        explanation.id
                    );
                }
            }
        }
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
