//! Where an application's shortcuts live, and what they point at.
//!
//! An uninstaller usually clears its own install directory and leaves
//! everything else: the Start Menu folder, the desktop icon, the pinned
//! taskbar entry. None of that is much disk space — a `.lnk` is a couple of
//! kilobytes — but a Start Menu full of entries that launch nothing is the
//! visible half of a machine that has not been cleaned up properly, and it is
//! the half people notice.
//!
//! # Reading the target without waking the installer
//!
//! `IShellLink::Resolve` is the obvious call and the wrong one. Resolving a
//! shortcut whose target has moved sends Windows looking for it, and for
//! anything installed by MSI that can trigger a repair — the installer
//! springs to life and reinstalls the very software somebody is trying to
//! remove. `GetPath` with `SLGP_RAWPATH` returns what the shortcut actually
//! stores, resolves nothing, and asks nobody.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use windows::core::{Interface, PCWSTR};
use windows::Win32::Storage::FileSystem::WIN32_FIND_DATAW;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, IPersistFile, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED, STGM_READ,
};
use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};

/// Return the path as stored, without resolving or searching for it.
const SLGP_RAWPATH: u32 = 0x4;

/// Where a shortcut was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Place {
    /// The Start Menu, for this user or for everyone.
    StartMenu,
    Desktop,
    /// Pinned to the taskbar.
    Taskbar,
}

impl Place {
    pub fn label(self) -> &'static str {
        match self {
            Self::StartMenu => "Start Menu",
            Self::Desktop => "Desktop",
            Self::Taskbar => "Taskbar",
        }
    }
}

/// One shortcut on this machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Shortcut {
    /// The `.lnk` file itself, which is the thing that would be removed.
    pub path: String,
    /// What it is called, which is what a person sees in the Start Menu.
    pub name: String,
    pub place: Place,
    /// What it points at, with any `%NAME%` expanded. `None` when the
    /// shortcut has no file target at all — the Store publishes its entries
    /// that way.
    pub target: Option<String>,
    /// True when the target is named but is not there any more.
    pub broken: bool,
    /// Whether this is for everyone on the machine, which needs administrator
    /// rights to remove.
    pub machine_wide: bool,
    pub bytes: u64,
}

/// COM apartment held for the life of a call, dropped last.
struct ComGuard;

impl ComGuard {
    fn enter() -> Option<Self> {
        let outcome = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        // Already initialised in another mode is fine; the calls below work
        // either way.
        if outcome.is_err() && outcome != windows::Win32::Foundation::RPC_E_CHANGED_MODE {
            return None;
        }
        Some(Self)
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

/// Read where a `.lnk` points, without resolving it.
///
/// The caller must already be inside a COM apartment.
fn target_of(lnk: &Path) -> Option<String> {
    let link: IShellLinkW =
        unsafe { CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER) }.ok()?;
    let file: IPersistFile = link.cast().ok()?;

    let path = wide(lnk);
    unsafe { file.Load(PCWSTR(path.as_ptr()), STGM_READ) }.ok()?;

    let mut buffer = [0_u16; 1024];
    let mut found = WIN32_FIND_DATAW::default();
    unsafe { link.GetPath(&mut buffer, &mut found, SLGP_RAWPATH) }.ok()?;

    let end = buffer.iter().position(|unit| *unit == 0).unwrap_or(buffer.len());
    let target = String::from_utf16_lossy(&buffer[..end]).trim().to_owned();
    if target.is_empty() {
        return None;
    }

    // The raw path is raw in both senses: it is also stored with the
    // environment variable left in. `%windir%\system32\magnify.exe` is not a
    // path any file check will match, and treating it as one reported Magnify,
    // Narrator and the On-Screen Keyboard as pointing at missing files -- in a
    // reader whose whole purpose is proposing that such shortcuts be removed.
    Some(kam_core::env::expand(&target))
}

fn folder(variable: &str, tail: &str) -> Option<PathBuf> {
    let base = std::env::var(variable).ok()?;
    let path = PathBuf::from(base).join(tail);
    path.is_dir().then_some(path)
}

/// Every place Windows keeps shortcuts, and who they belong to.
fn places() -> Vec<(PathBuf, Place, bool)> {
    let mut found = Vec::new();

    if let Some(path) = folder("APPDATA", r"Microsoft\Windows\Start Menu\Programs") {
        found.push((path, Place::StartMenu, false));
    }
    if let Some(path) = folder("ProgramData", r"Microsoft\Windows\Start Menu\Programs") {
        found.push((path, Place::StartMenu, true));
    }
    if let Some(path) = folder("USERPROFILE", "Desktop") {
        found.push((path, Place::Desktop, false));
    }
    if let Some(path) = folder("PUBLIC", "Desktop") {
        found.push((path, Place::Desktop, true));
    }
    if let Some(path) = folder(
        "APPDATA",
        r"Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar",
    ) {
        found.push((path, Place::Taskbar, false));
    }

    found
}

fn walk(folder: &Path, depth: usize, found: &mut Vec<PathBuf>) {
    // The Start Menu nests one or two deep in practice. The bound stops a
    // junction loop turning this into an unbounded walk.
    if depth > 4 {
        return;
    }
    let Ok(listing) = std::fs::read_dir(folder) else {
        return;
    };
    for item in listing.flatten() {
        let path = item.path();
        match item.file_type() {
            Ok(kind) if kind.is_symlink() => continue,
            Ok(kind) if kind.is_dir() => walk(&path, depth + 1, found),
            Ok(_)
                if path
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("lnk")) =>
            {
                found.push(path);
            }
            _ => {}
        }
    }
}

/// Every shortcut on this machine, with what it points at.
pub fn all() -> Vec<Shortcut> {
    let Some(_com) = ComGuard::enter() else {
        return Vec::new();
    };

    let mut shortcuts = Vec::new();
    for (folder, place, machine_wide) in places() {
        let mut files = Vec::new();
        walk(&folder, 0, &mut files);

        for file in files {
            let target = target_of(&file);
            shortcuts.push(Shortcut {
                name: file
                    .file_stem()
                    .map(|stem| stem.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                // A shortcut with no file target is not broken; Store entries
                // and control-panel items legitimately have none.
                broken: target
                    .as_deref()
                    .is_some_and(|path| !Path::new(path).exists()),
                bytes: std::fs::metadata(&file).map(|data| data.len()).unwrap_or(0),
                path: file.display().to_string(),
                place,
                machine_wide,
                target,
            });
        }
    }
    shortcuts
}

fn canonical(path: &str) -> String {
    path.to_lowercase().replace('/', "\\").trim_end_matches('\\').to_owned()
}

/// Shortcuts that point inside any of `roots`.
///
/// Used after an uninstall: the application's own measured directories are the
/// roots, so this finds the Start Menu folder and desktop icon belonging to
/// the thing just removed, without guessing from its name.
pub fn pointing_into(roots: &[String]) -> Vec<Shortcut> {
    if roots.is_empty() {
        return Vec::new();
    }
    let roots: Vec<String> = roots.iter().map(|root| canonical(root)).collect();

    all()
        .into_iter()
        .filter(|shortcut| {
            let Some(target) = shortcut.target.as_deref() else {
                return false;
            };
            let target = canonical(target);
            roots
                .iter()
                .any(|root| target == *root || target.starts_with(&format!("{root}\\")))
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn this_machine_has_shortcuts_that_resolve() {
        // Every Windows install has a Start Menu full of them. Finding none, or
        // finding them all without targets, means the reading is broken rather
        // than the machine unusual.
        let shortcuts = all();
        println!("{} shortcuts", shortcuts.len());
        assert!(!shortcuts.is_empty(), "no shortcuts at all");

        let resolved = shortcuts.iter().filter(|s| s.target.is_some()).count();
        let broken = shortcuts.iter().filter(|s| s.broken).count();
        println!("{resolved} have a file target, {broken} point at something missing");
        assert!(resolved > 0, "not one shortcut yielded a target");

        for shortcut in shortcuts.iter().filter(|s| s.target.is_some()).take(8) {
            println!(
                "  [{}] {} -> {}",
                shortcut.place.label(),
                shortcut.name,
                shortcut.target.as_deref().unwrap_or("?")
            );
        }
        for shortcut in shortcuts.iter().filter(|s| s.broken).take(5) {
            println!(
                "  BROKEN [{}] {} -> {}",
                shortcut.place.label(),
                shortcut.name,
                shortcut.target.as_deref().unwrap_or("?")
            );
        }
    }

    #[test]
    fn shortcuts_are_found_by_where_they_point() {
        // The join the cleanup depends on: given a directory, find the Start
        // Menu entries that launch something inside it.
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
        let matches = pointing_into(std::slice::from_ref(&root));
        println!("{} shortcuts point inside {root}", matches.len());
        for shortcut in matches.iter().take(5) {
            println!("  {} -> {}", shortcut.name, shortcut.target.as_deref().unwrap_or("?"));
        }
        // Windows ships accessories that launch out of System32.
        assert!(
            !matches.is_empty(),
            "nothing was found pointing into the Windows directory"
        );
    }

    #[test]
    fn an_empty_root_list_matches_nothing() {
        // Guards against the obvious catastrophe: an empty prefix matching
        // every shortcut on the machine and offering to delete the lot.
        assert!(pointing_into(&[]).is_empty());
    }

    #[test]
    fn a_partial_directory_name_does_not_match() {
        // "C:\Program Files\App" must not match "C:\Program Files\AppOther".
        let roots = [r"C:\Program Files\App".to_owned()];
        let inside = canonical(r"C:\Program Files\App\thing.exe");
        let sibling = canonical(r"C:\Program Files\AppOther\thing.exe");
        let root = canonical(&roots[0]);

        assert!(inside.starts_with(&format!("{root}\\")));
        assert!(!sibling.starts_with(&format!("{root}\\")));
        assert!(sibling.starts_with(&root), "the naive check would have matched");
    }
}
