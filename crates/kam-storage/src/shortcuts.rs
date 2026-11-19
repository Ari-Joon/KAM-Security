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
//!
//! # Whose answer "it points at something that is gone" is
//!
//! The person's, and nobody else's. A shortcut is read by Windows' shell, and
//! the shell answers for the account that asks: a shortcut kept relative to a
//! known folder such as the Desktop is placed under the asking account's
//! Desktop, `%LOCALAPPDATA%` in a stored path is the asking account's, and a
//! target on a mapped drive or a network share is there for the session that
//! mapped it and for no other.
//!
//! The agent is LocalSystem, in a session of its own. Asked there, a working
//! shortcut to a program in somebody's AppData could come back as a path under
//! the service's own profile, where nothing is, and be reported as pointing at
//! something that is gone, in a list whose purpose is to say what an uninstall
//! left behind. No rule about paths repairs that from inside the service,
//! because whether the target *exists* is itself a question about the person's
//! session.
//!
//! So the judgement is made by the window, which runs as the person, in the
//! way the Recycle Bin is used by the window. Read anywhere else, a shortcut
//! still yields its target as text, which is what the launch history needs,
//! and says that whether the target is there was not established. Nothing
//! here ever calls a target gone on the service's say-so.

use std::path::{Path, PathBuf};

use kam_core::UserContext;

use serde::{Deserialize, Serialize};
use windows::core::{Interface, GUID, PCWSTR};
use windows::Win32::Foundation::PROPERTYKEY;
use windows::Win32::Storage::FileSystem::WIN32_FIND_DATAW;
use windows::Win32::System::Com::StructuredStorage::PropVariantClear;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, IPersistFile, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED, STGM_READ,
};
use windows::Win32::System::Variant::VT_LPWSTR;
use windows::Win32::UI::Shell::PropertiesSystem::IPropertyStore;
use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};

/// Return the path as stored, without resolving or searching for it.
const SLGP_RAWPATH: u32 = 0x4;

/// `System.AppUserModel.ID`, the name Windows knows a program by.
///
/// Explorer records a launch under this name rather than under a path whenever
/// the shortcut declares one, which is most things people pin. Reading only
/// paths left Visual Studio Code and Discord showing as never opened while both
/// were running -- they are recorded as `Microsoft.VisualStudioCode` and
/// `com.squirrel.Discord.Discord`, which no amount of path matching will ever
/// join to an install directory.
const PKEY_APP_USER_MODEL_ID: PROPERTYKEY = PROPERTYKEY {
    fmtid: GUID::from_u128(0x9F4C2855_9F79_4B39_A8D0_E1D42DE1D5F3),
    pid: 5,
};

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
    /// The name Windows knows the program by, when the shortcut declares one.
    ///
    /// Explorer records a launch under this rather than under a path whenever
    /// it exists, so it is how a taskbar launch is joined back to a program.
    pub app_id: Option<String>,
    /// True when the target is named and is known not to be there any more.
    /// Only ever true for a shortcut read as the person it belongs to.
    pub broken: bool,
    /// Why what this points at could not be established, when it could not:
    /// the shortcut would not open, Windows would not say whether its target
    /// is there, or it was read by something other than the person. `None`
    /// when the target is known to be there, known to be gone, or the
    /// shortcut has no file target at all.
    ///
    /// A shortcut in this state is never offered for removal.
    #[serde(default)]
    pub target_unknown: Option<String>,
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

/// What one `.lnk` yielded.
#[derive(Debug, Default)]
struct Link {
    /// What it points at, with any `%NAME%` expanded. `None` when it has no
    /// file target, and also when it could not be read.
    target: Option<String>,
    app_id: Option<String>,
    /// Why it could not be read, when it could not. A shortcut that would not
    /// open is not a shortcut with no target: the first is a failure and the
    /// second is a Store entry.
    unread: Option<&'static str>,
}

impl Link {
    fn unread(why: &'static str) -> Self {
        Self {
            unread: Some(why),
            ..Self::default()
        }
    }
}

/// Read where a `.lnk` points, and what Windows calls it.
///
/// Both come out of one load, because loading is the expensive part and a
/// second pass over 159 shortcuts to read one more property would double the
/// cost of the whole survey.
///
/// The caller must already be inside a COM apartment.
fn read_link(lnk: &Path, user: &UserContext) -> Link {
    let Ok(link) =
        (unsafe { CoCreateInstance::<_, IShellLinkW>(&ShellLink, None, CLSCTX_INPROC_SERVER) })
    else {
        return Link::unread("Windows would not read shortcuts");
    };
    let Ok(file) = link.cast::<IPersistFile>() else {
        return Link::unread("Windows would not read shortcuts");
    };

    let path = wide(lnk);
    if unsafe { file.Load(PCWSTR(path.as_ptr()), STGM_READ) }.is_err() {
        return Link::unread("the shortcut would not open");
    }

    match target_from(&link, user) {
        Ok(target) => Link {
            target,
            app_id: app_id_from(&link),
            unread: None,
        },
        Err(()) => Link {
            app_id: app_id_from(&link),
            ..Link::unread("the shortcut would not say where it points")
        },
    }
}

/// The application id a shortcut declares, if it declares one.
fn app_id_from(link: &IShellLinkW) -> Option<String> {
    let store: IPropertyStore = link.cast().ok()?;
    let mut value = unsafe { store.GetValue(&PKEY_APP_USER_MODEL_ID) }.ok()?;

    // Anything other than a string means the property is absent or is
    // something this does not understand; either way there is no id here.
    let id = unsafe {
        if value.Anonymous.Anonymous.vt != VT_LPWSTR {
            None
        } else {
            let text = value.Anonymous.Anonymous.Anonymous.pwszVal;
            (!text.is_null()).then(|| text.to_string().ok()).flatten()
        }
    };
    // The variant owns a string allocation whichever branch was taken.
    let _ = unsafe { PropVariantClear(&mut value) };

    id.filter(|id| !id.trim().is_empty())
}

/// The file a shortcut names, or `None` when it names none. An error is the
/// shell refusing to answer, which is neither.
fn target_from(link: &IShellLinkW, user: &UserContext) -> Result<Option<String>, ()> {
    let mut buffer = [0_u16; 1024];
    let mut found = WIN32_FIND_DATAW::default();
    // A shortcut with no file target answers with a success that is not
    // S_OK and an empty path, so only a real failure lands here.
    unsafe { link.GetPath(&mut buffer, &mut found, SLGP_RAWPATH) }.map_err(|_| ())?;

    let end = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    let target = String::from_utf16_lossy(&buffer[..end]).trim().to_owned();
    if target.is_empty() {
        return Ok(None);
    }
    Ok(Some(expanded_for(&target, user)))
}

/// A stored target with its `%NAME%` references filled in, for one person.
///
/// The raw path is raw in both senses: it is also stored with the environment
/// variable left in. `%windir%\system32\magnify.exe` is not a path any file
/// check will match, and treating it as one reported Magnify, Narrator and the
/// On-Screen Keyboard as pointing at missing files -- in a reader whose whole
/// purpose is proposing that such shortcuts be removed.
///
/// Filled in for the person the shortcut belongs to. `%LOCALAPPDATA%` in
/// somebody's Start Menu means their AppData, and expanded by the agent it
/// meant LocalSystem's, where nothing anybody installed has ever been.
fn expanded_for(target: &str, user: &UserContext) -> String {
    kam_core::env::expand_for(target, user)
}

/// Whether a named target is there: yes, no, or why that could not be told.
type Exists<'a> = &'a dyn Fn(&str) -> std::io::Result<bool>;

fn on_disk(path: &str) -> std::io::Result<bool> {
    Path::new(path).try_exists()
}

/// What is known about where a shortcut leads: whether its target is known to
/// be gone, and otherwise why that could not be established, if it could not.
///
/// Three things have to hold before a target is called gone. The shortcut was
/// read. It was read as the person it belongs to, which a caller with no SID
/// is (see [`UserContext`]): for anybody else the shell's answer and the
/// drives in view are not that person's, as the top of this file sets out.
/// And Windows said plainly that the target is not there, rather than failing
/// to say. `Path::exists` hides that last difference, answering "no" for a
/// target it was not allowed to look at.
fn standing(link: &Link, user: &UserContext, exists: Exists) -> (bool, Option<String>) {
    if let Some(why) = link.unread {
        return (false, Some(why.to_owned()));
    }
    // No file target at all is not broken: Store entries and control-panel
    // items legitimately have none.
    let Some(target) = link.target.as_deref() else {
        return (false, None);
    };
    if user.sid().is_some() {
        return (
            false,
            Some(
                "it was read by the service, which cannot tell whether your shortcuts \
                 still lead anywhere"
                    .to_owned(),
            ),
        );
    }
    match exists(target) {
        Ok(true) => (false, None),
        Ok(false) => (true, None),
        Err(error) => (
            false,
            Some(format!(
                "Windows would not say whether {target} is still there: {error}"
            )),
        ),
    }
}

fn folder(base: &str, tail: &str) -> Option<PathBuf> {
    if base.is_empty() {
        return None;
    }
    let path = PathBuf::from(base).join(tail);
    path.is_dir().then_some(path)
}

fn machine(variable: &str, tail: &str) -> Option<PathBuf> {
    folder(&std::env::var(variable).ok()?, tail)
}

/// Every place Windows keeps shortcuts, and who they belong to.
///
/// The per-user places come from `user` rather than the environment. Read from
/// the environment inside the agent they would be LocalSystem's Start Menu and
/// LocalSystem's desktop, both of which are empty.
fn places(user: &UserContext) -> Vec<(PathBuf, Place, bool)> {
    let mut found = Vec::new();
    let roaming = user.roaming_app_data();

    if let Some(path) = folder(&roaming, r"Microsoft\Windows\Start Menu\Programs") {
        found.push((path, Place::StartMenu, false));
    }
    if let Some(path) = machine("ProgramData", r"Microsoft\Windows\Start Menu\Programs") {
        found.push((path, Place::StartMenu, true));
    }
    if let Some(path) = folder(user.profile(), "Desktop") {
        found.push((path, Place::Desktop, false));
    }
    if let Some(path) = machine("PUBLIC", "Desktop") {
        found.push((path, Place::Desktop, true));
    }
    if let Some(path) = folder(
        &roaming,
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
///
/// Empty when Windows would not let shortcuts be read at all, which a caller
/// that must not mistake for "there are none" asks [`try_all`] about instead.
pub fn all(user: &UserContext) -> Vec<Shortcut> {
    try_all(user).unwrap_or_default()
}

/// Every shortcut on this machine, or `None` when none could be read.
pub fn try_all(user: &UserContext) -> Option<Vec<Shortcut>> {
    let _com = ComGuard::enter()?;

    let mut shortcuts = Vec::new();
    for (folder, place, machine_wide) in places(user) {
        let mut files = Vec::new();
        walk(&folder, 0, &mut files);

        for file in files {
            let link = read_link(&file, user);
            let (broken, target_unknown) = standing(&link, user, &on_disk);
            shortcuts.push(Shortcut {
                name: file
                    .file_stem()
                    .map(|stem| stem.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                broken,
                target_unknown,
                bytes: std::fs::metadata(&file).map(|data| data.len()).unwrap_or(0),
                path: file.display().to_string(),
                place,
                machine_wide,
                target: link.target,
                app_id: link.app_id,
            });
        }
    }
    Some(shortcuts)
}

fn canonical(path: &str) -> String {
    path.to_lowercase()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_owned()
}

/// Shortcuts that point inside any of `roots`.
///
/// Used after an uninstall: the application's own measured directories are the
/// roots, so this finds the Start Menu folder and desktop icon belonging to
/// the thing just removed, without guessing from its name.
pub fn pointing_into(roots: &[String], user: &UserContext) -> Vec<Shortcut> {
    if roots.is_empty() {
        return Vec::new();
    }
    let roots: Vec<String> = roots.iter().map(|root| canonical(root)).collect();

    all(user)
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

/// Real shortcuts in a scratch profile, for tests here and in the leftover
/// check that reads them.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub(crate) mod testing {
    use super::*;

    /// A throwaway profile with a Desktop, and a folder standing in for a
    /// program's own. Under the temporary directory, and removed on drop.
    pub(crate) struct Scratch {
        root: PathBuf,
    }

    impl Scratch {
        pub(crate) fn new(tag: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("kam-shortcuts-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("profile").join("Desktop")).unwrap();
            std::fs::create_dir_all(root.join("program")).unwrap();
            Self { root }
        }

        /// Somebody running as themselves, whose profile is the scratch one.
        pub(crate) fn user(&self) -> UserContext {
            UserContext::new(None, &self.root.join("profile").to_string_lossy())
        }

        /// The folder the made-up program was installed into.
        pub(crate) fn program(&self) -> PathBuf {
            self.root.join("program")
        }

        pub(crate) fn desktop(&self) -> PathBuf {
            self.root.join("profile").join("Desktop")
        }

        /// A shortcut on the scratch Desktop pointing at `target`, written by
        /// Windows' own shell the way an installer writes one. False where the
        /// shell would not, in which case there is nothing to test with.
        pub(crate) fn shortcut(&self, name: &str, target: &Path) -> bool {
            let Some(_com) = ComGuard::enter() else {
                return false;
            };
            let Ok(link) = (unsafe {
                CoCreateInstance::<_, IShellLinkW>(&ShellLink, None, CLSCTX_INPROC_SERVER)
            }) else {
                return false;
            };
            let target = wide(target);
            if unsafe { link.SetPath(PCWSTR(target.as_ptr())) }.is_err() {
                return false;
            }
            let Ok(file) = link.cast::<IPersistFile>() else {
                return false;
            };
            let lnk = wide(&self.desktop().join(format!("{name}.lnk")));
            unsafe { file.Save(PCWSTR(lnk.as_ptr()), true) }.is_ok()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn link_to(target: &str) -> Link {
        Link {
            target: Some(target.to_owned()),
            app_id: None,
            unread: None,
        }
    }

    fn the_person() -> UserContext {
        UserContext::new(None, r"C:\Users\someone")
    }

    /// The agent's view of the same person: identified by SID, from outside.
    fn the_service_asking_for_them() -> UserContext {
        UserContext::new(Some("S-1-5-21-1-2-3-1001".to_owned()), r"C:\Users\someone")
    }

    #[test]
    fn a_target_is_only_called_gone_when_windows_says_it_is_not_there() {
        let target = r"C:\Program Files\Thing\thing.exe";

        let there = standing(&link_to(target), &the_person(), &|_| Ok(true));
        assert_eq!(there, (false, None));

        let gone = standing(&link_to(target), &the_person(), &|_| Ok(false));
        assert_eq!(gone, (true, None));

        // Not allowed to look is not "not there". `Path::exists` answers
        // false for both, which is how a target behind a folder this account
        // may not open came to be called gone.
        let denied = standing(&link_to(target), &the_person(), &|_| {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        });
        assert!(
            !denied.0,
            "a target that could not be checked was called gone"
        );
        let why = denied.1.expect("it should say what could not be told");
        assert!(why.contains(target), "{why}");
    }

    #[test]
    fn a_shortcut_that_would_not_open_is_not_one_with_no_target() {
        // A Store entry has no file target and that is all there is to say.
        let store_entry = Link::default();
        assert_eq!(
            standing(&store_entry, &the_person(), &|_| Ok(false)),
            (false, None)
        );

        let unread = Link::unread("the shortcut would not open");
        let (broken, why) = standing(&unread, &the_person(), &|_| Ok(false));
        assert!(!broken);
        assert_eq!(why.as_deref(), Some("the shortcut would not open"));
    }

    /// The service never calls a person's shortcut broken.
    ///
    /// The shell answers for the account that asks, and whether a target is
    /// there depends on the session's drives. Asked as LocalSystem, both are
    /// the service's. So for a caller identified from outside, which is what
    /// the agent holds, the answer is that it was not established, whatever
    /// the disk says to the service.
    #[test]
    fn a_shortcut_read_by_the_service_is_never_called_gone() {
        let target = r"C:\Users\someone\AppData\Local\Thing\thing.exe";
        let asked = std::cell::Cell::new(false);
        let (broken, why) = standing(&link_to(target), &the_service_asking_for_them(), &|_| {
            asked.set(true);
            Ok(false)
        });

        assert!(!broken, "the service called somebody's shortcut gone");
        assert!(
            why.is_some_and(|why| why.contains("service")),
            "it should say who read it"
        );
        assert!(!asked.get(), "the service's view of the disk was consulted");
    }

    /// `%LOCALAPPDATA%` in somebody's shortcut is theirs.
    ///
    /// It was filled in from the reading process's environment, which in the
    /// agent is LocalSystem's: a shortcut to a program in a person's AppData
    /// came out pointing into `C:\Windows\system32\config\systemprofile`.
    #[test]
    fn a_stored_target_is_filled_in_for_the_person_it_belongs_to() {
        let them = the_service_asking_for_them();
        assert_eq!(
            expanded_for(r"%LOCALAPPDATA%\Programs\Thing\thing.exe", &them),
            r"C:\Users\someone\AppData\Local\Programs\Thing\thing.exe"
        );
        assert_eq!(
            expanded_for(r"%USERPROFILE%\Desktop\tool.exe", &them),
            r"C:\Users\someone\Desktop\tool.exe"
        );
        // What is the same for everybody still comes from the machine.
        let windows = std::env::var("windir").unwrap();
        assert_eq!(
            expanded_for(r"%windir%\system32\magnify.exe", &them),
            format!(r"{windows}\system32\magnify.exe")
        );
    }

    /// Real shortcuts, written and read back by Windows' shell, as the person.
    ///
    /// One points at a file that is there and one at a file that is not, both
    /// inside a folder standing in for a program's own.
    #[test]
    fn a_real_shortcut_is_called_gone_only_when_its_target_is() {
        let scratch = testing::Scratch::new("standing");
        let present = scratch.program().join("thing.exe");
        std::fs::write(&present, b"not really a program").unwrap();
        let absent = scratch.program().join("removed.exe");
        if !scratch.shortcut("Thing", &present) || !scratch.shortcut("Removed", &absent) {
            // The shell would not write a shortcut here; nothing to show.
            return;
        }

        let found = try_all(&scratch.user()).expect("shortcuts should be readable");
        let named = |name: &str| {
            found
                .iter()
                .find(|shortcut| shortcut.name == name && shortcut.place == Place::Desktop)
                .unwrap_or_else(|| panic!("{name} was not found on the scratch Desktop"))
        };

        let thing = named("Thing");
        assert!(
            !thing.broken,
            "a shortcut to a file that is there was called gone"
        );
        assert_eq!(thing.target_unknown, None);
        assert_eq!(
            thing.target.as_deref().map(str::to_lowercase),
            Some(present.to_string_lossy().to_lowercase())
        );

        let removed = named("Removed");
        assert!(
            removed.broken,
            "a shortcut to a file that is gone was not noticed"
        );
        assert_eq!(removed.target_unknown, None);
    }

    #[test]
    fn this_machine_has_shortcuts_that_resolve() {
        // Every Windows install has a Start Menu full of them. Finding none, or
        // finding them all without targets, means the reading is broken rather
        // than the machine unusual.
        let shortcuts = all(&kam_core::UserContext::current());
        println!("{} shortcuts", shortcuts.len());
        assert!(!shortcuts.is_empty(), "no shortcuts at all");

        let resolved = shortcuts.iter().filter(|s| s.target.is_some()).count();
        let broken = shortcuts.iter().filter(|s| s.broken).count();
        let unknown = shortcuts
            .iter()
            .filter(|s| s.target_unknown.is_some())
            .count();
        println!(
            "{resolved} have a file target, {broken} point at something missing, \
             {unknown} could not be established"
        );
        for shortcut in shortcuts
            .iter()
            .filter(|s| s.target_unknown.is_some())
            .take(5)
        {
            println!(
                "  NOT ESTABLISHED [{}] {}: {}",
                shortcut.place.label(),
                shortcut.name,
                shortcut.target_unknown.as_deref().unwrap_or("?")
            );
        }
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
        let matches = pointing_into(
            std::slice::from_ref(&root),
            &kam_core::UserContext::current(),
        );
        println!("{} shortcuts point inside {root}", matches.len());
        for shortcut in matches.iter().take(5) {
            println!(
                "  {} -> {}",
                shortcut.name,
                shortcut.target.as_deref().unwrap_or("?")
            );
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
        assert!(pointing_into(&[], &kam_core::UserContext::current()).is_empty());
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
        assert!(
            sibling.starts_with(&root),
            "the naive check would have matched"
        );
    }
}
