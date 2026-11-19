//! What a shortcut stores, read from the file rather than asked of Windows.
//!
//! # Why the service does not ask Windows
//!
//! Windows' own reader answers for whoever asks. A shortcut whose target is
//! inside one of the folders Windows keeps for each account, such as the
//! Desktop, is stored relative to that folder, and the shell places it under
//! the asking account's own. Asked inside the service, that is LocalSystem's:
//! a Startup item starting a program from somebody's Desktop came back as a
//! path under the service's own profile, where nothing is, and was written
//! down as an item whose target could not be told.
//!
//! The window can ask as the person, and the Applications page does. The
//! watcher has no window to ask. So the service reads what the shortcut
//! stores, in the format Windows documents for it ([MS-SHLLINK]), and places a
//! target kept relative to one of the person's folders where that folder is
//! for them, as their own registry says. Where that cannot be done it says
//! why. It never guesses, and it asks Windows to resolve, search for or repair
//! nothing.
//!
//! # What is read
//!
//! - A target stored with variables in it, such as `%windir%\system32\x.exe`,
//!   is handed back as stored, for the caller to fill in as the right person.
//! - A target kept relative to one of a person's folders is placed under that
//!   folder as it is for them now. The shortcut says which folder and how far
//!   along its list of items the folder ends; the rest of the way is the same
//!   number of folder names at the end of the path it was saved with.
//! - Anything else is the path the shortcut was saved with, which is the same
//!   for every account.
//!
//! [MS-SHLLINK]: https://learn.microsoft.com/openspecs/windows_protocols/ms-shllink

use std::io::Read;
use std::path::Path;

use kam_core::registry::{self, View};
use kam_core::UserContext;
use windows::core::GUID;
use windows::Win32::UI::Shell as shell;

/// Far larger than any shortcut Windows writes. A file this size in a Startup
/// folder is not read whole into the service.
const LARGEST: u64 = 1024 * 1024;

/// Every shortcut begins with its own size, which is this.
const HEADER_SIZE: usize = 0x4C;

/// `{00021401-0000-0000-C000-000000000046}`, the class every shortcut names
/// straight after its size, as it lies in the file.
const LINK_CLASS: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

// What the shortcut says it holds.
const HAS_ITEMS: u32 = 0x1;
const HAS_LINK_INFO: u32 = 0x2;
const HAS_NAME: u32 = 0x4;
const HAS_RELATIVE_PATH: u32 = 0x8;
const HAS_WORKING_DIRECTORY: u32 = 0x10;
const HAS_ARGUMENTS: u32 = 0x20;
const HAS_ICON_LOCATION: u32 = 0x40;
const IS_UNICODE: u32 = 0x80;
const FORCE_NO_LINK_INFO: u32 = 0x100;
const HAS_INSTALLER_ID: u32 = 0x1000;
const DISABLE_KNOWN_FOLDER_TRACKING: u32 = 0x20_0000;

// The two halves of the record of where the target was when it was saved.
const LOCAL_PATH: u32 = 0x1;
const NETWORK_PATH: u32 = 0x2;
/// `DRIVE_REMOTE`, a drive letter that is a network share.
const NETWORK_DRIVE: u32 = 4;

// The extra blocks this reads, by the signature each begins with.
const VARIABLES_BLOCK: u32 = 0xA000_0001;
const SPECIAL_FOLDER_BLOCK: u32 = 0xA000_0005;
const KNOWN_FOLDER_BLOCK: u32 = 0xA000_000B;

/// Where the per-account folders are recorded, under each account's own hive.
const SHELL_FOLDERS: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";

/// What a shortcut in a Startup folder runs, as a command line: its target,
/// quoted, then its arguments.
///
/// `owner` is the person whose Startup folder it is in, `None` for the folder
/// everybody shares. `Ok(None)` for a shortcut that names no file at all. An
/// error is why what it runs could not be told, in words that finish "could
/// not tell what it runs:".
///
/// A target stored with variables comes back with them in, to be filled in by
/// the caller for the right person.
pub fn command(lnk: &Path, owner: Option<&UserContext>) -> Result<Option<String>, String> {
    command_with(lnk, owner, SHELL_FOLDERS)
}

/// The same, looking up a person's folders under `shell_folders` in their
/// hive. Apart so that a test can point it at a scratch key.
fn command_with(
    lnk: &Path,
    owner: Option<&UserContext>,
    shell_folders: &str,
) -> Result<Option<String>, String> {
    let mut bytes = Vec::new();
    std::fs::File::open(lnk)
        .and_then(|file| file.take(LARGEST + 1).read_to_end(&mut bytes))
        .map_err(|error| format!("the shortcut could not be read ({error})"))?;
    if bytes.len() as u64 > LARGEST {
        return Err("the file is far larger than any shortcut, so it was not read".to_owned());
    }
    let stored = parse(&bytes).ok_or_else(|| {
        "the shortcut is not whole, or not in a form that could be read".to_owned()
    })?;
    let Some(target) = target(&stored, owner, shell_folders)? else {
        return Ok(None);
    };
    Ok(Some(if stored.arguments.is_empty() {
        format!("\"{target}\"")
    } else {
        format!("\"{target}\" {}", stored.arguments)
    }))
}

/// A folder a target is kept relative to, as the shortcut names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Folder {
    /// By the id Windows has named its folders by since Vista.
    Known(GUID),
    /// By the number older versions of Windows used.
    Special(u32),
}

/// What one shortcut holds that says where it leads.
#[derive(Debug, Default)]
struct Stored {
    flags: u32,
    /// Where each item of the target's list starts, counted from the start of
    /// the list, and where the list ends.
    items: Vec<usize>,
    end: usize,
    /// The path the target had when the shortcut was saved.
    path: Option<String>,
    /// True when that path is on a network drive, or only a network path was
    /// kept. A network drive belongs to the session that connected it.
    network: bool,
    arguments: String,
    /// The target as stored with variables in it, when it was.
    expandable: Option<String>,
    /// The folder the target is kept relative to, and how far into the list
    /// of items that folder's part goes.
    known: Option<(Folder, usize)>,
    special: Option<(Folder, usize)>,
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn units(bytes: &[u8]) -> Vec<u16> {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect()
}

/// Text in UTF-16, up to the first NUL. `None` if there is no NUL, or the
/// text is not text.
fn wide_text(bytes: &[u8]) -> Option<String> {
    let units = units(bytes);
    let end = units.iter().position(|unit| *unit == 0)?;
    String::from_utf16(&units[..end]).ok()
}

/// Text in the machine's own code page, up to the first NUL if `terminated`.
///
/// The machine's, not anybody's: the code page Windows writes these in is
/// one setting for the whole machine, so the service reads them as the
/// person's shell would.
fn narrow_text(bytes: &[u8], terminated: bool) -> Option<String> {
    use windows::Win32::Globalization::{MultiByteToWideChar, CP_ACP, MB_ERR_INVALID_CHARS};

    let text = if terminated {
        &bytes[..bytes.iter().position(|byte| *byte == 0)?]
    } else {
        bytes
    };
    if text.is_empty() {
        return Some(String::new());
    }
    let length = unsafe { MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, text, None) };
    if length <= 0 {
        return None;
    }
    let mut units = vec![0_u16; length as usize];
    let written =
        unsafe { MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, text, Some(&mut units)) };
    if written != length {
        return None;
    }
    String::from_utf16(&units).ok()
}

/// Take a shortcut apart. `None` when it is not one, or is not whole.
///
/// Every length and position is checked against what is there, because the
/// file is written by whoever put it in the Startup folder.
fn parse(bytes: &[u8]) -> Option<Stored> {
    if u32_at(bytes, 0)? as usize != HEADER_SIZE || bytes.get(4..20)? != LINK_CLASS {
        return None;
    }
    let mut stored = Stored {
        flags: u32_at(bytes, 0x14)?,
        ..Stored::default()
    };
    let mut at = HEADER_SIZE;

    if stored.flags & HAS_ITEMS != 0 {
        let size = usize::from(u16_at(bytes, at)?);
        let list = bytes.get(at + 2..at + 2 + size)?;
        let mut item = 0;
        loop {
            let length = usize::from(u16_at(list, item)?);
            if length == 0 {
                break;
            }
            if length < 2 {
                return None;
            }
            stored.items.push(item);
            item += length;
        }
        stored.end = item;
        at += 2 + size;
    }

    if stored.flags & HAS_LINK_INFO != 0 {
        let size = u32_at(bytes, at)? as usize;
        let info = bytes.get(at..at.checked_add(size)?)?;
        if stored.flags & FORCE_NO_LINK_INFO == 0 {
            read_link_info(info, &mut stored)?;
        }
        at += size;
    }

    let unicode = stored.flags & IS_UNICODE != 0;
    for flag in [
        HAS_NAME,
        HAS_RELATIVE_PATH,
        HAS_WORKING_DIRECTORY,
        HAS_ARGUMENTS,
        HAS_ICON_LOCATION,
    ] {
        if stored.flags & flag == 0 {
            continue;
        }
        let count = usize::from(u16_at(bytes, at)?);
        let length = if unicode { count * 2 } else { count };
        let raw = bytes.get(at + 2..at + 2 + length)?;
        if flag == HAS_ARGUMENTS {
            stored.arguments = if unicode {
                String::from_utf16(&units(raw)).ok()?
            } else {
                narrow_text(raw, false)?
            }
            .trim()
            .to_owned();
        }
        at += 2 + length;
    }

    // The extra blocks, to the empty one that ends them. A shortcut cut short
    // before it is not taken as having none: the block that is missing could
    // be the one that says the target is kept relative to somebody's folder.
    loop {
        let size = u32_at(bytes, at)? as usize;
        if size < 4 {
            break;
        }
        let block = bytes.get(at..at.checked_add(size)?)?;
        match u32_at(block, 4)? {
            VARIABLES_BLOCK => {
                let unicode = block.get(0x10C..0x314).and_then(wide_text);
                let narrow = block.get(8..0x10C).and_then(|raw| narrow_text(raw, true));
                stored.expandable = unicode
                    .filter(|text| !text.is_empty())
                    .or(narrow)
                    .filter(|text| !text.is_empty());
            }
            KNOWN_FOLDER_BLOCK => {
                let id = block.get(8..24)?;
                let id = GUID::from_values(
                    u32_at(id, 0)?,
                    u16_at(id, 4)?,
                    u16_at(id, 6)?,
                    id.get(8..16)?.try_into().ok()?,
                );
                stored.known = Some((Folder::Known(id), u32_at(block, 24)? as usize));
            }
            SPECIAL_FOLDER_BLOCK => {
                stored.special = Some((
                    Folder::Special(u32_at(block, 8)?),
                    u32_at(block, 12)? as usize,
                ));
            }
            _ => {}
        }
        at += size;
    }
    Some(stored)
}

/// The record of where the target was when the shortcut was saved.
fn read_link_info(info: &[u8], stored: &mut Stored) -> Option<()> {
    let header = u32_at(info, 4)? as usize;
    let flags = u32_at(info, 8)?;
    let at = |offset: u32| info.get(offset as usize..);
    // Positions of the same two pieces of text in UTF-16, which newer
    // versions of Windows add after the older positions.
    let wide = |position: usize| {
        (header >= 0x24)
            .then(|| u32_at(info, position))
            .flatten()
            .filter(|offset| *offset != 0)
            .and_then(at)
            .and_then(wide_text)
    };

    if flags & LOCAL_PATH != 0 {
        let volume = u32_at(info, 12)?;
        stored.network = u32_at(at(volume)?, 4)? == NETWORK_DRIVE;
        let base = match wide(28) {
            Some(base) => base,
            None => narrow_text(at(u32_at(info, 16)?)?, true)?,
        };
        let suffix = match wide(32) {
            Some(suffix) => suffix,
            None => narrow_text(at(u32_at(info, 24)?)?, true)?,
        };
        stored.path = Some(format!("{base}{suffix}"));
    } else if flags & NETWORK_PATH != 0 {
        stored.network = true;
    }
    Some(())
}

/// Where a shortcut leads, for `owner`: `Ok(None)` when it names no file.
fn target(
    stored: &Stored,
    owner: Option<&UserContext>,
    shell_folders: &str,
) -> Result<Option<String>, String> {
    if stored.flags & HAS_INSTALLER_ID != 0 {
        return Err(
            "it is a Windows Installer shortcut, and Windows Installer decides what \
                    it runs when it is used"
                .to_owned(),
        );
    }
    // What Windows itself reads first, when the shortcut has it.
    if let Some(expandable) = &stored.expandable {
        return Ok(Some(expandable.clone()));
    }
    let relative = if stored.flags & DISABLE_KNOWN_FOLDER_TRACKING != 0 {
        None
    } else {
        stored.known.or(stored.special)
    };
    let Some((folder, offset)) = relative else {
        return absolute(stored);
    };

    let Some(id) = known_id(folder) else {
        return Err(format!(
            "it is kept relative to a folder Windows numbers {}, which the service does not \
             know how to find",
            match folder {
                Folder::Special(number) => number.to_string(),
                Folder::Known(id) => braced(id),
            }
        ));
    };
    if MACHINE_FOLDERS.contains(&id) {
        return absolute(stored);
    }
    let Some(called) = personal(id)
        .map(|folder| folder.called)
        .or_else(|| is_profile(id).then_some("the profile folder"))
    else {
        return Err(format!(
            "it is kept relative to a folder Windows knows as {}, and where that is for \
             the account is not something the service can look up",
            braced(id)
        ));
    };
    let Some(user) = owner else {
        return Err(format!(
            "it leads into {called} of whoever signs in, so what it runs depends on who \
             that is"
        ));
    };
    let base = place_for(id, user, shell_folders)?;
    let rest = remainder(stored, offset).ok_or_else(|| {
        format!(
            "it is kept relative to {called}, and the rest of the way is not stored in a \
             form that could be read"
        )
    })?;
    Ok(Some(if rest.is_empty() {
        base
    } else {
        format!(r"{base}\{rest}")
    }))
}

/// The path a shortcut was saved with, which is the same whoever reads it.
fn absolute(stored: &Stored) -> Result<Option<String>, String> {
    if stored.network {
        return Err(
            "it leads to a network location, which belongs to the session that \
                    connected it"
                .to_owned(),
        );
    }
    match &stored.path {
        Some(path) if !path.is_empty() => Ok(Some(path.clone())),
        // No list of items and no path: nothing on disk is named at all.
        _ if stored.flags & HAS_ITEMS == 0 => Ok(None),
        _ => Err("it does not name a file in a form the service reads".to_owned()),
    }
}

/// The folder names after a known folder's part of the list of items, taken
/// from the end of the path the shortcut was saved with: one name for each
/// item. `None` when the two do not fit together.
fn remainder(stored: &Stored, offset: usize) -> Option<String> {
    if offset != stored.end && !stored.items.contains(&offset) {
        return None;
    }
    let after = stored.items.iter().filter(|item| **item >= offset).count();
    let path = stored.path.as_deref()?;
    let names: Vec<&str> = path.split('\\').filter(|name| !name.is_empty()).collect();
    // At least one name, the drive, has to be left over for the folder.
    if after >= names.len() {
        return None;
    }
    Some(names[names.len() - after..].join("\\"))
}

/// A folder's id, whichever way the shortcut named it.
fn known_id(folder: Folder) -> Option<GUID> {
    match folder {
        Folder::Known(id) => Some(id),
        Folder::Special(number) => SPECIAL_FOLDERS
            .iter()
            .find(|(special, _)| *special == number & 0xFF)
            .map(|(_, id)| *id),
    }
}

fn braced(id: GUID) -> String {
    format!("{{{id:?}}}")
}

/// Whether a folder is the person's own profile folder.
///
/// Two ids come to it. The second is the profile as the shell shows it, as
/// the folder named for the person, and it is the one Windows' own shell
/// keeps a target by when nothing nearer holds it: a program in a person's
/// AppData, written down by Windows on the machine this was found on.
fn is_profile(id: GUID) -> bool {
    id == shell::FOLDERID_Profile || id == shell::FOLDERID_UsersFiles
}

/// The older numbers for the folders below, as the shortcut's older block
/// names them.
const SPECIAL_FOLDERS: [(u32, GUID); 27] = [
    (shell::CSIDL_DESKTOP, shell::FOLDERID_Desktop),
    (shell::CSIDL_DESKTOPDIRECTORY, shell::FOLDERID_Desktop),
    (shell::CSIDL_PERSONAL, shell::FOLDERID_Documents),
    (shell::CSIDL_MYMUSIC, shell::FOLDERID_Music),
    (shell::CSIDL_MYPICTURES, shell::FOLDERID_Pictures),
    (shell::CSIDL_MYVIDEO, shell::FOLDERID_Videos),
    (shell::CSIDL_APPDATA, shell::FOLDERID_RoamingAppData),
    (shell::CSIDL_LOCAL_APPDATA, shell::FOLDERID_LocalAppData),
    (shell::CSIDL_FAVORITES, shell::FOLDERID_Favorites),
    (shell::CSIDL_STARTMENU, shell::FOLDERID_StartMenu),
    (shell::CSIDL_PROGRAMS, shell::FOLDERID_Programs),
    (shell::CSIDL_STARTUP, shell::FOLDERID_Startup),
    (shell::CSIDL_PROFILE, shell::FOLDERID_Profile),
    (shell::CSIDL_WINDOWS, shell::FOLDERID_Windows),
    (shell::CSIDL_SYSTEM, shell::FOLDERID_System),
    (shell::CSIDL_SYSTEMX86, shell::FOLDERID_SystemX86),
    (shell::CSIDL_PROGRAM_FILES, shell::FOLDERID_ProgramFiles),
    (
        shell::CSIDL_PROGRAM_FILESX86,
        shell::FOLDERID_ProgramFilesX86,
    ),
    (
        shell::CSIDL_PROGRAM_FILES_COMMON,
        shell::FOLDERID_ProgramFilesCommon,
    ),
    (
        shell::CSIDL_PROGRAM_FILES_COMMONX86,
        shell::FOLDERID_ProgramFilesCommonX86,
    ),
    (shell::CSIDL_COMMON_APPDATA, shell::FOLDERID_ProgramData),
    (
        shell::CSIDL_COMMON_DESKTOPDIRECTORY,
        shell::FOLDERID_PublicDesktop,
    ),
    (
        shell::CSIDL_COMMON_DOCUMENTS,
        shell::FOLDERID_PublicDocuments,
    ),
    (
        shell::CSIDL_COMMON_STARTMENU,
        shell::FOLDERID_CommonStartMenu,
    ),
    (shell::CSIDL_COMMON_PROGRAMS, shell::FOLDERID_CommonPrograms),
    (shell::CSIDL_COMMON_STARTUP, shell::FOLDERID_CommonStartup),
    (shell::CSIDL_COMMON_MUSIC, shell::FOLDERID_PublicMusic),
];

/// Folders that are in the same place for every account, so the path the
/// shortcut was saved with is where it leads whoever reads it. This PC is
/// among them: under it are the drives, and a drive that is a network share,
/// which is a session's own, is told apart by the path's record of its drive.
const MACHINE_FOLDERS: [GUID; 19] = [
    shell::FOLDERID_ComputerFolder,
    shell::FOLDERID_Windows,
    shell::FOLDERID_System,
    shell::FOLDERID_SystemX86,
    shell::FOLDERID_ProgramFiles,
    shell::FOLDERID_ProgramFilesX64,
    shell::FOLDERID_ProgramFilesX86,
    shell::FOLDERID_ProgramFilesCommon,
    shell::FOLDERID_ProgramFilesCommonX64,
    shell::FOLDERID_ProgramFilesCommonX86,
    shell::FOLDERID_ProgramData,
    shell::FOLDERID_Public,
    shell::FOLDERID_PublicDesktop,
    shell::FOLDERID_PublicDocuments,
    shell::FOLDERID_PublicDownloads,
    shell::FOLDERID_PublicMusic,
    shell::FOLDERID_CommonStartMenu,
    shell::FOLDERID_CommonPrograms,
    shell::FOLDERID_CommonStartup,
];

/// How a person's `User Shell Folders` names one of their folders.
#[derive(Debug, Clone, Copy)]
enum Named {
    /// Windows' older folders go by a name of their own.
    As(&'static str),
    /// The newer go by their id, in braces.
    ById,
}

/// One of the folders Windows keeps for each account, and how to find where
/// it is for one person.
struct Personal {
    id: GUID,
    /// The folder in a sentence.
    called: &'static str,
    named: Named,
    /// Where it is when the person's registry does not say, which is where
    /// Windows itself puts it then: a folder inside another of these.
    default: (GUID, &'static str),
}

const PERSONAL: [Personal; 15] = [
    Personal {
        id: shell::FOLDERID_Desktop,
        called: "the Desktop",
        named: Named::As("Desktop"),
        default: (shell::FOLDERID_Profile, "Desktop"),
    },
    Personal {
        id: shell::FOLDERID_Documents,
        called: "the Documents folder",
        named: Named::As("Personal"),
        default: (shell::FOLDERID_Profile, "Documents"),
    },
    Personal {
        id: shell::FOLDERID_Downloads,
        called: "the Downloads folder",
        named: Named::ById,
        default: (shell::FOLDERID_Profile, "Downloads"),
    },
    Personal {
        id: shell::FOLDERID_Music,
        called: "the Music folder",
        named: Named::As("My Music"),
        default: (shell::FOLDERID_Profile, "Music"),
    },
    Personal {
        id: shell::FOLDERID_Pictures,
        called: "the Pictures folder",
        named: Named::As("My Pictures"),
        default: (shell::FOLDERID_Profile, "Pictures"),
    },
    Personal {
        id: shell::FOLDERID_Videos,
        called: "the Videos folder",
        named: Named::As("My Video"),
        default: (shell::FOLDERID_Profile, "Videos"),
    },
    Personal {
        id: shell::FOLDERID_RoamingAppData,
        called: "the AppData folder",
        named: Named::As("AppData"),
        default: (shell::FOLDERID_Profile, r"AppData\Roaming"),
    },
    Personal {
        id: shell::FOLDERID_LocalAppData,
        called: "the local AppData folder",
        named: Named::As("Local AppData"),
        default: (shell::FOLDERID_Profile, r"AppData\Local"),
    },
    Personal {
        id: shell::FOLDERID_LocalAppDataLow,
        called: "the low-integrity AppData folder",
        named: Named::ById,
        default: (shell::FOLDERID_Profile, r"AppData\LocalLow"),
    },
    Personal {
        id: shell::FOLDERID_Favorites,
        called: "the Favourites folder",
        named: Named::As("Favorites"),
        default: (shell::FOLDERID_Profile, "Favorites"),
    },
    Personal {
        id: shell::FOLDERID_StartMenu,
        called: "the Start Menu",
        named: Named::As("Start Menu"),
        default: (
            shell::FOLDERID_RoamingAppData,
            r"Microsoft\Windows\Start Menu",
        ),
    },
    Personal {
        id: shell::FOLDERID_Programs,
        called: "the Start Menu's programs",
        named: Named::As("Programs"),
        default: (shell::FOLDERID_StartMenu, "Programs"),
    },
    Personal {
        id: shell::FOLDERID_Startup,
        called: "the Startup folder",
        named: Named::As("Startup"),
        default: (shell::FOLDERID_Programs, "Startup"),
    },
    Personal {
        id: shell::FOLDERID_UserProgramFiles,
        called: "the folder of programs installed for one account",
        named: Named::ById,
        default: (shell::FOLDERID_LocalAppData, "Programs"),
    },
    Personal {
        id: shell::FOLDERID_SavedGames,
        called: "the Saved Games folder",
        named: Named::ById,
        default: (shell::FOLDERID_Profile, "Saved Games"),
    },
];

fn personal(id: GUID) -> Option<&'static Personal> {
    PERSONAL.iter().find(|folder| folder.id == id)
}

/// The value under `User Shell Folders` that says where `folder` is.
fn value_name(folder: &Personal) -> String {
    match folder.named {
        Named::As(name) => name.to_owned(),
        Named::ById => braced(folder.id),
    }
}

/// Where one of a person's folders is for them now, from their own registry.
///
/// Read from their hive, never from this process: inside the service every
/// one of these is LocalSystem's. A value that is there is where the folder
/// is; one that is not there leaves the folder where Windows puts it by
/// default. A record that could not be read is said, not stood in for.
fn place_for(id: GUID, user: &UserContext, shell_folders: &str) -> Result<String, String> {
    // Every chain in the table is a few folders long and ends at the profile.
    // The bound is a safeguard against a mistake in it, not a limit on depth.
    let mut tail: Vec<&str> = Vec::new();
    let mut id = id;
    for _ in 0..8 {
        if is_profile(id) {
            return Ok(joined(user.profile(), &tail));
        }
        let Some(folder) = personal(id) else {
            break;
        };
        let unread = |why: String| {
            format!(
                "it is kept relative to {} of the account it belongs to, and where that is \
                 for them could not be read ({why})",
                folder.called
            )
        };
        let (hive, prefix) = user.hive();
        let key = registry::Key::look(hive, &format!("{prefix}{shell_folders}"), View::Native)
            .map_err(|why| unread(why.describe("their record of where their folders are")))?;
        let name = value_name(folder);
        match key.read_string(&name) {
            Ok(Some(stored)) => {
                let placed = kam_core::env::expand_for(&stored, user);
                if placed.contains('%') {
                    return Err(unread(format!(
                        "it is recorded as {stored}, which names something the service cannot \
                         fill in"
                    )));
                }
                return Ok(joined(placed.trim_end_matches('\\'), &tail));
            }
            Ok(None) => {
                let (parent, inside) = folder.default;
                tail.insert(0, inside);
                id = parent;
            }
            Err(why) => return Err(unread(why.describe(&name))),
        }
    }
    Err("it is kept relative to a folder whose place could not be worked out".to_owned())
}

fn joined(base: &str, tail: &[&str]) -> String {
    std::iter::once(base)
        .chain(tail.iter().copied())
        .collect::<Vec<_>>()
        .join("\\")
}

/// Shortcuts written by Windows' own shell and by hand, for tests here and in
/// the startup reader.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub(crate) mod testing {
    use std::path::Path;

    use super::*;

    /// A shortcut built byte by byte, so each way of storing a target can be
    /// read without depending on how this machine's shell writes one.
    #[derive(Debug, Clone, Default)]
    pub(crate) struct Built {
        /// How many items the target's list holds.
        pub(crate) items: usize,
        pub(crate) path: Option<String>,
        pub(crate) network_drive: bool,
        pub(crate) arguments: String,
        pub(crate) variables: Option<String>,
        /// The folder the target is kept relative to, and after how many of
        /// the items that folder's part ends.
        pub(crate) known: Option<(GUID, usize)>,
        pub(crate) special: Option<(u32, usize)>,
        pub(crate) flags: u32,
        /// Leave off the empty block that ends the file.
        pub(crate) cut_short: bool,
    }

    const ITEM: usize = 12;

    impl Built {
        pub(crate) fn bytes(&self) -> Vec<u8> {
            let mut flags = self.flags | IS_UNICODE;
            if self.items > 0 {
                flags |= HAS_ITEMS;
            }
            if self.path.is_some() {
                flags |= HAS_LINK_INFO;
            }
            if !self.arguments.is_empty() {
                flags |= HAS_ARGUMENTS;
            }
            let mut out = Vec::new();
            out.extend((HEADER_SIZE as u32).to_le_bytes());
            out.extend(LINK_CLASS);
            out.extend(flags.to_le_bytes());
            out.resize(HEADER_SIZE, 0);

            if self.items > 0 {
                let mut list = Vec::new();
                for index in 0..self.items {
                    // What is in an item is Windows' business; only its
                    // length is read here.
                    list.extend((ITEM as u16).to_le_bytes());
                    list.push(0x31);
                    list.extend(std::iter::repeat_n(index as u8, ITEM - 3));
                }
                list.extend([0, 0]);
                out.extend((list.len() as u16).to_le_bytes());
                out.extend(list);
            }

            if let Some(path) = &self.path {
                let volume_at = 0x1C_u32;
                let volume: Vec<u8> = [
                    0x10_u32,
                    if self.network_drive { NETWORK_DRIVE } else { 3 },
                    0x1234,
                    0x10,
                ]
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect();
                let base_at = volume_at + volume.len() as u32;
                let mut base = path.as_bytes().to_vec();
                base.push(0);
                let suffix_at = base_at + base.len() as u32;
                let size = suffix_at + 1;
                for word in [size, 0x1C, LOCAL_PATH, volume_at, base_at, 0, suffix_at] {
                    out.extend(word.to_le_bytes());
                }
                out.extend(volume);
                out.extend(base);
                out.push(0);
            }

            if !self.arguments.is_empty() {
                let units: Vec<u16> = self.arguments.encode_utf16().collect();
                out.extend((units.len() as u16).to_le_bytes());
                out.extend(units.iter().flat_map(|unit| unit.to_le_bytes()));
            }

            if let Some(variables) = &self.variables {
                out.extend(0x314_u32.to_le_bytes());
                out.extend(VARIABLES_BLOCK.to_le_bytes());
                let mut narrow = variables.as_bytes().to_vec();
                narrow.resize(260, 0);
                out.extend(narrow);
                let mut wide: Vec<u8> = variables
                    .encode_utf16()
                    .flat_map(|unit| unit.to_le_bytes())
                    .collect();
                wide.resize(520, 0);
                out.extend(wide);
            }
            if let Some((id, after)) = self.known {
                out.extend(0x1C_u32.to_le_bytes());
                out.extend(KNOWN_FOLDER_BLOCK.to_le_bytes());
                out.extend(id.data1.to_le_bytes());
                out.extend(id.data2.to_le_bytes());
                out.extend(id.data3.to_le_bytes());
                out.extend(id.data4);
                out.extend(((after * ITEM) as u32).to_le_bytes());
            }
            if let Some((number, after)) = self.special {
                out.extend(0x10_u32.to_le_bytes());
                out.extend(SPECIAL_FOLDER_BLOCK.to_le_bytes());
                out.extend(number.to_le_bytes());
                out.extend(((after * ITEM) as u32).to_le_bytes());
            }
            if !self.cut_short {
                out.extend(0_u32.to_le_bytes());
            }
            out
        }
    }

    /// A Startup item kept relative to somebody's Desktop, as Explorer keeps
    /// one: saved when the Desktop was in OneDrive, which it no longer is.
    pub(crate) fn on_the_desktop() -> Built {
        Built {
            items: 5,
            path: Some(r"C:\Users\someone\OneDrive\Desktop\Projects\Tool\tool.exe".to_owned()),
            arguments: "--quiet".to_owned(),
            known: Some((shell::FOLDERID_Desktop, 2)),
            ..Built::default()
        }
    }

    /// A real shortcut, written the way Explorer writes one.
    pub(crate) fn written_by_windows(lnk: &Path, target: &Path, arguments: &str) {
        use windows::core::{Interface, HSTRING};
        use windows::Win32::System::Com::{
            CoCreateInstance, CoInitializeEx, CoUninitialize, IPersistFile, CLSCTX_INPROC_SERVER,
            COINIT_MULTITHREADED,
        };
        use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};

        let entered = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.is_ok();
        {
            let link: IShellLinkW =
                unsafe { CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER) }.unwrap();
            unsafe {
                link.SetPath(&HSTRING::from(target.as_os_str())).unwrap();
                link.SetArguments(&HSTRING::from(arguments)).unwrap();
            }
            let file: IPersistFile = link.cast().unwrap();
            unsafe { file.Save(&HSTRING::from(lnk.as_os_str()), true) }.unwrap();
        }
        if entered {
            unsafe { CoUninitialize() };
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::ERROR_SUCCESS;
    // Write entry points, used only to make the scratch key these tests read.
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegDeleteTreeW, RegSetValueExW, HKEY,
        HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    use super::testing::{on_the_desktop, Built};

    /// A folder under the temporary directory, removed when dropped.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "kam-shortcut-{tag}-{}-{}",
                std::process::id(),
                kam_core::clock::now_utc_iso().replace([':', '.'], "")
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn write(&self, name: &str, built: &Built) -> std::path::PathBuf {
            let lnk = self.0.join(name);
            std::fs::write(&lnk, built.bytes()).unwrap();
            lnk
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A stand-in for a person's `User Shell Folders`, under the test
    /// account's own `Software\KAM Security`, removed when dropped.
    struct ScratchFolders {
        path: String,
    }

    impl ScratchFolders {
        fn new(tag: &str) -> Self {
            let folders = Self {
                path: format!(
                    r"Software\KAM Security\test shell folders {tag} {}",
                    std::process::id()
                ),
            };
            folders.set("made by", "a test");
            folders
        }

        fn set(&self, name: &str, value: &str) {
            let path: Vec<u16> = self.path.encode_utf16().chain(std::iter::once(0)).collect();
            let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
            let data: Vec<u8> = value
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect();
            let mut handle = HKEY::default();
            unsafe {
                let made = RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    PCWSTR(path.as_ptr()),
                    None,
                    PWSTR::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_READ | KEY_WRITE,
                    None,
                    &mut handle,
                    None,
                );
                assert_eq!(made, ERROR_SUCCESS, "could not create {}", self.path);
                let set = RegSetValueExW(
                    handle,
                    PCWSTR(wide_name.as_ptr()),
                    None,
                    REG_SZ,
                    Some(&data),
                );
                let _ = RegCloseKey(handle);
                assert_eq!(set, ERROR_SUCCESS, "could not write {name}");
            }
        }
    }

    impl Drop for ScratchFolders {
        fn drop(&mut self) {
            let path: Vec<u16> = self.path.encode_utf16().chain(std::iter::once(0)).collect();
            unsafe {
                let _ = RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(path.as_ptr()));
                let _ = RegDeleteKeyW(HKEY_CURRENT_USER, PCWSTR(path.as_ptr()));
            }
        }
    }

    /// The test account itself, whose hive the scratch key is in.
    fn the_person() -> UserContext {
        UserContext::current()
    }

    /// A target kept relative to one of the person's folders is placed where
    /// that folder is for them now, as their own registry says, and never
    /// where it is for whoever is reading.
    ///
    /// The fault this was written for: read inside the service, a Startup
    /// item starting a program from somebody's Desktop was placed under the
    /// service's own Desktop, where nothing is.
    #[test]
    fn a_target_kept_by_a_persons_folder_is_placed_where_that_folder_is_for_them() {
        let scratch = Scratch::new("desktop");
        let folders = ScratchFolders::new("desktop");
        let lnk = scratch.write("Tool.lnk", &on_the_desktop());

        folders.set("Desktop", r"D:\Elsewhere\Desktop");
        assert_eq!(
            command_with(&lnk, Some(&the_person()), &folders.path),
            Ok(Some(
                r#""D:\Elsewhere\Desktop\Projects\Tool\tool.exe" --quiet"#.to_owned()
            ))
        );

        // Not there in the registry is where Windows puts it by default.
        let without = ScratchFolders::new("no desktop");
        assert_eq!(
            command_with(&lnk, Some(&the_person()), &without.path),
            Ok(Some(format!(
                r#""{}\Desktop\Projects\Tool\tool.exe" --quiet"#,
                the_person().profile()
            )))
        );

        // And a newer folder goes by its id.
        let downloads = Built {
            items: 3,
            path: Some(r"C:\Users\someone\Downloads\setup.exe".to_owned()),
            known: Some((shell::FOLDERID_Downloads, 2)),
            ..Built::default()
        };
        folders.set(&braced(shell::FOLDERID_Downloads), r"E:\Fetched");
        assert_eq!(
            command_with(
                &scratch.write("Setup.lnk", &downloads),
                Some(&the_person()),
                &folders.path
            ),
            Ok(Some(r#""E:\Fetched\setup.exe""#.to_owned()))
        );
    }

    /// Where the person's record of their folders cannot be read, the target
    /// could not be told, and the path the shortcut was saved with is not
    /// offered in its place: that is where the folder was, not where it is.
    #[test]
    fn a_persons_folder_that_cannot_be_looked_up_is_said_and_not_guessed() {
        let scratch = Scratch::new("unread");
        let lnk = scratch.write("Tool.lnk", &on_the_desktop());

        let missing = command_with(
            &lnk,
            Some(&the_person()),
            r"Software\KAM Security\no such key for a test",
        );
        let why = missing.expect_err("a folder nobody could look up was guessed at");
        assert!(why.contains("the Desktop"), "{why}");

        // Somebody whose hive is not loaded: the same, through the real key.
        let signed_out =
            UserContext::new(Some("S-1-5-21-0-0-0-31337".to_owned()), r"C:\Users\nobody");
        assert!(command(&lnk, Some(&signed_out)).is_err());

        // In the folder everybody shares, each person's Desktop is their own.
        let shared = command(&lnk, None).expect_err("one person's Desktop stood for everybody's");
        assert!(shared.contains("whoever signs in"), "{shared}");
    }

    /// A target stored with its variables is handed back as stored, for the
    /// caller to fill in as the right person.
    #[test]
    fn a_target_stored_with_variables_comes_back_as_stored() {
        let scratch = Scratch::new("variables");
        let built = Built {
            items: 4,
            path: Some(r"C:\Windows\System32\magnify.exe".to_owned()),
            variables: Some(r"%windir%\system32\magnify.exe".to_owned()),
            known: Some((shell::FOLDERID_Desktop, 0)),
            ..Built::default()
        };
        assert_eq!(
            command(&scratch.write("Magnify.lnk", &built), Some(&the_person())),
            Ok(Some(r#""%windir%\system32\magnify.exe""#.to_owned()))
        );
    }

    /// A target in a folder that is the same for everybody, or kept by no
    /// folder at all, is the path the shortcut was saved with.
    #[test]
    fn a_target_the_same_for_everybody_is_the_path_stored() {
        let scratch = Scratch::new("machine");
        let system = Built {
            items: 4,
            path: Some(r"C:\Windows\System32\cmd.exe".to_owned()),
            arguments: r#"/c "C:\Tools\go.cmd""#.to_owned(),
            known: Some((shell::FOLDERID_System, 3)),
            ..Built::default()
        };
        let expected = Ok(Some(
            r#""C:\Windows\System32\cmd.exe" /c "C:\Tools\go.cmd""#.to_owned(),
        ));
        assert_eq!(
            command(&scratch.write("Go.lnk", &system), Some(&the_person())),
            expected
        );
        assert_eq!(command(&scratch.write("Go.lnk", &system), None), expected);

        // The older way of naming a folder, the same.
        let older = Built {
            known: None,
            special: Some((shell::CSIDL_SYSTEM, 3)),
            ..system
        };
        assert_eq!(command(&scratch.write("Older.lnk", &older), None), expected);

        let plain = Built {
            items: 3,
            path: Some(r"D:\Games\game.exe".to_owned()),
            ..Built::default()
        };
        assert_eq!(
            command(&scratch.write("Game.lnk", &plain), None),
            Ok(Some(r#""D:\Games\game.exe""#.to_owned()))
        );
    }

    /// The older way of naming a person's folder is read the same way.
    #[test]
    fn a_persons_folder_named_the_older_way_is_placed_the_same() {
        let scratch = Scratch::new("older");
        let folders = ScratchFolders::new("older");
        folders.set("Desktop", r"D:\Elsewhere\Desktop");
        let older = Built {
            known: None,
            special: Some((shell::CSIDL_DESKTOPDIRECTORY, 2)),
            ..on_the_desktop()
        };
        assert_eq!(
            command_with(
                &scratch.write("Older.lnk", &older),
                Some(&the_person()),
                &folders.path
            ),
            Ok(Some(
                r#""D:\Elsewhere\Desktop\Projects\Tool\tool.exe" --quiet"#.to_owned()
            ))
        );
    }

    /// What cannot be told is said, each for its own reason.
    #[test]
    fn what_cannot_be_told_is_said_and_never_guessed() {
        let scratch = Scratch::new("untold");
        let person = the_person();

        let unknown = Built {
            known: Some((
                GUID::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef),
                2,
            )),
            ..on_the_desktop()
        };
        assert!(command(&scratch.write("Unknown.lnk", &unknown), Some(&person)).is_err());

        let network = Built {
            items: 2,
            path: Some(r"Z:\Shared\tool.exe".to_owned()),
            network_drive: true,
            ..Built::default()
        };
        let why = command(&scratch.write("Network.lnk", &network), Some(&person)).unwrap_err();
        assert!(why.contains("network"), "{why}");

        let installer = Built {
            flags: HAS_INSTALLER_ID,
            ..on_the_desktop()
        };
        assert!(command(&scratch.write("Installer.lnk", &installer), Some(&person)).is_err());

        // The block saying the target is kept by a folder could have been
        // the part that was cut off.
        let cut = Built {
            cut_short: true,
            known: None,
            ..on_the_desktop()
        };
        assert!(command(&scratch.write("Cut.lnk", &cut), Some(&person)).is_err());

        // A known folder that ends somewhere other than between two items.
        let bent = scratch.write("Bent.lnk", &on_the_desktop());
        let mut bytes = std::fs::read(&bent).unwrap();
        let block = bytes.len() - 8;
        bytes[block..block + 4].copy_from_slice(&5_u32.to_le_bytes());
        std::fs::write(&bent, bytes).unwrap();
        assert!(command(&bent, Some(&person)).is_err());

        let rubbish = scratch.0.join("Rubbish.lnk");
        std::fs::write(&rubbish, b"not a shortcut at all").unwrap();
        assert!(command(&rubbish, Some(&person)).is_err());
        assert!(command(&scratch.0.join("Absent.lnk"), Some(&person)).is_err());
    }

    /// A shortcut that names nothing on disk at all is not an error.
    #[test]
    fn a_shortcut_naming_nothing_on_disk_says_so() {
        let scratch = Scratch::new("nothing");
        assert_eq!(
            command(&scratch.write("Nothing.lnk", &Built::default()), None),
            Ok(None)
        );
    }

    /// Real shortcuts, written by Windows' own shell, read back to the file
    /// they point at.
    #[test]
    fn a_shortcut_written_by_windows_is_read_back_to_its_target() {
        let scratch = Scratch::new("real");
        let program = scratch.0.join("tool.exe");
        std::fs::write(&program, b"MZ").unwrap();
        let lnk = scratch.0.join("Tool.lnk");
        testing::written_by_windows(&lnk, &program, "--quiet");

        let stored = parse(&std::fs::read(&lnk).unwrap()).expect("Windows' own shortcut parses");
        println!(
            "kept relative to {:?}, saved as {:?}",
            stored.known, stored.path
        );
        let read = command(&lnk, Some(&the_person()))
            .expect("Windows' own shortcut is read")
            .expect("it names a file");
        assert_eq!(
            read.to_lowercase(),
            format!("\"{}\" --quiet", program.display()).to_lowercase()
        );

        let cmd = std::path::PathBuf::from(std::env::var("SystemRoot").unwrap())
            .join(r"System32\cmd.exe");
        let lnk = scratch.0.join("Cmd.lnk");
        testing::written_by_windows(&lnk, &cmd, "/c exit");
        println!(
            "Windows' own cmd.exe kept relative to {:?}",
            parse(&std::fs::read(&lnk).unwrap()).unwrap().known
        );
        assert_eq!(
            command(&lnk, None).unwrap().map(|read| read.to_lowercase()),
            Some(format!("\"{}\" /c exit", cmd.display()).to_lowercase())
        );
    }

    /// Windows' own shortcut to something in one of a person's folders, read
    /// for a person whose folder is somewhere else, leads into theirs. Not
    /// into the reader's, which is where Windows' own reader puts it: in the
    /// service, the reader is LocalSystem.
    #[test]
    fn windows_own_shortcut_is_read_for_its_person_and_not_for_the_reader() {
        let scratch = Scratch::new("theirs");
        let program = scratch.0.join("tool.exe");
        std::fs::write(&program, b"MZ").unwrap();
        let lnk = scratch.0.join("Tool.lnk");
        testing::written_by_windows(&lnk, &program, "");

        // Somebody whose folder that is, somewhere other than the reader's.
        let stored = parse(&std::fs::read(&lnk).unwrap()).unwrap();
        let folders = ScratchFolders::new("theirs");
        let them = match stored.known.and_then(|(folder, _)| known_id(folder)) {
            Some(id) if is_profile(id) => UserContext::new(None, r"D:\Their Own"),
            Some(id) if personal(id).is_some() => {
                folders.set(&value_name(personal(id).unwrap()), r"D:\Their Own");
                the_person()
            }
            _ => {
                // This machine's shell kept the temporary folder by no folder
                // of the person's, so there is nothing here to show.
                println!("no folder of the person's kept {}", program.display());
                return;
            }
        };

        let read = command_with(&lnk, Some(&them), &folders.path)
            .unwrap()
            .unwrap();
        let inside = scratch
            .0
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(
            read.starts_with(r#""D:\Their Own\"#)
                && read.ends_with(&format!(r#"\{inside}\tool.exe""#)),
            "read for the reader rather than for the person: {read}"
        );
    }
}
