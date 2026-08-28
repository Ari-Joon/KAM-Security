//! When each program was last actually run.
//!
//! "It is 4 GB" is a fact. "It is 4 GB and you have not opened it since March"
//! is a decision. The second one is what people are really asking a storage
//! tool, and nothing on Windows shows it.
//!
//! # Why not last-access times
//!
//! The obvious source is the filesystem's own last-access timestamp, and it is
//! useless: Windows stopped maintaining those by default years ago, because
//! updating a timestamp on every read is expensive. The scanner already checks
//! this before reporting anything based on it. On a machine where tracking is
//! off — which is nearly all of them — every file claims to have been touched
//! whenever it was written.
//!
//! # UserAssist
//!
//! Explorer keeps its own record instead: how many times you have launched
//! each program and when you last did, under `UserAssist`. It is what feeds
//! the Start Menu's "most used" list, so it exists on every machine and is
//! maintained without anybody opting in.
//!
//! Two oddities. The value names are ROT13, which is not obfuscation so much
//! as a decision somebody made in 1999 and nobody has revisited. And paths are
//! stored with known folders replaced by their GUIDs, so `{6D80...}` has to be
//! turned back into `C:\Program Files` before anything can be matched to it.
//!
//! # What it does not cover
//!
//! Launches by this user, of things Explorer saw start. A program run from a
//! terminal, by a service, or by another account is not in here. So an absent
//! entry means "no record of you launching it", never "never run" — and the
//! interface has to say the first thing rather than the second.

use std::collections::HashMap;

use kam_core::UserContext;
use serde::{Deserialize, Serialize};

use kam_core::registry::View;

/// Where Explorer keeps the counts.
const USER_ASSIST: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

/// The subkey holding launches of executables by path.
const EXECUTABLES: &str = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}";

/// The subkey holding launches of *shortcuts*.
///
/// Reading only the first key was a real gap rather than a simplification.
/// Anything started from the Start Menu, the taskbar or a desktop icon is
/// recorded here and nowhere else, and that is how most people start most
/// things: on this machine, Visual Studio Code and Discord both showed as never
/// opened while being open at the time.
///
/// The values are paths to `.lnk` files, so each is resolved to what it points
/// at before being joined against install directories. A shortcut that no
/// longer resolves is dropped rather than counted against its own path, which
/// would attribute a launch to the Start Menu folder.
const SHORTCUTS: &str = "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}";

/// Offsets into the 72-byte record. Undocumented by Microsoft and stable since
/// Windows 7; verified against real values on a live machine rather than taken
/// on faith.
const OFFSET_RUN_COUNT: usize = 4;
const OFFSET_LAST_RUN: usize = 60;
const RECORD_BYTES: usize = 68;

/// Seconds between the Windows epoch (1601) and the Unix epoch (1970).
const FILETIME_EPOCH_OFFSET: u64 = 11_644_473_600;

/// What Explorer has recorded about one program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usage {
    /// The executable, with known-folder GUIDs expanded back to real paths.
    ///
    /// Empty when the record names an application rather than a file and no
    /// shortcut could be found to translate it; `app_id` carries the name in
    /// that case.
    pub path: String,
    /// The name Windows recorded the launch under, when it recorded one.
    pub app_id: Option<String>,
    /// How many times this account has launched it.
    pub runs: u32,
    /// Seconds since the Unix epoch. `None` when the record has no time, which
    /// happens for entries Explorer created but never saw run.
    pub last_run: Option<u64>,
}

impl Usage {
    /// Whole days since it last ran.
    pub fn days_since(&self, now: u64) -> Option<u64> {
        let last = self.last_run?;
        Some(now.saturating_sub(last) / 86_400)
    }
}

/// Undo the ROT13 the value names are stored under.
fn rot13(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            other => other,
        })
        .collect()
}

/// Known-folder GUIDs, with what they stand for.
///
/// Only the ones that actually appear in these records. An unrecognised GUID
/// is left as written rather than guessed at, so a path that cannot be
/// resolved stays visibly unresolved instead of quietly becoming wrong.
fn expand_known_folder(path: &str, user: &UserContext) -> String {
    const FOLDERS: &[(&str, &str)] = &[
        ("{6D809377-6AF0-444B-8957-A3773F02200E}", "ProgramFiles"),
        (
            "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}",
            "ProgramFiles(x86)",
        ),
        (
            "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}",
            "SystemRoot\\System32",
        ),
        ("{F38BF404-1D43-42F2-9305-67DE0B28FC23}", "SystemRoot"),
        (
            "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}",
            "SystemRoot\\System32",
        ),
        (
            "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}",
            "USERPROFILE\\Desktop",
        ),
        (
            "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}",
            "USERPROFILE\\Documents",
        ),
        (
            "{374DE290-123F-4565-9164-39C4925E467B}",
            "USERPROFILE\\Downloads",
        ),
        ("{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}", "LOCALAPPDATA"),
        ("{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}", "APPDATA"),
        ("{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}", "ProgramData"),
        (
            "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}",
            "ProgramData\\Microsoft\\Windows\\Start Menu\\Programs",
        ),
        (
            "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}",
            "APPDATA\\Microsoft\\Windows\\Start Menu\\Programs",
        ),
    ];

    let upper = path.to_uppercase();
    for (guid, variable) in FOLDERS {
        if !upper.starts_with(guid) {
            continue;
        }
        // The variable may itself carry a tail, as with System32.
        let (name, tail) = match variable.split_once('\\') {
            Some((name, tail)) => (name, Some(tail)),
            None => (*variable, None),
        };
        // The three per-user roots come from `user`. Taken from the
        // environment inside the agent they resolve to LocalSystem's profile,
        // and every known-folder path under a person's AppData silently points
        // somewhere nobody has ever installed anything.
        let base = match name {
            "USERPROFILE" => user.profile().to_owned(),
            "LOCALAPPDATA" => user.local_app_data(),
            "APPDATA" => user.roaming_app_data(),
            other => match std::env::var(other) {
                Ok(value) => value,
                Err(_) => return path.to_owned(),
            },
        };
        let rest = &path[guid.len()..];
        let mut resolved = base;
        if let Some(tail) = tail {
            resolved.push('\\');
            resolved.push_str(tail);
        }
        resolved.push_str(rest);
        return resolved;
    }
    path.to_owned()
}

fn parse(name: &str, data: &[u8], user: &UserContext) -> Option<Usage> {
    if data.len() < RECORD_BYTES {
        return None;
    }

    let decoded = rot13(name);

    // Explorer's own bookkeeping rows, not programs.
    if decoded.starts_with("UEME_") {
        return None;
    }

    let runs = u32::from_le_bytes([
        data[OFFSET_RUN_COUNT],
        data[OFFSET_RUN_COUNT + 1],
        data[OFFSET_RUN_COUNT + 2],
        data[OFFSET_RUN_COUNT + 3],
    ]);

    let filetime = u64::from_le_bytes([
        data[OFFSET_LAST_RUN],
        data[OFFSET_LAST_RUN + 1],
        data[OFFSET_LAST_RUN + 2],
        data[OFFSET_LAST_RUN + 3],
        data[OFFSET_LAST_RUN + 4],
        data[OFFSET_LAST_RUN + 5],
        data[OFFSET_LAST_RUN + 6],
        data[OFFSET_LAST_RUN + 7],
    ]);

    // Some records carry a time that is not one — a stray value from an
    // upgrade, or a field Explorer never filled. Anything before Windows
    // existed or far in the future is discarded rather than shown as a date.
    let last_run = (filetime / 10_000_000)
        .checked_sub(FILETIME_EPOCH_OFFSET)
        .filter(|seconds| *seconds > 946_684_800 && *seconds < 4_102_444_800);

    Some(Usage {
        path: expand_known_folder(&decoded, user),
        app_id: None,
        runs,
        last_run,
    })
}

/// Read one of the two count keys.
fn read_key(subkey: &str, user: &UserContext) -> Vec<Usage> {
    let path = format!("{USER_ASSIST}\\{subkey}\\Count");
    let Some(key) = user.open_key(&path, View::Native) else {
        return Vec::new();
    };
    key.value_names()
        .into_iter()
        .filter_map(|name| {
            let data = key.binary(&name)?;
            parse(&name, &data, user)
        })
        .collect()
}

/// Everything Explorer has recorded for one account.
///
/// `user` matters here more than anywhere else in this crate. This data lives
/// only under the account that produced it, so reading it from the wrong hive
/// does not fail — it returns nothing, and every program looks as though it has
/// never been opened. The agent runs as LocalSystem, whose hive has no launch
/// history at all, which is precisely how that bug reached a screenshot.
pub fn all(user: &UserContext) -> Vec<Usage> {
    let mut found = read_key(EXECUTABLES, user);
    found.extend(read_key(SHORTCUTS, user));

    // Not every record names a file.
    //
    // Both keys mix two kinds of value: a path, and the name Windows knows a
    // program by -- `Microsoft.VisualStudioCode`, `com.squirrel.Discord.Discord`,
    // `Valve.Steam.Client`. The second kind is how anything started from the
    // Start Menu or the taskbar is recorded, which is how most people start
    // most things, and no amount of path matching will ever join one to an
    // install directory. Reading only the first kind left Visual Studio Code
    // and Discord showing as never opened while both were running.
    //
    // Shortcuts are what connect the two: a `.lnk` knows both the name and the
    // program, so it is read once and used as the translation table.
    let mut by_lnk: HashMap<String, String> = HashMap::new();
    let mut by_app_id: HashMap<String, String> = HashMap::new();
    for shortcut in crate::shortcuts::all(user) {
        let Some(target) = shortcut.target.filter(|target| !target.is_empty()) else {
            continue;
        };
        by_lnk.insert(shortcut.path.to_lowercase(), target.clone());
        if let Some(id) = shortcut.app_id {
            // A Start Menu entry and its pinned twin share an id and point at
            // the same program, so the first wins rather than the last
            // overwriting it for nothing.
            by_app_id.entry(id.to_lowercase()).or_insert(target);
        }
    }

    found
        .into_iter()
        .map(|mut usage| {
            if looks_like_a_path(&usage.path) && !ends_with_lnk(&usage.path) {
                return usage;
            }
            let key = usage.path.to_lowercase();
            if let Some(target) = by_lnk.get(&key).or_else(|| by_app_id.get(&key)) {
                usage.app_id = Some(usage.path.clone());
                usage.path = target.clone();
                return usage;
            }
            // A name no shortcut explains. Some of these are Store apps with no
            // install directory to attribute anything to; some are ordinary
            // programs that set their own name at runtime, which a shortcut
            // therefore never records -- Visual Studio Code does exactly that.
            //
            // The path is emptied rather than left as the name: a name in a
            // list of file locations matches nothing and reads as a bug. The
            // name is kept beside it, so the applications survey can try it
            // against what it knows is installed.
            usage.app_id = Some(std::mem::take(&mut usage.path));
            usage
        })
        .collect()
}

/// Whether a recorded value is a file path rather than an application name.
fn looks_like_a_path(value: &str) -> bool {
    // A drive letter, or a UNC path. Application ids contain neither.
    value.starts_with("\\\\")
        || matches!(value.as_bytes(), [letter, b':', b'\\', ..] if letter.is_ascii_alphabetic())
}

fn ends_with_lnk(value: &str) -> bool {
    value.len() > 4 && value[value.len() - 4..].eq_ignore_ascii_case(".lnk")
}

/// Launches recorded under a name rather than a path, by that name.
///
/// The applications survey matches these against what it knows is installed;
/// nothing else can, because a name like `Microsoft.VisualStudioCode` appears
/// nowhere on disk.
pub fn unattributed(user: &UserContext) -> Vec<Usage> {
    all(user)
        .into_iter()
        .filter(|usage| usage.path.is_empty() && usage.app_id.is_some())
        .collect()
}

/// Usage indexed by lowercased executable path, for joining against anything
/// that knows where a program lives.
pub fn by_path(user: &UserContext) -> HashMap<String, Usage> {
    let mut index: HashMap<String, Usage> = HashMap::new();
    for usage in all(user).into_iter().filter(|u| !u.path.is_empty()) {
        let key = usage.path.to_lowercase().replace('/', "\\");
        // The same program can appear more than once — under a versioned path
        // and a stable one. Keep whichever ran most recently.
        index
            .entry(key)
            .and_modify(|existing| {
                if usage.last_run > existing.last_run {
                    *existing = usage.clone();
                }
            })
            .or_insert(usage);
    }
    index
}

/// The most recent launch of anything inside `directory`.
///
/// An application is not one executable: a launcher, an updater and a handful
/// of helpers all live in the same folder, and what somebody means by "when
/// did I last use this" is the most recent of them.
pub fn latest_under(usage: &HashMap<String, Usage>, directory: &str) -> Option<Usage> {
    if directory.trim().is_empty() {
        return None;
    }
    let prefix = format!(
        "{}\\",
        directory
            .to_lowercase()
            .replace('/', "\\")
            .trim_end_matches('\\')
    );

    usage
        .iter()
        .filter(|(path, _)| path.starts_with(&prefix))
        .max_by_key(|(_, usage)| (usage.last_run, usage.runs))
        .map(|(_, usage)| usage.clone())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_path_is_told_apart_from_an_application_name() {
        assert!(looks_like_a_path(r"C:\Program Files\Thing\thing.exe"));
        assert!(looks_like_a_path(r"d:\games\a.exe"));
        assert!(looks_like_a_path(r"\\server\share\a.exe"));

        // Every one of these is a real value from this machine's own records.
        assert!(!looks_like_a_path("Microsoft.VisualStudioCode"));
        assert!(!looks_like_a_path("com.squirrel.Discord.Discord"));
        assert!(!looks_like_a_path("Valve.Steam.Client"));
        assert!(!looks_like_a_path("Chrome"));
        assert!(!looks_like_a_path(
            "Microsoft.WindowsStore_8wekyb3d8bbwe!App"
        ));
        // Steam's own protocol form, which is not a file either.
        assert!(!looks_like_a_path(r"steam:\\rungameid\1203220"));
    }

    #[test]
    fn a_shortcut_is_not_treated_as_the_program_it_points_at() {
        assert!(ends_with_lnk(r"C:\Users\me\Desktop\Thing.LNK"));
        assert!(ends_with_lnk(r"a.lnk"));
        assert!(!ends_with_lnk(r"C:\Program Files\Thing\thing.exe"));
        assert!(!ends_with_lnk(".lnk"));
    }

    #[test]
    fn records_naming_an_application_never_reach_the_path_index() {
        // A name in a list of file locations matches nothing and reads as a
        // bug, which is what it was before these were separated out.
        let index = by_path(&UserContext::current());
        for (key, usage) in &index {
            assert!(
                looks_like_a_path(key),
                "{key} is not a path but is in the path index"
            );
            assert!(!usage.path.is_empty());
        }
    }

    #[test]
    fn rot13_is_its_own_inverse() {
        assert_eq!(rot13("Zvpebfbsg"), "Microsoft");
        assert_eq!(rot13(&rot13("Microsoft")), "Microsoft");
        // Digits, braces and separators pass through untouched.
        assert_eq!(
            rot13(r"{6D809377-6AF0}\App\a.exe"),
            r"{6Q809377-6NS0}\Ncc\n.rkr"
        );
    }

    #[test]
    fn a_known_folder_becomes_a_real_path() {
        let expanded = expand_known_folder(
            r"{6D809377-6AF0-444B-8957-A3773F02200E}\App\thing.exe",
            &UserContext::current(),
        );
        assert!(
            expanded.to_lowercase().contains("program files"),
            "did not expand: {expanded}"
        );
        assert!(expanded.ends_with(r"\App\thing.exe"));
    }

    #[test]
    fn an_unknown_guid_is_left_visibly_unresolved() {
        // Better an obviously unresolved path than a confidently wrong one.
        let path = r"{00000000-0000-0000-0000-000000000000}\thing.exe";
        assert_eq!(expand_known_folder(path, &UserContext::current()), path);
    }

    #[test]
    fn explorers_own_bookkeeping_is_not_a_program() {
        // UEME_CTLSESSION and friends are counters, not applications.
        let name = super::rot13("UEME_CTLSESSION");
        assert!(parse(&name, &[0_u8; 72], &UserContext::current()).is_none());
    }

    #[test]
    fn a_short_record_is_ignored_rather_than_read_past() {
        assert!(parse("nccyr", &[0_u8; 8], &UserContext::current()).is_none());
    }

    #[test]
    fn an_impossible_timestamp_is_discarded() {
        // One real record on the development machine decoded to the year 1708.
        // A date like that is not a launch, it is a field nobody filled.
        let mut record = [0_u8; 72];
        record[OFFSET_RUN_COUNT] = 5;
        record[OFFSET_LAST_RUN..OFFSET_LAST_RUN + 8]
            .copy_from_slice(&33_777_293_561_036_915_u64.to_le_bytes());

        let usage = parse("nccyr.rkr", &record, &UserContext::current()).unwrap();
        assert_eq!(usage.runs, 5);
        assert_eq!(usage.last_run, None, "an absurd date must not be shown");
    }

    #[test]
    fn a_real_timestamp_is_kept() {
        let mut record = [0_u8; 72];
        record[OFFSET_RUN_COUNT] = 3;
        // 2026-08-23 in FILETIME, taken from a real record.
        record[OFFSET_LAST_RUN..OFFSET_LAST_RUN + 8]
            .copy_from_slice(&134_319_915_724_930_000_u64.to_le_bytes());

        let usage = parse("nccyr.rkr", &record, &UserContext::current()).unwrap();
        assert_eq!(usage.runs, 3);
        let seconds = usage.last_run.expect("should have kept the time");
        // Somewhere in 2026.
        assert!(seconds > 1_767_225_600, "too early: {seconds}");
        assert!(seconds < 1_798_761_600, "too late: {seconds}");
    }

    #[test]
    fn this_machine_has_a_usage_record() {
        // Every account that has launched anything has these. Finding none
        // means the reading is broken rather than the machine unused.
        let usage = all(&kam_core::UserContext::current());
        println!("{} programs with a launch record", usage.len());
        assert!(!usage.is_empty(), "no usage records at all");

        let dated = usage.iter().filter(|item| item.last_run.is_some()).count();
        println!("{dated} of them carry a usable last-run time");
        assert!(dated > 0, "not one record yielded a time");

        let mut recent: Vec<&Usage> = usage.iter().filter(|u| u.last_run.is_some()).collect();
        recent.sort_by_key(|u| std::cmp::Reverse(u.last_run));
        for item in recent.iter().take(8) {
            println!("  {} runs, {}", item.runs, item.path);
        }
    }

    #[test]
    fn a_directory_resolves_to_its_most_recent_launch() {
        let index = by_path(&kam_core::UserContext::current());
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
        match latest_under(&index, &root) {
            Some(usage) => println!("most recent under {root}: {}", usage.path),
            None => println!("nothing under {root} has been launched by this account"),
        }
        // An empty directory must never match everything.
        assert!(latest_under(&index, "").is_none());
        assert!(latest_under(&index, "   ").is_none());
    }
}
