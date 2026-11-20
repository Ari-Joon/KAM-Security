//! What Windows says about its own updates: the build it is on, the newest
//! operating system update installed and when, whether a restart is waiting to
//! finish one, whether updates are paused, and whether the Windows Update
//! service is switched off.
//!
//! # What this never says
//!
//! "Up to date". From this PC alone nothing can know whether a newer update
//! exists: that needs a search of Microsoft's catalogue, which is not made
//! here. What can be said is what is installed and when, with where each fact
//! came from, and a source that could not be read is named as unread.
//!
//! # Three traps, found by the review this answers
//!
//! - Windows Update's "last installed" date counts Defender's definitions and
//!   Store apps, which arrive daily: shown as "last update installed" it says
//!   today on a PC that has had no Windows patch for months. So it is not read.
//! - Update titles change their wording. A search for the words "Update for
//!   Windows 11" matched an entry a year old. The running build is what is
//!   matched instead: the cumulative update that brought it carries it in its
//!   title, "(26200.9974)". When no entry does, Windows' list of installed
//!   updates is asked, and the answer says it came from there.
//! - `ProductName` in the registry reads "Windows 10" on Windows 11, so it is
//!   not shown.
//!
//! # Where it runs
//!
//! In the window, as the person. Every source here is one an ordinary account
//! may read, so the service is not needed and is not asked.

use kam_core::registry::{Key, Unopened, View};
use serde::Serialize;
use windows::Win32::Foundation::RPC_E_CHANGED_MODE;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_ALL, COINIT_MULTITHREADED,
};
use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;
use windows::Win32::System::UpdateAgent::{
    orcSucceeded, orcSucceededWithErrors, uoInstallation, ISystemInformation, IUpdateSession,
    SystemInformation, UpdateSession,
};

const VERSION_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
const UPDATE_MARKER: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired";
const SERVICING_MARKER: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending";
const PAUSE_KEY: &str = r"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings";
const SERVICE_KEY: &str = r"SYSTEM\CurrentControlSet\Services\wuauserv";

/// The most history entries read. A PC that has run for years holds a few
/// thousand, most of them Defender's definitions.
const MOST_HISTORY: i32 = 20_000;

/// One fact, or why it could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Reading<T> {
    Read { value: T },
    Unread { why: String },
}

/// The build Windows is running, from its own record of its version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Build {
    /// "26200".
    pub build: String,
    /// The revision after the dot, 9974, when Windows records one.
    pub revision: Option<u32>,
    /// "25H2", when Windows records a name for its version.
    pub version: Option<String>,
}

impl Build {
    /// "26200.9974", or the build alone without a revision.
    fn full(&self) -> String {
        match self.revision {
            Some(revision) => format!("{}.{revision}", self.build),
            None => self.build.clone(),
        }
    }
}

/// The newest operating system update installed, and where that was read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Newest {
    /// The entry in Windows Update's history that names the running build.
    History {
        title: String,
        /// When it was installed, in UTC.
        installed_at: String,
    },
    /// The newest entries in Windows' list of installed updates, taken
    /// because the history did not answer. `history` says why not.
    List {
        /// Each as "KB5132061 (Security Update)".
        updates: Vec<String>,
        /// The day they were installed, as `2026-11-11`.
        installed_on: String,
        history: String,
    },
    /// Neither source could say.
    Unread { why: String },
}

/// Whether a restart is waiting to finish an update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Restart {
    /// Windows Update's own answer.
    pub windows_update: Reading<bool>,
    /// Whether the mark Windows Update leaves in the registry is there.
    pub update_marker: Reading<bool>,
    /// Whether the mark Windows' servicing leaves in the registry is there.
    pub servicing_marker: Reading<bool>,
}

/// Whether updates are paused, from the Windows Update settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Pause {
    NotPaused,
    /// Paused until this time, as Windows wrote it (UTC).
    Until {
        at: String,
    },
    /// A pause is recorded, and its end has passed.
    Ended {
        at: String,
    },
    /// A pause is recorded in a form this does not read as a time.
    Unrecognised {
        value: String,
    },
}

/// Everything the Overview shows about Windows Update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub build: Reading<Build>,
    pub newest: Newest,
    pub restart: Restart,
    pub pause: Reading<Pause>,
    /// Whether the Windows Update service is set to Disabled.
    pub service_disabled: Reading<bool>,
}

/// Read it all. Blocks for up to a second or so, so it must be called off the
/// window's thread.
pub fn survey() -> Report {
    let build = read_build();
    let com = Com::enter();
    let (windows_update, history) = match &com {
        Ok(_) => (restart_from_windows_update(), history()),
        Err(why) => (
            Reading::Unread { why: why.clone() },
            Err(format!("Windows Update's history could not be read: {why}")),
        ),
    };
    let newest = newest(&build, history, installed_list);
    drop(com);

    Report {
        build,
        newest,
        restart: Restart {
            windows_update,
            update_marker: marker(UPDATE_MARKER),
            servicing_marker: marker(SERVICING_MARKER),
        },
        pause: read_pause(&kam_core::clock::now_utc_iso()),
        service_disabled: read_service_disabled(),
    }
}

/// COM for the life of one survey, given back only if this call took it.
struct Com {
    owned: bool,
}

impl Com {
    fn enter() -> Result<Self, String> {
        let outcome = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if outcome == RPC_E_CHANGED_MODE {
            // Already set up on this thread the other way, which these
            // interfaces work with too; and not this call's to undo.
            return Ok(Self { owned: false });
        }
        if outcome.is_err() {
            return Err(format!("COM could not be started ({outcome:?})"));
        }
        Ok(Self { owned: true })
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        if self.owned {
            unsafe { CoUninitialize() };
        }
    }
}

fn unread<T>(what: &str, why: Unopened) -> Reading<T> {
    Reading::Unread {
        why: why.describe(what),
    }
}

fn read_build() -> Reading<Build> {
    let key = match Key::look(HKEY_LOCAL_MACHINE, VERSION_KEY, View::Native) {
        Ok(key) => key,
        Err(why) => return unread("Windows' record of its version", why),
    };
    let build = match key.read_string("CurrentBuild") {
        Ok(Some(build)) => build,
        Ok(None) => {
            return Reading::Unread {
                why: "Windows' record of its version holds no build number".to_owned(),
            }
        }
        Err(why) => return unread("The build number", why),
    };
    Reading::Read {
        value: Build {
            build,
            revision: key.read_dword("UBR").ok().flatten(),
            version: key.read_string("DisplayVersion").ok().flatten(),
        },
    }
}

fn restart_from_windows_update() -> Reading<bool> {
    let asked = unsafe {
        CoCreateInstance::<_, ISystemInformation>(&SystemInformation, None, CLSCTX_ALL)
            .and_then(|information| information.RebootRequired())
    };
    match asked {
        Ok(required) => Reading::Read {
            value: required.as_bool(),
        },
        Err(error) => Reading::Unread {
            why: format!("Windows Update could not be asked: {error}"),
        },
    }
}

/// One entry of Windows Update's history, as far as it matters here.
#[derive(Debug, Clone)]
struct Entry {
    title: String,
    /// Installed, and it worked.
    succeeded: bool,
    /// As an OLE date: days since the end of 1899, in UTC.
    date: f64,
}

fn history() -> Result<Vec<Entry>, String> {
    let failed = |error: windows::core::Error| {
        format!("Windows Update's history could not be read: {error}")
    };
    let searcher = unsafe {
        CoCreateInstance::<_, IUpdateSession>(&UpdateSession, None, CLSCTX_ALL)
            .and_then(|session| session.CreateUpdateSearcher())
    }
    .map_err(failed)?;
    let total = unsafe { searcher.GetTotalHistoryCount() }.map_err(failed)?;
    let entries =
        unsafe { searcher.QueryHistory(0, total.clamp(0, MOST_HISTORY)) }.map_err(failed)?;
    let count = unsafe { entries.Count() }.map_err(failed)?;

    let mut read = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
    for index in 0..count {
        let entry = unsafe { entries.get_Item(index) }.map_err(failed)?;
        let (operation, result, date, title) = unsafe {
            (
                entry.Operation(),
                entry.ResultCode(),
                entry.Date(),
                entry.Title(),
            )
        };
        // An entry that cannot be read whole is left out rather than guessed
        // at; the one wanted is matched by its title and its date both.
        let (Ok(operation), Ok(result), Ok(date), Ok(title)) = (operation, result, date, title)
        else {
            continue;
        };
        read.push(Entry {
            title: title.to_string(),
            succeeded: operation == uoInstallation
                && (result == orcSucceeded || result == orcSucceededWithErrors),
            date,
        });
    }
    Ok(read)
}

/// The update the running build came from, or the newest in Windows' list of
/// installed updates when the history cannot say.
///
/// `list` is asked only when the history does not answer, and is passed in so
/// the choice can be tested without either source.
fn newest(
    build: &Reading<Build>,
    history: Result<Vec<Entry>, String>,
    list: impl FnOnce() -> Result<Vec<(String, String, String)>, String>,
) -> Newest {
    let history_said = match (build, history) {
        (Reading::Read { value: build }, Ok(entries)) => match build.revision {
            Some(_) => {
                // The cumulative update that brought a build carries it in its
                // title in brackets, "(26200.9974)". That is what is matched,
                // not the wording around it.
                let needle = format!("({})", build.full());
                let matched = entries
                    .iter()
                    .filter(|entry| entry.succeeded && entry.title.contains(&needle))
                    .max_by(|a, b| a.date.total_cmp(&b.date));
                match matched.and_then(|entry| {
                    iso_from_ole_date(entry.date).map(|at| (entry.title.clone(), at))
                }) {
                    Some((title, installed_at)) => {
                        return Newest::History {
                            title,
                            installed_at,
                        }
                    }
                    None => format!(
                        "No update installed in Windows Update's history names build {}, the one \
                         Windows is running",
                        build.full()
                    ),
                }
            }
            None => "Windows records no revision for its build, so the update that brought it \
                     cannot be picked out of Windows Update's history"
                .to_owned(),
        },
        (Reading::Unread { .. }, Ok(_)) => {
            "The build Windows is running could not be read, so the update that brought it \
             cannot be picked out of Windows Update's history"
                .to_owned()
        }
        (_, Err(why)) => why,
    };

    match list().and_then(|rows| {
        newest_in_list(&rows).ok_or_else(|| {
            "Windows' list of installed updates holds no entry with a date that can be read"
                .to_owned()
        })
    }) {
        Ok((updates, installed_on)) => Newest::List {
            updates,
            installed_on,
            history: history_said,
        },
        Err(why) => Newest::Unread {
            why: format!("{history_said}. {why}."),
        },
    }
}

/// Windows' list of installed updates, as (id, kind, day installed).
fn installed_list() -> Result<Vec<(String, String, String)>, String> {
    let rows = kam_scanner::wmi::query(
        r"ROOT\CIMV2",
        "SELECT HotFixID, Description, InstalledOn FROM Win32_QuickFixEngineering",
        &["HotFixID", "Description", "InstalledOn"],
    )
    .map_err(|error| format!("Windows' list of installed updates could not be read: {error}"))?;
    let text = |row: &kam_scanner::wmi::Row, name: &str| {
        row.get(name)
            .and_then(kam_scanner::wmi::Value::text)
            .unwrap_or_default()
            .trim()
            .to_owned()
    };
    Ok(rows
        .iter()
        .map(|row| {
            (
                text(row, "HotFixID"),
                text(row, "Description"),
                text(row, "InstalledOn"),
            )
        })
        .collect())
}

/// The updates installed on the newest day in the list, and that day.
///
/// The list writes each day as month, day, year (`11/11/2026`). Anything else,
/// such as the raw timestamp older systems leave there, is not a day this can
/// read and is passed over rather than guessed at.
fn newest_in_list(rows: &[(String, String, String)]) -> Option<(Vec<String>, String)> {
    let dated: Vec<((u32, u32, u32), String)> = rows
        .iter()
        .filter(|(id, ..)| !id.is_empty())
        .filter_map(|(id, kind, installed)| {
            let day = month_day_year(installed)?;
            let named = if kind.is_empty() {
                id.clone()
            } else {
                format!("{id} ({kind})")
            };
            Some((day, named))
        })
        .collect();
    let newest = dated.iter().map(|(day, _)| *day).max()?;
    let updates = dated
        .into_iter()
        .filter(|(day, _)| *day == newest)
        .map(|(_, named)| named)
        .collect();
    let (year, month, day) = newest;
    Some((updates, format!("{year:04}-{month:02}-{day:02}")))
}

/// `11/11/2026` as (2026, 11, 11), when it is a real day.
fn month_day_year(text: &str) -> Option<(u32, u32, u32)> {
    let mut parts = text.split('/');
    let (Some(month), Some(day), Some(year), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let number = |part: &str, most: usize| {
        (!part.is_empty() && part.len() <= most && part.bytes().all(|b| b.is_ascii_digit()))
            .then(|| part.parse::<u32>().ok())
            .flatten()
    };
    let (month, day, year) = (number(month, 2)?, number(day, 2)?, number(year, 4)?);
    ((1..=12).contains(&month) && (1..=31).contains(&day) && year >= 1980)
        .then_some((year, month, day))
}

/// An OLE date, which Windows Update dates its history with, as UTC.
fn iso_from_ole_date(date: f64) -> Option<String> {
    // Day 25569 of the OLE calendar is 1 January 1970.
    let millis = (date - 25_569.0) * 86_400_000.0;
    (millis.is_finite() && millis >= 0.0)
        .then(|| kam_core::clock::iso_from_unix_millis(millis.round() as u64))
}

fn marker(path: &str) -> Reading<bool> {
    match Key::look(HKEY_LOCAL_MACHINE, path, View::Native) {
        Ok(_) => Reading::Read { value: true },
        Err(Unopened::Absent) => Reading::Read { value: false },
        Err(why) => unread("The mark", why),
    }
}

fn read_pause(now: &str) -> Reading<Pause> {
    let key = match Key::look(HKEY_LOCAL_MACHINE, PAUSE_KEY, View::Native) {
        Ok(key) => key,
        // Never paused on this PC: Windows writes this key when updates are
        // first paused.
        Err(Unopened::Absent) => {
            return Reading::Read {
                value: Pause::NotPaused,
            }
        }
        Err(why) => return unread("The Windows Update settings", why),
    };
    match key.read_string("PauseUpdatesExpiryTime") {
        Ok(recorded) => Reading::Read {
            value: pause_from(recorded.as_deref(), now),
        },
        Err(why) => unread("The pause in the Windows Update settings", why),
    }
}

/// What a recorded pause comes to at `now`, both as ISO 8601 in UTC.
fn pause_from(recorded: Option<&str>, now: &str) -> Pause {
    let Some(recorded) = recorded.map(str::trim).filter(|text| !text.is_empty()) else {
        return Pause::NotPaused;
    };
    // `2026-12-03T10:00:00Z`: compared as text up to the second, which orders
    // correctly for times written in this one shape and nothing else.
    let shaped = recorded.len() >= 19
        && recorded
            .bytes()
            .enumerate()
            .take(19)
            .all(|(index, byte)| match index {
                4 | 7 => byte == b'-',
                10 => byte == b'T',
                13 | 16 => byte == b':',
                _ => byte.is_ascii_digit(),
            });
    if !shaped || now.len() < 19 {
        return Pause::Unrecognised {
            value: recorded.to_owned(),
        };
    }
    if recorded[..19] > now[..19] {
        Pause::Until {
            at: recorded.to_owned(),
        }
    } else {
        Pause::Ended {
            at: recorded.to_owned(),
        }
    }
}

fn read_service_disabled() -> Reading<bool> {
    let key = match Key::look(HKEY_LOCAL_MACHINE, SERVICE_KEY, View::Native) {
        Ok(key) => key,
        Err(why) => return unread("The Windows Update service's settings", why),
    };
    match key.read_dword("Start") {
        // 4 is Disabled, as the Services console names it.
        Ok(Some(start)) => Reading::Read { value: start == 4 },
        Ok(None) => Reading::Unread {
            why: "The Windows Update service's settings hold no start type".to_owned(),
        },
        Err(why) => unread("The Windows Update service's start type", why),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn build(revision: Option<u32>) -> Reading<Build> {
        Reading::Read {
            value: Build {
                build: "26200".to_owned(),
                revision,
                version: Some("25H2".to_owned()),
            },
        }
    }

    fn entry(title: &str, succeeded: bool, date: f64) -> Entry {
        Entry {
            title: title.to_owned(),
            succeeded,
            date,
        }
    }

    /// 10 November 2026 at noon, UTC, as an OLE date.
    const NOVEMBER_10: f64 = 46_336.5;

    fn no_list() -> Result<Vec<(String, String, String)>, String> {
        panic!("the list was asked although the history answered")
    }

    /// The update that brought the running build is found by the build it
    /// names, not by the words in its title, and not by being the newest:
    /// Defender's definitions and Store apps arrive every day.
    #[test]
    fn the_update_that_brought_the_running_build_is_found_by_its_number() {
        let history = vec![
            entry(
                "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.441.75.0)",
                true,
                NOVEMBER_10 + 9.0,
            ),
            entry("9NBLGGH4NNS1-Microsoft.DesktopAppInstaller", true, NOVEMBER_10 + 8.0),
            // The same update tried again later and failed: not installed
            // then, so not the answer.
            entry(
                "2026-11 Security Update (KB5132061) (26200.9974)",
                false,
                NOVEMBER_10 + 1.0,
            ),
            entry(
                "2026-11 Security Update (KB5132061) (26200.9974)",
                true,
                NOVEMBER_10,
            ),
            // Worded as a search for "Update for Windows 11" would want, and
            // a year old.
            entry(
                "2025-10 Cumulative Update for Windows 11 Version 25H2 (KB5066835) (26200.6899)",
                true,
                NOVEMBER_10 - 384.0,
            ),
        ];
        assert_eq!(
            newest(&build(Some(9974)), Ok(history), no_list),
            Newest::History {
                title: "2026-11 Security Update (KB5132061) (26200.9974)".to_owned(),
                installed_at: "2026-11-10T12:00:00.000Z".to_owned(),
            }
        );
    }

    /// When no entry names the running build, Windows' list of installed
    /// updates answers instead, and the answer says why.
    #[test]
    fn the_list_of_installed_updates_answers_when_the_history_cannot() {
        let list = || {
            Ok(vec![
                (
                    "KB5131234".to_owned(),
                    "Update".to_owned(),
                    "10/14/2026".to_owned(),
                ),
                (
                    "KB5132061".to_owned(),
                    "Security Update".to_owned(),
                    "11/11/2026".to_owned(),
                ),
                (
                    "KB5132999".to_owned(),
                    "Update".to_owned(),
                    "11/11/2026".to_owned(),
                ),
                // A raw timestamp, as older systems leave: not a day.
                (
                    "KB4000001".to_owned(),
                    "Update".to_owned(),
                    "01cc2d3c4e7b0f00".to_owned(),
                ),
            ])
        };
        let other_build = vec![entry(
            "2026-10 Security Update (KB5131234) (26200.9900)",
            true,
            NOVEMBER_10 - 27.0,
        )];
        match newest(&build(Some(9974)), Ok(other_build), list) {
            Newest::List {
                updates,
                installed_on,
                history,
            } => {
                assert_eq!(
                    updates,
                    vec![
                        "KB5132061 (Security Update)".to_owned(),
                        "KB5132999 (Update)".to_owned()
                    ]
                );
                assert_eq!(installed_on, "2026-11-11");
                assert!(history.contains("26200.9974"), "{history}");
            }
            other => panic!("expected the list, got {other:?}"),
        }

        // A history that could not be read is said as such.
        match newest(
            &build(Some(9974)),
            Err("Windows Update's history could not be read: denied".to_owned()),
            list,
        ) {
            Newest::List { history, .. } => assert!(history.contains("denied"), "{history}"),
            other => panic!("expected the list, got {other:?}"),
        }
    }

    /// Neither source answering is a fact not known, with both reasons.
    #[test]
    fn neither_source_answering_is_said_with_both_reasons() {
        match newest(&build(None), Ok(Vec::new()), || {
            Err("Windows' list of installed updates could not be read: no WMI".to_owned())
        }) {
            Newest::Unread { why } => {
                assert!(why.contains("no revision"), "{why}");
                assert!(why.contains("no WMI"), "{why}");
            }
            other => panic!("expected nothing known, got {other:?}"),
        }
        match newest(&build(Some(1)), Ok(Vec::new()), || {
            Ok(vec![(
                "KB1".to_owned(),
                String::new(),
                "not a day".to_owned(),
            )])
        }) {
            Newest::Unread { why } => assert!(why.contains("date that can be read"), "{why}"),
            other => panic!("expected nothing known, got {other:?}"),
        }
    }

    #[test]
    fn only_a_real_month_day_and_year_is_read_as_a_day() {
        assert_eq!(month_day_year("11/11/2026"), Some((2026, 11, 11)));
        assert_eq!(month_day_year("1/2/2026"), Some((2026, 1, 2)));
        for not_a_day in [
            "13/1/2026",
            "1/32/2026",
            "2026-11-11",
            "11/11",
            "a/b/c",
            "",
            "1/1/26",
        ] {
            assert_eq!(month_day_year(not_a_day), None, "{not_a_day} was read");
        }
    }

    #[test]
    fn an_ole_date_is_read_as_utc() {
        assert_eq!(
            iso_from_ole_date(25_569.0).as_deref(),
            Some("1970-01-01T00:00:00.000Z")
        );
        assert_eq!(
            iso_from_ole_date(NOVEMBER_10).as_deref(),
            Some("2026-11-10T12:00:00.000Z")
        );
        assert_eq!(iso_from_ole_date(f64::NAN), None);
    }

    /// A pause is told apart from one that has ended, and from a value this
    /// cannot read as a time, which is shown as it was written.
    #[test]
    fn a_pause_is_read_against_the_time_now() {
        let now = "2026-11-20T09:30:00.000Z";
        assert_eq!(pause_from(None, now), Pause::NotPaused);
        assert_eq!(pause_from(Some("  "), now), Pause::NotPaused);
        assert_eq!(
            pause_from(Some("2026-12-03T10:00:00Z"), now),
            Pause::Until {
                at: "2026-12-03T10:00:00Z".to_owned()
            }
        );
        assert_eq!(
            pause_from(Some("2026-11-01T10:00:00Z"), now),
            Pause::Ended {
                at: "2026-11-01T10:00:00Z".to_owned()
            }
        );
        assert_eq!(
            pause_from(Some("3 December"), now),
            Pause::Unrecognised {
                value: "3 December".to_owned()
            }
        );
    }

    /// The whole survey reads this machine, so it is not run by default.
    /// Run by hand to see that every source is reached; what it prints is
    /// about the machine it runs on, and from a sandboxed shell even that is
    /// not to be trusted for the per-user half of the registry (none is read
    /// here).
    #[test]
    #[ignore = "reads this machine's real state"]
    fn show_this_machine() {
        println!("{:#?}", survey());
    }
}
