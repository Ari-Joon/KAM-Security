//! The quieter places a program can be started from.
//!
//! # Why these, and why they do not lengthen the list
//!
//! The startup survey reads the four places ordinary software uses, and says
//! why it leaves these out: each would dilute a list meant to be short enough
//! to read. That is true of a list and not of a comparison. On an ordinary
//! machine every one of these is exactly as Windows ships it, so they add
//! nothing to read, and the day one is used is the day it deserves a line.
//! So an entry exists here only when a place departs from what Windows ships,
//! recognised by its exact value, and each such entry is judged, watched and
//! compared like any other startup entry.
//!
//! - Winlogon's `Userinit` and `Shell`: programs Windows starts at every
//!   sign-in, and an account's own `Shell`.
//! - A `Debugger` under Image File Execution Options, which Windows starts in
//!   place of the program named, and `SilentProcessExit`'s `MonitorProcess`,
//!   which it starts when that program closes.
//! - An account's `UserInitMprLogonScript`: a script run at its every sign-in.
//! - `AppInit_DLLs`: libraries loaded into every program that uses Windows'
//!   own window functions.
//! - WMI event subscriptions whose consumer runs a command or a script.
//! - An account's own registration of a COM class a scheduled task hands its
//!   work to. Microsoft: "The user-specific settings have priority over the
//!   default settings." For a task that runs as that account, this is what
//!   runs, and the startup survey, which looks a task's class up for the
//!   whole machine, names the machine's file instead. That was the wrong
//!   answer for that account; this names the right one.
//!
//! What Windows ships is said as that and nothing more. A place at its default
//! is not called safe, and one that is set is not called dangerous: Process
//! Explorer makes itself Task Manager's debugger when asked to, and plenty of
//! management software uses WMI subscriptions.

use kam_core::changes::Unreadable;
use kam_core::registry::{self, Key, Unopened, View};
use kam_core::UserContext;
use windows::Win32::System::Registry::{HKEY, HKEY_LOCAL_MACHINE};

use crate::persistence::{self, Anchor, Entry, Survey};
use crate::wmi::{Row, Value};

/// Where Winlogon keeps the programs it starts, for the machine and, under
/// the same path in each account's hive, for that account.
const WINLOGON: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

/// Image File Execution Options. Shared by the two registry views, so one
/// read covers both (Microsoft's table of keys WOW64 affects).
const IMAGE_OPTIONS: &str =
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

const SILENT_EXIT: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";

/// Where `AppInit_DLLs` is kept, once for each registry view: the 32-bit
/// view's list is the one 32-bit programs load.
const APPINIT: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";

/// The WMI namespace event subscriptions live in.
const SUBSCRIPTIONS: &str = r"ROOT\subscription";

/// The places this reads, in a person's words, with what each holds: the
/// line that says they were checked names them.
pub const PLACES: &[(&str, Anchor)] = &[
    ("the Windows sign-in programs", Anchor::Winlogon),
    ("debugger redirections", Anchor::Debugger),
    (
        "programs set to start when another closes",
        Anchor::ExitMonitor,
    ),
    ("sign-in scripts", Anchor::LogonScript),
    ("AppInit libraries", Anchor::AppInit),
    ("WMI event subscriptions", Anchor::WmiSubscription),
    (
        "accounts' own registrations of the COM classes scheduled tasks use",
        Anchor::ComOverride,
    ),
];

/// The kinds of these that live in an account's own hive.
pub const PER_ACCOUNT: [Anchor; 3] = [Anchor::Winlogon, Anchor::LogonScript, Anchor::ComOverride];

/// Where Windows is, for recognising its own programs by their exact path.
fn windows_folder() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned())
}

/// How a machine key is written in the 32-bit view, so it can be pasted into
/// Registry Editor.
fn in_view(path: &str, view: View) -> String {
    match view {
        View::Native => format!(r"HKLM\{path}"),
        View::Wow6432 => format!(
            r"HKLM\SOFTWARE\WOW6432Node\{}",
            path.strip_prefix(r"SOFTWARE\").unwrap_or(path)
        ),
    }
}

/// What the machine as a whole starts from these places: Winlogon, debugger
/// redirections, programs started when another closes, AppInit libraries and
/// WMI subscriptions. Nobody's own.
pub fn of_machine() -> Survey {
    let mut survey = Survey::default();
    let windows = windows_folder();
    read_winlogon(
        &mut survey,
        HKEY_LOCAL_MACHINE,
        WINLOGON,
        &format!(r"HKLM\{WINLOGON}"),
        &windows,
        None,
    );
    read_named_programs(
        &mut survey,
        HKEY_LOCAL_MACHINE,
        IMAGE_OPTIONS,
        View::Native,
        &format!(r"HKLM\{IMAGE_OPTIONS}"),
        Anchor::Debugger,
        "Debugger",
    );
    for view in [View::Native, View::Wow6432] {
        read_named_programs(
            &mut survey,
            HKEY_LOCAL_MACHINE,
            SILENT_EXIT,
            view,
            &in_view(SILENT_EXIT, view),
            Anchor::ExitMonitor,
            "MonitorProcess",
        );
        read_appinit(
            &mut survey,
            HKEY_LOCAL_MACHINE,
            APPINIT,
            view,
            &in_view(APPINIT, view),
        );
    }
    // A key that is the same in both views reads twice: kept once.
    let mut seen = std::collections::HashSet::new();
    survey.entries.retain(|entry| {
        entry.anchor != Anchor::ExitMonitor
            || seen.insert((entry.name.to_lowercase(), entry.command.clone()))
    });
    subscriptions_from(
        &mut survey,
        crate::wmi::query(
            SUBSCRIPTIONS,
            "SELECT Name, CommandLineTemplate, ExecutablePath FROM CommandLineEventConsumer",
            &["Name", "CommandLineTemplate", "ExecutablePath"],
        )
        .map_err(|error| error.to_string()),
        crate::wmi::query(
            SUBSCRIPTIONS,
            "SELECT Name, ScriptingEngine, ScriptFileName, ScriptText FROM \
             ActiveScriptEventConsumer",
            &["Name", "ScriptingEngine", "ScriptFileName", "ScriptText"],
        )
        .map_err(|error| error.to_string()),
    );
    survey
}

/// What one account starts from these places, read from its own hive: its
/// own Winlogon `Shell`, its sign-in script, and its own registrations of
/// the COM classes the machine's scheduled tasks use (`handlers`, as
/// [`persistence::com_handlers`] gives them).
///
/// `None` when the account's hive is not there once read, as for
/// [`persistence::survey_of_account`].
pub fn of_account(user: &UserContext, handlers: &[(String, String)]) -> Option<Survey> {
    let mut survey = Survey::default();
    let (hive, prefix) = user.hive();
    let label = hive_label(user);
    let account_winlogon = account_path(WINLOGON);
    read_winlogon(
        &mut survey,
        hive,
        &format!("{prefix}{account_winlogon}"),
        &format!(r"{label}\{account_winlogon}"),
        &windows_folder(),
        Some(user),
    );
    read_logon_script(
        &mut survey,
        hive,
        &format!("{prefix}Environment"),
        &format!(r"{label}\Environment"),
        user,
    );
    read_com_overrides(
        &mut survey,
        hive,
        &format!(r"{prefix}Software\Classes"),
        &format!(r"{label}\Software\Classes"),
        handlers,
        user,
        persistence::com_server,
    );
    (!persistence::hive_gone(user)).then_some(survey)
}

/// The same places for the machine and for every account given. An account
/// whose hive went while it was read is a gap confined to its own hive.
pub fn survey_for(users: &[UserContext], handlers: &[(String, String)]) -> Survey {
    let mut survey = of_machine();
    for user in users {
        match of_account(user, handlers) {
            Some(theirs) => {
                survey.entries.extend(theirs.entries);
                survey.unreadable.extend(theirs.unreadable);
            }
            None => survey.unreadable.push(Unreadable::covering(
                &PER_ACCOUNT.map(Anchor::kind),
                &[hive_label(user)],
                "an account signed out while its quieter startup places were being read, so \
                 they are not shown",
            )),
        }
    }
    survey
}

/// How an account's hive is named in a location: by SID, as the startup
/// survey names it, so a location means the same hive whoever is signed in.
fn hive_label(user: &UserContext) -> String {
    match user.sid() {
        Some(sid) => format!(r"HKEY_USERS\{sid}"),
        None => "HKCU".to_owned(),
    }
}

/// A machine path as the same path is spelled in an account's hive.
fn account_path(path: &str) -> String {
    match path.strip_prefix(r"SOFTWARE\") {
        Some(rest) => format!(r"Software\{rest}"),
        None => path.to_owned(),
    }
}

/// Whether one item of a Winlogon value is Windows' own program, by its exact
/// path: `userinit.exe` in System32 for `Userinit`, and Explorer for `Shell`,
/// which Windows writes as its bare name.
fn windows_own(value: &str, item: &str, windows: &str) -> bool {
    let item = kam_core::env::expand(item.trim().trim_matches('"')).to_lowercase();
    let windows = windows.trim_end_matches('\\').to_lowercase();
    match value {
        "Userinit" => item == format!(r"{windows}\system32\userinit.exe"),
        "Shell" => item == "explorer.exe" || item == format!(r"{windows}\explorer.exe"),
        _ => false,
    }
}

/// The programs a Winlogon key has Windows start beyond its own.
///
/// Each value is a list separated by commas, and each item that is not
/// Windows' own program is an entry. The machine's `Userinit` as Windows
/// ships it is `C:\Windows\system32\userinit.exe,`, and its `Shell` is
/// `explorer.exe`; an account has no `Shell` of its own unless one is set.
fn read_winlogon(
    survey: &mut Survey,
    root: HKEY,
    path: &str,
    shown: &str,
    windows: &str,
    owner: Option<&UserContext>,
) {
    let key = match Key::look(root, path, View::Native) {
        Ok(key) => key,
        Err(Unopened::Absent) => return,
        Err(why) => {
            survey.unreadable.push(Unreadable::within(
                Anchor::Winlogon.kind(),
                shown,
                why.describe(shown),
            ));
            return;
        }
    };
    // An account's own Userinit is not one Windows reads.
    let values: &[&str] = match owner {
        None => &["Userinit", "Shell"],
        Some(_) => &["Shell"],
    };
    for value in values {
        let read = match key.read_string(value) {
            Ok(read) => read,
            Err(why) => {
                survey.unreadable.push(Unreadable::within(
                    Anchor::Winlogon.kind(),
                    shown,
                    format!(
                        "{}, so what it starts is not known",
                        why.describe(&format!("{shown}\\{value}"))
                    ),
                ));
                continue;
            }
        };
        let extra: Vec<&str> = read
            .as_deref()
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty() && !windows_own(value, item, windows))
            .collect();
        for (index, item) in extra.iter().enumerate() {
            let name = if index == 0 {
                (*value).to_owned()
            } else {
                format!("{value} ({})", index + 1)
            };
            survey.entries.push(persistence::entry(
                name,
                Anchor::Winlogon,
                shown.to_owned(),
                (*item).to_owned(),
                false,
                owner,
            ));
        }
    }
}

/// The programs a key of per-program settings names in one value: a
/// `Debugger` under Image File Execution Options, or a `MonitorProcess`
/// under `SilentProcessExit`. Windows ships neither for any program.
///
/// A program whose options keep a filter (`UseFilter`) can name a debugger for
/// one copy of it by its full path, in a key under its own; those are read
/// too, because a reader that looked only at the program's own key would
/// miss exactly the one set that way.
fn read_named_programs(
    survey: &mut Survey,
    root: HKEY,
    path: &str,
    view: View,
    shown: &str,
    anchor: Anchor,
    value: &str,
) {
    let key = match Key::look(root, path, view) {
        Ok(key) => key,
        Err(Unopened::Absent) => return,
        Err(why) => {
            survey.unreadable.push(Unreadable::within(
                anchor.kind(),
                shown,
                why.describe(shown),
            ));
            return;
        }
    };
    let listing = key.subkeys();
    if !listing.whole {
        survey.unreadable.push(Unreadable::within(
            anchor.kind(),
            shown,
            format!("{shown} could not be read to the end, so it may hold settings not shown"),
        ));
    }
    for program in listing.names {
        let place = format!(r"{shown}\{program}");
        let Some(options) = open_child(survey, &key, &program, &place, anchor) else {
            continue;
        };
        named_program(survey, &options, value, program.clone(), &place, anchor);
        if anchor == Anchor::Debugger && options.dword("UseFilter").unwrap_or(0) != 0 {
            let filters = options.subkeys();
            if !filters.whole {
                survey.unreadable.push(Unreadable::within(
                    anchor.kind(),
                    &place,
                    format!(
                        "{place} could not be read to the end, so it may hold settings not shown"
                    ),
                ));
            }
            for filter in filters.names {
                let filter_place = format!(r"{place}\{filter}");
                if let Some(filtered) = open_child(survey, &options, &filter, &filter_place, anchor)
                {
                    named_program(
                        survey,
                        &filtered,
                        value,
                        format!("{program} ({filter})"),
                        &filter_place,
                        anchor,
                    );
                }
            }
        }
    }
}

/// Open one subkey, saying so when it is there and will not open, or carries
/// a name that cannot be handed back to Windows to open it by.
fn open_child(
    survey: &mut Survey,
    key: &Key,
    name: &str,
    place: &str,
    anchor: Anchor,
) -> Option<Key> {
    if registry::is_hidden_name(name) {
        survey.unreadable.push(Unreadable::within(
            anchor.kind(),
            place,
            format!("{place} has a name that hides part of itself, so it could not be read"),
        ));
        return None;
    }
    match key.look_child(name) {
        Ok(child) => Some(child),
        Err(Unopened::Absent) => None,
        Err(why) => {
            survey.unreadable.push(Unreadable::within(
                anchor.kind(),
                place,
                why.describe(place),
            ));
            None
        }
    }
}

/// One program named in one value, as an entry.
fn named_program(
    survey: &mut Survey,
    key: &Key,
    value: &str,
    name: String,
    place: &str,
    anchor: Anchor,
) {
    match key.read_string(value) {
        Ok(Some(command)) => survey.entries.push(persistence::entry(
            name,
            anchor,
            place.to_owned(),
            command,
            false,
            None,
        )),
        Ok(None) => {}
        Err(why) => survey.unreadable.push(Unreadable::within(
            anchor.kind(),
            place,
            why.describe(&format!(r"{place}\{value}")),
        )),
    }
}

/// The libraries `AppInit_DLLs` lists, which Windows ships empty. Separated
/// by spaces or commas.
fn read_appinit(survey: &mut Survey, root: HKEY, path: &str, view: View, shown: &str) {
    let key = match Key::look(root, path, view) {
        Ok(key) => key,
        Err(Unopened::Absent) => return,
        Err(why) => {
            survey.unreadable.push(Unreadable::within(
                Anchor::AppInit.kind(),
                shown,
                why.describe(shown),
            ));
            return;
        }
    };
    match key.read_string("AppInit_DLLs") {
        Ok(listed) => {
            let libraries: Vec<String> = listed
                .unwrap_or_default()
                .split([' ', ','])
                .map(str::trim)
                .filter(|library| !library.is_empty())
                .map(str::to_owned)
                .collect();
            for (index, library) in libraries.into_iter().enumerate() {
                let name = if index == 0 {
                    "AppInit_DLLs".to_owned()
                } else {
                    format!("AppInit_DLLs ({})", index + 1)
                };
                survey.entries.push(persistence::entry(
                    name,
                    Anchor::AppInit,
                    shown.to_owned(),
                    library,
                    false,
                    None,
                ));
            }
        }
        Err(why) => survey.unreadable.push(Unreadable::within(
            Anchor::AppInit.kind(),
            shown,
            why.describe(&format!(r"{shown}\AppInit_DLLs")),
        )),
    }
}

/// An account's sign-in script, which Windows ships unset.
fn read_logon_script(survey: &mut Survey, root: HKEY, path: &str, shown: &str, user: &UserContext) {
    let key = match Key::look(root, path, View::Native) {
        Ok(key) => key,
        Err(Unopened::Absent) => return,
        Err(why) => {
            survey.unreadable.push(Unreadable::within(
                Anchor::LogonScript.kind(),
                shown,
                why.describe(shown),
            ));
            return;
        }
    };
    match key.read_string("UserInitMprLogonScript") {
        Ok(Some(command)) => survey.entries.push(persistence::entry(
            "UserInitMprLogonScript".to_owned(),
            Anchor::LogonScript,
            shown.to_owned(),
            command,
            false,
            Some(user),
        )),
        Ok(None) => {}
        Err(why) => survey.unreadable.push(Unreadable::within(
            Anchor::LogonScript.kind(),
            shown,
            why.describe(&format!(r"{shown}\UserInitMprLogonScript")),
        )),
    }
}

/// An account's own registrations of the COM classes scheduled tasks use.
///
/// `classes` is the account's `Software\Classes`, both views of it: the
/// 32-bit one is a key of its own there. A registration naming the same file
/// the machine's does (`machine` is how that is looked up) runs the same
/// thing and is not one; Windows ships none that differ.
fn read_com_overrides(
    survey: &mut Survey,
    root: HKEY,
    classes: &str,
    shown: &str,
    handlers: &[(String, String)],
    user: &UserContext,
    machine: impl Fn(&str) -> Option<std::path::PathBuf>,
) {
    for (task, class_id) in handlers {
        let class_id = class_id.trim();
        'views: for view in [r"CLSID", r"WOW6432Node\CLSID"] {
            for server in ["InprocServer32", "LocalServer32"] {
                let path = format!(r"{classes}\{view}\{class_id}\{server}");
                let place = format!(r"{shown}\{view}\{class_id}\{server}");
                let read = Key::look(root, &path, View::Native).and_then(|key| key.read_string(""));
                let command = match read {
                    Ok(Some(command)) => command,
                    Ok(None) | Err(Unopened::Absent) => continue,
                    Err(why) => {
                        survey.unreadable.push(Unreadable::within(
                            Anchor::ComOverride.kind(),
                            &place,
                            why.describe(&place),
                        ));
                        continue;
                    }
                };
                let theirs = persistence::resolve_for(&command, user).executable;
                let same = match (&theirs, machine(class_id)) {
                    (Some(theirs), Some(machine)) => theirs
                        .to_string_lossy()
                        .eq_ignore_ascii_case(&machine.to_string_lossy()),
                    _ => false,
                };
                if same {
                    continue;
                }
                survey.entries.push(persistence::entry(
                    task.clone(),
                    Anchor::ComOverride,
                    place,
                    command,
                    false,
                    Some(user),
                ));
                // One registration of a class is what runs for a task.
                break 'views;
            }
        }
    }
}

/// WMI event subscriptions whose consumer runs a command or a script, from
/// the rows WMI answered with.
///
/// Every such consumer is an entry, whether or not a binding ties it to an
/// event yet: Windows ships none of either kind (its own subscription writes
/// to the event log), and one that is not bound today can be bound tomorrow
/// without the consumer changing. A query that failed is a gap over every
/// subscription, never "none".
fn subscriptions_from(
    survey: &mut Survey,
    command_lines: Result<Vec<Row>, String>,
    scripts: Result<Vec<Row>, String>,
) {
    let text = |row: &Row, name: &str| {
        row.get(name)
            .and_then(Value::text)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_owned)
    };
    // Where it is, as WMI writes an object's path, so it can be found with
    // Windows' own tools.
    let place = |class: &str, name: &str| format!(r#"{SUBSCRIPTIONS}:{class}.Name="{name}""#);
    let mut failed = Vec::new();
    match command_lines {
        Ok(rows) => {
            for row in rows {
                let name = text(&row, "Name").unwrap_or_default();
                let Some(command) =
                    text(&row, "CommandLineTemplate").or_else(|| text(&row, "ExecutablePath"))
                else {
                    continue;
                };
                survey.entries.push(persistence::entry(
                    name.clone(),
                    Anchor::WmiSubscription,
                    place("CommandLineEventConsumer", &name),
                    command,
                    false,
                    None,
                ));
            }
        }
        Err(why) => failed.push(why),
    }
    match scripts {
        Ok(rows) => {
            for row in rows {
                let name = text(&row, "Name").unwrap_or_default();
                let location = place("ActiveScriptEventConsumer", &name);
                match text(&row, "ScriptFileName") {
                    Some(file) => survey.entries.push(persistence::entry(
                        name,
                        Anchor::WmiSubscription,
                        location,
                        file,
                        false,
                        None,
                    )),
                    None => {
                        let engine =
                            text(&row, "ScriptingEngine").unwrap_or_else(|| "script".to_owned());
                        survey.entries.push(Entry {
                            name,
                            anchor: Anchor::WmiSubscription,
                            location,
                            command: format!("a {engine} script held in the subscription"),
                            executable: None,
                            payload: None,
                            host: None,
                            hidden: false,
                            machine_wide: true,
                            missing: Some(
                                "its script is held inside the subscription itself, not in a \
                                 file"
                                    .to_owned(),
                            ),
                        });
                    }
                }
            }
        }
        Err(why) => failed.push(why),
    }
    if !failed.is_empty() {
        survey.unreadable.push(Unreadable::of(
            Anchor::WmiSubscription.kind(),
            format!(
                "WMI event subscriptions could not be read ({})",
                failed.join("; ")
            ),
        ));
    }
}

/// The line that says these places were checked, and what was found in them.
///
/// Built from what was read, so it never says a place is as Windows ships it
/// when that place could not be read.
pub fn also_checked(survey: &Survey) -> String {
    let names: Vec<&str> = PLACES.iter().map(|(name, _)| *name).collect();
    let unread: Vec<&str> = PLACES
        .iter()
        .filter(|(_, anchor)| {
            survey
                .unreadable
                .iter()
                .any(|source| source.kinds.iter().any(|kind| kind == anchor.kind()))
        })
        .map(|(name, _)| *name)
        .collect();
    let set: Vec<String> = survey
        .entries
        .iter()
        .filter(|entry| entry.anchor.is_quiet())
        .map(|entry| {
            format!(
                "{} \"{}\" ({})",
                entry.anchor.label(),
                entry.name,
                entry.command
            )
        })
        .collect();

    let mut line = format!("Also checked: {}.", joined(&names));
    match (set.is_empty(), unread.is_empty()) {
        (true, true) => line.push_str(" Nothing is set there beyond what Windows ships."),
        (true, false) => {
            line.push_str(" Nothing that could be read there is set beyond what Windows ships.")
        }
        (false, _) => line.push_str(&format!(
            " Set there beyond what Windows ships: {}.",
            set.join("; ")
        )),
    }
    if !unread.is_empty() {
        line.push_str(&format!(
            " {} could not be read in full, as the notes say.",
            capitalised(&joined(&unread))
        ));
    }
    line
}

/// Names joined for a sentence: "a", "a and b", "a, b and c".
fn joined(names: &[&str]) -> String {
    match names {
        [] => String::new(),
        [one] => (*one).to_owned(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

fn capitalised(text: &str) -> String {
    let mut characters = text.chars();
    match characters.next() {
        Some(first) => first.to_uppercase().chain(characters).collect(),
        None => String::new(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::scratch::ScratchKey;
    use windows::Win32::System::Registry::HKEY_CURRENT_USER;

    /// A Winlogon key laid out as the review read the development machine's,
    /// with each value exactly as Windows ships it.
    fn shipped_winlogon(scratch: &ScratchKey) {
        let windows = windows_folder();
        scratch.text(
            "Winlogon",
            "Userinit",
            &format!(r"{windows}\system32\userinit.exe,"),
        );
        scratch.text("Winlogon", "Shell", "explorer.exe");
    }

    fn winlogon(scratch: &ScratchKey, owner: Option<&UserContext>) -> Survey {
        let mut survey = Survey::default();
        read_winlogon(
            &mut survey,
            HKEY_CURRENT_USER,
            &scratch.under("Winlogon"),
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            &windows_folder(),
            owner,
        );
        survey
    }

    /// Winlogon as Windows ships it is no entry. A program added beside
    /// userinit.exe is one, by the program it adds; and Explorer replaced as
    /// the shell is one.
    #[test]
    fn winlogon_as_windows_ships_it_is_not_an_entry_and_a_program_added_is() {
        let scratch = ScratchKey::new("winlogon");
        shipped_winlogon(&scratch);
        let survey = winlogon(&scratch, None);
        assert!(survey.entries.is_empty(), "{:?}", survey.entries);
        assert!(survey.unreadable.is_empty());

        let windows = windows_folder();
        let added = std::env::temp_dir().join("kam-quiet-upd.exe");
        std::fs::write(&added, "MZ").unwrap();
        scratch.text(
            "Winlogon",
            "Userinit",
            &format!(r"{windows}\system32\userinit.exe,{},", added.display()),
        );
        scratch.text(
            "Winlogon",
            "Shell",
            "explorer.exe, kam-not-a-real-shell.exe",
        );
        let survey = winlogon(&scratch, None);
        std::fs::remove_file(&added).ok();
        let read: Vec<(&str, &str)> = survey
            .entries
            .iter()
            .map(|entry| (entry.name.as_str(), entry.command.as_str()))
            .collect();
        let added_text = added.display().to_string();
        assert_eq!(
            read,
            vec![
                ("Userinit", added_text.as_str()),
                ("Shell", "kam-not-a-real-shell.exe")
            ]
        );
        assert_eq!(survey.entries[0].anchor, Anchor::Winlogon);
        assert_eq!(survey.entries[0].target(), Some(added.as_path()));
        assert!(survey.entries[0].machine_wide);
    }

    /// An account's own Shell is read for that account, and its own Userinit
    /// is not one Windows reads.
    #[test]
    fn an_accounts_own_shell_is_read_for_it() {
        let scratch = ScratchKey::new("winlogon-account");
        scratch.text(
            "Winlogon",
            "Userinit",
            r"C:\Users\her\AppData\Roaming\upd.exe",
        );
        let her = UserContext::new(Some("S-1-5-21-1-2-3-1001".to_owned()), r"C:\Users\her");
        assert!(winlogon(&scratch, Some(&her)).entries.is_empty());

        scratch.text("Winlogon", "Shell", r"%APPDATA%\shell.exe");
        let survey = winlogon(&scratch, Some(&her));
        assert_eq!(survey.entries.len(), 1);
        assert_eq!(survey.entries[0].name, "Shell");
        assert!(!survey.entries[0].machine_wide);
    }

    fn named(scratch: &ScratchKey, anchor: Anchor, value: &str) -> Survey {
        let mut survey = Survey::default();
        read_named_programs(
            &mut survey,
            HKEY_CURRENT_USER,
            &scratch.under("Options"),
            View::Native,
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            anchor,
            value,
        );
        survey
    }

    /// Image File Execution Options as the review read them: programs with
    /// options and no debugger, which are no entry. A debugger set for Task
    /// Manager is one, by the program it is set for, and so is one set for a
    /// single copy of a program through a filter.
    #[test]
    fn a_debugger_set_for_a_program_is_an_entry_and_other_options_are_not() {
        let scratch = ScratchKey::new("image-options");
        scratch.number(r"Options\notepad.exe", "MitigationOptions", 0x100);
        scratch.number(r"Options\msedge.exe", "UseFilter", 0);
        assert!(named(&scratch, Anchor::Debugger, "Debugger")
            .entries
            .is_empty());

        scratch.text(
            r"Options\taskmgr.exe",
            "Debugger",
            r#""C:\Program Files\Process Explorer\procexp64.exe""#,
        );
        scratch.number(r"Options\sethc.exe", "UseFilter", 1);
        scratch.text(
            r"Options\sethc.exe\copy",
            "FilterFullPath",
            r"C:\Windows\System32\sethc.exe",
        );
        scratch.text(
            r"Options\sethc.exe\copy",
            "Debugger",
            r"C:\Windows\System32\cmd.exe",
        );
        let survey = named(&scratch, Anchor::Debugger, "Debugger");
        let mut read: Vec<&str> = survey
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        read.sort_unstable();
        assert_eq!(read, vec!["sethc.exe (copy)", "taskmgr.exe"]);
        assert!(survey
            .entries
            .iter()
            .all(|entry| entry.anchor == Anchor::Debugger));
        assert!(survey.unreadable.is_empty(), "{:?}", survey.unreadable);
    }

    /// A program set to start when another closes is an entry; the key not
    /// being there, which is how Windows ships, is none and no gap.
    #[test]
    fn a_program_started_when_another_closes_is_an_entry() {
        let scratch = ScratchKey::new("silent-exit");
        assert!(named(&scratch, Anchor::ExitMonitor, "MonitorProcess")
            .entries
            .is_empty());
        scratch.text(r"Options\notepad.exe", "ReportingMode", "1");
        scratch.text(
            r"Options\notepad.exe",
            "MonitorProcess",
            r"C:\ProgramData\x\watch.exe",
        );
        let survey = named(&scratch, Anchor::ExitMonitor, "MonitorProcess");
        assert_eq!(survey.entries.len(), 1);
        assert_eq!(survey.entries[0].name, "notepad.exe");
        assert_eq!(survey.entries[0].anchor, Anchor::ExitMonitor);
    }

    /// AppInit_DLLs as Windows ships it, empty, is no entry; each library it
    /// lists is one.
    #[test]
    fn each_appinit_library_is_an_entry() {
        let scratch = ScratchKey::new("appinit");
        scratch.text("Windows", "AppInit_DLLs", "");
        scratch.number("Windows", "LoadAppInit_DLLs", 0);
        let read = |scratch: &ScratchKey| {
            let mut survey = Survey::default();
            read_appinit(
                &mut survey,
                HKEY_CURRENT_USER,
                &scratch.under("Windows"),
                View::Native,
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            );
            survey
        };
        assert!(read(&scratch).entries.is_empty());
        scratch.text(
            "Windows",
            "AppInit_DLLs",
            r"C:\ProgramData\hook.dll, C:\ProgramData\two.dll",
        );
        let survey = read(&scratch);
        let names: Vec<&str> = survey
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        assert_eq!(names, vec!["AppInit_DLLs", "AppInit_DLLs (2)"]);
    }

    /// An account's sign-in script is an entry for that account, read with
    /// its own folders.
    #[test]
    fn an_accounts_sign_in_script_is_an_entry() {
        let scratch = ScratchKey::new("logon-script");
        let her = UserContext::new(Some("S-1-5-21-1-2-3-1001".to_owned()), r"C:\Users\her");
        let read = |scratch: &ScratchKey| {
            let mut survey = Survey::default();
            read_logon_script(
                &mut survey,
                HKEY_CURRENT_USER,
                &scratch.under("Environment"),
                r"HKEY_USERS\S-1-5-21-1-2-3-1001\Environment",
                &her,
            );
            survey
        };
        scratch.text("Environment", "TEMP", r"%USERPROFILE%\AppData\Local\Temp");
        assert!(read(&scratch).entries.is_empty());
        scratch.text(
            "Environment",
            "UserInitMprLogonScript",
            r"%APPDATA%\logon.cmd",
        );
        let survey = read(&scratch);
        assert_eq!(survey.entries.len(), 1);
        assert_eq!(survey.entries[0].anchor, Anchor::LogonScript);
        assert_eq!(
            survey.entries[0].location,
            r"HKEY_USERS\S-1-5-21-1-2-3-1001\Environment"
        );
        assert!(!survey.entries[0].machine_wide);
    }

    /// An account's own registration of a class a task uses is an entry for
    /// that task, naming the file that runs for that account. One that names
    /// the same file the machine registers is not, and a class no task uses
    /// is not read at all.
    #[test]
    fn an_accounts_own_registration_of_a_tasks_class_is_an_entry() {
        let scratch = ScratchKey::new("com");
        let her = UserContext::new(Some("S-1-5-21-1-2-3-1001".to_owned()), r"C:\Users\her");
        let task_class = "{58FB76B9-AC85-4E55-AC04-427593B1D060}";
        let other_class = "{11111111-2222-3333-4444-555555555555}";
        let handlers = vec![(
            r"Microsoft\Windows\CertificateServicesClient\UserTask".to_owned(),
            task_class.to_owned(),
        )];
        let machine_file = std::env::var("SystemRoot").unwrap() + r"\System32\kernel32.dll";
        let read = |scratch: &ScratchKey| {
            let mut survey = Survey::default();
            let machine = machine_file.clone();
            read_com_overrides(
                &mut survey,
                HKEY_CURRENT_USER,
                &scratch.under("Classes"),
                r"HKEY_USERS\S-1-5-21-1-2-3-1001\Software\Classes",
                &handlers,
                &her,
                move |_| Some(std::path::PathBuf::from(&machine)),
            );
            survey
        };

        // How the review found the development machine: classes of the
        // account's own, none of them one a task uses.
        scratch.text(
            &format!(r"Classes\CLSID\{other_class}\InprocServer32"),
            "",
            r"C:\Users\her\AppData\Local\Thing\thing.dll",
        );
        assert!(read(&scratch).entries.is_empty());

        // The same file the machine registers runs the same thing.
        scratch.text(
            &format!(r"Classes\CLSID\{task_class}\InprocServer32"),
            "",
            &machine_file,
        );
        assert!(read(&scratch).entries.is_empty());

        // A file of its own, in the 32-bit view.
        scratch.text(
            &format!(r"Classes\WOW6432Node\CLSID\{task_class}\InprocServer32"),
            "",
            r"C:\Users\her\AppData\Roaming\hook.dll",
        );
        let survey = read(&scratch);
        assert_eq!(survey.entries.len(), 1, "{:?}", survey.entries);
        let entry = &survey.entries[0];
        assert_eq!(entry.anchor, Anchor::ComOverride);
        assert_eq!(
            entry.name,
            r"Microsoft\Windows\CertificateServicesClient\UserTask"
        );
        assert_eq!(entry.command, r"C:\Users\her\AppData\Roaming\hook.dll");
        assert!(entry
            .location
            .starts_with(r"HKEY_USERS\S-1-5-21-1-2-3-1001\Software\Classes\WOW6432Node\CLSID"));
    }

    fn row(values: &[(&str, &str)]) -> Row {
        values
            .iter()
            .map(|(name, value)| ((*name).to_owned(), Value::Text((*value).to_owned())))
            .collect()
    }

    /// Windows' own subscription writes to the event log and is not one of
    /// the consumers read, so the development machine's answer is no entry.
    /// A consumer that runs a command is one, and one whose script is held in
    /// the subscription is one that says it has no file to judge.
    #[test]
    fn a_subscription_that_runs_a_command_or_a_script_is_an_entry() {
        let mut survey = Survey::default();
        subscriptions_from(&mut survey, Ok(Vec::new()), Ok(Vec::new()));
        assert!(survey.entries.is_empty());
        assert!(survey.unreadable.is_empty());

        let mut survey = Survey::default();
        subscriptions_from(
            &mut survey,
            Ok(vec![row(&[
                ("Name", "Updater"),
                ("CommandLineTemplate", "powershell.exe -enc SQBFAFgA"),
            ])]),
            Ok(vec![row(&[
                ("Name", "Quiet"),
                ("ScriptingEngine", "VBScript"),
                ("ScriptText", "x"),
            ])]),
        );
        assert_eq!(survey.entries.len(), 2);
        let updater = &survey.entries[0];
        assert_eq!(updater.name, "Updater");
        assert_eq!(updater.anchor, Anchor::WmiSubscription);
        assert_eq!(
            updater.location,
            r#"ROOT\subscription:CommandLineEventConsumer.Name="Updater""#
        );
        let quiet = &survey.entries[1];
        assert!(quiet.target().is_none());
        assert!(quiet
            .unresolved()
            .unwrap()
            .contains("held inside the subscription"));
    }

    /// WMI not answering is a gap over every subscription, never "none".
    #[test]
    fn subscriptions_that_could_not_be_read_are_a_gap_not_none() {
        let mut survey = Survey::default();
        subscriptions_from(
            &mut survey,
            Err("the namespace did not answer".to_owned()),
            Ok(Vec::new()),
        );
        assert!(survey.entries.is_empty());
        assert_eq!(survey.unreadable.len(), 1);
        assert!(survey.unreadable[0].covers(
            Anchor::WmiSubscription.kind(),
            r#"root\subscription:commandlineeventconsumer.name="anything""#
        ));
        assert!(survey.unreadable[0]
            .what
            .starts_with("WMI event subscriptions could not be read"));
    }

    /// The line names every place, says nothing is set when that is so, names
    /// what is set when something is, and never calls a place that could not
    /// be read as Windows ships it.
    #[test]
    fn the_also_checked_line_says_only_what_was_read() {
        let clean = also_checked(&Survey::default());
        assert!(
            clean.starts_with("Also checked: the Windows sign-in programs, debugger redirections")
        );
        assert!(
            clean.ends_with("Nothing is set there beyond what Windows ships."),
            "{clean}"
        );

        let mut set = Survey::default();
        set.entries.push(persistence::entry(
            "taskmgr.exe".to_owned(),
            Anchor::Debugger,
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe".to_owned(),
            r"C:\Tools\procexp64.exe".to_owned(),
            false,
            None,
        ));
        let line = also_checked(&set);
        assert!(
            line.contains(r#"Set there beyond what Windows ships: a debugger set for a program "taskmgr.exe" (C:\Tools\procexp64.exe)."#),
            "{line}"
        );

        let mut unread = Survey::default();
        unread.unreadable.push(Unreadable::of(
            Anchor::WmiSubscription.kind(),
            "WMI event subscriptions could not be read",
        ));
        let line = also_checked(&unread);
        assert!(!line.contains("Nothing is set there"), "{line}");
        assert!(
            line.contains("Nothing that could be read there is set"),
            "{line}"
        );
        assert!(
            line.contains("WMI event subscriptions could not be read in full"),
            "{line}"
        );
    }

    /// An account that is not signed in is not read as one with nothing set.
    #[test]
    fn an_account_that_is_not_signed_in_is_not_read_as_having_nothing_set() {
        let absent = UserContext::new(Some("S-1-5-21-1-2-3-31337".to_owned()), r"C:\Users\nobody");
        assert!(of_account(&absent, &[]).is_none());
    }
}
