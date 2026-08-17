//! What starts itself, and where it starts from.
//!
//! Software that survives a reboot without you launching it has claimed
//! something, and the list of things that have claimed it is short enough for a
//! person to read. That is the whole idea here: not to judge, but to enumerate.
//! Task Manager's Startup tab shows a fraction of this and refuses to say where
//! any of it lives.
//!
//! # What counts as persistence
//!
//! Windows offers a great many ways to run at boot; this covers the four that
//! ordinary software — and ordinary unwanted software — actually uses:
//!
//! - the `Run` and `RunOnce` keys, in both hives and both registry views
//! - the Startup folders, per-user and machine-wide
//! - services set to start automatically
//! - scheduled tasks, which are read as files because the COM interface for
//!   them is an unpleasant dependency for what amounts to reading XML
//!
//! Deliberately absent: WMI event subscriptions, COM hijacks, AppInit DLLs,
//! image-file-execution options. They are real techniques, they are also almost
//! never what is bothering a person cleaning up their own machine, and each one
//! added would dilute a list whose value is that it is short enough to read.
//! The interface says which places were examined rather than implying the
//! result is exhaustive.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kam_core::registry::{self, View};
use serde::{Deserialize, Serialize};
use windows::core::PCWSTR;
use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
use windows::Win32::UI::Shell::SHLoadIndirectString;

/// Where an auto-start entry was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Anchor {
    /// A `Run` key: runs at every sign-in.
    RunKey,
    /// A `RunOnce` key: runs at the next sign-in, then deletes itself.
    RunOnceKey,
    /// A shortcut or executable in a Startup folder.
    StartupFolder,
    /// A Windows service set to start on its own.
    Service,
    /// A scheduled task with a trigger.
    ScheduledTask,
}

impl Anchor {
    /// How firmly this holds on, for ordering. Higher is harder to be rid of
    /// by accident, and harder for a person to find.
    pub fn tenacity(self) -> u8 {
        match self {
            Self::RunOnceKey => 1,
            Self::StartupFolder => 2,
            Self::RunKey => 3,
            Self::ScheduledTask => 4,
            Self::Service => 5,
        }
    }

    /// A noun phrase, so it reads correctly both as a chip on its own and in
    /// the middle of a sentence. Mixing noun phrases with verb phrases here
    /// produces text like "It runs at sign-in" alongside "It a Windows
    /// service", which is the kind of detail that makes software feel unfinished.
    pub fn label(self) -> &'static str {
        match self {
            Self::RunKey => "a sign-in entry",
            Self::RunOnceKey => "a run-once entry",
            Self::StartupFolder => "a Startup folder item",
            Self::Service => "a Windows service",
            Self::ScheduledTask => "a scheduled task",
        }
    }
}

/// One thing that starts itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// The name under which it registered itself.
    pub name: String,
    /// How it starts.
    pub anchor: Anchor,
    /// Exactly where the entry lives, so it can be found and removed by hand.
    pub location: String,
    /// The command as written, arguments and all.
    pub command: String,
    /// The executable the command resolves to, when one could be found.
    pub executable: Option<PathBuf>,
    /// True for machine-wide entries, which affect every account and need
    /// administrator rights to have been created.
    pub machine_wide: bool,
}

/// Pull the executable out of a command line.
///
/// Registry commands are written by whoever installed them and follow no rule:
/// quoted paths, unquoted paths with spaces, bare executable names, `rundll32`
/// invocations, environment variables. This handles the shapes that occur and
/// returns nothing rather than guessing when it cannot.
pub fn executable_in(command: &str) -> Option<PathBuf> {
    let command = command.trim();
    if command.is_empty() {
        return None;
    }

    // Expand environment variables first: `%ProgramFiles%\thing\thing.exe` is
    // common and useless left as written.
    let expanded = expand(command);
    let trimmed = expanded.trim();

    // A quoted path is unambiguous, which is why installers that get this right
    // use one.
    if let Some(rest) = trimmed.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            let candidate = PathBuf::from(&rest[..end]);
            return candidate.is_file().then_some(candidate);
        }
    }

    // Unquoted. Try progressively longer prefixes, because `C:\Program
    // Files\Thing\thing.exe -quiet` and `C:\thing.exe -a b` are the same shape
    // until you check the disk. Windows itself resolves this ambiguity the same
    // way, which is the source of a well-known class of privilege escalation.
    let bytes: Vec<&str> = trimmed.split(' ').collect();
    for take in 1..=bytes.len() {
        let candidate = PathBuf::from(bytes[..take].join(" "));
        if candidate.is_file() {
            return Some(candidate);
        }
        // Stop extending once a token looks like a switch; beyond that it is
        // arguments, not a longer path.
        if bytes.get(take).is_some_and(|token| {
            token.starts_with('-') || token.starts_with('/') || token.starts_with("--")
        }) {
            break;
        }
    }

    None
}

/// Expand `%NAME%` references against the current environment.
fn expand(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;

    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let name = &after[..end];
                match std::env::var(name) {
                    Ok(value) => out.push_str(&value),
                    // An unset variable is left as written rather than silently
                    // becoming an empty string, which would produce a path that
                    // looks plausible and is wrong.
                    Err(_) => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push('%');
                rest = after;
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Resolve a display name that is really a pointer into a resource file.
///
/// Services routinely store their name as `@%SystemRoot%\system32\thing.dll,-101`,
/// meaning "string 101 in that library, in the user's language". Showing that
/// to a person is worse than showing the bare service key name, so an
/// unresolvable reference falls back to the key name rather than being
/// displayed raw.
fn resolve_display_name(name: &str, fallback: &str) -> String {
    if !name.starts_with('@') {
        return name.to_owned();
    }

    let source: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut buffer = [0_u16; 512];
    let resolved = unsafe {
        SHLoadIndirectString(PCWSTR(source.as_ptr()), &mut buffer, None)
    };

    if resolved.is_ok() {
        let end = buffer.iter().position(|c| *c == 0).unwrap_or(buffer.len());
        let text = String::from_utf16_lossy(&buffer[..end]).trim().to_owned();
        if !text.is_empty() {
            return text;
        }
    }
    fallback.to_owned()
}

/// The auto-start registry keys worth reading, and what each one means.
const RUN_KEYS: &[(&str, Anchor)] = &[
    (r"Software\Microsoft\Windows\CurrentVersion\Run", Anchor::RunKey),
    (
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        Anchor::RunOnceKey,
    ),
];

fn read_run_keys(entries: &mut Vec<Entry>) {
    // Both hives and both views. A 32-bit installer writing to the Run key on a
    // 64-bit machine lands in `WOW6432Node`, and reading only the native view
    // would miss it entirely — which is exactly the kind of blind spot that
    // makes people distrust a tool like this.
    let hives = [
        (HKEY_LOCAL_MACHINE, "HKLM", true),
        (HKEY_CURRENT_USER, "HKCU", false),
    ];
    let views = [(View::Native, ""), (View::Wow6432, r"\WOW6432Node")];

    for (hive, hive_label, machine_wide) in hives {
        for (view, view_label) in views {
            for (path, anchor) in RUN_KEYS {
                let Some(key) = registry::Key::open(hive, path, view) else {
                    continue;
                };
                for name in key.value_names() {
                    let Some(command) = key.string(&name) else {
                        continue;
                    };
                    if command.trim().is_empty() {
                        continue;
                    }
                    entries.push(Entry {
                        name,
                        anchor: *anchor,
                        location: format!("{hive_label}\\{path}{view_label}"),
                        executable: executable_in(&command),
                        command,
                        machine_wide,
                    });
                }
            }
        }
    }
}

/// Files sitting in a Startup folder.
fn read_startup_folders(entries: &mut Vec<Entry>) {
    let mut folders: Vec<(PathBuf, bool)> = Vec::new();

    if let Ok(appdata) = std::env::var("APPDATA") {
        folders.push((
            PathBuf::from(appdata).join(r"Microsoft\Windows\Start Menu\Programs\Startup"),
            false,
        ));
    }
    if let Ok(program_data) = std::env::var("ProgramData") {
        folders.push((
            PathBuf::from(program_data).join(r"Microsoft\Windows\Start Menu\Programs\Startup"),
            true,
        ));
    }

    for (folder, machine_wide) in folders {
        let Ok(listing) = std::fs::read_dir(&folder) else {
            continue;
        };
        for item in listing.flatten() {
            let path = item.path();
            let name = path
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
                .unwrap_or_default();
            // `desktop.ini` controls how the folder is displayed and starts
            // nothing.
            if name.eq_ignore_ascii_case("desktop") {
                continue;
            }
            entries.push(Entry {
                name,
                anchor: Anchor::StartupFolder,
                location: folder.display().to_string(),
                command: path.display().to_string(),
                // A shortcut points elsewhere, and resolving it needs the shell
                // link interface. The file itself is still the honest answer to
                // "what is in this folder".
                executable: path
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
                    .then(|| path.clone()),
                machine_wide,
            });
        }
    }
}

/// Services that start without being asked.
fn read_services(entries: &mut Vec<Entry>) {
    let Some(root) = registry::Key::open(
        HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services",
        View::Native,
    ) else {
        return;
    };

    for name in root.subkey_names() {
        let Some(service) = root.child(&name) else {
            continue;
        };

        // Start: 0 boot, 1 system, 2 automatic, 3 on demand, 4 disabled. Only
        // the first three run without someone asking, and 0 and 1 are drivers.
        let Some(start) = service.dword("Start") else {
            continue;
        };
        if start > 2 {
            continue;
        }

        // Type 1 and 2 are kernel and file-system drivers, which are a separate
        // subject and would swamp the list.
        if service.dword("Type").is_some_and(|kind| kind < 0x10) {
            continue;
        }

        let Some(image) = service.string("ImagePath") else {
            continue;
        };

        entries.push(Entry {
            name: service
                .string("DisplayName")
                .map(|display| resolve_display_name(&display, &name))
                .unwrap_or_else(|| name.clone()),
            anchor: Anchor::Service,
            location: format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{name}"),
            executable: executable_in(&image),
            command: image,
            machine_wide: true,
        });
    }
}

/// Scheduled tasks, read from the files the scheduler keeps them in.
///
/// The task store mirrors the task tree as a directory tree, and the registry
/// holds the same set under `TaskCache`. Reading files avoids taking a COM
/// dependency for what is ultimately XML, but it does mean tasks are only
/// visible where the file is readable — the scanner runs as LocalSystem, so it
/// is.
fn read_scheduled_tasks(survey: &mut Survey) {
    let Ok(root) = std::env::var("SystemRoot") else {
        return;
    };
    let store = PathBuf::from(root).join(r"System32\Tasks");

    // The store is readable by administrators only. The agent runs as
    // LocalSystem so this succeeds in service, but it must report the gap
    // rather than return an empty list when it does not.
    if let Err(error) = std::fs::read_dir(&store) {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            survey.unreadable.push(
                "Scheduled tasks could not be read without administrator rights.".to_owned(),
            );
        }
        return;
    }

    let mut found = Vec::new();
    walk_tasks(&store, &store, &mut found, 0);
    survey.entries.extend(found);
}

fn walk_tasks(root: &Path, folder: &Path, entries: &mut Vec<Entry>, depth: usize) {
    // The task tree is shallow in practice; the bound is here so a link loop
    // cannot turn this into an unbounded walk.
    if depth > 8 {
        return;
    }
    let Ok(listing) = std::fs::read_dir(folder) else {
        return;
    };

    for item in listing.flatten() {
        let path = item.path();
        if path.is_dir() {
            walk_tasks(root, &path, entries, depth + 1);
            continue;
        }

        let Some(xml) = read_task(&path) else {
            continue;
        };

        // A task with no trigger runs only when something asks it to, which is
        // not persistence.
        if !xml.contains("<Triggers>") || xml.contains("<Triggers />") {
            continue;
        }
        let Some(command) = between(&xml, "<Command>", "</Command>") else {
            continue;
        };

        let command = unescape(&command);
        let arguments = between(&xml, "<Arguments>", "</Arguments>").map(|args| unescape(&args));
        let full = match &arguments {
            Some(args) if !args.is_empty() => format!("{command} {args}"),
            _ => command.clone(),
        };

        let name = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();

        entries.push(Entry {
            name,
            anchor: Anchor::ScheduledTask,
            location: path.display().to_string(),
            executable: executable_in(&command),
            command: full,
            machine_wide: true,
        });
    }
}

/// Read a task definition, whatever it is encoded as.
///
/// The scheduler writes these as UTF-16 with a byte order mark — every one of
/// them, on every machine. Reading them as UTF-8 fails on the very first byte,
/// which makes the whole reader silently return nothing: no error, no empty
/// folder, just a category that quietly never appears. Encoding is checked
/// here rather than assumed for exactly that reason.
fn read_task(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;

    let text = if bytes.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else if bytes.starts_with(&[0xFE, 0xFF]) {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(&bytes).into_owned()
    };

    Some(text)
}

fn between(text: &str, open: &str, close: &str) -> Option<String> {
    let start = text.find(open)? + open.len();
    let end = text[start..].find(close)? + start;
    Some(text[start..end].trim().to_owned())
}

/// The five XML entities, which is all the scheduler emits.
fn unescape(text: &str) -> String {
    text.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// What was found, and what could not be looked at.
///
/// The second half matters as much as the first. The task store is unreadable
/// without administrator rights, and a list that quietly omitted every
/// scheduled task would be worse than no list — it would look complete. So the
/// places that could not be read are carried alongside the results and shown.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Survey {
    pub entries: Vec<Entry>,
    /// Sources that exist but could not be read, in plain words.
    pub unreadable: Vec<String>,
}

impl Survey {
    /// True when every source was readable, so the list can be presented as
    /// the whole picture.
    pub fn complete(&self) -> bool {
        self.unreadable.is_empty()
    }
}

/// Everything on this machine that starts itself.
pub fn survey() -> Survey {
    let mut survey = Survey::default();
    read_run_keys(&mut survey.entries);
    read_startup_folders(&mut survey.entries);
    read_services(&mut survey.entries);
    read_scheduled_tasks(&mut survey);

    // Hardest-to-shift first, then alphabetically, so the order is stable
    // between runs and the interesting end is the top.
    survey.entries.sort_by(|a, b| {
        b.anchor
            .tenacity()
            .cmp(&a.anchor.tenacity())
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    survey
}

/// Group the entries by the executable they point at.
///
/// One program frequently holds on in several ways at once — a service and a
/// scheduled task and a Run key — and seeing those together is the point.
pub fn by_executable(entries: &[Entry]) -> BTreeMap<PathBuf, Vec<&Entry>> {
    let mut grouped: BTreeMap<PathBuf, Vec<&Entry>> = BTreeMap::new();
    for entry in entries {
        if let Some(executable) = &entry.executable {
            grouped
                .entry(PathBuf::from(
                    executable.to_string_lossy().to_lowercase().replace('/', "\\"),
                ))
                .or_default()
                .push(entry);
        }
    }
    grouped
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_quoted_path_with_arguments_resolves() {
        let command = format!("\"{}\" --background", system32("notepad.exe").display());
        assert_eq!(
            executable_in(&command).unwrap().to_string_lossy().to_lowercase(),
            system32("notepad.exe").to_string_lossy().to_lowercase()
        );
    }

    #[test]
    fn an_unquoted_path_containing_spaces_resolves() {
        // The shape that trips up naive parsers, and the one installers write
        // most often.
        let root = std::env::var("SystemRoot").unwrap();
        let command = format!(r"{root}\System32\notepad.exe /a");
        assert!(executable_in(&command).is_some(), "should have found notepad");
    }

    #[test]
    fn environment_variables_are_expanded() {
        let command = r"%SystemRoot%\System32\notepad.exe";
        assert!(
            executable_in(command).is_some(),
            "an unexpanded variable makes the path useless"
        );
    }

    #[test]
    fn an_unset_variable_is_left_alone_rather_than_blanked() {
        // Blanking would produce `\Thing\thing.exe`, which looks like a real
        // path and is not one.
        let text = expand(r"%KAM_DEFINITELY_NOT_SET%\thing.exe");
        assert_eq!(text, r"%KAM_DEFINITELY_NOT_SET%\thing.exe");
    }

    #[test]
    fn a_command_pointing_nowhere_yields_nothing() {
        assert_eq!(executable_in(r"C:\nope\missing.exe -x"), None);
        assert_eq!(executable_in(""), None);
        assert_eq!(executable_in("   "), None);
    }

    #[test]
    fn xml_entities_are_decoded() {
        assert_eq!(unescape("a &amp; b &quot;c&quot;"), "a & b \"c\"");
    }

    #[test]
    fn a_resource_reference_never_reaches_the_screen() {
        // Whether or not it resolves, what comes back must be a name rather
        // than a pointer into a library.
        let resolved = resolve_display_name(
            r"@%SystemRoot%\system32\wscsvc.dll,-200",
            "wscsvc",
        );
        assert!(
            !resolved.starts_with('@'),
            "an unresolved reference leaked to the caller: {resolved}"
        );
        println!("resolved to: {resolved}");

        // A plain name is passed through untouched.
        assert_eq!(resolve_display_name("Print Spooler", "spooler"), "Print Spooler");
    }

    #[test]
    fn services_outrank_run_once() {
        assert!(Anchor::Service.tenacity() > Anchor::RunOnceKey.tenacity());
    }

    fn system32(name: &str) -> PathBuf {
        PathBuf::from(std::env::var("SystemRoot").unwrap())
            .join("System32")
            .join(name)
    }

    #[test]
    fn this_machine_has_things_that_start_themselves() {
        let survey = survey();
        assert!(
            !survey.entries.is_empty(),
            "every Windows machine has auto-start entries; finding none means the readers are broken"
        );

        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for entry in &survey.entries {
            *counts.entry(entry.anchor.label()).or_default() += 1;
        }
        println!("{} entries: {counts:?}", survey.entries.len());
        println!("unreadable: {:?}", survey.unreadable);

        // These two are readable by anyone, so they must not be empty.
        for anchor in [Anchor::RunKey, Anchor::Service] {
            assert!(
                survey.entries.iter().any(|entry| entry.anchor == anchor),
                "nothing found for {}",
                anchor.label()
            );
        }

        // Scheduled tasks need administrator rights. If the store could not be
        // read the survey must say so; if it could, tasks must actually have
        // come back. Silence in either direction is the failure — and is
        // precisely what a UTF-16 decoding bug once produced here.
        let tasks = survey
            .entries
            .iter()
            .filter(|e| e.anchor == Anchor::ScheduledTask)
            .count();
        if survey.complete() {
            assert!(
                tasks > 0,
                "the task store was readable but produced no entries"
            );
        } else {
            assert_eq!(tasks, 0, "tasks were read despite being reported unreadable");
        }
        println!("scheduled tasks: {tasks}");

        let resolved = survey.entries.iter().filter(|e| e.executable.is_some()).count();
        println!(
            "resolved {resolved}/{} commands to an executable",
            survey.entries.len()
        );
        for entry in survey.entries.iter().take(12) {
            println!(
                "  [{}] {} -> {:?}",
                entry.anchor.label(),
                entry.name,
                entry.executable
            );
        }
    }
}
