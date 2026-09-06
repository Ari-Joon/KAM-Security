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
//!
//! # What an entry actually runs
//!
//! The first version of this reader stopped at the first executable in the
//! command, and that was a mistake that mattered. A scheduled task whose
//! command is `cmd.exe /c "C:\Users\x\AppData\Local\...\analytics.cmd"` starts
//! `cmd.exe` in exactly the sense that a bus starts a passenger: the thing
//! worth looking at is the script, and `cmd.exe` is signed by Microsoft, lives
//! in `System32`, and hosts a dozen of Windows' own tasks. Judged by its
//! launcher, that task was indistinguishable from Windows. Judged by what it
//! ran, it was an unsigned script in a folder any program can write to,
//! registered as a hidden task, and it was the persistence of a real
//! credential-stealing infection that Defender never noticed.
//!
//! So every entry now carries both: the [`Entry::executable`] the command names
//! and, when that executable is one of the programs whose job is to run
//! something else, the [`Entry::payload`] it is told to run. Everything that
//! judges an entry judges the payload when there is one.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kam_core::registry::{self, View};
use kam_core::UserContext;
use serde::{Deserialize, Serialize};
use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, HKEY_USERS};

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
    /// What that executable is told to run, when it is a program whose job is
    /// to run other things: the script behind `cmd.exe /c`, the project behind
    /// `MSBuild.exe`, the library behind `rundll32.exe`. This is the thing to
    /// judge; the executable is only the vehicle.
    #[serde(default)]
    pub payload: Option<PathBuf>,
    /// The name of that vehicle, such as `cmd.exe`, when there is a payload.
    #[serde(default)]
    pub host: Option<String>,
    /// True for a scheduled task that asked not to be shown in Task Scheduler.
    /// Ordinary software has no reason to.
    #[serde(default)]
    pub hidden: bool,
    /// True for machine-wide entries, which affect every account and need
    /// administrator rights to have been created.
    pub machine_wide: bool,
}

impl Entry {
    /// The file that actually runs: the payload when there is one, otherwise
    /// the executable itself.
    pub fn target(&self) -> Option<&Path> {
        self.payload.as_deref().or(self.executable.as_deref())
    }
}

/// Programs whose purpose is to run something named on their command line.
///
/// Every one of these is signed by Microsoft, lives in a protected folder, and
/// is used by Windows itself — which is exactly why unwanted software starts
/// itself through them. Judging the host tells you nothing; judging what the
/// host is handed tells you everything.
const HOSTS: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "msbuild.exe",
    "msiexec.exe",
    "conhost.exe",
    "python.exe",
    "pythonw.exe",
    "node.exe",
    "java.exe",
    "javaw.exe",
];

/// Whether a file name is one of the launchers above.
pub fn is_host(name: &str) -> bool {
    let name = name.to_lowercase();
    HOSTS.contains(&name.as_str())
}

/// A command line taken apart.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resolved {
    pub executable: Option<PathBuf>,
    pub host: Option<String>,
    pub payload: Option<PathBuf>,
}

/// Pull the executable out of a command line.
///
/// Registry commands are written by whoever installed them and follow no rule:
/// quoted paths, unquoted paths with spaces, bare executable names, `rundll32`
/// invocations, environment variables. This handles the shapes that occur and
/// returns nothing rather than guessing when it cannot.
pub fn executable_in(command: &str) -> Option<PathBuf> {
    split_executable(&kam_core::env::expand(command.trim())).map(|(path, _)| path)
}

/// The executable at the front of a command, and everything after it.
fn split_executable(expanded: &str) -> Option<(PathBuf, String)> {
    let trimmed = expanded.trim();
    if trimmed.is_empty() {
        return None;
    }

    // A quoted path is unambiguous, which is why installers that get this right
    // use one.
    if let Some(rest) = trimmed.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            let candidate = locate(&rest[..end])?;
            return Some((candidate, rest[end + 1..].trim().to_owned()));
        }
    }

    // Unquoted. Try progressively longer prefixes, because `C:\Program
    // Files\Thing\thing.exe -quiet` and `C:\thing.exe -a b` are the same shape
    // until you check the disk. Windows itself resolves this ambiguity the same
    // way, which is the source of a well-known class of privilege escalation.
    let tokens: Vec<&str> = trimmed.split(' ').collect();
    for take in 1..=tokens.len() {
        if let Some(candidate) = locate(&tokens[..take].join(" ")) {
            return Some((candidate, tokens[take..].join(" ").trim().to_owned()));
        }
        // Stop extending once a token looks like a switch; beyond that it is
        // arguments, not a longer path.
        if tokens.get(take).is_some_and(|token| {
            token.starts_with('-') || token.starts_with('/') || token.starts_with("--")
        }) {
            break;
        }
    }

    None
}

/// Find a file from how a command names it.
///
/// A bare name such as `cmd.exe` or `rundll32.exe` is looked up in `System32`,
/// because that is where Windows would find it and because commands written
/// that way are common in the task store. Nothing else is searched: walking
/// `PATH` from inside a service would resolve names against SYSTEM's
/// environment rather than the user's, which is a way of being wrong quietly.
fn locate(text: &str) -> Option<PathBuf> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let direct = PathBuf::from(text);
    if direct.is_file() {
        return Some(direct);
    }
    if text.contains('\\') || text.contains('/') {
        return None;
    }
    let root = std::env::var("SystemRoot").ok()?;
    let base = PathBuf::from(&root);
    // The directories a bare Windows program name is found in. `System32`
    // covers cmd, wscript, rundll32, mshta and the rest; PowerShell lives one
    // level down and is written bare in the task store constantly, so missing
    // it meant every PowerShell-launched payload resolved to nothing.
    let dirs = [
        base.join("System32"),
        base.join(r"System32\WindowsPowerShell\v1.0"),
        base.join("SysWOW64"),
    ];
    for name in [text.to_owned(), format!("{text}.exe")] {
        for dir in &dirs {
            let candidate = dir.join(&name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Split arguments the way Windows programs mostly do: on spaces, with double
/// quotes grouping. Good enough for the commands installers and the scheduler
/// write; it does not try to reproduce `CommandLineToArgvW`'s backslash rules.
pub fn tokenise(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut had_quote = false;
    for character in text.chars() {
        match character {
            '"' => {
                quoted = !quoted;
                had_quote = true;
            }
            ' ' if !quoted => {
                if !current.is_empty() || had_quote {
                    tokens.push(std::mem::take(&mut current));
                }
                had_quote = false;
            }
            other => current.push(other),
        }
    }
    if !current.is_empty() || had_quote {
        tokens.push(current);
    }
    tokens
}

fn is_switch(token: &str) -> bool {
    token.starts_with('/') || token.starts_with('-')
}

/// The argument a host program is told to run, if it names a file that exists.
fn payload_of(host: &str, arguments: &str) -> Option<PathBuf> {
    let tokens = tokenise(arguments);
    let lower: Vec<String> = tokens.iter().map(|t| t.to_lowercase()).collect();
    let after = |flags: &[&str]| -> Option<&String> {
        lower
            .iter()
            .position(|token| flags.contains(&token.as_str()))
            .and_then(|index| tokens.get(index + 1))
    };
    let first_plain = || tokens.iter().find(|token| !is_switch(token));
    let ending_in = |suffixes: &[&str]| -> Option<&String> {
        tokens
            .iter()
            .find(|token| suffixes.iter().any(|s| token.to_lowercase().ends_with(s)))
    };

    let candidate: Option<&String> = match host {
        "cmd.exe" => after(&["/c", "/k"]).or_else(|| ending_in(&[".cmd", ".bat"])),
        "powershell.exe" | "pwsh.exe" => {
            after(&["-file", "-f", "-filepath"]).or_else(|| ending_in(&[".ps1"]))
        }
        "wscript.exe" | "cscript.exe" | "mshta.exe" | "regsvr32.exe" => first_plain(),
        "rundll32.exe" => first_plain(),
        "msbuild.exe" => first_plain()
            .or_else(|| ending_in(&[".csproj", ".vbproj", ".proj", ".targets", ".props", ".sln"])),
        "msiexec.exe" => after(&["/i", "/package", "/a", "/x", "/f", "/fa", "/p"])
            .or_else(|| ending_in(&[".msi", ".msp"])),
        "python.exe" | "pythonw.exe" | "node.exe" => first_plain(),
        "java.exe" | "javaw.exe" => after(&["-jar"]),
        _ => None,
    };
    let candidate = candidate?;

    // `rundll32 thing.dll,Entry` names the library and the function together.
    let candidate = if host == "rundll32.exe" {
        candidate.split(',').next().unwrap_or(candidate)
    } else {
        candidate.as_str()
    };
    let path = PathBuf::from(kam_core::env::expand(candidate.trim()));
    path.is_file().then_some(path)
}

/// Take a command apart: the executable, and what it is told to run.
///
/// `conhost.exe --headless <command>` is unwrapped, because it is not the
/// program but a way of running the program with no window, and the interesting
/// part is what follows.
pub fn resolve(command: &str) -> Resolved {
    resolve_expanded(&kam_core::env::expand(command.trim()), 0)
}

fn resolve_expanded(expanded: &str, depth: u8) -> Resolved {
    let Some((executable, rest)) = split_executable(expanded) else {
        return Resolved::default();
    };
    let name = executable
        .file_name()
        .map(|name| name.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    if name == "conhost.exe" && depth < 2 {
        // Skip conhost's own switches and their values, then resolve whatever
        // it was asked to host.
        let tokens = tokenise(&rest);
        let mut index = 0;
        while index < tokens.len() {
            let token = tokens[index].to_lowercase();
            if token == "--headless" || token == "--forcev1" || token == "--forcenotv2" {
                index += 1;
            } else if token.starts_with("--") {
                // `--width 80`, `--signal 0x494`: a switch with a value.
                index += 2;
            } else {
                break;
            }
        }
        if index < tokens.len() {
            let inner = tokens[index..]
                .iter()
                .map(|token| {
                    if token.contains(' ') {
                        format!("\"{token}\"")
                    } else {
                        token.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");
            let inner = resolve_expanded(&inner, depth + 1);
            if inner.executable.is_some() {
                return Resolved {
                    host: inner.host.or(Some("conhost.exe".to_owned())),
                    ..inner
                };
            }
        }
        return Resolved {
            executable: Some(executable),
            ..Default::default()
        };
    }

    if HOSTS.contains(&name.as_str()) {
        if let Some(payload) = payload_of(&name, &rest) {
            return Resolved {
                executable: Some(executable),
                host: Some(name),
                payload: Some(payload),
            };
        }
    }

    Resolved {
        executable: Some(executable),
        ..Default::default()
    }
}

/// The auto-start registry keys worth reading, and what each one means.
const RUN_KEYS: &[(&str, Anchor)] = &[
    (
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        Anchor::RunKey,
    ),
    (
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        Anchor::RunOnceKey,
    ),
];

fn read_run_keys(entries: &mut Vec<Entry>, users: &[UserContext]) {
    // Both hives and both views. A 32-bit installer writing to the Run key on a
    // 64-bit machine lands in `WOW6432Node`, and reading only the native view
    // would miss it entirely — which is exactly the kind of blind spot that
    // makes people distrust a tool like this.
    //
    // The per-user hive is the *caller's*, not the running process's. Inside a
    // LocalSystem service `HKEY_CURRENT_USER` is SYSTEM's own hive, where
    // nobody has ever put a startup entry, so a survey of what starts itself
    // silently omitted half of what does.
    let mut hives = vec![(HKEY_LOCAL_MACHINE, String::new(), "HKLM".to_owned(), true)];
    for user in users {
        let (hive, prefix) = user.hive();
        let label = match user.sid() {
            Some(sid) if users.len() > 1 => format!("HKEY_USERS\\{sid}"),
            _ => "HKCU".to_owned(),
        };
        hives.push((hive, prefix, label, false));
    }
    let views = [(View::Native, ""), (View::Wow6432, r"\WOW6432Node")];

    for (hive, prefix, hive_label, machine_wide) in hives {
        for (view, view_label) in views {
            for (path, anchor) in RUN_KEYS {
                let Some(key) = registry::Key::open(hive, &format!("{prefix}{path}"), view) else {
                    continue;
                };
                for name in key.value_names() {
                    let Some(command) = key.string(&name) else {
                        continue;
                    };
                    if command.trim().is_empty() {
                        continue;
                    }
                    entries.push(entry(
                        name,
                        *anchor,
                        format!("{hive_label}\\{path}{view_label}"),
                        command,
                        false,
                        machine_wide,
                    ));
                }
            }
        }
    }
}

/// Build an entry from a command, resolving what it runs.
fn entry(
    name: String,
    anchor: Anchor,
    location: String,
    command: String,
    hidden: bool,
    machine_wide: bool,
) -> Entry {
    let resolved = resolve(&command);
    Entry {
        name,
        anchor,
        location,
        command,
        executable: resolved.executable,
        payload: resolved.payload,
        host: resolved.host,
        hidden,
        machine_wide,
    }
}

/// Files sitting in a Startup folder.
fn read_startup_folders(entries: &mut Vec<Entry>, users: &[UserContext]) {
    let mut folders: Vec<(PathBuf, bool)> = Vec::new();

    // Per-user, so it comes from the caller rather than from `%APPDATA%`.
    for user in users {
        folders.push((
            PathBuf::from(user.roaming_app_data())
                .join(r"Microsoft\Windows\Start Menu\Programs\Startup"),
            false,
        ));
    }
    if let Ok(program_data) = std::env::var("ProgramData") {
        folders.push((
            PathBuf::from(program_data).join(r"Microsoft\Windows\Start Menu\Programs\StartUp"),
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
            let extension = path
                .extension()
                .map(|extension| extension.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            // A shortcut points elsewhere, and resolving it needs the shell
            // link interface. The file itself is still the honest answer to
            // "what is in this folder". A script or program placed here
            // directly is what runs, and is judged as such.
            let runs_directly = matches!(
                extension.as_str(),
                "exe"
                    | "com"
                    | "scr"
                    | "bat"
                    | "cmd"
                    | "ps1"
                    | "vbs"
                    | "vbe"
                    | "js"
                    | "jse"
                    | "wsf"
            );
            entries.push(Entry {
                name,
                anchor: Anchor::StartupFolder,
                location: folder.display().to_string(),
                command: path.display().to_string(),
                executable: runs_directly.then(|| path.clone()),
                payload: None,
                host: None,
                hidden: false,
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

        entries.push(entry(
            service
                .string("DisplayName")
                .map(|display| kam_core::mui::resolve(&display, &name))
                .unwrap_or_else(|| name.clone()),
            Anchor::Service,
            format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{name}"),
            image,
            false,
            true,
        ));
    }
}

/// Where the scheduler keeps its task definitions.
pub fn task_store() -> Option<PathBuf> {
    let root = std::env::var("SystemRoot").ok()?;
    Some(PathBuf::from(root).join(r"System32\Tasks"))
}

/// Scheduled tasks, read from the files the scheduler keeps them in.
///
/// The task store mirrors the task tree as a directory tree, and the registry
/// holds the same set under `TaskCache`. Reading files avoids taking a COM
/// dependency for what is ultimately XML, but it does mean tasks are only
/// visible where the file is readable — the scanner runs as LocalSystem, so it
/// is.
fn read_scheduled_tasks(survey: &mut Survey) {
    let Some(store) = task_store() else {
        return;
    };

    // The store is readable by administrators only. The agent runs as
    // LocalSystem so this succeeds in service, but it must report the gap
    // rather than return an empty list when it does not.
    if let Err(error) = std::fs::read_dir(&store) {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            survey
                .unreadable
                .push("Scheduled tasks could not be read without administrator rights.".to_owned());
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
        if let Some(entry) = task_entry(root, &path) {
            entries.push(entry);
        }
    }
}

/// Read one task definition file into an entry.
///
/// `None` for a task that runs only when something asks it to — no trigger is
/// not persistence — and for files that are not task definitions at all.
pub fn task_entry(root: &Path, path: &Path) -> Option<Entry> {
    let xml = read_task(path)?;

    // A task with no trigger runs only when something asks it to, which is
    // not persistence.
    if !xml.contains("<Triggers>") || xml.contains("<Triggers />") {
        return None;
    }
    let command = unescape(&between(&xml, "<Command>", "</Command>")?);
    let arguments = between(&xml, "<Arguments>", "</Arguments>").map(|args| unescape(&args));
    let full = match &arguments {
        Some(args) if !args.is_empty() => format!("{command} {args}"),
        _ => command.clone(),
    };

    // Hidden is a request to Task Scheduler not to list it. Windows uses it
    // for a handful of its own maintenance tasks; software that wants to be
    // found does not.
    let hidden = between(&xml, "<Hidden>", "</Hidden>")
        .is_some_and(|value| value.eq_ignore_ascii_case("true"));

    let name = path
        .strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string();

    Some(entry(
        name,
        Anchor::ScheduledTask,
        path.display().to_string(),
        full,
        hidden,
        true,
    ))
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

/// Everything on this machine that starts itself, for one person.
pub fn survey(user: &UserContext) -> Survey {
    survey_for(std::slice::from_ref(user))
}

/// Everything that starts itself, for several people at once.
///
/// The machine-wide sources — services, tasks, `HKLM` — are read once; the
/// per-user sources are read for each account given. This is what the watcher
/// uses, since a startup entry planted under any signed-in account is worth
/// noticing whoever is asking.
pub fn survey_for(users: &[UserContext]) -> Survey {
    let mut survey = Survey::default();
    read_run_keys(&mut survey.entries, users);
    read_startup_folders(&mut survey.entries, users);
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

/// Every account whose registry hive is currently loaded and has a profile.
///
/// Hives are loaded for people who are signed in, and stay loaded for a while
/// after. Service accounts and the `_Classes` shadow keys are skipped: neither
/// has a Startup folder anyone could plant something in.
pub fn signed_in_users() -> Vec<UserContext> {
    let Some(root) = registry::Key::open(HKEY_USERS, "", View::Native) else {
        return Vec::new();
    };
    root.subkey_names()
        .into_iter()
        .filter(|name| name.starts_with("S-1-5-21-") && !name.ends_with("_Classes"))
        .filter_map(|sid| UserContext::for_sid(&sid))
        .collect()
}

/// Group the entries by the file they actually run.
///
/// One program frequently holds on in several ways at once — a service and a
/// scheduled task and a Run key — and seeing those together is the point. The
/// key is the payload when there is one, so a script started by `cmd.exe` is
/// grouped with its own kind rather than with every other thing `cmd.exe` is
/// ever asked to run.
pub fn by_executable(entries: &[Entry]) -> BTreeMap<PathBuf, Vec<&Entry>> {
    let mut grouped: BTreeMap<PathBuf, Vec<&Entry>> = BTreeMap::new();
    for entry in entries {
        if let Some(target) = entry.target() {
            grouped
                .entry(PathBuf::from(
                    target.to_string_lossy().to_lowercase().replace('/', "\\"),
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
            executable_in(&command)
                .unwrap()
                .to_string_lossy()
                .to_lowercase(),
            system32("notepad.exe").to_string_lossy().to_lowercase()
        );
    }

    #[test]
    fn an_unquoted_path_containing_spaces_resolves() {
        // The shape that trips up naive parsers, and the one installers write
        // most often.
        let root = std::env::var("SystemRoot").unwrap();
        let command = format!(r"{root}\System32\notepad.exe /a");
        assert!(
            executable_in(&command).is_some(),
            "should have found notepad"
        );
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
    fn a_bare_system_program_name_is_found_in_system32() {
        // The task store is full of commands written as `cmd.exe` with no
        // path, and every one of them used to resolve to nothing.
        let found = executable_in("cmd.exe /c echo").unwrap();
        assert!(found
            .to_string_lossy()
            .to_lowercase()
            .ends_with(r"\system32\cmd.exe"));
        assert!(executable_in("rundll32 something.dll,Entry").is_some());
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
    fn quoted_arguments_stay_together() {
        assert_eq!(
            tokenise(r#"/c "C:\Some Folder\run.cmd" /launched"#),
            vec!["/c", r"C:\Some Folder\run.cmd", "/launched"]
        );
        assert_eq!(tokenise(r#""""#), vec![""]);
    }

    /// A script in a temporary folder, for the resolution tests. Nothing in it
    /// runs; it only has to exist.
    fn scratch_script(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("kam-persist-{}-{name}", std::process::id()));
        std::fs::write(&path, "@echo off\r\n").unwrap();
        path
    }

    #[test]
    fn a_script_run_through_cmd_is_the_payload() {
        // The exact shape of the scheduled task that carried a real infection:
        // cmd.exe is the vehicle, the script is the thing.
        let script = scratch_script("cmd-payload.cmd");
        let resolved = resolve(&format!(
            r#"C:\Windows\system32\cmd.exe /c "{}""#,
            script.display()
        ));
        assert_eq!(resolved.host.as_deref(), Some("cmd.exe"));
        assert_eq!(resolved.payload.as_deref(), Some(script.as_path()));
        assert!(resolved
            .executable
            .unwrap()
            .to_string_lossy()
            .to_lowercase()
            .ends_with("cmd.exe"));
        std::fs::remove_file(&script).unwrap();
    }

    #[test]
    fn a_hidden_console_is_unwrapped_to_what_it_hosts() {
        // The dropper's launcher: conhost --headless cmd.exe /c script. The
        // observation worth making is about the script, not about conhost.
        let script = scratch_script("headless.cmd");
        let resolved = resolve(&format!(
            r#""C:\Windows\System32\conhost.exe" --headless cmd.exe /c "{}" /launched"#,
            script.display()
        ));
        assert_eq!(resolved.host.as_deref(), Some("cmd.exe"));
        assert_eq!(resolved.payload.as_deref(), Some(script.as_path()));
        std::fs::remove_file(&script).unwrap();
    }

    #[test]
    fn a_powershell_script_and_a_project_file_are_payloads() {
        let script = scratch_script("thing.ps1");
        let resolved = resolve(&format!(
            r#"powershell.exe -NoProfile -File "{}""#,
            script.display()
        ));
        assert_eq!(resolved.payload.as_deref(), Some(script.as_path()));
        assert_eq!(resolved.host.as_deref(), Some("powershell.exe"));

        let project = scratch_script("Loader.csproj");
        let msbuild = std::path::PathBuf::from(std::env::var("SystemRoot").unwrap())
            .join(r"Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe");
        if msbuild.is_file() {
            let resolved = resolve(&format!(
                r#""{}" "{}" /nologo /v:q /noconlog"#,
                msbuild.display(),
                project.display()
            ));
            assert_eq!(resolved.payload.as_deref(), Some(project.as_path()));
            assert_eq!(resolved.host.as_deref(), Some("msbuild.exe"));
        }
        std::fs::remove_file(&script).unwrap();
        std::fs::remove_file(&project).unwrap();
    }

    #[test]
    fn a_host_told_to_run_nothing_that_exists_has_no_payload() {
        let resolved = resolve(r"C:\Windows\system32\cmd.exe /c C:\nowhere\gone.cmd");
        assert!(resolved.executable.is_some());
        assert_eq!(resolved.payload, None);
        assert_eq!(resolved.host, None, "no payload means no host either");
    }

    #[test]
    fn a_hidden_task_is_read_as_hidden() {
        let root = std::env::temp_dir();
        let path = root.join(format!("kam-task-{}", std::process::id()));
        let script = scratch_script("task-target.cmd");
        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\
             <Task><Settings><Hidden>true</Hidden></Settings>\
             <Triggers><LogonTrigger/></Triggers>\
             <Actions><Exec><Command>C:\\Windows\\system32\\cmd.exe</Command>\
             <Arguments>/c &quot;{}&quot;</Arguments></Exec></Actions></Task>",
            script.display()
        );
        // Written as the scheduler writes it: UTF-16 with a byte order mark.
        let mut bytes = vec![0xFF, 0xFE];
        for unit in xml.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        std::fs::write(&path, bytes).unwrap();

        let entry = task_entry(&root, &path).expect("a task with a trigger");
        assert!(entry.hidden);
        assert_eq!(entry.host.as_deref(), Some("cmd.exe"));
        assert_eq!(entry.payload.as_deref(), Some(script.as_path()));
        assert_eq!(entry.target(), Some(script.as_path()));

        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(&script).unwrap();
    }

    #[test]
    fn a_resource_reference_never_reaches_the_screen() {
        // Whether or not it resolves, what comes back must be a name rather
        // than a pointer into a library.
        let resolved = kam_core::mui::resolve(r"@%SystemRoot%\system32\wscsvc.dll,-200", "wscsvc");
        assert!(
            !resolved.starts_with('@'),
            "an unresolved reference leaked to the caller: {resolved}"
        );
        println!("resolved to: {resolved}");

        // A plain name is passed through untouched.
        assert_eq!(
            kam_core::mui::resolve("Print Spooler", "spooler"),
            "Print Spooler"
        );
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
        let survey = survey(&kam_core::UserContext::current());
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
            assert_eq!(
                tasks, 0,
                "tasks were read despite being reported unreadable"
            );
        }
        println!("scheduled tasks: {tasks}");

        let resolved = survey
            .entries
            .iter()
            .filter(|e| e.executable.is_some())
            .count();
        let through_hosts = survey
            .entries
            .iter()
            .filter(|e| e.payload.is_some())
            .count();
        println!(
            "resolved {resolved}/{} commands to an executable, {through_hosts} of them through a host",
            survey.entries.len()
        );
        for entry in survey.entries.iter().take(12) {
            println!(
                "  [{}] {} -> {:?}{}",
                entry.anchor.label(),
                entry.name,
                entry.target(),
                entry
                    .host
                    .as_deref()
                    .map(|host| format!(" (via {host})"))
                    .unwrap_or_default()
            );
        }
    }

    #[test]
    fn the_signed_in_accounts_include_the_one_running_the_tests() {
        let users = signed_in_users();
        println!("{} loaded profiles", users.len());
        let mine = UserContext::current();
        assert!(
            users
                .iter()
                .any(|user| user.profile().eq_ignore_ascii_case(mine.profile())),
            "the running account's hive is loaded, so it must be listed"
        );
    }
}
