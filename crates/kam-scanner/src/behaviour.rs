//! What a process start, or a new startup entry, means.
//!
//! # Why this exists
//!
//! Everything else in the scanner judges things at rest: a file's signature,
//! where it lives, how it holds on. That is the right way to read a machine
//! nobody has touched for a month, and it is useless against something that
//! ran three minutes ago, stole what it came for, and left a launcher behind.
//!
//! This module is the other half. The agent's watcher takes snapshots of what
//! starts itself and hands each newly appeared entry here to be judged; where a
//! live process feed is available it hands process starts here too. Nothing in
//! this module observes anything itself — it is a pure function from what was
//! seen to what it means, which is what makes it testable against the real
//! command lines of a real infection rather than against guesses.
//!
//! # What it looks for, and why
//!
//! The patterns below are not a malware signature database. They are the
//! handful of *shapes* that unwanted software uses to run without being
//! noticed, every one of which was present in the infection this was written
//! after:
//!
//! - a build tool — MSBuild, RegAsm and friends — used as a launcher, because
//!   it is signed by Microsoft and antivirus does not read the project files it
//!   is handed
//! - a console opened with no window, so a script can run unseen
//! - a script run from a folder any program can write to
//! - a hidden scheduled task, or a Run key, pointing at a script in AppData or
//!   Temp
//! - an unsigned installer run from Temp, claiming a hardware vendor whose real
//!   installers are always signed
//!
//! # What it deliberately does not do
//!
//! It does not stop anything. Stopping a process from a service that noticed it
//! a second late is theatre — the damage is done in the first hundred
//! milliseconds — and a product that kills processes on circumstantial evidence
//! will one day kill the wrong one. What it does is *write it down*, at once, in
//! the audit log, with the evidence attached. The person reading the log then
//! knows exactly which script, in which folder, started by what, at what time —
//! which is what took an afternoon of forensics to reconstruct by hand the
//! first time.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::persistence::{self, Anchor, Entry};
use crate::signature::{self, Signature};

/// How much attention an observation warrants. Two levels, deliberately: this
/// is a log of things a person should read, not a threat meter with a number
/// somebody will learn to ignore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Concern {
    /// Unusual, and worth a line in the log. Legitimate software does this.
    Notable,
    /// A shape with very few innocent explanations. Still not a verdict.
    Strong,
}

impl Concern {
    pub fn label(self) -> &'static str {
        match self {
            Self::Notable => "worth knowing",
            Self::Strong => "worth a look",
        }
    }

    /// The audit log records a strong concern as a state to be corrected and a
    /// notable one as something merely seen, matching how the weekly check
    /// already uses the two effects.
    pub fn is_strong(self) -> bool {
        self == Self::Strong
    }
}

/// What kind of thing was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    ProcessStart,
    ScheduledTask,
    SignInEntry,
    StartupFolder,
    Service,
}

impl Kind {
    /// The audit log's action name.
    pub fn action(self) -> &'static str {
        match self {
            Self::ProcessStart => "process_started",
            Self::ScheduledTask => "task_appeared",
            Self::SignInEntry => "sign_in_entry_appeared",
            Self::StartupFolder => "startup_item_appeared",
            Self::Service => "service_appeared",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::ProcessStart => "a program started",
            Self::ScheduledTask => "a scheduled task appeared",
            Self::SignInEntry => "a sign-in entry appeared",
            Self::StartupFolder => "a Startup folder item appeared",
            Self::Service => "a service appeared",
        }
    }

    fn of_anchor(anchor: Anchor) -> Self {
        match anchor {
            Anchor::ScheduledTask => Self::ScheduledTask,
            Anchor::RunKey | Anchor::RunOnceKey => Self::SignInEntry,
            Anchor::StartupFolder => Self::StartupFolder,
            Anchor::Service => Self::Service,
        }
    }
}

/// One thing the watcher thought worth writing down.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    /// When it was seen, in the audit log's format.
    pub at: String,
    pub kind: Kind,
    pub concern: Concern,
    /// One sentence, written for the person reading it.
    pub summary: String,
    /// Why, in the order it was decided. An observation with no evidence is an
    /// accusation, so this is never empty.
    pub evidence: Vec<String>,
    /// The file the observation is about: the script, the project, the
    /// installer. What a person would open Explorer on.
    pub subject: String,
    /// The command line as seen, so nothing has to be taken on trust.
    pub command: String,
    pub pid: Option<u32>,
}

/// A process the moment it started, as a live event feed would report it.
///
/// Kept deliberately small and plain so the judging logic can be exercised
/// against the exact command lines of a real infection in a unit test, with no
/// event source involved.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProcessStart {
    pub pid: u32,
    pub parent: u32,
    /// Image name, such as `MSBuild.exe`.
    pub name: String,
    pub path: Option<String>,
    pub command: String,
}

/// Extensions that run as scripts. A file with one of these cannot carry a
/// signature, which is part of why unwanted software is fond of them.
const SCRIPTS: &[&str] = &[
    "cmd", "bat", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "py", "pyw",
];

/// Build project files, which MSBuild will execute inline tasks from.
const PROJECTS: &[&str] = &[
    "csproj", "vbproj", "fsproj", "proj", "targets", "props", "sln",
];

/// Programs that exist to build software, and are therefore trusted by every
/// antivirus engine — which is exactly why they are used to run things that are
/// not software builds.
const BUILD_TOOLS: &[&str] = &[
    "msbuild.exe",
    "regasm.exe",
    "regsvcs.exe",
    "installutil.exe",
    "aspnet_compiler.exe",
];

/// Vendors whose real installers are always signed. An unsigned installer
/// bearing one of these names is not from them.
const SIGNING_VENDORS: &[&str] = &[
    "synaptics",
    "intel",
    "nvidia",
    "realtek",
    "advanced micro devices",
    "logitech",
    "dell",
    "hewlett",
    "lenovo",
    "broadcom",
    "qualcomm",
];

fn extension_of(path: &Path) -> String {
    path.extension()
        .map(|extension| extension.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

/// Whether the file is something that runs as text rather than as a program.
pub fn is_script(path: &Path) -> bool {
    let extension = extension_of(path);
    SCRIPTS.contains(&extension.as_str())
}

/// Whether the file is a build project MSBuild and friends will run code from.
pub fn is_project(path: &Path) -> bool {
    PROJECTS.contains(&extension_of(path).as_str())
}

/// The folders where unwanted software lands, named for a sentence.
///
/// Matched by shape rather than against the environment, because the watcher
/// runs as LocalSystem and `%LOCALAPPDATA%` there is SYSTEM's own, empty,
/// AppData. A path under any account's profile is what matters, whoever is
/// asking.
pub fn dropper_place(path: &str) -> Option<&'static str> {
    let text = path.to_lowercase().replace('/', "\\");
    // Defender's own engine lives under ProgramData and runs constantly; it is
    // not a dropper location and must never be treated as one.
    if text.contains(r"\programdata\microsoft\windows defender\") {
        return None;
    }
    if text.contains(r"\appdata\local\temp\") || text.contains(r"\windows\temp\") {
        return Some("Temp");
    }
    if text.contains(r"\appdata\local\") || text.contains(r"\appdata\roaming\") {
        return Some("AppData");
    }
    if text.contains(r"\users\public\") {
        return Some("the Public folder");
    }
    if text.contains(r"\downloads\") {
        return Some("Downloads");
    }
    if text.contains(r"\desktop\") {
        return Some("the Desktop");
    }
    if text.contains(r"\$recycle.bin\") {
        return Some("the Recycle Bin");
    }
    if text.contains(r"\programdata\") {
        return Some("ProgramData");
    }
    None
}

/// `conhost.exe --headless <program>`: a console with no window, hosting a
/// program directly. Distinct from the `--server`/`--signal` form, which is how
/// every real terminal talks to conhost and is entirely ordinary.
fn headless_console(command: &str) -> bool {
    let lower = command.to_lowercase();
    lower.contains("--headless") && !lower.contains("--server") && !lower.contains("--signal")
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

fn observation(
    kind: Kind,
    concern: Concern,
    summary: String,
    evidence: Vec<String>,
    subject: String,
    command: String,
    pid: Option<u32>,
) -> Observation {
    Observation {
        at: kam_core::clock::now_utc_iso(),
        kind,
        concern,
        summary,
        evidence,
        subject,
        command,
        pid,
    }
}

/// Judge one process start.
///
/// Returns `None` for the overwhelming majority of process starts, which are
/// ordinary and must not fill a log. It fires only on the specific shapes a
/// launcher-based infection uses.
pub fn judge_process(start: &ProcessStart) -> Option<Observation> {
    let name = start.name.to_lowercase();
    let resolved = persistence::resolve(&start.command);
    let observe = |concern, summary, evidence, subject: String| {
        Some(observation(
            Kind::ProcessStart,
            concern,
            summary,
            evidence,
            subject,
            start.command.clone(),
            Some(start.pid),
        ))
    };

    // --- a build tool used as a launcher -----------------------------------
    //
    // MSBuild with no project argument, running under the task scheduler or a
    // console, is the exact shape the infection used: the payload was an inline
    // task inside a `.csproj`, which Defender never reads. Ordinary MSBuild runs
    // are started by a developer at a shell or by an IDE and name a project on
    // a drive they work in.
    if BUILD_TOOLS.contains(&name.as_str()) {
        let mut evidence = vec![format!(
            "{} is a software build tool. It is signed by Microsoft, so antivirus trusts it, and it will run code from a project file — which antivirus does not read.",
            start.name
        )];
        let payload = resolved.payload.as_deref();
        let payload_place = payload.and_then(|path| dropper_place(&path.to_string_lossy()));
        match (payload, payload_place) {
            (Some(path), Some(place)) => {
                evidence.push(format!(
                    "Here it was handed {}, which sits in {place}.",
                    file_name(path)
                ));
                return observe(
                    Concern::Strong,
                    format!("{} ran a build tool against a file in {place}", start.name),
                    evidence,
                    path.display().to_string(),
                );
            }
            _ => {
                evidence.push(
                    "It was started with no project on its command line, which is not how a build is run."
                        .to_owned(),
                );
                return observe(
                    Concern::Notable,
                    format!("{} ran without building anything nameable", start.name),
                    evidence,
                    start.path.clone().unwrap_or_else(|| start.name.clone()),
                );
            }
        }
    }

    // --- a console with no window ------------------------------------------
    if name == "conhost.exe" && headless_console(&start.command) {
        let hosted = resolved
            .payload
            .as_deref()
            .or(resolved.executable.as_deref())
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "a command".to_owned());
        let mut evidence = vec![
            "conhost.exe was started with --headless, which runs a console program with no window a person could see."
                .to_owned(),
            "A real terminal attaches to conhost with --server and a signal handle; this did neither."
                .to_owned(),
        ];
        let place = resolved
            .payload
            .as_deref()
            .and_then(|path| dropper_place(&path.to_string_lossy()));
        if let Some(place) = place {
            evidence.push(format!("What it runs sits in {place}."));
            return observe(
                Concern::Strong,
                "A hidden console was opened to run a script from a writable folder".to_owned(),
                evidence,
                hosted,
            );
        }
        return observe(
            Concern::Notable,
            "A console was opened with no window".to_owned(),
            evidence,
            hosted,
        );
    }

    // --- a script host running a script from a writable folder -------------
    if let (Some(host), Some(payload)) = (resolved.host.as_deref(), resolved.payload.as_deref()) {
        if let Some(place) = dropper_place(&payload.to_string_lossy()) {
            if is_script(payload) || is_project(payload) {
                let evidence = vec![
                    format!("{host} was used to run {}.", file_name(payload)),
                    format!(
                        "That file sits in {place}, which any program can write to without asking."
                    ),
                ];
                return observe(
                    Concern::Notable,
                    format!("{host} ran a script from {place}"),
                    evidence,
                    payload.display().to_string(),
                );
            }
        }
    }

    // --- an unsigned installer from Temp claiming a hardware vendor --------
    if name == "msiexec.exe" {
        if let Some(msi) = msi_argument(&start.command) {
            if let Some(place) = dropper_place(&msi.to_string_lossy()) {
                let signature = signature::of(&msi);
                let unsigned = matches!(signature, Signature::Unsigned | Signature::Invalid { .. });
                let vendor = vendor_claim(&msi);
                if unsigned && (place == "Temp" || vendor.is_some()) {
                    let mut evidence = vec![format!(
                        "An installer package in {place} was run, and it carries no valid signature."
                    )];
                    if let Some(vendor) = vendor {
                        evidence.push(format!(
                            "It presents itself as {vendor} software, whose real installers are always signed."
                        ));
                    }
                    return observe(
                        Concern::Strong,
                        "An unsigned installer ran from a writable folder".to_owned(),
                        evidence,
                        msi.display().to_string(),
                    );
                }
            }
        }
    }

    None
}

/// The vendor an installer's file name claims, if any.
fn vendor_claim(path: &Path) -> Option<&'static str> {
    let text = path.to_string_lossy().to_lowercase();
    SIGNING_VENDORS
        .iter()
        .find(|vendor| text.contains(*vendor))
        .copied()
}

/// The `.msi` named on an `msiexec` command line, whether or not it still
/// exists. Installers that clean up after themselves remove the package within
/// seconds, and "an installer ran from Temp and is already gone" is still worth
/// a line.
fn msi_argument(command: &str) -> Option<PathBuf> {
    let tokens = persistence::tokenise(command);
    let lower: Vec<String> = tokens.iter().map(|token| token.to_lowercase()).collect();
    let after = lower
        .iter()
        .position(|token| {
            matches!(
                token.as_str(),
                "/i" | "/package" | "/a" | "/x" | "/f" | "/p"
            )
        })
        .and_then(|index| tokens.get(index + 1));
    let bare = tokens
        .iter()
        .skip(1)
        .find(|token| token.to_lowercase().ends_with(".msi"));
    after
        .or(bare)
        .map(|token| PathBuf::from(kam_core::env::expand(token.trim())))
}

/// Judge one newly appeared startup entry.
///
/// This is what the agent's snapshot watcher feeds: something that was not
/// starting itself at the last look and is now. The signature of what it runs
/// is checked here, because a new startup entry pointing at an unsigned script
/// in AppData is the resting form of exactly the infection this was written
/// after, and reads the same whether the process has run yet or not.
pub fn judge_entry(entry: &Entry) -> Option<Observation> {
    let kind = Kind::of_anchor(entry.anchor);
    let target = entry.target()?;
    let target_text = target.to_string_lossy().into_owned();
    let place = dropper_place(&target_text);
    let script = is_script(target) || is_project(target);
    let signature = signature::of(target);
    let unsigned = matches!(signature, Signature::Unsigned);

    let mut evidence = Vec::new();
    let mut concern = Concern::Notable;

    if let Some(host) = &entry.host {
        evidence.push(format!(
            "It runs through {host}, so what actually runs is {} rather than {host} itself.",
            file_name(target)
        ));
    }
    if entry.hidden {
        evidence.push(
            "The scheduled task is marked hidden, so it does not appear in Task Scheduler's list. Ordinary software has no reason to hide."
                .to_owned(),
        );
        concern = Concern::Strong;
    }
    if let Some(place) = place {
        evidence.push(format!(
            "What it runs sits in {place}, which any program can write to without administrator rights."
        ));
    }
    if script {
        evidence.push(format!(
            "{} is a script or project file, which carries no signature and is read as code when it runs.",
            file_name(target)
        ));
    }
    if unsigned && !script {
        evidence.push("Nobody signed the program it runs.".to_owned());
    }

    // The threshold. A new startup entry on its own is not worth a line — a
    // legitimate install adds them all the time. It becomes worth one when what
    // it runs sits in a writable folder AND is either unsigned, a script, run
    // through a launcher, or hidden. That combination is the shape, and holding
    // to it is what keeps this from becoming the scareware it replaces.
    let in_writable = place.is_some();
    let launched = entry.host.is_some();
    let worth_it = in_writable && (unsigned || script || launched || entry.hidden);
    if !worth_it {
        return None;
    }

    if in_writable && (script || launched) && (entry.hidden || unsigned) {
        concern = Concern::Strong;
    }

    let where_ = place.unwrap_or("a program folder");
    let summary = match kind {
        Kind::ScheduledTask if entry.hidden => {
            format!(
                "A hidden scheduled task now runs {} from {where_}",
                file_name(target)
            )
        }
        Kind::ScheduledTask => {
            format!(
                "A scheduled task now runs {} from {where_}",
                file_name(target)
            )
        }
        Kind::SignInEntry => {
            format!(
                "A sign-in entry now runs {} from {where_}",
                file_name(target)
            )
        }
        Kind::StartupFolder => {
            format!(
                "A Startup item now runs {} from {where_}",
                file_name(target)
            )
        }
        Kind::Service => format!("A service now runs {} from {where_}", file_name(target)),
        Kind::ProcessStart => unreachable!("entries are never process starts"),
    };

    Some(observation(
        kind,
        concern,
        summary,
        evidence,
        target_text,
        entry.command.clone(),
        None,
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn start(name: &str, command: &str) -> ProcessStart {
        ProcessStart {
            pid: 4242,
            parent: 1000,
            name: name.to_owned(),
            path: Some(format!(r"C:\Windows\System32\{name}")),
            command: command.to_owned(),
        }
    }

    /// A real file on disk that removes itself when the test ends.
    ///
    /// The previous version made a `kam-behaviour-<pid>` directory to hold
    /// these, and each test deleted its own file and left the directory. One
    /// empty folder per test run, twenty-six of them on the development
    /// machine before anybody noticed. Small, but this is a program that
    /// offers to tidy somebody's disk, and leaving litter on it is the one
    /// kind of bug it cannot afford to have.
    ///
    /// Two changes. No directory, because a directory is a second thing that
    /// has to be removed by somebody and nobody was. And the removal happens
    /// in `Drop` rather than at the end of each test, because a test that
    /// fails an assertion never reaches its last line — so the old cleanup was
    /// skipped exactly when a run left the most behind.
    struct Scratch(PathBuf);

    impl std::ops::Deref for Scratch {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// A real script on disk, so signature and existence checks behave. Nothing
    /// in it runs.
    fn scratch(name: &str, body: &str) -> Scratch {
        // Unique per call as well as per process: these tests run in parallel,
        // and two of them writing the same name would be a race that shows up
        // as a mystery failure once in a hundred runs.
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let unique = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Still inside the temp folder, which is what the rules under test care
        // about; the name carries its extension, which is the other thing they
        // read.
        let path = std::env::temp_dir().join(format!(
            "kam-behaviour-{}-{unique}-{name}",
            std::process::id()
        ));
        std::fs::write(&path, body).unwrap();
        Scratch(path)
    }

    #[test]
    fn msbuild_hosting_a_project_in_temp_is_the_headline_case() {
        // The exact shape of the infection: MSBuild handed a project file that
        // lives in a Temp folder, run from a hidden console.
        let project = scratch("NuGetFrameworks.csproj", "<Project/>");
        let command = format!(
            r#""C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" "{}" /nologo /noconlog"#,
            project.display()
        );
        let observation = judge_process(&start("MSBuild.exe", &command)).expect("must fire");
        assert_eq!(observation.concern, Concern::Strong);
        assert_eq!(observation.kind, Kind::ProcessStart);
        assert!(observation
            .subject
            .to_lowercase()
            .contains("nugetframeworks.csproj"));
        assert!(!observation.evidence.is_empty());
    }

    #[test]
    fn a_headless_console_running_a_script_from_appdata_is_strong() {
        let script = scratch("analytics.cmd", "@echo off");
        let command = format!(
            r#""C:\Windows\System32\conhost.exe" --headless cmd.exe /c "{}" /launched"#,
            script.display()
        );
        // Note the script lives in a temp dir, which dropper_place reads as Temp.
        let observation = judge_process(&start("conhost.exe", &command)).expect("must fire");
        assert_eq!(observation.concern, Concern::Strong);
    }

    #[test]
    fn an_ordinary_terminal_conhost_is_silent() {
        // Every real console on the machine looks like this. Firing on it would
        // bury the log instantly.
        let command = r"\??\C:\Windows\system32\conhost.exe --headless --width 80 --height 24 --signal 0x1c --server 0x2b";
        assert!(judge_process(&start("conhost.exe", command)).is_none());
    }

    #[test]
    fn a_developer_msbuild_with_a_real_project_elsewhere_is_quiet() {
        // MSBuild building a project in a source tree is not in a dropper
        // location, so it does not fire. This is the false positive that would
        // alienate the developers most likely to run this tool.
        let project = scratch_in_projects("App.csproj");
        if let Some(project) = project {
            let command = format!(
                r#""C:\Program Files\dotnet\MSBuild.exe" "{}""#,
                project.display()
            );
            let observation = judge_process(&start("MSBuild.exe", &command));
            // It may fire as Notable if no payload place is found, but must not
            // be Strong, and must not point at a dropper location.
            if let Some(observation) = observation {
                assert_ne!(observation.concern, Concern::Strong, "{:?}", observation);
            }
        }
    }

    fn scratch_in_projects(name: &str) -> Option<PathBuf> {
        let dir = PathBuf::from(std::env::var("USERPROFILE").ok()?).join("Documents");
        if !dir.is_dir() {
            return None;
        }
        let path = dir.join(format!("kam-test-{}-{name}", std::process::id()));
        std::fs::write(&path, "<Project/>").ok()?;
        Some(path)
    }

    #[test]
    fn an_ordinary_process_is_not_worth_a_line() {
        assert!(judge_process(&start(
            "chrome.exe",
            r"C:\Program Files\Google\Chrome\chrome.exe"
        ))
        .is_none());
        assert!(judge_process(&start("explorer.exe", r"C:\Windows\explorer.exe")).is_none());
    }

    fn entry(anchor: Anchor, command: &str, hidden: bool) -> Entry {
        let resolved = persistence::resolve(command);
        Entry {
            name: "Test".to_owned(),
            anchor,
            location: r"HKCU\...\Run".to_owned(),
            command: command.to_owned(),
            executable: resolved.executable,
            payload: resolved.payload,
            host: resolved.host,
            hidden,
            machine_wide: false,
        }
    }

    #[test]
    fn a_hidden_task_running_a_script_from_appdata_is_strong() {
        let script = scratch("CastleCore-launch.cmd", "@echo off");
        let command = format!(r#"C:\Windows\system32\cmd.exe /c "{}""#, script.display());
        let observation =
            judge_entry(&entry(Anchor::ScheduledTask, &command, true)).expect("fires");
        assert_eq!(observation.concern, Concern::Strong);
        assert_eq!(observation.kind, Kind::ScheduledTask);
        assert!(observation.summary.to_lowercase().contains("hidden"));
    }

    #[test]
    fn a_run_key_pointing_at_a_signed_program_in_program_files_is_quiet() {
        // The ordinary case: Steam, Discord, an updater. Signed or not, it is
        // not in a place this fires on.
        let command = r#""C:\Program Files\Thing\thing.exe" --background"#;
        assert!(judge_entry(&entry(Anchor::RunKey, command, false)).is_none());
    }

    #[test]
    fn a_plain_unsigned_run_key_in_appdata_still_needs_a_reason() {
        // Lots of legitimate software (Discord, Slack) runs unsigned-ish
        // updaters from AppData. An unsigned program alone in AppData is
        // notable, not strong — the strong signal is a script or a launcher.
        let program = scratch("updater.exe", "MZ");
        let command = format!(r#""{}"" --background"#, program.display());
        // Executable, not a script, no host: unsigned + writable -> Notable.
        let observation = judge_entry(&entry(Anchor::RunKey, &command, false));
        if let Some(observation) = observation {
            assert_eq!(observation.concern, Concern::Notable, "{observation:?}");
        }
    }

    #[test]
    fn defenders_own_folder_is_never_a_dropper_place() {
        assert_eq!(
            dropper_place(r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe"),
            None
        );
        assert_eq!(
            dropper_place(r"C:\Users\me\AppData\Local\Temp\x.cmd"),
            Some("Temp")
        );
        assert_eq!(dropper_place(r"C:\Program Files\App\app.exe"), None);
    }
}
