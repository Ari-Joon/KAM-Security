//! The weekly check.
//!
//! # What it is for
//!
//! Everything else in this product answers a question somebody asked. This is
//! the one thing that asks on their behalf, so that a machine nobody has opened
//! the window on for a month is not silently unprotected.
//!
//! It runs as a scheduled task rather than on a timer inside the agent, which
//! is what keeps the agent at no measurable CPU while nothing is happening. See
//! `kam-schedule` for why.
//!
//! # What it deliberately does not do
//!
//! It does not scan the disk. A weekly full scan is what makes people uninstall
//! antivirus software, and it would take minutes and gigabytes of reading to
//! tell somebody what Defender already told them in milliseconds. This reads
//! state: whether protection is on, whether the firewall is up, whether
//! anything new has taken up residence in a startup location, and whether a
//! drive is nearly full. Seconds, and almost no disk.
//!
//! It also does not pop anything up. Findings go into the audit log, which is
//! the same place every other action is recorded, and the window shows them the
//! next time somebody opens it. A weekly balloon saying "everything is fine" is
//! how a program teaches people to ignore it.

use kam_core::audit::{Effect, Entry};
use kam_core::{Store, UserContext};

use crate::server;

/// One thing worth a person's attention.
#[derive(Debug, Clone)]
pub struct Finding {
    pub summary: String,
    /// True when this is a state that should be corrected rather than noted.
    pub serious: bool,
}

impl Finding {
    fn note(summary: impl Into<String>) -> Self {
        Self {
            summary: summary.into(),
            serious: false,
        }
    }

    fn serious(summary: impl Into<String>) -> Self {
        Self {
            summary: summary.into(),
            serious: true,
        }
    }
}

/// A drive with less than this much free is worth mentioning.
const LOW_SPACE_FRACTION: f64 = 0.10;

/// Defender signatures older than this are stale enough to matter.
const STALE_SIGNATURE_DAYS: i64 = 7;

fn check_defender(findings: &mut Vec<Finding>) {
    match kam_scanner::defender::status() {
        Ok(status) => {
            // Defender phrases its own concerns, and it does it in one place so
            // the window and the check can never disagree about what is wrong.
            for concern in status.concerns() {
                findings.push(Finding::serious(concern));
            }
            if let Some(age) = status.signature_age_days {
                if age > STALE_SIGNATURE_DAYS {
                    findings.push(Finding::serious(format!(
                        "Defender's definitions are {age} days old"
                    )));
                }
            }
        }
        Err(error) => findings.push(Finding::note(format!(
            "Defender's state could not be read: {error}"
        ))),
    }
}

fn check_firewall(findings: &mut Vec<Finding>) {
    match kam_firewall::policy::survey() {
        Ok(report) => {
            for concern in &report.concerns {
                findings.push(Finding::serious(concern.clone()));
            }
        }
        Err(error) => findings.push(Finding::note(format!(
            "the firewall's state could not be read: {error}"
        ))),
    }
}

fn check_space(findings: &mut Vec<Finding>) {
    let Ok(volumes) = kam_storage::list_volumes() else {
        findings.push(Finding::note("the drives could not be listed".to_owned()));
        return;
    };
    for volume in volumes {
        if volume.total_bytes == 0 {
            continue;
        }
        let free = volume.free_bytes as f64 / volume.total_bytes as f64;
        if free < LOW_SPACE_FRACTION {
            findings.push(Finding::note(format!(
                "{} is {:.0}% full",
                volume.root,
                (1.0 - free) * 100.0
            )));
        }
    }
}

/// Anything that starts itself and is not signed by somebody.
///
/// Deliberately narrow. A list of everything that starts itself is a hundred
/// entries long on a normal machine and is a thing to browse, not a thing to be
/// told once a week. What is worth being told is the small set that nothing
/// vouches for.
fn check_startup(findings: &mut Vec<Finding>, user: &UserContext) {
    let survey = kam_scanner::persistence::survey(user);

    // This program's own files, so its own entries can be told apart from
    // everybody else's.
    //
    // This used to compare against `current_exe` alone, which is only ever one
    // of the two binaries this program is made of -- so whichever half was not
    // running got listed among the unsigned startup entries, and the program
    // reported part of itself as somebody else's unvouched-for software.
    let mut unsigned = Vec::new();
    let mut ourselves = false;
    for (executable, entries) in kam_scanner::persistence::by_executable(&survey.entries) {
        let path = executable.to_string_lossy();
        // Windows' own components are signed by catalogue and would otherwise
        // dominate the list; they are checked like anything else, and pass.
        if !matches!(
            kam_scanner::signature::of(&executable),
            kam_scanner::signature::Signature::Unsigned
        ) {
            continue;
        }
        if kam_core::ourselves::is_ours(&executable) {
            // Not hidden, and not listed among the others either. These files
            // are unsigned too, and saying so plainly is better than a weekly
            // line about an entry the reader installed themselves.
            ourselves = true;
            continue;
        }
        unsigned.push(
            entries
                .first()
                .map(|entry| entry.name.clone())
                .unwrap_or_else(|| path.to_string()),
        );
    }

    if !unsigned.is_empty() {
        unsigned.sort();
        findings.push(Finding::note(format!(
            "{} startup {} carry no signature: {}",
            unsigned.len(),
            if unsigned.len() == 1 {
                "entry"
            } else {
                "entries"
            },
            unsigned.join(", ")
        )));
    }

    if ourselves {
        findings.push(Finding::note(
            "this program starts itself too, and it is not signed either".to_owned(),
        ));
    }

    for unreadable in survey.reasons().iter().take(1) {
        findings.push(Finding::note(format!(
            "part of the startup survey could not be read: {unreadable}"
        )));
    }
}

/// Run every check and return what it found.
pub fn run(user: &UserContext) -> Vec<Finding> {
    let mut findings = Vec::new();
    check_defender(&mut findings);
    check_firewall(&mut findings);
    check_startup(&mut findings, user);
    check_space(&mut findings);
    // Anything that should be corrected sorts above anything merely noted.
    findings.sort_by_key(|finding| !finding.serious);
    findings
}

/// Run the check and write what it found into the audit log.
///
/// The summary entry is always written, including when nothing was found:
/// "checked, nothing to report" is the answer somebody wants to see next to a
/// date, and its absence is how you find out a schedule stopped firing.
pub fn run_and_record(store: &Store, user: &UserContext) -> Vec<Finding> {
    let findings = run(user);
    let serious = findings.iter().filter(|finding| finding.serious).count();

    for finding in &findings {
        server::record(
            store,
            Entry {
                module: "check",
                action: "finding",
                // Refused is the audit log's word for "this state is wrong",
                // which is exactly what a serious finding is.
                effect: if finding.serious {
                    Effect::Refused
                } else {
                    Effect::Observed
                },
                detail: finding.summary.clone(),
                undo_token: None,
            },
        );
    }

    server::record(
        store,
        Entry {
            module: "check",
            action: "weekly",
            effect: Effect::Observed,
            detail: match (findings.len(), serious) {
                (0, _) => "checked; nothing to report".to_owned(),
                (found, 0) => format!("checked; {found} things worth a look"),
                (found, bad) => {
                    format!("checked; {found} things worth a look, {bad} of them serious")
                }
            },
            undo_token: None,
        },
    );

    findings
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_serious_finding_sorts_above_a_note() {
        let mut findings = [
            Finding::note("a note"),
            Finding::serious("something wrong"),
            Finding::note("another note"),
        ];
        findings.sort_by_key(|finding| !finding.serious);
        assert!(findings[0].serious);
        assert_eq!(findings[0].summary, "something wrong");
    }

    #[test]
    fn a_check_that_finds_nothing_still_leaves_a_record() {
        // The absence of an entry is how somebody would find out the schedule
        // had quietly stopped firing, so silence is never the answer.
        let store = Store::open_in_memory().unwrap();
        run_and_record(&store, &UserContext::current());

        let entries = store.recent_audit(50).unwrap();
        let weekly = entries
            .iter()
            .find(|entry| entry.action == "weekly")
            .expect("the run itself should have been recorded");
        assert_eq!(weekly.module, "check");
        assert!(!weekly.detail.is_empty());
    }

    #[test]
    fn every_finding_is_recorded_beside_the_summary() {
        let store = Store::open_in_memory().unwrap();
        let findings = run_and_record(&store, &UserContext::current());

        let entries = store.recent_audit(200).unwrap();
        let recorded = entries
            .iter()
            .filter(|entry| entry.action == "finding")
            .count();
        assert_eq!(recorded, findings.len());
    }

    #[test]
    fn the_check_reads_state_rather_than_the_disk() {
        // The guarantee that makes a weekly check acceptable at all. If this
        // ever takes minutes, something in it has started scanning.
        let started = std::time::Instant::now();
        run(&UserContext::current());
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(90),
            "the check took {elapsed:?}, which is long enough that it is reading something it should not be"
        );
    }
}
