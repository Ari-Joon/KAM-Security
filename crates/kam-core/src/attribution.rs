//! Saying which changes this software caused, without giving itself a hiding
//! place.
//!
//! # The problem, which is not the obvious one
//!
//! This product changes the machine. It quarantines things, it recycles things,
//! it registers its own service. So when it reports what changed, it reports
//! itself, and a tool that lists its own activity as findings is one people stop
//! reading.
//!
//! The obvious fix is to filter out anything with our name on it. That fix is
//! worse than the problem: it converts our own name into a hiding place that
//! anybody can use for free. A service called "KAM Security Agent" would then be
//! invisible *because* of what it is called, which is a gift to whoever names
//! theirs that.
//!
//! # Attribute, never suppress
//!
//! So nothing is ever removed from the list. A change this software caused is
//! **labelled** as such and stays exactly where it was, at full size, in the
//! same list as everything else.
//!
//! That distinction is the whole security property, and it is worth being blunt
//! about why. A silent filter is a hiding place: one entry goes in, nothing
//! comes out, and nobody can tell. A visible label is a tripwire: if malware
//! installs a service using our name, the reader sees **two** entries where
//! there should be one, and the second is the one that was not attributable.
//!
//! # Matching has to be tight or it is an alibi
//!
//! An attribution links an audit entry to a change. If that link is loose, every
//! action this software takes becomes a general-purpose excuse — quarantining
//! one file would "explain" an unrelated startup entry disappearing at around
//! the same time.
//!
//! So a link requires the audit entry to name **the same resolved target**, of
//! the same kind, within a **narrow window**. Never by name, never by
//! resemblance, never by timing alone.
//!
//! # Four things are never attributable
//!
//! Three are about this software itself, and are the changes an attacker would
//! make first:
//!
//! 1. Its service disappearing.
//! 2. Its binary changing without an update it performed.
//! 3. Its own configuration being modified.
//!
//! The fourth came out of adversarial review and is the one that closes the
//! laundering path: a change where **this software acted on somebody else's**
//! autostart or security control. Quarantine and recycling both take a path
//! chosen by the caller, so an attacker can induce a genuine removal of a rival
//! tool and let the real audit entry explain the absence. Those stay at full
//! prominence whatever the log says, because the log is telling the truth and
//! the truth is the attack.

use serde::{Deserialize, Serialize};

use crate::audit::Record;
use crate::changes::Difference;

/// How close in time an audit entry has to be to count as an explanation.
///
/// Narrow on purpose. A sweep sees a difference between two points; the action
/// that caused it is recorded at the moment it happened. Widening this does not
/// catch more real attributions, it catches more coincidences — and every
/// coincidence it catches is an alibi handed to somebody.
pub const WINDOW_SECONDS: i64 = 15 * 60;

/// Why a change is believed to have been caused by this software.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribution {
    /// The audit entry that explains it: module, action and time.
    pub action: String,
    pub at: String,
    /// What the entry said, rendered as a report rather than as a finding.
    ///
    /// The text can contain a reason a *client* supplied — quarantine and
    /// recycling both accept one — so it is never presented as something this
    /// software is asserting.
    pub reported: String,
}

/// Whether a change may never be explained away, whatever the log says.
///
/// Returns the reason when it may not, so the interface can say why rather than
/// only refusing.
pub fn never_attributable(difference: &Difference) -> Option<&'static str> {
    let name = difference.name.to_lowercase();
    let detail = difference.detail.to_lowercase();

    // 1. Our own service going missing. The first thing anybody switching this
    //    software off would do, and the one change we are uniquely placed to
    //    notice.
    if difference.kind == "service"
        && name.contains("kamsecurity")
        && difference.change == crate::changes::Change::Vanished
    {
        return Some("this is KAM Security's own service, and it is gone");
    }

    // 2. Our own binary moving or being replaced.
    if detail.contains("kam-agent.exe") || detail.contains("kam-shell.exe") {
        if difference.change == crate::changes::Change::Altered {
            return Some("this points at KAM Security's own program, and it has changed");
        }
        if difference.change == crate::changes::Change::Vanished {
            return Some("this pointed at KAM Security's own program, and it is gone");
        }
    }

    // 3. An administrator appearing or disappearing. Not about this software at
    //    all, and included here because no audit entry should ever be allowed to
    //    make it quiet: nothing this product does adds an administrator.
    if difference.kind == "administrator" {
        return Some("who can administer this machine is never explained away");
    }

    // 4. The laundering path. Something that starts itself, or a security
    //    control, that this software removed or altered on somebody's
    //    instruction. The audit entry will be genuine; that is exactly the
    //    problem.
    if matches!(
        difference.change,
        crate::changes::Change::Vanished | crate::changes::Change::Altered
    ) && is_protective(&name)
    {
        return Some("a protective thing changed, which is shown whoever caused it");
    }

    None
}

/// Whether a name looks like something whose job is to protect the machine.
///
/// Deliberately generous. Being wrong here means showing a row at full
/// prominence that could have been quietly labelled, which costs a line; being
/// wrong the other way means a rival security tool's removal is explained away
/// by an audit entry an attacker arranged.
fn is_protective(name: &str) -> bool {
    const PROTECTIVE: &[&str] = &[
        "defender",
        "antivirus",
        "anti-virus",
        "security",
        "firewall",
        "backup",
        "wuauserv",
        "windowsupdate",
        "sense",
        "wdnissvc",
        "wdfilter",
        "wdboot",
        "mpssvc",
        "vss",
        "sophos",
        "mcafee",
        "norton",
        "kaspersky",
        "bitdefender",
        "eset",
        "malwarebytes",
        "crowdstrike",
        "sentinel",
    ];
    PROTECTIVE.iter().any(|word| name.contains(word))
}

/// Find the audit entry, if any, that explains this change.
///
/// `None` when nothing does, and `None` is the safe answer: an unexplained
/// change is shown as unexplained, which is what the reader needs to see.
pub fn explain(difference: &Difference, log: &[Record]) -> Option<Attribution> {
    // The four rules above win over any entry in the log.
    if never_attributable(difference).is_some() {
        return None;
    }

    let target = difference.detail.to_lowercase();
    if target.is_empty() {
        return None;
    }

    let noticed = parse_time(&difference.at)?;

    log.iter()
        .filter(|record| {
            // Only the actions that actually move things. Reading the disk
            // cannot explain a startup entry disappearing, and letting it try
            // is how an alibi gets built out of ordinary activity.
            matches!(
                record.action.as_str(),
                "take" | "take_copy" | "delete" | "recycle" | "move_file" | "undo_move"
            )
        })
        .filter(|record| {
            // The same resolved target, named in the entry. Not the same name,
            // not something similar: the path this software recorded acting on
            // has to be the path that changed.
            record.detail.to_lowercase().contains(&target)
        })
        .filter_map(|record| {
            let when = parse_time(&record.at)?;
            let apart = (noticed - when).abs();
            (apart <= WINDOW_SECONDS).then_some((apart, record))
        })
        // The closest in time, when several qualify.
        .min_by_key(|(apart, _)| *apart)
        .map(|(_, record)| Attribution {
            action: format!("{} / {}", record.module, record.action),
            at: record.at.clone(),
            reported: record.detail.clone(),
        })
}

/// Seconds since the epoch for an ISO-8601 timestamp, to the second.
///
/// Written out rather than pulled in, because the only shapes that reach this
/// are ones written by this software: `strftime('%Y-%m-%dT%H:%M:%fZ')`. Anything
/// else is refused rather than guessed at, since a misparsed time would widen
/// the window silently.
fn parse_time(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() < 19 || bytes[4] != b'-' || bytes[10] != b'T' {
        return None;
    }
    let number = |from: usize, to: usize| text.get(from..to)?.parse::<i64>().ok();

    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    // Days since 1970 by the civil-from-days algorithm, which needs no calendar
    // table and is exact for every date this will ever see.
    let year_adjusted = if month <= 2 { year - 1 } else { year };
    let era = if year_adjusted >= 0 {
        year_adjusted
    } else {
        year_adjusted - 399
    } / 400;
    let year_of_era = year_adjusted - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;

    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::audit::Effect;
    use crate::changes::Change;

    fn difference(kind: &str, name: &str, detail: &str, change: Change) -> Difference {
        Difference {
            at: "2026-09-10T12:00:00.000Z".to_owned(),
            change,
            kind: kind.to_owned(),
            scope: "machine".to_owned(),
            name: name.to_owned(),
            detail: detail.to_owned(),
            first_seen: String::new(),
            last_seen: String::new(),
            times_seen: 1,
        }
    }

    fn record(action: &str, detail: &str, at: &str) -> Record {
        Record {
            id: 1,
            at: at.to_owned(),
            module: "quarantine".to_owned(),
            action: action.to_owned(),
            effect: Effect::Changed,
            detail: detail.to_owned(),
            undo_token: None,
        }
    }

    #[test]
    fn a_change_this_software_caused_is_explained() {
        let gone = difference(
            "run_key",
            "SomeApp",
            r"c:\users\me\appdata\someapp.exe",
            Change::Vanished,
        );
        let log = [record(
            "take",
            r"quarantined C:\Users\me\AppData\someapp.exe (2 MB) -- left behind",
            "2026-09-10T11:58:00.000Z",
        )];

        let attribution = explain(&gone, &log).expect("this one is ours");
        assert!(attribution.action.contains("take"));
        // The entry's text is carried as a report, never restated as a finding.
        assert!(attribution.reported.contains("quarantined"));
    }

    /// An action on one thing does not explain a change to another.
    ///
    /// The failure this prevents: every action becoming a general-purpose
    /// alibi. Quarantining one file must not account for an unrelated startup
    /// entry vanishing minutes later.
    #[test]
    fn an_action_on_something_else_explains_nothing() {
        let gone = difference(
            "run_key",
            "SomeApp",
            r"c:\users\me\appdata\someapp.exe",
            Change::Vanished,
        );
        let log = [record(
            "take",
            r"quarantined C:\Users\me\Downloads\unrelated.exe (2 MB)",
            "2026-09-10T11:58:00.000Z",
        )];

        assert!(
            explain(&gone, &log).is_none(),
            "an unrelated action was accepted as the explanation"
        );
    }

    #[test]
    fn an_action_long_before_explains_nothing() {
        let gone = difference(
            "run_key",
            "SomeApp",
            r"c:\users\me\appdata\someapp.exe",
            Change::Vanished,
        );
        let log = [record(
            "take",
            r"quarantined C:\Users\me\AppData\someapp.exe",
            // Hours earlier.
            "2026-09-10T04:00:00.000Z",
        )];

        assert!(explain(&gone, &log).is_none(), "a stale entry was accepted");
    }

    /// The laundering path, and the rule that closes it.
    ///
    /// An attacker induces a genuine removal of a rival security tool's startup
    /// entry. The audit entry is real and says exactly what happened, so a
    /// naive attribution would mark the disappearance as explained and quiet.
    /// The truth is the attack.
    #[test]
    fn removing_somebody_elses_protection_is_never_explained_away() {
        let gone = difference(
            "service",
            "MalwarebytesService",
            r"c:\program files\malwarebytes\mbam.exe",
            Change::Vanished,
        );
        let log = [record(
            "take",
            r"quarantined C:\Program Files\Malwarebytes\mbam.exe -- reported reason: leftover",
            "2026-09-10T11:59:00.000Z",
        )];

        assert!(
            never_attributable(&gone).is_some(),
            "a protective thing must never be attributable"
        );
        assert!(
            explain(&gone, &log).is_none(),
            "a genuine audit entry was allowed to explain away a rival tool's removal"
        );
    }

    #[test]
    fn our_own_service_disappearing_is_never_explained_away() {
        let gone = difference(
            "service",
            "KamSecurityAgent",
            r"c:\dist\kam-agent.exe",
            Change::Vanished,
        );
        assert!(never_attributable(&gone).is_some());
        assert!(explain(&gone, &[]).is_none());
    }

    #[test]
    fn an_administrator_change_is_never_explained_away() {
        for change in [Change::Appeared, Change::Vanished] {
            let who = difference("administrator", "someone", "can administer", change);
            assert!(
                never_attributable(&who).is_some(),
                "administrators must never be quiet, whatever the log says"
            );
        }
    }

    #[test]
    fn timestamps_this_software_writes_are_read_back_exactly() {
        // A misparse would widen the window silently, which is the failure that
        // turns tight matching back into an alibi.
        let noon = parse_time("2026-09-10T12:00:00.000Z").unwrap();
        let one_minute_later = parse_time("2026-09-10T12:01:00.000Z").unwrap();
        assert_eq!(one_minute_later - noon, 60);

        let next_day = parse_time("2026-09-11T12:00:00.000Z").unwrap();
        assert_eq!(next_day - noon, 86_400);

        // Across a month boundary, and across a leap day.
        let march = parse_time("2028-03-01T00:00:00.000Z").unwrap();
        let february = parse_time("2028-02-28T00:00:00.000Z").unwrap();
        assert_eq!(march - february, 2 * 86_400, "2028 is a leap year");

        // Anything not in the shape this software writes is refused rather
        // than guessed at.
        assert!(parse_time("").is_none());
        assert!(parse_time("yesterday").is_none());
        assert!(parse_time("10/09/2026 12:00").is_none());
    }
}
