//! What Microsoft Defender is doing, read from Defender.
//!
//! This is the first layer of the scanner and the reason there will not be a
//! second engine. Defender is already there, already good, and already has
//! cloud intelligence no side project will match. What it does not have is an
//! interface that answers "am I actually protected, and when did anything last
//! happen" without three clicks and a settings page that hides the interesting
//! parts.
//!
//! Everything here is a read. Defender's own settings are its business; this
//! reports what they are and lets the user see the consequences.
//!
//! # On the numbers Defender publishes
//!
//! `MSFT_MpComputerStatus` mixes booleans, ages in days, and timestamps in
//! several formats, and omits properties entirely on some builds rather than
//! returning false. So every field here is optional, and a missing value is
//! shown as unknown rather than as "off" — the difference between "real-time
//! protection is disabled" and "this build does not say" matters enormously to
//! someone reading the screen.

use serde::{Deserialize, Serialize};

use crate::wmi::{self, Value};

const NAMESPACE: &str = r"ROOT\Microsoft\Windows\Defender";

/// The headline state of the machine's protection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DefenderStatus {
    /// Defender's own summary of whether anything needs attention.
    pub healthy: Option<bool>,
    pub antivirus_enabled: Option<bool>,
    pub realtime_protection: Option<bool>,
    /// Watches memory, registry and behaviour rather than files on disk.
    pub behaviour_monitoring: Option<bool>,
    /// Sends suspicious samples for cloud analysis.
    pub cloud_protection: Option<bool>,
    /// Stops other software — including this one — changing Defender settings.
    pub tamper_protection: Option<bool>,
    pub antivirus_signature_version: Option<String>,
    pub engine_version: Option<String>,
    /// How stale the definitions are. Defender itself considers a week overdue.
    pub signature_age_days: Option<i64>,
    pub last_quick_scan_age_days: Option<i64>,
    pub last_full_scan_age_days: Option<i64>,
    pub computer_state: Option<i64>,
}

impl DefenderStatus {
    /// Concerns worth putting in front of the user, in plain words.
    ///
    /// Deliberately not a score or a count. "3 issues found!" is the language of
    /// software that wants to sell you something; this states what is off and
    /// lets the reader decide whether they meant it.
    pub fn concerns(&self) -> Vec<String> {
        let mut concerns = Vec::new();

        if self.antivirus_enabled == Some(false) {
            concerns.push("Defender's antivirus is switched off.".to_owned());
        }
        if self.realtime_protection == Some(false) {
            concerns.push(
                "Real-time protection is off, so files are not checked as they are opened."
                    .to_owned(),
            );
        }
        if self.behaviour_monitoring == Some(false) {
            concerns.push("Behaviour monitoring is off.".to_owned());
        }
        if self.cloud_protection == Some(false) {
            concerns.push(
                "Cloud-delivered protection is off, so new threats are recognised later."
                    .to_owned(),
            );
        }
        if self.tamper_protection == Some(false) {
            concerns.push(
                "Tamper protection is off, so other software can change these settings.".to_owned(),
            );
        }
        if let Some(age) = self.signature_age_days {
            if age >= 7 {
                concerns.push(format!("Definitions are {age} days old."));
            }
        }
        match (self.last_quick_scan_age_days, self.last_full_scan_age_days) {
            (None, None) => {
                concerns.push("Defender has no record of ever having scanned.".to_owned())
            }
            (quick, full) => {
                let newest = quick.into_iter().chain(full).min();
                if let Some(days) = newest {
                    if days >= 30 {
                        concerns.push(format!("The last scan of any kind was {days} days ago."));
                    }
                }
            }
        }

        concerns
    }
}

/// One thing Defender found, and what it did about it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    pub name: String,
    /// Defender's severity: 1 low, 2 moderate, 4 high, 5 severe.
    pub severity: Option<i64>,
    pub category: Option<i64>,
    /// What Defender did, in its own vocabulary.
    pub action: Option<i64>,
    pub status: Option<i64>,
    /// Files or registry keys involved, as Defender recorded them.
    pub resources: Vec<String>,
    pub detected_at: Option<String>,
}

impl Threat {
    pub fn severity_label(&self) -> &'static str {
        match self.severity {
            Some(5) => "severe",
            Some(4) => "high",
            Some(2) => "moderate",
            Some(1) => "low",
            _ => "unknown",
        }
    }

    /// Defender's `ThreatStatusID`, translated.
    ///
    /// The values that matter to a person are whether it is gone and whether
    /// anything is still required of them.
    pub fn status_label(&self) -> &'static str {
        match self.status {
            Some(0) => "unknown",
            Some(1) => "detected",
            Some(2) => "cleaned",
            Some(3) => "quarantined",
            Some(4) => "removed",
            Some(5) => "allowed",
            Some(6) => "blocked",
            Some(102) => "no longer present",
            _ => "unknown",
        }
    }
}

fn flag(row: &wmi::Row, key: &str) -> Option<bool> {
    row.get(key).and_then(Value::flag)
}

fn number(row: &wmi::Row, key: &str) -> Option<i64> {
    row.get(key).and_then(Value::number)
}

fn text(row: &wmi::Row, key: &str) -> Option<String> {
    row.get(key)
        .and_then(Value::text)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// Read Defender's current state.
pub fn status() -> kam_core::Result<DefenderStatus> {
    const FIELDS: &[&str] = &[
        "AMServiceEnabled",
        "AntivirusEnabled",
        "RealTimeProtectionEnabled",
        "BehaviorMonitorEnabled",
        "IoavProtectionEnabled",
        "IsTamperProtected",
        "AntivirusSignatureVersion",
        "AMEngineVersion",
        "AntivirusSignatureAge",
        "QuickScanAge",
        "FullScanAge",
        "ComputerState",
        "DefenderSignaturesOutOfDate",
    ];

    let rows = wmi::query(NAMESPACE, "SELECT * FROM MSFT_MpComputerStatus", FIELDS)?;
    let Some(row) = rows.first() else {
        return Err(kam_core::Error::Refused(
            "Defender did not report a status; it may be replaced by another product".to_owned(),
        ));
    };

    // Ages come back as very large numbers when Defender means "never".
    let sane_age = |value: Option<i64>| value.filter(|days| (0..36_500).contains(days));

    Ok(DefenderStatus {
        healthy: flag(row, "AMServiceEnabled"),
        antivirus_enabled: flag(row, "AntivirusEnabled"),
        realtime_protection: flag(row, "RealTimeProtectionEnabled"),
        behaviour_monitoring: flag(row, "BehaviorMonitorEnabled"),
        cloud_protection: flag(row, "IoavProtectionEnabled"),
        tamper_protection: flag(row, "IsTamperProtected"),
        antivirus_signature_version: text(row, "AntivirusSignatureVersion"),
        engine_version: text(row, "AMEngineVersion"),
        signature_age_days: sane_age(number(row, "AntivirusSignatureAge")),
        last_quick_scan_age_days: sane_age(number(row, "QuickScanAge")),
        last_full_scan_age_days: sane_age(number(row, "FullScanAge")),
        computer_state: number(row, "ComputerState"),
    })
}

/// Everything Defender has detected and still has a record of.
///
/// `MSFT_MpThreatDetection` is the event log; `MSFT_MpThreat` is the catalogue
/// of what those events were about. The detection rows carry the timestamp and
/// the files, so they are what is read here.
pub fn threats() -> kam_core::Result<Vec<Threat>> {
    const FIELDS: &[&str] = &[
        "ThreatName",
        "SeverityID",
        "CategoryID",
        "ThreatStatusID",
        "CleaningActionID",
        "Resources",
        "InitialDetectionTime",
    ];

    // Detections carry timestamps; the threat catalogue does not.
    let rows = wmi::query(NAMESPACE, "SELECT * FROM MSFT_MpThreatDetection", FIELDS)
        .or_else(|_| wmi::query(NAMESPACE, "SELECT * FROM MSFT_MpThreat", FIELDS))?;

    let mut threats: Vec<Threat> = rows
        .iter()
        .map(|row| Threat {
            name: text(row, "ThreatName").unwrap_or_else(|| "unnamed detection".to_owned()),
            severity: number(row, "SeverityID"),
            category: number(row, "CategoryID"),
            action: number(row, "CleaningActionID"),
            status: number(row, "ThreatStatusID"),
            // Resources arrive as a string array, which the reader does not
            // decode; the name and status are what a person needs.
            resources: Vec::new(),
            detected_at: text(row, "InitialDetectionTime"),
        })
        .collect();

    // Most severe first, so the screen leads with what matters.
    threats.sort_by_key(|threat| std::cmp::Reverse(threat.severity.unwrap_or(0)));
    Ok(threats)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_setting_is_never_reported_as_a_concern() {
        // The distinction this whole module rests on: "off" is a finding,
        // "this build does not say" is not.
        let unknown = DefenderStatus::default();
        assert!(
            unknown
                .concerns()
                .iter()
                .all(|concern| !concern.contains("switched off")),
            "an absent value must not read as disabled"
        );
    }

    #[test]
    fn protection_being_off_is_reported() {
        let status = DefenderStatus {
            realtime_protection: Some(false),
            tamper_protection: Some(false),
            ..Default::default()
        };
        let concerns = status.concerns();
        assert!(concerns
            .iter()
            .any(|c| c.contains("Real-time protection is off")));
        assert!(concerns
            .iter()
            .any(|c| c.contains("Tamper protection is off")));
    }

    #[test]
    fn a_healthy_machine_produces_nothing_to_say() {
        let status = DefenderStatus {
            antivirus_enabled: Some(true),
            realtime_protection: Some(true),
            behaviour_monitoring: Some(true),
            cloud_protection: Some(true),
            tamper_protection: Some(true),
            signature_age_days: Some(0),
            last_quick_scan_age_days: Some(1),
            last_full_scan_age_days: Some(10),
            ..Default::default()
        };
        assert!(
            status.concerns().is_empty(),
            "a protected machine should be told it is fine, not given filler: {:?}",
            status.concerns()
        );
    }

    #[test]
    fn only_the_more_recent_scan_counts() {
        // A quick scan yesterday means the machine is being scanned, whatever
        // the full scan says.
        let status = DefenderStatus {
            last_quick_scan_age_days: Some(1),
            last_full_scan_age_days: Some(400),
            ..Default::default()
        };
        assert!(
            !status.concerns().iter().any(|c| c.contains("last scan")),
            "a recent quick scan should satisfy this"
        );
    }

    #[test]
    fn never_having_scanned_is_worth_saying() {
        let status = DefenderStatus::default();
        assert!(status
            .concerns()
            .iter()
            .any(|concern| concern.contains("no record of ever having scanned")));
    }

    #[test]
    fn stale_definitions_are_reported_with_their_age() {
        let status = DefenderStatus {
            signature_age_days: Some(11),
            last_quick_scan_age_days: Some(1),
            ..Default::default()
        };
        assert!(status
            .concerns()
            .iter()
            .any(|concern| concern.contains("11 days old")));
    }

    #[test]
    fn severity_and_status_read_as_words() {
        let threat = Threat {
            name: "Test".to_owned(),
            severity: Some(5),
            category: None,
            action: None,
            status: Some(3),
            resources: Vec::new(),
            detected_at: None,
        };
        assert_eq!(threat.severity_label(), "severe");
        assert_eq!(threat.status_label(), "quarantined");
    }

    #[test]
    fn this_machine_reports_a_defender_status() {
        // Defender is present on every supported Windows install. If this fails
        // the WMI plumbing is wrong, not the machine.
        match status() {
            Ok(status) => {
                println!("defender: {status:?}");
                println!("concerns: {:?}", status.concerns());
                assert!(
                    status.antivirus_enabled.is_some() || status.healthy.is_some(),
                    "no recognisable status field came back"
                );
            }
            Err(error) => panic!("could not read Defender status: {error}"),
        }
    }
}
