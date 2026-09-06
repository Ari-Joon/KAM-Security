//! Protections Windows already has and mostly leaves switched off.
//!
//! # Why this is worth a panel
//!
//! Defender ships a set of Attack Surface Reduction rules — narrow, specific
//! blocks on the handful of things malware does and ordinary software almost
//! never does. They are free, they are already on the machine, and on a
//! consumer installation essentially all of them are off. Turning the right
//! three on is the single cheapest security improvement available to most
//! people, and nothing in Windows ever suggests it.
//!
//! This is not hypothetical. The infection this product was hardened after ran
//! a script through a signed build tool out of a Temp folder and then read the
//! browser credential stores. Two of the rules below are aimed squarely at that
//! shape, and a third at the credential theft that followed.
//!
//! # What this module does and does not do
//!
//! It reads state and explains it. It does not turn anything on. Enabling an
//! ASR rule changes how every program on the machine is allowed to behave, and
//! a rule set in Block mode can stop software the owner depends on — which is
//! exactly why Microsoft ships them off and offers an Audit mode first. A
//! security tool that silently enabled them would be making that decision on
//! somebody's behalf, and the first thing they would know about it is their
//! work breaking.
//!
//! So this reports what is off, says what each one would prevent in plain
//! words, and leaves the decision where it belongs.
//!
//! # Where the state is read from
//!
//! The registry rather than WMI. `MSFT_MpPreference` returns the rule
//! identifiers and their actions as two parallel *arrays*, and the WMI reader
//! here deliberately handles only scalars. The same state is written under
//! Exploit Guard as one value per rule, which the existing registry reader
//! already enumerates — so this needs no new Windows API surface at all.

use kam_core::registry::{self, View};
use serde::{Deserialize, Serialize};
use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;

/// Where a locally configured rule set lands.
const LOCAL_ASR: &str =
    r"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules";

/// Where a policy-configured one lands. Policy wins where both exist.
const POLICY_ASR: &str =
    r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules";

const LOCAL_CFA: &str =
    r"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access";

const POLICY_CFA: &str = r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access";

/// What Defender is set to do when a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Configured, and doing nothing. The same as not configured, in effect.
    Off,
    /// Stops the behaviour.
    Block,
    /// Allows it and writes an event. The sensible way to try a rule out.
    Audit,
    /// Blocks, and tells the person why.
    Warn,
    /// Present with a value Defender does not document.
    Unknown(u32),
}

impl Mode {
    fn parse(value: u32) -> Self {
        match value {
            0 => Self::Off,
            1 => Self::Block,
            2 => Self::Audit,
            6 => Self::Warn,
            other => Self::Unknown(other),
        }
    }

    pub fn label(self) -> String {
        match self {
            Self::Off => "off".to_owned(),
            Self::Block => "blocking".to_owned(),
            Self::Audit => "auditing only".to_owned(),
            Self::Warn => "warning".to_owned(),
            Self::Unknown(value) => format!("set to an unrecognised value ({value})"),
        }
    }

    /// Whether this rule is actually preventing anything.
    pub fn is_protecting(self) -> bool {
        matches!(self, Self::Block | Self::Warn)
    }
}

/// One Attack Surface Reduction rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// The GUID Defender knows it by, so it can be turned on by hand.
    pub id: String,
    /// What it does, in words meant for a person.
    pub name: String,
    /// Why it is worth having, and what it would have stopped.
    pub explains: String,
    pub mode: Mode,
    /// True for the rules aimed at how this product's own case began.
    pub recommended: bool,
}

/// The rules worth naming, with what each one prevents.
///
/// Not the whole catalogue. These are the ones whose effect can be described
/// truthfully in a sentence to somebody who is not a security engineer, and
/// whose cost is low enough to be worth suggesting. An identifier that is
/// configured but not listed here is still reported, by its GUID, rather than
/// hidden — a rule this tool has not heard of is not a rule that should vanish
/// from the count.
const KNOWN: &[(&str, &str, &str, bool)] = &[
    (
        "01443614-cd74-433a-b99e-2ecdc07bfc25",
        "Block executables that are new, rare, or untrusted",
        "Stops a program running unless it is old enough, common enough, or on a trusted list. A freshly built dropper downloaded ten minutes ago is none of those, which is exactly what makes this the single most useful rule here.",
        true,
    ),
    (
        "d1e49aac-8f56-4280-b9ba-993a6d77406c",
        "Block programs started by PsExec and WMI",
        "Two administration tools that ordinary software has no reason to launch things through, and that malware uses constantly to run code and to move between machines.",
        true,
    ),
    (
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
        "Block credential theft from the Windows login service",
        "Stops programs reading passwords and tokens out of lsass.exe, the process that holds the credentials of everyone signed in. Almost nothing legitimate reads it.",
        true,
    ),
    (
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc",
        "Block obfuscated scripts",
        "Scripts deliberately written to be unreadable. Legitimate scripts have no reason to hide what they do, and this is the ordinary shape of a dropper's first stage.",
        true,
    ),
    (
        "d3e037e1-3eb8-44c8-a917-57927947596d",
        "Block scripts from launching downloaded programs",
        "Stops JavaScript and VBScript starting an executable they have just fetched, which is the join between the thing you clicked and the thing that does the damage.",
        true,
    ),
    (
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
        "Block programs arriving by email or webmail",
        "An executable that came straight out of a mail client or a webmail page, run without ever being saved and looked at.",
        true,
    ),
    (
        "e6db77e5-3df2-4cf1-b95a-636979351e5b",
        "Block persistence through WMI event subscription",
        "A way of arranging to be run again that leaves nothing in the startup folders, the Run keys, or the task store — and so is invisible to most tools that list what starts itself, including this one.",
        true,
    ),
    (
        "c1db55ab-c21a-4637-bb3f-a12568109d35",
        "Advanced ransomware protection",
        "Additional checks against the behaviour of programs that encrypt files in bulk.",
        false,
    ),
    (
        "56a863a9-875e-4185-98a7-b882c64b5ce5",
        "Block abuse of vulnerable signed drivers",
        "Stops a program loading a legitimately signed but known-flawed driver in order to reach the kernel through it.",
        false,
    ),
    (
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
        "Block Office applications from starting other programs",
        "Word and Excel have no ordinary reason to launch a program. This is what a malicious macro does first.",
        false,
    ),
    (
        "3b576869-a4ec-4529-8536-b80a7769e899",
        "Block Office applications from writing executable files",
        "The other half of the macro pattern: writing the program out before running it.",
        false,
    ),
    (
        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",
        "Block Win32 calls from Office macros",
        "A macro reaching past the document into the operating system's own interfaces.",
        false,
    ),
    (
        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
        "Block Office applications from injecting into other processes",
        "Writing code into a program that is already running, to borrow its identity and its permissions.",
        false,
    ),
    (
        "26190899-1602-49e8-8b27-eb1d0a1ce869",
        "Block Office communication apps from starting other programs",
        "The same rule as above, for Outlook and its relatives.",
        false,
    ),
    (
        "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",
        "Block Adobe Reader from starting other programs",
        "A PDF reader has no reason to launch anything.",
        false,
    ),
    (
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",
        "Block untrusted programs from USB drives",
        "An unsigned program running straight off a removable drive.",
        false,
    ),
    (
        "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb",
        "Block copied or impersonated system tools",
        "A copy of a Windows tool, moved somewhere else or renamed, which is how a trusted name gets used to do an untrusted thing.",
        false,
    ),
    (
        "33ddedf1-c6e0-47cb-833e-de6133960387",
        "Block rebooting into Safe Mode",
        "Safe Mode starts Windows without most of its protection, and some malware reboots into it deliberately.",
        false,
    ),
    (
        "a8f5898e-1dc8-49a9-9878-85004b8a61e6",
        "Block webshell creation for servers",
        "Aimed at Exchange servers rather than desktops.",
        false,
    ),
];

/// Controlled Folder Access: Defender's own ransomware guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FolderAccess {
    Off,
    On,
    AuditOnly,
    BlockDiskModificationOnly,
    AuditDiskModificationOnly,
    /// Nothing written, which is what an untouched machine looks like.
    NotConfigured,
    /// The key exists but could not be read.
    Unreadable,
}

impl FolderAccess {
    fn parse(value: Option<u32>) -> Self {
        match value {
            None => Self::NotConfigured,
            Some(0) => Self::Off,
            Some(1) => Self::On,
            Some(2) => Self::AuditOnly,
            Some(3) => Self::BlockDiskModificationOnly,
            Some(4) => Self::AuditDiskModificationOnly,
            Some(_) => Self::Unreadable,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::On => "on",
            Self::AuditOnly => "auditing only",
            Self::BlockDiskModificationOnly => "blocking disk changes only",
            Self::AuditDiskModificationOnly => "auditing disk changes only",
            Self::NotConfigured => "never configured",
            Self::Unreadable => "set to something unrecognised",
        }
    }

    pub fn is_protecting(self) -> bool {
        matches!(self, Self::On | Self::BlockDiskModificationOnly)
    }
}

/// The machine's hardening posture.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub rules: Vec<Rule>,
    pub controlled_folder_access: Option<FolderAccess>,
    /// Sources that exist but could not be read, in plain words.
    pub unreadable: Vec<String>,
}

impl Report {
    /// How many of the rules worth recommending are actually preventing
    /// something.
    pub fn recommended_on(&self) -> usize {
        self.rules
            .iter()
            .filter(|rule| rule.recommended && rule.mode.is_protecting())
            .count()
    }

    pub fn recommended_total(&self) -> usize {
        self.rules.iter().filter(|rule| rule.recommended).count()
    }

    /// Things worth saying, in plain words and without a count of "issues".
    ///
    /// Deliberately quiet when the answer is "these are off", because on a
    /// consumer machine they are all off and always have been, and shouting
    /// about the default state of Windows is how a tool becomes noise. It says
    /// it once, names what it would buy, and stops.
    pub fn concerns(&self) -> Vec<String> {
        let mut concerns = Vec::new();
        let on = self.recommended_on();
        let total = self.recommended_total();

        if total > 0 && on == 0 {
            concerns.push(format!(
                "None of the {total} recommended Attack Surface Reduction rules are switched on. \
                 They are free, already part of Defender, and off by default."
            ));
        } else if on < total {
            concerns.push(format!(
                "{on} of {total} recommended Attack Surface Reduction rules are switched on."
            ));
        }

        if self
            .controlled_folder_access
            .is_some_and(|state| !state.is_protecting())
        {
            concerns.push(
                "Controlled Folder Access is not protecting your documents. It stops unknown \
                 programs writing to your personal folders, which is what ransomware does."
                    .to_owned(),
            );
        }

        concerns
    }
}

/// Read one ASR rule set, as GUID to mode.
///
/// Values are written as strings on some builds and DWORDs on others, so both
/// are accepted rather than one being assumed.
fn read_rules(path: &str) -> Option<Vec<(String, u32)>> {
    let key = registry::Key::open(HKEY_LOCAL_MACHINE, path, View::Native)?;
    let mut found = Vec::new();
    for name in key.value_names() {
        if name.is_empty() {
            continue;
        }
        let value = key
            .dword(&name)
            .or_else(|| key.string(&name).and_then(|text| text.trim().parse().ok()));
        if let Some(value) = value {
            found.push((name.to_lowercase(), value));
        }
    }
    Some(found)
}

fn read_folder_access(path: &str) -> Option<u32> {
    registry::Key::open(HKEY_LOCAL_MACHINE, path, View::Native)?
        .dword("EnableControlledFolderAccess")
}

/// What is switched on, and what is not.
pub fn survey() -> Report {
    let mut report = Report::default();

    // Policy last, so it overwrites a locally set value for the same rule.
    let mut configured: std::collections::BTreeMap<String, u32> = Default::default();
    let local = read_rules(LOCAL_ASR);
    let policy = read_rules(POLICY_ASR);
    if local.is_none() && policy.is_none() {
        report.unreadable.push(
            "Defender's Attack Surface Reduction settings could not be read. They may never have \
             been configured, which is the default."
                .to_owned(),
        );
    }
    for set in [local, policy].into_iter().flatten() {
        for (id, mode) in set {
            configured.insert(id, mode);
        }
    }

    for (id, name, explains, recommended) in KNOWN {
        let mode = configured
            .get(&id.to_lowercase())
            .copied()
            .map(Mode::parse)
            .unwrap_or(Mode::Off);
        report.rules.push(Rule {
            id: (*id).to_owned(),
            name: (*name).to_owned(),
            explains: (*explains).to_owned(),
            mode,
            recommended: *recommended,
        });
    }

    // Anything configured that this list does not know about. Reported rather
    // than dropped: a rule nobody here has heard of is still a rule.
    let known: std::collections::BTreeSet<String> =
        KNOWN.iter().map(|(id, ..)| id.to_lowercase()).collect();
    for (id, mode) in &configured {
        if !known.contains(id) {
            report.rules.push(Rule {
                id: id.clone(),
                name: "A rule this version does not have a description for".to_owned(),
                explains:
                    "It is configured on this machine. Its identifier can be looked up in Microsoft's \
                     Attack Surface Reduction documentation."
                        .to_owned(),
                mode: Mode::parse(*mode),
                recommended: false,
            });
        }
    }

    // Recommended first, then the ones doing something, then by name — so the
    // top of the list is the part worth acting on.
    report.rules.sort_by(|a, b| {
        b.recommended
            .cmp(&a.recommended)
            .then_with(|| a.mode.is_protecting().cmp(&b.mode.is_protecting()))
            .then_with(|| a.name.cmp(&b.name))
    });

    report.controlled_folder_access = Some(FolderAccess::parse(
        read_folder_access(POLICY_CFA).or_else(|| read_folder_access(LOCAL_CFA)),
    ));

    report
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn every_listed_rule_has_a_real_guid_and_an_explanation() {
        // A rule identified by the wrong GUID would report the wrong thing
        // about somebody's machine, so the shape is checked structurally.
        for (id, name, explains, _) in KNOWN {
            assert_eq!(id.len(), 36, "{id} is not a GUID");
            assert_eq!(id.matches('-').count(), 4, "{id} is not shaped like a GUID");
            assert_eq!(&id.to_lowercase(), id, "{id} should be lowercase");
            assert!(!name.is_empty());
            assert!(
                explains.len() > 40,
                "{name} needs an explanation somebody can act on"
            );
        }
    }

    #[test]
    fn no_rule_is_listed_twice() {
        let mut seen = std::collections::BTreeSet::new();
        for (id, ..) in KNOWN {
            assert!(seen.insert(*id), "{id} appears twice");
        }
    }

    #[test]
    fn the_modes_defender_documents_are_understood() {
        assert_eq!(Mode::parse(0), Mode::Off);
        assert_eq!(Mode::parse(1), Mode::Block);
        assert_eq!(Mode::parse(2), Mode::Audit);
        assert_eq!(Mode::parse(6), Mode::Warn);
        assert!(Mode::parse(1).is_protecting());
        assert!(Mode::parse(6).is_protecting());
        // Auditing writes an event and stops nothing, so it is not protection.
        assert!(!Mode::parse(2).is_protecting());
        assert!(!Mode::parse(0).is_protecting());
    }

    #[test]
    fn an_untouched_machine_is_told_once_and_not_nagged() {
        // The default state of Windows is every rule off. Saying so once, with
        // what it would buy, is useful; a list of nineteen alarms is not.
        let report = Report {
            rules: KNOWN
                .iter()
                .map(|(id, name, explains, recommended)| Rule {
                    id: (*id).to_owned(),
                    name: (*name).to_owned(),
                    explains: (*explains).to_owned(),
                    mode: Mode::Off,
                    recommended: *recommended,
                })
                .collect(),
            controlled_folder_access: Some(FolderAccess::NotConfigured),
            unreadable: Vec::new(),
        };
        let concerns = report.concerns();
        assert_eq!(
            concerns.len(),
            2,
            "one sentence about the rules and one about folders: {concerns:?}"
        );
        assert!(concerns[0].contains("None of the"));
    }

    #[test]
    fn a_hardened_machine_says_nothing_about_the_rules() {
        let report = Report {
            rules: KNOWN
                .iter()
                .map(|(id, name, explains, recommended)| Rule {
                    id: (*id).to_owned(),
                    name: (*name).to_owned(),
                    explains: (*explains).to_owned(),
                    mode: Mode::Block,
                    recommended: *recommended,
                })
                .collect(),
            controlled_folder_access: Some(FolderAccess::On),
            unreadable: Vec::new(),
        };
        assert!(
            report.concerns().is_empty(),
            "a hardened machine should be quiet: {:?}",
            report.concerns()
        );
    }

    #[test]
    fn this_machine_can_be_surveyed() {
        let report = survey();
        println!(
            "{} rules, {} of {} recommended ones on, folders: {:?}",
            report.rules.len(),
            report.recommended_on(),
            report.recommended_total(),
            report.controlled_folder_access.map(|c| c.label())
        );
        for concern in report.concerns() {
            println!("  concern: {concern}");
        }
        for rule in report.rules.iter().filter(|r| r.mode.is_protecting()) {
            println!("  on: {} ({})", rule.name, rule.mode.label());
        }
        assert!(
            report.rules.len() >= KNOWN.len(),
            "every known rule should be reported whether or not it is configured"
        );
    }
}
