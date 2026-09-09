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

/// A protection that is simply on or off.
///
/// Attack Surface Reduction rules have four modes and a catalogue; these have
/// two states and a reason. They are kept apart from `Rule` because the
/// difference that matters to a reader is not the shape of the value but
/// whether Windows ships it on: an ASR rule being off is the default and worth
/// one quiet line, while Tamper Protection being off means somebody or
/// something turned it off, and that is a different sentence entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwitchState {
    On,
    Off,
    /// Nothing written. For most of these that means the Windows default,
    /// which is why each switch carries what its default actually is.
    NotConfigured,
    /// Present, and set to something undocumented.
    Unrecognised(u32),
}

impl SwitchState {
    pub fn label(self) -> String {
        match self {
            Self::On => "on".to_owned(),
            Self::Off => "off".to_owned(),
            Self::NotConfigured => "not configured".to_owned(),
            Self::Unrecognised(value) => format!("set to an unrecognised value ({value})"),
        }
    }
}

/// Whether Windows turns this on by itself.
///
/// The whole point of the distinction. A protection that is off *because that
/// is the default* is a suggestion; one that is off *against* the default is a
/// finding, because something changed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Default_ {
    /// Windows enables it. Finding it off is a question worth asking.
    On,
    /// Windows leaves it off. Finding it off is ordinary.
    Off,
    /// Depends on the hardware or the edition, so absence proves nothing.
    Varies,
}

/// One on-or-off protection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Switch {
    /// Stable key, so the interface can order and test against it.
    pub id: String,
    pub name: String,
    /// What it prevents, in words meant for somebody who is not a security
    /// engineer.
    pub explains: String,
    pub state: SwitchState,
    pub default: Default_,
    /// How a person turns it on themselves. Nothing here changes it: several of
    /// these can stop software the owner depends on, and one of them cannot be
    /// set programmatically at all by design.
    pub how: String,
}

impl Switch {
    pub fn is_protecting(&self) -> bool {
        self.state == SwitchState::On
    }

    /// Off when Windows would have had it on. The only case worth alarm.
    pub fn is_unexpectedly_off(&self) -> bool {
        self.default == Default_::On && matches!(self.state, SwitchState::Off)
    }
}

/// Read one machine-wide DWORD, preferring policy over the local setting.
fn dword(paths: &[&str], value: &str) -> Option<u32> {
    for path in paths {
        if let Some(key) = registry::Key::open(HKEY_LOCAL_MACHINE, path, View::Native) {
            if let Some(found) = key.dword(value) {
                return Some(found);
            }
        }
    }
    None
}

/// The protections that are a single switch, and what each one is worth.
fn switches() -> Vec<Switch> {
    let mut found = Vec::new();

    // Tamper Protection is deliberately absent here.
    //
    // It belongs in this list by every argument above, and it is already read
    // properly in `defender`, from `MSFT_MpComputerStatus.IsTamperProtected`,
    // which is what Defender itself reports. A registry version was written
    // here first and was wrong: the widely repeated mapping of 5 for on and 4
    // for off does not hold, and this machine reports 1 while Defender reports
    // protected. Two readings of one setting, one of them guessed from an
    // undocumented value, is how a security tool ends up confidently wrong.

    // Potentially Unwanted Application blocking. Off by default, and aimed at
    // exactly the band this product's rule engine already targets: bundleware,
    // "optimisers", browser hijackers. Defender will block them and simply is
    // not asked to.
    let pua = dword(
        &[
            r"SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine",
            r"SOFTWARE\Microsoft\Windows Defender\MpEngine",
        ],
        "MpEnablePus",
    );
    found.push(Switch {
        id: "pua-protection".to_owned(),
        name: "Blocking unwanted applications".to_owned(),
        explains: "Defender can block the software that is not quite malware — bundled toolbars, \
                   registry cleaners, driver updaters, the things that arrive alongside something \
                   else. It is off unless asked, and it covers the same ground this program's own \
                   rules do, from inside the engine."
            .to_owned(),
        state: match pua {
            Some(1) => SwitchState::On,
            // 2 is audit: it writes an event and allows it, which is not
            // protection and is not described as such.
            Some(0) | Some(2) => SwitchState::Off,
            Some(other) => SwitchState::Unrecognised(other),
            None => SwitchState::NotConfigured,
        },
        default: Default_::Off,
        how: "PowerShell as administrator: Set-MpPreference -PUAProtection Enabled".to_owned(),
    });

    // LSA protection. Stops another process reading the memory of the service
    // that holds signed-in credentials, which is the step between "ran code on
    // the machine" and "has the password".
    let lsa = dword(&[r"SYSTEM\CurrentControlSet\Control\Lsa"], "RunAsPPL");
    found.push(Switch {
        id: "lsa-protection".to_owned(),
        name: "Credential memory protection".to_owned(),
        explains: "Windows keeps the credentials of everyone signed in inside one service. This \
                   stops other programs reading that service's memory, which is the usual step \
                   between something running on the machine and something having your password."
            .to_owned(),
        state: match lsa {
            // 1 is enabled, 2 is enabled with a UEFI lock.
            Some(1) | Some(2) => SwitchState::On,
            Some(0) => SwitchState::Off,
            Some(other) => SwitchState::Unrecognised(other),
            None => SwitchState::NotConfigured,
        },
        default: Default_::Varies,
        how: "Windows Security > Device security > Core isolation, where recent versions of \
              Windows 11 offer it as Local Security Authority protection."
            .to_owned(),
    });

    // Memory integrity. Off on plenty of machines because an old driver blocks
    // it, so its absence is a question rather than a fault.
    let hvci = dword(
        &[
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
        ],
        "Enabled",
    );
    found.push(Switch {
        id: "memory-integrity".to_owned(),
        name: "Memory integrity".to_owned(),
        explains: "Checks drivers before they are allowed into the kernel, so a malicious or \
                   tampered driver cannot load. Windows turns it off when an existing driver is \
                   incompatible, so it being off often means an old driver rather than a decision."
            .to_owned(),
        state: match hvci {
            Some(1) => SwitchState::On,
            Some(0) => SwitchState::Off,
            Some(other) => SwitchState::Unrecognised(other),
            None => SwitchState::NotConfigured,
        },
        default: Default_::Varies,
        how: "Windows Security > Device security > Core isolation > Memory integrity.".to_owned(),
    });

    // The blocklist of drivers with known holes. Attackers bring a signed,
    // vulnerable driver with them precisely because it is signed; this is the
    // list that refuses them.
    let blocklist = dword(
        &[r"SYSTEM\CurrentControlSet\Control\CI\Config"],
        "VulnerableDriverBlocklistEnable",
    );
    found.push(Switch {
        id: "driver-blocklist".to_owned(),
        name: "Vulnerable driver blocklist".to_owned(),
        explains: "Microsoft keeps a list of signed drivers with known holes in them. Attackers \
                   bring one of those along on purpose, because being signed is what gets it \
                   loaded, and then use its hole to reach the kernel. This is the list that \
                   refuses them."
            .to_owned(),
        state: match blocklist {
            Some(1) => SwitchState::On,
            Some(0) => SwitchState::Off,
            Some(other) => SwitchState::Unrecognised(other),
            // On by default on Windows 11 and on Windows 10 with memory
            // integrity, so nothing written is not the same as off.
            None => SwitchState::NotConfigured,
        },
        default: Default_::On,
        how: "It follows memory integrity on most machines. Windows Security > Device security > \
              Core isolation."
            .to_owned(),
    });

    found
}

/// The machine's hardening posture.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub rules: Vec<Rule>,
    pub controlled_folder_access: Option<FolderAccess>,
    /// Protections that are simply on or off.
    pub switches: Vec<Switch>,
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

        // Something turned these off. Windows would have had them on, so this
        // is a finding rather than a suggestion, and it is said first and
        // separately from the list of things that are merely available.
        for switch in self.switches.iter().filter(|s| s.is_unexpectedly_off()) {
            concerns.insert(
                0,
                format!(
                    "{} is off, and Windows switches it on by itself. Something changed it.",
                    switch.name
                ),
            );
        }

        // Everything else worth having and not switched on, named once rather
        // than one line each: on an untouched machine most of these are off and
        // always have been, and a list of five complaints about the defaults is
        // how a tool becomes noise.
        let available: Vec<&str> = self
            .switches
            .iter()
            .filter(|s| !s.is_protecting() && !s.is_unexpectedly_off())
            .map(|s| s.name.as_str())
            .collect();
        if !available.is_empty() {
            concerns.push(format!(
                "Not switched on, and free: {}. Each says what it would prevent.",
                available.join(", ")
            ));
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
    let mut report = Report {
        switches: switches(),
        ..Default::default()
    };

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
    fn every_switch_is_named_once_and_explains_itself() {
        let found = switches();
        assert!(!found.is_empty());

        let mut ids: Vec<&str> = found.iter().map(|s| s.id.as_str()).collect();
        let before = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), before, "two switches share an id");

        for switch in &found {
            assert!(!switch.name.is_empty(), "{} has no name", switch.id);
            assert!(
                switch.explains.len() > 60,
                "{} does not explain what it prevents",
                switch.id
            );
            assert!(
                !switch.how.is_empty(),
                "{} does not say how to turn it on",
                switch.id
            );
        }
    }

    /// Off by default and off against the default are different sentences.
    ///
    /// This is the whole reason `Switch` exists beside `Rule`. Treating them
    /// the same would either shout about the ordinary state of Windows or stay
    /// quiet about something having turned a protection off, and the second is
    /// the one that matters.
    #[test]
    fn only_a_protection_windows_would_have_had_on_counts_as_a_finding() {
        let off_by_design = Switch {
            id: "x".to_owned(),
            name: "Something Windows leaves off".to_owned(),
            explains: "a".repeat(80),
            state: SwitchState::Off,
            default: Default_::Off,
            how: "somewhere".to_owned(),
        };
        assert!(!off_by_design.is_unexpectedly_off());

        let turned_off = Switch {
            default: Default_::On,
            ..off_by_design.clone()
        };
        assert!(turned_off.is_unexpectedly_off());

        // Not configured is not the same as off: for most of these it is the
        // default, and claiming somebody turned it off would be a lie.
        let untouched = Switch {
            state: SwitchState::NotConfigured,
            ..turned_off.clone()
        };
        assert!(!untouched.is_unexpectedly_off());
    }

    #[test]
    fn something_having_turned_a_protection_off_is_said_first() {
        let report = Report {
            rules: Vec::new(),
            controlled_folder_access: None,
            switches: vec![
                Switch {
                    id: "available".to_owned(),
                    name: "Merely available".to_owned(),
                    explains: "a".repeat(80),
                    state: SwitchState::Off,
                    default: Default_::Off,
                    how: "somewhere".to_owned(),
                },
                Switch {
                    id: "tampered".to_owned(),
                    name: "Something Windows enables".to_owned(),
                    explains: "a".repeat(80),
                    state: SwitchState::Off,
                    default: Default_::On,
                    how: "somewhere".to_owned(),
                },
            ],
            unreadable: Vec::new(),
        };

        let concerns = report.concerns();
        assert!(
            concerns[0].contains("Something Windows enables")
                && concerns[0].contains("Something changed it"),
            "the finding should lead: {concerns:?}"
        );
        assert!(
            concerns.iter().any(|c| c.contains("Merely available")),
            "the merely-available ones should still be named once: {concerns:?}"
        );
    }

    #[test]
    #[ignore = "reads this machine's real settings"]
    fn show_this_machine() {
        let report = survey();
        println!(
            "
--- switches ---"
        );
        for switch in &report.switches {
            println!(
                "  {:<32} {:<24} default {:?}{}",
                switch.name,
                switch.state.label(),
                switch.default,
                if switch.is_unexpectedly_off() {
                    "   <-- something turned this off"
                } else {
                    ""
                }
            );
        }
        println!(
            "
--- what it would say ---"
        );
        for concern in report.concerns() {
            println!("  {concern}");
        }
    }

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
            switches: Vec::new(),
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
            switches: Vec::new(),
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
