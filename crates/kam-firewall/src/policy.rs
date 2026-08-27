//! Reading and writing Windows Defender Firewall's rules, through its own COM
//! interface.
//!
//! `INetFwPolicy2` is the interface `wf.msc` and `netsh advfirewall` both use.
//! Nothing here reimplements filtering: the Windows Filtering Platform *is* the
//! network stack's filter layer, and a second one would be both impossible and
//! a bad idea. What is missing is a usable view of what the existing one has
//! been told to do.
//!
//! # Why this one runs in the agent
//!
//! Unlike the rule engine and the VirusTotal client, this genuinely needs
//! privilege: reading the policy needs administrative rights and changing it
//! certainly does. So it lives in the agent, where every change goes through
//! the audit log on its way.
//!
//! # On writing rules
//!
//! This is the first thing in the product that changes the machine rather than
//! describing it, and it is deliberately narrow. Rules created here are tagged
//! with a group of our own, so what this product added can always be told from
//! what Windows, an installer, or the user put there — and so removing them
//! never touches a rule that was not ours. Nothing else is modified, disabled,
//! or deleted; existing rules are read and shown, never edited.

use serde::{Deserialize, Serialize};
use windows::core::{Interface, BSTR};
use windows::Win32::Foundation::VARIANT_BOOL;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRules, NetFwPolicy2, NetFwRule, NET_FW_ACTION,
    NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK, NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE,
    NET_FW_PROFILE2_PUBLIC, NET_FW_PROFILE_TYPE2, NET_FW_RULE_DIRECTION, NET_FW_RULE_DIR_IN,
    NET_FW_RULE_DIR_OUT,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED,
};
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Variant::{VARIANT, VT_DISPATCH};

/// Every rule this product creates carries this group.
///
/// It is how "remove the block I added" stays honest: removal only ever
/// considers rules bearing this mark, so a rule Windows shipped or an installer
/// added cannot be deleted by us even by mistake.
pub const OUR_GROUP: &str = "KAM Security";

/// Prefix for the rules we create, so they read sensibly in `wf.msc` too —
/// someone looking at the Windows interface should be able to tell where a
/// rule came from without knowing this product exists.
///
/// Deliberately plain ASCII. An em-dash renders correctly in `wf.msc` and
/// PowerShell but turns to mojibake in `netsh advfirewall`, which still uses
/// the console codepage — and a security product whose rules look corrupted in
/// one of the two tools people inspect them with invites exactly the distrust
/// this is trying to avoid.
const RULE_PREFIX: &str = "KAM Security: block ";

/// COM apartment held for the life of a call.
///
/// Declared first in every function that uses it so it drops last: releasing
/// the apartment while an interface pointer is still alive is a use-after-free
/// in someone else's code.
struct ComGuard;

impl ComGuard {
    fn enter() -> kam_core::Result<Self> {
        // Deliberately not calling CoInitializeSecurity: this process may
        // already have set it, and a second call fails the whole apartment.
        let outcome = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        if outcome.is_err() && outcome != windows::Win32::Foundation::RPC_E_CHANGED_MODE {
            return Err(kam_core::Error::Refused(format!(
                "COM could not be started: {outcome:?}"
            )));
        }
        Ok(Self)
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

/// Which network a profile applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    /// A network joined to a company domain.
    Domain,
    /// Home or work: the machine is discoverable to others.
    Private,
    /// Cafés, airports, anything untrusted. Windows locks down hardest here.
    Public,
}

impl Profile {
    fn id(self) -> NET_FW_PROFILE_TYPE2 {
        match self {
            Self::Domain => NET_FW_PROFILE2_DOMAIN,
            Self::Private => NET_FW_PROFILE2_PRIVATE,
            Self::Public => NET_FW_PROFILE2_PUBLIC,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Domain => "Domain",
            Self::Private => "Private",
            Self::Public => "Public",
        }
    }

    pub fn all() -> [Self; 3] {
        [Self::Domain, Self::Private, Self::Public]
    }
}

/// What the firewall does with traffic nothing else matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Default {
    Allow,
    Block,
    /// Windows returned something outside the documented set.
    Unknown,
}

impl Default {
    fn from(action: NET_FW_ACTION) -> Self {
        match action {
            NET_FW_ACTION_ALLOW => Self::Allow,
            NET_FW_ACTION_BLOCK => Self::Block,
            _ => Self::Unknown,
        }
    }
}

/// One profile's state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileState {
    pub profile: Profile,
    pub enabled: bool,
    /// True when this is the profile in force on the current network.
    pub active: bool,
    pub inbound_default: Default,
    pub outbound_default: Default,
}

impl ProfileState {
    /// Concerns worth putting in front of someone, in plain words.
    ///
    /// Deliberately not a score. An inactive profile being off matters far less
    /// than the active one being off, and saying so is more use than a number.
    pub fn concerns(&self) -> Vec<String> {
        let mut concerns = Vec::new();
        let name = self.profile.label();

        if !self.enabled {
            concerns.push(if self.active {
                format!(
                    "The firewall is off for the {name} profile, which is the one \
                     in force on this network right now."
                )
            } else {
                format!("The firewall is off for the {name} profile.")
            });
        }

        if self.enabled && self.inbound_default == Default::Allow {
            concerns.push(format!(
                "The {name} profile allows unsolicited incoming connections by \
                 default, which is the opposite of how Windows ships."
            ));
        }

        concerns
    }
}

/// Which way traffic is going.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    In,
    Out,
    Unknown,
}

impl Direction {
    fn from(value: NET_FW_RULE_DIRECTION) -> Self {
        match value {
            NET_FW_RULE_DIR_IN => Self::In,
            NET_FW_RULE_DIR_OUT => Self::Out,
            _ => Self::Unknown,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::In => "incoming",
            Self::Out => "outgoing",
            Self::Unknown => "unspecified",
        }
    }
}

/// One firewall rule, as Windows holds it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub description: Option<String>,
    /// The program the rule applies to, when it names one.
    pub application: Option<String>,
    pub service: Option<String>,
    pub direction: Direction,
    pub action: Default,
    pub enabled: bool,
    /// Rules Windows groups together — "File and Printer Sharing" and the like.
    pub grouping: Option<String>,
    pub profiles: Vec<Profile>,
    /// IP protocol number: 6 is TCP, 17 is UDP, 256 means "any".
    pub protocol: Option<i32>,
    pub local_ports: Option<String>,
    pub remote_ports: Option<String>,
    pub remote_addresses: Option<String>,
    /// True when this product created it, so the interface can offer to remove
    /// it and can leave everything else alone.
    pub ours: bool,
}

impl Rule {
    /// The protocol in words, since the number means nothing to most readers.
    pub fn protocol_label(&self) -> &'static str {
        match self.protocol {
            Some(6) => "TCP",
            Some(17) => "UDP",
            Some(1) => "ICMP",
            Some(58) => "ICMPv6",
            Some(256) | None => "any protocol",
            _ => "other",
        }
    }
}

/// Everything read in one pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallReport {
    pub profiles: Vec<ProfileState>,
    pub rules: Vec<Rule>,
    /// Concerns across all profiles, phrased for a person.
    pub concerns: Vec<String>,
    pub total_rules: usize,
    pub enabled_rules: usize,
    /// How many of them block rather than allow.
    pub blocking_rules: usize,
    /// Rules this product added.
    pub our_rules: usize,
}

fn text(value: BSTR) -> Option<String> {
    let text = value.to_string();
    (!text.trim().is_empty()).then_some(text)
}

fn profiles_from_mask(mask: i32) -> Vec<Profile> {
    Profile::all()
        .into_iter()
        .filter(|profile| mask & profile.id().0 != 0 || mask == NET_FW_PROFILE_TYPE2(0x7FFF_FFFF).0)
        .collect()
}

fn open_policy() -> kam_core::Result<INetFwPolicy2> {
    unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }.map_err(|error| {
        kam_core::Error::Refused(format!(
            "the Windows Firewall service did not answer: {error}. It may be stopped, \
             or another security product may have taken it over."
        ))
    })
}

fn read_profiles(policy: &INetFwPolicy2) -> Vec<ProfileState> {
    let active_mask = unsafe { policy.CurrentProfileTypes() }.unwrap_or(0);

    Profile::all()
        .into_iter()
        .map(|profile| {
            let id = profile.id();
            ProfileState {
                profile,
                enabled: unsafe { policy.get_FirewallEnabled(id) }
                    .map(|enabled| enabled.as_bool())
                    .unwrap_or(false),
                active: active_mask & id.0 != 0,
                inbound_default: unsafe { policy.get_DefaultInboundAction(id) }
                    .map(Default::from)
                    .unwrap_or(Default::Unknown),
                outbound_default: unsafe { policy.get_DefaultOutboundAction(id) }
                    .map(Default::from)
                    .unwrap_or(Default::Unknown),
            }
        })
        .collect()
}

/// Read one rule out of its COM object.
///
/// Every property is fetched defensively. A rule left by uninstalled software
/// can have properties that fail to read, and one bad rule must not take the
/// whole list with it.
fn read_rule(rule: &INetFwRule) -> Option<Rule> {
    let raw = unsafe { rule.Name() }.ok().and_then(text)?;

    // Store applications register their rules under a resource pointer rather
    // than a name — 92 of the 671 rules on the development machine. Showing
    // those raw means a seventh of the list reads as corruption, so they are
    // resolved the same way service names are. A pointer that cannot be looked
    // up keeps its own text as the fallback, which is at least stable and
    // unique enough to identify the rule by.
    let name = kam_core::mui::resolve(&raw, &raw);
    let grouping = unsafe { rule.Grouping() }.ok().and_then(text);

    Some(Rule {
        ours: grouping.as_deref() == Some(OUR_GROUP),
        description: unsafe { rule.Description() }.ok().and_then(text),
        application: unsafe { rule.ApplicationName() }.ok().and_then(text),
        service: unsafe { rule.ServiceName() }.ok().and_then(text),
        direction: unsafe { rule.Direction() }
            .map(Direction::from)
            .unwrap_or(Direction::Unknown),
        action: unsafe { rule.Action() }.map(Default::from).unwrap_or(Default::Unknown),
        enabled: unsafe { rule.Enabled() }
            .map(|enabled| enabled.as_bool())
            .unwrap_or(false),
        profiles: profiles_from_mask(unsafe { rule.Profiles() }.unwrap_or(0)),
        protocol: unsafe { rule.Protocol() }.ok(),
        local_ports: unsafe { rule.LocalPorts() }.ok().and_then(text),
        remote_ports: unsafe { rule.RemotePorts() }.ok().and_then(text),
        remote_addresses: unsafe { rule.RemoteAddresses() }.ok().and_then(text),
        grouping,
        name,
    })
}

/// Walk the rule collection.
///
/// `INetFwRules` is an old-style COM collection, so this goes through
/// `IEnumVARIANT` rather than an index: the collection has no stable ordering
/// and `Item()` looks up by name, which is not unique.
fn read_rules(rules: &INetFwRules) -> kam_core::Result<Vec<Rule>> {
    let enumerator: IEnumVARIANT = unsafe { rules._NewEnum() }
        .and_then(|unknown| unknown.cast())
        .map_err(|error| {
            kam_core::Error::Refused(format!("the rule list could not be enumerated: {error}"))
        })?;

    let mut found = Vec::new();
    loop {
        // `Default` on VARIANT is a zeroed struct, which is VT_EMPTY and is
        // what the enumerator expects to overwrite.
        let mut batch: Vec<VARIANT> = (0..32).map(|_| VARIANT::default()).collect();
        let mut fetched = 0_u32;

        // Returns S_FALSE when fewer than asked for came back, which means the
        // last batch rather than a failure — so the count is what decides,
        // not the status.
        let outcome = unsafe { enumerator.Next(&mut batch, &mut fetched) };
        if fetched == 0 {
            break;
        }

        for item in batch.iter().take(fetched as usize) {
            if let Some(rule) = as_rule(item) {
                if let Some(read) = read_rule(&rule) {
                    found.push(read);
                }
            }
        }

        if outcome.is_err() {
            break;
        }
    }

    Ok(found)
}

/// Pull an `INetFwRule` out of the variant the enumerator handed back.
///
/// The collection yields `VT_DISPATCH`, so this checks the tag before touching
/// the union: reading `pdispVal` out of a variant holding something else would
/// interpret an integer as a pointer.
fn as_rule(variant: &VARIANT) -> Option<INetFwRule> {
    unsafe {
        let inner = &variant.Anonymous.Anonymous;
        if inner.vt != VT_DISPATCH {
            return None;
        }
        let dispatch = inner.Anonymous.pdispVal.as_ref()?;
        dispatch.cast::<INetFwRule>().ok()
    }
}

/// Read the firewall's state and every rule it holds.
pub fn survey() -> kam_core::Result<FirewallReport> {
    let _com = ComGuard::enter()?;
    let policy = open_policy()?;

    let profiles = read_profiles(&policy);
    let rules = unsafe { policy.Rules() }.map_err(|error| {
        kam_core::Error::Refused(format!("the firewall's rules could not be opened: {error}"))
    })?;
    let mut rules = read_rules(&rules)?;

    // Ours first so they are easy to find and remove, then blocking rules,
    // then alphabetically. A list of several hundred needs an order that puts
    // the actionable end on top.
    rules.sort_by(|a, b| {
        b.ours
            .cmp(&a.ours)
            .then_with(|| (b.action == Default::Block).cmp(&(a.action == Default::Block)))
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });

    let concerns = profiles.iter().flat_map(ProfileState::concerns).collect();

    Ok(FirewallReport {
        total_rules: rules.len(),
        enabled_rules: rules.iter().filter(|rule| rule.enabled).count(),
        blocking_rules: rules
            .iter()
            .filter(|rule| rule.enabled && rule.action == Default::Block)
            .count(),
        our_rules: rules.iter().filter(|rule| rule.ours).count(),
        profiles,
        rules,
        concerns,
    })
}

/// The name a block rule for `program` gets.
pub fn block_rule_name(program: &str) -> String {
    let leaf = program
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(program)
        .to_owned();
    format!("{RULE_PREFIX}{leaf}")
}

/// Stop a program reaching the network.
///
/// Creates one outbound block rule across all profiles, tagged with
/// [`OUR_GROUP`]. Outbound only and deliberately so: blocking a program's
/// incoming traffic rarely does what someone means, while stopping it phoning
/// out is exactly what "block this" is normally asking for.
///
/// Returns the rule name, which is the handle for undoing it.
pub fn block_program(path: &str) -> kam_core::Result<String> {
    if path.trim().is_empty() {
        return Err(kam_core::Error::Refused(
            "no program was given to block".to_owned(),
        ));
    }

    // The agent re-derives this rather than trusting the caller: a rule is
    // only meaningful if it names a file that exists, and a path that does not
    // resolve would create a rule that silently never matches anything.
    let program = std::path::Path::new(path);
    if !program.is_file() {
        return Err(kam_core::Error::Refused(format!(
            "{path} is not a program on this machine"
        )));
    }

    let _com = ComGuard::enter()?;
    let policy = open_policy()?;
    let rules = unsafe { policy.Rules() }
        .map_err(|error| kam_core::Error::Refused(format!("the rules could not be opened: {error}")))?;

    let name = block_rule_name(path);

    let rule: INetFwRule = unsafe { CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER) }
        .map_err(|error| {
            kam_core::Error::Refused(format!("a firewall rule could not be created: {error}"))
        })?;

    unsafe {
        rule.SetName(&BSTR::from(name.as_str())).ok();
        rule.SetDescription(&BSTR::from(
            format!("Added by KAM Security to stop {path} reaching the network.").as_str(),
        ))
        .ok();
        rule.SetApplicationName(&BSTR::from(path)).ok();
        rule.SetDirection(NET_FW_RULE_DIR_OUT).ok();
        rule.SetAction(NET_FW_ACTION_BLOCK).ok();
        rule.SetEnabled(VARIANT_BOOL::from(true)).ok();
        // Every profile: a block that stops applying when the laptop moves to
        // a different network is not what anyone means by "block".
        rule.SetProfiles(NET_FW_PROFILE_TYPE2(0x7FFF_FFFF).0).ok();
        // The mark that makes this removable by us and only by us.
        rule.SetGrouping(&BSTR::from(OUR_GROUP)).ok();
    }

    unsafe { rules.Add(&rule) }.map_err(|error| {
        kam_core::Error::Privileged(format!(
            "the rule could not be added: {error}. Changing firewall rules needs \
             administrative rights."
        ))
    })?;

    Ok(name)
}

/// Remove a rule this product created.
///
/// Refuses to touch anything else. The rule is looked up and its group checked
/// before removal, so a name collision with a Windows rule cannot lead to
/// deleting it — which is the failure this whole tagging scheme exists to
/// prevent.
pub fn remove_our_rule(name: &str) -> kam_core::Result<()> {
    let _com = ComGuard::enter()?;
    let policy = open_policy()?;
    let rules = unsafe { policy.Rules() }
        .map_err(|error| kam_core::Error::Refused(format!("the rules could not be opened: {error}")))?;

    let existing: INetFwRule = unsafe { rules.Item(&BSTR::from(name)) }.map_err(|_| {
        kam_core::Error::Refused(format!("there is no firewall rule called {name}"))
    })?;

    let grouping = unsafe { existing.Grouping() }.ok().and_then(text);
    if grouping.as_deref() != Some(OUR_GROUP) {
        return Err(kam_core::Error::Refused(format!(
            "{name} was not created by KAM Security, so it will not be removed here. \
             Use Windows Firewall to change rules this product did not add."
        )));
    }

    unsafe { rules.Remove(&BSTR::from(name)) }.map_err(|error| {
        kam_core::Error::Privileged(format!("the rule could not be removed: {error}"))
    })?;

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_rule_name_is_built_from_the_program() {
        assert_eq!(
            block_rule_name(r"C:\Program Files\Thing\thing.exe"),
            "KAM Security: block thing.exe"
        );
        assert_eq!(block_rule_name("thing.exe"), "KAM Security: block thing.exe");
    }

    #[test]
    fn our_rules_are_recognisably_ours() {
        // The whole safety story rests on this: a rule we did not create must
        // never look like one we did.
        assert!(block_rule_name("a.exe").starts_with(RULE_PREFIX));
        assert!(
            block_rule_name("a.exe").is_ascii(),
            "the rule name must survive the console codepage"
        );
        assert_eq!(OUR_GROUP, "KAM Security");
    }

    #[test]
    fn blocking_nothing_is_refused() {
        assert!(block_program("").is_err());
        assert!(block_program("   ").is_err());
    }

    #[test]
    fn blocking_a_path_that_is_not_a_program_is_refused() {
        // A rule naming a file that does not exist would sit in the list
        // looking effective and match nothing.
        assert!(block_program(r"C:\does\not\exist.exe").is_err());
    }

    #[test]
    fn removing_a_rule_we_did_not_create_is_refused() {
        // "Core Networking" ships with Windows. If this ever succeeds, the
        // guard is broken and this product can delete the operating system's
        // own firewall rules.
        let outcome = remove_our_rule("Core Networking - DNS (UDP-Out)");
        assert!(outcome.is_err(), "a Windows rule must never be removable here");
    }

    #[test]
    fn an_inactive_profile_being_off_reads_differently_from_an_active_one() {
        let inactive = ProfileState {
            profile: Profile::Public,
            enabled: false,
            active: false,
            inbound_default: Default::Block,
            outbound_default: Default::Allow,
        };
        let active = ProfileState {
            active: true,
            ..inactive.clone()
        };

        assert!(!inactive.concerns()[0].contains("in force"));
        assert!(active.concerns()[0].contains("in force on this network"));
    }

    #[test]
    fn a_healthy_profile_has_nothing_to_say() {
        let healthy = ProfileState {
            profile: Profile::Private,
            enabled: true,
            active: true,
            inbound_default: Default::Block,
            outbound_default: Default::Allow,
        };
        assert!(healthy.concerns().is_empty(), "{:?}", healthy.concerns());
    }

    #[test]
    fn allowing_inbound_by_default_is_worth_saying() {
        let permissive = ProfileState {
            profile: Profile::Public,
            enabled: true,
            active: true,
            inbound_default: Default::Allow,
            outbound_default: Default::Allow,
        };
        assert!(permissive.concerns()[0].contains("unsolicited incoming"));
    }

    #[test]
    fn protocol_numbers_read_as_names() {
        let rule = |protocol| Rule {
            name: "x".to_owned(),
            description: None,
            application: None,
            service: None,
            direction: Direction::Out,
            action: Default::Allow,
            enabled: true,
            grouping: None,
            profiles: Vec::new(),
            protocol,
            local_ports: None,
            remote_ports: None,
            remote_addresses: None,
            ours: false,
        };
        assert_eq!(rule(Some(6)).protocol_label(), "TCP");
        assert_eq!(rule(Some(17)).protocol_label(), "UDP");
        assert_eq!(rule(Some(256)).protocol_label(), "any protocol");
        assert_eq!(rule(None).protocol_label(), "any protocol");
    }

    /// The one test that exercises the code path which changes the machine.
    ///
    /// Ignored by default: it needs administrative rights and it really does
    /// write to the firewall. It targets `notepad.exe`, which has no network
    /// behaviour to disturb, and removes the rule again — so a completed run
    /// leaves the machine exactly as it found it.
    ///
    /// Everything else about blocking is tested through its refusals, and
    /// refusals do not prove the accepting path works. Shipping a button that
    /// changes someone's firewall without ever having watched it do so would
    /// not be defensible.
    ///
    /// Run with: cargo test -p kam-firewall -- --ignored
    #[test]
    #[ignore = "writes a real firewall rule; needs administrative rights"]
    fn a_block_can_be_created_and_taken_back() {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
        let target = format!(r"{root}\System32\notepad.exe");
        let expected = block_rule_name(&target);

        // Leave nothing behind from a previous interrupted run.
        let _ = remove_our_rule(&expected);

        let created = block_program(&target).expect("the rule should be created");
        assert_eq!(created, expected);

        let after = survey().expect("the firewall should be readable");
        let ours = after
            .rules
            .iter()
            .find(|rule| rule.name == expected)
            .expect("the new rule should be in the list");

        assert!(ours.ours, "the rule is not marked as ours");
        assert_eq!(ours.action, Default::Block);
        assert_eq!(ours.direction, Direction::Out, "blocks must be outbound only");
        assert!(ours.enabled, "a block that is not enabled blocks nothing");
        assert_eq!(ours.grouping.as_deref(), Some(OUR_GROUP));
        assert_eq!(
            ours.application.as_deref().map(str::to_lowercase),
            Some(target.to_lowercase())
        );
        println!("created and verified: {created}");

        remove_our_rule(&expected).expect("the rule should be removable");

        let restored = survey().expect("the firewall should still be readable");
        assert!(
            !restored.rules.iter().any(|rule| rule.name == expected),
            "the rule survived removal"
        );
        assert_eq!(
            restored.our_rules, 0,
            "the machine should be left exactly as it was found"
        );
        println!("removed cleanly; {} rules ours", restored.our_rules);
    }

    /// Diagnostic: dump every rule name so it can be diffed against
    /// `Get-NetFirewallRule`. Ignored by default.
    #[test]
    #[ignore = "diagnostic"]
    fn dump_rule_names() {
        let report = survey().unwrap();
        let mut out = String::new();
        for rule in &report.rules {
            out.push_str(&rule.name);
            out.push('\n');
        }
        let path = std::env::temp_dir().join("kam-rule-names.txt");
        std::fs::write(&path, out).unwrap();
        println!("wrote {} names to {}", report.rules.len(), path.display());
    }

    /// Create a real block rule, verify Windows holds it, then remove it.
    ///
    /// Ignored by default because it writes to the machine's firewall. It is
    /// the only way to test the one thing in this product that changes the
    /// system unprompted, and it cleans up after itself whether it passes or
    /// fails.
    ///
    /// Run with: cargo test -p kam-firewall -- --ignored --test-threads=1
    #[test]
    #[ignore = "creates a real firewall rule"]
    fn a_real_block_rule_is_created_and_removed() {
        // Something present on every Windows install, that nothing depends on
        // reaching the network. Blocking notepad outbound costs nothing even
        // if the cleanup somehow fails.
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
        let program = format!(r"{root}\System32\notepad.exe");
        let expected = block_rule_name(&program);

        // Leave nothing behind from an earlier failed run.
        let _ = remove_our_rule(&expected);

        let before = survey().expect("the firewall should be readable");
        let existed = before.rules.iter().any(|rule| rule.name == expected);
        assert!(!existed, "the rule was already there before the test");

        // --- create ------------------------------------------------------
        let created = block_program(&program).expect("the rule should be created");
        assert_eq!(created, expected);

        let after = survey().expect("the firewall should still be readable");
        let rule = after
            .rules
            .iter()
            .find(|rule| rule.name == expected)
            .expect("Windows does not have the rule that was just added");

        // Everything the interface promises about it.
        assert!(rule.ours, "the rule is not marked as ours");
        assert_eq!(rule.grouping.as_deref(), Some(OUR_GROUP));
        assert_eq!(rule.action, Default::Block);
        assert_eq!(rule.direction, Direction::Out, "should be outgoing only");
        assert!(rule.enabled, "a block that is not enabled blocks nothing");
        assert_eq!(
            rule.application.as_deref().map(str::to_lowercase),
            Some(program.to_lowercase()),
            "the rule names the wrong program"
        );
        assert_eq!(
            after.our_rules,
            before.our_rules + 1,
            "the count of our rules did not go up by exactly one"
        );
        assert_eq!(
            after.total_rules,
            before.total_rules + 1,
            "more than one rule appeared"
        );

        // --- remove ------------------------------------------------------
        remove_our_rule(&expected).expect("our own rule should be removable");

        let finally = survey().expect("the firewall should be readable");
        assert!(
            !finally.rules.iter().any(|rule| rule.name == expected),
            "the rule is still there after being removed"
        );
        assert_eq!(
            finally.total_rules, before.total_rules,
            "the machine was left with a different number of rules than it started with"
        );

        println!(
            "created and removed {expected}; {} rules before and after",
            before.total_rules
        );
    }

    #[test]
    fn this_machine_has_a_firewall_with_rules() {
        // Every Windows install ships hundreds of rules. Finding none means
        // the enumeration is broken, not that the machine is unusual.
        match survey() {
            Ok(report) => {
                println!(
                    "{} rules ({} enabled, {} blocking, {} ours)",
                    report.total_rules,
                    report.enabled_rules,
                    report.blocking_rules,
                    report.our_rules
                );
                for profile in &report.profiles {
                    println!(
                        "  {} enabled={} active={} in={:?} out={:?}",
                        profile.profile.label(),
                        profile.enabled,
                        profile.active,
                        profile.inbound_default,
                        profile.outbound_default
                    );
                }
                println!("concerns: {:?}", report.concerns);

                assert!(
                    report.total_rules > 20,
                    "only {} rules came back; enumeration is probably broken",
                    report.total_rules
                );
                assert!(
                    report.profiles.iter().any(|profile| profile.active),
                    "no profile is active, which cannot be true"
                );
            }
            Err(error) => panic!("could not read the firewall: {error}"),
        }
    }
}
