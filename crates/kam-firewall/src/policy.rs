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
    /// Whether the firewall is on for this profile. `None` when Windows would
    /// not say.
    ///
    /// It was a `bool` that read a failure as `false`, so a firewall whose
    /// state could not be read was reported as "off" -- a finding invented
    /// from a failed call, and the most alarming one this screen can make.
    pub enabled: Option<bool>,
    /// Whether this is the profile in force on the current network. `None`
    /// when Windows would not say which one is; that used to leave every
    /// profile reading as not in force.
    pub active: Option<bool>,
    pub inbound_default: Default,
    pub outbound_default: Default,
}

impl ProfileState {
    /// Concerns worth putting in front of someone, in plain words.
    ///
    /// Deliberately not a score. An inactive profile being off matters far less
    /// than the active one being off, and saying so is more use than a number.
    ///
    /// Only what was read. A state that could not be read is not a concern
    /// about the machine; it is a gap, and [`FirewallReport::unread`] says so.
    pub fn concerns(&self) -> Vec<String> {
        let mut concerns = Vec::new();
        let name = self.profile.label();

        if self.enabled == Some(false) {
            concerns.push(if self.active == Some(true) {
                format!(
                    "The firewall is off for the {name} profile, which is the one \
                     in force on this network right now."
                )
            } else {
                format!("The firewall is off for the {name} profile.")
            });
        }

        if self.enabled == Some(true) && self.inbound_default == Default::Allow {
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
    /// What could not be read, phrased for a person. When this is not empty
    /// the counts above are of what was read, not of everything there is.
    #[serde(default)]
    pub unread: Vec<String>,
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

/// Each profile's state, with every part that would not read named in
/// `unread` rather than filled in with a guess.
fn read_profiles(policy: &INetFwPolicy2, unread: &mut Vec<String>) -> Vec<ProfileState> {
    let active_mask = match unsafe { policy.CurrentProfileTypes() } {
        Ok(mask) => Some(mask),
        Err(error) => {
            unread.push(format!(
                "Which profile is in force on this network could not be read: {error}"
            ));
            None
        }
    };

    let mut profiles = Vec::new();
    for profile in Profile::all() {
        let id = profile.id();
        let name = profile.label();
        let enabled = match unsafe { policy.get_FirewallEnabled(id) } {
            Ok(enabled) => Some(enabled.as_bool()),
            Err(error) => {
                unread.push(format!(
                    "Whether the firewall is on for the {name} profile could not be read: {error}"
                ));
                None
            }
        };
        let inbound_default = match unsafe { policy.get_DefaultInboundAction(id) } {
            Ok(action) => Default::from(action),
            Err(error) => {
                unread.push(format!(
                    "What the {name} profile does with incoming connections by default \
                     could not be read: {error}"
                ));
                Default::Unknown
            }
        };
        let outbound_default = match unsafe { policy.get_DefaultOutboundAction(id) } {
            Ok(action) => Default::from(action),
            Err(error) => {
                unread.push(format!(
                    "What the {name} profile does with outgoing connections by default \
                     could not be read: {error}"
                ));
                Default::Unknown
            }
        };
        profiles.push(ProfileState {
            profile,
            enabled,
            active: active_mask.map(|mask| mask & id.0 != 0),
            inbound_default,
            outbound_default,
        });
    }
    profiles
}

/// Read one rule out of its COM object.
///
/// Every property is fetched defensively. A rule left by uninstalled software
/// can have properties that fail to read, and one bad rule must not take the
/// whole list with it. `None` only when even its name would not read, and the
/// caller counts that rather than dropping it in silence.
fn read_rule(rule: &INetFwRule) -> Option<Rule> {
    // An empty name is still a rule. It used to be dropped as though it were
    // not there, and left out of every count.
    let raw = unsafe { rule.Name() }.ok()?.to_string();

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
        action: unsafe { rule.Action() }
            .map(Default::from)
            .unwrap_or(Default::Unknown),
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

/// Walk the rule collection, handing every entry to `visit`.
///
/// `INetFwRules` is an old-style COM collection, so this goes through
/// `IEnumVARIANT` rather than an index: the collection has no stable ordering
/// and `Item()` looks up by name, which is not unique.
///
/// An entry that is not a rule object reaches `visit` as `None`, to be counted
/// rather than skipped. The answer is what stopped the walk before the end,
/// when something did: an error from the enumerator used to end the loop and
/// return as though the list had been read, so a list cut short was shown as
/// complete.
fn walk_rules(
    rules: &INetFwRules,
    mut visit: impl FnMut(Option<INetFwRule>),
) -> kam_core::Result<Option<String>> {
    let enumerator: IEnumVARIANT = unsafe { rules._NewEnum() }
        .and_then(|unknown| unknown.cast())
        .map_err(|error| {
            kam_core::Error::Refused(format!("the rule list could not be enumerated: {error}"))
        })?;

    loop {
        // `Default` on VARIANT is a zeroed struct, which is VT_EMPTY and is
        // what the enumerator expects to overwrite.
        let mut batch: Vec<VARIANT> = (0..32).map(|_| VARIANT::default()).collect();
        let mut fetched = 0_u32;

        // Returns S_FALSE when fewer than asked for came back, which means the
        // last batch rather than a failure. A real failure is an error status,
        // and is said whatever the count.
        let outcome = unsafe { enumerator.Next(&mut batch, &mut fetched) };
        for item in batch.iter().take(fetched as usize) {
            visit(as_rule(item));
        }
        if outcome.is_err() {
            return Ok(Some(windows::core::Error::from(outcome).to_string()));
        }
        if fetched == 0 {
            return Ok(None);
        }
    }
}

/// Every rule that could be read, with what could not be named in `unread`.
fn read_rules(rules: &INetFwRules, unread: &mut Vec<String>) -> kam_core::Result<Vec<Rule>> {
    let mut found = Vec::new();
    let mut unreadable = 0_usize;
    let stopped = walk_rules(rules, |item| match item.as_ref().and_then(read_rule) {
        Some(rule) => found.push(rule),
        None => unreadable += 1,
    })?;

    if unreadable > 0 {
        unread.push(if unreadable == 1 {
            "1 rule could not be read, so it is not listed or counted".to_owned()
        } else {
            format!("{unreadable} rules could not be read, so they are not listed or counted")
        });
    }
    if let Some(why) = stopped {
        unread.push(format!(
            "The list of rules could not be read to the end ({why}), so there may be \
             rules that are not listed or counted"
        ));
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

    let mut unread = Vec::new();
    let profiles = read_profiles(&policy, &mut unread);
    let rules = unsafe { policy.Rules() }.map_err(|error| {
        kam_core::Error::Refused(format!("the firewall's rules could not be opened: {error}"))
    })?;
    let mut rules = read_rules(&rules, &mut unread)?;

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
        unread,
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
    let rules = unsafe { policy.Rules() }.map_err(|error| {
        kam_core::Error::Refused(format!("the rules could not be opened: {error}"))
    })?;

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
/// Refuses to touch anything else. Every rule is read and the ones bearing
/// this name are counted before anything is removed, so a name collision with
/// a Windows rule cannot lead to deleting it — which is the failure this whole
/// tagging scheme exists to prevent.
///
/// # Why counting, and not looking the name up
///
/// This used to ask `Item(name)` for the rule, check that one's group, and
/// then call `Remove(name)`. Names are not unique -- on the development
/// machine 462 of 708 rules share a name with another -- so the rule whose
/// group was checked and the rule `Remove` acts on need not be the same one.
/// The rules this product makes are named after the program's file name
/// alone, so two blocked `setup.exe` from different folders already collide
/// with each other. Removal now goes ahead only when exactly one rule has the
/// name and it carries this product's group; anything else is refused and
/// says why.
pub fn remove_our_rule(name: &str) -> kam_core::Result<()> {
    let _com = ComGuard::enter()?;
    let policy = open_policy()?;
    let rules = unsafe { policy.Rules() }.map_err(|error| {
        kam_core::Error::Refused(format!("the rules could not be opened: {error}"))
    })?;

    // The group of every rule with this name, compared without regard to case
    // so that nothing `Remove` might match is left uncounted.
    let wanted = name.to_lowercase();
    let mut groups: Vec<Option<String>> = Vec::new();
    let mut unreadable = 0_usize;
    let stopped = walk_rules(&rules, |item| {
        let Some(rule) = item else {
            unreadable += 1;
            return;
        };
        match unsafe { rule.Name() } {
            Ok(raw) if raw.to_string().to_lowercase() == wanted => {
                groups.push(unsafe { rule.Grouping() }.ok().and_then(text));
            }
            Ok(_) => {}
            Err(_) => unreadable += 1,
        }
    })?;
    if stopped.is_some() || unreadable > 0 {
        return Err(kam_core::Error::Refused(format!(
            "Not every firewall rule could be read, so whether {name} is the only rule \
             with that name is not known. Nothing was removed. Use Windows Firewall to \
             remove it."
        )));
    }

    may_remove(name, &groups)?;

    unsafe { rules.Remove(&BSTR::from(name)) }.map_err(|error| {
        kam_core::Error::Privileged(format!("the rule could not be removed: {error}"))
    })?;

    Ok(())
}

/// Whether the rules called `name`, described by their groups, may be removed
/// by name.
fn may_remove(name: &str, groups: &[Option<String>]) -> kam_core::Result<()> {
    match groups {
        [] => Err(kam_core::Error::Refused(format!(
            "there is no firewall rule called {name}"
        ))),
        [only] if only.as_deref() == Some(OUR_GROUP) => Ok(()),
        [_] => Err(kam_core::Error::Refused(format!(
            "{name} was not created by KAM Security, so it will not be removed here. \
             Use Windows Firewall to change rules this product did not add."
        ))),
        several => Err(kam_core::Error::Refused(format!(
            "{} firewall rules are called {name}. Windows removes rules by name, so \
             removing it here could remove a rule other than the one you mean, and \
             nothing was removed. Use Windows Firewall, which lists each of them \
             separately, to remove the one you mean.",
            several.len()
        ))),
    }
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
        assert_eq!(
            block_rule_name("thing.exe"),
            "KAM Security: block thing.exe"
        );
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
        assert!(
            outcome.is_err(),
            "a Windows rule must never be removable here"
        );
    }

    #[test]
    fn an_inactive_profile_being_off_reads_differently_from_an_active_one() {
        let inactive = ProfileState {
            profile: Profile::Public,
            enabled: Some(false),
            active: Some(false),
            inbound_default: Default::Block,
            outbound_default: Default::Allow,
        };
        let active = ProfileState {
            active: Some(true),
            ..inactive.clone()
        };

        assert!(!inactive.concerns()[0].contains("in force"));
        assert!(active.concerns()[0].contains("in force on this network"));
    }

    #[test]
    fn a_healthy_profile_has_nothing_to_say() {
        let healthy = ProfileState {
            profile: Profile::Private,
            enabled: Some(true),
            active: Some(true),
            inbound_default: Default::Block,
            outbound_default: Default::Allow,
        };
        assert!(healthy.concerns().is_empty(), "{:?}", healthy.concerns());
    }

    #[test]
    fn allowing_inbound_by_default_is_worth_saying() {
        let permissive = ProfileState {
            profile: Profile::Public,
            enabled: Some(true),
            active: Some(true),
            inbound_default: Default::Allow,
            outbound_default: Default::Allow,
        };
        assert!(permissive.concerns()[0].contains("unsolicited incoming"));
    }

    /// A firewall whose state could not be read is not reported as off.
    ///
    /// `enabled` read a failed call as `false`, so the screen said "the
    /// firewall is off for the Public profile, which is the one in force"
    /// about a profile nobody had been able to read. Unknown is unknown.
    #[test]
    fn a_profile_that_could_not_be_read_is_not_called_off() {
        let unread = ProfileState {
            profile: Profile::Public,
            enabled: None,
            active: None,
            inbound_default: Default::Unknown,
            outbound_default: Default::Unknown,
        };
        assert!(
            unread
                .concerns()
                .iter()
                .all(|concern| !concern.contains("off")),
            "an unread profile was called off: {:?}",
            unread.concerns()
        );
    }

    /// Removal by name goes ahead only when the name picks out exactly one
    /// rule, and that rule is ours.
    ///
    /// `Remove` acts on a name, and names are not unique: the group that was
    /// checked used to belong to whichever rule `Item` returned, which need
    /// not be the rule `Remove` then deleted. Two blocks of two `setup.exe`
    /// from different folders share a name already.
    #[test]
    fn removal_needs_exactly_one_rule_of_ours_with_that_name() {
        let ours = || Some(OUR_GROUP.to_owned());
        let theirs = || Some("Core Networking".to_owned());
        let name = "KAM Security: block setup.exe";

        assert!(may_remove(name, &[ours()]).is_ok());

        let refused = |groups: &[Option<String>]| match may_remove(name, groups) {
            Err(kam_core::Error::Refused(message)) => message,
            other => panic!("{groups:?} was not refused: {other:?}"),
        };
        assert!(refused(&[]).contains("no firewall rule"));
        assert!(refused(&[theirs()]).contains("not created by KAM Security"));
        assert!(refused(&[None]).contains("not created by KAM Security"));
        // Ours and somebody else's under one name: the case that deleted the
        // wrong one.
        assert!(refused(&[ours(), theirs()]).contains("2 firewall rules"));
        // Two of ours under one name are refused too: which of them goes is
        // Windows' choice, not the person's.
        assert!(refused(&[ours(), ours()]).contains("2 firewall rules"));
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
        assert_eq!(
            ours.direction,
            Direction::Out,
            "blocks must be outbound only"
        );
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
    /// Run for the first time on 28 August 2026, through the agent, against a
    /// machine holding 675 rules: the rule was created, found again by name,
    /// removed, and the count came back to 675 with nothing left behind. The
    /// removal fence was exercised in the same pass and refused Windows' own
    /// DNS rule, which is the half that matters more -- see
    /// `removing_a_rule_we_did_not_create_is_refused`.
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
                        "  {} enabled={:?} active={:?} in={:?} out={:?}",
                        profile.profile.label(),
                        profile.enabled,
                        profile.active,
                        profile.inbound_default,
                        profile.outbound_default
                    );
                }
                println!("concerns: {:?}", report.concerns);
                println!("not read: {:?}", report.unread);

                assert!(
                    report.total_rules > 20,
                    "only {} rules came back; enumeration is probably broken",
                    report.total_rules
                );
                assert!(
                    report
                        .profiles
                        .iter()
                        .any(|profile| profile.active == Some(true)),
                    "no profile is active, which cannot be true"
                );
            }
            Err(error) => panic!("could not read the firewall: {error}"),
        }
    }
}
