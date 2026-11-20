//! Where this PC's traffic is sent: the hosts file, DNS servers set by hand,
//! and proxies.
//!
//! # Why these three
//!
//! Three small settings decide where a browser's traffic goes before any
//! website sees it. A line in the hosts file sends one name to a fixed
//! address, a DNS server set by hand answers for every name, and a proxy
//! carries every request. Changing one is an old move for adware and banking
//! malware, and an account's own proxy needs no administrator to change.
//!
//! Each is just as often set on purpose: an ad blocker's hosts file, a VPN's
//! DNS server, a developer's local proxy, a game pointing one of its addresses
//! at a machine on the home network. So what is read is said as a fact, with
//! where it was read from and, where there is one, a date. Nothing here says
//! whether it should be set.
//!
//! # What is left out on purpose
//!
//! The DNS servers a network hands out (`DhcpNameServer`) are not read. They
//! change with every network joined, so on a laptop they would read as changed
//! every time it moved. A server set by hand stays set, and only that says
//! something about this machine rather than about the network it is on.

use std::path::{Path, PathBuf};

use kam_core::changes::Unreadable;
use kam_core::registry::{Key, Unopened, View};
use kam_core::UserContext;
use serde::{Deserialize, Serialize};
use windows::Win32::System::Registry::{HKEY, HKEY_LOCAL_MACHINE};

/// The token a hosts file entry is filed under in What changed.
///
/// Stored, so never renamed: see [`crate::persistence::Anchor::kind`].
pub const HOSTS_ENTRY: &str = "hosts_entry";

/// The token an adapter's hand-set DNS servers are filed under.
pub const DNS_SERVERS: &str = "dns_servers";

/// The token a proxy is filed under, an account's or Windows' own.
pub const PROXY: &str = "proxy";

/// Where Windows keeps its TCP/IP settings, including where the hosts file is.
const TCPIP: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";
const TCPIP6: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters";

/// Where the names Windows shows for network adapters are kept, by adapter id.
const ADAPTER_NAMES: &str =
    r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}";

/// The key, in each account's own hive, that holds its proxy.
///
/// Microsoft's group policy specification places `ProxyEnable`, `ProxyServer`,
/// `ProxyOverride` and `AutoConfigURL` here.
const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

/// Where Windows' own proxy is kept, the one services and Windows Update use
/// (WinHTTP). Read through WinHTTP rather than from the value itself, whose
/// layout Microsoft does not document.
pub const WINHTTP_LOCATION: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections";

/// Everything read, and what could not be.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    /// The hosts file, when it could be read. When it could not, that is
    /// among `unreadable`, never an empty file.
    pub hosts: Option<Hosts>,
    /// Each network adapter that has DNS servers set by hand, one for each of
    /// IPv4 and IPv6 it sets them for.
    pub dns: Vec<HandSet>,
    /// How many adapters' settings were read, so that "none set by hand" can
    /// be told from "none read".
    pub adapters_read: usize,
    /// The asking account's own proxy, and Windows' own. One that could not
    /// be read is among `unreadable` instead.
    pub proxies: Vec<Proxy>,
    /// What could not be read, with the kinds and places it rules nothing out
    /// about, so What changed can hold to the same gaps.
    pub unreadable: Vec<Unreadable>,
}

/// The hosts file, as read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hosts {
    /// The file that was read, found where Windows' own settings say.
    pub path: String,
    /// Every name the file sends somewhere, in the order the file first names
    /// it.
    pub entries: Vec<HostsEntry>,
    /// When the file was last written, in the store's ISO form, when that
    /// could be read.
    pub changed: Option<String>,
}

/// One name the hosts file sends to a fixed address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostsEntry {
    /// As the file first spells it.
    pub name: String,
    /// Every address the file gives it, as written, in the file's order. A
    /// name given an IPv4 and an IPv6 address has both.
    pub addresses: Vec<String>,
}

/// Which version of IP a DNS setting is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    Ipv4,
    Ipv6,
}

impl Family {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
        }
    }
}

/// DNS servers set by hand on one network adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandSet {
    /// The adapter's name as Windows shows it, such as `Wi-Fi`, or its id when
    /// it has none.
    pub adapter: String,
    /// The adapter's id, which stays the same when it is renamed.
    pub interface: String,
    pub family: Family,
    /// The key the servers were read from, so they can be found by hand.
    pub location: String,
    /// In the order Windows asks them.
    pub servers: Vec<String>,
}

/// One proxy setting: an account's own, or Windows' own.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proxy {
    /// The profile folder of the account this belongs to, or `None` for
    /// Windows' own (WinHTTP), which services and Windows Update use.
    pub account: Option<String>,
    /// Where it was read from, so it can be found by hand.
    pub location: String,
    /// The proxy every request is sent through, when one is set and switched
    /// on.
    pub server: Option<String>,
    /// The addresses it is not used for, as written, when a server is set.
    pub bypass: Option<String>,
    /// The address of an automatic configuration script, which decides
    /// request by request, when one is set.
    pub script: Option<String>,
}

impl Proxy {
    /// Whether this sends anything anywhere other than straight out.
    pub fn is_set(&self) -> bool {
        self.server.is_some() || self.script.is_some()
    }
}

/// Everything this reads, for the person asking: the machine's settings, and
/// their own account's proxy.
pub fn survey(user: &UserContext) -> Report {
    let mut unreadable = Vec::new();
    let hosts = hosts(&mut unreadable);
    let (dns, adapters_read) = hand_set_dns(&mut unreadable);
    let mut proxies = Vec::new();
    if let Some(own) = proxy_of(user, &mut unreadable) {
        proxies.push(own);
    }
    if let Some(windows) = windows_proxy(&mut unreadable) {
        proxies.push(windows);
    }
    Report {
        hosts,
        dns,
        adapters_read,
        proxies,
        unreadable,
    }
}

/// The hosts file, from the folder Windows' own settings name.
///
/// Read from where Windows looks, not from where it usually is: the folder is
/// a setting (`DataBasePath`), and a hosts file written somewhere else and
/// pointed at would be the one in use.
pub fn hosts(unreadable: &mut Vec<Unreadable>) -> Option<Hosts> {
    let parameters = Key::look(HKEY_LOCAL_MACHINE, TCPIP, View::Native);
    let folder = database_folder(parameters, &format!(r"HKLM\{TCPIP}"), unreadable)?;
    hosts_in(&folder, unreadable)
}

/// The folder a `DataBasePath` value names, with its variables filled in.
///
/// `None`, and a gap covering every hosts entry, when it could not be read:
/// with no file named, nothing is known about any of them.
fn database_folder(
    parameters: Result<Key, Unopened>,
    shown: &str,
    unreadable: &mut Vec<Unreadable>,
) -> Option<PathBuf> {
    let read = parameters.and_then(|key| key.read_string("DataBasePath"));
    match read {
        Ok(Some(folder)) => Some(PathBuf::from(kam_core::env::expand(&folder))),
        Ok(None) => {
            unreadable.push(Unreadable::of(
                HOSTS_ENTRY,
                format!(
                    "Windows' own settings ({shown}) do not say where the hosts file is, so it \
                     was not read"
                ),
            ));
            None
        }
        Err(why) => {
            unreadable.push(Unreadable::of(
                HOSTS_ENTRY,
                format!(
                    "{}, so where the hosts file is could not be told and it was not read",
                    why.describe(&format!("Where the hosts file is ({shown})"))
                ),
            ));
            None
        }
    }
}

/// The hosts file in one folder.
///
/// A file that is not there is an empty file to Windows, and is said as one.
/// One that is there and would not read is a gap, never an empty file: some
/// security products lock it.
pub fn hosts_in(folder: &Path, unreadable: &mut Vec<Unreadable>) -> Option<Hosts> {
    let path = folder.join("hosts");
    let shown = path.display().to_string();
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Some(Hosts {
                path: shown,
                entries: Vec::new(),
                changed: None,
            });
        }
        Err(error) => {
            unreadable.push(Unreadable::within(
                HOSTS_ENTRY,
                &shown,
                format!("The hosts file at {shown} could not be read ({error})"),
            ));
            return None;
        }
    };
    let changed = std::fs::metadata(&path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|when| when.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|since| kam_core::clock::iso_from_unix_millis(since.as_millis() as u64));
    Some(Hosts {
        path: shown,
        entries: parse_hosts(&text_of(&bytes)),
        changed,
    })
}

/// A file's text, whichever of the encodings Notepad saves in it is.
fn text_of(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let units: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    String::from_utf8_lossy(bytes).into_owned()
}

/// Every name a hosts file sends to a fixed address.
///
/// One entry per line: an address, then one or more names, and anything from
/// a `#` on is a comment. A line with an address and no name sends nothing
/// anywhere and is not an entry. Each name is kept once, with every address
/// the file gives it, because a name is what a person looks up.
pub fn parse_hosts(text: &str) -> Vec<HostsEntry> {
    let mut entries: Vec<HostsEntry> = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default();
        let mut tokens = line.split_whitespace();
        let Some(address) = tokens.next() else {
            continue;
        };
        for name in tokens {
            match entries
                .iter_mut()
                .find(|entry| entry.name.eq_ignore_ascii_case(name))
            {
                Some(entry) => {
                    if !entry.addresses.iter().any(|known| known == address) {
                        entry.addresses.push(address.to_owned());
                    }
                }
                None => entries.push(HostsEntry {
                    name: name.to_owned(),
                    addresses: vec![address.to_owned()],
                }),
            }
        }
    }
    entries
}

/// Every adapter's DNS servers set by hand, for IPv4 and IPv6, and how many
/// adapters were read.
pub fn hand_set_dns(unreadable: &mut Vec<Unreadable>) -> (Vec<HandSet>, usize) {
    let v4 = format!(r"{TCPIP}\Interfaces");
    let v6 = format!(r"{TCPIP6}\Interfaces");
    hand_set_dns_in(
        HKEY_LOCAL_MACHINE,
        &[
            (v4.as_str(), format!(r"HKLM\{v4}"), Family::Ipv4),
            (v6.as_str(), format!(r"HKLM\{v6}"), Family::Ipv6),
        ],
        ADAPTER_NAMES,
        unreadable,
    )
}

/// The same, from the keys named, so a test can name its own.
///
/// Each place is the `Interfaces` key to walk, how it is shown, and which
/// version of IP it holds. `names` is the key whose subkeys give each adapter
/// the name Windows shows for it.
fn hand_set_dns_in(
    root: HKEY,
    places: &[(&str, String, Family)],
    names: &str,
    unreadable: &mut Vec<Unreadable>,
) -> (Vec<HandSet>, usize) {
    let mut found = Vec::new();
    let mut adapters = std::collections::BTreeSet::new();
    for (path, shown, family) in places {
        let interfaces = match Key::look(root, path, View::Native) {
            Ok(key) => key,
            Err(why) => {
                unreadable.push(Unreadable::within(
                    DNS_SERVERS,
                    shown,
                    format!(
                        "{}, so which adapters have {} DNS servers set by hand is not known",
                        why.describe(shown),
                        family.label()
                    ),
                ));
                continue;
            }
        };
        let listing = interfaces.subkeys();
        if !listing.whole {
            unreadable.push(Unreadable::within(
                DNS_SERVERS,
                shown,
                format!("{shown} could not be read to the end, so it may hold adapters not shown"),
            ));
        }
        for interface in listing.names {
            let place = format!(r"{shown}\{interface}");
            let servers = interfaces
                .look_child(&interface)
                .and_then(|key| key.read_string("NameServer"));
            let servers = match servers {
                Ok(servers) => servers,
                Err(why) => {
                    unreadable.push(Unreadable::within(
                        DNS_SERVERS,
                        &place,
                        format!(
                            "{}, so whether that adapter has DNS servers set by hand is not known",
                            why.describe(&place)
                        ),
                    ));
                    continue;
                }
            };
            adapters.insert(interface.to_lowercase());
            let servers: Vec<String> = servers
                .unwrap_or_default()
                .split([',', ' ', ';'])
                .map(str::trim)
                .filter(|server| !server.is_empty())
                .map(str::to_owned)
                .collect();
            if servers.is_empty() {
                continue;
            }
            found.push(HandSet {
                adapter: adapter_name(root, names, &interface).unwrap_or_else(|| interface.clone()),
                interface,
                family: *family,
                location: place,
                servers,
            });
        }
    }
    (found, adapters.len())
}

/// The name Windows shows for an adapter, such as `Wi-Fi`.
fn adapter_name(root: HKEY, names: &str, interface: &str) -> Option<String> {
    Key::open(
        root,
        &format!(r"{names}\{interface}\Connection"),
        View::Native,
    )?
    .string("Name")
}

/// One account's own proxy, read from its own hive.
///
/// `None` when it could not be read, which is then among `unreadable`, and
/// when the account's hive is not there once read: an account that signed out
/// while being read would otherwise look as though it had switched its proxy
/// off.
pub fn proxy_of(user: &UserContext, unreadable: &mut Vec<Unreadable>) -> Option<Proxy> {
    let (hive, prefix) = user.hive();
    let shown = match user.sid() {
        Some(sid) => format!(r"HKEY_USERS\{sid}\{INTERNET_SETTINGS}"),
        None => format!(r"HKCU\{INTERNET_SETTINGS}"),
    };
    let proxy = proxy_in(
        hive,
        &format!("{prefix}{INTERNET_SETTINGS}"),
        &shown,
        Some(user.profile().to_owned()),
        unreadable,
    );
    if crate::persistence::hive_gone(user) {
        return None;
    }
    proxy
}

/// The proxy one key holds.
///
/// A key that is not there holds none, which is how an account that has never
/// opened its proxy settings looks. One that is there and would not read is a
/// gap.
fn proxy_in(
    root: HKEY,
    path: &str,
    shown: &str,
    account: Option<String>,
    unreadable: &mut Vec<Unreadable>,
) -> Option<Proxy> {
    let mut proxy = Proxy {
        account,
        location: shown.to_owned(),
        ..Proxy::default()
    };
    let key = match Key::look(root, path, View::Native) {
        Ok(key) => key,
        Err(Unopened::Absent) => return Some(proxy),
        Err(why) => {
            unreadable.push(Unreadable::within(
                PROXY,
                shown,
                format!("{}, so its proxy is not known", why.describe(shown)),
            ));
            return None;
        }
    };
    let read = (|| -> Result<(), Unopened> {
        let enabled = key.read_dword("ProxyEnable")?.unwrap_or(0) != 0;
        if enabled {
            proxy.server = key.read_string("ProxyServer")?;
            if proxy.server.is_some() {
                proxy.bypass = key.read_string("ProxyOverride")?;
            }
        }
        proxy.script = key.read_string("AutoConfigURL")?;
        Ok(())
    })();
    match read {
        Ok(()) => Some(proxy),
        Err(why) => {
            unreadable.push(Unreadable::within(
                PROXY,
                shown,
                format!("{}, so its proxy is not known", why.describe(shown)),
            ));
            None
        }
    }
}

/// What WinHTTP says Windows' own proxy is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WinHttpAnswer {
    /// Straight out, through no proxy.
    Direct,
    /// Through a proxy, with what it is not used for when that is set.
    Named {
        server: String,
        bypass: Option<String>,
    },
    /// An answer this does not know how to read, kept by its number.
    Other(u32),
}

/// Windows' own proxy, as WinHTTP reports it.
pub fn windows_proxy(unreadable: &mut Vec<Unreadable>) -> Option<Proxy> {
    windows_proxy_from(ask_winhttp(), unreadable)
}

/// Windows' own proxy from what WinHTTP answered, so a test can supply the
/// answer.
fn windows_proxy_from(
    answer: Result<WinHttpAnswer, String>,
    unreadable: &mut Vec<Unreadable>,
) -> Option<Proxy> {
    let mut proxy = Proxy {
        account: None,
        location: WINHTTP_LOCATION.to_owned(),
        ..Proxy::default()
    };
    match answer {
        Ok(WinHttpAnswer::Direct) => Some(proxy),
        Ok(WinHttpAnswer::Named { server, bypass }) => {
            proxy.server = Some(server);
            proxy.bypass = bypass;
            Some(proxy)
        }
        Ok(WinHttpAnswer::Other(kind)) => {
            unreadable.push(Unreadable::within(
                PROXY,
                WINHTTP_LOCATION,
                format!(
                    "WinHTTP described Windows' own proxy in a way this does not read (access \
                     type {kind}), so it is not known"
                ),
            ));
            None
        }
        Err(why) => {
            unreadable.push(Unreadable::within(
                PROXY,
                WINHTTP_LOCATION,
                format!("Windows' own proxy could not be read from WinHTTP ({why})"),
            ));
            None
        }
    }
}

/// Ask WinHTTP for the proxy it uses by default.
///
/// It reads the machine-wide setting, the same for whoever asks, so the
/// service asking for it is not the wrong person.
fn ask_winhttp() -> Result<WinHttpAnswer, String> {
    use windows::Win32::Foundation::{GlobalFree, HGLOBAL};
    use windows::Win32::Networking::WinHttp::{
        WinHttpGetDefaultProxyConfiguration, WINHTTP_ACCESS_TYPE_NAMED_PROXY,
        WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_PROXY_INFO,
    };

    let mut info = WINHTTP_PROXY_INFO::default();
    unsafe { WinHttpGetDefaultProxyConfiguration(&mut info) }.map_err(|error| error.to_string())?;
    // Both strings are WinHTTP's, allocated for this call, and freed here
    // whatever the answer was.
    let take = |text: windows::core::PWSTR| -> Option<String> {
        if text.is_null() {
            return None;
        }
        let read = unsafe { text.to_string() }.ok();
        unsafe {
            let _ = GlobalFree(Some(HGLOBAL(text.0.cast())));
        }
        read.map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty())
    };
    let server = take(info.lpszProxy);
    let bypass = take(info.lpszProxyBypass);
    Ok(match (info.dwAccessType, server) {
        (WINHTTP_ACCESS_TYPE_NAMED_PROXY, Some(server)) => WinHttpAnswer::Named { server, bypass },
        (WINHTTP_ACCESS_TYPE_NAMED_PROXY, None) | (WINHTTP_ACCESS_TYPE_NO_PROXY, _) => {
            WinHttpAnswer::Direct
        }
        (other, _) => WinHttpAnswer::Other(other.0),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::scratch::ScratchKey;
    use windows::Win32::System::Registry::HKEY_CURRENT_USER;

    /// A folder in the temporary directory, removed when dropped. `name` is
    /// its own name, inside the folder `%TEMP%` names.
    struct ScratchFolder(PathBuf, String);

    impl ScratchFolder {
        fn new(tag: &str) -> Self {
            let name = format!(
                "kam-traffic-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|since| since.as_nanos())
                    .unwrap_or(0)
            );
            let folder = PathBuf::from(kam_core::env::expand("%TEMP%")).join(&name);
            std::fs::create_dir_all(&folder).unwrap();
            Self(folder, name)
        }
    }

    impl Drop for ScratchFolder {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The hosts file on the development machine, as the review read it on
    /// 12 November 2026: Microsoft's own comments, the two localhost lines it
    /// leaves commented out, and one live entry.
    const THIS_PC: &str = "# Copyright (c) 1993-2009 Microsoft Corp.\r\n\
        #\r\n\
        # This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n\
        #\r\n\
        # For example:\r\n\
        #\r\n\
        #      102.54.94.97     rhino.acme.com          # source server\r\n\
        #       38.25.63.10     x.acme.com              # x client host\r\n\
        \r\n\
        # localhost name resolution is handled within DNS itself.\r\n\
        #\t127.0.0.1       localhost\r\n\
        #\t::1             localhost\r\n\
        192.168.1.155 onlineconfigservice.ubi.com\r\n";

    /// The entry the owner's PC has is the one entry read, and Microsoft's
    /// examples, which are comments, are not entries.
    #[test]
    fn the_hosts_file_on_this_pc_holds_one_entry() {
        let entries = parse_hosts(THIS_PC);
        assert_eq!(
            entries,
            vec![HostsEntry {
                name: "onlineconfigservice.ubi.com".to_owned(),
                addresses: vec!["192.168.1.155".to_owned()],
            }]
        );
    }

    /// A line can name several names, a name can be given an address for each
    /// version of IP, a comment can follow an entry, and a line with an
    /// address and no name sends nothing anywhere.
    #[test]
    fn every_name_is_kept_once_with_each_address_it_is_given() {
        let entries = parse_hosts(
            "0.0.0.0 ads.example.com tracker.example.com # an ad blocker\n\
             ::1 Ads.Example.com\n\
             127.0.0.1\n\
             \t10.0.0.5\tbuild-server   \n",
        );
        let read: Vec<(&str, Vec<&str>)> = entries
            .iter()
            .map(|entry| {
                (
                    entry.name.as_str(),
                    entry.addresses.iter().map(String::as_str).collect(),
                )
            })
            .collect();
        assert_eq!(
            read,
            vec![
                ("ads.example.com", vec!["0.0.0.0", "::1"]),
                ("tracker.example.com", vec!["0.0.0.0"]),
                ("build-server", vec!["10.0.0.5"]),
            ]
        );
    }

    /// The hosts file is read from the folder Windows' own settings name, with
    /// its variables filled in, and says when it was last written.
    #[test]
    fn the_hosts_file_is_read_from_where_windows_settings_say() {
        let folder = ScratchFolder::new("hosts");
        std::fs::write(folder.0.join("hosts"), THIS_PC).unwrap();
        let settings = ScratchKey::new("tcpip");
        // As Windows writes it, with a variable left in.
        settings.expandable("", "DataBasePath", &format!(r"%TEMP%\{}", folder.1));

        let mut unreadable = Vec::new();
        let folder_named = database_folder(
            Key::look(HKEY_CURRENT_USER, &settings.path, View::Native),
            "the test settings",
            &mut unreadable,
        )
        .expect("the folder is named");
        let hosts = hosts_in(&folder_named, &mut unreadable).expect("the file reads");
        assert!(unreadable.is_empty(), "{unreadable:?}");
        assert_eq!(
            PathBuf::from(&hosts.path),
            folder.0.join("hosts"),
            "read from somewhere other than the folder named"
        );
        assert_eq!(hosts.entries.len(), 1);
        let changed = hosts.changed.expect("when it was written is read");
        assert!(kam_core::clock::is_iso(&changed), "{changed}");
    }

    /// No hosts file is an empty one, which is what Windows makes of it. A
    /// settings key that names no folder is a gap over every entry, never an
    /// empty file.
    #[test]
    fn a_missing_file_is_empty_but_a_missing_setting_is_a_gap() {
        let folder = ScratchFolder::new("no-hosts");
        let mut unreadable = Vec::new();
        let hosts = hosts_in(&folder.0, &mut unreadable).expect("an absent file is an answer");
        assert!(hosts.entries.is_empty());
        assert!(unreadable.is_empty());

        let settings = ScratchKey::new("tcpip-empty");
        let folder = database_folder(
            Key::look(HKEY_CURRENT_USER, &settings.path, View::Native),
            "the test settings",
            &mut unreadable,
        );
        assert!(folder.is_none());
        assert_eq!(unreadable.len(), 1);
        assert!(
            unreadable[0].covers(HOSTS_ENTRY, r"c:\windows\system32\drivers\etc\hosts"),
            "a hosts file nobody could find was read as an empty one: {unreadable:?}"
        );
    }

    /// The reads on the development machine: two adapters, each with servers
    /// given by its network and none set by hand. Neither is reported, and the
    /// servers the network gave are never taken for hand-set ones.
    #[test]
    fn servers_a_network_gave_are_not_taken_for_servers_set_by_hand() {
        let scratch = ScratchKey::new("dns");
        let wifi = "{11111111-2222-3333-4444-555555555555}";
        let vpn = "{66666666-7777-8888-9999-000000000000}";
        scratch.text(&format!(r"v4\Interfaces\{wifi}"), "NameServer", "");
        scratch.text(
            &format!(r"v4\Interfaces\{wifi}"),
            "DhcpNameServer",
            "192.168.1.1",
        );
        scratch.text(
            &format!(r"v4\Interfaces\{vpn}"),
            "DhcpNameServer",
            "10.7.0.2",
        );
        scratch.make(r"v6\Interfaces");
        scratch.text(&format!(r"names\{wifi}\Connection"), "Name", "Wi-Fi");

        let places = |scratch: &ScratchKey| {
            vec![
                (scratch.under(r"v4\Interfaces"), Family::Ipv4),
                (scratch.under(r"v6\Interfaces"), Family::Ipv6),
            ]
        };
        let read = |scratch: &ScratchKey| {
            let owned = places(scratch);
            let named: Vec<(&str, String, Family)> = owned
                .iter()
                .map(|(path, family)| (path.as_str(), format!(r"HKCU\{path}"), *family))
                .collect();
            let mut unreadable = Vec::new();
            let found = hand_set_dns_in(
                HKEY_CURRENT_USER,
                &named,
                &scratch.under("names"),
                &mut unreadable,
            );
            (found, unreadable)
        };

        let ((found, adapters), unreadable) = read(&scratch);
        assert!(found.is_empty(), "{found:?}");
        assert_eq!(adapters, 2);
        assert!(unreadable.is_empty(), "{unreadable:?}");

        // Set by hand on the Wi-Fi adapter, for both versions of IP.
        scratch.text(
            &format!(r"v4\Interfaces\{wifi}"),
            "NameServer",
            "1.1.1.1,8.8.8.8",
        );
        scratch.text(
            &format!(r"v6\Interfaces\{wifi}"),
            "NameServer",
            "2606:4700:4700::1111 2001:4860:4860::8888",
        );
        let ((found, adapters), _) = read(&scratch);
        assert_eq!(
            adapters, 2,
            "an adapter counted once for each version of IP"
        );
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].adapter, "Wi-Fi");
        assert_eq!(found[0].interface, wifi);
        assert_eq!(found[0].family, Family::Ipv4);
        assert_eq!(found[0].servers, vec!["1.1.1.1", "8.8.8.8"]);
        assert!(found[0]
            .location
            .ends_with(&format!(r"v4\Interfaces\{wifi}")));
        assert_eq!(found[1].family, Family::Ipv6);
        assert_eq!(found[1].servers.len(), 2);
    }

    /// No proxy key is no proxy. A proxy switched on is its server and what it
    /// is not used for; one switched off is no server, whatever address is
    /// still written down; and a configuration script is said whether or not
    /// a server is switched on.
    #[test]
    fn an_accounts_proxy_is_read_as_it_is_switched() {
        let scratch = ScratchKey::new("proxy");
        let path = scratch.under("Internet Settings");
        let read = || {
            let mut unreadable = Vec::new();
            let proxy = proxy_in(
                HKEY_CURRENT_USER,
                &path,
                &format!(r"HKCU\{path}"),
                Some(r"C:\Users\her".to_owned()),
                &mut unreadable,
            );
            assert!(unreadable.is_empty(), "{unreadable:?}");
            proxy.expect("the key reads")
        };

        let none = read();
        assert!(!none.is_set(), "{none:?}");
        assert_eq!(none.account.as_deref(), Some(r"C:\Users\her"));

        // How the development machine's account read: switched off, with the
        // usual exception list written down.
        scratch.number("Internet Settings", "ProxyEnable", 0);
        scratch.text("Internet Settings", "ProxyServer", "");
        scratch.text("Internet Settings", "ProxyOverride", "*.local");
        assert!(!read().is_set(), "a proxy switched off was read as on");

        // An address kept while switched off is still off.
        scratch.text("Internet Settings", "ProxyServer", "127.0.0.1:8080");
        assert!(
            !read().is_set(),
            "an address kept while switched off was read as on"
        );

        scratch.number("Internet Settings", "ProxyEnable", 1);
        let on = read();
        assert_eq!(on.server.as_deref(), Some("127.0.0.1:8080"));
        assert_eq!(on.bypass.as_deref(), Some("*.local"));
        assert_eq!(on.script, None);

        scratch.number("Internet Settings", "ProxyEnable", 0);
        scratch.text(
            "Internet Settings",
            "AutoConfigURL",
            "http://wpad.example/proxy.pac",
        );
        let script = read();
        assert_eq!(script.server, None);
        assert_eq!(
            script.script.as_deref(),
            Some("http://wpad.example/proxy.pac")
        );
        assert!(script.is_set());
    }

    /// Windows' own proxy is what WinHTTP says. "Direct access", which is how
    /// the development machine answered, is no proxy; a named one is its
    /// server; and an answer this cannot read is a gap, never "no proxy".
    #[test]
    fn windows_own_proxy_is_what_winhttp_says() {
        let mut unreadable = Vec::new();
        let direct = windows_proxy_from(Ok(WinHttpAnswer::Direct), &mut unreadable).unwrap();
        assert!(!direct.is_set());
        assert_eq!(direct.account, None);
        assert_eq!(direct.location, WINHTTP_LOCATION);

        let named = windows_proxy_from(
            Ok(WinHttpAnswer::Named {
                server: "proxy.corp.example:3128".to_owned(),
                bypass: Some("<local>".to_owned()),
            }),
            &mut unreadable,
        )
        .unwrap();
        assert_eq!(named.server.as_deref(), Some("proxy.corp.example:3128"));
        assert_eq!(named.bypass.as_deref(), Some("<local>"));
        assert!(unreadable.is_empty());

        for answer in [
            Err("the call failed".to_owned()),
            Ok(WinHttpAnswer::Other(4)),
        ] {
            let mut unreadable = Vec::new();
            assert!(windows_proxy_from(answer, &mut unreadable).is_none());
            assert_eq!(unreadable.len(), 1);
            assert!(unreadable[0].covers(PROXY, &WINHTTP_LOCATION.to_lowercase()));
        }
    }

    /// An account that is not signed in has no hive to read, and is not read
    /// as an account with no proxy.
    #[test]
    fn an_account_that_is_not_signed_in_is_not_read_as_having_no_proxy() {
        let absent = UserContext::new(Some("S-1-5-21-1-2-3-31337".to_owned()), r"C:\Users\nobody");
        let mut unreadable = Vec::new();
        assert!(proxy_of(&absent, &mut unreadable).is_none());
    }
}
