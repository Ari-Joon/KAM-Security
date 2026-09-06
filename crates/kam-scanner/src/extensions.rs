//! What is installed in the browsers, and what it is allowed to read.
//!
//! # Why this is in a security tool
//!
//! A browser extension with permission to read every page is, in practical
//! terms, a program with your passwords, your email, your bank and your session
//! cookies. It runs inside the browser, so nothing in the operating system sees
//! it as a separate program: it has no signature to verify, it starts nothing at
//! boot, it never appears in Task Manager, and every other layer of this product
//! — provenance, persistence, the behaviour watcher — is structurally blind to
//! it. That blindness is the reason this module exists.
//!
//! It is also one of the two ways an account gets taken over without the
//! password ever being guessed. The other is an infostealer reading the
//! credential store off disk, which the rules and the watcher now cover. This
//! covers the half that lives inside the browser.
//!
//! # What it says, and what it refuses to say
//!
//! It reports what is installed and what each extension asked for, and points at
//! the ones whose permissions are broad. It does **not** call anything
//! malicious. Ad blockers legitimately read every page; so do password managers,
//! translators, and every developer tool worth having. A list that flagged those
//! as threats would be wrong far more often than right, and would train someone
//! to ignore the one row that mattered.
//!
//! What it can say honestly is narrower and more useful: *this* extension can
//! read every page you visit, *this* one was not installed from a store, and
//! here is when it appeared. An extension that arrived without you installing it
//! is worth a second look whatever its permissions say.

use std::path::{Path, PathBuf};

use kam_core::UserContext;
use serde::{Deserialize, Serialize};

/// Where each browser keeps its profiles, relative to Local AppData.
///
/// All the Chromium browsers share one layout, which is why one reader serves
/// them. Firefox stores extensions completely differently and is not read here;
/// saying so is better than implying the list covers every browser.
const CHROMIUM: &[(&str, &str)] = &[
    ("Chrome", r"Google\Chrome\User Data"),
    ("Edge", r"Microsoft\Edge\User Data"),
    ("Brave", r"BraveSoftware\Brave-Browser\User Data"),
    ("Vivaldi", r"Vivaldi\User Data"),
    ("Opera", r"Programs\Opera\User Data"),
    ("Chromium", r"Chromium\User Data"),
];

/// Permissions that amount to reading everything the browser sees.
///
/// These are the ones worth naming in a sentence a person can act on. Anything
/// granting access to all sites is in effect a licence to read every page,
/// including the ones behind a login.
const EVERY_SITE: &[&str] = &[
    "<all_urls>",
    "*://*/*",
    "http://*/*",
    "https://*/*",
    "*://*/",
];

/// Permissions that are individually reasonable and collectively serious.
const SENSITIVE: &[(&str, &str)] = &[
    ("webRequest", "can watch every request the browser makes"),
    (
        "webRequestBlocking",
        "can change or block requests as they happen",
    ),
    (
        "cookies",
        "can read your cookies, which are what keep you signed in",
    ),
    (
        "debugger",
        "can drive the browser's own debugger, which sees everything",
    ),
    (
        "proxy",
        "can route your traffic through a server of its choosing",
    ),
    ("history", "can read your browsing history"),
    ("downloads", "can see and start downloads"),
    ("clipboardRead", "can read what you copy"),
    (
        "nativeMessaging",
        "can talk to a program installed outside the browser",
    ),
    (
        "management",
        "can enable, disable and remove other extensions",
    ),
    ("privacy", "can change your privacy settings"),
    ("scripting", "can run its own code on pages"),
    ("tabs", "can see the address of every tab"),
];

/// How an extension came to be installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Carries a store update URL, so it can be looked up and is kept current.
    Store,
    /// No update URL. Loaded from a folder, or placed there by something else.
    /// Not sinister on its own — this is how developers work — but it is how an
    /// extension arrives without anyone choosing it from a store.
    Sideloaded,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Self::Store => "installed from a store",
            Self::Sideloaded => "not from a store",
        }
    }
}

/// One installed extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Extension {
    pub browser: String,
    /// `Default`, `Profile 1`, and so on. Worth showing: people keep a work
    /// profile and a personal one and rarely think of them as separate.
    pub profile: String,
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    /// Everything the manifest asked for, as written.
    pub permissions: Vec<String>,
    /// The sites it may act on.
    pub hosts: Vec<String>,
    pub source: Source,
    /// True when its permissions let it read every page.
    pub reads_every_page: bool,
    /// Plain sentences about what it can do. Empty for an extension that asked
    /// for nothing interesting, which is most of them.
    pub notes: Vec<String>,
    pub path: String,
    /// Days since the extension folder appeared, when that can be read.
    pub added_days_ago: Option<u64>,
}

impl Extension {
    /// Whether this is one of the few rows worth reading first.
    ///
    /// Breadth alone is not enough — an ad blocker reads every page by design.
    /// It is breadth *without* a store behind it, or breadth plus the ability to
    /// watch traffic, that is worth a person's attention.
    pub fn worth_reading(&self) -> bool {
        if self.source == Source::Sideloaded {
            return true;
        }
        self.reads_every_page && !self.notes.is_empty()
    }
}

/// Everything found, and what could not be looked at.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub extensions: Vec<Extension>,
    /// Browsers and profiles that were read, so an empty list is explicable.
    pub examined: Vec<String>,
    /// Anything unreadable, in plain words.
    pub unreadable: Vec<String>,
}

impl Report {
    /// The rows worth putting first.
    pub fn worth_reading(&self) -> impl Iterator<Item = &Extension> {
        self.extensions.iter().filter(|e| e.worth_reading())
    }
}

/// Read one JSON file, tolerating anything that is not what we expect.
fn json(path: &Path) -> Option<serde_json::Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Resolve a `__MSG_name__` placeholder against the extension's own locale
/// files.
///
/// Chromium extensions localise their own names, so a great many manifests say
/// `__MSG_appName__` rather than anything a person would recognise. Leaving that
/// on screen makes the list useless, so the locale files are read the way the
/// browser reads them: the extension's default locale first, then English, then
/// whatever is there.
fn resolve_name(version_dir: &Path, raw: &str, default_locale: Option<&str>) -> String {
    let Some(key) = raw
        .strip_prefix("__MSG_")
        .and_then(|rest| rest.strip_suffix("__"))
    else {
        return raw.to_owned();
    };

    let locales = version_dir.join("_locales");
    let mut candidates: Vec<String> = Vec::new();
    if let Some(locale) = default_locale {
        candidates.push(locale.to_owned());
    }
    candidates.extend(["en".to_owned(), "en_US".to_owned(), "en_GB".to_owned()]);
    // Then anything at all, so a non-English extension still gets a name.
    if let Ok(listing) = std::fs::read_dir(&locales) {
        for item in listing.flatten() {
            if let Some(name) = item.file_name().to_str() {
                candidates.push(name.to_owned());
            }
        }
    }

    for locale in candidates {
        let messages = locales.join(&locale).join("messages.json");
        let Some(value) = json(&messages) else {
            continue;
        };
        // Message keys are matched case-insensitively by the browser.
        if let Some(object) = value.as_object() {
            for (name, entry) in object {
                if name.eq_ignore_ascii_case(key) {
                    if let Some(message) = entry.get("message").and_then(|m| m.as_str()) {
                        if !message.trim().is_empty() {
                            return message.to_owned();
                        }
                    }
                }
            }
        }
    }

    // Better the placeholder than a blank row: it is at least searchable.
    raw.to_owned()
}

fn strings(value: Option<&serde_json::Value>) -> Vec<String> {
    value
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Days since a path was created.
fn age_days(path: &Path, now: u64) -> Option<u64> {
    let created = std::fs::metadata(path).ok()?.created().ok()?;
    let seconds = created
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(now.saturating_sub(seconds) / 86_400)
}

/// Read one extension's newest installed version.
fn read_extension(
    browser: &str,
    profile: &str,
    id: &str,
    extension_dir: &Path,
    now: u64,
) -> Option<Extension> {
    // An extension folder holds one directory per installed version. The newest
    // is the one in use.
    let version_dir = std::fs::read_dir(extension_dir)
        .ok()?
        .flatten()
        .filter(|item| item.path().is_dir())
        .max_by_key(|item| {
            item.metadata()
                .and_then(|meta| meta.modified())
                .unwrap_or(std::time::UNIX_EPOCH)
        })?
        .path();

    let manifest = json(&version_dir.join("manifest.json"))?;

    let default_locale = manifest.get("default_locale").and_then(|v| v.as_str());
    let raw_name = manifest
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(id)
        .to_owned();
    let name = resolve_name(&version_dir, &raw_name, default_locale);

    let description = manifest
        .get("description")
        .and_then(|v| v.as_str())
        .map(|text| resolve_name(&version_dir, text, default_locale))
        .unwrap_or_default();

    // Manifest v2 puts hosts in `permissions`; v3 splits them out. Reading both
    // means one code path covers extensions of either age.
    let mut permissions = strings(manifest.get("permissions"));
    let mut hosts = strings(manifest.get("host_permissions"));
    permissions.extend(strings(manifest.get("optional_permissions")));
    hosts.extend(strings(manifest.get("optional_host_permissions")));

    // Split whatever landed in `permissions` that is really a site pattern.
    let (site_like, plain): (Vec<String>, Vec<String>) = permissions
        .into_iter()
        .partition(|item| item.contains("://") || item == "<all_urls>");
    hosts.extend(site_like);
    hosts.sort();
    hosts.dedup();
    let mut permissions = plain;
    permissions.sort();
    permissions.dedup();

    let reads_every_page = hosts
        .iter()
        .any(|host| EVERY_SITE.iter().any(|broad| host == broad))
        || hosts.iter().any(|host| host.starts_with("*://*"));

    let mut notes = Vec::new();
    if reads_every_page {
        notes.push(
            "It can read and change every page you visit, including pages you are signed in to."
                .to_owned(),
        );
    }
    for (permission, meaning) in SENSITIVE {
        if permissions.iter().any(|held| held == permission) {
            notes.push(format!("It {meaning}."));
        }
    }

    let source = if manifest.get("update_url").is_some() {
        Source::Store
    } else {
        Source::Sideloaded
    };
    if source == Source::Sideloaded {
        notes.push(
            "It carries no store update address, so it was loaded from a folder rather than installed from a store."
                .to_owned(),
        );
    }

    Some(Extension {
        browser: browser.to_owned(),
        profile: profile.to_owned(),
        id: id.to_owned(),
        name,
        version: manifest
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned(),
        description,
        permissions,
        hosts,
        source,
        reads_every_page,
        notes,
        added_days_ago: age_days(extension_dir, now),
        path: version_dir.display().to_string(),
    })
}

/// Every extension installed in every Chromium browser this account has.
pub fn survey(user: &UserContext) -> Report {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or_default();

    let mut report = Report::default();
    let local = PathBuf::from(user.local_app_data());

    for (browser, relative) in CHROMIUM {
        let root = local.join(relative);
        if !root.is_dir() {
            continue;
        }
        let listing = match std::fs::read_dir(&root) {
            Ok(listing) => listing,
            Err(error) => {
                report
                    .unreadable
                    .push(format!("{browser}: {root:?} could not be read ({error})"));
                continue;
            }
        };

        for item in listing.flatten() {
            let profile_dir = item.path();
            if !profile_dir.is_dir() {
                continue;
            }
            let profile = item.file_name().to_string_lossy().into_owned();
            // Chromium's profiles are `Default` and `Profile N`; everything else
            // in User Data is shared state rather than a profile.
            if profile != "Default" && !profile.starts_with("Profile ") {
                continue;
            }
            let extensions = profile_dir.join("Extensions");
            if !extensions.is_dir() {
                continue;
            }
            report.examined.push(format!("{browser} — {profile}"));

            let Ok(ids) = std::fs::read_dir(&extensions) else {
                report.unreadable.push(format!(
                    "{browser} — {profile}: the extension folder could not be read"
                ));
                continue;
            };
            for id_entry in ids.flatten() {
                let id_dir = id_entry.path();
                if !id_dir.is_dir() {
                    continue;
                }
                let id = id_entry.file_name().to_string_lossy().into_owned();
                if let Some(extension) = read_extension(browser, &profile, &id, &id_dir, now) {
                    report.extensions.push(extension);
                }
            }
        }
    }

    // The ones worth reading first, then by name so the order is stable.
    report.extensions.sort_by(|a, b| {
        b.worth_reading()
            .cmp(&a.worth_reading())
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    report
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Build an extension folder the way Chromium lays one out.
    fn plant(id: &str, manifest: &str, messages: Option<&str>) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "kam-ext-{}-{}-{id}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let version = root.join("1.0.0_0");
        std::fs::create_dir_all(&version).unwrap();
        std::fs::write(version.join("manifest.json"), manifest).unwrap();
        if let Some(messages) = messages {
            let locale = version.join("_locales").join("en");
            std::fs::create_dir_all(&locale).unwrap();
            std::fs::write(locale.join("messages.json"), messages).unwrap();
        }
        (root, version)
    }

    #[test]
    fn an_extension_that_reads_every_page_says_so() {
        let (root, _) = plant(
            "aaaa",
            r#"{"name":"Wide Open","version":"1.0","update_url":"https://clients2.google.com/service/update2/crx",
                "permissions":["tabs","cookies"],"host_permissions":["<all_urls>"]}"#,
            None,
        );
        let extension = read_extension("Chrome", "Default", "aaaa", &root, 0).unwrap();
        assert_eq!(extension.name, "Wide Open");
        assert!(extension.reads_every_page);
        assert_eq!(extension.source, Source::Store);
        assert!(extension
            .notes
            .iter()
            .any(|note| note.contains("every page you visit")));
        assert!(extension.notes.iter().any(|note| note.contains("cookies")));
        assert!(extension.worth_reading());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_narrow_store_extension_is_not_worth_reading() {
        // The ordinary case, and the one that has to stay quiet: most
        // extensions ask for very little and must not fill the list.
        let (root, _) = plant(
            "bbbb",
            r#"{"name":"Just A Theme","version":"2.1","update_url":"https://clients2.google.com/service/update2/crx",
                "permissions":["storage"]}"#,
            None,
        );
        let extension = read_extension("Chrome", "Default", "bbbb", &root, 0).unwrap();
        assert!(!extension.reads_every_page);
        assert!(extension.notes.is_empty(), "{:?}", extension.notes);
        assert!(!extension.worth_reading());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_sideloaded_extension_is_always_worth_reading() {
        // No update URL means nobody chose it from a store. That is how a
        // developer works, and also how something arrives uninvited.
        let (root, _) = plant(
            "cccc",
            r#"{"name":"Loaded By Hand","version":"0.1","permissions":["storage"]}"#,
            None,
        );
        let extension = read_extension("Chrome", "Default", "cccc", &root, 0).unwrap();
        assert_eq!(extension.source, Source::Sideloaded);
        assert!(extension.worth_reading());
        assert!(extension
            .notes
            .iter()
            .any(|note| note.contains("no store update address")));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_localised_name_is_resolved_rather_than_shown_raw() {
        // A great many real extensions name themselves with a placeholder. A
        // list full of __MSG_appName__ is a list nobody can use.
        let (root, _) = plant(
            "dddd",
            r#"{"name":"__MSG_appName__","version":"3.0","default_locale":"en",
                "update_url":"https://clients2.google.com/service/update2/crx","permissions":[]}"#,
            Some(r#"{"appName":{"message":"Adblock Something"}}"#),
        );
        let extension = read_extension("Chrome", "Default", "dddd", &root, 0).unwrap();
        assert_eq!(extension.name, "Adblock Something");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn manifest_v2_site_patterns_are_read_as_hosts() {
        // v2 mixes host patterns into `permissions`. Treating those as plain
        // permissions would miss that the extension reads every page.
        let (root, _) = plant(
            "eeee",
            r#"{"name":"Old Style","version":"1.0","manifest_version":2,
                "update_url":"https://clients2.google.com/service/update2/crx",
                "permissions":["tabs","https://*/*","http://*/*"]}"#,
            None,
        );
        let extension = read_extension("Chrome", "Default", "eeee", &root, 0).unwrap();
        assert!(
            extension.reads_every_page,
            "v2 host patterns were not recognised: {:?}",
            extension.hosts
        );
        assert!(!extension.permissions.iter().any(|p| p.contains("://")));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn this_machine_can_be_surveyed_without_falling_over() {
        let report = survey(&UserContext::current());
        println!(
            "examined {:?}, found {} extensions, {} worth reading",
            report.examined,
            report.extensions.len(),
            report.worth_reading().count()
        );
        for extension in report.worth_reading().take(10) {
            println!(
                "  [{}] {} ({}) — {}",
                extension.browser,
                extension.name,
                extension.source.label(),
                extension.notes.join(" ")
            );
        }
        // Every row must be nameable and attributable, whatever is installed.
        for extension in &report.extensions {
            assert!(!extension.name.is_empty(), "an extension with no name");
            assert!(!extension.id.is_empty());
            assert!(!extension.browser.is_empty());
        }
    }
}
