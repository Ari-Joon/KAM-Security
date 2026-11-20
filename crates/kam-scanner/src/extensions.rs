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

use kam_core::changes::Unreadable;
use kam_core::UserContext;
use serde::{Deserialize, Serialize};

/// The token an extension is filed under in What changed.
///
/// Stored, so never renamed: see [`crate::persistence::Anchor::kind`].
pub const BROWSER_EXTENSION: &str = "browser_extension";

/// Where Chromium's settings file says an extension came from, for the two
/// codes read here (`ManifestLocation` in Chromium's own source).
///
/// A part of the browser itself, which happens to be built as an extension.
/// The browser does not show these on its own extensions page either.
const COMPONENT: i64 = 5;

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
    /// Loaded from a folder elsewhere on this PC, which the browser's settings
    /// file names. Such an extension is never copied into the profile's
    /// `Extensions` folder, so reading that folder alone missed exactly the
    /// ones not from a store. Developers work this way, as the owner does.
    Folder,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Self::Store => "installed from a store",
            Self::Sideloaded => "not from a store",
            Self::Folder => "loaded from a folder on this PC",
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
    /// The profile folder it is installed in, which separates one account's
    /// and one profile's extensions from another's in What changed.
    #[serde(default)]
    pub profile_folder: String,
}

impl Extension {
    /// Whether this is one of the few rows worth reading first.
    ///
    /// Breadth alone is not enough — an ad blocker reads every page by design.
    /// It is breadth *without* a store behind it, or breadth plus the ability to
    /// watch traffic, that is worth a person's attention.
    pub fn worth_reading(&self) -> bool {
        if self.source != Source::Store {
            return true;
        }
        self.reads_every_page && !self.notes.is_empty()
    }
}

/// How many of a browser's own built-in parts one profile's settings file
/// lists. Counted rather than listed, as Windows' own scheduled tasks are in
/// What changed: they come with the browser and go with its updates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuiltIn {
    pub browser: String,
    pub profile: String,
    pub count: usize,
}

/// Everything found, and what could not be looked at.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub extensions: Vec<Extension>,
    /// Browsers and profiles that were read, so an empty list is explicable.
    pub examined: Vec<String>,
    /// Each profile's count of the browser's own built-in parts.
    #[serde(default)]
    pub built_in: Vec<BuiltIn>,
    /// Anything unreadable, in plain words, with the kind and place it rules
    /// nothing out about.
    pub unreadable: Vec<Unreadable>,
}

impl Report {
    /// The rows worth putting first.
    pub fn worth_reading(&self) -> impl Iterator<Item = &Extension> {
        self.extensions.iter().filter(|e| e.worth_reading())
    }
}

/// Read one JSON file, tolerating anything that is not what we expect.
fn json(path: &Path) -> Option<serde_json::Value> {
    read_json(path).ok()
}

/// Read one JSON file, saying why when it cannot be.
///
/// A leading byte order mark is skipped. Chromium accepts a manifest that
/// starts with one and serde_json does not, so an extension saved by an
/// editor that adds one was installed and running and was missing from this
/// list without a word.
fn read_json(path: &Path) -> Result<serde_json::Value, String> {
    let text = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    serde_json::from_str(text).map_err(|error| error.to_string())
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

/// The site patterns an extension's content scripts are injected into.
///
/// A content script runs inside the page and reads what is on it, so one
/// matching every site reads every page just as a host permission does.
/// Leaving these out described an extension that injects a script into every
/// page as one that reads none.
fn content_script_sites(manifest: &serde_json::Value) -> Vec<String> {
    manifest
        .get("content_scripts")
        .and_then(|scripts| scripts.as_array())
        .map(|scripts| {
            scripts
                .iter()
                .flat_map(|script| strings(script.get("matches")))
                .collect()
        })
        .unwrap_or_default()
}

/// Read one extension's newest installed version.
///
/// `Ok(None)` for a folder with no version in it, which is what the browser
/// leaves while removing one and is not an installed extension. An error says
/// why an extension that is there could not be read, so it can be named
/// rather than left out of the list as though it were not installed.
fn read_extension(
    browser: &str,
    profile: &str,
    id: &str,
    extension_dir: &Path,
    now: u64,
) -> Result<Option<Extension>, String> {
    // An extension folder holds one directory per installed version. The newest
    // is the one in use.
    let listing = std::fs::read_dir(extension_dir)
        .map_err(|error| format!("its folder could not be listed ({error})"))?;
    let Some(version_dir) = listing
        .flatten()
        .filter(|item| item.path().is_dir())
        .max_by_key(|item| {
            item.metadata()
                .and_then(|meta| meta.modified())
                .unwrap_or(std::time::UNIX_EPOCH)
        })
        .map(|item| item.path())
    else {
        return Ok(None);
    };

    let manifest = read_json(&version_dir.join("manifest.json"))
        .map_err(|why| format!("its manifest could not be read ({why})"))?;

    let source = if manifest.get("update_url").is_some() {
        Source::Store
    } else {
        Source::Sideloaded
    };
    Ok(Some(describe(
        browser,
        profile,
        id,
        &manifest,
        &version_dir,
        source,
        age_days(extension_dir, now),
    )))
}

/// What one extension is and may do, from its manifest.
///
/// `folder` is where its own files are, for its localised name, and is shown
/// as where it lives.
fn describe(
    browser: &str,
    profile: &str,
    id: &str,
    manifest: &serde_json::Value,
    folder: &Path,
    source: Source,
    added_days_ago: Option<u64>,
) -> Extension {
    let version_dir = folder;
    let default_locale = manifest.get("default_locale").and_then(|v| v.as_str());
    let raw_name = manifest
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(id)
        .to_owned();
    let name = resolve_name(version_dir, &raw_name, default_locale);

    let description = manifest
        .get("description")
        .and_then(|v| v.as_str())
        .map(|text| resolve_name(version_dir, text, default_locale))
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
    hosts.extend(content_script_sites(manifest));
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

    match source {
        Source::Store => {}
        Source::Sideloaded => notes.push(
            "It carries no store update address, so it was loaded from a folder rather than installed from a store."
                .to_owned(),
        ),
        Source::Folder => notes.push(format!(
            "Loaded from a folder on this PC ({}), not from a store, according to {browser}'s \
             settings file.",
            version_dir.display()
        )),
    }

    Extension {
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
        added_days_ago,
        path: version_dir.display().to_string(),
        profile_folder: String::new(),
    }
}

/// The settings file a Chromium profile keeps its extensions in, read.
///
/// `Secure Preferences` is where current versions keep them, and
/// `Preferences` where older ones did, so the second is read only when the
/// first holds none. `Ok(None)` when neither names any extension, which a
/// profile that has never had one looks like.
fn settings_of(profile_dir: &Path) -> Result<Option<serde_json::Value>, String> {
    let mut failed = None;
    for file in ["Secure Preferences", "Preferences"] {
        let path = profile_dir.join(file);
        match read_json(&path) {
            Ok(value) => {
                if let Some(settings) = value.pointer("/extensions/settings") {
                    if settings.is_object() {
                        return Ok(Some(settings.clone()));
                    }
                }
            }
            Err(_) if !path.exists() => {}
            Err(why) => {
                failed.get_or_insert(format!("{file} ({why})"));
            }
        }
    }
    match failed {
        Some(why) => Err(why),
        None => Ok(None),
    }
}

/// Whether `path` is the folder `parent` or lies inside it, compared as paths
/// rather than as text.
fn inside(path: &Path, parent: &Path) -> bool {
    let fold = |path: &Path| {
        path.to_string_lossy()
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_lowercase()
    };
    let (path, parent) = (fold(path), fold(parent));
    path == parent
        || path
            .strip_prefix(&parent)
            .is_some_and(|rest| rest.starts_with('\\'))
}

/// Days since a time Chromium writes in its settings file: microseconds since
/// 1601, as text.
fn days_since_chromium_time(text: &str, now: u64) -> Option<u64> {
    let micros: u64 = text.parse().ok()?;
    let seconds = (micros / 1_000_000).checked_sub(11_644_473_600)?;
    Some(now.saturating_sub(seconds) / 86_400)
}

/// The extensions one profile's settings file says are loaded from a folder
/// outside its `Extensions` folder, which reading that folder cannot find,
/// and how many of the browser's own built-in parts it lists.
///
/// An extension whose settings name a folder inside `Extensions`, or by a
/// path relative to it, is the folder reader's, and is left to it.
fn from_settings(
    browser: &str,
    profile: &str,
    profile_dir: &Path,
    settings: &serde_json::Value,
    now: u64,
) -> (Vec<Extension>, usize) {
    let extensions_dir = profile_dir.join("Extensions");
    let mut found = Vec::new();
    let mut built_in = 0;
    let Some(entries) = settings.as_object() else {
        return (found, built_in);
    };
    for (id, entry) in entries {
        let Some(path) = entry.get("path").and_then(|path| path.as_str()) else {
            continue;
        };
        let folder = PathBuf::from(path);
        if !folder.is_absolute() || inside(&folder, &extensions_dir) {
            continue;
        }
        if entry.get("location").and_then(serde_json::Value::as_i64) == Some(COMPONENT) {
            built_in += 1;
            continue;
        }
        // The extension's own manifest where it can be read, which is what
        // the browser loads; the copy the settings file keeps otherwise.
        let manifest = read_json(&folder.join("manifest.json"))
            .ok()
            .or_else(|| entry.get("manifest").cloned())
            .unwrap_or_else(|| serde_json::json!({}));
        let added = entry
            .get("first_install_time")
            .or_else(|| entry.get("install_time"))
            .and_then(|time| time.as_str())
            .and_then(|time| days_since_chromium_time(time, now));
        found.push(describe(
            browser,
            profile,
            id,
            &manifest,
            &folder,
            Source::Folder,
            added,
        ));
    }
    (found, built_in)
}

/// Whether a folder name has the shape of a Chromium extension id: 32 letters
/// from `a` to `p`.
fn is_extension_id(name: &str) -> bool {
    name.len() == 32 && name.bytes().all(|byte| (b'a'..=b'p').contains(&byte))
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
                report.unreadable.push(Unreadable::within(
                    BROWSER_EXTENSION,
                    &root.display().to_string(),
                    format!("{browser}: {} could not be read ({error})", root.display()),
                ));
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
            let shown = profile_dir.display().to_string();
            let extensions = profile_dir.join("Extensions");
            let has_settings = ["Secure Preferences", "Preferences"]
                .iter()
                .any(|file| profile_dir.join(file).is_file());
            // A profile with nothing in its Extensions folder can still run
            // an extension loaded from a folder, which only its settings file
            // names.
            if !extensions.is_dir() && !has_settings {
                continue;
            }
            report.examined.push(format!("{browser} ({profile})"));
            let mut listed: Vec<Extension> = Vec::new();

            if extensions.is_dir() {
                match std::fs::read_dir(&extensions) {
                    Ok(ids) => {
                        for id_entry in ids.flatten() {
                            let id_dir = id_entry.path();
                            if !id_dir.is_dir() {
                                continue;
                            }
                            let id = id_entry.file_name().to_string_lossy().into_owned();
                            match read_extension(browser, &profile, &id, &id_dir, now) {
                                Ok(Some(extension)) => listed.push(extension),
                                Ok(None) => {}
                                // The browser keeps working folders here too,
                                // such as `Temp` while one is being unpacked.
                                // One of those that does not read as an
                                // extension is not a missing one.
                                Err(_) if !is_extension_id(&id) => {}
                                // Named, not dropped. An extension whose
                                // manifest would not parse is still installed,
                                // and may still be running.
                                Err(why) => report.unreadable.push(Unreadable::within(
                                    BROWSER_EXTENSION,
                                    &shown,
                                    format!(
                                        "In {browser} ({profile}), the extension {id} could not \
                                         be read: {why}. What it is allowed to do is not shown."
                                    ),
                                )),
                            }
                        }
                    }
                    Err(_) => report.unreadable.push(Unreadable::within(
                        BROWSER_EXTENSION,
                        &shown,
                        format!("{browser} ({profile}): the extension folder could not be read"),
                    )),
                }
            }

            match settings_of(&profile_dir) {
                Ok(Some(settings)) => {
                    let (from_folders, built_in) =
                        from_settings(browser, &profile, &profile_dir, &settings, now);
                    for extension in from_folders {
                        if !listed.iter().any(|known| known.id == extension.id) {
                            listed.push(extension);
                        }
                    }
                    if built_in > 0 {
                        report.built_in.push(BuiltIn {
                            browser: (*browser).to_owned(),
                            profile: profile.clone(),
                            count: built_in,
                        });
                    }
                }
                Ok(None) => {}
                // Said, not taken for a profile with nothing loaded from a
                // folder: that is exactly what could not be read.
                Err(why) => report.unreadable.push(Unreadable::within(
                    BROWSER_EXTENSION,
                    &shown,
                    format!(
                        "In {browser} ({profile}), the settings file could not be read: {why}. \
                         Extensions loaded from a folder are not shown for it."
                    ),
                )),
            }

            for mut extension in listed {
                extension.profile_folder = shown.clone();
                report.extensions.push(extension);
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
        let extension = read_extension("Chrome", "Default", "aaaa", &root, 0)
            .unwrap()
            .unwrap();
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
        let extension = read_extension("Chrome", "Default", "bbbb", &root, 0)
            .unwrap()
            .unwrap();
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
        let extension = read_extension("Chrome", "Default", "cccc", &root, 0)
            .unwrap()
            .unwrap();
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
        let extension = read_extension("Chrome", "Default", "dddd", &root, 0)
            .unwrap()
            .unwrap();
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
        let extension = read_extension("Chrome", "Default", "eeee", &root, 0)
            .unwrap()
            .unwrap();
        assert!(
            extension.reads_every_page,
            "v2 host patterns were not recognised: {:?}",
            extension.hosts
        );
        assert!(!extension.permissions.iter().any(|p| p.contains("://")));
        std::fs::remove_dir_all(&root).ok();
    }

    /// A content script injected into every site reads every page, whatever
    /// the host permissions say.
    #[test]
    fn a_content_script_on_every_site_reads_every_page() {
        let (root, _) = plant(
            "ffff",
            r#"{"name":"Injector","version":"1.0","manifest_version":3,
                "update_url":"https://clients2.google.com/service/update2/crx",
                "permissions":["storage"],
                "content_scripts":[{"matches":["<all_urls>"],"js":["content.js"]}]}"#,
            None,
        );
        let extension = read_extension("Chrome", "Default", "ffff", &root, 0)
            .unwrap()
            .unwrap();
        std::fs::remove_dir_all(&root).ok();
        assert!(extension.reads_every_page, "{:?}", extension.hosts);
        assert!(extension.worth_reading());
    }

    /// A manifest starting with a byte order mark is read, as Chromium reads
    /// it, rather than dropped.
    #[test]
    fn a_manifest_with_a_byte_order_mark_is_read() {
        let (root, _) = plant(
            "gggg",
            "\u{feff}{\"name\":\"Saved With A Mark\",\"version\":\"1.0\",\
             \"update_url\":\"https://clients2.google.com/service/update2/crx\"}",
            None,
        );
        let read = read_extension("Chrome", "Default", "gggg", &root, 0);
        std::fs::remove_dir_all(&root).ok();
        assert_eq!(read.unwrap().unwrap().name, "Saved With A Mark");
    }

    /// An extension whose manifest will not parse is still installed, and is
    /// said to be unreadable rather than left out as though it were not there.
    #[test]
    fn an_unparseable_manifest_is_a_gap_not_an_absence() {
        let (root, _) = plant("hhhh", "{ this is not json", None);
        let read = read_extension("Chrome", "Default", "hhhh", &root, 0);
        std::fs::remove_dir_all(&root).ok();
        let why = read.expect_err("an unreadable manifest must be an error");
        assert!(why.contains("manifest"), "{why}");
    }

    /// A person's profile in the temporary folder, with one Chrome profile
    /// in it, removed when dropped.
    struct ScratchBrowser {
        home: PathBuf,
    }

    impl ScratchBrowser {
        fn new(tag: &str) -> Self {
            let home = std::env::temp_dir().join(format!(
                "kam-browser-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            std::fs::create_dir_all(home.join(r"AppData\Local\Google\Chrome\User Data\Default"))
                .unwrap();
            Self { home }
        }

        fn profile(&self) -> PathBuf {
            self.home
                .join(r"AppData\Local\Google\Chrome\User Data\Default")
        }

        fn user(&self) -> UserContext {
            UserContext::new(None, &self.home.display().to_string())
        }

        /// An extension installed from a store, in the profile's own folder.
        fn store_extension(&self, id: &str, name: &str) {
            let version = self.profile().join("Extensions").join(id).join("1.0_0");
            std::fs::create_dir_all(&version).unwrap();
            std::fs::write(
                version.join("manifest.json"),
                format!(
                    r#"{{"name":"{name}","version":"1.0",
                       "update_url":"https://clients2.google.com/service/update2/crx"}}"#
                ),
            )
            .unwrap();
        }

        /// A folder on this PC holding an extension's own files, outside the
        /// browser's folders, as a developer's project is.
        fn project(&self, relative: &str, name: &str) -> PathBuf {
            let folder = self.home.join(r"Desktop\Projects").join(relative);
            std::fs::create_dir_all(&folder).unwrap();
            std::fs::write(
                folder.join("manifest.json"),
                format!(
                    r#"{{"name":"{name}","version":"0.3","manifest_version":3,
                       "permissions":["storage"]}}"#
                ),
            )
            .unwrap();
            folder
        }

        fn settings(&self, file: &str, settings: serde_json::Value) {
            std::fs::write(
                self.profile().join(file),
                serde_json::json!({ "extensions": { "settings": settings } }).to_string(),
            )
            .unwrap();
        }
    }

    impl Drop for ScratchBrowser {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.home);
        }
    }

    const STORE_ID: &str = "nmmhkkegccagdldgiimedpiccmgmieda";
    const BOOSTER_ID: &str = "jghecgabfgfdldnmbfkhmffcabddioke";
    const SPEECH_ID: &str = "ohgofbmnpfanlpkkomogjgoemkhkcmno";

    /// Chrome's Default profile as the review read it on the development
    /// machine: an extension from a store in the profile's own folder; two
    /// loaded from folders on this PC (location 4), which the settings file
    /// names and the Extensions folder never holds; and parts of the browser
    /// itself (location 5), which are counted and not listed.
    #[test]
    fn an_extension_loaded_from_a_folder_is_found_in_the_settings_file() {
        let browser = ScratchBrowser::new("settings");
        browser.store_extension(STORE_ID, "From A Store");
        let booster = browser.project("Volume Booster for Chrome", "Volume Booster for Chrome");
        let speech = browser.project(r"Text to Speech\files\extension", "Text to Speech");
        browser.settings(
            "Secure Preferences",
            serde_json::json!({
                STORE_ID: { "location": 1, "path": format!(r"{STORE_ID}\1.0_0") },
                BOOSTER_ID: {
                    "location": 4,
                    "path": booster.display().to_string(),
                    "first_install_time": "13394637466180143"
                },
                SPEECH_ID: { "location": 4, "path": speech.display().to_string() },
                "mhjfbmdgcfjbbpaeojofohoefgiehjai": {
                    "location": 5,
                    "path": r"C:\Program Files\Google\Chrome\Application\153.0.8010.53\resources\pdf"
                },
                "ghbmnnjooekpmoecnnnilnnbdlolhkhi": {
                    "location": 5,
                    "path": r"C:\Program Files\Google\Chrome\Application\153.0.8010.53\resources\glic_extension"
                },
            }),
        );

        let report = survey(&browser.user());
        assert!(report.unreadable.is_empty(), "{:?}", report.unreadable);
        assert_eq!(report.examined, vec!["Chrome (Default)"]);
        let mut found: Vec<(&str, Source)> = report
            .extensions
            .iter()
            .map(|extension| (extension.id.as_str(), extension.source))
            .collect();
        found.sort_by(|a, b| a.0.cmp(b.0));
        let mut expected = vec![
            (BOOSTER_ID, Source::Folder),
            (STORE_ID, Source::Store),
            (SPEECH_ID, Source::Folder),
        ];
        expected.sort_by(|a, b| a.0.cmp(b.0));
        assert_eq!(found, expected, "{:?}", report.extensions);
        let speech_read = report
            .extensions
            .iter()
            .find(|extension| extension.id == SPEECH_ID)
            .unwrap();
        assert_eq!(speech_read.name, "Text to Speech");

        let booster_read = report
            .extensions
            .iter()
            .find(|extension| extension.id == BOOSTER_ID)
            .unwrap();
        assert_eq!(booster_read.name, "Volume Booster for Chrome");
        assert_eq!(PathBuf::from(&booster_read.path), booster);
        assert!(booster_read.worth_reading());
        assert!(booster_read.added_days_ago.is_some());
        assert!(
            booster_read
                .notes
                .iter()
                .any(|note| note.contains("not from a store, according to Chrome's settings file")),
            "{:?}",
            booster_read.notes
        );
        for extension in &report.extensions {
            assert_eq!(PathBuf::from(&extension.profile_folder), browser.profile());
        }
        assert_eq!(
            report.built_in,
            vec![BuiltIn {
                browser: "Chrome".to_owned(),
                profile: "Default".to_owned(),
                count: 2
            }]
        );
    }

    /// Older versions keep extensions in `Preferences`, which is read when
    /// `Secure Preferences` holds none. A profile with no Extensions folder
    /// at all is still read for them.
    #[test]
    fn the_older_settings_file_is_read_when_the_newer_names_no_extension() {
        let browser = ScratchBrowser::new("preferences");
        let booster = browser.project("Volume Booster for Chrome", "Volume Booster for Chrome");
        std::fs::write(browser.profile().join("Secure Preferences"), "{}").unwrap();
        browser.settings(
            "Preferences",
            serde_json::json!({
                BOOSTER_ID: { "location": 4, "path": booster.display().to_string() },
            }),
        );
        let report = survey(&browser.user());
        assert!(report.unreadable.is_empty(), "{:?}", report.unreadable);
        assert_eq!(report.extensions.len(), 1);
        assert_eq!(report.extensions[0].source, Source::Folder);
    }

    /// A settings file that would not read is said to be unread, confined to
    /// its own profile, and is never taken for a profile with nothing loaded
    /// from a folder.
    #[test]
    fn a_settings_file_that_will_not_read_is_a_gap_in_its_own_profile() {
        let browser = ScratchBrowser::new("unreadable-settings");
        browser.store_extension(STORE_ID, "From A Store");
        std::fs::write(browser.profile().join("Secure Preferences"), "{ not json").unwrap();
        let report = survey(&browser.user());
        assert_eq!(
            report.extensions.len(),
            1,
            "the folder's own extension is still read"
        );
        assert_eq!(report.unreadable.len(), 1, "{:?}", report.unreadable);
        let gap = &report.unreadable[0];
        assert!(
            gap.what.contains("settings file could not be read"),
            "{}",
            gap.what
        );
        let profile = browser.profile().display().to_string().to_lowercase();
        assert!(gap.covers(BROWSER_EXTENSION, &profile));
        assert!(!gap.covers(BROWSER_EXTENSION, r"c:\users\someone else\appdata\local"));
    }

    /// A folder inside the profile's own Extensions folder is the folder
    /// reader's however its path is spelled, and a folder whose name only
    /// begins the same way is not inside it.
    #[test]
    fn inside_is_decided_by_path_not_by_spelling() {
        let extensions =
            Path::new(r"C:\Users\her\AppData\Local\Google\Chrome\User Data\Default\Extensions");
        assert!(inside(
            Path::new(
                r"c:/users/her/appdata/local/google/chrome/user data/default/extensions/abc/1_0"
            ),
            extensions
        ));
        assert!(!inside(
            Path::new(
                r"C:\Users\her\AppData\Local\Google\Chrome\User Data\Default\Extensions Backup\abc"
            ),
            extensions
        ));
    }

    #[test]
    fn only_extension_shaped_folder_names_are_extension_ids() {
        assert!(is_extension_id("nmmhkkegccagdldgiimedpiccmgmieda"));
        assert!(!is_extension_id("Temp"));
        assert!(!is_extension_id("NMMHKKEGCCAGDLDGIIMEDPICCMGMIEDA"));
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
