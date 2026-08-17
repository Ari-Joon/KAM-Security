//! Where Steam actually put each game.
//!
//! Steam is the reason a games machine looks unmeasurable from the registry
//! alone. Its uninstall entries frequently carry no `InstallLocation`, and the
//! folder name rarely matches the store name — "Counter-Strike 2" lives in
//! `Counter-Strike Global Offensive`, "Mecha BREAK" in `MechaBREAK`. Name
//! matching cannot bridge that, so those games measure as zero bytes, which is
//! worse than saying nothing.
//!
//! Steam already keeps the mapping. Every installed game has an
//! `appmanifest_<id>.acf` beside it naming both the title and its directory, and
//! `libraryfolders.vdf` lists every library, including ones on other drives.
//! Reading those turns a guess into a lookup.
//!
//! # On the format
//!
//! ACF and VDF are Valve's key-value text format: quoted key, whitespace,
//! quoted value, with braces for nesting. Only flat lookups are needed here —
//! `name`, `installdir`, `path` — so this reads pairs and ignores structure
//! rather than implementing the format properly.

use std::path::{Path, PathBuf};

use crate::registry::{Key, View};
use windows::Win32::System::Registry::HKEY_CURRENT_USER;

/// One installed game, as Steam describes it.
#[derive(Debug, Clone)]
pub struct SteamApp {
    /// Store name, e.g. "Counter-Strike 2".
    pub name: String,
    /// Full path to the install directory.
    pub path: String,
    /// Steam's own identifier, taken from the manifest filename. Removing a
    /// Steam title means asking Steam, not running an uninstaller it does not
    /// have.
    pub app_id: String,
}

/// Pull the quoted key and value out of a line, when it has both.
///
/// Lines that open or close a block have one token or none, and are skipped.
fn key_value(line: &str) -> Option<(String, String)> {
    let mut tokens = Vec::new();
    let mut rest = line;
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        let end = after.find('"')?;
        tokens.push(after[..end].to_owned());
        rest = &after[end + 1..];
        if tokens.len() == 2 {
            break;
        }
    }
    match tokens.len() {
        2 => {
            let mut drain = tokens.drain(..);
            Some((drain.next()?, drain.next()?))
        }
        _ => None,
    }
}

fn find_value(text: &str, wanted: &str) -> Option<String> {
    text.lines().find_map(|line| {
        key_value(line).and_then(|(key, value)| key.eq_ignore_ascii_case(wanted).then_some(value))
    })
}

/// Steam's own install directory, from the registry.
fn steam_root() -> Option<PathBuf> {
    let key = Key::open(HKEY_CURRENT_USER, r"Software\Valve\Steam", View::Native)?;
    // Steam writes this with forward slashes, which Windows accepts anyway.
    key.string("SteamPath").map(PathBuf::from)
}

/// Every library folder, including ones on other drives.
///
/// The main install is always a library even though it is not always listed as
/// one, so it is added regardless.
fn library_paths(root: &Path) -> Vec<PathBuf> {
    let mut libraries = vec![root.to_path_buf()];

    let manifest = root.join("steamapps").join("libraryfolders.vdf");
    if let Ok(text) = std::fs::read_to_string(&manifest) {
        for line in text.lines() {
            if let Some((key, value)) = key_value(line) {
                if key.eq_ignore_ascii_case("path") {
                    // Paths are escaped in the file: C:\\Games\\SteamLibrary.
                    let path = PathBuf::from(value.replace("\\\\", "\\"));
                    if !libraries.contains(&path) {
                        libraries.push(path);
                    }
                }
            }
        }
    }

    libraries
}

/// Read every `appmanifest_*.acf` across every library.
pub fn installed_games() -> Vec<SteamApp> {
    let Some(root) = steam_root() else {
        return Vec::new();
    };

    let mut games = Vec::new();
    for library in library_paths(&root) {
        let steamapps = library.join("steamapps");
        let Ok(entries) = std::fs::read_dir(&steamapps) else {
            continue;
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with("appmanifest_") || !name.ends_with(".acf") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(entry.path()) else {
                continue;
            };
            let (Some(title), Some(directory)) =
                (find_value(&text, "name"), find_value(&text, "installdir"))
            else {
                continue;
            };

            // appmanifest_730.acf -> 730
            let app_id = name
                .trim_start_matches("appmanifest_")
                .trim_end_matches(".acf")
                .to_owned();

            let path = steamapps.join("common").join(&directory);
            games.push(SteamApp {
                name: title,
                path: path.display().to_string(),
                app_id,
            });
        }
    }

    games
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"
"AppState"
{
	"appid"		"730"
	"universe"		"1"
	"name"		"Counter-Strike 2"
	"StateFlags"		"4"
	"installdir"		"Counter-Strike Global Offensive"
	"SizeOnDisk"		"38654705664"
}
"#;

    #[test]
    fn the_app_id_comes_from_the_manifest_filename() {
        let name = "appmanifest_730.acf";
        assert_eq!(
            name.trim_start_matches("appmanifest_")
                .trim_end_matches(".acf"),
            "730"
        );
    }

    #[test]
    fn a_manifest_yields_the_name_and_directory() {
        // The pair that name matching alone can never connect.
        assert_eq!(
            find_value(MANIFEST, "name").as_deref(),
            Some("Counter-Strike 2")
        );
        assert_eq!(
            find_value(MANIFEST, "installdir").as_deref(),
            Some("Counter-Strike Global Offensive")
        );
    }

    #[test]
    fn lookup_is_case_insensitive_on_the_key() {
        assert_eq!(
            find_value(MANIFEST, "InstallDir").as_deref(),
            Some("Counter-Strike Global Offensive")
        );
    }

    #[test]
    fn a_missing_key_is_none() {
        assert!(find_value(MANIFEST, "nothing_like_this").is_none());
    }

    #[test]
    fn block_delimiters_are_not_mistaken_for_pairs() {
        assert!(key_value("{").is_none());
        assert!(key_value("}").is_none());
        assert!(
            key_value("\t\"AppState\"").is_none(),
            "one token is not a pair"
        );
    }

    #[test]
    fn only_the_first_two_tokens_of_a_line_are_taken() {
        let (key, value) = key_value("\t\"path\"\t\t\"D:\\\\SteamLibrary\"").unwrap();
        assert_eq!(key, "path");
        assert_eq!(value, "D:\\\\SteamLibrary");
    }

    #[test]
    fn this_machine_lists_steam_games_if_steam_is_installed() {
        // Informational rather than an assertion about the machine: a build box
        // without Steam must not fail the suite.
        match steam_root() {
            Some(root) => {
                let games = installed_games();
                println!("steam at {} with {} games", root.display(), games.len());
                assert!(
                    games.iter().all(|game| !game.name.trim().is_empty()),
                    "a game manifest produced an empty name"
                );
            }
            None => println!("steam not installed here; nothing to check"),
        }
    }
}
