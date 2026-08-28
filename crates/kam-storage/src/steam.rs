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

use crate::registry::View;
use kam_core::UserContext;

/// Windows' path separator, spelled once so escaping it is not a hazard.
const SEPARATOR: &str = r"\";

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
    /// When it was last played, in seconds since the Unix epoch.
    ///
    /// Steam writes this itself and it is the only reliable answer for a game.
    /// Explorer's launch history never sees one: Steam starts the game, so the
    /// person launched Steam, and every title on the machine shows as never
    /// opened. That is exactly what it did before this was read.
    pub last_played: Option<u64>,
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
///
/// Recorded per-user, which is why this needs to know which user. Read from the
/// wrong hive it simply is not there, and every Steam library along with it.
fn steam_root(user: &UserContext) -> Option<PathBuf> {
    let key = user.open_key(r"Software\Valve\Steam", View::Native)?;
    // Steam writes this with forward slashes, which Windows accepts anyway.
    key.string("SteamPath").map(PathBuf::from)
}

/// Every library folder, including ones on other drives.
///
/// The main install is always a library even though it is not always listed as
/// one, so it is added regardless.
fn library_paths(root: &Path) -> Vec<PathBuf> {
    let mut libraries = vec![tidy(root)];

    let manifest = root.join("steamapps").join("libraryfolders.vdf");
    if let Ok(text) = std::fs::read_to_string(&manifest) {
        for line in text.lines() {
            if let Some((key, value)) = key_value(line) {
                if key.eq_ignore_ascii_case("path") {
                    // Paths are escaped in the file: C:\\Games\\SteamLibrary.
                    let path = tidy(&PathBuf::from(value.replace("\\\\", "\\")));
                    if !libraries.iter().any(|known| same_place(known, &path)) {
                        libraries.push(path);
                    }
                }
            }
        }
    }

    libraries
}

/// Put a path into one shape.
///
/// Steam writes its own install directory into the registry with forward
/// slashes and a lowercase drive letter, and writes that same folder into
/// `libraryfolders.vdf` in ordinary Windows form. They are one directory, and
/// without this it is found twice under two spellings -- which showed up as the
/// same download cache being listed, measured and offered for clearing twice.
fn tidy(path: &Path) -> PathBuf {
    let text = path.to_string_lossy().replace('/', SEPARATOR);
    PathBuf::from(text.trim_end_matches(SEPARATOR))
}

fn same_place(a: &Path, b: &Path) -> bool {
    a.to_string_lossy()
        .eq_ignore_ascii_case(&b.to_string_lossy())
}

/// Every library folder on this machine, for anything that needs to look
/// inside one without caring what is installed there.
pub fn library_roots(user: &UserContext) -> Vec<PathBuf> {
    steam_root(user)
        .map(|root| library_paths(&root))
        .unwrap_or_default()
}

/// Read every `appmanifest_*.acf` across every library.
pub fn installed_games(user: &UserContext) -> Vec<SteamApp> {
    let Some(root) = steam_root(user) else {
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
                // Absent, or zero, for a game that has been installed and
                // never started. Zero would otherwise read as January 1970.
                last_played: find_value(&text, "LastPlayed")
                    .and_then(|value| value.parse::<u64>().ok())
                    .filter(|seconds| *seconds > 0),
            });
        }
    }

    games
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "reads this machine's real Steam library"]
    fn every_installed_game_carries_a_date_or_honestly_carries_none() {
        let games = installed_games(&UserContext::current());
        if games.is_empty() {
            return;
        }
        let played = games
            .iter()
            .filter(|game| game.last_played.is_some())
            .count();
        println!(
            "
{} games, {played} with a last-played time",
            games.len()
        );
        for game in games.iter().take(12) {
            println!("  {:<44} {:?}", game.name, game.last_played);
        }
        for game in &games {
            if let Some(seconds) = game.last_played {
                assert!(
                    (1_100_000_000..4_102_444_800).contains(&seconds),
                    "{} has an implausible time: {seconds}",
                    game.name
                );
            }
        }
    }

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
        match steam_root(&kam_core::UserContext::current()) {
            Some(root) => {
                let games = installed_games(&kam_core::UserContext::current());
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
