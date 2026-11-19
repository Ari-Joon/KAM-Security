//! What the measuring pages last found, kept for the person who found it.
//!
//! Storage, Applications and Cleanup each show a measurement that takes a
//! while, and each opened empty every time: "Nothing measured yet", after a
//! restart and after leaving the page and coming back. Each page now keeps
//! its last completed result here and shows it, with when it was measured,
//! until it is measured again.
//!
//! # Where, and why there
//!
//! In the person's own Local AppData, `%LOCALAPPDATA%\KAM Security\Remembered`,
//! one file for each page's result. The window writes and reads it, and the
//! window runs as the person, so it is theirs in the way everything else in
//! their profile is: another account cannot read it without being an
//! administrator, and the service never holds it.
//!
//! The service's own store was the other choice, keyed by the SID the pipe
//! gives, as scan summaries are. It was not taken. A page's result is the
//! page's own state, shaped by the page and changed by it as rows are acted
//! on, which the service does not know about. Kept by the service it would
//! be sent back and forth across the pipe for no reason, it would put several
//! megabytes per person into a store that holds the audit log, and keeping it
//! to its owner would rest on the service getting the caller right every
//! time, where here Windows' own permissions do it.
//!
//! # Bounded
//!
//! A fixed set of names, one file each, each at most [`MAX_BYTES`], so the
//! folder can never hold more than [`KINDS`] times that. A newer result
//! replaces the older one whole: it is written beside it and moved over it,
//! so a crash midway leaves the older one or the newer one, never half.
//!
//! # Read back, or said not to be
//!
//! A file that is not there is "nothing kept", and only that. A file that is
//! there and cannot be read, or is too large, or is not JSON, is an error
//! with its reason, so the page says it could not be read back rather than
//! showing an empty page as if nothing had ever been measured.

use std::path::{Path, PathBuf};

/// The results a page may keep. The name becomes a file name, so nothing
/// else is accepted.
pub const KINDS: [&str; 5] = [
    "storage",
    "applications",
    "cleanup-survey",
    "cleanup-duplicates",
    "cleanup-caches",
];

/// Largest result kept, as written. A page keeps at most what one answer
/// from the service could carry, and a little for its own notes.
pub const MAX_BYTES: usize = kam_ipc::MAX_FRAME_BYTES + 1024 * 1024;

/// The person's folder for kept results.
pub fn folder() -> PathBuf {
    folder_of(&kam_core::UserContext::current())
}

fn folder_of(user: &kam_core::UserContext) -> PathBuf {
    PathBuf::from(user.local_app_data())
        .join(kam_core::PRODUCT_NAME)
        .join("Remembered")
}

fn file_for(folder: &Path, kind: &str) -> Result<PathBuf, String> {
    if !KINDS.contains(&kind) {
        return Err(format!("\"{kind}\" is not a result a page keeps"));
    }
    Ok(folder.join(format!("{kind}.json")))
}

/// Keep `json` as the latest result of this kind, in place of the last.
pub fn remember_in(folder: &Path, kind: &str, json: &str) -> Result<(), String> {
    let file = file_for(folder, kind)?;
    if json.len() > MAX_BYTES {
        return Err(format!(
            "it is {} MB, and a kept result is at most {} MB",
            json.len().div_ceil(1024 * 1024),
            MAX_BYTES / (1024 * 1024)
        ));
    }
    serde_json::from_str::<serde_json::Value>(json)
        .map_err(|error| format!("it is not JSON: {error}"))?;

    std::fs::create_dir_all(folder)
        .map_err(|error| format!("{} could not be made: {error}", folder.display()))?;
    let beside = folder.join(format!("{kind}.json.new"));
    std::fs::write(&beside, json)
        .map_err(|error| format!("{} could not be written: {error}", beside.display()))?;
    std::fs::rename(&beside, &file).map_err(|error| {
        let _ = std::fs::remove_file(&beside);
        format!("{} could not be replaced: {error}", file.display())
    })
}

/// The latest result of this kind as it was kept, or `None` when none is.
pub fn recall_in(folder: &Path, kind: &str) -> Result<Option<String>, String> {
    let file = file_for(folder, kind)?;
    let size = match std::fs::metadata(&file) {
        Ok(data) => data.len(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{} could not be read: {error}", file.display())),
    };
    if size > MAX_BYTES as u64 {
        return Err(format!(
            "{} is larger than a kept result can be",
            file.display()
        ));
    }
    let json = std::fs::read_to_string(&file)
        .map_err(|error| format!("{} could not be read: {error}", file.display()))?;
    serde_json::from_str::<serde_json::Value>(&json)
        .map_err(|error| format!("{} is not readable: {error}", file.display()))?;
    Ok(Some(json))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("kam-remembered-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        path
    }

    #[test]
    fn a_result_kept_is_given_back_as_it_was_and_replaced_whole_by_the_next() {
        let folder = scratch("kept");
        assert_eq!(
            recall_in(&folder, "storage").unwrap(),
            None,
            "nothing kept yet"
        );

        remember_in(
            &folder,
            "storage",
            r#"{"shape":1,"measured_at":1,"result":"first"}"#,
        )
        .unwrap();
        remember_in(
            &folder,
            "storage",
            r#"{"shape":1,"measured_at":2,"result":"second"}"#,
        )
        .unwrap();
        assert_eq!(
            recall_in(&folder, "storage").unwrap().as_deref(),
            Some(r#"{"shape":1,"measured_at":2,"result":"second"}"#)
        );
        // Kinds are kept apart, and nothing is left beside the file.
        assert_eq!(recall_in(&folder, "applications").unwrap(), None);
        let names: Vec<String> = std::fs::read_dir(&folder)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["storage.json".to_owned()]);
        std::fs::remove_dir_all(&folder).unwrap();
    }

    /// The name becomes a file name, so only the pages' own are taken.
    #[test]
    fn only_the_pages_own_kinds_are_kept_or_read() {
        let folder = scratch("kinds");
        for kind in [
            "",
            "Storage",
            "storage.json",
            r"..\storage",
            "../storage",
            "nothing",
        ] {
            assert!(
                remember_in(&folder, kind, "{}").is_err(),
                "{kind:?} was kept"
            );
            assert!(recall_in(&folder, kind).is_err(), "{kind:?} was read");
        }
        assert!(!folder.exists(), "a refused name still made the folder");
    }

    /// A kept result that cannot be read back says so. It is never taken for
    /// nothing having been kept.
    #[test]
    fn a_kept_result_that_cannot_be_read_back_is_an_error_and_not_nothing() {
        let folder = scratch("damaged");
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(
            folder.join("cleanup-survey.json"),
            r#"{"shape":1,"result":["#,
        )
        .unwrap();
        let refusal = recall_in(&folder, "cleanup-survey").unwrap_err();
        assert!(refusal.contains("is not readable"), "{refusal}");

        // Too large to be one of ours: refused before it is read.
        let large = std::fs::File::create(folder.join("cleanup-caches.json")).unwrap();
        large.set_len(MAX_BYTES as u64 + 1).unwrap();
        drop(large);
        let refusal = recall_in(&folder, "cleanup-caches").unwrap_err();
        assert!(refusal.contains("larger than"), "{refusal}");
        std::fs::remove_dir_all(&folder).unwrap();
    }

    /// Nothing larger than the bound, and nothing that is not JSON, is kept,
    /// so the folder stays within [`KINDS`] times [`MAX_BYTES`].
    #[test]
    fn a_result_too_large_or_not_json_is_not_kept() {
        let folder = scratch("bounds");
        let too_large = format!("\"{}\"", "x".repeat(MAX_BYTES));
        let refusal = remember_in(&folder, "storage", &too_large).unwrap_err();
        assert!(refusal.contains("at most"), "{refusal}");
        assert!(remember_in(&folder, "storage", "not json").is_err());
        assert_eq!(recall_in(&folder, "storage").unwrap(), None);
        let _ = std::fs::remove_dir_all(&folder);
    }

    /// The folder is the person's own, in their profile's Local AppData.
    #[test]
    fn results_are_kept_in_the_persons_own_local_app_data() {
        let someone = kam_core::UserContext::new(None, r"C:\Users\someone");
        assert_eq!(
            folder_of(&someone),
            PathBuf::from(r"C:\Users\someone\AppData\Local\KAM Security\Remembered")
        );
    }
}
