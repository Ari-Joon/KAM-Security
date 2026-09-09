//! What a path actually points at, before anything is judged by it.
//!
//! # The bug class this exists to close
//!
//! Every fence in this crate decides whether a privileged file operation may
//! happen, and the paths they judge arrive as strings from a client, over a
//! pipe, into a process running as LocalSystem. A fence that reasons about the
//! *string* is only as strong as its author's knowledge of how many ways
//! Windows will spell the same object — and Windows will spell it many ways:
//!
//! - `\\?\C:\...`, the extended-length form, which skips the Win32 path parser.
//! - `\\?\UNC\server\share`, the same for network paths.
//! - `\??\C:\...`, the object-manager form.
//! - Forward slashes, which are separators throughout.
//! - `Name::$INDEX_ALLOCATION`, the directory's own index stream, which opens
//!   and renames exactly as the plain name does.
//! - `MICROS~1`, the 8.3 short name, present or absent per volume.
//! - `..`, and links pointing anywhere.
//!
//! Two of those were real holes rather than theoretical ones. The
//! extended-length prefix let `C:\Windows\System32\kernel32.dll` classify as
//! somewhere unrecognised rather than as Windows. The index-stream spelling let
//! `%LOCALAPPDATA%\Microsoft::$INDEX_ALLOCATION` past a deny list containing
//! `microsoft`, and moved the real directory.
//!
//! The lesson from both is the same, and it is why this module exists rather
//! than another string rule: **resolve first, then judge.** [`plain`] handles
//! the spellings that are pure text. [`resolved`] asks the filesystem, which
//! knows about all of them including the ones nobody here has thought of yet.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The plainest text form of a path: one separator, no prefix, lower case.
///
/// Text only — it does not touch the disk, so it is what to use when the path
/// need not exist, or when the cost of a filesystem call is not affordable.
/// [`resolved`] is stronger wherever it can be used.
pub(crate) fn plain(path: &str) -> String {
    let mut text = path.replace('/', "\\");

    // Order matters: the UNC form is a longer prefix of the extended one.
    for prefix in [r"\\?\UNC\", r"\??\UNC\"] {
        if let Some(rest) = text.strip_prefix(prefix) {
            text = format!(r"\\{rest}");
            return text.to_lowercase();
        }
    }
    for prefix in [r"\\?\", r"\??\", r"\\.\"] {
        if let Some(rest) = text.strip_prefix(prefix) {
            text = rest.to_owned();
            break;
        }
    }
    text.to_lowercase()
}

/// Whether any component of a path is a relative step.
///
/// Legitimate paths in this product are absolute and come from the master file
/// table or from a folder listing; neither produces `.` or `..`. A fence can
/// therefore refuse them outright, which is both simpler and stricter than
/// trying to work out where one would land.
pub(crate) fn has_relative_step(path: &str) -> bool {
    plain(path)
        .split('\\')
        .any(|part| part == ".." || part == ".")
}

/// The real path, with every alternate spelling and every link resolved.
///
/// Returns `None` when the path cannot be resolved at all, and callers are
/// expected to treat that as a refusal rather than falling back to the text:
/// something that cannot be located is not something to operate on as
/// LocalSystem.
///
/// # Why the loop
///
/// [`std::fs::canonicalize`] needs the path to exist, and a *destination* often
/// does not — that is the point of moving something there. So the deepest
/// ancestor that does exist is resolved, and the components below it are
/// appended unchanged. Those trailing components are names in a directory that
/// has been resolved, so nothing is being taken on trust: a link cannot hide in
/// a path that is not there yet.
pub(crate) fn resolved(path: &Path) -> Option<PathBuf> {
    let mut tail: Vec<OsString> = Vec::new();
    let mut current = path;

    loop {
        if let Ok(real) = std::fs::canonicalize(current) {
            let mut out = real;
            for part in tail.iter().rev() {
                out.push(part);
            }
            return Some(out);
        }
        // Not there yet: step up and remember the name.
        let parent = current.parent()?;
        tail.push(current.file_name()?.to_owned());
        current = parent;
    }
}

/// [`resolved`], as the plain text form the fences compare against.
pub(crate) fn resolved_plain(path: &str) -> Option<String> {
    let real = resolved(Path::new(path))?;
    Some(plain(&real.to_string_lossy()))
}

/// The real path of a directory a fence measures *from*.
///
/// # Both sides, or neither
///
/// A resolved path may only be compared against a resolved root. This is not a
/// nicety: `%LOCALAPPDATA%` is redirected for packaged applications, so
/// `C:\Users\someone\AppData\Local` resolves to
/// `...\AppData\Local\Packages\<package>\LocalCache\Local`. Judging a resolved
/// path against the root's own spelling made a directory sitting *directly*
/// inside Local AppData look several levels deep, and the fence refused it.
///
/// That was a false refusal rather than a false permission, so it broke the
/// feature instead of the safety — but the same mismatch runs the other way as
/// soon as a root is reached through a junction, which is ordinary on machines
/// with redirected profiles. Resolving both sides is the only version that is
/// right in both directions.
///
/// A root that cannot be resolved yields `None`, and a caller should skip it:
/// nothing can be inside a directory that is not there.
pub(crate) fn resolved_root(root: &str) -> Option<String> {
    existing_plain(root.trim_end_matches(['\\', '/']))
}

/// The real path of something that must already be there.
///
/// Stricter than [`resolved`], and the difference matters. `resolved` answers
/// for a path that does not exist yet by resolving its deepest existing
/// ancestor, which is what a move *destination* needs and exactly what a fence
/// over an existing object must not accept: `%LOCALAPPDATA%\NeverExisted` would
/// come back looking like a perfectly ordinary directory one level inside a data
/// root, because its parent is one.
///
/// Use this wherever the answer to "it is not there" should be a refusal rather
/// than a location.
pub(crate) fn existing_plain(path: &str) -> Option<String> {
    let real = std::fs::canonicalize(path).ok()?;
    Some(plain(&real.to_string_lossy()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn every_spelling_of_one_file_reduces_to_the_same_text() {
        let expected = r"c:\windows\system32\kernel32.dll";
        for spelling in [
            r"C:\Windows\System32\kernel32.dll",
            r"c:\windows\system32\kernel32.dll",
            r"C:/Windows/System32/kernel32.dll",
            r"\\?\C:\Windows\System32\kernel32.dll",
            r"\??\C:\Windows\System32\kernel32.dll",
            r"\\.\C:\Windows\System32\kernel32.dll",
        ] {
            assert_eq!(plain(spelling), expected, "{spelling} reduced wrongly");
        }
    }

    #[test]
    fn the_unc_form_keeps_its_double_leading_separator() {
        assert_eq!(plain(r"\\?\UNC\server\share\a.txt"), r"\\server\share\a.txt");
        assert_eq!(plain(r"\??\UNC\server\share"), r"\\server\share");
    }

    #[test]
    fn relative_steps_are_spotted_however_they_are_written() {
        assert!(has_relative_step(r"C:\Users\me\..\..\Windows"));
        assert!(has_relative_step(r"C:/Users/me/../Windows"));
        assert!(has_relative_step(r"\\?\C:\Users\me\.\a.txt"));
        assert!(!has_relative_step(r"C:\Users\me\Documents\a.txt"));
        // A name that merely contains dots is not a relative step.
        assert!(!has_relative_step(r"C:\Users\me\..config\a.txt"));
        assert!(!has_relative_step(r"C:\Users\me\file..txt"));
    }

    #[test]
    fn resolving_finds_the_real_name_behind_an_alternate_spelling() {
        // The index-stream spelling opens the directory and renames it, so a
        // fence that compares names must see through it. This is the exact
        // shape that got past the orphan deny list.
        let root = std::env::temp_dir().join("kam-paths-resolve");
        let victim = root.join("Microsoft");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&victim).unwrap();

        let sneaky = root.join("Microsoft::$INDEX_ALLOCATION");
        // Confirm the premise: Windows really does accept it as the directory.
        assert!(
            std::fs::symlink_metadata(&sneaky).is_ok_and(|m| m.is_dir()),
            "the premise no longer holds; this test needs revisiting"
        );

        let real = resolved(&sneaky).expect("the directory is there, so it resolves");
        assert!(
            plain(&real.to_string_lossy()).ends_with(r"\microsoft"),
            "{} still carries the stream spelling",
            real.display()
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_destination_that_does_not_exist_yet_still_resolves() {
        let root = std::env::temp_dir().join("kam-paths-destination");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let target = root.join("not-there").join("either").join("a.pdf");
        let real = resolved(&target).expect("the existing part resolves");
        let text = plain(&real.to_string_lossy());
        assert!(text.ends_with(r"\not-there\either\a.pdf"), "{text}");
        assert!(text.contains("kam-paths-destination"), "{text}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn something_that_cannot_be_located_at_all_resolves_to_nothing() {
        // A drive that is not there has no deepest existing ancestor, so this
        // is the case callers must refuse rather than guess about.
        assert!(resolved(Path::new(r"Q:\nowhere\a.txt")).is_none());
    }
}
