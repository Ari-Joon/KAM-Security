//! Recognising this program's own files.
//!
//! # Why this has to exist
//!
//! Every clause of the following is true of this software's own agent on a
//! development install: nobody signed it, it runs as a service, and it lives in
//! a folder the user can write to. Those three together are the strongest
//! unsigned-file signal the provenance reader has, so the program put *itself*
//! at the top of the list of programs worth looking at.
//!
//! That is funny once and corrosive afterwards. A person who sees a security
//! tool accuse itself learns that the list is mechanical rather than
//! considered, and the whole product rests on the list being worth reading.
//!
//! # Disclosure, not exemption
//!
//! The fix is emphatically **not** to hide these files. Excusing yourself from
//! your own checks is what the software this replaces does when it exempts its
//! own installer, and it is what malware does when it allowlists itself. The
//! facts are also genuinely worth knowing: an unsigned service running as
//! LocalSystem out of a writable directory is a real weakness of *this install*,
//! and anybody who can write that directory owns the machine.
//!
//! So these files are identified rather than removed. They are named as this
//! program, kept out of the ranking against other people's software, and
//! everything true about them is still said — in a place where it reads as this
//! program disclosing its own position rather than as a finding about a
//! stranger.
//!
//! # Why not simply "anything in our folder"
//!
//! Because that is a hiding place. A directory-only rule means anything dropped
//! beside the agent inherits the exemption, which turns the install folder into
//! the one place on the machine this software will not look. So a file is ours
//! only if it is one of the names below *and* it sits in the directory this
//! process is running from. Both halves, or it is treated like anything else.

use std::path::{Path, PathBuf};

/// The files this program is made of.
///
/// Deliberately a short, explicit list rather than a pattern. `kam-*.exe` would
/// match anything an attacker cares to name, and the whole point of pairing
/// this with the directory check is that neither half is enough on its own.
pub const COMPONENTS: &[&str] = &["kam-agent.exe", "kam-shell.exe"];

/// The directory this process is running from.
///
/// `None` when it cannot be determined, and every caller treats that as "then
/// nothing is ours" — which errs towards this program appearing in its own
/// reports, rather than towards something else being mistaken for it.
pub fn our_directory() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()?
        .parent()
        .map(Path::to_path_buf)
}

/// Whether `path` is one of this program's own files.
pub fn is_ours(path: &Path) -> bool {
    let Some(directory) = our_directory() else {
        return false;
    };
    ours_within(&directory, path)
}

/// The same test against a stated directory, so it can be exercised without
/// depending on where the test binary happens to live.
pub fn ours_within(directory: &Path, path: &Path) -> bool {
    let Some(name) = path.file_name() else {
        return false;
    };
    let name = name.to_string_lossy().to_lowercase();
    if !COMPONENTS.contains(&name.as_str()) {
        return false;
    }
    match path.parent() {
        Some(parent) => same_place(parent, directory),
        None => false,
    }
}

/// Whether two paths name the same directory, as Windows compares them.
///
/// Case-insensitive, and separators folded, because one side comes from
/// `current_exe` and the other from a registry value somebody typed. Not
/// canonicalised: `canonicalize` opens the path, and this is called for every
/// file in a scan.
fn same_place(left: &Path, right: &Path) -> bool {
    let plain = |path: &Path| {
        path.to_string_lossy()
            .to_lowercase()
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_owned()
    };
    plain(left) == plain(right)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn this_programs_own_binaries_are_recognised() {
        let here = PathBuf::from(r"C:\Program Files\KAM Security");
        assert!(ours_within(&here, &here.join("kam-agent.exe")));
        assert!(ours_within(&here, &here.join("kam-shell.exe")));
        // However it was spelled on the way in.
        assert!(ours_within(
            &here,
            &PathBuf::from(r"c:\program files\kam security\KAM-AGENT.EXE")
        ));
    }

    /// Being in the folder is not enough, and neither is being called the
    /// right thing.
    ///
    /// This is the half that keeps the rule from becoming a hiding place. A
    /// directory-only rule makes the install folder the one place on the
    /// machine this software will not look, which is precisely what somebody
    /// who had just written to that folder would want.
    #[test]
    fn neither_half_is_enough_on_its_own() {
        let here = PathBuf::from(r"C:\Program Files\KAM Security");

        assert!(
            !ours_within(&here, &here.join("evil.exe")),
            "anything dropped beside the agent was treated as the agent"
        );
        assert!(
            !ours_within(&here, &here.join("kam-agent.exe.bak")),
            "a name that merely contains ours was treated as ours"
        );
        assert!(
            !ours_within(&here, &here.join("updater").join("kam-agent.exe")),
            "a subdirectory was treated as the install directory"
        );
        assert!(
            !ours_within(&here, &PathBuf::from(r"C:\Users\someone\kam-agent.exe")),
            "our name somewhere else was treated as ours"
        );
        assert!(
            !ours_within(
                &here,
                &PathBuf::from(r"C:\Program Files\KAM Security Pro\kam-agent.exe")
            ),
            "a directory whose name merely starts the same was treated as ours"
        );
    }

    #[test]
    fn the_running_binary_is_recognised_as_ours() {
        // True of the test harness too: it lives wherever cargo put it, which
        // is not the install directory, so this asserts the mechanism rather
        // than the deployment.
        let Some(directory) = our_directory() else {
            panic!("the running binary has no directory");
        };
        assert!(ours_within(&directory, &directory.join("kam-agent.exe")));
        assert!(!ours_within(
            &directory,
            &directory.join("something-else.exe")
        ));
    }
}
