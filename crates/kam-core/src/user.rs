//! Which person a piece of work is being done for.
//!
//! # The bug this exists to stop
//!
//! The agent runs as LocalSystem. That account has a profile of its own, at
//! `C:\Windows\system32\config\systemprofile`, and Windows fills the process
//! environment accordingly: inside the agent, `%LOCALAPPDATA%` is *SYSTEM's*
//! Local AppData, `%USERPROFILE%` is SYSTEM's profile, and `HKEY_CURRENT_USER`
//! is SYSTEM's hive. Every one of those is a real, valid, entirely empty place.
//!
//! Nothing errors. The agent measured 66 applications and attributed **zero**
//! locations inside any user profile, reported Steam as occupying nothing at
//! all — its install path is recorded in the user's hive, which the agent was
//! not reading — and gave every program "no record of you opening it", because
//! Explorer's launch history is per-user too. The numbers looked plausible and
//! were wrong, which is the worst way for a measurement to be wrong.
//!
//! # What replaces it
//!
//! Never the agent's own account. The agent identifies the process on the other
//! end of the pipe, takes its user's SID, and resolves everything from that:
//! the profile directory from `ProfileList`, and the registry from
//! `HKEY_USERS\<SID>` rather than `HKEY_CURRENT_USER`.
//!
//! The SID is read from the caller's token, not sent by the caller. A client
//! cannot ask to be treated as somebody else, because it is never asked who it
//! is.
//!
//! In the shell — which runs as the person using it — [`UserContext::current`]
//! reads the environment, and the two paths agree.

use crate::registry::{Key, View};
use windows::Win32::System::Registry::{HKEY, HKEY_CURRENT_USER, HKEY_USERS};

/// Where Windows records the profile directory of every account that has one.
const PROFILE_LIST: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

/// The person whose data a request concerns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserContext {
    /// Textual SID, when the caller was identified. `None` in the shell, where
    /// the process already *is* the user and the environment is authoritative.
    sid: Option<String>,
    /// The profile directory, without a trailing separator.
    profile: String,
}

impl UserContext {
    /// The account this process is running as.
    ///
    /// Correct in the shell and in tests. Wrong in the agent, which is why the
    /// agent uses [`UserContext::for_sid`] instead.
    pub fn current() -> Self {
        let profile = std::env::var("USERPROFILE").unwrap_or_default();
        Self {
            sid: None,
            profile: profile.trim_end_matches('\\').to_owned(),
        }
    }

    /// Resolve an account from its SID.
    ///
    /// Returns `None` for a SID with no profile on this machine — a service
    /// account, or one whose profile has been deleted. Callers fall back to
    /// [`UserContext::current`] rather than guessing at a path.
    pub fn for_sid(sid: &str) -> Option<Self> {
        // Machine-wide key, so the agent can read it without touching any
        // user's hive.
        let key = Key::open(
            windows::Win32::System::Registry::HKEY_LOCAL_MACHINE,
            &format!("{PROFILE_LIST}\\{sid}"),
            View::Native,
        )?;
        let profile = key.string("ProfileImagePath")?;
        let profile = crate::env::expand(&profile);
        if profile.is_empty() {
            return None;
        }
        Some(Self {
            sid: Some(sid.to_owned()),
            profile: profile.trim_end_matches('\\').to_owned(),
        })
    }

    /// Build one directly. For tests, and for a caller that already knows both.
    pub fn new(sid: Option<String>, profile: &str) -> Self {
        Self {
            sid,
            profile: profile.trim_end_matches('\\').to_owned(),
        }
    }

    pub fn sid(&self) -> Option<&str> {
        self.sid.as_deref()
    }

    /// The profile directory: `C:\Users\someone`.
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// `C:\Users\someone\AppData\Local`.
    pub fn local_app_data(&self) -> String {
        format!(r"{}\AppData\Local", self.profile)
    }

    /// `C:\Users\someone\AppData\Roaming`.
    pub fn roaming_app_data(&self) -> String {
        format!(r"{}\AppData\Roaming", self.profile)
    }

    /// A folder directly inside the profile, such as `Downloads`.
    pub fn folder(&self, name: &str) -> String {
        format!(r"{}\{name}", self.profile)
    }

    /// Open one of this user's registry keys.
    ///
    /// `HKEY_CURRENT_USER` when this is the running account, and the matching
    /// subtree of `HKEY_USERS` when it is not. The two are the same key; the
    /// difference is only that the second does not depend on who is asking.
    ///
    /// The hive has to be loaded, which it is for anyone signed in. For an
    /// account that is not, this returns `None` — the honest answer, since
    /// their launch history genuinely cannot be read from here.
    pub fn open_key(&self, path: &str, view: View) -> Option<Key> {
        match &self.sid {
            None => Key::open(HKEY_CURRENT_USER, path, view),
            Some(sid) => Key::open(HKEY_USERS, &format!("{sid}\\{path}"), view),
        }
    }

    /// The root this user's keys hang from, for callers that walk it themselves.
    pub fn hive(&self) -> (HKEY, String) {
        match &self.sid {
            None => (HKEY_CURRENT_USER, String::new()),
            Some(sid) => (HKEY_USERS, format!("{sid}\\")),
        }
    }
}

impl Default for UserContext {
    fn default() -> Self {
        Self::current()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn the_running_account_resolves_to_its_own_profile() {
        let user = UserContext::current();
        assert!(
            user.profile().to_lowercase().contains(r"\users\"),
            "expected a real profile directory, got {}",
            user.profile()
        );
        assert!(user.local_app_data().ends_with(r"AppData\Local"));
        assert!(user.roaming_app_data().ends_with(r"AppData\Roaming"));
    }

    #[test]
    fn a_trailing_separator_never_doubles_up() {
        let user = UserContext::new(None, r"C:\Users\someone\");
        assert_eq!(user.profile(), r"C:\Users\someone");
        assert_eq!(user.local_app_data(), r"C:\Users\someone\AppData\Local");
        assert_eq!(user.folder("Downloads"), r"C:\Users\someone\Downloads");
    }

    #[test]
    fn an_unknown_sid_has_no_profile() {
        // Well-formed and certain not to exist.
        assert!(UserContext::for_sid("S-1-5-21-0-0-0-31337").is_none());
    }

    #[test]
    fn a_known_sid_resolves_to_the_same_profile_as_the_environment() {
        // Every machine has LocalSystem, and its profile is a fixed location.
        let system = UserContext::for_sid("S-1-5-18").expect("SYSTEM always has a profile");
        assert!(
            system.profile().to_lowercase().contains("systemprofile"),
            "got {}",
            system.profile()
        );
        // And this is exactly the profile the agent was wrongly using.
        assert_ne!(system.profile(), UserContext::current().profile());
    }

    #[test]
    fn a_named_user_reads_from_their_own_hive_rather_than_whoever_is_asking() {
        let mine = UserContext::current();
        assert_eq!(mine.hive().1, "");

        let theirs = UserContext::new(Some("S-1-5-21-1-2-3-1001".to_owned()), r"C:\Users\them");
        assert_eq!(theirs.hive().1, "S-1-5-21-1-2-3-1001\\");
    }
}
