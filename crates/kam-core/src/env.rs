//! Expanding the `%NAME%` references Windows stores instead of paths.
//!
//! Windows records a great many paths with the variable left in: a service's
//! `ImagePath` as `%SystemRoot%\system32\thing.exe`, a shortcut's target as
//! `%windir%\system32\magnify.exe`. Treating one of those as a literal path
//! means every check against it fails, and the failures are quiet and
//! plausible-looking rather than loud.
//!
//! That cost real damage twice before this moved here. The auto-start reader
//! could not resolve half of what it found. The shortcut reader reported
//! Magnify, Narrator and the On-Screen Keyboard as pointing at missing files —
//! and that reader exists to offer removing shortcuts whose target is gone, so
//! the bug would have proposed deleting working Start Menu entries.

use crate::UserContext;

/// Expand `%NAME%` references against the current environment.
///
/// An unset variable is left exactly as written. Substituting an empty string
/// would turn `%NOPE%\thing.exe` into `\thing.exe`, which looks like a real
/// path and is not one; leaving it alone keeps the failure visible.
pub fn expand(text: &str) -> String {
    expand_with(text, lookup)
}

/// Expand `%NAME%` references as they would expand for one particular person.
///
/// A command stored in somebody's own hive or Startup folder runs in their
/// session, so `%TEMP%` there means *their* Temp. Expanded inside the agent,
/// which runs as LocalSystem, it meant `C:\Windows\TEMP` instead, and
/// `%LOCALAPPDATA%` meant SYSTEM's empty profile: a sign-in entry running
/// `%TEMP%\upd.exe` was judged as a file in a folder where it does not exist,
/// so what it actually runs was never looked at.
///
/// The per-user variables come from the person's [`UserContext`]; everything
/// else, such as `%SystemRoot%` and `%ProgramFiles%`, is the same for everyone
/// and comes from this process. For a context with no SID the process *is*
/// that person, so its own environment is already the right one and is used
/// unchanged.
pub fn expand_for(text: &str, user: &UserContext) -> String {
    expand_with(text, |name| per_user(name, user).or_else(|| lookup(name)))
}

/// The value of one per-user variable for this person, when it is one.
fn per_user(name: &str, user: &UserContext) -> Option<String> {
    user.sid()?;
    let value = match name.to_ascii_uppercase().as_str() {
        "USERPROFILE" => user.profile().to_owned(),
        "LOCALAPPDATA" => user.local_app_data(),
        "APPDATA" => user.roaming_app_data(),
        "TEMP" | "TMP" => user.temp(),
        "HOMEDRIVE" => user.home_drive()?,
        "HOMEPATH" => user.home_path()?,
        _ => return None,
    };
    (!value.is_empty()).then_some(value)
}

fn expand_with(text: &str, lookup: impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;

    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];

        match after.find('%') {
            Some(end) => {
                let name = &after[..end];
                // Windows variable names are case-insensitive: %windir% and
                // %WinDir% are the same thing, and shortcuts use both.
                match lookup(name) {
                    Some(value) => out.push_str(&value),
                    None => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                // A lone % with no closing pair is literal text.
                out.push('%');
                rest = after;
                break;
            }
        }
    }

    out.push_str(rest);
    out
}

fn lookup(name: &str) -> Option<String> {
    if name.is_empty() {
        return None;
    }
    if let Ok(value) = std::env::var(name) {
        return Some(value);
    }
    // std::env::var is case-sensitive on the name; Windows is not.
    std::env::vars()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_variable_is_replaced() {
        let expanded = expand(r"%SystemRoot%\System32\notepad.exe");
        assert!(!expanded.contains('%'), "left unexpanded: {expanded}");
        assert!(std::path::Path::new(&expanded).is_file(), "{expanded}");
    }

    #[test]
    fn the_name_is_matched_without_regard_to_case() {
        // The bug this module was extracted for: shortcuts store %windir%,
        // services store %SystemRoot%, and both must work.
        for spelling in ["%windir%", "%WINDIR%", "%WinDir%"] {
            let expanded = expand(&format!(r"{spelling}\System32\notepad.exe"));
            assert!(
                std::path::Path::new(&expanded).is_file(),
                "{spelling} did not expand to a real path: {expanded}"
            );
        }
    }

    #[test]
    fn an_unset_variable_is_left_alone_rather_than_blanked() {
        // Blanking would produce "\thing.exe", which reads as a real path.
        assert_eq!(
            expand(r"%KAM_DEFINITELY_NOT_SET%\thing.exe"),
            r"%KAM_DEFINITELY_NOT_SET%\thing.exe"
        );
    }

    #[test]
    fn text_without_variables_is_untouched() {
        assert_eq!(
            expand(r"C:\Program Files\App\app.exe"),
            r"C:\Program Files\App\app.exe"
        );
        assert_eq!(expand(""), "");
    }

    #[test]
    fn a_lone_percent_is_literal() {
        assert_eq!(expand("100% done"), "100% done");
        assert_eq!(expand("%"), "%");
    }

    #[test]
    fn several_variables_in_one_string_all_expand() {
        let expanded = expand("%SystemRoot%;%SystemRoot%");
        assert!(!expanded.contains('%'), "{expanded}");
        assert!(expanded.contains(';'));
    }

    /// A named person's own folders come from their profile, not this process.
    ///
    /// The bug: inside the LocalSystem agent a sign-in entry reading
    /// `%TEMP%\upd.exe` expanded to `C:\Windows\TEMP\upd.exe`, and
    /// `%LOCALAPPDATA%` to SYSTEM's profile, so what the entry runs was looked
    /// for where it is not.
    #[test]
    fn a_named_persons_variables_expand_to_their_own_folders() {
        let them = UserContext::new(Some("S-1-5-21-1-2-3-1001".to_owned()), r"C:\Users\them");
        for (stored, expected) in [
            (
                r"%TEMP%\upd.exe",
                r"C:\Users\them\AppData\Local\Temp\upd.exe",
            ),
            (
                r"%tmp%\upd.exe",
                r"C:\Users\them\AppData\Local\Temp\upd.exe",
            ),
            (
                r"%LOCALAPPDATA%\x\y.exe",
                r"C:\Users\them\AppData\Local\x\y.exe",
            ),
            (
                r"%AppData%\x\y.exe",
                r"C:\Users\them\AppData\Roaming\x\y.exe",
            ),
            (r"%USERPROFILE%\x.exe", r"C:\Users\them\x.exe"),
            (r"%HOMEDRIVE%%HOMEPATH%\x.exe", r"C:\Users\them\x.exe"),
        ] {
            assert_eq!(expand_for(stored, &them), expected, "{stored}");
        }
    }

    #[test]
    fn machine_wide_variables_still_expand_for_a_named_person() {
        let them = UserContext::new(Some("S-1-5-21-1-2-3-1001".to_owned()), r"C:\Users\them");
        assert_eq!(
            expand_for(r"%SystemRoot%\System32\notepad.exe", &them),
            expand(r"%SystemRoot%\System32\notepad.exe")
        );
        assert_eq!(
            expand_for(r"%KAM_DEFINITELY_NOT_SET%\x.exe", &them),
            r"%KAM_DEFINITELY_NOT_SET%\x.exe"
        );
    }

    #[test]
    fn the_running_account_keeps_its_own_environment() {
        // No SID means this process is that person, so nothing is derived.
        let me = UserContext::current();
        assert_eq!(expand_for(r"%TEMP%\x", &me), expand(r"%TEMP%\x"));
    }
}
