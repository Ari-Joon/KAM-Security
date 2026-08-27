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

/// Expand `%NAME%` references against the current environment.
///
/// An unset variable is left exactly as written. Substituting an empty string
/// would turn `%NOPE%\thing.exe` into `\thing.exe`, which looks like a real
/// path and is not one; leaving it alone keeps the failure visible.
pub fn expand(text: &str) -> String {
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
        assert_eq!(expand(r"C:\Program Files\App\app.exe"), r"C:\Program Files\App\app.exe");
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
}
