//! Resolving the indirect strings Windows uses for display names.
//!
//! Windows stores a great many user-visible names not as text but as a pointer
//! to text: `@%SystemRoot%\system32\thing.dll,-101` for a resource in a
//! library, or `@{Package_1.0.0_x64__abc?ms-resource://Package/Resources/Name}`
//! for one in an installed application package. Both mean "look this up in the
//! user's language", and both are meaningless to a person.
//!
//! `SHLoadIndirectString` performs that lookup. It lives here rather than in
//! one caller because two unrelated modules hit the same wall independently:
//! service display names in the scanner, and firewall rule names in the
//! firewall. On this machine 92 of 671 firewall rules are stored this way, so
//! showing them raw means a seventh of the list reads as machine noise.

use windows::core::PCWSTR;
use windows::Win32::UI::Shell::SHLoadIndirectString;

/// Resolve an indirect string, falling back when it cannot be looked up.
///
/// Anything not beginning with `@` is already text and is returned untouched.
/// An unresolvable reference returns `fallback` rather than the raw pointer:
/// showing `@{Microsoft.WindowsCalculator_11.2606.0.0_x64__8wekyb3d8bbwe?…}` to
/// a person is worse than showing nothing useful at all, because it looks like
/// corruption.
pub fn resolve(name: &str, fallback: &str) -> String {
    if !name.starts_with('@') {
        return name.to_owned();
    }

    let source: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // Package resource paths are long; this is generous enough for all of them.
    let mut buffer = [0_u16; 1024];

    if unsafe { SHLoadIndirectString(PCWSTR(source.as_ptr()), &mut buffer, None) }.is_ok() {
        let end = buffer
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(buffer.len());
        let text = String::from_utf16_lossy(&buffer[..end]).trim().to_owned();
        if !text.is_empty() {
            return text;
        }
    }

    fallback.to_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_passes_through_untouched() {
        assert_eq!(resolve("Windows Calculator", "x"), "Windows Calculator");
        assert_eq!(resolve("", "x"), "");
    }

    #[test]
    fn a_library_resource_reference_resolves() {
        // wscsvc is the Security Center service, present on every install.
        let resolved = resolve(r"@%SystemRoot%\system32\wscsvc.dll,-200", "wscsvc");
        assert!(!resolved.starts_with('@'), "left unresolved: {resolved}");
        println!("{resolved}");
    }

    #[test]
    fn an_unresolvable_reference_falls_back_rather_than_leaking() {
        // The property that matters: a raw pointer must never reach a screen.
        let resolved = resolve("@{NotARealPackage?ms-resource://nope/Nope}", "fallback");
        assert_eq!(resolved, "fallback");
    }

    #[test]
    fn nothing_beginning_with_an_at_sign_ever_escapes() {
        for input in [
            r"@%SystemRoot%\system32\missing-library-xyz.dll,-999",
            "@{Broken",
            "@",
        ] {
            let resolved = resolve(input, "fallback");
            assert!(
                !resolved.starts_with('@'),
                "{input} resolved to {resolved}, which still looks like a pointer"
            );
        }
    }
}
