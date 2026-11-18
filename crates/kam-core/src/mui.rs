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

/// The application package an indirect string names, when it names one.
///
/// A Store application's rule, task or service is registered as
/// `@{<Name>_<version>_<architecture>__<publisher id>?ms-resource://...}`. The
/// part before the first underscore is the application's own identity: stable,
/// and readable where the whole pointer is not.
pub fn package_of(reference: &str) -> Option<&str> {
    let inner = reference.strip_prefix("@{")?;
    let name = inner.split(['_', '?', '}']).next()?;
    (!name.is_empty()).then_some(name)
}

/// A name fit to put in front of a person, whoever is asking.
///
/// [`resolve`], with a fallback that can still be read. A pointer into a
/// package can only be looked up by an account that package is installed for,
/// and one left behind by a version since replaced cannot be looked up by
/// anybody. Both happen: of the 65 rules named this way on the machine this
/// was written on, 22 point at versions that are gone. Those are shown as the
/// package's name and the fact that it could not be looked up, which is true
/// and is not a line of punctuation.
pub fn display(name: &str) -> String {
    if !name.starts_with('@') {
        return name.to_owned();
    }
    let fallback = match package_of(name) {
        Some(package) => format!("{package} (its name could not be looked up)"),
        None => "a name that could not be looked up".to_owned(),
    };
    resolve(name, &fallback)
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
    fn a_package_pointer_names_its_package() {
        assert_eq!(
            package_of(
                "@{Microsoft.WindowsAlarms_11.2607.6.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.WindowsAlarms/Resources/AppStoreName}"
            ),
            Some("Microsoft.WindowsAlarms")
        );
        // Not a package pointer, or not enough of one to name anything.
        assert_eq!(package_of(r"@%SystemRoot%\system32\wscsvc.dll,-200"), None);
        assert_eq!(package_of("@{"), None);
        assert_eq!(package_of("Windows Clock"), None);
    }

    /// What a person sees when the lookup fails is words, not the pointer.
    ///
    /// The Firewall page listed a seventh of its rules as raw pointers, because
    /// the lookup ran in the service, for whom no Store application is
    /// installed, and the fallback was the pointer itself.
    #[test]
    fn a_pointer_that_cannot_be_looked_up_is_shown_as_its_package() {
        let shown = display(
            "@{KamSecurity.NoSuchApp_1.0.0.0_x64__0000000000000?ms-resource://KamSecurity.NoSuchApp/Resources/AppName}",
        );
        assert_eq!(
            shown,
            "KamSecurity.NoSuchApp (its name could not be looked up)"
        );
        assert_eq!(display("@{"), "a name that could not be looked up");
        assert_eq!(display("Windows Clock"), "Windows Clock");
        assert_eq!(display(""), "");
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
