//! What a program says about itself, from its own version resource.
//!
//! # This is a claim, not evidence
//!
//! Everything here is read out of the file, and the file was written by whoever
//! made it. A program can call itself "Google Chrome" and name Google as its
//! company by typing those words into its own resources; nothing checks them and
//! nothing can. Malware does exactly this, because it works.
//!
//! So this is here to make a list *legible*, never to establish what something
//! is. `svchost.exe` forty times over is unreadable; a column saying "Host
//! Process for Windows Services" is not. That is the whole job.
//!
//! The part that cannot be typed in is the Authenticode signer, which is a
//! cryptographic claim someone can be held to. Where both are shown, the signer
//! is the one that means anything, and an interface built on this module should
//! make that ordering obvious rather than presenting the two as equals.
//!
//! # Why not just the file name
//!
//! Because the file name is what an attacker picks. A description that
//! disagrees with the signer is more interesting than either alone: "Google
//! Chrome", signed by nobody, sitting in a temp folder is a sentence worth
//! reading, and it needs the claim *and* the verification to be sayable at all.

use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};

/// What a file claims about itself. Every field is the file's own word.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Claims {
    /// `FileDescription`: the human sentence, and the one Explorer shows.
    /// "Host Process for Windows Services", "Google Chrome".
    pub description: Option<String>,
    /// `ProductName`: the suite it belongs to. Often broader than the file.
    pub product: Option<String>,
    /// `CompanyName`: who it says wrote it. Unverified, unlike a signer.
    pub company: Option<String>,
}

impl Claims {
    /// True when the file said nothing at all.
    pub fn is_empty(&self) -> bool {
        self.description.is_none() && self.product.is_none() && self.company.is_none()
    }

    /// The best single line to show, or nothing.
    ///
    /// Description first because it is the sentence written for a person to
    /// read; product second because it is at least a name; and nothing rather
    /// than the file name, which the caller already has and which this module
    /// must never appear to have confirmed.
    pub fn best(&self) -> Option<&str> {
        self.description
            .as_deref()
            .or(self.product.as_deref())
            .filter(|text| !text.is_empty())
    }
}

fn wide(text: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// How many elements of `T` can be read at `value` without leaving `block`.
///
/// # Why this exists at all
///
/// `VerQueryValueW` hands back a pointer *into* the block along with a length,
/// and is never told how big the block is — it can only bound itself using the
/// resource's own header fields, and those were written by whoever wrote the
/// file. Every one of these files is attacker-chosen and this runs inside a
/// LocalSystem process, so "the API told me the length" is not a safety
/// argument, it is a hope.
///
/// Adversarial review built a version block by hand with a lying length field
/// and called the real `VerQueryValueW` on this build of Windows: the honest
/// length came back clamped, and the oversized lie was rejected. So there is no
/// live out-of-bounds read here. That is a fact about Windows 11 26200's
/// implementation, though, not about this code — and the same reasoning
/// ("the platform validates it") is the one this codebase has refused
/// everywhere else. So the length is bounded here too, and the OS check becomes
/// the second line rather than the only one.
fn fits<T>(block: &[u8], value: *const core::ffi::c_void, count: u32) -> Option<usize> {
    let start = block.as_ptr() as usize;
    let offset = (value as usize).checked_sub(start)?;
    if offset > block.len() {
        return None;
    }
    let remaining = block.len() - offset;
    let wanted = (count as usize).checked_mul(std::mem::size_of::<T>())?;
    (wanted <= remaining).then_some(count as usize)
}

/// Read one string from an already-loaded version block.
///
/// # Safety
///
/// `block` must be the buffer filled by `GetFileVersionInfoW`, and `language`
/// the eight hex digits of a translation that block actually contains. Both
/// hold at the single call site below.
///
/// # The unit is characters here and bytes below
///
/// `VerQueryValueW` reports the length of a **string** value in `u16`
/// characters, and the length of a **binary** value in bytes. The translation
/// lookup further down is a binary value and is therefore counted differently.
/// Confirmed by measurement rather than read from documentation. Writing it
/// down because the two reads look identical and unifying them would silently
/// halve or double a bound.
unsafe fn string_value(block: &[u8], language: &str, name: &str) -> Option<String> {
    let query = wide(&format!(r"\StringFileInfo\{language}\{name}"));
    let mut value: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut length = 0_u32;

    let found = unsafe {
        VerQueryValueW(
            block.as_ptr() as *const core::ffi::c_void,
            PCWSTR(query.as_ptr()),
            &mut value,
            &mut length,
        )
    };
    if !found.as_bool() || value.is_null() || length == 0 {
        return None;
    }

    // Characters, not bytes. See the note above, and `fits` for why the answer
    // is checked rather than taken.
    let count = fits::<u16>(block, value, length)?;
    let characters = unsafe { std::slice::from_raw_parts(value as *const u16, count) };
    let text = String::from_utf16_lossy(characters);
    let text = text.trim_end_matches('\0').trim().to_owned();
    (!text.is_empty()).then_some(text)
}

/// Read what a file says about itself.
///
/// `None` when the file has no version resource at all, which is ordinary: many
/// perfectly legitimate programs ship without one, and its absence is not a
/// finding.
pub fn claims_of(path: &Path) -> Option<Claims> {
    let file = wide(&path.to_string_lossy());

    // Size first, then contents. A zero size means no resource.
    let mut handle = 0_u32;
    let size = unsafe { GetFileVersionInfoSizeW(PCWSTR(file.as_ptr()), Some(&mut handle)) };
    if size == 0 {
        return None;
    }
    // A resource this large is not one of ours to read.
    if size > 4 * 1024 * 1024 {
        return None;
    }

    let mut block = vec![0_u8; size as usize];
    unsafe {
        GetFileVersionInfoW(
            PCWSTR(file.as_ptr()),
            None,
            size,
            block.as_mut_ptr() as *mut core::ffi::c_void,
        )
    }
    .ok()?;

    // Which translation the strings are under. A file can carry several; the
    // first is the one Explorer shows, and picking the same one keeps this
    // consistent with what the person would see if they looked themselves.
    let language = unsafe {
        let query = wide(r"\VarFileInfo\Translation");
        let mut value: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut length = 0_u32;
        let found = VerQueryValueW(
            block.as_ptr() as *const core::ffi::c_void,
            PCWSTR(query.as_ptr()),
            &mut value,
            &mut length,
        );
        // Bytes here, not characters: this is a binary value, unlike the string
        // reads above. Two `u16` is four bytes, which is what `length >= 4`
        // checks, and `fits` re-checks the same span against the block.
        if found.as_bool()
            && !value.is_null()
            && length >= 4
            && fits::<u16>(&block, value, 2).is_some()
        {
            let parts = std::slice::from_raw_parts(value as *const u16, 2);
            format!("{:04x}{:04x}", parts[0], parts[1])
        } else {
            // US English, Unicode. The overwhelmingly common case, and a
            // reasonable guess when the file did not say.
            "040904b0".to_owned()
        }
    };

    let claims = unsafe {
        Claims {
            description: string_value(&block, &language, "FileDescription"),
            product: string_value(&block, &language, "ProductName"),
            company: string_value(&block, &language, "CompanyName"),
        }
    };

    (!claims.is_empty()).then_some(claims)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_windows_binary_describes_itself() {
        // Every supported machine has this one, and it carries a full resource.
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
        let path = std::path::PathBuf::from(root).join(r"System32\svchost.exe");

        let claims = claims_of(&path).expect("svchost.exe has a version resource");
        let best = claims.best().expect("it says something about itself");

        // The point of the whole module: this is more use than "svchost.exe".
        assert!(best.len() > "svchost.exe".len(), "{best:?}");
        assert_eq!(
            claims.company.as_deref(),
            Some("Microsoft Corporation"),
            "claims: {claims:?}"
        );
    }

    /// Nothing is read outside the block, whatever length comes back.
    ///
    /// `VerQueryValueW` returns a pointer into the block and a length, and is
    /// never told how large the block is — it can only bound itself with the
    /// resource's own header fields, which the file's author wrote. Adversarial
    /// review established that this build of Windows does validate them, so
    /// there is no live out-of-bounds read; this pins the bound anyway, because
    /// "the platform checks it" is the argument this codebase has refused
    /// everywhere else and a future build is not obliged to keep checking.
    #[test]
    fn a_length_that_runs_past_the_block_is_refused() {
        let block = vec![0_u8; 64];
        let base = block.as_ptr() as *const core::ffi::c_void;

        // Exactly fits: 32 characters of u16 in 64 bytes.
        assert_eq!(fits::<u16>(&block, base, 32), Some(32));
        // One past the end.
        assert_eq!(fits::<u16>(&block, base, 33), None);
        // A length that would overflow the multiply rather than merely exceed.
        assert_eq!(fits::<u16>(&block, base, u32::MAX), None);

        // A pointer partway in still bounds against what is left, not the whole.
        let middle = unsafe { block.as_ptr().add(60) } as *const core::ffi::c_void;
        assert_eq!(fits::<u16>(&block, middle, 2), Some(2));
        assert_eq!(fits::<u16>(&block, middle, 3), None);

        // A pointer outside the block entirely is refused rather than wrapped.
        let elsewhere = [0_u8; 8];
        assert_eq!(
            fits::<u16>(&block, elsewhere.as_ptr() as *const core::ffi::c_void, 1),
            None,
            "a pointer from somewhere else was accepted"
        );
    }

    #[test]
    fn a_file_with_no_resource_says_nothing_rather_than_guessing() {
        let scratch = std::env::temp_dir().join(format!("kam-version-{}.txt", std::process::id()));
        std::fs::write(&scratch, b"not a program").unwrap();

        assert!(
            claims_of(&scratch).is_none(),
            "a text file was read as having claims"
        );

        let _ = std::fs::remove_file(&scratch);
    }

    #[test]
    fn a_path_that_is_not_there_is_not_an_error() {
        assert!(claims_of(std::path::Path::new(r"C:\nowhere\at\all.exe")).is_none());
    }

    #[test]
    fn nothing_is_offered_when_the_file_said_nothing() {
        let empty = Claims::default();
        assert!(empty.is_empty());
        assert_eq!(empty.best(), None, "an empty claim must not become a label");
    }
}
