//! Storing the user's VirusTotal API key.
//!
//! The key is a credential. It is not ours, it is not shared, and it is worth
//! money to whoever takes it — a stolen key is someone else's quota and
//! someone else's account standing. So it is never written to disk in the
//! clear.
//!
//! # DPAPI rather than a file with a scary name
//!
//! `CryptProtectData` encrypts under a key derived from the user's own logon
//! credentials. The result can only be decrypted by this Windows account, on
//! this machine. Copying the file to another machine, or reading it from
//! another account on this one, yields nothing.
//!
//! An extra entropy value is mixed in, which means the blob cannot be decrypted
//! by any *other* program running as this user that has not been told the same
//! value. That is a modest bar — the entropy is in this source file, which is
//! public — but it stops the file being trivially readable by unrelated
//! software that merely calls the DPAPI defaults, and it costs nothing.
//!
//! No key is bundled with this product and none ever will be. The user brings
//! their own, from their own account, and it stays theirs.

use std::path::{Path, PathBuf};

use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
};

/// Mixed into the encryption so the blob is not readable by any process that
/// merely calls DPAPI with default parameters.
const ENTROPY: &[u8] = b"KAM Security/VirusTotal API key/v1";

/// Where the encrypted key lives.
///
/// Under the roaming profile so it follows a domain user between machines —
/// where, being DPAPI-protected under credentials that roam with them, it will
/// still decrypt.
pub fn key_path() -> kam_core::Result<PathBuf> {
    let base = std::env::var("APPDATA").map_err(|_| {
        kam_core::Error::Refused("this account has no application data folder".to_owned())
    })?;
    Ok(PathBuf::from(base)
        .join("KAM Security")
        .join("virustotal.key"))
}

fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    }
}

/// Copy an output blob out and release what Windows allocated for it.
fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    if out.pbData.is_null() || out.cbData == 0 {
        return Vec::new();
    }
    let copied = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
    unsafe {
        // DPAPI allocates with LocalAlloc, so this is the matching free.
        let _ = LocalFree(Some(HLOCAL(out.pbData as *mut core::ffi::c_void)));
    }
    copied
}

/// Encrypt and store the key.
pub fn store(key: &str) -> kam_core::Result<()> {
    store_at(&key_path()?, key)
}

/// Read and decrypt the stored key, if there is one.
pub fn load() -> Option<String> {
    load_from(&key_path().ok()?)
}

/// Forget the stored key.
pub fn clear() -> kam_core::Result<()> {
    clear_at(&key_path()?)
}

/// The three above name one fixed file. These take the path instead, so tests
/// can exercise the encryption without touching -- or destroying -- the key a
/// real person has stored.
fn store_at(path: &Path, key: &str) -> kam_core::Result<()> {
    let key = key.trim();
    if key.is_empty() {
        return clear_at(path);
    }

    // A VirusTotal v3 key is 64 lowercase hex characters. Checking here turns
    // a confusing 401 later into a clear message now.
    if !is_plausible(key) {
        return Err(kam_core::Error::Refused(
            "That does not look like a VirusTotal API key. They are 64 characters of \
             letters and digits, found under your VirusTotal profile."
                .to_owned(),
        ));
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let input = blob(key.as_bytes());
    let entropy = blob(ENTROPY);
    let mut output = CRYPT_INTEGER_BLOB::default();

    unsafe {
        CryptProtectData(
            &input,
            windows::core::w!("KAM Security VirusTotal key"),
            Some(&entropy),
            None,
            None,
            0,
            &mut output,
        )
    }
    .map_err(|error| {
        kam_core::Error::Refused(format!(
            "the key could not be encrypted for storage: {error}"
        ))
    })?;

    let sealed = take(output);
    std::fs::write(path, &sealed)?;
    Ok(())
}

/// Read and decrypt a stored key.
///
/// A key that cannot be decrypted is treated as absent rather than as an
/// error: that is what happens to a file copied from another account, and the
/// useful response is to ask for the key again.
fn load_from(path: &Path) -> Option<String> {
    let sealed = std::fs::read(path).ok()?;
    if sealed.is_empty() {
        return None;
    }

    let input = blob(&sealed);
    let entropy = blob(ENTROPY);
    let mut output = CRYPT_INTEGER_BLOB::default();

    unsafe {
        CryptUnprotectData(&input, None, Some(&entropy), None, None, 0, &mut output).ok()?;
    }

    let plain = take(output);
    let key = String::from_utf8(plain).ok()?;
    (!key.is_empty()).then_some(key)
}

fn clear_at(path: &Path) -> kam_core::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        // Already absent is the desired state, not a failure.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Whether a key is stored, without decrypting or returning it.
pub fn is_present() -> bool {
    load().is_some()
}

/// Whether a string has the shape of a VirusTotal key.
fn is_plausible(key: &str) -> bool {
    key.len() == 64 && key.chars().all(|c| c.is_ascii_alphanumeric())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A file of this test's own, so nothing here can disturb the key the
    /// person running the tests actually uses.
    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("kam-vt-key-{}-{name}", std::process::id()))
    }

    #[test]
    fn a_key_survives_a_round_trip() {
        let path = scratch("roundtrip");
        let sample = "a".repeat(64);

        store_at(&path, &sample).unwrap();
        assert_eq!(load_from(&path).as_deref(), Some(sample.as_str()));

        clear_at(&path).unwrap();
        assert_eq!(load_from(&path), None);
    }

    #[test]
    fn the_stored_file_does_not_contain_the_key() {
        // The entire point of this module. If this fails, a credential is
        // sitting in the clear in the user's profile.
        let path = scratch("secrecy");
        let sample = "b".repeat(64);
        store_at(&path, &sample).unwrap();

        let raw = std::fs::read(&path).unwrap();
        assert!(
            !raw.windows(sample.len())
                .any(|window| window == sample.as_bytes()),
            "the key was written to disk in the clear"
        );
        assert!(!raw.is_empty(), "nothing was written at all");

        clear_at(&path).unwrap();
    }

    #[test]
    fn another_entropy_value_cannot_read_it() {
        // DPAPI ties the blob to this account; the entropy ties it to this
        // program. Checking the second half holds.
        let path = scratch("entropy");
        store_at(&path, &"c".repeat(64)).unwrap();

        let sealed = std::fs::read(&path).unwrap();
        let input = blob(&sealed);
        let wrong = blob(b"some other program's entropy");
        let mut output = CRYPT_INTEGER_BLOB::default();
        let opened =
            unsafe { CryptUnprotectData(&input, None, Some(&wrong), None, None, 0, &mut output) };
        assert!(opened.is_err(), "the blob opened with the wrong entropy");

        clear_at(&path).unwrap();
    }

    #[test]
    fn a_malformed_key_is_refused_with_an_explanation() {
        let outcome = store_at(&scratch("malformed"), "not-a-real-key");
        assert!(outcome.is_err());
        let message = outcome.unwrap_err().to_string();
        assert!(
            message.contains("64 characters"),
            "the refusal should say what a key looks like: {message}"
        );
    }

    #[test]
    fn an_empty_key_clears_rather_than_failing() {
        // Emptying the box in the interface is how a person removes their key.
        let path = scratch("empty");
        store_at(&path, &"d".repeat(64)).unwrap();
        store_at(&path, "   ").unwrap();
        assert_eq!(load_from(&path), None);
    }

    #[test]
    fn clearing_something_already_absent_is_not_a_failure() {
        assert!(clear_at(&scratch("never-existed")).is_ok());
    }

    #[test]
    fn key_shape_is_checked() {
        assert!(is_plausible(&"0123456789abcdef".repeat(4)));
        assert!(!is_plausible("short"));
        assert!(!is_plausible(&"a".repeat(63)));
        assert!(!is_plausible(&"-".repeat(64)));
    }
}
