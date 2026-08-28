//! Who signed a file, and whether Windows still believes it.
//!
//! This is the question everything else in the provenance engine hangs off.
//! Signed by a name you recognise, chaining to a root the machine trusts, is
//! the single strongest ordinary signal that a binary is what it claims. Its
//! absence is not proof of anything — plenty of legitimate software is
//! unsigned — but combined with where a file came from and when it appeared, it
//! is what turns a list of executables into a shortlist.
//!
//! # Two calls, because they answer different questions
//!
//! `WinVerifyTrust` answers "does Windows trust this", which is the whole chain
//! validation, revocation policy and catalogue lookup, and is not something to
//! reimplement. It does not readily hand back a name.
//!
//! `CryptQueryObject` opens the embedded signature and answers "whose
//! certificate is this", which is what a person actually reads. It says nothing
//! about validity: a revoked or expired certificate still has a name on it.
//!
//! Both are needed, and conflating them would be the mistake. A file signed by
//! a certificate that no longer validates is more interesting than an unsigned
//! one, not less, and that only shows up by asking both questions.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND, TRUST_E_NOSIGNATURE};
use windows::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
};
use windows::Win32::Security::Cryptography::{
    CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext, CertGetNameStringW,
    CryptMsgClose, CryptMsgGetParam, CryptQueryObject, CERT_FIND_SUBJECT_CERT, CERT_INFO,
    CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_CONTENT_TYPE_FLAGS,
    CERT_QUERY_ENCODING_TYPE, CERT_QUERY_FORMAT_FLAG_ALL, CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO,
    CMSG_SIGNER_INFO_PARAM, HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};
use windows::Win32::Security::WinTrust::{
    WinVerifyTrustEx, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA,
    WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};

/// What is known about a file's signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Signature {
    /// Signed, and the chain validates on this machine right now.
    Valid {
        signer: String,
        /// Set when a system catalogue vouched for the file rather than the
        /// file carrying its own signature. Worth distinguishing: it is how
        /// Windows signs Windows, and almost never how third-party software
        /// signs itself.
        catalogue: Option<String>,
    },
    /// Signed, but Windows will not accept it: expired, revoked, untrusted
    /// root, or tampered with since. The name is still worth showing —
    /// something claimed to be that publisher.
    Invalid {
        signer: Option<String>,
        reason: String,
    },
    /// No signature at all, embedded or catalogue.
    Unsigned,
    /// The file could not be read to find out.
    Unknown { reason: String },
}

impl Signature {
    pub fn signer(&self) -> Option<&str> {
        match self {
            Self::Valid { signer, .. } => Some(signer),
            Self::Invalid { signer, .. } => signer.as_deref(),
            _ => None,
        }
    }

    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid { .. })
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

/// What `WinVerifyTrust` said, sorted into the three cases that differ.
enum Trust {
    /// Windows accepts it. Carries the catalogue that vouched for it, when a
    /// catalogue rather than the file itself held the signature.
    Trusted(Option<PathBuf>),
    /// Nothing to check: no embedded signature and no catalogue entry.
    Absent,
    /// A signature exists and Windows rejects it. Far more interesting than
    /// having none.
    Rejected(String),
    /// The file could not be read to reach an answer. Distinct from every
    /// other case: saying "Windows rejected this" about a file nothing could
    /// open would be an accusation invented out of an I/O error.
    Unreadable(String),
}

/// Translate the trust result into something a person can act on.
///
/// Returning `None` means "not signed" rather than "rejected", and getting
/// that split right is the difference between a useful shortlist and one that
/// flags every text file on the disk.
fn unreadable(code: i32) -> Option<&'static str> {
    // These say something went wrong reaching the bytes, not that anything is
    // wrong with them. Windows Store applications are the common case: their
    // executables are reparse points that ordinary reads cannot follow.
    match code as u32 {
        0x8009_2003 => Some("the file could not be read"),
        0x8007_0002 => Some("the file was not there when it was checked"),
        0x8007_0005 => Some("this account is not allowed to read the file"),
        _ => None,
    }
}

fn describe_trust(code: i32) -> Option<String> {
    // Documented WinVerifyTrust returns. Written as raw values because the
    // bindings spell these constants differently in every crate version, and a
    // wrong constant here would silently mis-describe a real finding.
    let message = match code as u32 {
        // Nothing was signed, or the file is not a form trust understands (a
        // text file, a data blob). Neither is a rejection.
        0x800B_0100 | 0x800B_0003 | 0x800B_0001 => return None,

        0x8009_6010 => "the file has been altered since it was signed",
        0x8009_600E => "the file is not signed in a way that can be checked",
        0x8009_6002 => "the certificate that signed this could not be found",
        0x8009_6003 => "the signature could not be checked",
        0x8009_6004 => "the signature does not match the file",
        0x8009_6005 => "the timestamp on the signature is not valid",
        0x800B_0004 => "Windows does not trust this publisher",
        0x800B_0101 => "the signing certificate has expired",
        0x800B_0109 => "the certificate chain ends at a root this machine does not trust",
        0x800B_010A => "the certificate chain is incomplete",
        0x800B_010C => "the signing certificate has been revoked",
        0x800B_010D => "this is signed with a test certificate, not a real one",
        0x800B_0111 => "this publisher is explicitly distrusted on this machine",
        0x8009_2026 => "local security policy rejects this signature",

        // Anything unrecognised keeps its code, so an unexpected result is
        // diagnosable rather than flattened into a vague sentence.
        other => return Some(format!("Windows rejected the signature (0x{other:08X})")),
    };
    Some(message.to_owned())
}

/// Run the trust provider over a prepared `WINTRUST_DATA`.
///
/// The state must be released whatever the verdict, or the provider leaks a
/// context for every file examined — and this runs over several hundred.
fn run_provider(data: &mut WINTRUST_DATA) -> i32 {
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // No window handle and no UI: this runs inside a service with no desktop,
    // where a trust dialog would block forever.
    let outcome = unsafe { WinVerifyTrustEx(HWND::default(), &mut action, data) };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrustEx(HWND::default(), &mut action, data);
    }
    outcome
}

/// Check the signature embedded in the file itself.
fn verify_embedded(path: &Path) -> i32 {
    let file = wide(path);
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(file.as_ptr()),
        hFile: HANDLE::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        // Revocation checking reaches the network. Over several hundred
        // binaries that is minutes of stalls, and the question here — does this
        // machine trust the signer — does not require it.
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        ..Default::default()
    };

    run_provider(&mut data)
}

/// Open a file for the catalogue hash, sharing freely so a running executable
/// can still be examined.
fn open_for_read(path: &Path) -> Option<HANDLE> {
    let file = wide(path);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(file.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .ok()?;
    Some(handle)
}

/// Ask a catalogue administrator for this file's hash, under one algorithm.
fn catalogue_hash(admin: isize, handle: HANDLE) -> Option<Vec<u8>> {
    let mut size = 0_u32;
    unsafe { CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut size, None, None) }.ok()?;
    if size == 0 {
        return None;
    }
    let mut hash = vec![0_u8; size as usize];
    unsafe {
        CryptCATAdminCalcHashFromFileHandle2(
            admin,
            handle,
            &mut size,
            Some(hash.as_mut_ptr()),
            None,
        )
    }
    .ok()?;
    Some(hash)
}

/// Check whether a system catalogue vouches for the file.
///
/// Most of Windows is signed this way: the binary carries no signature at all,
/// and a `.cat` file elsewhere lists its hash. Checking only embedded
/// signatures would report the entire operating system as unsigned, which
/// would make the whole layer worse than useless — it would bury the handful of
/// genuinely unsigned binaries in several hundred false ones.
fn verify_catalogue(path: &Path) -> Option<(i32, PathBuf)> {
    let handle = open_for_read(path)?;

    // SHA-256 for anything current; SHA-1 for catalogues old enough to predate
    // it. Passing no algorithm at all would silently mean SHA-1 only.
    let result = [w!("SHA256"), w!("SHA1")]
        .into_iter()
        .find_map(|algorithm| catalogue_attempt(handle, path, algorithm));

    unsafe {
        let _ = CloseHandle(handle);
    }
    result
}

fn catalogue_attempt(handle: HANDLE, path: &Path, algorithm: PCWSTR) -> Option<(i32, PathBuf)> {
    let mut admin: isize = 0;
    unsafe { CryptCATAdminAcquireContext2(&mut admin, None, algorithm, None, None) }.ok()?;

    let outcome = (|| {
        let hash = catalogue_hash(admin, handle)?;
        let context = unsafe { CryptCATAdminEnumCatalogFromHash(admin, &hash, None, None) };
        if context == 0 {
            return None;
        }

        let mut info = CATALOG_INFO {
            cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32,
            wszCatalogFile: [0; 260],
        };
        let found = unsafe { CryptCATCatalogInfoFromContext(context, &mut info, 0) }.is_ok();

        let verdict = found.then(|| {
            let end = info
                .wszCatalogFile
                .iter()
                .position(|c| *c == 0)
                .unwrap_or(info.wszCatalogFile.len());
            let catalogue = PathBuf::from(String::from_utf16_lossy(&info.wszCatalogFile[..end]));

            // The member tag is the file's hash as uppercase hex; that is how
            // the catalogue indexes its entries.
            let mut tag: Vec<u16> = hash
                .iter()
                .flat_map(|byte| format!("{byte:02X}").into_bytes())
                .map(u16::from)
                .collect();
            tag.push(0);

            let catalogue_path = wide(&catalogue);
            let member = wide(path);
            let mut hash_copy = hash.clone();

            let mut catalogue_info = WINTRUST_CATALOG_INFO {
                cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
                pcwszCatalogFilePath: PCWSTR(catalogue_path.as_ptr()),
                pcwszMemberTag: PCWSTR(tag.as_ptr()),
                pcwszMemberFilePath: PCWSTR(member.as_ptr()),
                hMemberFile: handle,
                pbCalculatedFileHash: hash_copy.as_mut_ptr(),
                cbCalculatedFileHash: hash_copy.len() as u32,
                hCatAdmin: admin,
                ..Default::default()
            };

            let mut data = WINTRUST_DATA {
                cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
                dwUIChoice: WTD_UI_NONE,
                fdwRevocationChecks: WTD_REVOKE_NONE,
                dwUnionChoice: WTD_CHOICE_CATALOG,
                Anonymous: WINTRUST_DATA_0 {
                    pCatalog: &mut catalogue_info,
                },
                dwStateAction: WTD_STATEACTION_VERIFY,
                ..Default::default()
            };

            (run_provider(&mut data), catalogue)
        });

        unsafe {
            let _ = CryptCATAdminReleaseCatalogContext(admin, context, 0);
        }
        verdict
    })();

    unsafe {
        let _ = CryptCATAdminReleaseContext(admin, 0);
    }
    outcome
}

/// Ask Windows whether it trusts the file, by either route.
fn verify_trust(path: &Path) -> Trust {
    let embedded = verify_embedded(path);
    if embedded == 0 {
        return Trust::Trusted(None);
    }

    // Only fall back to the catalogue when the file itself carried nothing. A
    // file with a *broken* embedded signature has already answered the
    // question, and asking again would let a tampered binary pass on the
    // strength of a catalogue entry for a version it no longer matches.
    if let Some(reason) = unreadable(embedded) {
        return Trust::Unreadable(reason.to_owned());
    }

    if embedded == TRUST_E_NOSIGNATURE.0 {
        if let Some((verdict, catalogue)) = verify_catalogue(path) {
            return match verdict {
                0 => Trust::Trusted(Some(catalogue)),
                other => match describe_trust(other) {
                    Some(reason) => Trust::Rejected(reason),
                    None => Trust::Absent,
                },
            };
        }
    }

    match describe_trust(embedded) {
        Some(reason) => Trust::Rejected(reason),
        None => Trust::Absent,
    }
}

/// Read the signer's name out of the embedded signature.
///
/// Independent of whether the signature validates: the name is what a person
/// reads, and "signed by X but no longer trusted" is a more useful sentence
/// than either half alone.
fn signer_name(path: &Path) -> Option<String> {
    let file = wide(path);
    let mut store = HCERTSTORE::default();
    let mut message: *mut std::ffi::c_void = std::ptr::null_mut();

    unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            file.as_ptr() as *const _,
            // Two shapes, because the two things asked about are different
            // files. An executable holds its signature embedded in itself; a
            // catalogue *is* a signed message. Asking for the union lets one
            // function answer for both.
            CERT_QUERY_CONTENT_TYPE_FLAGS(
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED.0
                    | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED.0,
            ),
            CERT_QUERY_FORMAT_FLAG_ALL,
            0,
            None,
            None,
            None,
            Some(&mut store),
            Some(&mut message),
            None,
        )
    }
    .ok()?;

    // `CryptQueryObject` can succeed having filled in only the certificate
    // store — a catalogue queried with a permissive content mask is one such
    // case. Reading the message handle unconditionally then dereferences null.
    if message.is_null() {
        unsafe {
            let _ = CertCloseStore(Some(store), 0);
        }
        return None;
    }

    let mut name = None;

    // Two calls: the first asks how large the signer info is, the second reads
    // it into a buffer of that size.
    let mut needed = 0_u32;
    let sized = unsafe { CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, None, &mut needed) };

    if sized.is_ok() && needed > 0 {
        let mut buffer = vec![0_u8; needed as usize];
        let read = unsafe {
            CryptMsgGetParam(
                message,
                CMSG_SIGNER_INFO_PARAM,
                0,
                Some(buffer.as_mut_ptr() as *mut _),
                &mut needed,
            )
        };

        if read.is_ok() {
            // The buffer begins with a CMSG_SIGNER_INFO, whose first two
            // fields after the version are the issuer and serial number that
            // identify the certificate in the store.
            let info = buffer.as_ptr() as *const CMSG_SIGNER_INFO;
            let mut criteria = CERT_INFO {
                Issuer: unsafe { (*info).Issuer },
                SerialNumber: unsafe { (*info).SerialNumber },
                ..Default::default()
            };

            let certificate = unsafe {
                CertFindCertificateInStore(
                    store,
                    CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0),
                    0,
                    CERT_FIND_SUBJECT_CERT,
                    Some(&mut criteria as *mut _ as *const _),
                    None,
                )
            };

            if !certificate.is_null() {
                let length = unsafe {
                    CertGetNameStringW(certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None)
                };
                if length > 1 {
                    let mut text = vec![0_u16; length as usize];
                    unsafe {
                        CertGetNameStringW(
                            certificate,
                            CERT_NAME_SIMPLE_DISPLAY_TYPE,
                            0,
                            None,
                            Some(&mut text),
                        )
                    };
                    let end = text.iter().position(|c| *c == 0).unwrap_or(text.len());
                    let display = String::from_utf16_lossy(&text[..end]);
                    if !display.is_empty() {
                        name = Some(display);
                    }
                }
                unsafe {
                    let _ = CertFreeCertificateContext(Some(certificate));
                }
            }
        }
    }

    unsafe {
        let _ = CryptMsgClose(Some(message));
        let _ = CertCloseStore(Some(store), 0);
    }

    name
}

/// Determine a file's signature state.
pub fn of(path: &Path) -> Signature {
    if !path.exists() {
        return Signature::Unknown {
            reason: "the file is not there".to_owned(),
        };
    }

    match verify_trust(path) {
        Trust::Trusted(catalogue) => {
            // A catalogue-signed file carries no certificate of its own; the
            // name lives in the catalogue that vouched for it.
            let source = catalogue.as_deref().unwrap_or(path);
            Signature::Valid {
                signer: signer_name(source).unwrap_or_else(|| "an unnamed signer".to_owned()),
                catalogue: catalogue.map(|path| path.display().to_string()),
            }
        }
        Trust::Absent => Signature::Unsigned,
        Trust::Rejected(reason) => Signature::Invalid {
            signer: signer_name(path),
            reason,
        },
        Trust::Unreadable(reason) => Signature::Unknown { reason },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_windows_binary_is_signed_and_trusted() {
        // notepad is signed by Microsoft and present on every install. If this
        // fails, the verification plumbing is wrong rather than the machine.
        let signature = of(Path::new(r"C:\Windows\System32\notepad.exe"));
        assert!(
            signature.is_valid(),
            "notepad should verify, got {signature:?}"
        );
        println!("notepad: {signature:?}");
        let signer = signature.signer().unwrap_or_default();
        assert!(
            signer.to_lowercase().contains("microsoft"),
            "unexpected signer: {signer}"
        );
    }

    #[test]
    fn a_text_file_is_unsigned_rather_than_invalid() {
        // The distinction the whole engine rests on: never signed is a
        // different statement from signed and no longer trusted.
        let path = std::env::temp_dir().join(format!("kam-sig-{}.txt", std::process::id()));
        std::fs::write(&path, b"not an executable").unwrap();
        assert_eq!(of(&path), Signature::Unsigned);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_missing_file_is_unknown_rather_than_unsigned() {
        let signature = of(Path::new(r"C:\this\does\not\exist.exe"));
        assert!(matches!(signature, Signature::Unknown { .. }));
    }

    #[test]
    fn our_own_binary_reports_something_coherent() {
        // Unsigned, since releases are not signed -- which is itself the
        // honest answer and worth asserting so it cannot silently change.
        let exe = std::env::current_exe().unwrap();
        let signature = of(&exe);
        println!("{}: {signature:?}", exe.display());
        assert!(!matches!(signature, Signature::Unknown { .. }));
    }
}
