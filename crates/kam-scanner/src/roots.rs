//! The certificate authorities this PC trusts, and which of them are on
//! Microsoft's own list.
//!
//! # Why this is in a security tool
//!
//! A certificate in a trusted root store lets whoever holds its key present
//! any website to this PC with a valid padlock, in every program that uses
//! Windows' own store. Security products add one to look inside encrypted
//! traffic, debugging proxies add one, a game launcher on the development
//! machine added one for itself, and so does malware that wants to read
//! somebody's bank. Windows lists them only in a console few people open.
//!
//! # "On Microsoft's list"
//!
//! Windows keeps a copy of the list of root authorities Microsoft publishes,
//! fetched by its automatic root update, in the registry. Each certificate is
//! looked up in that copy with Windows' own certificate functions, which key
//! the list on each certificate's thumbprint. That one is not on it is a fact
//! with a source and a date, and not a verdict: one that a program the person
//! installed added on purpose is not on it either.
//!
//! Nothing is fetched from the network. When the copy is not on this PC
//! (automatic root update can be switched off by policy), that is said, and
//! the certificates are still listed by store.

use std::ffi::c_void;

use kam_core::changes::Unreadable;
use kam_core::registry::{Key, Unopened, View};
use kam_core::UserContext;
use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::{GetLastError, CRYPT_E_NOT_FOUND, ERROR_NO_MORE_FILES, FILETIME};
use windows::Win32::Security::Cryptography::{
    CertCloseStore, CertCreateCTLContext, CertEnumCertificatesInStore, CertFindSubjectInCTL,
    CertFreeCTLContext, CertGetCertificateContextProperty, CertGetNameStringW, CertOpenStore,
    CERT_CONTEXT, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_ENCODING_TYPE, CERT_SHA1_HASH_PROP_ID,
    CERT_STORE_PROV_REG, CERT_STORE_READONLY_FLAG, CTL_CERT_SUBJECT_TYPE, CTL_CONTEXT, HCERTSTORE,
    PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};
use windows::Win32::System::Registry::{HKEY, HKEY_LOCAL_MACHINE};

/// The token a trusted root certificate is filed under in What changed.
///
/// Stored, so never renamed: see [`crate::persistence::Anchor::kind`].
pub const ROOT_CERTIFICATE: &str = "root_certificate";

/// The machine's root stores: where each is, how it is described, and
/// whether Windows fills it by itself.
///
/// The registry is where Windows keeps them (Microsoft: "System Store
/// Locations"), read in its native view.
const MACHINE_STORES: &[(&str, &str, bool)] = &[
    (
        r"SOFTWARE\Microsoft\SystemCertificates\ROOT",
        "The machine's own root store",
        false,
    ),
    (
        AUTHROOT,
        "The root store Windows fills by itself from Microsoft's list",
        true,
    ),
    (
        r"SOFTWARE\Microsoft\EnterpriseCertificates\Root",
        "The root store an organisation fills",
        false,
    ),
    (
        r"SOFTWARE\Policies\Microsoft\SystemCertificates\Root",
        "The root store group policy fills",
        false,
    ),
];

/// The store Windows fills by itself, as certificates are met that are on
/// Microsoft's list.
const AUTHROOT: &str = r"SOFTWARE\Microsoft\SystemCertificates\AuthRoot";

/// Each account's own root stores, in its own hive.
const ACCOUNT_STORES: &[(&str, &str)] = &[
    (
        r"Software\Microsoft\SystemCertificates\Root",
        "This account's own root store",
    ),
    (
        r"Software\Policies\Microsoft\SystemCertificates\Root",
        "The root store group policy fills for this account",
    ),
];

/// Where Windows keeps its copy of Microsoft's list, and when it fetched it.
const AUTO_UPDATE: &str = r"SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate";

/// What a list that is not there is said as. The words the owner approved.
const NOT_ON_THIS_PC: &str =
    "Microsoft's list is not on this PC, so the certificates could not be compared with it";

/// How certificates and lists are encoded, as every Windows store holds them.
const ENCODING: u32 = X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0;

/// Everything read, and what could not be.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    /// Each root store that is there, the machine's and the asking account's.
    pub stores: Vec<Store>,
    /// Microsoft's list as cached on this PC, or why it could not be used.
    pub list: List,
    /// Stores that could not be read, with the kind and place they rule
    /// nothing out about, so What changed can hold to the same gaps.
    pub unreadable: Vec<Unreadable>,
}

/// One root store, as read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Store {
    /// What it is, for a person.
    pub label: String,
    /// The key it is kept in, so it can be found by hand.
    pub location: String,
    /// The profile folder of the account it belongs to, or `None` for one of
    /// the machine's.
    pub account: Option<String>,
    /// True for the store Windows fills by itself, which grows as sites are
    /// visited.
    pub fills_itself: bool,
    /// By name, then thumbprint.
    pub certificates: Vec<Certificate>,
}

/// One trusted root certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Certificate {
    /// Its SHA-1 thumbprint in capitals, as Windows shows it, and what
    /// Microsoft's list is keyed on.
    pub thumbprint: String,
    /// The name it gives itself.
    pub name: String,
    /// When it stops being valid, in the store's ISO form.
    pub expires: Option<String>,
    /// Whether it is on Microsoft's list. `None` when the list could not be
    /// used, which is not the same as not being on it.
    pub listed: Option<bool>,
}

/// Microsoft's list as cached on this PC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum List {
    /// There, and read.
    Cached {
        /// When Windows last fetched it, when that is recorded.
        fetched: Option<String>,
        /// How many authorities it lists.
        entries: usize,
    },
    /// Not there, or not readable, and why, in a sentence.
    Missing { why: String },
}

impl Default for List {
    fn default() -> Self {
        Self::Missing {
            why: NOT_ON_THIS_PC.to_owned(),
        }
    }
}

/// A list held open, freed when dropped.
#[derive(Debug)]
struct Ctl(*mut CTL_CONTEXT);

impl Drop for Ctl {
    fn drop(&mut self) {
        unsafe {
            let _ = CertFreeCTLContext(Some(self.0));
        }
    }
}

/// Microsoft's list as cached on this PC, held open so that certificates can
/// be looked up in it.
#[derive(Debug)]
pub struct MicrosoftList {
    ctl: Option<Ctl>,
    state: List,
}

impl MicrosoftList {
    /// The copy Windows keeps, with when it was fetched.
    pub fn read() -> Self {
        Self::from_key(Key::look(HKEY_LOCAL_MACHINE, AUTO_UPDATE, View::Native))
    }

    /// The copy held in a key laid out as Windows lays out its own, so a test
    /// can supply one.
    fn from_key(key: Result<Key, Unopened>) -> Self {
        let key = match key {
            Ok(key) => key,
            Err(Unopened::Absent) => return Self::missing(NOT_ON_THIS_PC.to_owned()),
            Err(why) => {
                return Self::missing(format!(
                    "{}, so the certificates could not be compared with it",
                    why.describe("Microsoft's list")
                ))
            }
        };
        let Some(encoded) = key.binary("EncodedCtl") else {
            return Self::missing(NOT_ON_THIS_PC.to_owned());
        };
        let fetched = key
            .binary("LastSyncTime")
            .and_then(|bytes| bytes.get(..8).map(<[u8]>::to_vec))
            .and_then(|bytes| {
                let mut stamp = [0_u8; 8];
                stamp.copy_from_slice(&bytes);
                iso_of(u64::from_le_bytes(stamp))
            });
        Self::from_encoded(&encoded, fetched)
    }

    /// A list from its encoded form, as Windows stores it.
    pub fn from_encoded(encoded: &[u8], fetched: Option<String>) -> Self {
        let ctl = unsafe { CertCreateCTLContext(ENCODING, encoded) };
        if ctl.is_null() {
            return Self::missing(
                "Microsoft's list is on this PC but could not be read as a list, so the \
                 certificates could not be compared with it"
                    .to_owned(),
            );
        }
        let entries = unsafe { (*ctl).pCtlInfo.as_ref() }
            .map(|info| info.cCTLEntry as usize)
            .unwrap_or(0);
        Self {
            ctl: Some(Ctl(ctl)),
            state: List::Cached { fetched, entries },
        }
    }

    fn missing(why: String) -> Self {
        Self {
            ctl: None,
            state: List::Missing { why },
        }
    }

    /// What is known about the list, for the page.
    pub fn state(&self) -> &List {
        &self.state
    }

    /// Whether a certificate is on the list, asked of Windows' own lookup.
    /// `None` when there is no list to ask.
    fn lists(&self, certificate: *const CERT_CONTEXT) -> Option<bool> {
        let ctl = self.ctl.as_ref()?;
        let entry = unsafe {
            CertFindSubjectInCTL(
                ENCODING,
                CTL_CERT_SUBJECT_TYPE,
                certificate.cast::<c_void>(),
                ctl.0,
                0,
            )
        };
        Some(!entry.is_null())
    }
}

/// Every root store, the machine's and the asking person's own, with each
/// certificate looked up in Microsoft's list.
pub fn survey(user: &UserContext) -> Report {
    let list = MicrosoftList::read();
    let mut unreadable = Vec::new();
    let mut stores = machine_stores(&list, &mut unreadable);
    if let Some(own) = account_stores(user, &list, &mut unreadable) {
        stores.extend(own);
    }
    Report {
        stores,
        list: list.state().clone(),
        unreadable,
    }
}

/// The machine's root stores that are there.
pub fn machine_stores(list: &MicrosoftList, unreadable: &mut Vec<Unreadable>) -> Vec<Store> {
    MACHINE_STORES
        .iter()
        .filter_map(|(path, label, fills_itself)| {
            read_store(
                HKEY_LOCAL_MACHINE,
                path,
                &format!(r"HKLM\{path}"),
                label,
                None,
                *fills_itself,
                list,
                unreadable,
            )
        })
        .collect()
}

/// One account's own root stores that are there, read from its own hive.
///
/// `None` when the account's hive is not there once read: an account that
/// signed out while being read would otherwise look as though its own
/// certificates had been removed.
pub fn account_stores(
    user: &UserContext,
    list: &MicrosoftList,
    unreadable: &mut Vec<Unreadable>,
) -> Option<Vec<Store>> {
    let (hive, prefix) = user.hive();
    let stores = ACCOUNT_STORES
        .iter()
        .filter_map(|(path, label)| {
            let shown = match user.sid() {
                Some(sid) => format!(r"HKEY_USERS\{sid}\{path}"),
                None => format!(r"HKCU\{path}"),
            };
            read_store(
                hive,
                &format!("{prefix}{path}"),
                &shown,
                label,
                Some(user.profile()),
                false,
                list,
                unreadable,
            )
        })
        .collect();
    (!crate::persistence::hive_gone(user)).then_some(stores)
}

/// A certificate store held open, closed when dropped.
struct Opened(HCERTSTORE);

impl Drop for Opened {
    fn drop(&mut self) {
        unsafe {
            let _ = CertCloseStore(Some(self.0), 0);
        }
    }
}

/// One store kept in the registry, read with Windows' own certificate
/// functions.
///
/// `None` for a store whose key is not there, which holds nothing, and for
/// one that would not read, which is then among `unreadable`.
#[allow(clippy::too_many_arguments)]
fn read_store(
    root: HKEY,
    path: &str,
    shown: &str,
    label: &str,
    account: Option<&str>,
    fills_itself: bool,
    list: &MicrosoftList,
    unreadable: &mut Vec<Unreadable>,
) -> Option<Store> {
    let gap = |unreadable: &mut Vec<Unreadable>, why: String| {
        unreadable.push(Unreadable::within(ROOT_CERTIFICATE, shown, why));
    };
    let key = match Key::look(root, path, View::Native) {
        Ok(key) => key,
        Err(Unopened::Absent) => return None,
        Err(why) => {
            gap(
                unreadable,
                format!(
                    "{}, so which certificates it trusts is not known",
                    why.describe(shown)
                ),
            );
            return None;
        }
    };
    // The store reads the key it is handed, and keeps its own copy of it.
    let opened = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_REG,
            CERT_QUERY_ENCODING_TYPE(0),
            None,
            CERT_STORE_READONLY_FLAG,
            Some(key.handle().0.cast_const()),
        )
    };
    let store = match opened {
        Ok(store) => Opened(store),
        Err(error) => {
            gap(
                unreadable,
                format!(
                    "The certificates in {shown} could not be read ({error}), so which it \
                     trusts is not known"
                ),
            );
            return None;
        }
    };

    let mut certificates = Vec::new();
    // A certificate with no thumbprint to know it by, and a walk that stopped
    // on an error rather than at the end, both leave the list short.
    let mut skipped = false;
    let ended;
    let mut previous: *mut CERT_CONTEXT = std::ptr::null_mut();
    loop {
        // Each call frees the one before it, including the last.
        let next = unsafe {
            CertEnumCertificatesInStore(
                store.0,
                (!previous.is_null()).then_some(previous.cast_const()),
            )
        };
        if next.is_null() {
            let last = unsafe { GetLastError() }.0;
            ended = last == CRYPT_E_NOT_FOUND.0 as u32 || last == ERROR_NO_MORE_FILES.0;
            break;
        }
        match certificate_of(next, list) {
            Some(certificate) => certificates.push(certificate),
            None => skipped = true,
        }
        previous = next;
    }
    if skipped || !ended {
        gap(
            unreadable,
            format!("{shown} could not be read to the end, so it may hold certificates not shown"),
        );
    }
    certificates.sort_by(|a: &Certificate, b: &Certificate| {
        a.name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then_with(|| a.thumbprint.cmp(&b.thumbprint))
    });
    Some(Store {
        label: label.to_owned(),
        location: shown.to_owned(),
        account: account.map(str::to_owned),
        fills_itself,
        certificates,
    })
}

/// One certificate, with Microsoft's list asked about it. `None` when its
/// thumbprint could not be had, which leaves nothing to know it by.
fn certificate_of(context: *const CERT_CONTEXT, list: &MicrosoftList) -> Option<Certificate> {
    let mut hash = [0_u8; 20];
    let mut length = hash.len() as u32;
    unsafe {
        CertGetCertificateContextProperty(
            context,
            CERT_SHA1_HASH_PROP_ID,
            Some(hash.as_mut_ptr().cast::<c_void>()),
            &mut length,
        )
    }
    .ok()?;
    let thumbprint: String = hash[..(length as usize).min(hash.len())]
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect();

    let size = unsafe { CertGetNameStringW(context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None) };
    let mut name = vec![0_u16; size.max(1) as usize];
    let written = unsafe {
        CertGetNameStringW(
            context,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut name),
        )
    };
    let name = String::from_utf16_lossy(&name[..(written as usize).saturating_sub(1)]);

    let expires = unsafe { (*context).pCertInfo.as_ref() }.and_then(|info| {
        let FILETIME {
            dwLowDateTime,
            dwHighDateTime,
        } = info.NotAfter;
        iso_of((u64::from(dwHighDateTime) << 32) | u64::from(dwLowDateTime))
    });

    Some(Certificate {
        name: if name.trim().is_empty() {
            thumbprint.clone()
        } else {
            name
        },
        thumbprint,
        expires,
        listed: list.lists(context),
    })
}

/// A Windows time (hundreds of nanoseconds since 1601) in the store's ISO
/// form. `None` for one before 1970, which no certificate or list here has.
fn iso_of(stamp: u64) -> Option<String> {
    const TO_1970_MS: u64 = 11_644_473_600_000;
    (stamp / 10_000)
        .checked_sub(TO_1970_MS)
        .map(kam_core::clock::iso_from_unix_millis)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::scratch::ScratchKey;
    use windows::core::PSTR;
    use windows::Win32::Security::Cryptography::{
        szOID_OIWSEC_sha1, szOID_ROOT_LIST_SIGNER, CertAddEncodedCertificateToStore,
        CryptMsgEncodeAndSignCTL, CERT_OPEN_STORE_FLAGS, CERT_STORE_ADD_REPLACE_EXISTING,
        CMSG_SIGNED_ENCODE_INFO, CRYPT_ALGORITHM_IDENTIFIER, CRYPT_INTEGER_BLOB, CTL_ENTRY,
        CTL_INFO, CTL_USAGE,
    };
    use windows::Win32::System::Registry::HKEY_CURRENT_USER;

    // Three self-signed test roots, made with OpenSSL for these tests and for
    // nothing else, their keys not kept:
    //
    //   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes
    //     -subj "/CN=KAM Test Local Root" -not_before 20260217000000Z
    //     -not_after 20360217000000Z -outform DER -out local-root.der
    //
    // and likewise "KAM Test Listed Root" (to 2045) and "OU=KAM Test Old
    // Root" (1997 to 30 December 1999). Shaped like the three kinds of
    // certificate the review found on the development machine: one added on
    // this PC, valid to 2036; ones on Microsoft's list; and old ones long
    // expired.
    const LOCAL: &[u8] = include_bytes!("../testdata/local-root.der");
    const LISTED: &[u8] = include_bytes!("../testdata/listed-root.der");
    const OLD: &[u8] = include_bytes!("../testdata/old-root.der");

    const LOCAL_THUMBPRINT: &str = "4503EADFFC69CBDC85BF4B77D1BD5E62B9AD4B89";
    const LISTED_THUMBPRINT: &str = "266524B32BF8A84F3B420CD0AE7FFA130EB77D59";
    const OLD_THUMBPRINT: &str = "BA734E3B03B0B98240469FEA7BAA7476EE3B1B86";

    /// 12 November 2026, 15:56 UTC, when the copy of Microsoft's list on the
    /// development machine was fetched, as milliseconds since 1970.
    const FETCHED_MS: u64 = 1_794_498_960_000;

    /// The same moment as Windows writes a time: hundreds of nanoseconds
    /// since 1601.
    fn windows_time(unix_ms: u64) -> u64 {
        (unix_ms + 11_644_473_600_000) * 10_000
    }

    fn sha1_of(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
            .collect()
    }

    /// A list shaped like Microsoft's: keyed on SHA-1 thumbprints, for the
    /// root list signer's use, built and encoded by Windows' own functions.
    /// It carries no signature, which reading it does not need.
    fn list_of(thumbprints: &[&str]) -> Vec<u8> {
        let hashes: Vec<Vec<u8>> = thumbprints.iter().map(|one| sha1_of(one)).collect();
        let mut entries: Vec<CTL_ENTRY> = hashes
            .iter()
            .map(|hash| CTL_ENTRY {
                SubjectIdentifier: CRYPT_INTEGER_BLOB {
                    cbData: hash.len() as u32,
                    pbData: hash.as_ptr().cast_mut(),
                },
                ..CTL_ENTRY::default()
            })
            .collect();
        let mut usage = [PSTR(szOID_ROOT_LIST_SIGNER.0.cast_mut())];
        let mut sequence = [1_u8];
        let issued = windows_time(FETCHED_MS);
        let info = CTL_INFO {
            dwVersion: 0,
            SubjectUsage: CTL_USAGE {
                cUsageIdentifier: 1,
                rgpszUsageIdentifier: usage.as_mut_ptr(),
            },
            SequenceNumber: CRYPT_INTEGER_BLOB {
                cbData: 1,
                pbData: sequence.as_mut_ptr(),
            },
            ThisUpdate: FILETIME {
                dwLowDateTime: issued as u32,
                dwHighDateTime: (issued >> 32) as u32,
            },
            SubjectAlgorithm: CRYPT_ALGORITHM_IDENTIFIER {
                pszObjId: PSTR(szOID_OIWSEC_sha1.0.cast_mut()),
                ..CRYPT_ALGORITHM_IDENTIFIER::default()
            },
            cCTLEntry: entries.len() as u32,
            rgCTLEntry: entries.as_mut_ptr(),
            ..CTL_INFO::default()
        };
        let signing = CMSG_SIGNED_ENCODE_INFO {
            cbSize: std::mem::size_of::<CMSG_SIGNED_ENCODE_INFO>() as u32,
            ..CMSG_SIGNED_ENCODE_INFO::default()
        };
        let mut length = 0_u32;
        unsafe { CryptMsgEncodeAndSignCTL(ENCODING, &info, &signing, 0, None, &mut length) }
            .expect("Windows sizes the list");
        let mut encoded = vec![0_u8; length as usize];
        unsafe {
            CryptMsgEncodeAndSignCTL(
                ENCODING,
                &info,
                &signing,
                0,
                Some(encoded.as_mut_ptr()),
                &mut length,
            )
        }
        .expect("Windows encodes the list");
        encoded.truncate(length as usize);
        encoded
    }

    /// Put certificates into a store kept under a scratch key, with
    /// Windows' own functions, so that it is laid out as Windows lays out
    /// its own.
    fn plant(scratch: &ScratchKey, key: &str, certificates: &[&[u8]]) {
        let handle = scratch.make(key);
        let store = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_REG,
                CERT_QUERY_ENCODING_TYPE(0),
                None,
                CERT_OPEN_STORE_FLAGS(0),
                Some(handle.0.cast_const()),
            )
        }
        .expect("a store opens on the scratch key");
        for certificate in certificates {
            unsafe {
                CertAddEncodedCertificateToStore(
                    Some(store),
                    X509_ASN_ENCODING,
                    certificate,
                    CERT_STORE_ADD_REPLACE_EXISTING,
                    None,
                )
            }
            .expect("the certificate is added");
        }
        unsafe {
            CertCloseStore(Some(store), 0).unwrap();
            let _ = windows::Win32::System::Registry::RegCloseKey(handle);
        }
    }

    fn read(
        scratch: &ScratchKey,
        key: &str,
        list: &MicrosoftList,
    ) -> (Option<Store>, Vec<Unreadable>) {
        let mut unreadable = Vec::new();
        let store = read_store(
            HKEY_CURRENT_USER,
            &scratch.under(key),
            &format!(r"HKCU\{}", scratch.under(key)),
            "a test store",
            None,
            false,
            list,
            &mut unreadable,
        );
        (store, unreadable)
    }

    /// A store laid out as the development machine's own root store was: a
    /// certificate added on this PC, one on Microsoft's list and an old one
    /// long expired. Each is read by name, thumbprint and expiry, and only
    /// the listed one is on the list.
    #[test]
    fn each_certificate_is_read_and_looked_up_in_microsofts_list() {
        let scratch = ScratchKey::new("roots");
        plant(&scratch, "ROOT", &[LOCAL, LISTED, OLD]);
        let list = MicrosoftList::from_encoded(
            &list_of(&[LISTED_THUMBPRINT]),
            Some("2026-11-12T15:56:00.000Z".to_owned()),
        );
        assert_eq!(
            list.state(),
            &List::Cached {
                fetched: Some("2026-11-12T15:56:00.000Z".to_owned()),
                entries: 1
            }
        );

        let (store, unreadable) = read(&scratch, "ROOT", &list);
        assert!(unreadable.is_empty(), "{unreadable:?}");
        let store = store.expect("the store is there");
        let read: Vec<(&str, &str, Option<&str>, Option<bool>)> = store
            .certificates
            .iter()
            .map(|one| {
                (
                    one.name.as_str(),
                    one.thumbprint.as_str(),
                    one.expires.as_deref(),
                    one.listed,
                )
            })
            .collect();
        assert_eq!(
            read,
            vec![
                (
                    "KAM Test Listed Root",
                    LISTED_THUMBPRINT,
                    Some("2045-01-01T00:00:00.000Z"),
                    Some(true)
                ),
                (
                    "KAM Test Local Root",
                    LOCAL_THUMBPRINT,
                    Some("2036-02-17T00:00:00.000Z"),
                    Some(false)
                ),
                (
                    "KAM Test Old Root",
                    OLD_THUMBPRINT,
                    Some("1999-12-30T00:00:00.000Z"),
                    Some(false)
                ),
            ]
        );
    }

    /// With no list on this PC, the certificates are still read and listed,
    /// and none is said to be on the list or off it.
    #[test]
    fn without_microsofts_list_the_certificates_are_still_listed() {
        let scratch = ScratchKey::new("roots-no-list");
        plant(&scratch, "ROOT", &[LOCAL, LISTED]);
        // No AutoUpdate key at all.
        let list = MicrosoftList::from_key(Key::look(
            HKEY_CURRENT_USER,
            &scratch.under("AutoUpdate"),
            View::Native,
        ));
        assert_eq!(
            list.state(),
            &List::Missing {
                why: NOT_ON_THIS_PC.to_owned()
            }
        );
        let (store, _) = read(&scratch, "ROOT", &list);
        let store = store.unwrap();
        assert_eq!(store.certificates.len(), 2);
        assert!(store.certificates.iter().all(|one| one.listed.is_none()));
    }

    /// The list is read from where Windows keeps it, with the date Windows
    /// last fetched it, and one that is there but is not a list is said to
    /// be unreadable rather than taken for an empty list.
    #[test]
    fn the_list_is_read_with_the_date_windows_fetched_it() {
        let scratch = ScratchKey::new("roots-auto-update");
        // As Windows writes it, little-endian.
        scratch.bytes(
            "AutoUpdate",
            "LastSyncTime",
            &windows_time(FETCHED_MS).to_le_bytes(),
        );
        scratch.bytes(
            "AutoUpdate",
            "EncodedCtl",
            &list_of(&[LISTED_THUMBPRINT, OLD_THUMBPRINT]),
        );
        let list = MicrosoftList::from_key(Key::look(
            HKEY_CURRENT_USER,
            &scratch.under("AutoUpdate"),
            View::Native,
        ));
        assert_eq!(
            list.state(),
            &List::Cached {
                fetched: Some("2026-11-12T15:56:00.000Z".to_owned()),
                entries: 2
            }
        );

        scratch.bytes("AutoUpdate", "EncodedCtl", b"not a list at all");
        let list = MicrosoftList::from_key(Key::look(
            HKEY_CURRENT_USER,
            &scratch.under("AutoUpdate"),
            View::Native,
        ));
        let List::Missing { why } = list.state() else {
            panic!(
                "bytes that are not a list were read as one: {:?}",
                list.state()
            );
        };
        assert!(why.contains("could not be read as a list"), "{why}");
    }

    /// A store whose key is not there holds nothing and is not a gap. One
    /// whose key is there is a store, even with nothing in it.
    #[test]
    fn a_store_that_is_not_there_holds_nothing() {
        let scratch = ScratchKey::new("roots-absent");
        let list = MicrosoftList::from_encoded(&list_of(&[]), None);
        let (store, unreadable) = read(&scratch, "Policies Root", &list);
        assert!(store.is_none());
        assert!(unreadable.is_empty(), "{unreadable:?}");

        scratch.make("Empty Root");
        let (store, unreadable) = read(&scratch, "Empty Root", &list);
        assert_eq!(store.unwrap().certificates, Vec::new());
        assert!(unreadable.is_empty(), "{unreadable:?}");
    }

    /// An account that is not signed in has no hive to read, and is not read
    /// as an account whose own certificates have all gone.
    #[test]
    fn an_account_that_is_not_signed_in_is_not_read_as_trusting_nothing() {
        let absent = UserContext::new(Some("S-1-5-21-1-2-3-31337".to_owned()), r"C:\Users\nobody");
        let list = MicrosoftList::from_encoded(&list_of(&[]), None);
        let mut unreadable = Vec::new();
        assert!(account_stores(&absent, &list, &mut unreadable).is_none());
    }
}
