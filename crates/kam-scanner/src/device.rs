//! Facts about this device that Windows already knows: Secure Boot, the
//! security chip (TPM), whether drive C: is encrypted and protected, and
//! Remote Desktop.
//!
//! # Facts, not a score
//!
//! Each is said with where it came from. Nothing here counts checks passed or
//! calls a PC secure or not: what these facts are worth is the reader's to
//! weigh, and Windows Security already shows most of them, across several
//! screens. The gain is one place.
//!
//! # Who reads what
//!
//! Secure Boot and Remote Desktop are in the registry, which any account may
//! read, so the window reads them as the person. Whether there is a TPM and
//! whether a drive is encrypted, Windows tells anyone, in Windows Security and
//! in Explorer, but the documented sources, its WMI providers, answer only an
//! administrator. So the service reads those ([`held`]), and where it cannot,
//! the window asks the two places an ordinary account can: `tpmtool` for the
//! TPM, and the BitLocker property Explorer shows for a drive.
//!
//! # An empty answer is not "none"
//!
//! Asked without the rights it needs, Windows' own `Get-Tpm` gives back empty
//! values and no error. So an answer with nothing in it is said to be unread,
//! never taken as "no TPM". The only "no TPM" here is `tpmtool` saying so in
//! as many words.

use kam_core::registry::{Key, Unopened, View};
use serde::{Deserialize, Serialize};
use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;

use crate::wmi::{self, Protection, Row, Value};

/// The drive whose encryption is reported.
pub const DRIVE: &str = "C:";

/// The port Remote Desktop listens on unless Windows records another.
pub const USUAL_PORT: u16 = 3389;

const TPM_NAMESPACE: &str = r"ROOT\CIMV2\Security\MicrosoftTpm";
const ENCRYPTION_NAMESPACE: &str = r"ROOT\CIMV2\Security\MicrosoftVolumeEncryption";
const SECURE_BOOT_STATE: &str = r"SYSTEM\CurrentControlSet\Control\SecureBoot\State";
const SECURE_BOOT_SERVICING: &str = r"SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing";
const TERMINAL_SERVER: &str = r"SYSTEM\CurrentControlSet\Control\Terminal Server";
const TERMINAL_POLICY: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
const RDP_LISTENER: &str = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";

/// One fact, or why it could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Reading<T> {
    Read { value: T },
    Unread { why: String },
}

impl<T> Reading<T> {
    fn unread(why: impl Into<String>) -> Self {
        Self::Unread { why: why.into() }
    }

    /// This reading, or, when it is unread, what a second source reads.
    ///
    /// `instead` is given a value from the second source and why the first
    /// did not answer, so the answer can say both. When neither answers, the
    /// two reasons are kept together.
    pub fn or_second(
        self,
        second: impl FnOnce() -> Result<T, String>,
        instead: impl FnOnce(&mut T, String),
    ) -> Self {
        let Self::Unread { why: first } = self else {
            return self;
        };
        match second() {
            Ok(mut value) => {
                instead(&mut value, first);
                Self::Read { value }
            }
            Err(second) => Self::Unread {
                why: format!("{first}. {second}"),
            },
        }
    }
}

/// Where what is known about the TPM was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TpmSource {
    /// Windows' TPM provider, `Win32_Tpm`, asked by the service.
    Provider,
    /// `tpmtool getdeviceinformation`, run by the window as the person.
    Tpmtool,
}

/// The security chip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tpm {
    /// False only when `tpmtool` says there is none.
    pub present: bool,
    /// The version of the TPM specification it follows, such as "2.0".
    pub version: Option<String>,
    /// Whether Windows says it is ready: for use, in the provider's words, or
    /// for storage, in `tpmtool`'s. `None` when the source did not say.
    pub ready: Option<bool>,
    pub source: TpmSource,
    /// Why the service's source did not answer, when `tpmtool` did instead.
    #[serde(default)]
    pub instead_of: Option<String>,
}

/// How far a drive is encrypted, in the words BitLocker uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Conversion {
    Decrypted,
    Encrypted,
    Encrypting,
    Decrypting,
    EncryptionPaused,
    DecryptionPaused,
}

/// Where what is known about a drive's encryption was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionSource {
    /// Windows' drive encryption provider, `Win32_EncryptableVolume`, asked
    /// by the service.
    Provider,
    /// The BitLocker property Explorer shows for the drive, read by the
    /// window as the person.
    Explorer,
}

/// Whether a drive is encrypted, and whether its protection is on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Encryption {
    pub drive: String,
    /// `None` when the source did not say.
    pub conversion: Option<Conversion>,
    /// Whether its protection is on. `None` when the source says it does not
    /// know, or did not say.
    pub protection: Option<bool>,
    pub source: EncryptionSource,
    /// Why the service's source did not answer, when Explorer did instead.
    #[serde(default)]
    pub instead_of: Option<String>,
}

/// What the service reads, because the documented sources answer only an
/// administrator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Held {
    pub tpm: Reading<Tpm>,
    pub encryption: Reading<Encryption>,
}

/// Read the TPM and drive C: from Windows' providers. For the service.
pub fn held() -> Held {
    Held {
        tpm: tpm(),
        encryption: encryption(),
    }
}

fn tpm() -> Reading<Tpm> {
    let rows = match wmi::query_with(
        TPM_NAMESPACE,
        "SELECT * FROM Win32_Tpm",
        &["__PATH", "SpecVersion"],
        Protection::Private,
    ) {
        Ok(rows) => rows,
        Err(error) => {
            return Reading::unread(format!("Windows' TPM provider could not be read: {error}"))
        }
    };
    let Some(row) = rows.first() else {
        return Reading::unread(
            "Windows' TPM provider gave an empty answer, which says nothing either way about \
             whether there is a TPM",
        );
    };
    // The path comes from the query, never from a caller.
    let ready = row.get("__PATH").and_then(Value::text).and_then(|path| {
        wmi::call(
            TPM_NAMESPACE,
            path,
            "IsReady",
            &["IsReady", "ReturnValue"],
            Protection::Private,
        )
        .ok()
    });
    tpm_from_provider(row, ready.as_ref())
}

/// What the provider's instance and its answer to `IsReady` come to.
fn tpm_from_provider(row: &Row, ready: Option<&Row>) -> Reading<Tpm> {
    // "2.0, 0, 1.59": the specification's version, then its level and
    // revision.
    let version = row
        .get("SpecVersion")
        .and_then(Value::text)
        .and_then(|spec| spec.split(',').next())
        .map(str::trim)
        .filter(|version| !version.is_empty())
        .map(str::to_owned);
    let ready = ready
        .filter(|answer| answer.get("ReturnValue").and_then(Value::number) == Some(0))
        .and_then(|answer| answer.get("IsReady"))
        .and_then(Value::flag);
    if version.is_none() && ready.is_none() {
        return Reading::unread(
            "Windows' TPM provider answered with nothing filled in, which says nothing either \
             way about whether there is a TPM",
        );
    }
    Reading::Read {
        value: Tpm {
            present: true,
            version,
            ready,
            source: TpmSource::Provider,
            instead_of: None,
        },
    }
}

fn encryption() -> Reading<Encryption> {
    // `DRIVE` is this module's own constant, so nothing a caller sent is
    // written into the query.
    let rows = match wmi::query_with(
        ENCRYPTION_NAMESPACE,
        &format!(
            "SELECT DriveLetter, ConversionStatus, ProtectionStatus FROM \
             Win32_EncryptableVolume WHERE DriveLetter = '{DRIVE}'"
        ),
        &["ConversionStatus", "ProtectionStatus"],
        Protection::Private,
    ) {
        Ok(rows) => rows,
        Err(error) => {
            return Reading::unread(format!(
                "Windows' drive encryption provider could not be read: {error}"
            ))
        }
    };
    encryption_from_provider(rows.first())
}

/// What the provider's answer for drive C: comes to.
fn encryption_from_provider(row: Option<&Row>) -> Reading<Encryption> {
    let Some(row) = row else {
        return Reading::unread(format!(
            "Windows' drive encryption provider gave no answer for drive {DRIVE}"
        ));
    };
    // Both as Microsoft documents them for Win32_EncryptableVolume.
    let conversion = match row.get("ConversionStatus").and_then(Value::number) {
        Some(0) => Some(Conversion::Decrypted),
        Some(1) => Some(Conversion::Encrypted),
        Some(2) => Some(Conversion::Encrypting),
        Some(3) => Some(Conversion::Decrypting),
        Some(4) => Some(Conversion::EncryptionPaused),
        Some(5) => Some(Conversion::DecryptionPaused),
        _ => None,
    };
    let protection = match row.get("ProtectionStatus").and_then(Value::number) {
        Some(0) => Some(false),
        Some(1) => Some(true),
        // 2 is the provider saying it does not know.
        _ => None,
    };
    if conversion.is_none() && protection.is_none() {
        return Reading::unread(format!(
            "Windows' drive encryption provider answered for drive {DRIVE} with nothing KAM \
             can read"
        ));
    }
    Reading::Read {
        value: Encryption {
            drive: DRIVE.to_owned(),
            conversion,
            protection,
            source: EncryptionSource::Provider,
            instead_of: None,
        },
    }
}

/// What the BitLocker property Explorer shows for a drive says, by its value.
///
/// Microsoft does not document these values. They are the ones widely
/// published by people who compared them with BitLocker's own state; a value
/// not among them is said not to be known, never guessed at.
pub fn encryption_from_explorer(value: i64) -> Result<Encryption, String> {
    let (conversion, protection) = match value {
        1 => (Conversion::Encrypted, Some(true)),
        2 => (Conversion::Decrypted, Some(false)),
        3 => (Conversion::Encrypting, None),
        4 => (Conversion::Decrypting, None),
        // Encrypted with its protection suspended.
        5 => (Conversion::Encrypted, Some(false)),
        // Encrypted, protected and locked.
        6 => (Conversion::Encrypted, Some(true)),
        // Encrypted and waiting for its protection to be switched on, which
        // is how Windows leaves device encryption until a key is backed up.
        8 => (Conversion::Encrypted, Some(false)),
        other => {
            return Err(format!(
                "Explorer gives drive {DRIVE}'s BitLocker state as {other}, a value KAM does \
                 not know"
            ))
        }
    };
    Ok(Encryption {
        drive: DRIVE.to_owned(),
        conversion: Some(conversion),
        protection,
        source: EncryptionSource::Explorer,
        instead_of: None,
    })
}

/// What `tpmtool getdeviceinformation` says, read by its labels.
///
/// The labels are English and may be translated on other Windows languages.
/// There is no number or position to read instead, so an answer without them
/// is said not to be recognised rather than read some other way.
pub fn tpm_from_tpmtool(text: &str) -> Result<Tpm, String> {
    let mut present = None;
    let mut version = None;
    let mut ready = None;
    for line in text.lines() {
        let line = line.trim().trim_start_matches('-').trim();
        let Some((label, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        let flag = match value {
            "True" => Some(true),
            "False" => Some(false),
            _ => None,
        };
        match label.trim() {
            "TPM Present" => present = flag,
            "TPM Version" => version = (!value.is_empty()).then(|| value.to_owned()),
            "Ready For Storage" => ready = flag,
            _ => {}
        }
    }
    let present = present.ok_or_else(|| {
        "tpmtool's answer did not say whether there is a TPM in a form KAM recognises".to_owned()
    })?;
    Ok(Tpm {
        present,
        version: version.filter(|_| present),
        ready: ready.filter(|_| present),
        source: TpmSource::Tpmtool,
        instead_of: None,
    })
}

/// Secure Boot, as Windows records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecureBoot {
    pub on: bool,
    /// What Windows reports about moving Secure Boot to Microsoft's 2023
    /// certificates, as it writes it: Microsoft documents "NotStarted",
    /// "InProgress" and "Updated". `None` when it reports nothing.
    pub certificates: Option<String>,
    /// The error Windows recorded while doing that, when there is one.
    pub certificate_error: Option<u32>,
}

/// Read Secure Boot from the registry. Needs nobody special.
pub fn secure_boot() -> Reading<SecureBoot> {
    let enabled = Key::look(HKEY_LOCAL_MACHINE, SECURE_BOOT_STATE, View::Native)
        .and_then(|key| key.read_dword("UEFISecureBootEnabled"));
    let servicing = Key::look(HKEY_LOCAL_MACHINE, SECURE_BOOT_SERVICING, View::Native).ok();
    let certificates = servicing
        .as_ref()
        .and_then(|key| key.read_string("UEFICA2023Status").ok().flatten());
    let certificate_error = servicing
        .as_ref()
        .and_then(|key| key.read_dword("UEFICA2023Error").ok().flatten());
    secure_boot_from(enabled, certificates, certificate_error)
}

fn secure_boot_from(
    enabled: Result<Option<u32>, Unopened>,
    certificates: Option<String>,
    certificate_error: Option<u32>,
) -> Reading<SecureBoot> {
    let on = match enabled {
        Ok(Some(1)) => true,
        Ok(Some(0)) => false,
        Ok(Some(other)) => {
            return Reading::unread(format!(
                "Windows' Secure Boot state is a value KAM does not recognise ({other})"
            ))
        }
        Ok(None) => return Reading::unread("Windows records no Secure Boot state"),
        Err(Unopened::Absent) => {
            return Reading::unread(
                "Windows records no Secure Boot state, which a PC that does not start through \
                 UEFI does not have",
            )
        }
        Err(why) => return Reading::unread(why.describe("Windows' Secure Boot state")),
    };
    Reading::Read {
        value: SecureBoot {
            on,
            certificates,
            certificate_error: certificate_error.filter(|code| *code != 0),
        },
    }
}

/// Remote Desktop, as Windows records it, and whether anything is listening
/// where it would.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteDesktop {
    /// Whether it accepts connections.
    pub on: bool,
    /// True when a policy sets it, which overrides the switch in Settings.
    pub by_policy: bool,
    /// The port Windows records for it, when it records one.
    pub port: Option<u16>,
    /// Whether anything is listening on that port, or on [`USUAL_PORT`]
    /// when none is recorded.
    pub listening: Reading<bool>,
}

/// Read Remote Desktop from the registry. Needs nobody special.
///
/// `listening_on` asks whether anything listens on a port. It is passed in
/// because the socket table is read by the firewall crate, which depends on
/// this one.
pub fn remote_desktop(
    listening_on: impl FnOnce(u16) -> Result<bool, String>,
) -> Reading<RemoteDesktop> {
    let deny = |path: &str| {
        Key::look(HKEY_LOCAL_MACHINE, path, View::Native)
            .and_then(|key| key.read_dword("fDenyTSConnections"))
    };
    let port = Key::look(HKEY_LOCAL_MACHINE, RDP_LISTENER, View::Native)
        .and_then(|key| key.read_dword("PortNumber"));
    remote_desktop_from(
        deny(TERMINAL_POLICY),
        deny(TERMINAL_SERVER),
        port,
        listening_on,
    )
}

fn remote_desktop_from(
    policy: Result<Option<u32>, Unopened>,
    setting: Result<Option<u32>, Unopened>,
    port: Result<Option<u32>, Unopened>,
    listening_on: impl FnOnce(u16) -> Result<bool, String>,
) -> Reading<RemoteDesktop> {
    // A key that is not there records nothing, which is not a failure.
    let recorded = |read: Result<Option<u32>, Unopened>| match read {
        Err(Unopened::Absent) => Ok(None),
        other => other,
    };
    // A policy, where it says anything, decides; one that could not be read
    // might be deciding, so the setting alone is not the answer then.
    let (deny, by_policy) = match (recorded(policy), recorded(setting)) {
        (Ok(Some(deny)), _) => (deny, true),
        (Err(why), _) => return Reading::unread(why.describe("The policy for Remote Desktop")),
        (Ok(None), Ok(Some(deny))) => (deny, false),
        (Ok(None), Ok(None)) => {
            return Reading::unread(
                "Windows records no setting for whether Remote Desktop accepts connections",
            )
        }
        (Ok(None), Err(why)) => return Reading::unread(why.describe("Remote Desktop's setting")),
    };
    let on = match deny {
        0 => true,
        1 => false,
        other => {
            return Reading::unread(format!(
                "Remote Desktop's setting is a value KAM does not recognise ({other})"
            ))
        }
    };
    let port = port
        .ok()
        .flatten()
        .and_then(|port| u16::try_from(port).ok());
    let listening = match listening_on(port.unwrap_or(USUAL_PORT)) {
        Ok(listening) => Reading::Read { value: listening },
        Err(why) => Reading::Unread { why },
    };
    Reading::Read {
        value: RemoteDesktop {
            on,
            by_policy,
            port,
            listening,
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn row(pairs: &[(&str, Value)]) -> Row {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone()))
            .collect()
    }

    fn read<T: std::fmt::Debug>(reading: Reading<T>) -> T {
        match reading {
            Reading::Read { value } => value,
            Reading::Unread { why } => panic!("expected a fact, got unread: {why}"),
        }
    }

    fn why<T: std::fmt::Debug>(reading: Reading<T>) -> String {
        match reading {
            Reading::Unread { why } => why,
            Reading::Read { value } => panic!("expected unread, got {value:?}"),
        }
    }

    #[test]
    fn the_tpm_providers_answer_is_read_with_its_readiness() {
        let instance = row(&[("SpecVersion", Value::Text("2.0, 0, 1.59".to_owned()))]);
        let ready = row(&[
            ("IsReady", Value::Flag(true)),
            ("ReturnValue", Value::Number(0)),
        ]);
        assert_eq!(
            read(tpm_from_provider(&instance, Some(&ready))),
            Tpm {
                present: true,
                version: Some("2.0".to_owned()),
                ready: Some(true),
                source: TpmSource::Provider,
                instead_of: None,
            }
        );

        // A call that failed says nothing about readiness.
        let failed = row(&[
            ("IsReady", Value::Flag(true)),
            ("ReturnValue", Value::Number(5)),
        ]);
        assert_eq!(
            read(tpm_from_provider(&instance, Some(&failed))).ready,
            None
        );
    }

    /// The empty answer `Get-Tpm` gives without the rights it needs is not
    /// "no TPM".
    #[test]
    fn an_empty_answer_from_the_tpm_provider_is_unread_never_none() {
        let empty = row(&[("SpecVersion", Value::Empty)]);
        let reason = why(tpm_from_provider(&empty, None));
        assert!(reason.contains("says nothing either way"), "{reason}");
    }

    #[test]
    fn drive_encryption_is_read_as_microsoft_documents_it() {
        let answer = row(&[
            ("ConversionStatus", Value::Number(1)),
            ("ProtectionStatus", Value::Number(1)),
        ]);
        let encryption = read(encryption_from_provider(Some(&answer)));
        assert_eq!(encryption.conversion, Some(Conversion::Encrypted));
        assert_eq!(encryption.protection, Some(true));
        assert_eq!(encryption.drive, "C:");

        // 2 is the provider not knowing, which is not "off".
        let unknown = row(&[
            ("ConversionStatus", Value::Number(1)),
            ("ProtectionStatus", Value::Number(2)),
        ]);
        assert_eq!(
            read(encryption_from_provider(Some(&unknown))).protection,
            None
        );

        assert!(why(encryption_from_provider(None)).contains("no answer"));
        let blank = row(&[("ConversionStatus", Value::Empty)]);
        assert!(why(encryption_from_provider(Some(&blank))).contains("nothing KAM can read"));
    }

    #[test]
    fn explorers_bitlocker_value_is_read_only_where_it_is_known() {
        let on = encryption_from_explorer(1).unwrap();
        assert_eq!(
            (on.conversion, on.protection, on.source),
            (
                Some(Conversion::Encrypted),
                Some(true),
                EncryptionSource::Explorer
            )
        );
        let off = encryption_from_explorer(2).unwrap();
        assert_eq!(
            (off.conversion, off.protection),
            (Some(Conversion::Decrypted), Some(false))
        );
        let suspended = encryption_from_explorer(5).unwrap();
        assert_eq!(suspended.protection, Some(false));
        for unknown in [0, 7, 9, -1] {
            assert!(
                encryption_from_explorer(unknown).is_err(),
                "{unknown} was read as a state"
            );
        }
    }

    /// As `tpmtool getdeviceinformation` writes it, in English.
    const TPMTOOL: &str = "\
-TPM Present: True
-TPM Version: 2.0
-TPM Manufacturer ID: INTC
-TPM Manufacturer Full Name: Intel
-TPM Manufacturer Version: 600.18.0.0
-PPI Version: 1.3
-Is Initialized: True
-Ready For Storage: True
-Ready For Attestation: True
-Is Capable For Attestation: True
-Clear Needed To Recover: False
-Clear Possible: True
-TPM Has Vulnerable Firmware: False
-PCR7 Binding State: 3
-Maintenance Task Complete: True
-TPM Spec Version: 1.38
-TPM Errata Date: Thursday, December 8, 2016
-PC Client Version: 1.03
-Is Locked Out: False
";

    #[test]
    fn tpmtools_answer_is_read_by_its_labels() {
        assert_eq!(
            tpm_from_tpmtool(TPMTOOL).unwrap(),
            Tpm {
                present: true,
                version: Some("2.0".to_owned()),
                ready: Some(true),
                source: TpmSource::Tpmtool,
                instead_of: None,
            }
        );

        // Its own explicit "no" is the one "no TPM" there is.
        let none = tpm_from_tpmtool("-TPM Present: False\n-TPM Version: Unknown\n").unwrap();
        assert!(!none.present);
        assert_eq!(none.version, None);

        // Translated, or empty: not recognised, and not taken for "none".
        assert!(tpm_from_tpmtool("-TPM vorhanden: Wahr\n").is_err());
        assert!(tpm_from_tpmtool("").is_err());
    }

    /// A second source is asked only when the first did not answer, and an
    /// answer from it says why the first did not.
    #[test]
    fn a_second_source_answers_only_when_the_first_did_not() {
        let first: Reading<u32> = Reading::Read { value: 1 };
        assert_eq!(
            first.or_second(|| panic!("asked although the first answered"), |_, _| {}),
            Reading::Read { value: 1 }
        );

        let unread: Reading<(u32, String)> = Reading::unread("the service could not be asked");
        assert_eq!(
            unread.or_second(|| Ok((2, String::new())), |value, why| value.1 = why),
            Reading::Read {
                value: (2, "the service could not be asked".to_owned())
            }
        );

        let neither: Reading<u32> = Reading::unread("first reason");
        assert_eq!(
            neither.or_second(|| Err("second reason".to_owned()), |_, _| {}),
            Reading::unread("first reason. second reason")
        );
    }

    #[test]
    fn secure_boot_is_read_and_a_missing_record_is_not_taken_for_off() {
        let on = read(secure_boot_from(
            Ok(Some(1)),
            Some("Updated".to_owned()),
            Some(0),
        ));
        assert_eq!(
            on,
            SecureBoot {
                on: true,
                certificates: Some("Updated".to_owned()),
                // No error is no error.
                certificate_error: None,
            }
        );
        assert!(!read(secure_boot_from(Ok(Some(0)), None, None)).on);
        assert!(why(secure_boot_from(Err(Unopened::Absent), None, None)).contains("UEFI"));
        assert!(why(secure_boot_from(Err(Unopened::Denied), None, None)).contains("could not"));
        assert!(why(secure_boot_from(Ok(Some(7)), None, None)).contains("(7)"));
        assert!(why(secure_boot_from(Ok(None), None, None)).contains("no Secure Boot state"));
    }

    #[test]
    fn remote_desktop_follows_a_policy_where_one_says_anything() {
        let nothing_listening = |port: u16| {
            assert_eq!(port, 3389);
            Ok(false)
        };
        let off = read(remote_desktop_from(
            Err(Unopened::Absent),
            Ok(Some(1)),
            Ok(Some(3389)),
            nothing_listening,
        ));
        assert_eq!(
            off,
            RemoteDesktop {
                on: false,
                by_policy: false,
                port: Some(3389),
                listening: Reading::Read { value: false },
            }
        );

        let by_policy = read(remote_desktop_from(
            Ok(Some(0)),
            Ok(Some(1)),
            Ok(None),
            |port| {
                // No port recorded: the usual one is the one looked at.
                assert_eq!(port, USUAL_PORT);
                Err("the socket table could not be read".to_owned())
            },
        ));
        assert!(by_policy.on && by_policy.by_policy);
        assert_eq!(by_policy.port, None);
        assert_eq!(
            by_policy.listening,
            Reading::unread("the socket table could not be read")
        );

        // A policy that could not be read might be the one deciding.
        assert!(why(remote_desktop_from(
            Err(Unopened::Denied),
            Ok(Some(1)),
            Ok(None),
            |_| Ok(false)
        ))
        .contains("policy"));
        assert!(why(remote_desktop_from(
            Err(Unopened::Absent),
            Err(Unopened::Absent),
            Ok(None),
            |_| Ok(false)
        ))
        .contains("records no setting"));
        // With no policy key at all, a setting that could not be read is
        // the setting's to say, not the policy's.
        let setting = why(remote_desktop_from(
            Err(Unopened::Absent),
            Err(Unopened::Denied),
            Ok(None),
            |_| Ok(false),
        ));
        assert!(setting.starts_with("Remote Desktop's setting"), "{setting}");
        assert!(why(remote_desktop_from(
            Err(Unopened::Absent),
            Ok(Some(9)),
            Ok(None),
            |_| Ok(false)
        ))
        .contains("(9)"));
    }
}
