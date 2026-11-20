//! The "This device" facts on the Scanner page, gathered where each can be
//! read. See `kam_scanner::device` for what each fact is and why.
//!
//! Secure Boot and Remote Desktop are read here, as the person: the registry
//! holds both and any account may read it. The TPM and drive C: are asked of
//! the service, whose providers need an administrator, and where the service
//! cannot say, this asks the two places an ordinary account can: `tpmtool`
//! and the BitLocker property Explorer shows. A fact read the second way says
//! why the first did not answer.

use std::os::windows::process::CommandExt as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use kam_ipc::{Request, Response};
use kam_scanner::device::{self, Encryption, Reading, RemoteDesktop, SecureBoot, Tpm, DRIVE};
use serde::Serialize;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{PROPERTYKEY, RPC_E_CHANGED_MODE};
use windows::Win32::System::Com::StructuredStorage::PropVariantClear;
use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED};
use windows::Win32::System::Threading::CREATE_NO_WINDOW;
use windows::Win32::System::Variant::{VT_I2, VT_I4, VT_INT, VT_UI1, VT_UI2, VT_UI4, VT_UINT};
use windows::Win32::UI::Shell::PropertiesSystem::{
    IPropertyStore, PSGetPropertyKeyFromName, SHGetPropertyStoreFromParsingName, GPS_DEFAULT,
};

/// How long `tpmtool` may take. It answers in about a second.
const TPMTOOL_TIMEOUT: Duration = Duration::from_secs(30);

/// Everything the "This device" group shows.
#[derive(Debug, Clone, Serialize)]
pub struct Facts {
    pub secure_boot: Reading<SecureBoot>,
    pub tpm: Reading<Tpm>,
    pub encryption: Reading<Encryption>,
    pub remote_desktop: Reading<RemoteDesktop>,
}

/// Gather the facts. Asks the service and may run `tpmtool`, so it must be
/// called off the window's thread.
pub fn facts() -> Facts {
    let (tpm, encryption) = match kam_ipc::client::call(&Request::GetDeviceFacts) {
        Ok(Response::DeviceFacts(held)) => (held.tpm, held.encryption),
        Ok(Response::Error { message }) => unasked(&message),
        Ok(other) => unasked(&format!("it replied with something unexpected: {other:?}")),
        Err(error) => unasked(&error.to_string()),
    };
    Facts {
        secure_boot: device::secure_boot(),
        tpm: tpm.or_second(
            || run_tpmtool().and_then(|text| device::tpm_from_tpmtool(&text)),
            |tpm, why| tpm.instead_of = Some(why),
        ),
        encryption: encryption.or_second(
            || explorer_bitlocker().and_then(device::encryption_from_explorer),
            |encryption, why| encryption.instead_of = Some(why),
        ),
        remote_desktop: device::remote_desktop(kam_firewall::connections::listening_on),
    }
}

/// Both service-read facts, unread, when the service could not be asked.
fn unasked(why: &str) -> (Reading<Tpm>, Reading<Encryption>) {
    let why = format!("The service could not be asked: {why}");
    (
        Reading::Unread { why: why.clone() },
        Reading::Unread { why },
    )
}

fn system32() -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    PathBuf::from(root).join("System32")
}

/// What `tpmtool getdeviceinformation` writes, run by its full path.
fn run_tpmtool() -> Result<String, String> {
    let tool = system32().join("tpmtool.exe");
    if !tool.is_file() {
        return Err(format!("tpmtool is not on this PC, at {}", tool.display()));
    }
    let mut child = std::process::Command::new(&tool)
        .arg("getdeviceinformation")
        .current_dir(system32())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        // The window has no console; without this one would flash up.
        .creation_flags(CREATE_NO_WINDOW.0)
        .spawn()
        .map_err(|error| format!("tpmtool could not be started: {error}"))?;
    let output = crate::winget::drain(child.stdout.take());

    let started = Instant::now();
    let code = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code(),
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                return Err(format!("tpmtool could not be waited on: {error}"));
            }
        }
        if started.elapsed() > TPMTOOL_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "tpmtool had not answered after {} seconds and was stopped",
                TPMTOOL_TIMEOUT.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let text = crate::winget::text_of(output);
    match code {
        Some(0) => Ok(text),
        Some(code) => Err(format!("tpmtool ended with exit code {code}")),
        None => Err("tpmtool ended without an exit code".to_owned()),
    }
}

/// COM for one read, given back only if this call took it.
struct Com {
    owned: bool,
}

impl Com {
    fn enter() -> Result<Self, String> {
        let outcome = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        if outcome == RPC_E_CHANGED_MODE {
            return Ok(Self { owned: false });
        }
        if outcome.is_err() {
            return Err(format!("COM could not be started ({outcome:?})"));
        }
        Ok(Self { owned: true })
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        if self.owned {
            unsafe { CoUninitialize() };
        }
    }
}

/// The BitLocker state Explorer shows for drive C:, as its number.
fn explorer_bitlocker() -> Result<i64, String> {
    let failed = |what: &str, error: windows::core::Error| {
        format!("Explorer's BitLocker state for drive {DRIVE} could not be read ({what}: {error})")
    };
    let _com = Com::enter()?;

    let mut key = PROPERTYKEY::default();
    unsafe { PSGetPropertyKeyFromName(w!("System.Volume.BitLockerProtection"), &mut key) }
        .map_err(|error| failed("the property is not known", error))?;

    let root: Vec<u16> = format!(r"{DRIVE}\")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let store: IPropertyStore =
        unsafe { SHGetPropertyStoreFromParsingName(PCWSTR(root.as_ptr()), None, GPS_DEFAULT) }
            .map_err(|error| failed("the drive would not open", error))?;
    let mut value = unsafe { store.GetValue(&key) }.map_err(|error| failed("no value", error))?;

    let number = unsafe {
        let inner = &value.Anonymous.Anonymous;
        let held = &inner.Anonymous;
        match inner.vt {
            VT_I4 | VT_INT => Some(i64::from(held.lVal)),
            VT_UI4 | VT_UINT => Some(i64::from(held.ulVal)),
            VT_I2 => Some(i64::from(held.iVal)),
            VT_UI2 => Some(i64::from(held.uiVal)),
            VT_UI1 => Some(i64::from(held.bVal)),
            _ => None,
        }
    };
    let _ = unsafe { PropVariantClear(&mut value) };
    number.ok_or_else(|| format!("Explorer gives no BitLocker state for drive {DRIVE}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Gathers the facts on this machine, so it is not run by default. A test
    /// build is not beside the agent, so an installed service turns it away,
    /// and records that refusal in its Activity log; it then goes down the
    /// second sources, `tpmtool` and Explorer's property, which is what
    /// running it by hand is for. What it prints is about the machine it ran
    /// on.
    #[test]
    #[ignore = "reads this machine's real state, runs tpmtool, and an installed service records the refusal"]
    fn show_this_machine() {
        println!("{:#?}", facts());
    }
}
