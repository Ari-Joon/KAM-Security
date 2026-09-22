//! Asking Windows for permission before a machine-wide change.
//!
//! # Why this exists
//!
//! The agent makes a machine-wide change (a Defender protection, a firewall
//! rule, audit policy, KAM's own protection, a cache outside the person's own
//! profile) only for a caller running with administrator rights. That matches
//! Windows itself, which asks for consent before any of these.
//!
//! The window normally runs without those rights, as it should. So when a
//! person presses a button that needs them, this asks Windows in the ordinary
//! way: the usual permission prompt appears, and if they approve, a short-lived
//! copy of this program starts with administrator rights, makes that one
//! change, writes the agent's answer where the window can read it, and exits.
//! The window never runs elevated, and nothing is changed without the prompt
//! being answered.
//!
//! # What the approved copy will do
//!
//! Exactly one request, and only one of the kinds listed in `allowed`. The
//! request travels on its command line, encoded; anything that does not decode
//! to one of those kinds is refused before the agent is contacted. Its answer
//! goes into a file the window created beforehand in the person's own
//! temporary folder: the approved copy only ever writes into that existing
//! file, never creates one, and refuses a name of the wrong shape or a link.

use std::io::Write as _;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use kam_ipc::{Request, Response};
use serde::{Deserialize, Serialize};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, ERROR_CANCELLED, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, WaitForSingleObject, INFINITE,
};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

/// What the approved copy writes back.
#[derive(Debug, Serialize, Deserialize)]
enum Outcome {
    Answered(Response),
    Failed(String),
}

/// The only requests that travel through the permission prompt.
///
/// The same set the agent requires administrator rights for. Anything else
/// has no reason to be elevated and is refused here, before anything runs.
fn allowed(request: &Request) -> bool {
    matches!(
        request,
        Request::SetProtection { .. }
            | Request::SetHardening { .. }
            | Request::SetCanaryAuditing { .. }
            | Request::BlockProgram { .. }
            | Request::UnblockProgram { .. }
            | Request::ClearCache { .. }
    )
}

/// Make a machine-wide change, asking Windows for consent if it is needed.
///
/// Blocks until the prompt is answered and the change is made, so it must be
/// called off the window's thread.
pub fn call(request: Request) -> Result<Response, String> {
    if !allowed(&request) {
        return Err("that change does not go through the permission prompt".to_owned());
    }
    if this_process_is_elevated() {
        return kam_ipc::client::call(&request).map_err(|error| error.to_string());
    }
    ask_windows(&request)
}

fn ask_windows(request: &Request) -> Result<Response, String> {
    let encoded = hex(&serde_json::to_vec(request).map_err(|error| error.to_string())?);

    // Created here, by the person's own unelevated process, so the approved
    // copy only has to write into something that already exists.
    let result = result_path();
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&result)
        .map_err(|error| format!("could not prepare for the answer: {error}"))?;
    let _cleanup = Remove(result.clone());

    let exe = std::env::current_exe().map_err(|error| error.to_string())?;
    let parameters = format!("--apply {encoded} --result \"{}\"", result.display());

    let verb = wide("runas");
    let file = wide_path(&exe);
    let parameters = wide(&parameters);
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };

    if let Err(error) = unsafe { ShellExecuteExW(&mut info) } {
        if error.code() == ERROR_CANCELLED.to_hresult() {
            return Err(
                "You declined Windows' permission prompt, so nothing was changed.".to_owned(),
            );
        }
        return Err(format!("Windows could not ask for permission: {error}"));
    }

    let process = Owned(info.hProcess);
    unsafe { WaitForSingleObject(process.0, INFINITE) };
    let mut code = 0_u32;
    let _ = unsafe { GetExitCodeProcess(process.0, &mut code) };

    let written = std::fs::read(&result).unwrap_or_default();
    match serde_json::from_slice::<Outcome>(&written) {
        Ok(Outcome::Answered(response)) => Ok(response),
        Ok(Outcome::Failed(message)) => Err(message),
        // Nothing usable came back. Not "it worked": the window re-reads the
        // real state afterwards, and this says plainly that the answer is
        // missing rather than inventing one.
        Err(_) => Err(format!(
            "The change was approved but no answer came back (exit code {code}). \
             What the agent actually did is recorded in Activity."
        )),
    }
}

/// Entry point for the approved copy. `None` means this is an ordinary launch.
///
/// Called from `main` before the window or the tray exist, so the single-
/// instance handling never sees this process and nothing but the one change
/// happens in it.
pub fn run_if_asked() -> Option<i32> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) != Some("--apply") {
        return None;
    }
    Some(apply(&args))
}

fn apply(args: &[String]) -> i32 {
    let [_, apply, encoded, result_flag, result] = args else {
        return 2;
    };
    if apply != "--apply" || result_flag != "--result" {
        return 2;
    }
    let Some(result) = acceptable_result_path(Path::new(result)) else {
        return 2;
    };
    let Some(request) = unhex(encoded)
        .and_then(|bytes| serde_json::from_slice::<Request>(&bytes).ok())
        .filter(allowed)
    else {
        return 2;
    };

    let (outcome, code) = match kam_ipc::client::call(&request) {
        Ok(Response::Error { message }) => (Outcome::Failed(message), 1),
        Ok(response) => (Outcome::Answered(response), 0),
        Err(error) => (Outcome::Failed(error.to_string()), 1),
    };

    // Open, never create, and never through a link: see the module doc.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(&result);
    let Ok(mut file) = file else {
        return 3;
    };
    if file
        .metadata()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(true)
    {
        return 3;
    }
    match serde_json::to_vec(&outcome) {
        Ok(bytes) if file.write_all(&bytes).is_ok() => code,
        _ => 3,
    }
}

/// A result file of exactly the shape the window creates, in this person's
/// own temporary folder, and nowhere else.
fn acceptable_result_path(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?.to_str()?;
    let middle = name.strip_prefix("kam-consent-")?.strip_suffix(".json")?;
    if middle.len() < 16 || !middle.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let parent = path.parent()?;
    let temp = std::env::temp_dir();
    let same = |a: &Path, b: &Path| {
        let plain = |p: &Path| {
            p.to_string_lossy()
                .to_lowercase()
                .trim_end_matches(['\\', '/'])
                .to_owned()
        };
        plain(a) == plain(b)
    };
    same(parent, &temp).then(|| path.to_path_buf())
}

fn result_path() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_nanos())
        .unwrap_or_default();
    std::env::temp_dir().join(format!(
        "kam-consent-{:08x}{:024x}.json",
        std::process::id(),
        nanos
    ))
}

/// Whether this process already has administrator rights.
pub fn this_process_is_elevated() -> bool {
    let mut token = HANDLE::default();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
        return false;
    }
    let token = Owned(token);
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0_u32;
    let read = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some((&raw mut elevation).cast()),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    read.is_ok() && elevation.TokenIsElevated != 0
}

struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// Deletes the result file however the call ends.
struct Remove(PathBuf);

impl Drop for Remove {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || text.len() > 64 * 1024 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_request_survives_the_command_line() {
        let request = Request::SetProtection { enabled: false };
        let encoded = hex(&serde_json::to_vec(&request).unwrap());
        let decoded: Request = serde_json::from_slice(&unhex(&encoded).unwrap()).unwrap();
        assert!(matches!(decoded, Request::SetProtection { enabled: false }));
    }

    /// Only the changes that need consent may be carried through the prompt.
    #[test]
    fn only_machine_wide_changes_are_carried() {
        assert!(allowed(&Request::SetProtection { enabled: true }));
        assert!(allowed(&Request::UnblockProgram {
            rule: String::new()
        }));
        for other in [
            Request::GetSystemStatus,
            Request::ListVolumes,
            Request::EmptyQuarantine,
            Request::RestoreQuarantined { id: "x".to_owned() },
        ] {
            assert!(!allowed(&other), "{other:?} would be run elevated");
        }
    }

    #[test]
    fn the_answer_goes_only_to_a_file_of_the_expected_shape_in_temp() {
        let temp = std::env::temp_dir();
        let good = temp.join("kam-consent-0123456789abcdef0123.json");
        assert!(acceptable_result_path(&good).is_some());

        for bad in [
            temp.join("kam-consent-short.json"),
            temp.join("kam-consent-0123456789abcdefXYZ0.json"),
            temp.join("something-else.json"),
            temp.join("nested")
                .join("kam-consent-0123456789abcdef0123.json"),
            PathBuf::from(r"C:\Windows\kam-consent-0123456789abcdef0123.json"),
        ] {
            assert!(
                acceptable_result_path(&bad).is_none(),
                "{} accepted",
                bad.display()
            );
        }
    }

    #[test]
    fn malformed_encodings_decode_to_nothing() {
        assert!(unhex("abc").is_none());
        assert!(unhex("zz").is_none());
        assert_eq!(unhex("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn a_shape_the_approved_copy_does_not_expect_is_refused() {
        let args = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(apply(&args(&["kam-shell.exe", "--apply"])), 2);
        assert_eq!(
            apply(&args(&["kam-shell.exe", "--apply", "00", "--other", "x"])),
            2
        );
    }
}
