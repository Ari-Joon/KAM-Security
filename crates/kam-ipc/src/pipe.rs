//! Named pipe transport, and the access control that makes it safe to expose.
//!
//! The server end runs inside a SYSTEM process, so the pipe is the boundary
//! where an unprivileged caller meets full privilege. Three things defend it:
//!
//! 1. **A protected DACL.** Only SYSTEM, Administrators, and the interactive
//!    user can open the pipe at all. `D:P` blocks inherited ACEs, so nothing in
//!    the object's ancestry can widen this.
//! 2. **`PIPE_REJECT_REMOTE_CLIENTS`.** Named pipes are reachable over SMB by
//!    default. This is a local IPC channel and has no business accepting a
//!    connection from another machine.
//! 3. **Caller identification.** [`PipeStream::client_image_path`] resolves the
//!    connecting process's executable so the agent can decide whether to serve
//!    it. Being *allowed* to open the pipe is not the same as being trusted to
//!    drive it.
//!
//! The listener keeps [`MAX_PIPE_INSTANCES`] instances available. One is not
//! enough once connections are served concurrently: `CreateNamedPipeW` refuses
//! with `ERROR_PIPE_BUSY` while an existing instance is connected, so the accept
//! loop would spin on that error for as long as any request was in flight.

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

use kam_core::{Error, Result};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, ERROR_PIPE_CONNECTED, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, ReadFile, WriteFile, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_SHARE_MODE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::{MAX_PIPE_INSTANCES, PIPE_NAME};

/// Security descriptor applied to the pipe, in SDDL.
///
/// - `D:P` -- a protected DACL: inherited entries are not applied.
/// - `(A;;GA;;;SY)` -- Local System, full control. The agent itself.
/// - `(A;;GA;;;BA)` -- Builtin Administrators, full control.
/// - `(A;;0x120183;;;IU)` -- Interactive Users: read data, write data, read and
///   write attributes, read control, synchronise. Nothing else.
///
/// That mask is spelled out rather than written `GRGW` for one specific reason.
/// Generic write on a pipe expands to include `FILE_APPEND_DATA`, and on a
/// named pipe that bit *is* `FILE_CREATE_PIPE_INSTANCE`. Granting it lets any
/// process running as the desktop user create another instance of this pipe,
/// accept the shell's connections, and answer them — impersonating a SYSTEM
/// service to the user's own interface. It cannot gain privilege that way, but
/// it can report a clean machine on a dirty one, which for this application is
/// the worse failure.
///
/// Network, Anonymous, and every service account other than SYSTEM are absent,
/// and absence in a DACL is denial.
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x120183;;;IU)";

/// Exactly what a client needs, and nothing more: read data, write data, read
/// and write attributes, read control, synchronise.
///
/// It must be spelled out for the same reason the descriptor is. Asking for
/// `GENERIC_WRITE` expands to include `FILE_APPEND_DATA`, which the pipe's DACL
/// deliberately withholds, so a blanket request is refused outright — the
/// tightened descriptor and the client's access mask have to agree.
const CLIENT_ACCESS: u32 = 0x0012_0183;

const PIPE_BUFFER_BYTES: u32 = 64 * 1024;
/// Milliseconds a client will wait in `WaitNamedPipe` if all instances are busy.
const PIPE_DEFAULT_TIMEOUT_MS: u32 = 5_000;

fn wide(text: &str) -> Vec<u16> {
    OsString::from(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn full_pipe_path(name: &str) -> Vec<u16> {
    wide(&format!(r"\\.\pipe\{name}"))
}

fn win32(error: windows::core::Error, context: &str) -> Error {
    Error::Privileged(format!("{context}: {error}"))
}

/// A security descriptor parsed from SDDL, owning the allocation behind it.
struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self> {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let sddl = wide(sddl);
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(|error| win32(error, "could not parse the pipe security descriptor"))?;
        Ok(Self(descriptor))
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0 .0,
            bInheritHandle: false.into(),
        }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0 .0.is_null() {
            unsafe { LocalFree(Some(HLOCAL(self.0 .0))) };
        }
    }
}

/// A connected pipe, from either end.
#[derive(Debug)]
pub struct PipeStream {
    handle: HANDLE,
    /// True on the server end, which must disconnect before closing.
    is_server: bool,
}

// The handle is owned exclusively by this value and every call through it is a
// blocking synchronous Win32 call, so moving it between threads is sound.
unsafe impl Send for PipeStream {}

impl PipeStream {
    /// Process id at the far end. Server side only.
    pub fn client_process_id(&self) -> Result<u32> {
        let mut process_id = 0_u32;
        unsafe { GetNamedPipeClientProcessId(self.handle, &mut process_id) }
            .map_err(|error| win32(error, "could not identify the calling process"))?;
        Ok(process_id)
    }

    /// Full path of the executable at the far end.
    ///
    /// Opened with `PROCESS_QUERY_LIMITED_INFORMATION`, which is the least
    /// privilege that answers this question, and uses the Win32 path format so
    /// the result can be compared against the agent's own directory.
    pub fn client_image_path(&self) -> Result<PathBuf> {
        let process_id = self.client_process_id()?;

        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id) }
            .map_err(|error| win32(error, "could not open the calling process"))?;
        // Closed on drop, including on the early return below.
        let process = OwnedHandle(process);

        let mut buffer = [0_u16; 32_768];
        let mut length = buffer.len() as u32;
        unsafe {
            QueryFullProcessImageNameW(
                process.0,
                PROCESS_NAME_WIN32,
                PWSTR(buffer.as_mut_ptr()),
                &mut length,
            )
        }
        .map_err(|error| win32(error, "could not read the calling process image path"))?;

        Ok(PathBuf::from(OsString::from_wide(
            &buffer[..length as usize],
        )))
    }

    /// Textual SID of the account the caller is running as. Server side only.
    ///
    /// This is how the agent knows whose data a request is about. It runs as
    /// LocalSystem, so its own environment and `HKEY_CURRENT_USER` describe
    /// SYSTEM and nobody else; asking the caller who they are would be worse
    /// still, since a client could then name anybody. The answer comes from the
    /// caller's own access token, which the caller does not get to write.
    ///
    /// `PROCESS_QUERY_LIMITED_INFORMATION` is enough to open the token for
    /// reading, and `TOKEN_QUERY` is enough to read the user out of it. Neither
    /// permits impersonation, and nothing here acquires the caller's rights.
    pub fn client_sid(&self) -> Result<String> {
        let process_id = self.client_process_id()?;

        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id) }
            .map_err(|error| win32(error, "could not open the calling process"))?;
        let process = OwnedHandle(process);

        let mut token = HANDLE::default();
        unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) }
            .map_err(|error| win32(error, "could not open the caller's token"))?;
        let token = OwnedHandle(token);

        // Two calls: the first fails with the required length, which is the
        // documented way to size a variable-length token structure.
        let mut needed = 0_u32;
        let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut needed) };
        if needed == 0 {
            return Err(Error::Privileged(
                "the caller's token reported no size for its user".to_owned(),
            ));
        }

        let mut buffer = vec![0_u8; needed as usize];
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                Some(buffer.as_mut_ptr().cast()),
                needed,
                &mut needed,
            )
        }
        .map_err(|error| win32(error, "could not read the caller's user"))?;

        // The SID sits after the structure in the same allocation, which is
        // why the buffer must outlive the pointer read out of it.
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        let mut text = PWSTR::null();
        unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) }
            .map_err(|error| win32(error, "could not format the caller's SID"))?;

        let sid = unsafe { text.to_string() }
            .map_err(|_| Error::Protocol("the caller's SID was not valid text".to_owned()))?;
        unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
        Ok(sid)
    }
}

impl Read for PipeStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut read = 0_u32;
        unsafe { ReadFile(self.handle, Some(buffer), Some(&mut read), None) }
            .map_err(io::Error::other)?;
        Ok(read as usize)
    }
}

impl Write for PipeStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut written = 0_u32;
        unsafe { WriteFile(self.handle, Some(buffer), Some(&mut written), None) }
            .map_err(io::Error::other)?;
        Ok(written as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for PipeStream {
    fn drop(&mut self) {
        unsafe {
            if self.is_server {
                // DisconnectNamedPipe discards anything still sitting in the
                // pipe that the client has not read, so a response written
                // immediately before the disconnect would be thrown away.
                // FlushFileBuffers blocks until the client has drained it.
                //
                // The block is bounded only by the client, so a peer that stops
                // reading holds this thread. Acceptable while the accept loop
                // only ever serves a caller that passed the trust check; a
                // write deadline needs overlapped IO and is deferred.
                let _ = FlushFileBuffers(self.handle);
                let _ = DisconnectNamedPipe(self.handle);
            }
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Small RAII wrapper so an early return cannot leak a process handle.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// Server end. Creates one pipe instance per [`accept`](Self::accept) call.
#[derive(Debug)]
pub struct PipeListener {
    name: String,
    /// Cleared once the first instance has been created, so only that one asks
    /// for `FILE_FLAG_FIRST_PIPE_INSTANCE` -- later instances must not, or they
    /// would be refused for colliding with the name this listener owns.
    claim_name: AtomicBool,
}

impl PipeListener {
    pub fn new() -> Self {
        Self::with_name(PIPE_NAME)
    }

    /// Listener on a non-default pipe name, for tests running concurrently.
    pub fn with_name(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            claim_name: AtomicBool::new(true),
        }
    }

    /// Block until a client connects, then hand back the connected instance.
    pub fn accept(&self) -> Result<PipeStream> {
        let security = SecurityDescriptor::from_sddl(PIPE_SDDL)?;
        let attributes = security.attributes();
        let path = full_pipe_path(&self.name);

        // Only the first instance claims the name. The flag makes Windows
        // refuse the call outright if the pipe already exists, which is what
        // stops another process getting in first and impersonating the agent --
        // and tells us immediately if one already has.
        let first = self.claim_name.swap(false, AtomicOrdering::SeqCst);
        let open_mode = if first {
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE
        } else {
            PIPE_ACCESS_DUPLEX
        };

        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(path.as_ptr()),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                // Several instances, because connections are served on their
                // own threads: with one, creating the next instance fails with
                // ERROR_PIPE_BUSY for as long as a single request is in flight.
                MAX_PIPE_INSTANCES,
                PIPE_BUFFER_BYTES,
                PIPE_BUFFER_BYTES,
                PIPE_DEFAULT_TIMEOUT_MS,
                Some(&attributes),
            )
        };

        if handle.is_invalid() {
            let error = windows::core::Error::from_thread();
            if first {
                return Err(Error::Refused(format!(
                    "the agent pipe already exists, so something else is already \
                     serving it — refusing to share the name: {error}"
                )));
            }
            return Err(win32(error, "could not create the agent pipe"));
        }

        let stream = PipeStream {
            handle,
            is_server: true,
        };

        // A client that connected between CreateNamedPipeW and ConnectNamedPipe
        // surfaces as ERROR_PIPE_CONNECTED, which is success, not failure.
        if let Err(error) = unsafe { ConnectNamedPipe(stream.handle, None) } {
            if error.code() != ERROR_PIPE_CONNECTED.to_hresult() {
                return Err(win32(error, "could not accept a pipe connection"));
            }
        }

        Ok(stream)
    }
}

impl Default for PipeListener {
    fn default() -> Self {
        Self::new()
    }
}

/// Client end. Used by the shell, and by the integration tests.
pub fn connect(name: &str) -> Result<PipeStream> {
    let path = full_pipe_path(name);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            CLIENT_ACCESS,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    }
    .map_err(|error| win32(error, "could not connect to the agent"))?;

    Ok(PipeStream {
        handle,
        is_server: false,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::thread;

    use super::*;
    use crate::frame::{read_frame, write_frame};
    use crate::{Request, Response, SystemStatus};

    fn unique_name(tag: &str) -> String {
        format!("kam-test-{tag}-{}", std::process::id())
    }

    #[test]
    fn a_request_and_response_survive_a_real_pipe() {
        let name = unique_name("roundtrip");
        let listener = PipeListener::with_name(name.clone());

        let server = thread::spawn(move || {
            let mut stream = listener.accept().unwrap();
            let request: Request = read_frame(&mut stream).unwrap();
            assert!(matches!(request, Request::GetSystemStatus));
            write_frame(
                &mut stream,
                &Response::SystemStatus(SystemStatus {
                    protocol_version: crate::PROTOCOL_VERSION,
                    agent_version: "test".to_owned(),
                    running_as_service: false,
                    hostname: "test-host".to_owned(),
                }),
            )
            .unwrap();
        });

        // The listener creates its instance inside accept(), so the client
        // retries briefly rather than assuming the pipe already exists.
        let mut client = None;
        for _ in 0..50 {
            match connect(&name) {
                Ok(stream) => {
                    client = Some(stream);
                    break;
                }
                Err(_) => thread::sleep(std::time::Duration::from_millis(20)),
            }
        }
        let mut client = client.expect("the listener never came up");

        write_frame(&mut client, &Request::GetSystemStatus).unwrap();
        let response: Response = read_frame(&mut client).unwrap();
        match response {
            Response::SystemStatus(status) => assert_eq!(status.hostname, "test-host"),
            other => panic!("unexpected response: {other:?}"),
        }

        server.join().unwrap();
    }

    #[test]
    fn the_server_can_identify_the_process_at_the_far_end() {
        let name = unique_name("identify");
        let listener = PipeListener::with_name(name.clone());

        let server = thread::spawn(move || {
            let stream = listener.accept().unwrap();
            (
                stream.client_process_id().unwrap(),
                stream.client_image_path().unwrap(),
                stream.client_sid().unwrap(),
            )
        });

        let mut client = None;
        for _ in 0..50 {
            match connect(&name) {
                Ok(stream) => {
                    client = Some(stream);
                    break;
                }
                Err(_) => thread::sleep(std::time::Duration::from_millis(20)),
            }
        }
        let _client = client.expect("the listener never came up");

        let (process_id, image_path, sid) = server.join().unwrap();
        // Both ends are this test binary, so the answer is checkable.
        assert_eq!(process_id, std::process::id());
        assert!(
            image_path
                .to_string_lossy()
                .to_lowercase()
                .contains("kam_ipc"),
            "unexpected image path: {}",
            image_path.display()
        );

        // A user SID, not a service account: S-1-5-21-... is a domain or local
        // machine account, and SYSTEM would be S-1-5-18. The agent reads this
        // to work out whose AppData and whose launch history a request is
        // about, so getting SYSTEM's here would reproduce exactly the bug that
        // made it report every application as never opened.
        assert!(sid.starts_with("S-1-5-21-"), "unexpected SID: {sid}");
        assert_ne!(sid, "S-1-5-18", "that is LocalSystem, not the caller");

        // And it must name a real profile, since that is what it is used for.
        let user = kam_core::UserContext::for_sid(&sid).expect("the caller has a profile");
        assert_eq!(
            user.profile().to_lowercase(),
            kam_core::UserContext::current().profile().to_lowercase()
        );
    }

    #[test]
    fn the_sddl_parses_into_a_usable_descriptor() {
        let descriptor = SecurityDescriptor::from_sddl(PIPE_SDDL).unwrap();
        assert!(!descriptor.0 .0.is_null());
    }

    #[test]
    fn the_interactive_user_is_not_granted_pipe_instance_creation() {
        // Generic write on a pipe includes FILE_APPEND_DATA, which for a named
        // pipe is FILE_CREATE_PIPE_INSTANCE. Granting it would let any process
        // running as the desktop user stand up another instance of this pipe
        // and answer the shell in the agent's place.
        assert!(
            !PIPE_SDDL.contains("GW"),
            "the descriptor grants generic write: {PIPE_SDDL}"
        );
        assert!(PIPE_SDDL.contains("0x120183"), "expected an explicit mask");
        // FILE_APPEND_DATA / FILE_CREATE_PIPE_INSTANCE is 0x0004.
        assert_eq!(0x0012_0183 & 0x0000_0004, 0, "instance creation is granted");
    }

    #[test]
    fn a_second_listener_cannot_steal_a_name_already_being_served() {
        // The impersonation guard, exercised for real: while one listener holds
        // the name, a second must be refused rather than allowed to accept
        // connections meant for the first.
        let name = unique_name("exclusive");
        let holder = PipeListener::with_name(name.clone());

        let ready = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let signal = std::sync::Arc::clone(&ready);
        let served = thread::spawn(move || {
            signal.store(true, std::sync::atomic::Ordering::SeqCst);
            holder.accept()
        });

        while !ready.load(std::sync::atomic::Ordering::SeqCst) {
            thread::sleep(std::time::Duration::from_millis(5));
        }
        thread::sleep(std::time::Duration::from_millis(200));

        let impostor = PipeListener::with_name(name.clone());
        assert!(
            impostor.accept().is_err(),
            "a second listener claimed a pipe already being served"
        );

        // Let the holder finish so no thread is left parked.
        drop(connect(&name));
        let _ = served.join();
    }
}
