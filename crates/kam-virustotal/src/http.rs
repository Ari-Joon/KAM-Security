//! The smallest HTTPS client that will do, built on WinHTTP.
//!
//! One `GET` against one host, with one header. Bringing in a full HTTP stack
//! and a bundled TLS implementation for that would add a hundred crates to a
//! product that has just spent sixteen megabytes on a rule engine.
//!
//! Using the operating system's stack is also the better answer on its own
//! merits for this particular request. WinHTTP validates certificates against
//! the machine's own trust store and honours the system proxy configuration,
//! so a managed machine behind a corporate proxy works without being told
//! about it, and an administrator who has distrusted a certificate authority
//! has that decision respected. A bundled TLS stack with its own root list
//! would quietly ignore both.

use std::time::Duration;

use windows::core::PCWSTR;
use windows::Win32::Networking::WinHttp::{
    WinHttpAddRequestHeaders, WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest,
    WinHttpQueryDataAvailable, WinHttpQueryHeaders, WinHttpReadData, WinHttpReceiveResponse,
    WinHttpSendRequest, WinHttpSetTimeouts, INTERNET_DEFAULT_HTTPS_PORT,
    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_ADDREQ_FLAG_ADD, WINHTTP_FLAG_SECURE,
    WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_STATUS_CODE,
};

/// Refuse to read an unbounded response. A lookup answer is a few kilobytes;
/// anything approaching this is not the API behaving normally.
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

const TIMEOUT: Duration = Duration::from_secs(20);

/// One HTTP response worth acting on.
#[derive(Debug)]
pub struct Response {
    pub status: u32,
    pub body: String,
}

/// A WinHTTP handle that closes itself.
///
/// Four handles are opened per request and every early return has to release
/// them; doing that by hand is how handle leaks get written.
struct Handle(*mut core::ffi::c_void);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = WinHttpCloseHandle(self.0);
            }
        }
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Perform a `GET` over HTTPS.
///
/// `host` is a bare hostname and `path` begins with a slash. `headers` are
/// sent as written. There is no redirect handling beyond WinHTTP's own, no
/// request body, and no other verb: this is not a general HTTP client and
/// should not grow into one.
pub fn get(host: &str, path: &str, headers: &str) -> kam_core::Result<Response> {
    let refused = |what: &str, error: windows::core::Error| {
        kam_core::Error::Refused(format!("{what}: {error}"))
    };

    let session = Handle(unsafe {
        WinHttpOpen(
            windows::core::w!("KAM Security"),
            // Follow whatever proxy the machine is configured to use, rather
            // than assuming a direct connection.
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            PCWSTR::null(),
            PCWSTR::null(),
            0,
        )
    });
    if session.0.is_null() {
        return Err(kam_core::Error::Refused(
            "the network stack could not be opened".to_owned(),
        ));
    }

    let milliseconds = TIMEOUT.as_millis() as i32;
    unsafe {
        let _ = WinHttpSetTimeouts(
            session.0,
            milliseconds,
            milliseconds,
            milliseconds,
            milliseconds,
        );
    }

    let host_wide = wide(host);
    let connection = Handle(unsafe {
        WinHttpConnect(
            session.0,
            PCWSTR(host_wide.as_ptr()),
            INTERNET_DEFAULT_HTTPS_PORT,
            0,
        )
    });
    if connection.0.is_null() {
        return Err(kam_core::Error::Refused(format!(
            "could not reach {host}; check the network connection"
        )));
    }

    let path_wide = wide(path);
    let request = Handle(unsafe {
        WinHttpOpenRequest(
            connection.0,
            windows::core::w!("GET"),
            PCWSTR(path_wide.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            std::ptr::null(),
            // HTTPS, with the certificate checked against the machine's trust
            // store. Never cleared, and there is no option to.
            WINHTTP_FLAG_SECURE,
        )
    });
    if request.0.is_null() {
        return Err(kam_core::Error::Refused(
            "the request could not be prepared".to_owned(),
        ));
    }

    if !headers.is_empty() {
        let headers_wide: Vec<u16> = headers.encode_utf16().collect();
        unsafe {
            WinHttpAddRequestHeaders(request.0, &headers_wide, WINHTTP_ADDREQ_FLAG_ADD)
        }
        .map_err(|error| refused("the request headers were rejected", error))?;
    }

    unsafe { WinHttpSendRequest(request.0, None, None, 0, 0, 0) }.map_err(|error| {
        kam_core::Error::Refused(format!(
            "the request to {host} could not be sent; check the network connection ({error})"
        ))
    })?;

    unsafe { WinHttpReceiveResponse(request.0, std::ptr::null_mut()) }
        .map_err(|error| refused("no response came back", error))?;

    let mut status = 0_u32;
    let mut size = std::mem::size_of::<u32>() as u32;
    let mut index = 0_u32;
    unsafe {
        WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            PCWSTR::null(),
            Some(&mut status as *mut u32 as *mut core::ffi::c_void),
            &mut size,
            &mut index,
        )
    }
    .map_err(|error| refused("the response had no status", error))?;

    let mut body = Vec::new();
    loop {
        let mut available = 0_u32;
        if unsafe { WinHttpQueryDataAvailable(request.0, &mut available) }.is_err() {
            break;
        }
        if available == 0 {
            break;
        }

        let wanted = (available as usize).min(MAX_RESPONSE_BYTES - body.len());
        if wanted == 0 {
            return Err(kam_core::Error::Refused(
                "the response was larger than expected and was abandoned".to_owned(),
            ));
        }

        let mut chunk = vec![0_u8; wanted];
        let mut read = 0_u32;
        if unsafe {
            WinHttpReadData(
                request.0,
                chunk.as_mut_ptr() as *mut core::ffi::c_void,
                wanted as u32,
                &mut read,
            )
        }
        .is_err()
        {
            break;
        }
        if read == 0 {
            break;
        }
        chunk.truncate(read as usize);
        body.extend_from_slice(&chunk);
    }

    Ok(Response {
        status,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Proves the transport end to end: DNS, TLS against the machine's trust
    /// store, the request, the response, and status parsing.
    ///
    /// Ignored by default because it reaches the network, which does not
    /// belong in an ordinary test run. It sends no API key and a hash of all
    /// zeros, which is not any real file — so it discloses nothing about this
    /// machine, and the 401 it expects is proof the round trip worked.
    ///
    /// Run with: cargo test -p kam-virustotal -- --ignored
    #[test]
    #[ignore = "reaches the network"]
    fn the_transport_reaches_virustotal() {
        let response = get(
            "www.virustotal.com",
            &format!("/api/v3/files/{}", "0".repeat(64)),
            "accept: application/json",
        )
        .expect("the request should complete");

        println!("status {}", response.status);
        assert_eq!(
            response.status, 401,
            "an unauthenticated request should be refused, not {}",
            response.status
        );
        assert!(
            !response.body.is_empty(),
            "a body should have been read back"
        );
    }

    #[test]
    fn a_bad_hostname_fails_rather_than_hanging() {
        // The important property for an interface that blocks on this: an
        // unreachable host must come back, and with something a person can
        // read.
        let started = std::time::Instant::now();
        let outcome = get(
            "kam-security-this-host-does-not-exist.invalid",
            "/",
            "",
        );
        assert!(outcome.is_err(), "a nonexistent host should not succeed");
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "took too long to give up"
        );
        let message = outcome.unwrap_err().to_string();
        assert!(
            !message.is_empty(),
            "the failure should say something useful"
        );
        println!("{message}");
    }
}
