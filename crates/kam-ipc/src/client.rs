//! The client half of the protocol.
//!
//! One request per connection. The agent serves connections sequentially, so a
//! client that held one open between calls would block every other caller for
//! as long as it felt like it. Connecting per call costs a pipe open and keeps
//! that impossible.

use kam_core::Result;

use crate::frame::{read_frame, write_frame};
use crate::{pipe, Request, Response, PIPE_NAME};

/// Send one request to the agent on the default pipe and read the reply.
pub fn call(request: &Request) -> Result<Response> {
    call_on(PIPE_NAME, request)
}

/// As [`call`], against a named pipe chosen by the caller. Used by tests.
pub fn call_on(pipe_name: &str, request: &Request) -> Result<Response> {
    let mut stream = pipe::connect(pipe_name)?;
    write_frame(&mut stream, request)?;
    read_frame(&mut stream)
}
