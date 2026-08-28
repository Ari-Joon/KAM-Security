//! The client half of the protocol.
//!
//! One request per connection. The agent serves connections sequentially per
//! stream, so a client that held one open between calls would block that
//! instance for as long as it felt like it. Connecting per call costs a pipe
//! open and keeps that impossible.
//!
//! A reply is a stream: zero or more progress frames, then exactly one result.
//! [`call`] discards the progress and returns the result, which is what most
//! callers want; [`call_streaming`] hands each progress frame to a callback as
//! it arrives.

use kam_core::{Progress, Result};

use crate::frame::{read_frame, write_frame};
use crate::{pipe, Reply, Request, Response, PIPE_NAME};

/// Send one request and read the result, ignoring any progress along the way.
pub fn call(request: &Request) -> Result<Response> {
    call_on(PIPE_NAME, request)
}

/// As [`call`], against a named pipe chosen by the caller. Used by tests.
pub fn call_on(pipe_name: &str, request: &Request) -> Result<Response> {
    call_streaming_on(pipe_name, request, |_| {})
}

/// Send one request, reporting progress as it arrives, and return the result.
pub fn call_streaming(request: &Request, on_progress: impl FnMut(Progress)) -> Result<Response> {
    call_streaming_on(PIPE_NAME, request, on_progress)
}

/// As [`call_streaming`], against a named pipe chosen by the caller.
pub fn call_streaming_on(
    pipe_name: &str,
    request: &Request,
    on_progress: impl FnMut(Progress),
) -> Result<Response> {
    let mut stream = pipe::connect(pipe_name)?;
    write_frame(&mut stream, request)?;
    read_reply(&mut stream, on_progress)
}

/// Read frames until the one that ends the exchange.
///
/// There is no frame count to read up to and no sentinel beyond `Done`, which
/// is exactly why `Done` is a distinct variant rather than a flag on the
/// result: the loop cannot terminate by accident, and a malformed stream ends
/// as a read error rather than as a silently truncated answer.
///
/// Generic over the reader so the contract can be tested without a pipe.
pub fn read_reply<R: std::io::Read>(
    reader: &mut R,
    mut on_progress: impl FnMut(Progress),
) -> Result<Response> {
    loop {
        match read_frame::<_, Reply>(reader)? {
            Reply::Progress(progress) => on_progress(progress),
            Reply::Done(response) => return Ok(response),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn stream_of(replies: &[Reply]) -> std::io::Cursor<Vec<u8>> {
        let mut buffer = Vec::new();
        for reply in replies {
            write_frame(&mut buffer, reply).unwrap();
        }
        std::io::Cursor::new(buffer)
    }

    #[test]
    fn progress_frames_are_delivered_before_the_result() {
        let mut stream = stream_of(&[
            Reply::Progress(Progress {
                stage: "Reading".to_owned(),
                done: 0,
                total: Some(2),
                detail: None,
            }),
            Reply::Progress(Progress {
                stage: "Reading".to_owned(),
                done: 2,
                total: Some(2),
                detail: Some("a file".to_owned()),
            }),
            Reply::Done(Response::Acknowledged),
        ]);

        let mut seen = Vec::new();
        let response = read_reply(&mut stream, |progress| seen.push(progress)).unwrap();

        assert!(matches!(response, Response::Acknowledged));
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[1].done, 2);
        assert_eq!(seen[1].detail.as_deref(), Some("a file"));
    }

    #[test]
    fn a_reply_with_no_progress_still_works() {
        // Every short request takes this path, so it is the one that must not
        // regress when progress is added to a long one.
        let mut stream = stream_of(&[Reply::Done(Response::Acknowledged)]);
        let mut seen = 0;
        let response = read_reply(&mut stream, |_| seen += 1).unwrap();
        assert!(matches!(response, Response::Acknowledged));
        assert_eq!(seen, 0);
    }

    #[test]
    fn a_stream_that_ends_without_a_result_is_an_error() {
        // Rather than returning a plausible-looking empty answer.
        let mut stream = stream_of(&[Reply::Progress(Progress {
            stage: "Reading".to_owned(),
            done: 1,
            total: None,
            detail: None,
        })]);
        assert!(read_reply(&mut stream, |_| {}).is_err());
    }

    #[test]
    fn nothing_after_the_result_is_read() {
        // The connection is closed once the result arrives, so anything the
        // agent wrote afterwards must not be consumed as part of this call.
        let mut stream = stream_of(&[
            Reply::Done(Response::Acknowledged),
            Reply::Progress(Progress {
                stage: "too late".to_owned(),
                done: 0,
                total: None,
                detail: None,
            }),
        ]);
        read_reply(&mut stream, |_| panic!("read past the result")).unwrap();
    }
}
