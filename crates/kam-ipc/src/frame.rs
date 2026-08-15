//! Length-prefixed JSON framing.
//!
//! Wire format is a little-endian `u32` byte count followed by exactly that
//! many bytes of UTF-8 JSON. The transport underneath is a byte-mode named
//! pipe, which gives no message boundaries of its own.
//!
//! The length is validated against [`MAX_FRAME_BYTES`] *before* anything is
//! allocated. The reader runs inside a SYSTEM process, so a peer that claims a
//! four-gigabyte frame must not be able to make it allocate one.
//!
//! Kept generic over [`Read`] and [`Write`] so the codec is exercised by unit
//! tests against in-memory buffers, with no pipe and no privileges involved.

use std::io::{Read, Write};

use kam_core::{Error, Result};
use serde::{de::DeserializeOwned, Serialize};

use crate::MAX_FRAME_BYTES;

/// Serialise `value` and write it as one frame.
pub fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<()>
where
    W: Write,
    T: Serialize + ?Sized,
{
    let payload = serde_json::to_vec(value)
        .map_err(|error| Error::Protocol(format!("could not serialise frame: {error}")))?;

    let len = u32::try_from(payload.len())
        .map_err(|_| Error::Protocol("frame exceeds the maximum length".to_owned()))?;

    if payload.len() > MAX_FRAME_BYTES {
        return Err(Error::Protocol(format!(
            "frame of {} bytes exceeds the {MAX_FRAME_BYTES} byte limit",
            payload.len()
        )));
    }

    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

/// Read one frame and deserialise it.
///
/// Returns [`Error::Protocol`] for a frame that is oversized, truncated, or not
/// valid JSON for `T`. Callers treat any of those as fatal for the connection.
pub fn read_frame<R, T>(reader: &mut R) -> Result<T>
where
    R: Read,
    T: DeserializeOwned,
{
    let mut length_prefix = [0_u8; 4];
    reader.read_exact(&mut length_prefix)?;
    let len = u32::from_le_bytes(length_prefix) as usize;

    // Checked before the allocation below, not after.
    if len > MAX_FRAME_BYTES {
        return Err(Error::Protocol(format!(
            "peer announced a {len} byte frame, over the {MAX_FRAME_BYTES} byte limit"
        )));
    }

    let mut payload = vec![0_u8; len];
    reader.read_exact(&mut payload)?;

    serde_json::from_slice(&payload)
        .map_err(|error| Error::Protocol(format!("could not deserialise frame: {error}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::{Request, Response};

    #[test]
    fn round_trips_a_request() {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, &Request::GetSystemStatus).unwrap();

        let mut cursor = Cursor::new(buffer);
        let decoded: Request = read_frame(&mut cursor).unwrap();
        assert!(matches!(decoded, Request::GetSystemStatus));
    }

    #[test]
    fn reads_frames_back_to_back_from_one_stream() {
        // A byte-mode pipe carries no message boundaries, so two frames written
        // in sequence have to come back out as two frames.
        let mut buffer = Vec::new();
        write_frame(&mut buffer, &Request::GetSystemStatus).unwrap();
        write_frame(&mut buffer, &Request::GetSystemStatus).unwrap();

        let mut cursor = Cursor::new(buffer);
        let _: Request = read_frame(&mut cursor).unwrap();
        let _: Request = read_frame(&mut cursor).unwrap();
    }

    #[test]
    fn rejects_an_oversized_length_prefix_without_allocating() {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&u32::MAX.to_le_bytes());

        let mut cursor = Cursor::new(buffer);
        let outcome: Result<Request> = read_frame(&mut cursor);
        assert!(matches!(outcome, Err(Error::Protocol(_))));
    }

    #[test]
    fn rejects_a_truncated_payload() {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, &Request::GetSystemStatus).unwrap();
        buffer.truncate(buffer.len() - 1);

        let mut cursor = Cursor::new(buffer);
        let outcome: Result<Request> = read_frame(&mut cursor);
        assert!(matches!(outcome, Err(Error::Io(_))));
    }

    #[test]
    fn rejects_a_payload_that_is_not_valid_for_the_target_type() {
        let mut buffer = Vec::new();
        write_frame(
            &mut buffer,
            &Response::Error {
                message: "no".to_owned(),
            },
        )
        .unwrap();

        let mut cursor = Cursor::new(buffer);
        let outcome: Result<Request> = read_frame(&mut cursor);
        assert!(matches!(outcome, Err(Error::Protocol(_))));
    }
}
