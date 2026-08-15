//! The single error type shared across the workspace.

use std::io;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    /// The caller asked for something the agent will not do, such as moving a
    /// file that falls outside the safe file classes. Carries the reason so the
    /// UI can explain the refusal rather than showing a bare failure.
    #[error("refused: {0}")]
    Refused(String),

    /// A privileged operation failed. Wraps the underlying Win32 description.
    #[error("privileged operation failed: {0}")]
    Privileged(String),

    /// A peer sent something that does not fit the wire format: a bad length
    /// prefix, a truncated frame, or a payload that will not deserialise. The
    /// agent closes the connection rather than trying to interpret it.
    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("not implemented yet: {0}")]
    NotImplemented(&'static str),
}
