//! The contract between the unprivileged shell and the SYSTEM agent.
//!
//! Transport is a named pipe carrying length-prefixed JSON. The pipe's DACL
//! restricts it to the interactive user and Administrators, and the agent
//! verifies the connecting process image before accepting any request.
//!
//! Keeping the surface small and explicitly enumerated is the point: the agent
//! runs as SYSTEM, so every variant added here is new attack surface.

pub mod client;
pub mod frame;
pub mod pipe;

use kam_core::audit::Record;
use serde::{Deserialize, Serialize};

/// Bumped whenever `Request` or `Response` changes shape. The shell refuses to
/// talk to an agent reporting a different version rather than guessing.
pub const PROTOCOL_VERSION: u32 = 1;

/// Pipe name. The `\\.\pipe\` prefix is added by the transport.
pub const PIPE_NAME: &str = "kam-security-agent";

/// Maximum accepted frame size. Guards against a malformed length prefix
/// causing an enormous allocation in the SYSTEM process.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// Largest number of audit rows the agent will return in one response.
///
/// The store lives where only the agent can read it, so the shell has to ask
/// for history rather than opening the database. Capping the answer keeps a
/// careless caller from requesting the entire log in a single frame.
pub const MAX_AUDIT_ROWS: u32 = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Liveness and version handshake.
    GetSystemStatus,
    /// Most recent audit entries, newest first. `limit` is clamped to
    /// [`MAX_AUDIT_ROWS`] by the agent rather than rejected.
    GetRecentAudit { limit: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    SystemStatus(SystemStatus),
    RecentAudit {
        entries: Vec<Record>,
    },
    /// The agent declined or failed. `message` is safe to show to the user.
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    pub protocol_version: u32,
    pub agent_version: String,
    /// True when the agent is hosted by the service control manager rather
    /// than running as a foreground console process for development.
    pub running_as_service: bool,
    pub hostname: String,
}
