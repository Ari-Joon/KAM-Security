//! Maps an incoming [`Request`] onto the module that serves it.
//!
//! Every arm is expected to record an audit entry before returning. Keeping
//! dispatch in one place means the audit requirement is reviewable by reading a
//! single file.

use kam_ipc::{Request, Response, SystemStatus};

use crate::Mode;

pub fn handle(request: Request, mode: Mode) -> Response {
    match request {
        Request::GetSystemStatus => Response::SystemStatus(SystemStatus {
            protocol_version: kam_ipc::PROTOCOL_VERSION,
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
            running_as_service: mode == Mode::Service,
            hostname: hostname(),
        }),
    }
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_owned())
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn status_reports_the_current_protocol_version() {
        let Response::SystemStatus(status) = handle(Request::GetSystemStatus, Mode::Console) else {
            panic!("expected a status response");
        };
        assert_eq!(status.protocol_version, kam_ipc::PROTOCOL_VERSION);
        assert!(!status.running_as_service);
    }
}
