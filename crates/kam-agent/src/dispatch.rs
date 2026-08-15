//! Maps an incoming [`Request`] onto the module that serves it.
//!
//! Every arm records an audit entry. Keeping dispatch in one place means the
//! "every privileged action is logged" rule is reviewable by reading one file.

use kam_core::audit::{Effect, Entry};
use kam_core::Store;
use kam_ipc::{Request, Response, SystemStatus};

use crate::server;
use crate::Mode;

/// Everything a handler is allowed to reach.
#[derive(Debug)]
pub struct Context {
    pub mode: Mode,
    pub store: Store,
}

impl Context {
    pub fn audit(
        &self,
        module: &'static str,
        action: &'static str,
        effect: Effect,
        detail: String,
    ) {
        server::record(
            &self.store,
            Entry {
                module,
                action,
                effect,
                detail,
                undo_token: None,
            },
        );
    }

    fn running_as_service(&self) -> bool {
        self.mode == Mode::Service
    }
}

pub fn handle(request: Request, context: &Context) -> Response {
    match request {
        Request::GetSystemStatus => {
            let status = SystemStatus {
                protocol_version: kam_ipc::PROTOCOL_VERSION,
                agent_version: env!("CARGO_PKG_VERSION").to_owned(),
                running_as_service: context.running_as_service(),
                hostname: hostname(),
            };
            context.audit(
                "agent",
                "get_system_status",
                Effect::Observed,
                "reported agent status".to_owned(),
            );
            Response::SystemStatus(status)
        }
    }
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_owned())
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn context(mode: Mode) -> Context {
        Context {
            mode,
            store: Store::open_in_memory().unwrap(),
        }
    }

    #[test]
    fn status_reports_the_current_protocol_version() {
        let context = context(Mode::Console);
        let Response::SystemStatus(status) = handle(Request::GetSystemStatus, &context) else {
            panic!("expected a status response");
        };
        assert_eq!(status.protocol_version, kam_ipc::PROTOCOL_VERSION);
        assert!(!status.running_as_service);
    }

    #[test]
    fn serving_a_request_leaves_an_audit_trail() {
        let context = context(Mode::Service);
        let _ = handle(Request::GetSystemStatus, &context);

        let records = context.store.recent_audit(10).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].module, "agent");
        assert_eq!(records[0].action, "get_system_status");
        assert_eq!(records[0].effect, Effect::Observed);
    }
}
