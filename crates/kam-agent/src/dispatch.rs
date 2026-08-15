//! Maps an incoming [`Request`] onto the module that serves it.
//!
//! Keeping dispatch in one file means the audit rule can be checked by reading
//! one file. That rule is narrower than "log everything": the log records what
//! the agent *does to the system*, and what it *refuses* to do. Reads — status
//! polls, history reloads — are not recorded, because the shell issues them
//! continuously and auditing them would bury every entry that matters.

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
            // Not audited. The shell polls this to keep its connection
            // indicator honest, so auditing it would add a row every few
            // seconds and bury the entries that describe real actions. The rule
            // is: the log records what the agent *does to the system*, and what
            // it refuses. Answering questions about itself is neither.
            Response::SystemStatus(status)
        }

        Request::GetRecentAudit { limit } => {
            // Clamped rather than refused: a caller asking for more history
            // than exists is not doing anything wrong, and an error here would
            // be a worse experience than a shorter list.
            let limit = limit.min(kam_ipc::MAX_AUDIT_ROWS);
            match context.store.recent_audit(limit as usize) {
                Ok(entries) => {
                    // Deliberately not audited. Reading the log is not an action
                    // on the system, and recording every read would bury the
                    // entries that matter under entries about looking at them.
                    Response::RecentAudit { entries }
                }
                Err(error) => {
                    tracing::error!(%error, "could not read the audit log");
                    Response::Error {
                        message: "the audit log could not be read".to_owned(),
                    }
                }
            }
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
    fn reads_are_not_audited() {
        // The shell polls status and reloads history continuously. If either
        // were audited the log would fill with entries about being looked at,
        // and the entries that matter would be unfindable.
        let context = context(Mode::Service);
        let _ = handle(Request::GetSystemStatus, &context);
        let _ = handle(Request::GetRecentAudit { limit: 10 }, &context);

        assert!(context.store.recent_audit(10).unwrap().is_empty());
    }

    #[test]
    fn an_oversized_audit_request_is_clamped_rather_than_refused() {
        let context = context(Mode::Console);
        let response = handle(Request::GetRecentAudit { limit: u32::MAX }, &context);
        assert!(matches!(response, Response::RecentAudit { .. }));
    }
}
