//! The privileged half of KAM Security.
//!
//! Normally hosted by the Windows service control manager as SYSTEM. Pass
//! `--console` to run it as a foreground process instead, which is how it is
//! developed and debugged: same RPC surface, same dispatch, but attachable to a
//! debugger and restartable without reinstalling the service.
//!
//! Service hosting is only exercised by integration tests and release builds.

mod dispatch;

use std::process::ExitCode;

/// How the agent was started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Foreground process, for development.
    Console,
    /// Hosted by the service control manager.
    Service,
}

fn main() -> ExitCode {
    let mode = match parse_mode() {
        Ok(mode) => mode,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("usage: kam-agent [--console]");
            return ExitCode::FAILURE;
        }
    };

    init_tracing(mode);
    tracing::info!(?mode, version = env!("CARGO_PKG_VERSION"), "kam-agent starting");

    match mode {
        Mode::Console => run_console(),
        Mode::Service => {
            // Phase 1: register with the service control manager, create the
            // named pipe with its restricting DACL, and serve dispatch::handle.
            eprintln!("service hosting is not implemented yet; run with --console");
            ExitCode::FAILURE
        }
    }
}

fn parse_mode() -> Result<Mode, String> {
    let mut mode = Mode::Service;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--console" => mode = Mode::Console,
            other => return Err(format!("unrecognised argument: {other}")),
        }
    }
    Ok(mode)
}

fn init_tracing(mode: Mode) {
    // Console runs are read by a human at a terminal. Service runs will write
    // to the audit log and the Windows event log once Phase 1 lands.
    let builder = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("KAM_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_ansi(mode == Mode::Console);
    builder.init();
}

/// Development entry point. Answers one request on stdout so the transport can
/// be swapped in underneath without changing dispatch.
fn run_console() -> ExitCode {
    let response = dispatch::handle(kam_ipc::Request::GetSystemStatus, Mode::Console);
    match serde_json::to_string_pretty(&response) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            tracing::error!(%error, "failed to serialise response");
            ExitCode::FAILURE
        }
    }
}
