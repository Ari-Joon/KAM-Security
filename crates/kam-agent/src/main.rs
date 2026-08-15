//! The privileged half of KAM Security.
//!
//! Normally hosted by the Windows service control manager as SYSTEM. Pass
//! `--console` to run it as a foreground process instead, which is how it is
//! developed and debugged: same pipe, same dispatch, same trust check, but
//! attachable to a debugger and restartable without reinstalling the service.
//!
//! `--probe` connects to a running agent and prints its status. Because the
//! probe is this same executable it sits in the trusted directory, so ordinary
//! development exercises the caller check rather than bypassing it.

mod dispatch;
mod server;

use std::process::ExitCode;

use dispatch::Context;
use kam_ipc::pipe::PipeListener;

/// How the agent was started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Foreground process, for development.
    Console,
    /// Hosted by the service control manager.
    Service,
    /// Client mode: talk to a running agent and exit.
    Probe,
}

fn main() -> ExitCode {
    let mode = match parse_mode() {
        Ok(mode) => mode,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("usage: kam-agent [--console | --probe]");
            return ExitCode::FAILURE;
        }
    };

    init_tracing(mode);

    match run(mode) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "kam-agent failed");
            ExitCode::FAILURE
        }
    }
}

fn run(mode: Mode) -> kam_core::Result<()> {
    if mode == Mode::Probe {
        return server::probe();
    }

    tracing::info!(
        ?mode,
        version = env!("CARGO_PKG_VERSION"),
        "kam-agent starting"
    );

    if mode == Mode::Service {
        // Phase 1, remaining: register with the service control manager and
        // hand it a service_main that calls serve() below.
        eprintln!("service hosting is not implemented yet; run with --console");
        return Err(kam_core::Error::NotImplemented("service hosting"));
    }

    let context = Context {
        mode,
        store: server::open_store(mode == Mode::Service)?,
    };
    let listener = PipeListener::new();
    tracing::info!(pipe = kam_ipc::PIPE_NAME, "listening");
    server::serve(&listener, &context)
}

fn parse_mode() -> Result<Mode, String> {
    let mut mode = Mode::Service;
    for argument in std::env::args().skip(1) {
        match argument.as_str() {
            "--console" => mode = Mode::Console,
            "--probe" => mode = Mode::Probe,
            other => return Err(format!("unrecognised argument: {other}")),
        }
    }
    Ok(mode)
}

fn init_tracing(mode: Mode) {
    let filter = tracing_subscriber::EnvFilter::try_from_env("KAM_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(mode != Mode::Service)
        .init();
}
