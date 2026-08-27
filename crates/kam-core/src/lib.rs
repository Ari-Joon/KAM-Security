//! Shared foundations for every KAM Security crate: the error type, the audit
//! log, configuration, and the local SQLite store.
//!
//! Nothing in here is allowed to perform a privileged operation. This crate is
//! linked by both the agent and (indirectly) the shell, so it stays inert.

pub mod audit;
pub mod db;
pub mod env;
pub mod error;
pub mod mui;
pub mod progress;
pub mod registry;

pub use db::Store;
pub use error::{Error, Result};
pub use progress::{Cancelled, Progress, Reporter};

/// Product name as shown in the UI, service registration, and log output.
pub const PRODUCT_NAME: &str = "KAM Security";

/// Name the agent registers under in the Windows service control manager.
pub const SERVICE_NAME: &str = "KamSecurityAgent";
