//! Control plane over Windows Defender Firewall (see PLAN.md section 3.3).
//!
//! The Windows Filtering Platform *is* the network stack's filter layer, so
//! there is nothing to replace. What is missing is a usable interface: rule
//! management through `INetFwPolicy2`, a live connection table built from
//! `GetExtendedTcpTable` joined to process, signer and destination, and turning
//! any observed connection into a scoped outbound rule in one click.
//!
//! An ETW consumer on `Microsoft-Windows-Kernel-Network` provides near-real-time
//! connection events. Prompting *before* a connection opens would require a WFP
//! callout driver; observing and then blocking delivers nearly the same value
//! with no kernel code, and is deliberately where this module stops.

/// One observed outbound connection, resolved as far as we can take it.
#[derive(Debug, Clone)]
pub struct Connection {
    pub process_id: u32,
    pub image_path: String,
    /// Authenticode signer of the image, when it has one.
    pub signer: Option<String>,
    pub remote_address: String,
    pub remote_port: u16,
    /// Reverse DNS for the remote address, when it resolves.
    pub remote_host: Option<String>,
}
