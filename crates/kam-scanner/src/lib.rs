//! Threat detection, in four layers (see PLAN.md section 3.2).
//!
//! 1. **Defender orchestration** -- `MSFT_MpScan`, `MSFT_MpThreat` and
//!    `MSFT_MpPreference` over WMI, plus `MpCmdRun.exe`. Microsoft's engine and
//!    cloud intelligence, our interface. We do not ship a competing engine and
//!    we never install a real-time file interceptor.
//! 2. **YARA rules** -- aimed at what Defender tolerates to avoid false
//!    positives on commercial software: bundled adware, scareware optimisers,
//!    browser hijackers, stalkerware, unwanted persistence.
//! 3. **Provenance and reputation** -- the original contribution. Judges a
//!    binary by its history rather than by matching a signature.
//! 4. **VirusTotal** -- on demand, single file, user-supplied API key.

pub mod behaviour;
pub mod defender;
pub mod persistence;
pub mod provenance;
pub mod signature;
pub mod wmi;

pub use defender::{DefenderStatus, Threat};

/// Everything layer 3 knows about one executable on disk.
///
/// No single field is a verdict. An unsigned binary that arrived in AppData via
/// a browser download three weeks ago and registered a Run key is suspicious
/// without matching any signature; the same binary signed by a known vendor and
/// installed by MSI is not.
#[derive(Debug, Clone)]
pub struct Provenance {
    pub signature: SignatureState,
    /// Process that created the file, from the USN journal, when still known.
    pub written_by: Option<String>,
    /// Origin URL from the `Zone.Identifier` alternate data stream.
    pub downloaded_from: Option<String>,
    /// Run keys, services, scheduled tasks and startup entries pointing here.
    pub persistence_count: usize,
    pub location_risk: LocationRisk,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureState {
    /// Authenticode signature present and chaining to a trusted root.
    Valid {
        signer: String,
    },
    /// Signature present but expired, revoked, or failing to chain.
    Invalid {
        reason: String,
    },
    Unsigned,
}

/// How unusual it is for an executable to live where this one does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocationRisk {
    /// Program Files, System32, or a package-managed location.
    Expected,
    /// A user directory that legitimately holds executables.
    Unusual,
    /// Temp, Downloads, or a roaming profile directory.
    Suspicious,
}
