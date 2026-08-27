//! Storage intelligence: the flagship module.
//!
//! Four capabilities, built in this order (see PLAN.md section 3.1):
//!
//! 1. **Instant disk map** -- read the NTFS master file table directly through
//!    `FSCTL_ENUM_USN_DATA` rather than walking directories. Whole-volume
//!    inventory in seconds instead of minutes.
//! 2. **True application footprint** -- Control Panel shows `EstimatedSize`, a
//!    number the installer self-reports and which never counts anything outside
//!    the install directory. Real size is the sum across the install location,
//!    ProgramData, LocalAppData, AppData, service binaries and task payloads.
//! 3. **Orphan detection** -- directories whose owning application is no longer
//!    installed, ranked by size, last access, and confidence in the attribution.
//! 4. **Provenance** -- the `Zone.Identifier` alternate data stream records that
//!    a file was downloaded and usually from which URL; the USN journal records
//!    when it appeared and which process wrote it. Together they identify
//!    downloads the user never knew they had.
//!
//! Volumes that are not NTFS, or that are locked by BitLocker, fall back to
//! directory walking.

pub mod apps;
pub mod duplicates;
pub mod index;
pub mod mft;
pub mod organise;
pub mod orphans;
pub mod provenance;
pub mod remnants;
/// Re-exported from the shared crate, where it moved once the scanner
/// needed it too.
pub use kam_core::registry;
pub mod scan;
pub mod shortcuts;
pub mod steam;
pub mod volumes;

pub use apps::{AppFootprint, FootprintSummary};
pub use duplicates::{DuplicateGroup, DuplicateSummary};
pub use index::VolumeIndex;
pub use organise::{OrganiseSummary, Proposal};
pub use orphans::{Confidence, Orphan, OrphanSummary};
pub use provenance::{Download, DownloadSummary};
pub use scan::{scan, Scan, ScanMethod};
pub use volumes::{list as list_volumes, Volume};

/// Whether a file may be included in a move proposal.
///
/// This is a hard fence, not a heuristic: moving an executable or anything an
/// application owns breaks shortcuts, hard-coded paths and project references.
/// Only inert user documents are ever offered for reorganisation, and every
/// accepted move is recorded path-for-path so it can be reversed exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoveEligibility {
    /// Inert user content outside any install root, AppData, or git work tree.
    Eligible,
    /// Owned by an application, executable, or inside a repository.
    Fenced(FenceReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceReason {
    Executable,
    UnderInstallRoot,
    UnderApplicationData,
    InsideGitWorkTree,
    FileHandleOpen,
}
