//! Volume enumeration: what drives exist, how big they are, and how full.
//!
//! Cheap enough to call on every dashboard refresh — this asks the filesystem
//! for headline numbers rather than walking anything.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use kam_core::{Error, Result};
use serde::{Deserialize, Serialize};
use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::{
    GetDiskFreeSpaceExW, GetDriveTypeW, GetLogicalDriveStringsW, GetVolumeInformationW,
};
use windows::Win32::System::WindowsProgramming::{
    DRIVE_FIXED, DRIVE_RAMDISK, DRIVE_REMOTE, DRIVE_REMOVABLE,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriveKind {
    Fixed,
    Removable,
    Network,
    RamDisk,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Volume {
    /// Root path, e.g. `C:\`.
    pub root: String,
    /// Volume label, empty when unset.
    pub label: String,
    /// `NTFS`, `exFAT`, and so on. Empty when it could not be read.
    pub filesystem: String,
    pub kind: DriveKind,
    pub total_bytes: u64,
    pub free_bytes: u64,
    /// True when this volume can support the fast master-file-table path.
    /// Everything else falls back to walking directories.
    pub supports_mft: bool,
}

impl Volume {
    pub fn used_bytes(&self) -> u64 {
        self.total_bytes.saturating_sub(self.free_bytes)
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Trim a null-terminated wide buffer and convert it.
fn from_wide(buffer: &[u16]) -> String {
    let end = buffer.iter().position(|c| *c == 0).unwrap_or(buffer.len());
    OsString::from_wide(&buffer[..end])
        .to_string_lossy()
        .into_owned()
}

/// Every mounted drive letter on the machine.
///
/// Drives that cannot be queried — an empty card reader, a disconnected network
/// mapping — are skipped rather than reported with zeroes, which would read as
/// "this drive is full" in the UI.
pub fn list() -> Result<Vec<Volume>> {
    let mut buffer = [0_u16; 512];
    let length = unsafe { GetLogicalDriveStringsW(Some(&mut buffer)) };
    if length == 0 {
        return Err(Error::Privileged(format!(
            "could not enumerate drives: {}",
            windows::core::Error::from_thread()
        )));
    }

    let mut volumes = Vec::new();
    for root in buffer[..length as usize].split(|c| *c == 0) {
        if root.is_empty() {
            continue;
        }
        let root_string = from_wide(root);
        if let Some(volume) = describe(&root_string) {
            volumes.push(volume);
        }
    }
    Ok(volumes)
}

fn describe(root: &str) -> Option<Volume> {
    let wide_root = wide(root);
    let root_ptr = PCWSTR(wide_root.as_ptr());

    let kind = match unsafe { GetDriveTypeW(root_ptr) } {
        value if value == DRIVE_FIXED => DriveKind::Fixed,
        value if value == DRIVE_REMOVABLE => DriveKind::Removable,
        value if value == DRIVE_REMOTE => DriveKind::Network,
        value if value == DRIVE_RAMDISK => DriveKind::RamDisk,
        _ => DriveKind::Other,
    };

    let mut label_buffer = [0_u16; 256];
    let mut filesystem_buffer = [0_u16; 64];
    // Failure here is normal for an empty removable drive, so it downgrades to
    // blank fields rather than dropping the volume.
    let named = unsafe {
        GetVolumeInformationW(
            root_ptr,
            Some(&mut label_buffer),
            None,
            None,
            None,
            Some(&mut filesystem_buffer),
        )
    }
    .is_ok();

    let mut total_bytes = 0_u64;
    let mut free_bytes = 0_u64;
    unsafe {
        GetDiskFreeSpaceExW(
            root_ptr,
            None,
            Some(&mut total_bytes),
            Some(&mut free_bytes),
        )
    }
    .ok()?;

    let filesystem = if named {
        from_wide(&filesystem_buffer)
    } else {
        String::new()
    };

    Some(Volume {
        root: root.to_owned(),
        label: if named {
            from_wide(&label_buffer)
        } else {
            String::new()
        },
        supports_mft: filesystem.eq_ignore_ascii_case("NTFS"),
        filesystem,
        kind,
        total_bytes,
        free_bytes,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn the_system_drive_is_enumerated_and_sane() {
        let volumes = list().unwrap();
        let system = volumes
            .iter()
            .find(|volume| volume.root.starts_with('C'))
            .expect("no C: drive found");

        assert!(system.total_bytes > 0);
        assert!(system.free_bytes <= system.total_bytes);
        assert_eq!(system.kind, DriveKind::Fixed);
        // Every supported Windows install has C: on NTFS.
        assert!(system.supports_mft, "C: reported as {}", system.filesystem);
    }

    #[test]
    fn used_never_underflows() {
        let volume = Volume {
            root: "X:\\".to_owned(),
            label: String::new(),
            filesystem: String::new(),
            kind: DriveKind::Other,
            total_bytes: 0,
            free_bytes: 100,
            supports_mft: false,
        };
        assert_eq!(volume.used_bytes(), 0);
    }
}
