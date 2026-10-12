//! The icon the taskbar draws for the open window.
//!
//! Tauri hands a window only its *small* icon: `WM_SETICON` with `ICON_SMALL`,
//! through tao's `set_window_icon`. It never sets the large one, which tao
//! keeps behind a separate `set_taskbar_icon` that Tauri does not call. With
//! no large icon on the window and none on its class, the taskbar falls back
//! to whatever Explorer has cached for the executable or its pinned shortcut,
//! which is one more thing that can go stale. The owner saw a blank page there
//! after a deploy replaced the executable in place.
//!
//! So the window is given both icons directly, loaded at the sizes Windows
//! asks for from the icon tauri-build embeds in this executable. Nothing
//! outside the process is consulted.
//!
//! Failing here costs only the icon, so it is reported on stderr and otherwise
//! ignored: the window still opens.

use std::sync::OnceLock;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, LoadImageW, SendMessageW, ICON_BIG, ICON_SMALL, IMAGE_ICON, LR_DEFAULTCOLOR,
    SM_CXICON, SM_CXSMICON, SM_CYICON, SM_CYSMICON, SYSTEM_METRICS_INDEX, WM_SETICON,
};

/// The resource id tauri-build gives the application icon.
///
/// Taken from Tauri's own constant (it is `IDI_APPLICATION`'s number, 32512, so
/// that `LoadIcon` on the module finds it) rather than written out here, so the
/// two cannot drift apart. If loading fails anyway, the window keeps Tauri's own
/// small icon, which is exactly the state before this module existed.
const APPLICATION_ICON: u16 = tauri::utils::platform::WINDOWS_APP_ICON_RESOURCE_ID;

/// Large and small icon handles, as integers so they can live in a static.
///
/// Loaded once. The window is destroyed every time it is closed to the
/// notification area and rebuilt when reopened, and a window never frees the
/// icons it is handed, so loading per build would leak two handles each time.
static ICONS: OnceLock<Option<(isize, isize)>> = OnceLock::new();

/// Give `window` its large (taskbar) and small (title bar) icons.
pub fn apply(window: &tauri::WebviewWindow) {
    let hwnd = match window.hwnd() {
        // Tauri's HWND comes from its own copy of the `windows` crate; the
        // pointer inside is the same handle.
        Ok(handle) => HWND(handle.0),
        Err(error) => {
            eprintln!("could not set the taskbar icon: {error}");
            return;
        }
    };

    let Some((large, small)) = *ICONS.get_or_init(load) else {
        return;
    };

    for (which, icon) in [(ICON_BIG, large), (ICON_SMALL, small)] {
        // SAFETY: `hwnd` is a window this process created and still owns, and
        // `icon` is a handle loaded below that is never destroyed. The return
        // value is the previous icon, which tao owns and frees itself.
        unsafe {
            SendMessageW(
                hwnd,
                WM_SETICON,
                Some(WPARAM(which as usize)),
                Some(LPARAM(icon)),
            );
        }
    }
}

fn load() -> Option<(isize, isize)> {
    let large = load_at(SM_CXICON, SM_CYICON);
    let small = load_at(SM_CXSMICON, SM_CYSMICON);
    match (large, small) {
        (Ok(large), Ok(small)) => Some((large, small)),
        (Err(error), _) | (_, Err(error)) => {
            eprintln!("could not load the application icon from this executable: {error}");
            None
        }
    }
}

fn load_at(
    width: SYSTEM_METRICS_INDEX,
    height: SYSTEM_METRICS_INDEX,
) -> windows::core::Result<isize> {
    // SAFETY: a null name asks for this executable's own module, which lives
    // as long as the process; nothing is freed.
    let module = unsafe { GetModuleHandleW(PCWSTR::null()) }?;
    // SAFETY: no preconditions.
    let (cx, cy) = unsafe { (GetSystemMetrics(width), GetSystemMetrics(height)) };
    // SAFETY: the name is an integer resource id in place of a string pointer
    // (MAKEINTRESOURCE), which LoadImageW accepts; the module is valid for the
    // life of the process. Not LR_SHARED, because these sizes are chosen here
    // rather than being the resource's default.
    let icon = unsafe {
        LoadImageW(
            Some(module.into()),
            PCWSTR(APPLICATION_ICON as usize as *const u16),
            IMAGE_ICON,
            cx,
            cy,
            LR_DEFAULTCOLOR,
        )
    }?;
    Ok(icon.0 as isize)
}
