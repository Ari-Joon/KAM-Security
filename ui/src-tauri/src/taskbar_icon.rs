//! The icon the taskbar draws for the open window, and who the window says it is.
//!
//! Tauri hands a window only its *small* icon: `WM_SETICON` with `ICON_SMALL`,
//! through tao's `set_window_icon`. It never sets the large one, which tao
//! keeps behind a separate `set_taskbar_icon` that Tauri does not call. So the
//! window is given both icons directly, loaded at the sizes Windows asks for
//! from the icon tauri-build embeds in this executable.
//!
//! That was not enough on its own. The taskbar draws an application, not a
//! window, and a window that does not say which application it belongs to is
//! left for the taskbar to work out from the process. On the owner's machine
//! that came out as a blank page every time, while the same executable drew
//! correctly on the desktop and in every query made of the shell. Giving the
//! window an explicit AppUserModel identity, with the icon and relaunch command
//! that go with it, made the taskbar draw the logo at once; that was tried on
//! the running window before it was written here. The identity is Tauri's own
//! identifier, so notifications, a Start menu entry and a pinned shortcut can
//! all name the same application.
//!
//! Failing here costs only the icon, so it is reported on stderr and otherwise
//! ignored: the window still opens.

use std::sync::OnceLock;

use std::mem::ManuallyDrop;

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{E_OUTOFMEMORY, HWND, LPARAM, PROPERTYKEY, WPARAM};
use windows::Win32::System::Com::CoTaskMemAlloc;
use windows::Win32::System::Com::StructuredStorage::{
    PROPVARIANT, PROPVARIANT_0, PROPVARIANT_0_0, PROPVARIANT_0_0_0,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Variant::VT_LPWSTR;
use windows::Win32::UI::Shell::PropertiesSystem::{IPropertyStore, SHGetPropertyStoreForWindow};
use windows::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, LoadImageW, SendMessageW, ICON_BIG, ICON_SMALL, IMAGE_ICON, LR_DEFAULTCOLOR,
    SM_CXICON, SM_CXSMICON, SM_CYICON, SM_CYSMICON, SYSTEM_METRICS_INDEX, WM_SETICON,
};

/// Who the window says it is, to the taskbar and to notifications.
///
/// Tauri's own identifier, so anything else that has to name this
/// application (a notification, a Start menu shortcut) can use the same one.
pub const APP_ID: &str = "com.kamsecurity.shell";

/// The property set `PKEY_AppUserModel_*` belongs to.
const APP_USER_MODEL: GUID = GUID::from_u128(0x9F4C2855_9F79_4B39_A8D0_E1D42DE1D5F3);

/// Give the window an AppUserModel identity, with the icon and relaunch
/// command that go with it, so the taskbar draws this application rather than
/// guessing from the process.
fn identify(hwnd: HWND) -> windows::core::Result<()> {
    let exe = std::env::current_exe()
        .map_err(|error| windows::core::Error::new(E_OUTOFMEMORY, error.to_string()))?;
    let exe = exe.to_string_lossy();

    // SAFETY: `hwnd` is a window this process created and still owns.
    let store: IPropertyStore = unsafe { SHGetPropertyStoreForWindow(hwnd) }?;
    // The identity goes last, so the taskbar regroups the window with the
    // relaunch details already in place.
    let properties = [
        (2, format!("\"{exe}\"")),      // RelaunchCommand
        (3, format!("{exe},0")),        // RelaunchIconResource
        (4, "KAM Security".to_owned()), // RelaunchDisplayNameResource
        (5, APP_ID.to_owned()),         // ID
    ];
    for (pid, value) in properties {
        let key = PROPERTYKEY {
            fmtid: APP_USER_MODEL,
            pid,
        };
        let value = text(&value)?;
        // SAFETY: both live across the call, and the store copies the value.
        unsafe { store.SetValue(&key, &value) }?;
    }
    // SAFETY: as above.
    unsafe { store.Commit() }
}

/// A `VT_LPWSTR` property value.
///
/// Not `PROPVARIANT::from(&str)`, which makes a `VT_BSTR`: the AppUserModel
/// properties are documented as `VT_LPWSTR`, and that is the form shown to
/// work here. The text is allocated from the COM allocator because
/// `PROPVARIANT`'s `Drop` releases it with `PropVariantClear`, which frees it
/// there.
fn text(value: &str) -> windows::core::Result<PROPVARIANT> {
    let wide: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: a plain allocation, checked below.
    let raw = unsafe { CoTaskMemAlloc(wide.len() * 2) }.cast::<u16>();
    if raw.is_null() {
        return Err(E_OUTOFMEMORY.into());
    }
    // SAFETY: `raw` has room for exactly `wide.len()` units.
    unsafe { std::ptr::copy_nonoverlapping(wide.as_ptr(), raw, wide.len()) };
    Ok(PROPVARIANT {
        Anonymous: PROPVARIANT_0 {
            Anonymous: ManuallyDrop::new(PROPVARIANT_0_0 {
                vt: VT_LPWSTR,
                wReserved1: 0,
                wReserved2: 0,
                wReserved3: 0,
                Anonymous: PROPVARIANT_0_0_0 {
                    pwszVal: PWSTR(raw),
                },
            }),
        },
    })
}

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

    // First, and whatever happens to the icons: this is what the taskbar
    // actually needed.
    if let Err(error) = identify(hwnd) {
        eprintln!("could not tell the taskbar which application this window is: {error}");
    }

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
