//! The notification-area icon.
//!
//! # What this is, and what it is not
//!
//! It is a convenience and a reassurance: somewhere to see that protection is
//! on without opening anything, and a way to reach the window. It is **not** a
//! security feature. It detects nothing, blocks nothing, and the machine is
//! exactly as protected with it as without it. Saying otherwise would be the
//! same theatre as a red badge with an invented issue count.
//!
//! # The cost, which is the whole design constraint
//!
//! The agent does the work and costs almost nothing: two threads, 1.4 MB of
//! private memory, and zero measured CPU since it started, because it sits
//! blocked in `ConnectNamedPipe` until something asks it for something. A tray
//! icon must not undo that.
//!
//! Three decisions keep it honest:
//!
//! 1. **Closing the window destroys it.** The WebView is the expensive part —
//!    hundreds of megabytes — and hiding a window keeps all of it alive.
//!    Destroying it leaves only this process's event loop resident, and
//!    reopening rebuilds the window in well under a second.
//! 2. **Nothing polls.** There is no timer. Status is read when the menu is
//!    opened, because that is the only moment anybody could be looking at it.
//!    A tray icon that wakes every few seconds to refresh a tooltip nobody is
//!    reading is precisely the waste this project exists to be an alternative
//!    to.
//! 3. **It is off unless asked for.** Nothing is added to the run keys — this
//!    product reports on what starts itself at boot, and quietly adding itself
//!    to that list while doing so would be grotesque.

use tauri::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WindowEvent};

/// Bring the window back, building it again if closing destroyed it.
fn show_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
        return;
    }

    // The window was closed, so its WebView went with it. Rebuilding costs a
    // moment here and saves the memory the rest of the time, which is the
    // trade this whole module is built around.
    let built = tauri::WebviewWindowBuilder::new(
        app,
        "main",
        tauri::WebviewUrl::App("index.html".into()),
    )
    .title("KAM Security")
    .inner_size(1040.0, 720.0)
    .min_inner_size(720.0, 520.0)
    .build();

    match built {
        Ok(window) => {
            let _ = window.set_focus();
        }
        Err(error) => eprintln!("could not reopen the window: {error}"),
    }
}

/// A one-line summary of whether protection is on.
///
/// Read only when the menu is opened. It asks the agent, which answers from
/// Defender and the firewall; if the agent cannot be reached that is itself
/// the useful thing to say.
fn protection_summary() -> String {
    let Ok(status) = kam_ipc::client::call(&kam_ipc::Request::GetDefenderStatus) else {
        return "The KAM Security service is not answering".to_owned();
    };

    let kam_ipc::Response::Defender { concerns, .. } = status else {
        return "Protection state unknown".to_owned();
    };

    match concerns.len() {
        0 => "Defender is on and up to date".to_owned(),
        1 => "1 thing worth checking".to_owned(),
        many => format!("{many} things worth checking"),
    }
}

/// Attach the icon and wire the window's close behaviour.
pub fn install(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open KAM Security", true, None::<&str>)?;
    let status = MenuItem::with_id(app, "status", "Checking…", false, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;

    let menu = Menu::with_items(app, &[&status, &separator, &open, &quit])?;

    let status_item = status.clone();
    TrayIconBuilder::with_id("kam")
        .icon(app.default_window_icon().cloned().ok_or_else(|| {
            tauri::Error::AssetNotFound("the application icon is missing".to_owned())
        })?)
        .tooltip("KAM Security")
        .menu(&menu)
        // The menu is the only thing that should open on a left click; a left
        // click alone opens the window, which is what people expect.
        .show_menu_on_left_click(false)
        .on_menu_event(move |app, event: MenuEvent| match event.id().as_ref() {
            "open" => show_window(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(move |tray, event| {
            match event {
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } => show_window(tray.app_handle()),

                // The one moment somebody could be about to read the status,
                // and so the only moment worth spending anything to produce
                // it. Everything else here is idle.
                TrayIconEvent::Enter { .. } => {
                    let _ = status_item.set_text(protection_summary());
                }
                _ => {}
            }
        })
        .build(app)?;

    Ok(())
}

/// Let the window close without ending the program.
///
/// Returning to the tray rather than exiting is what makes the icon useful,
/// and destroying the window rather than hiding it is what makes it cheap.
pub fn on_window_event(window: &tauri::Window, event: &WindowEvent) {
    if let WindowEvent::CloseRequested { api, .. } = event {
        // Prevent the default close, then destroy explicitly. `hide` would
        // keep the WebView and everything it holds resident.
        api.prevent_close();
        let _ = window.destroy();
    }
}
