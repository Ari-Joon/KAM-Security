// Suppresses the console window that would otherwise open behind the app on
// Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // A copy started through Windows' permission prompt to make one change.
    // Handled before anything else exists, so it never opens a window, never
    // reaches the single-instance check, and exits as soon as the change is
    // made. See `consent.rs`.
    if let Some(code) = kam_shell_lib::consent::run_if_asked() {
        std::process::exit(code);
    }
    kam_shell_lib::run()
}
