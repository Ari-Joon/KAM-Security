// Suppresses the console window that would otherwise open behind the app on
// Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    kam_shell_lib::run()
}
