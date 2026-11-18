//! Gives `kam-agent.exe` the product's icon and a description of itself.
//!
//! Without a resource the service shows in Task Manager and in the Services
//! console as a blank page called `kam-agent.exe`, and its Details tab is
//! empty. That is a poor way for a security program to appear in the one
//! place somebody goes to ask what is running: a nameless, iconless process
//! running as LocalSystem is exactly what this product tells people to look
//! twice at. The window has always had both, through Tauri's own build step.
//!
//! The icon is the window's, read from where Tauri keeps it, so there is one
//! file and the two halves cannot drift apart.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    const ICON: &str = "../../ui/src-tauri/icons/icon.ico";
    println!("cargo:rerun-if-changed={ICON}");
    println!("cargo:rerun-if-changed=build.rs");

    // The target, not the host: the question is what is being built.
    if std::env::var_os("CARGO_CFG_WINDOWS").is_none() {
        return Ok(());
    }

    let mut resource = tauri_winres::WindowsResource::new();
    resource
        .set_icon(ICON)
        .set("FileDescription", "KAM Security service")
        .set("ProductName", "KAM Security")
        .set("OriginalFilename", "kam-agent.exe")
        .set("InternalName", "kam-agent")
        .set(
            "LegalCopyright",
            "KAM Security contributors, Apache-2.0 licence",
        );
    resource.compile()?;
    Ok(())
}
