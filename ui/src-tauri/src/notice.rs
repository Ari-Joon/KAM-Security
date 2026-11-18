//! Telling the person a download has landed, with Windows' own notifications.
//!
//! # Why a Start menu shortcut
//!
//! Windows delivers a notification on behalf of an *application identity*,
//! and a program run from a folder has none until it is given one. Packaged
//! apps get theirs from their package. Everything else gets it from a Start
//! menu shortcut carrying the identity as a property: without one, Windows
//! accepts the notification and shows nothing. So this program:
//!
//! - gives its process the identity `com.kamsecurity.shell` at start-up,
//!   before any window exists, so the window, its taskbar button and its
//!   shortcuts are one application to Windows;
//! - keeps a shortcut named "KAM Security" in the person's own Start menu,
//!   pointing at this program and carrying that identity, rewriting it if the
//!   program has moved. That is also the honest place for a program to appear,
//!   and the person can turn its notifications off in Windows' Settings, under
//!   Notifications, like any other app's.
//!
//! This was done directly with Windows' notification interfaces rather than a
//! plugin, because the plugin needs the same identity anyway and would add a
//! second notification path for the window to use.
//!
//! # Clicking one
//!
//! The program is in the notification area from sign-in, so it is running
//! when a notification is clicked, and Windows tells it. That opens the window
//! on the Downloads page at that file. A notification clicked later from the
//! notification centre, after the program has closed, does nothing; the page
//! has the same record.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use windows::core::{Interface, HSTRING};
use windows::Data::Xml::Dom::XmlDocument;
use windows::Foundation::TypedEventHandler;
use windows::Win32::Foundation::PROPERTYKEY;
use windows::Win32::System::Com::StructuredStorage::{
    PropVariantClear, PROPVARIANT, PROPVARIANT_0, PROPVARIANT_0_0, PROPVARIANT_0_0_0,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, IPersistFile, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
    STGM_READ,
};
use windows::Win32::System::Variant::VT_LPWSTR;
use windows::Win32::UI::Shell::PropertiesSystem::IPropertyStore;
use windows::Win32::UI::Shell::{
    IShellLinkW, SHStrDupW, SetCurrentProcessExplicitAppUserModelID, ShellLink,
};
use windows::UI::Notifications::{
    NotificationSetting, ToastNotification, ToastNotificationManager,
};

/// This program's identity to Windows. Tauri's identifier, so every part of
/// the program that names itself to Windows uses one name.
pub const APP_ID: &str = "com.kamsecurity.shell";

/// The shortcut's name in the Start menu.
const SHORTCUT: &str = "KAM Security.lnk";

/// `PKEY_AppUserModel_ID`, the property a shortcut carries its identity in.
const APP_USER_MODEL_ID: PROPERTYKEY = PROPERTYKEY {
    fmtid: windows::core::GUID::from_u128(0x9f4c2855_9f79_4b39_a8d0_e1d42de1d5f3),
    pid: 5,
};

/// Give this process its identity. Must run before any window exists.
pub fn claim_identity() {
    if let Err(error) = unsafe { SetCurrentProcessExplicitAppUserModelID(&HSTRING::from(APP_ID)) } {
        eprintln!("could not set the application identity: {error}");
    }
}

/// The person's own Start menu programs folder.
fn start_menu() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|roaming| {
        PathBuf::from(roaming)
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
    })
}

/// Make sure the Start menu shortcut exists, points here and carries the
/// identity. Runs on its own thread at start-up; COM is set up for it here.
pub fn ensure_shortcut() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|error| error.to_string())?;
    let folder = start_menu().ok_or("the Start menu folder could not be found")?;
    ensure_shortcut_at(&folder.join(SHORTCUT), &exe, APP_ID)
}

/// [`ensure_shortcut`] for any place, target and identity.
pub fn ensure_shortcut_at(link: &Path, target: &Path, app_id: &str) -> Result<(), String> {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
    }
    if let Some((existing_target, existing_id)) = read_shortcut(link) {
        if existing_target.eq_ignore_ascii_case(&target.to_string_lossy()) && existing_id == app_id
        {
            return Ok(());
        }
    }
    write_shortcut(link, target, app_id)
}

/// What a shortcut points at and the identity it carries, if it can be read.
fn read_shortcut(link: &Path) -> Option<(String, String)> {
    if !link.exists() {
        return None;
    }
    unsafe {
        let shell: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).ok()?;
        let file: IPersistFile = shell.cast().ok()?;
        file.Load(&HSTRING::from(link.as_os_str()), STGM_READ)
            .ok()?;
        let mut buffer = [0_u16; 1024];
        shell.GetPath(&mut buffer, std::ptr::null_mut(), 0).ok()?;
        let end = buffer
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(buffer.len());
        let target = String::from_utf16_lossy(&buffer[..end]);

        let store: IPropertyStore = shell.cast().ok()?;
        let value = store.GetValue(&APP_USER_MODEL_ID).ok()?;
        let inner = &value.Anonymous.Anonymous;
        let id = if inner.vt == VT_LPWSTR && !inner.Anonymous.pwszVal.is_null() {
            inner.Anonymous.pwszVal.to_string().unwrap_or_default()
        } else {
            String::new()
        };
        let mut value = value;
        let _ = PropVariantClear(&mut value);
        Some((target, id))
    }
}

fn write_shortcut(link: &Path, target: &Path, app_id: &str) -> Result<(), String> {
    let fail = |what: &str, error: windows::core::Error| {
        format!("the Start menu shortcut could not be {what}: {error}")
    };
    unsafe {
        let shell: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)
            .map_err(|error| fail("made", error))?;
        let target_text = HSTRING::from(target.as_os_str());
        shell
            .SetPath(&target_text)
            .map_err(|error| fail("pointed here", error))?;
        if let Some(folder) = target.parent() {
            let _ = shell.SetWorkingDirectory(&HSTRING::from(folder.as_os_str()));
        }
        let _ = shell.SetIconLocation(&target_text, 0);
        let _ = shell.SetDescription(&HSTRING::from("KAM Security"));

        // The identity, as a string property, allocated the way Windows'
        // own InitPropVariantFromString does and cleared the same way once
        // the store has its copy. With a buffer Rust owned, saving the
        // shortcut corrupted the heap (seen in this module's own test), so
        // this allocates and frees exactly as Windows' own helper does.
        let text = SHStrDupW(&HSTRING::from(app_id)).map_err(|error| fail("labelled", error))?;
        let mut value = PROPVARIANT {
            Anonymous: PROPVARIANT_0 {
                Anonymous: std::mem::ManuallyDrop::new(PROPVARIANT_0_0 {
                    vt: VT_LPWSTR,
                    wReserved1: 0,
                    wReserved2: 0,
                    wReserved3: 0,
                    Anonymous: PROPVARIANT_0_0_0 { pwszVal: text },
                }),
            },
        };
        let store: IPropertyStore = shell.cast().map_err(|error| fail("labelled", error))?;
        let set = store
            .SetValue(&APP_USER_MODEL_ID, &value)
            .and_then(|()| store.Commit());
        let _ = PropVariantClear(&mut value);
        set.map_err(|error| fail("labelled", error))?;

        if let Some(folder) = link.parent() {
            let _ = std::fs::create_dir_all(folder);
        }
        let file: IPersistFile = shell.cast().map_err(|error| fail("saved", error))?;
        file.Save(&HSTRING::from(link.as_os_str()), true)
            .map_err(|error| fail("saved", error))?;
    }
    Ok(())
}

/// Notifications kept alive so a click on one still reaches this program.
static SHOWN: Mutex<Vec<ToastNotification>> = Mutex::new(Vec::new());

/// How many are kept. Older ones have long left the screen.
const KEEP: usize = 20;

fn escaped(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .map(|c| match c {
            '&' => "&amp;".to_owned(),
            '<' => "&lt;".to_owned(),
            '>' => "&gt;".to_owned(),
            '"' => "&quot;".to_owned(),
            '\'' => "&apos;".to_owned(),
            other => other.to_string(),
        })
        .collect()
}

/// The notification's content, as Windows' toast schema wants it.
fn toast_xml(title: &str, body: &str) -> String {
    format!(
        "<toast><visual><binding template=\"ToastGeneric\"><text>{}</text><text>{}</text>\
         </binding></visual></toast>",
        escaped(title),
        escaped(body)
    )
}

/// Show one notification under `app_id`. `on_click` runs if it is clicked
/// while this program is running.
pub fn show(
    app_id: &str,
    title: &str,
    body: &str,
    on_click: impl Fn() + Send + 'static,
) -> Result<(), String> {
    let document = XmlDocument::new().map_err(|error| error.to_string())?;
    document
        .LoadXml(&HSTRING::from(toast_xml(title, body)))
        .map_err(|error| error.to_string())?;
    let toast =
        ToastNotification::CreateToastNotification(&document).map_err(|error| error.to_string())?;
    toast
        .Activated(&TypedEventHandler::new(move |_, _| {
            on_click();
            Ok(())
        }))
        .map_err(|error| error.to_string())?;
    let notifier = ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(app_id))
        .map_err(|error| error.to_string())?;
    notifier.Show(&toast).map_err(|error| error.to_string())?;

    if let Ok(mut shown) = SHOWN.lock() {
        shown.push(toast);
        let excess = shown.len().saturating_sub(KEEP);
        shown.drain(..excess);
    }
    Ok(())
}

/// What Windows says it will do with notifications under `app_id`. An error
/// when Windows does not recognise the identity at all.
pub fn setting(app_id: &str) -> Result<NotificationSetting, String> {
    ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(app_id))
        .and_then(|notifier| notifier.Setting())
        .map_err(|error| error.to_string())
}

/// Why Windows will not show this program's notifications, in a sentence,
/// or `None` when it will.
fn blocked_sentence(setting: NotificationSetting) -> Option<String> {
    let reason = match setting {
        NotificationSetting::Enabled => return None,
        NotificationSetting::DisabledForUser => {
            "Windows notifications are switched off for your account (Settings, System, \
             Notifications)"
        }
        NotificationSetting::DisabledForApplication => {
            "Notifications from KAM Security are switched off in Windows' Settings, under \
             Notifications"
        }
        NotificationSetting::DisabledByGroupPolicy => {
            "Your organisation's policy switches notifications off on this machine"
        }
        _ => "Windows will not show notifications from KAM Security",
    };
    Some(format!(
        "{reason}, so you will not be told when a download lands. Every check is still \
         recorded on this page."
    ))
}

/// Whether notices about new downloads can be seen, said when they cannot.
/// A failure is not an absence: not being able to tell is said too.
pub fn delivery_problem() -> Option<String> {
    match setting(APP_ID) {
        Ok(setting) => blocked_sentence(setting),
        Err(error) => Some(format!(
            "Windows did not say whether it will show KAM Security's notifications ({error}), \
             so you may not be told when a download lands. Every check is still recorded on \
             this page."
        )),
    }
}

/// The sentence a notification about a checked download says.
pub fn sentence(name: &str, scan: &kam_scanner::defender_file::FileScan) -> (String, String) {
    use kam_scanner::defender_file::Answer;
    let title = format!("New download: {name}");
    let body = match scan.answer {
        Answer::NothingFound => "Defender found nothing.".to_owned(),
        Answer::Flagged => format!(
            "{}. It is still in Downloads; open KAM Security to quarantine it.",
            scan.sentence()
        ),
        Answer::NotFinished => {
            "Defender could not finish checking it, so this is not a clean result.".to_owned()
        }
        // Nothing was checked, and the notice must not read as if it had
        // been. What Defender's own history says about it is the agent's
        // sentence.
        Answer::GoneBeforeCheck => format!(
            "It was gone before it could be checked. {}",
            scan.caveat.as_deref().unwrap_or_default()
        )
        .trim_end()
        .to_owned(),
    };
    (title, body)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use kam_scanner::defender_file::{parse_report, Answer};

    #[test]
    fn text_from_a_file_name_cannot_break_the_notification() {
        let xml = toast_xml("New download: a<b>&\"c\".exe", "line\nbreak");
        assert!(xml.contains("a&lt;b&gt;&amp;&quot;c&quot;.exe"), "{xml}");
        assert!(!xml.contains('\n'));
        let document = XmlDocument::new().unwrap();
        document
            .LoadXml(&HSTRING::from(xml))
            .expect("the escaped text is well formed");
    }

    #[test]
    fn each_answer_reads_as_a_plain_sentence_and_never_as_clean_when_unfinished() {
        let clean = parse_report(Some(0), "");
        assert_eq!(sentence("a.zip", &clean).1, "Defender found nothing.");
        let unfinished = parse_report(Some(2), "");
        assert_eq!(unfinished.answer, Answer::NotFinished);
        let body = sentence("a.zip", &unfinished).1;
        assert!(body.contains("not a clean result"), "{body}");
        assert!(!body.contains('—'), "no dashes in what the person reads");

        // A download that was gone before it could be checked is never
        // announced as one Defender found nothing in.
        let gone = kam_scanner::defender_file::FileScan::gone_before_check(Ok(Vec::new()));
        let body = sentence("a.exe", &gone).1;
        assert!(
            body.starts_with("It was gone before it could be checked.")
                && body.contains("not known"),
            "{body}"
        );
        assert!(!body.contains("found nothing"), "{body}");
    }

    /// A shortcut is written with the identity and read back with it.
    #[test]
    fn a_shortcut_carries_the_identity_it_was_given() {
        let folder =
            std::env::temp_dir().join(format!("kam-notice-shortcut-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&folder);
        std::fs::create_dir_all(&folder).unwrap();
        let link = folder.join("test.lnk");
        let target = std::env::current_exe().unwrap();

        ensure_shortcut_at(&link, &target, "com.kamsecurity.shell.test").unwrap();
        let (pointed, id) = read_shortcut(&link).expect("the shortcut reads back");
        assert!(
            pointed.eq_ignore_ascii_case(&target.to_string_lossy()),
            "{pointed}"
        );
        assert_eq!(id, "com.kamsecurity.shell.test");

        // Pointing it somewhere else rewrites it.
        let other = folder.join("elsewhere.exe");
        std::fs::write(&other, b"").unwrap();
        ensure_shortcut_at(&link, &other, "com.kamsecurity.shell.test").unwrap();
        assert!(read_shortcut(&link).unwrap().0.ends_with("elsewhere.exe"));

        let _ = std::fs::remove_dir_all(&folder);
    }

    /// Delivery, end to end, under a test identity so the real one is not
    /// touched. Ignored because it puts a notification on the screen of
    /// whoever runs it. It registers a test shortcut in the Start menu, shows
    /// one notification, confirms Windows put it in the notification centre's
    /// history for that identity, and then removes the notification and the
    /// shortcut. Windows' own settings key for the identity is left; it is
    /// where Windows records that the identity has sent notifications.
    #[test]
    #[ignore = "shows a real notification on this machine"]
    fn a_notification_is_delivered_under_a_registered_identity() {
        const TEST_ID: &str = "com.kamsecurity.shell.test";
        let link = start_menu().unwrap().join("KAM Security test.lnk");
        ensure_shortcut_at(&link, &std::env::current_exe().unwrap(), TEST_ID).unwrap();
        // Windows notices a new shortcut asynchronously.
        std::thread::sleep(std::time::Duration::from_secs(3));

        // Windows only reports a setting for an identity it knows; for one
        // it does not, this fails.
        let setting = setting(TEST_ID);
        println!("Windows' setting for {TEST_ID}: {setting:?}");

        show(
            TEST_ID,
            "KAM Security test notice",
            "Sent while building the Downloads page. Nothing happened to any file.",
            || {},
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_secs(2));

        let history = ToastNotificationManager::History().unwrap();
        let delivered = history
            .GetHistoryWithId(&HSTRING::from(TEST_ID))
            .and_then(|list| list.Size())
            .unwrap_or(0);
        println!("notifications in history for {TEST_ID}: {delivered}");
        let _ = history.ClearWithId(&HSTRING::from(TEST_ID));
        let _ = std::fs::remove_file(&link);

        let setting = setting.expect("Windows did not recognise the identity the shortcut carries");
        assert_eq!(
            setting,
            NotificationSetting::Enabled,
            "{}",
            blocked_sentence(setting).unwrap_or_default()
        );
        assert!(
            delivered >= 1,
            "Windows did not keep the notification, so it was not delivered"
        );
    }

    #[test]
    fn every_way_windows_can_refuse_is_said_in_a_sentence() {
        for setting in [
            NotificationSetting::DisabledForApplication,
            NotificationSetting::DisabledForUser,
            NotificationSetting::DisabledByGroupPolicy,
            NotificationSetting::DisabledByManifest,
        ] {
            let sentence = blocked_sentence(setting).unwrap_or_default();
            assert!(sentence.ends_with('.'), "{setting:?}: {sentence:?}");
        }
        assert_eq!(blocked_sentence(NotificationSetting::Enabled), None);
    }
}
