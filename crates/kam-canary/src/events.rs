//! Reading back what touched a canary.
//!
//! When a file carrying an audit rule is read, Windows writes event **4663** to
//! the Security log: "an attempt was made to access an object". The event names
//! the file, the process that opened it, and the account it ran as. That is
//! everything a person needs, and it is why this approach is worth the setup —
//! the answer is not "something read your documents" but "this program, at this
//! time, as this user".
//!
//! # Why the XML is read by hand
//!
//! `EvtRender` will hand back a rendered event as XML, and the three fields
//! wanted here are `<Data Name='ObjectName'>`, `<Data Name='ProcessName'>` and
//! `<Data Name='SubjectUserName'>`. Pulling those out with a string search is
//! not elegant, but the alternative is an XML parser dependency for four
//! extractions from a document Windows generates to a fixed shape — the same
//! trade already made in the scheduled-task reader, and for the same reason.

use serde::{Deserialize, Serialize};
use windows::core::PCWSTR;
use windows::Win32::System::EventLog::{
    EvtClose, EvtNext, EvtQuery, EvtQueryReverseDirection, EvtRender, EvtRenderEventXml, EVT_HANDLE,
};

/// How many events to look back through. The Security log on a busy machine
/// turns over quickly, and a canary that was read will be near the top.
const MAX_EVENTS: usize = 400;

/// Windows components whose job is to read every file on the machine.
///
/// This list exists because of what the first end-to-end test actually caught:
/// not the read it had just performed, but `SearchProtocolHost.exe` indexing the
/// decoy seconds after it was written. The indexer, the antimalware engine and
/// the sync clients all walk everything, and a canary that reported them would
/// be crying wolf on the day it was planted.
///
/// Filtering them is a real trade and worth stating plainly. Something that
/// managed to run *as* one of these, from its real path in `System32` or
/// `Program Files`, would go unreported here — but anything with that much
/// access already owns the machine, and a decoy file is not what stands between
/// you and it. The far likelier outcome without this list is that the feature
/// becomes noise and gets ignored, which costs more.
///
/// Decoys are also marked not-content-indexed when planted, so the indexer
/// should not read them at all. This is the second line, for the machines where
/// that attribute does not take.
const ROUTINE_READERS: &[&str] = &[
    r"\windows\system32\searchprotocolhost.exe",
    r"\windows\system32\searchindexer.exe",
    r"\windows\system32\searchfilterhost.exe",
    r"\windows\system32\svchost.exe",
    r"\windows\explorer.exe",
    r"\msmpeng.exe",
    r"\mpcmdrun.exe",
    r"\nissrv.exe",
    r"\onedrive.exe",
    r"\filesynchelper.exe",
    r"\backgroundtaskhost.exe",
];

/// Whether a read came from something that reads everything anyway.
fn routine(process: Option<&str>) -> bool {
    let Some(process) = process else {
        return false;
    };
    let lower = process.to_lowercase().replace('/', "\\");
    ROUTINE_READERS.iter().any(|known| lower.ends_with(known))
}

/// Something read a canary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trip {
    /// When Windows recorded it, as written in the event.
    pub at: String,
    /// The canary that was read.
    pub path: String,
    /// The program that read it, when the event named one.
    pub process: Option<String>,
    pub process_id: Option<String>,
    /// The account it ran as.
    pub user: Option<String>,
}

/// Pull one `<Data Name='X'>value</Data>` out of an event's XML.
fn data(xml: &str, name: &str) -> Option<String> {
    // Windows writes the attribute with single quotes; accept either so a
    // change of quoting style does not silently empty every field.
    for quote in ['\'', '"'] {
        let needle = format!("<Data Name={quote}{name}{quote}>");
        if let Some(start) = xml.find(&needle) {
            let rest = &xml[start + needle.len()..];
            if let Some(end) = rest.find("</Data>") {
                let value = rest[..end].trim();
                if !value.is_empty() && value != "-" {
                    return Some(unescape(value));
                }
            }
        }
    }
    None
}

/// The event's timestamp, from `<TimeCreated SystemTime='...'/>`.
fn timestamp(xml: &str) -> Option<String> {
    let start = xml.find("SystemTime=")? + "SystemTime=".len();
    let rest = &xml[start..];
    let quote = rest.chars().next()?;
    let rest = &rest[1..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_owned())
}

fn unescape(text: &str) -> String {
    text.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Render one event handle as XML.
fn render(event: EVT_HANDLE) -> Option<String> {
    unsafe {
        let mut needed = 0_u32;
        let mut properties = 0_u32;
        // First call sizes the buffer; it is expected to fail.
        let _ = EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            0,
            None,
            &mut needed,
            &mut properties,
        );
        if needed == 0 {
            return None;
        }

        let mut buffer = vec![0_u8; needed as usize];
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            needed,
            Some(buffer.as_mut_ptr().cast()),
            &mut needed,
            &mut properties,
        )
        .ok()?;

        // The buffer holds UTF-16, and `needed` counts bytes.
        let units: Vec<u16> = buffer[..needed as usize]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        let text = String::from_utf16_lossy(&units);
        Some(text.trim_end_matches('\u{0}').to_owned())
    }
}

/// Every recorded read of one of `paths`, newest first.
///
/// Returns nothing rather than failing when the Security log cannot be read:
/// an unprivileged caller genuinely cannot see it, and the report says
/// separately whether auditing is on, so an empty list is never mistaken for an
/// all-clear.
pub fn trips(paths: &[String]) -> Vec<Trip> {
    if paths.is_empty() {
        return Vec::new();
    }
    let wanted: Vec<String> = paths.iter().map(|path| path.to_lowercase()).collect();

    let channel: Vec<u16> = "Security"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // 4663 is the access itself. 4656 (a handle was requested) fires more often
    // and would double-count, so only the access is read.
    let query: Vec<u16> = "*[System[(EventID=4663)]]"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut found = Vec::new();

    unsafe {
        let Ok(results) = EvtQuery(
            None,
            PCWSTR(channel.as_ptr()),
            PCWSTR(query.as_ptr()),
            EvtQueryReverseDirection.0,
        ) else {
            return found;
        };

        let mut seen = 0_usize;
        while seen < MAX_EVENTS {
            let mut batch = [0_isize; 16];
            let mut returned = 0_u32;
            if EvtNext(results, &mut batch, 200, 0, &mut returned).is_err() || returned == 0 {
                break;
            }
            for handle in batch.iter().take(returned as usize) {
                let event = EVT_HANDLE(*handle);
                seen += 1;
                if let Some(xml) = render(event) {
                    if let Some(object) = data(&xml, "ObjectName") {
                        let lower = object.to_lowercase();
                        if wanted.contains(&lower) {
                            let process = data(&xml, "ProcessName");
                            // The indexer and the antimalware engine read
                            // everything; reporting them would make the canary
                            // noise on the day it was planted.
                            if !routine(process.as_deref()) {
                                found.push(Trip {
                                    at: timestamp(&xml).unwrap_or_default(),
                                    path: object,
                                    process,
                                    process_id: data(&xml, "ProcessId"),
                                    user: data(&xml, "SubjectUserName"),
                                });
                            }
                        }
                    }
                }
                let _ = EvtClose(event);
            }
        }
        let _ = EvtClose(results);
    }

    found
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A 4663 as Windows actually writes it, trimmed to the parts read here.
    const SAMPLE: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System><EventID>4663</EventID>
<TimeCreated SystemTime='2026-09-06T18:20:11.4821147Z'/>
</System>
<EventData>
<Data Name='SubjectUserSid'>S-1-5-21-1-2-3-1001</Data>
<Data Name='SubjectUserName'>akcar</Data>
<Data Name='ObjectName'>C:\Users\akcar\Documents\Backups\Chrome\Login Data</Data>
<Data Name='ProcessId'>0x1a2c</Data>
<Data Name='ProcessName'>C:\Users\akcar\AppData\Local\Temp\thing.exe</Data>
<Data Name='AccessList'>%%4416</Data>
</EventData></Event>"#;

    #[test]
    fn the_fields_a_person_needs_are_pulled_out_of_a_real_event() {
        assert_eq!(
            data(SAMPLE, "ObjectName").as_deref(),
            Some(r"C:\Users\akcar\Documents\Backups\Chrome\Login Data")
        );
        assert_eq!(
            data(SAMPLE, "ProcessName").as_deref(),
            Some(r"C:\Users\akcar\AppData\Local\Temp\thing.exe")
        );
        assert_eq!(data(SAMPLE, "SubjectUserName").as_deref(), Some("akcar"));
        assert_eq!(data(SAMPLE, "ProcessId").as_deref(), Some("0x1a2c"));
        assert_eq!(
            timestamp(SAMPLE).as_deref(),
            Some("2026-09-06T18:20:11.4821147Z")
        );
    }

    #[test]
    fn a_missing_or_empty_field_is_absent_rather_than_blank() {
        // Windows writes "-" for fields it has nothing for, and showing that on
        // screen would look like a name.
        assert_eq!(data(SAMPLE, "NotAField"), None);
        assert_eq!(
            data("<Data Name='ProcessName'>-</Data>", "ProcessName"),
            None
        );
        assert_eq!(data("<Data Name='X'>  </Data>", "X"), None);
    }

    #[test]
    fn double_quoted_attributes_are_read_too() {
        assert_eq!(
            data(r#"<Data Name="ObjectName">C:\thing</Data>"#, "ObjectName").as_deref(),
            Some(r"C:\thing")
        );
    }

    #[test]
    fn escaped_characters_come_back_as_written() {
        assert_eq!(
            data("<Data Name='X'>a &amp; b</Data>", "X").as_deref(),
            Some("a & b")
        );
    }

    #[test]
    fn reading_the_security_log_never_panics() {
        // Unprivileged this returns nothing, which is the honest answer and the
        // one the report distinguishes from "auditing is on and saw nothing".
        let trips = trips(&[r"C:\Users\nobody\Documents\nothing".to_owned()]);
        println!("{} trips", trips.len());
    }

    #[test]
    fn the_windows_search_indexer_is_not_reported_as_a_thief() {
        // The exact false positive the first end-to-end run produced: the
        // indexer read a decoy seconds after it was planted, because that is
        // its job.
        assert!(routine(Some(r"C:\Windows\System32\SearchProtocolHost.exe")));
        assert!(routine(Some(r"C:\Windows\System32\searchindexer.exe")));
        assert!(routine(Some(
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe"
        )));
        assert!(routine(Some(
            r"C:\Program Files\Microsoft OneDrive\OneDrive.exe"
        )));
    }

    #[test]
    fn anything_else_reading_a_decoy_is_still_reported() {
        // The signal this whole feature exists for must survive the filter.
        assert!(!routine(Some(r"C:\Users\me\AppData\Local\Temp\thing.exe")));
        assert!(!routine(Some(r"C:\Windows\System32\cmd.exe")));
        assert!(!routine(Some(
            r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe"
        )));
        assert!(!routine(None));
        // A name that merely ends in something similar must not slip through.
        assert!(!routine(Some(r"C:\Users\me\notsearchindexer.exe")));
    }

    #[test]
    fn asking_about_no_paths_does_no_work() {
        assert!(trips(&[]).is_empty());
    }
}
