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

use kam_core::UserContext;
use serde::{Deserialize, Serialize};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_TIMEOUT};
use windows::Win32::System::EventLog::{
    EvtClose, EvtNext, EvtQuery, EvtQueryReverseDirection, EvtRender, EvtRenderEventXml, EVT_HANDLE,
};

/// How many events to look back through. The Security log on a busy machine
/// turns over quickly, and a canary that was read will be near the top.
///
/// Counted without this program's own reads. Checking that a decoy is still
/// ours means reading it, every status call does that for every decoy, and
/// each read writes several events. Counted, they filled this window within
/// minutes while the Scanner page was open, and a real read older than that
/// was pushed out of it and never shown.
const MAX_EVENTS: usize = 400;

/// A ceiling on every event looked at, this program's own included, so a log
/// full of nothing but our own reads still ends.
const MAX_EXAMINED: usize = 20 * MAX_EVENTS;

/// How long to wait for the log to hand over the next batch.
const BATCH_WAIT_MS: u32 = 1000;

/// How many reads to hand back, after collapsing the duplicates.
///
/// Reading one file produces several 4663 events — Windows writes one per access
/// right exercised — so a single open of a single decoy can appear four or five
/// times. Left alone, one afternoon of testing filled the list with four hundred
/// rows describing about twenty actual reads, which is not a thing anybody can
/// read.
const MAX_TRIPS: usize = 50;

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
/// Each one is recognised only where it really lives. This matched the end of
/// the path, so a stealer that named itself `OneDrive.exe` or `svchost.exe`
/// and ran from Temp, or from `C:\Users\x\Windows\System32`, was filtered out
/// as routine: the one reader this feature exists to catch could opt out of it
/// by choosing a name.
///
/// Decoys are also marked not-content-indexed when planted, so the indexer
/// should not read them at all. This is the second line, for the machines where
/// that attribute does not take.
fn routine(process: Option<&str>, user: &UserContext) -> bool {
    let Some(process) = process else {
        return false;
    };
    let process = normalise(process);
    if is_ourselves(&process) {
        return true;
    }
    let Some((folder, file)) = process.rsplit_once('\\') else {
        return false;
    };
    let parent = folder.rsplit_once('\\').map(|(parent, _)| parent);
    let is = |candidate: Option<String>| candidate.is_some_and(|known| known == folder);
    let parent_is = |candidate: Option<String>| {
        candidate.is_some_and(|known| parent.is_some_and(|parent| parent == known))
    };

    let windows = machine_folder("SystemRoot");
    let system32 = windows.as_ref().map(|root| format!(r"{root}\system32"));
    let program_files = machine_folder("ProgramFiles");
    let program_files_x86 = machine_folder("ProgramFiles(x86)");
    let program_data = machine_folder("ProgramData");
    // OneDrive installs either for one person, in their own Local AppData,
    // or for the whole machine under Program Files.
    let onedrive = [
        (!user.profile().is_empty())
            .then(|| normalise(&format!(r"{}\Microsoft\OneDrive", user.local_app_data()))),
        program_files
            .as_ref()
            .map(|root| format!(r"{root}\microsoft onedrive")),
        program_files_x86
            .as_ref()
            .map(|root| format!(r"{root}\microsoft onedrive")),
    ];

    match file {
        "searchprotocolhost.exe"
        | "searchindexer.exe"
        | "searchfilterhost.exe"
        | "svchost.exe"
        | "backgroundtaskhost.exe" => is(system32),
        "explorer.exe" => is(windows),
        // Defender runs from its stub folder under Program Files, or from a
        // versioned folder under its Platform folder.
        "msmpeng.exe" | "mpcmdrun.exe" | "nissrv.exe" => {
            is(program_files
                .as_ref()
                .map(|root| format!(r"{root}\windows defender")))
                || parent_is(
                    program_data
                        .as_ref()
                        .map(|root| format!(r"{root}\microsoft\windows defender\platform")),
                )
        }
        "onedrive.exe" => onedrive.into_iter().any(is),
        // The helper sits in OneDrive's versioned folder.
        "filesynchelper.exe" => onedrive.into_iter().any(parent_is),
        _ => false,
    }
}

/// A path in the one spelling every comparison here uses: lower case,
/// backslashes, no extended-length prefix and no trailing separator.
fn normalise(path: &str) -> String {
    let lower = path.trim().to_lowercase().replace('/', "\\");
    let plain = lower.strip_prefix(r"\\?\").unwrap_or(&lower);
    plain.trim_end_matches('\\').to_owned()
}

/// A machine-wide folder named by an environment variable, normalised. These
/// are the same for every account, so this process's own are right even in
/// the agent.
fn machine_folder(variable: &str) -> Option<String> {
    std::env::var(variable)
        .ok()
        .map(|value| normalise(&value))
        .filter(|value| !value.is_empty())
}

/// Whether the reader was this very program.
///
/// It has to be, and finding out the hard way was instructive: checking whether
/// a decoy is still ours means reading it, that read is audited like any other,
/// and so the agent reported *itself* rifling through the documents — as a
/// strong concern, once every two minutes, for ever. A canary that cries wolf
/// about its own guardian trains somebody to ignore the one alert that matters.
///
/// Matched on the full image path rather than the file name, so that something
/// merely *called* `kam-agent.exe` somewhere else is still reported. If an
/// attacker can replace the binary at its real installed path then the canaries
/// are not what stands between you and them.
fn is_ourselves(lowered_process: &str) -> bool {
    let Ok(me) = std::env::current_exe() else {
        return false;
    };
    let me = normalise(&me.to_string_lossy());
    !me.is_empty() && lowered_process == me
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

/// What reading the Security log came to.
#[derive(Debug, Default)]
pub struct Read {
    /// Reads of a decoy, newest first.
    pub trips: Vec<Trip>,
    /// Why the log could not be read, or not to the end. `None` when it was.
    pub gap: Option<String>,
}

/// Every recorded read of one of `paths`, newest first.
///
/// A log that could not be read, or stopped answering partway, is said in
/// `gap` rather than returned as an empty list. It was returned as one, and
/// with auditing on the panel then read "decoys planted and being watched"
/// over a list that nothing had actually looked at.
pub fn trips(paths: &[String], user: &UserContext) -> Read {
    if paths.is_empty() {
        return Read::default();
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
    let mut gap = None;

    unsafe {
        let results = match EvtQuery(
            None,
            PCWSTR(channel.as_ptr()),
            PCWSTR(query.as_ptr()),
            EvtQueryReverseDirection.0,
        ) {
            Ok(results) => results,
            Err(error) => {
                return Read {
                    trips: Vec::new(),
                    gap: Some(format!(
                        "The Security log could not be read ({}), so whether anything has \
                         read a decoy cannot be shown.",
                        error.message()
                    )),
                }
            }
        };

        let mut seen = 0_usize;
        let mut examined = 0_usize;
        while seen < MAX_EVENTS && examined < MAX_EXAMINED {
            let mut batch = [0_isize; 16];
            let mut returned = 0_u32;
            if let Err(error) = EvtNext(results, &mut batch, BATCH_WAIT_MS, 0, &mut returned) {
                // The end of the log is the ordinary way to stop. Anything
                // else stopped the reading early, and reads older than that
                // point were never looked at.
                if error.code() != ERROR_NO_MORE_ITEMS.to_hresult() {
                    gap = Some(if error.code() == ERROR_TIMEOUT.to_hresult() {
                        "The Security log stopped answering partway through, so older \
                         reads of a decoy may not be shown."
                            .to_owned()
                    } else {
                        format!(
                            "The Security log could not be read to the end ({}), so older \
                             reads of a decoy may not be shown.",
                            error.message()
                        )
                    });
                }
                break;
            }
            if returned == 0 {
                break;
            }
            for handle in batch.iter().take(returned as usize) {
                let event = EVT_HANDLE(*handle);
                examined += 1;
                let xml = render(event);
                if counts_toward_window(xml.as_deref()) {
                    seen += 1;
                }
                if let Some(xml) = xml {
                    if let Some(object) = data(&xml, "ObjectName") {
                        let lower = object.to_lowercase();
                        // Files match exactly. A registry key is named by
                        // Windows in the kernel's own namespace rather than the
                        // form anything types, and which hive prefix it carries
                        // depends on the account — so those match on the tail of
                        // the path, which contains the decoy's own name and so
                        // cannot collide with anything else.
                        if wanted
                            .iter()
                            .any(|path| lower == *path || lower.ends_with(path))
                        {
                            let process = data(&xml, "ProcessName");
                            // The indexer and the antimalware engine read
                            // everything; reporting them would make the canary
                            // noise on the day it was planted.
                            if !routine(process.as_deref(), user) {
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

    Read {
        trips: collapse(found),
        gap,
    }
}

/// Whether an event counts toward the [`MAX_EVENTS`] window.
///
/// Our own reads are looked at but not counted, so they cannot push a real
/// read out of the window. An event that would not render counts, since
/// nothing can be said about who wrote it.
fn counts_toward_window(xml: Option<&str>) -> bool {
    !xml.and_then(|xml| data(xml, "ProcessName"))
        .is_some_and(|process| is_ourselves(&normalise(&process)))
}

/// Collapse the several events one read produces into one row.
///
/// Windows writes a 4663 per access right exercised, so opening one decoy once
/// yields four or five identical-looking events within the same second. The key
/// here is the second, the file and the program — which keeps two genuinely
/// separate reads apart while folding one read's worth of noise together.
fn collapse(trips: Vec<Trip>) -> Vec<Trip> {
    let mut seen = std::collections::HashSet::new();
    let mut kept = Vec::new();
    for trip in trips {
        // Timestamps are ISO 8601, so truncating at the decimal point is the
        // whole second without any parsing.
        let second = trip.at.split('.').next().unwrap_or(&trip.at).to_owned();
        let key = format!(
            "{second}\u{0}{}\u{0}{}",
            trip.path.to_lowercase(),
            trip.process.as_deref().unwrap_or_default().to_lowercase()
        );
        if seen.insert(key) {
            kept.push(trip);
            if kept.len() >= MAX_TRIPS {
                break;
            }
        }
    }
    kept
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

    fn me() -> UserContext {
        UserContext::new(Some("S-1-5-21-1-2-3-1001".to_owned()), r"C:\Users\me")
    }

    #[test]
    fn reading_the_security_log_never_panics() {
        // Unprivileged the log cannot be read, and that is said rather than
        // returned as an empty list.
        let read = trips(
            &[r"C:\Users\nobody\Documents\nothing".to_owned()],
            &UserContext::current(),
        );
        println!("{} trips, gap: {:?}", read.trips.len(), read.gap);
        if read.trips.is_empty() && read.gap.is_none() {
            println!("the log was read and nothing touched the path");
        }
    }

    #[test]
    fn the_windows_search_indexer_is_not_reported_as_a_thief() {
        // The exact false positive the first end-to-end run produced: the
        // indexer read a decoy seconds after it was planted, because that is
        // its job.
        let windows = std::env::var("SystemRoot").unwrap();
        let data = std::env::var("ProgramData").unwrap();
        let program_files = std::env::var("ProgramFiles").unwrap();
        for reader in [
            format!(r"{windows}\System32\SearchProtocolHost.exe"),
            format!(r"{windows}\System32\searchindexer.exe"),
            format!(r"{windows}\System32\svchost.exe"),
            format!(r"{windows}\explorer.exe"),
            format!(r"{data}\Microsoft\Windows Defender\Platform\4.18.1-0\MsMpEng.exe"),
            format!(r"{program_files}\Windows Defender\MpCmdRun.exe"),
            format!(r"{program_files}\Microsoft OneDrive\OneDrive.exe"),
            format!(r"{program_files}\Microsoft OneDrive\26.1.0\FileSyncHelper.exe"),
            r"C:\Users\me\AppData\Local\Microsoft\OneDrive\OneDrive.exe".to_owned(),
        ] {
            assert!(routine(Some(&reader), &me()), "{reader}");
        }
    }

    /// A routine reader is routine only where it really lives.
    ///
    /// The exemption matched the end of the path, so a stealer that named
    /// itself after one of these and ran from anywhere else was filtered out
    /// as routine, which is the one reader this feature exists to catch.
    #[test]
    fn a_thief_named_like_a_routine_reader_is_still_reported() {
        for impostor in [
            r"C:\Users\me\AppData\Local\Temp\OneDrive.exe",
            r"C:\Users\me\AppData\Local\Temp\MsMpEng.exe",
            r"C:\Users\me\AppData\Local\Temp\svchost.exe",
            r"C:\Users\me\Windows\System32\svchost.exe",
            r"C:\Users\me\Windows\explorer.exe",
            r"C:\Users\me\AppData\Local\Microsoft\OneDriveX\OneDrive.exe",
            r"C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe",
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\a\b\MsMpEng.exe",
            r"C:\Users\other\AppData\Local\Microsoft\OneDrive\OneDrive.exe",
        ] {
            assert!(
                !routine(Some(impostor), &me()),
                "{impostor} was waved through as routine"
            );
        }
    }

    #[test]
    fn the_agent_does_not_report_its_own_status_checks() {
        // Checking a decoy means reading it, and that read is audited like any
        // other. Without this the product reported itself as a thief every two
        // minutes.
        let me_exe = std::env::current_exe().unwrap();
        assert!(routine(Some(&me_exe.to_string_lossy()), &me()));
        // Upper case, and forward slashes, must not defeat it.
        assert!(routine(
            Some(&me_exe.to_string_lossy().to_uppercase()),
            &me()
        ));
    }

    #[test]
    fn something_merely_named_like_us_elsewhere_is_still_reported() {
        // The match is on the whole installed path, not the file name, so a
        // copy planted somewhere else does not inherit the exemption.
        assert!(!routine(
            Some(r"C:\Users\me\AppData\Local\Temp\kam-agent.exe"),
            &me()
        ));
        assert!(!routine(Some(r"D:\elsewhere\kam-shell.exe"), &me()));
    }

    #[test]
    fn anything_else_reading_a_decoy_is_still_reported() {
        // The signal this whole feature exists for must survive the filter.
        assert!(!routine(
            Some(r"C:\Users\me\AppData\Local\Temp\thing.exe"),
            &me()
        ));
        assert!(!routine(Some(r"C:\Windows\System32\cmd.exe"), &me()));
        assert!(!routine(
            Some(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe"),
            &me()
        ));
        assert!(!routine(None, &me()));
        // A name that merely ends in something similar must not slip through.
        assert!(!routine(Some(r"C:\Users\me\notsearchindexer.exe"), &me()));
    }

    #[test]
    fn one_read_reported_several_times_collapses_to_one_row() {
        // What Windows actually writes: several events for one open, differing
        // only in which access right was exercised.
        let one = |at: &str, path: &str, process: &str| Trip {
            at: at.to_owned(),
            path: path.to_owned(),
            process: Some(process.to_owned()),
            process_id: Some("0x1".to_owned()),
            user: Some("akcar".to_owned()),
        };
        let collapsed = collapse(vec![
            one("2026-09-06T20:41:07.0242280Z", r"C:\decoy", "thief.exe"),
            one("2026-09-06T20:41:07.0235908Z", r"C:\decoy", "thief.exe"),
            one("2026-09-06T20:41:07.0229571Z", r"C:\decoy", "thief.exe"),
        ]);
        assert_eq!(collapsed.len(), 1, "one read should be one row");
    }

    #[test]
    fn two_genuinely_separate_reads_are_both_kept() {
        // The signal must survive the collapsing: a second read a minute later,
        // or by a different program, is a different thing worth seeing.
        let one = |at: &str, process: &str| Trip {
            at: at.to_owned(),
            path: r"C:\decoy".to_owned(),
            process: Some(process.to_owned()),
            process_id: None,
            user: None,
        };
        let collapsed = collapse(vec![
            one("2026-09-06T20:41:07.1Z", "thief.exe"),
            one("2026-09-06T20:42:11.1Z", "thief.exe"),
            one("2026-09-06T20:41:07.1Z", "other.exe"),
        ]);
        assert_eq!(collapsed.len(), 3, "{collapsed:#?}");
    }

    #[test]
    fn the_list_stays_short_enough_to_read() {
        let many: Vec<Trip> = (0..500)
            .map(|index| Trip {
                at: format!("2026-09-06T20:41:{:02}.0Z", index % 60),
                path: format!(r"C:\decoy-{index}"),
                process: None,
                process_id: None,
                user: None,
            })
            .collect();
        assert_eq!(collapse(many).len(), MAX_TRIPS);
    }

    /// Our own status checks read every decoy and write several events each,
    /// and counting them filled the look-back window within minutes.
    #[test]
    fn our_own_reads_do_not_use_up_the_window() {
        let me_exe = std::env::current_exe().unwrap();
        let ours = format!(
            "<Data Name='ProcessName'>{}</Data>",
            me_exe.to_string_lossy().to_uppercase()
        );
        assert!(!counts_toward_window(Some(&ours)));
        assert!(counts_toward_window(Some(SAMPLE)));
        assert!(counts_toward_window(None));
    }

    #[test]
    fn asking_about_no_paths_does_no_work() {
        let read = trips(&[], &me());
        assert!(read.trips.is_empty());
        assert!(read.gap.is_none());
    }
}
