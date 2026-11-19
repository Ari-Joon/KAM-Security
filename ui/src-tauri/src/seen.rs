//! When this person last opened Active downloads, so that the results
//! recorded since can be counted beside its name.
//!
//! # Why there is a count at all
//!
//! A download Defender flags is announced with a Windows notification, and
//! Windows shows that only to somebody who has notifications switched on.
//! With them off, nothing anywhere said that a download had been flagged
//! unless the page happened to be open. The count is the sign that does not
//! depend on Windows: the results this person has not looked at yet, beside
//! the page's name in the menu and on the Overview.
//!
//! # Whose it is, and where it is kept
//!
//! It is the person's, not the service's: a note of what one account has
//! looked at. So it is kept in that account's own hive, under
//! `HKCU\Software\KAM Security`, beside the choices about starting at sign-in
//! and the right-click menu, and written by this unelevated process as them.
//! Another account on the same PC has its own. The service is never asked to
//! remember it. It only counts the caller's own rows after a moment the
//! caller names, so there is no account for it to get wrong.
//!
//! Nothing is kept in memory here. Closing the window, quitting and
//! restarting all find the same value where it was left.
//!
//! # What is counted from
//!
//! The first time this program runs with nothing on record, the moment is set
//! to then. Counting from the beginning would greet somebody with every
//! flagged download they have ever had, all long since seen, as if it were
//! news.
//!
//! # What cannot be told is not nothing
//!
//! A value that is there and cannot be read, or is not a time, is "could not
//! tell", and so is a service that does not answer. None of them is ever
//! shown as a count of nothing. Opening the page writes a fresh value, which
//! also puts right one that had gone bad.

use std::os::windows::ffi::OsStrExt;

use kam_ipc::{Request, Response};
use serde::Serialize;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegGetValueW, RegSetValueExW, HKEY, HKEY_CURRENT_USER,
    KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ, RRF_RT_REG_SZ,
};

/// Where it is kept, beside this account's other choices.
const KEY: &str = r"Software\KAM Security";
const VALUE: &str = "DownloadsSeenAt";

/// What is on record about when the page was last opened.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Mark {
    At(String),
    /// Nothing is on record.
    Never,
    /// Something is there, and it could not be read or is not a time.
    Unreadable(String),
}

/// The results this person has not looked at yet, or why they could not be
/// counted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Unseen {
    Counted {
        /// Downloads Defender flagged.
        flagged: u64,
        /// Checks that did not finish.
        unfinished: u64,
        /// The moment they are counted from.
        since: String,
    },
    Unknown {
        reason: String,
    },
}

/// What putting it on record that the page was opened found there before.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Looked {
    /// When the page was opened the time before, which is what the rows
    /// recorded since are new against. `None` when nothing readable was on
    /// record.
    previous: Option<String>,
}

/// At start: if nothing is on record, count from now.
pub fn start_counting() {
    if let Err(reason) = start_counting_at(KEY, &kam_core::clock::now_utc_iso()) {
        eprintln!("{reason}");
    }
}

/// The results not looked at yet, counted by the agent from the moment on
/// record.
pub fn unseen() -> Unseen {
    unseen_with(KEY, &kam_core::clock::now_utc_iso(), &ask_the_agent)
}

/// Put it on record that the page is in front of the person now.
pub fn looked() -> Result<Looked, String> {
    looked_at(KEY, &kam_core::clock::now_utc_iso())
}

/// Ask the agent how many of this person's results recorded after `since`
/// are ones to look at: flagged, and unfinished.
fn ask_the_agent(since: &str) -> Result<(u64, u64), String> {
    let request = Request::CountDownloadsSince {
        since: since.to_owned(),
    };
    match kam_ipc::client::call(&request) {
        Ok(Response::DownloadsSince {
            flagged,
            unfinished,
        }) => Ok((flagged, unfinished)),
        Ok(Response::Error { message }) => Err(message),
        Ok(other) => Err(format!(
            "the agent answered something unexpected: {other:?}"
        )),
        Err(error) => Err(error.to_string()),
    }
}

fn start_counting_at(key: &str, now: &str) -> Result<(), String> {
    match read(key) {
        Mark::Never => write(key, now),
        // On record already. One that cannot be read is left for the count
        // to say so, and for the next opening of the page to put right.
        Mark::At(_) | Mark::Unreadable(_) => Ok(()),
    }
}

/// Whoever does the counting: given the moment to count from, how many
/// flagged and how many unfinished, or why that could not be told. The agent
/// in the program, and whatever a test needs in a test.
type Count<'a> = dyn Fn(&str) -> Result<(u64, u64), String> + 'a;

fn unseen_with(key: &str, now: &str, count: &Count<'_>) -> Unseen {
    let since = match read(key) {
        Mark::Unreadable(reason) => {
            return Unseen::Unknown {
                reason: format!(
                    "when Active downloads was last opened could not be read ({reason})"
                ),
            }
        }
        // A moment later than now means the clock has been put back since.
        // Left as it is, nothing would be counted until the clock caught up
        // with it, so counting starts again from now.
        Mark::At(at) if at.as_str() <= now => at,
        Mark::At(_) | Mark::Never => match write(key, now) {
            Ok(()) => now.to_owned(),
            Err(reason) => {
                return Unseen::Unknown {
                    reason: format!("where to count from could not be put on record ({reason})"),
                }
            }
        },
    };
    match count(&since) {
        Ok((flagged, unfinished)) => Unseen::Counted {
            flagged,
            unfinished,
            since,
        },
        Err(reason) => Unseen::Unknown { reason },
    }
}

fn looked_at(key: &str, now: &str) -> Result<Looked, String> {
    let previous = match read(key) {
        Mark::At(at) if at.as_str() <= now => Some(at),
        Mark::At(_) => Some(now.to_owned()),
        Mark::Never | Mark::Unreadable(_) => None,
    };
    write(key, now).map_err(|reason| {
        format!(
            "It could not be put on record that this page was opened ({reason}), so the count \
             beside its name in the menu will not clear."
        )
    })?;
    Ok(Looked { previous })
}

fn wide(text: &str) -> Vec<u16> {
    std::ffi::OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Read the value under `key` in the person's own hive.
///
/// "Not there" and "could not be read" are told apart, because only the
/// first may be answered by starting to count from now.
fn read(key: &str) -> Mark {
    let key = wide(key);
    let value = wide(VALUE);
    // A time is twenty-four characters. Anything that does not fit in this
    // is not one.
    let mut buffer = [0_u16; 64];
    let mut size = std::mem::size_of_val(&buffer) as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            PCWSTR(key.as_ptr()),
            PCWSTR(value.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buffer.as_mut_ptr().cast()),
            Some(&mut size),
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Mark::Never;
    }
    if status != ERROR_SUCCESS {
        return Mark::Unreadable(format!("Windows error {}", status.0));
    }
    let end = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    let text = String::from_utf16_lossy(&buffer[..end]);
    if kam_core::clock::is_iso(&text) {
        Mark::At(text)
    } else {
        Mark::Unreadable("what is on record is not a time".to_owned())
    }
}

fn write(key: &str, at: &str) -> Result<(), String> {
    let key_wide = wide(key);
    let mut handle = HKEY::default();
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(key_wide.as_ptr()),
            None,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut handle,
            None,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(format!("could not open {key}: Windows error {}", status.0));
    }
    let name = wide(VALUE);
    let bytes: Vec<u8> = wide(at)
        .iter()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    let status =
        unsafe { RegSetValueExW(handle, PCWSTR(name.as_ptr()), None, REG_SZ, Some(&bytes)) };
    unsafe {
        let _ = RegCloseKey(handle);
    }
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(format!(
            "could not write {VALUE}: Windows error {}",
            status.0
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const EARLIER: &str = "2026-11-18T09:00:00.000Z";
    const NOW: &str = "2026-11-19T10:02:00.123Z";
    const LATER: &str = "2026-11-20T08:30:00.000Z";

    /// A scratch key in the person's own hive, never the one the program
    /// uses, removed when the test is over.
    struct Scratch(String);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let key = format!(
                r"Software\KAM Security\test-seen-{}-{tag}",
                std::process::id()
            );
            remove(&key);
            Self(key)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            remove(&self.0);
        }
    }

    fn remove(key: &str) {
        let _ = unsafe {
            windows::Win32::System::Registry::RegDeleteKeyW(
                HKEY_CURRENT_USER,
                PCWSTR(wide(key).as_ptr()),
            )
        };
    }

    /// A count that must not be asked for.
    fn never_asked(_: &str) -> Result<(u64, u64), String> {
        panic!("the agent was asked to count from a moment that was never established")
    }

    /// The first run counts from then, so that nobody is greeted with their
    /// whole history as news. A later start changes nothing: the moment is
    /// read back from the registry each time, which is all "it survives a
    /// restart" comes to.
    #[test]
    fn counting_starts_at_the_first_run_and_the_moment_outlives_the_program() {
        let scratch = Scratch::new("start");
        assert_eq!(read(&scratch.0), Mark::Never);

        start_counting_at(&scratch.0, EARLIER).unwrap();
        assert_eq!(read(&scratch.0), Mark::At(EARLIER.to_owned()));
        start_counting_at(&scratch.0, NOW).unwrap();
        assert_eq!(
            read(&scratch.0),
            Mark::At(EARLIER.to_owned()),
            "a second start moved the moment, as if the page had been opened"
        );

        let counted = unseen_with(&scratch.0, NOW, &|since| {
            assert_eq!(since, EARLIER, "counted from the wrong moment");
            Ok((2, 1))
        });
        assert_eq!(
            counted,
            Unseen::Counted {
                flagged: 2,
                unfinished: 1,
                since: EARLIER.to_owned()
            }
        );
    }

    /// Opening the page moves the moment to now, which is what clears the
    /// count, and says what it was before, which is what the rows that are
    /// new are new against.
    #[test]
    fn opening_the_page_moves_the_moment_and_says_what_it_was() {
        let scratch = Scratch::new("looked");
        // Opened with nothing on record at all.
        assert_eq!(
            looked_at(&scratch.0, EARLIER).unwrap(),
            Looked { previous: None }
        );
        assert_eq!(
            looked_at(&scratch.0, NOW).unwrap(),
            Looked {
                previous: Some(EARLIER.to_owned())
            }
        );
        assert_eq!(read(&scratch.0), Mark::At(NOW.to_owned()));

        let counted = unseen_with(&scratch.0, LATER, &|since| {
            assert_eq!(since, NOW);
            Ok((0, 0))
        });
        assert!(matches!(
            counted,
            Unseen::Counted {
                flagged: 0,
                unfinished: 0,
                ..
            }
        ));
    }

    /// Nothing that could not be told is ever a count of nothing: not a
    /// value that cannot be read, not one that is not a time, and not a
    /// service that did not answer.
    #[test]
    fn what_could_not_be_told_is_never_a_count_of_nothing() {
        let scratch = Scratch::new("unknown");

        // The service does not answer, or cannot read its history.
        write(&scratch.0, EARLIER).unwrap();
        let unanswered = unseen_with(&scratch.0, NOW, &|_| {
            Err("the download history could not be read".to_owned())
        });
        assert_eq!(
            unanswered,
            Unseen::Unknown {
                reason: "the download history could not be read".to_owned()
            }
        );

        // Something that is not a time is on record.
        write(&scratch.0, "soon").unwrap();
        assert!(matches!(read(&scratch.0), Mark::Unreadable(_)));
        let unread = unseen_with(&scratch.0, NOW, &never_asked);
        assert!(
            matches!(&unread, Unseen::Unknown { reason } if reason.contains("not a time")),
            "{unread:?}"
        );
        // And it is not taken for a first run, which would start counting
        // from now and hide whatever had been recorded since the last look.
        start_counting_at(&scratch.0, NOW).unwrap();
        assert!(matches!(read(&scratch.0), Mark::Unreadable(_)));

        // Something of the wrong kind is on record.
        set_number(&scratch.0, 7);
        assert!(matches!(read(&scratch.0), Mark::Unreadable(_)));
        assert!(matches!(
            unseen_with(&scratch.0, NOW, &never_asked),
            Unseen::Unknown { .. }
        ));

        // Opening the page puts it right.
        assert_eq!(
            looked_at(&scratch.0, NOW).unwrap(),
            Looked { previous: None }
        );
        assert_eq!(read(&scratch.0), Mark::At(NOW.to_owned()));
    }

    /// A moment later than now is a clock that was put back. It would hide
    /// every result until the clock caught up, so counting starts from now.
    #[test]
    fn a_moment_in_the_future_does_not_hide_what_comes_before_it() {
        let scratch = Scratch::new("future");
        write(&scratch.0, LATER).unwrap();
        let counted = unseen_with(&scratch.0, NOW, &|since| {
            assert_eq!(since, NOW);
            Ok((1, 0))
        });
        assert!(matches!(counted, Unseen::Counted { flagged: 1, .. }));
        assert_eq!(read(&scratch.0), Mark::At(NOW.to_owned()));

        write(&scratch.0, LATER).unwrap();
        assert_eq!(
            looked_at(&scratch.0, NOW).unwrap(),
            Looked {
                previous: Some(NOW.to_owned())
            }
        );
    }

    /// Put a number where the time should be.
    fn set_number(key: &str, number: u32) {
        use windows::Win32::System::Registry::REG_DWORD;
        let key_wide = wide(key);
        let mut handle = HKEY::default();
        let opened = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(key_wide.as_ptr()),
                None,
                None,
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                None,
                &mut handle,
                None,
            )
        };
        assert_eq!(opened, ERROR_SUCCESS);
        let name = wide(VALUE);
        let status = unsafe {
            RegSetValueExW(
                handle,
                PCWSTR(name.as_ptr()),
                None,
                REG_DWORD,
                Some(&number.to_le_bytes()),
            )
        };
        unsafe {
            let _ = RegCloseKey(handle);
        }
        assert_eq!(status, ERROR_SUCCESS);
    }
}
