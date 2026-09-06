//! The time, written the way the audit log writes it.
//!
//! The store stamps rows with SQLite's own clock in `%Y-%m-%dT%H:%M:%fZ`. Code
//! that produces a timestamp outside the database — the watcher, which notes
//! when it saw something rather than when it got round to recording it — needs
//! the same shape, so the interface can sort and display both alike. Pulling in
//! a date library for one format string would be out of proportion, and the
//! civil-date arithmetic below is a well-known handful of lines.

use std::time::{SystemTime, UNIX_EPOCH};

/// Now, in UTC, as `2026-09-06T14:12:02.417Z`.
pub fn now_utc_iso() -> String {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    iso_from_unix_millis(since.as_millis() as u64)
}

/// Render a Unix time in milliseconds in the audit log's format.
pub fn iso_from_unix_millis(millis: u64) -> String {
    let seconds = millis / 1000;
    let millis = millis % 1000;
    let days = seconds / 86_400;
    let remainder = seconds % 86_400;
    let (year, month, day) = civil_from_days(days as i64);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        remainder / 3600,
        (remainder % 3600) / 60,
        remainder % 60
    )
}

/// Days since 1970-01-01 to a proleptic Gregorian date. Howard Hinnant's
/// algorithm, which is exact for every date this program will ever see.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_known_instant_renders_in_the_stores_format() {
        // 2026-09-06T14:12:02.417Z
        assert_eq!(
            iso_from_unix_millis(1_788_703_922_417),
            "2026-09-06T14:12:02.417Z"
        );
    }

    #[test]
    fn the_epoch_and_a_leap_day_come_out_right() {
        assert_eq!(iso_from_unix_millis(0), "1970-01-01T00:00:00.000Z");
        // 2024-02-29T00:00:00Z
        assert_eq!(
            iso_from_unix_millis(1_709_164_800_000),
            "2024-02-29T00:00:00.000Z"
        );
    }

    #[test]
    fn now_looks_like_an_audit_timestamp() {
        let now = now_utc_iso();
        assert_eq!(now.len(), 24, "{now}");
        assert!(now.ends_with('Z'));
        assert!(now.starts_with("20"));
    }
}
