//! Quarantined items are deleted for good once their thirty days are up.
//!
//! # Why this exists
//!
//! The quarantine has always said thirty days. For its first three months
//! nothing acted on that: the store enforced the age rule in `purge`, and
//! nothing ever called `purge`, so an item stayed until somebody deleted it by
//! hand and the sentence on the Cleanup page was not true. Asked which it
//! should be, the owner chose that thirty days means thirty days.
//!
//! # Why its own thread and not the watcher's loop
//!
//! The watcher stands down when protection is switched off. Expiry is a
//! promise about what is kept, not about what is watched, and it has to hold
//! whichever way that switch is set.
//!
//! # What keeps it from taking something early
//!
//! The age is checked by the store and not here:
//! [`kam_quarantine::Store::purge`] refuses anything younger than thirty days
//! whoever asks. This module only chooses when to ask. It waits a quarter of an
//! hour after the service starts before its first pass, because a machine can
//! come up with its clock wrong and have it put right a minute later, and a
//! deletion cannot be put right. A clock that stays wrong for longer than that
//! is beyond what a program can tell from the inside.
//!
//! Every item that goes is written to the audit log with the path it came
//! from, so the log can always answer where something went.

use std::thread::JoinHandle;
use std::time::Duration;

use kam_core::audit::{Effect, Entry};

use crate::dispatch::human_bytes;
use crate::server;
use crate::service::Shutdown;

/// How long after the service starts before anything is deleted. See the
/// module note: long enough for a clock that booted wrong to be corrected.
const FIRST_PASS_AFTER: Duration = Duration::from_secs(15 * 60);

/// How often to look afterwards. An item whose time is up goes within a few
/// hours of it, and a directory listing four times a day costs nothing.
const EVERY: Duration = Duration::from_secs(6 * 60 * 60);

/// What happened to one item whose thirty days were up.
#[derive(Debug)]
pub(crate) struct Expired {
    pub original_path: String,
    /// The bytes freed, or why the item is still there.
    pub outcome: Result<u64, String>,
}

/// Delete everything that is due, and say what became of each.
///
/// Apart from the loop and from the audit log so that it can be tested against
/// a scratch store. One item that cannot be removed does not stop the rest:
/// the same rule as emptying the quarantine by hand.
pub(crate) fn expire(quarantine: &kam_quarantine::Store) -> Result<Vec<Expired>, String> {
    let due = quarantine
        .expired()
        .map_err(|error| format!("the quarantine could not be listed: {error}"))?;

    Ok(due
        .into_iter()
        .map(|item| Expired {
            outcome: quarantine
                .purge(&item.id)
                .map_err(|error| error.to_string()),
            original_path: item.original_path,
        })
        .collect())
}

/// One pass: delete what is due and write each deletion down.
fn pass(running_as_service: bool) {
    let quarantine = match server::open_quarantine(running_as_service) {
        Ok(quarantine) => quarantine,
        Err(error) => {
            tracing::warn!(%error, "the quarantine could not be opened, so nothing in it was expired");
            return;
        }
    };
    let expired = match expire(&quarantine) {
        Ok(expired) => expired,
        Err(error) => {
            tracing::warn!(%error, "nothing in quarantine was expired");
            return;
        }
    };
    if expired.is_empty() {
        return;
    }

    // Opened only when there is something to write: on almost every pass
    // there is not.
    let store = match server::open_store(running_as_service) {
        Ok(store) => Some(store),
        Err(error) => {
            tracing::error!(%error, "items were expired from quarantine and could not be recorded");
            None
        }
    };

    for item in expired {
        let entry = match &item.outcome {
            Ok(bytes) => {
                tracing::info!(path = %item.original_path, bytes, "expired from quarantine");
                Entry {
                    module: "quarantine",
                    action: "expire",
                    // Recorded without an undo token, because there is no undo.
                    effect: Effect::Changed,
                    detail: format!(
                        "deleted {} for good after its {} days in quarantine, freeing {}",
                        item.original_path,
                        kam_quarantine::RETENTION_DAYS,
                        human_bytes(*bytes)
                    ),
                    undo_token: None,
                }
            }
            Err(error) => {
                tracing::warn!(path = %item.original_path, %error, "could not be expired from quarantine");
                Entry {
                    module: "quarantine",
                    action: "expire",
                    effect: Effect::Refused,
                    detail: format!(
                        "{} has had its {} days in quarantine and could not be deleted: {error}",
                        item.original_path,
                        kam_quarantine::RETENTION_DAYS
                    ),
                    undo_token: None,
                }
            }
        };
        if let Some(store) = &store {
            server::record(store, entry);
        }
    }
}

/// Sleep for `duration`, or until the service is told to stop.
///
/// Returns true when the caller should stop. Checked every second so that
/// `sc stop` is prompt, as the watcher's wait is.
fn wait(shutdown: &Shutdown, duration: Duration) -> bool {
    for _ in 0..duration.as_secs() {
        if shutdown.is_signalled() {
            return true;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    shutdown.is_signalled()
}

fn run(running_as_service: bool, shutdown: Shutdown) {
    if wait(&shutdown, FIRST_PASS_AFTER) {
        return;
    }
    loop {
        pass(running_as_service);
        if wait(&shutdown, EVERY) {
            return;
        }
    }
}

/// Start the expiry pass on its own thread and hand back its handle, so the
/// caller can join it when the service stops.
pub fn spawn(running_as_service: bool, shutdown: Shutdown) -> Option<JoinHandle<()>> {
    match std::thread::Builder::new()
        .name("kam-quarantine-expiry".to_owned())
        .spawn(move || run(running_as_service, shutdown))
    {
        Ok(handle) => Some(handle),
        Err(error) => {
            // Said loudly, because the Cleanup page promises this happens.
            tracing::error!(%error, "the quarantine expiry thread could not be started");
            None
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Put an item's clock back by rewriting when it says it was taken.
    fn age(root: &std::path::Path, id: &str, days: u64) {
        let path = root.join(id).join("manifest.json");
        let mut manifest: kam_quarantine::Manifest =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        manifest.quarantined_at -= days * 86_400;
        std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    }

    /// The whole promise in one place: what is past thirty days goes, what is
    /// not stays, and the pass reports the path a person would recognise.
    #[test]
    fn a_pass_deletes_what_is_past_thirty_days_and_nothing_else() {
        let scratch = std::env::temp_dir().join(format!("kam-expiry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let root = scratch.join("quarantine");
        let quarantine = kam_quarantine::Store::open(&root).unwrap();

        let old = scratch.join("old.bin");
        std::fs::write(&old, vec![1_u8; 512]).unwrap();
        let old_item = quarantine.take(&old, 512, "a test").unwrap();
        age(&root, &old_item.id, kam_quarantine::RETENTION_DAYS + 1);

        let recent = scratch.join("recent.bin");
        std::fs::write(&recent, vec![2_u8; 256]).unwrap();
        let recent_item = quarantine.take(&recent, 256, "a test").unwrap();
        age(&root, &recent_item.id, kam_quarantine::RETENTION_DAYS - 1);

        let expired = expire(&quarantine).unwrap();
        assert_eq!(expired.len(), 1, "{expired:?}");
        assert_eq!(expired[0].outcome, Ok(512));
        assert!(
            expired[0].original_path.ends_with("old.bin"),
            "the report does not name where the item came from: {:?}",
            expired[0].original_path
        );

        assert!(
            quarantine.manifest(&old_item.id).is_err(),
            "it is still held"
        );
        assert!(
            quarantine.manifest(&recent_item.id).is_ok(),
            "an item a day short of thirty days was deleted"
        );

        // Nothing is left to do, and doing it again is not an error.
        assert!(expire(&quarantine).unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn a_stop_ends_the_wait_at_once() {
        // Named rather than `Shutdown::new()`: signalling pokes the pipe, and
        // this must not poke a real agent's.
        let shutdown = Shutdown::for_pipe(&format!("kam-test-expiry-{}", std::process::id()));
        let started = std::time::Instant::now();
        let signalled = {
            let clone = shutdown.clone();
            std::thread::spawn(move || wait(&clone, Duration::from_secs(600)))
        };
        std::thread::sleep(Duration::from_millis(200));
        shutdown.signal();
        assert!(
            signalled.join().unwrap(),
            "the wait did not report the stop"
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the wait ran on after the stop"
        );
    }
}
