//! The one place anything is ever removed from, or moved within, the system.
//!
//! Product rule: nothing is deleted. Every module routes destructive intent
//! through here, which stages the item, records everything needed to put it
//! back, and keeps it for thirty days. Purging afterwards is a separate,
//! explicit call.
//!
//! # Why this is a rename, not a copy
//!
//! The store lives on the same volume as the thing being quarantined, so
//! staging is `MoveFile` within one filesystem: a directory entry is unlinked
//! from one parent and linked to another. Nothing is read, nothing is written,
//! and a 45 GB folder is quarantined as fast as a 4 KB one.
//!
//! It also means the security descriptor and every timestamp survive untouched,
//! because no file is rewritten — there is nothing to reapply on restore, and
//! therefore nothing to get wrong. A cross-volume move would need all of that
//! captured and replayed, so it is refused instead.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use kam_core::{Error, Result};
use serde::{Deserialize, Serialize};

/// How long a quarantined item is kept before it may be purged.
pub const RETENTION_DAYS: u64 = 30;

/// What the payload is called inside an item's directory. Fixed, so a restore
/// does not depend on the manifest being readable.
const PAYLOAD: &str = "payload";
const MANIFEST: &str = "manifest.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    File,
    Directory,
}

/// Everything required to put one item back exactly where it was.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Identifier, and the name of the directory holding the payload. Also the
    /// undo token recorded in the audit log.
    pub id: String,
    pub original_path: String,
    pub kind: ItemKind,
    pub bytes: u64,
    /// Seconds since the Unix epoch.
    pub quarantined_at: u64,
    /// Which module staged it, and why. Shown to the user verbatim.
    pub reason: String,
    /// True once the item has been restored; the payload is gone.
    #[serde(default)]
    pub restored: bool,
}

impl Manifest {
    /// Seconds until this item may be purged. Zero once it is eligible.
    pub fn retention_remaining(&self, now: u64) -> u64 {
        let expires = self.quarantined_at + RETENTION_DAYS * 86_400;
        expires.saturating_sub(now)
    }
}

/// One file moved from where it was to where it now is.
///
/// Quarantine takes something out of use; this puts it somewhere better. Both
/// are renames within a volume and both must be undoable, so they share a store
/// and differ only in where the destination is.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveRecord {
    pub id: String,
    pub from: String,
    pub to: String,
    pub bytes: u64,
    pub moved_at: u64,
    #[serde(default)]
    pub undone: bool,
}

#[derive(Debug)]
pub struct Store {
    root: PathBuf,
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// Windows path comparison is case-insensitive, and a volume is identified by
/// its first character.
fn volume_of(path: &Path) -> Option<char> {
    path.to_str()
        .and_then(|text| text.chars().next())
        .filter(char::is_ascii_alphabetic)
        .map(|letter| letter.to_ascii_uppercase())
}

impl Store {
    /// Open, creating the directory if it is not there.
    pub fn open(root: &Path) -> Result<Self> {
        fs::create_dir_all(root)?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Whether an id is one this store issued.
    ///
    /// A strict whitelist, not a search for the dangerous shapes. `allocate_id`
    /// produces `<seconds>-<four digits>` or `<seconds>-overflow` and nothing else,
    /// so anything that is not exactly that is not ours — and refusing everything
    /// unfamiliar is the only version of this that stays correct when somebody
    /// invents a new way to write a path.
    ///
    /// No separator, colon or dot can pass, which is what makes the join below
    /// safe rather than merely usually safe.
    fn is_issued_id(id: &str) -> bool {
        let Some((seconds, suffix)) = id.split_once('-') else {
            return false;
        };
        let sane_seconds = !seconds.is_empty()
            && seconds.len() <= 20
            && seconds.bytes().all(|byte| byte.is_ascii_digit());
        let sane_suffix = suffix == "overflow"
            || (suffix.len() == 4 && suffix.bytes().all(|b| b.is_ascii_digit()));
        sane_seconds && sane_suffix
    }

    /// Where an item lives, for an id this store issued.
    ///
    /// # Why this validates rather than joining
    ///
    /// The id crosses the trust boundary: it arrives from a client, over the pipe,
    /// into a process running as LocalSystem, and is then used to build a path that
    /// gets deleted or written through. `Path::join` does not treat it as a name.
    /// On Windows an absolute id **discards the root entirely** —
    /// `quarantine.join(r"C:\Users\someone\Documents")` is
    /// `C:\Users\someone\Documents` — and `..` walks out of the store.
    ///
    /// Found by adversarial review, which demonstrated both: two decoy directories
    /// deleted outside the store, one by an absolute id and one by `..`. The only
    /// gate was a readable `manifest.json`, which anybody who can write a folder
    /// can put there.
    ///
    /// The deletion was the obvious half. The worse half is [`Store::restore`],
    /// which reads a payload from this directory and renames it to whatever the
    /// manifest names as its original path: with a traversal id and a planted
    /// manifest, that is an arbitrary file write as LocalSystem, which is an
    /// escalation primitive rather than a nuisance. Both go through here, so one
    /// guard covers restore, purge, delete and manifest at once.
    fn item_directory(&self, id: &str) -> Result<PathBuf> {
        if !Self::is_issued_id(id) {
            return Err(Error::Refused(format!(
                "{id} is not an identifier this store issued"
            )));
        }
        Ok(self.root.join(id))
    }

    /// Move `path` into quarantine and return its manifest.
    ///
    /// `bytes` is passed in rather than measured here: the caller has already
    /// totalled it from the master file table, and walking the tree again to
    /// confirm would cost more than the move itself.
    pub fn take(&self, path: &Path, bytes: u64, reason: &str) -> Result<Manifest> {
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            Error::Refused(format!("{} cannot be read: {error}", path.display()))
        })?;

        // Refusing a reparse point matters here: renaming a junction moves the
        // link, and a later restore would put it back somewhere else entirely.
        if metadata.file_type().is_symlink() {
            return Err(Error::Refused(format!(
                "{} is a junction or symbolic link; quarantining it would move \
                 the link rather than what it points at",
                path.display()
            )));
        }

        if volume_of(path) != volume_of(&self.root) {
            return Err(Error::Refused(format!(
                "{} is on a different volume from the quarantine store; a \
                 cross-volume move would have to copy and re-apply permissions, \
                 which this deliberately does not do",
                path.display()
            )));
        }

        let id = self.allocate_id();
        // The id came from `allocate_id`, so this cannot fail; it is still
        // asked rather than assumed, because the day it can is the day the
        // format changes under it.
        let directory = self.item_directory(&id)?;
        fs::create_dir_all(&directory)?;

        let manifest = Manifest {
            id: id.clone(),
            original_path: path.display().to_string(),
            kind: if metadata.is_dir() {
                ItemKind::Directory
            } else {
                ItemKind::File
            },
            bytes,
            quarantined_at: now_seconds(),
            reason: reason.to_owned(),
            restored: false,
        };

        // Written before the move. If the process dies between the two, an
        // orphaned manifest with nothing beside it is recoverable; a payload
        // with no manifest is an unlabelled directory nobody can put back.
        self.write_manifest(&manifest)?;

        let destination = directory.join(PAYLOAD);
        if let Err(error) = fs::rename(path, &destination) {
            let _ = fs::remove_dir_all(&directory);
            return Err(Error::Refused(format!(
                "{} could not be moved into quarantine: {error}",
                path.display()
            )));
        }

        Ok(manifest)
    }

    /// Put an item back where it came from.
    pub fn restore(&self, id: &str) -> Result<Manifest> {
        let mut manifest = self.manifest(id)?;
        if manifest.restored {
            return Err(Error::Refused(format!("{id} has already been restored")));
        }

        let original = PathBuf::from(&manifest.original_path);
        // Something has taken the name back since. Overwriting it would destroy
        // whatever that is, which is precisely what quarantine exists to avoid.
        if original.exists() {
            return Err(Error::Refused(format!(
                "{} exists again; restoring would overwrite it",
                original.display()
            )));
        }

        if let Some(parent) = original.parent() {
            fs::create_dir_all(parent)?;
        }

        let payload = self.item_directory(id)?.join(PAYLOAD);
        fs::rename(&payload, &original).map_err(|error| {
            Error::Refused(format!(
                "{} could not be restored to {}: {error}",
                id,
                original.display()
            ))
        })?;

        manifest.restored = true;
        self.write_manifest(&manifest)?;
        Ok(manifest)
    }

    /// Delete an item permanently, once its retention has elapsed.
    ///
    /// This is the automatic path: nothing here decides on its own that an
    /// item is old enough, but when something does, the age rule is checked
    /// here rather than trusted from the caller.
    pub fn purge(&self, id: &str) -> Result<u64> {
        let manifest = self.manifest(id)?;
        let remaining = manifest.retention_remaining(now_seconds());
        if remaining > 0 && !manifest.restored {
            return Err(Error::Refused(format!(
                "{id} is still within its {RETENTION_DAYS}-day retention, \
                 {} days remaining",
                remaining.div_ceil(86_400)
            )));
        }
        self.remove(id, manifest.bytes)
    }

    /// Delete an item permanently, at somebody's explicit request.
    ///
    /// The retention period exists so that a mistake has thirty days to be
    /// noticed, and nothing in this product deletes anything on its own. But it
    /// is the machine's owner asking, about something they put here themselves,
    /// and a quarantine that can only be emptied by waiting a month is a
    /// quarantine that fills up with things somebody has already decided about.
    ///
    /// Separate from [`Store::purge`] rather than a flag on it, so that the
    /// automatic path cannot ever take this one by passing the wrong argument,
    /// and so the audit log records which of the two happened.
    pub fn delete_now(&self, id: &str) -> Result<u64> {
        let manifest = self.manifest(id)?;
        self.remove(id, manifest.bytes)
    }

    /// Take the item's directory off the disk.
    ///
    /// A restored item has already had its payload moved back, so removing the
    /// directory takes only the manifest and frees nothing; reporting the size
    /// it once held would be a lie in a column of real numbers.
    fn remove(&self, id: &str, bytes: u64) -> Result<u64> {
        let directory = self.item_directory(id)?;
        let held = directory.join(PAYLOAD).exists();
        fs::remove_dir_all(directory)?;
        Ok(if held { bytes } else { 0 })
    }

    pub fn manifest(&self, id: &str) -> Result<Manifest> {
        let path = self.item_directory(id)?.join(MANIFEST);
        let text = fs::read_to_string(&path)
            .map_err(|error| Error::Refused(format!("no quarantined item {id}: {error}")))?;
        serde_json::from_str(&text)
            .map_err(|error| Error::Refused(format!("{id} has an unreadable manifest: {error}")))
    }

    /// Everything currently held, newest first.
    pub fn list(&self) -> Result<Vec<Manifest>> {
        let mut items = Vec::new();
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(_) => return Ok(items),
        };
        for entry in entries.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Ok(manifest) = self.manifest(&name) {
                items.push(manifest);
            }
        }
        items.sort_by_key(|item| std::cmp::Reverse(item.quarantined_at));
        Ok(items)
    }

    fn moves_directory(&self) -> PathBuf {
        self.root.join("moves")
    }

    /// Move a file, recording how to put it back.
    ///
    /// Refuses to overwrite: if something already sits at the destination, the
    /// move is abandoned rather than resolved by guessing which the user wanted.
    pub fn move_file(&self, from: &Path, to: &Path, bytes: u64) -> Result<MoveRecord> {
        let metadata = fs::symlink_metadata(from).map_err(|error| {
            Error::Refused(format!("{} cannot be read: {error}", from.display()))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(Error::Refused(format!(
                "{} is a link; moving it would move the link and not the file",
                from.display()
            )));
        }
        if !metadata.is_file() {
            return Err(Error::Refused(format!("{} is not a file", from.display())));
        }
        if to.exists() {
            return Err(Error::Refused(format!(
                "{} already exists; moving would overwrite it",
                to.display()
            )));
        }
        if volume_of(from) != volume_of(to) {
            return Err(Error::Refused(
                "moving between drives would copy rather than rename, which this does not do"
                    .to_owned(),
            ));
        }

        if let Some(parent) = to.parent() {
            fs::create_dir_all(parent)?;
        }

        let directory = self.moves_directory();
        fs::create_dir_all(&directory)?;

        let record = MoveRecord {
            id: self.allocate_id(),
            from: from.display().to_string(),
            to: to.display().to_string(),
            bytes,
            moved_at: now_seconds(),
            undone: false,
        };
        // Written first, for the same reason quarantine writes its manifest
        // first: a record with no move is recoverable, a move with no record is
        // a file that silently changed place.
        self.write_move(&record)?;

        fs::rename(from, to).map_err(|error| {
            let _ = fs::remove_file(directory.join(format!("{}.json", record.id)));
            Error::Refused(format!(
                "{} could not be moved to {}: {error}",
                from.display(),
                to.display()
            ))
        })?;

        Ok(record)
    }

    /// Put a moved file back where it was.
    pub fn undo_move(&self, id: &str) -> Result<MoveRecord> {
        let mut record = self.move_record(id)?;
        if record.undone {
            return Err(Error::Refused(format!("{id} has already been undone")));
        }

        let from = PathBuf::from(&record.from);
        let to = PathBuf::from(&record.to);
        if from.exists() {
            return Err(Error::Refused(format!(
                "{} exists again; putting the file back would overwrite it",
                from.display()
            )));
        }
        if let Some(parent) = from.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::rename(&to, &from).map_err(|error| {
            Error::Refused(format!("{} could not be put back: {error}", to.display()))
        })?;

        record.undone = true;
        self.write_move(&record)?;
        Ok(record)
    }

    pub fn move_record(&self, id: &str) -> Result<MoveRecord> {
        let path = self.moves_directory().join(format!("{id}.json"));
        let text = fs::read_to_string(&path)
            .map_err(|error| Error::Refused(format!("no recorded move {id}: {error}")))?;
        serde_json::from_str(&text)
            .map_err(|error| Error::Refused(format!("{id} has an unreadable record: {error}")))
    }

    /// Every move recorded, newest first.
    pub fn moves(&self) -> Result<Vec<MoveRecord>> {
        let mut records = Vec::new();
        let Ok(entries) = fs::read_dir(self.moves_directory()) else {
            return Ok(records);
        };
        for entry in entries.flatten() {
            if let Ok(text) = fs::read_to_string(entry.path()) {
                if let Ok(record) = serde_json::from_str::<MoveRecord>(&text) {
                    records.push(record);
                }
            }
        }
        records.sort_by_key(|record| std::cmp::Reverse(record.moved_at));
        Ok(records)
    }

    fn write_move(&self, record: &MoveRecord) -> Result<()> {
        let directory = self.moves_directory();
        fs::create_dir_all(&directory)?;
        let text = serde_json::to_string_pretty(record)
            .map_err(|error| Error::Refused(format!("could not write a move record: {error}")))?;
        fs::write(directory.join(format!("{}.json", record.id)), text)?;
        Ok(())
    }

    fn write_manifest(&self, manifest: &Manifest) -> Result<()> {
        let path = self.item_directory(&manifest.id)?.join(MANIFEST);
        let text = serde_json::to_string_pretty(manifest)
            .map_err(|error| Error::Refused(format!("could not write a manifest: {error}")))?;
        fs::write(path, text)?;
        Ok(())
    }

    /// Timestamp plus a counter, so two items staged in the same second do not
    /// collide and the directory listing sorts chronologically.
    fn allocate_id(&self) -> String {
        let seconds = now_seconds();
        for suffix in 0..10_000 {
            let id = format!("{seconds}-{suffix:04}");
            if !self.root.join(&id).exists() {
                return id;
            }
        }
        format!("{seconds}-overflow")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Deleting on request works; deleting on the automatic path still waits.
    ///
    /// The two exist separately so that the rule protecting somebody from their
    /// own mistake cannot be lifted by the code that is meant to enforce it.
    /// An id from a client is not a path fragment until it has been checked.
    ///
    /// Every one of these was demonstrated by adversarial review to escape the
    /// store. On Windows an absolute id discards the root entirely, so
    /// `quarantine.join(absolute)` *is* the absolute path, and `..` walks out.
    /// The only gate was a readable manifest, which anybody who can write a
    /// folder can plant.
    #[test]
    fn an_id_that_is_not_ours_never_becomes_a_path() {
        let scratch = Scratch::new("hostile-ids");
        let store = scratch.store();

        let hostile = [
            r"C:\Users\akcar\Documents",
            r"C:\Windows\System32",
            r"..\victim",
            r"..\..\anything",
            r"\\?\C:\Users",
            r"\\server\share",
            r"..",
            r".",
            r"",
            r"1757441-0001\..\..",
            r"1757441-0001/../..",
            r"not-an-id",
            r"1757441-00001",
            r"abcdefg-0001",
        ];

        for id in hostile {
            assert!(store.delete_now(id).is_err(), "{id:?} passed delete_now");
            assert!(store.restore(id).is_err(), "{id:?} passed restore");
            assert!(store.purge(id).is_err(), "{id:?} passed purge");
            assert!(store.manifest(id).is_err(), "{id:?} passed manifest");
        }
    }

    /// And a directory outside the store survives being named.
    ///
    /// The test above is about the guard; this is about the consequence.
    /// Review deleted two decoy directories this way, one by an absolute id and
    /// one by `..`, each gated only by a planted manifest.
    #[test]
    fn a_directory_outside_the_store_is_not_deleted_however_it_is_named() {
        let scratch = Scratch::new("escape");
        let store = scratch.store();

        let victim = scratch.join("victim");
        fs::create_dir_all(&victim).unwrap();
        fs::write(victim.join("precious.txt"), b"do not delete me").unwrap();

        // The manifest has to be there, or this test proves nothing.
        //
        // Without the guard, `delete_now` still calls `manifest` first, so a
        // directory with no manifest is refused for that reason and the test
        // passes whether the fix exists or not. Planting one is exactly what
        // the attack requires and exactly what makes this a reproduction: the
        // manifest gate was never a defence, because anybody who can write a
        // folder can write a file in it.
        let planted = Manifest {
            id: "planted".to_owned(),
            original_path: victim.join("precious.txt").to_string_lossy().into_owned(),
            kind: ItemKind::Directory,
            bytes: 1,
            quarantined_at: 1,
            reason: "planted by an attacker".to_owned(),
            restored: false,
        };
        fs::write(victim.join(MANIFEST), serde_json::to_vec(&planted).unwrap()).unwrap();

        let absolute = victim.to_string_lossy().into_owned();
        assert!(store.delete_now(&absolute).is_err());
        assert!(store.delete_now(r"..\victim").is_err());
        assert!(store.restore(&absolute).is_err());

        assert!(
            victim.join("precious.txt").exists(),
            "a directory outside the store was reached"
        );
    }

    /// The ids the store issues are still accepted, or nothing works.
    #[test]
    fn the_ids_this_store_issues_are_accepted() {
        assert!(Store::is_issued_id("1757441-0001"));
        assert!(Store::is_issued_id("1757441-9999"));
        assert!(Store::is_issued_id("1757441-overflow"));
        assert!(!Store::is_issued_id("1757441"));
        assert!(!Store::is_issued_id("-0001"));

        // A real round trip, so the whitelist cannot be so strict that the
        // product stops working.
        let scratch = Scratch::new("issued");
        let store = scratch.store();
        let source = scratch.join("thing.bin");
        fs::write(&source, vec![1_u8; 64]).unwrap();

        let manifest = store.take(&source, 64, "a test").unwrap();
        assert!(
            Store::is_issued_id(&manifest.id),
            "{} was refused",
            manifest.id
        );
        assert!(store.manifest(&manifest.id).is_ok());
        store.restore(&manifest.id).unwrap();
        assert!(source.exists());
    }

    #[test]
    fn an_item_can_be_deleted_on_request_but_not_by_the_clock_alone() {
        let scratch = Scratch::new("delete-now");
        let store = scratch.store();

        let source = scratch.join("victim.bin");
        std::fs::write(&source, vec![4_u8; 3000]).unwrap();
        let manifest = store.take(&source, 3000, "a test").unwrap();

        // Fresh, so the automatic path must refuse it.
        let refused = store.purge(&manifest.id);
        assert!(refused.is_err(), "retention was not enforced");
        assert!(
            store.manifest(&manifest.id).is_ok(),
            "it was removed anyway"
        );

        // Asked for directly, it goes, and reports what that freed.
        let freed = store.delete_now(&manifest.id).unwrap();
        assert_eq!(freed, 3000);
        assert!(store.manifest(&manifest.id).is_err(), "it is still there");
        assert!(store.list().unwrap().is_empty());
    }

    /// Deleting a restored item frees nothing, and says so.
    ///
    /// Its payload went back where it came from; only the record is left, and
    /// reporting the size it once held would be a lie in a column of real
    /// numbers.
    #[test]
    fn deleting_a_restored_record_frees_nothing() {
        let scratch = Scratch::new("delete-restored");
        let store = scratch.store();

        let source = scratch.join("returned.bin");
        std::fs::write(&source, vec![5_u8; 2048]).unwrap();
        let manifest = store.take(&source, 2048, "a test").unwrap();
        store.restore(&manifest.id).unwrap();
        assert!(source.exists());

        assert_eq!(store.delete_now(&manifest.id).unwrap(), 0);
        assert!(
            source.exists(),
            "restoring then deleting took the file back"
        );
    }

    #[test]
    fn deleting_something_that_is_not_there_is_an_error_rather_than_a_silence() {
        let scratch = Scratch::new("delete-missing");
        let store = scratch.store();
        assert!(store.delete_now("no-such-id").is_err());
    }

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "kam-quarantine-{}-{tag}-{}",
                std::process::id(),
                now_seconds()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }

        fn store(&self) -> Store {
            Store::open(&self.0.join("store")).unwrap()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn taking_a_directory_moves_it_out_of_the_way() {
        let scratch = Scratch::new("take");
        let store = scratch.store();
        let victim = scratch.join("orphaned-app");
        fs::create_dir_all(victim.join("nested")).unwrap();
        fs::write(victim.join("nested/data.bin"), vec![0_u8; 2048]).unwrap();

        let manifest = store
            .take(&victim, 2048, "left behind by an uninstall")
            .unwrap();

        assert!(!victim.exists(), "the original should be gone");
        assert_eq!(manifest.kind, ItemKind::Directory);
        assert_eq!(manifest.bytes, 2048);
        assert!(!manifest.restored);
        // The payload is still on disk, intact.
        let payload = store.root().join(&manifest.id).join(PAYLOAD);
        assert!(payload.join("nested/data.bin").exists());
    }

    #[test]
    fn restoring_puts_it_back_with_its_contents() {
        let scratch = Scratch::new("restore");
        let store = scratch.store();
        let victim = scratch.join("app-data");
        fs::create_dir_all(&victim).unwrap();
        fs::write(victim.join("settings.json"), b"{}").unwrap();

        let manifest = store.take(&victim, 2, "test").unwrap();
        assert!(!victim.exists());

        store.restore(&manifest.id).unwrap();
        assert!(victim.join("settings.json").exists());
        assert!(store.manifest(&manifest.id).unwrap().restored);
    }

    #[test]
    fn restoring_twice_is_refused() {
        let scratch = Scratch::new("twice");
        let store = scratch.store();
        let victim = scratch.join("thing");
        fs::create_dir_all(&victim).unwrap();

        let manifest = store.take(&victim, 0, "test").unwrap();
        store.restore(&manifest.id).unwrap();
        assert!(store.restore(&manifest.id).is_err());
    }

    #[test]
    fn restoring_over_something_that_came_back_is_refused() {
        // The whole point of quarantine is not destroying things, so if the
        // name has been reused, the restore must not win.
        let scratch = Scratch::new("occupied");
        let store = scratch.store();
        let victim = scratch.join("thing");
        fs::create_dir_all(&victim).unwrap();

        let manifest = store.take(&victim, 0, "test").unwrap();
        fs::create_dir_all(&victim).unwrap();
        fs::write(victim.join("new.txt"), b"reinstalled").unwrap();

        let outcome = store.restore(&manifest.id);
        assert!(matches!(outcome, Err(Error::Refused(_))));
        assert!(victim.join("new.txt").exists(), "must not be overwritten");
    }

    #[test]
    fn purging_before_retention_elapses_is_refused() {
        let scratch = Scratch::new("purge");
        let store = scratch.store();
        let victim = scratch.join("thing");
        fs::create_dir_all(&victim).unwrap();

        let manifest = store.take(&victim, 0, "test").unwrap();
        assert!(store.purge(&manifest.id).is_err());
        assert!(store.manifest(&manifest.id).is_ok(), "still there");
    }

    #[test]
    fn retention_counts_down_and_stops_at_zero() {
        let manifest = Manifest {
            id: "x".to_owned(),
            original_path: String::new(),
            kind: ItemKind::File,
            bytes: 0,
            quarantined_at: 1_000_000,
            reason: String::new(),
            restored: false,
        };
        assert_eq!(
            manifest.retention_remaining(1_000_000),
            RETENTION_DAYS * 86_400
        );
        assert_eq!(
            manifest.retention_remaining(1_000_000 + 86_400),
            29 * 86_400
        );
        assert_eq!(manifest.retention_remaining(9_999_999_999), 0);
    }

    #[test]
    fn a_junction_is_refused_rather_than_relocated() {
        let scratch = Scratch::new("junction");
        let store = scratch.store();
        let real = scratch.join("real");
        fs::create_dir_all(&real).unwrap();
        let link = scratch.join("link");

        // Creating a directory symlink needs privilege or developer mode; if it
        // is unavailable the guard cannot be exercised here, so skip rather
        // than fail on a machine that simply does not allow it.
        if std::os::windows::fs::symlink_dir(&real, &link).is_err() {
            return;
        }

        let outcome = store.take(&link, 0, "test");
        assert!(matches!(outcome, Err(Error::Refused(_))));
        assert!(link.exists(), "the link should be untouched");
    }

    #[test]
    fn a_move_relocates_the_file_and_can_be_undone() {
        let scratch = Scratch::new("move");
        let store = scratch.store();
        let from = scratch.join("Downloads");
        let to = scratch.join("Documents/Invoices");
        fs::create_dir_all(&from).unwrap();
        let source = from.join("bill.pdf");
        fs::write(&source, b"invoice").unwrap();

        let record = store.move_file(&source, &to.join("bill.pdf"), 7).unwrap();
        assert!(!source.exists(), "the original should be gone");
        assert!(to.join("bill.pdf").exists(), "and the destination present");

        store.undo_move(&record.id).unwrap();
        assert!(source.exists(), "and back again");
        assert!(!to.join("bill.pdf").exists());
        assert!(store.move_record(&record.id).unwrap().undone);
    }

    #[test]
    fn a_move_refuses_to_overwrite_the_destination() {
        let scratch = Scratch::new("clobber");
        let store = scratch.store();
        let source = scratch.join("a.pdf");
        let target = scratch.join("b.pdf");
        fs::write(&source, b"new").unwrap();
        fs::write(&target, b"existing").unwrap();

        assert!(store.move_file(&source, &target, 3).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"existing");
        assert!(source.exists(), "and the source is left alone");
    }

    #[test]
    fn undoing_over_something_that_came_back_is_refused() {
        let scratch = Scratch::new("undo-clobber");
        let store = scratch.store();
        let source = scratch.join("a.pdf");
        let target = scratch.join("sub/a.pdf");
        fs::write(&source, b"one").unwrap();

        let record = store.move_file(&source, &target, 3).unwrap();
        fs::write(&source, b"a different file with the same name").unwrap();

        assert!(store.undo_move(&record.id).is_err());
        assert_eq!(
            fs::read(&source).unwrap(),
            b"a different file with the same name"
        );
    }

    #[test]
    fn undoing_twice_is_refused() {
        let scratch = Scratch::new("undo-twice");
        let store = scratch.store();
        let source = scratch.join("a.pdf");
        fs::write(&source, b"x").unwrap();
        let record = store
            .move_file(&source, &scratch.join("sub/a.pdf"), 1)
            .unwrap();
        store.undo_move(&record.id).unwrap();
        assert!(store.undo_move(&record.id).is_err());
    }

    #[test]
    fn listing_returns_newest_first() {
        let scratch = Scratch::new("list");
        let store = scratch.store();
        for name in ["one", "two", "three"] {
            let victim = scratch.join(name);
            fs::create_dir_all(&victim).unwrap();
            store.take(&victim, 0, "test").unwrap();
        }
        let items = store.list().unwrap();
        assert_eq!(items.len(), 3);
        for pair in items.windows(2) {
            assert!(pair[0].quarantined_at >= pair[1].quarantined_at);
        }
    }
}
