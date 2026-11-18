//! The Downloads folder: where it is, what in it is finished, and what an
//! archive's members may be called before any of them is written to disk.
//!
//! Everything here is a pure decision or a read, and it is shared on purpose.
//! The window watches the folder and takes archives apart, as the person; the
//! agent fences what it will quarantine, as LocalSystem. Both have to agree on
//! where Downloads is and on what counts as inside it, and a rule written twice
//! is a rule that drifts.
//!
//! # Inside means inside, after resolution
//!
//! The quarantine fence for downloads is the same shape as every other fence in
//! this crate: the path arrives as a string from a client, so it is resolved
//! before it is judged, and judged a component at a time. `Downloads2` is not
//! inside `Downloads`, a junction inside Downloads that leads elsewhere is
//! elsewhere, and `..` is refused outright rather than worked out.

use std::path::{Path, PathBuf};

use kam_core::registry::View;
use kam_core::UserContext;

use crate::paths;

/// Where Explorer records each known folder for a person, when they have moved
/// it. The values carry `%USERPROFILE%` unexpanded.
const SHELL_FOLDERS: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";

/// `FOLDERID_Downloads`, as Explorer names the value.
const DOWNLOADS_ID: &str = "{374DE290-123F-4565-9164-39C4925E467B}";

/// The person's Downloads folder, as Explorer would open it.
///
/// Read from their own hive, so a folder moved to another drive is found where
/// it really is, and expanded for *them*: inside the agent, `%USERPROFILE%`
/// would otherwise mean LocalSystem's empty profile. When nothing is recorded,
/// it is the folder of that name in their profile, which is Windows' default.
pub fn folder_for(user: &UserContext) -> String {
    user.open_key(SHELL_FOLDERS, View::Native)
        .and_then(|key| key.string(DOWNLOADS_ID))
        .map(|raw| kam_core::env::expand_for(raw.trim(), user))
        .filter(|path| is_absolute_text(path))
        .map(|path| path.trim_end_matches('\\').to_owned())
        .unwrap_or_else(|| user.folder("Downloads"))
}

/// A drive path or a UNC path, which is all a known folder can be.
fn is_absolute_text(path: &str) -> bool {
    let bytes = path.as_bytes();
    let drive = bytes.len() > 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/');
    drive || path.starts_with(r"\\")
}

/// Extensions browsers and download tools give a file while it is still
/// arriving. Chrome and Edge write `.crdownload`, Firefox `.part`, Opera
/// `.opdownload`, Safari and some managers `.download`, older Internet
/// Explorer `.partial`, and plenty of tools `.tmp`.
const PARTIAL_EXTENSIONS: &[&str] = &[
    "crdownload",
    "part",
    "partial",
    "tmp",
    "download",
    "opdownload",
];

/// Whether a name in Downloads belongs to something that has not finished
/// arriving, or is not a download at all.
///
/// Name-based only. Whether a file is *still growing* is a question about time,
/// which the watcher answers by looking twice; this answers the question that
/// the name alone settles.
pub fn is_partial(name: &str) -> bool {
    let lower = name.trim().to_lowercase();
    if lower.is_empty() {
        return true;
    }
    // Explorer's own settings file for the folder, and Office's lock files,
    // land here without anybody downloading anything.
    if lower == "desktop.ini" || lower.starts_with("~$") {
        return true;
    }
    // Chrome stages a download under a hidden name of its own before it has
    // chosen the real one.
    if lower.starts_with(".com.google.chrome.") {
        return true;
    }
    match lower.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() => PARTIAL_EXTENSIONS.contains(&extension),
        _ => false,
    }
}

/// What kind of archive a name says a file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveKind {
    /// A zip, which this product can take apart.
    Zip,
    /// Another container Defender looks inside, but which this product does
    /// not take apart: 7-Zip, RAR, disc images, cabinets, tarballs.
    Other,
}

/// The archive kind a file name implies, if any.
pub fn archive_kind(name: &str) -> Option<ArchiveKind> {
    let lower = name.to_lowercase();
    let extension = lower.rsplit_once('.').map(|(_, extension)| extension)?;
    match extension {
        "zip" => Some(ArchiveKind::Zip),
        "7z" | "rar" | "iso" | "img" | "cab" | "tar" | "gz" | "tgz" | "bz2" | "xz" | "zst"
        | "vhd" | "vhdx" => Some(ArchiveKind::Other),
        _ => None,
    }
}

/// Whether a file is a program or installer, the kinds that carry an
/// Authenticode signature worth reading.
pub fn is_program(name: &str) -> bool {
    let lower = name.to_lowercase();
    let Some((_, extension)) = lower.rsplit_once('.') else {
        return false;
    };
    matches!(
        extension,
        "exe"
            | "dll"
            | "sys"
            | "scr"
            | "msi"
            | "msp"
            | "msix"
            | "msixbundle"
            | "appx"
            | "appxbundle"
            | "cab"
            | "ps1"
            | "psm1"
    )
}

/// Decide whether a path may be quarantined as one of the caller's downloads.
///
/// Returns where the path really leads, which is what must be acted on: the
/// text that arrived is only what somebody asked for.
pub fn check_quarantinable(path: &str, user: &UserContext) -> Result<PathBuf, String> {
    check_inside(path, &folder_for(user))
}

/// [`check_quarantinable`] against a Downloads folder given rather than read,
/// so the fence can be tested on a folder that is not anybody's real one.
pub fn check_inside(path: &str, downloads: &str) -> Result<PathBuf, String> {
    // Refused rather than worked out: nothing that produces a legitimate path
    // here writes `..`, so the only reason to send one is to climb out.
    if paths::has_relative_step(path) {
        return Err(format!(
            "{path} contains a step up a folder, so it was not taken as one of your downloads"
        ));
    }

    let real = std::fs::canonicalize(path).map_err(|error| {
        format!("{path} could not be found on disk ({error}), so nothing was done to it")
    })?;
    let Some(root) = paths::resolved_root(downloads) else {
        return Err(format!(
            "your Downloads folder ({downloads}) could not be found, so nothing in it can be \
             quarantined from here"
        ));
    };

    let plain = paths::plain(&real.to_string_lossy());
    let inside = paths::below(&plain, &root).is_some_and(|rest| !rest.is_empty());
    if !inside {
        return Err(format!(
            "{path} is not inside your Downloads folder ({downloads}) once links and short \
             names are followed, and only a download can be quarantined this way"
        ));
    }

    let metadata = std::fs::symlink_metadata(&real)
        .map_err(|error| format!("{path} could not be read: {error}"))?;
    if metadata.is_dir() {
        return Err(format!("{path} is a folder, not a downloaded file"));
    }
    if metadata.file_type().is_symlink() {
        return Err(format!("{path} is a link rather than a file"));
    }

    Ok(strip_extended(real))
}

/// `canonicalize` answers in the extended-length form. Kept as a drive path
/// where it is one, because that is what every message and record shows.
fn strip_extended(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        _ => path,
    }
}

/// Why an archive member will not be written to disk, judged by its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameRefusal {
    /// No name at all once separators are taken away.
    Empty,
    /// A control character, newlines included. Never a real file name, and the
    /// shape an attempt to forge a line in Defender's report takes.
    ControlCharacter,
    /// Begins at a root, so it would be written wherever that root is.
    Absolute,
    /// Begins with a drive letter, so it names a place on that drive.
    DriveLetter,
    /// A colon after the drive position: an alternate data stream, which would
    /// hide data behind an innocent file.
    Stream,
    /// A `..` step, which climbs out of the folder it is being written into.
    ParentStep,
    /// A part ending in a dot or a space, which Windows quietly removes, so the
    /// file written is not the file named.
    TrailingDotOrSpace,
    /// A character Windows does not allow in a name.
    Forbidden(char),
    /// A device name such as `CON` or `NUL`, which opens the device rather than
    /// creating a file.
    Device(String),
    /// A part longer than any name Windows allows.
    TooLong,
}

impl NameRefusal {
    /// The reason, as a sentence for the person reading the list.
    pub fn sentence(&self) -> String {
        match self {
            Self::Empty => "It has no name.".to_owned(),
            Self::ControlCharacter => {
                "Its name contains a control character, which no real file name has.".to_owned()
            }
            Self::Absolute => {
                "Its name starts at the root of a drive, so it would be written outside the \
                 new folder."
                    .to_owned()
            }
            Self::DriveLetter => {
                "Its name starts with a drive letter, so it would be written outside the new \
                 folder."
                    .to_owned()
            }
            Self::Stream => {
                "Its name contains a colon, which Windows reads as a hidden stream inside \
                 another file."
                    .to_owned()
            }
            Self::ParentStep => {
                "Its name climbs out of the folder with \"..\", so it would be written \
                 somewhere else."
                    .to_owned()
            }
            Self::TrailingDotOrSpace => {
                "Part of its name ends in a dot or a space, which Windows removes, so a \
                 different file would be written."
                    .to_owned()
            }
            Self::Forbidden(character) => {
                format!("Its name contains {character:?}, which Windows does not allow.")
            }
            Self::Device(device) => format!(
                "Part of its name is {device}, which Windows reserves for a device rather \
                 than a file."
            ),
            Self::TooLong => "Part of its name is longer than Windows allows.".to_owned(),
        }
    }
}

/// Windows' reserved device names. Matched on the part before the first dot,
/// because `NUL.txt` opens the device as surely as `NUL` does.
const DEVICES: &[&str] = &[
    "con", "prn", "aux", "nul", "conin$", "conout$", "com0", "com1", "com2", "com3", "com4",
    "com5", "com6", "com7", "com8", "com9", "com¹", "com²", "com³", "lpt0", "lpt1", "lpt2", "lpt3",
    "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9", "lpt¹", "lpt²", "lpt³",
];

/// The parts of an archive member's name, if it is safe to write below a
/// folder; otherwise why not.
///
/// This is the zip-slip rule. A member's name is chosen by whoever made the
/// archive, and the classic attack is a name like `../../Start Menu/run.exe`
/// that writes outside the folder it is extracted into. The answer here is a
/// list of plain parts to join one at a time, never a path to trust, and the
/// extractor checks again where each one really lands.
pub fn safe_relative(name: &str) -> Result<Vec<String>, NameRefusal> {
    if name.chars().any(char::is_control) {
        return Err(NameRefusal::ControlCharacter);
    }
    let text = name.replace('\\', "/");
    if text.starts_with('/') {
        return Err(NameRefusal::Absolute);
    }
    let bytes = text.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(NameRefusal::DriveLetter);
    }
    if text.contains(':') {
        return Err(NameRefusal::Stream);
    }

    let mut parts = Vec::new();
    for part in text.split('/') {
        // `a//b` and a trailing separator on a folder are untidy, not
        // dangerous.
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return Err(NameRefusal::ParentStep);
        }
        if part.ends_with('.') || part.ends_with(' ') {
            return Err(NameRefusal::TrailingDotOrSpace);
        }
        if let Some(bad) = part
            .chars()
            .find(|c| matches!(c, '<' | '>' | '"' | '|' | '?' | '*'))
        {
            return Err(NameRefusal::Forbidden(bad));
        }
        let base = part
            .split('.')
            .next()
            .unwrap_or_default()
            .trim_end()
            .to_lowercase();
        if DEVICES.contains(&base.as_str()) {
            return Err(NameRefusal::Device(part.to_owned()));
        }
        if part.chars().count() > 255 {
            return Err(NameRefusal::TooLong);
        }
        parts.push(part.to_owned());
    }
    if parts.is_empty() {
        return Err(NameRefusal::Empty);
    }
    Ok(parts)
}

/// The name of the folder the files Defender did not flag are extracted into:
/// `<archive name> (checked by KAM)`, then ` (2)`, ` (3)` and so on while a
/// name is taken.
///
/// `taken` says whether something of that name already exists, so nothing is
/// ever extracted into, or over, a folder that was already there.
pub fn extraction_folder_name(archive: &str, taken: impl Fn(&str) -> bool) -> String {
    let stem = match archive.rsplit_once('.') {
        Some((stem, extension)) if extension.eq_ignore_ascii_case("zip") && !stem.is_empty() => {
            stem
        }
        _ => archive,
    };
    // The archive's own name came from wherever it was downloaded from, so it
    // is made safe as a folder name rather than trusted to be one.
    let mut safe: String = stem
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '<' | '>' | '"' | '|' | '?' | '*' | ':' | '/' | '\\') {
                '_'
            } else {
                c
            }
        })
        .collect();
    while safe.ends_with('.') || safe.ends_with(' ') {
        safe.pop();
    }
    if safe.trim().is_empty() || safe_relative(&safe).is_err() {
        safe = "archive".to_owned();
    }

    let first = format!("{safe} (checked by KAM)");
    if !taken(&first) {
        return first;
    }
    (2_u32..)
        .map(|n| format!("{safe} (checked by KAM) ({n})"))
        .find(|candidate| !taken(candidate))
        .unwrap_or(first)
}

/// Whether `inner` lies strictly inside `outer`, comparing a component at a
/// time after both have been resolved by the caller.
pub fn lies_within(inner: &Path, outer: &Path) -> bool {
    let inner = paths::plain(&inner.to_string_lossy());
    let outer = paths::plain(&outer.to_string_lossy());
    paths::below(&inner, &outer).is_some_and(|rest| !rest.is_empty())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // --- what has finished arriving -------------------------------------

    #[test]
    fn a_download_still_arriving_is_not_taken_for_a_finished_one() {
        for partial in [
            "setup.exe.crdownload",
            "Unconfirmed 123456.crdownload",
            "movie.mkv.part",
            "thing.zip.PARTIAL",
            "report.pdf.tmp",
            "app.dmg.download",
            "big.iso.opdownload",
            ".com.google.Chrome.a1B2c3",
            "desktop.ini",
            "~$report.docx",
            "",
        ] {
            assert!(is_partial(partial), "{partial:?} was taken as finished");
        }
    }

    #[test]
    fn a_finished_download_is_not_mistaken_for_a_partial_one() {
        for finished in [
            "setup.exe",
            "photos.zip",
            "notes.txt",
            "partial-results.csv",
            "tmp",
            ".tmp",
            "download.pdf",
            "the.part.two.pdf",
        ] {
            assert!(
                !is_partial(finished),
                "{finished:?} was taken as still arriving"
            );
        }
    }

    #[test]
    fn archives_and_programs_are_told_apart_by_name() {
        assert_eq!(archive_kind("Photos.ZIP"), Some(ArchiveKind::Zip));
        assert_eq!(archive_kind("tools.7z"), Some(ArchiveKind::Other));
        assert_eq!(archive_kind("disc.iso"), Some(ArchiveKind::Other));
        assert_eq!(archive_kind("setup.exe"), None);
        assert_eq!(archive_kind("zip"), None);
        assert!(is_program("Setup.EXE"));
        assert!(is_program("installer.msi"));
        assert!(!is_program("notes.txt"));
        assert!(!is_program("exe"));
    }

    // --- archive member names (zip-slip) --------------------------------

    #[test]
    fn a_member_that_would_land_outside_the_folder_is_refused() {
        let cases: &[(&str, NameRefusal)] = &[
            ("../evil.exe", NameRefusal::ParentStep),
            ("a/../../evil.exe", NameRefusal::ParentStep),
            (r"a\..\..\evil.exe", NameRefusal::ParentStep),
            ("/etc/passwd", NameRefusal::Absolute),
            (r"\Windows\System32\evil.dll", NameRefusal::Absolute),
            (r"\\server\share\evil.exe", NameRefusal::Absolute),
            (r"\\?\C:\evil.exe", NameRefusal::Absolute),
            ("C:/Users/Public/evil.exe", NameRefusal::DriveLetter),
            (r"c:evil.exe", NameRefusal::DriveLetter),
            ("notes.txt:hidden.exe", NameRefusal::Stream),
            ("dir/file.txt:$DATA", NameRefusal::Stream),
            ("evil.exe.", NameRefusal::TrailingDotOrSpace),
            ("folder /evil.exe", NameRefusal::TrailingDotOrSpace),
            ("...", NameRefusal::TrailingDotOrSpace),
            (
                "readme\n    file : x.zip->a.txt",
                NameRefusal::ControlCharacter,
            ),
            ("a\u{0}b", NameRefusal::ControlCharacter),
            ("what?.txt", NameRefusal::Forbidden('?')),
            ("a|b", NameRefusal::Forbidden('|')),
            ("CON", NameRefusal::Device("CON".to_owned())),
            ("docs/nul.txt", NameRefusal::Device("nul.txt".to_owned())),
            ("LPT1 .log", NameRefusal::Device("LPT1 .log".to_owned())),
            ("", NameRefusal::Empty),
            ("//", NameRefusal::Absolute),
            ("./", NameRefusal::Empty),
        ];
        for (name, expected) in cases {
            assert_eq!(
                safe_relative(name).as_ref(),
                Err(expected),
                "{name:?} was not refused for the right reason"
            );
        }
        assert_eq!(safe_relative(&"a".repeat(256)), Err(NameRefusal::TooLong));
    }

    #[test]
    fn an_ordinary_member_keeps_its_folders() {
        assert_eq!(
            safe_relative("tools/eicar.com").unwrap(),
            vec!["tools".to_owned(), "eicar.com".to_owned()]
        );
        assert_eq!(
            safe_relative(r"docs\guide\read me.pdf").unwrap(),
            vec![
                "docs".to_owned(),
                "guide".to_owned(),
                "read me.pdf".to_owned()
            ]
        );
        assert_eq!(safe_relative("folder/").unwrap(), vec!["folder".to_owned()]);
        assert_eq!(
            safe_relative("./a//b.txt").unwrap(),
            vec!["a".to_owned(), "b.txt".to_owned()]
        );
        // Dots inside a name are not steps, and device names only count whole.
        assert!(safe_relative("..config/file..txt").is_ok());
        assert!(safe_relative("console.log").is_ok());
        assert!(safe_relative("com10.txt").is_ok());
        // Every refusal reads as a sentence.
        assert!(NameRefusal::ParentStep.sentence().ends_with('.'));
    }

    #[test]
    fn the_folder_for_clean_parts_never_reuses_an_existing_name() {
        let taken = ["Photos (checked by KAM)", "Photos (checked by KAM) (2)"];
        assert_eq!(
            extraction_folder_name("Photos.zip", |name| taken.contains(&name)),
            "Photos (checked by KAM) (3)"
        );
        assert_eq!(
            extraction_folder_name("x.ZIP", |_| false),
            "x (checked by KAM)"
        );
        // A hostile archive name cannot become a path.
        assert_eq!(
            extraction_folder_name("..\\..\\evil.zip", |_| false),
            ".._.._evil (checked by KAM)"
        );
        assert_eq!(
            extraction_folder_name("...zip", |_| false),
            "archive (checked by KAM)"
        );
        assert_eq!(
            extraction_folder_name("con.zip", |_| false),
            "archive (checked by KAM)"
        );
    }

    // --- the quarantine fence -------------------------------------------

    /// A throwaway profile with a Downloads folder, and things around it that
    /// look like it but are not it.
    struct Scratch {
        root: PathBuf,
        downloads: PathBuf,
    }

    impl Scratch {
        fn new(tag: &str) -> Self {
            let root = std::env::temp_dir()
                .join(format!("kam-downloads-fence-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            let downloads = root.join("Downloads");
            std::fs::create_dir_all(downloads.join("nested")).unwrap();
            std::fs::create_dir_all(root.join("Downloads2")).unwrap();
            std::fs::create_dir_all(root.join("Documents")).unwrap();
            std::fs::write(downloads.join("setup.exe"), b"MZ").unwrap();
            std::fs::write(downloads.join("nested").join("inner.txt"), b"x").unwrap();
            std::fs::write(root.join("Downloads2").join("lookalike.exe"), b"MZ").unwrap();
            std::fs::write(root.join("Documents").join("taxes.pdf"), b"%PDF").unwrap();
            Self { root, downloads }
        }

        fn downloads(&self) -> String {
            self.downloads.to_string_lossy().into_owned()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn a_file_in_downloads_is_inside_the_fence() {
        let scratch = Scratch::new("inside");
        for file in [
            scratch.downloads.join("setup.exe"),
            scratch.downloads.join("nested").join("inner.txt"),
        ] {
            let real = check_inside(&file.to_string_lossy(), &scratch.downloads())
                .unwrap_or_else(|refusal| panic!("{} was refused: {refusal}", file.display()));
            assert!(
                !real.to_string_lossy().starts_with(r"\\?\"),
                "{}",
                real.display()
            );
        }
    }

    #[test]
    fn anything_outside_downloads_is_refused_however_it_is_spelled() {
        let scratch = Scratch::new("outside");
        let downloads = scratch.downloads();
        let outside = [
            // A sibling whose name begins the same way: a string prefix would
            // have let this through.
            scratch
                .root
                .join("Downloads2")
                .join("lookalike.exe")
                .to_string_lossy()
                .into_owned(),
            scratch
                .root
                .join("Documents")
                .join("taxes.pdf")
                .to_string_lossy()
                .into_owned(),
            // Climbing out with `..`, which is refused before it is resolved.
            format!(r"{downloads}\..\Documents\taxes.pdf"),
            format!("{downloads}/../Documents/taxes.pdf"),
            // The folder itself, and a folder inside it: not downloaded files.
            downloads.clone(),
            format!(r"{downloads}\nested"),
            // Something that is not there at all.
            format!(r"{downloads}\never-existed.exe"),
            // Windows' own files.
            r"C:\Windows\System32\kernel32.dll".to_owned(),
        ];
        for path in outside {
            assert!(
                check_inside(&path, &downloads).is_err(),
                "{path} was let through the fence"
            );
        }
        // Nothing was touched by being refused.
        assert!(scratch.root.join("Documents").join("taxes.pdf").exists());
    }

    /// A junction inside Downloads that leads somewhere else is somewhere else.
    ///
    /// The fence judges where a path really leads, so this is the case that
    /// shows it does. Junctions need no special rights to create, which is
    /// exactly why they are the realistic way to try this.
    #[test]
    fn a_junction_inside_downloads_that_leads_out_is_refused() {
        let scratch = Scratch::new("junction");
        let link = scratch.downloads.join("shortcut-to-documents");
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(scratch.root.join("Documents"))
            .output();
        if !made.is_ok_and(|output| output.status.success()) {
            // Not a failure of the fence; the premise could not be set up.
            return;
        }
        let through = link.join("taxes.pdf");
        let refusal = check_inside(&through.to_string_lossy(), &scratch.downloads())
            .expect_err("a file reached through a junction out of Downloads was let through");
        assert!(
            refusal.contains("not inside your Downloads folder"),
            "{refusal}"
        );
        let _ = std::fs::remove_dir(&link);
    }

    #[test]
    fn a_downloads_folder_that_is_not_there_refuses_everything() {
        let scratch = Scratch::new("missing-root");
        let file = scratch.downloads.join("setup.exe");
        let missing = scratch
            .root
            .join("NoSuchDownloads")
            .to_string_lossy()
            .into_owned();
        assert!(check_inside(&file.to_string_lossy(), &missing).is_err());
    }

    #[test]
    fn within_compares_whole_components() {
        assert!(lies_within(
            Path::new(r"C:\Users\me\Downloads\a.txt"),
            Path::new(r"C:\Users\me\Downloads")
        ));
        assert!(lies_within(
            Path::new(r"\\?\C:\Users\me\Downloads\x\a.txt"),
            Path::new(r"c:\users\me\downloads")
        ));
        assert!(!lies_within(
            Path::new(r"C:\Users\me\Downloads2\a.txt"),
            Path::new(r"C:\Users\me\Downloads")
        ));
        assert!(!lies_within(
            Path::new(r"C:\Users\me\Downloads"),
            Path::new(r"C:\Users\me\Downloads")
        ));
        assert!(!lies_within(
            Path::new(r"C:\Users\me"),
            Path::new(r"C:\Users\me\Downloads")
        ));
    }

    #[test]
    fn the_downloads_folder_of_the_person_running_this_is_an_absolute_path() {
        let folder = folder_for(&UserContext::current());
        assert!(is_absolute_text(&folder), "{folder}");
        assert!(!folder.contains('%'), "{folder} was not expanded");
    }

    #[test]
    fn a_profile_with_nothing_recorded_gets_the_windows_default() {
        // A SID that is certainly not loaded, so its hive cannot be opened and
        // the default is what comes back.
        let user = UserContext::new(Some("S-1-5-21-0-0-0-31337".to_owned()), r"C:\Users\nobody");
        assert_eq!(folder_for(&user), r"C:\Users\nobody\Downloads");
    }
}
