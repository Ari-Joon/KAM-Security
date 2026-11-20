//! What winget, Windows' own package tool, says about newer versions of the
//! apps on this PC.
//!
//! # Why the window and not the service
//!
//! winget belongs to the signed-in account. It is reached through an alias in
//! the person's own Local AppData, keeps its catalogue there, and knows the
//! apps installed for them. The service is LocalSystem, for whom none of that
//! exists. So this runs here, as the person, by its full path, and only when
//! they press the button: it fetches the catalogue from Microsoft over the
//! network and takes seconds.
//!
//! # Only the community source
//!
//! `--source winget`. The Store's source asks for its agreement to be accepted
//! on first use, and accepting an agreement is the person's decision, never
//! this program's. `--disable-interactivity` so nothing can sit waiting for an
//! answer nobody will see.
//!
//! # Reading the answer
//!
//! winget has no structured output for this: on the machine this was written
//! for, neither `winget upgrade --help` nor `winget list --help` mentions JSON
//! or an output format. The answer is a fixed-width table, and it is read by
//! position, never by splitting on spaces: names hold spaces ("7-Zip 25.00
//! (x64)") and so can a version ("< 3.14.7"). The columns start where the
//! header's words start, counted in the screen columns winget pads by (a
//! Chinese or Korean character takes two), and a header word is only taken as
//! the start of a column if every row has a space just before it, because a
//! translated header can hold a space of its own.
//!
//! Nothing here depends on the English words. The header is translated on
//! other Windows languages and so are the sentences around the table; what
//! does not change is the order of the columns (name, id, installed version,
//! version on offer) and the number winget writes in front of its closing
//! sentence, which is how many rows it listed. The table is checked against
//! that number, and an answer that disagrees with itself is said not to have
//! been read. The one line found by its text is the count of apps whose
//! versions winget could not compare, which is the line naming the option
//! `--include-unknown`: an option's name is not translated.

use std::os::windows::process::CommandExt as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::Serialize;
use windows::Win32::System::Threading::CREATE_NO_WINDOW;

/// How long winget may take before it is stopped. It took eight seconds on
/// the machine this was written for; a catalogue download on a slow line
/// takes longer, and a winget still silent after this is not going to answer.
const TIMEOUT: Duration = Duration::from_secs(120);

/// How often the wait looks at whether winget has finished.
const POLL: Duration = Duration::from_millis(100);

/// The most of winget's output that is kept. Its table for a few hundred apps
/// is tens of kilobytes; anything past this is not a table this reads.
const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

/// How much of what winget said is carried back to be shown when its answer
/// could not be used, in lines.
const SAID_LINES: usize = 40;

/// One app winget says has a newer version, as winget gave it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Newer {
    /// As winget shows it, which may be cut short and end in "…".
    pub name: String,
    pub id: String,
    /// The version installed, as winget read it. Can be a range such as
    /// "< 3.14.7" when winget only knows it is older than that.
    pub installed: String,
    /// The version winget's catalogue offers.
    pub available: String,
}

/// What asking winget came to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Answer {
    /// There is no winget for this account to ask.
    NotInstalled { looked_at: String },
    /// winget did not answer, or answered with an error. `said` is what it
    /// wrote, with its exit code.
    NotAnswered { said: String },
    /// winget answered, and not with a table this recognises. `why` says what
    /// was wrong with it and `said` is what it wrote.
    NotRecognised { why: String, said: String },
    /// The table, read and checked against winget's own count.
    Listed {
        apps: Vec<Newer>,
        /// How many apps winget said it could not compare, when it said so.
        not_compared: Option<u64>,
        /// Anything else winget wrote around the table, as it wrote it.
        also_said: Vec<String>,
    },
}

/// One press of the button.
#[derive(Debug, Clone, Serialize)]
pub struct Asked {
    pub answer: Answer,
    /// When winget was asked, so the panel can date what it shows.
    pub asked_at: String,
    /// How long winget took, in milliseconds.
    pub took_ms: u64,
}

/// Where winget is for this account: the alias Windows puts in the person's
/// own Local AppData. Named in full, so no search can find something else of
/// the same name first (the lesson recorded above `powershell` in the
/// scanner's `hardening` module).
fn alias() -> PathBuf {
    PathBuf::from(kam_core::UserContext::current().local_app_data())
        .join(r"Microsoft\WindowsApps\winget.exe")
}

/// Ask winget which installed apps have a newer version. Blocks for as long
/// as winget takes, so it must be called off the window's thread.
pub fn ask() -> Asked {
    let asked_at = kam_core::clock::now_utc_iso();
    let started = Instant::now();
    let answer = run(&alias());
    Asked {
        answer,
        asked_at,
        took_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

fn run(winget: &std::path::Path) -> Answer {
    // The alias is a link of a kind only process creation follows, so it is
    // looked at itself rather than through: asking whether it "exists" by
    // following it answers no for a winget that is there.
    if std::fs::symlink_metadata(winget).is_err() {
        return Answer::NotInstalled {
            looked_at: winget.display().to_string(),
        };
    }

    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    let spawned = std::process::Command::new(winget)
        .args(["upgrade", "--source", "winget", "--disable-interactivity"])
        .current_dir(PathBuf::from(root).join("System32"))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        // The window has no console, and without this one would flash up
        // on the person's screen for as long as winget runs.
        .creation_flags(CREATE_NO_WINDOW.0)
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Answer::NotInstalled {
                looked_at: winget.display().to_string(),
            };
        }
        Err(error) => {
            return Answer::NotAnswered {
                said: format!("winget could not be started: {error}"),
            };
        }
    };

    let output = drain(child.stdout.take());
    let error_output = drain(child.stderr.take());

    let started = Instant::now();
    let finished = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status.code()),
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                break Err(format!("winget could not be waited on: {error}"));
            }
        }
        if started.elapsed() > TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            break Err(format!(
                "winget had not finished after {} seconds and was stopped",
                TIMEOUT.as_secs()
            ));
        }
        std::thread::sleep(POLL);
    };

    let output = text_of(output);
    let error_output = text_of(error_output);

    match finished {
        Ok(code) => read(&output, &error_output, code),
        Err(stopped) => {
            let said = said(&output, &error_output);
            Answer::NotAnswered {
                said: if said.is_empty() {
                    stopped
                } else {
                    format!("{stopped}. Before that it said:\n{said}")
                },
            }
        }
    }
}

/// Read a pipe on its own thread for as long as winget runs. A pipe nobody
/// reads fills up and stalls winget until the timeout.
fn drain<Pipe: std::io::Read + Send + 'static>(
    pipe: Option<Pipe>,
) -> Option<std::thread::JoinHandle<Vec<u8>>> {
    pipe.map(|mut pipe| {
        std::thread::spawn(move || {
            let mut kept = Vec::new();
            let mut chunk = [0_u8; 8192];
            loop {
                match pipe.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        if kept.len() + read <= MAX_OUTPUT_BYTES {
                            kept.extend_from_slice(&chunk[..read]);
                        }
                    }
                }
            }
            kept
        })
    })
}

/// What a drained pipe held. winget writes UTF-8.
fn text_of(reader: Option<std::thread::JoinHandle<Vec<u8>>>) -> String {
    reader
        .and_then(|reader| reader.join().ok())
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default()
}

/// Read what winget wrote, given how it ended. The whole of the reading, kept
/// apart from running winget so it can be tested on saved answers.
fn read(output: &str, error_output: &str, code: Option<i32>) -> Answer {
    match code {
        Some(0) => {}
        Some(code) => {
            let said = said(output, error_output);
            return Answer::NotAnswered {
                said: if said.is_empty() {
                    format!(
                        "winget ended with exit code {} and said nothing",
                        exit_text(code)
                    )
                } else {
                    format!("{said}\n(exit code {})", exit_text(code))
                },
            };
        }
        None => {
            return Answer::NotAnswered {
                said: format!(
                    "winget ended without an exit code. {}",
                    said(output, error_output)
                ),
            };
        }
    }

    let lines: Vec<String> = screen_lines(output)
        .into_iter()
        .filter(|line| !is_progress(line))
        .collect();
    match table(&lines) {
        Ok(read) => Answer::Listed {
            apps: read.apps,
            not_compared: read.not_compared,
            also_said: read.also_said,
        },
        Err(why) => Answer::NotRecognised {
            why,
            said: said(output, error_output),
        },
    }
}

/// What a table came to.
struct Table {
    apps: Vec<Newer>,
    not_compared: Option<u64>,
    also_said: Vec<String>,
}

/// Find the table, read it by position, and check it against winget's count.
fn table(lines: &[String]) -> Result<Table, String> {
    // The rule under the header: a line of dashes as wide as the table.
    let rule = lines
        .iter()
        .enumerate()
        .skip(1)
        .find(|(index, line)| {
            line.len() >= 3 && line.chars().all(|c| c == '-') && !lines[index - 1].is_empty()
        })
        .map(|(index, _)| index)
        .ok_or_else(|| "it holds no table".to_owned())?;
    let header = &lines[rule - 1];
    let headed = word_starts(header);
    if headed.len() < 4 {
        return Err(format!(
            "its table has {} {} where four were expected (name, id, the version installed and \
             the version on offer)",
            headed.len(),
            if headed.len() == 1 {
                "column"
            } else {
                "columns"
            }
        ));
    }

    // The rows run from under the rule to winget's count, which is the first
    // line that does not reach the fourth column: every row has a version on
    // offer there, and winget's closing sentence is shorter than a row.
    let cut_short =
        || "it ended before its count of the rows, so it may have been cut short".to_owned();
    let body = &lines[rule + 1..];
    let reaching = |line: &String| width_of(line) > headed[3];
    let ended = body
        .iter()
        .position(|line| !reaching(line))
        .ok_or_else(cut_short)?;
    let rows = &body[..ended];
    let after = &body[ended..];
    let counted_at = after
        .iter()
        .position(|line| !line.is_empty())
        .ok_or_else(cut_short)?;
    let count_line = &after[counted_at];
    let counted = leading_number(count_line).ok_or_else(|| {
        format!(
            "the line after its table does not begin with winget's count of the rows: \"{}\"",
            count_line.trim()
        )
    })?;
    if counted != rows.len() as u64 {
        return Err(format!(
            "winget's own count, {counted}, does not match the {} {} in its table",
            rows.len(),
            if rows.len() == 1 { "row" } else { "rows" }
        ));
    }

    // A header word is the start of a column only if every row has a space
    // just before it. A translated header can hold a space of its own
    // ("Nom du paquet"), and a row's text runs straight across that.
    let starts: Vec<usize> = headed
        .iter()
        .copied()
        .enumerate()
        .filter(|&(index, column)| {
            index == 0
                || rows
                    .iter()
                    .all(|row| column_char(row, column - 1).is_none_or(|c| c == ' '))
        })
        .map(|(_, column)| column)
        .collect();
    if starts.len() < 4 {
        return Err(
            "its rows do not line up with the columns of its header, so they cannot be read by \
             position"
                .to_owned(),
        );
    }

    let mut apps = Vec::with_capacity(rows.len());
    for row in rows {
        let field = |index: usize| field(row, starts[index], starts.get(index + 1).copied());
        let newer = Newer {
            name: field(0),
            id: field(1),
            installed: field(2),
            available: field(3),
        };
        if newer.name.is_empty()
            || newer.id.is_empty()
            || newer.installed.is_empty()
            || newer.available.is_empty()
        {
            return Err(format!(
                "a row of its table has an empty column: \"{}\"",
                row.trim()
            ));
        }
        apps.push(newer);
    }

    let mut not_compared = None;
    let mut also_said: Vec<String> = lines[..rule - 1]
        .iter()
        .filter(|line| !line.is_empty())
        .cloned()
        .collect();
    for line in &after[counted_at + 1..] {
        if line.is_empty() {
            continue;
        }
        match leading_number(line) {
            Some(number) if not_compared.is_none() && line.contains("--include-unknown") => {
                not_compared = Some(number);
            }
            _ => also_said.push(line.clone()),
        }
    }
    also_said.truncate(SAID_LINES);

    Ok(Table {
        apps,
        not_compared,
        also_said,
    })
}

/// The lines as a screen would end up showing them.
///
/// winget draws a spinner and a progress bar while it fetches its catalogue,
/// by going back to the start of the line and writing over it. Only what is
/// left after the last return is what was shown, and colour or cursor codes
/// are no part of the text, except that one moving the cursor back along the
/// line is a return by another name.
fn screen_lines(text: &str) -> Vec<String> {
    text.split('\n')
        .map(|line| {
            let line = line.trim_end_matches('\r');
            let shown = line.rsplit('\r').next().unwrap_or(line);
            let mut kept = String::with_capacity(shown.len());
            let mut chars = shown.chars().peekable();
            while let Some(c) = chars.next() {
                match c {
                    '\u{1b}' => {
                        if chars.peek() == Some(&'[') {
                            chars.next();
                            for code in chars.by_ref() {
                                if ('@'..='~').contains(&code) {
                                    if code == 'G' {
                                        kept.clear();
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    '\u{8}' => {
                        kept.pop();
                    }
                    c if c.is_control() => {}
                    c => kept.push(c),
                }
            }
            kept.trim_end().to_owned()
        })
        .collect()
}

/// A spinner or progress bar left on a line of its own.
fn is_progress(line: &str) -> bool {
    let trimmed = line.trim();
    matches!(trimmed, "-" | "\\" | "|" | "/")
        || trimmed
            .chars()
            .any(|c| matches!(c, '\u{2588}' | '\u{2592}' | '\u{2593}' | '\u{2591}'))
}

/// What winget wrote, cleaned of its progress drawing, for a person to read.
fn said(output: &str, error_output: &str) -> String {
    let mut lines: Vec<String> = screen_lines(output)
        .into_iter()
        .chain(screen_lines(error_output))
        .filter(|line| !line.is_empty() && !is_progress(line))
        .collect();
    if lines.len() > SAID_LINES {
        let left_out = lines.len() - SAID_LINES;
        lines.truncate(SAID_LINES);
        lines.push(format!("(and {left_out} more lines)"));
    }
    lines.join("\n")
}

/// An exit code as winget's documentation lists it: its errors are written as
/// eight hexadecimal digits, such as 0x8A150014.
fn exit_text(code: i32) -> String {
    if code < 0 {
        format!("0x{:08X}", code as u32)
    } else {
        code.to_string()
    }
}

/// The number a line begins with, when it begins with one.
fn leading_number(line: &str) -> Option<u64> {
    let digits: String = line
        .trim_start()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// How many screen columns a character takes, as winget counts when it pads.
///
/// Two for the wide characters of Chinese, Japanese and Korean and the
/// full-width forms, none for a mark that combines with the character before
/// it, one for everything else. Approximate at the edges, and safe there: a
/// row that does not line up is caught by the check on the spaces before each
/// column, and the answer is then said not to have been read.
fn char_width(c: char) -> usize {
    match u32::from(c) {
        0x0300..=0x036F
        | 0x1AB0..=0x1AFF
        | 0x1DC0..=0x1DFF
        | 0x200B..=0x200F
        | 0x20D0..=0x20FF
        | 0xFE00..=0xFE0F
        | 0xFE20..=0xFE2F => 0,
        0x1100..=0x115F
        | 0x2E80..=0x303E
        | 0x3041..=0x33FF
        | 0x3400..=0x4DBF
        | 0x4E00..=0x9FFF
        | 0xA000..=0xA4CF
        | 0xAC00..=0xD7A3
        | 0xF900..=0xFAFF
        | 0xFE30..=0xFE4F
        | 0xFF00..=0xFF60
        | 0xFFE0..=0xFFE6
        | 0x1F300..=0x1F64F
        | 0x1F900..=0x1F9FF
        | 0x20000..=0x2FFFD
        | 0x30000..=0x3FFFD => 2,
        _ => 1,
    }
}

/// Each character of a line with the screen column it starts at.
fn columns(line: &str) -> impl Iterator<Item = (usize, char)> + '_ {
    line.chars().scan(0_usize, |column, c| {
        let at = *column;
        *column += char_width(c);
        Some((at, c))
    })
}

fn width_of(line: &str) -> usize {
    line.chars().map(char_width).sum()
}

/// The screen columns at which the words of a line start.
fn word_starts(line: &str) -> Vec<usize> {
    let mut starts = Vec::new();
    let mut after_space = true;
    for (column, c) in columns(line) {
        if c == ' ' {
            after_space = true;
        } else {
            if after_space {
                starts.push(column);
            }
            after_space = false;
        }
    }
    starts
}

/// The character covering one screen column, if the line reaches that far.
fn column_char(line: &str, wanted: usize) -> Option<char> {
    columns(line)
        .find(|&(column, c)| column <= wanted && wanted < column + char_width(c).max(1))
        .map(|(_, c)| c)
}

/// The text between two screen columns, trimmed. `end` of `None` is the rest
/// of the line.
fn field(line: &str, start: usize, end: Option<usize>) -> String {
    columns(line)
        .filter(|&(column, _)| column >= start && end.is_none_or(|end| column < end))
        .map(|(_, c)| c)
        .collect::<String>()
        .trim()
        .to_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Answers as winget writes them, in the shape the November review saw
    /// on the machine this was written for: the header, a rule of dashes as
    /// wide as the table, the rows, winget's count, and the line about the
    /// apps it could not compare. Made up, not copied: the names and versions
    /// are what such a table holds.
    const ENGLISH: &str = "\
Name                             Id                      Version          Available
-----------------------------------------------------------------------------------
7-Zip 25.00 (x64)                7zip.7zip               25.00            26.06
Git                              Git.Git                 2.51.1           2.56.0.4
Python Launcher                  Python.Launcher         < 3.14.7         3.15.2
3 upgrades available.
3 package(s) have version numbers that cannot be determined. Use --include-unknown to see all results.
";

    fn listed(answer: Answer) -> (Vec<Newer>, Option<u64>, Vec<String>) {
        match answer {
            Answer::Listed {
                apps,
                not_compared,
                also_said,
            } => (apps, not_compared, also_said),
            other => panic!("expected a list, got {other:?}"),
        }
    }

    fn not_recognised(answer: Answer) -> String {
        match answer {
            Answer::NotRecognised { why, .. } => why,
            other => panic!("expected an answer that was not recognised, got {other:?}"),
        }
    }

    fn newer(name: &str, id: &str, installed: &str, available: &str) -> Newer {
        Newer {
            name: name.to_owned(),
            id: id.to_owned(),
            installed: installed.to_owned(),
            available: available.to_owned(),
        }
    }

    #[test]
    fn a_table_is_read_by_position_with_spaces_inside_names_and_versions() {
        let (apps, not_compared, also_said) = listed(read(ENGLISH, "", Some(0)));
        assert_eq!(
            apps,
            vec![
                newer("7-Zip 25.00 (x64)", "7zip.7zip", "25.00", "26.06"),
                newer("Git", "Git.Git", "2.51.1", "2.56.0.4"),
                // Split on spaces, this is "<" installed and "3.14.7" on offer.
                newer("Python Launcher", "Python.Launcher", "< 3.14.7", "3.15.2"),
            ]
        );
        assert_eq!(not_compared, Some(3));
        assert!(also_said.is_empty(), "{also_said:?}");
    }

    /// The same table under a German header and closing sentence. Nothing
    /// is read by its words, so nothing changes.
    #[test]
    fn a_header_in_another_language_is_read_the_same_way() {
        let german = "\
Name                             ID                      Version          Verfügbar
-----------------------------------------------------------------------------------
7-Zip 25.00 (x64)                7zip.7zip               25.00            26.06
Git                              Git.Git                 2.51.1           2.56.0.4
2 Aktualisierungen verfügbar.
";
        let (apps, not_compared, _) = listed(read(german, "", Some(0)));
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[1], newer("Git", "Git.Git", "2.51.1", "2.56.0.4"));
        assert_eq!(not_compared, None);
    }

    /// A translated header word with a space in it is one column, not two,
    /// because the rows' text runs across that space.
    #[test]
    fn a_space_inside_a_translated_header_word_does_not_start_a_column() {
        let french = "\
Nom du paquet                    ID                         Version          Disponible
---------------------------------------------------------------------------------------
7-Zip 25.00 (x64)                7zip.7zip                  25.00            26.06
Microsoft Visual Studio Code     Microsoft.VisualStudioCode 1.105.1          1.106.0
2 mises à niveau disponibles.
";
        let (apps, _, _) = listed(read(french, "", Some(0)));
        assert_eq!(
            apps,
            vec![
                newer("7-Zip 25.00 (x64)", "7zip.7zip", "25.00", "26.06"),
                newer(
                    "Microsoft Visual Studio Code",
                    "Microsoft.VisualStudioCode",
                    "1.105.1",
                    "1.106.0"
                ),
            ]
        );
    }

    /// Rows whose text crosses where the header says a column starts cannot
    /// be read by position, and are not guessed at.
    #[test]
    fn rows_that_do_not_line_up_with_the_header_are_not_read() {
        // The second row's id runs past the start of the version column, as
        // no table winget pads would.
        let crossing = "\
Name                             Id                      Version          Available
-----------------------------------------------------------------------------------
7-Zip 25.00 (x64)                7zip.7zip               25.00            26.06
Microsoft Visual Studio Code     Microsoft.VisualStudioCode 1.105.1       1.106.0
2 upgrades available.
";
        let why = not_recognised(read(crossing, "", Some(0)));
        assert!(why.contains("do not line up"), "{why}");
    }

    /// Wide characters take two screen columns, and winget pads by screen
    /// columns, so a row holding them is read by those and not by count of
    /// characters.
    ///
    /// The padding is written out by hand from each word's width, two
    /// columns for every Hangul syllable, rather than made by the code under
    /// test: a table padded by the same reckoning that reads it would agree
    /// with itself however wrong that reckoning was.
    #[test]
    fn wide_characters_are_counted_as_the_two_columns_winget_pads_them_to() {
        let gap = |spaces: usize| " ".repeat(spaces);
        // Columns 22, 21 and 10 wide, then the last: the id column starts at
        // screen column 23, the version at 45, the version on offer at 56.
        let korean = [
            format!("이름{}ID{}버전{}사용 가능", gap(19), gap(20), gap(7)),
            "-".repeat(65),
            format!(
                "카카오톡{}Kakao.KakaoTalk{}25.8.0{}25.9.2",
                gap(15),
                gap(7),
                gap(5)
            ),
            format!("Git{}Git.Git{}2.51.1{}2.56.0.4", gap(20), gap(15), gap(5)),
            "2 업그레이드를 사용할 수 있습니다.".to_owned(),
        ]
        .join("\n");
        let (apps, _, _) = listed(read(&korean, "", Some(0)));
        assert_eq!(
            apps,
            vec![
                newer("카카오톡", "Kakao.KakaoTalk", "25.8.0", "25.9.2"),
                // The space in the header's last word is not a column: the
                // version on offer runs across it.
                newer("Git", "Git.Git", "2.51.1", "2.56.0.4"),
            ]
        );
    }

    #[test]
    fn a_table_that_stops_before_its_count_is_not_read() {
        let cut: String = ENGLISH.lines().take(4).collect::<Vec<_>>().join("\n");
        let why = not_recognised(read(&cut, "", Some(0)));
        assert!(why.contains("cut short"), "{why}");

        // Cut in the middle of a row: the row does not reach the column of
        // the version on offer, and the line where the count should be is
        // not a number.
        let mid_row = &ENGLISH[..ENGLISH.find("2.51.1").unwrap()];
        let why = not_recognised(read(mid_row, "", Some(0)));
        assert!(why.contains("count"), "{why}");
    }

    #[test]
    fn a_count_that_does_not_match_the_rows_is_said_not_to_have_been_read() {
        let disagreeing = ENGLISH.replace("3 upgrades available.", "34 upgrades available.");
        let why = not_recognised(read(&disagreeing, "", Some(0)));
        assert!(why.contains("34") && why.contains('3'), "{why}");
        assert!(why.contains("does not match"), "{why}");
    }

    /// The spinner and the progress bar winget draws while it fetches its
    /// catalogue are written over with returns, and the header is written
    /// over the last of them on the same line. What is left is the table.
    #[test]
    fn progress_drawn_before_the_table_is_left_out() {
        let drawn = format!(
            "   - \r   \\ \r   | \r\r  \u{2588}\u{2588}\u{2588}\u{2592}\u{2592}  1.2 MB / 5.9 MB\r                 \r{ENGLISH}"
        );
        let (apps, _, also_said) = listed(read(&drawn, "", Some(0)));
        assert_eq!(apps.len(), 3);
        assert!(
            also_said.is_empty(),
            "progress was kept as text: {also_said:?}"
        );

        // A cursor sent back along the line does the same as a return.
        let moved =
            format!("  \u{2588}\u{2588}\u{2592}  0.4 MB / 5.9 MB\u{1b}[1G\u{1b}[2K{ENGLISH}");
        let (apps, _, _) = listed(read(&moved, "", Some(0)));
        assert_eq!(apps.len(), 3);

        // A bar left on a line of its own is not something winget said.
        let left = format!("  \u{2588}\u{2588}\u{2588}\u{2588}  5.9 MB / 5.9 MB\n{ENGLISH}");
        let (_, _, also_said) = listed(read(&left, "", Some(0)));
        assert!(also_said.is_empty(), "{also_said:?}");
    }

    /// Lines winget writes around the table are kept as it wrote them, and
    /// the count of what it could not compare is taken only from the line
    /// that names the option for it.
    #[test]
    fn other_lines_are_kept_as_winget_wrote_them() {
        let pinned = ENGLISH.replace(
            "3 package(s) have version numbers",
            "1 package(s) have pins that prevent upgrade. Use the 'winget pin' command to view and edit pins.\n3 package(s) have version numbers",
        );
        let warned = format!("Failed in attempting to update the source: winget\n{pinned}");
        let (apps, not_compared, also_said) = listed(read(&warned, "", Some(0)));
        assert_eq!(apps.len(), 3);
        assert_eq!(not_compared, Some(3));
        assert_eq!(
            also_said,
            vec![
                "Failed in attempting to update the source: winget".to_owned(),
                "1 package(s) have pins that prevent upgrade. Use the 'winget pin' command to view and edit pins."
                    .to_owned(),
            ]
        );
    }

    /// A Source column, which winget adds when more than one source is
    /// asked, comes after the four that are read.
    #[test]
    fn a_column_after_the_fourth_is_left_alone() {
        let sourced = "\
Name                Id              Version     Available   Source
------------------------------------------------------------------
Git                 Git.Git         2.51.1      2.56.0.4    winget
1 upgrades available.
";
        let (apps, _, _) = listed(read(sourced, "", Some(0)));
        assert_eq!(apps, vec![newer("Git", "Git.Git", "2.51.1", "2.56.0.4")]);
    }

    /// A name cut short by winget is shown as winget cut it.
    #[test]
    fn a_name_winget_cut_short_is_kept_as_it_is() {
        let cut = "\
Name                Id              Version     Available
---------------------------------------------------------
Microsoft Visual C… Microsoft.VCRe… 14.40.338   14.44.352
1 upgrades available.
";
        let (apps, _, _) = listed(read(cut, "", Some(0)));
        assert_eq!(
            apps,
            vec![newer(
                "Microsoft Visual C…",
                "Microsoft.VCRe…",
                "14.40.338",
                "14.44.352"
            )]
        );
    }

    #[test]
    fn an_answer_with_no_table_is_not_recognised() {
        let why = not_recognised(read(
            "No installed package found matching input criteria.\n",
            "",
            Some(0),
        ));
        assert!(why.contains("no table"), "{why}");

        let narrow = "\
Name     Id
-----------
Git      Git.Git
1 upgrades available.
";
        let why = not_recognised(read(narrow, "", Some(0)));
        assert!(why.contains("four were expected"), "{why}");
    }

    /// An error is said with what winget said and its exit code, never read
    /// as a table even when one is there.
    #[test]
    fn an_exit_code_other_than_zero_is_an_answer_that_was_not_given() {
        match read(ENGLISH, "", Some(-1_978_335_212)) {
            Answer::NotAnswered { said } => {
                assert!(said.contains("0x8A150014"), "{said}");
                assert!(
                    said.contains("7-Zip"),
                    "what winget said was not kept: {said}"
                );
            }
            other => panic!("expected no answer, got {other:?}"),
        }
        match read("", "", Some(1)) {
            Answer::NotAnswered { said } => assert!(said.contains("said nothing"), "{said}"),
            other => panic!("expected no answer, got {other:?}"),
        }
        assert!(matches!(
            read(ENGLISH, "", None),
            Answer::NotAnswered { .. }
        ));
    }

    #[test]
    fn exit_codes_are_written_as_winget_documents_them() {
        assert_eq!(exit_text(-1_978_335_212), "0x8A150014");
        assert_eq!(exit_text(1), "1");
    }

    #[test]
    fn an_account_with_no_winget_is_told_so_and_nothing_is_started() {
        let nowhere = std::env::temp_dir()
            .join(format!("kam-winget-test-{}", std::process::id()))
            .join("winget.exe");
        assert_eq!(
            run(&nowhere),
            Answer::NotInstalled {
                looked_at: nowhere.display().to_string()
            }
        );
    }

    /// What is carried back to be shown is cut to a length a panel can hold.
    #[test]
    fn what_winget_said_is_kept_to_a_readable_length() {
        let long: String = (0..100).map(|line| format!("line {line}\n")).collect();
        let kept = said(&long, "");
        assert_eq!(kept.lines().count(), SAID_LINES + 1);
        assert!(kept.ends_with("(and 60 more lines)"), "{kept}");
    }
}
