//! Asking VirusTotal what seventy antivirus engines think of one file.
//!
//! # This sends a hash, never a file
//!
//! The lookup transmits the file's SHA-256 and nothing else. The file itself
//! never leaves the machine, is never uploaded, and there is no code here that
//! could upload it. That distinction is the whole reason this feature is
//! acceptable to ship: uploading someone's file to a third party publishes its
//! contents permanently and irrevocably to anyone with a VirusTotal account,
//! and people keep documents, keys and licensed software on their machines.
//!
//! A hash is not nothing, and the interface says so: it tells VirusTotal that
//! somebody holds a file with that hash. For ordinary software that is
//! uninteresting. For a file unique to one person it is a small disclosure, so
//! every lookup is a deliberate, individual action. Nothing here runs
//! automatically, in bulk, or in the background.
//!
//! # The key is the user's
//!
//! No API key ships with this product. The user supplies their own, it is
//! stored encrypted under their Windows account (see [`key`]), and without one
//! this feature simply does not appear.
//!
//! # Reading the answer honestly
//!
//! "6 of 70 engines flagged this" is the number people take as a verdict, and
//! it is not one. Detection counts in the low single figures are overwhelmingly
//! false positives — obscure engines flag installers, packers, keygens, and
//! anything written in a language whose runtime they distrust. A file nobody
//! has submitted before is not suspicious either; most files on most machines
//! are not in VirusTotal.
//!
//! So this reports the count, names the engines, and states plainly which
//! reading the evidence supports. Anything else would be dressing an ambiguous
//! number as certainty.

pub mod http;
pub mod key;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const HOST: &str = "www.virustotal.com";

/// Largest file worth hashing for a lookup.
///
/// Hashing reads every byte, and a person waiting on an interface will not
/// thank us for a two-minute pause on a game archive.
const MAX_HASH_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// What the result actually supports saying.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Standing {
    /// No engine flagged it.
    Clean,
    /// VirusTotal has never seen this file. Common and unalarming: most files
    /// on most machines have never been submitted by anyone.
    NotKnown,
    /// A handful of engines flagged it, which usually means nothing.
    Isolated,
    /// Enough engines agree that it is worth taking seriously.
    Substantial,
}

impl Standing {
    pub fn label(self) -> &'static str {
        match self {
            Self::Clean => "nothing flagged it",
            Self::NotKnown => "not known to VirusTotal",
            Self::Isolated => "a few engines flagged it",
            Self::Substantial => "many engines flagged it",
        }
    }
}

/// One engine's opinion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub engine: String,
    /// What that engine called it. Vendor naming, reproduced as given.
    pub verdict: String,
}

/// What VirusTotal knows about one file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub sha256: String,
    pub standing: Standing,
    pub malicious: u32,
    pub suspicious: u32,
    pub harmless: u32,
    pub undetected: u32,
    /// How many engines returned any answer at all.
    pub engines: u32,
    /// Only the engines that flagged it. The rest is a list of names nobody
    /// reads.
    pub detections: Vec<Detection>,
    /// VirusTotal's community score. Negative means users voted it malicious.
    pub reputation: Option<i64>,
    pub first_seen: Option<String>,
    pub last_analysed: Option<String>,
    /// The name VirusTotal most often sees this file under, which is a useful
    /// check against what it is called here.
    pub common_name: Option<String>,
    /// The page a person can open to see the full report themselves.
    pub permalink: String,
    /// What the numbers support saying, in plain words.
    pub summary: String,
}

fn text(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)?
        .as_str()
        .map(str::to_owned)
        .filter(|found| !found.is_empty())
}

/// Format a Unix timestamp as a date.
///
/// Only a date is needed, and pulling in a calendar library to render one is
/// not worth it. This is the civil-from-days algorithm, which is exact.
fn date(epoch_seconds: i64) -> String {
    let days = epoch_seconds.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

fn timestamp(value: &serde_json::Value, key: &str) -> Option<String> {
    value.get(key)?.as_i64().filter(|t| *t > 0).map(date)
}

/// Decide what the numbers support saying.
///
/// The thresholds are judgement, and they are deliberately conservative in the
/// direction of not alarming people. A single engine disagreeing with sixty
/// others is evidence about that engine.
fn interpret(malicious: u32, suspicious: u32, engines: u32) -> (Standing, String) {
    let flagged = malicious + suspicious;

    if flagged == 0 {
        return (
            Standing::Clean,
            format!("None of the {engines} engines that examined this flagged it."),
        );
    }

    if flagged <= 3 {
        return (
            Standing::Isolated,
            format!(
                "{flagged} of {engines} engines flagged this, which on its own usually means \
                 nothing. A small number of detections against a large majority is the normal \
                 signature of a false positive — installers, packers and less common software \
                 collect them routinely. Worth reading which engines, and what they called it, \
                 before drawing any conclusion."
            ),
        );
    }

    if flagged <= 10 {
        return (
            Standing::Substantial,
            format!(
                "{flagged} of {engines} engines flagged this. That is more than the usual \
                 false-positive noise and worth looking into, though it is still short of \
                 agreement — check whether the names below describe the same thing."
            ),
        );
    }

    (
        Standing::Substantial,
        format!(
            "{flagged} of {engines} engines flagged this, and that many independent engines \
             rarely agree by accident. Treat it as malicious unless you have specific reason \
             to think otherwise."
        ),
    )
}

/// Read a file's SHA-256.
///
/// VirusTotal indexes by SHA-256, so blake3 — used everywhere else in this
/// project for duplicate detection, where only self-consistency matters —
/// cannot serve here.
pub fn hash_file(path: &str) -> kam_core::Result<String> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > MAX_HASH_BYTES {
        return Err(kam_core::Error::Refused(format!(
            "{} is too large to hash for a lookup",
            path
        )));
    }

    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    // Streamed rather than read whole: these are executables, and some of them
    // are very large.
    std::io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

/// Parse the file report VirusTotal returns.
fn parse(body: &str, sha256: &str) -> kam_core::Result<Verdict> {
    let root: serde_json::Value = serde_json::from_str(body)
        .map_err(|error| kam_core::Error::Refused(format!("the reply was not readable: {error}")))?;

    let attributes = root
        .get("data")
        .and_then(|data| data.get("attributes"))
        .ok_or_else(|| {
            kam_core::Error::Refused("the reply did not contain a file report".to_owned())
        })?;

    let stats = attributes.get("last_analysis_stats");
    let count = |name: &str| -> u32 {
        stats
            .and_then(|stats| stats.get(name))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0) as u32
    };

    let malicious = count("malicious");
    let suspicious = count("suspicious");
    let harmless = count("harmless");
    let undetected = count("undetected");
    let engines = malicious + suspicious + harmless + undetected;

    let mut detections: Vec<Detection> = Vec::new();
    if let Some(results) = attributes
        .get("last_analysis_results")
        .and_then(serde_json::Value::as_object)
    {
        for (engine, outcome) in results {
            let category = outcome.get("category").and_then(serde_json::Value::as_str);
            if !matches!(category, Some("malicious") | Some("suspicious")) {
                continue;
            }
            detections.push(Detection {
                engine: engine.clone(),
                verdict: text(outcome, "result")
                    .unwrap_or_else(|| "flagged without a name".to_owned()),
            });
        }
    }
    detections.sort_by_key(|detection| detection.engine.to_lowercase());

    let (standing, summary) = interpret(malicious, suspicious, engines);

    Ok(Verdict {
        sha256: sha256.to_owned(),
        standing,
        malicious,
        suspicious,
        harmless,
        undetected,
        engines,
        detections,
        reputation: attributes.get("reputation").and_then(serde_json::Value::as_i64),
        first_seen: timestamp(attributes, "first_submission_date"),
        last_analysed: timestamp(attributes, "last_analysis_date"),
        common_name: text(attributes, "meaningful_name"),
        permalink: format!("https://www.virustotal.com/gui/file/{sha256}"),
        summary,
    })
}

/// Look one hash up.
///
/// Takes a hash rather than a path, so that nothing in this function could
/// send a file even by mistake.
pub fn look_up(sha256: &str) -> kam_core::Result<Verdict> {
    let sha256 = sha256.trim().to_lowercase();
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(kam_core::Error::Refused(
            "that is not a SHA-256 hash".to_owned(),
        ));
    }

    let Some(api_key) = key::load() else {
        return Err(kam_core::Error::Refused(
            "No VirusTotal key is stored. Add one to use this.".to_owned(),
        ));
    };

    let response = http::get(
        HOST,
        &format!("/api/v3/files/{sha256}"),
        &format!("x-apikey: {api_key}\r\naccept: application/json"),
    )?;

    match response.status {
        200 => parse(&response.body, &sha256),

        // Not an error. Most files have never been submitted by anyone.
        404 => Ok(Verdict {
            sha256: sha256.clone(),
            standing: Standing::NotKnown,
            malicious: 0,
            suspicious: 0,
            harmless: 0,
            undetected: 0,
            engines: 0,
            detections: Vec::new(),
            reputation: None,
            first_seen: None,
            last_analysed: None,
            common_name: None,
            permalink: format!("https://www.virustotal.com/gui/file/{sha256}"),
            summary: "VirusTotal has no record of this file. That is unremarkable on its own \
                      — most files on most machines have never been submitted by anyone — and \
                      it is not evidence either way."
                .to_owned(),
        }),

        401 => Err(kam_core::Error::Refused(
            "VirusTotal rejected the API key. Check it was copied whole from your profile."
                .to_owned(),
        )),

        429 => Err(kam_core::Error::Refused(
            "VirusTotal's rate limit was reached. A free key allows four lookups a minute and \
             five hundred a day; waiting a minute is usually enough."
                .to_owned(),
        )),

        other => Err(kam_core::Error::Refused(format!(
            "VirusTotal answered with status {other}."
        ))),
    }
}

/// Hash a file and look it up.
///
/// The one call the interface makes, kept together so that the hash a lookup
/// used is always the hash of the file that was on disk at that moment.
pub fn look_up_file(path: &str) -> kam_core::Result<Verdict> {
    look_up(&hash_file(path)?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_known_hash_is_computed_correctly() {
        // The empty file's SHA-256 is a published constant, so this checks the
        // hashing rather than merely checking it is self-consistent.
        let path = std::env::temp_dir().join(format!("kam-vt-empty-{}", std::process::id()));
        std::fs::write(&path, b"").unwrap();
        assert_eq!(
            hash_file(&path.display().to_string()).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_owned()
                + "",
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_hash_of_known_content_matches_the_published_value() {
        let path = std::env::temp_dir().join(format!("kam-vt-abc-{}", std::process::id()));
        std::fs::write(&path, b"abc").unwrap();
        assert_eq!(
            hash_file(&path.display().to_string()).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn nothing_flagged_reads_as_clean() {
        let (standing, summary) = interpret(0, 0, 72);
        assert_eq!(standing, Standing::Clean);
        assert!(summary.contains("None of the 72"));
    }

    #[test]
    fn a_couple_of_detections_are_described_as_probably_nothing() {
        // The single most important judgement in this module. Two engines out
        // of seventy is the everyday false-positive pattern, and presenting it
        // as a threat is how people are frightened into deleting their own
        // software.
        let (standing, summary) = interpret(2, 0, 70);
        assert_eq!(standing, Standing::Isolated);
        assert!(
            summary.contains("usually means nothing"),
            "should not read as an accusation: {summary}"
        );
        assert!(summary.contains("false positive"));
    }

    #[test]
    fn broad_agreement_is_stated_plainly() {
        let (standing, summary) = interpret(48, 3, 70);
        assert_eq!(standing, Standing::Substantial);
        assert!(
            summary.contains("rarely agree by accident"),
            "{summary}"
        );
    }

    #[test]
    fn suspicious_counts_alongside_malicious() {
        let (standing, _) = interpret(0, 5, 70);
        assert_eq!(standing, Standing::Substantial);
    }

    #[test]
    fn a_malformed_hash_is_refused_before_anything_is_sent() {
        // Nothing should reach the network on a bad input.
        for bad in ["", "abc", &"z".repeat(64), &"a".repeat(63)] {
            assert!(look_up(bad).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn a_report_is_parsed() {
        let body = r#"{
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 2, "suspicious": 1,
                        "harmless": 0, "undetected": 67
                    },
                    "last_analysis_results": {
                        "AlphaAV": { "category": "malicious", "result": "Win32/Thing.A" },
                        "BetaAV":  { "category": "undetected", "result": null },
                        "GammaAV": { "category": "suspicious", "result": "Heuristic.X" },
                        "DeltaAV": { "category": "malicious", "result": null }
                    },
                    "reputation": -3,
                    "first_submission_date": 1600000000,
                    "last_analysis_date": 1700000000,
                    "meaningful_name": "setup.exe"
                }
            }
        }"#;

        let verdict = parse(body, &"a".repeat(64)).unwrap();
        assert_eq!(verdict.engines, 70);
        assert_eq!(verdict.malicious, 2);
        assert_eq!(verdict.suspicious, 1);
        assert_eq!(verdict.standing, Standing::Isolated);
        assert_eq!(verdict.reputation, Some(-3));
        assert_eq!(verdict.common_name.as_deref(), Some("setup.exe"));

        // Only the engines that flagged it, and an engine that flagged without
        // naming anything still gets listed.
        assert_eq!(verdict.detections.len(), 3);
        let engines: Vec<&str> = verdict.detections.iter().map(|d| d.engine.as_str()).collect();
        assert_eq!(engines, vec!["AlphaAV", "DeltaAV", "GammaAV"]);
        assert_eq!(verdict.detections[1].verdict, "flagged without a name");
    }

    #[test]
    fn a_reply_that_is_not_a_report_is_refused() {
        assert!(parse("{}", &"a".repeat(64)).is_err());
        assert!(parse("not json", &"a".repeat(64)).is_err());
    }

    #[test]
    fn dates_are_converted_correctly() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(1_600_000_000), "2020-09-13");
        assert_eq!(date(1_700_000_000), "2023-11-14");
    }
}
