//! Whether a newer release of KAM Security has been published.
//!
//! # What this does, and what it deliberately does not
//!
//! It asks one fixed address one question: what is the latest published release
//! of this repository. It compares the answer with the version that is running
//! and reports the release's number, date, notes and page. It never downloads
//! anything, never installs anything and never runs anything. The person reads
//! the notes and decides.
//!
//! Installing is a separate and much larger question. This program runs a
//! service as LocalSystem, so whatever an updater installs runs with the highest
//! privilege Windows has, on every machine where it is installed. Doing that
//! safely needs releases signed with a key that never touches the build servers,
//! and a release pipeline hardened before it is trusted with that. Until both
//! exist, telling the person, with the release notes in front of them, is the
//! honest amount to automate.
//!
//! # A failed check is not "up to date"
//!
//! Offline, rate-limited, or an answer that does not parse: each is reported as
//! "could not check", and never folded into "you have the latest version". The
//! rule that runs through the rest of this product, that a failure is not an
//! absence, applies to its own updates as much as to anything it reports on.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

/// The API host. Fixed: nothing here is ever asked of a host taken from input.
const HOST: &str = "api.github.com";

/// The latest published release. GitHub excludes drafts and pre-releases from
/// this address, which is what a person running a release wants compared.
const LATEST: &str = "/repos/Ari-Joon/KAM-Security/releases/latest";

/// Every release page lives under this. A link in the response that does not
/// is not opened; the list of releases is offered instead.
pub const RELEASES: &str = "https://github.com/Ari-Joon/KAM-Security/releases";

/// Release notes are shown as text, and a page of them is plenty.
const NOTES_LIMIT: usize = 6_000;

/// What the check found.
#[derive(Debug, Clone, Serialize)]
pub struct UpdateCheck {
    /// The version that is running.
    pub current: String,
    /// The latest published release, when it could be read.
    pub latest: Option<Release>,
    /// True only when `latest` was read, both versions parsed, and the
    /// published one is higher. Every other outcome is false: `ahead` says when
    /// the running version is the higher one, and `problem` says why when the
    /// two could not be compared at all.
    pub newer: bool,
    /// True only when both versions parsed and the running one is higher than
    /// the latest published release: a build that has not been released yet.
    /// Not newer is not the same as level, and only level is "the latest".
    pub ahead: bool,
    /// Why the answer is incomplete, in plain words. `None` means the check
    /// completed and its answer is the whole answer.
    pub problem: Option<String>,
}

impl UpdateCheck {
    /// Nothing known yet beyond the version that is running.
    fn unanswered(current: &str) -> Self {
        Self {
            current: current.to_owned(),
            latest: None,
            newer: false,
            ahead: false,
            problem: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Release {
    /// The version, without a leading `v`.
    pub version: String,
    pub name: String,
    /// When it was published, as GitHub reports it (RFC 3339).
    pub published_at: String,
    /// The release notes as plain text, shortened if long. Never rendered as
    /// HTML: they come from the network.
    pub notes: String,
    /// The release's own page, or the list of releases when the link GitHub
    /// returned is not one of this repository's.
    pub url: String,
}

/// The fields read from GitHub's answer; everything else is ignored.
#[derive(Debug, Deserialize)]
struct Answer {
    tag_name: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    published_at: Option<String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    html_url: Option<String>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
}

/// Ask GitHub, and compare with `current`.
pub fn check(current: &str) -> UpdateCheck {
    let mut result = UpdateCheck::unanswered(current);

    // GitHub refuses API requests without a User-Agent. The version header pins
    // the response shape so a future API change cannot quietly alter it.
    let headers = "Accept: application/vnd.github+json\r\n\
                   User-Agent: KAM-Security-update-check\r\n\
                   X-GitHub-Api-Version: 2022-11-28";

    let response = match kam_virustotal::http::get(HOST, LATEST, headers) {
        Ok(response) => response,
        Err(error) => {
            result.problem = Some(format!("Could not reach GitHub to check: {error}"));
            return result;
        }
    };

    match response.status {
        200 => {}
        404 => {
            result.problem =
                Some("GitHub reports no published release to compare with.".to_owned());
            return result;
        }
        403 | 429 => {
            result.problem = Some(
                "GitHub declined to answer just now, usually because too many checks \
                 came from this network in the last hour. Try again later."
                    .to_owned(),
            );
            return result;
        }
        other => {
            result.problem = Some(format!("GitHub answered with status {other}."));
            return result;
        }
    }

    let answer: Answer = match serde_json::from_str(&response.body) {
        Ok(answer) => answer,
        Err(error) => {
            result.problem = Some(format!("GitHub's answer could not be read: {error}"));
            return result;
        }
    };

    judge(current, answer)
}

/// Compare the running version with the release GitHub returned.
///
/// Kept apart from the network so it can be tested, because this is where
/// three different answers are told apart: a newer release exists, this is
/// the latest release, and this build is ahead of every release. The last used
/// to fall into the second, so a build not yet published was called "the
/// latest release" beside the previous release's date.
fn judge(current: &str, answer: Answer) -> UpdateCheck {
    let mut result = UpdateCheck::unanswered(current);

    // The address already excludes both; checked anyway, because "latest" must
    // never mean a draft nobody has published or a pre-release nobody asked for.
    if answer.draft || answer.prerelease {
        result.problem =
            Some("GitHub returned an unpublished release as the latest one.".to_owned());
        return result;
    }

    let release = Release {
        version: answer.tag_name.trim_start_matches(['v', 'V']).to_owned(),
        name: answer.name.unwrap_or_default(),
        published_at: answer.published_at.unwrap_or_default(),
        notes: shorten(&answer.body.unwrap_or_default()),
        url: answer
            .html_url
            .filter(|url| is_our_release_page(url))
            .unwrap_or_else(|| RELEASES.to_owned()),
    };

    match compare(current, &release.version) {
        Some(order) => {
            result.newer = order == Ordering::Less;
            result.ahead = order == Ordering::Greater;
        }
        None => {
            result.problem = Some(format!(
                "The versions {current} and {} could not be compared, so this does not \
                 say whether one is newer.",
                release.version
            ));
        }
    }

    result.latest = Some(release);
    result
}

/// How the running version stands against a published one, compared as
/// numbers. `None` when either does not parse.
fn compare(running: &str, published: &str) -> Option<Ordering> {
    Some(parse(running)?.cmp(&parse(published)?))
}

/// Whether `url` is a page under this repository's releases.
///
/// The only link this ever opens. A response that named anywhere else is not
/// followed, whatever it says.
pub fn is_our_release_page(url: &str) -> bool {
    url == RELEASES
        || url
            .strip_prefix(RELEASES)
            .is_some_and(|rest| rest.starts_with('/') && !rest.contains(['?', '#', '\\']))
}

/// A version as three numbers, and whether it carries a pre-release suffix.
///
/// Deliberately small. Tags here are `vMAJOR.MINOR.PATCH`; anything else does
/// not parse, and an unparseable version is reported rather than guessed at.
fn parse(version: &str) -> Option<(u64, u64, u64, bool)> {
    let version = version.trim().trim_start_matches(['v', 'V']);
    let (core, suffix) = match version.split_once(['-', '+']) {
        Some((core, suffix)) => (core, Some(suffix)),
        None => (version, None),
    };
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    // A release sorts above its own pre-releases: 1.2.0 > 1.2.0-rc.1. The
    // boolean is "is a full release", so `true` compares greater.
    Some((major, minor, patch, suffix.is_none()))
}

fn shorten(notes: &str) -> String {
    let notes = notes.trim();
    if notes.chars().count() <= NOTES_LIMIT {
        return notes.to_owned();
    }
    let mut kept: String = notes.chars().take(NOTES_LIMIT).collect();
    kept.push_str("\n\n(The rest is on the release page.)");
    kept
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_as_numbers_not_text() {
        // As text, "0.10.0" sorts below "0.9.0". That is the classic way an
        // update check tells somebody on 0.9 that they are up to date.
        assert!(parse("0.10.0") > parse("0.9.0"));
        assert!(parse("v1.0.0") > parse("0.99.99"));
        assert_eq!(parse("v0.4.0"), parse("0.4.0"));
    }

    #[test]
    fn a_release_is_newer_than_its_own_prerelease() {
        assert!(parse("1.2.0") > parse("1.2.0-rc.1"));
        assert!(parse("1.2.1-rc.1") > parse("1.2.0"));
    }

    #[test]
    fn a_version_that_does_not_parse_is_not_guessed_at() {
        for bad in ["", "latest", "1.2", "1.2.3.4", "one.two.three"] {
            assert_eq!(parse(bad), None, "{bad:?} parsed");
        }
    }

    /// Only this repository's release pages are ever opened.
    ///
    /// The link arrives in a network response, and the one thing a check for
    /// updates must never become is a way to open an arbitrary address.
    #[test]
    fn only_this_repositorys_release_pages_are_trusted() {
        assert!(is_our_release_page(
            "https://github.com/Ari-Joon/KAM-Security/releases/tag/v0.4.0"
        ));
        assert!(is_our_release_page(RELEASES));

        for foreign in [
            "https://github.com/Ari-Joon/KAM-Security-evil/releases/tag/v9",
            "https://github.com/someone-else/KAM-Security/releases/tag/v9",
            "https://example.com/Ari-Joon/KAM-Security/releases/tag/v9",
            "http://github.com/Ari-Joon/KAM-Security/releases/tag/v9",
            "https://github.com/Ari-Joon/KAM-Security/releasesX",
            "https://github.com/Ari-Joon/KAM-Security/releases/tag/v9?next=https://example.com",
            "javascript:alert(1)",
        ] {
            assert!(!is_our_release_page(foreign), "{foreign} was trusted");
        }
    }

    /// A release as GitHub would return it, published on v0.4.0's date.
    fn published(tag: &str) -> Answer {
        Answer {
            tag_name: tag.to_owned(),
            name: None,
            published_at: Some("2026-09-14T09:10:08Z".to_owned()),
            body: None,
            html_url: None,
            draft: false,
            prerelease: false,
        }
    }

    /// Behind, level and ahead are three answers, not two.
    ///
    /// Between tagging v0.5.0 and publishing it, the window said "0.5.0 is the
    /// latest release, published 14 September 2026", which was v0.4.0's date.
    /// The check reported only "not newer", and the window read that as level.
    #[test]
    fn behind_level_and_ahead_are_told_apart() {
        let behind = judge("0.4.0", published("v0.5.0"));
        assert!(behind.newer && !behind.ahead, "{behind:?}");

        let level = judge("0.5.0", published("v0.5.0"));
        assert!(!level.newer && !level.ahead, "{level:?}");

        let ahead = judge("0.5.0", published("v0.4.0"));
        assert!(!ahead.newer && ahead.ahead, "{ahead:?}");
        assert_eq!(
            ahead
                .latest
                .as_ref()
                .map(|release| release.version.as_str()),
            Some("0.4.0"),
            "the release it is ahead of is still reported"
        );

        for answer in [&behind, &level, &ahead] {
            assert!(answer.problem.is_none(), "{answer:?}");
        }
    }

    /// Versions that cannot be compared claim neither direction, and say so.
    #[test]
    fn an_uncomparable_version_is_neither_newer_nor_ahead() {
        let odd = judge("0.5.0", published("latest"));
        assert!(!odd.newer && !odd.ahead, "{odd:?}");
        assert!(odd.problem.is_some());
    }

    #[test]
    fn long_notes_are_shortened_and_say_so() {
        let long = "x".repeat(NOTES_LIMIT + 50);
        let short = shorten(&long);
        assert!(short.ends_with("(The rest is on the release page.)"));
        assert!(short.chars().count() < long.chars().count() + 50);
    }

    /// Reaches the network, so it does not run by default.
    #[test]
    #[ignore = "reaches the network"]
    fn this_repository_answers() {
        let check = check("0.0.1");
        println!("{check:#?}");
        assert!(check.problem.is_none(), "{:?}", check.problem);
        assert!(check.newer, "0.0.1 should be older than any real release");
    }
}
