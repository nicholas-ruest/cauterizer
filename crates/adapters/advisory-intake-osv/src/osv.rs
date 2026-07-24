//! Normalizes the real-world OSV.dev advisory schema into the same
//! provider-neutral `NormalizedFixture` shape Advisory Intake's fixture path
//! (`cauterizer_advisory_intake::application::fixture`) already produces, so
//! artifact-commit and domain code are shared, unmodified, between the
//! fixture and live-acquisition paths.
//!
//! OSV's real schema does not line up field-for-field with CVE-Bench's
//! bespoke fixture format. In particular:
//! - `affected[].ranges[].events[]` are event *objects*
//!   (`{"introduced":"0"}`, `{"fixed":"1.2.3"}`, ...), not the fixture
//!   format's flat comparator strings (`">=1.0.0"`).
//! - one `affected[]` package entry can carry multiple `ranges[]`, while the
//!   fixture format's `Affected` has exactly one range per entry.
//! - `modified`/`published` are RFC 3339 strings, not epoch seconds.
//! - a genuine OSV response always carries extra fields the fixture format's
//!   `#[serde(deny_unknown_fields)]` `Fixture` struct would reject outright
//!   (`summary`, `details`, `references`, `severity`, `database_specific`,
//!   `schema_version`, ...).
//!
//! Rather than force OSV's shape through the fixture module's private types
//! (which would either weaken `deny_unknown_fields` for the fixture path or
//! never successfully parse a real OSV response), this module owns its own
//! tolerant OSV deserialization and maps the result onto the shared,
//! provider-neutral `NormalizedFixture`/`ClassifiedArtifact`/
//! `CanonicalAffected` output types. Each OSV range event is deterministically
//! encoded as `"<kind>:<value>"` (e.g. `"introduced:0"`, `"fixed:1.2.3"`),
//! preserving OSV's declared event order; a single `affected[]` entry with
//! multiple `ranges[]` is flattened into one `CanonicalAffected` per range.

use crate::acquire::OsvAcquisitionReason;
use cauterizer_advisory_intake::application::fixture::{
    ArtifactClass, CanonicalAffected, ClassifiedArtifact, NormalizedFixture,
};
use cauterizer_syntax::digest::Sha256Digest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Hard limits applied before an OSV response can enter the domain, mirroring
/// `cauterizer_advisory_intake::application::fixture::FixtureLimits`.
#[derive(Clone, Copy, Debug)]
pub struct OsvLimits {
    /// Maximum raw JSON bytes.
    pub max_bytes: usize,
    /// Maximum aliases.
    pub max_aliases: usize,
    /// Maximum flattened affected-range entries.
    pub max_affected: usize,
    /// Maximum range events across every affected entry.
    pub max_ranges: usize,
    /// Maximum UTF-8 bytes in any accepted string.
    pub max_string_bytes: usize,
    /// Maximum seconds an observation may be ahead of retrieval time.
    pub max_future_skew_seconds: u64,
}
impl Default for OsvLimits {
    fn default() -> Self {
        Self {
            max_bytes: 1_048_576,
            max_aliases: 128,
            max_affected: 256,
            max_ranges: 2_048,
            max_string_bytes: 4_096,
            max_future_skew_seconds: 300,
        }
    }
}

/// Tolerant OSV advisory shape: unknown fields (`summary`, `details`,
/// `references`, `severity`, ...) are intentionally ignored rather than
/// rejected, since a real OSV response always carries them.
#[derive(Deserialize)]
struct OsvAdvisory {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    modified: String,
    /// Presence (any value, including an empty string) marks a withdrawal
    /// per the OSV schema; only `Option::is_some` is consulted.
    #[serde(default)]
    withdrawn: Option<String>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}
#[derive(Deserialize)]
struct OsvAffected {
    package: OsvPackage,
    #[serde(default)]
    ranges: Vec<OsvRange>,
}
#[derive(Deserialize)]
struct OsvPackage {
    ecosystem: String,
    name: String,
}
#[derive(Deserialize)]
struct OsvRange {
    #[serde(rename = "type")]
    range_type: String,
    #[serde(default)]
    events: Vec<OsvEvent>,
}
#[derive(Deserialize)]
struct OsvEvent {
    #[serde(default)]
    introduced: Option<String>,
    #[serde(default)]
    fixed: Option<String>,
    #[serde(default)]
    last_affected: Option<String>,
    #[serde(default)]
    limit: Option<String>,
}
impl OsvEvent {
    /// Encodes the event's single populated kind as `"<kind>:<value>"`.
    /// Returns `None` when zero or more than one kind is present.
    fn encode(&self) -> Option<String> {
        let mut present = [
            self.introduced.as_deref().map(|v| ("introduced", v)),
            self.fixed.as_deref().map(|v| ("fixed", v)),
            self.last_affected.as_deref().map(|v| ("last_affected", v)),
            self.limit.as_deref().map(|v| ("limit", v)),
        ]
        .into_iter()
        .flatten();
        let (kind, value) = present.next()?;
        if present.next().is_some() {
            return None;
        }
        Some(format!("{kind}:{value}"))
    }
}

/// Canonical wire shape for OSV-sourced normalization output. `schema_version`
/// is `2` (distinct from the fixture path's `1`) since OSV-encoded `events`
/// strings (`"introduced:0"`) are not interchangeable with the fixture
/// format's comparator strings (`">=1.0.0"`) despite sharing a field name.
#[derive(Serialize)]
struct Canonical<'a> {
    schema_version: u16,
    id: &'a str,
    aliases: &'a [String],
    modified_at_epoch_seconds: u64,
    withdrawn: bool,
    affected: &'a [CanonicalAffected],
}

/// Parses and deterministically normalizes one raw OSV.dev advisory response.
///
/// # Errors
/// Returns a stable reason without embedding raw source content.
pub fn normalize(
    raw: &[u8],
    retrieved_at_epoch_seconds: u64,
    limits: &OsvLimits,
) -> Result<NormalizedFixture, OsvAcquisitionReason> {
    if raw.len() > limits.max_bytes {
        return Err(OsvAcquisitionReason::ResponseTooLarge);
    }
    let advisory: OsvAdvisory =
        serde_json::from_slice(raw).map_err(|_| OsvAcquisitionReason::MalformedResponse)?;
    if advisory.id.is_empty() || advisory.id.len() > limits.max_string_bytes {
        return Err(OsvAcquisitionReason::MalformedResponse);
    }
    let modified_at_epoch_seconds = parse_rfc3339_to_epoch_seconds(&advisory.modified)
        .ok_or(OsvAcquisitionReason::InvalidTimestamp)?;
    if modified_at_epoch_seconds
        > retrieved_at_epoch_seconds.saturating_add(limits.max_future_skew_seconds)
    {
        return Err(OsvAcquisitionReason::InvalidTimestamp);
    }
    if advisory.aliases.len() > limits.max_aliases || advisory.affected.len() > limits.max_affected
    {
        return Err(OsvAcquisitionReason::ReferenceLimitExceeded);
    }
    let strings = std::iter::once(&advisory.id)
        .chain(advisory.aliases.iter())
        .chain(
            advisory
                .affected
                .iter()
                .flat_map(|a| [&a.package.ecosystem, &a.package.name]),
        );
    if strings.into_iter().any(|s| bad_string(s, limits)) {
        return Err(OsvAcquisitionReason::ReferenceLimitExceeded);
    }
    let unique: BTreeSet<_> = advisory.aliases.iter().collect();
    if unique.len() != advisory.aliases.len() {
        return Err(OsvAcquisitionReason::AmbiguousAlias);
    }
    let affected = flatten_affected(&advisory.affected, limits)?;
    let range_count = affected
        .iter()
        .try_fold(0usize, |n, a| n.checked_add(a.events.len()))
        .ok_or(OsvAcquisitionReason::ReferenceLimitExceeded)?;
    if range_count > limits.max_ranges {
        return Err(OsvAcquisitionReason::ReferenceLimitExceeded);
    }
    let mut aliases = advisory.aliases;
    aliases.sort();
    let withdrawn = advisory.withdrawn.is_some();
    let canonical = serde_json::to_vec(&Canonical {
        schema_version: 2,
        id: &advisory.id,
        aliases: &aliases,
        modified_at_epoch_seconds,
        withdrawn,
        affected: &affected,
    })
    .map_err(|_| OsvAcquisitionReason::MalformedResponse)?;
    Ok(NormalizedFixture {
        external_id: advisory.id,
        aliases,
        modified_at_epoch_seconds,
        withdrawn,
        affected,
        raw: ClassifiedArtifact {
            class: ArtifactClass::PublicSourceRaw,
            digest: Sha256Digest::of_bytes(raw),
            bytes: raw.to_vec(),
        },
        canonical: ClassifiedArtifact {
            class: ArtifactClass::PublicCanonical,
            digest: Sha256Digest::of_bytes(&canonical),
            bytes: canonical,
        },
    })
}

fn bad_string(value: &str, limits: &OsvLimits) -> bool {
    value.is_empty() || value.len() > limits.max_string_bytes || value.trim() != value
}

fn flatten_affected(
    entries: &[OsvAffected],
    limits: &OsvLimits,
) -> Result<Vec<CanonicalAffected>, OsvAcquisitionReason> {
    let mut affected = Vec::new();
    for entry in entries {
        for range in &entry.ranges {
            if !matches!(range.range_type.as_str(), "SEMVER" | "ECOSYSTEM" | "GIT") {
                return Err(OsvAcquisitionReason::UnsupportedRangeSemantics);
            }
            let mut events = Vec::with_capacity(range.events.len());
            for event in &range.events {
                let encoded = event
                    .encode()
                    .ok_or(OsvAcquisitionReason::UnsupportedRangeSemantics)?;
                if encoded.len() > limits.max_string_bytes {
                    return Err(OsvAcquisitionReason::ReferenceLimitExceeded);
                }
                events.push(encoded);
            }
            if events.is_empty() {
                return Err(OsvAcquisitionReason::UnsupportedRangeSemantics);
            }
            affected.push(CanonicalAffected {
                ecosystem: entry.package.ecosystem.clone(),
                package: entry.package.name.clone(),
                range_type: range.range_type.clone(),
                events,
            });
            if affected.len() > limits.max_affected {
                return Err(OsvAcquisitionReason::ReferenceLimitExceeded);
            }
        }
    }
    Ok(affected)
}

/// Parses a canonical `YYYY-MM-DDTHH:MM:SS[.fraction]Z` instant into epoch
/// seconds. OSV always emits RFC 3339 UTC timestamps with a `Z` suffix.
fn parse_rfc3339_to_epoch_seconds(value: &str) -> Option<u64> {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes.last() != Some(&b'Z')
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return None;
    }
    for index in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18] {
        if !bytes.get(index)?.is_ascii_digit() {
            return None;
        }
    }
    let year = decimal(bytes, 0, 4)?;
    let month = decimal(bytes, 5, 7)?;
    let day = decimal(bytes, 8, 10)?;
    let hour = decimal(bytes, 11, 13)?;
    let minute = decimal(bytes, 14, 16)?;
    let second = decimal(bytes, 17, 19)?;
    if year == 0
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let days = days_from_civil(i64::from(year), month, day);
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3_600 + i64::from(minute) * 60 + i64::from(second))?;
    u64::try_from(seconds).ok()
}
fn decimal(bytes: &[u8], start: usize, end: usize) -> Option<u32> {
    bytes
        .get(start..end)?
        .iter()
        .try_fold(0u32, |value, &digit| {
            digit.checked_sub(b'0').map(|d| value * 10 + u32::from(d))
        })
}
const fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}
const fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}
/// Days since the Unix epoch for a proleptic Gregorian civil date, using
/// Howard Hinnant's `days_from_civil` algorithm.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let year_of_era = y - era * 400;
    let month_index = i64::from((month + 9) % 12);
    let day_of_year = (153 * month_index + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_SHAPED_OSV: &[u8] = br#"{
        "id": "GHSA-aaaa-bbbb-cccc",
        "summary": "Example advisory",
        "details": "Long-form description text, intentionally dropped by normalization.",
        "aliases": ["CVE-2026-0001"],
        "modified": "2026-07-23T00:00:00Z",
        "published": "2026-07-20T00:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": "crates.io", "name": "widget", "purl": "pkg:cargo/widget"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}
                ],
                "database_specific": {"anything": true}
            }
        ],
        "references": [{"type": "ADVISORY", "url": "https://example.invalid/a"}],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "schema_version": "1.6.0"
    }"#;

    #[test]
    fn accepts_real_shaped_osv_response_and_ignores_unknown_fields() {
        let advisory = normalize(REAL_SHAPED_OSV, 2_000_000_000, &OsvLimits::default()).unwrap();
        assert_eq!(advisory.external_id, "GHSA-aaaa-bbbb-cccc");
        assert_eq!(advisory.aliases, vec!["CVE-2026-0001".to_owned()]);
        assert!(!advisory.withdrawn);
        assert_eq!(advisory.affected.len(), 1);
        assert_eq!(advisory.affected[0].ecosystem, "crates.io");
        assert_eq!(advisory.affected[0].package, "widget");
        assert_eq!(advisory.affected[0].range_type, "SEMVER");
        assert_eq!(
            advisory.affected[0].events,
            vec!["introduced:0".to_owned(), "fixed:1.2.3".to_owned()]
        );
        assert_ne!(advisory.raw.digest, advisory.canonical.digest);
        // Free-text fields never enter the canonical artifact.
        let canonical_text = String::from_utf8(advisory.canonical.bytes.clone()).unwrap();
        assert!(!canonical_text.contains("Long-form description"));
    }

    #[test]
    fn flattens_multiple_ranges_per_affected_package() {
        let multi = br#"{"id":"OSV-1","modified":"2026-01-01T00:00:00Z","affected":[
            {"package":{"ecosystem":"crates.io","name":"widget"},"ranges":[
                {"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]},
                {"type":"GIT","events":[{"introduced":"abc"},{"last_affected":"def"}]}
            ]}
        ]}"#;
        let advisory = normalize(multi, 2_000_000_000, &OsvLimits::default()).unwrap();
        assert_eq!(advisory.affected.len(), 2);
        assert_eq!(advisory.affected[1].range_type, "GIT");
    }

    #[test]
    fn marks_withdrawal_from_presence_of_the_withdrawn_field() {
        let withdrawn = br#"{"id":"OSV-1","modified":"2026-01-01T00:00:00Z","withdrawn":"2026-01-02T00:00:00Z"}"#;
        assert!(
            normalize(withdrawn, 2_000_000_000, &OsvLimits::default())
                .unwrap()
                .withdrawn
        );
    }

    #[test]
    fn rejects_oversize_before_parse_and_malformed_json() {
        let limits = OsvLimits {
            max_bytes: 4,
            ..OsvLimits::default()
        };
        assert_eq!(
            normalize(REAL_SHAPED_OSV, 2_000_000_000, &limits),
            Err(OsvAcquisitionReason::ResponseTooLarge)
        );
        assert_eq!(
            normalize(b"not json", 2_000_000_000, &OsvLimits::default()),
            Err(OsvAcquisitionReason::MalformedResponse)
        );
        assert_eq!(
            normalize(br#"{"id":"x"}"#, 2_000_000_000, &OsvLimits::default()),
            Err(OsvAcquisitionReason::MalformedResponse)
        );
    }

    #[test]
    fn rejects_future_timestamp_duplicate_alias_and_ambiguous_or_unknown_range() {
        let future = br#"{"id":"x","modified":"2099-01-01T00:00:00Z"}"#;
        assert_eq!(
            normalize(future, 1, &OsvLimits::default()),
            Err(OsvAcquisitionReason::InvalidTimestamp)
        );
        let duplicate =
            br#"{"id":"x","aliases":["CVE-1","CVE-1"],"modified":"2026-01-01T00:00:00Z"}"#;
        assert_eq!(
            normalize(duplicate, 2_000_000_000, &OsvLimits::default()),
            Err(OsvAcquisitionReason::AmbiguousAlias)
        );
        let unknown_range = br#"{"id":"x","modified":"2026-01-01T00:00:00Z","affected":[
            {"package":{"ecosystem":"crates.io","name":"widget"},"ranges":[{"type":"UNKNOWN","events":[{"introduced":"0"}]}]}
        ]}"#;
        assert_eq!(
            normalize(unknown_range, 2_000_000_000, &OsvLimits::default()),
            Err(OsvAcquisitionReason::UnsupportedRangeSemantics)
        );
        let ambiguous_event = br#"{"id":"x","modified":"2026-01-01T00:00:00Z","affected":[
            {"package":{"ecosystem":"crates.io","name":"widget"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0","fixed":"1.0.0"}]}]}
        ]}"#;
        assert_eq!(
            normalize(ambiguous_event, 2_000_000_000, &OsvLimits::default()),
            Err(OsvAcquisitionReason::UnsupportedRangeSemantics)
        );
    }

    #[test]
    fn epoch_conversion_matches_known_instants() {
        assert_eq!(
            parse_rfc3339_to_epoch_seconds("1970-01-01T00:00:00Z"),
            Some(0)
        );
        assert_eq!(
            parse_rfc3339_to_epoch_seconds("2023-01-01T00:00:00Z"),
            Some(1_672_531_200)
        );
        assert_eq!(
            parse_rfc3339_to_epoch_seconds("2026-07-23T00:00:00Z"),
            Some(1_784_764_800)
        );
        assert_eq!(parse_rfc3339_to_epoch_seconds("not-a-time"), None);
        assert_eq!(
            parse_rfc3339_to_epoch_seconds("2026-07-23T00:00:00+00:00"),
            None
        );
    }
}
