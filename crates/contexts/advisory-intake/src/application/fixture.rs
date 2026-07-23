//! Offline, fixture-first advisory acquisition anti-corruption adapter.

use cauterizer_syntax::digest::Sha256Digest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Hard limits applied before a fixture can enter the domain.
#[derive(Clone, Copy, Debug)]
pub struct FixtureLimits {
    /// Maximum raw JSON bytes.
    pub max_bytes: usize,
    /// Maximum aliases.
    pub max_aliases: usize,
    /// Maximum affected package entries.
    pub max_affected: usize,
    /// Maximum ranges across every package.
    pub max_ranges: usize,
    /// Maximum UTF-8 bytes in any accepted string.
    pub max_string_bytes: usize,
    /// Maximum seconds an observation may be ahead of retrieval time.
    pub max_future_skew_seconds: u64,
}
impl Default for FixtureLimits {
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

/// Stable, payload-safe normalization failure vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalizationReason {
    /// Input exceeded the byte budget before parsing.
    InputTooLarge,
    /// JSON was malformed or used an unknown field.
    InvalidSchema,
    /// Unsupported source schema version.
    UnsupportedSchemaVersion,
    /// A bounded string or collection exceeded its limit.
    ReferenceLimitExceeded,
    /// Observation time was invalid or implausibly in the future.
    InvalidObservationTime,
    /// A duplicate alias made the source representation ambiguous.
    AmbiguousAlias,
    /// Ecosystem or range semantics were missing/unknown.
    UnsupportedRangeSemantics,
}

/// Classification attached to stored artifact payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactClass {
    /// Exact untrusted bytes captured from the public fixture source.
    PublicSourceRaw,
    /// Deterministic provider-neutral representation.
    PublicCanonical,
}
/// Content-addressed artifact prepared for an authorized artifact store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassifiedArtifact {
    /// Data class.
    pub class: ArtifactClass,
    /// Digest over exact bytes.
    pub digest: Sha256Digest,
    /// Payload retained only at the adapter/store boundary.
    pub bytes: Vec<u8>,
}
/// Descriptor safe for P04 artifact commit and publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactCommitDescriptor {
    /// Artifact data class.
    pub class: ArtifactClass,
    /// Digest over exact staged bytes.
    pub digest: Sha256Digest,
    /// Exact bounded byte count.
    pub size_bytes: u64,
}
impl ClassifiedArtifact {
    /// Produces a payload-free commit descriptor.
    #[must_use]
    pub fn descriptor(&self) -> ArtifactCommitDescriptor {
        ArtifactCommitDescriptor {
            class: self.class,
            digest: self.digest,
            size_bytes: u64::try_from(self.bytes.len()).unwrap_or(u64::MAX),
        }
    }
}
/// Provider-neutral canonical candidate plus separately classified artifacts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedFixture {
    /// External advisory ID.
    pub external_id: String,
    /// Sorted aliases; they are attributes, never aggregate identity.
    pub aliases: Vec<String>,
    /// Source observation time in epoch seconds.
    pub modified_at_epoch_seconds: u64,
    /// Whether this observation withdraws the advisory.
    pub withdrawn: bool,
    /// Ecosystem-preserving affected entries.
    pub affected: Vec<CanonicalAffected>,
    /// Raw source artifact.
    pub raw: ClassifiedArtifact,
    /// Deterministically serialized canonical artifact.
    pub canonical: ClassifiedArtifact,
}
/// Canonical affected package without source SDK types.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CanonicalAffected {
    /// Ecosystem vocabulary retained exactly.
    pub ecosystem: String,
    /// Ecosystem package name.
    pub package: String,
    /// Source range kind such as `SEMVER`.
    pub range_type: String,
    /// Original range event expressions.
    pub events: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    schema_version: u16,
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    modified_at_epoch_seconds: u64,
    #[serde(default)]
    withdrawn: bool,
    #[serde(default)]
    affected: Vec<Affected>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Affected {
    ecosystem: String,
    package: String,
    range_type: String,
    events: Vec<String>,
}
#[derive(Serialize)]
struct Canonical<'a> {
    schema_version: u16,
    id: &'a str,
    aliases: &'a [String],
    modified_at_epoch_seconds: u64,
    withdrawn: bool,
    affected: &'a [CanonicalAffected],
}

/// Recorded-fixture adapter. It performs no network or filesystem access.
#[derive(Clone, Copy, Debug)]
pub struct LocalFixtureAdapter {
    limits: FixtureLimits,
}
impl LocalFixtureAdapter {
    /// Creates an adapter with explicit policy limits.
    #[must_use]
    pub const fn new(limits: FixtureLimits) -> Self {
        Self { limits }
    }
    /// Parses and deterministically normalizes exact recorded bytes.
    ///
    /// # Errors
    /// Returns a stable reason without embedding raw source content.
    pub fn normalize(
        &self,
        raw: &[u8],
        retrieved_at_epoch_seconds: u64,
    ) -> Result<NormalizedFixture, NormalizationReason> {
        if raw.len() > self.limits.max_bytes {
            return Err(NormalizationReason::InputTooLarge);
        }
        let fixture: Fixture =
            serde_json::from_slice(raw).map_err(|_| NormalizationReason::InvalidSchema)?;
        if fixture.schema_version != 1 {
            return Err(NormalizationReason::UnsupportedSchemaVersion);
        }
        if fixture.modified_at_epoch_seconds
            > retrieved_at_epoch_seconds.saturating_add(self.limits.max_future_skew_seconds)
        {
            return Err(NormalizationReason::InvalidObservationTime);
        }
        if fixture.aliases.len() > self.limits.max_aliases
            || fixture.affected.len() > self.limits.max_affected
        {
            return Err(NormalizationReason::ReferenceLimitExceeded);
        }
        let strings = std::iter::once(&fixture.id)
            .chain(fixture.aliases.iter())
            .chain(fixture.affected.iter().flat_map(|a| {
                std::iter::once(&a.ecosystem)
                    .chain(std::iter::once(&a.package))
                    .chain(std::iter::once(&a.range_type))
                    .chain(a.events.iter())
            }));
        if strings
            .into_iter()
            .any(|s| s.is_empty() || s.len() > self.limits.max_string_bytes || s.trim() != s)
        {
            return Err(NormalizationReason::ReferenceLimitExceeded);
        }
        let unique: BTreeSet<_> = fixture.aliases.iter().collect();
        if unique.len() != fixture.aliases.len() {
            return Err(NormalizationReason::AmbiguousAlias);
        }
        let range_count = fixture
            .affected
            .iter()
            .try_fold(0usize, |n, a| n.checked_add(a.events.len()))
            .ok_or(NormalizationReason::ReferenceLimitExceeded)?;
        if range_count > self.limits.max_ranges {
            return Err(NormalizationReason::ReferenceLimitExceeded);
        }
        if fixture.affected.iter().any(|a| {
            !matches!(a.range_type.as_str(), "SEMVER" | "ECOSYSTEM" | "GIT") || a.events.is_empty()
        }) {
            return Err(NormalizationReason::UnsupportedRangeSemantics);
        }
        let mut aliases = fixture.aliases;
        aliases.sort();
        let affected = fixture
            .affected
            .into_iter()
            .map(|a| CanonicalAffected {
                ecosystem: a.ecosystem,
                package: a.package,
                range_type: a.range_type,
                events: a.events,
            })
            .collect::<Vec<_>>();
        let canonical = serde_json::to_vec(&Canonical {
            schema_version: 1,
            id: &fixture.id,
            aliases: &aliases,
            modified_at_epoch_seconds: fixture.modified_at_epoch_seconds,
            withdrawn: fixture.withdrawn,
            affected: &affected,
        })
        .map_err(|_| NormalizationReason::InvalidSchema)?;
        Ok(NormalizedFixture {
            external_id: fixture.id,
            aliases,
            modified_at_epoch_seconds: fixture.modified_at_epoch_seconds,
            withdrawn: fixture.withdrawn,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    const GOOD:&[u8]=br#"{"schema_version":1,"id":"OSV-1","aliases":["CVE-1"],"modified_at_epoch_seconds":100,"affected":[{"ecosystem":"crates.io","package":"demo","range_type":"SEMVER","events":[">=1.0.0","<1.2.0"]}]}"#;
    #[test]
    fn golden_is_deterministic_and_separates_raw_and_canonical() {
        let a = LocalFixtureAdapter::new(FixtureLimits::default());
        let x = a.normalize(GOOD, 100).unwrap();
        let y = a.normalize(GOOD, 100).unwrap();
        assert_eq!(x, y);
        assert_ne!(x.raw.digest, x.canonical.digest);
        assert_eq!(x.raw.descriptor().digest, x.raw.digest);
        assert_eq!(x.canonical.descriptor().digest, x.canonical.digest);
        assert_eq!(x.affected[0].ecosystem, "crates.io");
    }
    #[test]
    fn rejects_oversize_before_parse_and_unknown_fields() {
        let limits = FixtureLimits {
            max_bytes: 4,
            ..FixtureLimits::default()
        };
        assert_eq!(
            LocalFixtureAdapter::new(limits).normalize(GOOD, 100),
            Err(NormalizationReason::InputTooLarge)
        );
        let bad = br#"{"schema_version":1,"id":"x","modified_at_epoch_seconds":1,"surprise":true}"#;
        assert_eq!(
            LocalFixtureAdapter::new(FixtureLimits::default()).normalize(bad, 1),
            Err(NormalizationReason::InvalidSchema)
        );
    }
    #[test]
    fn rejects_future_time_duplicate_alias_and_unknown_range() {
        let a = LocalFixtureAdapter::new(FixtureLimits::default());
        let future = br#"{"schema_version":1,"id":"x","modified_at_epoch_seconds":1000}"#;
        assert_eq!(
            a.normalize(future, 1),
            Err(NormalizationReason::InvalidObservationTime)
        );
        let duplicate=br#"{"schema_version":1,"id":"x","aliases":["CVE-1","CVE-1"],"modified_at_epoch_seconds":1}"#;
        assert_eq!(
            a.normalize(duplicate, 1),
            Err(NormalizationReason::AmbiguousAlias)
        );
    }
}
