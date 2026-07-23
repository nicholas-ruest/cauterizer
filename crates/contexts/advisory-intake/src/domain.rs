//! Private immutable Advisory Intake aggregate.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use cauterizer_syntax::classification::DataClass;
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
use cauterizer_syntax::schema::{SchemaName, SchemaVersion};

macro_rules! owned_id {
    ($name:ident,$prefix:literal) => {
        #[doc = concat!("Advisory Intake identifier with `", $prefix, "` prefix.")]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(ContextQualifiedId);
        impl $name {
            /// Creates an ID from a canonical opaque component.
            ///
            /// # Errors
            /// Returns [`AdvisoryError::InvalidValue`] for invalid shared syntax.
            pub fn new(opaque: &str) -> Result<Self, AdvisoryError> {
                ContextQualifiedId::new($prefix, opaque)
                    .map(Self)
                    .map_err(|_| AdvisoryError::InvalidValue)
            }
            /// Returns the context-qualified spelling.
            #[must_use]
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }
    };
}
owned_id!(AdvisoryRecordId, "advisory-record");
owned_id!(AcquisitionId, "acquisition");
owned_id!(SnapshotId, "advisory-snapshot");
owned_id!(FailureId, "normalization-failure");

/// Provider-neutral upstream identity and pinned adapter provenance.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AdvisorySource {
    /// Canonical provider-neutral source name.
    pub source: String,
    /// Source-owned advisory identity.
    pub external_id: String,
    /// Pinned adapter or fixture revision.
    pub adapter_revision: String,
}
impl AdvisorySource {
    /// Creates bounded provider-neutral source provenance.
    ///
    /// # Errors
    /// Rejects malformed source, external identity, or adapter revision.
    pub fn new(
        source: String,
        external_id: String,
        adapter_revision: String,
    ) -> Result<Self, AdvisoryError> {
        if !bounded_token(&source, 64)
            || !bounded_reference(&external_id, 128)
            || !bounded_reference(&adapter_revision, 128)
        {
            return Err(AdvisoryError::InvalidValue);
        }
        Ok(Self {
            source,
            external_id,
            adapter_revision,
        })
    }
}

/// Classified immutable artifact reference; payload never enters the aggregate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdvisoryArtifactRef {
    /// Exact immutable payload digest.
    pub digest: Sha256Digest,
    /// Payload disclosure classification.
    pub classification: DataClass,
    /// Payload schema identity.
    pub schema_name: SchemaName,
    /// Immutable payload schema revision.
    pub schema_version: SchemaVersion,
    /// Exact validated payload length.
    pub size_bytes: u64,
}

/// Ecosystem name retained exactly rather than translated to generic semver.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Ecosystem(String);
impl Ecosystem {
    /// Creates a canonical ecosystem name.
    ///
    /// # Errors
    /// Rejects malformed or oversized names.
    pub fn new(value: String) -> Result<Self, AdvisoryError> {
        if !bounded_token(&value, 48) {
            return Err(AdvisoryError::InvalidRange);
        }
        Ok(Self(value))
    }
    /// Returns the preserved ecosystem name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Ecosystem-preserving affected range with opaque native boundaries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AffectedRange {
    /// Ecosystem retaining authority over range interpretation.
    pub ecosystem: Ecosystem,
    /// Ecosystem-native package coordinate.
    pub package: String,
    /// Native introduced boundary.
    pub introduced: String,
    /// Optional native fixed boundary.
    pub fixed: Option<String>,
    /// Optional native last-affected boundary.
    pub last_affected: Option<String>,
}
impl AffectedRange {
    /// Creates one ecosystem-preserving range.
    ///
    /// # Errors
    /// Rejects malformed or contradictory boundaries.
    pub fn new(
        ecosystem: Ecosystem,
        package: String,
        introduced: String,
        fixed: Option<String>,
        last_affected: Option<String>,
    ) -> Result<Self, AdvisoryError> {
        if !bounded_reference(&package, 256)
            || !bounded_reference(&introduced, 128)
            || fixed.as_ref().is_some_and(|v| !bounded_reference(v, 128))
            || last_affected
                .as_ref()
                .is_some_and(|v| !bounded_reference(v, 128))
            || fixed.is_some() && last_affected.is_some()
        {
            return Err(AdvisoryError::InvalidRange);
        }
        Ok(Self {
            ecosystem,
            package,
            introduced,
            fixed,
            last_affected,
        })
    }
}

/// Severity retains the exact metric family, revision, and source vector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeverityVector {
    /// Severity metric family.
    pub metric: String,
    /// Metric specification revision.
    pub version: String,
    /// Exact attributed source vector.
    pub vector: String,
    /// Source attribution for this observation.
    pub source: AdvisorySource,
}
impl SeverityVector {
    /// Creates a bounded severity observation.
    ///
    /// # Errors
    /// Rejects malformed metric, revision, or vector values.
    pub fn new(
        metric: String,
        version: String,
        vector: String,
        source: AdvisorySource,
    ) -> Result<Self, AdvisoryError> {
        if !bounded_token(&metric, 32)
            || !bounded_reference(&version, 32)
            || vector.is_empty()
            || vector.len() > 256
            || !vector.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(AdvisoryError::InvalidSeverity);
        }
        Ok(Self {
            metric,
            version,
            vector,
            source,
        })
    }
}

/// Canonical immutable advisory snapshot accepted after normalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdvisorySnapshot {
    /// Immutable snapshot identity.
    pub id: SnapshotId,
    /// Idempotent acquisition identity.
    pub acquisition_id: AcquisitionId,
    /// Digest of complete normalization input.
    pub input_digest: Sha256Digest,
    /// Pinned source provenance.
    pub source: AdvisorySource,
    /// Application-supplied acquisition time.
    pub acquired_at_ms: u64,
    /// Source-declared publication time.
    pub published_at_ms: Option<u64>,
    /// Source-declared modification time.
    pub modified_at_ms: Option<u64>,
    /// Separately classified raw observation artifact.
    pub raw: AdvisoryArtifactRef,
    /// Separately classified canonical snapshot artifact.
    pub canonical: AdvisoryArtifactRef,
    /// Bounded observed advisory aliases.
    pub aliases: BTreeSet<String>,
    /// Ecosystem-preserving affected ranges.
    pub affected: Vec<AffectedRange>,
    /// Attributed severity observations.
    pub severity: Vec<SeverityVector>,
}

/// Stable normalization failure safe to expose without raw source payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalizationReason {
    /// Input did not satisfy its declared schema.
    MalformedSchema,
    /// Raw source exceeded the admission limit.
    OversizedSource,
    /// Source time was invalid or outside policy bounds.
    InvalidTimestamp,
    /// Source identifier or reference was malformed.
    InvalidReference,
    /// Affected range could not be represented safely.
    InvalidRange,
    /// Severity metric provenance was malformed.
    InvalidSeverity,
    /// Alias candidates could not be merged automatically.
    AliasAmbiguous,
}

/// Immutable failed acquisition fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizationFailure {
    /// Stable immutable failure identity.
    pub id: FailureId,
    /// Acquisition attempt that failed.
    pub acquisition_id: AcquisitionId,
    /// Digest of exact failed input.
    pub input_digest: Sha256Digest,
    /// Pinned source provenance.
    pub source: AdvisorySource,
    /// Stable safe failure reason.
    pub reason: NormalizationReason,
    /// Application-supplied observation time.
    pub observed_at_ms: u64,
}

/// Append-only aggregate history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdvisoryFact {
    /// A canonical immutable snapshot was accepted.
    SnapshotRecorded {
        /// Accepted snapshot.
        snapshot_id: SnapshotId,
    },
    /// A source reported withdrawal of an existing snapshot.
    WithdrawalObserved {
        /// Snapshot whose source advisory was withdrawn.
        snapshot_id: SnapshotId,
        /// Source making the observation.
        source: AdvisorySource,
        /// Application-supplied observation time.
        observed_at_ms: u64,
    },
    /// An observed alias was resolved by policy or review.
    AliasResolved {
        /// Canonical alias spelling.
        alias: String,
        /// Selected attributed advisory identity.
        selected: AdvisorySource,
    },
    /// A bounded source observation failed normalization.
    NormalizationFailed {
        /// Immutable failure fact.
        failure_id: FailureId,
    },
}

/// Sole advisory history aggregate.
#[derive(Clone, Debug)]
pub struct AdvisoryRecord {
    organization_id: OrganizationId,
    id: AdvisoryRecordId,
    snapshots: BTreeMap<SnapshotId, AdvisorySnapshot>,
    acquisitions: BTreeMap<AcquisitionId, Sha256Digest>,
    failures: BTreeMap<FailureId, NormalizationFailure>,
    aliases: BTreeMap<String, BTreeSet<AdvisorySource>>,
    resolved_aliases: BTreeMap<String, AdvisorySource>,
    facts: Vec<AdvisoryFact>,
    pending: Vec<AdvisoryFact>,
}

impl AdvisoryRecord {
    /// Creates an empty organization-owned advisory history.
    #[must_use]
    pub fn new(organization_id: OrganizationId, id: AdvisoryRecordId) -> Self {
        Self {
            organization_id,
            id,
            snapshots: BTreeMap::new(),
            acquisitions: BTreeMap::new(),
            failures: BTreeMap::new(),
            aliases: BTreeMap::new(),
            resolved_aliases: BTreeMap::new(),
            facts: Vec::new(),
            pending: Vec::new(),
        }
    }
    /// Returns the immutable tenant boundary.
    #[must_use]
    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }
    /// Returns the aggregate identity.
    #[must_use]
    pub fn id(&self) -> &AdvisoryRecordId {
        &self.id
    }
    /// Records a new immutable snapshot or returns the exact prior retry.
    ///
    /// # Errors
    /// Rejects invalid artifact bindings, aliases, or conflicting retry/history IDs.
    pub fn record_snapshot(
        &mut self,
        snapshot: AdvisorySnapshot,
    ) -> Result<AdvisorySnapshot, AdvisoryError> {
        validate_snapshot(&snapshot)?;
        if let Some(digest) = self.acquisitions.get(&snapshot.acquisition_id) {
            if digest != &snapshot.input_digest {
                return Err(AdvisoryError::IdempotencyConflict);
            }
            return self
                .snapshots
                .values()
                .find(|s| s.acquisition_id == snapshot.acquisition_id)
                .cloned()
                .ok_or(AdvisoryError::InvariantViolation);
        }
        if self.snapshots.contains_key(&snapshot.id) {
            return Err(AdvisoryError::ImmutableHistoryConflict);
        }
        for alias in &snapshot.aliases {
            validate_alias(alias)?;
            self.aliases
                .entry(alias.clone())
                .or_default()
                .insert(snapshot.source.clone());
        }
        self.acquisitions
            .insert(snapshot.acquisition_id.clone(), snapshot.input_digest);
        self.snapshots.insert(snapshot.id.clone(), snapshot.clone());
        self.append(AdvisoryFact::SnapshotRecorded {
            snapshot_id: snapshot.id.clone(),
        });
        Ok(snapshot)
    }
    /// Adds a withdrawal observation without modifying any snapshot.
    ///
    /// # Errors
    /// Returns [`AdvisoryError::SnapshotNotFound`] for an unknown snapshot.
    pub fn record_withdrawal(
        &mut self,
        snapshot_id: &SnapshotId,
        source: AdvisorySource,
        observed_at_ms: u64,
    ) -> Result<(), AdvisoryError> {
        if !self.snapshots.contains_key(snapshot_id) {
            return Err(AdvisoryError::SnapshotNotFound);
        }
        let fact = AdvisoryFact::WithdrawalObserved {
            snapshot_id: snapshot_id.clone(),
            source,
            observed_at_ms,
        };
        if !self.facts.contains(&fact) {
            self.append(fact);
        }
        Ok(())
    }
    /// Records one candidate mapping; multiple sources remain ambiguous.
    ///
    /// # Errors
    /// Returns [`AdvisoryError::InvalidAlias`] for malformed aliases.
    pub fn observe_alias(
        &mut self,
        alias: String,
        candidate: AdvisorySource,
    ) -> Result<(), AdvisoryError> {
        validate_alias(&alias)?;
        self.aliases.entry(alias).or_default().insert(candidate);
        Ok(())
    }
    /// Resolves only an unambiguous alias automatically.
    ///
    /// # Errors
    /// Returns a stable absent or ambiguous alias error.
    pub fn resolve_alias(&mut self, alias: &str) -> Result<AdvisorySource, AdvisoryError> {
        let candidates = self
            .aliases
            .get(alias)
            .ok_or(AdvisoryError::AliasNotFound)?;
        if candidates.len() != 1 {
            return Err(AdvisoryError::AliasAmbiguous);
        }
        let selected = candidates
            .iter()
            .next()
            .cloned()
            .ok_or(AdvisoryError::AliasNotFound)?;
        self.resolved_aliases
            .insert(alias.to_owned(), selected.clone());
        self.append(AdvisoryFact::AliasResolved {
            alias: alias.to_owned(),
            selected: selected.clone(),
        });
        Ok(selected)
    }
    /// Records an explicit reviewed choice only if it is an observed candidate.
    ///
    /// # Errors
    /// Rejects a choice that was not observed for this alias.
    pub fn resolve_alias_explicitly(
        &mut self,
        alias: &str,
        selected: &AdvisorySource,
    ) -> Result<(), AdvisoryError> {
        if !self
            .aliases
            .get(alias)
            .is_some_and(|set| set.contains(selected))
        {
            return Err(AdvisoryError::InvalidAliasSelection);
        }
        if self.resolved_aliases.get(alias) == Some(selected) {
            return Ok(());
        }
        self.resolved_aliases
            .insert(alias.to_owned(), selected.clone());
        self.append(AdvisoryFact::AliasResolved {
            alias: alias.to_owned(),
            selected: selected.clone(),
        });
        Ok(())
    }
    /// Records a bounded normalization failure idempotently.
    ///
    /// # Errors
    /// Rejects conflicting failure or acquisition replay identities.
    pub fn record_failure(&mut self, failure: NormalizationFailure) -> Result<(), AdvisoryError> {
        if let Some(existing) = self.failures.get(&failure.id) {
            return if existing == &failure {
                Ok(())
            } else {
                Err(AdvisoryError::IdempotencyConflict)
            };
        }
        if let Some(digest) = self.acquisitions.get(&failure.acquisition_id) {
            if digest != &failure.input_digest {
                return Err(AdvisoryError::IdempotencyConflict);
            }
            return if self.failures.values().any(|existing| existing == &failure) {
                Ok(())
            } else {
                Err(AdvisoryError::IdempotencyConflict)
            };
        }
        self.acquisitions
            .insert(failure.acquisition_id.clone(), failure.input_digest);
        self.failures.insert(failure.id.clone(), failure.clone());
        self.append(AdvisoryFact::NormalizationFailed {
            failure_id: failure.id,
        });
        Ok(())
    }
    /// Iterates immutable snapshots in stable identity order.
    pub fn snapshots(&self) -> impl Iterator<Item = &AdvisorySnapshot> {
        self.snapshots.values()
    }
    /// Returns complete append-only aggregate history.
    #[must_use]
    pub fn history(&self) -> &[AdvisoryFact] {
        &self.facts
    }
    /// Drains new facts for atomic state/outbox persistence.
    pub fn take_pending_facts(&mut self) -> Vec<AdvisoryFact> {
        std::mem::take(&mut self.pending)
    }
    fn append(&mut self, fact: AdvisoryFact) {
        self.facts.push(fact.clone());
        self.pending.push(fact);
    }
}

/// Stable advisory invariant failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdvisoryError {
    /// A bounded source or identity value was malformed.
    InvalidValue,
    /// Ecosystem range could not be represented faithfully.
    InvalidRange,
    /// Severity provenance or vector was malformed.
    InvalidSeverity,
    /// Alias syntax was malformed.
    InvalidAlias,
    /// Snapshot artifact, size, classification, or time binding was invalid.
    InvalidArtifactBinding,
    /// Replay identity was reused for different canonical input.
    IdempotencyConflict,
    /// Existing immutable history identity cannot be replaced.
    ImmutableHistoryConflict,
    /// Referenced snapshot was absent.
    SnapshotNotFound,
    /// Alias has no observed candidates.
    AliasNotFound,
    /// Alias has multiple candidates and cannot merge automatically.
    AliasAmbiguous,
    /// Explicit selection was not an observed candidate.
    InvalidAliasSelection,
    /// Persisted state violated an internal history invariant.
    InvariantViolation,
}
impl fmt::Display for AdvisoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for AdvisoryError {}

fn validate_snapshot(snapshot: &AdvisorySnapshot) -> Result<(), AdvisoryError> {
    if snapshot.raw.digest == snapshot.canonical.digest
        || snapshot.raw.size_bytes > 10 * 1024 * 1024
        || snapshot.canonical.size_bytes > 2 * 1024 * 1024
        || snapshot.raw.classification < snapshot.canonical.classification
        || snapshot.affected.len() > 1024
        || snapshot.aliases.len() > 512
        || snapshot.severity.len() > 64
        || snapshot
            .modified_at_ms
            .zip(snapshot.published_at_ms)
            .is_some_and(|(m, p)| m < p)
    {
        return Err(AdvisoryError::InvalidArtifactBinding);
    }
    for alias in &snapshot.aliases {
        validate_alias(alias)?;
    }
    Ok(())
}
fn validate_alias(value: &str) -> Result<(), AdvisoryError> {
    if bounded_reference(value, 128) {
        Ok(())
    } else {
        Err(AdvisoryError::InvalidAlias)
    }
}
fn bounded_token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
        })
}
fn bounded_reference(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && value.bytes().all(|b| b.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn source(n: &str) -> AdvisorySource {
        AdvisorySource::new("fixture".into(), n.into(), "fixture-v1".into()).unwrap()
    }
    fn artifact(bytes: &[u8], class: DataClass) -> AdvisoryArtifactRef {
        AdvisoryArtifactRef {
            digest: Sha256Digest::of_bytes(bytes),
            classification: class,
            schema_name: SchemaName::parse("dev.cauterizer.advisory.snapshot").unwrap(),
            schema_version: SchemaVersion::parse("1.0.0").unwrap(),
            size_bytes: bytes.len() as u64,
        }
    }
    fn snapshot(n: u64) -> AdvisorySnapshot {
        AdvisorySnapshot {
            id: SnapshotId::new(&format!("{n:08}")).unwrap(),
            acquisition_id: AcquisitionId::new(&format!("{n:08}")).unwrap(),
            input_digest: Sha256Digest::of_bytes(format!("input{n}")),
            source: source(&format!("CVE-{n}")),
            acquired_at_ms: n,
            published_at_ms: Some(n),
            modified_at_ms: Some(n),
            raw: artifact(format!("raw{n}").as_bytes(), DataClass::Confidential),
            canonical: artifact(format!("canonical{n}").as_bytes(), DataClass::Public),
            aliases: BTreeSet::from([format!("CVE-{n}")]),
            affected: vec![
                AffectedRange::new(
                    Ecosystem::new("cargo".into()).unwrap(),
                    "crate".into(),
                    "0".into(),
                    Some("1.2.3".into()),
                    None,
                )
                .unwrap(),
            ],
            severity: vec![
                SeverityVector::new(
                    "cvss".into(),
                    "3.1".into(),
                    "CVSS:3.1/AV:N".into(),
                    source("NVD"),
                )
                .unwrap(),
            ],
        }
    }
    #[test]
    fn snapshots_and_withdrawals_are_append_only() {
        let mut r = AdvisoryRecord::new(
            OrganizationId::new("00000000").unwrap(),
            AdvisoryRecordId::new("00000000").unwrap(),
        );
        let first = snapshot(1);
        r.record_snapshot(first.clone()).unwrap();
        r.record_withdrawal(&first.id, source("CVE-1"), 2).unwrap();
        r.record_snapshot(snapshot(2)).unwrap();
        assert_eq!(r.snapshots().count(), 2);
        assert!(matches!(
            r.history()[1],
            AdvisoryFact::WithdrawalObserved { .. }
        ));
    }
    #[test]
    fn acquisition_retry_is_idempotent_and_conflict_rejected() {
        let mut r = AdvisoryRecord::new(
            OrganizationId::new("00000000").unwrap(),
            AdvisoryRecordId::new("00000000").unwrap(),
        );
        let first = snapshot(1);
        assert_eq!(
            r.record_snapshot(first.clone()).unwrap(),
            r.record_snapshot(first.clone()).unwrap()
        );
        let mut conflict = first;
        conflict.input_digest = Sha256Digest::of_bytes(b"other");
        assert_eq!(
            r.record_snapshot(conflict),
            Err(AdvisoryError::IdempotencyConflict)
        );
    }
    #[test]
    fn ambiguous_aliases_never_auto_merge() {
        let mut r = AdvisoryRecord::new(
            OrganizationId::new("00000000").unwrap(),
            AdvisoryRecordId::new("00000000").unwrap(),
        );
        for count in 2..20 {
            let alias = format!("CVE-{count}");
            for candidate in 0..count {
                r.observe_alias(alias.clone(), source(&format!("SRC-{candidate}")))
                    .unwrap();
            }
            assert_eq!(r.resolve_alias(&alias), Err(AdvisoryError::AliasAmbiguous));
        }
    }
    #[test]
    fn ranges_and_severity_preserve_provenance() {
        let value = snapshot(1);
        assert_eq!(value.affected[0].ecosystem.as_str(), "cargo");
        assert_eq!(value.severity[0].version, "3.1");
        assert_eq!(value.severity[0].source.adapter_revision, "fixture-v1");
    }
    #[test]
    fn malformed_and_oversized_values_fail_boundedly() {
        assert!(AdvisorySource::new("UPPER".into(), "id".into(), "v".into()).is_err());
        assert!(
            AffectedRange::new(
                Ecosystem::new("cargo".into()).unwrap(),
                "x".repeat(300),
                "0".into(),
                None,
                None
            )
            .is_err()
        );
        for length in [0, 129, 1024] {
            assert_eq!(
                validate_alias(&"x".repeat(length)).is_ok(),
                (1..=128).contains(&length)
            );
        }
    }
}
