//! Same-context commit adapter for separately governed advisory artifacts.

#![forbid(unsafe_code)]

use cauterizer_advisory_intake::application::fixture::{ArtifactClass, NormalizedFixture};
use cauterizer_infrastructure::artifacts::{
    AccessDomain, ArtifactDescriptor, ArtifactError, ArtifactMetadata, ArtifactStore, QuarantineId,
    QuarantineUpload,
};
use cauterizer_syntax::classification::{DataClass, RetentionMetadata};
use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
use cauterizer_syntax::schema::{SchemaName, SchemaVersion};
use cauterizer_syntax::time::UtcInstant;

/// Governance inputs supplied by deployment policy, never by the source fixture.
pub struct AdvisoryArtifactPolicy {
    /// Owning organization.
    pub organization_id: OrganizationId,
    /// Residency, retention, and legal-hold decision.
    pub retention: RetentionMetadata,
    /// Envelope key reference.
    pub encryption_key_ref: ContextQualifiedId,
    /// Canonical commit time.
    pub created_at: UtcInstant,
    /// Canonical retention day.
    pub created_day: u64,
}

/// Pair of committed content addresses safe for aggregate references.
pub struct CommittedAdvisoryArtifacts {
    /// Exact raw source observation.
    pub raw: ArtifactDescriptor,
    /// Deterministically normalized canonical representation.
    pub canonical: ArtifactDescriptor,
}

/// Quarantines, validates, and commits raw and canonical bytes independently.
///
/// # Errors
/// Returns a stable artifact error and never returns a descriptor for a failed
/// or partial upload. A caller may abandon the other quarantine on failure.
pub fn commit_normalized<S: ArtifactStore>(
    store: &mut S,
    fixture: &NormalizedFixture,
    policy: &AdvisoryArtifactPolicy,
    raw_quarantine: &QuarantineId,
    canonical_quarantine: &QuarantineId,
) -> Result<CommittedAdvisoryArtifacts, ArtifactError> {
    let raw = commit_one(store, &fixture.raw, policy, raw_quarantine)?;
    let canonical = commit_one(store, &fixture.canonical, policy, canonical_quarantine)?;
    Ok(CommittedAdvisoryArtifacts { raw, canonical })
}

fn commit_one<S: ArtifactStore>(
    store: &mut S,
    artifact: &cauterizer_advisory_intake::application::fixture::ClassifiedArtifact,
    policy: &AdvisoryArtifactPolicy,
    quarantine: &QuarantineId,
) -> Result<ArtifactDescriptor, ArtifactError> {
    let (schema, producer) = match artifact.class {
        ArtifactClass::PublicSourceRaw => {
            ("dev.cauterizer.advisory-intake.raw", "advisory-fixture-raw")
        }
        ArtifactClass::PublicCanonical => (
            "dev.cauterizer.advisory-intake.canonical",
            "advisory-fixture-normalizer",
        ),
    };
    store.begin_quarantine(
        quarantine.clone(),
        QuarantineUpload {
            expected_digest: artifact.digest,
            expected_size: u64::try_from(artifact.bytes.len())
                .map_err(|_| ArtifactError::SizeMismatch)?,
            metadata: ArtifactMetadata {
                organization_id: policy.organization_id.clone(),
                classification: DataClass::Public,
                retention: policy.retention.clone(),
                access_domain: AccessDomain::Acquisition,
                media_type: "application/json".into(),
                schema_name: SchemaName::parse(schema)
                    .map_err(|_| ArtifactError::InvalidMetadata)?,
                schema_version: SchemaVersion::parse("1.0.0")
                    .map_err(|_| ArtifactError::InvalidMetadata)?,
                encryption_key_ref: policy.encryption_key_ref.clone(),
                producer: producer.into(),
                created_at: policy.created_at.clone(),
                created_day: policy.created_day,
            },
        },
    )?;
    store.write_quarantine(quarantine, &artifact.bytes)?;
    store.validate_and_commit(quarantine)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cauterizer_advisory_intake::application::fixture::{FixtureLimits, LocalFixtureAdapter};
    use cauterizer_infrastructure::artifacts::{ArtifactReadAuthorization, InMemoryArtifactStore};
    use cauterizer_syntax::classification::RegionCode;

    #[test]
    fn raw_and_canonical_are_separate_committed_verified_artifacts() {
        let fixture = LocalFixtureAdapter::new(FixtureLimits::default())
            .normalize(
                br#"{"schema_version":1,"id":"OSV-1","modified_at_epoch_seconds":1}"#,
                1,
            )
            .unwrap();
        let organization = OrganizationId::new("00000000").unwrap();
        let policy = AdvisoryArtifactPolicy {
            organization_id: organization.clone(),
            retention: RetentionMetadata::new(RegionCode::parse("local-1").unwrap(), 30, false)
                .unwrap(),
            encryption_key_ref: ContextQualifiedId::new("key", "00000000").unwrap(),
            created_at: UtcInstant::parse("2026-07-23T00:00:00Z").unwrap(),
            created_day: 1,
        };
        let mut store = InMemoryArtifactStore::default();
        let committed = commit_normalized(
            &mut store,
            &fixture,
            &policy,
            &QuarantineId::new("00000001").unwrap(),
            &QuarantineId::new("00000002").unwrap(),
        )
        .unwrap();
        assert_ne!(committed.raw.digest, committed.canonical.digest);
        let authorization = ArtifactReadAuthorization {
            organization_id: organization,
            access_domain: AccessDomain::Acquisition,
            maximum_classification: DataClass::Public,
        };
        assert_eq!(
            store
                .read_verified(committed.raw.digest, &authorization)
                .unwrap(),
            fixture.raw.bytes
        );
        assert_eq!(
            store
                .read_verified(committed.canonical.digest, &authorization)
                .unwrap(),
            fixture.canonical.bytes
        );
    }
}
