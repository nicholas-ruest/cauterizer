//! Closed, versioned Advisory Intake published language.
//!
//! Raw and canonical bodies remain separately classified artifacts. Published
//! facts contain only immutable descriptors and normalized consumer metadata.

use cauterizer_syntax::classification::DataClass;
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{
    AggregateSequence, CausationId, ContextQualifiedId, CorrelationId, OrganizationId,
};
use cauterizer_syntax::schema::{SchemaName, SchemaVersion};
use cauterizer_syntax::time::UtcInstant;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Current semantic contract revision.
pub const CONTRACT_VERSION: &str = "1.0.0";
/// Stable event schema identity.
pub const EVENT_SCHEMA_NAME: &str = "dev.cauterizer.advisory-intake.event";

/// Authorized immutable artifact metadata; it never embeds artifact content.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryArtifactDescriptorV1 {
    /// Tenant owning the descriptor and payload authorization.
    pub organization_id: OrganizationId,
    /// Server-computed content digest.
    pub digest: Sha256Digest,
    /// Validated payload byte length.
    pub size_bytes: u64,
    /// Validated media type.
    pub media_type: String,
    /// Immutable payload schema identity.
    pub schema_name: SchemaName,
    /// Immutable payload schema revision.
    pub schema_version: SchemaVersion,
    /// Data handling class enforced by artifact reads.
    pub classification: DataClass,
}

/// Ecosystem-preserving affected-package range.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AffectedRangeV1 {
    /// Canonical ecosystem vocabulary, not a provider SDK enum.
    pub ecosystem: String,
    /// Ecosystem-native package identity.
    pub package: String,
    /// Version-range scheme and version retained verbatim after validation.
    pub range_type: String,
    /// Canonical normalized range expression.
    pub range: String,
}

/// Severity retaining metric and revision provenance.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeverityV1 {
    /// Metric family, such as `CVSS`.
    pub metric: String,
    /// Exact metric revision, such as `3.1`.
    pub metric_version: String,
    /// Validated vector or source-native score representation.
    pub vector: String,
}

/// Immutable normalized snapshot safe for downstream selection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisorySnapshotV1 {
    /// Tenant scope.
    pub organization_id: OrganizationId,
    /// Immutable snapshot identity; updates create a new identity.
    pub snapshot_id: ContextQualifiedId,
    /// Stable source observation identity without upstream types.
    pub source_observation_id: String,
    /// Validated primary advisory identifier.
    pub advisory_id: String,
    /// Sorted aliases; ambiguity is represented rather than auto-merged.
    pub aliases: Vec<String>,
    /// Ecosystem-preserving affected ranges.
    pub affected: Vec<AffectedRangeV1>,
    /// Severity observations with complete provenance.
    pub severities: Vec<SeverityV1>,
    /// Separately classified immutable raw-source descriptor.
    pub raw_artifact: AdvisoryArtifactDescriptorV1,
    /// Separately classified canonical-normalization descriptor.
    pub canonical_artifact: AdvisoryArtifactDescriptorV1,
    /// Canonical snapshot time supplied by the application clock.
    pub observed_at: UtcInstant,
}

/// Stable normalization rejection vocabulary.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalizationFailureReasonV1 {
    /// Input exceeded its declared byte/reference bound.
    InputLimitExceeded,
    /// Input did not match the supported source schema.
    MalformedSource,
    /// Required attribution was absent.
    MissingProvenance,
    /// Alias evidence was ambiguous and required human resolution.
    AmbiguousAlias,
    /// Range syntax was invalid for its declared ecosystem.
    InvalidAffectedRange,
    /// Severity metric or revision was unsupported/malformed.
    InvalidSeverity,
}

/// Versioned integration-event envelope.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryIntakeEventV1 {
    /// Immutable schema identity.
    pub schema_name: SchemaName,
    /// Semantic schema revision.
    pub schema_version: SchemaVersion,
    /// Owning tenant.
    pub organization_id: OrganizationId,
    /// Advisory aggregate identity.
    pub aggregate_id: ContextQualifiedId,
    /// Aggregate ordering sequence.
    pub aggregate_sequence: AggregateSequence,
    /// Globally unique event identity.
    pub event_id: ContextQualifiedId,
    /// Canonical occurrence time.
    pub occurred_at: UtcInstant,
    /// End-to-end trace.
    pub correlation_id: CorrelationId,
    /// Command or event causing this fact.
    pub causation_id: CausationId,
    /// Consumer-required fact.
    pub payload: AdvisoryIntakeEventPayloadV1,
}

/// Published immutable Advisory Intake facts.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum AdvisoryIntakeEventPayloadV1 {
    /// A complete immutable normalized snapshot was accepted.
    AdvisorySnapshotted {
        /// Accepted snapshot.
        snapshot: Box<AdvisorySnapshotV1>,
    },
    /// A withdrawal observation appended without erasing prior snapshots.
    AdvisoryWithdrawalObserved {
        /// Snapshot to which the observed withdrawal applies.
        snapshot_id: ContextQualifiedId,
        /// Immutable withdrawal-source descriptor.
        observation_artifact: AdvisoryArtifactDescriptorV1,
    },
    /// Human/policy resolution recorded one alias relationship.
    AdvisoryAliasResolved {
        /// First advisory snapshot.
        snapshot_id: ContextQualifiedId,
        /// Resolved alias spelling.
        alias: String,
    },
    /// Untrusted source input failed normalization safely.
    AdvisoryNormalizationFailed {
        /// Source observation identifier safe for audit.
        source_observation_id: String,
        /// Stable bounded failure reason.
        reason: NormalizationFailureReasonV1,
        /// Raw descriptor when quarantine validation completed; never raw bytes.
        raw_artifact: Option<AdvisoryArtifactDescriptorV1>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use cauterizer_syntax::schema::{SchemaChange, classify_schema_change};
    use schemars::schema_for;
    use serde_json::{Value, json};

    fn artifact(classification: DataClass, bytes: &[u8]) -> AdvisoryArtifactDescriptorV1 {
        AdvisoryArtifactDescriptorV1 {
            organization_id: "org_00000000".parse().unwrap(),
            digest: Sha256Digest::of_bytes(bytes),
            size_bytes: bytes.len() as u64,
            media_type: "application/json".into(),
            schema_name: SchemaName::parse("dev.cauterizer.advisory.normalized").unwrap(),
            schema_version: SchemaVersion::parse("1.0.0").unwrap(),
            classification,
        }
    }

    fn snapshot() -> AdvisorySnapshotV1 {
        AdvisorySnapshotV1 {
            organization_id: "org_00000000".parse().unwrap(),
            snapshot_id: "advisory-snapshot_00000000".parse().unwrap(),
            source_observation_id: "fixture-2026-0001".into(),
            advisory_id: "CVE-2026-0001".into(),
            aliases: vec!["GHSA-aaaa-bbbb-cccc".into()],
            affected: vec![AffectedRangeV1 {
                ecosystem: "crates.io".into(),
                package: "widget".into(),
                range_type: "semver".into(),
                range: ">=1.0.0,<1.2.3".into(),
            }],
            severities: vec![SeverityV1 {
                metric: "CVSS".into(),
                metric_version: "3.1".into(),
                vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into(),
            }],
            raw_artifact: artifact(DataClass::Internal, b"raw"),
            canonical_artifact: artifact(DataClass::Public, b"canonical"),
            observed_at: UtcInstant::parse("2026-07-23T00:00:00Z").unwrap(),
        }
    }

    #[test]
    fn golden_normalization_fixture_is_stable() {
        assert_eq!(
            serde_json::to_value(snapshot()).unwrap(),
            json!({
                "organization_id":"org_00000000",
                "snapshot_id":"advisory-snapshot_00000000",
                "source_observation_id":"fixture-2026-0001",
                "advisory_id":"CVE-2026-0001",
                "aliases":["GHSA-aaaa-bbbb-cccc"],
                "affected":[{"ecosystem":"crates.io","package":"widget","range_type":"semver","range":">=1.0.0,<1.2.3"}],
                "severities":[{"metric":"CVSS","metric_version":"3.1","vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                "raw_artifact":{"organization_id":"org_00000000","digest":Sha256Digest::of_bytes(b"raw").to_string(),"size_bytes":3,"media_type":"application/json","schema_name":"dev.cauterizer.advisory.normalized","schema_version":"1.0.0","classification":"internal"},
                "canonical_artifact":{"organization_id":"org_00000000","digest":Sha256Digest::of_bytes(b"canonical").to_string(),"size_bytes":9,"media_type":"application/json","schema_name":"dev.cauterizer.advisory.normalized","schema_version":"1.0.0","classification":"public"},
                "observed_at":"2026-07-23T00:00:00Z"
            })
        );
    }

    #[test]
    fn schemas_are_closed_and_required_descriptor_removal_is_breaking() {
        let current = serde_json::to_value(schema_for!(AdvisorySnapshotV1)).unwrap();
        assert_eq!(current["additionalProperties"], Value::Bool(false));
        let mut changed = current.clone();
        changed["required"]
            .as_array_mut()
            .unwrap()
            .retain(|v| v != "canonical_artifact");
        assert_eq!(
            classify_schema_change(&current, &changed),
            SchemaChange::SecurityCriticalBreaking
        );
        assert_eq!(
            serde_json::to_value(schema_for!(AdvisoryArtifactDescriptorV1)).unwrap()["additionalProperties"],
            Value::Bool(false)
        );
    }

    #[test]
    fn published_contracts_are_descriptor_only_and_privacy_classified() {
        let wire = serde_json::to_value(snapshot()).unwrap();
        for forbidden in [
            "raw_content",
            "canonical_content",
            "description",
            "details",
            "payload",
            "credits",
        ] {
            assert!(
                wire.get(forbidden).is_none(),
                "leaked content field {forbidden}"
            );
        }
        assert_eq!(wire["raw_artifact"]["classification"], "internal");
        assert_eq!(wire["canonical_artifact"]["classification"], "public");
    }

    #[test]
    fn unknown_fields_reasons_and_source_sdk_types_fail_closed() {
        let mut wire = serde_json::to_value(snapshot()).unwrap();
        wire.as_object_mut()
            .unwrap()
            .insert("osv_record".into(), json!({"details":"secret"}));
        assert!(serde_json::from_value::<AdvisorySnapshotV1>(wire).is_err());
        assert!(
            serde_json::from_str::<NormalizationFailureReasonV1>("\"future_unknown\"").is_err()
        );
        let schema = serde_json::to_string(&schema_for!(AdvisoryIntakeEventV1))
            .unwrap()
            .to_ascii_lowercase();
        for forbidden in ["osv::", "osvclient", "github_advisory", "provider_response"] {
            assert!(
                !schema.contains(forbidden),
                "source SDK type leaked: {forbidden}"
            );
        }
    }

    #[test]
    fn withdrawal_is_an_append_only_fact_referencing_prior_snapshot() {
        let payload = AdvisoryIntakeEventPayloadV1::AdvisoryWithdrawalObserved {
            snapshot_id: snapshot().snapshot_id,
            observation_artifact: artifact(DataClass::Internal, b"withdrawn"),
        };
        let wire = serde_json::to_value(payload).unwrap();
        assert_eq!(wire["type"], "advisory_withdrawal_observed");
        assert!(wire["data"].get("snapshot_id").is_some());
        assert!(wire["data"].get("deleted_snapshot").is_none());
    }
}
