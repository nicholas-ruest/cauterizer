//! Closed versioned coordination facts which never claim another context's result.
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{
    AggregateSequence, CausationId, ContextQualifiedId, CorrelationId, OrganizationId,
};
use cauterizer_syntax::schema::{SchemaName, SchemaVersion};
use cauterizer_syntax::time::UtcInstant;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Current contract revision.
pub const CONTRACT_VERSION: &str = "1.0.0";
/// Stable event schema.
pub const EVENT_SCHEMA_NAME: &str = "dev.cauterizer.remediation-runs.event";

/// Solver/verifier separation declaration.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceModeV1 {
    /// Required separation is declared.
    Conformant,
    /// Separation cannot be demonstrated.
    NonConformant,
}

/// Immutable cross-context inputs bound exactly once.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunInputsV1 {
    /// Advisory snapshot reference.
    pub advisory_snapshot_id: ContextQualifiedId,
    /// Authorized canonical advisory digest.
    pub advisory_snapshot_digest: Sha256Digest,
    /// Authorized immutable target resolution.
    pub target_resolution_id: ContextQualifiedId,
    /// Committed acquisition bundle digest.
    pub acquisition_artifact_digest: Sha256Digest,
    /// Immutable run policy revision.
    pub policy_version: SchemaVersion,
    /// Information-flow declaration.
    pub conformance_mode: ConformanceModeV1,
    /// Valid worst-case cost reservation.
    pub budget_reservation_id: ContextQualifiedId,
}

/// Append-only run-owned event envelope.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationRunEventV1 {
    /// Schema identity.
    pub schema_name: SchemaName,
    /// Schema revision.
    pub schema_version: SchemaVersion,
    /// Owning tenant.
    pub organization_id: OrganizationId,
    /// Run identity.
    pub run_id: ContextQualifiedId,
    /// Aggregate order.
    pub aggregate_sequence: AggregateSequence,
    /// Event identity.
    pub event_id: ContextQualifiedId,
    /// Canonical event time.
    pub occurred_at: UtcInstant,
    /// Trace correlation.
    pub correlation_id: CorrelationId,
    /// Causing command/authenticated fact.
    pub causation_id: CausationId,
    /// Run-owned payload.
    pub payload: RemediationRunEventPayloadV1,
}

/// Requests and run-owned lifecycle facts; foreign completion claims are absent.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum RemediationRunEventPayloadV1 {
    /// Run identity created.
    RemediationRunCreated,
    /// Immutable inputs bound.
    RunInputsBound {
        /// Exact inputs.
        inputs: RunInputsV1,
    },
    /// Baseline work requested, not completed.
    BaselineRequested {
        /// Request identity.
        request_id: ContextQualifiedId,
    },
    /// Proposal work requested, not completed.
    ProposalRequested {
        /// Request identity.
        request_id: ContextQualifiedId,
    },
    /// Assessment requested without asserting a verdict.
    AssessmentRequested {
        /// Request identity.
        request_id: ContextQualifiedId,
    },
    /// Evidence requested without asserting a bundle.
    EvidenceRequested {
        /// Request identity.
        request_id: ContextQualifiedId,
    },
    /// Run became terminally cancelled.
    RunCancelled {
        /// Stable reason.
        reason_code: String,
    },
    /// Run-owned event chain sealed.
    RunRecordSealed {
        /// Complete event-chain digest.
        event_chain_digest: Sha256Digest,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use schemars::schema_for;
    use serde_json::{Value, json};
    #[test]
    fn schema_is_closed_and_request_wire_is_stable() {
        let schema = serde_json::to_value(schema_for!(RemediationRunEventV1)).unwrap();
        assert_eq!(schema["additionalProperties"], Value::Bool(false));
        assert_eq!(
            serde_json::to_value(RemediationRunEventPayloadV1::AssessmentRequested {
                request_id: "assessment-request_00000000".parse().unwrap()
            })
            .unwrap(),
            json!({"type":"assessment_requested","data":{"request_id":"assessment-request_00000000"}})
        );
    }
    #[test]
    fn schema_cannot_fabricate_foreign_results() {
        let schema = serde_json::to_string(&schema_for!(RemediationRunEventV1))
            .unwrap()
            .to_ascii_lowercase();
        for forbidden in [
            "execution_observed",
            "patch_proposed",
            "candidate_assessed",
            "evidence_bundle_finalized",
            "verified_for_fixture",
        ] {
            assert!(
                !schema.contains(forbidden),
                "fabricated authority: {forbidden}"
            );
        }
        assert!(
            serde_json::from_value::<RemediationRunEventPayloadV1>(
                json!({"type":"candidate_assessed","data":{"verdict":"verified_for_fixture"}})
            )
            .is_err()
        );
    }
}
