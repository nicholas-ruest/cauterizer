//! Closed signed declarative protocol for ephemeral workers.
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
use cauterizer_syntax::schema::SchemaVersion;
use cauterizer_syntax::time::UtcInstant;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Current worker protocol revision.
pub const PROTOCOL_VERSION: &str = "1.0.0";

/// Physically distinct worker pool/job authority.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobClassV1 {
    /// Restricted network acquisition.
    Acquisition,
    /// Candidate generation without verifier access.
    Solver,
    /// Hermetic independent evaluation.
    Verifier,
}
/// Network authority declared for one lease.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicyV1 {
    /// Only acquisition allowlist proxy may be reached.
    AcquisitionAllowlisted,
    /// No guest egress.
    EgressDenied,
}
/// Narrow worker capability vocabulary.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, JsonSchema, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorkerCapabilityV1 {
    /// Read one declared input digest.
    ReadDeclaredArtifact,
    /// Write observation artifacts only.
    WriteObservation,
    /// Emit bounded heartbeat.
    EmitHeartbeat,
}

/// Immutable verified worker environment.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentEnvelopeV1 {
    /// Content digest of immutable worker image.
    pub image_digest: Sha256Digest,
    /// Digest of the approved dependency/environment bundle.
    pub environment_digest: Sha256Digest,
    /// Backend security profile revision.
    pub sandbox_profile: String,
    /// Whether the backend was qualified to emit conformant receipts.
    pub conformant_backend: bool,
}
/// Externally enforced resource bounds.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimitsV1 {
    /// CPU time milliseconds.
    pub cpu_millis: u64,
    /// Wall time milliseconds.
    pub wall_millis: u64,
    /// Memory bytes.
    pub memory_bytes: u64,
    /// Scratch disk bytes.
    pub disk_bytes: u64,
    /// Process count.
    pub process_count: u32,
    /// Total captured output bytes before truncation.
    pub output_bytes: u64,
}
/// Immutable declarative guest request.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRequestV1 {
    /// Tenant partition.
    pub organization_id: OrganizationId,
    /// Lease identity.
    pub lease_id: ContextQualifiedId,
    /// Unique worker workload identity.
    pub worker_identity: ContextQualifiedId,
    /// Physical job class.
    pub job_class: JobClassV1,
    /// Immutable environment.
    pub environment: EnvironmentEnvelopeV1,
    /// Exact executable and arguments; no shell interpolation.
    pub argv: Vec<String>,
    /// Sanitized deterministic non-secret environment.
    pub environment_variables: BTreeMap<String, String>,
    /// Exact readable artifact digests.
    pub input_artifacts: Vec<Sha256Digest>,
    /// Explicit capability set.
    pub capabilities: Vec<WorkerCapabilityV1>,
    /// Network authority.
    pub network_policy: NetworkPolicyV1,
    /// External resource bounds.
    pub resources: ResourceLimitsV1,
    /// Exclusive lease expiry.
    pub expires_at: UtcInstant,
}

/// Signature over canonical request bytes.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedExecutionRequestV1 {
    /// Protocol revision.
    pub protocol_version: SchemaVersion,
    /// Complete declarative request.
    pub request: ExecutionRequestV1,
    /// Non-secret signing-key reference.
    pub signing_key_id: ContextQualifiedId,
    /// Closed signature algorithm profile.
    pub signature_algorithm: SignatureAlgorithmV1,
    /// Detached signature encoded by the selected signer profile.
    pub signature: String,
}
/// Supported detached-signature algorithms.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithmV1 {
    /// Ed25519 signature over RFC 8785 canonical JSON bytes.
    Ed25519,
}
/// Terminal execution reason; it reports observations without policy authority.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalOutcomeV1 {
    /// Process exited.
    Exited,
    /// External deadline fired.
    TimedOut,
    /// Authorized cancellation.
    Cancelled,
    /// Worker heartbeat/identity was lost.
    WorkerLost,
    /// Admission or supervisor failure.
    Failed,
}
/// Mandatory cleanup result on every terminal path.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupOutcomeV1 {
    /// Ephemeral worker and scratch were removed.
    Confirmed,
    /// Cleanup failed and requires governed intervention.
    Failed,
}
/// Redacted output metadata; raw guest output never enters the protocol.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedOutputV1 {
    /// Digest of bounded redacted stdout artifact.
    pub stdout_digest: Option<Sha256Digest>,
    /// Digest of bounded redacted stderr artifact.
    pub stderr_digest: Option<Sha256Digest>,
    /// Captured bytes across both streams.
    pub captured_bytes: u64,
    /// Whether external enforcement truncated output.
    pub truncated: bool,
}
/// Authoritative signed terminal observation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalReceiptV1 {
    /// Tenant copied from request.
    pub organization_id: OrganizationId,
    /// Lease copied from request.
    pub lease_id: ContextQualifiedId,
    /// Exact allocated worker identity.
    pub worker_identity: ContextQualifiedId,
    /// Observed terminal reason.
    pub outcome: TerminalOutcomeV1,
    /// Mandatory cleanup fact.
    pub cleanup: CleanupOutcomeV1,
    /// Bounded redacted output metadata.
    pub output: RedactedOutputV1,
    /// Observation artifact digests only.
    pub observation_artifacts: Vec<Sha256Digest>,
    /// Backend conformance statement.
    pub conformant: bool,
    /// Canonical completion time.
    pub completed_at: UtcInstant,
    /// Receipt signer reference.
    pub signing_key_id: ContextQualifiedId,
    /// Detached signature.
    pub signature: String,
}

/// Stable protocol validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    /// Missing/invalid bound.
    InvalidResourceLimit,
    /// Request contains secret-like environment.
    SecretEnvironment,
    /// Class and network policy conflict.
    NetworkPolicyMismatch,
    /// Empty/unsafe command.
    InvalidCommand,
    /// Receipt identity differs.
    IdentityMismatch,
    /// Output exceeded declared limit.
    OutputLimitExceeded,
    /// Weak backend claimed conformance.
    InvalidConformance,
}

impl ExecutionRequestV1 {
    /// Validates security-critical admission invariants.
    ///
    /// # Errors
    ///
    /// Rejects absent limits, unsafe commands, secret-like environment names,
    /// or a job-class/network-policy mismatch.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.resources.cpu_millis == 0
            || self.resources.wall_millis == 0
            || self.resources.memory_bytes == 0
            || self.resources.disk_bytes == 0
            || self.resources.process_count == 0
            || self.resources.output_bytes == 0
        {
            return Err(ProtocolError::InvalidResourceLimit);
        }
        if self.argv.is_empty() || self.argv.iter().any(|v| v.is_empty() || v.contains('\0')) {
            return Err(ProtocolError::InvalidCommand);
        }
        if self.environment_variables.keys().any(|key| {
            let key = key.to_ascii_uppercase();
            key.contains("SECRET")
                || key.contains("TOKEN")
                || key.contains("PASSWORD")
                || key.contains("CREDENTIAL")
        }) {
            return Err(ProtocolError::SecretEnvironment);
        }
        if (self.job_class == JobClassV1::Acquisition)
            != (self.network_policy == NetworkPolicyV1::AcquisitionAllowlisted)
        {
            return Err(ProtocolError::NetworkPolicyMismatch);
        }
        Ok(())
    }
}
impl TerminalReceiptV1 {
    /// Validates identity, output, cleanup, and backend conformance binding.
    ///
    /// # Errors
    ///
    /// Rejects identity substitution, output-limit violations, or a conformance
    /// claim made by a backend which was not qualified as conformant.
    pub fn validate_against(&self, request: &ExecutionRequestV1) -> Result<(), ProtocolError> {
        if self.organization_id != request.organization_id
            || self.lease_id != request.lease_id
            || self.worker_identity != request.worker_identity
        {
            return Err(ProtocolError::IdentityMismatch);
        }
        if self.output.captured_bytes > request.resources.output_bytes {
            return Err(ProtocolError::OutputLimitExceeded);
        }
        if self.conformant && !request.environment.conformant_backend {
            return Err(ProtocolError::InvalidConformance);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use schemars::schema_for;
    use serde_json::{Value, json};
    fn request() -> ExecutionRequestV1 {
        ExecutionRequestV1 {
            organization_id: "org_00000000".parse().unwrap(),
            lease_id: "lease_00000000".parse().unwrap(),
            worker_identity: "worker_00000000".parse().unwrap(),
            job_class: JobClassV1::Verifier,
            environment: EnvironmentEnvelopeV1 {
                image_digest: Sha256Digest::of_bytes(b"image"),
                environment_digest: Sha256Digest::of_bytes(b"env"),
                sandbox_profile: "hosted-v1".into(),
                conformant_backend: true,
            },
            argv: vec!["/workspace/bin/test".into()],
            environment_variables: BTreeMap::from([("TZ".into(), "UTC".into())]),
            input_artifacts: vec![Sha256Digest::of_bytes(b"input")],
            capabilities: vec![
                WorkerCapabilityV1::ReadDeclaredArtifact,
                WorkerCapabilityV1::WriteObservation,
            ],
            network_policy: NetworkPolicyV1::EgressDenied,
            resources: ResourceLimitsV1 {
                cpu_millis: 1000,
                wall_millis: 2000,
                memory_bytes: 1024,
                disk_bytes: 1024,
                process_count: 4,
                output_bytes: 128,
            },
            expires_at: UtcInstant::parse("2026-07-23T01:00:00Z").unwrap(),
        }
    }
    fn receipt() -> TerminalReceiptV1 {
        let r = request();
        TerminalReceiptV1 {
            organization_id: r.organization_id,
            lease_id: r.lease_id,
            worker_identity: r.worker_identity,
            outcome: TerminalOutcomeV1::Exited,
            cleanup: CleanupOutcomeV1::Confirmed,
            output: RedactedOutputV1 {
                stdout_digest: None,
                stderr_digest: None,
                captured_bytes: 0,
                truncated: false,
            },
            observation_artifacts: vec![],
            conformant: true,
            completed_at: UtcInstant::parse("2026-07-23T00:00:00Z").unwrap(),
            signing_key_id: "key_00000000".parse().unwrap(),
            signature: "sig-v1:abc".into(),
        }
    }
    #[test]
    fn schemas_are_closed_and_have_no_verdict_vocabulary() {
        let schema = serde_json::to_value(schema_for!(TerminalReceiptV1)).unwrap();
        assert_eq!(schema["additionalProperties"], Value::Bool(false));
        let all = format!(
            "{}{}",
            serde_json::to_string(&schema_for!(ExecutionRequestV1)).unwrap(),
            serde_json::to_string(&schema_for!(TerminalReceiptV1)).unwrap()
        )
        .to_ascii_lowercase();
        for word in ["verdict", "verified_for_fixture", "safe_to_deploy"] {
            assert!(!all.contains(word));
        }
    }
    #[test]
    fn adversarial_unknown_privilege_mount_secret_and_socket_fields_are_rejected() {
        let mut wire = serde_json::to_value(request()).unwrap();
        for field in ["host_mount", "daemon_socket", "privileged", "secret"] {
            wire.as_object_mut()
                .unwrap()
                .insert(field.into(), json!(true));
            assert!(serde_json::from_value::<ExecutionRequestV1>(wire.clone()).is_err());
            wire.as_object_mut().unwrap().remove(field);
        }
    }
    #[test]
    fn malformed_limits_secrets_and_evaluation_egress_fail_admission() {
        let mut r = request();
        r.resources.memory_bytes = 0;
        assert_eq!(r.validate(), Err(ProtocolError::InvalidResourceLimit));
        let mut r = request();
        r.environment_variables
            .insert("API_TOKEN".into(), "secret".into());
        assert_eq!(r.validate(), Err(ProtocolError::SecretEnvironment));
        let mut r = request();
        r.network_policy = NetworkPolicyV1::AcquisitionAllowlisted;
        assert_eq!(r.validate(), Err(ProtocolError::NetworkPolicyMismatch));
    }
    #[test]
    fn every_terminal_receipt_requires_cleanup_field_and_bounded_output() {
        let mut wire = serde_json::to_value(receipt()).unwrap();
        wire.as_object_mut().unwrap().remove("cleanup");
        assert!(serde_json::from_value::<TerminalReceiptV1>(wire).is_err());
        let mut receipt = receipt();
        receipt.output.captured_bytes = 129;
        assert_eq!(
            receipt.validate_against(&request()),
            Err(ProtocolError::OutputLimitExceeded)
        );
    }
    #[test]
    fn weak_backend_cannot_claim_conformance_and_identity_substitution_fails() {
        let mut r = request();
        r.environment.conformant_backend = false;
        assert_eq!(
            receipt().validate_against(&r),
            Err(ProtocolError::InvalidConformance)
        );
        let mut bad = receipt();
        bad.organization_id = "org_11111111".parse().unwrap();
        assert_eq!(
            bad.validate_against(&request()),
            Err(ProtocolError::IdentityMismatch)
        );
    }
}
