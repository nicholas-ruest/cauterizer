//! Deterministic verification-fixture qualification.

use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
use cauterizer_syntax::time::UtcInstant;
use serde::Serialize;
use std::fmt;

/// P00-selected qualification repetition count.
pub const QUALIFICATION_REPETITIONS: u8 = 10;

/// Verifier-owned, anti-corrupted view of a fresh execution request.
///
/// Cross-context adapters must derive this value from the versioned execution
/// protocol and authenticate the corresponding receipt. Provider and worker
/// protocol types deliberately do not enter verification policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationRequest {
    /// Tenant partition.
    pub organization_id: OrganizationId,
    /// Globally unique execution lease.
    pub lease_id: ContextQualifiedId,
    /// Globally unique verifier workload.
    pub worker_identity: ContextQualifiedId,
    /// Immutable worker image.
    pub image_digest: Sha256Digest,
    /// Immutable environment bundle.
    pub environment_digest: Sha256Digest,
    /// Backend profile asserted by the authenticated execution boundary.
    pub sandbox_profile: String,
    /// Exact non-shell command.
    pub argv: Vec<String>,
    /// Exact readable artifacts.
    pub input_artifacts: Vec<Sha256Digest>,
    /// Whether externally enforced egress denial is required.
    pub egress_denied: bool,
    /// CPU limit in milliseconds.
    pub cpu_millis: u64,
    /// Wall limit in milliseconds.
    pub wall_millis: u64,
    /// Memory bound.
    pub memory_bytes: u64,
    /// Scratch disk bound.
    pub disk_bytes: u64,
    /// Process-count bound.
    pub process_count: u32,
    /// Redacted output bound.
    pub output_bytes: u64,
    /// Exclusive lease expiry.
    pub expires_at: UtcInstant,
}

impl QualificationRequest {
    /// Enforces the verifier's hermetic request invariants.
    ///
    /// # Errors
    /// Rejects missing identities, mutable commands, weak backends, egress, or
    /// absent externally enforced resource bounds.
    pub fn validate(&self) -> Result<(), QualificationError> {
        if !self.lease_id.as_str().starts_with("verification_")
            || !self.worker_identity.as_str().starts_with("worker_")
            || self.sandbox_profile.trim().is_empty()
            || self.argv.is_empty()
            || self
                .argv
                .iter()
                .any(|part| part.is_empty() || part.contains('\0'))
            || self.input_artifacts.is_empty()
            || !self.egress_denied
            || self.cpu_millis == 0
            || self.wall_millis == 0
            || self.memory_bytes == 0
            || self.disk_bytes == 0
            || self.process_count == 0
            || self.output_bytes == 0
        {
            return Err(QualificationError::InvalidExecutionRequest);
        }
        Ok(())
    }
}

/// Stable identity visible to solvers without revealing verifier storage keys.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicFixtureDescriptor {
    /// Public CVE identifier.
    pub advisory_id: String,
    /// Immutable vulnerable source content.
    pub source_bundle_digest: Sha256Digest,
    /// Immutable, solver-readable build environment.
    pub environment_bundle_digest: Sha256Digest,
    /// Public acquisition manifest.
    pub acquisition_manifest_digest: Sha256Digest,
    /// Qualification policy revision.
    pub qualification_policy: String,
    /// Digest of the complete verifier-held qualification record.
    pub qualification_digest: Sha256Digest,
}

/// Verifier-only control. It is intentionally absent from public descriptors.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Control {
    /// Vulnerable revision with no patch.
    VulnerableBase,
    /// Syntactically valid empty change.
    NoOp,
    /// Intentionally ineffective patch.
    Bad,
    /// Pinned upstream reference fix.
    Gold,
}

/// Policy interpretation of one bounded execution observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestOutcome {
    /// Required suites passed.
    Pass,
    /// Intended assertion or required suite failed.
    Fail,
}

/// Normalized verifier observation. Raw output, timing and paths are excluded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationObservation {
    /// Policy result.
    pub outcome: TestOutcome,
    /// Digest after removing declared nondeterministic fields.
    pub normalized_digest: Sha256Digest,
    /// Digest of the exact request authenticated by the execution boundary.
    pub request_digest: Sha256Digest,
    /// Digest of the signed/versioned execution receipt.
    pub receipt_digest: Sha256Digest,
    /// Tenant authenticated by the execution boundary.
    pub organization_id: OrganizationId,
    /// Fresh workload identity authenticated by the execution boundary.
    pub worker_identity: ContextQualifiedId,
    /// Whether the receipt signature and issuer trust chain were authenticated.
    pub authenticated: bool,
    /// Whether the execution receipt proves the hosted conformance profile.
    pub conformant: bool,
    /// Whether mandatory worker cleanup was confirmed.
    pub cleanup_confirmed: bool,
}

/// Boundary to P09. Implementations may only receive its published request contract.
pub trait QualificationRunner {
    /// Executes one fresh verifier request.
    /// # Errors
    /// Returns a stable failure without exposing guest output.
    fn execute(
        &mut self,
        request: &QualificationRequest,
        control: Control,
    ) -> Result<QualificationObservation, QualificationError>;
}

/// Builds fresh P09 requests while retaining hidden fixture knowledge in the adapter.
pub trait QualificationPlan {
    /// Constructs the exact request for a control/repetition pair.
    /// # Errors
    /// Rejects an invalid or non-hermetic plan.
    fn request(
        &self,
        control: Control,
        repetition: u8,
    ) -> Result<QualificationRequest, QualificationError>;

    /// Produces the public descriptor after a successful qualification.
    fn publish(&self, qualification_digest: Sha256Digest) -> PublicFixtureDescriptor;

    /// Stable policy version included in the qualification record.
    fn policy_version(&self) -> &str;
}

/// Deterministic qualification service.
pub struct QualificationService;

impl QualificationService {
    /// Runs all four controls ten times in fresh verifier jobs.
    /// # Errors
    /// Fails closed on any mismatch, weak receipt, reused identity, or invalid request.
    pub fn qualify(
        plan: &impl QualificationPlan,
        runner: &mut impl QualificationRunner,
    ) -> Result<PublicFixtureDescriptor, QualificationError> {
        let mut evidence = b"cauterizer.fixture-qualification-record.v1\0".to_vec();
        append(&mut evidence, plan.policy_version());
        let mut identities = std::collections::BTreeSet::new();
        for control in [
            Control::VulnerableBase,
            Control::NoOp,
            Control::Bad,
            Control::Gold,
        ] {
            let mut expected_digest = None;
            for repetition in 0..QUALIFICATION_REPETITIONS {
                let request = plan.request(control, repetition)?;
                request.validate()?;
                if !identities.insert(request.worker_identity.clone()) {
                    return Err(QualificationError::ReusedWorkerIdentity);
                }
                let request_digest = request.canonical_digest();
                let observation = runner.execute(&request, control)?;
                let expected = if control == Control::Gold {
                    TestOutcome::Pass
                } else {
                    TestOutcome::Fail
                };
                if observation.outcome != expected {
                    return Err(QualificationError::ControlMismatch);
                }
                if !observation.authenticated
                    || observation.request_digest != request_digest
                    || observation.organization_id != request.organization_id
                    || observation.worker_identity != request.worker_identity
                    || !observation.conformant
                    || !observation.cleanup_confirmed
                {
                    return Err(QualificationError::NonConformant);
                }
                if expected_digest
                    .replace(observation.normalized_digest)
                    .is_some_and(|digest| digest != observation.normalized_digest)
                {
                    return Err(QualificationError::Nondeterministic);
                }
                evidence.push(control.code());
                evidence.push(repetition);
                evidence.extend_from_slice(request_digest.as_bytes());
                evidence.extend_from_slice(observation.receipt_digest.as_bytes());
                evidence.extend_from_slice(observation.normalized_digest.as_bytes());
            }
        }
        Ok(plan.publish(Sha256Digest::of_bytes(evidence)))
    }
}

impl QualificationRequest {
    /// Computes the deterministic digest that an execution receipt must bind.
    #[must_use]
    pub fn canonical_digest(&self) -> Sha256Digest {
        let mut bytes = b"cauterizer.verification-qualification-request.v1\0".to_vec();
        append(&mut bytes, self.organization_id.as_str());
        append(&mut bytes, self.lease_id.as_str());
        append(&mut bytes, self.worker_identity.as_str());
        bytes.extend_from_slice(self.image_digest.as_bytes());
        bytes.extend_from_slice(self.environment_digest.as_bytes());
        append(&mut bytes, &self.sandbox_profile);
        for argument in &self.argv {
            append(&mut bytes, argument);
        }
        for digest in &self.input_artifacts {
            bytes.extend_from_slice(digest.as_bytes());
        }
        bytes.push(u8::from(self.egress_denied));
        bytes.extend_from_slice(&self.cpu_millis.to_be_bytes());
        bytes.extend_from_slice(&self.wall_millis.to_be_bytes());
        bytes.extend_from_slice(&self.memory_bytes.to_be_bytes());
        bytes.extend_from_slice(&self.disk_bytes.to_be_bytes());
        bytes.extend_from_slice(&self.process_count.to_be_bytes());
        bytes.extend_from_slice(&self.output_bytes.to_be_bytes());
        append(&mut bytes, &self.expires_at.to_string());
        Sha256Digest::of_bytes(bytes)
    }
}

impl Control {
    const fn code(self) -> u8 {
        match self {
            Self::VulnerableBase => 0,
            Self::NoOp => 1,
            Self::Bad => 2,
            Self::Gold => 3,
        }
    }
}

fn append(target: &mut Vec<u8>, value: &str) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value.as_bytes());
}

/// Stable fail-closed qualification failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationError {
    /// Plan violated the P09 request contract.
    InvalidExecutionRequest,
    /// A supposedly fresh worker identity was reused.
    ReusedWorkerIdentity,
    /// A control did not produce its mandatory result.
    ControlMismatch,
    /// Repetitions disagreed after normalization.
    Nondeterministic,
    /// Hosted conformance or cleanup proof was absent.
    NonConformant,
    /// Execution boundary was unavailable.
    ExecutionUnavailable,
}

impl fmt::Display for QualificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl std::error::Error for QualificationError {}
