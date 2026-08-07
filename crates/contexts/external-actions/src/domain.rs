//! Authorization and delivery model for review-only SCM mutations.

use std::collections::BTreeSet;
use std::fmt;

use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{ContextQualifiedId, IdempotencyKey, OrganizationId};
use serde::{Deserialize, Serialize};

const MAX_VALUE: usize = 256;

macro_rules! owned_id {
    ($doc:literal, $name:ident, $prefix:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        pub struct $name(ContextQualifiedId);
        impl $name {
            /// Creates a context-qualified identifier.
            ///
            /// # Errors
            /// Returns [`ExternalActionError::InvalidValue`] for invalid shared identifier syntax.
            pub fn new(opaque: &str) -> Result<Self, ExternalActionError> {
                ContextQualifiedId::new($prefix, opaque)
                    .map(Self)
                    .map_err(|_| ExternalActionError::InvalidValue)
            }
            /// Returns its canonical representation.
            #[must_use]
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }
    };
}

owned_id!(
    "Stable installation grant identifier.",
    ExternalActionGrantId,
    "actiongrant"
);
owned_id!(
    "Stable external delivery identifier.",
    ExternalActionDeliveryId,
    "actiondelivery"
);

/// An SCM capability. Dangerous capabilities are represented so requests can be
/// rejected explicitly, but can never be placed in a valid grant.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionCapability {
    /// Create a remediation tracking issue.
    CreateIssue,
    /// Update an existing remediation issue.
    UpdateIssue,
    /// Create a namespaced remediation branch.
    CreateRemediationBranch,
    /// Push a candidate commit to a remediation branch.
    PushCandidateCommit,
    /// Open a pull request for human review.
    OpenPullRequest,
    /// Update a previously opened pull request.
    UpdatePullRequest,
    /// Publish a sanitized verification result.
    PostVerificationResult,
    /// Close a duplicate or superseded issue.
    CloseSupersededIssue,
    /// Merge a pull request; permanently prohibited.
    MergePullRequest,
    /// Force-push a protected branch; permanently prohibited.
    ForcePushProtectedBranch,
    /// Publish a package; permanently prohibited.
    PublishPackage,
    /// Create a release; permanently prohibited.
    CreateRelease,
    /// Deploy software; permanently prohibited.
    Deploy,
    /// Change repository administration; permanently prohibited.
    ModifyRepositoryAdministration,
}

impl ActionCapability {
    /// Whether ADR-025 permits this capability at all.
    #[must_use]
    pub const fn is_permitted(self) -> bool {
        matches!(
            self,
            Self::CreateIssue
                | Self::UpdateIssue
                | Self::CreateRemediationBranch
                | Self::PushCandidateCommit
                | Self::OpenPullRequest
                | Self::UpdatePullRequest
                | Self::PostVerificationResult
                | Self::CloseSupersededIssue
        )
    }
}

/// Installation-time, repository-scoped authorization. It contains a reference
/// to credentials, never credential material.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExternalActionGrant {
    /// Stable grant identity.
    pub id: ExternalActionGrantId,
    /// Organization that owns the grant.
    pub organization_id: OrganizationId,
    /// Provider installation reference, not credential material.
    pub installation_ref: String,
    /// Exact repository authorized by the grant.
    pub repository: String,
    /// Required namespace for remediation branches.
    pub branch_prefix: String,
    /// Explicit allowed capability set.
    pub capabilities: BTreeSet<ActionCapability>,
    /// Whether future use remains enabled.
    pub enabled: bool,
    /// Exclusive Unix expiry second. Legacy grants use the maximum value.
    #[serde(default = "maximum_expiry")]
    expires_at_epoch_seconds: u64,
    /// Resource and policy bounds for code-changing actions.
    #[serde(default)]
    constraints: GrantConstraints,
}

/// Installation-time hard limits applied to attested remediation work.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct GrantConstraints {
    /// Maximum candidate patch bytes.
    pub max_patch_bytes: u64,
    /// Maximum changed source lines.
    pub max_changed_lines: u64,
    /// Maximum solver attempts.
    pub max_attempts: u32,
    /// Maximum elapsed remediation time in milliseconds.
    pub max_elapsed_millis: u64,
    /// Maximum compute or solver units.
    pub max_compute_units: u64,
    /// Maximum spend in micros of the configured billing currency.
    pub max_spend_micros: u64,
}

impl GrantConstraints {
    /// Creates non-zero hard bounds.
    ///
    /// # Errors
    /// Returns [`ExternalActionError::InvalidGrant`] when any bound is zero.
    pub const fn new(
        max_patch_bytes: u64,
        max_changed_lines: u64,
        max_attempts: u32,
        max_elapsed_millis: u64,
        max_compute_units: u64,
        max_spend_micros: u64,
    ) -> Result<Self, ExternalActionError> {
        if max_patch_bytes == 0
            || max_changed_lines == 0
            || max_attempts == 0
            || max_elapsed_millis == 0
            || max_compute_units == 0
            || max_spend_micros == 0
        {
            return Err(ExternalActionError::InvalidGrant);
        }
        Ok(Self {
            max_patch_bytes,
            max_changed_lines,
            max_attempts,
            max_elapsed_millis,
            max_compute_units,
            max_spend_micros,
        })
    }

    fn permits(&self, attestation: &DeliveryAttestation) -> bool {
        attestation.policy_approved
            && attestation.patch_bytes <= self.max_patch_bytes
            && attestation.changed_lines <= self.max_changed_lines
            && attestation.attempts <= self.max_attempts
            && attestation.elapsed_millis <= self.max_elapsed_millis
            && attestation.compute_units <= self.max_compute_units
            && attestation.spend_micros <= self.max_spend_micros
    }
}

/// Immutable, redacted policy decision and exact resource measurements.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeliveryAttestation {
    /// Digest of the exact candidate being delivered.
    pub candidate_digest: Sha256Digest,
    /// Digest of the versioned allow/deny-path policy result.
    pub policy_result_digest: Sha256Digest,
    /// Whether every changed path and required metadata passed policy.
    pub policy_approved: bool,
    /// Exact patch size in bytes.
    pub patch_bytes: u64,
    /// Exact changed source lines.
    pub changed_lines: u64,
    /// Solver attempts consumed.
    pub attempts: u32,
    /// Elapsed remediation time in milliseconds.
    pub elapsed_millis: u64,
    /// Compute or solver units consumed.
    pub compute_units: u64,
    /// Spend in micros of the configured billing currency.
    pub spend_micros: u64,
}

const fn maximum_expiry() -> u64 {
    u64::MAX
}

impl ExternalActionGrant {
    /// Exclusive expiry used when translating authority to provider integrations.
    #[must_use]
    pub const fn expires_at_epoch_seconds(&self) -> u64 {
        self.expires_at_epoch_seconds
    }
    /// Creates an enabled installation grant after fail-closed validation.
    ///
    /// # Errors
    /// Returns [`ExternalActionError::InvalidGrant`] when scope, capabilities, or values violate policy.
    pub fn new(
        id: ExternalActionGrantId,
        organization_id: OrganizationId,
        installation_ref: impl Into<String>,
        repository: impl Into<String>,
        branch_prefix: impl Into<String>,
        capabilities: BTreeSet<ActionCapability>,
    ) -> Result<Self, ExternalActionError> {
        let installation_ref = installation_ref.into();
        let repository = repository.into();
        let branch_prefix = branch_prefix.into();
        if capabilities.is_empty()
            || capabilities
                .iter()
                .any(|capability| !capability.is_permitted())
            || !safe_value(&installation_ref)
            || !safe_value(&repository)
            || !safe_value(&branch_prefix)
            || repository.contains("..")
            || branch_prefix.starts_with('/')
        {
            return Err(ExternalActionError::InvalidGrant);
        }
        Ok(Self {
            id,
            organization_id,
            installation_ref,
            repository,
            branch_prefix,
            capabilities,
            enabled: true,
            expires_at_epoch_seconds: u64::MAX,
            constraints: GrantConstraints::default(),
        })
    }

    /// Creates a grant with a mandatory finite expiry.
    ///
    /// # Errors
    /// Returns [`ExternalActionError::InvalidGrant`] for zero or maximum expiry, or normal grant validation failures.
    pub fn new_expiring(
        id: ExternalActionGrantId,
        organization_id: OrganizationId,
        installation_ref: impl Into<String>,
        repository: impl Into<String>,
        branch_prefix: impl Into<String>,
        capabilities: BTreeSet<ActionCapability>,
        expires_at_epoch_seconds: u64,
    ) -> Result<Self, ExternalActionError> {
        if expires_at_epoch_seconds == 0 || expires_at_epoch_seconds == u64::MAX {
            return Err(ExternalActionError::InvalidGrant);
        }
        let mut grant = Self::new(
            id,
            organization_id,
            installation_ref,
            repository,
            branch_prefix,
            capabilities,
        )?;
        grant.expires_at_epoch_seconds = expires_at_epoch_seconds;
        Ok(grant)
    }

    /// Applies explicit installation constraints to this grant.
    #[must_use]
    pub fn with_constraints(mut self, constraints: GrantConstraints) -> Self {
        self.constraints = constraints;
        self
    }

    /// Revokes all future use without deleting audit state.
    pub fn revoke(&mut self) {
        self.enabled = false;
    }

    /// Checks organization, repository, and capability binding.
    ///
    /// # Errors
    /// Returns a policy error when the grant is revoked, mismatched, or cannot authorize the capability.
    pub fn authorizes(
        &self,
        organization_id: &OrganizationId,
        repository: &str,
        capability: ActionCapability,
    ) -> Result<(), ExternalActionError> {
        if !capability.is_permitted() {
            return Err(ExternalActionError::ProhibitedCapability);
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ExternalActionError::NotAuthorized)?
            .as_secs();
        self.authorizes_at(organization_id, repository, capability, now)
    }

    /// Checks authority at an explicit Unix second for deterministic policy evaluation.
    ///
    /// # Errors
    /// Returns a policy error when expired, revoked, mismatched, or prohibited.
    pub fn authorizes_at(
        &self,
        organization_id: &OrganizationId,
        repository: &str,
        capability: ActionCapability,
        now_epoch_seconds: u64,
    ) -> Result<(), ExternalActionError> {
        if !capability.is_permitted() {
            return Err(ExternalActionError::ProhibitedCapability);
        }
        if !self.enabled || now_epoch_seconds >= self.expires_at_epoch_seconds {
            return Err(ExternalActionError::GrantRevoked);
        }
        if &self.organization_id != organization_id
            || self.repository != repository
            || !self.capabilities.contains(&capability)
        {
            return Err(ExternalActionError::NotAuthorized);
        }
        Ok(())
    }

    /// Checks complete request scope, including remediation branch restrictions.
    ///
    /// # Errors
    /// Returns an authority error or branch-policy violation.
    pub fn authorizes_request(
        &self,
        request: &ExternalActionRequest,
    ) -> Result<(), ExternalActionError> {
        request.validate()?;
        self.authorizes(
            &request.organization_id,
            &request.repository,
            request.capability,
        )?;
        if matches!(
            request.capability,
            ActionCapability::CreateRemediationBranch | ActionCapability::PushCandidateCommit
        ) && (!request.subject.starts_with(&self.branch_prefix)
            || matches!(request.subject.as_str(), "main" | "master")
            || request.subject.contains(".."))
        {
            return Err(ExternalActionError::NotAuthorized);
        }
        if matches!(
            request.capability,
            ActionCapability::CreateRemediationBranch
                | ActionCapability::PushCandidateCommit
                | ActionCapability::OpenPullRequest
                | ActionCapability::UpdatePullRequest
        ) {
            let Some(attestation) = &request.policy_attestation else {
                return Err(ExternalActionError::NotAuthorized);
            };
            if !self.constraints.permits(attestation) {
                return Err(ExternalActionError::NotAuthorized);
            }
        }
        Ok(())
    }
}

impl fmt::Debug for ExternalActionGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExternalActionGrant")
            .field("id", &self.id)
            .field("organization_id", &self.organization_id)
            .field("repository", &self.repository)
            .field("branch_prefix", &self.branch_prefix)
            .field("capabilities", &self.capabilities)
            .field("enabled", &self.enabled)
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .finish_non_exhaustive()
    }
}

/// Secret-free, audit-safe request. The content points at pre-redacted evidence.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExternalActionRequest {
    /// Organization requesting the action.
    pub organization_id: OrganizationId,
    /// Installation grant to evaluate.
    pub grant_id: ExternalActionGrantId,
    /// Exact target repository.
    pub repository: String,
    /// Requested provider capability.
    pub capability: ActionCapability,
    /// Stable replay identity.
    pub idempotency_key: IdempotencyKey,
    /// Stable logical object identity shared across candidate updates.
    #[serde(default)]
    pub correlation_key: String,
    /// Bounded provider-visible title or subject.
    pub subject: String,
    /// Pre-redacted provider-visible body.
    pub redacted_body: String,
    /// Redacted policy decision required for code-changing actions.
    #[serde(default)]
    pub policy_attestation: Option<DeliveryAttestation>,
}

impl fmt::Debug for ExternalActionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExternalActionRequest")
            .field("organization_id", &self.organization_id)
            .field("grant_id", &self.grant_id)
            .field("repository", &self.repository)
            .field("capability", &self.capability)
            .field("idempotency_key", &self.idempotency_key)
            .field("subject", &"[REDACTED]")
            .field("redacted_body", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl ExternalActionRequest {
    /// Validates bounded, single-line routing data and redacted content.
    ///
    /// # Errors
    /// Returns [`ExternalActionError::UnsafeRequest`] for unsafe routing or content.
    pub fn validate(&self) -> Result<(), ExternalActionError> {
        if !safe_value(&self.repository)
            || !safe_correlation_key(&self.correlation_key)
            || !safe_text(&self.subject)
            || contains_secret_marker(&self.subject)
            || self.redacted_body.len() > 16_384
            || contains_secret_marker(&self.redacted_body)
        {
            return Err(ExternalActionError::UnsafeRequest);
        }
        Ok(())
    }
}

fn safe_correlation_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn contains_secret_marker(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "authorization:",
        "bearer ",
        "private_key",
        "access_token",
        "api_key",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn safe_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_VALUE
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !byte.is_ascii_control())
}

fn safe_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_VALUE
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
}

/// Durable local lifecycle. `Unknown` requires reconciliation before retry.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub enum DeliveryStatus {
    /// Persisted but not known to have reached the provider.
    Pending,
    /// Provider outcome was ambiguous and requires reconciliation.
    Unknown,
    /// Automated reconciliation was exhausted; an operator must review it.
    ReconciliationExhausted,
    /// Provider confirmed successful delivery.
    Succeeded {
        /// Opaque provider identity used for follow-up mutations.
        #[serde(default)]
        remote_id: String,
        /// Sanitized human-facing provider URL.
        #[serde(alias = "remote_reference")]
        remote_url: String,
    },
    /// Provider conclusively rejected the request.
    Rejected {
        /// Stable local reason code, never a raw provider response.
        reason_code: String,
    },
}

impl fmt::Debug for DeliveryStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => formatter.write_str("Pending"),
            Self::Unknown => formatter.write_str("Unknown"),
            Self::ReconciliationExhausted => formatter.write_str("ReconciliationExhausted"),
            Self::Succeeded { .. } => {
                formatter.write_str("Succeeded { remote_id: [REDACTED], remote_url: [REDACTED] }")
            }
            Self::Rejected { reason_code } => formatter
                .debug_struct("Rejected")
                .field("reason_code", reason_code)
                .finish(),
        }
    }
}

/// Returns whether a provider object reference is bounded and log-injection safe.
#[must_use]
pub fn is_safe_external_reference(value: &str) -> bool {
    safe_value(value) && !contains_secret_marker(value)
}

/// One immutable-identity delivery record updated through its lifecycle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExternalActionDelivery {
    /// Stable delivery identity.
    pub id: ExternalActionDeliveryId,
    /// Exact request bound to the idempotency identity.
    pub request: ExternalActionRequest,
    /// Current durable delivery state.
    pub status: DeliveryStatus,
    /// Number of provider mutation attempts.
    pub attempts: u32,
    /// Number of remote reconciliation reads already attempted.
    #[serde(default)]
    pub reconciliation_attempts: u32,
    /// Earliest Unix second at which another reconciliation may be claimed.
    #[serde(default)]
    pub next_reconcile_at_epoch_seconds: u64,
    /// Exclusive Unix-second lease held by one reconciliation worker.
    #[serde(default)]
    pub reconciliation_lease_until_epoch_seconds: Option<u64>,
    /// Monotonic fencing token incremented for every successful lease claim.
    #[serde(default)]
    pub reconciliation_claim_token: u64,
}

impl ExternalActionDelivery {
    /// Creates a validated pending delivery.
    ///
    /// # Errors
    /// Returns the request validation failure.
    pub fn pending(
        id: ExternalActionDeliveryId,
        request: ExternalActionRequest,
    ) -> Result<Self, ExternalActionError> {
        request.validate()?;
        Ok(Self {
            id,
            request,
            status: DeliveryStatus::Pending,
            attempts: 0,
            reconciliation_attempts: 0,
            next_reconcile_at_epoch_seconds: 0,
            reconciliation_lease_until_epoch_seconds: None,
            reconciliation_claim_token: 0,
        })
    }

    /// Marks an ambiguous mutation and schedules deterministic reconciliation.
    pub fn mark_unknown(&mut self, now_epoch_seconds: u64, policy: ReconciliationPolicy) {
        self.status = DeliveryStatus::Unknown;
        self.reconciliation_lease_until_epoch_seconds = None;
        self.next_reconcile_at_epoch_seconds =
            now_epoch_seconds.saturating_add(policy.delay_seconds(self.reconciliation_attempts));
    }

    /// Releases a reconciliation lease and schedules the next eligible read.
    pub fn defer_reconciliation(&mut self, now_epoch_seconds: u64, policy: ReconciliationPolicy) {
        self.mark_unknown(now_epoch_seconds, policy);
    }
}

/// Bounded deterministic reconciliation timing policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconciliationPolicy {
    /// Maximum reconciliation reads before manual review.
    pub max_attempts: u32,
    /// Initial retry delay in seconds.
    pub base_delay_seconds: u64,
    /// Maximum retry delay in seconds.
    pub max_delay_seconds: u64,
    /// Claim lease duration in seconds.
    pub lease_seconds: u64,
}

impl ReconciliationPolicy {
    /// Production-safe default: eight reads, 30-second exponential delay, one-hour cap.
    pub const DEFAULT: Self = Self {
        max_attempts: 8,
        base_delay_seconds: 30,
        max_delay_seconds: 3_600,
        lease_seconds: 60,
    };

    /// Validates a non-zero, capped policy.
    ///
    /// # Errors
    /// Returns [`ExternalActionError::InvalidValue`] for zero or inverted bounds.
    pub const fn new(
        max_attempts: u32,
        base_delay_seconds: u64,
        max_delay_seconds: u64,
        lease_seconds: u64,
    ) -> Result<Self, ExternalActionError> {
        if max_attempts == 0
            || base_delay_seconds == 0
            || max_delay_seconds < base_delay_seconds
            || lease_seconds == 0
        {
            return Err(ExternalActionError::InvalidValue);
        }
        Ok(Self {
            max_attempts,
            base_delay_seconds,
            max_delay_seconds,
            lease_seconds,
        })
    }

    /// Returns capped exponential delay for the completed reconciliation count.
    #[must_use]
    pub const fn delay_seconds(self, completed_attempts: u32) -> u64 {
        let shift = if completed_attempts > 63 {
            63
        } else {
            completed_attempts
        };
        let calculated = self.base_delay_seconds.saturating_mul(1_u64 << shift);
        if calculated < self.max_delay_seconds {
            calculated
        } else {
            self.max_delay_seconds
        }
    }
}

/// Public errors contain codes only, never provider response bodies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalActionError {
    /// A context-owned identifier or value was invalid.
    InvalidValue,
    /// The proposed installation grant violated policy.
    InvalidGrant,
    /// The referenced grant has been revoked.
    GrantRevoked,
    /// The grant does not authorize this target or capability.
    NotAuthorized,
    /// ADR-025 permanently prohibits the capability.
    ProhibitedCapability,
    /// The global emergency stop is active.
    KillSwitchEngaged,
    /// Request content was unsafe or insufficiently redacted.
    UnsafeRequest,
    /// An idempotency key was reused for a different request.
    IdempotencyConflict,
    /// A requested local record did not exist.
    NotFound,
    /// Provider outcome was unavailable or ambiguous.
    RemoteUnavailable,
    /// Provider conclusively rejected the operation.
    RemoteRejected,
}

impl fmt::Display for ExternalActionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "external action failed: {self:?}")
    }
}
impl std::error::Error for ExternalActionError {}

#[cfg(test)]
mod tests {
    use super::*;
    fn org() -> OrganizationId {
        OrganizationId::new("organization1").unwrap()
    }
    #[test]
    fn dangerous_capabilities_can_never_be_granted() {
        let result = ExternalActionGrant::new(
            ExternalActionGrantId::new("grant0001").unwrap(),
            org(),
            "install-1",
            "owner/repo",
            "cauterizer/",
            BTreeSet::from([ActionCapability::MergePullRequest]),
        );
        assert_eq!(result.unwrap_err(), ExternalActionError::InvalidGrant);
    }
    #[test]
    fn request_rejects_likely_secret_material() {
        let request = ExternalActionRequest {
            organization_id: org(),
            grant_id: ExternalActionGrantId::new("grant0001").unwrap(),
            repository: "owner/repo".into(),
            capability: ActionCapability::CreateIssue,
            idempotency_key: IdempotencyKey::new("one").unwrap(),
            correlation_key: "one".into(),
            subject: "fix".into(),
            redacted_body: "Authorization: Bearer secret".into(),
            policy_attestation: None,
        };
        assert_eq!(request.validate(), Err(ExternalActionError::UnsafeRequest));
        let mut safe = request;
        safe.redacted_body = "redacted".into();
        safe.correlation_key = "x".repeat(129);
        assert_eq!(safe.validate(), Err(ExternalActionError::UnsafeRequest));
        safe.correlation_key = "invalid/correlation".into();
        assert_eq!(safe.validate(), Err(ExternalActionError::UnsafeRequest));
    }

    #[test]
    fn expiry_and_branch_prefix_fail_closed() {
        let grant = ExternalActionGrant::new_expiring(
            ExternalActionGrantId::new("grant0002").unwrap(),
            org(),
            "install-1",
            "owner/repo",
            "cauterizer/",
            BTreeSet::from([ActionCapability::CreateRemediationBranch]),
            100,
        )
        .unwrap();
        assert_eq!(
            grant.authorizes_at(
                &org(),
                "owner/repo",
                ActionCapability::CreateRemediationBranch,
                100
            ),
            Err(ExternalActionError::GrantRevoked)
        );
        let branch_grant = ExternalActionGrant::new(
            ExternalActionGrantId::new("grant0004").unwrap(),
            org(),
            "install-1",
            "owner/repo",
            "cauterizer/",
            BTreeSet::from([ActionCapability::CreateRemediationBranch]),
        )
        .unwrap()
        .with_constraints(GrantConstraints::new(100, 10, 2, 1_000, 10, 100).unwrap());
        let request = ExternalActionRequest {
            organization_id: org(),
            grant_id: branch_grant.id.clone(),
            repository: "owner/repo".into(),
            capability: ActionCapability::CreateRemediationBranch,
            idempotency_key: IdempotencyKey::new("branch-policy").unwrap(),
            correlation_key: "branch-policy".into(),
            subject: "feature/unscoped".into(),
            redacted_body: "branch".into(),
            policy_attestation: Some(DeliveryAttestation {
                candidate_digest: Sha256Digest::of_bytes("candidate"),
                policy_result_digest: Sha256Digest::of_bytes("policy"),
                policy_approved: true,
                patch_bytes: 1,
                changed_lines: 1,
                attempts: 1,
                elapsed_millis: 1,
                compute_units: 1,
                spend_micros: 1,
            }),
        };
        assert_eq!(
            branch_grant.authorizes_request(&request),
            Err(ExternalActionError::NotAuthorized)
        );
    }

    #[test]
    fn debug_output_redacts_provider_text_and_references() {
        let request = ExternalActionRequest {
            organization_id: org(),
            grant_id: ExternalActionGrantId::new("grant0003").unwrap(),
            repository: "owner/repo".into(),
            capability: ActionCapability::CreateIssue,
            idempotency_key: IdempotencyKey::new("debug-redaction").unwrap(),
            correlation_key: "debug-redaction".into(),
            subject: "sensitive title".into(),
            redacted_body: "sensitive body".into(),
            policy_attestation: None,
        };
        let output = format!(
            "{request:?} {:?}",
            DeliveryStatus::Succeeded {
                remote_id: "secret-id".into(),
                remote_url: "secret-reference".into()
            }
        );
        assert!(!output.contains("sensitive title"));
        assert!(!output.contains("sensitive body"));
        assert!(!output.contains("secret-reference"));
    }

    #[test]
    fn mutation_attestation_is_required_and_every_limit_is_inclusive() {
        let constraints = GrantConstraints::new(10, 20, 3, 40, 50, 60).unwrap();
        let grant = ExternalActionGrant::new(
            ExternalActionGrantId::new("grant0005").unwrap(),
            org(),
            "install-1",
            "owner/repo",
            "cauterizer/",
            BTreeSet::from([
                ActionCapability::OpenPullRequest,
                ActionCapability::CreateIssue,
            ]),
        )
        .unwrap()
        .with_constraints(constraints);
        let attestation = DeliveryAttestation {
            candidate_digest: Sha256Digest::of_bytes("candidate"),
            policy_result_digest: Sha256Digest::of_bytes("policy"),
            policy_approved: true,
            patch_bytes: 10,
            changed_lines: 20,
            attempts: 3,
            elapsed_millis: 40,
            compute_units: 50,
            spend_micros: 60,
        };
        let mut request = ExternalActionRequest {
            organization_id: org(),
            grant_id: grant.id.clone(),
            repository: "owner/repo".into(),
            capability: ActionCapability::OpenPullRequest,
            idempotency_key: IdempotencyKey::new("boundary-policy").unwrap(),
            correlation_key: "boundary-policy".into(),
            subject: "review".into(),
            redacted_body: "verified".into(),
            policy_attestation: Some(attestation.clone()),
        };
        assert_eq!(grant.authorizes_request(&request), Ok(()));
        request.policy_attestation.as_mut().unwrap().patch_bytes += 1;
        assert_eq!(
            grant.authorizes_request(&request),
            Err(ExternalActionError::NotAuthorized)
        );
        request.policy_attestation = None;
        assert_eq!(
            grant.authorizes_request(&request),
            Err(ExternalActionError::NotAuthorized)
        );
        request.capability = ActionCapability::CreateIssue;
        assert_eq!(grant.authorizes_request(&request), Ok(()));
    }

    #[test]
    fn reconciliation_backoff_is_deterministic_and_capped() {
        let policy = ReconciliationPolicy::new(4, 10, 25, 5).unwrap();
        assert_eq!(policy.delay_seconds(0), 10);
        assert_eq!(policy.delay_seconds(1), 20);
        assert_eq!(policy.delay_seconds(2), 25);
        assert_eq!(policy.delay_seconds(63), 25);
        let mut delivery = ExternalActionDelivery::pending(
            ExternalActionDeliveryId::new("reconcile1").unwrap(),
            ExternalActionRequest {
                organization_id: org(),
                grant_id: ExternalActionGrantId::new("grant0006").unwrap(),
                repository: "owner/repo".into(),
                capability: ActionCapability::CreateIssue,
                idempotency_key: IdempotencyKey::new("reconcile-policy").unwrap(),
                correlation_key: "reconcile-policy".into(),
                subject: "issue".into(),
                redacted_body: "body".into(),
                policy_attestation: None,
            },
        )
        .unwrap();
        delivery.mark_unknown(100, policy);
        assert_eq!(delivery.next_reconcile_at_epoch_seconds, 110);
        delivery.reconciliation_attempts = 2;
        delivery.defer_reconciliation(110, policy);
        assert_eq!(delivery.next_reconcile_at_epoch_seconds, 135);
        assert_eq!(delivery.reconciliation_lease_until_epoch_seconds, None);
    }
}
