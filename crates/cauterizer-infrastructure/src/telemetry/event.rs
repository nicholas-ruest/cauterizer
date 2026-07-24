//! The closed telemetry event schema: allowlisted event kinds, bounded
//! dimensions, and a redaction guard that keeps classified payload content
//! out of every constructed event.
//!
//! Every event carries only enums, identifiers, digests, and the bounded
//! [`DetailReference`] below -- never an arbitrary tenant- or payload-shaped
//! string. [`classified_detail`] is the one place a caller may attach free
//! text, and it never keeps [`DataClass::Confidential`] or
//! [`DataClass::RestrictedSecurity`] content as text: those values are
//! one-way hashed into a [`DetailReference::Digest`] instead. See
//! `redaction_corpus_tests` for the adversarial proof.

use cauterizer_syntax::classification::DataClass;
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{IdentityRef, OrganizationId};
use cauterizer_syntax::sensitive::Sensitive;
use serde::Serialize;

/// Bound on any free-text detail carried by a telemetry event.
const MAX_DETAIL_TEXT_CHARS: usize = 256;

/// Closed allowlist of telemetry event kinds.
///
/// Ten of these map exactly onto the alert identifiers named by
/// `docs/architecture/abuse-case-test-matrix.md`'s "Alert and audit linkage"
/// paragraph (see [`crate::telemetry::alerts`]);
/// [`TelemetryEventKind::RequestObserved`] exists only to feed RED metrics
/// and never fires an alert on its own.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryEventKind {
    /// Repeated cross-organization denials (AC-001/AC-002).
    CrossOrganizationDenial,
    /// Capability misuse: a job token used outside its declared digest,
    /// operation, audience, or validity window (AC-003).
    CapabilityMisuse,
    /// An undeclared network/socket/mount access attempted from a sandbox
    /// lease (AC-004/AC-005).
    SandboxEgressAttempt,
    /// A sandbox lease, scratch directory, or descendant process failed to
    /// tear down completely (AC-007).
    CleanupFailure,
    /// A solver identity called a verifier-only storage API (AC-011/AC-012).
    VerifierStoreSolverAccess,
    /// The evidence signer denied a signing request under its policy
    /// (AC-020).
    SignerPolicyDenial,
    /// A redaction guard rejected/transformed an attempted raw secret
    /// payload before it reached a sink (AC-021).
    SecretRedactionDetected,
    /// A break-glass/support elevation session was used (AC-027).
    BreakGlassUse,
    /// An inbound event failed producer/schema/organization authentication
    /// (AC-025/AC-026).
    EventAuthenticationFailure,
    /// An export was denied by authorization/approval policy (AC-022/AC-023).
    ExportAuthorizationFailure,
    /// A generic request outcome sample, recorded only for RED metrics.
    RequestObserved,
}

/// Closed set of bounded contexts a telemetry event may be attributed to.
///
/// This is the only tenant-independent label used as a metric dimension, so
/// cardinality stays fixed regardless of tenant volume.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundedContext {
    /// Organization & Access.
    OrganizationAccess,
    /// Advisory Intake.
    AdvisoryIntake,
    /// Asset Portfolio.
    AssetPortfolio,
    /// Commercial Entitlements.
    CommercialEntitlements,
    /// Isolated Execution.
    IsolatedExecution,
    /// Remediation Runs.
    RemediationRuns,
    /// Patch Proposals.
    PatchProposals,
    /// Verification.
    Verification,
    /// Evidence.
    Evidence,
    /// External Actions.
    ExternalActions,
    /// Integration Management.
    IntegrationManagement,
}

/// Closed outcome label used as the other RED metric dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The operation completed as requested.
    Success,
    /// The operation was denied by policy/authorization.
    Denied,
    /// The operation failed for a reason other than authorization.
    Error,
}

/// Closed set of audit-safe reason codes.
///
/// Reason codes are developer-chosen at each call site, never derived from
/// tenant input, so this stays a fixed enum rather than free text a tenant
/// could inflate into unbounded cardinality.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    /// The requested tenant did not match the authenticated tenant.
    TenantMismatch,
    /// A capability/job token was used past its validity window.
    ExpiredCapability,
    /// A capability/job token was used against a substituted digest.
    DigestMismatch,
    /// A capability/job token was used for a substituted audience/verb.
    AudienceMismatch,
    /// A sandbox lease attempted undeclared network egress.
    UndeclaredEgress,
    /// A sandbox lease probed a host mount or runtime daemon socket.
    MountOrSocketProbe,
    /// A lease's scratch state did not fully tear down.
    LeaseCleanupIncomplete,
    /// A descendant process survived lease cleanup.
    DescendantProcessSurvived,
    /// A solver identity called a verifier-only storage API.
    SolverVerifierStoreProbe,
    /// The signer denied a request under its policy.
    SignerPolicyViolation,
    /// A redaction guard matched a secret-shaped pattern.
    SecretPatternMatched,
    /// A break-glass/support elevation session was opened.
    BreakGlassSessionOpened,
    /// An inbound event's signature/authentication failed.
    EventSignatureInvalid,
    /// An inbound event's schema/version was rejected.
    EventSchemaRejected,
    /// An export was attempted without a required approval.
    ExportApprovalMissing,
    /// An export was denied by policy independent of approval.
    ExportPolicyDenied,
    /// The operation succeeded (recorded for RED metrics only).
    RequestSucceeded,
    /// The operation failed for a non-authorization reason.
    RequestFailed,
}

/// A safe, allowlisted reference to event detail.
///
/// There is no variant that can hold [`DataClass::Confidential`] or
/// [`DataClass::RestrictedSecurity`] text; [`classified_detail`] is the only
/// constructor, and it downgrades those two classes to a digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetailReference {
    /// No additional detail.
    None,
    /// Bounded, truncated public/internal text.
    Text(String),
    /// A one-way digest standing in for confidential/restricted content.
    Digest(Sha256Digest),
}

/// Hashes or bounds a candidate detail value according to its classification.
///
/// [`DataClass::Public`] and [`DataClass::Internal`] values may be kept as
/// bounded text. [`DataClass::Confidential`] and
/// [`DataClass::RestrictedSecurity`] values are always collapsed to a
/// SHA-256 digest: the plaintext is read only long enough to hash it and is
/// never stored in the returned value.
#[must_use]
pub fn classified_detail(class: DataClass, raw: &Sensitive<String>) -> DetailReference {
    match class {
        DataClass::Public | DataClass::Internal => {
            let bounded: String = raw
                .expose_sensitive()
                .chars()
                .take(MAX_DETAIL_TEXT_CHARS)
                .collect();
            DetailReference::Text(bounded)
        }
        DataClass::Confidential | DataClass::RestrictedSecurity => {
            DetailReference::Digest(Sha256Digest::of_bytes(raw.expose_sensitive().as_bytes()))
        }
    }
}

/// One allowlisted, redaction-safe telemetry event.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TelemetryEvent {
    /// The allowlisted event kind.
    pub kind: TelemetryEventKind,
    /// The bounded context this event is attributed to.
    pub context: BoundedContext,
    /// The bounded outcome of the underlying operation.
    pub outcome: Outcome,
    /// The stable, audit-safe reason for the outcome.
    pub reason: ReasonCode,
    /// Opaque tenant reference, never a raw tenant-supplied string.
    pub organization_id: Option<OrganizationId>,
    /// Opaque actor reference.
    pub actor: Option<IdentityRef>,
    /// Unix-epoch milliseconds this event was observed.
    pub observed_at_unix_millis: u64,
    /// Operation duration, when known, for RED duration metrics.
    pub duration_millis: Option<u32>,
    /// Redaction-safe event detail; see [`classified_detail`].
    pub detail: DetailReference,
}

impl TelemetryEvent {
    /// Builds a minimal event with no organization, actor, duration, or
    /// detail attached.
    #[must_use]
    pub const fn new(
        kind: TelemetryEventKind,
        context: BoundedContext,
        outcome: Outcome,
        reason: ReasonCode,
        observed_at_unix_millis: u64,
    ) -> Self {
        Self {
            kind,
            context,
            outcome,
            reason,
            organization_id: None,
            actor: None,
            observed_at_unix_millis,
            duration_millis: None,
            detail: DetailReference::None,
        }
    }

    /// Attaches an opaque organization reference.
    #[must_use]
    pub fn with_organization(mut self, organization_id: OrganizationId) -> Self {
        self.organization_id = Some(organization_id);
        self
    }

    /// Attaches an opaque actor reference.
    #[must_use]
    pub fn with_actor(mut self, actor: IdentityRef) -> Self {
        self.actor = Some(actor);
        self
    }

    /// Attaches a RED-metric duration sample.
    #[must_use]
    pub const fn with_duration_millis(mut self, duration_millis: u32) -> Self {
        self.duration_millis = Some(duration_millis);
        self
    }

    /// Attaches detail through the redaction guard: the caller declares the
    /// classification and only [`classified_detail`]'s safe output is kept.
    #[must_use]
    pub fn with_classified_detail(mut self, class: DataClass, raw: &Sensitive<String>) -> Self {
        self.detail = classified_detail(class, raw);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classified_detail_keeps_public_and_internal_text() {
        let raw = Sensitive::new("dispatcher_lag_ok".to_owned());
        assert_eq!(
            classified_detail(DataClass::Public, &raw),
            DetailReference::Text("dispatcher_lag_ok".to_owned())
        );
        assert_eq!(
            classified_detail(DataClass::Internal, &raw),
            DetailReference::Text("dispatcher_lag_ok".to_owned())
        );
    }

    #[test]
    fn classified_detail_digests_confidential_and_restricted_text() {
        let raw = Sensitive::new("do-not-leak".to_owned());
        assert!(matches!(
            classified_detail(DataClass::Confidential, &raw),
            DetailReference::Digest(_)
        ));
        assert!(matches!(
            classified_detail(DataClass::RestrictedSecurity, &raw),
            DetailReference::Digest(_)
        ));
    }

    #[test]
    fn public_text_is_bounded_not_unbounded() {
        let raw = Sensitive::new("a".repeat(10_000));
        let DetailReference::Text(text) = classified_detail(DataClass::Public, &raw) else {
            panic!("expected bounded text");
        };
        assert_eq!(text.len(), MAX_DETAIL_TEXT_CHARS);
    }

    #[test]
    fn builder_composes_every_optional_field() {
        let org = OrganizationId::new("acmecorp1").unwrap();
        let actor =
            IdentityRef::Human(cauterizer_syntax::identifiers::ActorId::new("alice0001").unwrap());
        let event = TelemetryEvent::new(
            TelemetryEventKind::RequestObserved,
            BoundedContext::RemediationRuns,
            Outcome::Success,
            ReasonCode::RequestSucceeded,
            1_000,
        )
        .with_organization(org.clone())
        .with_actor(actor.clone())
        .with_duration_millis(42);
        assert_eq!(event.organization_id, Some(org));
        assert_eq!(event.actor, Some(actor));
        assert_eq!(event.duration_millis, Some(42));
        assert_eq!(event.detail, DetailReference::None);
    }
}
