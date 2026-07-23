//! Application-owned durable process-manager ports.
use cauterizer_syntax::authorization::AuthorizationRequestContext;
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{ContextQualifiedId, IdempotencyKey, OrganizationId};
use std::fmt;

/// Tenant-qualified run key.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RunKey {
    /// Tenant.
    pub tenant: OrganizationId,
    /// Context-owned run identity.
    pub run_id: ContextQualifiedId,
}
/// Optimistically versioned aggregate.
#[derive(Clone, Debug)]
pub struct Versioned<A> {
    /// State.
    pub aggregate: A,
    /// Monotonic version.
    pub version: u64,
}
/// Atomic state/outbox replacement.
pub struct Commit<A, E> {
    /// Replacement aggregate.
    pub aggregate: A,
    /// Facts published transactionally.
    pub events: Vec<E>,
}
/// Direct-command retry/concurrency binding.
#[derive(Clone, Debug)]
pub struct CommandControl {
    /// Caller-observed version.
    pub expected_version: u64,
    /// Tenant/run-scoped retry key.
    pub idempotency_key: IdempotencyKey,
    /// Digest of complete canonical input.
    pub request_digest: Sha256Digest,
}
/// Authenticated owning-context event metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboundEnvelope {
    /// Tenant asserted by verified contract.
    pub tenant: OrganizationId,
    /// Stable producer context.
    pub producer: String,
    /// Producer aggregate stream.
    pub stream: String,
    /// Strict next sequence.
    pub sequence: u64,
    /// Globally unique event identity.
    pub event_id: ContextQualifiedId,
    /// Digest of authenticated canonical event.
    pub payload_digest: Sha256Digest,
}
/// Atomic commit result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitOutcome {
    /// New version.
    Committed(u64),
    /// Exact command already committed.
    Replayed(u64),
    /// Exact inbound event already applied.
    DuplicateInbound(u64),
}
/// Generic durable run repository. A relational adapter must implement each method as one transaction.
pub trait RemediationRunRepository<A: Clone, E: Clone> {
    /// Loads one exact tenant/run key.
    /// # Errors
    /// Returns stable storage failure.
    fn load(&self, key: &RunKey) -> Result<Option<Versioned<A>>, RepositoryError>;
    /// Creates a run under an idempotency binding.
    /// # Errors
    /// Rejects collision, nonzero version, retry conflict, or storage failure.
    fn create(
        &self,
        key: RunKey,
        control: &CommandControl,
        commit: Commit<A, E>,
    ) -> Result<CommitOutcome, RepositoryError>;
    /// Commits a direct command, state, and outbox atomically.
    /// # Errors
    /// Rejects stale version/retry conflict or storage failure.
    fn commit_command(
        &self,
        key: &RunKey,
        control: &CommandControl,
        commit: Commit<A, E>,
    ) -> Result<CommitOutcome, RepositoryError>;
    /// Commits an authenticated inbound transition, inbox receipt, state, and outbox atomically.
    /// # Errors
    /// Rejects tenant mismatch, payload substitution, gaps, stale version, or storage failure.
    fn commit_inbound(
        &self,
        key: &RunKey,
        expected_version: u64,
        envelope: &InboundEnvelope,
        commit: Commit<A, E>,
    ) -> Result<CommitOutcome, RepositoryError>;
}
/// Stable durable-boundary failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryError {
    /// Missing run.
    NotFound,
    /// Stale version or create collision.
    Conflict,
    /// Retry/event identity reused for different payload.
    IdempotencyConflict,
    /// Event skipped a producer sequence.
    OutOfOrder,
    /// Tenant boundary mismatch.
    TenantMismatch,
    /// Version exhausted.
    VersionExhausted,
    /// Dependency unavailable.
    Unavailable,
}
impl fmt::Display for RepositoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotFound => "run_not_found",
            Self::Conflict => "run_version_conflict",
            Self::IdempotencyConflict => "run_idempotency_conflict",
            Self::OutOfOrder => "run_inbound_out_of_order",
            Self::TenantMismatch => "run_tenant_mismatch",
            Self::VersionExhausted => "run_version_exhausted",
            Self::Unavailable => "run_repository_unavailable",
        })
    }
}
impl std::error::Error for RepositoryError {}
/// Deny-default authorization result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDecision {
    /// Explicit allow.
    Allow,
    /// Deny or missing grant.
    Deny,
}
/// Organization & Access anti-corruption port.
pub trait RunAuthorizer {
    /// Evaluates complete request.
    fn authorize(&self, request: &AuthorizationRequestContext) -> AuthorizationDecision;
}
/// Coarse audit result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditOutcome {
    /// Denied before domain work.
    Denied,
    /// Committed/replayed.
    Succeeded,
    /// Authorized failure.
    Failed,
}
/// Payload-free audit fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditFact {
    /// Tenant.
    pub tenant: OrganizationId,
    /// Action.
    pub action: String,
    /// Run identity.
    pub run: String,
    /// Coarse result.
    pub outcome: AuditOutcome,
}
/// Mandatory append-only audit sink.
pub trait AuditSink {
    /// Records one fact.
    /// # Errors
    /// Fails when durable audit is unavailable.
    fn record(&self, fact: AuditFact) -> Result<(), AuditError>;
}
/// Stable audit failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditError;
impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("run_audit_unavailable")
    }
}
impl std::error::Error for AuditError {}
