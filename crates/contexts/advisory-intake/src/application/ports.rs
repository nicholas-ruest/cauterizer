//! Application-owned persistence, authorization, and audit ports.
use crate::domain::{AdvisoryFact, AdvisoryRecord};
use cauterizer_syntax::authorization::AuthorizationRequestContext;
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{IdempotencyKey, OrganizationId};
use std::fmt;
/// Optimistically versioned aggregate.
#[derive(Clone, Debug)]
pub struct VersionedRecord {
    /// Aggregate state.
    pub aggregate: AdvisoryRecord,
    /// Monotonic version.
    pub version: u64,
}
/// Atomic state/outbox replacement.
pub struct RecordCommit {
    /// Replacement aggregate.
    pub aggregate: AdvisoryRecord,
    /// Relay-visible facts.
    pub facts: Vec<AdvisoryFact>,
}
/// Exact command binding.
#[derive(Clone, Debug)]
pub struct CommandControl {
    /// Caller-observed version.
    pub expected_version: u64,
    /// Tenant-scoped retry key.
    pub idempotency_key: IdempotencyKey,
    /// Complete canonical request digest.
    pub request_digest: Sha256Digest,
}
/// Atomic commit result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitOutcome {
    /// Newly committed version.
    Committed(u64),
    /// Exact prior command version.
    Replayed(u64),
}
/// Tenant-qualified repository, suitable for a relational transaction adapter.
pub trait AdvisoryRecordRepository {
    /// Loads exactly one tenant/record aggregate.
    /// # Errors
    /// Returns a stable storage failure.
    fn load(
        &self,
        tenant: &OrganizationId,
        record: &str,
    ) -> Result<Option<VersionedRecord>, RepositoryError>;
    /// Creates state atomically.
    /// # Errors
    /// Rejects an existing tenant/record key.
    fn create(
        &self,
        tenant: OrganizationId,
        record: String,
        commit: RecordCommit,
    ) -> Result<u64, RepositoryError>;
    /// Creates a record with an atomic retry binding; exact retries replay.
    /// # Errors
    /// Rejects nonzero expected version, key reuse, collision, or storage failure.
    fn create_command(
        &self,
        tenant: OrganizationId,
        record: String,
        control: &CommandControl,
        commit: RecordCommit,
    ) -> Result<CommitOutcome, RepositoryError>;
    /// Atomically checks retry/version and commits state, facts, and retry binding.
    /// # Errors
    /// Rejects stale versions, conflicting retries, absence, or storage failure.
    fn commit(
        &self,
        tenant: &OrganizationId,
        record: &str,
        control: &CommandControl,
        commit: RecordCommit,
    ) -> Result<CommitOutcome, RepositoryError>;
}
/// Stable persistence failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryError {
    /// Missing record.
    NotFound,
    /// Stale/create collision.
    Conflict,
    /// Same retry key, different input.
    IdempotencyConflict,
    /// Version exhausted.
    VersionExhausted,
    /// Dependency unavailable.
    Unavailable,
}
impl fmt::Display for RepositoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotFound => "advisory_record_not_found",
            Self::Conflict => "advisory_record_conflict",
            Self::IdempotencyConflict => "advisory_idempotency_conflict",
            Self::VersionExhausted => "advisory_version_exhausted",
            Self::Unavailable => "advisory_repository_unavailable",
        })
    }
}
impl std::error::Error for RepositoryError {}
/// Deny-default decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDecision {
    /// Explicit grant.
    Allow,
    /// Deny or absent grant.
    Deny,
}
/// Organization & Access anti-corruption port.
pub trait AdvisoryAuthorizer {
    /// Evaluates the complete request.
    fn authorize(&self, request: &AuthorizationRequestContext) -> AuthorizationDecision;
}
/// Audit-safe result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditOutcome {
    /// Denied before work.
    Denied,
    /// Committed or replayed.
    Succeeded,
    /// Authorized failure.
    Failed,
}
/// Append-only audit fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditFact {
    /// Tenant.
    pub tenant: OrganizationId,
    /// Action.
    pub action: String,
    /// Record ID.
    pub record: String,
    /// Coarse result.
    pub outcome: AuditOutcome,
}
/// Mandatory audit sink.
pub trait AuditSink {
    /// Records a fact.
    /// # Errors
    /// Fails when durable audit is unavailable.
    fn record(&self, fact: AuditFact) -> Result<(), AuditError>;
}
/// Stable audit error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditError;
impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("advisory_audit_unavailable")
    }
}
impl std::error::Error for AuditError {}
