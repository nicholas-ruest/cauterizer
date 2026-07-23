//! Durable lease persistence and command retry ports.
use crate::domain::{ExecutionEvent, ExecutionLease};
use cauterizer_syntax::authorization::AuthorizationRequestContext;
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{IdempotencyKey, OrganizationId};
use std::fmt;
/// Tenant-qualified lease key.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LeaseKey {
    /// Tenant.
    pub tenant: OrganizationId,
    /// Lease ID spelling.
    pub lease: String,
}
/// Versioned lease.
#[derive(Clone, Debug)]
pub struct VersionedLease {
    /// Aggregate.
    pub aggregate: ExecutionLease,
    /// Version.
    pub version: u64,
}
/// Exact retry binding.
#[derive(Clone, Debug)]
pub struct CommandControl {
    /// Caller-observed version.
    pub expected_version: u64,
    /// Retry key.
    pub idempotency_key: IdempotencyKey,
    /// Canonical request digest.
    pub request_digest: Sha256Digest,
}
/// State and outbox commit.
pub struct LeaseCommit {
    /// Replacement state.
    pub aggregate: ExecutionLease,
    /// Newly emitted events only.
    pub events: Vec<ExecutionEvent>,
}
/// Commit result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitOutcome {
    /// New version.
    Committed(u64),
    /// Exact prior result.
    Replayed(u64),
}
/// Transactional lease repository.
pub trait ExecutionLeaseRepository {
    /// Loads exact tenant/lease.
    /// # Errors
    /// Returns stable storage failure.
    fn load(&self, key: &LeaseKey) -> Result<Option<VersionedLease>, RepositoryError>;
    /// Creates state/outbox/retry atomically.
    /// # Errors
    /// Rejects collision, stale version, retry conflict, or storage failure.
    fn create(
        &self,
        key: LeaseKey,
        control: &CommandControl,
        commit: LeaseCommit,
    ) -> Result<CommitOutcome, RepositoryError>;
    /// Commits state/outbox/retry atomically.
    /// # Errors
    /// Rejects absence, stale version, retry conflict, or storage failure.
    fn commit(
        &self,
        key: &LeaseKey,
        control: &CommandControl,
        commit: LeaseCommit,
    ) -> Result<CommitOutcome, RepositoryError>;
}
/// Stable repository error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryError {
    /// Missing lease.
    NotFound,
    /// Stale version/collision.
    Conflict,
    /// Retry key substitution.
    IdempotencyConflict,
    /// Version exhausted.
    VersionExhausted,
    /// Dependency unavailable.
    Unavailable,
}
impl fmt::Display for RepositoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for RepositoryError {}
/// Deny-default authorization decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDecision {
    /// Explicit allow.
    Allow,
    /// Denied or absent grant.
    Deny,
}
/// Organization & Access port.
pub trait ExecutionAuthorizer {
    /// Evaluates complete request.
    fn authorize(&self, request: &AuthorizationRequestContext) -> AuthorizationDecision;
}
/// Coarse audit outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditOutcome {
    /// Denied.
    Denied,
    /// Committed/replayed.
    Succeeded,
    /// Authorized rejection.
    Failed,
}
/// Payload-free audit fact.
pub struct AuditFact {
    /// Tenant.
    pub tenant: OrganizationId,
    /// Action.
    pub action: String,
    /// Lease.
    pub lease: String,
    /// Result.
    pub outcome: AuditOutcome,
}
/// Mandatory audit sink.
pub trait AuditSink {
    /// Records one fact.
    /// # Errors
    /// Fails when durable audit unavailable.
    fn record(&self, fact: AuditFact) -> Result<(), AuditError>;
}
/// Audit failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditError;
impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("execution_audit_unavailable")
    }
}
impl std::error::Error for AuditError {}
