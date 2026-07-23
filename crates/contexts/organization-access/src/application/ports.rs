//! Application-owned persistence, time, ID, event, and audit ports.

use crate::contracts::{AuthorizationAuditFactV1, OrganizationAccessEventV1};
use crate::domain::AuthorizationPolicy;
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{IdempotencyKey, OrganizationId};
use cauterizer_syntax::time::UtcInstant;
use std::fmt;

/// Aggregate plus its optimistic concurrency version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Versioned<T> {
    /// Loaded aggregate.
    pub aggregate: T,
    /// Version that must still be current when saving.
    pub version: u64,
}

/// Atomic save request for aggregate state and integration facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SaveOrganization<T> {
    /// New aggregate state.
    pub aggregate: T,
    /// Expected current version; `None` means create-only.
    pub expected_version: Option<u64>,
    /// Public facts persisted atomically with state.
    pub events: Vec<OrganizationAccessEventV1>,
}

/// Organization aggregate persistence owned by this application.
pub trait OrganizationRepository {
    /// Concrete domain aggregate stored by an implementation.
    type Aggregate: Clone;

    /// Loads one organization. Tenant and aggregate are the same identifier here.
    ///
    /// # Errors
    ///
    /// Returns a repository error when persisted state cannot be read safely.
    fn load(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Option<Versioned<Self::Aggregate>>, RepositoryError>;

    /// Atomically creates or conditionally updates state and its event outbox.
    ///
    /// # Errors
    ///
    /// Returns a conflict for stale versions or corruption for invalid state.
    fn save(
        &mut self,
        organization_id: &OrganizationId,
        request: SaveOrganization<Self::Aggregate>,
    ) -> Result<u64, RepositoryError>;
}

/// Deterministic application clock.
pub trait Clock {
    /// Returns the current canonical instant.
    fn now(&self) -> UtcInstant;
    /// Returns the same instant as Unix milliseconds for domain expiry rules.
    fn now_unix_millis(&self) -> u64;
}

/// Deterministic, context-qualified identifier source.
pub trait IdGenerator {
    /// Returns the next canonical opaque component for a requested namespace.
    fn next_opaque(&mut self, context: &'static str) -> String;
}

/// Append-only authorization audit sink.
pub trait AuditSink {
    /// Records a security decision.
    ///
    /// # Errors
    ///
    /// Returns an audit error when the fact cannot be durably appended.
    fn record(&mut self, fact: AuthorizationAuditFactV1) -> Result<(), AuditError>;
}

/// Organization-scoped immutable authorization policy snapshots.
pub trait AuthorizationPolicyRepository {
    /// Loads the current policy without falling back to another organization.
    fn load_policy(&self, organization_id: &OrganizationId) -> Option<AuthorizationPolicy>;
}

/// Stored idempotent command result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdempotentResult<T> {
    /// Digest of canonical command input.
    pub request_digest: Sha256Digest,
    /// Stable prior result.
    pub result: T,
}

/// Organization-scoped idempotency result store.
pub trait IdempotencyStore<T: Clone> {
    /// Returns a prior result for this exact organization/key.
    fn get(
        &self,
        organization_id: &OrganizationId,
        key: &IdempotencyKey,
    ) -> Option<IdempotentResult<T>>;
    /// Stores a result only if the organization/key is absent.
    ///
    /// # Errors
    ///
    /// Returns a conflict when the key already binds different input or output.
    fn put(
        &mut self,
        organization_id: OrganizationId,
        key: IdempotencyKey,
        value: IdempotentResult<T>,
    ) -> Result<(), IdempotencyError>;
}

/// Stable repository failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepositoryError {
    /// Expected version did not match persisted state.
    Conflict {
        /// Version required by the caller.
        expected: Option<u64>,
        /// Version currently persisted.
        actual: Option<u64>,
    },
    /// Persisted state was invalid/corrupt.
    CorruptState,
}
impl fmt::Display for RepositoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict { .. } => f.write_str("organization version conflict"),
            Self::CorruptState => f.write_str("organization state is corrupt"),
        }
    }
}
impl std::error::Error for RepositoryError {}

/// Stable idempotency failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdempotencyError {
    /// The same key was used for different canonical input.
    ConflictingRequest,
}
impl fmt::Display for IdempotencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("idempotency key conflicts with prior request")
    }
}
impl std::error::Error for IdempotencyError {}

/// Stable audit persistence failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditError;
impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("authorization audit could not be recorded")
    }
}
impl std::error::Error for AuditError {}
