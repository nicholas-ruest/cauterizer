//! Application-owned ports with no persistence or provider types.

use std::fmt;

use cauterizer_syntax::authorization::{ActionName, AuthorizationRequestContext};
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{ContextQualifiedId, IdempotencyKey, OrganizationId};
use cauterizer_syntax::schema::SchemaVersion;

/// Tenant-qualified entitlement-account repository key.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AccountKey {
    /// Immutable owning tenant.
    pub organization_id: OrganizationId,
    /// Context-owned account ID.
    pub account_id: ContextQualifiedId,
}

/// Optimistically versioned aggregate snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Versioned<A> {
    /// Private aggregate value owned by the domain module.
    pub aggregate: A,
    /// Monotonically increasing repository version.
    pub version: u64,
}

/// Staged aggregate mutation and outgoing facts committed together.
pub struct RepositoryCommit<A, E> {
    /// Replacement aggregate after its invariants passed.
    pub aggregate: A,
    /// Immutable domain/public facts made relay-visible atomically.
    pub events: Vec<E>,
}

/// Context repository contract. Implementations must isolate tenant keys and
/// make aggregate state plus outgoing events visible atomically.
pub trait EntitlementAccountRepository<A: Clone, E: Clone> {
    /// Loads one exact tenant-qualified account.
    ///
    /// # Errors
    ///
    /// Storage failures return a payload-safe error.
    fn load(&self, key: &AccountKey) -> Result<Option<Versioned<A>>, RepositoryError>;

    /// Executes an invariant-enforcing mutation under one optimistic lock.
    ///
    /// The callback runs while the account is exclusively locked. No state or
    /// event becomes visible if it fails or if the expected version is stale.
    ///
    /// # Errors
    ///
    /// Returns conflict, missing account, version exhaustion, or callback error.
    fn transact<T, F>(
        &self,
        key: &AccountKey,
        expected_version: u64,
        operation: F,
    ) -> Result<T, RepositoryError>
    where
        F: FnOnce(&A) -> Result<(RepositoryCommit<A, E>, T), RepositoryError>;

    /// Creates an account only when no tenant-qualified account exists.
    ///
    /// # Errors
    ///
    /// Existing account or storage failure leaves all state unchanged.
    fn create(
        &self,
        key: AccountKey,
        commit: RepositoryCommit<A, E>,
    ) -> Result<u64, RepositoryError>;
}

/// Stable repository failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryError {
    /// Requested account does not exist in this tenant.
    NotFound,
    /// Create collided or optimistic version was stale.
    Conflict,
    /// Aggregate version cannot advance.
    VersionExhausted,
    /// Domain behavior rejected the mutation; details stay in its own result contract.
    MutationRejected,
    /// Persistence dependency unavailable.
    Unavailable,
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotFound => "entitlement_account_not_found",
            Self::Conflict => "entitlement_account_version_conflict",
            Self::VersionExhausted => "entitlement_account_version_exhausted",
            Self::MutationRejected => "entitlement_mutation_rejected",
            Self::Unavailable => "entitlement_repository_unavailable",
        })
    }
}
impl std::error::Error for RepositoryError {}

/// Exact prior command result bound to canonical input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdempotencyRecord<R> {
    /// Digest of the complete canonical command.
    pub request_digest: Sha256Digest,
    /// Stable prior result.
    pub result: R,
}

/// Tenant- and command-scoped idempotency result store.
pub trait IdempotencyStore<R: Clone> {
    /// Returns a prior result for this exact tenant/scope/key.
    fn get(
        &self,
        organization_id: &OrganizationId,
        scope: &ActionName,
        key: &IdempotencyKey,
    ) -> Option<IdempotencyRecord<R>>;
    /// Records a result or validates an exact retry.
    ///
    /// # Errors
    ///
    /// A key already bound to different input/result is rejected.
    fn put(
        &self,
        organization_id: OrganizationId,
        scope: ActionName,
        key: IdempotencyKey,
        record: IdempotencyRecord<R>,
    ) -> Result<(), IdempotencyError>;
}

/// Stable idempotency conflict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdempotencyError;
impl fmt::Display for IdempotencyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("entitlement_idempotency_conflict")
    }
}
impl std::error::Error for IdempotencyError {}

/// Coarse authorization result; commercial policy cannot weaken verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDecision {
    /// Exact tenant/action/resource/purpose request was authorized.
    Allow,
    /// Deny by default.
    Deny,
}

/// Organization & Access anti-corruption port.
pub trait CommercialAuthorizer {
    /// Evaluates the complete shared authorization request.
    fn authorize(&self, request: &AuthorizationRequestContext) -> AuthorizationDecision;
}

/// Audit-safe commercial operation result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditOutcome {
    /// Authorization denied; no mutation attempted.
    Denied,
    /// Authorization succeeded; the separately recorded operation may now execute.
    Authorized,
    /// Command committed or returned its exact prior result.
    Succeeded,
    /// Authorized command failed without provider/payload details.
    Failed,
}

/// Append-only audit fact for admission and privileged mutations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditFact {
    /// Tenant boundary.
    pub organization_id: OrganizationId,
    /// Stable action vocabulary.
    pub action: ActionName,
    /// Correlation-safe command/resource reference.
    pub subject: ContextQualifiedId,
    /// Policy version used by the authorizer.
    pub policy_version: SchemaVersion,
    /// Coarse non-sensitive outcome.
    pub outcome: AuditOutcome,
}

/// Append-only audit sink. Failure must fail closed for admission/mutation.
pub trait AuditSink {
    /// Records one security/commercial decision.
    ///
    /// # Errors
    ///
    /// Durable audit failure is returned to the handler.
    fn record(&self, fact: AuditFact) -> Result<(), AuditError>;
}

/// Stable mandatory-audit failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditError;
impl fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("entitlement_audit_unavailable")
    }
}
impl std::error::Error for AuditError {}
