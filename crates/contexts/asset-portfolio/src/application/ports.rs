//! Application-owned ports for persistence, authorization, and audit.

use std::fmt;

use cauterizer_syntax::authorization::AuthorizationRequestContext;
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{IdempotencyKey, OrganizationId};

use crate::domain::{AssetEvent, AssetPortfolio};

/// Optimistically versioned portfolio.
#[derive(Clone, Debug)]
pub struct VersionedPortfolio {
    /// Aggregate state.
    pub aggregate: AssetPortfolio,
    /// Monotonic persistence version.
    pub version: u64,
}

/// Atomic aggregate and outbox replacement.
pub struct PortfolioCommit {
    /// Replacement state.
    pub aggregate: AssetPortfolio,
    /// Facts made relay-visible in the same transaction.
    pub events: Vec<AssetEvent>,
}

/// Caller-supplied concurrency and exact-retry binding for a command.
#[derive(Clone, Debug)]
pub struct CommandControl {
    /// Version observed by the caller before constructing the command.
    pub expected_version: u64,
    /// Tenant-scoped stable retry key.
    pub idempotency_key: IdempotencyKey,
    /// Digest of the canonical complete command input.
    pub request_digest: Sha256Digest,
}

/// Result of an atomic command commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandCommitOutcome {
    /// State and outbox advanced to this version.
    Committed(u64),
    /// The exact command was already committed at this version.
    Replayed(u64),
}

/// Tenant-qualified optimistic repository contract, implementable by a relational adapter.
pub trait AssetPortfolioRepository {
    /// Loads exactly one tenant portfolio.
    ///
    /// # Errors
    /// Returns a payload-safe storage failure.
    fn load(&self, tenant: &OrganizationId) -> Result<Option<VersionedPortfolio>, RepositoryError>;
    /// Creates a tenant portfolio and its outbox rows atomically.
    ///
    /// # Errors
    /// Returns conflict or storage failure without partial visibility.
    fn create(
        &self,
        tenant: OrganizationId,
        commit: PortfolioCommit,
    ) -> Result<u64, RepositoryError>;
    /// Commits state and outbox rows under an expected version.
    ///
    /// # Errors
    /// Returns conflict, absence, exhaustion, or storage failure atomically.
    fn commit_command(
        &self,
        tenant: &OrganizationId,
        control: &CommandControl,
        commit: PortfolioCommit,
    ) -> Result<CommandCommitOutcome, RepositoryError>;
}

/// Stable repository failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryError {
    /// Tenant portfolio is absent.
    NotFound,
    /// Optimistic version or create collided.
    Conflict,
    /// Retry key was previously bound to different canonical input.
    IdempotencyConflict,
    /// Version counter cannot advance.
    VersionExhausted,
    /// Storage dependency is unavailable.
    Unavailable,
}
impl fmt::Display for RepositoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotFound => "asset_portfolio_not_found",
            Self::Conflict => "asset_portfolio_conflict",
            Self::IdempotencyConflict => "asset_idempotency_conflict",
            Self::VersionExhausted => "asset_portfolio_version_exhausted",
            Self::Unavailable => "asset_portfolio_unavailable",
        })
    }
}
impl std::error::Error for RepositoryError {}

/// Deny-default policy decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDecision {
    /// Policy explicitly allowed the request.
    Allow,
    /// Policy denied or had no matching grant.
    Deny,
}
/// Organization & Access anti-corruption port.
pub trait AssetAuthorizer {
    /// Evaluates the complete request.
    fn authorize(&self, request: &AuthorizationRequestContext) -> AuthorizationDecision;
}

/// Audit outcome without source or revision payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditOutcome {
    /// Admission was denied.
    Denied,
    /// Operation committed or query succeeded.
    Succeeded,
    /// Authorized operation failed safely.
    Failed,
}
/// Append-only audit fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditFact {
    /// Tenant boundary.
    pub organization_id: OrganizationId,
    /// Stable action.
    pub action: String,
    /// Context-owned resource ID.
    pub resource: String,
    /// Coarse result.
    pub outcome: AuditOutcome,
}
/// Mandatory audit boundary.
pub trait AuditSink {
    /// Records one decision.
    /// # Errors
    /// Fails when durable audit is unavailable.
    fn record(&self, fact: AuditFact) -> Result<(), AuditError>;
}
/// Stable audit failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditError;
impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("asset_audit_unavailable")
    }
}
impl std::error::Error for AuditError {}
