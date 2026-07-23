//! Commercial Entitlements application ports and deterministic local adapters.

/// In-memory adapters used by local mode and repository contract tests.
pub mod memory;
/// Application-owned persistence, authorization, audit, and time ports.
pub mod ports;
/// Authorized, audited commercial admission handlers.
pub mod service;

pub use memory::{
    InMemoryAuditSink, InMemoryEntitlementRepository, InMemoryIdempotencyStore, StaticAuthorizer,
};
pub use ports::{
    AccountKey, AuditError, AuditFact, AuditOutcome, AuditSink, AuthorizationDecision,
    CommercialAuthorizer, EntitlementAccountRepository, IdempotencyError, IdempotencyRecord,
    IdempotencyStore, RepositoryCommit, RepositoryError, Versioned,
};
pub use service::{
    CommercialApplicationError, CommercialCommandResult, EntitlementApplicationService,
    ReleaseReservation, ReserveBudget, SettleUsage,
};
