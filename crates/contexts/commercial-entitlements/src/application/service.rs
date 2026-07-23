//! Authorized and idempotent cost-admission application handlers.

use std::fmt;
use std::sync::{Arc, Mutex};

use cauterizer_syntax::authorization::{ActionName, AuthorizationRequestContext};
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::IdempotencyKey;
use cauterizer_syntax::schema::SchemaVersion;

use crate::domain::{
    BudgetReservation, EntitlementAccount, EntitlementError, EntitlementEvent, ReservationId,
    ReservationRequest, UsageRecord,
};

use super::ports::{
    AccountKey, AuditError, AuditFact, AuditOutcome, AuditSink, AuthorizationDecision,
    CommercialAuthorizer, EntitlementAccountRepository, IdempotencyError, IdempotencyRecord,
    IdempotencyStore, RepositoryCommit, RepositoryError,
};

/// Stable result vocabulary shared by mutating commercial handlers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommercialCommandResult {
    /// Worst-case capacity was admitted.
    Reserved(BudgetReservation),
    /// Held capacity was returned.
    Released(BudgetReservation),
    /// Actual immutable usage was recorded.
    Settled(UsageRecord),
}

/// Common command security/retry metadata.
pub struct CommandContext {
    /// Complete authenticated request; action/resource/purpose are policy inputs.
    pub authorization: AuthorizationRequestContext,
    /// Policy revision used by the external authorizer.
    pub policy_version: SchemaVersion,
    /// Tenant-qualified aggregate key.
    pub account: AccountKey,
    /// Required optimistic repository version.
    pub expected_version: u64,
    /// Tenant/action-scoped retry key.
    pub idempotency_key: IdempotencyKey,
    /// Canonical digest of the complete command.
    pub request_digest: Sha256Digest,
}

/// Worst-case budget admission command.
pub struct ReserveBudget {
    /// Security/retry metadata.
    pub context: CommandContext,
    /// Domain-owned admission request.
    pub request: ReservationRequest,
}

/// Idempotent unused-capacity release command.
pub struct ReleaseReservation {
    /// Security/retry metadata.
    pub context: CommandContext,
    /// Exact reservation identity.
    pub reservation_id: ReservationId,
}

/// Idempotent actual-usage settlement command.
pub struct SettleUsage {
    /// Security/retry metadata.
    pub context: CommandContext,
    /// Immutable usage record.
    pub usage: UsageRecord,
}

/// Direct application facade independent of billing providers and transports.
pub struct EntitlementApplicationService<R, I, Z, A> {
    repository: R,
    idempotency: I,
    authorizer: Z,
    audit: A,
    command_lock: Arc<Mutex<()>>,
}

impl<R, I, Z, A> EntitlementApplicationService<R, I, Z, A>
where
    R: EntitlementAccountRepository<EntitlementAccount, EntitlementEvent>,
    I: IdempotencyStore<CommercialCommandResult>,
    Z: CommercialAuthorizer,
    A: AuditSink,
{
    /// Wires application-owned ports.
    #[must_use]
    pub fn new(repository: R, idempotency: I, authorizer: Z, audit: A) -> Self {
        Self {
            repository,
            idempotency,
            authorizer,
            audit,
            command_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Strongly admits worst-case budget.
    ///
    /// # Errors
    ///
    /// Denies unauthorized/cross-tenant input and rejects stale, conflicting,
    /// over-quota, suspended, unauditable, or replay-conflicting commands.
    pub fn reserve(
        &self,
        command: ReserveBudget,
    ) -> Result<BudgetReservation, CommercialApplicationError> {
        let scope = ActionName::parse("entitlements.reserve")
            .map_err(|_| CommercialApplicationError::InvalidCommand)?;
        let _guard = self.lock_commands()?;
        if let Some(result) = self.preflight(&command.context, &scope)? {
            return match result {
                CommercialCommandResult::Reserved(value) => Ok(value),
                _ => Err(CommercialApplicationError::IdempotencyConflict),
            };
        }
        if command.request.request_digest != command.context.request_digest {
            return Err(CommercialApplicationError::InvalidCommand);
        }
        let result = self.repository.transact(
            &command.context.account,
            command.context.expected_version,
            |account| {
                let mut account = account.clone();
                let reservation = account
                    .reserve(command.request)
                    .map_err(|_| RepositoryError::MutationRejected)?;
                let events = account.take_pending_events();
                Ok((
                    RepositoryCommit {
                        aggregate: account,
                        events,
                    },
                    reservation,
                ))
            },
        )?;
        self.remember(
            &command.context,
            scope,
            CommercialCommandResult::Reserved(result.clone()),
        )?;
        Ok(result)
    }

    /// Idempotently releases unused held budget.
    ///
    /// # Errors
    ///
    /// Uses the same fail-closed authorization, audit, retry, and concurrency rules.
    #[allow(clippy::needless_pass_by_value)]
    pub fn release(
        &self,
        command: ReleaseReservation,
    ) -> Result<BudgetReservation, CommercialApplicationError> {
        let scope = ActionName::parse("entitlements.release")
            .map_err(|_| CommercialApplicationError::InvalidCommand)?;
        let _guard = self.lock_commands()?;
        if let Some(result) = self.preflight(&command.context, &scope)? {
            return match result {
                CommercialCommandResult::Released(value) => Ok(value),
                _ => Err(CommercialApplicationError::IdempotencyConflict),
            };
        }
        let result = self.repository.transact(
            &command.context.account,
            command.context.expected_version,
            |account| {
                let mut account = account.clone();
                let reservation = account
                    .release(&command.reservation_id)
                    .map_err(|_| RepositoryError::MutationRejected)?;
                let events = account.take_pending_events();
                Ok((
                    RepositoryCommit {
                        aggregate: account,
                        events,
                    },
                    reservation,
                ))
            },
        )?;
        self.remember(
            &command.context,
            scope,
            CommercialCommandResult::Released(result.clone()),
        )?;
        Ok(result)
    }

    /// Idempotently settles immutable actual usage.
    ///
    /// # Errors
    ///
    /// Uses the same fail-closed authorization, audit, retry, and concurrency rules.
    pub fn settle(&self, command: SettleUsage) -> Result<UsageRecord, CommercialApplicationError> {
        let scope = ActionName::parse("entitlements.settle")
            .map_err(|_| CommercialApplicationError::InvalidCommand)?;
        let _guard = self.lock_commands()?;
        if let Some(result) = self.preflight(&command.context, &scope)? {
            return match result {
                CommercialCommandResult::Settled(value) => Ok(value),
                _ => Err(CommercialApplicationError::IdempotencyConflict),
            };
        }
        if command.usage.settlement_digest != command.context.request_digest {
            return Err(CommercialApplicationError::InvalidCommand);
        }
        let result = self.repository.transact(
            &command.context.account,
            command.context.expected_version,
            |account| {
                let mut account = account.clone();
                let usage = account
                    .settle(command.usage)
                    .map_err(|_| RepositoryError::MutationRejected)?;
                let events = account.take_pending_events();
                Ok((
                    RepositoryCommit {
                        aggregate: account,
                        events,
                    },
                    usage,
                ))
            },
        )?;
        self.remember(
            &command.context,
            scope,
            CommercialCommandResult::Settled(result.clone()),
        )?;
        Ok(result)
    }

    fn preflight(
        &self,
        context: &CommandContext,
        scope: &ActionName,
    ) -> Result<Option<CommercialCommandResult>, CommercialApplicationError> {
        if context.authorization.organization_id() != &context.account.organization_id
            || context.authorization.action() != scope
        {
            return Err(CommercialApplicationError::Unauthorized);
        }
        if let Some(prior) = self.idempotency.get(
            &context.account.organization_id,
            scope,
            &context.idempotency_key,
        ) {
            return if prior.request_digest == context.request_digest {
                Ok(Some(prior.result))
            } else {
                Err(CommercialApplicationError::IdempotencyConflict)
            };
        }
        let decision = self.authorizer.authorize(&context.authorization);
        let outcome = if decision == AuthorizationDecision::Allow {
            AuditOutcome::Authorized
        } else {
            AuditOutcome::Denied
        };
        self.audit.record(AuditFact {
            organization_id: context.account.organization_id.clone(),
            action: scope.clone(),
            subject: context.account.account_id.clone(),
            policy_version: context.policy_version.clone(),
            outcome,
        })?;
        if decision == AuthorizationDecision::Deny {
            return Err(CommercialApplicationError::Unauthorized);
        }
        Ok(None)
    }

    fn remember(
        &self,
        context: &CommandContext,
        scope: ActionName,
        result: CommercialCommandResult,
    ) -> Result<(), CommercialApplicationError> {
        self.idempotency.put(
            context.account.organization_id.clone(),
            scope,
            context.idempotency_key.clone(),
            IdempotencyRecord {
                request_digest: context.request_digest,
                result,
            },
        )?;
        Ok(())
    }

    fn lock_commands(&self) -> Result<std::sync::MutexGuard<'_, ()>, CommercialApplicationError> {
        self.command_lock
            .lock()
            .map_err(|_| CommercialApplicationError::Unavailable)
    }
}

/// Payload-safe application failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommercialApplicationError {
    /// Request/action/tenant was not authorized.
    Unauthorized,
    /// Boundary input was inconsistent or non-canonical.
    InvalidCommand,
    /// Same replay key was bound to different canonical input or result type.
    IdempotencyConflict,
    /// Domain admission/lifecycle policy denied the mutation.
    DomainRejected,
    /// Optimistic repository version was stale.
    VersionConflict,
    /// Mandatory audit could not be recorded.
    AuditUnavailable,
    /// Application dependency unavailable.
    Unavailable,
}

impl From<RepositoryError> for CommercialApplicationError {
    fn from(value: RepositoryError) -> Self {
        match value {
            RepositoryError::Conflict => Self::VersionConflict,
            RepositoryError::MutationRejected => Self::DomainRejected,
            RepositoryError::NotFound
            | RepositoryError::VersionExhausted
            | RepositoryError::Unavailable => Self::Unavailable,
        }
    }
}
impl From<IdempotencyError> for CommercialApplicationError {
    fn from(_: IdempotencyError) -> Self {
        Self::IdempotencyConflict
    }
}
impl From<AuditError> for CommercialApplicationError {
    fn from(_: AuditError) -> Self {
        Self::AuditUnavailable
    }
}
impl From<EntitlementError> for CommercialApplicationError {
    fn from(_: EntitlementError) -> Self {
        Self::DomainRejected
    }
}
impl fmt::Display for CommercialApplicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unauthorized => "commercial_unauthorized",
            Self::InvalidCommand => "commercial_invalid_command",
            Self::IdempotencyConflict => "commercial_idempotency_conflict",
            Self::DomainRejected => "commercial_denied",
            Self::VersionConflict => "commercial_version_conflict",
            Self::AuditUnavailable => "commercial_audit_unavailable",
            Self::Unavailable => "commercial_unavailable",
        })
    }
}
impl std::error::Error for CommercialApplicationError {}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use cauterizer_syntax::authorization::{Purpose, ResourceRef};
    use cauterizer_syntax::identifiers::{ActorId, IdentityRef, OrganizationId};

    use crate::application::{
        InMemoryAuditSink, InMemoryEntitlementRepository, InMemoryIdempotencyStore,
        StaticAuthorizer,
    };
    use crate::domain::{
        DeploymentProfile, EntitlementAccount, Plan, PlanId, QuotaWindow, ReservationId,
        UsageDimension, UsageRecordId,
    };

    use super::*;

    type Repository = InMemoryEntitlementRepository<EntitlementAccount, EntitlementEvent>;
    type Service = EntitlementApplicationService<
        Repository,
        InMemoryIdempotencyStore<CommercialCommandResult>,
        StaticAuthorizer,
        InMemoryAuditSink,
    >;

    fn account_key() -> AccountKey {
        AccountKey {
            organization_id: OrganizationId::new("00000000").unwrap(),
            account_id: cauterizer_syntax::identifiers::ContextQualifiedId::new(
                "entitlement-account",
                "00000000",
            )
            .unwrap(),
        }
    }

    fn dimension() -> UsageDimension {
        UsageDimension::new("solver.tokens").unwrap()
    }

    fn setup() -> (Service, Repository, StaticAuthorizer, InMemoryAuditSink) {
        let repository = Repository::default();
        let plan = Plan::metered(
            PlanId::new("00000000").unwrap(),
            1,
            BTreeMap::from([(dimension(), 10)]),
            BTreeSet::new(),
        )
        .unwrap();
        let mut account = EntitlementAccount::open(
            OrganizationId::new("00000000").unwrap(),
            DeploymentProfile::Production,
            plan,
        )
        .unwrap();
        let events = account.take_pending_events();
        repository
            .create(
                account_key(),
                RepositoryCommit {
                    aggregate: account,
                    events,
                },
            )
            .unwrap();
        let authorizer = StaticAuthorizer::default();
        let audit = InMemoryAuditSink::default();
        let service = EntitlementApplicationService::new(
            repository.clone(),
            InMemoryIdempotencyStore::default(),
            authorizer.clone(),
            audit.clone(),
        );
        (service, repository, authorizer, audit)
    }

    fn authorization(action: &str) -> AuthorizationRequestContext {
        AuthorizationRequestContext::new(
            OrganizationId::new("00000000").unwrap(),
            IdentityRef::Human(ActorId::new("00000000").unwrap()),
            ActionName::parse(action).unwrap(),
            ResourceRef::parse("entitlement-account:00000000").unwrap(),
            Purpose::parse("cost admission").unwrap(),
        )
    }

    fn context(action: &str, version: u64, key: &str, digest: Sha256Digest) -> CommandContext {
        CommandContext {
            authorization: authorization(action),
            policy_version: SchemaVersion::parse("1.0.0").unwrap(),
            account: account_key(),
            expected_version: version,
            idempotency_key: IdempotencyKey::new(key).unwrap(),
            request_digest: digest,
        }
    }

    fn reservation(number: u64, units: u64, digest: Sha256Digest) -> ReservationRequest {
        ReservationRequest {
            id: ReservationId::new(&format!("{number:08}")).unwrap(),
            request_digest: digest,
            window: QuotaWindow::new(0, 100).unwrap(),
            worst_case: BTreeMap::from([(dimension(), units)]),
        }
    }

    #[test]
    fn reserve_and_release_are_authorized_audited_and_exactly_idempotent() {
        let (service, repository, authorizer, audit) = setup();
        let reserve_auth = authorization("entitlements.reserve");
        authorizer.allow(reserve_auth);
        let reserve_digest = Sha256Digest::of_bytes("reserve-1");
        let reserve = || ReserveBudget {
            context: context("entitlements.reserve", 1, "reserve-0001", reserve_digest),
            request: reservation(1, 6, reserve_digest),
        };
        let first = service.reserve(reserve()).unwrap();
        assert_eq!(service.reserve(reserve()).unwrap(), first);
        assert_eq!(repository.load(&account_key()).unwrap().unwrap().version, 2);

        authorizer.allow(authorization("entitlements.release"));
        let release_digest = Sha256Digest::of_bytes("release-1");
        let release = || ReleaseReservation {
            context: context("entitlements.release", 2, "release-0001", release_digest),
            reservation_id: ReservationId::new("00000001").unwrap(),
        };
        let released = service.release(release()).unwrap();
        assert_eq!(service.release(release()).unwrap(), released);
        assert_eq!(repository.load(&account_key()).unwrap().unwrap().version, 3);
        assert_eq!(audit.facts().len(), 2);
    }

    #[test]
    fn settlement_handler_is_idempotent_and_usage_reconciles() {
        let (service, repository, authorizer, _) = setup();
        authorizer.allow(authorization("entitlements.reserve"));
        let reserve_digest = Sha256Digest::of_bytes("reserve-2");
        service
            .reserve(ReserveBudget {
                context: context("entitlements.reserve", 1, "reserve-0002", reserve_digest),
                request: reservation(2, 8, reserve_digest),
            })
            .unwrap();
        authorizer.allow(authorization("entitlements.settle"));
        let settle_digest = Sha256Digest::of_bytes("settle-2");
        let settle = || SettleUsage {
            context: context("entitlements.settle", 2, "settle-0002", settle_digest),
            usage: UsageRecord {
                id: UsageRecordId::new("00000002").unwrap(),
                reservation_id: ReservationId::new("00000002").unwrap(),
                settlement_digest: settle_digest,
                actual: BTreeMap::from([(dimension(), 5)]),
                recorded_at_ms: 50,
            },
        };
        let first = service.settle(settle()).unwrap();
        assert_eq!(service.settle(settle()).unwrap(), first);
        let stored = repository.load(&account_key()).unwrap().unwrap();
        assert_eq!(stored.version, 3);
        assert_eq!(stored.aggregate.usage_records().count(), 1);
    }

    #[test]
    fn denial_and_audit_failure_never_mutate_or_reserve() {
        let (service, repository, authorizer, audit) = setup();
        let digest = Sha256Digest::of_bytes("denied");
        let command = || ReserveBudget {
            context: context("entitlements.reserve", 1, "reserve-denied", digest),
            request: reservation(1, 6, digest),
        };
        assert_eq!(
            service.reserve(command()),
            Err(CommercialApplicationError::Unauthorized)
        );
        assert_eq!(repository.load(&account_key()).unwrap().unwrap().version, 1);
        authorizer.allow(authorization("entitlements.reserve"));
        audit.set_available(false);
        assert_eq!(
            service.reserve(command()),
            Err(CommercialApplicationError::AuditUnavailable)
        );
        assert_eq!(repository.load(&account_key()).unwrap().unwrap().version, 1);
    }
}
