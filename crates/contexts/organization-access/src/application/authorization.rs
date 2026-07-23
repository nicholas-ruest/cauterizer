//! Audited, tenant-scoped authorization application service.

use super::ports::{
    AuditSink, AuthorizationPolicyRepository, Clock, OrganizationRepository, RepositoryError,
};
use crate::contracts::{
    AuditedOperationOutcomeV1, AuthorizationAuditFactV1, AuthorizationOutcomeV1,
    AuthorizationReasonV1, CONTRACT_VERSION,
};
use crate::domain::{AuthorizationDecision, DecisionContext, DecisionReason, Organization};
use cauterizer_syntax::authorization::AuthorizationRequestContext;
use cauterizer_syntax::identifiers::{CausationId, ContextQualifiedId, CorrelationId};
use cauterizer_syntax::schema::SchemaVersion;
use std::fmt;

/// Complete request metadata needed for a deterministic, audited decision.
pub struct EvaluateAuthorization {
    /// Authenticated organization, identity, action, resource, and purpose.
    pub request: AuthorizationRequestContext,
    /// Authenticated contextual conditions evaluated by the pure policy.
    pub context: DecisionContext,
    /// Immutable policy version used for the decision.
    pub policy_version: SchemaVersion,
    /// Unique identifier for this authorization request.
    pub request_id: ContextQualifiedId,
    /// Trace identifier copied into the audit fact.
    pub correlation_id: CorrelationId,
    /// Command or event that caused this decision.
    pub causation_id: CausationId,
}

/// Application service that fails closed when state, policy, or audit is unavailable.
pub struct AuthorizationService<R, P, A, C> {
    repository: R,
    policies: P,
    audit: A,
    clock: C,
}

impl<R, P, A, C> AuthorizationService<R, P, A, C>
where
    R: OrganizationRepository<Aggregate = Organization>,
    P: AuthorizationPolicyRepository,
    A: AuditSink,
    C: Clock,
{
    /// Creates an authorization service from application-owned ports.
    #[must_use]
    pub const fn new(repository: R, policies: P, audit: A, clock: C) -> Self {
        Self {
            repository,
            policies,
            audit,
            clock,
        }
    }

    /// Evaluates and durably audits one exact organization-scoped request.
    ///
    /// # Errors
    ///
    /// Fails closed if organization state or policy is unavailable, repository
    /// access fails, or the mandatory security audit fact cannot be recorded.
    pub fn evaluate(
        &mut self,
        command: EvaluateAuthorization,
    ) -> Result<AuthorizationDecision, AuthorizationApplicationError> {
        let organization_id = command.request.organization_id().clone();
        let aggregate = self
            .repository
            .load(&organization_id)?
            .ok_or(AuthorizationApplicationError::Unavailable)?
            .aggregate;
        if aggregate.id() != &organization_id {
            return Err(AuthorizationApplicationError::Unavailable);
        }
        let policy = self
            .policies
            .load_policy(&organization_id)
            .ok_or(AuthorizationApplicationError::Unavailable)?;
        let decision = aggregate.authorize(&policy, &command.request, &command.context);
        self.audit
            .record(AuthorizationAuditFactV1 {
                schema_version: SchemaVersion::parse(CONTRACT_VERSION)
                    .map_err(|_| AuthorizationApplicationError::Unavailable)?,
                request_id: command.request_id,
                organization_id,
                actor: command.request.actor().clone(),
                action: command.request.action().clone(),
                resource: command.request.resource().clone(),
                purpose: command.request.purpose().clone(),
                outcome: if decision.is_allowed() {
                    AuthorizationOutcomeV1::Allow
                } else {
                    AuthorizationOutcomeV1::Deny
                },
                reason: reason(decision.reason()),
                operation_outcome: AuditedOperationOutcomeV1::NotAttempted,
                policy_version: command.policy_version,
                decided_at: self.clock.now(),
                correlation_id: command.correlation_id,
                causation_id: command.causation_id,
            })
            .map_err(|_| AuthorizationApplicationError::AuditUnavailable)?;
        Ok(decision)
    }

    /// Borrows the audit adapter for inspection and tests.
    #[must_use]
    pub const fn audit(&self) -> &A {
        &self.audit
    }
}

const fn reason(reason: DecisionReason) -> AuthorizationReasonV1 {
    match reason {
        DecisionReason::RoleGrant => AuthorizationReasonV1::RoleGrant,
        DecisionReason::BreakGlass => AuthorizationReasonV1::BreakGlassGrant,
        DecisionReason::Unauthenticated => AuthorizationReasonV1::Unauthenticated,
        DecisionReason::OrganizationMismatch => AuthorizationReasonV1::OrganizationMismatch,
        DecisionReason::IdentityMismatch => AuthorizationReasonV1::IdentityMismatch,
        DecisionReason::Inactive => AuthorizationReasonV1::SubjectInactive,
        DecisionReason::NoMatchingGrant => AuthorizationReasonV1::NoMatchingGrant,
        DecisionReason::ConditionsNotSatisfied => AuthorizationReasonV1::ConditionsNotSatisfied,
    }
}

/// Stable authorization application failures; all callers must treat these as deny.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizationApplicationError {
    /// Organization or policy was absent or inconsistent.
    Unavailable,
    /// Aggregate repository failed.
    Repository(RepositoryError),
    /// The security audit fact could not be persisted.
    AuditUnavailable,
}

impl From<RepositoryError> for AuthorizationApplicationError {
    fn from(value: RepositoryError) -> Self {
        Self::Repository(value)
    }
}

impl fmt::Display for AuthorizationApplicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "authorization_unavailable",
            Self::Repository(_) => "authorization_repository_error",
            Self::AuditUnavailable => "authorization_audit_unavailable",
        })
    }
}

impl std::error::Error for AuthorizationApplicationError {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::application::memory::{
        InMemoryAuditSink, InMemoryOrganizationRepository, InMemoryPolicyRepository,
    };
    use crate::application::ports::{Clock, OrganizationRepository, SaveOrganization};
    use crate::domain::{
        EventContext, EventId, MemberId, Permission, PermissionRule, PolicyConditions,
        ResourceSelector, Role, RoleRule,
    };
    use cauterizer_syntax::authorization::{ActionName, Purpose, ResourceRef};
    use cauterizer_syntax::identifiers::{ActorId, IdentityRef, OrganizationId};
    use cauterizer_syntax::time::UtcInstant;

    #[derive(Clone)]
    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> UtcInstant {
            UtcInstant::parse("2026-07-22T00:00:00Z").unwrap()
        }
        fn now_unix_millis(&self) -> u64 {
            1_000
        }
    }

    struct FailingAudit;
    impl crate::application::ports::AuditSink for FailingAudit {
        fn record(
            &mut self,
            _fact: AuthorizationAuditFactV1,
        ) -> Result<(), crate::application::ports::AuditError> {
            Err(crate::application::ports::AuditError)
        }
    }

    fn event() -> EventContext {
        EventContext {
            event_id: EventId::new("00000000").unwrap(),
            occurred_at_ms: 1_000,
            correlation_id: CorrelationId::new("00000000").unwrap(),
            causation_id: CausationId::new("00000000").unwrap(),
        }
    }

    fn service() -> AuthorizationService<
        InMemoryOrganizationRepository<Organization>,
        InMemoryPolicyRepository,
        InMemoryAuditSink,
        FixedClock,
    > {
        let organization_id = OrganizationId::new("00000000").unwrap();
        let actor = ActorId::new("00000000").unwrap();
        let mut organization = Organization::create(
            organization_id.clone(),
            "Test",
            MemberId::new("00000000").unwrap(),
            actor,
            event(),
        )
        .unwrap();
        organization.take_pending_events();
        let mut repository = InMemoryOrganizationRepository::default();
        repository
            .save(
                &organization_id,
                SaveOrganization {
                    aggregate: organization,
                    expected_version: None,
                    events: vec![],
                },
            )
            .unwrap();
        let mut policies = InMemoryPolicyRepository::default();
        policies.insert(crate::domain::AuthorizationPolicy::new(
            organization_id,
            vec![RoleRule {
                role: Role::Owner,
                permissions: vec![PermissionRule {
                    permission: Permission::new("members.read").unwrap(),
                    resources: ResourceSelector::AnyInOrganization,
                    conditions: PolicyConditions {
                        require_mfa: true,
                        environment: Some("production".into()),
                        allowed_purposes: BTreeSet::from(["administration".into()]),
                        required_claims: BTreeSet::new(),
                    },
                }],
            }],
        ));
        AuthorizationService::new(
            repository,
            policies,
            InMemoryAuditSink::default(),
            FixedClock,
        )
    }

    fn command(organization: &str, authenticated: bool) -> EvaluateAuthorization {
        EvaluateAuthorization {
            request: AuthorizationRequestContext::new(
                OrganizationId::new(organization).unwrap(),
                IdentityRef::Human(ActorId::new("00000000").unwrap()),
                ActionName::parse("members.read").unwrap(),
                ResourceRef::parse("organization:00000000").unwrap(),
                Purpose::parse("administration").unwrap(),
            ),
            context: DecisionContext {
                now_ms: 1_000,
                authenticated,
                mfa_verified: true,
                environment: "production".into(),
                claims: BTreeSet::new(),
            },
            policy_version: SchemaVersion::parse("1.0.0").unwrap(),
            request_id: "request_00000000".parse().unwrap(),
            correlation_id: CorrelationId::new("00000000").unwrap(),
            causation_id: CausationId::new("00000000").unwrap(),
        }
    }

    #[test]
    fn explicit_allow_is_returned_and_audited() {
        let mut service = service();
        let decision = service.evaluate(command("00000000", true)).unwrap();
        assert!(decision.is_allowed());
        assert_eq!(service.audit().facts().len(), 1);
        assert_eq!(
            service.audit().facts()[0].outcome,
            AuthorizationOutcomeV1::Allow
        );
    }

    #[test]
    fn unauthenticated_request_is_denied_and_audited() {
        let mut service = service();
        let decision = service.evaluate(command("00000000", false)).unwrap();
        assert!(!decision.is_allowed());
        assert_eq!(
            service.audit().facts()[0].reason,
            AuthorizationReasonV1::Unauthenticated
        );
    }

    #[test]
    fn foreign_organization_never_falls_back_to_home_policy() {
        let mut service = service();
        assert_eq!(
            service.evaluate(command("11111111", true)),
            Err(AuthorizationApplicationError::Unavailable)
        );
        assert!(service.audit().facts().is_empty());
    }

    #[test]
    fn audit_failure_fails_closed_even_for_an_allowed_policy_decision() {
        let base = service();
        let mut service =
            AuthorizationService::new(base.repository, base.policies, FailingAudit, FixedClock);
        assert_eq!(
            service.evaluate(command("00000000", true)),
            Err(AuthorizationApplicationError::AuditUnavailable)
        );
    }
}
