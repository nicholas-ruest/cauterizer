//! Authorized, idempotent mutation commands for Organization & Access.
//!
//! This module deliberately contains no transport or identity-provider types.

use std::collections::BTreeSet;
use std::fmt;

use super::events::{CanonicalEventTimes, EventMappingError, map_domain_event_v1};
use super::ports::{
    AuditError, AuditSink, AuthorizationPolicyRepository, Clock, IdGenerator, IdempotencyError,
    IdempotencyStore, IdempotentResult, OrganizationRepository, RepositoryError, SaveOrganization,
};
use crate::contracts::{
    AuditedOperationOutcomeV1, AuthorizationAuditFactV1, AuthorizationOutcomeV1,
    AuthorizationReasonV1, CONTRACT_VERSION,
};
use crate::domain::{
    AccessTarget, BreakGlassGrantId, DecisionContext, DecisionReason, DomainError, EventContext,
    EventId, MemberId, MembershipStatus, Organization, Permission, Role, RoleDefinition,
    WorkloadPrincipalId,
};
use cauterizer_syntax::authorization::AuthorizationRequestContext;
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{
    ActorId, CausationId, CorrelationId, IdempotencyKey, OrganizationId,
};
use cauterizer_syntax::schema::SchemaVersion;
use cauterizer_syntax::time::UtcInstant;

/// Metadata required by every security-sensitive organization mutation.
pub struct MutationContext {
    /// Exact authenticated authorization request. Its organization is the repository partition.
    pub authorization: AuthorizationRequestContext,
    /// Authenticated request-time conditions used by the current policy.
    pub decision_context: DecisionContext,
    /// Immutable policy version evaluated for this attempt.
    pub policy_version: SchemaVersion,
    /// Unique audited authorization-request identifier.
    pub request_id: cauterizer_syntax::identifiers::ContextQualifiedId,
    /// Required optimistic aggregate version.
    pub expected_version: u64,
    /// Organization-scoped replay key.
    pub idempotency_key: IdempotencyKey,
    /// Digest of the complete canonical command, including mutation and metadata.
    pub request_digest: Sha256Digest,
    /// End-to-end request trace.
    pub correlation_id: CorrelationId,
    /// Command or event which caused this mutation.
    pub causation_id: CausationId,
}

/// All Organization aggregate mutations supported by the application boundary.
pub enum OrganizationMutation {
    /// Invite the exact human actor; the membership ID is injected.
    InviteMember {
        /// Human actor bound to the invitation.
        actor: ActorId,
    },
    /// Accept the exact invitation as its bound actor.
    AcceptMembership {
        /// Existing invitation identifier.
        member_id: MemberId,
        /// Exact actor bound to the invitation.
        actor: ActorId,
    },
    /// Define an immutable custom role.
    DefineRole {
        /// Stable organization-owned role identifier.
        id: String,
        /// Maximum permission set for the role.
        permissions: BTreeSet<Permission>,
    },
    /// Assign a built-in or defined custom role.
    AssignRole {
        /// Active membership receiving the role.
        member_id: MemberId,
        /// Built-in or previously defined custom role.
        role: Role,
    },
    /// Store provider-neutral federation policy metadata.
    ConfigureFederation {
        /// Provider-neutral configuration version.
        configuration_version: String,
    },
    /// Provision an injected short-lived workload principal.
    ProvisionServicePrincipal {
        /// Explicit bounded workload scopes.
        scopes: BTreeSet<Permission>,
        /// Domain expiry as Unix milliseconds.
        expires_at_ms: u64,
        /// Canonical external spelling of the same expiry.
        expires_at: UtcInstant,
    },
    /// Grant independently approved emergency access using an injected grant ID.
    GrantBreakGlass {
        /// Human receiving emergency access.
        beneficiary: ActorId,
        /// Independent active owner approving access.
        approved_by: ActorId,
        /// Explicit emergency scope.
        permissions: BTreeSet<Permission>,
        /// Bounded private incident justification.
        justification: String,
        /// Domain expiry as Unix milliseconds.
        expires_at_ms: u64,
        /// Canonical external spelling of the same expiry.
        expires_at: UtcInstant,
    },
    /// Revoke one exact aggregate-owned access record.
    Revoke {
        /// Exact aggregate-owned record to revoke.
        target: AccessTarget,
        /// Authenticated human revoker recorded in the private fact.
        revoked_by: ActorId,
    },
}

/// Stable result returned for both first execution and exact retries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationResult {
    /// Mutated organization.
    pub organization_id: OrganizationId,
    /// New repository version.
    pub version: u64,
    /// Generated membership, workload, or break-glass identifier, when applicable.
    pub generated_id: Option<String>,
}

/// Authenticated metadata required by organization queries.
pub struct QueryContext {
    /// Exact organization-scoped authorization request.
    pub authorization: AuthorizationRequestContext,
    /// Authenticated request-time conditions.
    pub decision_context: DecisionContext,
    /// Immutable policy version used for audit.
    pub policy_version: SchemaVersion,
    /// Unique request identifier.
    pub request_id: cauterizer_syntax::identifiers::ContextQualifiedId,
    /// End-to-end trace identifier.
    pub correlation_id: CorrelationId,
    /// Query causation identifier.
    pub causation_id: CausationId,
}

/// Tenant-filtered organization application view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrganizationView {
    /// Exact tenant identifier.
    pub organization_id: OrganizationId,
    /// Bounded display name.
    pub name: String,
    /// Current aggregate sequence.
    pub sequence: u64,
    /// Memberships in stable identifier order.
    pub memberships: Vec<MembershipView>,
    /// Active workload principal IDs; scopes are intentionally omitted.
    pub active_service_principals: Vec<String>,
    /// Active emergency grant IDs; justification and permissions are omitted.
    pub active_break_glass_grants: Vec<String>,
}

/// Payload-safe membership application view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipView {
    /// Membership identifier.
    pub id: String,
    /// Bound actor.
    pub actor: ActorId,
    /// Current lifecycle status.
    pub status: MembershipStatus,
}

/// Application service for authorized aggregate mutations.
pub struct OrganizationCommandService<R, P, I, A, C, G> {
    repository: R,
    policies: P,
    idempotency: I,
    audit: A,
    clock: C,
    ids: G,
}

impl<R, P, I, A, C, G> OrganizationCommandService<R, P, I, A, C, G>
where
    R: OrganizationRepository<Aggregate = Organization>,
    P: AuthorizationPolicyRepository,
    I: IdempotencyStore<MutationResult>,
    A: AuditSink,
    C: Clock,
    G: IdGenerator,
{
    /// Creates a command service from application-owned ports.
    #[must_use]
    pub const fn new(
        repository: R,
        policies: P,
        idempotency: I,
        audit: A,
        clock: C,
        ids: G,
    ) -> Self {
        Self {
            repository,
            policies,
            idempotency,
            audit,
            clock,
            ids,
        }
    }

    /// Authorizes and applies exactly one aggregate mutation.
    ///
    /// Exact retries return the original result. Reusing a key with a different
    /// digest fails before authorization or aggregate mutation.
    ///
    /// # Errors
    ///
    /// Fails closed for unavailable state/policy/audit, authorization denial,
    /// stale versions, conflicting replay keys, invalid IDs, domain rejection,
    /// event mapping failure, or persistence failure.
    pub fn execute(
        &mut self,
        context: MutationContext,
        mutation: OrganizationMutation,
    ) -> Result<MutationResult, CommandError> {
        let organization_id = context.authorization.organization_id().clone();
        if context.authorization.action().as_str() != mutation.required_action() {
            return Err(CommandError::ActionMismatch);
        }
        if let Some(previous) = self
            .idempotency
            .get(&organization_id, &context.idempotency_key)
        {
            return if previous.request_digest == context.request_digest {
                Ok(previous.result)
            } else {
                Err(CommandError::IdempotencyConflict)
            };
        }

        let loaded = self
            .repository
            .load(&organization_id)?
            .ok_or(CommandError::Unavailable)?;
        if loaded.version != context.expected_version || loaded.aggregate.id() != &organization_id {
            return Err(CommandError::Conflict);
        }
        let policy = self
            .policies
            .load_policy(&organization_id)
            .ok_or(CommandError::Unavailable)?;
        let decision =
            loaded
                .aggregate
                .authorize(&policy, &context.authorization, &context.decision_context);
        self.audit.record(AuthorizationAuditFactV1 {
            schema_version: SchemaVersion::parse(CONTRACT_VERSION)
                .map_err(|_| CommandError::Unavailable)?,
            request_id: context.request_id.clone(),
            organization_id: organization_id.clone(),
            actor: context.authorization.actor().clone(),
            action: context.authorization.action().clone(),
            resource: context.authorization.resource().clone(),
            purpose: context.authorization.purpose().clone(),
            outcome: if decision.is_allowed() {
                AuthorizationOutcomeV1::Allow
            } else {
                AuthorizationOutcomeV1::Deny
            },
            reason: audit_reason(decision.reason()),
            operation_outcome: AuditedOperationOutcomeV1::NotAttempted,
            policy_version: context.policy_version.clone(),
            decided_at: self.clock.now(),
            correlation_id: context.correlation_id.clone(),
            causation_id: context.causation_id.clone(),
        })?;
        if !decision.is_allowed() {
            return Err(CommandError::Denied);
        }

        let mut aggregate = loaded.aggregate;
        let occurred_at = self.clock.now();
        let event = EventContext {
            event_id: EventId::new(&self.ids.next_opaque("org-event"))
                .map_err(|_| CommandError::InvalidGeneratedIdentifier)?,
            occurred_at_ms: self.clock.now_unix_millis(),
            correlation_id: context.correlation_id.clone(),
            causation_id: context.causation_id.clone(),
        };
        let expires_at = mutation.expires_at().cloned();
        let generated_id = self.apply(&mut aggregate, mutation, event)?;
        let events = aggregate
            .take_pending_events()
            .iter()
            .map(|event| {
                map_domain_event_v1(
                    event,
                    CanonicalEventTimes {
                        occurred_at: occurred_at.clone(),
                        expires_at: expires_at.clone(),
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let version = self.repository.save(
            &organization_id,
            SaveOrganization {
                aggregate,
                expected_version: Some(context.expected_version),
                events,
            },
        )?;
        let result = MutationResult {
            organization_id: organization_id.clone(),
            version,
            generated_id,
        };
        self.idempotency.put(
            organization_id,
            context.idempotency_key,
            IdempotentResult {
                request_digest: context.request_digest,
                result: result.clone(),
            },
        )?;
        Ok(result)
    }

    /// Borrows the repository for application integration tests and queries.
    #[must_use]
    pub const fn repository(&self) -> &R {
        &self.repository
    }

    /// Borrows the audit sink for application integration tests.
    #[must_use]
    pub const fn audit(&self) -> &A {
        &self.audit
    }

    /// Authorizes and returns one tenant-filtered organization view.
    ///
    /// # Errors
    ///
    /// Fails closed when organization/policy/audit is unavailable or the query
    /// is not explicitly authorized for `organization.read`.
    pub fn get_organization(
        &mut self,
        context: QueryContext,
    ) -> Result<OrganizationView, CommandError> {
        if context.authorization.action().as_str() != "organization.read" {
            return Err(CommandError::ActionMismatch);
        }
        let organization_id = context.authorization.organization_id().clone();
        let loaded = self
            .repository
            .load(&organization_id)?
            .ok_or(CommandError::Unavailable)?;
        if loaded.aggregate.id() != &organization_id {
            return Err(CommandError::Unavailable);
        }
        let policy = self
            .policies
            .load_policy(&organization_id)
            .ok_or(CommandError::Unavailable)?;
        let decision =
            loaded
                .aggregate
                .authorize(&policy, &context.authorization, &context.decision_context);
        self.audit.record(AuthorizationAuditFactV1 {
            schema_version: SchemaVersion::parse(CONTRACT_VERSION)
                .map_err(|_| CommandError::Unavailable)?,
            request_id: context.request_id,
            organization_id: organization_id.clone(),
            actor: context.authorization.actor().clone(),
            action: context.authorization.action().clone(),
            resource: context.authorization.resource().clone(),
            purpose: context.authorization.purpose().clone(),
            outcome: if decision.is_allowed() {
                AuthorizationOutcomeV1::Allow
            } else {
                AuthorizationOutcomeV1::Deny
            },
            reason: audit_reason(decision.reason()),
            operation_outcome: AuditedOperationOutcomeV1::NotAttempted,
            policy_version: context.policy_version,
            decided_at: self.clock.now(),
            correlation_id: context.correlation_id,
            causation_id: context.causation_id,
        })?;
        if !decision.is_allowed() {
            return Err(CommandError::Denied);
        }
        let now = context.decision_context.now_ms;
        Ok(OrganizationView {
            organization_id,
            name: loaded.aggregate.name().to_owned(),
            sequence: loaded.aggregate.sequence().get(),
            memberships: loaded
                .aggregate
                .memberships()
                .map(|membership| MembershipView {
                    id: membership.id().as_str().to_owned(),
                    actor: membership.actor_id().clone(),
                    status: membership.status(),
                })
                .collect(),
            active_service_principals: loaded
                .aggregate
                .service_principals()
                .filter(|principal| !principal.is_revoked() && now < principal.expires_at_ms())
                .map(|principal| principal.id().as_str().to_owned())
                .collect(),
            active_break_glass_grants: loaded
                .aggregate
                .break_glass_grants()
                .filter(|grant| grant.is_active_at(now))
                .map(|grant| grant.id().as_str().to_owned())
                .collect(),
        })
    }

    fn apply(
        &mut self,
        aggregate: &mut Organization,
        mutation: OrganizationMutation,
        event: EventContext,
    ) -> Result<Option<String>, CommandError> {
        match mutation {
            OrganizationMutation::InviteMember { actor } => {
                let id = MemberId::new(&self.ids.next_opaque("member"))
                    .map_err(|_| CommandError::InvalidGeneratedIdentifier)?;
                aggregate.invite_member(id.clone(), actor, event)?;
                Ok(Some(id.as_str().to_owned()))
            }
            OrganizationMutation::AcceptMembership { member_id, actor } => {
                aggregate.accept_membership(&member_id, &actor, event)?;
                Ok(None)
            }
            OrganizationMutation::DefineRole { id, permissions } => {
                aggregate.define_role(RoleDefinition::new(id, permissions)?, event)?;
                Ok(None)
            }
            OrganizationMutation::AssignRole { member_id, role } => {
                aggregate.assign_role(&member_id, role, event)?;
                Ok(None)
            }
            OrganizationMutation::ConfigureFederation {
                configuration_version,
            } => {
                aggregate.configure_federation(configuration_version, event)?;
                Ok(None)
            }
            OrganizationMutation::ProvisionServicePrincipal {
                scopes,
                expires_at_ms,
                expires_at: _,
            } => {
                let id = WorkloadPrincipalId::new(&self.ids.next_opaque("workload"))
                    .map_err(|_| CommandError::InvalidGeneratedIdentifier)?;
                aggregate.provision_service_principal(
                    id.clone(),
                    scopes,
                    self.clock.now_unix_millis(),
                    expires_at_ms,
                    event,
                )?;
                Ok(Some(id.as_str().to_owned()))
            }
            OrganizationMutation::GrantBreakGlass {
                beneficiary,
                approved_by,
                permissions,
                justification,
                expires_at_ms,
                expires_at: _,
            } => {
                let id = BreakGlassGrantId::new(&self.ids.next_opaque("breakglass"))
                    .map_err(|_| CommandError::InvalidGeneratedIdentifier)?;
                aggregate.grant_break_glass(
                    id.clone(),
                    beneficiary,
                    approved_by,
                    permissions,
                    justification,
                    self.clock.now_unix_millis(),
                    expires_at_ms,
                    event,
                )?;
                Ok(Some(id.as_str().to_owned()))
            }
            OrganizationMutation::Revoke { target, revoked_by } => {
                aggregate.revoke_access(target, revoked_by, event)?;
                Ok(None)
            }
        }
    }
}

/// Stable fail-closed command failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandError {
    /// Organization or current policy was unavailable.
    Unavailable,
    /// Authorization was not an explicit allow.
    Denied,
    /// Required aggregate version was stale.
    Conflict,
    /// Authorization action did not name the requested mutation.
    ActionMismatch,
    /// A replay key was reused with different canonical input.
    IdempotencyConflict,
    /// Injected identifier material was invalid.
    InvalidGeneratedIdentifier,
    /// Aggregate invariant rejected the mutation.
    Domain(DomainError),
    /// Persistence failed.
    Repository(RepositoryError),
    /// Mandatory audit persistence failed.
    AuditUnavailable,
    /// A private domain fact could not be represented by the public contract.
    EventMapping,
}

impl From<DomainError> for CommandError {
    fn from(value: DomainError) -> Self {
        Self::Domain(value)
    }
}
impl From<RepositoryError> for CommandError {
    fn from(value: RepositoryError) -> Self {
        Self::Repository(value)
    }
}
impl From<IdempotencyError> for CommandError {
    fn from(_: IdempotencyError) -> Self {
        Self::IdempotencyConflict
    }
}
impl From<AuditError> for CommandError {
    fn from(_: AuditError) -> Self {
        Self::AuditUnavailable
    }
}
impl From<EventMappingError> for CommandError {
    fn from(_: EventMappingError) -> Self {
        Self::EventMapping
    }
}
impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "command_unavailable",
            Self::Denied => "authorization_denied",
            Self::Conflict => "organization_version_conflict",
            Self::ActionMismatch => "authorization_action_mismatch",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::InvalidGeneratedIdentifier => "invalid_generated_identifier",
            Self::Domain(_) => "domain_error",
            Self::Repository(_) => "repository_error",
            Self::AuditUnavailable => "audit_unavailable",
            Self::EventMapping => "event_mapping_error",
        })
    }
}

impl OrganizationMutation {
    const fn required_action(&self) -> &'static str {
        match self {
            Self::InviteMember { .. } => "members.invite",
            Self::AcceptMembership { .. } => "members.accept",
            Self::DefineRole { .. } => "roles.define",
            Self::AssignRole { .. } => "roles.assign",
            Self::ConfigureFederation { .. } => "federation.configure",
            Self::ProvisionServicePrincipal { .. } => "principals.provision",
            Self::GrantBreakGlass { .. } => "break-glass.grant",
            Self::Revoke { .. } => "access.revoke",
        }
    }

    const fn expires_at(&self) -> Option<&UtcInstant> {
        match self {
            Self::ProvisionServicePrincipal { expires_at, .. }
            | Self::GrantBreakGlass { expires_at, .. } => Some(expires_at),
            _ => None,
        }
    }
}
impl std::error::Error for CommandError {}

const fn audit_reason(reason: DecisionReason) -> AuthorizationReasonV1 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::memory::{
        InMemoryAuditSink, InMemoryIdempotencyStore, InMemoryOrganizationRepository,
        InMemoryPolicyRepository,
    };
    use crate::application::ports::{Clock, IdGenerator, OrganizationRepository};
    use crate::domain::{
        AuthorizationPolicy, PermissionRule, PolicyConditions, ResourceSelector, RoleRule,
    };
    use cauterizer_syntax::authorization::{ActionName, Purpose, ResourceRef};
    use cauterizer_syntax::identifiers::{AggregateSequence, IdentityRef};

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

    struct SequentialIds(u64);
    impl IdGenerator for SequentialIds {
        fn next_opaque(&mut self, _context: &'static str) -> String {
            self.0 += 1;
            format!("00000000{:08}", self.0)
        }
    }

    type Service = OrganizationCommandService<
        InMemoryOrganizationRepository<Organization>,
        InMemoryPolicyRepository,
        InMemoryIdempotencyStore<MutationResult>,
        InMemoryAuditSink,
        FixedClock,
        SequentialIds,
    >;

    fn service() -> Service {
        let organization_id = OrganizationId::new("00000000").unwrap();
        let owner = ActorId::new("00000000").unwrap();
        let mut aggregate = Organization::create(
            organization_id.clone(),
            "Test",
            MemberId::new("00000000").unwrap(),
            owner,
            EventContext {
                event_id: EventId::new("00000000").unwrap(),
                occurred_at_ms: 1_000,
                correlation_id: CorrelationId::new("00000000").unwrap(),
                causation_id: CausationId::new("00000000").unwrap(),
            },
        )
        .unwrap();
        aggregate.take_pending_events();
        let mut repository = InMemoryOrganizationRepository::default();
        repository
            .save(
                &organization_id,
                SaveOrganization {
                    aggregate,
                    expected_version: None,
                    events: vec![],
                },
            )
            .unwrap();
        let mut policies = InMemoryPolicyRepository::default();
        policies.insert(AuthorizationPolicy::new(
            organization_id,
            vec![RoleRule {
                role: Role::Owner,
                permissions: vec![
                    PermissionRule {
                        permission: Permission::new("members.invite").unwrap(),
                        resources: ResourceSelector::AnyInOrganization,
                        conditions: PolicyConditions::default(),
                    },
                    PermissionRule {
                        permission: Permission::new("organization.read").unwrap(),
                        resources: ResourceSelector::AnyInOrganization,
                        conditions: PolicyConditions::default(),
                    },
                ],
            }],
        ));
        OrganizationCommandService::new(
            repository,
            policies,
            InMemoryIdempotencyStore::default(),
            InMemoryAuditSink::default(),
            FixedClock,
            SequentialIds(10),
        )
    }

    fn context(action: &str, digest: &str) -> MutationContext {
        MutationContext {
            authorization: AuthorizationRequestContext::new(
                OrganizationId::new("00000000").unwrap(),
                IdentityRef::Human(ActorId::new("00000000").unwrap()),
                ActionName::parse(action).unwrap(),
                ResourceRef::parse("organization:00000000").unwrap(),
                Purpose::parse("administration").unwrap(),
            ),
            decision_context: DecisionContext {
                now_ms: 1_000,
                authenticated: true,
                mfa_verified: true,
                environment: "local".into(),
                claims: BTreeSet::new(),
            },
            policy_version: SchemaVersion::parse("1.0.0").unwrap(),
            request_id: "request_00000000".parse().unwrap(),
            expected_version: 1,
            idempotency_key: IdempotencyKey::new("invite-0001").unwrap(),
            request_digest: Sha256Digest::of_bytes(digest),
            correlation_id: CorrelationId::new("00000000").unwrap(),
            causation_id: CausationId::new("00000000").unwrap(),
        }
    }

    #[test]
    fn invite_is_authorized_persisted_published_audited_and_idempotent() {
        let mut service = service();
        let actor = ActorId::new("11111111").unwrap();
        let first = service
            .execute(
                context("members.invite", "same"),
                OrganizationMutation::InviteMember {
                    actor: actor.clone(),
                },
            )
            .unwrap();
        let retry = service
            .execute(
                context("members.invite", "same"),
                OrganizationMutation::InviteMember { actor },
            )
            .unwrap();
        assert_eq!(first, retry);
        assert_eq!(first.version, 2);
        assert_eq!(service.repository().outbox().len(), 1);
        assert_eq!(service.audit().facts().len(), 1);
        assert_eq!(
            service.repository().outbox()[0].aggregate_sequence,
            AggregateSequence::new(2).unwrap()
        );
    }

    #[test]
    fn changed_replay_and_mismatched_action_fail_before_second_mutation() {
        let mut command_service = service();
        command_service
            .execute(
                context("members.invite", "first"),
                OrganizationMutation::InviteMember {
                    actor: ActorId::new("11111111").unwrap(),
                },
            )
            .unwrap();
        assert_eq!(
            command_service.execute(
                context("members.invite", "changed"),
                OrganizationMutation::InviteMember {
                    actor: ActorId::new("22222222").unwrap()
                },
            ),
            Err(CommandError::IdempotencyConflict)
        );
        let mut fresh = service();
        assert_eq!(
            fresh.execute(
                context("members.read", "wrong-action"),
                OrganizationMutation::InviteMember {
                    actor: ActorId::new("11111111").unwrap()
                },
            ),
            Err(CommandError::ActionMismatch)
        );
    }

    #[test]
    fn organization_query_is_authorized_audited_and_payload_safe() {
        let mut service = service();
        let authorization = AuthorizationRequestContext::new(
            OrganizationId::new("00000000").unwrap(),
            IdentityRef::Human(ActorId::new("00000000").unwrap()),
            ActionName::parse("organization.read").unwrap(),
            ResourceRef::parse("organization:00000000").unwrap(),
            Purpose::parse("administration").unwrap(),
        );
        let view = service
            .get_organization(QueryContext {
                authorization,
                decision_context: DecisionContext {
                    now_ms: 1_000,
                    authenticated: true,
                    mfa_verified: true,
                    environment: "local".into(),
                    claims: BTreeSet::new(),
                },
                policy_version: SchemaVersion::parse("1.0.0").unwrap(),
                request_id: "request_00000001".parse().unwrap(),
                correlation_id: CorrelationId::new("00000001").unwrap(),
                causation_id: CausationId::new("00000001").unwrap(),
            })
            .unwrap();
        assert_eq!(
            view.organization_id,
            OrganizationId::new("00000000").unwrap()
        );
        assert_eq!(view.memberships.len(), 1);
        assert!(view.active_service_principals.is_empty());
        assert_eq!(service.audit().facts().len(), 1);
    }
}
