//! Organization aggregate and invariant-enforcing behavior.

use std::collections::BTreeMap;

use cauterizer_syntax::identifiers::{ActorId, AggregateSequence, OrganizationId};
use cauterizer_syntax::{authorization::AuthorizationRequestContext, identifiers::IdentityRef};

use super::{
    AccessTarget, AuthorizationDecision, AuthorizationPolicy, BreakGlassGrantId, DecisionContext,
    DecisionReason, DomainError, DomainEvent, EventContext, MemberId, Membership, MembershipStatus,
    OrganizationEvent, Permission, Role, ServicePrincipal, SubjectAccess, SupportAccessGrant,
    WorkloadPrincipalId,
};

const MAX_ORGANIZATION_NAME_LENGTH: usize = 120;
const MAX_WORKLOAD_LIFETIME_MILLIS: u64 = 24 * 60 * 60 * 1_000;
pub(crate) const MAX_BREAK_GLASS_MILLIS: u64 = 60 * 60 * 1_000;

/// Tenant aggregate owning workforce and workload access records.
#[derive(Clone, Debug)]
pub struct Organization {
    id: OrganizationId,
    name: String,
    sequence: AggregateSequence,
    memberships: BTreeMap<MemberId, Membership>,
    actor_memberships: BTreeMap<ActorId, MemberId>,
    service_principals: BTreeMap<WorkloadPrincipalId, ServicePrincipal>,
    break_glass_grants: BTreeMap<BreakGlassGrantId, SupportAccessGrant>,
    role_definitions: BTreeMap<String, crate::domain::RoleDefinition>,
    federation_configuration_version: Option<String>,
    pending_events: Vec<DomainEvent>,
}

impl Organization {
    /// Creates an organization with one active human owner.
    ///
    /// # Errors
    ///
    /// Returns an error when the organization name is empty or exceeds 120
    /// bytes, or when the initial event sequence cannot be constructed.
    pub fn create(
        id: OrganizationId,
        name: impl Into<String>,
        owner_member_id: MemberId,
        owner_actor_id: ActorId,
        event: EventContext,
    ) -> Result<Self, DomainError> {
        let name = name.into();
        if name.trim().is_empty() || name.len() > MAX_ORGANIZATION_NAME_LENGTH {
            return Err(DomainError::InvalidOrganizationName);
        }
        let sequence = AggregateSequence::new(1).map_err(|_| DomainError::SequenceExhausted)?;
        let owner = Membership::initial_owner(owner_member_id.clone(), owner_actor_id.clone());
        let payload = OrganizationEvent::OrganizationCreated {
            owner_member_id: owner_member_id.clone(),
            owner_actor_id: owner_actor_id.clone(),
        };
        Ok(Self {
            id: id.clone(),
            name,
            sequence,
            memberships: BTreeMap::from([(owner_member_id.clone(), owner)]),
            actor_memberships: BTreeMap::from([(owner_actor_id, owner_member_id)]),
            service_principals: BTreeMap::new(),
            break_glass_grants: BTreeMap::new(),
            role_definitions: BTreeMap::new(),
            federation_configuration_version: None,
            pending_events: vec![DomainEvent::new(id, sequence, event, payload)],
        })
    }

    /// Returns the immutable organization ID.
    #[must_use]
    pub const fn id(&self) -> &OrganizationId {
        &self.id
    }

    /// Returns the organization display name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the current aggregate sequence.
    #[must_use]
    pub const fn sequence(&self) -> AggregateSequence {
        self.sequence
    }

    /// Looks up a membership without exposing mutable aggregate state.
    #[must_use]
    pub fn membership(&self, id: &MemberId) -> Option<&Membership> {
        self.memberships.get(id)
    }

    /// Iterates memberships in stable identifier order.
    pub fn memberships(&self) -> impl Iterator<Item = &Membership> {
        self.memberships.values()
    }

    /// Looks up a workload principal.
    #[must_use]
    pub fn service_principal(&self, id: &WorkloadPrincipalId) -> Option<&ServicePrincipal> {
        self.service_principals.get(id)
    }

    /// Iterates service principals in stable identifier order.
    pub fn service_principals(&self) -> impl Iterator<Item = &ServicePrincipal> {
        self.service_principals.values()
    }

    /// Looks up an emergency access grant.
    #[must_use]
    pub fn break_glass_grant(&self, id: &BreakGlassGrantId) -> Option<&SupportAccessGrant> {
        self.break_glass_grants.get(id)
    }

    /// Iterates emergency grants in stable identifier order.
    pub fn break_glass_grants(&self) -> impl Iterator<Item = &SupportAccessGrant> {
        self.break_glass_grants.values()
    }

    /// Returns one organization-owned custom role definition.
    #[must_use]
    pub fn role_definition(&self, id: &str) -> Option<&crate::domain::RoleDefinition> {
        self.role_definitions.get(id)
    }

    /// Returns provider-neutral federation configuration metadata, if configured.
    #[must_use]
    pub fn federation_configuration_version(&self) -> Option<&str> {
        self.federation_configuration_version.as_deref()
    }

    /// Defines a custom role and its maximum permission set.
    ///
    /// # Errors
    ///
    /// Rejects invalid/empty definitions, duplicate role IDs, or exhausted sequencing.
    pub fn define_role(
        &mut self,
        definition: crate::domain::RoleDefinition,
        event: EventContext,
    ) -> Result<(), DomainError> {
        self.ensure_can_record()?;
        if self.role_definitions.contains_key(definition.id()) {
            return Err(DomainError::RoleAlreadyExists);
        }
        let role_id = definition.id().to_owned();
        self.role_definitions.insert(role_id.clone(), definition);
        self.record(event, OrganizationEvent::RoleDefined { role_id })
    }

    /// Configures provider-neutral federation policy metadata.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, non-canonical versions or exhausted sequencing.
    pub fn configure_federation(
        &mut self,
        configuration_version: String,
        event: EventContext,
    ) -> Result<(), DomainError> {
        self.ensure_can_record()?;
        if configuration_version.is_empty()
            || configuration_version.len() > 64
            || !configuration_version.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
            })
        {
            return Err(DomainError::InvalidFederationConfiguration);
        }
        self.federation_configuration_version = Some(configuration_version.clone());
        self.record(
            event,
            OrganizationEvent::FederationConfigured {
                configuration_version,
            },
        )
    }

    /// Evaluates an authenticated request against this aggregate snapshot.
    #[must_use]
    pub fn authorize(
        &self,
        policy: &AuthorizationPolicy,
        request: &AuthorizationRequestContext,
        context: &DecisionContext,
    ) -> AuthorizationDecision {
        match request.actor() {
            IdentityRef::Human(actor) => {
                let Some(membership) = self
                    .actor_memberships
                    .get(actor)
                    .and_then(|id| self.memberships.get(id))
                else {
                    return AuthorizationDecision::denied(DecisionReason::IdentityMismatch);
                };
                let grants = self
                    .break_glass_grants
                    .values()
                    .filter(|grant| grant.beneficiary() == actor)
                    .collect::<Vec<_>>();
                policy.decide(
                    request,
                    &self.id,
                    context,
                    SubjectAccess::Human {
                        membership,
                        custom_roles: &[],
                        break_glass: &grants,
                    },
                )
            }
            IdentityRef::Service(service) => {
                let Ok(id) = WorkloadPrincipalId::new(service.opaque()) else {
                    return AuthorizationDecision::denied(DecisionReason::IdentityMismatch);
                };
                let Some(principal) = self.service_principals.get(&id) else {
                    return AuthorizationDecision::denied(DecisionReason::IdentityMismatch);
                };
                policy.decide(
                    request,
                    &self.id,
                    context,
                    SubjectAccess::Service(principal),
                )
            }
        }
    }

    /// Invites one actor into this organization.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::MembershipAlreadyExists`] when either membership
    /// ID or actor was previously recorded.
    pub fn invite_member(
        &mut self,
        member_id: MemberId,
        actor_id: ActorId,
        event: EventContext,
    ) -> Result<(), DomainError> {
        self.ensure_can_record()?;
        if self.memberships.contains_key(&member_id)
            || self.actor_memberships.contains_key(&actor_id)
        {
            return Err(DomainError::MembershipAlreadyExists);
        }
        self.memberships.insert(
            member_id.clone(),
            Membership::invited(member_id.clone(), actor_id.clone()),
        );
        self.actor_memberships
            .insert(actor_id.clone(), member_id.clone());
        self.record(
            event,
            OrganizationEvent::MemberInvited {
                member_id,
                actor_id,
            },
        )
    }

    /// Accepts an invitation as the exact bound actor.
    ///
    /// # Errors
    ///
    /// Returns a stable error when the membership does not exist, is not
    /// invited, or is bound to a different actor.
    pub fn accept_membership(
        &mut self,
        member_id: &MemberId,
        accepting_actor: &ActorId,
        event: EventContext,
    ) -> Result<(), DomainError> {
        self.ensure_can_record()?;
        let membership = self
            .memberships
            .get_mut(member_id)
            .ok_or(DomainError::MembershipNotFound)?;
        if membership.status() != MembershipStatus::Invited {
            return Err(DomainError::MembershipNotInvited);
        }
        if membership.actor_id() != accepting_actor {
            return Err(DomainError::InvitationActorMismatch);
        }
        membership.accept();
        self.record(
            event,
            OrganizationEvent::MembershipAccepted {
                member_id: member_id.clone(),
                actor_id: accepting_actor.clone(),
            },
        )
    }

    /// Assigns a built-in or defined custom role to an active member.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown custom role or a missing/inactive member.
    pub fn assign_role(
        &mut self,
        member_id: &MemberId,
        role: Role,
        event: EventContext,
    ) -> Result<(), DomainError> {
        self.ensure_can_record()?;
        if let Role::Custom(id) = &role
            && !self.role_definitions.contains_key(id)
        {
            return Err(DomainError::UnknownRole);
        }
        let membership = self
            .memberships
            .get_mut(member_id)
            .ok_or(DomainError::MembershipNotFound)?;
        if membership.status() != MembershipStatus::Active {
            return Err(DomainError::MembershipNotActive);
        }
        membership.assign(role.clone());
        self.record(
            event,
            OrganizationEvent::RoleAssigned {
                member_id: member_id.clone(),
                role,
            },
        )
    }

    /// Provisions a short-lived service principal with explicit scopes.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate IDs, empty scopes, or an expiry outside
    /// `(now, now + 24 hours]`.
    pub fn provision_service_principal(
        &mut self,
        id: WorkloadPrincipalId,
        scopes: impl IntoIterator<Item = Permission>,
        now_ms: u64,
        expires_at_ms: u64,
        event: EventContext,
    ) -> Result<(), DomainError> {
        self.ensure_can_record()?;
        if self.service_principals.contains_key(&id) {
            return Err(DomainError::AccessAlreadyExists);
        }
        let scopes = scopes
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        if scopes.is_empty() {
            return Err(DomainError::EmptyScope);
        }
        if expires_at_ms <= now_ms || expires_at_ms - now_ms > MAX_WORKLOAD_LIFETIME_MILLIS {
            return Err(DomainError::InvalidWorkloadExpiry);
        }
        self.service_principals.insert(
            id.clone(),
            ServicePrincipal::new(id.clone(), scopes, expires_at_ms),
        );
        self.record(
            event,
            OrganizationEvent::ServicePrincipalProvisioned {
                principal_id: id,
                expires_at_ms,
            },
        )
    }

    /// Grants owner-approved, time-bounded emergency access to a human actor.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicates, invalid scope/justification/window,
    /// self-approval, or an approver that is not an active owner.
    #[allow(clippy::too_many_arguments)]
    pub fn grant_break_glass(
        &mut self,
        id: BreakGlassGrantId,
        beneficiary: ActorId,
        approved_by: ActorId,
        permissions: impl IntoIterator<Item = Permission>,
        justification: impl Into<String>,
        issued_at_ms: u64,
        expires_at_ms: u64,
        event: EventContext,
    ) -> Result<(), DomainError> {
        self.ensure_can_record()?;
        if self.break_glass_grants.contains_key(&id) {
            return Err(DomainError::AccessAlreadyExists);
        }
        if !self.is_active_owner_actor(&approved_by) {
            return Err(DomainError::ApproverNotActiveOwner);
        }
        let grant = SupportAccessGrant::create(
            id.clone(),
            beneficiary.clone(),
            approved_by.clone(),
            permissions.into_iter().collect(),
            justification.into(),
            issued_at_ms,
            expires_at_ms,
        )?;
        self.break_glass_grants.insert(id.clone(), grant);
        self.record(
            event,
            OrganizationEvent::BreakGlassAccessGranted {
                grant_id: id,
                beneficiary,
                approved_by,
                expires_at_ms,
            },
        )
    }

    /// Revokes an aggregate-owned access record.
    ///
    /// # Errors
    ///
    /// Returns an error when the target is missing or when membership
    /// revocation would remove the final active owner.
    pub fn revoke_access(
        &mut self,
        target: AccessTarget,
        revoked_by: ActorId,
        event: EventContext,
    ) -> Result<(), DomainError> {
        self.ensure_can_record()?;
        match &target {
            AccessTarget::Membership(id) => {
                let membership = self
                    .memberships
                    .get(id)
                    .ok_or(DomainError::AccessNotFound)?;
                if membership.is_active_owner() && self.active_owner_count() == 1 {
                    return Err(DomainError::LastOwner);
                }
                self.memberships
                    .get_mut(id)
                    .ok_or(DomainError::AccessNotFound)?
                    .revoke();
            }
            AccessTarget::ServicePrincipal(id) => self
                .service_principals
                .get_mut(id)
                .ok_or(DomainError::AccessNotFound)?
                .revoke(),
            AccessTarget::BreakGlass(id) => self
                .break_glass_grants
                .get_mut(id)
                .ok_or(DomainError::AccessNotFound)?
                .revoke(),
        }
        self.record(
            event,
            OrganizationEvent::AccessRevoked { target, revoked_by },
        )
    }

    /// Drains new events for atomic aggregate/event/outbox persistence.
    pub fn take_pending_events(&mut self) -> Vec<DomainEvent> {
        std::mem::take(&mut self.pending_events)
    }

    fn active_owner_count(&self) -> usize {
        self.memberships
            .values()
            .filter(|membership| membership.is_active_owner())
            .count()
    }

    fn is_active_owner_actor(&self, actor_id: &ActorId) -> bool {
        self.actor_memberships
            .get(actor_id)
            .and_then(|member_id| self.memberships.get(member_id))
            .is_some_and(Membership::is_active_owner)
    }

    fn ensure_can_record(&self) -> Result<(), DomainError> {
        self.sequence
            .checked_next()
            .map(|_| ())
            .ok_or(DomainError::SequenceExhausted)
    }

    fn record(
        &mut self,
        context: EventContext,
        payload: OrganizationEvent,
    ) -> Result<(), DomainError> {
        let next = self
            .sequence
            .checked_next()
            .ok_or(DomainError::SequenceExhausted)?;
        self.sequence = next;
        self.pending_events
            .push(DomainEvent::new(self.id.clone(), next, context, payload));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use cauterizer_syntax::authorization::ActionName;
    use cauterizer_syntax::identifiers::{CausationId, CorrelationId};

    use super::*;
    use crate::domain::{EventId, RoleDefinition};

    fn id(suffix: u64) -> String {
        format!("00000000{suffix:08}")
    }

    fn actor(suffix: u64) -> ActorId {
        ActorId::new(&id(suffix)).unwrap()
    }

    fn permission(action: &str) -> Permission {
        Permission::from_action(ActionName::parse(action).unwrap())
    }

    fn event(suffix: u64) -> EventContext {
        EventContext {
            event_id: EventId::new(&id(suffix)).unwrap(),
            occurred_at_ms: suffix,
            correlation_id: CorrelationId::new(&id(suffix)).unwrap(),
            causation_id: CausationId::new(&id(suffix)).unwrap(),
        }
    }

    fn organization() -> (Organization, MemberId, ActorId) {
        let owner_member = MemberId::new(&id(1)).unwrap();
        let owner_actor = actor(1);
        let organization = Organization::create(
            OrganizationId::new(&id(1)).unwrap(),
            "Acme Security",
            owner_member.clone(),
            owner_actor.clone(),
            event(1),
        )
        .unwrap();
        (organization, owner_member, owner_actor)
    }

    #[test]
    fn creation_establishes_one_active_owner_and_event() {
        let (mut organization, owner_member, _) = organization();
        let owner = organization.membership(&owner_member).unwrap();
        assert_eq!(owner.status(), MembershipStatus::Active);
        assert!(owner.roles().contains(&Role::Owner));
        let events = organization.take_pending_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].sequence().get(), 1);
        assert!(matches!(
            events[0].payload(),
            OrganizationEvent::OrganizationCreated { .. }
        ));
    }

    #[test]
    fn invitation_can_only_be_accepted_by_bound_actor_once() {
        let (mut organization, _, _) = organization();
        let member = MemberId::new(&id(2)).unwrap();
        let invited_actor = actor(2);
        organization
            .invite_member(member.clone(), invited_actor.clone(), event(2))
            .unwrap();
        assert_eq!(
            organization
                .accept_membership(&member, &actor(3), event(3))
                .unwrap_err(),
            DomainError::InvitationActorMismatch
        );
        organization
            .accept_membership(&member, &invited_actor, event(4))
            .unwrap();
        assert_eq!(
            organization
                .accept_membership(&member, &invited_actor, event(5))
                .unwrap_err(),
            DomainError::MembershipNotInvited
        );
    }

    #[test]
    fn duplicate_actor_invitation_is_rejected_even_with_new_member_id() {
        let (mut organization, _, _) = organization();
        organization
            .invite_member(MemberId::new(&id(2)).unwrap(), actor(2), event(2))
            .unwrap();
        assert_eq!(
            organization
                .invite_member(MemberId::new(&id(3)).unwrap(), actor(2), event(3))
                .unwrap_err(),
            DomainError::MembershipAlreadyExists
        );
    }

    #[test]
    fn built_in_role_can_only_be_assigned_to_active_member() {
        let (mut organization, _, _) = organization();
        let member = MemberId::new(&id(2)).unwrap();
        let member_actor = actor(2);
        organization
            .invite_member(member.clone(), member_actor.clone(), event(2))
            .unwrap();
        assert_eq!(
            organization
                .assign_role(&member, Role::Reviewer, event(3))
                .unwrap_err(),
            DomainError::MembershipNotActive
        );
        organization
            .accept_membership(&member, &member_actor, event(4))
            .unwrap();
        organization
            .assign_role(&member, Role::Reviewer, event(5))
            .unwrap();
        assert!(
            organization
                .membership(&member)
                .unwrap()
                .roles()
                .contains(&Role::Reviewer)
        );
    }

    #[test]
    fn custom_roles_must_be_defined_before_assignment() {
        let (mut organization, _, _) = organization();
        let member = MemberId::new(&id(2)).unwrap();
        let member_actor = actor(2);
        organization
            .invite_member(member.clone(), member_actor.clone(), event(2))
            .unwrap();
        organization
            .accept_membership(&member, &member_actor, event(3))
            .unwrap();
        assert_eq!(
            organization.assign_role(&member, Role::Custom("triage".into()), event(4)),
            Err(DomainError::UnknownRole)
        );
        organization
            .define_role(
                RoleDefinition::new("triage".into(), BTreeSet::from([permission("runs.read")]))
                    .unwrap(),
                event(5),
            )
            .unwrap();
        organization
            .assign_role(&member, Role::Custom("triage".into()), event(6))
            .unwrap();
        assert!(
            organization
                .membership(&member)
                .unwrap()
                .roles()
                .contains(&Role::Custom("triage".into()))
        );
    }

    #[test]
    fn federation_configuration_is_provider_neutral_and_versioned() {
        let (mut organization, _, _) = organization();
        assert_eq!(
            organization.configure_federation("OIDC provider secret".into(), event(2)),
            Err(DomainError::InvalidFederationConfiguration)
        );
        organization
            .configure_federation("policy-1.0".into(), event(3))
            .unwrap();
        assert_eq!(
            organization.federation_configuration_version(),
            Some("policy-1.0")
        );
        assert!(matches!(
            organization.take_pending_events().last().unwrap().payload(),
            OrganizationEvent::FederationConfigured { configuration_version }
                if configuration_version == "policy-1.0"
        ));
    }

    #[test]
    fn final_active_owner_cannot_be_revoked() {
        let (mut organization, owner_member, owner_actor) = organization();
        let sequence = organization.sequence();
        let events_before = organization.pending_events.clone();
        let owner_before = organization.membership(&owner_member).unwrap().clone();
        assert_eq!(
            organization
                .revoke_access(
                    AccessTarget::Membership(owner_member.clone()),
                    owner_actor,
                    event(2),
                )
                .unwrap_err(),
            DomainError::LastOwner
        );
        assert_eq!(organization.sequence(), sequence);
        assert_eq!(organization.pending_events, events_before);
        assert_eq!(organization.membership(&owner_member), Some(&owner_before));
    }

    #[test]
    fn owner_can_be_revoked_after_another_active_owner_exists() {
        let (mut organization, first_owner, first_actor) = organization();
        let second_owner = MemberId::new(&id(2)).unwrap();
        let second_actor = actor(2);
        organization
            .invite_member(second_owner.clone(), second_actor.clone(), event(2))
            .unwrap();
        organization
            .accept_membership(&second_owner, &second_actor, event(3))
            .unwrap();
        organization
            .assign_role(&second_owner, Role::Owner, event(4))
            .unwrap();
        organization
            .revoke_access(
                AccessTarget::Membership(first_owner.clone()),
                second_actor,
                event(5),
            )
            .unwrap();
        assert_eq!(
            organization.membership(&first_owner).unwrap().status(),
            MembershipStatus::Revoked
        );
        assert!(
            !organization
                .membership(&first_owner)
                .unwrap()
                .roles()
                .contains(&Role::Owner)
        );
        assert_ne!(first_actor, actor(2));
    }

    #[test]
    fn workload_principals_require_explicit_scope_and_short_expiry() {
        let (mut organization, _, _) = organization();
        let principal = WorkloadPrincipalId::new(&id(1)).unwrap();
        assert_eq!(
            organization
                .provision_service_principal(principal.clone(), [], 1_000, 2_000, event(2),)
                .unwrap_err(),
            DomainError::EmptyScope
        );
        assert_eq!(
            organization
                .provision_service_principal(
                    principal,
                    [permission("runs.execute")],
                    1_000,
                    1_000 + MAX_WORKLOAD_LIFETIME_MILLIS + 1,
                    event(3),
                )
                .unwrap_err(),
            DomainError::InvalidWorkloadExpiry
        );
    }

    #[test]
    fn break_glass_is_human_approved_bounded_and_auditable() {
        let (mut organization, _, owner_actor) = organization();
        let grant_id = BreakGlassGrantId::new(&id(1)).unwrap();
        let beneficiary = actor(9);
        organization
            .grant_break_glass(
                grant_id.clone(),
                beneficiary.clone(),
                owner_actor,
                [permission("support.inspect")],
                "Incident IR-2026-0042",
                1_000,
                1_000 + MAX_BREAK_GLASS_MILLIS,
                event(2),
            )
            .unwrap();
        let grant = organization.break_glass_grant(&grant_id).unwrap();
        assert!(grant.is_active_at(1_001));
        assert!(!grant.is_active_at(1_000 + MAX_BREAK_GLASS_MILLIS));
        assert_eq!(grant.beneficiary(), &beneficiary);
        assert_eq!(grant.approved_by(), &actor(1));
        assert_eq!(grant.expires_at_ms(), 1_000 + MAX_BREAK_GLASS_MILLIS);
        assert!(grant.permissions().contains(&permission("support.inspect")));
        assert_eq!(grant.justification(), "Incident IR-2026-0042");

        let emitted = organization.take_pending_events();
        let granted = emitted.last().unwrap();
        assert_eq!(granted.organization_id(), organization.id());
        assert_eq!(granted.context(), &event(2));
        assert!(matches!(
            granted.payload(),
            OrganizationEvent::BreakGlassAccessGranted {
                grant_id: emitted_grant_id,
                beneficiary: emitted_beneficiary,
                approved_by: emitted_approver,
                expires_at_ms,
            } if emitted_grant_id == &grant_id
                && emitted_beneficiary == &beneficiary
                && emitted_approver == &actor(1)
                && *expires_at_ms == 1_000 + MAX_BREAK_GLASS_MILLIS
        ));
    }

    #[test]
    fn break_glass_window_is_issued_inclusive_and_expiry_exclusive() {
        let (mut organization, _, owner_actor) = organization();
        let grant_id = BreakGlassGrantId::new(&id(8)).unwrap();
        organization
            .grant_break_glass(
                grant_id.clone(),
                actor(9),
                owner_actor,
                [permission("support.inspect")],
                "Incident response",
                1_000,
                2_000,
                event(2),
            )
            .unwrap();
        let grant = organization.break_glass_grant(&grant_id).unwrap();
        assert!(!grant.is_active_at(999));
        assert!(grant.is_active_at(1_000));
        assert!(grant.is_active_at(1_999));
        assert!(!grant.is_active_at(2_000));
    }

    #[test]
    fn failed_last_owner_revocation_after_other_activity_is_transactional() {
        let (mut organization, owner_member, owner_actor) = organization();
        organization
            .invite_member(MemberId::new(&id(2)).unwrap(), actor(2), event(2))
            .unwrap();
        let sequence = organization.sequence();
        let events_before = organization.pending_events.clone();
        assert_eq!(
            organization.revoke_access(
                AccessTarget::Membership(owner_member.clone()),
                owner_actor,
                event(3),
            ),
            Err(DomainError::LastOwner)
        );
        assert_eq!(organization.sequence(), sequence);
        assert_eq!(organization.pending_events, events_before);
        let owner = organization.membership(&owner_member).unwrap();
        assert_eq!(owner.status(), MembershipStatus::Active);
        assert!(owner.roles().contains(&Role::Owner));
    }

    #[test]
    fn break_glass_rejects_self_approval_and_non_owner_approval() {
        let (mut organization, _, owner_actor) = organization();
        assert_eq!(
            organization
                .grant_break_glass(
                    BreakGlassGrantId::new(&id(1)).unwrap(),
                    owner_actor.clone(),
                    owner_actor,
                    [permission("support.inspect")],
                    "incident",
                    1,
                    2,
                    event(2),
                )
                .unwrap_err(),
            DomainError::SelfApprovedBreakGlass
        );
        assert_eq!(
            organization
                .grant_break_glass(
                    BreakGlassGrantId::new(&id(2)).unwrap(),
                    actor(9),
                    actor(8),
                    [permission("support.inspect")],
                    "incident",
                    1,
                    2,
                    event(3),
                )
                .unwrap_err(),
            DomainError::ApproverNotActiveOwner
        );
    }

    #[test]
    fn all_successful_behaviors_advance_event_sequence_once() {
        let (mut organization, _, _) = organization();
        for suffix in 2..=25 {
            let member = MemberId::new(&id(suffix)).unwrap();
            organization
                .invite_member(member, actor(suffix), event(suffix))
                .unwrap();
            assert_eq!(organization.sequence().get(), suffix);
        }
        let events = organization.take_pending_events();
        for (index, event) in events.iter().enumerate() {
            assert_eq!(event.sequence().get(), u64::try_from(index + 1).unwrap());
        }
    }
}
