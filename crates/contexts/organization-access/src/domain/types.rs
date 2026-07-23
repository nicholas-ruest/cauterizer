//! Organization-owned identifiers and value objects.

use std::collections::BTreeSet;
use std::fmt;

use cauterizer_syntax::authorization::ActionName;
use cauterizer_syntax::authorization::AuthorizationRequestContext;
use cauterizer_syntax::identifiers::{ActorId, ContextQualifiedId};

const MAX_JUSTIFICATION_LENGTH: usize = 500;

/// A bounded action that may be granted to a role or principal.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Permission {
    action: ActionName,
    resources: super::authorization::ResourceSelector,
    conditions: super::authorization::PolicyConditions,
}

impl Permission {
    /// Parses a canonical permission action.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::InvalidPermission`] for malformed action syntax.
    pub fn new(value: &str) -> Result<Self, DomainError> {
        ActionName::parse(value)
            .map(|action| Self {
                action,
                resources: super::authorization::ResourceSelector::AnyInOrganization,
                conditions: super::authorization::PolicyConditions::default(),
            })
            .map_err(|_| DomainError::InvalidPermission)
    }

    /// Creates a permission from an already validated action.
    #[must_use]
    pub fn from_action(action: ActionName) -> Self {
        Self {
            action,
            resources: super::authorization::ResourceSelector::AnyInOrganization,
            conditions: super::authorization::PolicyConditions::default(),
        }
    }

    /// Creates a resource- and condition-scoped permission.
    #[must_use]
    pub const fn scoped(
        action: ActionName,
        resources: super::authorization::ResourceSelector,
        conditions: super::authorization::PolicyConditions,
    ) -> Self {
        Self {
            action,
            resources,
            conditions,
        }
    }

    /// Returns the canonical action spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.action.as_str()
    }

    pub(crate) fn matches(
        &self,
        request: &AuthorizationRequestContext,
        context: &super::authorization::DecisionContext,
    ) -> bool {
        self.action.as_str() == request.action().as_str()
            && self.resources.valid()
            && self.resources.matches(request.resource())
            && self.conditions.valid()
            && self.conditions.matches(request, context)
    }
}

/// Built-in and organization-defined roles.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Role {
    /// Full organization administration subject to policy conditions.
    Owner,
    /// Operates remediation workflows.
    SecurityOperator,
    /// Reviews evidence without mutation authority.
    Reviewer,
    /// Organization-defined role referenced by its bounded identifier.
    Custom(String),
}

/// Immutable definition of an organization-owned custom role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleDefinition {
    id: String,
    permissions: BTreeSet<Permission>,
}

impl RoleDefinition {
    /// Creates a non-empty custom role definition.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::EmptyRole`] for an invalid ID or empty permission set.
    pub fn new(id: String, permissions: BTreeSet<Permission>) -> Result<Self, DomainError> {
        if id.is_empty() || id.len() > 64 || permissions.is_empty() {
            return Err(DomainError::EmptyRole);
        }
        Ok(Self { id, permissions })
    }

    /// Returns the stable role identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the role's maximum permission set.
    #[must_use]
    pub const fn permissions(&self) -> &BTreeSet<Permission> {
        &self.permissions
    }
}

/// Public name for a support emergency-access grant.
pub type BreakGlassGrant = SupportAccessGrant;

macro_rules! context_id {
    ($(#[$meta:meta])* $name:ident, $context:literal) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(ContextQualifiedId);

        impl $name {
            /// Creates an ID from a bounded lowercase opaque component.
            ///
            /// # Errors
            ///
            /// Returns an error when the opaque component is not valid shared
            /// identifier syntax.
            pub fn new(opaque: &str) -> Result<Self, DomainError> {
                ContextQualifiedId::new($context, opaque)
                    .map(Self)
                    .map_err(|_| DomainError::InvalidIdentifier)
            }

            /// Returns the canonical context-qualified spelling.
            #[must_use]
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }
    };
}

context_id!(
    /// Organization-owned membership identifier.
    MemberId,
    "member"
);
context_id!(
    /// Organization-owned workload principal identifier.
    WorkloadPrincipalId,
    "workload"
);
context_id!(
    /// Time-bounded break-glass grant identifier.
    BreakGlassGrantId,
    "breakglass"
);
context_id!(
    /// Organization domain-event identifier.
    EventId,
    "org-event"
);

/// Membership lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MembershipStatus {
    /// Invited but not yet accepted by the bound actor.
    Invited,
    /// Active and eligible for role-based authorization.
    Active,
    /// Permanently revoked membership record.
    Revoked,
}

/// A workforce actor's organization membership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Membership {
    id: MemberId,
    actor_id: ActorId,
    status: MembershipStatus,
    roles: BTreeSet<Role>,
}

impl Membership {
    pub(crate) fn invited(id: MemberId, actor_id: ActorId) -> Self {
        Self {
            id,
            actor_id,
            status: MembershipStatus::Invited,
            roles: BTreeSet::new(),
        }
    }

    pub(crate) fn initial_owner(id: MemberId, actor_id: ActorId) -> Self {
        Self {
            id,
            actor_id,
            status: MembershipStatus::Active,
            roles: BTreeSet::from([Role::Owner]),
        }
    }

    /// Returns the membership ID.
    #[must_use]
    pub const fn id(&self) -> &MemberId {
        &self.id
    }

    /// Returns the bound workforce actor.
    #[must_use]
    pub const fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }

    /// Returns the lifecycle state.
    #[must_use]
    pub const fn status(&self) -> MembershipStatus {
        self.status
    }

    /// Returns assigned roles.
    #[must_use]
    pub const fn roles(&self) -> &BTreeSet<Role> {
        &self.roles
    }

    pub(crate) fn accept(&mut self) {
        self.status = MembershipStatus::Active;
    }

    pub(crate) fn assign(&mut self, role: Role) {
        self.roles.insert(role);
    }

    pub(crate) fn revoke(&mut self) {
        self.status = MembershipStatus::Revoked;
        self.roles.clear();
    }

    pub(crate) fn is_active_owner(&self) -> bool {
        self.status == MembershipStatus::Active && self.roles.contains(&Role::Owner)
    }
}

/// A short-lived non-human organization principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServicePrincipal {
    id: WorkloadPrincipalId,
    scopes: BTreeSet<Permission>,
    expires_at_ms: u64,
    revoked: bool,
}

impl ServicePrincipal {
    pub(crate) fn new(
        id: WorkloadPrincipalId,
        scopes: BTreeSet<Permission>,
        expires_at_ms: u64,
    ) -> Self {
        Self {
            id,
            scopes,
            expires_at_ms,
            revoked: false,
        }
    }

    /// Returns the principal ID.
    #[must_use]
    pub const fn id(&self) -> &WorkloadPrincipalId {
        &self.id
    }

    /// Returns explicit scopes granted to the workload.
    #[must_use]
    pub const fn scopes(&self) -> &BTreeSet<Permission> {
        &self.scopes
    }

    /// Returns the absolute Unix-millisecond expiry supplied by the application.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Reports whether access was explicitly revoked.
    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub(crate) fn revoke(&mut self) {
        self.revoked = true;
    }
}

/// An approved, justified emergency human access grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupportAccessGrant {
    id: BreakGlassGrantId,
    beneficiary: ActorId,
    approved_by: ActorId,
    permissions: BTreeSet<Permission>,
    justification: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
    revoked: bool,
}

impl SupportAccessGrant {
    /// Returns whether the grant is currently usable.
    #[must_use]
    pub fn is_active_at(&self, now_ms: u64) -> bool {
        !self.revoked && self.issued_at_ms <= now_ms && now_ms < self.expires_at_ms
    }

    /// Returns the grant ID.
    #[must_use]
    pub const fn id(&self) -> &BreakGlassGrantId {
        &self.id
    }

    /// Returns the human beneficiary.
    #[must_use]
    pub const fn beneficiary(&self) -> &ActorId {
        &self.beneficiary
    }

    /// Returns the approving human owner.
    #[must_use]
    pub const fn approved_by(&self) -> &ActorId {
        &self.approved_by
    }

    /// Returns the explicit emergency permissions.
    #[must_use]
    pub const fn permissions(&self) -> &BTreeSet<Permission> {
        &self.permissions
    }

    /// Returns the bounded human justification.
    #[must_use]
    pub fn justification(&self) -> &str {
        &self.justification
    }

    /// Returns the expiry as Unix milliseconds.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Reports whether the grant was revoked before expiry.
    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub(crate) fn create(
        id: BreakGlassGrantId,
        beneficiary: ActorId,
        approved_by: ActorId,
        permissions: BTreeSet<Permission>,
        justification: String,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Self, DomainError> {
        if beneficiary == approved_by {
            return Err(DomainError::SelfApprovedBreakGlass);
        }
        if justification.trim().is_empty() || justification.len() > MAX_JUSTIFICATION_LENGTH {
            return Err(DomainError::InvalidJustification);
        }
        if permissions.is_empty() {
            return Err(DomainError::EmptyScope);
        }
        if expires_at_ms <= issued_at_ms
            || expires_at_ms - issued_at_ms > super::organization::MAX_BREAK_GLASS_MILLIS
        {
            return Err(DomainError::InvalidBreakGlassWindow);
        }
        Ok(Self {
            id,
            beneficiary,
            approved_by,
            permissions,
            justification,
            issued_at_ms,
            expires_at_ms,
            revoked: false,
        })
    }

    pub(crate) fn revoke(&mut self) {
        self.revoked = true;
    }
}

/// A revocable access record owned by the aggregate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccessTarget {
    /// Workforce membership.
    Membership(MemberId),
    /// Workload principal.
    ServicePrincipal(WorkloadPrincipalId),
    /// Emergency human grant.
    BreakGlass(BreakGlassGrantId),
}

/// Stable domain failures returned by aggregate behavior.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DomainError {
    /// A context-owned identifier was malformed.
    InvalidIdentifier,
    /// The organization name was empty or exceeded its bound.
    InvalidOrganizationName,
    /// A permission name was malformed.
    InvalidPermission,
    /// A custom role must contain a permission.
    EmptyRole,
    /// A role ID was already defined.
    RoleAlreadyExists,
    /// Federation configuration metadata was malformed.
    InvalidFederationConfiguration,
    /// A referenced role was not defined.
    UnknownRole,
    /// A membership actor or ID was already recorded.
    MembershipAlreadyExists,
    /// A membership was not found.
    MembershipNotFound,
    /// Only an invited membership may be accepted.
    MembershipNotInvited,
    /// The accepting actor did not match the invitation.
    InvitationActorMismatch,
    /// The operation requires an active membership.
    MembershipNotActive,
    /// Revocation would remove the final active owner.
    LastOwner,
    /// A principal or grant ID was already recorded.
    AccessAlreadyExists,
    /// A revocation target was not found.
    AccessNotFound,
    /// A workload scope or emergency permission set was empty.
    EmptyScope,
    /// A workload expiry was absent or not short lived.
    InvalidWorkloadExpiry,
    /// Emergency access justification was empty or oversized.
    InvalidJustification,
    /// Emergency access was self-approved.
    SelfApprovedBreakGlass,
    /// The emergency access window was absent or too long.
    InvalidBreakGlassWindow,
    /// The approver is not an active organization owner.
    ApproverNotActiveOwner,
    /// Aggregate event sequence exhausted its numeric range.
    SequenceExhausted,
}

impl fmt::Display for DomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.reason_code())
    }
}

impl DomainError {
    /// Returns a stable machine reason code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidIdentifier => "invalid_identifier",
            Self::InvalidOrganizationName => "invalid_organization_name",
            Self::InvalidPermission => "invalid_permission",
            Self::EmptyRole => "empty_role",
            Self::RoleAlreadyExists => "role_already_exists",
            Self::InvalidFederationConfiguration => "invalid_federation_configuration",
            Self::UnknownRole => "unknown_role",
            Self::MembershipAlreadyExists => "membership_already_exists",
            Self::MembershipNotFound => "membership_not_found",
            Self::MembershipNotInvited => "membership_not_invited",
            Self::InvitationActorMismatch => "invitation_actor_mismatch",
            Self::MembershipNotActive => "membership_not_active",
            Self::LastOwner => "last_owner",
            Self::AccessAlreadyExists => "access_already_exists",
            Self::AccessNotFound => "access_not_found",
            Self::EmptyScope => "empty_scope",
            Self::InvalidWorkloadExpiry => "invalid_workload_expiry",
            Self::InvalidJustification => "invalid_justification",
            Self::SelfApprovedBreakGlass => "self_approved_break_glass",
            Self::InvalidBreakGlassWindow => "invalid_break_glass_window",
            Self::ApproverNotActiveOwner => "approver_not_active_owner",
            Self::SequenceExhausted => "sequence_exhausted",
        }
    }
}

impl std::error::Error for DomainError {}
