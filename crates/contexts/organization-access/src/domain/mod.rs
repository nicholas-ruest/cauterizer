//! Organization and Access domain model.

mod authorization;
mod events;
mod organization;
mod types;

pub use authorization::{
    AuthorizationDecision, AuthorizationPolicy, DecisionContext, DecisionReason, PermissionRule,
    PolicyConditions, ResourceSelector, RoleRule, SubjectAccess,
};
pub use events::{DomainEvent, EventContext, OrganizationEvent};
pub use organization::Organization;
pub use types::{
    AccessTarget, BreakGlassGrant, BreakGlassGrantId, DomainError, EventId, MemberId, Membership,
    MembershipStatus, Permission, Role, RoleDefinition, ServicePrincipal, SupportAccessGrant,
    WorkloadPrincipalId,
};
