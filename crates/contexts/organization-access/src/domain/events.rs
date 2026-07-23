//! Immutable facts emitted by the Organization aggregate.

use cauterizer_syntax::identifiers::{
    ActorId, AggregateSequence, CausationId, CorrelationId, OrganizationId,
};

use super::{AccessTarget, BreakGlassGrantId, EventId, MemberId, Role, WorkloadPrincipalId};

/// Caller-supplied event identity and audit correlation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventContext {
    /// Unique event ID.
    pub event_id: EventId,
    /// Unix-millisecond time from the injected application clock.
    pub occurred_at_ms: u64,
    /// Logical request correlation ID.
    pub correlation_id: CorrelationId,
    /// Command/event causation ID.
    pub causation_id: CausationId,
}

/// Organization event envelope with immutable tenant and ordering metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainEvent {
    organization_id: OrganizationId,
    sequence: AggregateSequence,
    context: EventContext,
    payload: OrganizationEvent,
}

impl DomainEvent {
    pub(crate) const fn new(
        organization_id: OrganizationId,
        sequence: AggregateSequence,
        context: EventContext,
        payload: OrganizationEvent,
    ) -> Self {
        Self {
            organization_id,
            sequence,
            context,
            payload,
        }
    }

    /// Returns the immutable tenant/aggregate ID.
    #[must_use]
    pub const fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// Returns the one-based aggregate ordering sequence.
    #[must_use]
    pub const fn sequence(&self) -> AggregateSequence {
        self.sequence
    }

    /// Returns event identity, time, and tracing references.
    #[must_use]
    pub const fn context(&self) -> &EventContext {
        &self.context
    }

    /// Returns the immutable fact payload.
    #[must_use]
    pub const fn payload(&self) -> &OrganizationEvent {
        &self.payload
    }
}

/// Facts owned by the Organization & Access context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OrganizationEvent {
    /// Organization and initial owner became active.
    OrganizationCreated {
        /// Initial membership ID.
        owner_member_id: MemberId,
        /// Initial human owner.
        owner_actor_id: ActorId,
    },
    /// A workforce actor was invited.
    MemberInvited {
        /// New membership ID.
        member_id: MemberId,
        /// Actor bound to the invitation.
        actor_id: ActorId,
    },
    /// The bound actor accepted an invitation.
    MembershipAccepted {
        /// Activated membership ID.
        member_id: MemberId,
        /// Actor that accepted.
        actor_id: ActorId,
    },
    /// A role was assigned to an active member.
    RoleAssigned {
        /// Target membership ID.
        member_id: MemberId,
        /// Assigned role.
        role: Role,
    },
    /// A custom role definition was created.
    RoleDefined {
        /// Stable organization-owned role identifier.
        role_id: String,
    },
    /// Provider-neutral federation policy metadata changed.
    FederationConfigured {
        /// Monotonic opaque configuration version.
        configuration_version: String,
    },
    /// A short-lived workload principal was provisioned.
    ServicePrincipalProvisioned {
        /// Principal ID.
        principal_id: WorkloadPrincipalId,
        /// Absolute expiry.
        expires_at_ms: u64,
    },
    /// Approved emergency access was granted.
    BreakGlassAccessGranted {
        /// Grant ID.
        grant_id: BreakGlassGrantId,
        /// Human beneficiary.
        beneficiary: ActorId,
        /// Human owner that approved it.
        approved_by: ActorId,
        /// Absolute expiry.
        expires_at_ms: u64,
    },
    /// A membership, principal, or emergency grant was revoked.
    AccessRevoked {
        /// Exact revoked record.
        target: AccessTarget,
        /// Human actor requesting revocation.
        revoked_by: ActorId,
    },
}
