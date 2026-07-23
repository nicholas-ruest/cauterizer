//! Governed mapping from private domain events to published v1 contracts.

use cauterizer_syntax::identifiers::{ContextQualifiedId, ServicePrincipalId};
use cauterizer_syntax::schema::{SchemaName, SchemaVersion};
use cauterizer_syntax::time::UtcInstant;

use crate::contracts::{
    AccessSubjectV1, CONTRACT_VERSION, ORGANIZATION_AGGREGATE_TYPE,
    OrganizationAccessEventPayloadV1, OrganizationAccessEventV1,
};
use crate::domain::{AccessTarget, DomainEvent, OrganizationEvent, Role};

const EVENT_SCHEMA_NAME: &str = "dev.cauterizer.organization-access.event";

/// Canonical timestamps supplied by the application clock boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalEventTimes {
    /// Canonical occurrence time corresponding to the domain event's Unix time.
    pub occurred_at: UtcInstant,
    /// Canonical expiry for events whose domain payload carries an expiry instant.
    pub expires_at: Option<UtcInstant>,
}

/// Stable failure returned when a private fact cannot be represented safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventMappingError {
    /// A context-owned identifier could not be represented by its public type.
    InvalidIdentifier,
    /// A compile-time governed schema constant was invalid.
    InvalidSchemaMetadata,
    /// An expiring fact was mapped without its explicit canonical expiry.
    MissingCanonicalExpiry,
}

/// Maps one immutable aggregate fact to its governed public v1 representation.
///
/// The mapper is deliberately pure: callers supply canonical timestamps and it
/// neither consults a clock nor publishes private role permissions, emergency
/// justification, or identity-provider configuration.
///
/// # Errors
///
/// Returns [`EventMappingError`] if a domain identifier cannot be converted,
/// governed schema metadata is invalid, or an expiring fact lacks its supplied
/// canonical expiry.
pub fn map_domain_event_v1(
    event: &DomainEvent,
    times: CanonicalEventTimes,
) -> Result<OrganizationAccessEventV1, EventMappingError> {
    Ok(OrganizationAccessEventV1 {
        schema_name: SchemaName::parse(EVENT_SCHEMA_NAME)
            .map_err(|_| EventMappingError::InvalidSchemaMetadata)?,
        schema_version: SchemaVersion::parse(CONTRACT_VERSION)
            .map_err(|_| EventMappingError::InvalidSchemaMetadata)?,
        aggregate_type: ORGANIZATION_AGGREGATE_TYPE.to_owned(),
        organization_id: event.organization_id().clone(),
        aggregate_sequence: event.sequence(),
        event_id: parse_context_id(event.context().event_id.as_str())?,
        occurred_at: times.occurred_at,
        correlation_id: event.context().correlation_id.clone(),
        causation_id: event.context().causation_id.clone(),
        payload: map_payload(event.payload(), times.expires_at)?,
    })
}

fn map_payload(
    event: &OrganizationEvent,
    expires_at: Option<UtcInstant>,
) -> Result<OrganizationAccessEventPayloadV1, EventMappingError> {
    Ok(match event {
        OrganizationEvent::OrganizationCreated { owner_actor_id, .. } => {
            OrganizationAccessEventPayloadV1::OrganizationCreated {
                owner: owner_actor_id.clone(),
            }
        }
        OrganizationEvent::MemberInvited {
            member_id,
            actor_id,
        } => OrganizationAccessEventPayloadV1::MemberInvited {
            membership_id: parse_context_id(member_id.as_str())?,
            actor: actor_id.clone(),
        },
        OrganizationEvent::MembershipAccepted {
            member_id,
            actor_id,
        } => OrganizationAccessEventPayloadV1::MembershipAccepted {
            membership_id: parse_context_id(member_id.as_str())?,
            actor: actor_id.clone(),
        },
        OrganizationEvent::RoleAssigned { member_id, role } => {
            OrganizationAccessEventPayloadV1::RoleAssigned {
                membership_id: parse_context_id(member_id.as_str())?,
                role: role_name(role),
            }
        }
        OrganizationEvent::RoleDefined { role_id } => {
            OrganizationAccessEventPayloadV1::RoleDefined {
                role_id: role_id.clone(),
            }
        }
        OrganizationEvent::FederationConfigured {
            configuration_version,
        } => OrganizationAccessEventPayloadV1::FederationConfigured {
            configuration_version: configuration_version.clone(),
        },
        OrganizationEvent::ServicePrincipalProvisioned { principal_id, .. } => {
            OrganizationAccessEventPayloadV1::ServicePrincipalProvisioned {
                service_principal: service_id(principal_id.as_str())?,
                expires_at: expires_at.ok_or(EventMappingError::MissingCanonicalExpiry)?,
            }
        }
        OrganizationEvent::BreakGlassAccessGranted {
            grant_id,
            beneficiary,
            approved_by,
            ..
        } => OrganizationAccessEventPayloadV1::BreakGlassAccessGranted {
            grant_id: parse_context_id(grant_id.as_str())?,
            actor: beneficiary.clone(),
            approved_by: approved_by.clone(),
            expires_at: expires_at.ok_or(EventMappingError::MissingCanonicalExpiry)?,
        },
        OrganizationEvent::AccessRevoked { target, .. } => {
            OrganizationAccessEventPayloadV1::AccessRevoked {
                subject: access_subject(target)?,
            }
        }
    })
}

fn parse_context_id(value: &str) -> Result<ContextQualifiedId, EventMappingError> {
    value
        .parse()
        .map_err(|_| EventMappingError::InvalidIdentifier)
}

fn service_id(value: &str) -> Result<ServicePrincipalId, EventMappingError> {
    value
        .strip_prefix("workload_")
        .ok_or(EventMappingError::InvalidIdentifier)
        .and_then(|opaque| {
            ServicePrincipalId::new(opaque).map_err(|_| EventMappingError::InvalidIdentifier)
        })
}

fn access_subject(target: &AccessTarget) -> Result<AccessSubjectV1, EventMappingError> {
    match target {
        AccessTarget::Membership(id) => {
            Ok(AccessSubjectV1::Membership(parse_context_id(id.as_str())?))
        }
        AccessTarget::ServicePrincipal(id) => {
            Ok(AccessSubjectV1::ServicePrincipal(service_id(id.as_str())?))
        }
        AccessTarget::BreakGlass(id) => Ok(AccessSubjectV1::BreakGlassGrant(parse_context_id(
            id.as_str(),
        )?)),
    }
}

fn role_name(role: &Role) -> String {
    match role {
        Role::Owner => "owner".into(),
        Role::SecurityOperator => "security_operator".into(),
        Role::Reviewer => "reviewer".into(),
        Role::Custom(name) => name.clone(),
    }
}

#[cfg(test)]
mod tests {
    use cauterizer_syntax::identifiers::{
        ActorId, AggregateSequence, CausationId, CorrelationId, OrganizationId,
    };

    use super::*;
    use crate::domain::{BreakGlassGrantId, EventContext, EventId, MemberId, WorkloadPrincipalId};

    fn domain_event(payload: OrganizationEvent) -> DomainEvent {
        DomainEvent::new(
            OrganizationId::new("00000000").unwrap(),
            AggregateSequence::new(7).unwrap(),
            EventContext {
                event_id: EventId::new("00000001").unwrap(),
                occurred_at_ms: 1_000,
                correlation_id: CorrelationId::new("00000002").unwrap(),
                causation_id: CausationId::new("00000003").unwrap(),
            },
            payload,
        )
    }

    fn times(expiry: bool) -> CanonicalEventTimes {
        CanonicalEventTimes {
            occurred_at: UtcInstant::parse("2026-07-22T00:00:01Z").unwrap(),
            expires_at: expiry.then(|| UtcInstant::parse("2026-07-22T01:00:01Z").unwrap()),
        }
    }

    #[test]
    fn maps_every_non_expiring_variant_without_private_details() {
        let actor = ActorId::new("00000001").unwrap();
        let member = MemberId::new("00000001").unwrap();
        let cases = [
            domain_event(OrganizationEvent::OrganizationCreated {
                owner_member_id: member.clone(),
                owner_actor_id: actor.clone(),
            }),
            domain_event(OrganizationEvent::MemberInvited {
                member_id: member.clone(),
                actor_id: actor.clone(),
            }),
            domain_event(OrganizationEvent::MembershipAccepted {
                member_id: member.clone(),
                actor_id: actor,
            }),
            domain_event(OrganizationEvent::RoleAssigned {
                member_id: member.clone(),
                role: Role::Custom("incident-reviewer".into()),
            }),
            domain_event(OrganizationEvent::RoleDefined {
                role_id: "incident-reviewer".into(),
            }),
            domain_event(OrganizationEvent::FederationConfigured {
                configuration_version: "revision-7".into(),
            }),
            domain_event(OrganizationEvent::AccessRevoked {
                target: AccessTarget::Membership(member),
                revoked_by: ActorId::new("00000002").unwrap(),
            }),
        ];

        for event in cases {
            let published = map_domain_event_v1(&event, times(false)).unwrap();
            assert_eq!(published.aggregate_sequence.get(), 7);
            assert_eq!(published.aggregate_type, ORGANIZATION_AGGREGATE_TYPE);
            let wire = serde_json::to_string(&published).unwrap();
            assert!(!wire.contains("revoked_by"));
            assert!(!wire.contains("permissions"));
        }
    }

    #[test]
    fn maps_expiring_variants_only_with_explicit_canonical_expiry() {
        let workload = domain_event(OrganizationEvent::ServicePrincipalProvisioned {
            principal_id: WorkloadPrincipalId::new("00000001").unwrap(),
            expires_at_ms: 3_601_000,
        });
        assert_eq!(
            map_domain_event_v1(&workload, times(false)),
            Err(EventMappingError::MissingCanonicalExpiry)
        );
        let published = map_domain_event_v1(&workload, times(true)).unwrap();
        assert!(matches!(
            published.payload,
            OrganizationAccessEventPayloadV1::ServicePrincipalProvisioned { .. }
        ));

        let emergency = domain_event(OrganizationEvent::BreakGlassAccessGranted {
            grant_id: BreakGlassGrantId::new("00000001").unwrap(),
            beneficiary: ActorId::new("00000002").unwrap(),
            approved_by: ActorId::new("00000003").unwrap(),
            expires_at_ms: 3_601_000,
        });
        let wire =
            serde_json::to_string(&map_domain_event_v1(&emergency, times(true)).unwrap()).unwrap();
        assert!(!wire.contains("justification"));
        assert!(wire.contains("approved_by"));
    }

    #[test]
    fn maps_each_revocation_target_without_identity_provider_types() {
        let targets = [
            AccessTarget::Membership(MemberId::new("00000001").unwrap()),
            AccessTarget::ServicePrincipal(WorkloadPrincipalId::new("00000001").unwrap()),
            AccessTarget::BreakGlass(BreakGlassGrantId::new("00000001").unwrap()),
        ];
        for target in targets {
            let event = domain_event(OrganizationEvent::AccessRevoked {
                target,
                revoked_by: ActorId::new("00000002").unwrap(),
            });
            let published = map_domain_event_v1(&event, times(false)).unwrap();
            assert!(matches!(
                published.payload,
                OrganizationAccessEventPayloadV1::AccessRevoked { .. }
            ));
        }
    }
}
