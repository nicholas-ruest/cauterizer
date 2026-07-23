//! Versioned, provider-neutral published language for Organization & Access.

use std::collections::BTreeMap;

use cauterizer_syntax::authorization::{ActionName, Purpose, ResourceRef};
use cauterizer_syntax::identifiers::{
    ActorId, AggregateSequence, CausationId, ContextQualifiedId, CorrelationId, IdentityRef,
    OrganizationId, ServicePrincipalId,
};
use cauterizer_syntax::schema::{SchemaName, SchemaVersion};
use cauterizer_syntax::time::UtcInstant;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Current major version of Organization & Access contracts.
pub const CONTRACT_MAJOR_VERSION: u16 = 1;
/// Current semantic version emitted by this producer.
pub const CONTRACT_VERSION: &str = "1.0.0";
/// Stable aggregate type in event envelopes.
pub const ORGANIZATION_AGGREGATE_TYPE: &str = "organization";

/// Versioned fact published after an Organization aggregate transition.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationAccessEventV1 {
    /// Immutable schema identity for registry and compatibility checks.
    pub schema_name: SchemaName,
    /// Semantic schema version; consumers accept compatible v1 revisions.
    pub schema_version: SchemaVersion,
    /// Stable aggregate type, currently `organization`.
    pub aggregate_type: String,
    /// Owning organization and tenant boundary.
    pub organization_id: OrganizationId,
    /// Aggregate event ordering sequence.
    pub aggregate_sequence: AggregateSequence,
    /// Unique event identifier for inbox deduplication.
    pub event_id: ContextQualifiedId,
    /// Canonical event time supplied by the application clock.
    pub occurred_at: UtcInstant,
    /// Request trace identifier.
    pub correlation_id: CorrelationId,
    /// Command/event that caused this fact.
    pub causation_id: CausationId,
    /// Consumer-required, non-secret event payload.
    pub payload: OrganizationAccessEventPayloadV1,
}

/// Public Organization & Access event variants.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum OrganizationAccessEventPayloadV1 {
    /// An organization was created with its initial owner.
    OrganizationCreated {
        /// Initial human owner of the organization.
        owner: ActorId,
    },
    /// A membership invitation was recorded.
    MemberInvited {
        /// Aggregate-owned membership record.
        membership_id: ContextQualifiedId,
        /// Human actor bound to the invitation.
        actor: ActorId,
    },
    /// An invited actor accepted membership.
    MembershipAccepted {
        /// Membership record that became active.
        membership_id: ContextQualifiedId,
        /// Human actor that accepted the invitation.
        actor: ActorId,
    },
    /// A bounded role name was assigned to a membership.
    RoleAssigned {
        /// Membership receiving the role.
        membership_id: ContextQualifiedId,
        /// Stable built-in or organization-defined role name.
        role: String,
    },
    /// An organization-owned custom role definition was created.
    RoleDefined {
        /// Stable organization-owned role identifier.
        role_id: String,
    },
    /// Federation configuration changed; provider SDK content is excluded.
    FederationConfigured {
        /// Opaque revision of the provider-neutral federation configuration.
        configuration_version: String,
    },
    /// A workload identity was provisioned.
    ServicePrincipalProvisioned {
        /// Newly provisioned workload identity.
        service_principal: ServicePrincipalId,
        /// Absolute expiry of the short-lived workload identity.
        expires_at: UtcInstant,
    },
    /// A time-bounded break-glass grant was issued.
    BreakGlassAccessGranted {
        /// Aggregate-owned emergency grant record.
        grant_id: ContextQualifiedId,
        /// Human actor receiving emergency access.
        actor: ActorId,
        /// Distinct human owner that approved the grant.
        approved_by: ActorId,
        /// Absolute expiry of the emergency grant.
        expires_at: UtcInstant,
    },
    /// Access was revoked for an exact aggregate-owned subject.
    AccessRevoked {
        /// Exact aggregate-owned record whose access was revoked.
        subject: AccessSubjectV1,
    },
}

/// Provider-neutral reference to a revocable access record.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "id",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum AccessSubjectV1 {
    /// Human organization membership record.
    Membership(ContextQualifiedId),
    /// Workload identity record.
    ServicePrincipal(ServicePrincipalId),
    /// Emergency support-access grant record.
    BreakGlassGrant(ContextQualifiedId),
}

/// Authenticated organization-scoped input to an authorization decision.
///
/// Conditions are validated claims established by the application boundary;
/// their presence never grants authority by itself.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationContextV1 {
    /// Semantic version of this authorization-context schema.
    pub schema_version: SchemaVersion,
    /// Unique request identifier retained in security audit.
    pub request_id: ContextQualifiedId,
    /// End-to-end trace correlation identifier.
    pub correlation_id: CorrelationId,
    /// Command or event that caused this request.
    pub causation_id: CausationId,
    /// Organization whose policy must evaluate the request.
    pub organization_id: OrganizationId,
    /// Authenticated human or workload identity.
    pub actor: IdentityRef,
    /// Exact operation being requested.
    pub action: ActionName,
    /// Opaque context-owned target of the operation.
    pub resource: ResourceRef,
    /// Audit-safe declared reason for the operation.
    pub purpose: Purpose,
    /// Canonical, policy-understood contextual attributes only.
    pub conditions: BTreeMap<String, String>,
}

/// Stable authorization outcome. Anything other than an explicit allow is deny.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationOutcomeV1 {
    /// Policy explicitly proved the exact request is permitted.
    Allow,
    /// Policy did not prove the exact request is permitted.
    Deny,
}

/// Stable, audit-safe policy reason vocabulary.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationReasonV1 {
    /// An assigned role and all contextual constraints matched.
    RoleGrant,
    /// An active, independently approved emergency grant matched.
    BreakGlassGrant,
    /// No authenticated identity was established.
    Unauthenticated,
    /// Request, resource, or policy organization did not match.
    OrganizationMismatch,
    /// Supplied access records did not belong to the authenticated actor.
    IdentityMismatch,
    /// Membership, workload identity, or grant was inactive.
    SubjectInactive,
    /// No explicit permission matched the request.
    NoMatchingGrant,
    /// A permission matched but its contextual constraints did not.
    ConditionsNotSatisfied,
    /// Policy input or configuration was invalid and failed closed.
    InvalidPolicy,
    /// Authorization state exceeded the permitted freshness bound.
    StaleAuthorizationState,
}

/// Versioned policy result consumed by downstream application boundaries.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationDecisionV1 {
    /// Semantic version of this authorization-decision schema.
    pub schema_version: SchemaVersion,
    /// Request to which this decision applies.
    pub request_id: ContextQualifiedId,
    /// Organization whose policy made the decision.
    pub organization_id: OrganizationId,
    /// Authenticated identity evaluated by policy.
    pub actor: IdentityRef,
    /// Exact operation evaluated by policy.
    pub action: ActionName,
    /// Exact opaque resource evaluated by policy.
    pub resource: ResourceRef,
    /// Declared purpose evaluated by policy.
    pub purpose: Purpose,
    /// Fail-closed authorization result.
    pub outcome: AuthorizationOutcomeV1,
    /// Stable explanation of the result.
    pub reason: AuthorizationReasonV1,
    /// Immutable semantic version of the policy snapshot used.
    pub policy_version: SchemaVersion,
    /// Canonical instant at which policy made the decision.
    pub decided_at: UtcInstant,
}

/// Result of the privileged operation whose authorization was evaluated.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditedOperationOutcomeV1 {
    /// The authorized operation completed successfully.
    Succeeded,
    /// The operation was attempted but failed.
    Failed,
    /// Policy denial or precondition failure prevented an attempt.
    NotAttempted,
}

/// Append-only, payload-safe authorization audit fact.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationAuditFactV1 {
    /// Semantic version of this audit-fact schema.
    pub schema_version: SchemaVersion,
    /// Unique request represented by this audit fact.
    pub request_id: ContextQualifiedId,
    /// Organization owning the audited security boundary.
    pub organization_id: OrganizationId,
    /// Authenticated identity whose request was audited.
    pub actor: IdentityRef,
    /// Exact requested operation.
    pub action: ActionName,
    /// Opaque context-owned resource reference.
    pub resource: ResourceRef,
    /// Audit-safe declared reason for the request.
    pub purpose: Purpose,
    /// Authorization policy result.
    pub outcome: AuthorizationOutcomeV1,
    /// Stable policy reason for the result.
    pub reason: AuthorizationReasonV1,
    /// Outcome of the privileged operation after authorization.
    pub operation_outcome: AuditedOperationOutcomeV1,
    /// Immutable semantic version of the evaluated policy.
    pub policy_version: SchemaVersion,
    /// Canonical authorization decision time.
    pub decided_at: UtcInstant,
    /// End-to-end trace correlation identifier.
    pub correlation_id: CorrelationId,
    /// Command or event that caused the audited request.
    pub causation_id: CausationId,
}

#[cfg(test)]
mod tests {
    use super::*;
    use cauterizer_syntax::schema::SchemaChange;
    use cauterizer_syntax::schema::classify_schema_change;
    use schemars::schema_for;
    use serde_json::{Value, json};

    #[test]
    fn stable_enum_wire_vocabulary_is_golden() {
        assert_eq!(
            serde_json::to_value(AuthorizationOutcomeV1::Allow).unwrap(),
            json!("allow")
        );
        assert_eq!(
            serde_json::to_value(AuthorizationOutcomeV1::Deny).unwrap(),
            json!("deny")
        );
        assert_eq!(
            serde_json::to_value(AuthorizationReasonV1::OrganizationMismatch).unwrap(),
            json!("organization_mismatch")
        );
        assert_eq!(
            serde_json::to_value(AuditedOperationOutcomeV1::NotAttempted).unwrap(),
            json!("not_attempted")
        );
    }

    #[test]
    fn unknown_security_fields_and_unknown_reasons_are_rejected() {
        let context = AuthorizationContextV1 {
            schema_version: SchemaVersion::parse(CONTRACT_VERSION).unwrap(),
            request_id: "request_00000000".parse().unwrap(),
            correlation_id: "correlation_00000000".parse().unwrap(),
            causation_id: "causation_00000000".parse().unwrap(),
            organization_id: "org_00000000".parse().unwrap(),
            actor: IdentityRef::Human("actor_00000000".parse().unwrap()),
            action: ActionName::parse("runs.read").unwrap(),
            resource: ResourceRef::parse("run:00000000").unwrap(),
            purpose: Purpose::parse("incident response").unwrap(),
            conditions: BTreeMap::new(),
        };
        let mut wire = serde_json::to_value(context).unwrap();
        wire.as_object_mut()
            .unwrap()
            .insert("authority".into(), json!("owner"));
        assert!(serde_json::from_value::<AuthorizationContextV1>(wire).is_err());
        assert!(serde_json::from_str::<AuthorizationReasonV1>("\"future_superuser\"").is_err());
    }

    #[test]
    fn schemas_are_closed_and_security_critical() {
        for schema in [
            serde_json::to_value(schema_for!(OrganizationAccessEventV1)).unwrap(),
            serde_json::to_value(schema_for!(AuthorizationContextV1)).unwrap(),
            serde_json::to_value(schema_for!(AuthorizationDecisionV1)).unwrap(),
            serde_json::to_value(schema_for!(AuthorizationAuditFactV1)).unwrap(),
        ] {
            let object = schema
                .get("properties")
                .is_some()
                .then_some(&schema)
                .or_else(|| schema.get("schema"));
            let object = object.expect("root object schema");
            assert_eq!(
                object.get("additionalProperties"),
                Some(&Value::Bool(false))
            );
        }
    }

    #[test]
    fn required_field_removal_is_a_breaking_schema_change() {
        let current = serde_json::to_value(schema_for!(AuthorizationDecisionV1)).unwrap();
        let mut changed = current.clone();
        changed
            .get_mut("required")
            .and_then(Value::as_array_mut)
            .expect("required array")
            .retain(|field| field != "policy_version");
        assert_eq!(
            classify_schema_change(&current, &changed),
            SchemaChange::SecurityCriticalBreaking
        );
    }

    #[test]
    fn event_payload_golden_shape_is_stable() {
        let payload = OrganizationAccessEventPayloadV1::AccessRevoked {
            subject: AccessSubjectV1::BreakGlassGrant("breakglass_00000000".parse().unwrap()),
        };
        assert_eq!(
            serde_json::to_value(payload).unwrap(),
            json!({"type":"access_revoked","data":{"subject":{"type":"break_glass_grant","id":"breakglass_00000000"}}})
        );
    }

    #[test]
    fn role_defined_payload_does_not_publish_permission_internals() {
        let payload = OrganizationAccessEventPayloadV1::RoleDefined {
            role_id: "incident-reviewer".into(),
        };
        assert_eq!(
            serde_json::to_value(payload).unwrap(),
            json!({"type":"role_defined","data":{"role_id":"incident-reviewer"}})
        );
    }
}
