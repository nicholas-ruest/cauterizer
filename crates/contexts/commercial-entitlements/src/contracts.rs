//! Versioned published language for Commercial Entitlements.
//!
//! These contracts admit or deny cost-incurring work. They intentionally have
//! no vocabulary capable of changing verification rules, evidence requirements,
//! or verdicts.

use cauterizer_syntax::identifiers::{
    AggregateSequence, CausationId, ContextQualifiedId, CorrelationId, OrganizationId,
};
use cauterizer_syntax::schema::{SchemaName, SchemaVersion};
use cauterizer_syntax::time::UtcInstant;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Current semantic version emitted by this context.
pub const CONTRACT_VERSION: &str = "1.0.0";
/// Stable event schema name.
pub const EVENT_SCHEMA_NAME: &str = "dev.cauterizer.commercial-entitlements.event";
/// Stable aggregate type.
pub const AGGREGATE_TYPE: &str = "entitlement-account";

/// Cost dimensions which may be limited or reserved.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageDimensionV1 {
    /// Solver model tokens.
    SolverTokens,
    /// Isolated execution wall-clock milliseconds.
    ExecutionMilliseconds,
    /// Retained artifact byte-days.
    StorageByteDays,
    /// Installed connector count.
    ConnectorInstallations,
}

/// Stable commercial admission outcome.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionOutcomeV1 {
    /// Worst-case budget was reserved and work may start.
    Reserved,
    /// Commercial policy denied starting cost-incurring work.
    Denied,
}

/// Stable, explainable commercial reason codes.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommercialReasonV1 {
    /// Plan explicitly grants the requested cost dimension.
    Granted,
    /// Explicit unlimited local-development grant.
    UnlimitedLocalDevelopment,
    /// Hard organization quota would be exceeded.
    HardLimitExceeded,
    /// Commercial access is suspended.
    CommercialAccessSuspended,
    /// No applicable grant exists.
    EntitlementMissing,
}

/// Immutable reservation contract required before cost-incurring work.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservedUsageV1 {
    /// Exact metered dimension.
    pub dimension: UsageDimensionV1,
    /// Non-zero worst-case amount held for this dimension.
    pub amount: u64,
}

/// Immutable reservation contract required before cost-incurring work.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetReservationV1 {
    /// Tenant owning both reservation and later usage.
    pub organization_id: OrganizationId,
    /// Opaque reservation identity.
    pub reservation_id: ContextQualifiedId,
    /// Complete worst-case budget held atomically across dimensions.
    pub reserved: Vec<ReservedUsageV1>,
    /// Exclusive reservation expiry.
    pub expires_at: UtcInstant,
    /// Admission outcome; only `reserved` authorizes work.
    pub outcome: AdmissionOutcomeV1,
    /// Explainable commercial reason, never a security conclusion.
    pub reason: CommercialReasonV1,
}

impl BudgetReservationV1 {
    /// Returns true only for a structurally positive admission contract.
    /// Downstream handlers must additionally authenticate the envelope, match its
    /// tenant/resource binding, and reject it at or after `expires_at`.
    #[must_use]
    pub fn is_positive_admission(&self) -> bool {
        self.outcome == AdmissionOutcomeV1::Reserved
            && matches!(
                self.reason,
                CommercialReasonV1::Granted | CommercialReasonV1::UnlimitedLocalDevelopment
            )
            && !self.reserved.is_empty()
            && self.reserved.iter().all(|usage| usage.amount > 0)
    }
}

/// Versioned integration-event envelope.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommercialEntitlementsEventV1 {
    /// Immutable schema identity.
    pub schema_name: SchemaName,
    /// Semantic schema version.
    pub schema_version: SchemaVersion,
    /// Stable aggregate type.
    pub aggregate_type: String,
    /// Owning tenant.
    pub organization_id: OrganizationId,
    /// Opaque entitlement-account identity.
    pub aggregate_id: ContextQualifiedId,
    /// Aggregate ordering sequence.
    pub aggregate_sequence: AggregateSequence,
    /// Globally unique event identity.
    pub event_id: ContextQualifiedId,
    /// Canonical event time.
    pub occurred_at: UtcInstant,
    /// End-to-end trace.
    pub correlation_id: CorrelationId,
    /// Command or event which caused this fact.
    pub causation_id: CausationId,
    /// Consumer-required commercial fact.
    pub payload: CommercialEntitlementsEventPayloadV1,
}

/// Published Commercial Entitlements facts.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CommercialEntitlementsEventPayloadV1 {
    /// A versioned plan became active.
    PlanAssigned {
        /// Stable plan identifier.
        plan_id: String,
        /// Immutable plan revision.
        plan_version: String,
    },
    /// One cost/feature grant became active.
    EntitlementGranted {
        /// Stable grant identifier.
        grant_id: ContextQualifiedId,
        /// Cost dimension governed by the grant.
        dimension: UsageDimensionV1,
    },
    /// Worst-case budget was atomically reserved.
    BudgetReserved {
        /// Complete immutable admission contract.
        reservation: BudgetReservationV1,
    },
    /// Actual immutable usage settled a reservation.
    UsageSettled {
        /// Reservation consumed by settlement.
        reservation_id: ContextQualifiedId,
        /// Immutable usage-record identifier.
        usage_record_id: ContextQualifiedId,
        /// Actual measured usage.
        actual_amount: u64,
    },
    /// Unused reserved budget was released.
    ReservationReleased {
        /// Reservation being closed.
        reservation_id: ContextQualifiedId,
        /// Unused amount returned to available budget.
        released_amount: u64,
    },
    /// An auditable non-payment credit adjusted available budget.
    CreditApplied {
        /// Immutable credit-adjustment identifier.
        credit_id: ContextQualifiedId,
        /// Adjusted cost dimension.
        dimension: UsageDimensionV1,
        /// Non-negative credited amount.
        amount: u64,
    },
    /// New cost-incurring admission was suspended.
    CommercialAccessSuspended {
        /// Stable audit-safe suspension reason.
        reason_code: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use cauterizer_syntax::schema::{SchemaChange, classify_schema_change};
    use schemars::schema_for;
    use serde_json::{Value, json};

    #[test]
    fn wire_vocabulary_and_event_tag_are_stable() {
        assert_eq!(
            serde_json::to_value(UsageDimensionV1::SolverTokens).unwrap(),
            json!("solver_tokens")
        );
        let payload = CommercialEntitlementsEventPayloadV1::ReservationReleased {
            reservation_id: "reservation_00000000".parse().unwrap(),
            released_amount: 42,
        };
        assert_eq!(
            serde_json::to_value(payload).unwrap(),
            json!({
                "type":"reservation_released",
                "data":{"reservation_id":"reservation_00000000","released_amount":42}
            })
        );
    }

    #[test]
    fn schemas_are_closed_and_required_field_removal_is_breaking() {
        for schema in [
            serde_json::to_value(schema_for!(CommercialEntitlementsEventV1)).unwrap(),
            serde_json::to_value(schema_for!(BudgetReservationV1)).unwrap(),
        ] {
            assert_eq!(
                schema.get("additionalProperties"),
                Some(&Value::Bool(false))
            );
        }
        let current = serde_json::to_value(schema_for!(BudgetReservationV1)).unwrap();
        let mut changed = current.clone();
        changed
            .get_mut("required")
            .and_then(Value::as_array_mut)
            .unwrap()
            .retain(|field| field != "organization_id");
        assert_eq!(
            classify_schema_change(&current, &changed),
            SchemaChange::SecurityCriticalBreaking
        );
    }

    #[test]
    fn unknown_security_critical_fields_and_variants_are_rejected() {
        let input = json!({
            "organization_id":"org_00000000",
            "reservation_id":"reservation_00000000",
            "reserved":[{"dimension":"solver_tokens","amount":10}],
            "expires_at":"2026-07-23T01:00:00Z",
            "outcome":"reserved",
            "reason":"granted",
            "weaken_verification":true
        });
        assert!(serde_json::from_value::<BudgetReservationV1>(input).is_err());
        assert!(serde_json::from_str::<UsageDimensionV1>("\"verification_shortcut\"").is_err());
    }

    #[test]
    fn commercial_schema_cannot_express_verification_or_verdict_semantics() {
        let schemas = format!(
            "{}{}",
            serde_json::to_string(&schema_for!(CommercialEntitlementsEventV1)).unwrap(),
            serde_json::to_string(&schema_for!(BudgetReservationV1)).unwrap()
        )
        .to_ascii_lowercase();
        for forbidden in [
            "verdict",
            "verifiedforfixture",
            "verification_policy",
            "evidence_requirement",
            "weaken",
        ] {
            assert!(
                !schemas.contains(forbidden),
                "commercial schema leaked forbidden security vocabulary: {forbidden}"
            );
        }
    }

    #[test]
    fn denial_is_only_commercial_admission_and_never_a_verdict() {
        let denied = BudgetReservationV1 {
            organization_id: "org_00000000".parse().unwrap(),
            reservation_id: "reservation_00000000".parse().unwrap(),
            reserved: Vec::new(),
            expires_at: UtcInstant::parse("2026-07-23T01:00:00Z").unwrap(),
            outcome: AdmissionOutcomeV1::Denied,
            reason: CommercialReasonV1::HardLimitExceeded,
        };
        let wire = serde_json::to_value(denied).unwrap();
        assert_eq!(wire["outcome"], "denied");
        assert!(wire.get("verdict").is_none());
        assert!(wire.get("verification").is_none());
        assert!(
            !serde_json::from_value::<BudgetReservationV1>(wire)
                .unwrap()
                .is_positive_admission()
        );
    }

    #[test]
    fn only_positive_granted_reservations_authorize_cost_incurring_work() {
        let mut reservation = BudgetReservationV1 {
            organization_id: "org_00000000".parse().unwrap(),
            reservation_id: "reservation_00000000".parse().unwrap(),
            reserved: vec![ReservedUsageV1 {
                dimension: UsageDimensionV1::SolverTokens,
                amount: 10,
            }],
            expires_at: UtcInstant::parse("2026-07-23T01:00:00Z").unwrap(),
            outcome: AdmissionOutcomeV1::Reserved,
            reason: CommercialReasonV1::Granted,
        };
        assert!(reservation.is_positive_admission());
        reservation.reserved[0].amount = 0;
        assert!(!reservation.is_positive_admission());
    }
}
