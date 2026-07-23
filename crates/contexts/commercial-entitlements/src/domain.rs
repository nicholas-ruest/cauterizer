//! Private aggregate model for commercial admission and immutable usage.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
use serde::{Deserialize, Serialize};

/// Metered resource category. It deliberately contains no verification semantics.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct UsageDimension(String);

impl UsageDimension {
    /// Creates a bounded canonical usage dimension.
    ///
    /// # Errors
    /// Returns [`EntitlementError::InvalidValue`] for invalid syntax.
    pub fn new(value: impl Into<String>) -> Result<Self, EntitlementError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 64
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'-' | b'_')
            })
        {
            return Err(EntitlementError::InvalidValue);
        }
        Ok(Self(value))
    }

    /// Returns the canonical dimension.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

macro_rules! owned_id {
    ($name:ident, $prefix:literal) => {
        #[doc = concat!("Commercial context identifier with `", $prefix, "` prefix.")]
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        pub struct $name(ContextQualifiedId);
        impl $name {
            /// Creates an ID from a canonical opaque component.
            ///
            /// # Errors
            /// Returns [`EntitlementError::InvalidValue`] for invalid shared ID syntax.
            pub fn new(opaque: &str) -> Result<Self, EntitlementError> {
                ContextQualifiedId::new($prefix, opaque)
                    .map(Self)
                    .map_err(|_| EntitlementError::InvalidValue)
            }
            /// Returns the context-qualified spelling.
            #[must_use]
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }
    };
}

owned_id!(PlanId, "plan");
owned_id!(ReservationId, "reservation");
owned_id!(UsageRecordId, "usage");
owned_id!(CreditAdjustmentId, "credit");

/// Explicit runtime profile needed to enable an unlimited development plan.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DeploymentProfile {
    /// Production-like enforcement; unlimited plans are forbidden.
    Production,
    /// Explicit local-only development runtime.
    LocalDevelopment,
}

/// One immutable plan revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Plan {
    id: PlanId,
    revision: u64,
    hard_limits: BTreeMap<UsageDimension, u64>,
    features: BTreeSet<String>,
    unlimited_local_development: bool,
}

impl Plan {
    /// Creates a production-enforced plan revision.
    ///
    /// # Errors
    /// Returns an error for revision zero, empty quotas, zero limits, or bad feature names.
    pub fn metered(
        id: PlanId,
        revision: u64,
        hard_limits: BTreeMap<UsageDimension, u64>,
        features: BTreeSet<String>,
    ) -> Result<Self, EntitlementError> {
        if revision == 0
            || hard_limits.is_empty()
            || hard_limits.values().any(|limit| *limit == 0)
            || !valid_features(&features)
        {
            return Err(EntitlementError::InvalidValue);
        }
        Ok(Self {
            id,
            revision,
            hard_limits,
            features,
            unlimited_local_development: false,
        })
    }

    /// Creates the explicit unlimited local-development plan.
    #[must_use]
    pub fn unlimited_local_development(id: PlanId, revision: u64) -> Self {
        Self {
            id,
            revision,
            hard_limits: BTreeMap::new(),
            features: BTreeSet::new(),
            unlimited_local_development: true,
        }
    }

    /// Stable plan ID.
    #[must_use]
    pub const fn id(&self) -> &PlanId {
        &self.id
    }
    /// Immutable plan revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

/// Explicit quota interval supplied by the application clock/calendar policy.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct QuotaWindow {
    /// Inclusive canonical window start epoch milliseconds.
    pub starts_at_ms: u64,
    /// Exclusive canonical window end epoch milliseconds.
    pub ends_at_ms: u64,
}

impl QuotaWindow {
    /// Creates a non-empty interval.
    ///
    /// # Errors
    /// Returns an error unless end is strictly after start.
    pub fn new(starts_at_ms: u64, ends_at_ms: u64) -> Result<Self, EntitlementError> {
        if ends_at_ms <= starts_at_ms {
            return Err(EntitlementError::InvalidValue);
        }
        Ok(Self {
            starts_at_ms,
            ends_at_ms,
        })
    }
}

/// Worst-case resource request required before expensive work.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReservationRequest {
    /// Stable retry identity.
    pub id: ReservationId,
    /// Canonical digest of the complete admission request.
    pub request_digest: Sha256Digest,
    /// Quota interval charged by this work.
    pub window: QuotaWindow,
    /// Non-zero worst-case units per dimension.
    pub worst_case: BTreeMap<UsageDimension, u64>,
}

/// Immutable reservation lifecycle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ReservationStatus {
    /// Budget remains held for work or later settlement.
    Active,
    /// Unused held capacity was returned without usage.
    Released,
    /// Actual usage was recorded and unused capacity returned.
    Settled {
        /// Immutable usage record produced by settlement.
        usage_record_id: UsageRecordId,
    },
}

/// Durable contract proving cost admission for exact worst-case work.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BudgetReservation {
    request: ReservationRequest,
    status: ReservationStatus,
}

impl BudgetReservation {
    /// Reservation ID.
    #[must_use]
    pub const fn id(&self) -> &ReservationId {
        &self.request.id
    }
    /// Current immutable lifecycle result.
    #[must_use]
    pub const fn status(&self) -> &ReservationStatus {
        &self.status
    }
    /// Reserved worst-case units.
    #[must_use]
    pub const fn worst_case(&self) -> &BTreeMap<UsageDimension, u64> {
        &self.request.worst_case
    }
}

/// Immutable rated usage fact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UsageRecord {
    /// Stable record identity.
    pub id: UsageRecordId,
    /// Reservation this record settles.
    pub reservation_id: ReservationId,
    /// Canonical settlement input digest for replay conflict detection.
    pub settlement_digest: Sha256Digest,
    /// Actual non-negative units by dimension.
    pub actual: BTreeMap<UsageDimension, u64>,
    /// Application-supplied observation time.
    pub recorded_at_ms: u64,
}

/// Immutable quota credit adjustment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CreditAdjustment {
    /// Stable replay identity.
    pub id: CreditAdjustmentId,
    /// Quota interval receiving capacity.
    pub window: QuotaWindow,
    /// Positive additional units.
    pub units: BTreeMap<UsageDimension, u64>,
    /// Bounded auditable reason, never payment data.
    pub reason: String,
}

/// Aggregate facts persisted atomically with account state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum EntitlementEvent {
    /// Plan revision became active.
    PlanAssigned {
        /// Assigned plan.
        plan_id: PlanId,
        /// Assigned immutable revision.
        revision: u64,
    },
    /// Feature was explicitly granted in addition to plan features.
    EntitlementGranted {
        /// Granted feature name.
        feature: String,
    },
    /// Worst-case capacity was held.
    BudgetReserved {
        /// Admitted reservation.
        reservation_id: ReservationId,
    },
    /// Held capacity was returned.
    ReservationReleased {
        /// Released reservation.
        reservation_id: ReservationId,
    },
    /// Immutable actual usage was recorded.
    UsageSettled {
        /// Settled reservation.
        reservation_id: ReservationId,
        /// Immutable resulting usage fact.
        usage_record_id: UsageRecordId,
    },
    /// Quota credit was applied.
    CreditApplied {
        /// Applied immutable credit adjustment.
        credit_id: CreditAdjustmentId,
    },
    /// New commercial admissions were suspended.
    CommercialAccessSuspended,
}

/// Sole commercial aggregate root.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EntitlementAccount {
    organization_id: OrganizationId,
    profile: DeploymentProfile,
    plan: Plan,
    granted_features: BTreeSet<String>,
    suspended: bool,
    reservations: BTreeMap<ReservationId, BudgetReservation>,
    usage: BTreeMap<UsageRecordId, UsageRecord>,
    credits: BTreeMap<CreditAdjustmentId, CreditAdjustment>,
    #[serde(skip)]
    pending_events: Vec<EntitlementEvent>,
}

impl EntitlementAccount {
    /// Opens an account with one explicit plan.
    ///
    /// # Errors
    /// Rejects an unlimited plan outside local development or a zero plan revision.
    pub fn open(
        organization_id: OrganizationId,
        profile: DeploymentProfile,
        plan: Plan,
    ) -> Result<Self, EntitlementError> {
        validate_plan_profile(profile, &plan)?;
        let event = EntitlementEvent::PlanAssigned {
            plan_id: plan.id.clone(),
            revision: plan.revision,
        };
        Ok(Self {
            organization_id,
            profile,
            plan,
            granted_features: BTreeSet::new(),
            suspended: false,
            reservations: BTreeMap::new(),
            usage: BTreeMap::new(),
            credits: BTreeMap::new(),
            pending_events: vec![event],
        })
    }

    /// Owning tenant.
    #[must_use]
    pub const fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// Serializes durable private state for a same-context repository adapter.
    ///
    /// Pending events are deliberately excluded and must be committed separately.
    ///
    /// # Errors
    /// Returns an error if serialization unexpectedly fails.
    pub fn durable_snapshot(&self) -> Result<serde_json::Value, EntitlementError> {
        serde_json::to_value(self).map_err(|_| EntitlementError::InvariantViolation)
    }

    /// Rehydrates durable state and revalidates tenant/profile/plan invariants.
    ///
    /// # Errors
    /// Rejects malformed state, tenant substitution, invalid plan/profile, or pending events.
    pub fn rehydrate(
        organization_id: &OrganizationId,
        value: serde_json::Value,
    ) -> Result<Self, EntitlementError> {
        let account: Self =
            serde_json::from_value(value).map_err(|_| EntitlementError::InvariantViolation)?;
        if &account.organization_id != organization_id || !account.pending_events.is_empty() {
            return Err(EntitlementError::InvariantViolation);
        }
        validate_plan_profile(account.profile, &account.plan)?;
        Ok(account)
    }

    /// Assigns a new immutable plan revision. Existing reservations remain honored.
    ///
    /// # Errors
    /// Rejects stale revisions and unlimited plans outside local development.
    pub fn assign_plan(&mut self, plan: Plan) -> Result<(), EntitlementError> {
        validate_plan_profile(self.profile, &plan)?;
        if plan.revision <= self.plan.revision {
            return Err(EntitlementError::StalePlanRevision);
        }
        self.pending_events.push(EntitlementEvent::PlanAssigned {
            plan_id: plan.id.clone(),
            revision: plan.revision,
        });
        self.plan = plan;
        Ok(())
    }

    /// Grants one bounded feature without changing security semantics.
    ///
    /// # Errors
    /// Rejects malformed feature names.
    pub fn grant_entitlement(&mut self, feature: String) -> Result<(), EntitlementError> {
        if !valid_feature(&feature) {
            return Err(EntitlementError::InvalidValue);
        }
        if self.granted_features.insert(feature.clone()) {
            self.pending_events
                .push(EntitlementEvent::EntitlementGranted { feature });
        }
        Ok(())
    }

    /// Reports whether the active plan or an explicit grant supplies a feature.
    #[must_use]
    pub fn has_entitlement(&self, feature: &str) -> bool {
        self.plan.features.contains(feature) || self.granted_features.contains(feature)
    }

    /// Strongly admits worst-case work against this aggregate snapshot.
    ///
    /// # Errors
    /// Denies suspension, malformed requests, conflicting retries, unknown quota
    /// dimensions, arithmetic overflow, or any hard-limit exceedance.
    pub fn reserve(
        &mut self,
        request: ReservationRequest,
    ) -> Result<BudgetReservation, EntitlementError> {
        validate_reservation(&request)?;
        if let Some(existing) = self.reservations.get(&request.id) {
            return if existing.request == request {
                Ok(existing.clone())
            } else {
                Err(EntitlementError::IdempotencyConflict)
            };
        }
        if self.suspended {
            return Err(EntitlementError::Suspended);
        }
        if !self.plan.unlimited_local_development {
            for (dimension, requested) in &request.worst_case {
                let limit = self
                    .plan
                    .hard_limits
                    .get(dimension)
                    .ok_or(EntitlementError::NotEntitled)?;
                let consumed = self.consumed(&request.window, dimension)?;
                let credited = self.credited(&request.window, dimension)?;
                if consumed
                    .checked_add(*requested)
                    .ok_or(EntitlementError::ArithmeticOverflow)?
                    > limit
                        .checked_add(credited)
                        .ok_or(EntitlementError::ArithmeticOverflow)?
                {
                    return Err(EntitlementError::QuotaExceeded);
                }
            }
        }
        let reservation = BudgetReservation {
            request: request.clone(),
            status: ReservationStatus::Active,
        };
        self.reservations
            .insert(request.id.clone(), reservation.clone());
        self.pending_events.push(EntitlementEvent::BudgetReserved {
            reservation_id: request.id,
        });
        Ok(reservation)
    }

    /// Idempotently returns an active reservation without recording usage.
    ///
    /// # Errors
    /// Returns an error for an absent or already-settled reservation.
    pub fn release(&mut self, id: &ReservationId) -> Result<BudgetReservation, EntitlementError> {
        let reservation = self
            .reservations
            .get_mut(id)
            .ok_or(EntitlementError::ReservationNotFound)?;
        match reservation.status {
            ReservationStatus::Active => {
                reservation.status = ReservationStatus::Released;
                self.pending_events
                    .push(EntitlementEvent::ReservationReleased {
                        reservation_id: id.clone(),
                    });
            }
            ReservationStatus::Released => {}
            ReservationStatus::Settled { .. } => return Err(EntitlementError::AlreadySettled),
        }
        Ok(reservation.clone())
    }

    /// Idempotently settles immutable actual usage and releases unused capacity.
    ///
    /// # Errors
    /// Rejects absent/released reservations, conflicting retries, duplicate usage
    /// IDs, or actual usage beyond the admitted worst case.
    pub fn settle(&mut self, record: UsageRecord) -> Result<UsageRecord, EntitlementError> {
        if let Some(existing) = self.usage.get(&record.id) {
            return if existing == &record {
                Ok(existing.clone())
            } else {
                Err(EntitlementError::IdempotencyConflict)
            };
        }
        let reservation = self
            .reservations
            .get_mut(&record.reservation_id)
            .ok_or(EntitlementError::ReservationNotFound)?;
        match &reservation.status {
            ReservationStatus::Released => return Err(EntitlementError::AlreadyReleased),
            ReservationStatus::Settled { usage_record_id } => {
                let existing = self
                    .usage
                    .get(usage_record_id)
                    .ok_or(EntitlementError::InvariantViolation)?;
                return if existing == &record {
                    Ok(existing.clone())
                } else {
                    Err(EntitlementError::IdempotencyConflict)
                };
            }
            ReservationStatus::Active => {}
        }
        for (dimension, actual) in &record.actual {
            if *actual
                > reservation
                    .request
                    .worst_case
                    .get(dimension)
                    .copied()
                    .unwrap_or(0)
            {
                return Err(EntitlementError::SettlementExceedsReservation);
            }
        }
        let usage_id = record.id.clone();
        reservation.status = ReservationStatus::Settled {
            usage_record_id: usage_id.clone(),
        };
        self.usage.insert(usage_id.clone(), record.clone());
        self.pending_events.push(EntitlementEvent::UsageSettled {
            reservation_id: record.reservation_id.clone(),
            usage_record_id: usage_id,
        });
        Ok(record)
    }

    /// Applies one immutable positive credit adjustment idempotently.
    ///
    /// # Errors
    /// Rejects empty adjustments, malformed reasons, or conflicting ID reuse.
    pub fn apply_credit(&mut self, credit: CreditAdjustment) -> Result<(), EntitlementError> {
        if credit.units.is_empty()
            || credit.units.values().any(|units| *units == 0)
            || credit.reason.trim().is_empty()
            || credit.reason.len() > 256
        {
            return Err(EntitlementError::InvalidValue);
        }
        if let Some(existing) = self.credits.get(&credit.id) {
            return if existing == &credit {
                Ok(())
            } else {
                Err(EntitlementError::IdempotencyConflict)
            };
        }
        self.credits.insert(credit.id.clone(), credit.clone());
        self.pending_events.push(EntitlementEvent::CreditApplied {
            credit_id: credit.id,
        });
        Ok(())
    }

    /// Suspends all new admissions; settlement and release remain available.
    pub fn suspend(&mut self) {
        if !self.suspended {
            self.suspended = true;
            self.pending_events
                .push(EntitlementEvent::CommercialAccessSuspended);
        }
    }

    /// Returns immutable usage facts for reconciliation.
    pub fn usage_records(&self) -> impl Iterator<Item = &UsageRecord> {
        self.usage.values()
    }

    /// Drains new facts for atomic state/outbox persistence.
    pub fn take_pending_events(&mut self) -> Vec<EntitlementEvent> {
        std::mem::take(&mut self.pending_events)
    }

    fn consumed(
        &self,
        window: &QuotaWindow,
        dimension: &UsageDimension,
    ) -> Result<u64, EntitlementError> {
        self.reservations
            .values()
            .filter(|reservation| &reservation.request.window == window)
            .filter_map(|reservation| match &reservation.status {
                ReservationStatus::Active => Some(
                    reservation
                        .request
                        .worst_case
                        .get(dimension)
                        .copied()
                        .unwrap_or(0),
                ),
                ReservationStatus::Settled { usage_record_id } => self
                    .usage
                    .get(usage_record_id)
                    .map(|record| record.actual.get(dimension).copied().unwrap_or(0)),
                ReservationStatus::Released => None,
            })
            .try_fold(0_u64, |sum, value| {
                sum.checked_add(value)
                    .ok_or(EntitlementError::ArithmeticOverflow)
            })
    }

    fn credited(
        &self,
        window: &QuotaWindow,
        dimension: &UsageDimension,
    ) -> Result<u64, EntitlementError> {
        self.credits
            .values()
            .filter(|credit| &credit.window == window)
            .map(|credit| credit.units.get(dimension).copied().unwrap_or(0))
            .try_fold(0_u64, |sum, value| {
                sum.checked_add(value)
                    .ok_or(EntitlementError::ArithmeticOverflow)
            })
    }
}

/// Stable invariant and admission failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntitlementError {
    /// A bounded value or required collection was invalid.
    InvalidValue,
    /// Plan revision did not advance monotonically.
    StalePlanRevision,
    /// New commercial admissions are suspended.
    Suspended,
    /// Active plan lacks the requested quota dimension or feature.
    NotEntitled,
    /// Admission would exceed the hard tenant limit.
    QuotaExceeded,
    /// Safe quota arithmetic exceeded its numeric range.
    ArithmeticOverflow,
    /// A replay identity was reused for different canonical input.
    IdempotencyConflict,
    /// Reservation identity was not found.
    ReservationNotFound,
    /// Released capacity cannot later be settled.
    AlreadyReleased,
    /// Settled capacity cannot later be released.
    AlreadySettled,
    /// Actual usage exceeded the admitted worst case.
    SettlementExceedsReservation,
    /// Persisted aggregate state violated an internal lifecycle invariant.
    InvariantViolation,
}

impl fmt::Display for EntitlementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for EntitlementError {}

fn validate_plan_profile(profile: DeploymentProfile, plan: &Plan) -> Result<(), EntitlementError> {
    if plan.revision == 0
        || (plan.unlimited_local_development && profile != DeploymentProfile::LocalDevelopment)
    {
        return Err(EntitlementError::InvalidValue);
    }
    Ok(())
}
fn valid_feature(feature: &str) -> bool {
    !feature.is_empty()
        && feature.len() <= 64
        && feature.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
        })
}
fn valid_features(features: &BTreeSet<String>) -> bool {
    features.iter().all(|feature| valid_feature(feature))
}
fn validate_reservation(request: &ReservationRequest) -> Result<(), EntitlementError> {
    if request.worst_case.is_empty() || request.worst_case.values().any(|value| *value == 0) {
        return Err(EntitlementError::InvalidValue);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn dimension() -> UsageDimension {
        UsageDimension::new("solver.tokens").unwrap()
    }
    fn window() -> QuotaWindow {
        QuotaWindow::new(0, 100).unwrap()
    }
    fn plan(revision: u64, limit: u64) -> Plan {
        Plan::metered(
            PlanId::new("00000000").unwrap(),
            revision,
            BTreeMap::from([(dimension(), limit)]),
            BTreeSet::new(),
        )
        .unwrap()
    }
    fn account(limit: u64) -> EntitlementAccount {
        EntitlementAccount::open(
            OrganizationId::new("00000000").unwrap(),
            DeploymentProfile::Production,
            plan(1, limit),
        )
        .unwrap()
    }
    fn request(number: u64, units: u64) -> ReservationRequest {
        ReservationRequest {
            id: ReservationId::new(&format!("{number:08}")).unwrap(),
            request_digest: Sha256Digest::of_bytes(format!("digest-{number}")),
            window: window(),
            worst_case: BTreeMap::from([(dimension(), units)]),
        }
    }

    #[test]
    fn unlimited_plan_is_explicitly_local_only() {
        let unlimited = Plan::unlimited_local_development(PlanId::new("00000000").unwrap(), 1);
        assert_eq!(
            EntitlementAccount::open(
                OrganizationId::new("00000000").unwrap(),
                DeploymentProfile::Production,
                unlimited.clone()
            )
            .unwrap_err(),
            EntitlementError::InvalidValue
        );
        assert!(
            EntitlementAccount::open(
                OrganizationId::new("00000000").unwrap(),
                DeploymentProfile::LocalDevelopment,
                unlimited
            )
            .is_ok()
        );
    }
    #[test]
    fn reservation_retries_are_identical_and_conflicts_fail() {
        let mut account = account(10);
        let first = request(1, 6);
        assert_eq!(
            account.reserve(first.clone()).unwrap(),
            account.reserve(first.clone()).unwrap()
        );
        let mut conflict = first;
        conflict.worst_case.insert(dimension(), 7);
        assert_eq!(
            account.reserve(conflict),
            Err(EntitlementError::IdempotencyConflict)
        );
    }
    #[test]
    fn sequential_race_model_never_exceeds_hard_limit_in_any_order() {
        for first in 1..10 {
            let second = 10 - first + 1;
            for reverse in [false, true] {
                let mut account = account(10);
                let requests = if reverse {
                    [request(2, second), request(1, first)]
                } else {
                    [request(1, first), request(2, second)]
                };
                let outcomes = requests.map(|request| account.reserve(request).is_ok());
                assert_eq!(outcomes.iter().filter(|ok| **ok).count(), 1);
            }
        }
    }
    #[test]
    fn release_and_settlement_are_idempotent_and_usage_immutable() {
        let mut account = account(10);
        account.reserve(request(1, 10)).unwrap();
        let record = UsageRecord {
            id: UsageRecordId::new("00000001").unwrap(),
            reservation_id: ReservationId::new("00000001").unwrap(),
            settlement_digest: Sha256Digest::of_bytes("settle-1"),
            actual: BTreeMap::from([(dimension(), 4)]),
            recorded_at_ms: 1,
        };
        assert_eq!(
            account.settle(record.clone()).unwrap(),
            account.settle(record.clone()).unwrap()
        );
        let mut changed = record;
        changed.actual.insert(dimension(), 5);
        assert_eq!(
            account.settle(changed),
            Err(EntitlementError::IdempotencyConflict)
        );
    }
    #[test]
    fn settlement_cannot_exceed_admitted_worst_case() {
        let mut account = account(10);
        account.reserve(request(1, 5)).unwrap();
        let record = UsageRecord {
            id: UsageRecordId::new("00000001").unwrap(),
            reservation_id: ReservationId::new("00000001").unwrap(),
            settlement_digest: Sha256Digest::of_bytes("settle"),
            actual: BTreeMap::from([(dimension(), 6)]),
            recorded_at_ms: 1,
        };
        assert_eq!(
            account.settle(record),
            Err(EntitlementError::SettlementExceedsReservation)
        );
    }
    #[test]
    fn downgrade_and_suspension_preserve_existing_settlement_but_deny_new_work() {
        let mut account = account(10);
        account.reserve(request(1, 8)).unwrap();
        account.assign_plan(plan(2, 5)).unwrap();
        assert_eq!(
            account.reserve(request(2, 1)),
            Err(EntitlementError::QuotaExceeded)
        );
        account.suspend();
        let record = UsageRecord {
            id: UsageRecordId::new("00000001").unwrap(),
            reservation_id: ReservationId::new("00000001").unwrap(),
            settlement_digest: Sha256Digest::of_bytes("settle"),
            actual: BTreeMap::from([(dimension(), 3)]),
            recorded_at_ms: 1,
        };
        assert!(account.settle(record).is_ok());
        assert_eq!(
            account.reserve(request(3, 1)),
            Err(EntitlementError::Suspended)
        );
    }
    #[test]
    fn credit_and_release_reconcile_reserved_capacity() {
        let mut account = account(10);
        account.reserve(request(1, 10)).unwrap();
        assert_eq!(
            account.reserve(request(2, 1)),
            Err(EntitlementError::QuotaExceeded)
        );
        account
            .release(&ReservationId::new("00000001").unwrap())
            .unwrap();
        account.reserve(request(2, 10)).unwrap();
        account
            .apply_credit(CreditAdjustment {
                id: CreditAdjustmentId::new("00000001").unwrap(),
                window: window(),
                units: BTreeMap::from([(dimension(), 2)]),
                reason: "service adjustment".into(),
            })
            .unwrap();
        account.reserve(request(3, 2)).unwrap();
    }
    #[test]
    fn quota_property_holds_across_many_reservation_release_sequences() {
        for limit in 1..32 {
            let mut account = account(limit);
            for index in 1..=limit {
                assert!(account.reserve(request(index, 1)).is_ok());
            }
            assert_eq!(
                account.reserve(request(99, 1)),
                Err(EntitlementError::QuotaExceeded)
            );
            for index in 1..=limit {
                account
                    .release(&ReservationId::new(&format!("{index:08}")).unwrap())
                    .unwrap();
            }
            assert!(account.reserve(request(100, limit)).is_ok());
        }
    }
}
