//! Generic transactional-outbox dispatch loop: claim, invoke a handler, then
//! acknowledge, retry, or dead-letter.
//!
//! P04 built the durable claim/ack/retry/dead-letter primitives
//! ([`crate::postgres::PostgresMetadataStore::claim_outbox`] and friends) and
//! the in-memory consumer-ordering reference model
//! ([`crate::delivery::ReliableInbox`]). Nothing tied the two together into an
//! actual dispatch loop that a worker process runs. This module is that loop,
//! written against a small port trait so it is unit-testable without a real
//! `PostgreSQL` connection: [`PostgresDispatchPort`] is the real adapter and
//! tests use an in-memory fake.
//!
//! ## Consumer handler guidance
//!
//! A handler's job is only to get one event durably into the consumer's own
//! atomic effect boundary (for example
//! [`crate::postgres::PostgresMetadataStore::consume_inbox_atomic`]), not to
//! enforce delivery ordering itself. When that boundary reports
//! `HeldForGap` (a predecessor has not committed yet), the handler must
//! return [`crate::delivery::HandlerFailure::Retryable`], not `Ok(())`: the
//! outbox row has to remain claimable so a later dispatch pass retries it
//! after the predecessor lands. Treating `HeldForGap` as success would
//! acknowledge the outbox row away with no other mechanism left to ever
//! replay the held event.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Mutex;

use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
use serde_json::Value;

use crate::delivery::HandlerFailure;
use crate::postgres::{PostgresError, PostgresMetadataStore};

/// A boxed future borrowing from the call that produced it.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A boxed, non-borrowing handler outcome future.
pub type HandlerFuture = Pin<Box<dyn Future<Output = Result<(), HandlerFailure>> + Send>>;

/// One outbox row leased for exactly this dispatch attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchClaim {
    /// Tenant owning the event.
    pub organization_id: OrganizationId,
    /// Stable outbox row identity.
    pub outbox_id: String,
    /// Published event identity.
    pub event_id: String,
    /// Complete versioned event envelope, opaque to the dispatch loop.
    pub event: Value,
    /// Attempt count before this lease.
    pub attempts: u32,
    /// Exact lease token this claim must present to every terminal/retry call.
    pub claim_token: String,
}

/// Stable, payload-safe dispatch port failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchPortError {
    /// The lease token no longer owns the outbox row.
    ClaimLost,
    /// A claim/retry/dead-letter bound (batch size, lease, delay, reason code)
    /// was rejected before any row was touched.
    InvalidBound,
    /// A stable adapter-reported failure that is not one of the above.
    Adapter(String),
}

impl std::fmt::Display for DispatchPortError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClaimLost => formatter.write_str("dispatch_claim_lost"),
            Self::InvalidBound => formatter.write_str("dispatch_invalid_bound"),
            Self::Adapter(reason) => formatter.write_str(reason),
        }
    }
}
impl std::error::Error for DispatchPortError {}

impl From<PostgresError> for DispatchPortError {
    fn from(value: PostgresError) -> Self {
        match value {
            PostgresError::OutboxClaimLost => Self::ClaimLost,
            PostgresError::InvalidDeliveryBound => Self::InvalidBound,
            other => Self::Adapter(other.to_string()),
        }
    }
}

/// The claim/ack/retry/dead-letter boundary the dispatch loop drives.
///
/// A production adapter wraps [`PostgresMetadataStore`]
/// ([`PostgresDispatchPort`]); tests use an in-memory fake so crash/retry
/// sequences can be simulated deterministically without a database.
pub trait DispatchPort: Send + Sync {
    /// Claims a bounded, immediately-visible batch.
    fn claim<'a>(
        &'a self,
        organization_id: &'a OrganizationId,
        claim_token: &'a str,
        limit: u16,
        lease_seconds: u32,
    ) -> BoxFuture<'a, Result<Vec<DispatchClaim>, DispatchPortError>>;

    /// Marks one exactly leased row delivered.
    fn acknowledge<'a>(
        &'a self,
        organization_id: &'a OrganizationId,
        outbox_id: &'a str,
        claim_token: &'a str,
    ) -> BoxFuture<'a, Result<(), DispatchPortError>>;

    /// Releases one exact lease for bounded delayed retry.
    fn retry<'a>(
        &'a self,
        organization_id: &'a OrganizationId,
        outbox_id: &'a str,
        claim_token: &'a str,
        delay_seconds: u32,
        reason_code: &'a str,
    ) -> BoxFuture<'a, Result<(), DispatchPortError>>;

    /// Moves one exactly leased row to terminal relay failure.
    fn dead_letter<'a>(
        &'a self,
        organization_id: &'a OrganizationId,
        outbox_id: &'a str,
        claim_token: &'a str,
        reason_code: &'a str,
    ) -> BoxFuture<'a, Result<(), DispatchPortError>>;
}

/// Wraps [`PostgresMetadataStore`] as a [`DispatchPort`].
#[derive(Clone)]
pub struct PostgresDispatchPort {
    store: PostgresMetadataStore,
}

impl PostgresDispatchPort {
    /// Creates the real adapter from an already-migrated metadata store.
    #[must_use]
    pub const fn new(store: PostgresMetadataStore) -> Self {
        Self { store }
    }
}

impl DispatchPort for PostgresDispatchPort {
    fn claim<'a>(
        &'a self,
        organization_id: &'a OrganizationId,
        claim_token: &'a str,
        limit: u16,
        lease_seconds: u32,
    ) -> BoxFuture<'a, Result<Vec<DispatchClaim>, DispatchPortError>> {
        Box::pin(async move {
            let token = parse_id(claim_token)?;
            let claims = self
                .store
                .claim_outbox(organization_id, &token, limit, lease_seconds)
                .await?;
            Ok(claims
                .into_iter()
                .map(|claim| DispatchClaim {
                    organization_id: claim.organization_id,
                    outbox_id: claim.outbox_id,
                    event_id: claim.event_id,
                    event: claim.event,
                    attempts: u32::try_from(claim.attempts).unwrap_or(u32::MAX),
                    claim_token: claim.claim_token,
                })
                .collect())
        })
    }

    fn acknowledge<'a>(
        &'a self,
        organization_id: &'a OrganizationId,
        outbox_id: &'a str,
        claim_token: &'a str,
    ) -> BoxFuture<'a, Result<(), DispatchPortError>> {
        Box::pin(async move {
            let outbox_id = parse_id(outbox_id)?;
            let token = parse_id(claim_token)?;
            self.store
                .acknowledge_outbox(organization_id, &outbox_id, &token)
                .await?;
            Ok(())
        })
    }

    fn retry<'a>(
        &'a self,
        organization_id: &'a OrganizationId,
        outbox_id: &'a str,
        claim_token: &'a str,
        delay_seconds: u32,
        reason_code: &'a str,
    ) -> BoxFuture<'a, Result<(), DispatchPortError>> {
        Box::pin(async move {
            let outbox_id = parse_id(outbox_id)?;
            let token = parse_id(claim_token)?;
            self.store
                .retry_outbox(organization_id, &outbox_id, &token, delay_seconds, reason_code)
                .await?;
            Ok(())
        })
    }

    fn dead_letter<'a>(
        &'a self,
        organization_id: &'a OrganizationId,
        outbox_id: &'a str,
        claim_token: &'a str,
        reason_code: &'a str,
    ) -> BoxFuture<'a, Result<(), DispatchPortError>> {
        Box::pin(async move {
            let outbox_id = parse_id(outbox_id)?;
            let token = parse_id(claim_token)?;
            self.store
                .dead_letter_outbox(organization_id, &outbox_id, &token, reason_code)
                .await?;
            Ok(())
        })
    }
}

fn parse_id(value: &str) -> Result<ContextQualifiedId, DispatchPortError> {
    ContextQualifiedId::from_str(value).map_err(|_| DispatchPortError::InvalidBound)
}

/// Bounded batch size, lease, and retry policy for one dispatch pass.
///
/// Mirrors [`crate::delivery::DeliveryPolicy`]'s fail-closed-on-empty
/// construction and its `attempts < max_attempts` retry-vs-dead-letter
/// comparison exactly (see [`dispatch_batch`]). It is a distinct type rather
/// than a literal reuse of `DeliveryPolicy` because that type also carries a
/// consumer identity and producer/schema allowlists the generic outbox-level
/// dispatch loop does not have: it dispatches opaque envelopes to a handler
/// before any consumer-specific schema/producer decoding happens.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatchPolicy {
    batch_limit: u16,
    lease_seconds: u32,
    max_attempts: u16,
    retry_delay_seconds: u32,
}

impl DispatchPolicy {
    /// Creates a fail-closed dispatch policy.
    ///
    /// # Errors
    ///
    /// Every bound must be non-zero.
    pub fn new(
        batch_limit: u16,
        lease_seconds: u32,
        max_attempts: u16,
        retry_delay_seconds: u32,
    ) -> Result<Self, DispatchConfigurationError> {
        if batch_limit == 0 || lease_seconds == 0 || max_attempts == 0 || retry_delay_seconds == 0
        {
            return Err(DispatchConfigurationError::EmptyPolicy);
        }
        Ok(Self {
            batch_limit,
            lease_seconds,
            max_attempts,
            retry_delay_seconds,
        })
    }
}

/// Invalid static dispatch configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchConfigurationError {
    /// Every batch/lease/attempt/delay bound must be non-zero.
    EmptyPolicy,
}

impl std::fmt::Display for DispatchConfigurationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::EmptyPolicy => "dispatch policy bounds must be non-zero",
        })
    }
}
impl std::error::Error for DispatchConfigurationError {}

/// Outcome counts of one bounded dispatch pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DispatchReport {
    /// Rows the handler completed and this pass acknowledged.
    pub acknowledged: usize,
    /// Rows released for bounded delayed retry.
    pub retried: usize,
    /// Rows moved to terminal relay failure this pass.
    pub dead_lettered: usize,
}

impl DispatchReport {
    /// Total rows this pass reached a claim/handler decision for.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.acknowledged + self.retried + self.dead_lettered
    }
}

/// Claims one bounded batch and drives each claimed row through `handler`.
///
/// On `Ok(())` the row is acknowledged. On
/// [`HandlerFailure::Poison`](crate::delivery::HandlerFailure::Poison) the
/// row is dead-lettered immediately, matching
/// [`crate::delivery::ReliableInbox`]'s poison handling. On
/// [`HandlerFailure::Retryable`](crate::delivery::HandlerFailure::Retryable)
/// the row is retried while `attempts` (counted including this failure)
/// stays below `policy`'s `max_attempts`, and dead-lettered with the same
/// stable reason code once exhausted — the identical `attempts <
/// max_attempts` comparison [`crate::delivery::ReliableInbox::receive`] uses.
///
/// A crash at any point before this call returns loses no event: an
/// unclaimed row is untouched, a claimed-but-not-yet-decided row's lease
/// simply expires and becomes reclaimable again, and an acknowledged row is
/// never reconsidered. A crash can cause the same event to be claimed and
/// handled more than once (at-least-once delivery); handlers must apply
/// their effect idempotently, exactly as
/// [`crate::postgres::PostgresMetadataStore::consume_inbox_atomic`] already
/// does for its callers.
///
/// # Errors
///
/// Returns the port's error immediately if claiming the batch fails. A
/// failure while acknowledging/retrying/dead-lettering one row also returns
/// immediately without processing the remaining claimed rows; already
/// decided rows in this pass are not rolled back.
pub async fn dispatch_batch<P, H>(
    port: &P,
    organization_id: &OrganizationId,
    claim_token: &str,
    policy: DispatchPolicy,
    mut handler: H,
) -> Result<DispatchReport, DispatchPortError>
where
    P: DispatchPort + ?Sized,
    H: FnMut(DispatchClaim) -> HandlerFuture,
{
    let claims = port
        .claim(
            organization_id,
            claim_token,
            policy.batch_limit,
            policy.lease_seconds,
        )
        .await?;
    let mut report = DispatchReport::default();
    for claim in claims {
        let outbox_id = claim.outbox_id.clone();
        let token = claim.claim_token.clone();
        let attempts = claim.attempts;
        match handler(claim).await {
            Ok(()) => {
                port.acknowledge(organization_id, &outbox_id, &token).await?;
                report.acknowledged += 1;
            }
            Err(HandlerFailure::Poison(code)) => {
                port.dead_letter(organization_id, &outbox_id, &token, code.as_str())
                    .await?;
                report.dead_lettered += 1;
            }
            Err(HandlerFailure::Retryable(code)) => {
                let attempted = attempts.saturating_add(1);
                if attempted < u32::from(policy.max_attempts) {
                    port.retry(
                        organization_id,
                        &outbox_id,
                        &token,
                        policy.retry_delay_seconds,
                        code.as_str(),
                    )
                    .await?;
                    report.retried += 1;
                } else {
                    port.dead_letter(organization_id, &outbox_id, &token, code.as_str())
                        .await?;
                    report.dead_lettered += 1;
                }
            }
        }
    }
    Ok(report)
}

/// In-memory, deterministic [`DispatchPort`] for tests.
///
/// Models the same claim-token ownership rule the real adapter enforces in
/// `PostgreSQL`: acknowledge/retry/dead-letter only succeed against the
/// exact current lease. [`Self::expire_claim`] is a test-only escape hatch
/// simulating a crashed worker whose lease has timed out without it calling
/// back at all, freeing the row for reclaim exactly like the real adapter's
/// `claim_expires_at` bound.
#[derive(Default)]
pub struct FakeDispatchPort {
    rows: Mutex<HashMap<String, FakeRow>>,
}

struct FakeRow {
    event_id: String,
    event: Value,
    attempts: u32,
    claim_token: Option<String>,
    delivered: bool,
    dead_lettered: bool,
    last_reason: Option<String>,
}

/// Snapshot of one fake outbox row's terminal/attempt state for assertions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FakeRowState {
    /// Attempts recorded so far.
    pub attempts: u32,
    /// Whether the row was acknowledged.
    pub delivered: bool,
    /// Whether the row was dead-lettered.
    pub dead_lettered: bool,
    /// The most recent retry/dead-letter reason code, if any.
    pub last_reason: Option<String>,
}

impl FakeDispatchPort {
    /// Creates a fake outbox seeded with `(outbox_id, event_id, event)` rows.
    #[must_use]
    pub fn new(seed: impl IntoIterator<Item = (String, String, Value)>) -> Self {
        let rows = seed
            .into_iter()
            .map(|(outbox_id, event_id, event)| {
                (
                    outbox_id,
                    FakeRow {
                        event_id,
                        event,
                        attempts: 0,
                        claim_token: None,
                        delivered: false,
                        dead_lettered: false,
                        last_reason: None,
                    },
                )
            })
            .collect();
        Self {
            rows: Mutex::new(rows),
        }
    }

    /// Simulates a crashed worker: the lease disappears with no acknowledge,
    /// retry, or dead-letter call, exactly as if its `claim_expires_at` had
    /// elapsed.
    ///
    /// # Panics
    ///
    /// Panics only if the internal lock is poisoned by an earlier panic.
    pub fn expire_claim(&self, outbox_id: &str) {
        if let Some(row) = self.rows.lock().unwrap().get_mut(outbox_id) {
            row.claim_token = None;
        }
    }

    /// Returns a snapshot of one row's current terminal/attempt state.
    ///
    /// # Panics
    ///
    /// Panics only if the internal lock is poisoned by an earlier panic.
    #[must_use]
    pub fn state(&self, outbox_id: &str) -> Option<FakeRowState> {
        self.rows.lock().unwrap().get(outbox_id).map(|row| FakeRowState {
            attempts: row.attempts,
            delivered: row.delivered,
            dead_lettered: row.dead_lettered,
            last_reason: row.last_reason.clone(),
        })
    }
}

impl DispatchPort for FakeDispatchPort {
    fn claim<'a>(
        &'a self,
        organization_id: &'a OrganizationId,
        claim_token: &'a str,
        limit: u16,
        _lease_seconds: u32,
    ) -> BoxFuture<'a, Result<Vec<DispatchClaim>, DispatchPortError>> {
        Box::pin(async move {
            if limit == 0 {
                return Err(DispatchPortError::InvalidBound);
            }
            let mut rows = self.rows.lock().unwrap();
            let mut claimed = Vec::new();
            let mut keys: Vec<_> = rows.keys().cloned().collect();
            keys.sort();
            for outbox_id in keys {
                if claimed.len() >= usize::from(limit) {
                    break;
                }
                let row = rows.get_mut(&outbox_id).expect("key from this map");
                if row.delivered || row.dead_lettered || row.claim_token.is_some() {
                    continue;
                }
                row.claim_token = Some(claim_token.to_owned());
                claimed.push(DispatchClaim {
                    organization_id: organization_id.clone(),
                    outbox_id,
                    event_id: row.event_id.clone(),
                    event: row.event.clone(),
                    attempts: row.attempts,
                    claim_token: claim_token.to_owned(),
                });
            }
            Ok(claimed)
        })
    }

    fn acknowledge<'a>(
        &'a self,
        _organization_id: &'a OrganizationId,
        outbox_id: &'a str,
        claim_token: &'a str,
    ) -> BoxFuture<'a, Result<(), DispatchPortError>> {
        Box::pin(async move {
            let mut rows = self.rows.lock().unwrap();
            let row = rows.get_mut(outbox_id).ok_or(DispatchPortError::ClaimLost)?;
            if row.claim_token.as_deref() != Some(claim_token) {
                return Err(DispatchPortError::ClaimLost);
            }
            row.delivered = true;
            row.claim_token = None;
            Ok(())
        })
    }

    fn retry<'a>(
        &'a self,
        _organization_id: &'a OrganizationId,
        outbox_id: &'a str,
        claim_token: &'a str,
        _delay_seconds: u32,
        reason_code: &'a str,
    ) -> BoxFuture<'a, Result<(), DispatchPortError>> {
        Box::pin(async move {
            let mut rows = self.rows.lock().unwrap();
            let row = rows.get_mut(outbox_id).ok_or(DispatchPortError::ClaimLost)?;
            if row.claim_token.as_deref() != Some(claim_token) {
                return Err(DispatchPortError::ClaimLost);
            }
            row.attempts = row.attempts.saturating_add(1);
            row.claim_token = None;
            row.last_reason = Some(reason_code.to_owned());
            Ok(())
        })
    }

    fn dead_letter<'a>(
        &'a self,
        _organization_id: &'a OrganizationId,
        outbox_id: &'a str,
        claim_token: &'a str,
        reason_code: &'a str,
    ) -> BoxFuture<'a, Result<(), DispatchPortError>> {
        Box::pin(async move {
            let mut rows = self.rows.lock().unwrap();
            let row = rows.get_mut(outbox_id).ok_or(DispatchPortError::ClaimLost)?;
            if row.claim_token.as_deref() != Some(claim_token) {
                return Err(DispatchPortError::ClaimLost);
            }
            row.dead_lettered = true;
            row.claim_token = None;
            row.last_reason = Some(reason_code.to_owned());
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::FailureCode;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn organization() -> OrganizationId {
        OrganizationId::new("00000000").unwrap()
    }

    fn policy(max_attempts: u16) -> DispatchPolicy {
        DispatchPolicy::new(10, 30, max_attempts, 1).unwrap()
    }

    fn seed_one() -> FakeDispatchPort {
        FakeDispatchPort::new([(
            "outbox_00000001".to_owned(),
            "event_00000001".to_owned(),
            serde_json::json!({"kind": "test"}),
        )])
    }

    #[test]
    fn empty_policy_bounds_are_rejected() {
        assert_eq!(
            DispatchPolicy::new(0, 30, 3, 1),
            Err(DispatchConfigurationError::EmptyPolicy)
        );
        assert_eq!(
            DispatchPolicy::new(10, 0, 3, 1),
            Err(DispatchConfigurationError::EmptyPolicy)
        );
        assert_eq!(
            DispatchPolicy::new(10, 30, 0, 1),
            Err(DispatchConfigurationError::EmptyPolicy)
        );
        assert_eq!(
            DispatchPolicy::new(10, 30, 3, 0),
            Err(DispatchConfigurationError::EmptyPolicy)
        );
    }

    #[tokio::test]
    async fn successful_handler_is_acknowledged_and_not_redelivered() {
        let port = seed_one();
        let organization = organization();
        let calls = Arc::new(AtomicUsize::new(0));
        let handled = Arc::clone(&calls);
        let report = dispatch_batch(&port, &organization, "claim_00000001", policy(3), move |_| {
            handled.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        })
        .await
        .unwrap();
        assert_eq!(report, DispatchReport {
            acknowledged: 1,
            retried: 0,
            dead_lettered: 0,
        });
        assert!(port.state("outbox_00000001").unwrap().delivered);

        // Crash-after-ack: nothing is left to claim, so the handler never runs again.
        let handled_again = Arc::clone(&calls);
        let report = dispatch_batch(&port, &organization, "claim_00000002", policy(3), move |_| {
            handled_again.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        })
        .await
        .unwrap();
        assert_eq!(report.total(), 0);
        assert_eq!(calls_after(&calls), 1);
    }

    fn calls_after(calls: &Arc<AtomicUsize>) -> usize {
        calls.load(Ordering::SeqCst)
    }

    #[tokio::test]
    async fn poison_failure_dead_letters_immediately() {
        let port = seed_one();
        let organization = organization();
        let code = FailureCode::parse("unsupported_required_semantics").unwrap();
        let report = dispatch_batch(&port, &organization, "claim_00000001", policy(5), move |_| {
            let code = code.clone();
            Box::pin(async move { Err(HandlerFailure::Poison(code)) })
        })
        .await
        .unwrap();
        assert_eq!(report, DispatchReport {
            acknowledged: 0,
            retried: 0,
            dead_lettered: 1,
        });
        let state = port.state("outbox_00000001").unwrap();
        assert!(state.dead_lettered);
        assert_eq!(state.attempts, 0);
        assert_eq!(
            state.last_reason.as_deref(),
            Some("unsupported_required_semantics")
        );
    }

    #[tokio::test]
    async fn retryable_failure_is_bounded_then_dead_lettered_with_a_stable_reason() {
        let port = seed_one();
        let organization = organization();
        let code = FailureCode::parse("dependency_unavailable").unwrap();
        let calls = Arc::new(AtomicUsize::new(0));

        for attempt in 0..2 {
            let calls = Arc::clone(&calls);
            let code = code.clone();
            let report = dispatch_batch(
                &port,
                &organization,
                &format!("claim_{attempt:08}"),
                policy(3),
                move |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    let code = code.clone();
                    Box::pin(async move { Err(HandlerFailure::Retryable(code)) })
                },
            )
            .await
            .unwrap();
            assert_eq!(report.retried, 1);
            assert!(!port.state("outbox_00000001").unwrap().dead_lettered);
        }

        // Third attempt exceeds max_attempts=3 and dead-letters with the same code.
        let calls_final = Arc::clone(&calls);
        let code = code.clone();
        let report = dispatch_batch(
            &port,
            &organization,
            "claim_final",
            policy(3),
            move |_| {
                calls_final.fetch_add(1, Ordering::SeqCst);
                let code = code.clone();
                Box::pin(async move { Err(HandlerFailure::Retryable(code)) })
            },
        )
        .await
        .unwrap();
        assert_eq!(report.dead_lettered, 1);
        let state = port.state("outbox_00000001").unwrap();
        assert!(state.dead_lettered);
        assert_eq!(state.last_reason.as_deref(), Some("dependency_unavailable"));
        assert_eq!(calls_after(&calls), 3);

        // No further claim is possible once dead-lettered.
        let empty = dispatch_batch(&port, &organization, "claim_after", policy(3), |_| {
            Box::pin(async { Ok(()) })
        })
        .await
        .unwrap();
        assert_eq!(empty.total(), 0);
    }

    #[tokio::test]
    async fn crash_after_claim_loses_no_event() {
        let port = seed_one();
        let organization = organization();

        // The worker claims the batch, then dies before invoking any handler.
        let claimed = port
            .claim(&organization, "claim_crashed", 10, 30)
            .await
            .unwrap();
        assert_eq!(claimed.len(), 1);
        port.expire_claim("outbox_00000001");

        // A fresh dispatch pass reclaims and successfully applies the event exactly once.
        let calls = Arc::new(AtomicUsize::new(0));
        let handled = Arc::clone(&calls);
        let report = dispatch_batch(&port, &organization, "claim_recovered", policy(3), move |_| {
            handled.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        })
        .await
        .unwrap();
        assert_eq!(report.acknowledged, 1);
        assert_eq!(calls_after(&calls), 1);
        assert!(port.state("outbox_00000001").unwrap().delivered);
    }

    #[tokio::test]
    async fn crash_after_handler_success_before_ack_is_at_least_once_not_lost_and_dedupes() {
        let port = seed_one();
        let organization = organization();
        // An idempotent side-effect sink, standing in for a real consumer's
        // own idempotent apply (e.g. `consume_inbox_atomic`).
        let applied = Arc::new(Mutex::new(std::collections::HashSet::<String>::new()));
        let invocations = Arc::new(AtomicUsize::new(0));

        // The handler runs and succeeds, but the process crashes before this
        // pass's internal acknowledge call ever reaches the port.
        let claimed = port
            .claim(&organization, "claim_first", 10, 30)
            .await
            .unwrap();
        let event_id = claimed[0].event_id.clone();
        invocations.fetch_add(1, Ordering::SeqCst);
        applied.lock().unwrap().insert(event_id.clone());
        port.expire_claim("outbox_00000001"); // crash: no acknowledge call happens

        // The event was never acknowledged, so at-least-once redelivery
        // claims and handles it again.
        let applied_second = Arc::clone(&applied);
        let invocations_second = Arc::clone(&invocations);
        let report = dispatch_batch(&port, &organization, "claim_second", policy(3), move |claim| {
            invocations_second.fetch_add(1, Ordering::SeqCst);
            let applied = Arc::clone(&applied_second);
            Box::pin(async move {
                applied.lock().unwrap().insert(claim.event_id.clone());
                Ok(())
            })
        })
        .await
        .unwrap();

        assert_eq!(report.acknowledged, 1);
        assert_eq!(invocations.load(Ordering::SeqCst), 2, "at least once");
        assert_eq!(
            applied.lock().unwrap().len(),
            1,
            "idempotent effect application means no duplicated side effect"
        );
        assert!(port.state("outbox_00000001").unwrap().delivered);
    }

    #[tokio::test]
    async fn batch_limit_bounds_one_pass() {
        let port = FakeDispatchPort::new([
            (
                "outbox_00000001".to_owned(),
                "event_00000001".to_owned(),
                serde_json::json!({}),
            ),
            (
                "outbox_00000002".to_owned(),
                "event_00000002".to_owned(),
                serde_json::json!({}),
            ),
        ]);
        let organization = organization();
        let report = dispatch_batch(
            &port,
            &organization,
            "claim_00000001",
            DispatchPolicy::new(1, 30, 3, 1).unwrap(),
            |_| Box::pin(async { Ok(()) }),
        )
        .await
        .unwrap();
        assert_eq!(report.acknowledged, 1);
        let delivered = ["outbox_00000001", "outbox_00000002"]
            .into_iter()
            .filter(|id| port.state(id).unwrap().delivered)
            .count();
        assert_eq!(delivered, 1);
    }
}
