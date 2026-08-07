//! `PostgreSQL` persistence for External Actions grants, delivery state, and emergency stops.

#![forbid(unsafe_code)]

use std::fmt;

use cauterizer_external_actions::application::{RemoteActionGateway, RemoteError};
use cauterizer_external_actions::domain::{
    DeliveryStatus, ExternalActionDelivery, ExternalActionError, ExternalActionGrant,
    ExternalActionGrantId, ExternalActionRequest, ReconciliationPolicy, is_safe_external_reference,
};
use cauterizer_syntax::identifiers::{IdempotencyKey, OrganizationId};
use serde_json::Value;
use sqlx::{PgPool, Postgres, Row, Transaction};

/// Embedded checksummed migrations owned by this adapter.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate::Migrator {
    ignore_missing: true,
    ..sqlx::migrate!("./migrations")
};

/// Tenant-scoped durable External Actions repository.
#[derive(Clone)]
pub struct PostgresExternalActionRepository {
    pool: PgPool,
}

/// Async production orchestration using durable `PostgreSQL` state and a blocking provider port.
#[derive(Clone)]
pub struct PostgresExternalActionService<R> {
    repository: PostgresExternalActionRepository,
    remote: R,
}

/// Atomic result of attempting to lease an unknown delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconciliationClaim {
    /// This worker exclusively owns the reconciliation lease.
    Claimed(Box<ExternalActionDelivery>),
    /// Backoff or another unexpired lease prevents work now.
    NotReady,
    /// The bounded attempt count was exhausted and manual review is required.
    Exhausted,
}

impl<R> PostgresExternalActionService<R>
where
    R: RemoteActionGateway + Clone + Send + Sync + 'static,
{
    /// Creates a durable fail-closed service.
    #[must_use]
    pub const fn new(repository: PostgresExternalActionRepository, remote: R) -> Self {
        Self { repository, remote }
    }

    /// Executes or safely resumes one external action.
    ///
    /// Blocking provider work is isolated from the async executor. Ambiguous
    /// results are durably marked `Unknown` and reconciled before another mutation.
    ///
    /// # Errors
    /// Returns only sanitized validation, policy, persistence, kill-switch, or provider failures.
    pub async fn execute(
        &self,
        id: cauterizer_external_actions::domain::ExternalActionDeliveryId,
        request: ExternalActionRequest,
    ) -> Result<ExternalActionDelivery, ExternalActionError> {
        request.validate()?;
        if !request.capability.is_permitted() {
            return Err(ExternalActionError::ProhibitedCapability);
        }
        let delivery = if let Some(existing) = self
            .repository
            .find_delivery(&request.organization_id, &request.idempotency_key)
            .await
            .map_err(ExternalActionError::from)?
        {
            if existing.request != request {
                return Err(ExternalActionError::IdempotencyConflict);
            }
            match existing.status {
                DeliveryStatus::Succeeded { .. } | DeliveryStatus::Rejected { .. } => {
                    return Ok(existing);
                }
                DeliveryStatus::ReconciliationExhausted => {
                    return Err(ExternalActionError::RemoteUnavailable);
                }
                DeliveryStatus::Pending => existing,
                DeliveryStatus::Unknown => {
                    let now = unix_now()?;
                    match self
                        .repository
                        .claim_reconciliation(
                            &existing.request.organization_id,
                            &existing.request.idempotency_key,
                            now,
                            ReconciliationPolicy::DEFAULT,
                        )
                        .await
                        .map_err(ExternalActionError::from)?
                    {
                        ReconciliationClaim::Claimed(claimed) => *claimed,
                        ReconciliationClaim::NotReady | ReconciliationClaim::Exhausted => {
                            return Err(ExternalActionError::RemoteUnavailable);
                        }
                    }
                }
            }
        } else {
            let pending = ExternalActionDelivery::pending(id, request)?;
            self.repository
                .insert_delivery(&pending)
                .await
                .map_err(ExternalActionError::from)?
        };
        self.resume(delivery).await
    }

    async fn resume(
        &self,
        mut delivery: ExternalActionDelivery,
    ) -> Result<ExternalActionDelivery, ExternalActionError> {
        let organization_id = &delivery.request.organization_id;
        let grant = self
            .repository
            .find_grant(organization_id, &delivery.request.grant_id)
            .await
            .map_err(ExternalActionError::from)?
            .ok_or(ExternalActionError::NotAuthorized)?;
        grant.authorizes_request(&delivery.request)?;
        if matches!(delivery.status, DeliveryStatus::Unknown) {
            let remote = self.remote.clone();
            let request = delivery.request.clone();
            let installation_ref = grant.installation_ref.clone();
            if let Ok(Some(receipt)) = tokio::task::spawn_blocking(move || {
                remote.find_existing(&request, &installation_ref)
            })
            .await
            .map_err(|_| ExternalActionError::RemoteUnavailable)?
            {
                if !safe_receipt(&receipt) {
                    return Err(ExternalActionError::RemoteUnavailable);
                }
                delivery.status = DeliveryStatus::Succeeded {
                    remote_id: receipt.remote_id,
                    remote_url: receipt.remote_url,
                };
                self.repository
                    .update_delivery(&delivery)
                    .await
                    .map_err(ExternalActionError::from)?;
                return Ok(delivery);
            }
            delivery.defer_reconciliation(unix_now()?, ReconciliationPolicy::DEFAULT);
            self.repository
                .update_delivery(&delivery)
                .await
                .map_err(ExternalActionError::from)?;
            return Err(ExternalActionError::RemoteUnavailable);
        }

        // Re-evaluate immediately before the provider mutation so an emergency
        // stop engaged during authorization or reconciliation wins the race.
        if self
            .repository
            .kill_switch_engaged(organization_id)
            .await
            .map_err(ExternalActionError::from)?
        {
            return Err(ExternalActionError::KillSwitchEngaged);
        }
        if self
            .repository
            .installation_kill_switch_engaged(organization_id, &grant.installation_ref)
            .await
            .map_err(ExternalActionError::from)?
        {
            return Err(ExternalActionError::KillSwitchEngaged);
        }
        delivery.attempts = delivery.attempts.saturating_add(1);
        let remote = self.remote.clone();
        let request = delivery.request.clone();
        let installation_ref = grant.installation_ref;
        match tokio::task::spawn_blocking(move || remote.deliver(&request, &installation_ref))
            .await
            .map_err(|_| ExternalActionError::RemoteUnavailable)?
        {
            Ok(receipt) => {
                if !safe_receipt(&receipt) {
                    delivery.mark_unknown(unix_now()?, ReconciliationPolicy::DEFAULT);
                    self.repository
                        .update_delivery(&delivery)
                        .await
                        .map_err(ExternalActionError::from)?;
                    return Err(ExternalActionError::RemoteUnavailable);
                }
                delivery.status = DeliveryStatus::Succeeded {
                    remote_id: receipt.remote_id,
                    remote_url: receipt.remote_url,
                };
            }
            Err(RemoteError::Rejected) => {
                delivery.status = DeliveryStatus::Rejected {
                    reason_code: "provider_rejected".into(),
                };
            }
            Err(RemoteError::UnavailableOrAmbiguous) => {
                delivery.mark_unknown(unix_now()?, ReconciliationPolicy::DEFAULT);
            }
        }
        self.repository
            .update_delivery(&delivery)
            .await
            .map_err(ExternalActionError::from)?;
        match delivery.status {
            DeliveryStatus::Unknown | DeliveryStatus::ReconciliationExhausted => {
                Err(ExternalActionError::RemoteUnavailable)
            }
            DeliveryStatus::Rejected { .. } => Err(ExternalActionError::RemoteRejected),
            DeliveryStatus::Pending | DeliveryStatus::Succeeded { .. } => Ok(delivery),
        }
    }
}

impl PostgresExternalActionRepository {
    /// Creates an adapter from a least-privilege application pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Creates or replaces an installation grant within its owning tenant.
    ///
    /// # Errors
    /// Returns a sanitized serialization or database failure.
    pub async fn put_grant(&self, grant: &ExternalActionGrant) -> Result<(), AdapterError> {
        let value = serde_json::to_value(grant).map_err(|_| AdapterError::InvalidState)?;
        let mut transaction = self.tenant_transaction(&grant.organization_id).await?;
        sqlx::query(
            "INSERT INTO external_action_grants(organization_id,grant_id,grant_document) VALUES($1,$2,$3) \
             ON CONFLICT(organization_id,grant_id) DO UPDATE SET grant_document=EXCLUDED.grant_document",
        )
        .bind(grant.organization_id.as_str())
        .bind(grant.id.as_str())
        .bind(value)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Loads one grant without crossing the supplied tenant boundary.
    ///
    /// # Errors
    /// Returns a sanitized persisted-state or database failure.
    pub async fn find_grant(
        &self,
        organization_id: &OrganizationId,
        id: &ExternalActionGrantId,
    ) -> Result<Option<ExternalActionGrant>, AdapterError> {
        let mut transaction = self.tenant_transaction(organization_id).await?;
        let row = sqlx::query(
            "SELECT grant_document FROM external_action_grants WHERE organization_id=$1 AND grant_id=$2",
        )
        .bind(organization_id.as_str())
        .bind(id.as_str())
        .fetch_optional(&mut *transaction)
        .await?;
        let result = row
            .map(|row| row.try_get::<Value, _>("grant_document"))
            .transpose()?
            .map(|value| serde_json::from_value(value).map_err(|_| AdapterError::InvalidState))
            .transpose()?;
        transaction.commit().await?;
        Ok(result)
    }

    /// Revokes a grant durably and atomically without removing its audit state.
    ///
    /// # Errors
    /// Returns [`AdapterError::NotFound`] or a sanitized database/state failure.
    pub async fn revoke_grant(
        &self,
        organization_id: &OrganizationId,
        id: &ExternalActionGrantId,
    ) -> Result<(), AdapterError> {
        let mut transaction = self.tenant_transaction(organization_id).await?;
        let row = sqlx::query(
            "SELECT grant_document FROM external_action_grants WHERE organization_id=$1 AND grant_id=$2 FOR UPDATE",
        )
        .bind(organization_id.as_str())
        .bind(id.as_str())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(AdapterError::NotFound)?;
        let mut grant: ExternalActionGrant = serde_json::from_value(row.try_get("grant_document")?)
            .map_err(|_| AdapterError::InvalidState)?;
        grant.revoke();
        sqlx::query(
            "UPDATE external_action_grants SET grant_document=$3 WHERE organization_id=$1 AND grant_id=$2",
        )
        .bind(organization_id.as_str())
        .bind(id.as_str())
        .bind(serde_json::to_value(grant).map_err(|_| AdapterError::InvalidState)?)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Atomically inserts a delivery or returns the exact existing replay.
    ///
    /// # Errors
    /// Rejects request substitution with [`AdapterError::IdempotencyConflict`].
    pub async fn insert_delivery(
        &self,
        delivery: &ExternalActionDelivery,
    ) -> Result<ExternalActionDelivery, AdapterError> {
        let organization_id = &delivery.request.organization_id;
        let request =
            serde_json::to_value(&delivery.request).map_err(|_| AdapterError::InvalidState)?;
        let state = serde_json::to_value(delivery).map_err(|_| AdapterError::InvalidState)?;
        let mut transaction = self.tenant_transaction(organization_id).await?;
        let inserted = sqlx::query(
            "INSERT INTO external_action_deliveries(organization_id,delivery_id,idempotency_key,request,delivery) \
             VALUES($1,$2,$3,$4,$5) ON CONFLICT(organization_id,idempotency_key) DO NOTHING RETURNING delivery",
        )
        .bind(organization_id.as_str())
        .bind(delivery.id.as_str())
        .bind(delivery.request.idempotency_key.as_str())
        .bind(&request)
        .bind(state)
        .fetch_optional(&mut *transaction)
        .await?;
        let value = if let Some(row) = inserted {
            row.try_get("delivery")?
        } else {
            let row = sqlx::query(
                "SELECT request,delivery FROM external_action_deliveries WHERE organization_id=$1 AND idempotency_key=$2 FOR UPDATE",
            )
            .bind(organization_id.as_str())
            .bind(delivery.request.idempotency_key.as_str())
            .fetch_one(&mut *transaction)
            .await?;
            let persisted_request: Value = row.try_get("request")?;
            if persisted_request != request {
                return Err(AdapterError::IdempotencyConflict);
            }
            row.try_get("delivery")?
        };
        let result = serde_json::from_value(value).map_err(|_| AdapterError::InvalidState)?;
        transaction.commit().await?;
        Ok(result)
    }

    /// Loads a delivery by organization-scoped replay key.
    ///
    /// # Errors
    /// Returns a sanitized persisted-state or database failure.
    pub async fn find_delivery(
        &self,
        organization_id: &OrganizationId,
        key: &IdempotencyKey,
    ) -> Result<Option<ExternalActionDelivery>, AdapterError> {
        let mut transaction = self.tenant_transaction(organization_id).await?;
        let row = sqlx::query(
            "SELECT delivery FROM external_action_deliveries WHERE organization_id=$1 AND idempotency_key=$2",
        )
        .bind(organization_id.as_str())
        .bind(key.as_str())
        .fetch_optional(&mut *transaction)
        .await?;
        let result = row
            .map(|row| row.try_get::<Value, _>("delivery"))
            .transpose()?
            .map(|value| serde_json::from_value(value).map_err(|_| AdapterError::InvalidState))
            .transpose()?;
        transaction.commit().await?;
        Ok(result)
    }

    /// Atomically leases an eligible unknown delivery for one reconciliation read.
    ///
    /// # Errors
    /// Returns a sanitized persisted-state or database failure.
    pub async fn claim_reconciliation(
        &self,
        organization_id: &OrganizationId,
        key: &IdempotencyKey,
        now_epoch_seconds: u64,
        policy: ReconciliationPolicy,
    ) -> Result<ReconciliationClaim, AdapterError> {
        let mut transaction = self.tenant_transaction(organization_id).await?;
        let row = sqlx::query(
            "SELECT delivery FROM external_action_deliveries WHERE organization_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(organization_id.as_str())
        .bind(key.as_str())
        .fetch_optional(&mut *transaction)
        .await?;
        // A concurrent cleanup, revocation, or tenant-scoped repair may remove
        // an otherwise eligible row between scheduler observations. Treat the
        // absence as not-ready: it is safe, non-mutating, and lets the caller
        // reconcile from its authoritative delivery index instead of turning a
        // harmless race into a failed CI/worker run.
        let Some(row) = row else {
            transaction.commit().await?;
            return Ok(ReconciliationClaim::NotReady);
        };
        let mut delivery: ExternalActionDelivery = serde_json::from_value(row.try_get("delivery")?)
            .map_err(|_| AdapterError::InvalidState)?;
        if !matches!(delivery.status, DeliveryStatus::Unknown) {
            transaction.commit().await?;
            return Ok(ReconciliationClaim::NotReady);
        }
        if delivery.reconciliation_attempts >= policy.max_attempts {
            delivery.status = DeliveryStatus::ReconciliationExhausted;
            delivery.reconciliation_lease_until_epoch_seconds = None;
            self.write_delivery_in_transaction(&mut transaction, &delivery)
                .await?;
            transaction.commit().await?;
            return Ok(ReconciliationClaim::Exhausted);
        }
        if now_epoch_seconds < delivery.next_reconcile_at_epoch_seconds
            || delivery
                .reconciliation_lease_until_epoch_seconds
                .is_some_and(|until| now_epoch_seconds < until)
        {
            transaction.commit().await?;
            return Ok(ReconciliationClaim::NotReady);
        }
        delivery.reconciliation_attempts = delivery.reconciliation_attempts.saturating_add(1);
        delivery.reconciliation_claim_token = delivery.reconciliation_claim_token.saturating_add(1);
        delivery.reconciliation_lease_until_epoch_seconds =
            Some(now_epoch_seconds.saturating_add(policy.lease_seconds));
        self.write_delivery_in_transaction(&mut transaction, &delivery)
            .await?;
        transaction.commit().await?;
        Ok(ReconciliationClaim::Claimed(Box::new(delivery)))
    }

    /// Updates lifecycle state under a row lock while preserving identity and request.
    ///
    /// # Errors
    /// Rejects missing rows and any identity or request substitution.
    pub async fn update_delivery(
        &self,
        delivery: &ExternalActionDelivery,
    ) -> Result<(), AdapterError> {
        let organization_id = &delivery.request.organization_id;
        let mut transaction = self.tenant_transaction(organization_id).await?;
        let row = sqlx::query(
            "SELECT delivery,request FROM external_action_deliveries WHERE organization_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(organization_id.as_str())
        .bind(delivery.request.idempotency_key.as_str())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(AdapterError::NotFound)?;
        let current: ExternalActionDelivery = serde_json::from_value(row.try_get("delivery")?)
            .map_err(|_| AdapterError::InvalidState)?;
        let request =
            serde_json::to_value(&delivery.request).map_err(|_| AdapterError::InvalidState)?;
        let persisted_request: Value = row.try_get("request")?;
        let current_is_terminal = matches!(
            &current.status,
            DeliveryStatus::Succeeded { .. }
                | DeliveryStatus::Rejected { .. }
                | DeliveryStatus::ReconciliationExhausted
        );
        if current.id != delivery.id
            || persisted_request != request
            || delivery.attempts < current.attempts
            || (matches!(current.status, DeliveryStatus::Unknown)
                && current.reconciliation_claim_token != delivery.reconciliation_claim_token)
            || (current_is_terminal && current.status != delivery.status)
        {
            return Err(AdapterError::IdempotencyConflict);
        }
        sqlx::query(
            "UPDATE external_action_deliveries SET delivery=$3 WHERE organization_id=$1 AND idempotency_key=$2",
        )
        .bind(organization_id.as_str())
        .bind(delivery.request.idempotency_key.as_str())
        .bind(serde_json::to_value(delivery).map_err(|_| AdapterError::InvalidState)?)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Persists the tenant-specific emergency stop.
    ///
    /// # Errors
    /// Returns a sanitized database failure.
    pub async fn set_kill_switch(
        &self,
        organization_id: &OrganizationId,
        engaged: bool,
    ) -> Result<(), AdapterError> {
        let mut transaction = self.tenant_transaction(organization_id).await?;
        sqlx::query(
            "INSERT INTO external_action_kill_switches(organization_id,installation_ref,engaged) VALUES($1,'*',$2) \
             ON CONFLICT(organization_id,installation_ref) DO UPDATE SET engaged=EXCLUDED.engaged",
        )
        .bind(organization_id.as_str())
        .bind(engaged)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Reads the tenant emergency stop, defaulting fail-closed to engaged when absent.
    ///
    /// # Errors
    /// Returns a sanitized database failure.
    pub async fn kill_switch_engaged(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<bool, AdapterError> {
        let mut transaction = self.tenant_transaction(organization_id).await?;
        let value = sqlx::query_scalar(
            "SELECT engaged FROM external_action_kill_switches WHERE organization_id=$1 AND installation_ref='*'",
        )
        .bind(organization_id.as_str())
        .fetch_optional(&mut *transaction)
        .await?
        .unwrap_or(true);
        transaction.commit().await?;
        Ok(value)
    }

    /// Persists an installation-specific emergency stop.
    ///
    /// # Errors
    /// Returns a sanitized database failure.
    pub async fn set_installation_kill_switch(
        &self,
        organization_id: &OrganizationId,
        installation_ref: &str,
        engaged: bool,
    ) -> Result<(), AdapterError> {
        if installation_ref.is_empty() || installation_ref == "*" {
            return Err(AdapterError::InvalidState);
        }
        let mut transaction = self.tenant_transaction(organization_id).await?;
        sqlx::query(
            "INSERT INTO external_action_kill_switches(organization_id,installation_ref,engaged) VALUES($1,$2,$3) \
             ON CONFLICT(organization_id,installation_ref) DO UPDATE SET engaged=EXCLUDED.engaged",
        )
        .bind(organization_id.as_str())
        .bind(installation_ref)
        .bind(engaged)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Reads an installation emergency stop, inheriting the global state when unset.
    ///
    /// # Errors
    /// Returns a sanitized database failure.
    pub async fn installation_kill_switch_engaged(
        &self,
        organization_id: &OrganizationId,
        installation_ref: &str,
    ) -> Result<bool, AdapterError> {
        let mut transaction = self.tenant_transaction(organization_id).await?;
        let value = sqlx::query_scalar(
            "SELECT engaged FROM external_action_kill_switches WHERE organization_id=$1 AND installation_ref=$2",
        )
        .bind(organization_id.as_str())
        .bind(installation_ref)
        .fetch_optional(&mut *transaction)
        .await?;
        transaction.commit().await?;
        match value {
            Some(engaged) => Ok(engaged),
            None => self.kill_switch_engaged(organization_id).await,
        }
    }

    async fn tenant_transaction<'a>(
        &'a self,
        organization_id: &OrganizationId,
    ) -> Result<Transaction<'a, Postgres>, AdapterError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SELECT set_config('app.organization_id', $1, true)")
            .bind(organization_id.as_str())
            .execute(&mut *transaction)
            .await?;
        Ok(transaction)
    }

    async fn write_delivery_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        delivery: &ExternalActionDelivery,
    ) -> Result<(), AdapterError> {
        sqlx::query(
            "UPDATE external_action_deliveries SET delivery=$3 WHERE organization_id=$1 AND idempotency_key=$2",
        )
        .bind(delivery.request.organization_id.as_str())
        .bind(delivery.request.idempotency_key.as_str())
        .bind(serde_json::to_value(delivery).map_err(|_| AdapterError::InvalidState)?)
        .execute(&mut **transaction)
        .await?;
        Ok(())
    }
}

fn unix_now() -> Result<u64, ExternalActionError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ExternalActionError::RemoteUnavailable)
}

fn safe_receipt(receipt: &cauterizer_external_actions::application::RemoteReceipt) -> bool {
    is_safe_external_reference(&receipt.remote_id)
        && is_safe_external_reference(&receipt.remote_url)
}

/// Stable adapter failures that never expose SQL or provider payloads.
#[derive(Debug)]
pub enum AdapterError {
    /// Database operation failed.
    Database,
    /// Persisted or supplied JSON state was invalid.
    InvalidState,
    /// The requested record was absent.
    NotFound,
    /// A replay key was reused with a different request or identity.
    IdempotencyConflict,
}

impl From<sqlx::Error> for AdapterError {
    fn from(_: sqlx::Error) -> Self {
        Self::Database
    }
}
impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "external actions persistence failed: {self:?}")
    }
}
impl std::error::Error for AdapterError {}

impl From<AdapterError> for ExternalActionError {
    fn from(value: AdapterError) -> Self {
        match value {
            AdapterError::IdempotencyConflict => Self::IdempotencyConflict,
            AdapterError::NotFound => Self::NotFound,
            AdapterError::Database | AdapterError::InvalidState => Self::RemoteUnavailable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cauterizer_external_actions::application::{RemoteError, RemoteReceipt};
    use cauterizer_external_actions::domain::{
        ActionCapability, DeliveryAttestation, ExternalActionDeliveryId, ExternalActionRequest,
        GrantConstraints,
    };
    use cauterizer_syntax::digest::Sha256Digest;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn organization() -> OrganizationId {
        OrganizationId::new("adapterorg").unwrap()
    }

    #[derive(Clone, Default)]
    struct TestRemote {
        calls: Arc<AtomicUsize>,
    }

    impl RemoteActionGateway for TestRemote {
        fn find_existing(
            &self,
            _: &ExternalActionRequest,
            _: &str,
        ) -> Result<Option<RemoteReceipt>, RemoteError> {
            Ok(None)
        }

        fn deliver(
            &self,
            _: &ExternalActionRequest,
            _: &str,
        ) -> Result<RemoteReceipt, RemoteError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(RemoteReceipt {
                remote_id: "adapter-42".into(),
                remote_url: "https://scm.invalid/pr/adapter-42".into(),
            })
        }
    }

    #[test]
    fn repository_is_clone_send_and_sync() {
        fn assert_adapter<T: Clone + Send + Sync>() {}
        assert_adapter::<PostgresExternalActionRepository>();
    }

    fn grant() -> ExternalActionGrant {
        ExternalActionGrant::new(
            ExternalActionGrantId::new("grant0001").unwrap(),
            organization(),
            "installation-1",
            "owner/repo",
            "cauterizer/",
            BTreeSet::from([ActionCapability::OpenPullRequest]),
        )
        .unwrap()
        .with_constraints(GrantConstraints::new(100, 10, 2, 1_000, 10, 100).unwrap())
    }
    fn delivery(subject: &str) -> ExternalActionDelivery {
        ExternalActionDelivery::pending(
            ExternalActionDeliveryId::new("delivery01").unwrap(),
            ExternalActionRequest {
                organization_id: organization(),
                grant_id: grant().id,
                repository: "owner/repo".into(),
                capability: ActionCapability::OpenPullRequest,
                idempotency_key: IdempotencyKey::new("adapter-replay-key").unwrap(),
                correlation_key: "adapter-replay".into(),
                subject: subject.into(),
                redacted_body: "verified evidence".into(),
                policy_attestation: Some(attestation()),
            },
        )
        .unwrap()
    }

    fn attestation() -> DeliveryAttestation {
        DeliveryAttestation {
            candidate_digest: Sha256Digest::of_bytes("candidate"),
            policy_result_digest: Sha256Digest::of_bytes("policy"),
            policy_approved: true,
            patch_bytes: 1,
            changed_lines: 1,
            attempts: 1,
            elapsed_millis: 1,
            compute_units: 1,
            spend_micros: 1,
        }
    }

    #[test]
    fn delivery_json_preserves_unknown_recovery_state() {
        let mut value = delivery("fix");
        value.status = DeliveryStatus::Unknown;
        value.attempts = 1;
        let rebuilt: ExternalActionDelivery =
            serde_json::from_value(serde_json::to_value(&value).unwrap()).unwrap();
        assert_eq!(rebuilt, value);
    }

    #[test]
    fn delivery_json_preserves_typed_receipt_and_reads_legacy_reference() {
        let mut value = delivery("typed receipt");
        value.status = DeliveryStatus::Succeeded {
            remote_id: "42".into(),
            remote_url: "https://scm.invalid/pr/42".into(),
        };
        let rebuilt: ExternalActionDelivery =
            serde_json::from_value(serde_json::to_value(&value).unwrap()).unwrap();
        assert_eq!(rebuilt, value);
        let legacy: DeliveryStatus = serde_json::from_value(serde_json::json!({
            "Succeeded": { "remote_reference": "https://scm.invalid/pr/legacy" }
        }))
        .unwrap();
        assert_eq!(
            legacy,
            DeliveryStatus::Succeeded {
                remote_id: String::new(),
                remote_url: "https://scm.invalid/pr/legacy".into(),
            }
        );
    }

    #[tokio::test]
    async fn durable_replay_revocation_and_kill_switch_when_database_is_configured() {
        let Some(url) = postgres_test_url() else {
            return;
        };
        let pool = PgPool::connect(&url).await.unwrap();
        MIGRATOR.run(&pool).await.unwrap();
        reset_test_tenant(&pool, &organization()).await;
        let first = PostgresExternalActionRepository::new(pool.clone());
        first.put_grant(&grant()).await.unwrap();
        let inserted = first.insert_delivery(&delivery("fix")).await.unwrap();
        let replay = PostgresExternalActionRepository::new(pool.clone())
            .insert_delivery(&delivery("fix"))
            .await
            .unwrap();
        assert_eq!(inserted, replay);
        assert!(matches!(
            first.insert_delivery(&delivery("substitution")).await,
            Err(AdapterError::IdempotencyConflict)
        ));
        let mut unknown = inserted;
        unknown.status = DeliveryStatus::Unknown;
        unknown.attempts = 1;
        first.update_delivery(&unknown).await.unwrap();
        let restarted = PostgresExternalActionRepository::new(pool);
        assert_eq!(
            restarted
                .find_delivery(
                    &organization(),
                    &IdempotencyKey::new("adapter-replay-key").unwrap()
                )
                .await
                .unwrap(),
            Some(unknown)
        );
        first
            .revoke_grant(&organization(), &grant().id)
            .await
            .unwrap();
        assert!(
            !restarted
                .find_grant(&organization(), &grant().id)
                .await
                .unwrap()
                .unwrap()
                .enabled
        );
        assert!(
            restarted
                .kill_switch_engaged(&organization())
                .await
                .unwrap()
        );
        first.set_kill_switch(&organization(), false).await.unwrap();
        assert!(
            !restarted
                .kill_switch_engaged(&organization())
                .await
                .unwrap()
        );
        first
            .set_installation_kill_switch(&organization(), "installation-1", true)
            .await
            .unwrap();
        assert!(
            restarted
                .installation_kill_switch_engaged(&organization(), "installation-1")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn production_service_is_fail_closed_and_replay_safe_when_database_is_configured() {
        let Some(url) = postgres_test_url() else {
            return;
        };
        let pool = PgPool::connect(&url).await.unwrap();
        MIGRATOR.run(&pool).await.unwrap();
        let service_organization = OrganizationId::new("serviceorg").unwrap();
        reset_test_tenant(&pool, &service_organization).await;
        let repository = PostgresExternalActionRepository::new(pool);
        let service_grant = ExternalActionGrant::new(
            ExternalActionGrantId::new("serviceg1").unwrap(),
            service_organization.clone(),
            "installation-service",
            "owner/service-repo",
            "cauterizer/",
            BTreeSet::from([ActionCapability::OpenPullRequest]),
        )
        .unwrap()
        .with_constraints(GrantConstraints::new(100, 10, 2, 1_000, 10, 100).unwrap());
        repository.put_grant(&service_grant).await.unwrap();
        let request = ExternalActionRequest {
            organization_id: service_organization.clone(),
            grant_id: service_grant.id,
            repository: "owner/service-repo".into(),
            capability: ActionCapability::OpenPullRequest,
            idempotency_key: IdempotencyKey::new("service-replay-key").unwrap(),
            correlation_key: "service-replay".into(),
            subject: "fix service".into(),
            redacted_body: "verified evidence".into(),
            policy_attestation: Some(attestation()),
        };
        let remote = TestRemote::default();
        let service = PostgresExternalActionService::new(repository.clone(), remote.clone());
        assert_eq!(
            service
                .execute(
                    ExternalActionDeliveryId::new("serviced1").unwrap(),
                    request.clone()
                )
                .await,
            Err(ExternalActionError::KillSwitchEngaged)
        );
        assert_eq!(remote.calls.load(Ordering::SeqCst), 0);
        repository
            .set_kill_switch(&service_organization, false)
            .await
            .unwrap();
        let delivered = service
            .execute(
                ExternalActionDeliveryId::new("serviced2").unwrap(),
                request.clone(),
            )
            .await
            .unwrap();
        assert!(matches!(delivered.status, DeliveryStatus::Succeeded { .. }));
        let restarted = PostgresExternalActionService::new(repository, remote.clone());
        assert_eq!(
            restarted
                .execute(ExternalActionDeliveryId::new("serviced3").unwrap(), request)
                .await
                .unwrap(),
            delivered
        );
        assert_eq!(remote.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn reconciliation_claim_enforces_backoff_lease_and_exhaustion_when_database_is_configured()
     {
        let Some(url) = postgres_test_url() else {
            return;
        };
        let pool = PgPool::connect(&url).await.unwrap();
        MIGRATOR.run(&pool).await.unwrap();
        let repository = PostgresExternalActionRepository::new(pool);
        let policy = ReconciliationPolicy::new(2, 10, 20, 5).unwrap();
        let mut unknown = delivery("reconciliation schedule");
        unknown.request.idempotency_key = IdempotencyKey::new("claim-schedule-key").unwrap();
        unknown.id = ExternalActionDeliveryId::new("claimdel1").unwrap();
        unknown.mark_unknown(100, policy);
        repository.insert_delivery(&unknown).await.unwrap();
        assert_eq!(
            repository
                .claim_reconciliation(
                    &organization(),
                    &unknown.request.idempotency_key,
                    109,
                    policy
                )
                .await
                .unwrap(),
            ReconciliationClaim::NotReady
        );
        let first = repository.clone();
        let second = repository.clone();
        let key_one = unknown.request.idempotency_key.clone();
        let key_two = key_one.clone();
        let claim_organization = organization();
        let (left, right) = tokio::join!(
            first.claim_reconciliation(&claim_organization, &key_one, 110, policy),
            second.claim_reconciliation(&claim_organization, &key_two, 110, policy)
        );
        let claims = [left.unwrap(), right.unwrap()];
        assert_eq!(
            claims
                .iter()
                .filter(|result| matches!(result, ReconciliationClaim::Claimed(_)))
                .count(),
            1
        );
        let stale_claim = claims
            .iter()
            .find_map(|result| match result {
                ReconciliationClaim::Claimed(delivery) => Some((**delivery).clone()),
                ReconciliationClaim::NotReady | ReconciliationClaim::Exhausted => None,
            })
            .unwrap();
        assert_eq!(
            claims
                .iter()
                .filter(|result| **result == ReconciliationClaim::NotReady)
                .count(),
            1
        );
        assert_eq!(
            repository
                .claim_reconciliation(
                    &organization(),
                    &unknown.request.idempotency_key,
                    114,
                    policy
                )
                .await
                .unwrap(),
            ReconciliationClaim::NotReady
        );
        assert!(matches!(
            repository
                .claim_reconciliation(
                    &organization(),
                    &unknown.request.idempotency_key,
                    115,
                    policy
                )
                .await
                .unwrap(),
            ReconciliationClaim::Claimed(_)
        ));
        let mut stale_completion = stale_claim;
        stale_completion.status = DeliveryStatus::Succeeded {
            remote_id: "stale".into(),
            remote_url: "https://scm.invalid/pr/stale".into(),
        };
        assert!(matches!(
            repository.update_delivery(&stale_completion).await,
            Err(AdapterError::IdempotencyConflict)
        ));
        assert_reconciliation_exhaustion(&repository, &unknown, policy).await;
    }

    async fn assert_reconciliation_exhaustion(
        repository: &PostgresExternalActionRepository,
        unknown: &ExternalActionDelivery,
        policy: ReconciliationPolicy,
    ) {
        let mut claimed = repository
            .find_delivery(&organization(), &unknown.request.idempotency_key)
            .await
            .unwrap()
            .unwrap();
        claimed.reconciliation_lease_until_epoch_seconds = None;
        claimed.next_reconcile_at_epoch_seconds = 115;
        repository.update_delivery(&claimed).await.unwrap();
        assert_eq!(
            repository
                .claim_reconciliation(
                    &organization(),
                    &unknown.request.idempotency_key,
                    115,
                    policy
                )
                .await
                .unwrap(),
            ReconciliationClaim::Exhausted
        );
        assert!(matches!(
            repository
                .find_delivery(&organization(), &unknown.request.idempotency_key)
                .await
                .unwrap()
                .unwrap()
                .status,
            DeliveryStatus::ReconciliationExhausted
        ));
        let remote = TestRemote::default();
        let service = PostgresExternalActionService::new(repository.clone(), remote.clone());
        assert_eq!(
            service
                .execute(
                    ExternalActionDeliveryId::new("exhausted1").unwrap(),
                    unknown.request.clone()
                )
                .await,
            Err(ExternalActionError::RemoteUnavailable)
        );
        assert_eq!(remote.calls.load(Ordering::SeqCst), 0);
    }

    fn postgres_test_url() -> Option<String> {
        match std::env::var("CAUTERIZER_TEST_ADAPTER_POSTGRES_URL") {
            Ok(url) => Some(url),
            Err(error) if std::env::var_os("CAUTERIZER_REQUIRE_POSTGRES_TESTS").is_some() => {
                panic!("CAUTERIZER_TEST_ADAPTER_POSTGRES_URL is required: {error}")
            }
            Err(_) => None,
        }
    }

    async fn reset_test_tenant(pool: &PgPool, organization_id: &OrganizationId) {
        let mut transaction = pool.begin().await.unwrap();
        sqlx::query("SELECT set_config('app.organization_id', $1, true)")
            .bind(organization_id.as_str())
            .execute(&mut *transaction)
            .await
            .unwrap();
        for table in [
            "external_action_deliveries",
            "external_action_grants",
            "external_action_kill_switches",
        ] {
            sqlx::query(&format!("DELETE FROM {table} WHERE organization_id = $1"))
                .bind(organization_id.as_str())
                .execute(&mut *transaction)
                .await
                .unwrap();
        }
        transaction.commit().await.unwrap();
    }
}
