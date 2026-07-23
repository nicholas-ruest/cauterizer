//! Same-context `PostgreSQL` durability adapter for Commercial Entitlements.

#![forbid(unsafe_code)]

use cauterizer_commercial_entitlements::application::ports::AccountKey;
use cauterizer_commercial_entitlements::domain::{
    EntitlementAccount, EntitlementError, EntitlementEvent,
};
use cauterizer_syntax::authorization::ActionName;
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{IdempotencyKey, OrganizationId};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use sqlx::{PgPool, Row};

/// Context-owned migrations for durable accounts, idempotency, and outbox facts.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// First execution or exact durable replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableOutcome<R> {
    /// Mutation and facts committed at this aggregate version.
    Committed {
        /// New optimistic version.
        version: u64,
        /// Stable application result.
        result: R,
    },
    /// Exact prior result; aggregate and outbox were not changed.
    Replayed(R),
}

/// Stable adapter failure without SQL or commercial payload details.
#[derive(Debug)]
pub enum AdapterError {
    /// Account was absent.
    NotFound,
    /// Expected version was stale or create collided.
    Conflict,
    /// Same idempotency identity was reused with different canonical input.
    IdempotencyConflict,
    /// Persisted state or result violated its schema/domain invariants.
    CorruptState,
    /// Domain admission or lifecycle behavior rejected the mutation.
    Domain(EntitlementError),
    /// Database dependency failed.
    Unavailable,
}

impl From<EntitlementError> for AdapterError {
    fn from(value: EntitlementError) -> Self {
        Self::Domain(value)
    }
}

/// Tenant-scoped production repository.
#[derive(Clone)]
pub struct PostgresEntitlementRepository {
    pool: PgPool,
}

impl PostgresEntitlementRepository {
    /// Creates an adapter from a least-privilege application pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Applies context-owned migrations.
    ///
    /// # Errors
    /// Returns [`AdapterError::Unavailable`] on migration failure.
    pub async fn migrate(&self) -> Result<(), AdapterError> {
        MIGRATOR
            .run(&self.pool)
            .await
            .map_err(|_| AdapterError::Unavailable)
    }

    /// Loads one exact tenant-qualified aggregate and invariant-validates its state.
    ///
    /// # Errors
    /// Fails closed on database, numeric, JSON, or tenant-integrity errors.
    pub async fn load(
        &self,
        key: &AccountKey,
    ) -> Result<Option<(EntitlementAccount, u64)>, AdapterError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| AdapterError::Unavailable)?;
        set_tenant(&mut tx, &key.organization_id).await?;
        let row = sqlx::query(
            "SELECT organization_id,version,state FROM commercial_entitlement_accounts \
             WHERE organization_id=$1 AND account_id=$2",
        )
        .bind(key.organization_id.as_str())
        .bind(key.account_id.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| AdapterError::Unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let stored_org: String = row
            .try_get("organization_id")
            .map_err(|_| AdapterError::CorruptState)?;
        if stored_org != key.organization_id.as_str() {
            return Err(AdapterError::CorruptState);
        }
        let version: i64 = row
            .try_get("version")
            .map_err(|_| AdapterError::CorruptState)?;
        let state: Value = row
            .try_get("state")
            .map_err(|_| AdapterError::CorruptState)?;
        let account = EntitlementAccount::rehydrate(&key.organization_id, state)
            .map_err(|_| AdapterError::CorruptState)?;
        Ok(Some((
            account,
            u64::try_from(version).map_err(|_| AdapterError::CorruptState)?,
        )))
    }

    /// Creates an account and its initial events atomically.
    ///
    /// # Errors
    /// Rejects tenant mismatch, duplicate account, invalid state, or database failure.
    pub async fn create(
        &self,
        key: &AccountKey,
        account: &mut EntitlementAccount,
    ) -> Result<u64, AdapterError> {
        if account.organization_id() != &key.organization_id {
            return Err(AdapterError::CorruptState);
        }
        let mut staged = account.clone();
        let events = staged.take_pending_events();
        let state = staged.durable_snapshot()?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| AdapterError::Unavailable)?;
        set_tenant(&mut tx, &key.organization_id).await?;
        let inserted = sqlx::query(
            "INSERT INTO commercial_entitlement_accounts \
             (organization_id,account_id,version,state) VALUES ($1,$2,1,$3) \
             ON CONFLICT DO NOTHING",
        )
        .bind(key.organization_id.as_str())
        .bind(key.account_id.as_str())
        .bind(state)
        .execute(&mut *tx)
        .await
        .map_err(|_| AdapterError::Unavailable)?;
        if inserted.rows_affected() != 1 {
            return Err(AdapterError::Conflict);
        }
        append_events(&mut tx, key, 1, &events).await?;
        tx.commit().await.map_err(|_| AdapterError::Unavailable)?;
        account.take_pending_events();
        Ok(1)
    }

    /// Executes a domain mutation, idempotency result, state update, and outbox append
    /// in one `PostgreSQL` transaction under a row lock.
    ///
    /// # Errors
    /// Rejects stale versions, conflicting retries, domain denial, corrupt state/results,
    /// or database failure. No partial write becomes visible.
    #[allow(clippy::too_many_lines)]
    pub async fn transact<R, F>(
        &self,
        key: &AccountKey,
        expected_version: u64,
        scope: &ActionName,
        idempotency_key: &IdempotencyKey,
        request_digest: Sha256Digest,
        operation: F,
    ) -> Result<DurableOutcome<R>, AdapterError>
    where
        R: Clone + DeserializeOwned + Serialize,
        F: FnOnce(&mut EntitlementAccount) -> Result<R, EntitlementError>,
    {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| AdapterError::Unavailable)?;
        set_tenant(&mut tx, &key.organization_id).await?;
        let idempotency_lock = format!(
            "{}|{}|{}",
            key.organization_id.as_str(),
            scope.as_str(),
            idempotency_key.as_str()
        );
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(idempotency_lock)
            .execute(&mut *tx)
            .await
            .map_err(|_| AdapterError::Unavailable)?;
        if let Some(row) = sqlx::query(
            "SELECT request_digest,result FROM commercial_entitlement_idempotency \
             WHERE organization_id=$1 AND command_scope=$2 AND idempotency_key=$3 FOR UPDATE",
        )
        .bind(key.organization_id.as_str())
        .bind(scope.as_str())
        .bind(idempotency_key.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| AdapterError::Unavailable)?
        {
            let stored: String = row
                .try_get("request_digest")
                .map_err(|_| AdapterError::CorruptState)?;
            if stored != request_digest.to_string() {
                return Err(AdapterError::IdempotencyConflict);
            }
            let value: Value = row
                .try_get("result")
                .map_err(|_| AdapterError::CorruptState)?;
            return serde_json::from_value(value)
                .map(DurableOutcome::Replayed)
                .map_err(|_| AdapterError::CorruptState);
        }
        let row = sqlx::query(
            "SELECT version,state FROM commercial_entitlement_accounts \
             WHERE organization_id=$1 AND account_id=$2 FOR UPDATE",
        )
        .bind(key.organization_id.as_str())
        .bind(key.account_id.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| AdapterError::Unavailable)?
        .ok_or(AdapterError::NotFound)?;
        let version: i64 = row
            .try_get("version")
            .map_err(|_| AdapterError::CorruptState)?;
        if u64::try_from(version).ok() != Some(expected_version) {
            return Err(AdapterError::Conflict);
        }
        let next = expected_version
            .checked_add(1)
            .ok_or(AdapterError::Conflict)?;
        let state: Value = row
            .try_get("state")
            .map_err(|_| AdapterError::CorruptState)?;
        let mut account = EntitlementAccount::rehydrate(&key.organization_id, state)
            .map_err(|_| AdapterError::CorruptState)?;
        let result = operation(&mut account)?;
        let events = account.take_pending_events();
        let durable_state = account.durable_snapshot()?;
        let encoded_result =
            serde_json::to_value(&result).map_err(|_| AdapterError::CorruptState)?;
        sqlx::query(
            "UPDATE commercial_entitlement_accounts SET version=$3,state=$4,\
             updated_at=transaction_timestamp() WHERE organization_id=$1 AND account_id=$2",
        )
        .bind(key.organization_id.as_str())
        .bind(key.account_id.as_str())
        .bind(i64::try_from(next).map_err(|_| AdapterError::Conflict)?)
        .bind(durable_state)
        .execute(&mut *tx)
        .await
        .map_err(|_| AdapterError::Unavailable)?;
        append_events(&mut tx, key, next, &events).await?;
        sqlx::query(
            "INSERT INTO commercial_entitlement_idempotency \
             (organization_id,command_scope,idempotency_key,request_digest,result) \
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(key.organization_id.as_str())
        .bind(scope.as_str())
        .bind(idempotency_key.as_str())
        .bind(request_digest.to_string())
        .bind(encoded_result)
        .execute(&mut *tx)
        .await
        .map_err(|_| AdapterError::Unavailable)?;
        tx.commit().await.map_err(|_| AdapterError::Unavailable)?;
        Ok(DurableOutcome::Committed {
            version: next,
            result,
        })
    }
}

async fn set_tenant(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: &OrganizationId,
) -> Result<(), AdapterError> {
    sqlx::query("SELECT set_config('app.organization_id', $1, true)")
        .bind(organization_id.as_str())
        .execute(&mut **tx)
        .await
        .map_err(|_| AdapterError::Unavailable)?;
    Ok(())
}

async fn append_events(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    key: &AccountKey,
    version: u64,
    events: &[EntitlementEvent],
) -> Result<(), AdapterError> {
    for (index, event) in events.iter().enumerate() {
        sqlx::query(
            "INSERT INTO commercial_entitlement_outbox \
             (organization_id,account_id,aggregate_version,event_index,event) \
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(key.organization_id.as_str())
        .bind(key.account_id.as_str())
        .bind(i64::try_from(version).map_err(|_| AdapterError::Conflict)?)
        .bind(i32::try_from(index).map_err(|_| AdapterError::Conflict)?)
        .bind(serde_json::to_value(event).map_err(|_| AdapterError::CorruptState)?)
        .execute(&mut **tx)
        .await
        .map_err(|_| AdapterError::Unavailable)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use cauterizer_commercial_entitlements::domain::{
        BudgetReservation, DeploymentProfile, Plan, PlanId, QuotaWindow, ReservationId,
        ReservationRequest, UsageDimension,
    };
    use cauterizer_syntax::identifiers::ContextQualifiedId;

    fn organization() -> OrganizationId {
        OrganizationId::new("entitle0").unwrap()
    }

    fn key() -> AccountKey {
        AccountKey {
            organization_id: organization(),
            account_id: ContextQualifiedId::new("entitlement-account", "entitle0").unwrap(),
        }
    }

    fn account() -> EntitlementAccount {
        EntitlementAccount::open(
            organization(),
            DeploymentProfile::Production,
            Plan::metered(
                PlanId::new("entitle0").unwrap(),
                1,
                BTreeMap::from([(UsageDimension::new("solver.tokens").unwrap(), 10)]),
                BTreeSet::new(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn reservation(id: &str, units: u64) -> ReservationRequest {
        ReservationRequest {
            id: ReservationId::new(id).unwrap(),
            request_digest: Sha256Digest::of_bytes(format!("reservation-{id}-{units}")),
            window: QuotaWindow::new(0, 100).unwrap(),
            worst_case: BTreeMap::from([(UsageDimension::new("solver.tokens").unwrap(), units)]),
        }
    }

    #[test]
    fn durable_snapshot_round_trips_without_pending_events() {
        let mut original = account();
        original.take_pending_events();
        original.reserve(reservation("00000001", 4)).unwrap();
        original.take_pending_events();
        let snapshot = original.durable_snapshot().unwrap();
        let restored = EntitlementAccount::rehydrate(&organization(), snapshot).unwrap();
        assert_eq!(
            restored.durable_snapshot().unwrap(),
            original.durable_snapshot().unwrap()
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn postgres_atomic_reservation_replay_and_restart_when_database_is_configured() {
        let Some(url) = postgres_test_url() else {
            return;
        };
        let pool = PgPool::connect(&url).await.unwrap();
        let repository = PostgresEntitlementRepository::new(pool.clone());
        repository.migrate().await.unwrap();
        let key = key();
        let mut cleanup = pool.begin().await.unwrap();
        set_tenant(&mut cleanup, &key.organization_id)
            .await
            .unwrap();
        for table in [
            "commercial_entitlement_outbox",
            "commercial_entitlement_idempotency",
            "commercial_entitlement_accounts",
        ] {
            sqlx::query(&format!("DELETE FROM {table} WHERE organization_id=$1"))
                .bind(key.organization_id.as_str())
                .execute(&mut *cleanup)
                .await
                .unwrap();
        }
        cleanup.commit().await.unwrap();

        let mut initial = account();
        assert_eq!(repository.create(&key, &mut initial).await.unwrap(), 1);

        let first_repository = repository.clone();
        let second_repository = repository.clone();
        let first_key = key.clone();
        let second_key = key.clone();
        let first_scope = ActionName::parse("entitlements.reserve").unwrap();
        let second_scope = first_scope.clone();
        let first_idempotency = IdempotencyKey::new("reserve-00000001").unwrap();
        let second_idempotency = IdempotencyKey::new("reserve-00000002").unwrap();
        let first_request = reservation("00000001", 6);
        let second_request = reservation("00000002", 6);
        let first_digest = first_request.request_digest;
        let second_digest = second_request.request_digest;
        let (first, second) = tokio::join!(
            first_repository.transact(
                &first_key,
                1,
                &first_scope,
                &first_idempotency,
                first_digest,
                |account| account.reserve(first_request),
            ),
            second_repository.transact(
                &second_key,
                1,
                &second_scope,
                &second_idempotency,
                second_digest,
                |account| account.reserve(second_request),
            )
        );
        assert_eq!(
            [&first, &second]
                .into_iter()
                .filter(|result| matches!(result, Ok(DurableOutcome::Committed { .. })))
                .count(),
            1
        );
        assert_eq!(
            [&first, &second]
                .into_iter()
                .filter(|result| matches!(result, Err(AdapterError::Conflict)))
                .count(),
            1
        );

        let (winning_key, winning_digest, winning_request) = if first.is_ok() {
            (first_idempotency, first_digest, reservation("00000001", 6))
        } else {
            (
                second_idempotency,
                second_digest,
                reservation("00000002", 6),
            )
        };
        assert!(matches!(
            repository
                .transact(
                    &key,
                    1,
                    &first_scope,
                    &winning_key,
                    winning_digest,
                    |account| account.reserve(winning_request),
                )
                .await
                .unwrap(),
            DurableOutcome::Replayed(_)
        ));
        assert!(matches!(
            repository
                .transact(
                    &key,
                    2,
                    &first_scope,
                    &winning_key,
                    Sha256Digest::of_bytes("substituted"),
                    |_| -> Result<BudgetReservation, EntitlementError> {
                        unreachable!("conflicting retry must fail before callback")
                    },
                )
                .await,
            Err(AdapterError::IdempotencyConflict)
        ));

        let restarted = PostgresEntitlementRepository::new(pool);
        let (loaded, version) = restarted.load(&key).await.unwrap().unwrap();
        assert_eq!(version, 2);
        assert_eq!(loaded.usage_records().count(), 0);
        assert!(
            restarted
                .load(&AccountKey {
                    organization_id: OrganizationId::new("foreign0").unwrap(),
                    account_id: key.account_id,
                })
                .await
                .unwrap()
                .is_none()
        );
    }

    fn postgres_test_url() -> Option<String> {
        match std::env::var("CAUTERIZER_TEST_ADAPTER_POSTGRES_URL")
            .or_else(|_| std::env::var("CAUTERIZER_TEST_DATABASE_URL"))
        {
            Ok(url) => Some(url),
            Err(error) if std::env::var_os("CAUTERIZER_REQUIRE_POSTGRES_TESTS").is_some() => {
                panic!(
                    "CAUTERIZER_TEST_ADAPTER_POSTGRES_URL (or legacy \
                     CAUTERIZER_TEST_DATABASE_URL) is required when \
                     CAUTERIZER_REQUIRE_POSTGRES_TESTS is set: {error}"
                );
            }
            Err(_) => None,
        }
    }
}
