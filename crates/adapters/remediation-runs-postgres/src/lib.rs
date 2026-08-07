//! Same-context `PostgreSQL` adapter for durable remediation timelines.

#![forbid(unsafe_code)]

use cauterizer_infrastructure::postgres::{
    PostgresError, PostgresMetadataStore, PostgresMutation, PostgresOutcome,
};
use cauterizer_remediation_runs::application::review_delivery::{
    AsyncReviewDeliveryRepository, GenerationClaim, GenerationLease, GenerationLeaseRepository,
    ReviewDelivery, ReviewDeliveryError, ReviewDeliveryKey, VersionedDelivery,
};
use cauterizer_remediation_runs::domain::{RemediationRun, RemediationRunId, RunEvent};
use cauterizer_syntax::identifiers::OrganizationId;
use serde_json::Value;
use sqlx::{PgPool, Row};

const AGGREGATE_TYPE: &str = "remediation_run";
/// Adapter-owned review-delivery migrations.
pub static REVIEW_DELIVERY_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate::Migrator {
    // All context-owned migration streams share one deployment database. Ignore
    // versions owned by another stream while retaining checksum validation for
    // this adapter's own migrations.
    ignore_missing: true,
    ..sqlx::migrate!("./migrations")
};

/// `PostgreSQL` review-delivery repository with tenant-local transactions.
#[derive(Clone)]
pub struct PostgresReviewDeliveryRepository {
    pool: PgPool,
}
impl PostgresReviewDeliveryRepository {
    /// Constructs the adapter.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    async fn load_tx(
        &self,
        key: &ReviewDeliveryKey,
    ) -> Result<Option<VersionedDelivery>, ReviewDeliveryError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| ReviewDeliveryError::Unavailable)?;
        sqlx::query("SELECT set_config('app.organization_id',$1,true)")
            .bind(key.organization_id.as_str())
            .execute(&mut *tx)
            .await
            .map_err(|_| ReviewDeliveryError::Unavailable)?;
        let row = sqlx::query("SELECT version,state FROM review_deliveries WHERE organization_id=$1 AND run_id=$2 AND candidate_digest=$3")
            .bind(key.organization_id.as_str()).bind(key.run_id.as_str()).bind(key.candidate_digest.to_tagged_hex())
            .fetch_optional(&mut *tx).await.map_err(|_| ReviewDeliveryError::Unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let version: i64 = row
            .try_get("version")
            .map_err(|_| ReviewDeliveryError::Unavailable)?;
        let state: Value = row
            .try_get("state")
            .map_err(|_| ReviewDeliveryError::Unavailable)?;
        let delivery: ReviewDelivery =
            serde_json::from_value(state).map_err(|_| ReviewDeliveryError::Unavailable)?;
        if &delivery.key != key {
            return Err(ReviewDeliveryError::Unavailable);
        }
        Ok(Some(VersionedDelivery {
            delivery,
            version: u64::try_from(version).map_err(|_| ReviewDeliveryError::Unavailable)?,
        }))
    }
}
impl AsyncReviewDeliveryRepository for PostgresReviewDeliveryRepository {
    async fn load(
        &self,
        key: &ReviewDeliveryKey,
    ) -> Result<Option<VersionedDelivery>, ReviewDeliveryError> {
        self.load_tx(key).await
    }
    async fn create(
        &self,
        delivery: ReviewDelivery,
    ) -> Result<VersionedDelivery, ReviewDeliveryError> {
        let key = delivery.key.clone();
        let state =
            serde_json::to_value(&delivery).map_err(|_| ReviewDeliveryError::Unavailable)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| ReviewDeliveryError::Unavailable)?;
        sqlx::query("SELECT set_config('app.organization_id',$1,true)")
            .bind(key.organization_id.as_str())
            .execute(&mut *tx)
            .await
            .map_err(|_| ReviewDeliveryError::Unavailable)?;
        let result = sqlx::query("INSERT INTO review_deliveries(organization_id,run_id,candidate_digest,version,state) VALUES($1,$2,$3,1,$4) ON CONFLICT DO NOTHING")
            .bind(key.organization_id.as_str()).bind(key.run_id.as_str()).bind(key.candidate_digest.to_tagged_hex()).bind(state)
            .execute(&mut *tx).await.map_err(|_| ReviewDeliveryError::Unavailable)?;
        tx.commit()
            .await
            .map_err(|_| ReviewDeliveryError::Unavailable)?;
        let existing = self
            .load_tx(&key)
            .await?
            .ok_or(ReviewDeliveryError::Unavailable)?;
        if result.rows_affected() == 0 && existing.delivery != delivery {
            return Err(ReviewDeliveryError::Conflict);
        }
        Ok(existing)
    }
    async fn save(
        &self,
        expected_version: u64,
        delivery: ReviewDelivery,
    ) -> Result<VersionedDelivery, ReviewDeliveryError> {
        let key = delivery.key.clone();
        let next = expected_version
            .checked_add(1)
            .ok_or(ReviewDeliveryError::Conflict)?;
        let state =
            serde_json::to_value(&delivery).map_err(|_| ReviewDeliveryError::Unavailable)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| ReviewDeliveryError::Unavailable)?;
        sqlx::query("SELECT set_config('app.organization_id',$1,true)")
            .bind(key.organization_id.as_str())
            .execute(&mut *tx)
            .await
            .map_err(|_| ReviewDeliveryError::Unavailable)?;
        let result = sqlx::query("UPDATE review_deliveries SET version=$4,state=$5 WHERE organization_id=$1 AND run_id=$2 AND candidate_digest=$3 AND version=$6")
            .bind(key.organization_id.as_str()).bind(key.run_id.as_str()).bind(key.candidate_digest.to_tagged_hex())
            .bind(i64::try_from(next).map_err(|_| ReviewDeliveryError::Conflict)?).bind(state)
            .bind(i64::try_from(expected_version).map_err(|_| ReviewDeliveryError::Conflict)?)
            .execute(&mut *tx).await.map_err(|_| ReviewDeliveryError::Unavailable)?;
        if result.rows_affected() != 1 {
            return Err(ReviewDeliveryError::Conflict);
        }
        tx.commit()
            .await
            .map_err(|_| ReviewDeliveryError::Unavailable)?;
        Ok(VersionedDelivery {
            delivery,
            version: next,
        })
    }
    async fn load_active(
        &self,
        organization: &OrganizationId,
        run: &RemediationRunId,
    ) -> Result<Option<VersionedDelivery>, ReviewDeliveryError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| ReviewDeliveryError::Unavailable)?;
        sqlx::query("SELECT set_config('app.organization_id',$1,true)")
            .bind(organization.as_str())
            .execute(&mut *tx)
            .await
            .map_err(|_| ReviewDeliveryError::Unavailable)?;
        let rows = sqlx::query(
            "SELECT version,state FROM review_deliveries WHERE organization_id=$1 AND run_id=$2",
        )
        .bind(organization.as_str())
        .bind(run.as_str())
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| ReviewDeliveryError::Unavailable)?;
        let mut active = Vec::new();
        for row in rows {
            let delivery: ReviewDelivery = serde_json::from_value(
                row.try_get("state")
                    .map_err(|_| ReviewDeliveryError::Unavailable)?,
            )
            .map_err(|_| ReviewDeliveryError::Unavailable)?;
            if !delivery.is_superseded() {
                let version: i64 = row
                    .try_get("version")
                    .map_err(|_| ReviewDeliveryError::Unavailable)?;
                active.push(VersionedDelivery {
                    delivery,
                    version: u64::try_from(version)
                        .map_err(|_| ReviewDeliveryError::Unavailable)?,
                });
            }
        }
        match active.len() {
            0 => Ok(None),
            1 => Ok(active.pop()),
            _ => Err(ReviewDeliveryError::Conflict),
        }
    }
}

impl GenerationLeaseRepository for PostgresReviewDeliveryRepository {
    async fn claim(
        &self,
        organization: &OrganizationId,
        run: &RemediationRunId,
        owner: &str,
        now_unix: u64,
        lease_seconds: u64,
    ) -> Result<GenerationClaim, ReviewDeliveryError> {
        if owner.is_empty() || owner.len() > 128 || lease_seconds == 0 {
            return Err(ReviewDeliveryError::Conflict);
        }
        let expiry = now_unix
            .checked_add(lease_seconds)
            .ok_or(ReviewDeliveryError::Conflict)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| ReviewDeliveryError::Unavailable)?;
        sqlx::query("SELECT set_config('app.organization_id',$1,true)")
            .bind(organization.as_str())
            .execute(&mut *tx)
            .await
            .map_err(|_| ReviewDeliveryError::Unavailable)?;
        let row = sqlx::query(
            "INSERT INTO review_generation_leases(organization_id,run_id,owner,fence,expires_at_unix) VALUES($1,$2,$3,1,$4) \
             ON CONFLICT(organization_id,run_id) DO UPDATE SET owner=EXCLUDED.owner,fence=review_generation_leases.fence+1,expires_at_unix=EXCLUDED.expires_at_unix \
             WHERE review_generation_leases.expires_at_unix <= $5 RETURNING fence,expires_at_unix")
            .bind(organization.as_str()).bind(run.as_str()).bind(owner)
            .bind(i64::try_from(expiry).map_err(|_| ReviewDeliveryError::Conflict)?)
            .bind(i64::try_from(now_unix).map_err(|_| ReviewDeliveryError::Conflict)?)
            .fetch_optional(&mut *tx).await.map_err(|_| ReviewDeliveryError::Unavailable)?;
        tx.commit()
            .await
            .map_err(|_| ReviewDeliveryError::Unavailable)?;
        let Some(row) = row else {
            return Ok(GenerationClaim::Held);
        };
        let fence: i64 = row
            .try_get("fence")
            .map_err(|_| ReviewDeliveryError::Unavailable)?;
        Ok(GenerationClaim::Acquired(GenerationLease {
            organization_id: organization.clone(),
            run_id: run.clone(),
            owner: owner.into(),
            fence: u64::try_from(fence).map_err(|_| ReviewDeliveryError::Unavailable)?,
            expires_at_unix: expiry,
        }))
    }
    async fn is_current(
        &self,
        lease: &GenerationLease,
        now_unix: u64,
    ) -> Result<bool, ReviewDeliveryError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| ReviewDeliveryError::Unavailable)?;
        sqlx::query("SELECT set_config('app.organization_id',$1,true)")
            .bind(lease.organization_id.as_str())
            .execute(&mut *tx)
            .await
            .map_err(|_| ReviewDeliveryError::Unavailable)?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM review_generation_leases WHERE organization_id=$1 AND run_id=$2 AND owner=$3 AND fence=$4 AND expires_at_unix>$5)")
            .bind(lease.organization_id.as_str()).bind(lease.run_id.as_str()).bind(&lease.owner)
            .bind(i64::try_from(lease.fence).map_err(|_| ReviewDeliveryError::Conflict)?)
            .bind(i64::try_from(now_unix).map_err(|_| ReviewDeliveryError::Conflict)?)
            .fetch_one(&mut *tx).await.map_err(|_| ReviewDeliveryError::Unavailable)?;
        Ok(exists)
    }
}

/// Tenant/run-filtered durable timeline repository using the P04 atomic unit of work.
#[derive(Clone)]
pub struct PostgresRemediationRunRepository {
    pool: PgPool,
    metadata: PostgresMetadataStore,
}

impl PostgresRemediationRunRepository {
    /// Creates an adapter from a least-privilege application pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            metadata: PostgresMetadataStore::new(pool.clone()),
            pool,
        }
    }

    /// Loads one ordered timeline and rebuilds all transition/dedupe state.
    ///
    /// # Errors
    /// Returns a stable database or invalid-history error.
    pub async fn load(
        &self,
        organization_id: &OrganizationId,
        run_id: &RemediationRunId,
    ) -> Result<Option<(RemediationRun, u64)>, AdapterError> {
        let mut transaction = self.pool.begin().await.map_err(PostgresError::from)?;
        sqlx::query("SELECT set_config('app.organization_id', $1, true)")
            .bind(organization_id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(PostgresError::from)?;
        let row = sqlx::query(
            "SELECT version,state FROM aggregate_snapshots WHERE organization_id=$1 \
             AND aggregate_type=$2 AND aggregate_id=$3",
        )
        .bind(organization_id.as_str())
        .bind(AGGREGATE_TYPE)
        .bind(run_id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(PostgresError::from)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let version: i64 = row.try_get("version").map_err(PostgresError::from)?;
        let state: Value = row.try_get("state").map_err(PostgresError::from)?;
        let timeline: Vec<RunEvent> =
            serde_json::from_value(state).map_err(|_| AdapterError::InvalidHistory)?;
        let run = RemediationRun::rebuild(&timeline).map_err(|_| AdapterError::InvalidHistory)?;
        if run.organization_id() != organization_id || run.id() != run_id {
            return Err(AdapterError::IdentityMismatch);
        }
        Ok(Some((
            run,
            u64::try_from(version).map_err(|_| AdapterError::InvalidHistory)?,
        )))
    }

    /// Atomically persists the timeline with caller-supplied events/outbox/result.
    ///
    /// # Errors
    /// Rejects tenant/run/type mismatch or the shared transactional failure.
    pub async fn save(
        &self,
        run: &RemediationRun,
        mut mutation: PostgresMutation,
    ) -> Result<PostgresOutcome, AdapterError> {
        if &mutation.organization_id != run.organization_id()
            || mutation.aggregate_type != AGGREGATE_TYPE
            || mutation.aggregate_id.as_str() != run.id().as_str()
        {
            return Err(AdapterError::IdentityMismatch);
        }
        mutation.state =
            serde_json::to_value(run.timeline()).map_err(|_| AdapterError::InvalidHistory)?;
        self.metadata.execute(mutation).await.map_err(Into::into)
    }
}

/// Stable adapter failure without database/history payloads.
#[derive(Debug)]
pub enum AdapterError {
    /// Shared transactional `PostgreSQL` failure.
    Postgres(PostgresError),
    /// Persisted timeline did not rebuild under current versioned semantics.
    InvalidHistory,
    /// Tenant, run, or aggregate type did not match.
    IdentityMismatch,
}

impl From<PostgresError> for AdapterError {
    fn from(value: PostgresError) -> Self {
        Self::Postgres(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cauterizer_infrastructure::postgres::MIGRATOR;
    use cauterizer_remediation_runs::application::review_delivery::{
        PlanKind, PlannedAction, PlannedSubject, ReviewDeliveryPlan, ReviewStage, StageCheckpoint,
    };
    use cauterizer_remediation_runs::domain::RunLineage;
    use cauterizer_syntax::digest::Sha256Digest;
    use cauterizer_syntax::identifiers::{ContextQualifiedId, IdempotencyKey};
    use cauterizer_syntax::schema::{SchemaName, SchemaVersion};
    use cauterizer_syntax::time::UtcInstant;

    #[test]
    fn timeline_json_rebuilds_identically() {
        let run = RemediationRun::create(
            OrganizationId::new("00000000").unwrap(),
            RemediationRunId::new("00000000").unwrap(),
            RunLineage {
                parent: None,
                supersedes: None,
            },
        );
        let value = serde_json::to_value(run.timeline()).unwrap();
        let timeline: Vec<RunEvent> = serde_json::from_value(value).unwrap();
        let rebuilt = RemediationRun::rebuild(&timeline).unwrap();
        assert_eq!(rebuilt.timeline(), run.timeline());
    }
    fn review_plan() -> ReviewDeliveryPlan {
        ReviewDeliveryPlan::new(
            PlanKind::VerifiedReview,
            [
                ReviewStage::Issue,
                ReviewStage::Branch,
                ReviewStage::Commit,
                ReviewStage::PullRequest,
                ReviewStage::Summary,
            ]
            .into_iter()
            .map(|stage| {
                (
                    stage,
                    PlannedAction {
                        template_bytes: vec![stage as u8],
                        template_digest: Sha256Digest::of_bytes([stage as u8]),
                        subject: if stage == ReviewStage::Summary {
                            PlannedSubject::PriorStageRemoteId(ReviewStage::PullRequest)
                        } else {
                            PlannedSubject::Literal(vec![])
                        },
                    },
                )
            })
            .collect(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn review_delivery_restart_conflict_and_supersession_when_configured() {
        let Some(url) = postgres_test_url() else {
            return;
        };
        let pool = PgPool::connect(&url).await.unwrap();
        REVIEW_DELIVERY_MIGRATOR.run(&pool).await.unwrap();
        let key = ReviewDeliveryKey {
            organization_id: OrganizationId::new("delivery1").unwrap(),
            run_id: RemediationRunId::new("delivery1").unwrap(),
            candidate_digest: Sha256Digest::of_bytes(b"candidate"),
        };
        sqlx::query("SELECT set_config('app.organization_id',$1,false)")
            .bind(key.organization_id.as_str())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM review_deliveries WHERE organization_id=$1")
            .bind(key.organization_id.as_str())
            .execute(&pool)
            .await
            .unwrap();
        let repository = PostgresReviewDeliveryRepository::new(pool);
        let mut saved = repository
            .create(ReviewDelivery::new(key.clone(), review_plan()))
            .await
            .unwrap();
        for stage in [
            ReviewStage::Issue,
            ReviewStage::Branch,
            ReviewStage::Commit,
            ReviewStage::PullRequest,
            ReviewStage::Summary,
        ] {
            let request_digest = saved.delivery.materialize(stage).unwrap().request_digest;
            saved
                .delivery
                .checkpoint(
                    stage,
                    StageCheckpoint {
                        request_digest,
                        remote_reference: format!("https://scm.invalid/{stage:?}"),
                        remote_id: format!("remote-{stage:?}"),
                    },
                )
                .unwrap();
            repository
                .save(saved.version, saved.delivery)
                .await
                .unwrap();
            saved = repository.load(&key).await.unwrap().unwrap();
        }
        let stale = saved.clone();
        saved
            .delivery
            .supersede(Sha256Digest::of_bytes(b"replacement"))
            .unwrap();
        repository
            .save(saved.version, saved.delivery)
            .await
            .unwrap();
        assert_eq!(
            repository.save(stale.version, stale.delivery).await,
            Err(ReviewDeliveryError::Conflict)
        );
        assert!(repository.load(&key).await.unwrap().unwrap().version > 1);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn active_lookup_and_generation_fencing_when_configured() {
        let Some(url) = postgres_test_url() else {
            return;
        };
        let pool = PgPool::connect(&url).await.unwrap();
        REVIEW_DELIVERY_MIGRATOR.run(&pool).await.unwrap();
        let organization = OrganizationId::new("delivery2").unwrap();
        let run = RemediationRunId::new("delivery2").unwrap();
        sqlx::query("SELECT set_config('app.organization_id',$1,false)")
            .bind(organization.as_str())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM review_deliveries WHERE organization_id=$1")
            .bind(organization.as_str())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM review_generation_leases WHERE organization_id=$1")
            .bind(organization.as_str())
            .execute(&pool)
            .await
            .unwrap();
        let repository = PostgresReviewDeliveryRepository::new(pool);
        let key = |name: &[u8]| ReviewDeliveryKey {
            organization_id: organization.clone(),
            run_id: run.clone(),
            candidate_digest: Sha256Digest::of_bytes(name),
        };
        let first = repository
            .create(ReviewDelivery::new(key(b"one"), review_plan()))
            .await
            .unwrap();
        assert_eq!(
            repository
                .load_active(&organization, &run)
                .await
                .unwrap()
                .unwrap()
                .delivery
                .key,
            first.delivery.key
        );
        let second = repository
            .create(ReviewDelivery::new(key(b"two"), review_plan()))
            .await
            .unwrap();
        assert_eq!(
            repository.load_active(&organization, &run).await,
            Err(ReviewDeliveryError::Conflict)
        );
        let mut old = first.delivery;
        old.supersede(second.delivery.key.candidate_digest).unwrap();
        repository.save(first.version, old).await.unwrap();
        assert_eq!(
            repository
                .load_active(&organization, &run)
                .await
                .unwrap()
                .unwrap()
                .delivery
                .key,
            second.delivery.key
        );

        let (left, right) = tokio::join!(
            repository.claim(&organization, &run, "worker-a", 100, 10),
            repository.claim(&organization, &run, "worker-b", 100, 10)
        );
        let claims = [left.unwrap(), right.unwrap()];
        assert_eq!(
            claims
                .iter()
                .filter(|claim| matches!(claim, GenerationClaim::Acquired(_)))
                .count(),
            1
        );
        let original = claims
            .iter()
            .find_map(|claim| match claim {
                GenerationClaim::Acquired(lease) => Some(lease.clone()),
                GenerationClaim::Held => None,
            })
            .unwrap();
        assert_eq!(
            claims
                .iter()
                .filter(|claim| matches!(claim, GenerationClaim::Held))
                .count(),
            1
        );
        assert_eq!(
            repository
                .claim(&organization, &run, "worker-c", 109, 10)
                .await
                .unwrap(),
            GenerationClaim::Held
        );
        let recovered = repository
            .claim(&organization, &run, "worker-c", 110, 10)
            .await
            .unwrap();
        let GenerationClaim::Acquired(recovered) = recovered else {
            panic!("expired lease must recover");
        };
        assert_eq!(recovered.fence, 2);
        assert!(!repository.is_current(&original, 110).await.unwrap());
        assert!(repository.is_current(&recovered, 110).await.unwrap());
    }

    #[tokio::test]
    async fn postgres_17_restart_rebuild_when_database_is_configured() {
        let Some(url) = postgres_test_url() else {
            return;
        };
        let pool = PgPool::connect(&url).await.unwrap();
        MIGRATOR.run(&pool).await.unwrap();
        let organization = OrganizationId::new("rrrrrrrr").unwrap();
        let run_id = RemediationRunId::new("00000000").unwrap();
        let run = RemediationRun::create(
            organization.clone(),
            run_id.clone(),
            RunLineage {
                parent: None,
                supersedes: None,
            },
        );
        let repository = PostgresRemediationRunRepository::new(pool.clone());
        let mutation = PostgresMutation {
            organization_id: organization.clone(),
            aggregate_type: AGGREGATE_TYPE.into(),
            aggregate_id: ContextQualifiedId::new("run", "00000000").unwrap(),
            expected_version: None,
            state_schema: SchemaName::parse("dev.cauterizer.remediation-runs.state").unwrap(),
            state_version: SchemaVersion::parse("1.0.0").unwrap(),
            state: Value::Null,
            events: Vec::new(),
            command_scope: "remediation-runs.create".into(),
            idempotency_key: IdempotencyKey::new("create-00000000").unwrap(),
            request_digest: Sha256Digest::of_bytes("create-run"),
            result_schema: SchemaName::parse("dev.cauterizer.remediation-runs.result").unwrap(),
            result: serde_json::json!({"run_id":"run_00000000"}),
            result_expires_at: UtcInstant::parse("2027-07-23T00:00:00Z").unwrap(),
            required_artifacts: Vec::new(),
        };
        assert!(matches!(
            repository.save(&run, mutation).await.unwrap(),
            PostgresOutcome::Committed { version: 1, .. }
        ));
        let restarted = PostgresRemediationRunRepository::new(pool);
        let (rebuilt, version) = restarted
            .load(&organization, &run_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(version, 1);
        assert_eq!(rebuilt.timeline(), run.timeline());
        assert!(
            restarted
                .load(&OrganizationId::new("ssssssss").unwrap(), &run_id)
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
