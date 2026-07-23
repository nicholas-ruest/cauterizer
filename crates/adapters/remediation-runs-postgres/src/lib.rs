//! Same-context `PostgreSQL` adapter for durable remediation timelines.

#![forbid(unsafe_code)]

use cauterizer_infrastructure::postgres::{
    PostgresError, PostgresMetadataStore, PostgresMutation, PostgresOutcome,
};
use cauterizer_remediation_runs::domain::{RemediationRun, RemediationRunId, RunEvent};
use cauterizer_syntax::identifiers::OrganizationId;
use serde_json::Value;
use sqlx::{PgPool, Row};

const AGGREGATE_TYPE: &str = "remediation_run";

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

    #[tokio::test]
    async fn postgres_17_restart_rebuild_when_database_is_configured() {
        let Ok(url) = std::env::var("CAUTERIZER_TEST_DATABASE_URL") else {
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
}
