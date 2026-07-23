//! Same-context `PostgreSQL` adapter for Asset Portfolio.

#![forbid(unsafe_code)]

use cauterizer_asset_portfolio::domain::{AssetPortfolio, AssetSnapshot};
use cauterizer_infrastructure::postgres::{
    PostgresError, PostgresMetadataStore, PostgresMutation, PostgresOutcome,
};
use cauterizer_syntax::identifiers::OrganizationId;
use serde_json::Value;
use sqlx::{PgPool, Row};

const AGGREGATE_TYPE: &str = "asset_portfolio";

/// Tenant-filtered relational repository using the P04 atomic unit of work.
#[derive(Clone)]
pub struct PostgresAssetPortfolioRepository {
    pool: PgPool,
    metadata: PostgresMetadataStore,
}

impl PostgresAssetPortfolioRepository {
    /// Creates the adapter from a least-privilege application pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            metadata: PostgresMetadataStore::new(pool.clone()),
            pool,
        }
    }

    /// Loads and invariant-validates one exact tenant portfolio.
    ///
    /// # Errors
    /// Returns a payload-safe database or corrupt-state error.
    pub async fn load(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Option<(AssetPortfolio, u64)>, AdapterError> {
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
        .bind(aggregate_id(organization_id))
        .fetch_optional(&mut *transaction)
        .await
        .map_err(PostgresError::from)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let version: i64 = row.try_get("version").map_err(PostgresError::from)?;
        let state: Value = row.try_get("state").map_err(PostgresError::from)?;
        let snapshots: Vec<AssetSnapshot> =
            serde_json::from_value(state).map_err(|_| AdapterError::CorruptState)?;
        let portfolio = AssetPortfolio::rehydrate(organization_id.clone(), snapshots)
            .map_err(|_| AdapterError::CorruptState)?;
        Ok(Some((
            portfolio,
            u64::try_from(version).map_err(|_| AdapterError::CorruptState)?,
        )))
    }

    /// Atomically saves state, events, outbox records, and idempotency result.
    ///
    /// # Errors
    /// Rejects identity mismatch or a shared `PostgreSQL` transaction failure.
    pub async fn save(
        &self,
        portfolio: &AssetPortfolio,
        mut mutation: PostgresMutation,
    ) -> Result<PostgresOutcome, AdapterError> {
        if &mutation.organization_id != portfolio.organization_id()
            || mutation.aggregate_type != AGGREGATE_TYPE
            || mutation.aggregate_id.as_str() != aggregate_id(portfolio.organization_id())
        {
            return Err(AdapterError::TenantMismatch);
        }
        mutation.state =
            serde_json::to_value(portfolio.snapshot()).map_err(|_| AdapterError::CorruptState)?;
        self.metadata.execute(mutation).await.map_err(Into::into)
    }
}

/// Stable adapter failure without database or state payloads.
#[derive(Debug)]
pub enum AdapterError {
    /// Shared `PostgreSQL` transaction failed.
    Postgres(PostgresError),
    /// Persisted state failed syntax or aggregate invariant validation.
    CorruptState,
    /// Mutation identity did not match the aggregate tenant.
    TenantMismatch,
}

impl From<PostgresError> for AdapterError {
    fn from(value: PostgresError) -> Self {
        Self::Postgres(value)
    }
}

fn aggregate_id(organization_id: &OrganizationId) -> String {
    format!("asset-portfolio_{}", organization_id.opaque())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cauterizer_asset_portfolio::domain::{
        AssetId, AssetType, Criticality, Environment, SourceLocator,
    };
    use cauterizer_infrastructure::postgres::MIGRATOR;
    use cauterizer_syntax::digest::Sha256Digest;
    use cauterizer_syntax::identifiers::{ContextQualifiedId, IdempotencyKey};
    use cauterizer_syntax::schema::{SchemaName, SchemaVersion};
    use cauterizer_syntax::time::UtcInstant;

    #[test]
    fn snapshot_codec_round_trips_through_invariant_rehydration() {
        let organization = OrganizationId::new("00000000").unwrap();
        let mut portfolio = AssetPortfolio::new(organization.clone());
        portfolio
            .register(
                AssetId::new("00000000").unwrap(),
                AssetType::Repository,
                SourceLocator::parse("https://code.example.com/acme/widget.git").unwrap(),
                Environment::Production,
                Criticality::High,
            )
            .unwrap();
        let encoded = serde_json::to_value(portfolio.snapshot()).unwrap();
        let decoded: Vec<AssetSnapshot> = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, portfolio.snapshot());
        assert!(AssetPortfolio::rehydrate(organization, decoded).is_ok());
    }

    #[tokio::test]
    async fn postgres_17_save_and_restart_when_database_is_configured() {
        let Some(url) = postgres_test_url() else {
            return;
        };
        let pool = PgPool::connect(&url).await.unwrap();
        MIGRATOR.run(&pool).await.unwrap();
        let organization = OrganizationId::new("zzzzzzzz").unwrap();
        let mut portfolio = AssetPortfolio::new(organization.clone());
        portfolio
            .register(
                AssetId::new("00000000").unwrap(),
                AssetType::Repository,
                SourceLocator::parse("https://code.example.com/acme/widget.git").unwrap(),
                Environment::Production,
                Criticality::Critical,
            )
            .unwrap();
        let repository = PostgresAssetPortfolioRepository::new(pool.clone());
        let mutation = PostgresMutation {
            organization_id: organization.clone(),
            aggregate_type: AGGREGATE_TYPE.into(),
            aggregate_id: ContextQualifiedId::new("asset-portfolio", organization.opaque())
                .unwrap(),
            expected_version: None,
            state_schema: SchemaName::parse("dev.cauterizer.asset-portfolio.state").unwrap(),
            state_version: SchemaVersion::parse("1.0.0").unwrap(),
            state: Value::Null,
            events: Vec::new(),
            command_scope: "asset-portfolio.register".into(),
            idempotency_key: IdempotencyKey::new("register-00000000").unwrap(),
            request_digest: Sha256Digest::of_bytes("register-asset"),
            result_schema: SchemaName::parse("dev.cauterizer.asset-portfolio.result").unwrap(),
            result: serde_json::json!({"asset_id":"asset_00000000"}),
            result_expires_at: UtcInstant::parse("2027-07-23T00:00:00Z").unwrap(),
            required_artifacts: Vec::new(),
        };
        assert!(matches!(
            repository.save(&portfolio, mutation).await.unwrap(),
            PostgresOutcome::Committed { version: 1, .. }
        ));
        let restarted = PostgresAssetPortfolioRepository::new(pool);
        let (loaded, version) = restarted.load(&organization).await.unwrap().unwrap();
        assert_eq!(version, 1);
        assert_eq!(loaded.snapshot(), portfolio.snapshot());
        assert!(
            restarted
                .load(&OrganizationId::new("yyyyyyyy").unwrap())
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
