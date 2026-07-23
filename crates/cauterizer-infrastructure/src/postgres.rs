//! PostgreSQL 17 metadata adapter for atomic aggregate and outbox persistence.

use crate::artifacts::AccessDomain;
use crate::s3_artifacts::StoredObjectExpectation;
use cauterizer_syntax::classification::DataClass;
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{
    AggregateSequence, CausationId, ContextQualifiedId, CorrelationId, IdempotencyKey,
    OrganizationId,
};
use cauterizer_syntax::schema::{SchemaName, SchemaVersion};
use cauterizer_syntax::time::UtcInstant;
use serde_json::Value;
use sqlx::{PgConnection, PgPool, Row};
use std::fmt;
use std::future::Future;
use std::pin::Pin;

/// Embedded, checksummed `PostgreSQL` migrations for this adapter.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// One append-only event and its relay-visible outbox identity.
pub struct PostgresEvent {
    /// Aggregate-local ordering sequence.
    pub sequence: AggregateSequence,
    /// Globally unique producer event ID.
    pub event_id: ContextQualifiedId,
    /// Versioned event schema.
    pub schema_name: SchemaName,
    /// Semantic event version.
    pub schema_version: SchemaVersion,
    /// Canonical JSON event payload.
    pub payload: Value,
    /// Canonical occurrence time.
    pub occurred_at: UtcInstant,
    /// Request trace identifier.
    pub correlation_id: CorrelationId,
    /// Causative command/event identifier.
    pub causation_id: CausationId,
    /// Unique outbox row ID.
    pub outbox_id: ContextQualifiedId,
}

/// Complete atomic metadata mutation.
pub struct PostgresMutation {
    /// Tenant partition.
    pub organization_id: OrganizationId,
    /// Stable context aggregate type.
    pub aggregate_type: String,
    /// Context-owned aggregate ID.
    pub aggregate_id: ContextQualifiedId,
    /// Required current version; `None` means create-only.
    pub expected_version: Option<u64>,
    /// Persisted state schema.
    pub state_schema: SchemaName,
    /// Persisted state semantic version.
    pub state_version: SchemaVersion,
    /// Canonical JSON aggregate state.
    pub state: Value,
    /// Events made visible atomically with state.
    pub events: Vec<PostgresEvent>,
    /// Command scope used with the idempotency key.
    pub command_scope: String,
    /// Organization-scoped idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// Digest of the complete canonical command.
    pub request_digest: Sha256Digest,
    /// Result schema name.
    pub result_schema: SchemaName,
    /// Stable canonical command result.
    pub result: Value,
    /// Canonical replay-retention expiry.
    pub result_expires_at: UtcInstant,
    /// Committed artifact descriptors referenced by this state transition.
    pub required_artifacts: Vec<ArtifactReference>,
}

/// A committed content address that must exist before an aggregate may refer to it.
pub struct ArtifactReference {
    /// Physically and logically isolated artifact namespace.
    pub access_domain: AccessDomain,
    /// Exact content digest bound into aggregate state or events.
    pub digest: Sha256Digest,
}

/// Successful first commit or exact replay.
#[derive(Clone, Debug, PartialEq)]
pub enum PostgresOutcome {
    /// New atomic state/event/outbox/result commit.
    Committed {
        /// Newly stored optimistic aggregate version.
        version: u64,
        /// Stable command result atomically stored for replay.
        result: Value,
    },
    /// Prior exact command result; no writes occurred.
    Replayed(Value),
}

/// One exclusively leased relay record.
#[derive(Clone, Debug, PartialEq)]
pub struct OutboxClaim {
    /// Tenant owning the event.
    pub organization_id: OrganizationId,
    /// Stable outbox row identity.
    pub outbox_id: String,
    /// Published event identity.
    pub event_id: String,
    /// Complete versioned event envelope.
    pub event: Value,
    /// Attempt count before this lease.
    pub attempts: i32,
    /// Exact lease token required by every terminal/retry mutation.
    pub claim_token: String,
}

/// Aggregate delivery health used by reconciliation/alerting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryReconciliation {
    /// Relay rows ready now, including reclaimable expired leases.
    pub ready_outbox: i64,
    /// Future aggregate events waiting on missing predecessors.
    pub held_events: i64,
    /// Poison records awaiting governed resolution.
    pub open_dead_letters: i64,
    /// Replay operations that have not reached a terminal audit outcome.
    pub pending_replays: i64,
}

/// Complete metadata for one atomic consumer effect.
pub struct PostgresInboxEvent {
    /// Tenant boundary.
    pub organization_id: OrganizationId,
    /// Consumer and deployed handler identity.
    pub consumer: String,
    /// Version of handler semantics, not the event schema.
    pub handler_version: SchemaVersion,
    /// Authenticated producer.
    pub producer: String,
    /// Globally unique producer event ID.
    pub event_id: ContextQualifiedId,
    /// Versioned schema identity.
    pub schema_name: SchemaName,
    /// Versioned schema revision.
    pub schema_version: SchemaVersion,
    /// Aggregate type used in the ordered stream key.
    pub aggregate_type: String,
    /// Aggregate stream ID.
    pub aggregate_id: ContextQualifiedId,
    /// One-based stream position.
    pub aggregate_sequence: AggregateSequence,
    /// Payload governance inherited by inbox/held storage.
    pub classification: DataClass,
    /// Canonical complete-envelope digest.
    pub envelope_digest: Sha256Digest,
    /// Complete event retained only when a predecessor is missing.
    pub event: Value,
}

/// Atomic consumer result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboxOutcome {
    /// Consumer SQL effect and inbox/checkpoint committed together.
    Applied,
    /// Exact event was previously applied by this handler version.
    Duplicate,
    /// Event was retained because a predecessor has not committed.
    HeldForGap {
        /// Next required stream position.
        expected: u64,
    },
}

/// Boxed SQL effect whose lifetime cannot escape the consumer transaction.
pub type ConsumerEffect<'a> = Pin<Box<dyn Future<Output = Result<(), PostgresError>> + Send + 'a>>;

/// Stable relational adapter failures.
#[derive(Debug)]
pub enum PostgresError {
    /// SQL or migration failure without provider details in public output.
    Database(sqlx::Error),
    /// Migration failure.
    Migration(sqlx::migrate::MigrateError),
    /// Expected aggregate version was stale.
    VersionConflict,
    /// Idempotency key already binds different canonical input.
    IdempotencyConflict,
    /// Numeric conversion exceeded `PostgreSQL`'s signed range.
    NumericRange,
    /// Lease duration, retry delay, or claim limit was outside its safe bound.
    InvalidDeliveryBound,
    /// Lease token no longer owns the outbox row.
    OutboxClaimLost,
    /// Event identity was reused with a different canonical envelope.
    InboxIdentityConflict,
    /// Event sequence regressed behind a checkpoint without a deduplication fact.
    InboxSequenceConflict,
    /// An aggregate attempted to bind an absent or tombstoned artifact.
    UncommittedArtifact,
    /// Stored artifact metadata could not be interpreted safely.
    InvalidArtifactMetadata,
}

impl fmt::Display for PostgresError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Database(_) => "postgres_metadata_error",
            Self::Migration(_) => "postgres_migration_error",
            Self::VersionConflict => "aggregate_version_conflict",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::NumericRange => "numeric_range_error",
            Self::InvalidDeliveryBound => "invalid_delivery_bound",
            Self::OutboxClaimLost => "outbox_claim_lost",
            Self::InboxIdentityConflict => "inbox_identity_conflict",
            Self::InboxSequenceConflict => "inbox_sequence_conflict",
            Self::UncommittedArtifact => "uncommitted_artifact_reference",
            Self::InvalidArtifactMetadata => "invalid_artifact_metadata",
        })
    }
}
impl std::error::Error for PostgresError {}
impl From<sqlx::Error> for PostgresError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value)
    }
}
impl From<sqlx::migrate::MigrateError> for PostgresError {
    fn from(value: sqlx::migrate::MigrateError) -> Self {
        Self::Migration(value)
    }
}

/// PostgreSQL-backed transactional metadata store.
#[derive(Clone)]
pub struct PostgresMetadataStore {
    pool: PgPool,
}

impl PostgresMetadataStore {
    /// Creates an adapter from a least-privilege application pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Applies the embedded migration set under `PostgreSQL` advisory locking.
    ///
    /// # Errors
    ///
    /// Returns a stable migration error when any migration cannot complete.
    pub async fn migrate(&self) -> Result<(), PostgresError> {
        MIGRATOR.run(&self.pool).await?;
        Ok(())
    }

    /// Loads live artifact metadata for exact-key object-store reconciliation.
    ///
    /// # Errors
    ///
    /// Fails closed on database errors, unknown access domains, malformed digests,
    /// negative sizes, or tenant substitution.
    pub async fn live_artifact_expectations(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Vec<StoredObjectExpectation>, PostgresError> {
        let mut connection = self.pool.acquire().await?;
        sqlx::query("SELECT set_config('app.organization_id', $1, false)")
            .bind(organization_id.as_str())
            .execute(&mut *connection)
            .await?;
        let rows = sqlx::query(
            "SELECT organization_id, access_domain, digest, size_bytes \
             FROM artifact_descriptors WHERE organization_id=$1 AND tombstoned_at IS NULL \
             ORDER BY access_domain, digest",
        )
        .bind(organization_id.as_str())
        .fetch_all(&mut *connection)
        .await?;
        rows.into_iter()
            .map(|row| {
                let stored_org: String = row.try_get("organization_id")?;
                if stored_org != organization_id.as_str() {
                    return Err(PostgresError::InvalidArtifactMetadata);
                }
                let domain: String = row.try_get("access_domain")?;
                let digest: String = row.try_get("digest")?;
                let size: i64 = row.try_get("size_bytes")?;
                Ok(StoredObjectExpectation {
                    organization_id: organization_id.clone(),
                    access_domain: AccessDomain::parse(&domain)
                        .ok_or(PostgresError::InvalidArtifactMetadata)?,
                    digest: digest
                        .parse()
                        .map_err(|_| PostgresError::InvalidArtifactMetadata)?,
                    size: u64::try_from(size)
                        .map_err(|_| PostgresError::InvalidArtifactMetadata)?,
                })
            })
            .collect()
    }

    /// Atomically stores aggregate state, events, outbox rows, and replay result.
    ///
    /// # Errors
    ///
    /// Returns a stable database, stale-version, conflicting-key, or numeric
    /// range error. `PostgreSQL` rolls the entire transaction back on every error.
    #[allow(clippy::too_many_lines)]
    pub async fn execute(
        &self,
        mutation: PostgresMutation,
    ) -> Result<PostgresOutcome, PostgresError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT set_config('app.organization_id', $1, true)")
            .bind(mutation.organization_id.as_str())
            .execute(&mut *tx)
            .await?;

        if let Some(row) = sqlx::query(
            "SELECT request_digest, result FROM idempotency_results \
             WHERE organization_id=$1 AND command_scope=$2 AND idempotency_key=$3 FOR UPDATE",
        )
        .bind(mutation.organization_id.as_str())
        .bind(&mutation.command_scope)
        .bind(mutation.idempotency_key.as_str())
        .fetch_optional(&mut *tx)
        .await?
        {
            let digest: String = row.try_get("request_digest")?;
            if digest != mutation.request_digest.to_string() {
                return Err(PostgresError::IdempotencyConflict);
            }
            return Ok(PostgresOutcome::Replayed(row.try_get("result")?));
        }

        let current: Option<i64> = sqlx::query_scalar(
            "SELECT version FROM aggregate_snapshots WHERE organization_id=$1 \
             AND aggregate_type=$2 AND aggregate_id=$3 FOR UPDATE",
        )
        .bind(mutation.organization_id.as_str())
        .bind(&mutation.aggregate_type)
        .bind(mutation.aggregate_id.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        let expected = mutation.expected_version.map(to_i64).transpose()?;
        if current != expected {
            return Err(PostgresError::VersionConflict);
        }

        for reference in &mutation.required_artifacts {
            let committed: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM artifact_descriptors WHERE organization_id=$1 \
                 AND access_domain=$2 AND digest=$3 AND tombstoned_at IS NULL)",
            )
            .bind(mutation.organization_id.as_str())
            .bind(reference.access_domain.as_str())
            .bind(reference.digest.to_string())
            .fetch_one(&mut *tx)
            .await?;
            if !committed {
                return Err(PostgresError::UncommittedArtifact);
            }
        }
        let version = current
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(PostgresError::NumericRange)?;

        sqlx::query(
            "INSERT INTO aggregate_snapshots \
             (organization_id,aggregate_type,aggregate_id,version,schema_name,schema_version,state) \
             VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT \
             (organization_id,aggregate_type,aggregate_id) DO UPDATE SET \
             version=EXCLUDED.version,schema_name=EXCLUDED.schema_name,\
             schema_version=EXCLUDED.schema_version,state=EXCLUDED.state,updated_at=transaction_timestamp()",
        )
        .bind(mutation.organization_id.as_str())
        .bind(&mutation.aggregate_type)
        .bind(mutation.aggregate_id.as_str())
        .bind(version)
        .bind(mutation.state_schema.as_str())
        .bind(mutation.state_version.as_str())
        .bind(&mutation.state)
        .execute(&mut *tx)
        .await?;

        for event in &mutation.events {
            sqlx::query(
                "INSERT INTO aggregate_events \
                 (organization_id,aggregate_type,aggregate_id,aggregate_sequence,event_id,\
                  schema_name,schema_version,payload,occurred_at,correlation_id,causation_id) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::timestamptz,$10,$11)",
            )
            .bind(mutation.organization_id.as_str())
            .bind(&mutation.aggregate_type)
            .bind(mutation.aggregate_id.as_str())
            .bind(to_i64(event.sequence.get())?)
            .bind(event.event_id.as_str())
            .bind(event.schema_name.as_str())
            .bind(event.schema_version.as_str())
            .bind(&event.payload)
            .bind(event.occurred_at.as_str())
            .bind(event.correlation_id.as_str())
            .bind(event.causation_id.as_str())
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO transactional_outbox \
                 (organization_id,outbox_id,event_id,event) VALUES ($1,$2,$3,$4)",
            )
            .bind(mutation.organization_id.as_str())
            .bind(event.outbox_id.as_str())
            .bind(event.event_id.as_str())
            .bind(&event.payload)
            .execute(&mut *tx)
            .await?;
        }

        sqlx::query(
            "INSERT INTO idempotency_results \
             (organization_id,command_scope,idempotency_key,request_digest,result_schema,result,expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7::timestamptz)",
        )
        .bind(mutation.organization_id.as_str())
        .bind(&mutation.command_scope)
        .bind(mutation.idempotency_key.as_str())
        .bind(mutation.request_digest.to_string())
        .bind(mutation.result_schema.as_str())
        .bind(&mutation.result)
        .bind(mutation.result_expires_at.as_str())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(PostgresOutcome::Committed {
            version: u64::try_from(version).map_err(|_| PostgresError::NumericRange)?,
            result: mutation.result,
        })
    }

    /// Claims ready outbox rows with a database-time lease.
    ///
    /// Concurrent dispatchers do not block one another; expired claims are
    /// reclaimable and every later mutation requires the exact new token.
    ///
    /// # Errors
    ///
    /// Rejects a zero/oversized batch or lease outside 1 second..=1 hour.
    pub async fn claim_outbox(
        &self,
        organization_id: &OrganizationId,
        claim_token: &ContextQualifiedId,
        limit: u16,
        lease_seconds: u32,
    ) -> Result<Vec<OutboxClaim>, PostgresError> {
        if limit == 0 || limit > 1_000 || lease_seconds == 0 || lease_seconds > 3_600 {
            return Err(PostgresError::InvalidDeliveryBound);
        }
        let mut tx = self.pool.begin().await?;
        set_tenant(&mut tx, organization_id).await?;
        let rows = sqlx::query(
            "WITH ready AS (\
               SELECT organization_id,outbox_id FROM transactional_outbox \
               WHERE organization_id=$1 AND delivered_at IS NULL AND dead_lettered_at IS NULL \
                 AND available_at <= transaction_timestamp() \
                 AND next_attempt_at <= transaction_timestamp() \
                 AND (claim_token IS NULL OR claim_expires_at <= transaction_timestamp()) \
               ORDER BY next_attempt_at,available_at,outbox_id \
               FOR UPDATE SKIP LOCKED LIMIT $2\
             ) \
             UPDATE transactional_outbox AS target SET \
               claim_token=$3, \
               claim_expires_at=transaction_timestamp()+($4::bigint * interval '1 second'), \
               claimed_at=transaction_timestamp() \
             FROM ready WHERE target.organization_id=ready.organization_id \
               AND target.outbox_id=ready.outbox_id \
             RETURNING target.organization_id,target.outbox_id,target.event_id,target.event,\
                       target.attempts,target.claim_token",
        )
        .bind(organization_id.as_str())
        .bind(i64::from(limit))
        .bind(claim_token.as_str())
        .bind(i64::from(lease_seconds))
        .fetch_all(&mut *tx)
        .await?;
        let claims = rows
            .into_iter()
            .map(|row| {
                Ok(OutboxClaim {
                    organization_id: organization_id.clone(),
                    outbox_id: row.try_get("outbox_id")?,
                    event_id: row.try_get("event_id")?,
                    event: row.try_get("event")?,
                    attempts: row.try_get("attempts")?,
                    claim_token: row.try_get("claim_token")?,
                })
            })
            .collect::<Result<Vec<_>, PostgresError>>()?;
        tx.commit().await?;
        Ok(claims)
    }

    /// Marks one exactly leased outbox row delivered.
    ///
    /// # Errors
    ///
    /// A missing/stale token fails rather than acknowledging another worker's lease.
    pub async fn acknowledge_outbox(
        &self,
        organization_id: &OrganizationId,
        outbox_id: &ContextQualifiedId,
        claim_token: &ContextQualifiedId,
    ) -> Result<(), PostgresError> {
        self.finish_outbox(
            organization_id,
            outbox_id,
            claim_token,
            "delivered_at=transaction_timestamp(),terminal_reason_code=NULL",
            None,
        )
        .await
    }

    /// Releases one exact lease for bounded delayed retry.
    ///
    /// # Errors
    ///
    /// Delay must be 1 second..=24 hours and the lease token must still match.
    pub async fn retry_outbox(
        &self,
        organization_id: &OrganizationId,
        outbox_id: &ContextQualifiedId,
        claim_token: &ContextQualifiedId,
        delay_seconds: u32,
        reason_code: &str,
    ) -> Result<(), PostgresError> {
        if delay_seconds == 0 || delay_seconds > 86_400 || !valid_reason_code(reason_code) {
            return Err(PostgresError::InvalidDeliveryBound);
        }
        let mut tx = self.pool.begin().await?;
        set_tenant(&mut tx, organization_id).await?;
        let changed = sqlx::query(
            "UPDATE transactional_outbox SET attempts=attempts+1, \
             next_attempt_at=transaction_timestamp()+($4::bigint * interval '1 second'), \
             last_error_code=$5,claim_token=NULL,claim_expires_at=NULL \
             WHERE organization_id=$1 AND outbox_id=$2 AND claim_token=$3 \
               AND delivered_at IS NULL AND dead_lettered_at IS NULL",
        )
        .bind(organization_id.as_str())
        .bind(outbox_id.as_str())
        .bind(claim_token.as_str())
        .bind(i64::from(delay_seconds))
        .bind(reason_code)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        require_claim(changed)?;
        tx.commit().await?;
        Ok(())
    }

    /// Moves one exactly leased outbox row to terminal relay failure.
    ///
    /// # Errors
    ///
    /// Requires a bounded reason code and the current claim token.
    pub async fn dead_letter_outbox(
        &self,
        organization_id: &OrganizationId,
        outbox_id: &ContextQualifiedId,
        claim_token: &ContextQualifiedId,
        reason_code: &str,
    ) -> Result<(), PostgresError> {
        if !valid_reason_code(reason_code) {
            return Err(PostgresError::InvalidDeliveryBound);
        }
        self.finish_outbox(
            organization_id,
            outbox_id,
            claim_token,
            "dead_lettered_at=transaction_timestamp(),terminal_reason_code=$4",
            Some(reason_code),
        )
        .await
    }

    async fn finish_outbox(
        &self,
        organization_id: &OrganizationId,
        outbox_id: &ContextQualifiedId,
        claim_token: &ContextQualifiedId,
        assignment: &str,
        reason: Option<&str>,
    ) -> Result<(), PostgresError> {
        let mut tx = self.pool.begin().await?;
        set_tenant(&mut tx, organization_id).await?;
        let statement = format!(
            "UPDATE transactional_outbox SET {assignment},claim_token=NULL,claim_expires_at=NULL \
             WHERE organization_id=$1 AND outbox_id=$2 AND claim_token=$3 \
               AND delivered_at IS NULL AND dead_lettered_at IS NULL"
        );
        let mut query = sqlx::query(&statement)
            .bind(organization_id.as_str())
            .bind(outbox_id.as_str())
            .bind(claim_token.as_str());
        if let Some(reason) = reason {
            query = query.bind(reason);
        }
        let changed = query.execute(&mut *tx).await?.rows_affected();
        require_claim(changed)?;
        tx.commit().await?;
        Ok(())
    }

    /// Applies consumer-owned SQL and inbox/checkpoint state in one transaction.
    ///
    /// The effect is not invoked for duplicates or gaps. Context code may use
    /// only its own tables through the supplied least-privilege connection.
    ///
    /// # Errors
    ///
    /// Conflicting identity/sequence, SQL failure, or effect failure rolls back
    /// every write including the inbox fact.
    #[allow(clippy::too_many_lines)]
    pub async fn consume_inbox_atomic<F>(
        &self,
        event: &PostgresInboxEvent,
        effect: F,
    ) -> Result<InboxOutcome, PostgresError>
    where
        F: for<'a> FnOnce(&'a mut PgConnection) -> ConsumerEffect<'a> + Send,
    {
        let schema_major = i32::try_from(
            event
                .schema_version
                .semver()
                .map_err(|_| PostgresError::InboxIdentityConflict)?
                .major,
        )
        .map_err(|_| PostgresError::NumericRange)?;
        let sequence = to_i64(event.aggregate_sequence.get())?;
        let mut tx = self.pool.begin().await?;
        set_tenant(&mut tx, &event.organization_id).await?;

        let stored: Option<String> = sqlx::query_scalar(
            "SELECT envelope_digest FROM durable_inbox WHERE organization_id=$1 \
             AND consumer=$2 AND handler_version=$3 AND producer=$4 \
             AND event_id=$5 AND schema_major=$6 FOR UPDATE",
        )
        .bind(event.organization_id.as_str())
        .bind(&event.consumer)
        .bind(event.handler_version.as_str())
        .bind(&event.producer)
        .bind(event.event_id.as_str())
        .bind(schema_major)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(stored) = stored {
            return if stored == event.envelope_digest.to_string() {
                Ok(InboxOutcome::Duplicate)
            } else {
                Err(PostgresError::InboxIdentityConflict)
            };
        }

        let expected: i64 = sqlx::query_scalar(
            "INSERT INTO delivery_stream_checkpoints \
             (organization_id,consumer,handler_version,producer,aggregate_type,aggregate_id,next_sequence) \
             VALUES ($1,$2,$3,$4,$5,$6,1) ON CONFLICT \
             (organization_id,consumer,handler_version,producer,aggregate_type,aggregate_id) \
             DO UPDATE SET updated_at=delivery_stream_checkpoints.updated_at \
             RETURNING next_sequence",
        )
        .bind(event.organization_id.as_str())
        .bind(&event.consumer)
        .bind(event.handler_version.as_str())
        .bind(&event.producer)
        .bind(&event.aggregate_type)
        .bind(event.aggregate_id.as_str())
        .fetch_one(&mut *tx)
        .await?;
        if sequence < expected {
            return Err(PostgresError::InboxSequenceConflict);
        }
        if sequence > expected {
            let changed = sqlx::query(
                "INSERT INTO delivery_held_events \
                 (organization_id,consumer,handler_version,producer,event_id,schema_name,schema_version,\
                  schema_major,aggregate_type,aggregate_id,aggregate_sequence,classification,\
                  envelope_digest,event) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) \
                 ON CONFLICT (organization_id,consumer,handler_version,producer,event_id,schema_major) \
                 DO UPDATE SET envelope_digest=EXCLUDED.envelope_digest \
                 WHERE delivery_held_events.envelope_digest=EXCLUDED.envelope_digest",
            )
            .bind(event.organization_id.as_str())
            .bind(&event.consumer)
            .bind(event.handler_version.as_str())
            .bind(&event.producer)
            .bind(event.event_id.as_str())
            .bind(event.schema_name.as_str())
            .bind(event.schema_version.as_str())
            .bind(schema_major)
            .bind(&event.aggregate_type)
            .bind(event.aggregate_id.as_str())
            .bind(sequence)
            .bind(data_class(event.classification))
            .bind(event.envelope_digest.to_string())
            .bind(&event.event)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed == 0 {
                return Err(PostgresError::InboxIdentityConflict);
            }
            tx.commit().await?;
            return Ok(InboxOutcome::HeldForGap {
                expected: u64::try_from(expected).map_err(|_| PostgresError::NumericRange)?,
            });
        }

        effect(&mut tx).await?;
        sqlx::query(
            "INSERT INTO durable_inbox \
             (organization_id,consumer,handler_version,producer,event_id,schema_major,aggregate_type,\
              aggregate_id,aggregate_sequence,classification,envelope_digest) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(event.organization_id.as_str())
        .bind(&event.consumer)
        .bind(event.handler_version.as_str())
        .bind(&event.producer)
        .bind(event.event_id.as_str())
        .bind(schema_major)
        .bind(&event.aggregate_type)
        .bind(event.aggregate_id.as_str())
        .bind(sequence)
        .bind(data_class(event.classification))
        .bind(event.envelope_digest.to_string())
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE delivery_stream_checkpoints SET next_sequence=$7,updated_at=transaction_timestamp() \
             WHERE organization_id=$1 AND consumer=$2 AND handler_version=$3 AND producer=$4 \
               AND aggregate_type=$5 AND aggregate_id=$6 AND next_sequence=$8",
        )
        .bind(event.organization_id.as_str())
        .bind(&event.consumer)
        .bind(event.handler_version.as_str())
        .bind(&event.producer)
        .bind(&event.aggregate_type)
        .bind(event.aggregate_id.as_str())
        .bind(sequence.checked_add(1).ok_or(PostgresError::NumericRange)?)
        .bind(sequence)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE FROM delivery_held_events WHERE organization_id=$1 AND consumer=$2 \
             AND handler_version=$3 AND producer=$4 AND event_id=$5 AND schema_major=$6",
        )
        .bind(event.organization_id.as_str())
        .bind(&event.consumer)
        .bind(event.handler_version.as_str())
        .bind(&event.producer)
        .bind(event.event_id.as_str())
        .bind(schema_major)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(InboxOutcome::Applied)
    }

    /// Returns tenant-safe delivery drift counts under one database snapshot.
    ///
    /// # Errors
    ///
    /// Database failures return a stable adapter error.
    pub async fn reconcile_delivery(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<DeliveryReconciliation, PostgresError> {
        let mut tx = self.pool.begin().await?;
        set_tenant(&mut tx, organization_id).await?;
        let ready_outbox = sqlx::query_scalar(
            "SELECT count(*) FROM transactional_outbox WHERE organization_id=$1 \
             AND delivered_at IS NULL AND dead_lettered_at IS NULL \
             AND available_at<=transaction_timestamp() AND next_attempt_at<=transaction_timestamp() \
             AND (claim_token IS NULL OR claim_expires_at<=transaction_timestamp())",
        )
        .bind(organization_id.as_str())
        .fetch_one(&mut *tx)
        .await?;
        let held_events =
            count_for_tenant(&mut tx, "delivery_held_events", organization_id).await?;
        let open_dead_letters: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM delivery_dead_letters WHERE organization_id=$1 AND resolved_at IS NULL",
        )
        .bind(organization_id.as_str())
        .fetch_one(&mut *tx)
        .await?;
        let pending_replays: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM delivery_replay_audit WHERE organization_id=$1 AND completed_at IS NULL",
        )
        .bind(organization_id.as_str())
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(DeliveryReconciliation {
            ready_outbox,
            held_events,
            open_dead_letters,
            pending_replays,
        })
    }
}

async fn set_tenant(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: &OrganizationId,
) -> Result<(), PostgresError> {
    sqlx::query("SELECT set_config('app.organization_id', $1, true)")
        .bind(organization_id.as_str())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

fn require_claim(changed: u64) -> Result<(), PostgresError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(PostgresError::OutboxClaimLost)
    }
}

fn valid_reason_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && !value.starts_with('_')
        && !value.ends_with('_')
        && !value.contains("__")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

const fn data_class(value: DataClass) -> &'static str {
    match value {
        DataClass::Public => "public",
        DataClass::Internal => "internal",
        DataClass::Confidential => "confidential",
        DataClass::RestrictedSecurity => "restricted_security",
    }
}

async fn count_for_tenant(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    table: &str,
    organization_id: &OrganizationId,
) -> Result<i64, PostgresError> {
    debug_assert_eq!(table, "delivery_held_events");
    Ok(
        sqlx::query_scalar("SELECT count(*) FROM delivery_held_events WHERE organization_id=$1")
            .bind(organization_id.as_str())
            .fetch_one(&mut **tx)
            .await?,
    )
}

fn to_i64(value: u64) -> Result<i64, PostgresError> {
    i64::try_from(value).map_err(|_| PostgresError::NumericRange)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;
    #[test]
    fn migration_contains_atomicity_and_tenant_isolation_primitives() {
        let migration = include_str!("../migrations/0001_p04_metadata.sql");
        let delivery = include_str!("../migrations/0002_delivery_reliability.sql");
        for required in [
            "CREATE TABLE aggregate_snapshots",
            "CREATE TABLE aggregate_events",
            "CREATE TABLE transactional_outbox",
            "CREATE TABLE durable_inbox",
            "CREATE TABLE delivery_dead_letters",
            "CREATE TABLE idempotency_results",
            "CREATE TABLE artifact_descriptors",
            "ENABLE ROW LEVEL SECURITY",
            "CREATE POLICY tenant_isolation",
        ] {
            assert!(migration.contains(required), "missing {required}");
        }
        assert!(
            include_str!("../migrations/0001_p04_metadata.down.sql")
                .contains("DROP TABLE IF EXISTS aggregate_snapshots")
        );
        for required in [
            "CREATE TABLE delivery_stream_checkpoints",
            "CREATE TABLE delivery_held_events",
            "CREATE TABLE delivery_replay_audit",
            "durable_inbox_stream_position",
            "delivery_dead_letter_event_identity",
            "transactional_outbox_expired_claims",
            "claim_expires_at",
            "next_attempt_at",
            "FORCE ROW LEVEL SECURITY",
        ] {
            assert!(delivery.contains(required), "missing {required}");
        }
        let rollback = include_str!("../migrations/0002_delivery_reliability.down.sql");
        for required in [
            "DROP TABLE IF EXISTS delivery_replay_audit",
            "DROP TABLE IF EXISTS delivery_held_events",
            "DROP TABLE IF EXISTS delivery_stream_checkpoints",
            "DROP COLUMN IF EXISTS claim_token",
        ] {
            assert!(rollback.contains(required), "missing rollback {required}");
        }
    }

    #[test]
    fn adapter_sql_declares_nonblocking_claim_and_exact_lease_ownership() {
        let source = include_str!("postgres.rs");
        for required in [
            "FOR UPDATE SKIP LOCKED",
            "claim_expires_at <= transaction_timestamp()",
            "outbox_id=$2 AND claim_token=$3",
            "effect(&mut *tx).await?",
            "INSERT INTO durable_inbox",
            "INSERT INTO delivery_stream_checkpoints",
        ] {
            assert!(
                source.contains(required),
                "missing adapter invariant {required}"
            );
        }
    }

    #[tokio::test]
    async fn delivery_bounds_fail_before_database_access() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1:1/unused")
            .unwrap();
        let store = PostgresMetadataStore::new(pool);
        let organization = OrganizationId::new("00000000").unwrap();
        let token = ContextQualifiedId::new("claim", "00000000").unwrap();
        assert!(matches!(
            store.claim_outbox(&organization, &token, 0, 30).await,
            Err(PostgresError::InvalidDeliveryBound)
        ));
        assert!(matches!(
            store.claim_outbox(&organization, &token, 1, 3_601).await,
            Err(PostgresError::InvalidDeliveryBound)
        ));
        let outbox = ContextQualifiedId::new("outbox", "00000000").unwrap();
        assert!(matches!(
            store
                .retry_outbox(&organization, &outbox, &token, 0, "retry")
                .await,
            Err(PostgresError::InvalidDeliveryBound)
        ));
        assert!(matches!(
            store
                .dead_letter_outbox(&organization, &outbox, &token, "provider error: secret")
                .await,
            Err(PostgresError::InvalidDeliveryBound)
        ));
    }

    fn mutation(digest_input: &str) -> PostgresMutation {
        PostgresMutation {
            organization_id: OrganizationId::new("00000000").unwrap(),
            aggregate_type: "test-aggregate".into(),
            aggregate_id: ContextQualifiedId::new("test", "00000000").unwrap(),
            expected_version: None,
            state_schema: SchemaName::parse("dev.cauterizer.test.state").unwrap(),
            state_version: SchemaVersion::parse("1.0.0").unwrap(),
            state: serde_json::json!({"state":"created"}),
            events: vec![PostgresEvent {
                sequence: AggregateSequence::new(1).unwrap(),
                event_id: ContextQualifiedId::new("event", "00000000").unwrap(),
                schema_name: SchemaName::parse("dev.cauterizer.test.created").unwrap(),
                schema_version: SchemaVersion::parse("1.0.0").unwrap(),
                payload: serde_json::json!({"type":"created"}),
                occurred_at: UtcInstant::parse("2026-07-23T00:00:00Z").unwrap(),
                correlation_id: CorrelationId::new("00000000").unwrap(),
                causation_id: CausationId::new("00000000").unwrap(),
                outbox_id: ContextQualifiedId::new("outbox", "00000000").unwrap(),
            }],
            command_scope: "test.create".into(),
            idempotency_key: IdempotencyKey::new("create-00000000").unwrap(),
            request_digest: Sha256Digest::of_bytes(digest_input),
            result_schema: SchemaName::parse("dev.cauterizer.test.result").unwrap(),
            result: serde_json::json!({"id":"test_00000000"}),
            result_expires_at: UtcInstant::parse("2027-07-23T00:00:00Z").unwrap(),
            required_artifacts: Vec::new(),
        }
    }

    fn inbox_event(sequence: u64, event_suffix: &str) -> PostgresInboxEvent {
        PostgresInboxEvent {
            organization_id: OrganizationId::new("00000000").unwrap(),
            consumer: "remediation-runs".into(),
            handler_version: SchemaVersion::parse("1.0.0").unwrap(),
            producer: "advisory-intake".into(),
            event_id: ContextQualifiedId::new("event", event_suffix).unwrap(),
            schema_name: SchemaName::parse("dev.cauterizer.advisory.snapshotted").unwrap(),
            schema_version: SchemaVersion::parse("1.0.0").unwrap(),
            aggregate_type: "advisory-record".into(),
            aggregate_id: ContextQualifiedId::new("advisory", "00000000").unwrap(),
            aggregate_sequence: AggregateSequence::new(sequence).unwrap(),
            classification: DataClass::Internal,
            envelope_digest: Sha256Digest::of_bytes(format!("event-{sequence}")),
            event: serde_json::json!({"sequence":sequence}),
        }
    }

    fn no_op_effect(connection: &mut PgConnection) -> ConsumerEffect<'_> {
        Box::pin(async move {
            sqlx::query("SELECT 1").execute(connection).await?;
            Ok(())
        })
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn postgres_transaction_round_trip_when_database_is_configured() {
        let url = match std::env::var("CAUTERIZER_TEST_POSTGRES_URL") {
            Ok(url) => url,
            Err(error) if std::env::var_os("CAUTERIZER_REQUIRE_POSTGRES_TESTS").is_some() => {
                panic!(
                    "CAUTERIZER_TEST_POSTGRES_URL is required when \
                     CAUTERIZER_REQUIRE_POSTGRES_TESTS is set: {error}"
                );
            }
            Err(_) => return,
        };
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let store = PostgresMetadataStore::new(pool.clone());
        store.migrate().await.unwrap();
        let mut invalid_reference = mutation("artifact-reference");
        invalid_reference
            .required_artifacts
            .push(ArtifactReference {
                access_domain: AccessDomain::Verifier,
                digest: Sha256Digest::of_bytes("not-committed"),
            });
        assert!(matches!(
            store.execute(invalid_reference).await,
            Err(PostgresError::UncommittedArtifact)
        ));
        assert!(matches!(
            store.execute(mutation("same")).await.unwrap(),
            PostgresOutcome::Committed { version: 1, .. }
        ));
        assert!(matches!(
            store.execute(mutation("same")).await.unwrap(),
            PostgresOutcome::Replayed(_)
        ));
        assert!(matches!(
            store.execute(mutation("different")).await,
            Err(PostgresError::IdempotencyConflict)
        ));
        let counts: (i64, i64, i64, i64) = (
            sqlx::query_scalar("SELECT count(*) FROM aggregate_snapshots")
                .fetch_one(&pool)
                .await
                .unwrap(),
            sqlx::query_scalar("SELECT count(*) FROM aggregate_events")
                .fetch_one(&pool)
                .await
                .unwrap(),
            sqlx::query_scalar("SELECT count(*) FROM transactional_outbox")
                .fetch_one(&pool)
                .await
                .unwrap(),
            sqlx::query_scalar("SELECT count(*) FROM idempotency_results")
                .fetch_one(&pool)
                .await
                .unwrap(),
        );
        assert_eq!(counts, (1, 1, 1, 1));

        let first_token = ContextQualifiedId::new("claim", "00000000").unwrap();
        let claims = store
            .claim_outbox(
                &OrganizationId::new("00000000").unwrap(),
                &first_token,
                10,
                30,
            )
            .await
            .unwrap();
        assert_eq!(claims.len(), 1);
        let outbox_id: ContextQualifiedId = claims[0].outbox_id.parse().unwrap();
        store
            .retry_outbox(
                &OrganizationId::new("00000000").unwrap(),
                &outbox_id,
                &first_token,
                1,
                "transient_dependency",
            )
            .await
            .unwrap();
        sqlx::query(
            "UPDATE transactional_outbox SET next_attempt_at=transaction_timestamp() \
             WHERE organization_id='org_00000000'",
        )
        .execute(&pool)
        .await
        .unwrap();
        let second_token = ContextQualifiedId::new("claim", "11111111").unwrap();
        let claims = store
            .claim_outbox(
                &OrganizationId::new("00000000").unwrap(),
                &second_token,
                10,
                30,
            )
            .await
            .unwrap();
        assert_eq!(claims[0].attempts, 1);
        store
            .acknowledge_outbox(
                &OrganizationId::new("00000000").unwrap(),
                &outbox_id,
                &second_token,
            )
            .await
            .unwrap();
        assert!(matches!(
            store
                .acknowledge_outbox(
                    &OrganizationId::new("00000000").unwrap(),
                    &outbox_id,
                    &first_token,
                )
                .await,
            Err(PostgresError::OutboxClaimLost)
        ));

        let second = inbox_event(2, "00000002");
        assert_eq!(
            store
                .consume_inbox_atomic(&second, no_op_effect)
                .await
                .unwrap(),
            InboxOutcome::HeldForGap { expected: 1 }
        );
        assert_eq!(
            store
                .reconcile_delivery(&OrganizationId::new("00000000").unwrap())
                .await
                .unwrap()
                .held_events,
            1
        );
        let first = inbox_event(1, "00000001");
        assert_eq!(
            store
                .consume_inbox_atomic(&first, no_op_effect)
                .await
                .unwrap(),
            InboxOutcome::Applied
        );
        assert_eq!(
            store
                .consume_inbox_atomic(&second, no_op_effect)
                .await
                .unwrap(),
            InboxOutcome::Applied
        );
        assert_eq!(
            store
                .consume_inbox_atomic(&second, no_op_effect)
                .await
                .unwrap(),
            InboxOutcome::Duplicate
        );
    }

    #[tokio::test]
    async fn postgres_artifact_reconciliation_snapshot_when_database_is_configured() {
        let url = match std::env::var("CAUTERIZER_TEST_POSTGRES_URL") {
            Ok(url) => url,
            Err(error) if std::env::var_os("CAUTERIZER_REQUIRE_POSTGRES_TESTS").is_some() => {
                panic!(
                    "CAUTERIZER_TEST_POSTGRES_URL is required when \
                     CAUTERIZER_REQUIRE_POSTGRES_TESTS is set: {error}"
                );
            }
            Err(_) => return,
        };
        let pool = PgPoolOptions::new().connect(&url).await.unwrap();
        let store = PostgresMetadataStore::new(pool.clone());
        store.migrate().await.unwrap();
        let organization = OrganizationId::new("artifact0").unwrap();
        let digest = Sha256Digest::of_bytes("postgres-s3-reconciliation");
        sqlx::query(
            "INSERT INTO artifact_descriptors \
             (organization_id,access_domain,digest,size_bytes,media_type,schema_name,\
              schema_version,classification,region,retention_days,legal_hold,\
              encryption_key_ref,producer,created_at) \
             VALUES ($1,'verifier',$2,26,'application/octet-stream',\
              'dev.cauterizer.artifact.payload','1.0.0','restricted_security',\
              'us-east-1',30,false,'key_artifact0','verification',\
              '2026-07-23T00:00:00Z'::timestamptz) \
             ON CONFLICT (organization_id,access_domain,digest) DO UPDATE SET \
              tombstoned_at=NULL,size_bytes=EXCLUDED.size_bytes",
        )
        .bind(organization.as_str())
        .bind(digest.to_string())
        .execute(&pool)
        .await
        .unwrap();
        let expectations = store
            .live_artifact_expectations(&organization)
            .await
            .unwrap();
        assert_eq!(
            expectations,
            vec![StoredObjectExpectation {
                organization_id: organization.clone(),
                access_domain: AccessDomain::Verifier,
                digest,
                size: 26,
            }]
        );
        sqlx::query(
            "UPDATE artifact_descriptors SET tombstoned_at=transaction_timestamp(),\
             tombstone_reason='test_cleanup' WHERE organization_id=$1",
        )
        .bind(organization.as_str())
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            store
                .live_artifact_expectations(&organization)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
