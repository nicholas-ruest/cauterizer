//! Cross-context, at-least-once, per-aggregate-ordering-only proof for P14.
//!
//! DB-gated and self-skipping exactly like `postgres.rs`'s existing tests:
//! set `CAUTERIZER_TEST_POSTGRES_URL` to run it, or set
//! `CAUTERIZER_REQUIRE_POSTGRES_TESTS` to make its absence a hard failure.
//!
//! A simulated producer context (`remediation-runs`) publishes through the
//! transactional outbox, the generic dispatcher
//! (`cauterizer_infrastructure::dispatcher`) drives delivery, and a
//! simulated consumer context (`patch-proposals`) absorbs each event through
//! `consume_inbox_atomic`. Per the guidance documented on the `dispatcher`
//! module, the handler here reports a `HeldForGap` consumer outcome back to
//! the dispatcher as a retryable failure rather than success, so an
//! out-of-order event's outbox row stays claimable until its predecessor has
//! actually committed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use cauterizer_infrastructure::delivery::{FailureCode, HandlerFailure};
use cauterizer_infrastructure::dispatcher::{
    DispatchClaim, DispatchPolicy, HandlerFuture, PostgresDispatchPort, dispatch_batch,
};
use cauterizer_infrastructure::postgres::{
    ConsumerEffect, InboxOutcome, PostgresEvent, PostgresInboxEvent, PostgresMetadataStore,
    PostgresMutation, PostgresOutcome,
};
use cauterizer_syntax::classification::DataClass;
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{
    AggregateSequence, CausationId, ContextQualifiedId, CorrelationId, IdempotencyKey,
    OrganizationId,
};
use cauterizer_syntax::schema::{SchemaName, SchemaVersion};
use cauterizer_syntax::time::UtcInstant;
use sqlx::PgConnection;
use sqlx::postgres::PgPoolOptions;

#[derive(Clone)]
struct EventMeta {
    type_name: String,
    id: ContextQualifiedId,
    sequence: AggregateSequence,
}

fn no_op_effect(connection: &mut PgConnection) -> ConsumerEffect<'_> {
    Box::pin(async move {
        sqlx::query("SELECT 1").execute(connection).await?;
        Ok(())
    })
}

/// A fresh, lowercase-hex organization suffix so repeated runs of this test
/// against a real, non-reset `PostgreSQL` instance never collide with a
/// prior run's rows: every UNIQUE/PRIMARY KEY constraint touched here is
/// scoped by `organization_id` first.
fn unique_org_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos()
        .into();
    format!("{nanos:0>8x}")
}

#[allow(clippy::too_many_arguments)]
fn publish(
    organization: &OrganizationId,
    aggregate_type: &str,
    aggregate_id: &ContextQualifiedId,
    expected_version: Option<u64>,
    sequence: u64,
    event_suffix: &str,
    outbox_suffix: &str,
    idempotency_suffix: &str,
) -> PostgresMutation {
    PostgresMutation {
        organization_id: organization.clone(),
        aggregate_type: aggregate_type.to_owned(),
        aggregate_id: aggregate_id.clone(),
        expected_version,
        state_schema: SchemaName::parse("dev.cauterizer.test.state").unwrap(),
        state_version: SchemaVersion::parse("1.0.0").unwrap(),
        state: serde_json::json!({"sequence": sequence}),
        events: vec![PostgresEvent {
            sequence: AggregateSequence::new(sequence).unwrap(),
            event_id: ContextQualifiedId::new("event", event_suffix).unwrap(),
            schema_name: SchemaName::parse("dev.cauterizer.remediation-runs.advanced").unwrap(),
            schema_version: SchemaVersion::parse("1.0.0").unwrap(),
            payload: serde_json::json!({"sequence": sequence}),
            occurred_at: UtcInstant::parse("2026-07-23T00:00:00Z").unwrap(),
            correlation_id: CorrelationId::new("00000000").unwrap(),
            causation_id: CausationId::new("00000000").unwrap(),
            outbox_id: ContextQualifiedId::new("outbox", outbox_suffix).unwrap(),
        }],
        command_scope: "p14-integration.publish".into(),
        idempotency_key: IdempotencyKey::new(format!("p14-integration-{idempotency_suffix}"))
            .unwrap(),
        request_digest: Sha256Digest::of_bytes(event_suffix),
        result_schema: SchemaName::parse("dev.cauterizer.test.result").unwrap(),
        result: serde_json::json!({"event_id": event_suffix}),
        result_expires_at: UtcInstant::parse("2027-07-23T00:00:00Z").unwrap(),
        required_artifacts: Vec::new(),
    }
}

fn inbox_event(claim: &DispatchClaim, info: &EventMeta) -> PostgresInboxEvent {
    PostgresInboxEvent {
        organization_id: claim.organization_id.clone(),
        consumer: "patch-proposals".into(),
        handler_version: SchemaVersion::parse("1.0.0").unwrap(),
        producer: "remediation-runs".into(),
        event_id: claim.event_id.parse().expect("valid event id"),
        schema_name: SchemaName::parse("dev.cauterizer.remediation-runs.advanced").unwrap(),
        schema_version: SchemaVersion::parse("1.0.0").unwrap(),
        aggregate_type: info.type_name.clone(),
        aggregate_id: info.id.clone(),
        aggregate_sequence: info.sequence,
        classification: DataClass::Internal,
        envelope_digest: Sha256Digest::of_bytes(claim.event_id.as_bytes()),
        event: claim.event.clone(),
    }
}

/// Builds a fresh handler closure sharing the given counters/state, so the
/// same "flaky once, then succeeds" event behaves identically across
/// separate `dispatch_batch` passes (simulating a crash/retry).
fn make_handler(
    store: PostgresMetadataStore,
    meta: Arc<HashMap<String, EventMeta>>,
    invocation_counts: Arc<Mutex<HashMap<String, u32>>>,
) -> impl FnMut(DispatchClaim) -> HandlerFuture {
    move |claim: DispatchClaim| {
        let store = store.clone();
        let meta = Arc::clone(&meta);
        let invocation_counts = Arc::clone(&invocation_counts);
        Box::pin(async move {
            let attempt_number = {
                let mut counts = invocation_counts.lock().unwrap();
                let count = counts.entry(claim.event_id.clone()).or_insert(0);
                *count += 1;
                *count
            };

            // Simulate one transient crash/retry for the first aggregate's
            // first event, and only that event's first attempt.
            if claim.event_id.as_str() == "event_a1000001" && attempt_number == 1 {
                let code = FailureCode::parse("simulated_transient_crash").unwrap();
                return Err(HandlerFailure::Retryable(code));
            }

            let info = meta
                .get(claim.event_id.as_str())
                .expect("event registered by this test");
            let event = inbox_event(&claim, info);
            match store.consume_inbox_atomic(&event, no_op_effect).await {
                Ok(InboxOutcome::Applied | InboxOutcome::Duplicate) => Ok(()),
                Ok(InboxOutcome::HeldForGap { .. }) => {
                    // Per `dispatcher`'s module docs: a missing predecessor is
                    // reported as retryable, never as success.
                    let code = FailureCode::parse("predecessor_pending").unwrap();
                    Err(HandlerFailure::Retryable(code))
                }
                Err(_) => {
                    let code = FailureCode::parse("consumer_effect_failed").unwrap();
                    Err(HandlerFailure::Retryable(code))
                }
            }
        })
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn outbox_dispatch_is_at_least_once_and_orders_only_within_one_aggregate() {
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
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    let store = PostgresMetadataStore::new(pool.clone());
    store.migrate().await.unwrap();

    let organization = OrganizationId::new(&unique_org_suffix()).unwrap();
    let aggregate_a = ContextQualifiedId::new("remediation-run", "aaaaaaaa").unwrap();
    let aggregate_b = ContextQualifiedId::new("remediation-run", "bbbbbbbb").unwrap();

    // Publish A1, B1, A2 (A2 depends on A1) from the simulated producer,
    // deliberately interleaved and outbox-ordered A1 < B1 < A2 so a single
    // claim batch contains all three.
    assert!(matches!(
        store
            .execute(publish(
                &organization,
                "remediation-run",
                &aggregate_a,
                None,
                1,
                "a1000001",
                "00000001",
                "a1",
            ))
            .await
            .unwrap(),
        PostgresOutcome::Committed { version: 1, .. }
    ));
    assert!(matches!(
        store
            .execute(publish(
                &organization,
                "remediation-run",
                &aggregate_b,
                None,
                1,
                "b1000001",
                "00000002",
                "b1",
            ))
            .await
            .unwrap(),
        PostgresOutcome::Committed { version: 1, .. }
    ));
    assert!(matches!(
        store
            .execute(publish(
                &organization,
                "remediation-run",
                &aggregate_a,
                Some(1),
                2,
                "a2000002",
                "00000003",
                "a2",
            ))
            .await
            .unwrap(),
        PostgresOutcome::Committed { version: 2, .. }
    ));

    let mut meta = HashMap::new();
    meta.insert(
        "event_a1000001".to_owned(),
        EventMeta {
            type_name: "remediation-run".into(),
            id: aggregate_a.clone(),
            sequence: AggregateSequence::new(1).unwrap(),
        },
    );
    meta.insert(
        "event_b1000001".to_owned(),
        EventMeta {
            type_name: "remediation-run".into(),
            id: aggregate_b.clone(),
            sequence: AggregateSequence::new(1).unwrap(),
        },
    );
    meta.insert(
        "event_a2000002".to_owned(),
        EventMeta {
            type_name: "remediation-run".into(),
            id: aggregate_a.clone(),
            sequence: AggregateSequence::new(2).unwrap(),
        },
    );
    let meta = Arc::new(meta);
    let invocation_counts = Arc::new(Mutex::new(HashMap::new()));

    let port = PostgresDispatchPort::new(store.clone());
    let policy = DispatchPolicy::new(10, 30, 5, 1).unwrap();

    // Pass 1: A1 fails transiently (simulated crash/retry) and is retried;
    // A2 is held for its missing predecessor and is also retried; B1, on an
    // entirely unrelated aggregate, is applied and acknowledged immediately.
    let report1 = dispatch_batch(
        &port,
        &organization,
        "claim_00000pass1",
        policy,
        make_handler(
            store.clone(),
            Arc::clone(&meta),
            Arc::clone(&invocation_counts),
        ),
    )
    .await
    .unwrap();
    assert_eq!(report1.acknowledged, 1, "only b1 applies on the first pass");
    assert_eq!(
        report1.retried, 2,
        "a1 (transient) and a2 (held) are retried"
    );
    assert_eq!(report1.dead_lettered, 0);

    // (b) Per-aggregate-only ordering: aggregate B's stream is already fully
    // applied while aggregate A's stream is still incomplete.
    let applied_b1: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM durable_inbox WHERE organization_id=$1 AND event_id=$2)",
    )
    .bind(organization.as_str())
    .bind("event_b1000001")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(applied_b1, "b1 does not wait on aggregate a's stream");
    let reconciliation = store.reconcile_delivery(&organization).await.unwrap();
    assert_eq!(reconciliation.held_events, 1, "a2 is held pending a1");

    // Force the retry delay to have elapsed instead of sleeping in the test.
    sqlx::query("UPDATE transactional_outbox SET next_attempt_at=transaction_timestamp() WHERE organization_id=$1")
        .bind(organization.as_str())
        .execute(&pool)
        .await
        .unwrap();

    // Pass 2: A1 now succeeds (its simulated crash was transient), and A2 -
    // reprocessed after A1 committed within this same pass - now applies too.
    let report2 = dispatch_batch(
        &port,
        &organization,
        "claim_00000pass2",
        policy,
        make_handler(
            store.clone(),
            Arc::clone(&meta),
            Arc::clone(&invocation_counts),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        report2.acknowledged, 2,
        "a1 and a2 both apply on the second pass"
    );
    assert_eq!(report2.retried, 0);
    assert_eq!(report2.dead_lettered, 0);

    // (a) At-least-once delivery survived the simulated crash/retry: a1 was
    // invoked twice (one failure, one success), never lost.
    {
        let counts = invocation_counts.lock().unwrap();
        assert_eq!(counts.get("event_a1000001").copied(), Some(2));
        assert_eq!(counts.get("event_a2000002").copied(), Some(2));
        assert_eq!(counts.get("event_b1000001").copied(), Some(1));
    }

    // Every event ends up durably applied exactly once.
    for event_id in ["event_a1000001", "event_b1000001", "event_a2000002"] {
        let applied_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM durable_inbox WHERE organization_id=$1 AND event_id=$2",
        )
        .bind(organization.as_str())
        .bind(event_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(applied_count, 1, "{event_id} applied exactly once");
    }

    // (c) Duplicate redelivery of an already-acknowledged event is a no-op,
    // via `consume_inbox_atomic`'s existing idempotency.
    let phantom_claim = DispatchClaim {
        organization_id: organization.clone(),
        outbox_id: "outbox_00000001".into(),
        event_id: "event_a1000001".into(),
        event: serde_json::json!({"sequence": 1}),
        attempts: 0,
        claim_token: "unused".into(),
    };
    let duplicate_event = inbox_event(&phantom_claim, meta.get("event_a1000001").unwrap());
    assert_eq!(
        store
            .consume_inbox_atomic(&duplicate_event, no_op_effect)
            .await
            .unwrap(),
        InboxOutcome::Duplicate
    );
    let applied_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM durable_inbox WHERE organization_id=$1 AND event_id=$2",
    )
    .bind(organization.as_str())
    .bind("event_a1000001")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        applied_count, 1,
        "duplicate redelivery did not double-apply"
    );
}
