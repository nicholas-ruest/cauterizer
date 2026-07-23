-- P04 transactional metadata baseline for PostgreSQL 17.
-- Every tenant-owned row includes organization_id; application roles must also
-- set `app.organization_id` so RLS independently enforces the tenant predicate.

CREATE TABLE aggregate_snapshots (
    organization_id text NOT NULL,
    aggregate_type text NOT NULL,
    aggregate_id text NOT NULL,
    version bigint NOT NULL CHECK (version > 0),
    schema_name text NOT NULL,
    schema_version text NOT NULL,
    state jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, aggregate_type, aggregate_id)
);

CREATE TABLE aggregate_events (
    organization_id text NOT NULL,
    aggregate_type text NOT NULL,
    aggregate_id text NOT NULL,
    aggregate_sequence bigint NOT NULL CHECK (aggregate_sequence > 0),
    event_id text NOT NULL,
    schema_name text NOT NULL,
    schema_version text NOT NULL,
    payload jsonb NOT NULL,
    occurred_at timestamptz NOT NULL,
    correlation_id text NOT NULL,
    causation_id text NOT NULL,
    PRIMARY KEY (organization_id, aggregate_type, aggregate_id, aggregate_sequence),
    UNIQUE (organization_id, event_id)
);

CREATE TABLE transactional_outbox (
    organization_id text NOT NULL,
    outbox_id text NOT NULL,
    event_id text NOT NULL,
    event jsonb NOT NULL,
    available_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    claimed_at timestamptz,
    delivered_at timestamptz,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error_code text,
    PRIMARY KEY (organization_id, outbox_id),
    UNIQUE (organization_id, event_id)
);
CREATE INDEX transactional_outbox_ready
    ON transactional_outbox (available_at, outbox_id)
    WHERE delivered_at IS NULL;

CREATE TABLE durable_inbox (
    organization_id text NOT NULL,
    consumer text NOT NULL,
    handler_version text NOT NULL,
    producer text NOT NULL,
    event_id text NOT NULL,
    schema_major integer NOT NULL CHECK (schema_major > 0),
    aggregate_type text NOT NULL,
    aggregate_id text NOT NULL,
    aggregate_sequence bigint NOT NULL CHECK (aggregate_sequence > 0),
    processed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, consumer, handler_version, producer, event_id, schema_major)
);

CREATE TABLE delivery_dead_letters (
    organization_id text NOT NULL,
    dead_letter_id text NOT NULL,
    consumer text NOT NULL,
    event jsonb NOT NULL,
    reason_code text NOT NULL,
    attempts integer NOT NULL CHECK (attempts > 0),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    resolved_at timestamptz,
    resolution_code text,
    PRIMARY KEY (organization_id, dead_letter_id)
);

CREATE TABLE idempotency_results (
    organization_id text NOT NULL,
    command_scope text NOT NULL,
    idempotency_key text NOT NULL,
    request_digest text NOT NULL,
    result_schema text NOT NULL,
    result jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id, command_scope, idempotency_key)
);

CREATE TABLE artifact_descriptors (
    organization_id text NOT NULL,
    access_domain text NOT NULL CHECK (access_domain IN ('tenant', 'acquisition', 'solver', 'verifier', 'evidence')),
    digest text NOT NULL,
    size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
    media_type text NOT NULL,
    schema_name text NOT NULL,
    schema_version text NOT NULL,
    classification text NOT NULL,
    region text NOT NULL,
    retention_days integer NOT NULL CHECK (retention_days > 0),
    legal_hold boolean NOT NULL DEFAULT false,
    encryption_key_ref text NOT NULL,
    producer text NOT NULL,
    created_at timestamptz NOT NULL,
    tombstoned_at timestamptz,
    tombstone_reason text,
    PRIMARY KEY (organization_id, access_domain, digest)
);

ALTER TABLE aggregate_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE aggregate_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE transactional_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE durable_inbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery_dead_letters ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE artifact_descriptors ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'aggregate_snapshots', 'aggregate_events', 'transactional_outbox',
    'durable_inbox', 'delivery_dead_letters', 'idempotency_results',
    'artifact_descriptors'
  ] LOOP
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (organization_id = current_setting(''app.organization_id'', true)) WITH CHECK (organization_id = current_setting(''app.organization_id'', true))',
      table_name
    );
  END LOOP;
END $$;
