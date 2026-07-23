-- P04 durable delivery state. This migration makes every transition represented
-- by `delivery::ReliableInbox` persistable without storing tenant-ambiguous keys.

ALTER TABLE transactional_outbox
    ADD COLUMN claim_token text,
    ADD COLUMN claim_expires_at timestamptz,
    ADD COLUMN next_attempt_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    ADD COLUMN dead_lettered_at timestamptz,
    ADD COLUMN terminal_reason_code text,
    ADD CONSTRAINT outbox_claim_shape CHECK (
        (claim_token IS NULL AND claim_expires_at IS NULL)
        OR (claim_token IS NOT NULL AND claim_expires_at IS NOT NULL)
    ),
    ADD CONSTRAINT outbox_terminal_shape CHECK (
        NOT (delivered_at IS NOT NULL AND dead_lettered_at IS NOT NULL)
    );

DROP INDEX transactional_outbox_ready;
CREATE INDEX transactional_outbox_ready
    ON transactional_outbox (next_attempt_at, available_at, outbox_id)
    WHERE delivered_at IS NULL AND dead_lettered_at IS NULL;
CREATE INDEX transactional_outbox_expired_claims
    ON transactional_outbox (claim_expires_at, outbox_id)
    WHERE delivered_at IS NULL AND dead_lettered_at IS NULL AND claim_token IS NOT NULL;

ALTER TABLE durable_inbox
    ADD COLUMN classification text NOT NULL CHECK (
        classification IN ('public', 'internal', 'confidential', 'restricted_security')
    ),
    ADD COLUMN envelope_digest text NOT NULL CHECK (
        envelope_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    ADD CONSTRAINT durable_inbox_stream_position UNIQUE (
        organization_id, consumer, handler_version, producer,
        aggregate_type, aggregate_id, aggregate_sequence
    );

CREATE TABLE delivery_stream_checkpoints (
    organization_id text NOT NULL,
    consumer text NOT NULL,
    handler_version text NOT NULL,
    producer text NOT NULL,
    aggregate_type text NOT NULL,
    aggregate_id text NOT NULL,
    next_sequence bigint NOT NULL CHECK (next_sequence > 0),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (
        organization_id, consumer, handler_version, producer,
        aggregate_type, aggregate_id
    )
);

CREATE TABLE delivery_held_events (
    organization_id text NOT NULL,
    consumer text NOT NULL,
    handler_version text NOT NULL,
    producer text NOT NULL,
    event_id text NOT NULL,
    schema_name text NOT NULL,
    schema_version text NOT NULL,
    schema_major integer NOT NULL CHECK (schema_major > 0),
    aggregate_type text NOT NULL,
    aggregate_id text NOT NULL,
    aggregate_sequence bigint NOT NULL CHECK (aggregate_sequence > 0),
    classification text NOT NULL CHECK (
        classification IN ('public', 'internal', 'confidential', 'restricted_security')
    ),
    envelope_digest text NOT NULL CHECK (
        envelope_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    event jsonb NOT NULL,
    received_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (
        organization_id, consumer, handler_version, producer,
        aggregate_type, aggregate_id, aggregate_sequence
    ),
    UNIQUE (
        organization_id, consumer, handler_version, producer,
        event_id, schema_major
    )
);
CREATE INDEX delivery_held_events_oldest
    ON delivery_held_events (organization_id, consumer, received_at);

ALTER TABLE delivery_dead_letters
    DROP CONSTRAINT delivery_dead_letters_attempts_check,
    ADD COLUMN handler_version text NOT NULL,
    ADD COLUMN producer text NOT NULL,
    ADD COLUMN event_id text NOT NULL,
    ADD COLUMN schema_name text NOT NULL,
    ADD COLUMN schema_version text NOT NULL,
    ADD COLUMN schema_major integer NOT NULL CHECK (schema_major > 0),
    ADD COLUMN aggregate_type text NOT NULL,
    ADD COLUMN aggregate_id text NOT NULL,
    ADD COLUMN aggregate_sequence bigint NOT NULL CHECK (aggregate_sequence > 0),
    ADD COLUMN classification text NOT NULL CHECK (
        classification IN ('public', 'internal', 'confidential', 'restricted_security')
    ),
    ADD COLUMN envelope_digest text NOT NULL CHECK (
        envelope_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    ADD COLUMN next_replay_at timestamptz,
    ADD CONSTRAINT delivery_dead_letters_attempts_check CHECK (attempts >= 0),
    ADD CONSTRAINT delivery_dead_letter_resolution_shape CHECK (
        (resolved_at IS NULL AND resolution_code IS NULL)
        OR (resolved_at IS NOT NULL AND resolution_code IS NOT NULL)
    ),
    ADD CONSTRAINT delivery_dead_letter_event_identity UNIQUE (
        organization_id, consumer, handler_version, producer,
        event_id, schema_major
    );
CREATE INDEX delivery_dead_letters_open
    ON delivery_dead_letters (organization_id, consumer, created_at)
    WHERE resolved_at IS NULL;

CREATE TABLE delivery_replay_audit (
    organization_id text NOT NULL,
    replay_id text NOT NULL,
    dead_letter_id text NOT NULL,
    actor_id text NOT NULL,
    justification text NOT NULL CHECK (
        length(justification) BETWEEN 1 AND 512
        AND justification = btrim(justification)
    ),
    requested_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    completed_at timestamptz,
    outcome_code text,
    PRIMARY KEY (organization_id, replay_id),
    FOREIGN KEY (organization_id, dead_letter_id)
        REFERENCES delivery_dead_letters (organization_id, dead_letter_id),
    CHECK (
        (completed_at IS NULL AND outcome_code IS NULL)
        OR (completed_at IS NOT NULL AND outcome_code IS NOT NULL)
    )
);

ALTER TABLE delivery_stream_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery_stream_checkpoints FORCE ROW LEVEL SECURITY;
ALTER TABLE delivery_held_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery_held_events FORCE ROW LEVEL SECURITY;
ALTER TABLE delivery_replay_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery_replay_audit FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON delivery_stream_checkpoints
    USING (organization_id = current_setting('app.organization_id', true))
    WITH CHECK (organization_id = current_setting('app.organization_id', true));
CREATE POLICY tenant_isolation ON delivery_held_events
    USING (organization_id = current_setting('app.organization_id', true))
    WITH CHECK (organization_id = current_setting('app.organization_id', true));
CREATE POLICY tenant_isolation ON delivery_replay_audit
    USING (organization_id = current_setting('app.organization_id', true))
    WITH CHECK (organization_id = current_setting('app.organization_id', true));

-- Existing delivery tables also fail closed for a table-owning application role.
ALTER TABLE transactional_outbox FORCE ROW LEVEL SECURITY;
ALTER TABLE durable_inbox FORCE ROW LEVEL SECURITY;
ALTER TABLE delivery_dead_letters FORCE ROW LEVEL SECURITY;
