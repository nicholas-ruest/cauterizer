ALTER TABLE delivery_dead_letters NO FORCE ROW LEVEL SECURITY;
ALTER TABLE durable_inbox NO FORCE ROW LEVEL SECURITY;
ALTER TABLE transactional_outbox NO FORCE ROW LEVEL SECURITY;

DROP TABLE IF EXISTS delivery_replay_audit;

DROP INDEX IF EXISTS delivery_dead_letters_open;
ALTER TABLE delivery_dead_letters
    DROP CONSTRAINT IF EXISTS delivery_dead_letter_event_identity,
    DROP CONSTRAINT IF EXISTS delivery_dead_letter_resolution_shape,
    DROP CONSTRAINT IF EXISTS delivery_dead_letters_attempts_check,
    DROP COLUMN IF EXISTS next_replay_at,
    DROP COLUMN IF EXISTS envelope_digest,
    DROP COLUMN IF EXISTS classification,
    DROP COLUMN IF EXISTS aggregate_sequence,
    DROP COLUMN IF EXISTS aggregate_id,
    DROP COLUMN IF EXISTS aggregate_type,
    DROP COLUMN IF EXISTS schema_major,
    DROP COLUMN IF EXISTS schema_version,
    DROP COLUMN IF EXISTS schema_name,
    DROP COLUMN IF EXISTS event_id,
    DROP COLUMN IF EXISTS producer,
    DROP COLUMN IF EXISTS handler_version;
ALTER TABLE delivery_dead_letters
    ADD CONSTRAINT delivery_dead_letters_attempts_check CHECK (attempts > 0);

DROP TABLE IF EXISTS delivery_held_events;
DROP TABLE IF EXISTS delivery_stream_checkpoints;

ALTER TABLE durable_inbox
    DROP CONSTRAINT IF EXISTS durable_inbox_stream_position,
    DROP COLUMN IF EXISTS envelope_digest,
    DROP COLUMN IF EXISTS classification;

DROP INDEX IF EXISTS transactional_outbox_expired_claims;
DROP INDEX IF EXISTS transactional_outbox_ready;
ALTER TABLE transactional_outbox
    DROP CONSTRAINT IF EXISTS outbox_terminal_shape,
    DROP CONSTRAINT IF EXISTS outbox_claim_shape,
    DROP COLUMN IF EXISTS terminal_reason_code,
    DROP COLUMN IF EXISTS dead_lettered_at,
    DROP COLUMN IF EXISTS next_attempt_at,
    DROP COLUMN IF EXISTS claim_expires_at,
    DROP COLUMN IF EXISTS claim_token;
CREATE INDEX transactional_outbox_ready
    ON transactional_outbox (available_at, outbox_id)
    WHERE delivered_at IS NULL;
