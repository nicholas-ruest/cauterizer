-- P14 dead-letter replay ledger origin tracking.
--
-- `delivery_dead_letters` (0001/0002) was shaped only for consumer/inbox-side
-- poison records: it required handler_version, producer, schema_name,
-- schema_version, schema_major, aggregate_type, aggregate_id,
-- aggregate_sequence, classification, and envelope_digest, none of which a
-- producer/outbox-side relay dead letter (`transactional_outbox.dead_lettered_at`,
-- written by `dead_letter_outbox`) has in decomposed form. Nothing populated
-- this table at all, so `delivery_replay_audit`'s existing foreign key to it
-- had no row it could ever reference and replay was structurally impossible.
--
-- This migration adds an explicit `source` discriminator and an `outbox_id`
-- back-reference so `dead_letter_outbox` can record an outbox-origin ledger
-- row, and relaxes the inbox-only columns to nullable for that origin. Only
-- the outbox-origin path is populated by this prompt (see
-- `PostgresMetadataStore::dead_letter_outbox`/`replay_dead_letter`);
-- consumer/inbox-origin dead-lettering remains a documented future item.

ALTER TABLE delivery_dead_letters
    ADD COLUMN source text NOT NULL DEFAULT 'outbox' CHECK (source IN ('outbox', 'inbox')),
    ADD COLUMN outbox_id text,
    ALTER COLUMN handler_version DROP NOT NULL,
    ALTER COLUMN producer DROP NOT NULL,
    ALTER COLUMN schema_name DROP NOT NULL,
    ALTER COLUMN schema_version DROP NOT NULL,
    ALTER COLUMN schema_major DROP NOT NULL,
    ALTER COLUMN aggregate_type DROP NOT NULL,
    ALTER COLUMN aggregate_id DROP NOT NULL,
    ALTER COLUMN aggregate_sequence DROP NOT NULL,
    ALTER COLUMN classification DROP NOT NULL,
    ALTER COLUMN envelope_digest DROP NOT NULL,
    ADD CONSTRAINT delivery_dead_letter_source_shape CHECK (
        (source = 'outbox' AND outbox_id IS NOT NULL)
        OR (source = 'inbox' AND outbox_id IS NULL
            AND handler_version IS NOT NULL AND producer IS NOT NULL
            AND schema_name IS NOT NULL AND schema_version IS NOT NULL
            AND schema_major IS NOT NULL AND aggregate_type IS NOT NULL
            AND aggregate_id IS NOT NULL AND aggregate_sequence IS NOT NULL
            AND classification IS NOT NULL AND envelope_digest IS NOT NULL)
    ),
    ADD CONSTRAINT delivery_dead_letters_outbox_origin_identity
        UNIQUE (organization_id, outbox_id, attempts);
