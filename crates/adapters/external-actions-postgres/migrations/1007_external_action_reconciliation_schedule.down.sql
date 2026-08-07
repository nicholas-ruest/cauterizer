DROP INDEX IF EXISTS external_action_deliveries_recovery_idx;

CREATE INDEX external_action_deliveries_recovery_idx
    ON external_action_deliveries (organization_id, idempotency_key)
    WHERE delivery->>'status' IN ('Pending', 'Unknown');
