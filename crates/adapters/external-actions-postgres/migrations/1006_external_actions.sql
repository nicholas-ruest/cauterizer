CREATE TABLE IF NOT EXISTS external_action_grants (
    organization_id text NOT NULL,
    grant_id text NOT NULL,
    grant_document jsonb NOT NULL,
    PRIMARY KEY (organization_id, grant_id),
    CHECK (grant_document->>'organization_id' = organization_id),
    CHECK (grant_document->>'id' = grant_id)
);

CREATE TABLE IF NOT EXISTS external_action_deliveries (
    organization_id text NOT NULL,
    delivery_id text NOT NULL,
    idempotency_key text NOT NULL,
    request jsonb NOT NULL,
    delivery jsonb NOT NULL,
    PRIMARY KEY (organization_id, delivery_id),
    UNIQUE (organization_id, idempotency_key),
    CHECK (delivery->>'id' = delivery_id),
    CHECK (request->>'organization_id' = organization_id)
);

CREATE TABLE IF NOT EXISTS external_action_kill_switches (
    organization_id text NOT NULL,
    installation_ref text NOT NULL,
    engaged boolean NOT NULL,
    PRIMARY KEY (organization_id, installation_ref)
);

CREATE INDEX IF NOT EXISTS external_action_deliveries_recovery_idx
    ON external_action_deliveries (organization_id, idempotency_key)
    WHERE delivery->>'status' IN ('Pending', 'Unknown');
CREATE INDEX IF NOT EXISTS external_action_grants_enabled_idx
    ON external_action_grants (organization_id, grant_id)
    WHERE grant_document->>'enabled' = 'true';

ALTER TABLE external_action_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE external_action_grants FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS external_action_grants_tenant ON external_action_grants;
CREATE POLICY external_action_grants_tenant ON external_action_grants
    USING (organization_id = current_setting('app.organization_id', true))
    WITH CHECK (organization_id = current_setting('app.organization_id', true));

ALTER TABLE external_action_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE external_action_deliveries FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS external_action_deliveries_tenant ON external_action_deliveries;
CREATE POLICY external_action_deliveries_tenant ON external_action_deliveries
    USING (organization_id = current_setting('app.organization_id', true))
    WITH CHECK (organization_id = current_setting('app.organization_id', true));

ALTER TABLE external_action_kill_switches ENABLE ROW LEVEL SECURITY;
ALTER TABLE external_action_kill_switches FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS external_action_kill_switches_tenant ON external_action_kill_switches;
CREATE POLICY external_action_kill_switches_tenant ON external_action_kill_switches
    USING (organization_id = current_setting('app.organization_id', true))
    WITH CHECK (organization_id = current_setting('app.organization_id', true));
