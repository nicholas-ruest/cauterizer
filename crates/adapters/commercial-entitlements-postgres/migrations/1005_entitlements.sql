CREATE TABLE commercial_entitlement_accounts (
    organization_id text NOT NULL,
    account_id text NOT NULL,
    version bigint NOT NULL CHECK (version > 0),
    state jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, account_id)
);
CREATE TABLE commercial_entitlement_idempotency (
    organization_id text NOT NULL,
    command_scope text NOT NULL,
    idempotency_key text NOT NULL,
    request_digest text NOT NULL,
    result jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, command_scope, idempotency_key)
);
CREATE TABLE commercial_entitlement_outbox (
    sequence bigint GENERATED ALWAYS AS IDENTITY,
    organization_id text NOT NULL,
    account_id text NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    event_index integer NOT NULL CHECK (event_index >= 0),
    event jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (sequence),
    UNIQUE (organization_id, account_id, aggregate_version, event_index)
);
ALTER TABLE commercial_entitlement_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE commercial_entitlement_accounts FORCE ROW LEVEL SECURITY;
ALTER TABLE commercial_entitlement_idempotency ENABLE ROW LEVEL SECURITY;
ALTER TABLE commercial_entitlement_idempotency FORCE ROW LEVEL SECURITY;
ALTER TABLE commercial_entitlement_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE commercial_entitlement_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY commercial_entitlement_accounts_tenant ON commercial_entitlement_accounts
USING (organization_id = current_setting('app.organization_id', true))
WITH CHECK (organization_id = current_setting('app.organization_id', true));
CREATE POLICY commercial_entitlement_idempotency_tenant ON commercial_entitlement_idempotency
USING (organization_id = current_setting('app.organization_id', true))
WITH CHECK (organization_id = current_setting('app.organization_id', true));
CREATE POLICY commercial_entitlement_outbox_tenant ON commercial_entitlement_outbox
USING (organization_id = current_setting('app.organization_id', true))
WITH CHECK (organization_id = current_setting('app.organization_id', true));
