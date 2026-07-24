-- P12 versioned signing-key trust metadata. This table never stores private
-- key bytes: only the publishable key identity, algorithm, validity window,
-- and lifecycle state that Isolated Execution and Evidence (P13) need to
-- make trust decisions. Rows are append-only history, not mutated state:
-- every generate/rotate/revoke/destroy transition inserts a new
-- `metadata_version` for its `key_id`, so the trust record for a key is
-- fully versioned and auditable.

CREATE TABLE signing_key_trust_metadata (
    organization_id text NOT NULL,
    key_id text NOT NULL,
    metadata_version bigint NOT NULL CHECK (metadata_version > 0),
    trust_domain text NOT NULL,
    algorithm text NOT NULL,
    trust_label text NOT NULL,
    not_before timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    state text NOT NULL CHECK (state IN ('active', 'overlap', 'revoked', 'destroyed')),
    revoked_at timestamptz,
    revocation_reason text,
    recorded_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, key_id, metadata_version),
    CONSTRAINT signing_key_revocation_shape CHECK (
        (state <> 'revoked' AND revoked_at IS NULL AND revocation_reason IS NULL)
        OR (state = 'revoked' AND revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)
    )
);

CREATE INDEX signing_key_trust_metadata_current
    ON signing_key_trust_metadata (organization_id, key_id, metadata_version DESC);

CREATE INDEX signing_key_trust_metadata_by_domain
    ON signing_key_trust_metadata (organization_id, trust_domain, metadata_version DESC);

ALTER TABLE signing_key_trust_metadata ENABLE ROW LEVEL SECURITY;
ALTER TABLE signing_key_trust_metadata FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON signing_key_trust_metadata
    USING (organization_id = current_setting('app.organization_id', true))
    WITH CHECK (organization_id = current_setting('app.organization_id', true));
