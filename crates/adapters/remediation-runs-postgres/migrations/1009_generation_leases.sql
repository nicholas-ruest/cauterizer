CREATE TABLE IF NOT EXISTS review_generation_leases (
  organization_id text NOT NULL,
  run_id text NOT NULL,
  owner text NOT NULL,
  fence bigint NOT NULL CHECK (fence > 0),
  expires_at_unix bigint NOT NULL,
  PRIMARY KEY (organization_id, run_id)
);
ALTER TABLE review_generation_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE review_generation_leases FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS review_generation_leases_tenant ON review_generation_leases;
CREATE POLICY review_generation_leases_tenant ON review_generation_leases
  USING (organization_id = current_setting('app.organization_id', true))
  WITH CHECK (organization_id = current_setting('app.organization_id', true));
