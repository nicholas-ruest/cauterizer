CREATE TABLE IF NOT EXISTS review_deliveries (
  organization_id text NOT NULL,
  run_id text NOT NULL,
  candidate_digest text NOT NULL,
  version bigint NOT NULL CHECK (version > 0),
  state jsonb NOT NULL,
  PRIMARY KEY (organization_id, run_id, candidate_digest)
);
ALTER TABLE review_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE review_deliveries FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS review_deliveries_tenant ON review_deliveries;
CREATE POLICY review_deliveries_tenant ON review_deliveries
  USING (organization_id = current_setting('app.organization_id', true))
  WITH CHECK (organization_id = current_setting('app.organization_id', true));
