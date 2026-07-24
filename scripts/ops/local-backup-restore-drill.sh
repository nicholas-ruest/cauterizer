#!/usr/bin/env bash
# Local PostgreSQL backup/restore drill (P18).
#
# STATUS: manual, local-nonconformant procedure. Per ADR-017 and the P18
# prompt's own scope limit, this drill runs against a single local Docker
# container on one machine. It makes NO availability claim (no multi-zone
# PostgreSQL, no hosted collector, no RPO/RTO commitment, no named
# operations/product reviewer signed off on it). It exists to prove the
# dump/restore mechanics preserve data -- including tombstones and legal
# holds -- not to certify a production recovery objective.
#
# What it does:
#   1. Starts a throwaway PostgreSQL 17 container (the same image pinned in
#      .github/workflows/ci.yml) and applies this workspace's P04/P14/P12
#      metadata migrations (crates/cauterizer-infrastructure/migrations).
#   2. Seeds representative rows into artifact_descriptors and
#      aggregate_events, including one tombstoned artifact and one
#      legal-hold artifact.
#   3. Runs `pg_dump` (custom format, inside the container) to produce a
#      backup file on the host.
#   4. Restores that backup into a second, fresh database in the same
#      container via `pg_restore`.
#   5. Asserts the restored database's rows are byte-identical to the
#      source database's rows (including tombstoned_at/tombstone_reason and
#      legal_hold), by comparing canonical row digests.
#   6. Does the equivalent for the local filesystem artifact store: tars a
#      populated store root, restores it into a fresh directory, and
#      asserts every file's SHA-256 is unchanged.
#   7. Tears down the container and temporary directories on exit (success
#      or failure).
#
# Usage: scripts/ops/local-backup-restore-drill.sh
# Requires: docker (daemon reachable), bash, sha256sum, tar.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
migrations_dir="$repo_root/crates/cauterizer-infrastructure/migrations"

image="postgres:17.5-alpine@sha256:6567bca8d7bc8c82c5922425a0baee57be8402df92bae5eacad5f01ae9544daa"
container_name="cauterizer-backup-restore-drill-$$"
pg_user="cauterizer_drill"
pg_password="cauterizer_drill"
source_db="cauterizer_drill_source"
restore_db="cauterizer_drill_restore"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/cauterizer-backup-drill.XXXXXX")"
artifact_root="$work_dir/artifact-store"
artifact_restore_root="$work_dir/artifact-store-restored"
dump_file="/tmp/cauterizer_drill.dump"

log() { printf '[backup-restore-drill] %s\n' "$*" >&2; }
fail() { log "FAILED: $*"; exit 1; }

cleanup() {
  local status=$?
  log "cleaning up (exit status $status)"
  docker rm -f "$container_name" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
  exit "$status"
}
trap cleanup EXIT

command -v docker >/dev/null || fail "docker is required"
docker info >/dev/null 2>&1 || fail "docker daemon is not reachable"
[[ -d "$migrations_dir" ]] || fail "missing migrations directory: $migrations_dir"

log "starting PostgreSQL container $container_name"
docker run -d --name "$container_name" \
  -e POSTGRES_USER="$pg_user" \
  -e POSTGRES_PASSWORD="$pg_password" \
  -e POSTGRES_DB="$source_db" \
  "$image" >/dev/null

log "waiting for PostgreSQL to accept connections"
for _ in $(seq 1 60); do
  if docker exec "$container_name" pg_isready -U "$pg_user" -d "$source_db" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "$container_name" pg_isready -U "$pg_user" -d "$source_db" >/dev/null 2>&1 \
  || fail "PostgreSQL did not become ready"

psql_source() { docker exec -i "$container_name" psql -v ON_ERROR_STOP=1 -U "$pg_user" -d "$source_db" "$@"; }

log "applying migrations to $source_db"
for migration in "$migrations_dir"/*.sql; do
  [[ "$migration" == *.down.sql ]] && continue
  log "  applying $(basename "$migration")"
  psql_source < "$migration" >/dev/null
done

log "seeding representative rows (including a tombstone and a legal hold)"
psql_source >/dev/null <<'SQL'
INSERT INTO artifact_descriptors (
    organization_id, access_domain, digest, size_bytes, media_type,
    schema_name, schema_version, classification, region, retention_days,
    legal_hold, encryption_key_ref, producer, created_at,
    tombstoned_at, tombstone_reason
) VALUES
    ('org_drillorg01', 'tenant', 'sha256:' || repeat('a1', 32), 1024,
     'application/octet-stream', 'dev.cauterizer.artifact', '1.0.0',
     'confidential', 'local-1', 30, false, 'key_drill001', 'drill-script',
     transaction_timestamp(), NULL, NULL),
    ('org_drillorg01', 'tenant', 'sha256:' || repeat('b2', 32), 2048,
     'application/octet-stream', 'dev.cauterizer.artifact', '1.0.0',
     'confidential', 'local-1', 30, true, 'key_drill002', 'drill-script',
     transaction_timestamp(), NULL, NULL),
    ('org_drillorg01', 'tenant', 'sha256:' || repeat('c3', 32), 512,
     'application/octet-stream', 'dev.cauterizer.artifact', '1.0.0',
     'internal', 'local-1', 30, false, 'key_drill003', 'drill-script',
     transaction_timestamp(), transaction_timestamp(), 'retention_expired');

INSERT INTO aggregate_events (
    organization_id, aggregate_type, aggregate_id, aggregate_sequence,
    event_id, schema_name, schema_version, payload, occurred_at,
    correlation_id, causation_id
) VALUES (
    'org_drillorg01', 'remediation_run', 'run_drillrun001', 1,
    'event_drillevt01', 'dev.cauterizer.remediation_run_event', '1.0.0',
    '{"kind":"drill_seed"}'::jsonb, transaction_timestamp(),
    'correlation_drilldrill1', 'causation_drilldrill01'
);
SQL

row_digest() {
  # A stable, order-independent digest of every row in both seeded tables.
  psql_source -At -c "
    SELECT md5(string_agg(row_digest, ',' ORDER BY row_digest)) FROM (
      SELECT md5(t::text) AS row_digest FROM artifact_descriptors t
      UNION ALL
      SELECT md5(t::text) AS row_digest FROM aggregate_events t
    ) digests;
  "
}

source_digest="$(row_digest)"
[[ -n "$source_digest" ]] || fail "could not compute source row digest"
log "source row digest: $source_digest"

log "dumping $source_db with pg_dump (custom format)"
docker exec "$container_name" pg_dump -U "$pg_user" -Fc -d "$source_db" -f "$dump_file"

log "creating fresh restore target database $restore_db"
docker exec "$container_name" createdb -U "$pg_user" "$restore_db"

log "restoring backup into $restore_db with pg_restore"
docker exec "$container_name" pg_restore -U "$pg_user" -d "$restore_db" --no-owner "$dump_file"

restore_digest="$(docker exec "$container_name" psql -At -U "$pg_user" -d "$restore_db" -c "
    SELECT md5(string_agg(row_digest, ',' ORDER BY row_digest)) FROM (
      SELECT md5(t::text) AS row_digest FROM artifact_descriptors t
      UNION ALL
      SELECT md5(t::text) AS row_digest FROM aggregate_events t
    ) digests;
  ")"
log "restored row digest: $restore_digest"

[[ "$source_digest" == "$restore_digest" ]] \
  || fail "restored rows differ from source rows (digest mismatch)"

tombstoned_count="$(docker exec "$container_name" psql -At -U "$pg_user" -d "$restore_db" -c \
  "SELECT count(*) FROM artifact_descriptors WHERE tombstoned_at IS NOT NULL AND tombstone_reason = 'retention_expired';")"
[[ "$tombstoned_count" == "1" ]] || fail "expected exactly one restored tombstone, found $tombstoned_count"

legal_hold_count="$(docker exec "$container_name" psql -At -U "$pg_user" -d "$restore_db" -c \
  "SELECT count(*) FROM artifact_descriptors WHERE legal_hold = true;")"
[[ "$legal_hold_count" == "1" ]] || fail "expected exactly one restored legal hold, found $legal_hold_count"

log "PostgreSQL dump/restore preserved data, tombstone, and legal hold intact"

log "exercising the equivalent filesystem-artifact-store backup/restore"
mkdir -p "$artifact_root/tenant/committed/org_drillorg01" "$artifact_root/tenant/quarantine/org_drillorg01"
printf 'drill payload one' > "$artifact_root/tenant/committed/org_drillorg01/sha256_a1a1a1.bin"
printf 'drill payload two' > "$artifact_root/tenant/committed/org_drillorg01/sha256_b2b2b2.bin"
# A tombstone marker file, mirroring the metadata-layer tombstone above: the
# payload bytes are gone, but the fact that this digest once existed and why
# is retained (a bounded reason code, never raw content).
printf 'retention_expired' > "$artifact_root/tenant/committed/org_drillorg01/sha256_c3c3c3.tombstone"

before_manifest="$(cd "$artifact_root" && find . -type f -print0 | sort -z | xargs -0 sha256sum)"

tar_file="$work_dir/artifact-store-backup.tar.gz"
tar -C "$artifact_root" -czf "$tar_file" .
mkdir -p "$artifact_restore_root"
tar -C "$artifact_restore_root" -xzf "$tar_file"

after_manifest="$(cd "$artifact_restore_root" && find . -type f -print0 | sort -z | xargs -0 sha256sum)"

[[ "$before_manifest" == "$after_manifest" ]] \
  || fail "restored filesystem artifact store differs from the original (sha256 mismatch)"
[[ -f "$artifact_restore_root/tenant/committed/org_drillorg01/sha256_c3c3c3.tombstone" ]] \
  || fail "restored filesystem tombstone marker is missing"

log "filesystem artifact store backup/restore preserved every file and its tombstone marker"
log "DRILL PASSED: PostgreSQL + filesystem artifact state, including tombstones and legal"
log "holds, survived a local dump/restore cycle intact. This is NOT an availability, RPO,"
log "or RTO claim -- see ADR-017 and the header comment above."
