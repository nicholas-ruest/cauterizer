#!/usr/bin/env bash
# Local release rollback rehearsal (P20).
#
# STATUS: manual, local-nonconformant procedure -- the same honesty scope as
# scripts/ops/local-backup-restore-drill.sh (P18), which this drill extends.
# It makes NO availability/RPO/RTO claim and is not a substitute for a real
# canary/rollback exercise against a hosted release pipeline. It exists to
# prove, against real local PostgreSQL, that:
#
#   1. This workspace's EXISTING invariants actually detect a bad release --
#      not a hypothetical: it runs P13's evidence-bundle tamper-vector test
#      suite, P20's release-admission tamper-vector test suite, and P14's
#      real outbox/inbox dispatcher integration test (which proves at-least-
#      once delivery, per-aggregate ordering, and dead-letter handling) all
#      against a live database.
#   2. A concrete "bad release admitted" scenario -- a row representing
#      already-committed, signed evidence-bundle-referenced artifact state
#      gets corrupted in place, simulating a bad migration or a compromised
#      write that slipped past admission -- is caught by comparing the live
#      row digest against the digest captured at last-known-good backup
#      time, and is recoverable via pg_dump/pg_restore (P18's mechanism)
#      to that last-known-good point *without losing* a second, untouched
#      row standing in for an already-signed evidence bundle.
#
# Usage: scripts/ops/local-release-rollback-drill.sh
# Requires: docker (daemon reachable), cargo, bash, sha256sum, psql/pg_dump
#           inside the container (via docker exec).

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
migrations_dir="$repo_root/crates/cauterizer-infrastructure/migrations"

image="postgres:17.5-alpine@sha256:6567bca8d7bc8c82c5922425a0baee57be8402df92bae5eacad5f01ae9544daa"
container_name="cauterizer-rollback-drill-$$"
pg_user="cauterizer_rollback"
pg_password="cauterizer_rollback"
source_db="cauterizer_rollback_source"
restore_db="cauterizer_rollback_restore"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/cauterizer-rollback-drill.XXXXXX")"
dump_file="/tmp/cauterizer_rollback_drill.dump"

log() { printf '[release-rollback-drill] %s\n' "$*" >&2; }
fail() { log "FAILED: $*"; exit 1; }
step() { printf '\n[release-rollback-drill] === %s ===\n' "$*" >&2; }

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
command -v cargo >/dev/null || fail "cargo is required"
[[ -d "$migrations_dir" ]] || fail "missing migrations directory: $migrations_dir"

log "starting PostgreSQL container $container_name"
docker run -d --name "$container_name" \
  -e POSTGRES_USER="$pg_user" \
  -e POSTGRES_PASSWORD="$pg_password" \
  -e POSTGRES_DB="$source_db" \
  -p 127.0.0.1:0:5432 \
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

host_port="$(docker port "$container_name" 5432/tcp | head -n1 | cut -d: -f2)"
[[ -n "$host_port" ]] || fail "could not determine mapped host port"
postgres_url="postgresql://${pg_user}:${pg_password}@127.0.0.1:${host_port}/${source_db}"

psql_source() { docker exec -i "$container_name" psql -v ON_ERROR_STOP=1 -U "$pg_user" -d "$source_db" "$@"; }

# --- Part 1: prove the system's EXISTING invariants actually detect a bad
# release/bad event, using real code and (for the dispatcher) a real live
# database, not just this script's own SQL narrative. ---

step "Part 1: run the existing detection invariants this drill relies on"

log "P13 evidence-bundle tamper-vector suite (offline, cryptographic)"
( cd "$repo_root" && cargo test -p cauterizer-evidence --lib -- --quiet ) \
  || fail "P13 evidence tamper-vector tests did not pass"

log "P20 release-admission tamper-vector suite (offline, cryptographic)"
( cd "$repo_root" && cargo test -p cauterizer-infrastructure release_admission -- --quiet ) \
  || fail "P20 release-admission tamper-vector tests did not pass"

log "P14 outbox/inbox dispatcher integration test against a live database"
log "(this also applies this workspace's own migrations to $source_db via"
log "PostgresMetadataStore::migrate, which Part 2 below then reuses)"
( cd "$repo_root" \
    && CAUTERIZER_REQUIRE_POSTGRES_TESTS=1 \
       CAUTERIZER_TEST_POSTGRES_URL="$postgres_url" \
       cargo test -p cauterizer-infrastructure --test p14_dispatch_delivery -- --quiet ) \
  || fail "P14 dispatcher integration test did not pass against the live drill database"

log "all three existing invariant suites passed against real code and a real database"

[[ -d "$migrations_dir" ]] || fail "missing migrations directory: $migrations_dir"

# --- Part 2: a concrete bad-release-admitted-then-rolled-back scenario. ---

step "Part 2: seed last-known-good state and take a backup"

log "seeding a last-known-good release: one already-signed evidence-bundle"
log "artifact and one legitimate remediation event"
psql_source >/dev/null <<'SQL'
INSERT INTO artifact_descriptors (
    organization_id, access_domain, digest, size_bytes, media_type,
    schema_name, schema_version, classification, region, retention_days,
    legal_hold, encryption_key_ref, producer, created_at,
    tombstoned_at, tombstone_reason
) VALUES (
    'org_rollback01', 'evidence', 'sha256:' || repeat('e5', 32), 4096,
    'application/vnd.in-toto+json', 'dev.cauterizer.evidence_bundle', '1.0.0',
    'confidential', 'local-1', 365, false, 'key_rollback001',
    'release-rollback-drill', transaction_timestamp(), NULL, NULL
);

INSERT INTO aggregate_events (
    organization_id, aggregate_type, aggregate_id, aggregate_sequence,
    event_id, schema_name, schema_version, payload, occurred_at,
    correlation_id, causation_id
) VALUES (
    'org_rollback01', 'remediation_run', 'run_rollbackrun1', 1,
    'event_rollbackevt1', 'dev.cauterizer.remediation_run_event', '1.0.0',
    '{"kind":"last_known_good_release"}'::jsonb, transaction_timestamp(),
    'correlation_rollback01', 'causation_rollback01'
);
SQL

row_digest() {
  psql_source -At -c "
    SELECT md5(string_agg(row_digest, ',' ORDER BY row_digest)) FROM (
      SELECT md5(t::text) AS row_digest FROM artifact_descriptors t
      UNION ALL
      SELECT md5(t::text) AS row_digest FROM aggregate_events t
    ) digests;
  "
}
evidence_row_digest() {
  psql_source -At -c "
    SELECT md5(t::text) FROM artifact_descriptors t
    WHERE organization_id = 'org_rollback01' AND access_domain = 'evidence';
  "
}

last_known_good_digest="$(row_digest)"
last_known_good_evidence_digest="$(evidence_row_digest)"
[[ -n "$last_known_good_digest" ]] || fail "could not compute last-known-good digest"
log "last-known-good digest: $last_known_good_digest"
log "last-known-good evidence-artifact row digest: $last_known_good_evidence_digest"

log "dumping $source_db as the last-known-good backup"
docker exec "$container_name" pg_dump -U "$pg_user" -Fc -d "$source_db" -f "$dump_file"

step "Part 3: simulate a bad release being admitted"

log "corrupting the evidence artifact's digest in place (simulated bad"
log "migration / compromised write that slipped past admission) and"
log "inserting an unrelated poison row the bad release also introduced"
psql_source >/dev/null <<'SQL'
UPDATE artifact_descriptors
SET digest = 'sha256:' || repeat('ba', 32)
WHERE organization_id = 'org_rollback01' AND access_domain = 'evidence';

INSERT INTO artifact_descriptors (
    organization_id, access_domain, digest, size_bytes, media_type,
    schema_name, schema_version, classification, region, retention_days,
    legal_hold, encryption_key_ref, producer, created_at,
    tombstoned_at, tombstone_reason
) VALUES (
    'org_rollback01', 'evidence', 'sha256:' || repeat('bd', 32), 4096,
    'application/vnd.in-toto+json', 'dev.cauterizer.evidence_bundle', '1.0.0',
    'confidential', 'local-1', 365, false, 'key_rollback_bad',
    'bad-release-simulation', transaction_timestamp(), NULL, NULL
);
SQL

corrupted_digest="$(row_digest)"
log "digest after the bad release: $corrupted_digest"
if [[ "$corrupted_digest" == "$last_known_good_digest" ]]; then
  fail "the simulated bad release did not actually change any observable state"
fi
log "DETECTED: current state digest no longer matches the last-known-good digest"
log "captured at backup time -- exactly the mismatch a release admission gate"
log "(crates/cauterizer-infrastructure/src/release_admission.rs) or a P13"
log "evidence re-verification would fail closed on"

step "Part 4: roll back to last-known-good without losing evidence"

log "creating fresh restore target database $restore_db"
docker exec "$container_name" createdb -U "$pg_user" "$restore_db"

log "restoring the pre-corruption backup into $restore_db"
docker exec "$container_name" pg_restore -U "$pg_user" -d "$restore_db" --no-owner "$dump_file"

restored_digest="$(docker exec "$container_name" psql -At -U "$pg_user" -d "$restore_db" -c "
    SELECT md5(string_agg(row_digest, ',' ORDER BY row_digest)) FROM (
      SELECT md5(t::text) AS row_digest FROM artifact_descriptors t
      UNION ALL
      SELECT md5(t::text) AS row_digest FROM aggregate_events t
    ) digests;
  ")"
log "restored state digest: $restored_digest"

[[ "$restored_digest" == "$last_known_good_digest" ]] \
  || fail "restored state does not match the last-known-good digest -- rollback failed"

restored_evidence_digest="$(docker exec "$container_name" psql -At -U "$pg_user" -d "$restore_db" -c "
    SELECT md5(t::text) FROM artifact_descriptors t
    WHERE organization_id = 'org_rollback01' AND access_domain = 'evidence';
  ")"
[[ "$restored_evidence_digest" == "$last_known_good_evidence_digest" ]] \
  || fail "the already-signed evidence artifact row was not recovered byte-identical"

restored_row_count="$(docker exec "$container_name" psql -At -U "$pg_user" -d "$restore_db" -c "
    SELECT count(*) FROM artifact_descriptors WHERE organization_id = 'org_rollback01';
  ")"
[[ "$restored_row_count" == "1" ]] \
  || fail "expected exactly the one pre-corruption evidence row after rollback, found $restored_row_count"

log "RESTORED: rollback recovered the exact last-known-good state; the"
log "already-signed evidence-bundle artifact row is present, byte-identical,"
log "and the bad release's corrupted digest and poison row are both gone"

log ""
log "DRILL PASSED: a bad release was admitted, detected by digest mismatch"
log "against the last-known-good backup, and rolled back via pg_dump/pg_restore"
log "with zero evidence loss -- while P13's evidence tamper-vector suite,"
log "P20's release-admission tamper-vector suite, and P14's live-database"
log "outbox/inbox dispatcher test all independently passed. This is NOT an"
log "availability, RPO, or RTO claim -- see ADR-017, P18's backup/restore"
log "drill, and docs/architecture/production-readiness-track.md."
