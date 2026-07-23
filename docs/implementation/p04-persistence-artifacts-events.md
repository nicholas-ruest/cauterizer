# P04 persistence, artifacts, and reliable events

Status: implemented and verified on 2026-07-23.

## Delivered boundaries

- PostgreSQL 17 migrations and adapter atomically persist optimistic snapshots,
  append-only events, transactional outbox records, and idempotency results.
- Durable inbox, stream checkpoint, held-delivery, dead-letter, and replay-audit
  structures support replay-safe, ordered consumers and governed recovery.
- Content-addressed artifacts enter a non-addressable quarantine and are published
  only after size, SHA-256, media type, and schema checks. Descriptors bind the
  organization, access domain, classification, region, retention, legal hold,
  encryption key, producer, schema, and digest.
- Artifact reads authorize the complete namespace before lookup and verify the
  digest again. Acquisition, solver, verifier, evidence, and general tenant
  namespaces are distinct authorities.
- The development filesystem adapter uses create-only quarantine files,
  immutable destination reservation, bounded reads, owner-only permissions, and
  symlink rejection. The production boundary is an S3-compatible object-store
  port; production deployments must pair it with PostgreSQL descriptors.
- Envelope encryption and signing are ports. AES-256-GCM and Ed25519 development
  implementations are explicitly labeled `untrusted-development`; hosted use
  requires the P00-selected KMS/HSM implementation.

## Migration and rollback

Apply migrations with the infrastructure adapter before starting writers. The
migration is additive and enables row-level security on every tenant-owned table.
Application transactions set `app.organization_id`; deployment roles must not own
tables or possess `BYPASSRLS`.

Rollback is destructive and exists for local/test recovery only. Stop all
writers and relay workers, retain object payloads, take a verified database
backup, and apply `0001_p04_metadata.down.sql`. Hosted rollback must restore the
pre-migration database rather than discard append-only history.

## Operations and reconciliation

Relay workers claim ready outbox rows with leases, publish the exact stored event,
then acknowledge by claim token. Expired claims are recoverable. Consumers key
deduplication by organization, consumer/handler version, producer, event ID, and
schema major; aggregate sequence gaps are held. Exhausted or poison deliveries go
to dead letters and require an authorized, reason-coded replay audit.

Reconciliation compares aggregate events to outbox rows, unresolved outbox rows
to broker acknowledgements, inbox rows to stream checkpoints, committed artifact
descriptors to exact object keys, and mark-and-sweep roots to tombstones. Never
use object-store listing or error differences as authorization evidence.

## Verification evidence

- Debug profile: 28 infrastructure tests pass.
- Optimized profile: 26 tests passed in 68.998 seconds during the pre-delivery
  baseline, including compilation;
  test execution itself completed in 0.01 seconds. This is build/test evidence,
  not a production throughput SLO.
- PostgreSQL integration was exercised against `postgres:17-alpine`, covering a
  fresh migration, commit, exact replay, conflicting idempotency input,
  uncommitted-artifact rejection, atomic row counts, lease retry/reclamation,
  exact-token acknowledgement, ordered inbox processing, and reconciliation.
  The current migrations also completed a clean up/down/up cycle.
- Strict Clippy (`-D warnings`), formatting, and corruption, partial-upload,
  cross-domain, historical-schema, ordering, retry, and replay tests are gates.

## Residual development constraints

The filesystem descriptor index is process-local and is not a production
reconciliation source. Standard-library filesystem APIs cannot provide the same
beneath-directory race guarantees as a hardened object-store service. Development
encryption retains its supplied key in process memory and callers own nonce
uniqueness. These adapters are deliberately non-conformant for hosted use.
