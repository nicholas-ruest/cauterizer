# ADR-013: Separate Transactional Metadata from Content-Addressed Artifacts

- **Status**: proposed
- **Date**: 2026-07-22
- **Deciders**:
- **Tags**: persistence, object-storage, integrity

## Context

Lifecycle metadata needs transactions and queries; source trees, logs, patches, test outputs, and evidence bundles are large immutable blobs. Storing both identically harms consistency, cost, and access control.

## Decision

Use a relational transactional store for aggregates, projections, outbox/inbox, authorization metadata, and artifact descriptors. Use encrypted object storage for immutable content-addressed artifacts. A descriptor records tenant, digest algorithm/value, size, media/schema type, classification, region, retention, encryption-key reference, producer, and creation time.

Artifacts are uploaded to quarantine, validated, hashed server-side, then atomically made addressable; domain state may reference only committed descriptors. Reads verify digest and authorization. Garbage collection is mark-and-sweep from retained domain/evidence roots with legal-hold awareness. Hidden verifier and solver stores use separate access domains.

## Consequences

### Positive
- Fits consistency and storage characteristics while preserving integrity.
- Enables lifecycle, tiering, replication, and tenant policy.

### Negative
- Requires reconciliation of metadata and blob stores.
- Digest equality and cross-region replication create privacy considerations.

### Neutral
- Specific database/object-store products remain undecided.

## Links

- Depends on [ADR-003](ADR-003-use-immutable-snapshots-and-an-append-only-run-lifecycle.md)
- Depends on [ADR-011](ADR-011-classify-encrypt-redact-and-retain-data-by-policy.md)
