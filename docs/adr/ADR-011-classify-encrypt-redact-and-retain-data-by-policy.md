# ADR-011: Classify, Encrypt, Redact, and Retain Data by Policy

- **Status**: proposed
- **Date**: 2026-07-22
- **Deciders**:
- **Tags**: privacy, data-governance, encryption, retention

## Context

Advisories, source, exploit tests, model prompts, logs, identities, and evidence can contain secrets, personal data, or embargoed vulnerability information. Immutability must not become indefinite uncontrolled retention.

## Decision

Define four data classes: Public, Internal, Confidential, and Restricted Security. Every schema field and artifact class has an owner, classification, region, encryption, log, export, and retention policy. Encrypt in transit and at rest; use per-tenant or per-domain envelope keys for Restricted data. Redact before telemetry and export, never after ingestion into an uncontrolled sink.

Retention creates cryptographically attributable tombstones and erases protected payloads/keys while retaining the minimum non-sensitive audit fact. Legal hold suspends deletion through an explicit authorization. Backups inherit classification and deletion schedules. Production data is forbidden in lower environments unless irreversibly sanitized.

## Consequences

### Positive
- Supports privacy, embargoed security work, and data-residency commitments.
- Makes deletion compatible with append-only audit semantics.

### Negative
- Field-level classification and backup deletion add operational complexity.
- Some evidence bundles cannot be freely portable.

### Neutral
- Exact regulatory mappings require legal/compliance review per market.

## Links

- Depends on [ADR-003](ADR-003-use-immutable-snapshots-and-an-append-only-run-lifecycle.md)
- Depends on [ADR-010](ADR-010-enforce-tenant-isolation-and-zero-trust-authorization.md)
