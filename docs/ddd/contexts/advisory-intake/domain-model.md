# Advisory Intake: Domain Model

## Aggregate root

`AdvisoryRecord` is the sole aggregate root and is persisted through domain port `AdvisoryRecordRepository`. State is private; behavior validates invariants before emitting immutable events. Cross-context objects are represented only by IDs and digests.

## Invariants

- `Snapshots are immutable and attributable`
- `Withdrawal creates a new fact and never erases history`
- `Ambiguous aliases do not merge automatically`
- `Severity always retains metric/version provenance`

## Value objects

- `AdvisoryRecordId`
- `AdvisorySource`
- `ExternalAdvisoryId`
- `AffectedRange`
- `SeverityVector`
- `AdvisorySnapshotRef`

## Domain services and policies

- `AdvisoryNormalizer`
- `AliasResolutionPolicy`
- `SnapshotAcceptancePolicy`

## Repository contract

`AdvisoryRecordRepository` supports load-by-tenant-and-ID, optimistic concurrency, atomic aggregate/event-outbox persistence, and invariant existence checks. Read projections serve queries.

## Domain constraints

- No infrastructure, SDK, framework, network, clock, random, or storage dependencies.
- IDs, clocks, and policy inputs enter explicitly.
- Events include tenant, aggregate ID/type, sequence, schema version, event ID, time, correlation, and causation.
- Sensitive values never default-stringify.

