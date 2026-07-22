# ADR-021: Govern Schema and Contract Evolution

- **Status**: proposed
- **Date**: 2026-07-22
- **Deciders**:
- **Tags**: schemas, compatibility, migrations

## Context

Long-lived runs and evidence must remain readable across upgrades, while APIs, events, policies, and adapter contracts evolve. In-place reinterpretation would alter historical meaning.

## Decision

Every persisted document, API, event, policy, and evidence predicate has an explicit semantic version and immutable published schema. Additive compatible changes preserve major version; breaking semantic or required-field changes create a new major version. Producers support current and previous major during a published window; consumers ignore allowed unknown fields and reject unknown security-critical semantics.

Migrations are versioned, reversible where possible, resumable, observable, tenant-safe, and tested against production-scale snapshots. Historical signed evidence is never rewritten; verifiers retain versioned interpretation. Use expand/migrate/contract deployment and compatibility tests in CI.

## Consequences

### Positive
- Enables rolling upgrades and durable evidence verification.
- Prevents silent historical reinterpretation.

### Negative
- Multiple versions and migrators increase maintenance.
- Security-critical extensions require stricter parsing than ordinary additive data.

### Neutral
- Tool choice for schema registry and migrations remains open.

## Links

- Depends on [ADR-012](ADR-012-use-versioned-events-with-transactional-outbox-and-inbox.md)
- Depends on [ADR-014](ADR-014-design-contract-first-idempotent-apis.md)
