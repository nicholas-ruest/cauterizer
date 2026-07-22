# Remediation Runs: Domain Model

## Aggregate root

`RemediationRun` is the sole aggregate root and is persisted through domain port `RemediationRunRepository`. State is private; behavior validates invariants before emitting immutable events. Cross-context objects are represented only by IDs and digests.

## Invariants

- `One immutable advisory, target, policy, tenant, and conformance mode per run`
- `Only authenticated owning-context events advance state`
- `Terminal runs never reopen`
- `Conflicting idempotency-key reuse is rejected`

## Value objects

- `RemediationRunId`
- `RunInputs`
- `RunPolicyRef`
- `ResourceBudget`
- `IdempotencyKey`
- `RunState`
- `RunLineage`

## Domain services and policies

- `RunTransitionPolicy`
- `NextStepPolicy`
- `CancellationPolicy`

## Repository contract

`RemediationRunRepository` supports load-by-tenant-and-ID, optimistic concurrency, atomic aggregate/event-outbox persistence, and invariant existence checks. Read projections serve queries.

## Domain constraints

- No infrastructure, SDK, framework, network, clock, random, or storage dependencies.
- IDs, clocks, and policy inputs enter explicitly.
- Events include tenant, aggregate ID/type, sequence, schema version, event ID, time, correlation, and causation.
- Sensitive values never default-stringify.

