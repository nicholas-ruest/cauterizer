# Isolated Execution: Domain Model

## Aggregate root

`ExecutionLease` is the sole aggregate root and is persisted through domain port `ExecutionLeaseRepository`. State is private; behavior validates invariants before emitting immutable events. Cross-context objects are represented only by IDs and digests.

## Invariants

- `Request/environment/capabilities are immutable after allocation`
- `No undeclared privilege, secret, host mount, or egress`
- `One authoritative terminal receipt per lease`
- `Every terminal path records cleanup`

## Value objects

- `ExecutionLeaseId`
- `ExecutionRequest`
- `EnvironmentRef`
- `CapabilityEnvelope`
- `ResourceLimits`
- `ExecutionReceipt`
- `CleanupReceipt`

## Domain services and policies

- `ExecutionAdmissionPolicy`
- `EnvironmentVerificationService`
- `OutputSanitizationPolicy`

## Repository contract

`ExecutionLeaseRepository` supports load-by-tenant-and-ID, optimistic concurrency, atomic aggregate/event-outbox persistence, and invariant existence checks. Read projections serve queries.

## Domain constraints

- No infrastructure, SDK, framework, network, clock, random, or storage dependencies.
- IDs, clocks, and policy inputs enter explicitly.
- Events include tenant, aggregate ID/type, sequence, schema version, event ID, time, correlation, and causation.
- Sensitive values never default-stringify.

