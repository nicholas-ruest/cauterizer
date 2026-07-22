# Patch Proposals: Domain Model

## Aggregate root

`ProposalAttempt` is the sole aggregate root and is persisted through domain port `ProposalAttemptRepository`. State is private; behavior validates invariants before emitting immutable events. Cross-context objects are represented only by IDs and digests.

## Invariants

- `Brief and configuration are immutable`
- `Output cannot exceed scope/budgets`
- `One successful attempt yields one immutable candidate`
- `Conformant attempts consume no verifier information or contaminated memory`

## Value objects

- `ProposalAttemptId`
- `SolverBrief`
- `SolverIdentity`
- `ProposalBudget`
- `AllowedToolSet`
- `UnifiedPatch`
- `CandidatePatchRef`

## Domain services and policies

- `SolverViewPolicy`
- `PatchNormalizationService`
- `ProposalAdmissionPolicy`

## Repository contract

`ProposalAttemptRepository` supports load-by-tenant-and-ID, optimistic concurrency, atomic aggregate/event-outbox persistence, and invariant existence checks. Read projections serve queries.

## Domain constraints

- No infrastructure, SDK, framework, network, clock, random, or storage dependencies.
- IDs, clocks, and policy inputs enter explicitly.
- Events include tenant, aggregate ID/type, sequence, schema version, event ID, time, correlation, and causation.
- Sensitive values never default-stringify.

