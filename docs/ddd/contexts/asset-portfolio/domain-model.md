# Asset Portfolio: Domain Model

## Aggregate root

`AssetPortfolio` is the sole aggregate root and is persisted through domain port `AssetPortfolioRepository`. State is private; behavior validates invariants before emitting immutable events. Cross-context objects are represented only by IDs and digests.

## Invariants

- `Every remediation target is an active organization-owned asset`
- `Source authorization is explicit and revocable`
- `Target revision is immutable once bound to a run`
- `Scope exclusions override broad inclusions and are explainable`

## Value objects

- `AssetId`
- `AssetType`
- `SourceLocator`
- `RevisionSelector`
- `Environment`
- `Criticality`
- `ScopeRule`
- `Ownership`

## Domain services and policies

- `ScopeEvaluationPolicy`
- `TargetResolutionPolicy`
- `AssetRiskContextPolicy`

## Repository contract

`AssetPortfolioRepository` supports load-by-tenant-and-ID, optimistic concurrency, atomic aggregate/event-outbox persistence, and invariant existence checks. Read projections serve queries.

## Domain constraints

- No infrastructure, SDK, framework, network, clock, random, or storage dependencies.
- IDs, clocks, and policy inputs enter explicitly.
- Events include tenant, aggregate ID/type, sequence, schema version, event ID, time, correlation, and causation.
- Sensitive values never default-stringify.

