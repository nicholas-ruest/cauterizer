# Asset Portfolio: Application Model

## Commands

- `RegisterAsset`
- `VerifySourceOwnership`
- `ClassifyAsset`
- `DefineScope`
- `DeactivateAsset`
- `ResolveTargetRevision`

Handlers authenticate and authorize, validate tenant and idempotency scope, load one aggregate, invoke behavior, atomically persist aggregate/events/outbox, and return a stable result. They never call another context's repository.

## Queries

- `GetAsset`
- `SearchAssets`
- `EvaluateScope`
- `ListOwnedRepositories`
- `GetRiskContext`

Queries read tenant-filtered projections, enforce field authorization/classification, use cursor pagination where plural, and declare consistency/freshness.

## Application rules

- Translate public DTOs through anti-corruption layers.
- Propagate deadlines, correlation, causation, actor, tenant, and purpose.
- Reserve commercial budget before costly operations where applicable.
- Audit privileged/security-sensitive decisions.
- Return stable problem codes; never provider errors, stack traces, internal paths, or hidden verifier details.

