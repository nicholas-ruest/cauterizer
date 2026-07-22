# External Actions: Domain Model

## Aggregate root

`ActionAuthorization` is the sole aggregate root and is persisted through domain port `ActionAuthorizationRepository`. State is private; behavior validates invariants before emitting immutable events. Cross-context objects are represented only by IDs and digests.

## Invariants

- `Only eligible verified evidence may be authorized`
- `Actor/action/resource/destination/expiry are exact`
- `Agent/service cannot impersonate human approval`
- `Expired/revoked/mismatched grants deny`
- `Actions are idempotent and auditable`

## Value objects

- `ActionAuthorizationId`
- `HumanActorRef`
- `ActionType`
- `ActionScope`
- `AuthorizationPeriod`
- `ExportPolicyRef`
- `ActionReceipt`

## Domain services and policies

- `EvidenceEligibilityPolicy`
- `AuthorizationPolicy`
- `ExportRedactionPolicy`
- `ExternalActionPolicy`

## Repository contract

`ActionAuthorizationRepository` supports load-by-tenant-and-ID, optimistic concurrency, atomic aggregate/event-outbox persistence, and invariant existence checks. Read projections serve queries.

## Domain constraints

- No infrastructure, SDK, framework, network, clock, random, or storage dependencies.
- IDs, clocks, and policy inputs enter explicitly.
- Events include tenant, aggregate ID/type, sequence, schema version, event ID, time, correlation, and causation.
- Sensitive values never default-stringify.

