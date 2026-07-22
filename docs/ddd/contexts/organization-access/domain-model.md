# Organization & Access: Domain Model

## Aggregate root

`Organization` is the sole aggregate root and is persisted through domain port `OrganizationRepository`. State is private; behavior validates invariants before emitting immutable events. Cross-context objects are represented only by IDs and digests.

## Invariants

- `Every actor-to-resource decision is organization-scoped and deny-by-default`
- `The last active organization owner cannot be removed`
- `Break-glass access is time-bound, justified, approved, and audited`
- `Service principals use short-lived workload identity and explicit scopes`

## Value objects

- `OrganizationId`
- `ActorId`
- `Membership`
- `Role`
- `Permission`
- `PolicyCondition`
- `FederationConfig`
- `SupportAccessGrant`

## Domain services and policies

- `AuthorizationPolicy`
- `FederationPolicy`
- `SupportAccessPolicy`

## Repository contract

`OrganizationRepository` supports load-by-tenant-and-ID, optimistic concurrency, atomic aggregate/event-outbox persistence, and invariant existence checks. Read projections serve queries.

## Domain constraints

- No infrastructure, SDK, framework, network, clock, random, or storage dependencies.
- IDs, clocks, and policy inputs enter explicitly.
- Events include tenant, aggregate ID/type, sequence, schema version, event ID, time, correlation, and causation.
- Sensitive values never default-stringify.

