# Commercial Entitlements: Domain Model

## Aggregate root

`EntitlementAccount` is the sole aggregate root and is persisted through domain port `EntitlementAccountRepository`. State is private; behavior validates invariants before emitting immutable events. Cross-context objects are represented only by IDs and digests.

## Invariants

- `Expensive work requires a valid reservation`
- `Reservation and settlement are idempotent`
- `Concurrent reservations cannot exceed hard tenant limits`
- `Plan level never weakens security or evidence requirements`

## Value objects

- `PlanId`
- `Entitlement`
- `Quota`
- `UsageDimension`
- `BudgetReservation`
- `UsageRecord`
- `CreditAdjustment`

## Domain services and policies

- `EntitlementPolicy`
- `QuotaReservationPolicy`
- `UsageRatingPolicy`

## Repository contract

`EntitlementAccountRepository` supports load-by-tenant-and-ID, optimistic concurrency, atomic aggregate/event-outbox persistence, and invariant existence checks. Read projections serve queries.

## Domain constraints

- No infrastructure, SDK, framework, network, clock, random, or storage dependencies.
- IDs, clocks, and policy inputs enter explicitly.
- Events include tenant, aggregate ID/type, sequence, schema version, event ID, time, correlation, and causation.
- Sensitive values never default-stringify.

