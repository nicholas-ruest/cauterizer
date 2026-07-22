# Integration Management: Domain Model

## Aggregate root

`IntegrationInstallation` is the sole aggregate root and is persisted through domain port `IntegrationInstallationRepository`. State is private; behavior validates invariants before emitting immutable events. Cross-context objects are represented only by IDs and digests.

## Invariants

- `Installation capabilities cannot exceed connector manifest or admin consent`
- `Secret values are referenced but never readable from the aggregate`
- `Revoked/disabled connectors cannot initiate work`
- `Webhook retries are idempotent and payload-classification aware`

## Value objects

- `ConnectorId`
- `ConnectorVersion`
- `CapabilityManifest`
- `InstallationId`
- `ConsentGrant`
- `SecretRef`
- `HealthStatus`
- `WebhookDelivery`

## Domain services and policies

- `ConnectorAdmissionPolicy`
- `CompatibilityPolicy`
- `WebhookDeliveryPolicy`

## Repository contract

`IntegrationInstallationRepository` supports load-by-tenant-and-ID, optimistic concurrency, atomic aggregate/event-outbox persistence, and invariant existence checks. Read projections serve queries.

## Domain constraints

- No infrastructure, SDK, framework, network, clock, random, or storage dependencies.
- IDs, clocks, and policy inputs enter explicitly.
- Events include tenant, aggregate ID/type, sequence, schema version, event ID, time, correlation, and causation.
- Sensitive values never default-stringify.

