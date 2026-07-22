# ADR-014: Design Contract-First Idempotent APIs

- **Status**: proposed
- **Date**: 2026-07-22
- **Deciders**:
- **Tags**: api, idempotency, compatibility

## Context

Web UI, CLI, automation, and enterprise integrations need stable behavior across retries and rolling upgrades. Exposing domain internals or asynchronous operations as long synchronous requests would create brittle clients.

## Decision

Define external HTTP APIs with OpenAPI and asynchronous event/webhook schemas with AsyncAPI or equivalent machine-readable contracts before implementation. Mutating requests require tenant scope, idempotency key, request schema version, and optimistic concurrency token where applicable. Long operations return operation/run resources and use polling or signed webhooks.

Use opaque IDs, RFC 7807-style problem details, cursor pagination, explicit rate-limit headers, correlation IDs, and stable machine reason codes. Do not expose internal stack traces, storage paths, hidden verifier details, or provider SDK types. Breaking changes require a new major contract and migration/deprecation window.

## Consequences

### Positive
- Enables SDK generation, deterministic retries, and enterprise automation.
- Separates public compatibility from internal refactoring.

### Negative
- Contract governance and compatibility testing slow ad hoc changes.
- Async workflows require client education.

### Neutral
- GraphQL may support read composition later but cannot bypass application authorization.

## Links

- Depends on [ADR-003](ADR-003-use-immutable-snapshots-and-an-append-only-run-lifecycle.md)
- Depends on [ADR-010](ADR-010-enforce-tenant-isolation-and-zero-trust-authorization.md)
