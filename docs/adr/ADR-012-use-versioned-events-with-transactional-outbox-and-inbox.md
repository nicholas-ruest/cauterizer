# ADR-012: Use Versioned Events with Transactional Outbox and Inbox

- **Status**: proposed
- **Date**: 2026-07-22
- **Deciders**:
- **Tags**: events, messaging, reliability

## Context

Eleven contexts coordinate long-running work. Distributed transactions are unavailable, and naive publish-after-commit loses messages while at-least-once delivery creates duplicates.

## Decision

Persist domain changes and outgoing events atomically through a transactional outbox. Consumers use durable inbox deduplication keyed by event ID and handler version. Delivery is at least once; handlers are idempotent and order-sensitive streams include aggregate sequence numbers.

Every event has event ID, tenant ID, aggregate ID/type, sequence, event type/version, occurred time, correlation/causation IDs, producer version, data classification, and payload. Consumers tolerate unknown additive fields. Poison events enter a tenant-safe dead-letter workflow with operator replay; they are never silently dropped. Events contain references/digests rather than large or Restricted payloads.

## Consequences

### Positive
- Prevents lost state transitions and enables replay/audit.
- Formalizes duplicate, ordering, and poison-message behavior.

### Negative
- Adds outbox relay, inbox storage, schema registry, and operational tooling.
- Eventual consistency must be explicit in UX and APIs.

### Neutral
- Broker technology remains a deployment ADR detail.

## Links

- Depends on [ADR-003](ADR-003-use-immutable-snapshots-and-an-append-only-run-lifecycle.md)
- Depends on [ADR-009](ADR-009-add-enterprise-platform-bounded-contexts.md)
