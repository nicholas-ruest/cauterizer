# ADR-017: Define SLOs, Resilience, and Disaster Recovery

- **Status**: proposed
- **Date**: 2026-07-22
- **Deciders**:
- **Tags**: reliability, slo, disaster-recovery

## Context

Enterprise operation requires explicit availability, durability, recovery, and support promises. A long-running security workflow must survive process, worker, provider, zone, and regional failures without duplicating external actions or losing evidence.

## Decision

Set service-level indicators for API availability/latency, queue age, run completion, artifact durability, webhook delivery, and evidence verification. Initial contractual SLOs are chosen only after load tests; internal objectives must be stricter than customer commitments. Define error budgets and release policy.

All commands are retry-safe, workflows resume from durable state, and dependencies use bounded exponential backoff, jitter, deadlines, circuit breakers, bulkheads, and load shedding. Operate multi-zone by default. Define tier-specific RPO/RTO, encrypted tested backups, cross-region recovery for eligible data, quarterly restore tests, and documented degraded modes. External Actions remains fail-closed.

## Consequences

### Positive
- Makes reliability measurable and commercially supportable.
- Converts recovery from assumption into tested capability.

### Negative
- Redundancy, drills, and telemetry add cost.
- Some third-party outages remain outside direct control.

### Neutral
- Exact SLO/RPO/RTO values are commercial decisions informed by benchmarks.

## Links

- Depends on [ADR-012](ADR-012-use-versioned-events-with-transactional-outbox-and-inbox.md)
- Depends on [ADR-013](ADR-013-separate-transactional-metadata-from-content-addressed-artifacts.md)
