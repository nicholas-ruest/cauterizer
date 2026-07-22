# ADR-018: Deploy Control, Data, and Execution Planes Separately

- **Status**: proposed
- **Date**: 2026-07-22
- **Deciders**:
- **Tags**: deployment, isolation, scaling

## Context

API/control workloads, durable data services, and hostile execution have different trust, scaling, and failure characteristics. Co-locating them expands the trusted computing base and lets workload spikes threaten authorization or evidence services.

## Decision

Define three deployable planes: a control plane for APIs, identity, coordination, policy, and entitlements; a data plane for transactional metadata, events, artifacts, audit, and keys; and an execution plane for ephemeral acquisition/solver/verifier workers. Use separate identities, network policies, autoscaling, quotas, node pools/accounts, and release controls.

Execution cannot initiate control/data-plane calls except through narrow job-scoped endpoints. Verifier and solver pools are separately isolated. Support SaaS multi-tenant, dedicated tenant, and customer-managed execution-plane editions through the same contracts. Infrastructure is declarative, immutable, scanned, signed, and promoted across environments.

## Consequences

### Positive
- Limits blast radius and scales expensive workers independently.
- Enables enterprise deployment editions without domain forks.

### Negative
- Raises networking, infrastructure, and release complexity.
- Customer-managed workers require compatibility and support boundaries.

### Neutral
- Specific cloud/orchestrator products remain a later choice.

## Links

- Depends on [ADR-004](ADR-004-isolate-all-untrusted-execution-in-ephemeral-workers.md)
- Depends on [ADR-017](ADR-017-define-slos-resilience-and-disaster-recovery.md)
