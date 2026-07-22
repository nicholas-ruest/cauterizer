# ADR-023: Enforce Entitlements, Quotas, and Auditable Usage

- **Status**: proposed
- **Date**: 2026-07-22
- **Deciders**:
- **Tags**: commercial, entitlements, metering, cost

## Context

Solver tokens, isolated compute, storage, connectors, retention, and support tiers have material cost. Billing-provider state must not be queried synchronously inside security decisions, and quota races must not permit uncontrolled spend.

## Decision

Commercial Entitlements owns versioned plan grants, feature flags, quotas, reservations, usage records, credits, and enforcement decisions. A run reserves worst-case budget before expensive work and settles actual immutable usage afterward. Reservation and settlement are idempotent; concurrent limits are strongly enforced per tenant.

Billing/payment providers are adapters receiving minimal rated usage and customer references; Cauterizer stores no card data. Verification semantics never vary by plan: plans may limit scale, retention, integrations, deployment, or support, but cannot buy a weaker security verdict. Emit explainable usage and admin-visible budget alerts.

## Consequences

### Positive
- Supports sustainable pricing, spend protection, and enterprise procurement.
- Decouples security correctness from payment availability.

### Negative
- Usage reconciliation, disputes, and provider webhooks add complexity.
- Reservation policy can temporarily reduce utilization.

### Neutral
- Pricing and packaging remain product decisions outside the domain mechanics.

## Links

- Depends on [ADR-009](ADR-009-add-enterprise-platform-bounded-contexts.md)
- Depends on [ADR-012](ADR-012-use-versioned-events-with-transactional-outbox-and-inbox.md)
