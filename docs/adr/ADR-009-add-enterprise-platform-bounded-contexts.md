# ADR-009: Add Enterprise Platform Bounded Contexts

- **Status**: proposed
- **Date**: 2026-07-22
- **Deciders**:
- **Tags**: ddd, enterprise, commercial

## Context

The original seven contexts model the remediation engine but omit customer tenancy, owned assets, integration lifecycle, and paid-plan enforcement. Those concerns cannot be scattered through security contexts without corrupting their language and authorization boundaries.

## Decision

Extend ADR-002 with four contexts: **Organization & Access**, **Asset Portfolio**, **Integration Management**, and **Commercial Entitlements**. The resulting eleven-context map is canonical. These contexts publish tenant, target, connection, and entitlement facts; they never participate in verification verdict calculation.

Organization & Access owns organizations, memberships, service principals, roles, and authorization policy. Asset Portfolio owns customer-authorized repositories/components and engagement scope. Integration Management owns external connector configuration and health without owning secret material. Commercial Entitlements owns plans, quotas, usage reservations, and billable usage records without owning payment-card data.

## Consequences

### Positive
- Establishes tenant isolation and commercial product boundaries.
- Keeps identity, scope, integrations, and billing out of remediation aggregates.

### Negative
- Adds coordination and consistency requirements.
- Requires four more domain packages and contract suites.

### Neutral
- Payment processing remains an external adapter; this is not a payments platform.

## Links

- Extends [ADR-002](ADR-002-separate-the-system-into-seven-bounded-contexts.md)
- [Context map](../ddd/context-map.md)
