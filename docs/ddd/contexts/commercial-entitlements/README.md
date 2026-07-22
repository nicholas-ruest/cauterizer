# Commercial Entitlements Context Scaffold

- **Subdomain type**: Supporting / commercial
- **Aggregate root**: `EntitlementAccount`
- **Repository port**: `EntitlementAccountRepository`
- **Status**: proposed

## Mission

Own plans, grants, quotas, reservations, usage settlement, credits, and commercial enforcement without changing verification semantics.

## Ownership

Owns: plan assignments; feature grants; quota windows; budget reservations; immutable usage records; credit adjustments.

Does not own: payment-card data; invoice rendering; verification policy; provider token counting internals.

## Relationships

- Upstream: billing provider and Organization & Access.
- Downstream: Remediation Runs, Patch Proposals, Isolated Execution, Integration Management.
- All integrations use versioned published contracts and tenant-scoped opaque references.

## Package blueprint

- [Domain model](domain-model.md)
- [Application model](application.md)
- [Published contracts](contracts.md)
- [Operations and security](operations.md)
- [Test specification](testing.md)

A future implementation maps this context to an independent module with `domain/`, `application/`, and `infrastructure/`; only its application facade and published contracts are public.

