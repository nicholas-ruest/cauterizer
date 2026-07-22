# Asset Portfolio Context Scaffold

- **Subdomain type**: Supporting
- **Aggregate root**: `AssetPortfolio`
- **Repository port**: `AssetPortfolioRepository`
- **Status**: proposed

## Mission

Own customer-authorized repositories, packages, components, environments, criticality, ownership, and remediation scope.

## Ownership

Owns: assets; immutable target locators; ownership; environments; criticality; scope rules; source authorization.

Does not own: advisory truth; source checkout; test execution; patch verdicts.

## Relationships

- Upstream: Organization & Access and SCM adapters.
- Downstream: Advisory Intake and Remediation Runs.
- All integrations use versioned published contracts and tenant-scoped opaque references.

## Package blueprint

- [Domain model](domain-model.md)
- [Application model](application.md)
- [Published contracts](contracts.md)
- [Operations and security](operations.md)
- [Test specification](testing.md)

A future implementation maps this context to an independent module with `domain/`, `application/`, and `infrastructure/`; only its application facade and published contracts are public.

