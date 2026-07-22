# Organization & Access Context Scaffold

- **Subdomain type**: Supporting / platform
- **Aggregate root**: `Organization`
- **Repository port**: `OrganizationRepository`
- **Status**: proposed

## Mission

Own enterprise tenants, memberships, federated identities, service principals, roles, policy assignments, support access, and organization lifecycle.

## Ownership

Owns: organizations; memberships; role assignments; identity-provider configuration; service principals; break-glass grants.

Does not own: password authentication implementation; payment data; remediation verdicts; connector secrets.

## Relationships

- Upstream: external IdP/SCIM adapters.
- Downstream: all tenant-scoped contexts.
- All integrations use versioned published contracts and tenant-scoped opaque references.

## Package blueprint

- [Domain model](domain-model.md)
- [Application model](application.md)
- [Published contracts](contracts.md)
- [Operations and security](operations.md)
- [Test specification](testing.md)

A future implementation maps this context to an independent module with `domain/`, `application/`, and `infrastructure/`; only its application facade and published contracts are public.

