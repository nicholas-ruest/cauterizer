# Integration Management Context Scaffold

- **Subdomain type**: Supporting / platform
- **Aggregate root**: `IntegrationInstallation`
- **Repository port**: `IntegrationInstallationRepository`
- **Status**: proposed

## Mission

Own connector catalog entries, tenant installations, consented capabilities, configuration metadata, health, compatibility, and webhook delivery.

## Ownership

Owns: connector manifests; installations; capability consent; version compatibility; health; webhook delivery state.

Does not own: secret values; upstream domain semantics; payment data; external-action authorization.

## Relationships

- Upstream: Organization & Access, Commercial Entitlements, secret manager.
- Downstream: all contexts through narrow adapter ports.
- All integrations use versioned published contracts and tenant-scoped opaque references.

## Package blueprint

- [Domain model](domain-model.md)
- [Application model](application.md)
- [Published contracts](contracts.md)
- [Operations and security](operations.md)
- [Test specification](testing.md)

A future implementation maps this context to an independent module with `domain/`, `application/`, and `infrastructure/`; only its application facade and published contracts are public.

