# External Actions Context Scaffold

- **Subdomain type**: Supporting / governance
- **Aggregate root**: `ActionAuthorization`
- **Repository port**: `ActionAuthorizationRepository`
- **Status**: proposed

## Mission

Bind authenticated human intent to a narrowly eligible evidence digest and perform governed exports or future mutations.

## Ownership

Owns: authorization request; grant; denial; revocation; action execution record; export redaction; receipts.

Does not own: verdict changes; evidence mutation; identity lifecycle; connector secret values.

## Relationships

- Upstream: Organization & Access, Evidence, Integration Management.
- Downstream: approved external destinations.
- All integrations use versioned published contracts and tenant-scoped opaque references.

## Package blueprint

- [Domain model](domain-model.md)
- [Application model](application.md)
- [Published contracts](contracts.md)
- [Operations and security](operations.md)
- [Test specification](testing.md)

A future implementation maps this context to an independent module with `domain/`, `application/`, and `infrastructure/`; only its application facade and published contracts are public.

