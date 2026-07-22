# Advisory Intake Context Scaffold

- **Subdomain type**: Supporting
- **Aggregate root**: `AdvisoryRecord`
- **Repository port**: `AdvisoryRecordRepository`
- **Status**: proposed

## Mission

Acquire, normalize, attribute, deduplicate, and snapshot vulnerability information without treating remote data as trusted truth.

## Ownership

Owns: source observations; normalized snapshots; aliases; affected ranges; severity vectors; withdrawal history.

Does not own: asset authorization; queue priority; patch verification; external submission.

## Relationships

- Upstream: OSV and approved advisory connectors.
- Downstream: Asset Portfolio and Remediation Runs.
- All integrations use versioned published contracts and tenant-scoped opaque references.

## Package blueprint

- [Domain model](domain-model.md)
- [Application model](application.md)
- [Published contracts](contracts.md)
- [Operations and security](operations.md)
- [Test specification](testing.md)

A future implementation maps this context to an independent module with `domain/`, `application/`, and `infrastructure/`; only its application facade and published contracts are public.

