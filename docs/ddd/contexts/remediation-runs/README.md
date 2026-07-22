# Remediation Runs Context Scaffold

- **Subdomain type**: Core
- **Aggregate root**: `RemediationRun`
- **Repository port**: `RemediationRunRepository`
- **Status**: proposed

## Mission

Coordinate one immutable advisory-target-policy attempt through durable, idempotent, resumable lifecycle transitions.

## Ownership

Owns: run identity; bound inputs; lifecycle; budgets; correlation; cancellation; lineage; sealed run record.

Does not own: execution internals; candidate generation; verdict calculation; signing; approval.

## Relationships

- Upstream: Organization & Access, Commercial Entitlements, Asset Portfolio, Advisory Intake.
- Downstream: Isolated Execution, Patch Proposals, Verification, Evidence.
- All integrations use versioned published contracts and tenant-scoped opaque references.

## Package blueprint

- [Domain model](domain-model.md)
- [Application model](application.md)
- [Published contracts](contracts.md)
- [Operations and security](operations.md)
- [Test specification](testing.md)

A future implementation maps this context to an independent module with `domain/`, `application/`, and `infrastructure/`; only its application facade and published contracts are public.

