# Isolated Execution Context Scaffold

- **Subdomain type**: Supporting / security critical
- **Aggregate root**: `ExecutionLease`
- **Repository port**: `ExecutionLeaseRepository`
- **Status**: proposed

## Mission

Admit and execute declarative jobs in ephemeral confined workers, returning observations without verdict authority.

## Ownership

Owns: job admission; capability envelope; worker lease; resource limits; receipts; cleanup.

Does not own: patch choice; test interpretation; verdict; signing; external action.

## Relationships

- Upstream: Remediation Runs and Verification.
- Downstream: Verification and Evidence through receipt descriptors.
- All integrations use versioned published contracts and tenant-scoped opaque references.

## Package blueprint

- [Domain model](domain-model.md)
- [Application model](application.md)
- [Published contracts](contracts.md)
- [Operations and security](operations.md)
- [Test specification](testing.md)

A future implementation maps this context to an independent module with `domain/`, `application/`, and `infrastructure/`; only its application facade and published contracts are public.

