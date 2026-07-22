# Evidence Context Scaffold

- **Subdomain type**: Core / trust
- **Aggregate root**: `EvidenceBundle`
- **Repository port**: `EvidenceBundleRepository`
- **Status**: proposed

## Mission

Assemble, finalize, sign, verify, retain, and supersede scoped claims over exact remediation artifacts and verdicts.

## Ownership

Owns: predicate schema; manifest; completeness; artifact bindings; signature metadata; verification; bundle lineage.

Does not own: test execution; verdict computation; authorization; private key material.

## Relationships

- Upstream: Remediation Runs, Verification, Isolated Execution, key service.
- Downstream: External Actions and customer verifiers.
- All integrations use versioned published contracts and tenant-scoped opaque references.

## Package blueprint

- [Domain model](domain-model.md)
- [Application model](application.md)
- [Published contracts](contracts.md)
- [Operations and security](operations.md)
- [Test specification](testing.md)

A future implementation maps this context to an independent module with `domain/`, `application/`, and `infrastructure/`; only its application facade and published contracts are public.

