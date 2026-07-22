# Verification Context Scaffold

- **Subdomain type**: Core / security critical
- **Aggregate root**: `CandidateAssessment`
- **Repository port**: `CandidateAssessmentRepository`
- **Status**: proposed

## Mission

Independently qualify fixtures, grade candidates in fresh environments, and issue deterministic narrowly scoped verdicts.

## Ownership

Owns: fixture qualification; assessment; observations; conformance declaration; policy verdict; reason codes.

Does not own: candidate generation; worker execution; evidence signing; approval.

## Relationships

- Upstream: Patch Proposals and Isolated Execution through segregated contracts.
- Downstream: Remediation Runs and Evidence.
- All integrations use versioned published contracts and tenant-scoped opaque references.

## Package blueprint

- [Domain model](domain-model.md)
- [Application model](application.md)
- [Published contracts](contracts.md)
- [Operations and security](operations.md)
- [Test specification](testing.md)

A future implementation maps this context to an independent module with `domain/`, `application/`, and `infrastructure/`; only its application facade and published contracts are public.

