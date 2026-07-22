# Patch Proposals Context Scaffold

- **Subdomain type**: Supporting / probabilistic
- **Aggregate root**: `ProposalAttempt`
- **Repository port**: `ProposalAttemptRepository`
- **Status**: proposed

## Mission

Create one immutable bounded candidate patch from an approved solver view under cost, time, tool, and information limits.

## Ownership

Owns: solver brief; attempt; provider provenance; budgets; candidate normalization; failure reasons.

Does not own: hidden tests; verifier results; verdicts; release decisions.

## Relationships

- Upstream: Remediation Runs, Commercial Entitlements, Asset Portfolio.
- Downstream: Verification through one-way PatchProposed.
- All integrations use versioned published contracts and tenant-scoped opaque references.

## Package blueprint

- [Domain model](domain-model.md)
- [Application model](application.md)
- [Published contracts](contracts.md)
- [Operations and security](operations.md)
- [Test specification](testing.md)

A future implementation maps this context to an independent module with `domain/`, `application/`, and `infrastructure/`; only its application facade and published contracts are public.

