# ADR-019: Secure the Software Supply Chain and Release Process

- **Status**: proposed
- **Date**: 2026-07-22
- **Deciders**:
- **Tags**: supply-chain, release, sbom, provenance

## Context

Cauterizer is a security product that executes hostile software. Compromised dependencies, build actions, images, or release credentials would invalidate its evidence and customer trust.

## Decision

Pin dependencies and actions by immutable digest; use lockfiles, automated vulnerability/license review, SBOMs, secret scanning, SAST, dependency review, and reproducible/hermetic builds where feasible. Build releases on isolated CI identities, sign artifacts and provenance, verify before deployment, and require protected branches, review, status gates, and separation of release duties.

Maintain vulnerability disclosure, patch SLAs, coordinated release/rollback, artifact revocation, and customer security advisories. Production accepts only policy-approved signed artifacts. Generated code and agent changes pass the same review and test gates as human changes.

## Consequences

### Positive
- Protects the product and strengthens evidence credibility.
- Supports enterprise procurement and incident response.

### Negative
- Pinning, provenance, and license review slow upgrades.
- Reproducibility across worker ecosystems is difficult.

### Neutral
- SLSA claims are made only after formal assessment, not by tool presence.

## Links

- Depends on [ADR-007](ADR-007-emit-in-toto-compatible-evidence-bundles.md)
- Depends on [ADR-015](ADR-015-centralize-secrets-and-cryptographic-key-lifecycle.md)
