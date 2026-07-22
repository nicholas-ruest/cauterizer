# ADR-022: Adopt Risk-Based Verification and Release Gates

- **Status**: proposed
- **Date**: 2026-07-22
- **Deciders**:
- **Tags**: testing, quality, release

## Context

Unit tests alone cannot validate information-flow separation, tenancy, sandbox confinement, evidence integrity, or disaster recovery. “Enterprise grade” requires measurable gates tied to architectural risks.

## Decision

Use a test pyramid plus architecture and operations gates: domain invariant/property tests; contract and schema compatibility tests; adapter tests against recorded fixtures; integration tests; end-to-end CVE fixtures; authorization/tenant-isolation tests; sandbox adversarial tests; conformance leakage tests; evidence tamper tests; fuzzing; performance/soak/chaos tests; backup restore and regional failover drills.

Map every ADR invariant and abuse case to automated or procedural evidence in a traceability matrix. Releases require static checks, tests, SBOM/license/security gates, migration rehearsal, signed provenance, canary analysis, rollback proof, and risk-based human approval. Flaky tests are quarantined with an owner and deadline, never silently retried to green.

## Consequences

### Positive
- Makes architecture claims falsifiable and release quality auditable.
- Finds cross-cutting failures ordinary feature tests miss.

### Negative
- High-fidelity environments and adversarial suites cost time and compute.
- Traceability needs continuous maintenance.

### Neutral
- Coverage percentages are supporting metrics, not release evidence by themselves.

## Links

- Depends on [ADR-005](ADR-005-enforce-a-solver-grader-conformance-firewall.md)
- Depends on [ADR-019](ADR-019-secure-the-software-supply-chain-and-release-process.md)
