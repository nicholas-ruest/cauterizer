# ADR-008: Integrate Upstream Tools Through Replaceable Adapters

- **Status**: proposed
- **Date**: 2026-07-22
- **Deciders**:
- **Tags**: adapters, dependencies, orchestration, anti-corruption

## Context

The proposed ecosystem includes OSV, a HackerOne meta-harness, CVE-Bench, agentic-flow, ruflo, and ruDevolution/ruvector. Research found rapid upstream evolution, an unavailable advertised HackerOne npm package, a small CVE-Bench dataset with an internal count annotation inconsistency, and unresolved ruDevolution crate/license questions. Binding the canonical domain to any SDK would transfer upstream churn and authority assumptions into Cauterizer's core.

## Decision

All external systems are infrastructure adapters behind context-owned ports and anti-corruption layers. Canonical domain contracts never expose upstream SDK types.

Initial adapter roles are:

- OSV: read-only public advisory acquisition into `AdvisorySnapshot`;
- HackerOne meta-harness: optional source-pinned, mock/read-only intake or export translation after license and compatibility checks;
- CVE-Bench: pinned fixture and grader adapter behind the solver/grader firewall;
- agentic-flow: optional model/provider routing behind the Patch Proposals solver port;
- ruflo: optional workflow scheduling through coarse idempotent application commands;
- ruDevolution/ruvector: optional analysis artifact provider for Evidence.

Every adapter declares its upstream source/version/commit, license assessment, capabilities, network needs, failure modes, and contract-test fixture. Missing optional adapters produce explicit `Unavailable` outcomes; they never silently weaken verification.

Ruflo and agentic-flow are not correctness dependencies. The deterministic path must remain usable through direct application services with a mock or manual solver. Orchestration has no raw sandbox, verifier-store, signing, approval, or external-write capability.

Runtime and physical deployment technology remain undecided. A later ADR will select them after the threat model and sandbox spike; TypeScript affinity alone is insufficient grounds for a security-core choice.

## Consequences

### Positive

- Contains upstream churn, missing packages, and licensing uncertainty.
- Supports deterministic local fallback and contract testing.
- Prevents orchestration frameworks from entering the trusted verdict path.

### Negative

- Requires translation code and explicit compatibility maintenance.
- Some upstream features will not be exposed through narrow ports.
- Pinning improves repeatability but creates an upgrade and vulnerability-management burden.

### Neutral

- Vendoring is permitted only after license review and with source provenance recorded.
- Adapter replacement does not change domain semantics when its contract remains satisfied.

## Validation before acceptance

- Define the minimal port for each MVP dependency.
- Resolve license and distribution status before pinning or vendoring.
- Prove the end-to-end path with optional orchestration disabled.

## Links

- Depends on [ADR-002](ADR-002-separate-the-system-into-seven-bounded-contexts.md)
- Depends on [ADR-006](ADR-006-make-remediation-verdicts-deterministic-and-evidence-based.md)
- Depends on [ADR-007](ADR-007-emit-in-toto-compatible-evidence-bundles.md)
- [Context map](../ddd/context-map.md)
