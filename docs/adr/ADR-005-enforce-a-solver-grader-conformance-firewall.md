# ADR-005: Enforce a Solver-Grader Conformance Firewall

- **Status**: proposed
- **Date**: 2026-07-22
- **Deciders**:
- **Tags**: conformance, confidentiality, solver, grader

## Context

CVE-Bench derives its value from a hidden oracle: the solver sees the public advisory and vulnerable source but not the gold patch, hidden security test, FAIL-to-PASS identifiers, or grading feedback. Shared storage, logs, caches, process identity, agent memory, or repeated adaptive queries can leak that oracle and convert a remediation task into answer retrieval or test overfitting.

## Decision

Patch Proposals and Verification operate across a mandatory conformance firewall.

The solver receives only a versioned `SolverBrief` containing:

- the public problem statement and approved references;
- the immutable vulnerable source view;
- public build/test instructions explicitly allowed by policy;
- patch format, path, size, attempt, time, token, and cost limits.

The solver never receives or can access:

- gold/reference patch content or digest lookup capability;
- hidden security tests or identifiers;
- verifier-only paths, stores, logs, caches, timing details, or pass/fail signals;
- grader credentials, policy internals that expose the oracle, or prior conformant-run memory.

Verification creates a fresh workspace and identity after candidate submission. Solver and verifier use separate artifact namespaces, caches, service identities, logs, and memory. Conformant runs disable persistent solver learning unless a formal information-flow analysis proves isolation. The verifier emits a final structured evaluation; interactive test-driven retries against hidden results are prohibited.

Every run records a conformance declaration and enough metadata to audit the separation. If isolation cannot be demonstrated, the run is labeled `non-conformant` and cannot support the MVP success claim.

## Consequences

### Positive

- Preserves an independent test of remediation ability.
- Prevents hidden-test overfitting and self-certification.
- Makes conformant and exploratory workflows distinguishable.

### Negative

- Reduces opportunities for iterative repair using grader feedback.
- Requires separate identities, storage, caches, and observability views.
- Side-channel elimination is difficult and needs recurring review.

### Neutral

- Public baseline tests may be available to the solver if explicitly declared.
- Non-conformant exploratory runs may exist but must be labeled and segregated.

## Validation before acceptance

- Produce a data-flow diagram for every hidden artifact.
- Demonstrate that solver credentials cannot enumerate verifier resources.
- Decide whether timing, error classes, and retry counts reveal meaningful oracle information.

## Links

- Depends on [ADR-002](ADR-002-separate-the-system-into-seven-bounded-contexts.md)
- Depends on [ADR-004](ADR-004-isolate-all-untrusted-execution-in-ephemeral-workers.md)
- [Patch Proposals context](../ddd/contexts/patch-proposals.md)
- [Verification context](../ddd/contexts/verification.md)
- [CVE-Bench](https://github.com/ruvnet/CVE-bench)
