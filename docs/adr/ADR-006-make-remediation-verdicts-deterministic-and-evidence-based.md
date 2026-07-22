# ADR-006: Make Remediation Verdicts Deterministic and Evidence-Based

- **Status**: proposed
- **Date**: 2026-07-22
- **Deciders**:
- **Tags**: policy, verification, determinism

## Context

A model can propose a patch and rationale but cannot be trusted to certify its own work. A hidden security test demonstrates one expected behavior, not the absence of every vulnerability. CVSS conveys severity, not complete operational risk. Cauterizer therefore needs narrow, reproducible decision semantics that do not turn probabilistic opinions or a single passing test into an unrestricted “safe” claim.

## Decision

Verification is the sole owner of remediation verdicts. A versioned deterministic policy evaluates immutable observations from fresh isolated executions.

The initial verdict vocabulary is:

- `VerifiedForFixture`: the declared vulnerable baseline failed, the declared gold control passed during fixture qualification, and the candidate passed the hidden security test plus required regression and policy checks.
- `Rejected`: at least one required check failed or the patch violated policy.
- `Inconclusive`: required evidence was missing, unstable, timed out, corrupted, or could not be reproduced.
- `NonConformant`: the solver/grader separation or declared evaluation procedure was violated.

`VerifiedForFixture` is deliberately not named `Safe`, `FixedEverywhere`, or `ReadyToDeploy`.

Minimum policy inputs are:

- exact advisory and target revision;
- fixture qualification result;
- candidate patch digest and changed paths;
- hidden security-test result;
- required baseline regression result;
- repeatability/flakiness observations;
- sandbox and conformance status;
- patch scope, size, forbidden content, and budget limits;
- evidence completeness and integrity.

Policy evaluation is pure: the same canonical inputs and policy version produce the same decision and reasons. AI-generated scores, CVSS, exploit likelihood, or operator priority may inform queueing but cannot override missing verification evidence.

## Consequences

### Positive

- Produces reviewable and reproducible outcomes.
- Prevents marketing language from exceeding observed evidence.
- Separates prioritization from proof of fixture-specific remediation.

### Negative

- Deterministic gates may reject useful patches when environments are flaky.
- A narrow verdict is less convenient than a binary “fixed” label.
- Regression-suite selection becomes a security-sensitive policy decision.

### Neutral

- Human approval may authorize export but cannot rewrite a verdict.
- Future policies can add evidence types through explicit versioning.

## Validation before acceptance

- Define the initial policy schema and canonical reason codes.
- Select the required baseline regression subset for the MVP fixture.
- Define how repeated inconsistent outcomes become `Inconclusive` rather than cherry-picked success.

## Links

- Depends on [ADR-003](ADR-003-use-immutable-snapshots-and-an-append-only-run-lifecycle.md)
- Depends on [ADR-005](ADR-005-enforce-a-solver-grader-conformance-firewall.md)
- [Verification context](../ddd/contexts/verification.md)
