# Bounded Context: Patch Proposals

## Purpose and ownership

Produce an immutable candidate patch from an approved solver brief under explicit time, token, attempt, tool, path, and cost limits. It owns proposal attempts, solver provenance, candidate normalization, and proposal failure reasons.

It does not know hidden verifier artifacts, receive hidden-test feedback in conformant mode, grade its output, or assert that a candidate fixes a vulnerability.

## Aggregate

### `ProposalAttempt`

Identity: `ProposalAttemptId`; belongs to one remediation run but is not a child object mutable through that run.

Invariants:

- A proposal binds one immutable `SolverBrief` digest and solver configuration.
- The brief contains only information approved for the solver view.
- Attempt, cost, token, wall-clock, path, tool, and patch-size budgets cannot be exceeded.
- A successful attempt yields exactly one normalized candidate patch and rationale.
- Candidate content is immutable after submission.
- Solver output cannot include binaries, forbidden paths, undeclared artifacts, or executable control instructions.
- A conformant attempt cannot consume verifier events or persistent memory containing verifier information.

Repository: `ProposalAttemptRepository`.

## Value objects

- `SolverBrief`, `SolverIdentity`, `SolverConfiguration`
- `ProposalBudget`, `AllowedToolSet`, `SourceViewRef`
- `UnifiedPatch`, `PatchScope`, `ProposalRationale`
- `CandidatePatchRef`, `ProposalFailureReason`

## Domain services and policies

- `SolverViewPolicy`: constructs/validates the complete visible information set.
- `PatchNormalizationService`: canonicalizes and hashes unified diffs without applying them.
- `ProposalAdmissionPolicy`: checks output shape and budget compliance.

## Commands and queries

- `OpenProposalAttempt`, `SubmitSolverOutput`, `AbortProposalAttempt`
- `RecordProviderFailure`, `RecordBudgetExhaustion`
- `GetCandidatePatch`, `GetProposalProvenance`

## Domain events

- `ProposalAttemptOpened`, `PatchProposed`, `ProposalAttemptFailed`
- `ProposalBudgetExhausted`, `SolverProviderFailed`, `SolverOutputRejected`

Every event carries `ProposalAttemptId`; `PatchProposed` carries candidate digest and remediation-run reference, not a verdict.

## Published language

Publishes `CandidatePatchDescriptor` and proposal provenance. It never publishes raw model credentials, private prompts, chain-of-thought, or verifier information.

## Adapters

A manual/mock solver is the deterministic fallback. agentic-flow or direct provider integrations implement a context-owned `SolverPort`; provider SDK types are confined to infrastructure. Replacing routing cannot change proposal-domain semantics.

## Firewall obligations

Separate service identity, artifact namespace, cache, logs, telemetry visibility, and memory from Verification. No interactive callback after candidate submission in conformant runs.
