# Bounded Context: Remediation Runs

## Purpose and ownership

Own the identity, lifecycle, budgets, policy references, and idempotent coordination state for one advisory-target remediation attempt. It is the process manager, not the owner of execution observations, patches, verdict rules, evidence signatures, or approvals.

## Aggregate

### `RemediationRun`

Identity: `RemediationRunId` derived independently from idempotency key; the key is unique within a command scope.

Invariants:

- A run binds exactly one immutable advisory snapshot, target revision, run policy, and conformance mode.
- Bound input digests cannot change after creation.
- State advances only when the owning context's authenticated event is recorded.
- Terminal states cannot reopen; retry creates a new attempt or child run with lineage.
- Duplicate commands with identical idempotency key and payload are harmless; conflicting reuse is rejected.
- Budgets cannot increase without a separately recorded authorized policy change.
- Cancellation cannot erase completed events or artifacts.

Repository: `RemediationRunRepository`, backed by an append-only event stream and rebuildable projection per ADR-003.

## Lifecycle

```text
Draft -> InputsBound -> BaselineRequested -> BaselineObserved
      -> ProposalRequested -> PatchReceived -> AssessmentRequested
      -> Assessed -> EvidenceRequested -> Sealed

Any non-terminal active state -> Cancelled
Required missing/failed evidence -> Inconclusive -> Sealed
Conformance violation -> NonConformant -> Sealed
```

The exact state vocabulary may be refined before acceptance, but no transition may imply another context's result before its event exists.

## Value objects

- `RunInputs`, `TargetRevisionRef`, `RunPolicyRef`, `ConformanceMode`
- `ResourceBudget`, `AttemptBudget`, `IdempotencyKey`
- `RunState`, `RunLineage`, `ArtifactRef`

## Commands and queries

- `CreateRun`, `BindInputs`, `RequestBaseline`, `RequestProposal`
- `RequestAssessment`, `RequestEvidence`, `CancelRun`, `SealRun`
- `GetRun`, `GetRunTimeline`, `ListRunnableSteps`

## Domain events

- `RemediationRunCreated`, `RunInputsBound`, `BaselineRequested`
- `ProposalRequested`, `AssessmentRequested`, `EvidenceRequested`
- `RunCancelled`, `RunDeclaredInconclusive`, `RunDeclaredNonConformant`
- `RunRecordSealed`

Integration handlers also record references from `ExecutionObserved`, `PatchProposed`, `CandidateAssessed`, and `EvidenceBundleFinalized` without taking ownership of their contents.

## Published language

Publishes run ID, immutable input refs, lifecycle events, coarse idempotent application commands, and a redacted status projection. It never publishes hidden verifier locations.

## Orchestration boundary

Ruflo or another orchestrator may invoke coarse application commands and observe public status. It cannot append domain events directly, forge completion, raise budgets, access hidden artifacts, sign bundles, or authorize export.
