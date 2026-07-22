# Bounded Context: Verification

## Purpose and ownership

Independently assess a candidate patch against a qualified fixture, required regression checks, conformance facts, and a versioned deterministic policy. Verification alone owns remediation verdict semantics.

It does not generate patches, mutate execution observations, sign evidence, approve export, or claim that fixture success proves universal safety.

## Aggregate

### `CandidateAssessment`

Identity: `CandidateAssessmentId`; binds one candidate patch, target revision, fixture, and assessment policy.

Invariants:

- Candidate, target, fixture, environment, and policy digests are immutable once assessment opens.
- Candidate grading uses a fresh workspace and verifier-only identity.
- A fixture is eligible only after vulnerable-base `FAIL` and gold-control `PASS` qualification is recorded.
- Hidden test and required regression observations come from declared isolated executions.
- Missing, corrupt, flaky, timed-out, or unqualified evidence cannot produce `VerifiedForFixture`.
- Conformance failure produces `NonConformant` regardless of test outcome.
- The same canonical inputs and policy version yield the same verdict and reason codes.
- A finalized assessment is immutable; correction creates a superseding assessment.

Repository: `CandidateAssessmentRepository`.

## Verdict value object

`AssessmentVerdict` is exactly one of:

- `VerifiedForFixture`
- `Rejected`
- `Inconclusive`
- `NonConformant`

No alias maps these values to `Safe` or `ReadyToDeploy`.

## Other value objects

- `QualifiedFixtureRef`, `CandidatePatchRef`, `AssessmentPolicyRef`
- `SecurityTestObservation`, `RegressionObservation`, `PatchScopeObservation`
- `ConformanceDeclaration`, `EvidenceCompleteness`
- `DecisionReason`, `AssessmentSummary`

## Domain services and policies

- `FixtureQualificationPolicy`: base-FAIL/gold-PASS discrimination.
- `CandidateEvaluationPolicy`: pure verdict and reason-code calculation.
- `PatchScopePolicy`: forbidden paths/content, binary, size, and unrelated-change checks.
- `FlakinessPolicy`: repeated-outcome treatment without success cherry-picking.

## Commands and queries

- `QualifyFixture`, `OpenCandidateAssessment`, `RecordAssessmentObservation`
- `DeclareConformance`, `FinalizeCandidateAssessment`, `SupersedeAssessment`
- `GetAssessment`, `ExplainVerdict`, `GetFixtureQualification`

## Domain events

- `FixtureQualified`, `FixtureQualificationFailed`
- `CandidateAssessmentOpened`, `AssessmentObservationRecorded`
- `CandidateAssessed`, `CandidateAssessmentSuperseded`

Events carry `CandidateAssessmentId`; fixture events carry their fixture aggregate/reference identity as specified before implementation.

## Published language

Publishes the immutable `AssessmentDescriptor`, verdict, reason codes, and observation digests. Hidden artifact contents and locations never enter the published contract.

## Information security

Verifier data uses a separate identity, store, cache, logs, and memory. Patch Proposals cannot subscribe to assessment outcomes for conformant attempts. Operators may inspect results only under policy that preserves benchmark claims.
