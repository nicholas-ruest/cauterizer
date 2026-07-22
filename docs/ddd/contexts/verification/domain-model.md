# Verification: Domain Model

## Aggregate root

`CandidateAssessment` is the sole aggregate root and is persisted through domain port `CandidateAssessmentRepository`. State is private; behavior validates invariants before emitting immutable events. Cross-context objects are represented only by IDs and digests.

## Invariants

- `Fixture requires vulnerable-base FAIL and gold-control PASS`
- `Candidate uses fresh verifier workspace and identity`
- `Missing/flaky/corrupt evidence cannot verify`
- `Conformance failure dominates test success`
- `Final assessments are immutable`

## Value objects

- `CandidateAssessmentId`
- `QualifiedFixtureRef`
- `AssessmentPolicyRef`
- `SecurityTestObservation`
- `RegressionObservation`
- `AssessmentVerdict`
- `DecisionReason`

## Domain services and policies

- `FixtureQualificationPolicy`
- `CandidateEvaluationPolicy`
- `PatchScopePolicy`
- `FlakinessPolicy`

## Repository contract

`CandidateAssessmentRepository` supports load-by-tenant-and-ID, optimistic concurrency, atomic aggregate/event-outbox persistence, and invariant existence checks. Read projections serve queries.

## Domain constraints

- No infrastructure, SDK, framework, network, clock, random, or storage dependencies.
- IDs, clocks, and policy inputs enter explicitly.
- Events include tenant, aggregate ID/type, sequence, schema version, event ID, time, correlation, and causation.
- Sensitive values never default-stringify.

