# DDD Validation Report

Date: 2026-07-22  
Scope: `docs/ddd/`  
Method: documentation-level application of `ruflo-ddd:ddd-validate`; no `src/*/domain/` implementation exists.

## Summary

| Category | Errors | Warnings | Result |
|---|---:|---:|---|
| BOUNDARY | 0 | 1 | Document model passes; implementation cannot yet be inspected |
| INVARIANT | 0 | 1 | Every aggregate documents invariants; enforcement is unimplemented |
| EVENT | 0 | 1 | Events are past-tense and context-owned; immutability is unimplemented |
| REPOSITORY | 0 | 1 | One domain repository is specified per aggregate; placement is unimplemented |
| Total | 0 | 4 | Documentation valid with pre-implementation limitations |

## Context discovery

Eleven documented bounded-context packages were found, each containing overview, domain model, application model, contracts, operations/security, and test specifications:

1. Organization & Access
2. Commercial Entitlements
3. Asset Portfolio
4. Integration Management
5. Advisory Intake
6. Remediation Runs
7. Isolated Execution
8. Patch Proposals
9. Verification
10. Evidence
11. External Actions

No `src/*/domain/` contexts exist, consistent with the instruction not to implement.

## Boundary checks

Result: **Pass at design level**.

- The context map gives every cross-context relationship a published contract or integration event.
- Internal entities and repository representations are not shared.
- Cross-context references are opaque IDs and digests.
- Upstream SDK types are confined behind anti-corruption layers.
- Patch Proposals has no permitted dependency on Verification results in conformant runs.
- Execution reports observations but cannot assign verdicts.
- Evidence records Verification's verdict without recomputing it.
- External Actions cannot alter a verdict or evidence bundle.
- Organization & Access owns tenant and actor policy; tenant filtering is required independently at application, persistence, artifact, event, worker, and telemetry boundaries.
- Commercial Entitlements can limit consumption but cannot weaken verification semantics.
- Asset Portfolio is the sole owner of customer-authorized target scope.
- Integration Management owns connector capabilities but not secret values or another context's domain semantics.

Warning `BOUNDARY-001`: physical imports, database access, service identities, stores, caches, telemetry, and deployment permissions cannot be validated until implementation exists.

## Aggregate invariant checks

Result: **Pass at design level**.

Each context defines one aggregate root, identifies its ownership, and lists behavior-level invariants. Child concepts are value objects or immutable references; no document exposes public setters or mutable public properties.

Particularly important invariants are present:

- immutable advisory/run/patch/assessment/bundle bindings;
- idempotent run commands and append-only history;
- resource/capability confinement for execution;
- solver/grader information separation;
- deterministic, narrow verdict semantics;
- signer authority separation;
- exact-scope human authorization.

Warning `INVARIANT-001`: tests proving these invariants do not exist. Future aggregate APIs must prevent construction or mutation that bypasses them.

## Event checks

Result: **Pass at design level**.

- Documented domain and integration events use past-tense fact names.
- Context documents explicitly require immutable events.
- Each event family states that it carries the owning aggregate ID.
- The DDD overview requires event ID, occurred-at timestamp, and schema version globally.
- Imperative names appear only under commands/queries or action types, not as events.

Warning `EVENT-001`: event payload schemas, immutable types, serialization, and compatibility tests are not implemented.

## Repository checks

Result: **Pass at design level**.

| Context | Aggregate | Domain repository interface |
|---|---|---|
| Organization & Access | `Organization` | `OrganizationRepository` |
| Commercial Entitlements | `EntitlementAccount` | `EntitlementAccountRepository` |
| Asset Portfolio | `AssetPortfolio` | `AssetPortfolioRepository` |
| Integration Management | `IntegrationInstallation` | `IntegrationInstallationRepository` |
| Advisory Intake | `AdvisoryRecord` | `AdvisoryRecordRepository` |
| Remediation Runs | `RemediationRun` | `RemediationRunRepository` |
| Isolated Execution | `ExecutionLease` | `ExecutionLeaseRepository` |
| Patch Proposals | `ProposalAttempt` | `ProposalAttemptRepository` |
| Verification | `CandidateAssessment` | `CandidateAssessmentRepository` |
| Evidence | `EvidenceBundle` | `EvidenceBundleRepository` |
| External Actions | `ActionAuthorization` | `ActionAuthorizationRepository` |

Warning `REPOSITORY-001`: source placement and dependency direction cannot be checked. When implemented, interfaces belong to the owning domain and implementations to infrastructure; a context must not query another context's repository.

## Required future CI validation

When implementation begins, automate these gates:

1. Detect imports into another context's internal domain/application/infrastructure paths.
2. Detect cross-context database/repository access.
3. Enforce immutable aggregate and event types.
4. Require aggregate ID, event ID, schema version, and timestamp in every event.
5. Require exactly one repository interface per aggregate root and no infrastructure imports in domain code.
6. Verify forbidden Patch Proposals-to-Verification data paths, including caches, telemetry, and memory—not only language imports.
7. Verify tenant predicates and capability checks across database, artifact, event, cache, telemetry, worker, and connector boundaries.
8. Verify entitlement reservations are atomic and cannot influence verdict rules.
9. Verify connector manifests prevent capability escalation and secret-value exposure.

## Verdict

The proposed DDD documentation is internally coherent and passes the skill's checks at the only level currently possible. It must be revalidated against source and deployment configuration before any ADR is accepted or implementation is released.
