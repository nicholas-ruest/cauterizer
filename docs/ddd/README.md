# Cauterizer Domain-Driven Design

Status: proposed domain model  
Date: 2026-07-22

## Domain vision

Cauterizer turns an approved vulnerability statement into independently verifiable remediation evidence while keeping hostile execution, probabilistic patch generation, deterministic verification, signing, and external authority separate.

It is not initially a vulnerability scanner, deployment platform, or autonomous publisher.

## Subdomains

| Subdomain | Type | Bounded context | Purpose |
|---|---|---|---|
| Tenant governance | Supporting/platform | [Organization & Access](contexts/organization-access/README.md) | Isolate organizations, identities, roles, and policy |
| Commercial operations | Supporting/commercial | [Commercial Entitlements](contexts/commercial-entitlements/README.md) | Enforce plans, quotas, reservations, and usage |
| Customer scope | Supporting | [Asset Portfolio](contexts/asset-portfolio/README.md) | Own authorized targets, environments, and scope |
| Connector ecosystem | Supporting/platform | [Integration Management](contexts/integration-management/README.md) | Govern connector installation, capabilities, and health |
| Remediation lifecycle | Core | [Remediation Runs](contexts/remediation-runs/README.md) | Coordinate immutable, idempotent remediation state |
| Independent patch assessment | Core | [Verification](contexts/verification/README.md) | Produce narrowly scoped deterministic verdicts |
| Verifiable claims | Core | [Evidence](contexts/evidence/README.md) | Bind process, inputs, observations, and verdicts |
| Vulnerability normalization | Supporting | [Advisory Intake](contexts/advisory-intake/README.md) | Normalize and snapshot untrusted advisories |
| Hostile workload containment | Supporting | [Isolated Execution](contexts/isolated-execution/README.md) | Execute declared jobs without verdict authority |
| Candidate generation | Supporting | [Patch Proposals](contexts/patch-proposals/README.md) | Produce bounded candidate patches |
| Human-governed handoff | Supporting | [External Actions](contexts/external-actions/README.md) | Authorize and export eligible outcomes |

Generic capabilities include cryptographic primitives, object storage, queues, telemetry, schema validation, and identity. They have no domain authority.

The directory-based context packages are the implementation-grade scaffold. The earlier single-file context summaries remain concise conceptual references; where detail differs, the directory package and ADR-009 govern.

## Ubiquitous language

- **Advisory Snapshot**: immutable normalized vulnerability information and source provenance at one instant.
- **Target Revision**: immutable repository identity and commit selected for a run.
- **Remediation Run**: the aggregate coordinating one advisory-target-policy attempt.
- **Fixture**: declared vulnerable base, hidden security test, and qualification controls used for evaluation.
- **Solver Brief**: the complete information and limits intentionally exposed to a solver.
- **Candidate Patch**: immutable proposed diff plus generator provenance; never a fix by assertion.
- **Execution**: one isolated observation-producing job.
- **Evaluation**: verifier-owned facts about applying and testing one candidate.
- **Verdict**: deterministic policy result: `VerifiedForFixture`, `Rejected`, `Inconclusive`, or `NonConformant`.
- **Evidence Bundle**: verifiable statement binding exact artifacts, observations, policy, and verdict.
- **Approval Grant**: human authorization scoped to a specific eligible evidence digest and action.
- **Conformant Run**: run whose solver/verifier information separation satisfies ADR-005.

Avoid the unqualified words **safe**, **fixed**, **proof**, and **approved**. State the subject and scope: “candidate is `VerifiedForFixture`,” “manifest signature verified,” or “export approved by actor X.”

## Global modeling rules

1. Aggregate state changes only through behavior that enforces its invariants; no public mutable fields or setters.
2. Domain events are immutable, past-tense, and include their aggregate identifier, event identifier, occurred-at time, and schema version.
3. Each aggregate root has exactly one repository interface owned by its domain; implementations belong to infrastructure.
4. Cross-context references are opaque IDs and immutable digests, not object references.
5. Integration handlers are idempotent and tolerate duplicate and out-of-order delivery.
6. Contexts consume only another context's published API/events through an anti-corruption layer.
7. An event reports a fact that occurred; commands are imperative requests and are not called events.

## Aggregate catalog

| Context | Aggregate root | Repository |
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

## Context documentation contract

Each context document specifies ownership, aggregate boundaries, value objects, invariants, events, commands/queries, repository, published language, integrations, and excluded responsibilities. These documents guide future implementation but do not prescribe a TypeScript or service directory today.

## Related documents

- [Context map](context-map.md)
- [Implementation scaffold](implementation-scaffold.md)
- [Architecture decisions](../adr/README.md)
- [DDD validation report](../reviews/ddd-validation.md)
