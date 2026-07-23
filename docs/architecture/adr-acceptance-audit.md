# ADR Acceptance Audit for P00

Status: P00 implementation baseline complete; ADR acceptance and empirical gates remain open
Audited: 2026-07-22  
Scope: ADR-001 through ADR-024, the DDD overview/context map/scaffold, security threat-model scaffold, production-readiness blueprint, decision traceability, and P00 in `.plans/implementation-prompts.md`

The recommendations in this audit predate the final selections in [platform-decisions.md](platform-decisions.md). Where they differ, the platform decision baseline is authoritative for implementation. In particular, Cauterizer uses PostgreSQL and the S3-compatible artifact-store port in local integration as well as hosted deployments; SQLite is not an implementation target.

## Acceptance rule

An ADR may move from `proposed` to `accepted` only when its implementation-affecting questions have explicit answers, its accountable deciders are named, and any required proof is either present or captured as a bounded spike with owner, exit criteria, and deadline. A role is not a named decider: P00 should record accountable people or the project's formally authorized maintainer identity.

No ADR currently satisfies that rule. Every ADR remains `proposed`; the repository-level
implementation decider recorded in `p00-decision-record.md` does not substitute for the
product, security, privacy/legal, or operations approvals required by an individual ADR.
ADR-009 through ADR-024 also omit an explicit validation section; omission is not
acceptance. The resolutions below are implementation constraints and bounded empirical
gates, not silent ADR acceptance.

The machine-readable source of truth for gate state and exact evidence locations is
[`p00-acceptance.tsv`](p00-acceptance.tsv). Run
`scripts/ci/verify-p00-acceptance.sh baseline` on every change to this baseline. Run
`scripts/ci/verify-p00-acceptance.sh external-ready` before claiming that the external
approval and hosted-environment gates are satisfied. The latter intentionally fails while
the named approval and empirical evidence files are absent.

## Baseline recommendations that constrain all decisions

- Trusted core: Rust 2024 for domain, application, contracts, persistence, policy, cryptography interfaces, CLI/API/workers, and orchestration ports. TypeScript is limited to a mandatory ecosystem surface that lacks a practical Rust implementation and remains behind a Rust-owned versioned port.
- Initial edition: a single-operator local/offline CLI with one explicitly bootstrapped organization, fixture-only inputs, direct application orchestration, and human-gated redacted export. It is not a conformant hosted sandbox or production identity deployment.
- Production boundary: organization-scoped contracts remain suitable for multi-tenant SaaS, dedicated enterprise, and customer-managed execution, but hosted claims require independent identities, plane separation, managed PostgreSQL/object storage, KMS/HSM, secret manager, and a gVisor-class or stronger execution boundary.
- Canonical external form: RFC 8785 JSON Canonicalization Scheme encoded as UTF-8, SHA-256 digests expressed as lowercase hex with an explicit algorithm tag. Use deterministic CBOR only later, under a separately versioned schema, if benchmarks justify it.
- Persistence: PostgreSQL 17 is the transactional system of record in local integration
  and hosted deployments. Artifacts use an S3-compatible port, with MinIO for local
  integration. A process-local filesystem adapter may support unit/development exercises
  but is explicitly non-conformant and is not a behavioral substitute.
- Local delivery: database-backed transactional outbox/inbox polling. Production port: the same durable contracts with PostgreSQL-backed dispatch initially; introduce a broker only after load evidence, without changing domain events.
- Cryptography: Ed25519 evidence signatures through a Rust-owned signer port; development keys are generated locally with restrictive permissions and bundles are marked untrusted. Production signing and envelope master keys remain non-exportable KMS/HSM operations with rotation and revocation metadata.

## ADR-by-ADR audit

### ADR-001 — Bound the MVP to an Offline Human-Gated Loop

- Current state: `proposed`; deciders absent.
- Unresolved: deployment model, approval authority, export content, and redaction rules.
- Concrete resolution: select the local/offline single-operator CLI as MVP. Only a human organization owner with an authenticated authorization context may approve `DryRun` or `Export` for one exact organization, action, evidence digest, destination class, purpose, and expiry. Export a canonical manifest, narrow verdict/reason codes, public artifact descriptors, signature material, and bounded redacted observations; exclude source/patch payloads by default, secrets, prompts, hidden test data/identifiers, internal paths, raw logs, and oracle-revealing timing. Missing or mismatched approval denies.
- Can be accepted now: **No**. Accept after named product and security deciders approve the export schema/redaction table and forbidden-authority tests.

### ADR-002 — Separate the System into Seven Bounded Contexts

- Current state: `proposed`; deciders absent. ADR-009 expands the model to eleven contexts.
- Unresolved: end-to-end scenario walk, unique ownership of sensitive data, no solver-to-verifier dependency, and reconciliation of “seven” with the later eleven-context model.
- Concrete resolution: amend the title/decision to distinguish seven core remediation contexts plus four enterprise platform contexts, or supersede it with ADR-009. Adopt the existing context-map flow as the scenario. Add a data-owner table covering raw advisory, source, solver brief, candidate, hidden tests/gold control, observations, verdict, bundle, approvals, credentials, audit, and usage. Retain one-way `PatchProposed` submission and prohibit solver consumption of assessment events.
- Can be accepted now: **No**. The numbering/model conflict, named ownership table, and scenario review must be resolved by architecture and security deciders.

### ADR-003 — Immutable Snapshots and Append-Only Run Lifecycle

- Current state: `proposed`; deciders absent.
- Unresolved: canonical serialization/digest, privacy deletion, and lifecycle failure analysis.
- Concrete resolution: use JCS/UTF-8 plus tagged SHA-256. Preserve immutable descriptors and event facts while cryptographically erasing or deleting payloads at retention expiry; replace payload accessibility with a tombstone containing digest, class, deletion reason/time, policy version, and legal-hold state. Never claim a tombstone verifies unavailable content. Validate the documented run state machine with model/property tests for retry, key conflict, cancellation races, crash-before/after commit, duplicates, reordering, and projection rebuild.
- Can be accepted now: **No**. Requires a reviewed state-transition table and privacy/security approval of erasure semantics.

### ADR-004 — Ephemeral Workers

- Current state: `proposed`; deciders absent.
- Unresolved: sandbox backends, adversarial suite, trusted computing base, and residual escape risk.
- Concrete resolution: local backend is rootless Podman with no network, read-only root, user namespaces, dropped capabilities, seccomp, bounded cgroup resources, no host/runtime sockets, explicit scratch, and unconditional cleanup; label all its receipts `NonConformantLocal`. Hosted conformant target is Kubernetes on dedicated nodes using gVisor `runsc` (or a stronger independently reviewed microVM boundary), separate solver/verifier pools and identities, default-deny network policy, immutable signed images, and no ambient credentials. A bounded spike must prove each enforcement and document kernel/runtime/orchestrator/image/worker-supervisor TCB and residual kernel/runtime escape risk.
- Can be accepted now: **No**. Backend probes and accountable security risk acceptance are mandatory.

### ADR-005 — Solver-Grader Conformance Firewall

- Current state: `proposed`; deciders absent.
- Unresolved: hidden-data flow, resource enumeration, and timing/error/retry side channels.
- Concrete resolution: draw every hidden artifact from verifier-only acquisition/storage through fresh verifier identity to bounded observation and verdict. Give solver identities no API, object-store prefix, key, telemetry dimension, cache, queue, or list permission that reaches verifier resources. Treat timing, distinct errors, retry counts, queue placement, log volume, and artifact existence as meaningful channels: expose only a terminal coarse status after candidate finalization, fixed reason classes, bounded/padded response timing where observable, fixed attempt policy, and no conformant adaptive retry. Persistent solver memory is disabled.
- Can be accepted now: **No**. Requires executable negative enumeration tests, leakage review, DFD, and security decider.

### ADR-006 — Deterministic Evidence-Based Verdicts

- Current state: `proposed`; deciders absent.
- Unresolved: policy schema/reason codes, fixture regression subset, and inconsistent outcomes.
- Concrete resolution: define a versioned Rust-owned policy input schema binding all digests and qualification facts. Initial stable reasons should cover baseline-not-vulnerable, gold-control-failed, hidden-test-failed, regression-failed, forbidden-change, incomplete/corrupt evidence, timeout/resource exhaustion, unstable-observation, and conformance violation. The exact regression command set must come from the selected pinned fixture and be stored by digest. Require a fixed predeclared repeat count (recommend three); any disagreement, timeout, or missing observation is `Inconclusive`, never majority-voted or retried selectively.
- Can be accepted now: **No**. Blocked on the fixture decision and reviewed golden policy vectors.

### ADR-007 — in-toto-Compatible Evidence Bundles

- Current state: `proposed`; deciders absent.
- Unresolved: predicate/verifier, canonicalization/digests, signer/revocation, and complete tamper testing.
- Concrete resolution: use in-toto Statement v1 with a versioned Cauterizer predicate, JCS/UTF-8, SHA-256 subjects/materials, and Ed25519 signatures. The Rust verifier must validate schema/version, canonical bytes, every referenced digest, signature, key validity interval, revocation state at signing and verification policy time, organization/scope binding, and verdict-policy binding. Local keys create explicitly untrusted development bundles; production calls a non-exportable KMS/HSM signer port. Build field-by-field and artifact-by-artifact mutation vectors.
- Can be accepted now: **No**. Predicate v1, trust policy, test vectors, and key/security deciders are missing.

### ADR-008 — Replaceable Upstream Adapters

- Current state: `proposed`; deciders absent.
- Unresolved: minimal MVP ports, license/distribution qualification, pinned fixture, and orchestration-free proof.
- Concrete resolution: define Rust-owned ports for advisory fixture load, source acquisition, sandbox execution, solver, evidence signing, clock/IDs, and artifact storage. Select exactly one CVE-Bench case only after recording repository URL, immutable commit, case path, license/SPDX analysis for code and fixture data, dependency locks/checksums, redistribution constraints, and vulnerable/gold commands. Direct Rust CLI/application orchestration is the mandatory reference path; Ruflo/model adapters remain optional outer adapters.
- Can be accepted now: **No**. The exact fixture and legal/reproducibility record are absent.

### ADR-009 — Enterprise Platform Bounded Contexts

- Current state: `proposed`; deciders absent; no explicit validation section.
- Unresolved: authoritative relationship to ADR-002, delivery scope, and whether enterprise contexts contaminate the offline MVP.
- Concrete resolution: accept eleven logical contexts while delivering only the minimum local implementations needed for organization scope, unlimited local entitlement, authorized local asset, and fixture integration. Preserve full versioned contracts, but defer federation, billing providers, and live connectors. State explicitly that ADR-009 extends/supersedes ADR-002's context count without weakening its boundaries.
- Can be accepted now: **No**. Requires formal ADR relationship and architecture/product deciders.

### ADR-010 — Tenant Isolation and Zero-Trust Authorization

- Current state: `proposed`; deciders absent; no explicit validation section.
- Unresolved: local identity bootstrap, production identity boundary, policy semantics, and storage/worker enforcement evidence.
- Concrete resolution: every command/query/event/artifact descriptor carries `OrganizationId` and authenticated actor/service identity; deny by default over actor, organization, action, resource, purpose, and conditions. Local mode bootstraps one human owner explicitly and must advertise that it is not federation. Production uses OIDC/SAML/SCIM through adapters, PostgreSQL tenant predicates/RLS defense in depth, tenant-scoped object paths and keys, and per-job identities. Add cross-tenant generative tests at API, repository, event, artifact, cache, worker, and support paths.
- Can be accepted now: **No**. Needs policy decision tables, identity/security deciders, and negative test evidence.

### ADR-011 — Data Classification, Encryption, Redaction, Retention

- Current state: `proposed`; deciders absent; no explicit validation section.
- Unresolved: complete inventory, class definitions/defaults, residency, retention/deletion, backup behavior, and redaction policy.
- Concrete resolution: adopt `Public`, `Internal`, `Confidential`, `Restricted`, and `Secret` classes. Hidden verifier material, private source/patches/prompts/raw logs, credentials, key material, identity/audit, and usage each need named owners. Recommended defaults: Secret values never persisted outside secret facilities; Restricted payloads 30 days; Confidential 90 days; operational telemetry 30 days; audit/evidence metadata 365 days; public fixture/evidence as policy permits. Organization policy may shorten, legal hold may extend, and deletion must include object versions, caches, replicas, and backup expiry. Region is immutable metadata and cross-region copy is denied without policy.
- Can be accepted now: **No**. Defaults are product/legal/security decisions and require a completed inventory and deletion test plan.

### ADR-012 — Transactional Outbox and Inbox

- Current state: `proposed`; deciders absent; no explicit validation section.
- Unresolved: local/hosted transport, ordering, authentication, deduplication horizon, poison handling, and schema compatibility.
- Concrete resolution: atomically persist aggregate change and outbox row in SQLite locally/PostgreSQL hosted; dispatch with bounded polling and authenticated producer envelopes. Consumers use durable `(consumer, event_id)` inbox records, aggregate sequence checks, idempotent effects, and explicit out-of-order holding/replay. Dead-letter after bounded attempts with authorization-protected replay. Retain deduplication at least as long as event replay/retention. Do not select Kafka/NATS before benchmark evidence requires it.
- Can be accepted now: **No**. Requires delivery semantics and recovery test vectors approved by architecture/operations.

### ADR-013 — Transactional Metadata and Content-Addressed Artifacts

- Current state: `proposed`; deciders absent; no explicit validation section.
- Unresolved: concrete stores, commit protocol, metadata schema, erasure/GC, solver/verifier segregation, and production consistency.
- Concrete resolution: SQLite plus separate filesystem CAS roots locally; PostgreSQL plus S3-compatible encrypted object storage hosted. Upload to an organization/access-domain quarantine, stream-size and SHA-256 verify server-side, validate media/schema, then atomically publish a descriptor. Reads authorize before lookup and rehash content. Mark-and-sweep only from retained roots with legal holds and tombstones. Never globally deduplicate Restricted content across organizations or solver/verifier domains.
- Can be accepted now: **No**. Needs schema, reconciliation protocol, corruption tests, and data/security deciders.

### ADR-014 — Contract-First Idempotent APIs

- Current state: `proposed`; deciders absent; no explicit validation section.
- Unresolved: canonical envelopes, idempotency retention/conflicts, concurrency tokens, and MVP transport.
- Concrete resolution: define contracts in Rust and generate/check JSON Schema/OpenAPI components; canonical JSON follows the P00 baseline. Persist idempotency key, authenticated organization/actor, operation, request digest, result reference, and expiry. Exact retry returns the prior result; same key/different digest is a stable conflict. Use aggregate sequence/ETag concurrency, RFC 9457-compatible problem details, opaque cursors, and coarse errors. The local CLI invokes the same application facades without requiring HTTP.
- Can be accepted now: **No**. Requires contract/error/idempotency compatibility vectors and API decider.

### ADR-015 — Secrets and Cryptographic Key Lifecycle

- Current state: `proposed`; deciders absent; no explicit validation section.
- Unresolved: secret/KMS products, signer algorithm, local key handling, trust roots, rotation/revocation/destruction, and outage behavior.
- Concrete resolution: Ed25519 behind Rust signer/verifier traits. Local development stores a generated key only in a user-restricted file and marks output untrusted; no key enters repository, logs, evidence, events, or workers. Hosted deployments use workload identity, tenant-scoped secret-manager references, non-exportable KMS/HSM signing and envelope keys, versioned trust metadata, overlap rotation, revocation, compromise response, and fail-closed signing/action behavior. Product selection is an infrastructure adapter decision after deployment environment selection.
- Can be accepted now: **No**. Requires key/secret inventory, lifecycle table, compromise drill, and security/operations deciders.

### ADR-016 — Audit-Safe Observability

- Current state: `proposed`; deciders absent; no explicit validation section.
- Unresolved: telemetry/audit schemas, prohibited fields, tenant tokenization, retention, alerts, and local/production sinks.
- Concrete resolution: implement Rust tracing/metrics ports with a structured allowlist; payload-like values use non-printable sensitive wrappers. Local mode uses bounded structured files with separate append-only audit; hosted mode exports OpenTelemetry and an integrity-protected audit stream through separate identities/sinks. Define and test alerts listed in the threat model. Audit decisions and references, never secret/source/patch/prompt/test bodies.
- Can be accepted now: **No**. Needs schemas, redaction corpus, access policy, and security/operations deciders.

### ADR-017 — SLOs, Resilience, and Disaster Recovery

- Current state: `proposed`; deciders absent; no explicit validation section.
- Unresolved: numeric SLO/RPO/RTO, benchmark basis, edition tiers, degraded modes, backups/restores, and ownership.
- Concrete resolution: do not invent contractual numbers in P00. Define SLIs and an internal benchmark plan now; record provisional engineering objectives only after P15/P18 measurements. Local mode documents manual encrypted backup/export and no availability claim. Hosted mode requires multi-zone PostgreSQL/object storage, resumable workers, bounded retries/circuit breaking/load shedding, fail-closed External Actions, per-class backup policy, and restore/failover drills before production acceptance.
- Can be accepted now: **No**. A bounded measurement spike is acceptable for P00, but ADR acceptance needs measured targets and operations/product deciders.

### ADR-018 — Control, Data, and Execution Planes

- Current state: `proposed`; deciders absent; no explicit validation section.
- Unresolved: apparent tension between local single-process mode and production plane separation, identities/protocols, and edition topology.
- Concrete resolution: treat planes as trust/deployment contracts, not an MVP microservice mandate. Local binaries may share one host but use explicit ports, separate processes/roots/identities where feasible, and are non-conformant for hosted claims. Production deploys distinct control, data, acquisition, solver, and verifier identities/network policies/node pools; execution calls only job-scoped endpoints. Preserve identical versioned job/contracts across SaaS, dedicated, and customer-managed execution.
- Can be accepted now: **No**. Requires DFD/protocol/identity inventory and architecture/security/operations deciders.

### ADR-019 — Software Supply Chain and Release

- Current state: `proposed`; deciders absent; no explicit validation section.
- Unresolved: supported Rust/toolchain pins, dependency/license policy, CI/release identity, reproducibility, signing, review, disclosure, and rollback.
- Concrete resolution: pin Rust stable by exact channel, commit `Cargo.lock`, deny unsafe by default, run fmt/Clippy/tests/audit/deny/secret/SAST checks, generate SPDX or CycloneDX SBOM, pin CI actions by commit, use least-privilege isolated release identity, sign release artifacts/provenance, and verify before admission. Record fixture and non-Rust adapter licenses explicitly. Local development builds are not signed releases.
- Can be accepted now: **No**. Needs policy files, reproducibility spike, release ownership, and security/release deciders.

### ADR-020 — Networked Acquisition vs Hermetic Evaluation

- Current state: `proposed`; deciders absent; no explicit validation section.
- Unresolved: exact fixture/source/dependency pins, allowlists/proxy, redirect and integrity policy, license/scanning gates, SBOM, and cache trust.
- Concrete resolution: local MVP should prefer a pre-acquired, verified fixture bundle; any acquisition runs as a distinct rootless job with only explicit repository/registry destinations and recorded redirects. Require immutable commit, locks/checksums, toolchain/image digests, license decision, SBOM, scanning result, and content-addressed output. Reproduction/solver/verifier run with network denied and read-only approved bundles. Mutable or unverifiable dependency resolution fails qualification.
- Can be accepted now: **No**. Blocked on exact CVE fixture qualification and network/integrity test evidence.

### ADR-021 — Schema and Contract Evolution

- Current state: `proposed`; deciders absent; no explicit validation section.
- Unresolved: schema source of truth/registry, compatibility rules for security-critical fields, support window, migrators, and historical verifier distribution.
- Concrete resolution: Rust types plus checked-in generated schemas are the source pair, with drift tests. Use semantic versions and explicit schema names; ordinary optional additive fields may be ignored, but unknown security-critical capabilities, algorithms, classifications, policy semantics, or action fields fail closed. Support current and previous major for a published window chosen before external release. Never rewrite signed evidence; ship versioned offline interpretation and golden vectors.
- Can be accepted now: **No**. Requires compatibility matrix, migration policy, and architecture/product deciders.

### ADR-022 — Risk-Based Verification and Release Gates

- Current state: `proposed`; deciders absent; no explicit validation section.
- Unresolved: complete ADR/abuse-case test matrix, gate ownership, severity policy, flaky-test process, benchmark thresholds, and production review evidence.
- Concrete resolution: create one traceability row per ADR invariant and threat with automated/procedural evidence, owner, frequency, and release gate. Rust test layers include unit, model/property, contract, integration, end-to-end fixture, cross-tenant, sandbox adversarial, leakage, tamper, fuzz, performance/soak/chaos, and restore. Critical/high findings block unless a named risk owner records bounded acceptance with expiry. Quarantined flaky tests need owner/deadline and cannot satisfy a gate.
- Can be accepted now: **No**. P00 specifically requires the missing abuse-case matrix and named release/security deciders.

### ADR-023 — Entitlements, Quotas, and Usage

- Current state: `proposed`; deciders absent; no explicit validation section.
- Unresolved: local plan, reservation units/windows, hard limits, concurrency semantics, settlement/reconciliation, and billing boundary.
- Concrete resolution: provide an explicit unlimited local-development grant that remains organization-scoped and auditable. Production admits expensive work only after an atomic worst-case reservation in PostgreSQL; settle immutable measured usage idempotently and reconcile asynchronously. Provider outages do not enter verification semantics. Plans may constrain scale/features/retention but never verdict requirements. Payment data remains outside Cauterizer.
- Can be accepted now: **No**. Requires quota/usage schema, concurrency properties, and commercial/product/architecture deciders.

### ADR-024 — Integrations, Plugins, and Webhooks

- Current state: `proposed`; deciders absent; no explicit validation section.
- Unresolved: MVP integration scope, manifest schema, execution boundary, webhook algorithms/replay windows, connector secret access, publication/revocation, and support ownership.
- Concrete resolution: no arbitrary plugin loading or live mutation in MVP. The fixture adapter is in-tree but obeys a Rust-owned capability manifest. Future connectors run out of process or in constrained WASI/WASM where feasible, with destination/data-class/scope/resource declarations. Inbound/outbound webhooks use versioned schemas, bounded bodies, tenant routing, timestamp plus nonce replay defense, HMAC or asymmetric signatures through managed secrets, idempotency, Restricted-field deny by default, revocation, and audit. External mutation remains forbidden until a later ADR.
- Can be accepted now: **No**. Needs manifest/webhook contracts, threat tests, and integration/security deciders.

## P00 blocking decision register

The following must be resolved before product implementation begins; a bounded spike may satisfy the gate only where noted.

| Decision | Recommended P00 outcome | Acceptance evidence |
|---|---|---|
| Deployment | Local/offline CLI, one organization, export-only; hosted boundary documented | ADR-001/018 amendments and DFD |
| Deciders | Named product, architecture, security, privacy/legal, and operations accountabilities as applicable | Non-empty ADR fields and recorded approval |
| Rust runtime | Rust 2024 trusted core; direct application/CLI path | toolchain ADR/pin and architecture rule |
| Canonical bytes/digest | JCS UTF-8 plus tagged SHA-256 | cross-platform golden vectors |
| Metadata/artifact stores | PostgreSQL 17 plus S3-compatible storage; MinIO for local integration | transaction/corruption/reconciliation plan |
| Delivery | transactional DB outbox/inbox polling first | retry/replay/poison state model |
| Sandbox | rootless Podman non-conformant local; gVisor-class hosted candidate | bounded enforcement spike and residual-risk owner |
| Fixture | one exact CVE-Bench commit/case with license and locked environment | FAIL/PASS qualification record and reproducibility runs |
| Signing/keys | Ed25519 local-untrusted; KMS/HSM non-exportable hosted | predicate/trust schema and rotation/revocation tests |
| Data policy | completed inventory with class/region/retention/key owner | deletion/backup/redaction test matrix |
| Approval | human owner; exact action/evidence/scope/destination/expiry | deny-path decision table |
| Regression/flakiness | exact fixture commands; fixed three-run policy, disagreement is inconclusive | qualification vectors |
| Side channels | timing/errors/retries are oracle channels; coarse terminal disclosure only | enumeration and leakage suite |
| Threat/release evidence | DFD, STRIDE review, abuse-case matrix, inventories, residual risks | named review and traceability links |

## Overall conclusion

**The P00 implementation decision baseline is complete; no ADR or external empirical gate
is thereby accepted.** P01 and later implementation may proceed under the bounded,
fail-closed decisions in this record. Named product/security/privacy/legal/operations
approvals, fixture redistribution approval, real fixture qualification, and hosted sandbox
evidence remain external or phase-bound gates. Their absence must block the corresponding
claim, never be inferred from code, a role label, or this document.

The acceptance registry and verification script make that distinction executable. A
baseline pass proves only that the selected decisions, threat artifacts, evidence
requirements, and external gate placeholders are complete and internally consistent.
Only an `external-ready` pass against independently supplied records can prove the external
gates, and even that does not change an ADR status without a reviewed ADR amendment.
