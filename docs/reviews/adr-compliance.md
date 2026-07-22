# ADR Compliance Report

Date: 2026-07-22  
Scope: new `docs/` architecture and DDD documents plus `.plans/deep-research.md` and `.plans/intial.md`

## Review basis

`git diff main...HEAD` contains no committed branch changes, while the new documentation is untracked. The review therefore covered the complete working-tree `docs/` set and its two planning inputs directly.

All 24 ADRs are `proposed`. Under the ADR review rules, only `accepted` ADRs are enforceable; therefore this report records internal consistency and warnings rather than implementation violations.

AgentDB relationship and supersession queries were unavailable in this session. Filesystem inspection found no pre-existing ADRs and no supersession declarations.

## Violations

None. There are no accepted ADRs and no product code to violate them.

## Warnings

- [!] ADR-001 — intended deployment model and authorization actors are unresolved.
- [!] ADR-003 — canonical serialization, digest algorithms, retention, and privacy-deletion semantics are unresolved.
- [!] ADR-004 — the concrete sandbox backend and trusted computing base are intentionally deferred.
- [!] ADR-005 — side-channel and memory-isolation design requires a deployment-level data-flow review.
- [!] ADR-006 — the initial policy schema, reason codes, regression subset, and flakiness threshold are unresolved.
- [!] ADR-007 — predicate schema, signer/key custody, canonicalization, and revocation are unresolved.
- [!] ADR-008 — runtime/deployment technology, adapter ports, and upstream license checks remain future decisions.
- [!] ADR-009 — adding four enterprise contexts requires acceptance of their ownership and consistency boundaries.
- [!] ADR-010 — identity provider, authorization engine, tenant storage controls, and support-access policy remain selections.
- [!] ADR-011 — field-level data inventory, jurisdictions, retention periods, and legal-hold process require privacy/legal review.
- [!] ADR-012 — broker, schema registry, outbox relay, dead-letter ownership, and replay limits remain selections.
- [!] ADR-013 — relational/object-store products, regional topology, reconciliation, and garbage collection remain selections.
- [!] ADR-014 — contract tooling, public deprecation windows, and rate-limit tiers remain selections.
- [!] ADR-015 — KMS/HSM, certificate identity, key hierarchy, recovery, and rotation periods remain selections.
- [!] ADR-016 — telemetry platform, retention, SIEM format, sampling, and alert ownership remain selections.
- [!] ADR-017 — contractual SLO/RPO/RTO values require benchmark and commercial input.
- [!] ADR-018 — cloud/orchestration products and supported deployment editions remain selections.
- [!] ADR-019 — target supply-chain assurance level, license policy, and patch SLAs require acceptance.
- [!] ADR-020 — package proxies, scanning, environment-bundle format, and ecosystem coverage remain selections.
- [!] ADR-021 — support windows, schema registry, and migration framework remain selections.
- [!] ADR-022 — release evidence, performance thresholds, and independent review cadence remain selections.
- [!] ADR-023 — product packaging, quota dimensions, reconciliation cadence, and billing adapter remain product decisions.
- [!] ADR-024 — plugin runtime, marketplace policy, connector review, and webhook support limits remain selections.
- [!] All ADRs — deciders are blank and status is proposed; documentation must not represent these decisions as accepted.

## Compliant documents

- [x] `docs/ddd/README.md` — applies ADR-001/002 language and keeps verdict, evidence, and approval distinct.
- [x] `docs/ddd/context-map.md` — applies ADR-002/005/008 boundaries and adapter policy.
- [x] Advisory Intake — read-only, immutable snapshots and anti-corruption layers align with ADR-001/003/008.
- [x] Remediation Runs — append-only/idempotent lifecycle aligns with ADR-003 and does not seize other contexts' authority.
- [x] Isolated Execution — capability/resource model aligns with ADR-004 and emits observations rather than verdicts.
- [x] Patch Proposals — solver view, budgets, and one-way submission align with ADR-005/008.
- [x] Verification — deterministic scoped verdicts align with ADR-005/006.
- [x] Evidence — in-toto-compatible scoped claims and signer separation align with ADR-007.
- [x] External Actions — human-scoped dry-run export aligns with ADR-001.
- [x] Organization & Access package — tenant, workforce identity, service principal, and support-access rules align with ADR-009/010/016.
- [x] Commercial Entitlements package — reservation and settlement semantics align with ADR-023 without weakening verification.
- [x] Asset Portfolio package — explicit customer ownership and scope align with ADR-009/010/020.
- [x] Integration Management package — manifest, capability, webhook, and secret-reference rules align with ADR-008/015/024.
- [x] All eleven context packages — domain/application/contracts/operations/testing layers align with ADR-012/014/021/022.
- [x] `docs/reviews/ddd-validation.md` — correctly limits its claim to documentation-level validation.

## Relationship review

The declared ADR dependency order is acyclic. ADR-001 through ADR-008 define the remediation kernel; ADR-009 through ADR-024 extend enterprise platform, operations, commercial, and delivery concerns without superseding the kernel.

See [the ADR index](../adr/README.md) for the complete dependency table.

No record claims to supersede another. ADR-008 explicitly defers runtime selection instead of smuggling a technology choice into an adapter decision.

## Unlinked changes

- [?] None inside `docs/`: all substantive DDD documents link to the ADR index, a governing ADR, or both.
- [?] The one-line root `README.md` predates these records and does not link to `docs/`; this is documentation drift, not an ADR violation, and changing it was outside the requested docs-only scope.

## Suggested actions before acceptance

1. Name deciders and select the deployment threat model.
2. Resolve each ADR's “Validation before acceptance” items.
3. Accept records in dependency order, beginning with ADR-001 and ADR-002.
4. Create a separate runtime/deployment ADR after the sandbox spike.
5. Decide enterprise product editions, commercial packaging, data regions, support objectives, and compliance target markets.
6. Repeat ADR review after implementation exists, enforcing only accepted records.

## Verdict

No ADR violation was found. The proposed ADR series and DDD model are mutually consistent, but none is enforceable or represented as implemented.
