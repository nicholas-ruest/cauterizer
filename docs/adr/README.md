# Architecture Decision Record Index

All records are dated 2026-07-22 and initially have status `proposed`.

| ID | Decision | Depends on |
|---|---|---|
| [ADR-001](ADR-001-bound-the-mvp-to-an-offline-human-gated-loop.md) | Bound the MVP to an offline human-gated loop | — |
| [ADR-002](ADR-002-separate-the-system-into-seven-bounded-contexts.md) | Separate the system into seven bounded contexts | ADR-001 |
| [ADR-003](ADR-003-use-immutable-snapshots-and-an-append-only-run-lifecycle.md) | Use immutable snapshots and an append-only run lifecycle | ADR-001, ADR-002 |
| [ADR-004](ADR-004-isolate-all-untrusted-execution-in-ephemeral-workers.md) | Isolate all untrusted execution in ephemeral workers | ADR-001, ADR-003 |
| [ADR-005](ADR-005-enforce-a-solver-grader-conformance-firewall.md) | Enforce a solver-grader conformance firewall | ADR-002, ADR-004 |
| [ADR-006](ADR-006-make-remediation-verdicts-deterministic-and-evidence-based.md) | Make remediation verdicts deterministic and evidence-based | ADR-003, ADR-005 |
| [ADR-007](ADR-007-emit-in-toto-compatible-evidence-bundles.md) | Emit in-toto-compatible evidence bundles | ADR-003, ADR-006 |
| [ADR-008](ADR-008-integrate-upstream-tools-through-replaceable-adapters.md) | Integrate upstream tools through replaceable adapters | ADR-002, ADR-006, ADR-007 |
| [ADR-009](ADR-009-add-enterprise-platform-bounded-contexts.md) | Add enterprise platform bounded contexts | ADR-002 |
| [ADR-010](ADR-010-enforce-tenant-isolation-and-zero-trust-authorization.md) | Enforce tenant isolation and zero-trust authorization | ADR-009 |
| [ADR-011](ADR-011-classify-encrypt-redact-and-retain-data-by-policy.md) | Classify, encrypt, redact, and retain data by policy | ADR-003, ADR-010 |
| [ADR-012](ADR-012-use-versioned-events-with-transactional-outbox-and-inbox.md) | Use versioned events with transactional outbox and inbox | ADR-003, ADR-009 |
| [ADR-013](ADR-013-separate-transactional-metadata-from-content-addressed-artifacts.md) | Separate transactional metadata from content-addressed artifacts | ADR-003, ADR-011 |
| [ADR-014](ADR-014-design-contract-first-idempotent-apis.md) | Design contract-first idempotent APIs | ADR-003, ADR-010 |
| [ADR-015](ADR-015-centralize-secrets-and-cryptographic-key-lifecycle.md) | Centralize secrets and cryptographic key lifecycle | ADR-007, ADR-010 |
| [ADR-016](ADR-016-build-audit-safe-observability.md) | Build audit-safe observability | ADR-010, ADR-011 |
| [ADR-017](ADR-017-define-slos-resilience-and-disaster-recovery.md) | Define SLOs, resilience, and disaster recovery | ADR-012, ADR-013 |
| [ADR-018](ADR-018-deploy-control-data-and-execution-planes-separately.md) | Deploy control, data, and execution planes separately | ADR-004, ADR-017 |
| [ADR-019](ADR-019-secure-the-software-supply-chain-and-release-process.md) | Secure the software supply chain and release process | ADR-007, ADR-015 |
| [ADR-020](ADR-020-separate-networked-acquisition-from-hermetic-evaluation.md) | Separate networked acquisition from hermetic evaluation | ADR-004, ADR-019 |
| [ADR-021](ADR-021-govern-schema-and-contract-evolution.md) | Govern schema and contract evolution | ADR-012, ADR-014 |
| [ADR-022](ADR-022-adopt-risk-based-verification-and-release-gates.md) | Adopt risk-based verification and release gates | ADR-005, ADR-019 |
| [ADR-023](ADR-023-enforce-entitlements-quotas-and-auditable-usage.md) | Enforce entitlements, quotas, and auditable usage | ADR-009, ADR-012 |
| [ADR-024](ADR-024-govern-integrations-plugins-and-webhooks.md) | Govern integrations, plugins, and webhooks | ADR-008, ADR-015 |

## Status policy

- `proposed`: design candidate awaiting an explicit decision.
- `accepted`: approved and enforceable against implementation.
- `deprecated`: retained for history but discouraged.
- `superseded`: replaced by a linked newer ADR.

Acceptance requires named deciders, resolution of each record's open validation items, and confirmation that its consequences fit the intended deployment threat model.
