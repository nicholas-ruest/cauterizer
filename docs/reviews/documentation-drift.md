# Documentation Drift Report

Date: 2026-07-22  
Scope: `docs/`, `.plans/`, repository history, and current product source

## Result

The new documentation is consistent with the deep research and initial goal plan. There is no product implementation against which API, module, behavior, or deployment drift can be tested.

## Alignment with planning inputs

| Planning conclusion | Documentation coverage | Result |
|---|---|---|
| Offline-first, human-gated, export-only MVP | ADR-001; External Actions | Aligned |
| Versioned canonical domain independent of upstream tools | ADR-002/008; DDD overview | Aligned |
| Immutable snapshots and append-only run state | ADR-003; Remediation Runs | Aligned |
| Ephemeral hostile-workload sandbox | ADR-004; Isolated Execution | Aligned |
| Solver cannot inspect or invoke grader | ADR-005; context map; Patch Proposals | Aligned |
| Independent deterministic verdict | ADR-006; Verification | Aligned |
| in-toto/SLSA-compatible evidence | ADR-007; Evidence | Aligned |
| Upstream tools are optional pinned adapters | ADR-008; context map | Aligned |
| Enterprise tenant and access boundary | ADR-009/010; Organization & Access | Aligned |
| Commercially enforceable cost/usage model | ADR-023; Commercial Entitlements | Aligned |
| Customer-authorized target inventory | ADR-009; Asset Portfolio | Aligned |
| Governed connector ecosystem | ADR-024; Integration Management | Aligned |
| Production reliability and deployment planes | ADR-017/018; production-readiness blueprint | Aligned |
| Secure release and dependency acquisition | ADR-019/020; traceability matrix | Aligned |
| No decompilation witness as proof of a fix | ADR-007; Evidence | Aligned |
| No broad safety claim from one hidden test | ADR-006; ubiquitous language | Aligned |

## Known non-drift gaps

These are intentional unresolved decisions, not inconsistencies:

- local, trusted-CI, or multi-tenant deployment model;
- control-plane runtime and physical module/service topology;
- sandbox backend;
- MVP CVE-Bench instance;
- canonical serialization and digest algorithms;
- evidence predicate and key custody;
- retention/redaction rules for private data;
- regression-suite and flakiness policy;
- optional ruDevolution need and license status.

## Repository-level drift

- Root `README.md` contains only the project title and does not point to the architecture documents.
- Generated ruflo configuration describes available orchestration capabilities but is not a product architecture and must not be treated as implementing ADR-008.
- No `src/`, tests, package manifest, CI, or deployment configuration exists. Any statement about implemented behavior would therefore be drift; the documents consistently use proposed/future language.

## Future drift gates

1. Validate local Markdown links and ADR numbering.
2. Compare context modules and imports with `docs/ddd/context-map.md`.
3. Compare event/contract schemas with context documents.
4. Compare sandbox deployment policy with ADR-004.
5. Test solver/verifier identities, stores, caches, logs, telemetry, and memory against ADR-005.
6. Compare policy reason codes and verdict vocabulary with ADR-006.
7. Validate evidence schema and verifier behavior against ADR-007.
8. Inventory upstream pins/licenses and adapter contract tests against ADR-008.

## Documentation generator note

The document-worker MCP operation specified by `ruflo-docs:doc-gen` was not exposed in this session. Documentation was generated directly from the two requested planning sources and checked for drift locally. No recurring documentation job was scheduled because the user requested documents, not automation.

## Verdict

Documentation-to-plan drift: **none found**.  
Documentation-to-implementation drift: **not assessable because implementation does not exist**.
