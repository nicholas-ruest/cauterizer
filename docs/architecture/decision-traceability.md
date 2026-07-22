# Decision and Delivery Traceability

## Capability-to-context map

| Capability | Owning context | Primary ADRs |
|---|---|---|
| Tenant, SSO, SCIM, roles, service principals | Organization & Access | 009, 010, 016 |
| Plans, quotas, budget, usage | Commercial Entitlements | 009, 023 |
| Repositories, components, scope, criticality | Asset Portfolio | 009, 010, 020 |
| Connector catalog/installations/webhooks | Integration Management | 008, 015, 024 |
| Advisory acquisition/normalization | Advisory Intake | 008, 011, 020 |
| Durable remediation workflow | Remediation Runs | 003, 012, 014, 017 |
| Hostile workload execution | Isolated Execution | 004, 018, 020 |
| Model/manual candidate generation | Patch Proposals | 005, 008, 023 |
| Fixture qualification and verdict | Verification | 005, 006, 022 |
| Attestation and offline verification | Evidence | 007, 013, 015, 021 |
| Human approval and external mutation | External Actions | 001, 010, 024 |

## Cross-cutting quality ownership

| Quality | Governing ADR | Required proof |
|---|---|---|
| Tenant isolation | 010 | storage/API/event/worker negative tests and review |
| Privacy and retention | 011 | data inventory, deletion and backup tests |
| Message reliability | 012 | outbox/inbox, replay, poison-message tests |
| Data integrity | 003, 013 | digest, corruption, reconciliation tests |
| API compatibility | 014, 021 | schema diff and consumer contract tests |
| Key safety | 015 | rotation, revocation, compromise drills |
| Audit/observability | 016 | redaction tests, SIEM export, alert exercises |
| Availability/recovery | 017 | SLO dashboards, restore and failover exercises |
| Isolation/deployment | 004, 018, 020 | escape tests and network-policy verification |
| Supply chain | 019 | SBOM, provenance, signature admission |
| Release quality | 022 | ADR/test traceability and release evidence |
| Commercial controls | 023 | quota concurrency and usage reconciliation |
| Connector ecosystem | 024 | capability, webhook, revocation tests |

## Delivery rule

An implementation item is not complete unless it links to its context use case, aggregate invariant or contract, governing ADRs, automated tests, operational telemetry, runbook, migration impact, security/privacy classification, and rollout/rollback plan.
