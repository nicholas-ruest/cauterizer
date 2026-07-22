# Production Readiness Blueprint

Status: proposed implementation contract

## Product editions

One domain model supports three deployable editions:

1. Multi-tenant SaaS: shared control/data planes with enforced tenant partitions and isolated execution pools.
2. Dedicated enterprise: customer-dedicated data and execution resources with managed control plane.
3. Customer-managed execution: SaaS control plane dispatches signed, capability-scoped jobs to an attested customer worker plane.

Edition differences are deployment, scale, residency, integration, retention, and support entitlements. Verification semantics and safety gates never weaken by edition.

## Required product surfaces

- Web console for assets, advisories, runs, evidence, approvals, integrations, usage, and administration.
- Versioned public API, CLI, generated SDKs, signed outbound webhooks, and SIEM/audit export.
- SSO (OIDC/SAML), SCIM, service principals, RBAC plus conditional ABAC, MFA/step-up integration, and break-glass governance.
- Tenant configuration for regions, retention, data classes, policy, budgets, connectors, notification, and approval rules.
- Operator console for queue health, connector health, workers, dead letters, evidence verification, tenant-safe support, and incident response.

## Production gates

| Gate | Required evidence |
|---|---|
| Functional | All context use cases and acceptance scenarios pass |
| Architecture | Import/dependency rules and ADR traceability pass |
| Security | Threat model, abuse cases, tenant isolation, sandbox, authz, fuzz, pen test |
| Privacy | Data inventory, classification, retention/deletion, residency, DPA inputs |
| Reliability | Load/soak, chaos, backup restore, failover, error-budget policy |
| Supply chain | SBOM, signatures, provenance, vulnerability/license gates |
| Operations | Dashboards, alerts, runbooks, on-call, support-access workflow |
| Commercial | Entitlement, quota, usage reconciliation, upgrade/downgrade, invoices adapter |
| Compliance | Control mapping and collected evidence reviewed by accountable owners |
| Release | Migration rehearsal, canary, rollback proof, customer communication |

## Nonfunctional acceptance targets

Exact numeric commitments require benchmark data, but implementation must define and validate:

- API availability and latency by endpoint class.
- Event publication/consumption lag and dead-letter rate.
- Run queue time, execution startup, completion, cancellation, and stuck-run rate.
- Artifact durability and evidence verification availability.
- Tenant-isolation and authorization decision error rate (target: zero known cross-tenant acceptance).
- RPO/RTO per edition and data class.
- Model/compute/storage cost per run and quota overshoot bound.
- Maximum supported tenants, assets, concurrent runs, artifact size, and retention.

## Organizational readiness

Every production component has a named engineering owner, security owner, service tier, SLO, data owner, on-call rotation, runbook, escalation path, dependency inventory, and end-of-life policy. Commercial launch additionally requires support SLAs, status page, vulnerability disclosure, security contact, incident communications, terms/privacy review, and customer evidence package.
