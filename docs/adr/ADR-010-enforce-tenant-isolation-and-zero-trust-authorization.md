# ADR-010: Enforce Tenant Isolation and Zero-Trust Authorization

- **Status**: proposed
- **Date**: 2026-07-22
- **Deciders**:
- **Tags**: tenancy, iam, authorization, zero-trust

## Context

Enterprise customers require isolation across data, compute, keys, integrations, logs, and support access. Authentication alone cannot prevent confused-deputy actions or cross-tenant object references.

## Decision

Every customer-owned aggregate, command, event, artifact, log, metric dimension, cache entry, and job carries an immutable `OrganizationId`. Authorization is deny-by-default and evaluated at every application boundary against actor, organization, action, resource, purpose, and conditions.

Use OIDC/SAML federation for workforce users, SCIM for lifecycle provisioning, workload identity for services, short-lived credentials, MFA policy hooks, and auditable break-glass access. RBAC supplies stable roles; contextual ABAC constrains resource scope, environment, approval state, and sensitivity. Database and object-store access enforce tenant predicates independently of API filtering. Workers receive per-job capability tokens limited to exact artifact digests and expiry.

## Consequences

### Positive
- Provides enterprise SSO/provisioning and defense against cross-tenant access.
- Makes service-to-service authority explicit and short-lived.

### Negative
- Authorization policy and test matrices become substantial product components.
- Tenant-aware telemetry requires cardinality and privacy controls.

### Neutral
- Dedicated single-tenant deployments may exist, but contracts remain tenant-scoped.

## Links

- Depends on [ADR-009](ADR-009-add-enterprise-platform-bounded-contexts.md)
- [Organization & Access](../ddd/contexts/organization-access/README.md)
