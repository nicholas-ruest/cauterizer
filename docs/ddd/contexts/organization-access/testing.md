# Organization & Access: Test Specification

## Context-specific suites

- `cross-tenant property tests`
- `role/condition decision tables`
- `SAML/OIDC/SCIM contract fixtures`
- `last-owner invariant`
- `break-glass expiry and audit`

## Common gates

- Aggregate examples plus property/model tests for every invariant.
- Repository contract tests against every implementation.
- Command idempotency, optimistic concurrency, and duplicate-event tests.
- API/event compatibility for supported versions.
- Tenant-isolation and field-authorization negative tests.
- Fuzzing at untrusted parsers and boundary DTOs.
- Failure injection for timeout, outage, retry, and partial delivery.
- Load/soak tests against SLO assumptions.

## Definition of done

A feature requires domain, contract, authorization, audit, observability, migration, failure-mode, and runbook evidence. Happy-path unit tests alone are insufficient.

