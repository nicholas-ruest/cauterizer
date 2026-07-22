# Asset Portfolio: Test Specification

## Context-specific suites

- `scope precedence tables`
- `cross-tenant asset denial`
- `SCM URL/redirect validation`
- `revision immutability`
- `ownership revocation`

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

