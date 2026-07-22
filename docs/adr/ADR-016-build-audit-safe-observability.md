# ADR-016: Build Audit-Safe Observability

- **Status**: proposed
- **Date**: 2026-07-22
- **Deciders**:
- **Tags**: observability, audit, telemetry

## Context

Production diagnosis requires metrics, logs, and traces, while security operations require immutable audit. Combining them leaks sensitive payloads and makes compliance evidence dependent on mutable operational telemetry.

## Decision

Separate operational observability from security audit. Use structured logs, distributed traces, RED/USE metrics, and correlation/causation IDs with classification-aware redaction. Never record source, patches, prompts, test bodies, secrets, or private advisory content by default. Tenant IDs are tokenized or access-controlled dimensions.

Audit records every privileged/security-relevant action with actor, tenant, action, resource, purpose, decision, policy version, time, request/correlation ID, and outcome. Audit is append-only, integrity-protected, access-controlled, retained by policy, and exportable to customer SIEM. Alert on cross-tenant denial, break-glass use, signature/key failures, sandbox violations, hidden-data access attempts, and anomalous spend.

## Consequences

### Positive
- Supports SRE operations, incident response, and enterprise audit integrations.
- Reduces telemetry as an exfiltration path.

### Negative
- Dual pipelines and redaction tests add cost.
- High-cardinality traces require sampling and careful tenant handling.

### Neutral
- Audit evidence complements but does not replace Evidence bundles.

## Links

- Depends on [ADR-010](ADR-010-enforce-tenant-isolation-and-zero-trust-authorization.md)
- Depends on [ADR-011](ADR-011-classify-encrypt-redact-and-retain-data-by-policy.md)
