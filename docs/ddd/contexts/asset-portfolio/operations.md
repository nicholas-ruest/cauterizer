# Asset Portfolio: Operations and Security

## Threat boundary

Prevent SSRF, repository confusion, credential leakage, unauthorized forks, and out-of-scope target selection.

## Reliability

Reads support interactive inventory; source verification and revision resolution are asynchronous and observable.

## Required telemetry

- RED metrics for APIs and queue age/failure metrics for async work.
- Structured redacted logs with tenant-safe correlation and causation.
- Traces without payload capture.
- Audit records for authorization, configuration, privilege, integrity failure, and intervention.

## Runbooks

Cover dependency outage, poison messages, stuck work, quota exhaustion, integrity failure, tenant-isolation alert, and rollback/recovery. Each alert has severity, owner, dashboard, safe mitigation, escalation, and post-incident evidence.

## Deployment controls

Least-privilege workload identity, deny-default network, encryption, readiness, graceful shutdown, backpressure, canary, compatible migration, and tested rollback.

