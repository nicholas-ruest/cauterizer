# Verification: Operations and Security

## Threat boundary

Verifier-only store, identity, cache, logs, telemetry, memory, test names, paths, and timing; no feedback to conformant solver.

## Reliability

Determinism, flaky rate, fixture health, assessment latency, and false-accept controls are measured.

## Required telemetry

- RED metrics for APIs and queue age/failure metrics for async work.
- Structured redacted logs with tenant-safe correlation and causation.
- Traces without payload capture.
- Audit records for authorization, configuration, privilege, integrity failure, and intervention.

## Runbooks

Cover dependency outage, poison messages, stuck work, quota exhaustion, integrity failure, tenant-isolation alert, and rollback/recovery. Each alert has severity, owner, dashboard, safe mitigation, escalation, and post-incident evidence.

## Deployment controls

Least-privilege workload identity, deny-default network, encryption, readiness, graceful shutdown, backpressure, canary, compatible migration, and tested rollback.

