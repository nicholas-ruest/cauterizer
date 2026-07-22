# External Actions: Operations and Security

## Threat boundary

Step-up authentication, separation of duties, destination binding, replay defense, least-privilege connector capability, and fail-closed policy.

## Reliability

Approval UX may be interactive; external action delivery is durable, idempotent, observable, and safely replayable.

## Required telemetry

- RED metrics for APIs and queue age/failure metrics for async work.
- Structured redacted logs with tenant-safe correlation and causation.
- Traces without payload capture.
- Audit records for authorization, configuration, privilege, integrity failure, and intervention.

## Runbooks

Cover dependency outage, poison messages, stuck work, quota exhaustion, integrity failure, tenant-isolation alert, and rollback/recovery. Each alert has severity, owner, dashboard, safe mitigation, escalation, and post-incident evidence.

## Deployment controls

Least-privilege workload identity, deny-default network, encryption, readiness, graceful shutdown, backpressure, canary, compatible migration, and tested rollback.

