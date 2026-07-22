# Advisory Intake: Published Contracts

## Integration events

- `AdvisorySnapshotted`
- `AdvisoryWithdrawalObserved`
- `AdvisoryAliasResolved`
- `AdvisoryNormalizationFailed`

Events are past-tense facts. Payloads include the owning aggregate ID and only consumer-required data; large, Confidential, or Restricted content is an authorized digest reference.

## Contract rules

- Contract-first, tenant-scoped, versioned, and backward-compatible within a major version.
- Mutations require idempotency keys; conditional updates require aggregate version.
- Long work returns an operation/resource ID.
- Errors use stable problem types and reason codes.
- Unknown security-critical semantics are rejected.

## Consumer obligations

Consumers deduplicate through inboxes, validate producer/schema/tenant, tolerate allowed additive fields, and use aggregate sequence for ordering. Poison messages enter governed dead-letter handling.

## Compatibility gates

Test current and previous supported majors, schema diffs, examples, privacy classification, and authorization fields in CI.

