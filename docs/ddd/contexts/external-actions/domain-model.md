# External Actions: Domain Model

## Aggregate roots

`ExternalActionGrant` owns installation-time, repository-scoped authority.
`ExternalActionDelivery` owns one idempotent external effect and its remote-state
reconciliation. Both are persisted through context-owned repository ports;
cross-context objects are represented only by IDs, digests, and versioned
contracts.

## Invariants

- An administrator grants exact repository capabilities; an agent cannot grant
  or widen its own authority.
- Issue, remediation-branch, candidate-commit, pull-request, and redacted
  evidence-summary actions may be granted.
- Merge, approval, protected/default-branch push, force-push, administration,
  publication, release, and deployment are never grantable.
- Organization, installation, repository, action, candidate/evidence digest,
  destination, expiry, budget, and kill-switch state must match exactly.
- Exact retries reconcile the same remote object; conflicting reuse denies.
- Maintainer changes are not overwritten blindly.
- Every action is redacted, idempotent, auditable, and receipted.

## Value objects

- `ExternalActionGrantId`, `ExternalActionDeliveryId`
- `InstallationAuthority`, `RepositoryScope`, `CapabilitySet`
- `ActionType`, `ActionScope`, `AuthorizationPeriod`, `ActionBudget`
- `BranchPolicy`, `PathPolicy`, `MetadataPolicy`
- `RemoteObjectIdentity`, `RemoteRevision`, `DeliveryRequestDigest`
- `RedactionDecision`, `ReconciliationDecision`, `DeliveryReceipt`

## Domain services and policies

- `ExternalActionAuthorizationPolicy`
- `EvidenceEligibilityPolicy`
- `DeliveryIdentityPolicy`
- `ExternalContentPolicy`
- `RemoteReconciliationPolicy`

## Repository contracts

Repositories support tenant-scoped load, optimistic concurrency, atomic
aggregate/event-outbox persistence, deterministic delivery identity, and
invariant existence checks. Read projections serve queries.

## Domain constraints

- No infrastructure, provider SDK, framework, network, clock, random, or
  storage dependencies.
- IDs, clocks, policy inputs, connector results, and remote observations enter
  explicitly.
- Events include tenant, aggregate ID/type, sequence, schema version, event ID,
  time, correlation, causation, request digest, and classification.
- Credentials and sensitive values never enter aggregates or default-stringify.
