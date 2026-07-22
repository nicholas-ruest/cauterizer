# Bounded Context: Isolated Execution

## Purpose and ownership

Execute a declared workload in an ephemeral confined environment and report bounded observations. It owns worker allocation, capability/resource envelopes, lease state, cleanup status, and raw execution receipts.

It does not choose a patch, interpret a security test, assign a remediation verdict, sign evidence, or authorize an external action.

## Aggregate

### `ExecutionLease`

Identity: `ExecutionLeaseId`; one lease governs one immutable `ExecutionRequest` and at most one authoritative terminal receipt.

Invariants:

- The request digest, environment digest, command, mounts, network policy, and limits are immutable after allocation.
- No request may include a secret, host path, runtime daemon socket, privilege escalation, or undeclared capability.
- Network defaults to denied; any acquisition-network exception is a distinct job class and cannot be reused for grading.
- A lease has one active worker identity and cannot be reassigned without a new attempt.
- Completion, timeout, cancellation, and worker loss all require a cleanup result.
- Output beyond policy limits is truncated with an explicit receipt; truncation is never silent.
- A worker observation cannot contain a domain verdict.

Repository: `ExecutionLeaseRepository`.

## Value objects

- `ExecutionRequest`, `ExecutionPurpose`, `EnvironmentRef`, `DeclaredCommand`
- `CapabilityEnvelope`, `NetworkPolicy`, `FilesystemPolicy`
- `ResourceLimits`, `OutputLimits`, `LeaseDuration`
- `ExecutionReceipt`, `ExitObservation`, `CleanupReceipt`

## Domain services and policies

- `ExecutionAdmissionPolicy`: rejects requests exceeding declared capability limits.
- `EnvironmentVerificationService`: verifies immutable worker/base-image identity.
- `OutputSanitizationPolicy`: bounds and redacts logs without changing exit facts.

## Commands and queries

- `AllocateExecution`, `StartExecution`, `CancelExecution`, `RecordHeartbeat`
- `CompleteExecution`, `RecordTimeout`, `RecordWorkerLoss`, `ConfirmCleanup`
- `GetExecutionReceipt`, `GetLeaseStatus`

## Domain events

- `ExecutionAllocated`, `ExecutionStarted`, `ExecutionObserved`
- `ExecutionTimedOut`, `ExecutionCancelled`, `ExecutionWorkerLost`
- `ExecutionOutputTruncated`, `ExecutionCleanupConfirmed`, `ExecutionCleanupFailed`

Each event carries `ExecutionLeaseId`; terminal observations also carry the request and environment digests.

## Published language

Publishes `ExecutionRequest` acceptance and `ExecutionObservationDescriptor`. Payload logs remain protected artifacts referenced by digest and classification.

## Integration

Remediation Runs requests work. Verification interprets relevant observations through its own anti-corruption layer. Evidence may bind receipts by digest. No consumer gets an interactive worker control channel.

## Acceptance tests implied by the model

Network denial, secret absence, forbidden mounts, fork/disk/log exhaustion, symlink traversal, timeout, cancellation, worker crash, and cleanup failure must each produce explicit observable outcomes.
