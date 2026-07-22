# ADR-004: Isolate All Untrusted Execution in Ephemeral Workers

- **Status**: proposed
- **Date**: 2026-07-22
- **Deciders**:
- **Tags**: sandbox, security, execution

## Context

Repository content, dependency installers, build scripts, tests, exploit regressions, and generated patches are all untrusted. A subprocess or ordinary container with ambient network, host mounts, credentials, or a daemon socket is not an adequate boundary. A successful patch result is meaningless if the evaluated code could modify its grader or fabricate its evidence.

## Decision

Every checkout, dependency build, reproduction, patch application, and test execution occurs in a fresh ephemeral worker created from an immutable, verified environment specification.

The execution policy requires:

- non-root identity and no privilege escalation;
- read-only base filesystem with explicit bounded scratch space;
- no host filesystem mounts or container/runtime daemon socket;
- no injected secrets or cloud instance credentials;
- default-deny network egress during reproduction and grading;
- a separate, audited acquisition phase for dependencies;
- dropped capabilities and syscall confinement;
- CPU, memory, disk, process, output, and wall-clock limits;
- deterministic locale/timezone where practical;
- sanitized environment and bounded, redacted logs;
- unconditional cleanup after completion, timeout, cancellation, or crash.

The control plane sends a declarative `ExecutionRequest`; it never exposes an interactive privileged shell capability to agents. The worker returns observations and artifact digests, not a verdict.

The concrete sandbox backend is deferred until the deployment threat model is selected. Acceptance requires evidence that the chosen backend enforces these controls (for example, a gVisor-class boundary for hosted untrusted workloads).

## Consequences

### Positive

- Reduces the blast radius of hostile repositories and tests.
- Separates execution observations from policy and signing authority.
- Makes resource use and cleanup testable.

### Negative

- Increases startup latency, infrastructure cost, and platform complexity.
- Offline execution complicates dependency resolution and fixture construction.
- No sandbox eliminates all risk; backend patching and defense-in-depth remain necessary.

### Neutral

- Local development may use a weaker backend only if results are explicitly labeled non-conformant and untrusted.
- This ADR does not authorize active testing against live systems.

## Validation before acceptance

- Select a deployment-specific sandbox backend.
- Define adversarial tests for network, mounts, secrets, forks, disk, symlinks, log flooding, and cleanup.
- Document the trusted computing base and residual escape risk.

## Links

- Depends on [ADR-001](ADR-001-bound-the-mvp-to-an-offline-human-gated-loop.md)
- Depends on [ADR-003](ADR-003-use-immutable-snapshots-and-an-append-only-run-lifecycle.md)
- [Isolated Execution context](../ddd/contexts/isolated-execution.md)
