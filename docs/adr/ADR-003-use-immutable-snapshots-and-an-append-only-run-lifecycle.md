# ADR-003: Use Immutable Snapshots and an Append-Only Run Lifecycle

- **Status**: proposed
- **Date**: 2026-07-22
- **Deciders**:
- **Tags**: state, provenance, idempotency, storage

## Context

Advisories change, upstream branches move, tools are upgraded, model configurations vary, and long-running jobs fail or retry. A mutable “current run” record cannot prove which inputs produced a patch or verdict and makes recovery vulnerable to partial writes and duplicate commands.

## Decision

All decision-relevant inputs and outputs are immutable, content-addressed snapshots. Remediation Runs owns an append-only lifecycle composed of immutable domain events and a derived current-state projection.

Required snapshot subjects include:

- advisory content and source metadata;
- immutable target revision and acquisition manifest;
- policy and schema versions;
- solver view and configuration;
- candidate patch;
- execution environment identity and declared command;
- bounded logs and test results;
- verification decision;
- evidence manifest and signature metadata.

A run command carries an idempotency key and expected prior state. Appending a transition is atomic. Repeating the same valid command returns the existing result; using the same key for different content is rejected. Historical events and artifacts are never overwritten. Corrections produce new snapshots and explicit supersession links.

The lifecycle vocabulary is documented in the Remediation Runs context. Projections are disposable and rebuildable from the event stream plus verified artifacts.

## Retention and confidentiality

Content addressing does not imply that all content is public. Public metadata, sensitive payloads, hidden verifier assets, and secrets use separate stores and access policies. Digests may cross boundaries; payload access does not.

## Consequences

### Positive

- Enables replay, crash recovery, independent verification, and precise audit.
- Prevents retries from silently producing competing histories.
- Binds decisions to exact inputs instead of mutable upstream names.

### Negative

- Requires retention, garbage-collection, and privacy policies.
- Append-only history increases storage and schema-evolution complexity.
- Content hashes can reveal equality and require careful treatment for sensitive material.

### Neutral

- This ADR does not choose a database or object store.
- Event sourcing is limited to the run lifecycle; contexts need not event-source every aggregate.

## Validation before acceptance

- Define canonical serialization and digest algorithms.
- Specify sensitive-data deletion without falsifying retained history.
- Test the state model against retries, cancellation, crashes, and duplicate delivery on paper.

## Links

- Depends on [ADR-001](ADR-001-bound-the-mvp-to-an-offline-human-gated-loop.md)
- Depends on [ADR-002](ADR-002-separate-the-system-into-seven-bounded-contexts.md)
- [Remediation Runs context](../ddd/contexts/remediation-runs.md)
- [Evidence context](../ddd/contexts/evidence.md)
