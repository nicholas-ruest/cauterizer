# ADR-020: Separate Networked Acquisition from Hermetic Evaluation

- **Status**: proposed
- **Date**: 2026-07-22
- **Deciders**:
- **Tags**: dependencies, hermeticity, sandbox

## Context

Building real projects often needs repositories and package registries, while grading with network access allows tests or patches to exfiltrate data or depend on mutable remote state.

## Decision

Acquisition is a distinct restricted job that resolves approved sources through allowlisted proxies, verifies checksums/signatures, scans content, creates an SBOM, and emits an immutable dependency/environment bundle. Reproduction, solver tooling, and verification consume only approved bundles with network denied.

Lock resolution, source URLs, redirects, package integrity, platform, toolchain, and timestamps are recorded. Mutable versions, unverified scripts, dependency confusion, typosquatting, and license-policy violations fail acquisition. Cache entries are content-addressed, tenant-policy aware, scanned, and never writable by evaluation workers.

## Consequences

### Positive
- Makes grading repeatable and sharply reduces egress risk.
- Produces dependency evidence and reusable environments.

### Negative
- Many upstream projects require special environment recipes.
- Proxies, caches, scanning, and licenses add latency and operations.

### Neutral
- A non-hermetic exploratory mode may exist only with explicit non-conformant labeling.

## Links

- Depends on [ADR-004](ADR-004-isolate-all-untrusted-execution-in-ephemeral-workers.md)
- Depends on [ADR-019](ADR-019-secure-the-software-supply-chain-and-release-process.md)
