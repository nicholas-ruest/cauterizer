# ADR-001: Bound the MVP to an Offline Human-Gated Loop

- **Status**: proposed
- **Date**: 2026-07-22
- **Deciders**:
- **Tags**: scope, safety, governance, mvp

## Context

The seed vision describes an autonomous cyber-immune system that discovers vulnerabilities, proposes fixes, proves them, and acts. The research found that the repository has no implementation, the proposed dependencies have uneven maturity, and the highest-risk operations involve untrusted code execution and external mutations. Treating broad autonomy as the first milestone would mix discovery, remediation, proof, and publication before their authority boundaries exist.

The smallest independently useful claim is narrower: given an approved public vulnerability and immutable target revision, Cauterizer can reproduce the vulnerable behavior, obtain a bounded candidate patch, independently grade it, and produce evidence for a human decision.

## Decision

The initial Cauterizer product boundary is an offline-first, export-only remediation loop over one pinned public CVE-Bench fixture.

The MVP may:

- ingest an approved public advisory snapshot;
- fetch or use a pinned public source revision during an explicit acquisition phase;
- reproduce, solve, and grade inside isolated workers;
- create a policy decision and verifiable evidence bundle;
- present or export a redacted result for human review.

The MVP must not:

- scan or exploit live targets;
- submit vulnerability reports;
- create external tickets automatically;
- merge patches, publish packages, release, or deploy;
- grant an agent the capability to authorize an external mutation.

Any external mutation is a new architectural goal requiring its own threat model, authorization semantics, audit design, and superseding or extending ADR.

## Decision rules

1. Human approval is a domain fact with actor, intent, scope, target, expiry, and evidence digest—not a UI button or model assertion.
2. Approval does not make an unsafe run safe; it can only authorize an action already allowed by deterministic policy.
3. A missing, expired, mismatched, or unverifiable approval is denial.
4. Dry-run and export are the only External Actions capabilities in the MVP.

## Consequences

### Positive

- Establishes a testable vertical slice without irreversible side effects.
- Keeps safety claims proportional to available evidence.
- Allows deterministic core behavior to mature before orchestration breadth.

### Negative

- Delays the most visible autonomous features.
- Requires operators to bridge exports into existing workflows manually.
- Does not by itself reduce time from verified patch to deployment.

### Neutral

- Continuous advisory polling may be designed later but is not needed to prove the MVP.
- Human approval remains necessary even if future automation prepares every preceding artifact.

## Validation before acceptance

- Name the intended deployment model: local tool, trusted CI, or multi-tenant service.
- Define who is permitted to approve which action.
- Confirm export contents and redaction requirements.

## Links

- [Deep research](../../.plans/deep-research.md)
- [Initial goal plan](../../.plans/intial.md)
- [External Actions context](../ddd/contexts/external-actions.md)
