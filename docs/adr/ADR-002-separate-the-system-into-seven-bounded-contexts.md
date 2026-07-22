# ADR-002: Separate the System into Seven Bounded Contexts

- **Status**: proposed
- **Date**: 2026-07-22
- **Deciders**:
- **Tags**: ddd, boundaries, architecture

## Context

Cauterizer combines advisory normalization, run coordination, hostile execution, probabilistic patch generation, hidden-oracle verification, policy, attestation, and human-authorized export. A single shared model would allow concerns with radically different authority and confidentiality needs to leak into one another. In particular, solver access to verification internals or orchestration access to signing/external-action capabilities would invalidate core safety claims.

## Decision

Define seven bounded contexts:

1. **Advisory Intake** — normalize and snapshot untrusted vulnerability information.
2. **Remediation Runs** — own run identity, lifecycle, budgets, and state transitions.
3. **Isolated Execution** — execute declared jobs under resource and capability confinement.
4. **Patch Proposals** — produce bounded candidate patches from an explicitly limited solver view.
5. **Verification** — independently grade candidate patches and apply deterministic acceptance policy.
6. **Evidence** — construct, sign, and verify claims over immutable run artifacts.
7. **External Actions** — record human authorization and produce redacted dry-run/export artifacts.

Each context owns its language, aggregates, invariants, repositories, and internal data. Cross-context communication uses versioned public contracts and past-tense integration events. No context imports or queries another context's internal entities or persistence representation.

The shared kernel is limited to technical primitives with no domain authority: opaque identifiers, digest syntax, canonical timestamp representation, schema-envelope metadata, and error/result envelopes. `Advisory`, `Run`, `Evaluation`, and `EvidenceBundle` are not shared-kernel types.

## Relationship policy

- Upstream contexts publish immutable facts; downstream contexts translate them through anti-corruption layers.
- Remediation Runs coordinates process state but does not own another context's domain rules.
- Verification is the sole owner of remediation verdict semantics.
- Evidence records a verdict but cannot manufacture or override it.
- External Actions consumes eligible evidence but cannot alter verification history.

## Consequences

### Positive

- Aligns software boundaries with security authority boundaries.
- Prevents upstream SDK types from becoming the canonical domain.
- Makes optional adapters and independent testing practical.

### Negative

- Introduces explicit translation and versioning overhead.
- Requires eventual consistency and duplicate-message handling.
- Some concepts need context-qualified names rather than convenient global types.

### Neutral

- The contexts may initially deploy in one process; logical boundaries do not require microservices.
- Physical module layout remains an implementation decision constrained by these boundaries.

## Validation before acceptance

- Walk one complete remediation scenario through the context map.
- Confirm every sensitive datum has exactly one authoritative owner.
- Confirm no required use case needs solver-to-verifier queries.

## Links

- Depends on [ADR-001](ADR-001-bound-the-mvp-to-an-offline-human-gated-loop.md)
- [DDD overview](../ddd/README.md)
- [Context map](../ddd/context-map.md)
