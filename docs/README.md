# Cauterizer Architecture and Domain Documentation

This directory defines the proposed architecture and domain model for Cauterizer. It is documentation only: no source layout, runtime, workflow, or external integration is created by these records.

## Source material

- [Deep research](../.plans/deep-research.md)
- [Initial goal plan](../.plans/intial.md)

## Architecture decisions

The [ADR index](adr/README.md) contains proposed decisions. Proposed ADRs describe the current design hypothesis and are not enforceable until accepted by named deciders.

## Domain-driven design

The [DDD overview](ddd/README.md) defines eleven bounded contexts and links each implementation-grade package scaffold: domain model, application use cases, published contracts, operations/security, and test specification. The [context map](ddd/context-map.md) governs their relationships.

## Production architecture

- [Production readiness blueprint](architecture/production-readiness.md)
- [Security threat-model scaffold](architecture/security-threat-model.md)
- [Decision and delivery traceability](architecture/decision-traceability.md)
- [Future DDD source/package layout](ddd/implementation-scaffold.md)

## Review artifacts

- [DDD validation report](reviews/ddd-validation.md)
- [ADR compliance review](reviews/adr-compliance.md)
- [Documentation drift report](reviews/documentation-drift.md)

## Document rules

1. ADRs own cross-cutting architectural decisions; DDD documents apply those decisions to domain boundaries.
2. Contexts integrate through published contracts or events, never another context's internal model.
3. A proposed decision must not be described as implemented or accepted.
4. Any future implementation drift must be resolved by changing the implementation or superseding the relevant ADR—not by silently editing history.
5. Security claims must distinguish observed behavior, provenance/integrity, policy compliance, and semantic correctness.
