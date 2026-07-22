# ADR-024: Govern Integrations, Plugins, and Webhooks

- **Status**: proposed
- **Date**: 2026-07-22
- **Deciders**:
- **Tags**: integrations, plugins, webhooks, marketplace

## Context

Commercial adoption needs SCM, advisory, identity, SIEM, ticketing, model, and billing integrations. Arbitrary in-process plugins would enlarge the trusted computing base and turn connector compromise into platform compromise.

## Decision

Integration Management owns connector definitions, installations, capability manifests, health, version compatibility, and delivery state. Adapters run out of process or in sandboxed WASM/worker boundaries with declared network destinations, data classes, scopes, rate limits, and resource budgets. Installation requires tenant-admin consent and least-privilege credentials held by ADR-015 facilities.

Inbound webhooks require signature, timestamp/replay defense, schema validation, tenant routing, idempotency, and bounded payloads. Outbound webhooks are signed, retried with backoff, observable, replayable by authorized operators, and suppress Restricted fields unless explicitly allowed. Plugin publication requires provenance, license/security review, compatibility tests, revocation, and support ownership.

## Consequences

### Positive
- Enables an ecosystem without making plugins part of the core trust boundary.
- Provides enterprise connector governance and diagnosability.

### Negative
- Sandboxed/out-of-process integrations have higher latency and stricter APIs.
- Marketplace review and compatibility support are ongoing costs.

### Neutral
- Initial adapters may ship in-tree but still obey the same manifest and port contracts.

## Links

- Depends on [ADR-008](ADR-008-integrate-upstream-tools-through-replaceable-adapters.md)
- Depends on [ADR-015](ADR-015-centralize-secrets-and-cryptographic-key-lifecycle.md)
