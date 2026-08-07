# ADR-024: Govern Integrations, Plugins, and Webhooks

- **Status**: proposed
- **Date**: 2026-07-22
- **Deciders**:
- **Tags**: integrations, plugins, webhooks, marketplace

## Context

Commercial adoption needs SCM, advisory, identity, SIEM, ticketing, model, and billing integrations. Arbitrary in-process plugins would enlarge the trusted computing base and turn connector compromise into platform compromise.

## Decision

Integration Management owns connector definitions, installations, capability manifests, health, version compatibility, and delivery state. Adapters run out of process or in sandboxed WASM/worker boundaries with declared network destinations, data classes, scopes, rate limits, and resource budgets. Installation requires tenant-admin consent and least-privilege credentials held by ADR-015 facilities.

SCM installations may expose only the issue, remediation-branch, commit, and
pull-request capabilities authorized by ADR-025. They must not expose merge,
approval, protected/default-branch push, repository administration, release,
package publication, deployment, or branch-protection mutation. Installation
consent is the authority for bounded issue and pull-request delivery; a fresh
human approval is not required for each conformant run. External Actions still
re-authorizes every invocation against the installation grant.

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
- Provider SDK types and credentials remain inside the connector boundary.

## Implementation status

This ADR remains `proposed`. The SCM slice now has a provider-neutral
capability manifest and installation grant, a deterministic fake connector,
and an in-tree GitHub adapter. GitHub tests cover tenant/installation mismatch,
branch restrictions, idempotency, reconciliation, Git Data object transfer,
secret/size/injection rejection, coarsened errors, and trusted receipt URLs.
External Actions independently re-authorizes each request and persists grants,
kill switches, deliveries, reconciliation scheduling, and terminal outcomes in
PostgreSQL.

Still unimplemented or externally unvalidated are inbound webhook
signature/timestamp/replay handling, outbound webhook delivery, durable
connector health/version state, out-of-process or WASM connector hosting,
marketplace provenance/support workflows, production credential custody, and a
real GitHub App permission exercise. None is implied by the in-tree adapter.

## Links

- Depends on [ADR-008](ADR-008-integrate-upstream-tools-through-replaceable-adapters.md)
- Depends on [ADR-015](ADR-015-centralize-secrets-and-cryptographic-key-lifecycle.md)
- Extended by [ADR-025](ADR-025-automate-remediation-and-deliver-reviewable-pull-requests.md)
