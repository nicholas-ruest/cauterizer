# P08 durable Remediation Runs

Status: implemented and verified on 2026-07-23.

## Process boundary

`RemediationRun` binds exactly one organization, advisory snapshot, authorized
target revision and acquisition digest, verification policy, conformance mode,
commercial reservation, canonical input digest, and lineage. Its append-only
lifecycle covers input binding, baseline request/observation, proposal
request/receipt, assessment request/result, inconclusive/non-conformant branches,
evidence request/receipt, budget exhaustion, cancellation, and sealing.

Request commands never manufacture another context's result. State advances from
baseline, patch, assessment, or evidence waiting states only after a tenant/run
bound authenticated fact from Isolated Execution, Patch Proposals, Verification,
or Evidence respectively. Producer/payload substitution, sequence gaps, duplicate
identity with changed payload, and terminal reopening fail closed.

## Durability and coordination

Accepted command key/digest bindings and authenticated fact envelopes are part of
the durable event history, so rebuilding after a crash preserves deduplication as
well as state. The transactional repository couples optimistic version checks,
state, append-only events, outbox, inbox sequence/deduplication, and exact command
results. A same-context PostgreSQL adapter stores the complete ordered timeline in
the P04 unit of work and invariant-validates it during restart rebuild.

The direct application facade exposes coarse create/bind/request/cancel/seal
commands and four explicit owning-context handlers. It enforces exact
tenant/action/resource authorization and mandatory audit without requiring ruflo
or another orchestrator.

## Projections and operations

Tenant projections are disposable and rebuild deterministically from ordered
events. They provide redacted state, complete timeline, and tenant-safe stuck-step
queries. Monitor state/step age, inbox gaps, replay conflicts, outbox age,
optimistic conflicts, cancellation races, budget exhaustion, audit failure, and
terminal-transition rejection. Recovery replays the retained timeline and inbox;
operators never edit a projection or synthesize a foreign result.

## Verification evidence

- 14 context tests cover the full lifecycle, model transitions, every recorded
  verdict, command/fact dedupe after rebuild, producer/tenant/order rejection,
  crash replay, cancellation/budget races, terminal immutability, projection
  rebuild, timeline, and stuck-step isolation.
- The same-context PostgreSQL adapter has timeline codec and conditional
  PostgreSQL 17 save/restart/foreign-tenant tests.
- Strict Clippy with warnings denied, formatting, architecture, and workspace
  tests are release gates.
- The optimized context suite completed in 8.048 seconds including compilation;
  test execution completed below the timer's 0.01-second resolution. This is a
  regression baseline, not a workflow completion SLO.
