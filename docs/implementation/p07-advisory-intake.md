# P07 Advisory Intake

Status: implemented and verified on 2026-07-23.

## Delivered boundary

`AdvisoryRecord` retains immutable attributable snapshots, append-only withdrawal
observations, explicit source provenance, ecosystem-native affected ranges,
severity metric/version/vector provenance, ambiguous alias candidates, reviewed
alias decisions, and bounded normalization failures. Acquisition and command
identities are exact-retry idempotent; changed input never rewrites history.

The initial acquisition adapter is offline and fixture-only. It performs no live
network or filesystem access. Before parsing it enforces a byte limit, then a
closed schema/version, observation-time skew, bounded strings, aliases, affected
packages, and range references, plus known range semantics. Failures return stable
reason codes without source payloads.

Raw observation bytes and deterministic canonical bytes have distinct SHA-256
digests and classifications. The same-context artifact adapter places each into a
separate P04 quarantine, validates it server-side, and commits it in the
acquisition access domain. Aggregates and published events carry only authorized
descriptor metadata and digests; raw bodies never enter domain state, events,
logs, or downstream contracts.

## Reliability and security

The repository transaction couples optimistic state, outgoing facts, and
tenant-scoped idempotency results. Exact retries replay without advancing state;
stale versions and conflicting key reuse roll back. Typed handlers enforce exact
tenant/action/resource authorization and mandatory audit for snapshot, failure,
withdrawal, and alias decisions. Multiple alias candidates never auto-merge.

No source SDK/provider type is present. Live OSV acquisition remains intentionally
absent until P16; adding it requires the same anti-corruption port, SSRF/redirect
policy, provenance, fixture compatibility, and failure vocabulary.

## Verification evidence

- 20 context tests cover deterministic normalization, malformed/oversized input,
  unknown schema, future time, reference limits, immutable history, withdrawal,
  ecosystem/severity provenance, alias ambiguity, exact replay/conflict, and stale
  rollback, authorization/audit, and cross-tenant denial.
- A same-context integration test proves raw and canonical payloads become two
  independently committed, digest-verified P04 artifacts.
- Strict Clippy with warnings denied, formatting, architecture, and diff checks
  are required. No lint suppression is used for the domain model.
- The optimized context suite completed in 9.199 seconds including compilation;
  test execution completed below the timer's 0.01-second resolution. This is a
  regression baseline rather than a hosted ingestion SLO.

## Operations

Monitor fixture/source freshness, normalization failures by stable reason,
artifact quarantine age, snapshot lag, alias ambiguity, outbox age, audit failure,
and replay conflicts. On malformed-source spikes, stop acquisition, retain the
raw digest under policy, preserve existing snapshots, update the recorded fixture
and normalizer deliberately, then replay under a new acquisition identity. Never
delete or mutate prior snapshot/withdrawal history to reflect an upstream update.
