# P06 Asset Portfolio

Status: implemented and verified on 2026-07-23.

## Delivered boundary

`AssetPortfolio` owns organization assets, provider-neutral HTTPS source
locators, environment and criticality, explicit source ownership, exclusion-first
scope policy, deactivation, and immutable target resolution receipts. Repository,
package, and component identities contain no SCM SDK/provider types.

Target resolution is split at the acquisition boundary. Domain code creates an
exact request but performs no network lookup. The fixture adapter applies an
explicit host allowlist to every HTTPS redirect, rejects credentials, unsafe
ports, IP literals, local/metadata destinations, traversal/encoded separators,
redirect loops, excessive hops, and revision substitution. Repository revisions
must be full lowercase hexadecimal identities; a receipt binds the exact tenant,
asset, resolution request, canonical source, immutable revision, and acquisition
artifact SHA-256 digest.

The authorized facade exposes typed operations rather than a caller-supplied
domain closure. Run binding returns a receipt only after tenant isolation,
authorization, active ownership, exclusion-first scope evaluation, and exact
stored resolution checks. Ownership revocation and deactivation deny subsequent
binding immediately.

## Persistence and reliability

The in-memory repository provides deterministic optimistic transaction and
aggregate/outbox rollback tests. The PostgreSQL adapter encodes deterministic
domain snapshots, revalidates every invariant during rehydration, uses P04 row
level tenant isolation, and saves state/events/outbox/idempotency results in the
shared optimistic transaction. A restart test against PostgreSQL 17 proves the
saved portfolio reloads in the same tenant and is absent from another tenant.

## Verification evidence

- 20 Asset Portfolio tests cover strict parsing, scope decision tables,
  revocation, receipt immutability, destination substitution, SSRF/redirect
  fixtures, projection tenant isolation, stale rollback, mandatory audit, and
  exact run-binding denials.
- 28 shared-infrastructure tests and two same-context adapter tests include
  snapshot round-trip and conditional PostgreSQL 17 restart integration.
- Strict Clippy with warnings denied, formatting, architecture rules, and diff
  checks are release gates.
- The optimized context suite completed in 7.267 seconds including compilation;
  test execution completed below the timer's 0.01-second resolution. This is a
  regression baseline rather than a hosted latency SLO.

## Operations

Alert on ownership-verification age, resolution queue age, redirect denials,
destination/revision substitution, RLS violations, optimistic conflicts, audit
failure, and projection drift. On source compromise or ownership loss, revoke
ownership first, stop acquisition, retain immutable receipts for evidence, rotate
source credentials outside this context, and require a fresh ownership proof and
new resolution identity. Never mutate a prior receipt or authorize a mutable
revision.
