# P05 Commercial Entitlements

Status: implemented and verified on 2026-07-23.

## Delivered boundary

`EntitlementAccount` owns immutable plan revisions, explicit feature grants,
windowed hard quotas, worst-case reservations, immutable usage records, positive
credit adjustments, and commercial suspension. Production profiles reject the
explicit unlimited local-development plan. Plan changes never alter verification,
verdict, evidence, or security-policy semantics.

Every cost-incurring downstream command must carry the exact active
`BudgetReservation` contract. Admission uses the worst-case amount, settlement
accepts actual usage no greater than that amount, and release returns unused held
capacity. Existing reservations remain settleable after downgrade or suspension.

The application facade validates the tenant/action authorization context, fails
closed when mandatory audit is unavailable, binds retries to canonical SHA-256
input, and uses an optimistic repository transaction that commits aggregate state
and outgoing facts together. The same-context
`cauterizer-commercial-entitlements-postgres` adapter persists tenant-RLS
account snapshots, durable idempotency results, and an append-only outbox.
Reservation, settlement, aggregate version, command result, and events commit
under one row lock and one database transaction. A transaction-scoped advisory
lock serializes identical idempotency identities before lookup, so simultaneous
retries cannot both mutate. The in-memory adapters remain deterministic
local/reference implementations.

## Reliability and reconciliation

Reservation, release, settlement, and credits are exact-retry idempotent and
reject changed input under a reused identity. Immutable usage records are the
settlement ledger. Reconciliation compares active/settled/released reservations,
usage records, credits, and rated external usage by tenant, quota window, and
dimension; drift creates an operational alert and never silently changes a
verification result.

Operators may suspend new admissions while retaining release and settlement.
Quota exhaustion is an admission denial with a stable commercial reason, not a
security verdict. No payment-card, invoice, billing-provider SDK, or provider
error data enters this context.

## Verification evidence

- 20 context tests cover quota-order properties, a 16-thread optimistic race,
  exact reservation/settlement retries, rollback, immutable usage, credits,
  downgrade, suspension, tenant/action authorization, mandatory audit, schema
  closure/drift, and the verification-semantics firewall.
- Strict Clippy with warnings denied, formatting, and diff validation pass.
- The PostgreSQL adapter test uses `CAUTERIZER_TEST_ADAPTER_POSTGRES_URL`
  (or the legacy database variable) and becomes mandatory when
  `CAUTERIZER_REQUIRE_POSTGRES_TESTS` is set. It covers concurrent hard-limit
  reservation, exact durable replay, conflicting-key rejection, restart
  rehydration, and foreign-tenant denial.
- The optimized test suite completed in 13.771 seconds including compilation;
  test execution completed below the timer's 0.01-second resolution. This is a
  regression baseline, not a hosted throughput SLO.

## Operations

Alert on quota-denial rate, reservation age, settlement lag, reconciliation drift,
optimistic-conflict rate, audit write failures, and outbox age. Safe mitigation is
to stop new admission, preserve current reservations and immutable usage, repair
the dependency, reconcile, and replay with the original idempotency identity.
Never increase quota or apply credit without an authorized, reason-coded audit
fact. Rollback must preserve all usage and settlement facts.
