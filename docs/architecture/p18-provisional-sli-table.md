# P18 — Provisional SLI Table

**Status: PROVISIONAL. NOT a contractual SLO/RPO/RTO.**

Per ADR-017 ("Initial contractual SLOs are chosen only after load tests...
Exact SLO/RPO/RTO values are commercial decisions informed by benchmarks"),
none of the numbers below are commitments. They combine this prompt's
telemetry output shape with a handful of local, single-machine timing
measurements taken in this development sandbox. There is no hosted load
test, no multi-zone PostgreSQL, and no named operations/product decider
behind any figure here. Treat every row as "this is what one CI-sized
container did once," not as a promise about production hardware, network
conditions, or contended load.

## What is real here

- The **indicator shape** (rate, errors, duration; RED metrics keyed on
  [`BoundedContext`] x [`Outcome`], see
  `crates/cauterizer-infrastructure/src/telemetry/metrics.rs`) is the actual
  schema this prompt shipped, and is what a future hosted exporter would
  populate.
- The **alert set** (ten identifiers, see
  `crates/cauterizer-infrastructure/src/telemetry/alerts.rs`) is the actual
  executable alert suite, each with a passing synthetic-trigger test.
- The **timing numbers** below are real measurements from this sandbox, not
  fabricated placeholders, produced by tests that print their own numbers
  with `--nocapture` and assert only a generous sanity bound (not a
  performance contract):
  - `cauterizer_infrastructure::telemetry::sink::tests::local_file_sink_write_throughput_measurement`
  - `cauterizer_infrastructure::dispatcher::tests::dispatch_throughput_local_measurement`

## Provisional local indicators

| Indicator | Measurement | Local sample value | Caveats |
|---|---|---|---|
| Telemetry structured-write throughput | 5,000 events written + flushed to `LocalFileTelemetrySink` on local disk, `cargo test --release` | ~163,000 events/sec | Single process, single disk, no concurrent writers, no fsync durability guarantee beyond `flush()`, one run. |
| Outbox dispatch throughput | 5,000 rows through `dispatch_batch` against the in-memory `FakeDispatchPort` (P14), `cargo test --release` | ~191,000 rows/sec | **Not PostgreSQL** — the in-memory fake port has none of `PostgresDispatchPort`'s network/transaction/lock latency. This number characterizes the dispatch loop's own overhead only, not a realistic outbox-drain rate. |
| Concurrent dispatch correctness | 200 rows, 32 concurrent workers, `many_concurrent_workers_claim_disjoint_rows_and_acknowledge_each_event_exactly_once` (P14) | 100% exactly-once delivery, 0 lost/duplicated events | Correctness evidence, not a throughput number; also against the in-memory fake port. |
| Redaction guard correctness | Redaction corpus test (P18, this prompt) | 0 raw-text leaks across 5 adversarial payload classes | See `crates/cauterizer-infrastructure/src/telemetry/redaction_corpus_tests.rs`; demonstrated load-bearing by a temporary bypass-and-restore during development (see that file's module doc). |
| Alert suite coverage | 10/10 alert identifiers from the abuse-case-test-matrix "Alert and audit linkage" paragraph | 10/10 fire-on-trigger, 10/10 quiet-on-normal-traffic | Synthetic fixtures only; no production traffic has exercised these. |

## Explicitly out of scope for this table

- API availability/latency percentiles under realistic load (needs a hosted
  load test per ADR-017).
- Queue age, run completion rate, artifact durability, webhook delivery
  under production traffic.
- Any RPO/RTO number: `scripts/ops/local-backup-restore-drill.sh` proves the
  dump/restore *mechanism* preserves data and tombstones on one local
  container; it makes no recovery-time or recovery-point commitment (see
  that script's header).
- Error budgets and release policy: these require the contractual SLOs this
  table explicitly is not.

## Who can turn this into a real SLO table

Per ADR-017, someone with authority over commercial commitments, informed by
a hosted load test against production-shaped infrastructure. No such
reviewer or environment exists for this session; this table is scaffolding
for that future work, not a substitute for it.
