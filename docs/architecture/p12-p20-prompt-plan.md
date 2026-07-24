# P12–P20 Implementation Prompt Plan

Status: reconstruction, not a recovery

The original prompt list lived at `.plans/implementation-prompts.md`, which was
gitignored and was never committed. It is permanently lost: no git history, no
dangling objects, no backup. **This document is authored fresh** — it is not a
transcription or recollection of the original text. It is grounded in what P00's
own artifacts say still needs to happen: [`adr-acceptance-audit.md`](adr-acceptance-audit.md)
(concrete resolution per ADR), [`p00-decision-record.md`](p00-decision-record.md),
[`platform-decisions.md`](platform-decisions.md), [`production-readiness.md`](production-readiness.md),
[`decision-traceability.md`](decision-traceability.md), and the forward references
already dropped into completed work: `docs/implementation/p03-organization-access.md`
(P18), `docs/implementation/p07-advisory-intake.md` (P16), `platform-decisions.md`
(P20), and `p00-decision-record.md` (P13, P18, P20). Where those files name a prompt
number for specific scope, this plan honors it. Everything else is a best-effort
reconstruction of intent, scoped against the real crate layout under `crates/`.

P00–P11 are done (workspace/CI baseline; syntax/contract primitives; organization
access; persistence/artifacts/events; commercial entitlements; asset portfolio;
advisory intake; remediation runs; isolated execution; fixture qualification;
patch proposals). No ADR is `accepted`; every prompt below still requires the named
external/architecture/security reviewers the audit calls for before its ADR moves
out of `proposed`. Local-only code completeness is not ADR acceptance.

## P12 — Secrets and Signing Key Lifecycle Service

ADRs: ADR-015 (local scope); placeholder for hosted KMS/HSM half.

Goal: Replace the ad hoc Ed25519 key handling already inlined in
`crates/cauterizer-infrastructure/src/crypto.rs` and `contexts/isolated-execution`
with one Rust-owned key lifecycle service that Evidence (P13) and Isolated
Execution both consume through a signer port.

Scope:
- New `SignerPort`/`KeyLifecyclePort` traits in `crates/cauterizer-infrastructure/src/crypto.rs` covering generate, current-key lookup, sign, verify, rotate-with-overlap, revoke, and destroy.
- Local dev adapter: key material generated per installation, written mode `0600` outside the repo, never logged/persisted in domain state; every signature carries key ID, trust-domain tag, and `untrusted-development` marker.
- Versioned trust metadata record (key ID, algorithm, not-before/expiry, revocation state) persisted via a new migration in `crates/cauterizer-infrastructure/migrations`.
- Wire `isolated-execution`'s worker-protocol signer (`contexts/isolated-execution/src/application/authentication.rs`) through the new port instead of a private key.

Acceptance:
- Rotation-with-overlap, revocation, and compromise-response unit/property tests pass; a revoked key fails verification on the next check (zero cache TTL, matching the P03 pattern).
- No private key byte ever appears in logs, events, evidence, or error `Debug` output (assert via redaction tests).
- Isolated Execution's existing 21-test suite still passes unmodified against the new port.

Flag: local file-based key custody only. Hosted KMS/HSM-backed non-exportable
signing, workload identity, and a compromise drill are out of scope — no cloud KMS
account exists for an autonomous session to provision or approve. Stub the port so
a future hosted adapter is a drop-in; do not claim production signing conformance.

## P13 — In-toto Evidence Bundle Attestation

ADRs: ADR-007; ADR-006 (verdict linkage). Named by `p00-decision-record.md` row
"Evidence predicate and trust policy … P13 completion."

Goal: Build out `crates/contexts/evidence` (currently a stub) into the bundle
assembly, signing, and offline-verification boundary for a finalized `Verdict`
from P12/Verification, using the P12 signer port.

Scope:
- Domain: `EvidenceBundle` aggregate — in-toto Statement v1 envelope, versioned Cauterizer predicate (subject digests, materials, verdict-policy binding, organization/scope binding).
- Application: assemble-bundle handler consuming a finalized `Verdict` (from P12) plus referenced artifact digests from P04's artifact store; sign via `SignerPort` (P12).
- Infrastructure: Rust offline verifier validating schema/version, JCS canonical bytes, every referenced digest, signature, key validity interval, and revocation state at signing time vs. verification-policy time.
- Field-by-field and artifact-by-artifact mutation/tamper test vectors (golden fixtures under `crates/contexts/evidence/tests`).

Acceptance:
- Verifier rejects every tamper vector (altered subject, materials, predicate field, signature, expired/revoked key) with a stable reason code.
- Bundle assembly is exact-retry idempotent and fails closed on missing/mismatched digests.
- Local bundles are provably labeled `untrusted-development`; no code path can silently relabel one `trusted`.

Flag: none of this requires external infrastructure — it is fully code-completable
locally against the P12 dev signer. Production trust-root distribution and
KMS-backed signing remain P12's hosted placeholder.

## P14 — Transactional Outbox/Inbox Delivery Hardening

ADRs: ADR-012.

Goal: Harden the outbox/inbox groundwork P04 already laid (`transactional.rs`,
`delivery.rs`, migration `0002_delivery_reliability`) into the full durable
delivery contract: ordering, dedup horizon, poison handling, and replay.

Scope:
- Extend `crates/cauterizer-infrastructure/src/delivery.rs` dispatcher to use `FOR UPDATE SKIP LOCKED` bounded polling with authenticated producer envelopes.
- Durable inbox: `(consumer, event_id)` uniqueness, aggregate-sequence checks, idempotent effect application, explicit out-of-order holding/replay.
- Dead-letter table + migration after a bounded retry count, with authorization-protected replay command.
- Cross-context integration test: publish from `remediation-runs`, consume in `patch-proposals` and `verification`, proving at-least-once delivery with per-aggregate ordering only.

Acceptance:
- Duplicate delivery, out-of-order delivery, and crash-before/after-commit tests show no duplicated side effects and no lost events.
- Dead-lettered events are replayable only by an authorized actor and are audited.
- Deduplication retention is at least as long as configured event replay/retention (ADR-011 defaults).

Flag: fully local/PostgreSQL-testable. No broker (NATS JetStream) is introduced —
platform-decisions.md defers that until load evidence requires it; this prompt
produces the benchmark harness that would generate that evidence, not the broker.

## P15 — Risk-Based Verification and Release Gates

ADRs: ADR-022. Referenced by `adr-acceptance-audit.md` (ADR-017: "record
provisional engineering objectives only after P15/P18 measurements").

Goal: Turn the abuse-case test matrix into an enforced, traceable release gate,
and produce the performance/soak/chaos measurements ADR-017 needs as SLI input.

Scope:
- `scripts/ci/verify-release-gates.sh`: one row per ADR invariant/abuse case in `docs/architecture/abuse-case-test-matrix.md`, mapped to an automated test, owner, and cadence.
- New `crates/architecture-tests` additions for the still-missing layers: cross-tenant generative, leakage/tamper, fuzz targets (`cargo-fuzz` harnesses for canonical JSON/evidence parsing), and a soak/chaos harness for the outbox dispatcher (P14) and sandbox lease lifecycle (P09).
- Quarantine mechanism: flaky test annotation requiring owner, reason, and expiry ≤14 days; quarantined tests cannot satisfy a gate.
- Critical/high finding acceptance record format (`.evidence/release/*.md`) with named risk owner and expiry.

Acceptance:
- `verify-release-gates.sh` fails the build if any ADR/abuse-case row lacks linked evidence or has an expired quarantine/acceptance.
- Soak/chaos run against local Podman + PostgreSQL/MinIO produces recorded latency/throughput/error-rate numbers stored as the ADR-017 provisional SLI baseline (explicitly `local-nonconformant`, not a contractual SLO).
- Cross-tenant and leakage fuzz targets run in CI on a bounded corpus/time budget.

Flag: hosted gVisor/Kubernetes sandbox conformance (ADR-004 hosted target) and the
full AC-004–AC-015/AC-030 hosted-backend suite referenced by
`p00-acceptance.tsv`'s `P00-HOSTED-SANDBOX` gate are folded in here as the closest
thematic fit but are **not implementable by this prompt**: they require a real
dedicated Kubernetes/gVisor cluster and an independent security reviewer. This
prompt delivers the test *matrix and harness* only; running it against a hosted
backend and getting the named sign-off is a separate infra/ops track item.

## P16 — Live Advisory Acquisition (OSV)

ADRs: ADR-008, ADR-011, ADR-020 (networked-acquisition-governance half). Named
by `docs/implementation/p07-advisory-intake.md`: "Live OSV acquisition remains
intentionally absent until P16."

Goal: Add a live, networked OSV acquisition adapter behind Advisory Intake's
existing anti-corruption port, reusing P07's normalization/failure vocabulary,
without weakening the fixture-only guarantees other contexts rely on.

Scope:
- New adapter crate `crates/adapters/advisory-intake-osv` implementing the same acquisition port `crates/contexts/advisory-intake` already defines, alongside the existing fixture adapter (`advisory-intake-artifacts`).
- SSRF/redirect defense: destination allowlist, no redirect-following across origins, byte-limit before parse, TLS pinning of the OSV host, timeout/retry policy with no adaptive backoff that leaks state.
- Raw-bytes-vs-canonical-bytes split into two independently digested P04 quarantine artifacts, exactly as P07 does for the fixture path.
- Provenance fields distinguishing `fixture` vs `live-osv` source class on every `AdvisoryRecord` snapshot.

Acceptance:
- SSRF/redirect/oversize/malformed-schema negative tests deny with stable reason codes and no partial state.
- Live acquisition is feature-gated and off by default; existing P07 fixture-path tests are unaffected.
- Cross-context test proves a live-acquired advisory flows through the same normalization/alias pipeline as a fixture-acquired one with identical invariants.

Flag: this covers the *advisory* half of ADR-020's networked-acquisition
governance. The **hermetic fixture pipeline** half of ADR-020 (network-denied
CVE-Bench acquisition, SBOM/scanning gate, content-addressed pinned bundle) is
folded in here as the closest thematic fit but stays a placeholder: it depends on
the already-tracked external gates `P00-FIXTURE-LEGAL` and
`P00-FIXTURE-QUALIFICATION` in `p00-acceptance.tsv`, which require named
legal/security reviewers and cannot be satisfied by code alone.

## P17 — Schema and Contract Evolution Governance

ADRs: ADR-021.

Goal: Give every published contract (organization-access, advisory-intake,
isolated-execution, evidence, etc.) an enforced compatibility policy instead of
ad hoc versioning per context.

Scope:
- Shared `crates/cauterizer-contracts` module: semantic-version + schema-name registry, drift test generator comparing Rust types to checked-in JSON Schema.
- Compatibility classifier: ordinary optional-additive fields are ignorable; unknown security-critical capability/algorithm/classification/policy/action fields fail closed (extend the classifier already implied by P03's "security-critical breaking" contract tests).
- Migration/deprecation-window policy: current + previous major supported for a published window; golden vectors per historical major stored under `crates/cauterizer-contracts/tests/golden`.
- CI check (`cargo test -p cauterizer-contracts --test schema_drift`) blocking merges that change a schema without a version bump matching its compatibility class.

Acceptance:
- Adding a new required field to an existing v1 contract fails CI unless it ships as v2 with a golden previous-major fixture.
- Unknown-but-non-critical additive fields round-trip without error; unknown security-critical fields are rejected by every consuming context, not just the origin.
- Evidence bundles (P13) are proven never rewritten by a schema migration — only re-interpreted by a versioned offline reader.

Flag: none. Fully code-completable; no external approval blocks it, though the
window length itself (currently unspecified) should be ratified by an
architecture decider before ADR-021 can move to `accepted`.

## P18 — Audit-Safe Observability and Production Telemetry

ADRs: ADR-016; bounded ADR-017 SLI definition; ADR-012 backup/reconciliation
follow-up. Named twice by `docs/implementation/p03-organization-access.md`:
"P18 owns production exporters and measured telemetry" and "production tabletop
exercises remain a P18 release-readiness obligation." Also named by
`p00-decision-record.md`: "Storage, deletion, and event recovery … P04 and P18
completion" and "Reliability and production objectives … P18 and P20 completion."

Goal: Replace every context's bounded structured-file logging (established
piecemeal since P03) with one Rust tracing/metrics/audit port with a real
OpenTelemetry exporter and an integrity-protected audit stream, plus close the
outbox/inbox backup-and-recovery loop P04/P14 left open.

Scope:
- `crates/cauterizer-infrastructure` telemetry module: structured allowlist schema, non-printable sensitive-value wrapper, RED metrics with bounded dimensions (mirrors the pattern P03 already applies to authorization decisions, generalized to every context).
- Local sink: bounded structured files + separate append-only audit file. Hosted sink: OpenTelemetry exporter + integrity-protected audit stream through a distinct identity (stub adapter behind the same port).
- Alert definitions from `docs/architecture/security-threat-model.md`, implemented as executable checks against the local sink (cross-tenant attempt, break-glass use, repeated privilege escalation, audit publication failure, dead-letter growth).
- Backup/restore drill script for PostgreSQL + MinIO local integration environment; tombstone and legal-hold reconciliation test against ADR-011 retention defaults.

Acceptance:
- Redaction corpus test: no context can emit a payload-classified (Confidential/RestrictedSecurity) value through metrics, traces, or telemetry logs — only digests/reason codes/references.
- All five threat-model alerts fire against synthetic triggers in the local sink.
- A local encrypted backup/restore drill recovers PostgreSQL + artifact state to a consistent point with tombstones intact; documented as a manual, non-conformant-local procedure (no availability claim).
- Provisional SLI dashboard combines this prompt's telemetry with P15's soak numbers into one reviewed (not yet contractual) objectives table.

Flag: local sink, local backup/restore drill, and the alert suite are fully
code-completable. The hosted OpenTelemetry/audit-stream exporter is a stub
adapter only — no hosted collector, multi-zone PostgreSQL, or named
operations/product reviewer exists for this session to exercise; ADR-017's actual
RPO/RTO commitments and the `P00-PRIVACY-KEY-RISK` external gate remain
placeholders folded in here.

## P19 — Content-Addressed Artifacts and Contract-First APIs

ADRs: ADR-013, ADR-014.

Goal: Harden P04's artifact adapters (`artifacts.rs`, `s3_artifacts.rs`,
`filesystem_artifacts.rs`) into the full CAS commit protocol, and give
`crates/cauterizer-api` a contract-first, idempotent HTTP surface over the
existing application facades.

Scope:
- CAS commit protocol: quarantine upload → stream size/hash verify server-side → media/schema validation → atomic descriptor publish, with mark-and-sweep GC respecting legal holds and per-class retention (ADR-011).
- Explicit solver-public / verifier-hidden / evidence / quarantine bucket-prefix segregation enforced in `s3_artifacts.rs`, matching the P09/P11 solver-verifier firewall boundary.
- `cauterizer-api`: OpenAPI/JSON-Schema-generated contracts from `cauterizer-contracts` (P17); idempotency-key table (org/actor/operation/request-digest/result-ref/expiry); RFC 9457 problem-details error shape; aggregate-sequence/ETag concurrency tokens; opaque pagination cursors.
- CLI (`cauterizer-cli`) continues to call the same application facades directly — the API crate wraps, it does not replace, the local path.

Acceptance:
- Exact-retry with the same idempotency key returns the identical prior result; same key with a different request digest returns a stable conflict, never silently applies either version.
- Corruption test: server-side rehash mismatch on read blocks the read and raises an integrity alert (feeds P18).
- Solver-identity credentials cannot list or read verifier-hidden or evidence buckets in a negative-permission test (extends the P09 firewall test suite).
- Generated OpenAPI/JSON Schema for every public endpoint passes the P17 drift check.

Flag: none. Fully code-completable against MinIO/PostgreSQL local integration;
no external approval required for the API/CAS layer itself.

## P20 — Software Supply Chain and Release Hardening

ADRs: ADR-019; production-readiness capstone folding ADR-004 (hosted sandbox),
ADR-015 (hosted KMS/HSM), ADR-017 (hosted SLO/DR drills), ADR-018 (plane
separation deployment), and ADR-020 (hermetic fixture pipeline) references.
`platform-decisions.md` scopes its record to "P01 through P20"; `p00-decision-
record.md` ties "Reliability and production objectives" to "P18 and P20
completion" — this prompt is the closing release-readiness item of that pair.

Goal: Make the workspace's build and release path itself trustworthy — pinned
toolchain, reproducible builds, signed artifacts and provenance, gated
dependency/license/SAST admission — and record, rather than fake, everything
that still requires real hosted infrastructure or a named external approver.

Scope:
- CI hardening: pin Rust stable by exact channel, commit `Cargo.lock`, `#![forbid(unsafe_code)]` workspace default (deny-by-default already implied by P00; make it enforced), `cargo fmt`/clippy/test/`cargo-audit`/`cargo-deny`/secret-scan/SAST as blocking jobs, pin all GitHub Actions by commit SHA.
- SBOM generation (SPDX or CycloneDX) per release build; license ledger covering the fixture (P10/P16) and any non-Rust adapter dependency.
- Release identity: least-privilege isolated signing identity, artifact + provenance signing, admission verification step before any artifact is treated as releasable.
- `docs/architecture/production-readiness-track.md` appendix (or a section of this file, author's choice at implementation time) enumerating the five infra/ops placeholders below with owner-to-be-named, exit criteria, and the exact `p00-acceptance.tsv` gate they map to.

Acceptance:
- A tampered dependency, an unpinned Action, or a missing SBOM fails the release job.
- Release artifacts verify against the recorded provenance and signature before `verify-p00-acceptance.sh external-ready` is allowed to pass on the release-related rows.
- Rollback rehearsal: a simulated bad release is caught by canary/verification and rolled back without evidence loss (ties into P18's backup/restore drill).

Flag — explicit infra/ops placeholder track, folded here rather than invented as
fake prompts, each requiring named external approval and real infrastructure this
session cannot provision:
- **Hosted gVisor/Kubernetes sandbox** (ADR-004 hosted target) — needs a dedicated cluster and independent security review; test harness exists from P15.
- **KMS/HSM production signing** (ADR-015 hosted) — needs a cloud KMS/HSM account and workload-identity setup; port exists from P12.
- **SLO/DR measurement and drills** (ADR-017 hosted commitments) — needs multi-zone PostgreSQL/object storage and a real failover exercise; provisional local SLIs exist from P15/P18.
- **Plane separation deployment** (ADR-018) — needs real distinct node pools/network policies/identities per plane; local mode remains explicitly non-conformant.
- **Hermetic fixture acquisition pipeline** (ADR-020 hermetic half) — blocked on `P00-FIXTURE-LEGAL`/`P00-FIXTURE-QUALIFICATION`, both `external_required` in `p00-acceptance.tsv`.

None of these five can be truthfully marked complete by an autonomous coding
session; they require named product/security/privacy-legal/operations
accountabilities per `adr-acceptance-audit.md`'s acceptance rule, plus
provisioned cloud resources. This plan records them as open rather than closing
them silently.
