# Production Readiness Track

**Status: six open infra/ops placeholders. None are complete. None can be
closed by an autonomous coding session.**

This is the honest close-out of the P12–P20 implementation arc (see
[`p12-p20-prompt-plan.md`](p12-p20-prompt-plan.md)). Each of P12, P15, P16,
P18, and P19 individually flagged five of these placeholders as out of
reach without real hosted infrastructure and a named external approver. P20
folds them into one place rather than leaving separate "flag" sections
scattered across prompt-plan history, and records what changed between the
plan's original guess and what P12–P19 actually shipped — in two cases
(P16's live acquisition adapter, P19's API crate) the delivered code is
narrower than the plan assumed, and this document says so rather than
implying more coverage than exists.

Per [`adr-acceptance-audit.md`](adr-acceptance-audit.md)'s acceptance rule,
an ADR moves from `proposed` to `accepted` only when its accountable
deciders are *named people*, not roles. Every "owner" below is therefore
**owner-to-be-named** — this document cannot name them and does not attempt
to.

## 1. Hosted gVisor/Kubernetes sandbox conformance (ADR-004 hosted target)

- **Current state**: local-only. `contexts/isolated-execution` and P09's
  hardened cleanup/secret-handling run against a local sandbox backend;
  `.evidence/p00/local-sandbox-qualification.md` is the only sandbox
  qualification evidence path this workspace can populate today.
- **What P12–P19 built toward it**: P15 turned the abuse-case test matrix
  into an enforced release gate (`scripts/ci/verify-release-gates.sh`,
  `docs/architecture/abuse-case-test-matrix.tsv`) and added the
  cross-tenant/leakage/tamper fuzz targets and the outbox/sandbox
  soak-chaos harness — all runnable today, but only against the local
  backend. None of it has ever executed against a gVisor-or-stronger
  cluster.
- **Owner-to-be-named**: platform/infrastructure owner to provision the
  cluster, plus the independent security reviewer named in
  `adr-acceptance-audit.md`.
- **Exit criteria**: a dedicated gVisor-or-stronger Kubernetes cluster
  exists; AC-004 through AC-015 and AC-030 (per
  `abuse-case-test-matrix.md`) pass on that exact backend; independent
  topology/data-flow review completes; residual risks are accepted and
  signed.
- **`p00-acceptance.tsv` gate**: `P00-HOSTED-SANDBOX` (`external_required`,
  due `hosted-conformant-release`). Sibling baseline gate `P00-LOCAL-SANDBOX`
  (`external_required`, due `P01`) covers the local-only evidence this
  workspace *can* produce and remains separately open.

## 2. KMS/HSM production signing (ADR-015 hosted)

- **Current state**: local-only. P12 shipped `SignerPort`/`KeyLifecyclePort`
  with a single concrete implementation family
  (`UntrustedDevelopmentKeyLifecycle`, file-custody, mode `0600`, no cache
  TTL) that hardcodes the `"untrusted-development"` trust label on every
  signature. P13's offline verifier enforces a hardcoded
  `ACCEPTED_TRUST_LABELS = ["untrusted-development"]` allowlist, so no
  bundle can be silently reinterpreted as production-trusted no matter what
  a future signer claims.
- **What P12–P19 built toward it**: the port abstraction itself is the
  hosted-adapter drop-in point — a KMS/HSM-backed `SignerPort` can be added
  without changing any caller. P20 added
  `crates/cauterizer-infrastructure/src/release_admission.rs`, which proves
  the sign/verify/tamper-detection *logic* a release pipeline needs
  (digest-mismatch rejection, corrupted-signature rejection,
  edited-after-signing rejection, revoked-key rejection) independent of
  which concrete `SignerPort` backs it — so swapping in a hosted signer
  changes zero admission logic, only which adapter is injected.
- **Owner-to-be-named**: named cryptography/security reviewer plus a cloud
  platform owner to provision and operate the KMS/HSM account and workload
  identity.
- **Exit criteria**: a cloud KMS/HSM account is provisioned; workload
  identity is wired so private key material never leaves the KMS/HSM
  boundary; a compromise-response drill runs against the real hosted
  signer (not the local dev adapter); `ACCEPTED_TRUST_LABELS` is widened
  only through a reviewed change that names the new label's trust basis.
- **`p00-acceptance.tsv` gate**: `P00-PRIVACY-KEY-RISK` (`external_required`,
  due `hosted-production`) is the closest existing gate — its evidence
  requirement explicitly names "KMS-HSM lifecycle." The umbrella gate
  `P00-NAMED-APPROVALS` (`external_required`, due `hosted-production`) also
  applies, since any hosted signing claim needs a named security approval.

## 3. SLO/DR measurement and drills (ADR-017 hosted commitments)

- **Current state**: local-only and explicitly provisional. P15 produced a
  local soak/chaos harness and numbers labeled `local-nonconformant`. P18
  added `docs/architecture/p18-provisional-sli-table.md` (real local
  timing numbers, no contractual claim) and
  `scripts/ops/local-backup-restore-drill.sh` (real PostgreSQL 17 +
  filesystem artifact store dump/restore, tombstone and legal-hold
  integrity proven, no availability claim). P20 extended that pattern with
  `scripts/ops/local-release-rollback-drill.sh`, which actually runs
  against a fresh local Docker PostgreSQL container: it seeds a
  last-known-good state, takes a backup, simulates a bad release corrupting
  an already-signed evidence artifact's digest in place, detects the
  corruption by digest comparison, and restores via `pg_dump`/`pg_restore`
  with the previously-signed evidence row recovered byte-identical and the
  corrupted/poison state gone — while also running P13's evidence
  tamper-vector suite, P20's release-admission tamper-vector suite, and
  P14's live-database outbox/inbox dispatcher test as independent
  detection-invariant proof. All of this remains single-machine,
  single-container, and non-contractual.
- **What P12–P19 built toward it**: P14 (durable outbox/inbox, dead-letter
  replay — the mechanism a real DR drill would exercise under load), P15
  (soak/chaos harness and provisional SLI baseline), P18 (telemetry, ten
  threat-model alerts, backup/restore drill), P20 (release-admission logic
  and rollback rehearsal).
- **Owner-to-be-named**: named operations/product decider to ratify
  ADR-017's actual RPO/RTO commitments, per
  `p00-decision-record.md`'s "Reliability and production objectives" row
  (tied to "P18 and P20 completion" for the *measurement inputs*, not the
  sign-off itself, which remains outstanding).
- **Exit criteria**: multi-zone PostgreSQL and object storage exist; a real
  failover exercise runs against them; RPO/RTO numbers are measured under
  realistic load and signed off, superseding every provisional local number
  in this workspace.
- **`p00-acceptance.tsv` gate**: no dedicated SLO/DR row exists in the
  registry today. The closest mapping is the umbrella gate
  `P00-NAMED-APPROVALS` (`external_required`, due `hosted-production`),
  whose evidence requirement names "operations" as one of the required
  approving roles; a real ADR-017 row would need to be added to
  `p00-acceptance.tsv` alongside that approval, which is itself an
  open action, not something this document can add unilaterally.

## 4. Plane separation deployment (ADR-018)

- **Current state**: local-only, single-process. P19 built
  `crates/cauterizer-api` as a thin, function-based HTTP-*shaped* contract
  layer over `OrganizationAccessFacade` — explicitly **not a bound axum
  server** ("to avoid shipping untested routes," per the P19 commit). There
  is today no network listener to separate into planes at all; `cauterizer
  -cli` continues to call application facades directly, in-process.
- **What P12–P19 built toward it**: P09's isolated-execution sandbox
  already separates the untrusted execution plane from the trusted core at
  the process/sandbox boundary (local-only). P19's
  `crates/cauterizer-infrastructure/src/artifact_access.rs`
  (`ArtifactCredentialIssuer`/`ScopedArtifactStore`) enforces solver /
  verifier / evidence bucket-prefix segregation at the credential level —
  a real, tested data-plane-scoped separation — but this is authorization
  scoping within one process, not node/network/identity separation across
  planes.
- **Owner-to-be-named**: platform/infrastructure owner.
- **Exit criteria**: distinct node pools, network policies, and identities
  exist per plane (control / solver / verifier / evidence); an adversarial
  test proves a compromised plane cannot reach another plane's network
  surface, not just its storage credentials.
- **`p00-acceptance.tsv` gate**: no dedicated row exists. Closest mapping
  is again the umbrella `P00-NAMED-APPROVALS` gate (`external_required`,
  due `hosted-production`), which requires named operations sign-off
  before any hosted-production claim, including a plane-separation claim.

## 5. Hermetic fixture acquisition pipeline (ADR-020 hermetic half)

- **Current state**: partially built, explicitly not hermetic. P10 pinned
  and locally qualified the CVE-Bench fixture. P16 added
  `crates/adapters/advisory-intake-osv` with an `HttpFetchPort` trait,
  destination allowlisting, same-origin-only redirect handling, byte-limit
  checks, DNS-rebinding defense, and a fixed retry policy — but, per the
  P16 commit message, **no real HTTP transport is wired**: only the port,
  a scripted fake transport used in tests, and the SSRF-defense logic
  exist today. A live `reqwest`-backed adapter was left as "a documented
  follow-up rather than shipping an untested network path." This is
  narrower than `p12-p20-prompt-plan.md`'s original assumption that P16
  would deliver live acquisition end-to-end.
- **What P12–P19 built toward it**: the `HttpFetchPort` abstraction and its
  SSRF/DNS-rebinding defenses are directly reusable by a future hermetic
  pipeline once a real transport is wired behind them; P07/P10's raw-bytes
  -vs-canonical-bytes quarantine split is already the pattern P16 reused
  for the live-vs-fixture provenance distinction.
- **License ledger cross-reference**: the plan originally called for a
  standalone license ledger in this document. It is **already tracked** and
  is not duplicated here: `p00-acceptance.tsv`'s `P00-FIXTURE-LEGAL` row
  (`external_required`, due `P10`, evidence path
  `.evidence/p00/fixture-license-approval.md`) requires "License ledger
  notices redistribution decision named legal-security reviewers reviewed
  pins and approval date" for the fixture and any non-Rust adapter
  dependency. That evidence file does not exist yet (`.evidence/p00/` is
  empty in this workspace) — the gate is correctly open, not silently
  satisfied.
- **Owner-to-be-named**: the legal/security reviewers already required by
  `P00-FIXTURE-LEGAL`/`P00-FIXTURE-QUALIFICATION`, plus an engineering
  owner to wire the real (non-fake) transport behind `HttpFetchPort` once
  those approvals land.
- **Exit criteria**: `P00-FIXTURE-LEGAL` approved; `P00-FIXTURE-QUALIFICATION`
  approved (ten fresh network-denied qualification runs); a real transport
  wired behind the existing SSRF/DNS-rebinding defenses; network-denied
  CVE-Bench acquisition and an SBOM/scanning gate added in front of the
  pinned, content-addressed bundle.
- **`p00-acceptance.tsv` gates**: `P00-FIXTURE-LEGAL` and
  `P00-FIXTURE-QUALIFICATION` (both `external_required`, due `P10`) —
  already tracked; cross-referenced here, not re-invented.

## 6. Real SCM installation and GitHub delivery validation (ADR-025)

- **Current state**: the review-only delivery policy, local fake connector,
  capability-restricted GitHub adapter, Git Data candidate transfer, durable
  review checkpoints, PostgreSQL External Actions adapter, exact-request
  idempotency, leased/backed-off ambiguity reconciliation, grant
  expiry/constraints, global plus installation kill switches, executable
  production command composition, immutable review plans/resume, generation
  fencing, command verification, visible feedback, typed receipts, stable-
  correlation desired-state PATCH, and locked crash-replay-safe checkout
  publication are implemented. GitHub adapter tests use scripted HTTP, and
  live database tests are gated by `CAUTERIZER_TEST_ADAPTER_POSTGRES_URL`.
  No real GitHub App credential or repository is configured, and no test has
  created a GitHub issue, branch, commit, or pull request.
- **Implemented evidence**: see
  [`adr-025-implementation.md`](adr-025-implementation.md). Local tests cover
  one review chain after visible repair, command verification, issue-only hidden
  failure, Git Data translation, durable immutable checkpoints and resume,
  generation fencing, checkout locking/crash replay, forbidden
  capabilities, replay/concurrency, redaction, tenant/installation mismatch,
  expiration, resource constraints, kill switches, and fail-closed ambiguous
  lookup.
- **Owner-to-be-named**: repository administrator for a disposable validation
  organization plus an independent security reviewer of the GitHub App
  permissions and credential boundary.
- **Exit criteria**: provision a least-privilege GitHub App; run crash/timeout,
  duplicate webhook, eventual-consistency, stale-head, concurrent-maintainer,
  revocation, and kill-switch scenarios against a disposable repository;
  prove that merge, administration, release, package, deployment, and
  protected-branch operations are unavailable to the credential itself.
- **Acceptance implication**: until that exercise and named review complete,
  ADR-025 remains `proposed` and the repository may claim a local/adapter
  implementation, not validated autonomous GitHub delivery.

## What this document is not

It is not an ADR, not an approval, and not a schedule commitment. It does
not mark any of the six items above complete, partially-accepted, or
"good enough for now." Each remains blocked on real infrastructure, a named
external approver, or both, exactly as `p12-p20-prompt-plan.md` originally
scoped — this document's only job is to record, precisely and after the
fact, what P12–P20 actually built toward each one and what is still
missing.
