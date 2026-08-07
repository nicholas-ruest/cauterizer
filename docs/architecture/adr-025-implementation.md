# ADR-025 implementation evidence

This document maps the proposed [ADR-025](../adr/ADR-025-automate-remediation-and-deliver-reviewable-pull-requests.md)
to code and tests as of 2026-08-07. It records implementation evidence; it
does not accept the ADR or substitute local fakes for hosted validation.

## Implemented paths

| ADR requirement | Implementation | Test evidence | Status |
|---|---|---|---|
| Permanently forbid merge, protected-branch force-push, publish, release, deploy, and repository administration | `ActionCapability::is_permitted` and fail-closed grant construction in `crates/contexts/external-actions/src/domain.rs` | `dangerous_capabilities_can_never_be_granted` | Implemented locally |
| Installation-time repository authority, revocation, expiry, branch prefix, and capability scope | `ExternalActionGrant`, `GrantConstraints`, `authorizes_request`, PostgreSQL grant persistence/revocation | `expiry_and_branch_prefix_fail_closed`; environment-gated adapter persistence test | Implemented; live database run is environment-gated |
| Path-policy result, candidate identity, patch size, changed lines, attempts, elapsed time, compute, and spend | Digested `DeliveryAttestation`, exact numeric measurements, and fail-closed mutation defaults | `mutation_attestation_is_required_and_every_limit_is_inclusive`; worker delivery-digest binding test | Implemented at delivery admission |
| Issue-only reporting when no verified candidate exists | Worker review flow creates the issue before checking for a verified outcome | `hidden_failure_creates_issue_but_no_branch_commit_or_pull_request` | Implemented with fake SCM connector |
| Iterative visible-feedback repair followed by independent decision | Executable worker command composes the Remediation Runs loop, solver-visible command evaluator, diagnostics feedback, and independent command verifier | `retries_visible_failure_then_delivers_complete_review_chain_exactly_once`; command-verifier and visible-evaluator tests | Implemented locally; hosted isolation remains external |
| Issue, remediation branch, candidate commit, pull request, and evidence-summary delivery | Production command constructs an immutable `ReviewDeliveryPlan`, persists it, resumes the next incomplete stage, and executes through durable External Actions and `ScmGateway` | `persisted_plan_resumes_after_checkpoint_without_replaying_prior_action`; complete-review-chain and typed-receipt tests | Implemented and command-wired; real GitHub credentials unvalidated |
| GitHub issue/PR and Git Data translation | `crates/adapters/integration-management-github` transfers blobs/trees/commits, advances only the remediation ref, and uses stable ownership plus exact state markers to PATCH an existing issue/PR | `transfers_git_objects_then_advances_only_remediation_ref`; `fresh_connector_updates_owned_issue_without_duplicate_post`; `fresh_connector_updates_owned_pull_request_and_validates_head`; ambiguity tests | Implemented and contract-tested with scripted HTTP; real credentials unvalidated |
| Exact candidate bytes reach SCM without giving the solver connector access | Production command uses `FilesystemCandidateArtifacts`, `RepairCandidateAdapter`, `PublishingVisibleEvaluator`, and digest-bound `GitCommitTransfer`; checkout publication is locked and deterministic across crash replay | artifact restart/substitution/exact-bytes tests; `publish_reuses_exact_deterministic_candidate_after_preplan_crash`; `concurrent_publishers_have_one_winner_and_leave_checkout_clean` | Implemented and command-wired |
| Hidden verifier result remains behind a sealed bridge | Production command constructs `CommandVerificationStore` behind `HiddenAssessmentAdapter`/`RepairHiddenVerifier`; only the coarse decision returns to orchestration | command-verifier adapter tests plus verifier-context tests | Implemented locally; hosted verifier isolation unvalidated |
| Durable exact-request idempotency | Memory repository plus `crates/adapters/external-actions-postgres`; unique tenant/key constraint and full request comparison | replay, substitution-conflict, concurrent-insert, and environment-gated PostgreSQL replay tests | Implemented |
| Crash/timeout ambiguity must reconcile before retry | `DeliveryStatus::Unknown`; durable capped backoff, atomic leases, fencing, exhaustion/manual review, and remote lookup before retry | ambiguity/no-match tests; deterministic backoff test; environment-gated concurrent claim, lease recovery, stale fencing, and exhaustion test | Implemented scheduler; hosted provider timing unvalidated |
| Partial issue-to-PR progress survives restart | Immutable `ReviewDeliveryPlan`, stage checkpoints with typed remote identity, production resume loop, PostgreSQL repository, active-run lookup, and generation lease/fencing | `persisted_plan_resumes_after_checkpoint_without_replaying_prior_action`; `checkpoints_restart_replay_and_supersession`; out-of-order/substitution/concurrency test; `active_lookup_and_generation_fencing_when_configured`; environment-gated PostgreSQL restart test | Implemented and command-wired; live database run is environment-gated |
| Global and per-installation emergency stops | Fail-closed memory switch; tenant-global and installation-keyed PostgreSQL switches checked immediately before mutation | `kill_switch_prevents_remote_call`; environment-gated cross-instance persistence test | Implemented |
| Terminal delivery state cannot regress | Memory and PostgreSQL lifecycle guards; PostgreSQL row locks and monotonic attempt checks | `terminal_delivery_cannot_be_regressed_or_substituted` | Implemented |
| Tenant isolation | Organization participates in every grant/delivery key; forced PostgreSQL RLS uses transaction-local `app.organization_id` | worker wrong-tenant test; environment-gated PostgreSQL cross-instance test | Implemented; hosted role configuration unvalidated |
| Secret-safe diagnostics and untrusted provider responses | Custom redacted `Debug`, bounded request validation, secret-marker rejection, and sanitized remote references | request-secret and debug-redaction tests | Implemented locally |
| Durable recovery queries | Adapter-owned migration `1006_external_actions.sql`, unique indexes, and partial recovery/enabled-grant indexes | Adapter compile/test suite | Implemented |
| Coarse operator control without SCM authority | Transport-neutral remediation trigger/status/cancel/reconcile handlers and CLI parser | exact retry/conflict, tenant status, cancel replay, reconcile permission, and forbidden CLI verb tests | Implemented control surface; no bound HTTP server |

## External validation gates

The following are not demonstrated by this repository alone:

- A real GitHub App installation with least-privilege credentials has not been
  provisioned or exercised. A production `ReqwestTransport` and GitHub
  anti-corruption adapter and executable production command exist, but provider
  contract tests use scripted HTTP.
- GitHub-specific eventual consistency, timeout-before-response behavior,
  concurrent maintainer edits, stale branch heads, and credential revocation
  have not been tested against GitHub. The local model deliberately keeps an
  unmatched ambiguous delivery in `Unknown`.
- The PostgreSQL integration tests require
  `CAUTERIZER_TEST_ADAPTER_POSTGRES_URL`; ordinary local runs skip live database
  assertions when it is absent.
- The repair/verifier composition is local and deterministic. It has not run
  against a hosted gVisor-or-stronger sandbox or a production model provider.
- KMS/HSM evidence signing, hosted plane separation, production SLO/DR, and
  named product/security approvals remain open in the
  [production-readiness track](production-readiness-track.md).

## Reproduction commands

```bash
cargo test -p cauterizer-external-actions --all-targets
cargo test -p cauterizer-external-actions-postgres --all-targets
cargo test -p cauterizer-worker --all-targets
cargo test -p cauterizer-integration-management-github --all-targets
cargo test -p cauterizer-remediation-runs-postgres --all-targets
cargo clippy -p cauterizer-external-actions -p cauterizer-external-actions-postgres -p cauterizer-worker --all-targets -- -D warnings
```

Set `CAUTERIZER_TEST_ADAPTER_POSTGRES_URL` to a disposable PostgreSQL database
to execute the live adapter cases. These commands provide implementation
evidence only; they do not satisfy the external gates above.
