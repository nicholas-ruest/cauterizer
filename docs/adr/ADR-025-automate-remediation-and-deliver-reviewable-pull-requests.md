# ADR-025: Automate Remediation and Deliver Reviewable Pull Requests

- **Status**: proposed
- **Date**: 2026-08-07
- **Deciders**:
- **Tags**: autonomy, remediation, scm, issues, pull-requests, authority
- **Supersedes**: [ADR-001](ADR-001-bound-the-mvp-to-an-offline-human-gated-loop.md)

## Context

The original MVP stopped after producing an export for a human decision. That
boundary preserves safety, but it does not deliver the product objective: an
agent that resolves an admitted vulnerability and presents the resulting code
change where maintainers already review work.

Requiring human authorization for every issue or pull request turns the agent
into a report generator. Conversely, allowing it to merge, publish, release,
deploy, or mutate production would combine code generation with irreversible
authority. The useful boundary lies between autonomous preparation of a
reviewable change and human-controlled integration of that change.

An iterative coding agent needs ordinary build and test feedback. It must not
receive hidden verifier inputs, observations, reason details, timing, retry
behavior, or verdicts that would let it optimize against the grading oracle.

## Decision

Cauterizer is an automated vulnerability-remediation system that may, within a
pre-authorized repository scope:

- ingest an advisory or repository security finding;
- qualify the affected immutable target revision;
- reproduce the declared vulnerable behavior in isolated execution;
- generate, apply, build, test, inspect, and revise candidate patches within a
  bounded attempt, time, compute, and cost budget;
- independently verify a finalized candidate behind the solver/verifier
  firewall;
- create and update a deduplicated issue;
- create a remediation branch, push commits to that branch, and create or
  update a pull request for human review; and
- post a redacted verification and evidence summary to the issue or pull
  request.

Cauterizer must not:

- merge or approve a pull request;
- push to a protected or default branch;
- force-push or rewrite human-authored history;
- publish a package or artifact as a release;
- create a release, deploy, or mutate a production environment;
- close a vulnerability as remediated solely because a pull request exists;
- weaken branch protection, required checks, review rules, or repository
  security settings; or
- give the solver access to hidden verifier material or verifier-derived
  adaptive feedback.

Human review is required for integration of the proposed change, not for each
agent step that prepares the issue and pull request.

## Authority model

Repository issue and pull-request delivery uses an installation-time grant from
an authorized repository or organization administrator. The grant is a
revocable, expiring, least-privilege policy object and includes:

- exact organization and repository identities;
- permitted actions and destination host;
- remediation branch prefix and prohibition on protected/default branches;
- permitted issue labels and pull-request metadata;
- path allow/deny rules and maximum patch size;
- maximum attempts, elapsed time, compute, and spend;
- credential identity and expiry; and
- required evidence and verification policy versions.

Every external action re-evaluates the grant against the exact repository,
run, candidate digest, action, destination, and current policy. Missing,
expired, revoked, mismatched, or ambiguous authority denies the action.
Credentials are held by Integration Management facilities and are exposed only
to the capability-bound connector, never to the solver or sandbox.

## Agentic repair loop

One remediation run may contain multiple immutable proposal attempts. The
solver may receive its declared brief plus bounded feedback from solver-visible
operations such as patch application, compilation, linting, public tests, and
policy checks. Each attempt records input digests, model/provider and tool
provenance, usage, output patch, visible observations, and supersession.

The independent verifier runs only after a candidate is finalized. Its hidden
fixtures, tests, raw observations, reason detail, timing, and retry state never
flow back into the same run's solver. A failed hidden assessment terminates the
conformant run or requires a new run under an explicitly versioned disclosure
policy; it is not adaptive solver feedback.

The loop terminates deterministically on verified candidate, attempt/budget
exhaustion, cancellation, non-conformance, terminal infrastructure failure, or
an unrecoverable scope violation.

## Delivery semantics

SCM actions are durable, idempotent External Actions performed through a
capability-bound Integration Management connector. Stable identities bind one
advisory, repository, target revision, and remediation lineage so retries do
not create duplicate issues, branches, or pull requests.

At minimum, the action vocabulary is:

- `CreateOrUpdateRemediationIssue`;
- `CreateRemediationBranch`;
- `PushCandidateCommit`;
- `CreateOrUpdateRemediationPullRequest`; and
- `PostRemediationEvidenceSummary`.

Receipts record the request digest, installation/grant identity, remote object
identity, remote revision when applicable, result, timestamp, and correlation
lineage. Partial delivery is reconciled by reading remote state through the
connector before retrying. A newer verified candidate updates the existing
pull request when safe; it does not silently create a competing pull request.

Issue and pull-request text must distinguish `VerifiedForFixture`, `Rejected`,
`Inconclusive`, and `NonConformant`. A created pull request is a proposed
remediation, not proof that the vulnerability is resolved or deployed.

## Security and operational controls

- A global and per-installation kill switch prevents new external writes and
  stops queued writes before connector invocation.
- Repository credentials cannot merge, administer repositories, manage branch
  protection, publish releases, or access repositories outside the grant.
- Candidate commits identify machine authorship and link the immutable run and
  evidence digest without embedding secrets, hidden tests, or restricted logs.
- External text and metadata pass a versioned redaction and injection-safety
  policy before delivery.
- Connector responses and repository content are untrusted input.
- Audit failure, uncertainty about remote state, or authorization failure
  fails closed and never triggers a broader retry.
- Maintainer commits on the remediation branch are not overwritten. The agent
  stops or creates a new explicitly linked candidate according to policy.

## Consequences

### Positive

- Delivers concrete fixes in the normal human review workflow.
- Removes per-run approval as a bottleneck without granting integration or
  deployment authority.
- Keeps deterministic verification independent from probabilistic generation.
- Makes retries and remote side effects auditable and deduplicated.

### Negative

- SCM credentials and outbound writes enlarge the trusted and operational
  surface.
- Iterative generation increases compute cost and requires explicit budgets.
- Repository races, contributor workflows, and provider outages require
  reconciliation rather than simple retries.
- A verified fixture-specific patch still requires maintainer judgment.

### Neutral

- Automatic merging may be considered only by a separate future ADR and is not
  implied by this decision.
- Maintainers may require additional CI, reviewers, or policy checks before
  merge.
- Issue-only delivery remains valid when no candidate reaches the configured
  verification threshold.

## Required implementation evidence before acceptance

Implementation status is tracked without changing this ADR's `proposed`
status. Detailed requirement-to-code evidence and external gates are in
[`adr-025-implementation.md`](../architecture/adr-025-implementation.md).

| Required evidence | Current status | Repository evidence | Remaining gate |
|---|---|---|---|
| Exactly one issue and pull request after retry | Executable production command, immutable durable review plan/resume, typed receipts, and stable-correlation create-or-update delivery implemented | `persisted_plan_resumes_after_checkpoint_without_replaying_prior_action`; Review Delivery restart/conflict/supersession and generation-fencing tests; External Actions replay/concurrency tests; GitHub desired-state PATCH tests | Repeat the crash/retry campaign with real GitHub credentials and provider faults |
| Visible repair feedback without hidden-verifier leakage | Implemented in the executable command using separate visible-command and sealed-verifier adapters | Worker end-to-end tests, command verifier tests, and Remediation Runs agentic orchestration | Hosted sandbox/verifier execution remains unvalidated |
| Forbidden SCM permissions | Implemented in domain and local connector policy | `dangerous_capabilities_can_never_be_granted`; worker wrong-installation/tenant/expiry tests | Validate the least-privilege GitHub App permission set against GitHub |
| Revocation and kill switches | Implemented in memory and PostgreSQL paths | `kill_switch_prevents_remote_call`; environment-gated PostgreSQL persistence test | Run live PostgreSQL test in CI and exercise a real installation |
| Ambiguous remote-state reconciliation | Durable scheduler and provider-neutral/GitHub reconciliation implemented | ambiguity/no-match tests; lease/backoff/fencing/exhaustion tests; GitHub fresh-connector recovery tests | GitHub timeout-before-response and concurrent-maintainer-edit exercises |
| Redaction and injection safety | Implemented for bounded requests, debug output, and provider references | `request_rejects_likely_secret_material`; `debug_output_redacts_provider_text_and_references` | Provider-specific adversarial review against real GitHub rendering and responses |
| Budgets, scope, and duplicate prevention | Implemented at the delivery boundary | `mutation_attestation_is_required_and_every_limit_is_inclusive`; substitution, concurrent-insert, and terminal-regression tests | End-to-end hosted budget/cancellation/provider-outage campaign |
| Named product/security approval | Not complete | None claimed | Named deciders must review the authority schema and forbidden-action matrix |

- An end-to-end fixture run creates exactly one issue and one pull request,
  including after crash/retry injection.
- A visible-test repair loop improves a candidate without exposing any hidden
  verifier data or side channel.
- Negative permission tests prove the connector cannot merge, push protected
  branches, change repository settings, publish, release, or deploy.
- Revocation and kill-switch tests stop queued and subsequent external writes.
- Remote-state reconciliation covers timeout-before-response,
  success-before-local-commit, concurrent maintainer edits, and stale target
  revision.
- Redaction tests prevent secrets, prompts, hidden test identifiers, raw logs,
  and restricted source material from entering issues, commits, or pull-request
  text.
- Budget, cancellation, duplicate advisory, superseding candidate, and
  provider-outage tests terminate with stable outcomes.
- Named product and security deciders approve the installation-time authority
  schema and forbidden-action matrix.

## Links

- Extends [ADR-003](ADR-003-use-immutable-snapshots-and-an-append-only-run-lifecycle.md)
- Preserves [ADR-005](ADR-005-enforce-a-solver-grader-conformance-firewall.md)
- Uses [ADR-006](ADR-006-make-remediation-verdicts-deterministic-and-evidence-based.md)
- Extends [ADR-008](ADR-008-integrate-upstream-tools-through-replaceable-adapters.md)
- Uses [ADR-010](ADR-010-enforce-tenant-isolation-and-zero-trust-authorization.md)
- Uses [ADR-012](ADR-012-use-versioned-events-with-transactional-outbox-and-inbox.md)
- Extends [ADR-024](ADR-024-govern-integrations-plugins-and-webhooks.md)
- [External Actions context](../ddd/contexts/external-actions.md)
