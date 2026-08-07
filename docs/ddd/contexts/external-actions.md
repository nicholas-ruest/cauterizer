# Bounded Context: External Actions

## Purpose and ownership

Authorize, execute, reconcile, and receipt bounded effects outside Cauterizer.
For automated remediation this context may create or update repository issues,
remediation branches, candidate commits, pull requests, and redacted evidence
summaries under an installation-time grant.

It does not alter advisories, runs, patches, assessments, or evidence. It cannot
merge or approve pull requests, push protected/default branches, administer a
repository, publish, release, deploy, or mutate production.

## Aggregates

### `ExternalActionGrant`

Identity: `ExternalActionGrantId`; scoped to one organization, connector
installation, destination, repository set, capability set, and authorization
period.

Invariants:

- A repository or organization administrator establishes the grant when the
  integration is installed; an agent cannot create or widen its own grant.
- Scope includes exact repositories, permitted action types, destination host,
  remediation branch prefix, path rules, budgets, issue/PR metadata policy,
  issue time, and expiry.
- Missing, expired, revoked, destination-mismatched, repository-mismatched, or
  capability-mismatched authority denies the action.
- Merge, approval, protected/default-branch push, force-push, repository
  administration, publication, release, and deployment are not grantable
  action types.
- Grant evaluation happens for every attempted external effect, including
  retries and reconciliation.
- A global or installation kill switch denies queued and new writes.

Repository: `ExternalActionGrantRepository`.

### `ExternalActionDelivery`

Identity: `ExternalActionDeliveryId`; deterministically bound to one
organization, remediation lineage, repository, action type, request digest,
and intended remote object.

Invariants:

- Delivery requires a currently valid `ExternalActionGrant` and an eligible
  immutable run/candidate/evidence reference for the requested action.
- Exact retries return or reconcile the prior result; the same identity with a
  different request digest is a conflict.
- Remote state is read and reconciled after ambiguous outcomes before another
  mutation is attempted.
- One advisory/repository/remediation lineage maps to one active issue and one
  active pull request unless an explicit supersession policy says otherwise.
- Maintainer-authored commits and remote metadata are never overwritten
  blindly.
- External text is generated through versioned redaction and injection-safety
  policies and contains no undeclared sensitive or verifier-hidden material.
- A pull request describes a proposed remediation. It does not change the
  verification verdict or claim that the change was merged or deployed.

Repository: `ExternalActionDeliveryRepository`.

## Value objects

- `InstallationAuthority`, `RepositoryScope`, `CapabilitySet`
- `ActionType`, `ActionScope`, `DestinationClass`, `AuthorizationPeriod`
- `BranchPolicy`, `PathPolicy`, `MetadataPolicy`, `ActionBudget`
- `RemoteObjectIdentity`, `RemoteRevision`, `DeliveryRequestDigest`
- `RedactionDecision`, `ReconciliationDecision`, `DeliveryReceipt`
- `RevocationReason`, `KillSwitchState`

## Domain services and policies

- `ExternalActionAuthorizationPolicy`: evaluates installation authority,
  tenant, destination, repository, capability, candidate, evidence, expiry,
  budget, and kill-switch state.
- `EvidenceEligibilityPolicy`: selects which verdict/evidence state is required
  for each action. Issue creation may report failure; candidate commit and PR
  delivery require the configured candidate policy.
- `DeliveryIdentityPolicy`: deterministically derives issue, branch, and pull
  request identity for idempotency and deduplication.
- `ExternalContentPolicy`: derives redacted, injection-safe issue/PR/commit
  content.
- `RemoteReconciliationPolicy`: resolves timeout, crash, stale revision, and
  concurrent-maintainer outcomes without duplicating or overwriting work.

## Commands and queries

- `GrantExternalActions`, `RevokeExternalActions`, `SetExternalActionKillSwitch`
- `CreateOrUpdateRemediationIssue`
- `CreateRemediationBranch`
- `PushCandidateCommit`
- `CreateOrUpdateRemediationPullRequest`
- `PostRemediationEvidenceSummary`
- `ReconcileExternalActionDelivery`
- `GetExternalActionGrant`, `ExplainExternalActionDecision`,
  `GetExternalActionDelivery`

## Domain events

- `ExternalActionsGranted`, `ExternalActionsRevoked`,
  `ExternalActionKillSwitchChanged`
- `ExternalActionRequested`, `ExternalActionAuthorized`,
  `ExternalActionDenied`
- `RemediationIssueDelivered`, `RemediationBranchCreated`,
  `CandidateCommitPushed`, `RemediationPullRequestDelivered`,
  `EvidenceSummaryPosted`
- `ExternalActionDeliveryUncertain`, `ExternalActionDeliveryReconciled`,
  `ExternalActionFailed`

All events carry organization, installation, repository, action, request
digest, correlation/causation lineage, and classification. Successful delivery
events carry the stable remote identity and remote revision when applicable;
they never carry connector secrets or Restricted payloads.

## Published language

Publishes coarse authorization decisions and delivery receipts. Connector
credentials, provider response bodies, private source, prompts, hidden verifier
material, and sensitive evidence payloads remain access-controlled.

## Human boundary

Humans configure or revoke installation authority and review the resulting pull
request. Cauterizer stops before approval, merge, publication, release, or
deployment. Adding any of those actions requires a separate ADR; they cannot be
inferred from connector installation, a verified verdict, or this context's
existence.

## Governing decisions

- [ADR-010](../../adr/ADR-010-enforce-tenant-isolation-and-zero-trust-authorization.md)
- [ADR-012](../../adr/ADR-012-use-versioned-events-with-transactional-outbox-and-inbox.md)
- [ADR-024](../../adr/ADR-024-govern-integrations-plugins-and-webhooks.md)
- [ADR-025](../../adr/ADR-025-automate-remediation-and-deliver-reviewable-pull-requests.md)
