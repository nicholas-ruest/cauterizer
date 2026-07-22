# Bounded Context: External Actions

## Purpose and ownership

Record a human's narrowly scoped authorization over an eligible evidence bundle and produce a redacted dry-run/export artifact. It owns approval semantics, authorization expiry/revocation, export policy, and export receipts.

It does not alter advisories, runs, patches, assessments, or evidence; it does not submit, merge, release, or deploy in the MVP.

## Aggregate

### `ActionAuthorization`

Identity: `ActionAuthorizationId`; scoped to one action type, evidence digest, destination class, and actor.

Invariants:

- Authorization requires an authenticated human actor; an agent or service cannot impersonate approval.
- The referenced evidence bundle must be finalized, authenticated under policy, and eligible for the requested action.
- Scope includes exact action, subject/evidence digest, destination class, issue time, and expiry.
- Missing, expired, revoked, destination-mismatched, or digest-mismatched authorization denies the action.
- Approval cannot override a `Rejected`, `Inconclusive`, or `NonConformant` verdict.
- One authorization cannot be widened or reused for a different bundle/action.
- Export content is generated through a versioned redaction policy and contains no undeclared sensitive material.
- MVP action type is limited to `CreateDryRunExport`.

Repository: `ActionAuthorizationRepository`.

## Value objects

- `HumanActor`, `ActionType`, `ActionScope`, `DestinationClass`
- `ApprovalIntent`, `AuthorizationPeriod`, `RevocationReason`
- `ExportPolicyRef`, `RedactionDecision`, `ExportArtifactRef`
- `AuthorizationReceipt`, `DryRunExportReceipt`

## Domain services and policies

- `EvidenceEligibilityPolicy`: validates bundle status, verdict, signature, and claim scope.
- `AuthorizationPolicy`: validates human identity, scope, intent, expiry, and revocation.
- `ExportRedactionPolicy`: deterministically derives allowed export fields.

## Commands and queries

- `RequestActionAuthorization`, `GrantActionAuthorization`, `RevokeActionAuthorization`
- `CreateDryRunExport`
- `GetAuthorization`, `ExplainAuthorizationDecision`, `GetExportReceipt`

## Domain events

- `ActionAuthorizationRequested`, `ActionAuthorizationGranted`
- `ActionAuthorizationDenied`, `ActionAuthorizationRevoked`
- `DryRunExportCreated`, `DryRunExportFailed`

All events carry `ActionAuthorizationId`; grant and export events carry the exact evidence digest and actor identifier.

## Published language

Publishes authorization status and redacted export receipts. Private approval evidence and sensitive bundle payloads remain access-controlled.

## Future boundary

Adding ticket creation, HackerOne submission, patch merge, release, or deployment requires a new action type only after a dedicated ADR defines destination verification, least-privilege credentials, two-person or equivalent controls, rollback/revocation, and audit obligations. Those capabilities must not be inferred from this context's existence.
