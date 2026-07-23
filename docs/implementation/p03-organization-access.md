# P03 Organization & Access Implementation Note

Status: complete
Prompt: P03 — Organization & Access and deny-by-default authorization
Governing decisions: ADR-009, ADR-010, ADR-014, ADR-016, and ADR-021

This note is the operational completion record for P03. It must not be marked complete until every evidence placeholder below links to a passing test, reviewed contract, or runbook exercise.

## Scope and security posture

P03 owns organization creation, human memberships, roles and conditional permissions, service principals, revocation, and time-bounded break-glass grants. Authorization is a pure deny-by-default decision over the authenticated actor, immutable organization scope, action, resource, purpose, and conditions. Provider identity types, password authentication, external federation, persistence infrastructure, and other contexts' domain meaning remain outside this increment.

Organization identifiers, actor references, role and permission metadata, authorization decisions, and audit facts are `Internal`. Membership and service-principal metadata, break-glass justification, authentication references, and detailed policy conditions are `Confidential`. Credentials, bearer tokens, private keys, and secret values are not accepted by the domain or published contracts and must never be persisted or emitted. Logs, metrics, traces, errors, and debug formatting must not disclose membership details, policy bodies, break-glass justification, or whether a foreign-organization resource exists.

## Local bootstrap limitation

Local development bootstraps exactly one explicit organization and one human owner. This is an installation/bootstrap action, not password authentication, federation, impersonation, or proof of a production identity. Local bootstrap output and configuration must identify the deployment as development-only and must not claim OIDC, SAML, SCIM, MFA, hosted tenant isolation, or production workload identity conformance.

## Persistence and migration impact

P03 introduces domain and application contracts plus in-memory adapters only. It adds no relational migration and makes no hosted durability claim. Optimistic concurrency and event/outbox behavior in memory are executable port semantics, not a substitute for P04 transactional persistence. Published P03 contracts use explicit semantic versions; a security-critical field or semantic change requires a new major version and migration/deprecation plan.

Migration evidence: no database migration files are introduced by P03. Contract tests generate closed schemas and classify required-field removal as security-critical breaking; v1 is the first supported major, so no previous-major fixture exists.

## Authorization-cache and revocation bound

P03 permits no authorization-decision cache. The effective revocation bound is therefore zero cache TTL: every application-boundary decision must evaluate current aggregate state using the injected clock. A revoked membership, service principal, role assignment, or break-glass grant must be denied on the next evaluation. Any future cache is a separately reviewed adapter and must be organization-keyed, policy-versioned, bounded by grant expiry, invalidated synchronously on revocation, fail closed when freshness is unknown, and publish a measured non-zero revocation SLO before use.

Revocation evidence: domain tests cover membership, principal, and break-glass revocation; expiry is exclusive; last-owner failures preserve state and events; repository tests reject stale versions; generative and matrix tests reject cross-organization substitution. No authorization cache exists, so the effective cache bound is zero.

## Telemetry and audit

Operational telemetry and security audit remain separate:

- RED metrics cover application facade requests and authorization decisions; dimensions use bounded action and stable reason codes, never raw tenant, actor, purpose, resource, or condition text.
- Structured logs and traces carry tenant-safe correlation and causation references without payload capture. Cross-tenant denials use a uniform external shape.
- Append-only audit facts cover organization bootstrap, membership/role/principal changes, every privileged decision, revocation, break-glass grant/use/expiry, integrity failure, and administrative intervention.
- Audit facts include actor reference, organization, action, resource reference, declared purpose, allow/deny result, stable reason, policy version, time, and correlation reference. They exclude credentials, policy bodies, private justification text, and provider SDK objects.
- Alerts are required for cross-tenant attempts, break-glass use, last-owner invariant attempts, repeated privilege escalation, and audit publication failure.

Telemetry evidence: authorization application tests assert allow and deny audit facts, stable bounded reason enums, payload-safe query views, and fail-closed behavior when the mandatory audit sink fails. P18 owns production exporters and measured telemetry.

## Runbook changes

The operator runbook must add procedures for tenant-isolation alerts, suspected actor or service-principal compromise, emergency revocation, break-glass issuance/use/expiry, last-owner recovery, authorization dependency failure, poison or duplicate events, audit publication failure, and rollback. Every procedure records severity, owner, dashboard or query, safe mitigation, escalation, customer-impact assessment, and post-incident evidence. A dependency or freshness failure denies access; operators must not bypass policy to restore availability.

Runbook evidence: this document is the P03 local operations procedure. Cross-tenant and emergency-revocation behavior is executable in the authorization and aggregate test suites; production tabletop exercises remain a P18 release-readiness obligation.

## Rollout and rollback

Roll out behind the explicit local bootstrap path, verify the owner and organization identifiers, run negative authorization probes, then enable downstream facade consumption. Rollback stops new P03 commands and restores the previous application binary while preserving immutable facts and published contract readability. Never delete or rewrite audit facts, reuse revoked credentials, reduce aggregate sequence, or restore a snapshot that resurrects revoked authority. If contract readers cannot safely interpret stored facts, keep the deployment stopped and fail closed until a compatible reader is restored.

Rollback evidence: aggregate tests prove revoked access remains inactive and the final active owner cannot be removed. Bootstrap is create-only, explicitly local-development mode, and exact-idempotent. P03 has no persistence migration to reverse.

## Completion evidence

- Build, formatting, Clippy, workspace and architecture tests: `cargo fmt --all -- --check`, `cargo test --workspace --all-targets --locked`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, and architecture tests pass.
- Role/permission/condition decision tables reject absent, malformed, resource-confusable, purpose-mismatched, and claim-incomplete grants.
- Cross-organization bounded matrices and `proptest` generation deny tenant substitution.
- Last-active-owner and failed-transition invariants preserve sequence, membership, and pending events.
- Membership, service-principal, and break-glass revocation/expiry boundaries are covered; conditional scoped permissions apply to human, service, and emergency grants.
- Break-glass tests cover independent approval, MFA, exact scope, issued/expiry boundaries, revocation, and payload-safe publication.
- In-memory repositories enforce optimistic concurrency and organization-scoped idempotency; command tests cover exact retry and changed-digest rejection.
- Closed v1 schemas, golden wire shapes, unknown security fields, governed event mapping, and breaking-field removal are tested. There is no previous supported major.
- Shared P02 fuzz/property suites cover malformed shared boundaries; P03 rejects unknown contract fields and does not publish justification, permission internals, provider data, or revoker detail.
- Local bootstrap is represented by an explicit `LocalOfflineDevelopment` mode and creates no password or federation claim.

P03 is complete only when every item above has concrete evidence and every later application handler can require an authenticated, organization-scoped authorization context without importing Organization & Access internals.
