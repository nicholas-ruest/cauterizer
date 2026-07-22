# Data, Secret, and Cryptographic Key Inventory

Status: implementation baseline; privacy, legal, security, and service owners must approve before hosted production  
Date: 2026-07-22  
Governing decisions: ADR-003, ADR-005, ADR-007, ADR-010 through ADR-016, ADR-020, and ADR-024  

This inventory supplies the field/artifact-level policy required by ADR-011 and the custody model required by ADR-015. It applies to all eleven bounded contexts. “Payload retention” never means authority to retain a secret in an event, log, metric, trace, model prompt, support bundle, or evidence statement.

## Policy conventions

- Classes, from least to most restrictive: `Public`, `Internal`, `Confidential`, `RestrictedSecurity`.
- Every stored record binds `OrganizationId` unless it is an explicitly public catalog/schema record.
- All network links use TLS 1.3 where supported and authenticated workload identity in hosted deployments. Stored Confidential and Restricted Security payloads use envelope encryption; Restricted Security uses a separate tenant/access-domain data-encryption key.
- Region is the organization's configured residency region. Cross-region movement is denied unless policy explicitly permits it and the descriptor records source, destination, purpose, and authorization.
- Retention starts when a run becomes terminal unless the row says otherwise. Legal hold suspends deletion; it never widens readers.
- Logs contain bounded identifiers, reason codes, sizes, and durations. Payloads, source fragments, patches, prompts, tests, tokens, credentials, and raw URLs with credentials are forbidden.

## Data inventory

| Owner / data set | Representative fields or artifacts | Class | System of record / access domains | Default retention and deletion | Export / telemetry |
|---|---|---|---|---|---|
| Organization & Access: organization, membership, role and policy | organization ID/name, actor reference, role, conditional permission, revocation, break-glass fact | Internal; actor contact/IdP subject Confidential | PostgreSQL; tenant policy role; restricted operator JIT role | active life + 7 years for authorization/audit facts; erase contact/profile 30 days after removal where law permits | actor IDs pseudonymized in telemetry; no IdP tokens/claims payload |
| Commercial Entitlements | plan/grant, reservation, immutable usage, credit, settlement | Internal; provider customer reference Confidential | PostgreSQL; tenant commercial role | financial/usage facts 7 years; transient reservation detail 400 days | minimal rated usage only; no payment-card data |
| Asset Portfolio | repository/package locator, ownership, environment, scope, immutable target revision | Confidential; public repository metadata may be Public | PostgreSQL plus public source artifact domain | active life + 400 days; source bundle per run rules | redact credentials, private hostnames and paths; no raw locator in general telemetry |
| Integration Management | connector type, capabilities, destination, installation, webhook receipt | Internal/Confidential; connector secret Restricted Security | PostgreSQL descriptor + secret manager; connector-specific identity | installation facts 400 days after removal; secrets destroyed within 24 hours after revocation; webhook payload 30 days | destination/capability allowed in audit; payload and secret never logged |
| Advisory Intake: canonical public snapshot | advisory text, aliases, ranges, severity, provenance digest | Public when source is public; otherwise Confidential | PostgreSQL descriptor + canonical artifact store | public: superseded + 365 days; private: terminal run + 90 days unless evidence-required | public export allowed; private text excluded from telemetry |
| Advisory Intake: raw/private report and exploit material | raw record, reporter/PII, embargo data, proof-of-concept | Restricted Security | quarantine then intake-restricted artifact domain with tenant key | 30 days after terminal run; PII minimized at ingestion; cryptographic erasure | never default export/model/support/telemetry; explicit restricted review only |
| Remediation Runs | immutable input refs, lifecycle events, budgets, policy refs, correlation/causation IDs | Internal; linkage to private assets Confidential | PostgreSQL aggregate/event/outbox/projection | lifecycle and minimum audit 7 years; rebuildable projections may be purged/rebuilt | reason/status codes only; no artifact payload |
| Isolated Execution: request/lease/receipt | environment/capability/resource envelope, identity, times, exit/resource facts, cleanup outcome | Internal/Confidential | PostgreSQL + class-specific queue/inbox | 400 days; worker credentials expire at terminal state | bounded metrics permitted; command args/env redacted |
| Isolated Execution: stdout/stderr/core/temp output | bounded execution output and generated files | Confidential; exploit/hidden/secret-bearing output Restricted Security | class-specific artifact store; core dumps disabled | Confidential 30 days; Restricted Security 7 days unless evidence-required; scratch destroyed on every terminal path | no payload telemetry; export only after redaction policy |
| Patch Proposals: solver brief | approved problem/source/test instructions and budgets | Confidential, or Public only if every component is public | solver-public artifact domain | terminal run + 90 days; evidence-bound copy 400 days | provider receives only approved fields; telemetry contains sizes/counts |
| Patch Proposals: candidate/rationale/provider metadata | unified diff, bounded provenance, provider/model/config/cost | Confidential | solver output domain, then immutable candidate descriptor | terminal run + 90 days; finalized evidence inputs 400 days | patch/rationale never logged; no chain-of-thought retained |
| Verification: hidden test, gold patch, oracle/control | hidden security test, gold diff, qualification controls and internal names | Restricted Security | verifier-hidden artifact domain, separate key/identity/store | qualified fixture life + 180 days after retirement; immediate replacement on suspected leakage | never solver/model/default export; public evidence exposes digests and declared omissions only |
| Verification: observations and assessment | test inventory/results, timing, logs, conformance facts, policy verdict/reasons | Confidential; hidden detail Restricted Security | verifier-only artifacts + PostgreSQL assessment; published coarse contract separately | detailed observations 180 days; finalized assessment/audit 7 years | solver gets nothing; evidence includes only policy-approved bounded observations |
| Evidence: manifest/predicate/signature | input/artifact digests, commands, coarse observations, verdict/reasons, omissions, signer metadata | Internal/Confidential according to referenced subject; signature/public schema Public | evidence artifact domain + PostgreSQL descriptor | finalized manifest, signature, and minimum verification material 7 years; referenced payload follows stricter applicable rule and omission declaration | only redacted bundle export; no claim broadening |
| External Actions: Approval Grant and receipt | human actor, auth event, intent, evidence digest, action/destination, validity, nonce, revocation/use | Confidential; audit status Internal | PostgreSQL, tenant authorization role | 7 years | redacted receipt may export; intent/contact excluded from telemetry |
| External Actions: dry-run export | redacted eligible evidence representation | Confidential unless every included field is explicitly Public | local destination selected by human; descriptor/receipt in PostgreSQL | generated file is user-custodied; Cauterizer staging deleted within 24 hours | no automatic transmission; export manifest declares omissions/redactions |
| Event delivery and dead letters | versioned event envelope, IDs, tenant, producer, payload | class of payload, minimum Internal | PostgreSQL outbox/inbox/dead letter; hosted NATS transport | successful transport 30 days; inbox dedupe 400 days; dead letter 30 days then explicit resolution | payload not logged; counts/lag/reason codes allowed |
| Idempotency results | tenant, actor, command/action, key hash, request hash, result ref | Internal/Confidential | PostgreSQL | 400 days or owning aggregate retention, whichever is longer | key material never logged; collision/conflict reason code allowed |
| Operational audit | authorization decision, privileged access, configuration/key/retention/action changes | Internal; support/break-glass detail Confidential | append-only audit store | 7 years | SIEM export is schema-bounded and tenant/purpose authorized |
| Metrics/traces/logs | service/operation, pseudonymous tenant/actor, status, reason, latency, resource counts | Internal | audit-safe observability platform | metrics 400 days; traces 30 days; logs 90 days; security audit remains 7 years | sampling never bypasses payload prohibition; tenant-safe support views |
| Backups and recovery copies | encrypted PostgreSQL/object metadata/payload snapshots | inherits highest contained class | separate backup identity/account and keys | rolling 35 days; deletion manifests verified after expiry | no direct analyst access or lower-environment restoration |

## Secrets inventory

| Secret | Owner and permitted consumers | Storage/injection | Rotation/expiry | Explicit prohibitions |
|---|---|---|---|---|
| OIDC/SAML/SCIM client secret or private key | Organization & Access adapter only | production secret manager by tenant/installation reference | 90 days or provider maximum; immediate on compromise/removal | never domain aggregate/event, worker, evidence, model, log, or support bundle |
| Connector/API/webhook credential | Integration Management adapter for one tenant, capability, and destination | secret manager; short-lived scoped retrieval | 90 days; webhook overlap max 24 hours; revoke on uninstall | never returned after creation or shared between tenants/connectors |
| Acquisition source/registry token | acquisition broker and one job only | workload identity mints destination-bound ephemeral token | <=15 minutes and terminal-job revocation | never solver/verifier, source bundle, SBOM, command log, or cache key |
| Database credential | one service/role/plane | workload identity/dynamic secret, TLS client authentication | <=24 hours; preferably per connection/session | no shared superuser; no cross-context read privilege by default |
| Object-store credential | one service/job and access domain | workload identity, scoped pre-signed operation where needed | job token <=15 minutes; service identity continuously renewable | no list permission for job tokens; solver cannot address verifier domain |
| NATS credential | producer/consumer and exact subjects | workload identity-issued scoped credential | <=24 hours; immediate on workload revocation | no wildcard across tenant/security domains |
| Model-provider API credential | Patch Proposals provider adapter only | secret manager to outbound adapter, not worker guest | 30 days or short-lived federation; revoke on provider incident | never verifier, prompts, evidence, events, telemetry, or artifact payload |
| Local development signing seed | local Evidence signer only | OS-protected file outside repository, mode `0600` | manual yearly rotation or immediate compromise; identity is untrusted-development | never production trust root, committed fixture, environment variable dump, or shared default |
| Break-glass recovery material | split security/operations custodians | HSM/secret manager recovery workflow with quorum | exercise every 180 days; rotate after every use | no single-person retrieval; every attempt audited/customer-visible as policy requires |

## Cryptographic key inventory and lifecycle

| Key/keyset | Purpose and scope | Custody | Rotation and overlap | Revocation/destruction and verification behavior |
|---|---|---|---|---|
| Evidence signing key | sign canonical eligible evidence manifest; one trust domain/environment | production KMS/HSM signer; private key non-exportable; local Ed25519 exception marked untrusted | production 90 days, 30-day verification overlap; key ID and certificate/identity chain recorded | stop signing immediately; publish time-aware revocation; historical verification reports signing-time trust and current revocation distinctly |
| Audit checkpoint signing key | sign append-only audit/event-chain checkpoints | separate KMS/HSM identity from Evidence | 90 days with 30-day public-key overlap | preserve public verification material for audit retention; compromise triggers new checkpoint lineage and incident record |
| Tenant metadata KEK | wrap data keys for Confidential transactional fields/artifact descriptors | regional KMS, per tenant and environment | annual or policy-triggered; lazy rewrap with bounded completion SLO | disable then destroy after verified rewrap/deletion; KMS audit retained |
| Tenant solver-public DEK | encrypt approved solver-visible artifacts | generated data key wrapped by tenant KEK and solver access-domain policy | per artifact or bounded batch; batch <=30 days | destroy/tombstone on retention; never grant verifier-hidden access implicitly |
| Tenant verifier-hidden DEK | encrypt hidden tests, gold patches, oracle and sensitive observations | distinct verifier KMS context/role; not derivable by solver | per fixture/artifact or bounded batch; rotate on any suspected leakage | immediate revoke/re-encrypt; prior affected fixture becomes unqualified until requalification |
| Evidence artifact DEK | encrypt bundle payloads and verification material | Evidence access domain, wrapped by tenant KEK | per bundle preferred | deletion must preserve only declared non-sensitive tombstone/signature metadata; offline export is separately user-custodied |
| Backup encryption key | encrypt backup sets independently of online services | separate backup account KMS/HSM and recovery quorum | 90 days; restore drills validate old-key availability | destruction follows last backup expiry and legal hold; online services cannot decrypt backups directly |
| TLS/service identity key | workload authentication and transport encryption | service mesh/workload identity issuer; node-local short-lived key | <=24 hours, automated | revocation removes workload access; never reused as evidence signer or envelope key |
| Webhook signing key | authenticate one installation's outbound webhook | secret manager/KMS, tenant and installation scoped | 90 days, max 24-hour dual-sign overlap | revoke on uninstall/compromise; receiver-facing key ID/version retained with receipt |
| Idempotency-key hashing key | keyed digest when raw client idempotency values require concealment | application KMS/secret reference per environment | annual with versioned dual lookup for 400-day result window | destruction after lookup window; never use for signatures or encryption |

Key states are `Generated`, `Active`, `Retiring`, `Revoked`, `Compromised`, and `Destroyed`. Only `Active` keys sign/encrypt. Verification may use `Retiring` and historically valid `Revoked` public keys under explicit time-aware policy; a compromised key never yields an unqualified “valid” result. Every state transition records actor/workload, purpose, previous/new state, time, ticket/incident reference, affected tenants/artifacts, and completion evidence.

## Required controls and tests

- Schema review fails when a field/artifact lacks owner, class, region, retention, and export/log policy.
- Authorization tests attempt cross-tenant and cross-domain reads by opaque ID and by known digest; unauthorized and missing responses are indistinguishable.
- Redaction canary tests inject credential, token, PII, patch, and hidden-test markers and assert absence from logs, traces, metrics, errors, events, exports, model requests, and support bundles.
- Lifecycle tests cover quarantine failure, partial upload, digest mismatch, legal hold, tombstone creation, key destruction, backup expiry, restore without widening access, and deletion reconciliation.
- Rotation tests cover overlap, stale worker/service identity, signer revocation at signing time versus verification time, and verifier-hidden key compromise forcing fixture requalification.
- The inventory and actual schemas/artifact registries are compared in CI; drift blocks release rather than creating an undocumented default.

