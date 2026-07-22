# Platform Decision Baseline

Status: selected for implementation; security-sensitive selections require the qualification gates below  
Date: 2026-07-22  
Accountable project decider: Nick Ruest, repository owner  
Required hosted-production reviewers: platform engineering, security architecture, privacy/legal, and operations owners (to be named before hosted acceptance)  

This record resolves the implementation-affecting choices needed by P01 through P20 without changing the status of an ADR. It is subordinate to ADR-001 through ADR-024. A conflict is resolved in favor of the ADR until an accountable decider amends that ADR. Product code must not silently substitute another product or algorithm.

## Scope and authority

The first deployment is a single-operator, local/offline tool. Its contracts remain organization-scoped so the same trusted core can later run in a multi-tenant control plane. It may acquire an explicitly approved public source, execute a pinned public fixture, accept a manual or bounded solver patch, verify it independently, sign an evidence bundle with a development identity, and create a redacted dry-run export.

It has no authority to scan or exploit a live target, submit a report, mutate a ticket, push a branch, merge, publish, release, or deploy. Adding any such authority requires a new threat model and an ADR extending ADR-001. This decision implements the boundaries owned by the Remediation Runs, Isolated Execution, Patch Proposals, Verification, Evidence, and External Actions contexts; no one context inherits another's authority.

## Selected platform

| Concern | Selection | Binding constraints and reason | Governing ADRs and DDD |
|---|---|---|---|
| Trusted runtime | Rust 2024, stable toolchain pinned by exact channel; Tokio current workspace-pinned major for async binaries | Rust owns domain policy, contracts, orchestration ports, persistence, worker supervisor, canonicalization, signing eligibility, and offline verification. `unsafe` is denied by default. Python exists only inside the pinned upstream fixture; TypeScript is reserved for browser UI or an SDK where Rust/WASM is unsuitable. | ADR-002, 008, 019, 021; implementation scaffold and all context packages |
| External encoding | UTF-8 JSON conforming to RFC 8785 JSON Canonicalization Scheme (JCS) before hashing/signing | Reject duplicate keys, non-finite numbers, invalid Unicode, and values outside each schema's bounds before canonicalization. Domain decimals and 64-bit identifiers serialize as constrained strings when JSON number interoperability is unsafe. Checked-in golden vectors are normative. | ADR-003, 007, 014, 021; Evidence and shared-kernel rules |
| Digest | SHA-256 identified as `sha256`, lowercase 64-character hexadecimal at contract boundaries | Hash bytes after the declared canonicalization; artifact digests hash original committed bytes. Domain separation prefixes apply to Merkle/event-chain nodes. No bare or algorithm-implicit digest is accepted. | ADR-003, 007, 013; Evidence and Remediation Runs |
| Signatures | Ed25519 for local development; production signing through a KMS/HSM-backed signer port with a deployment-approved algorithm and time-aware trust policy | The local key is generated per installation, stored with mode `0600`, never silently imported, and marks every bundle `untrusted-development`. Production services receive sign operations, not private keys. Signature metadata binds algorithm, key ID, trust domain, signed-at time, and canonical manifest digest. | ADR-007, 015; Evidence |
| Transactional store | PostgreSQL 17, supported minor pinned in deployment manifests | Use row-level tenant predicates as defense in depth, explicit transactions, optimistic aggregate sequence checks, transactional outbox, durable inbox uniqueness, and migration locks. SQLite is not a behavioral substitute; tests may use it only for syntax-free unit fixtures. | ADR-003, 010, 012, 013, 017; all repositories |
| Artifact store | S3-compatible object-store port; MinIO in local/integration environments and a provider's versioned, encrypted S3-compatible service in hosted deployments | Objects are quarantined, streamed through server-side size/type/hash validation, then committed under tenant/access-domain/digest identity. Bucket/prefix policy separately isolates solver-public, verifier-hidden, evidence, and quarantine material. Filesystem storage is a local development adapter and cannot claim hosted durability. | ADR-011, 013, 015, 018; Evidence, Advisory Intake, Isolated Execution |
| Event delivery | PostgreSQL transactional outbox/inbox is the system of record; a Rust dispatcher uses `FOR UPDATE SKIP LOCKED`. Hosted fan-out uses NATS JetStream behind an event transport port. | Delivery is at least once. Consumers deduplicate by producer, event ID, schema major, and aggregate sequence; ordering is guaranteed only per aggregate. JetStream acknowledgement never replaces inbox commit. Local mode needs no broker. | ADR-012, 014, 021; context map consistency model |
| Local sandbox | Rootless Podman with OCI images, no daemon socket, no host mounts, read-only root, dropped capabilities, `no-new-privileges`, seccomp, bounded tmpfs/cgroup v2 resources, sanitized environment, and network `none` for evaluation | This backend is always labeled `non-conformant-local` because a shared host kernel is not the required hosted isolation boundary. Results cannot be promoted by relabeling. | ADR-004, 018, 020, 022; Isolated Execution |
| Hosted sandbox | Kubernetes execution plane on dedicated nodes using gVisor `runsc`, separate acquisition/solver/verifier node pools, identities, namespaces, network policies, and artifact credentials | A deployment is conformant only after adversarial tests prove its exact kernel/runtime/network/storage configuration. Kata/Firecracker may be added later behind the same port after equivalent qualification; it is not the initial selection. | ADR-004, 005, 018, 020, 022; Isolated Execution and Verification |
| Secret custody | Production secret-manager references plus workload identity; envelope master and signing keys in KMS/HSM. Local mode uses explicitly development-only files outside the repository. | Connector secrets are tenant scoped and non-readable after creation. Evaluation workers normally receive no secret; unavoidable acquisition tokens are one-job, destination-bound, short-lived, and excluded from artifacts and telemetry. | ADR-010, 011, 015, 016; Organization & Access and Integration Management |

Tokio, PostgreSQL, MinIO, NATS, Podman, Kubernetes, and gVisor are infrastructure adapters, never domain vocabulary. Versions are pinned in lockfiles/deployment manifests and upgraded through compatibility, adversarial, migration, rollback, and evidence-verification gates.

## Exact initial fixture

Select CVE-Bench instance `CVE-2022-29217` against `jpadilla/pyjwt` vulnerable revision `24b29adfebcb4f057a3cef5aaf35653bc0c1c8cc`. Pin the benchmark repository at `47abc2b2b522f4d8afd07296d2a35042d8639f1d` and hash the selected dataset record, test patch, gold patch, environment recipe, resolved wheels, base image manifest, and commands independently. The repository HEAD and dataset-to-base mapping were independently verified on 2026-07-22 before this decision was recorded.

This is the preferred first fixture because it is a compact Python package, its security assertion is self-contained, it does not require a browser/database/service topology, and its public repository and benchmark harness are MIT-licensed at the selected revisions. That is a selection, not a qualification or redistribution conclusion. P10 must record the upstream source license and all transitive build/runtime licenses, retain notices, and obtain security/legal approval before distributing a source or environment bundle.

The fixture is eligible only if an amd64 Linux spike, repeated at least ten times in fresh network-denied verifier jobs, produces:

- vulnerable base plus hidden security test: ten deterministic `FAIL` observations for the intended assertion;
- gold patch plus the identical hidden test and baseline suite: ten deterministic `PASS` observations;
- no-op and intentionally bad controls: never `PASS`;
- identical normalized command, environment, dependency, observation, and policy digests across repetitions except fields explicitly declared nondeterministic;
- zero unpinned network resolution during evaluation and no hidden-artifact visibility from solver credentials.

Pin CPython and every wheel by image/content digest during the P10 acquisition spike rather than guessing those values here. If the gate fails, do not silently choose another instance. Record the failure and run a bounded selection spike over the other already validated CVE-Bench entries using the same criteria; an exact replacement requires this record to be amended.

## Data classification and retention defaults

The four authoritative classes are `Public`, `Internal`, `Confidential`, and `RestrictedSecurity`. The detailed inventory is in [data-and-key-inventory.md](data-and-key-inventory.md). Defaults apply unless a stricter tenant, legal-hold, residency, contract, or incident rule applies:

| Class | Typical Cauterizer material | Online retention | Backups | Export/log rule |
|---|---|---:|---:|---|
| Public | public advisory, public source/license metadata, public schema | active life + 365 days after supersession | 35 days | export allowed by policy; structured logs may contain identifiers, never payloads |
| Internal | aggregate/events/projections, policy versions, non-sensitive usage and operations metadata | 400 days; finalized evidence metadata 7 years | 35 days | authenticated tenant/operator use; pseudonymize actor references in telemetry |
| Confidential | candidate patch, solver brief/output, private asset metadata, approval intent, detailed logs | 90 days after run terminal; evidence-required artifacts 400 days | 35 days | explicit field authorization and redaction before export; no payload telemetry |
| Restricted Security | hidden tests/gold patches, exploit material, raw private advisories, secrets, sensitive verifier logs | 30 days after run terminal; qualified fixture controls 180 days; keys/secrets by lifecycle | 35 days encrypted under separate keys | no solver access, model prompt, general support bundle, metrics, traces, or default export |

Legal hold is an authorized, audited fact with subject, reason, issuer, issue/expiry, and scope; it suspends deletion but not access controls. Expiry creates a tombstone, destroys/deauthorizes applicable data-encryption keys, removes payloads from primary storage, and queues backup expiry. Minimum audit tombstones retain tenant, artifact class, digest, deletion policy/version, actor/service, and time but no recoverable payload or secret.

## Human approval and export semantics

Only an authenticated human organization member with `external_actions.approve_export` and any configured step-up condition may issue an Approval Grant. Service principals, workers, solvers, models, and orchestrators are categorically ineligible. The External Actions context records the grant; UI state is not authority.

A grant binds exactly: organization, human actor and authentication event, action `CreateDryRunExport`, eligible evidence-bundle digest, destination class (local file or stdout in the MVP), declared intent, redaction-policy version, issued-at, not-before, expiry, and a unique nonce/idempotency key. Default validity is 15 minutes and may be shortened, never extended after issuance. It is single-use; a successful receipt consumes it. Revocation, actor suspension, evidence supersession, policy change affecting eligibility, digest mismatch, clock uncertainty beyond 30 seconds, or any missing field denies execution.

Approval cannot change a verdict, bypass redaction, authorize a destination outside the grant, or make a `Rejected`, `Inconclusive`, or `NonConformant` assessment eligible. The MVP export is produced locally and never transmitted by Cauterizer. A new evidence digest or redaction policy requires a new grant.

## Baseline regression and flakiness policy

For the selected fixture, qualification and candidate assessment run the same pinned upstream unit-test suite declared by the acquisition recipe plus the verifier-hidden CVE test. The gold patch must pass both. Candidate acceptance requires:

1. clean application to the exact target digest with no undeclared generated/binary/file-mode changes;
2. hidden security test pass;
3. all baseline tests that passed on the vulnerable base remain passing;
4. no new failure, timeout, crash, resource-limit breach, skipped test, deselection, collection error, warning promoted by policy, or test-count reduction;
5. patch-scope and evidence-completeness policy pass.

Tests already failing on the vulnerable base are recorded and must not increase in count or change reason; they cannot be used to hide a candidate regression. Run base, gold, and candidate in fresh identical environments. Qualification uses ten repetitions; normal candidate assessment uses three. Any disagreement, nondeterministic test inventory, or normalized observation mismatch produces `Inconclusive`, never retry-to-green. A quarantined flaky test needs an owner, reason, expiry no longer than 14 days, and policy version; the hidden CVE test cannot be quarantined.

## Solver/verifier side-channel contract

The conformant information-flow rule is noninterference, not merely lack of a direct API callback.

- Solver and verifier use different workload identities, Kubernetes namespaces/node pools, service accounts, object buckets/prefixes, envelope keys, databases or database roles/schemas, queues/subjects, caches, scratch volumes, image pull credentials, and telemetry destinations.
- The solver can read only the approved solver brief, public source bundle, public build instructions, and its own bounded outputs. It cannot list or address verifier artifacts, qualification material, assessment events, verdicts, verifier logs, metrics, traces, timings, queue depth, retry count, cache keys, worker placement, or support diagnostics.
- The verifier accepts immutable candidate and public/hidden input descriptors through a one-way assessment request. It never sends test names, failures, timing, pass/fail bits, reason details, or adaptive hints to Patch Proposals. Remediation Runs receives only the finalized published assessment contract after the attempt is closed.
- No process, memory, disk layer, cache, mutable image, temporary volume, IPC namespace, network namespace, or worker instance is reused between solver and verifier job classes. Hosted nodes are dedicated by class; if unavoidable hardware sharing is introduced later, microarchitectural leakage is an explicit residual risk requiring an ADR and independent review.
- Operator telemetry is access-controlled and delayed/aggregated where necessary. Correlation IDs visible to the solver are remapped at the verifier boundary. Artifact-not-found and unauthorized responses are indistinguishable and constant-shape; sensitive comparisons are constant-time where applicable.
- Model/provider memory, prompt caching, training, and cross-request retention are disabled contractually and technically for solver calls. Provider use makes a run non-conformant unless zero-retention and tenant-isolation controls are verified.

Local Podman shares a host kernel, scheduler, and operator account and therefore cannot prove these hosted side-channel assumptions; local outcomes remain `NonConformant` regardless of functional test success.

## Decision gates and residual risks

These selections authorize implementation, not an ADR status change. Before a hosted production claim, named accountable individuals must sign the threat review, privacy/retention review, fixture qualification, cryptographic design review, sandbox adversarial report, disaster-recovery evidence, and residual-risk register.

Known residual risks include shared-hardware timing channels below gVisor, sandbox/runtime vulnerabilities, dependency compromise before acquisition scanning, local development key theft, SHA-256 metadata correlation, deletion lag in immutable backups, and a benchmark fixture's narrow representativeness. Tests must assert that these conditions cannot be relabeled away and that failure yields denial, `Inconclusive`, or `NonConformant` as appropriate.
