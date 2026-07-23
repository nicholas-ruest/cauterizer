# P00 Decision Record

Status: complete for implementation; empirical acceptance gates remain phase-bound  
Date: 2026-07-22  
Accountable project decider: Nick Ruest, repository owner  

## Decision

P00 authorizes implementation under the selections in [platform-decisions.md](platform-decisions.md), the ownership and lifecycle rules in [data-and-key-inventory.md](data-and-key-inventory.md), the trust contract in [data-flow-and-trust-boundaries.md](data-flow-and-trust-boundaries.md), and the release tests in [abuse-case-test-matrix.md](abuse-case-test-matrix.md).

The first executable edition is an organization-scoped, local/offline, export-only system. Rust 2024 owns the trusted core. PostgreSQL is the transactional system of record; artifacts use an S3-compatible port with MinIO for local integration; canonical external JSON uses RFC 8785 JCS and tagged SHA-256; local evidence uses an explicitly untrusted Ed25519 development signer. Rootless Podman is always non-conformant. A hosted deployment may claim conformance only after qualification of its exact dedicated Kubernetes/gVisor execution profile and solver/verifier separation.

The initial fixture is CVE-Bench `CVE-2022-29217`, benchmark commit `47abc2b2b522f4d8afd07296d2a35042d8639f1d`, targeting PyJWT base `24b29adfebcb4f057a3cef5aaf35653bc0c1c8cc`. These repository and dataset pins were verified before selection. Qualification and redistribution approval are deliberately not inferred from selection.

No authority exists to scan a live target, submit a report, mutate a ticket, merge, publish, release, or deploy. The only MVP external action is a one-use, human-authorized, redacted local dry-run export bound to an exact authenticated evidence digest.

## Bounded empirical gates

| Gate | Owner | Exit criteria | Due before |
|---|---|---|---|
| Rust architecture and supply-chain baseline | Platform engineering | Reproducible workspace, architecture tests, lockfile, dependency/license/advisory gates, SBOM and pinned CI | P01 completion |
| Canonicalization and schema semantics | Evidence engineering and security review | Cross-platform golden vectors, malformed-input rejection, compatibility classification | P02 completion |
| Tenant authorization | Identity/security engineering | Deny-by-default decision tables and cross-organization negative/property tests | P03 completion |
| Storage, deletion, and event recovery | Data/platform engineering | Atomic outbox, inbox replay, artifact quarantine/commit, corruption, tombstone, backup and reconciliation tests | P04 and P18 completion |
| Fixture license and deterministic qualification | Verification engineering plus legal/security approval | License ledger and ten fresh base-FAIL/gold-PASS runs with no-op/bad controls and no evaluation network | P10 completion |
| Local sandbox enforcement | Platform security | All local adversarial probes pass, receipts remain `non-conformant-local`, and TCB/residual risks are recorded | P09 completion |
| Hosted sandbox and conformance firewall | Platform and verification security | AC-004 through AC-015 and AC-030 pass on the exact backend; independent topology/data-flow review | Before any hosted conformant release |
| Evidence predicate and trust policy | Evidence/security engineering | Predicate schema, complete tamper vectors, signing-time/current revocation behavior, offline verification | P13 completion |
| Reliability and production objectives | Operations/product owners | Load/soak/chaos/restore measurements establish SLO/RPO/RTO proposals and rollback evidence | P18 and P20 completion |
| Hosted privacy, key, and residual-risk acceptance | Named privacy/legal/security/operations owners | Approved retention/residency, KMS/HSM lifecycle, deletion/restore drills, signed residual-risk register | Before hosted production acceptance |

Failure of a gate blocks its dependent phase or forces truthful `Inconclusive`, `NonConformant`, or `untrusted-development` labeling. No downstream feature may relabel missing evidence.

## ADR status policy

ADR-001 through ADR-024 remain `proposed` at P00. Their implementation direction is sufficiently explicit to begin P01, but acceptance requires the named empirical proof and accountable reviewers identified above and in the ADR acceptance audit. A later phase changes status only when its evidence exists; no bulk or ceremonial acceptance is permitted.

## P00 evidence

- [ADR acceptance audit](adr-acceptance-audit.md)
- [Platform decision baseline](platform-decisions.md)
- [Data, secret, and key inventory](data-and-key-inventory.md)
- [Data flow and trust boundaries](data-flow-and-trust-boundaries.md)
- [Abuse-case test matrix](abuse-case-test-matrix.md)
- [Security threat-model scaffold](security-threat-model.md)
- [DDD context map](../ddd/context-map.md)

These artifacts satisfy P00's decision baseline. They are specifications and bounded spike commitments, not evidence that later implementation or production qualification has already passed.

## Machine-verifiable acceptance state

[`p00-acceptance.tsv`](p00-acceptance.tsv) is the canonical gate registry. It
separates repository-present baseline decisions from evidence that requires named external
reviewers or execution on an exact external environment.

```text
scripts/ci/verify-p00-acceptance.sh baseline
scripts/ci/verify-p00-acceptance.sh external-ready
```

The baseline command must pass in CI. The external-ready command must fail until every
external evidence record exists and contains an approved decision, named reviewers,
reviewed repository revision, and evidence digests. Supplying those records does not
silently accept an ADR; ADR status changes require a separately reviewed amendment.
