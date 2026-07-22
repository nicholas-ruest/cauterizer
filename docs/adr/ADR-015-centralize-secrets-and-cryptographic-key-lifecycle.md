# ADR-015: Centralize Secrets and Cryptographic Key Lifecycle

- **Status**: proposed
- **Date**: 2026-07-22
- **Deciders**:
- **Tags**: secrets, kms, signing, cryptography

## Context

Connectors need credentials and Evidence needs signing authority. Files, environment-wide secrets, or long-lived shared keys would allow workers or orchestration to impersonate privileged components.

## Decision

Store secrets only in an approved secret manager; store signing/envelope master keys in KMS/HSM-backed services. Applications receive short-lived workload identity and request scoped operations, not raw master keys. Connector secrets are tenant-scoped, versioned, rotatable, and never returned after creation. Workers receive only narrowly scoped ephemeral tokens when unavoidable; verifier jobs normally receive no external secret.

Define generation, import, activation, rotation, overlap, revocation, compromise, destruction, and audit states. Signing includes key ID and certificate/identity chain. Verification uses time-aware trust policy and revocation data. Secret values are excluded from logs, metrics, traces, events, errors, evidence, support bundles, and model prompts.

## Consequences

### Positive
- Limits credential exposure and supports rotation and non-repudiation.
- Separates signing from orchestration and execution.

### Negative
- KMS/secret-manager outages affect privileged operations.
- Key recovery and regional residency need careful procedures.

### Neutral
- Local development uses explicitly non-production keys and marks bundles untrusted.

## Links

- Depends on [ADR-007](ADR-007-emit-in-toto-compatible-evidence-bundles.md)
- Depends on [ADR-010](ADR-010-enforce-tenant-isolation-and-zero-trust-authorization.md)
