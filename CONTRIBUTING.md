# Contributing to Cauterizer

Cauterizer is a security-sensitive Rust workspace. Changes must preserve organization isolation, deterministic verification, immutable evidence, and the solver/verifier information-flow boundary.

## Development workflow

1. Read the governing ADRs and the complete DDD package for the bounded context being changed.
2. Keep domain behavior in its owning context. Add cross-context behavior through an application facade or a versioned contract.
3. Add tests for successful behavior, denial/failure paths, retries, tenant boundaries, classification/redaction, and compatibility as relevant.
4. Run formatting, Clippy with warnings denied, the full test suite, architecture tests, dependency/license/advisory checks, and documentation/schema drift checks before review.
5. Record migration, telemetry, runbook, security/privacy classification, rollout, and rollback effects in the change.

Use the exact pinned Rust toolchain and commit `Cargo.lock`. Prefer Rust 2024 throughout the trusted core. A non-Rust adapter must sit behind a Rust-owned port, be pinned, and document why Rust was impractical.

## Architecture requirements

The enforceable rules are documented in [Architecture Rules](docs/development/architecture-rules.md). Package manifests should declare:

```toml
[package.metadata.cauterizer]
layer = "domain" # domain, application, infrastructure, contracts, shared, or binary
context = "remediation-runs" # omit only for context-neutral mechanism crates
```

Domain crates depend only on their own domain code and approved syntax/mechanism crates. They must not depend on runtimes, databases, HTTP clients/servers, queues, cloud SDKs, or another context's internals. Contracts contain serialized public shapes, never domain entities or upstream SDK types.

Unsafe Rust is forbidden by default. Do not locally suppress `unsafe_code`. A necessary exception requires a dedicated minimal crate, a written safety invariant and threat analysis, tests (including Miri/fuzzing where applicable), security-owner review, and an explicit amendment to the architecture checker before code is merged.

## Security expectations

- Never commit secrets, credentials, private source, hidden verifier assets, raw prompts, or unredacted sensitive logs.
- Treat repositories, advisories, patches, builds, tests, fixtures, and model output as untrusted input.
- Do not give solver-visible code access to verifier stores, identities, caches, telemetry, result events, timing, or retry details.
- Do not add authority to scan live targets, mutate tickets, submit reports, merge, publish, release, or deploy. The MVP permits only a human-gated dry-run/export.
- Findings must fail closed. Never weaken a verdict, authorization rule, or conformance gate to make a test pass.

## Review and commits

Keep increments reviewable and link them to their implementation prompt, ADRs, DDD context/use case, and verification evidence. Generated or agent-authored code passes the same review and release gates as human-authored code. Do not bypass protected-branch or signing policy.

