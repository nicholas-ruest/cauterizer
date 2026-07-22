# Evidence: Domain Model

## Aggregate root

`EvidenceBundle` is the sole aggregate root and is persisted through domain port `EvidenceBundleRepository`. State is private; behavior validates invariants before emitting immutable events. Cross-context objects are represented only by IDs and digests.

## Invariants

- `All decision-relevant material is digest-bound`
- `Bundle matches one sealed run and finalized assessment`
- `Required artifacts resolve before signing`
- `Final bundles are immutable`
- `Unsigned bundles are explicitly untrusted`

## Value objects

- `EvidenceBundleId`
- `InTotoStatement`
- `CauterizerPredicate`
- `ArtifactSubject`
- `RedactionManifest`
- `SignatureEnvelope`
- `ClaimScope`

## Domain services and policies

- `ManifestAssemblyService`
- `EvidenceCompletenessPolicy`
- `BundleSigningPolicy`
- `OfflineVerificationService`

## Repository contract

`EvidenceBundleRepository` supports load-by-tenant-and-ID, optimistic concurrency, atomic aggregate/event-outbox persistence, and invariant existence checks. Read projections serve queries.

## Domain constraints

- No infrastructure, SDK, framework, network, clock, random, or storage dependencies.
- IDs, clocks, and policy inputs enter explicitly.
- Events include tenant, aggregate ID/type, sequence, schema version, event ID, time, correlation, and causation.
- Sensitive values never default-stringify.

