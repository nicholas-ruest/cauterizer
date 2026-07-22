# Bounded Context: Evidence

## Purpose and ownership

Construct, finalize, sign, and verify a scoped claim over exact run inputs, observations, policy, and verdict. It owns evidence schema versions, manifest completeness, artifact binding, signature metadata, and supersession lineage.

It does not rerun tests, calculate a remediation verdict, expand a verdict's meaning, or grant external-action authority.

## Aggregate

### `EvidenceBundle`

Identity: `EvidenceBundleId`; final identity also binds the canonical manifest digest.

Invariants:

- Every decision-relevant subject and material is content-addressed.
- A bundle references one sealed run record and one finalized assessment.
- The manifest verdict exactly matches Verification's published assessment.
- Required artifacts resolve and match their digests before finalization/signing.
- Redacted or omitted material is declared with classification and reason; omission cannot hide a required policy input.
- Signing identity is distinct from solver, worker, orchestrator, and approver authority.
- Finalized bundles are immutable; correction creates a new bundle with an explicit supersedes link.
- Unsigned bundles are labeled `untrusted-development` and are never represented as authenticated.

Repository: `EvidenceBundleRepository`.

## Value objects

- `InTotoStatement`, `CauterizerPredicate`, `PredicateVersion`
- `ArtifactSubject`, `MaterialDescriptor`, `BuilderIdentity`
- `RedactionManifest`, `OmissionDeclaration`
- `SignatureEnvelope`, `SignerIdentity`, `VerificationResult`
- `BundleLineage`, `ClaimScope`

## Domain services and policies

- `ManifestAssemblyService`: builds the canonical predicate from published inputs.
- `EvidenceCompletenessPolicy`: checks required artifact classes and digests.
- `BundleSigningPolicy`: determines whether a manifest is eligible for signing.
- `OfflineVerificationService`: validates schema, hashes, signature, lineage, and claim scope.

## Commands and queries

- `OpenEvidenceBundle`, `AttachPublishedArtifact`, `DeclareRedaction`
- `FinalizeEvidenceBundle`, `SignEvidenceBundle`, `SupersedeEvidenceBundle`
- `GetEvidenceBundle`, `VerifyEvidenceBundle`, `ExplainClaimScope`

## Domain events

- `EvidenceBundleOpened`, `EvidenceArtifactAttached`
- `EvidenceBundleFinalized`, `EvidenceBundleSigned`
- `EvidenceBundleVerificationFailed`, `EvidenceBundleSuperseded`

All events carry `EvidenceBundleId`; signing events carry signer and manifest digests, never private key material.

## Published language

Publishes an in-toto Statement v1-compatible envelope with a versioned Cauterizer predicate and offline verification result. SLSA terms are used only where their semantics apply; no SLSA level is claimed by format adoption alone.

## Optional analysis evidence

ruDevolution/ruvector witness output may be referenced as an analysis artifact with its tool/source version and digest. It supports traceability of that transformation, not patch correctness or vulnerability closure.
