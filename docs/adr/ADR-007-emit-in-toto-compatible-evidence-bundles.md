# ADR-007: Emit in-toto-Compatible Evidence Bundles

- **Status**: proposed
- **Date**: 2026-07-22
- **Deciders**:
- **Tags**: evidence, attestation, in-toto, slsa

## Context

Cauterizer must let a reviewer establish which inputs, process, policy, and observations produced a verdict. A custom hash chain alone would create a proprietary verifier and could be mistaken for proof of semantic correctness. in-toto supplies a stable statement envelope, while SLSA provenance provides established vocabulary for subjects, builders, inputs, and build processes.

## Decision

Evidence emits an in-toto Statement v1-compatible envelope with a versioned Cauterizer predicate. The predicate may reuse SLSA provenance concepts where semantically accurate, but Cauterizer does not claim a SLSA level unless every requirement of that level is independently assessed.

An `EvidenceBundle` includes or references by digest:

- advisory and target snapshots;
- acquisition and execution environment identities;
- solver brief, solver configuration, and candidate patch;
- conformance declaration;
- declared commands and bounded observations;
- fixture qualification and candidate evaluation results;
- policy version, verdict, and reason codes;
- lifecycle event-chain root;
- redaction manifest and omitted-sensitive-material declarations;
- signer identity, signature, and verification instructions.

Signatures authenticate the statement producer; hashes bind exact bytes; policy and test evidence support a scoped verdict. None of these alone proves semantic equivalence or absence of other vulnerabilities. Optional ruDevolution witness data is a nested referenced artifact and never substitutes for independent verification.

Signing is a separate capability from orchestration, solving, execution, and grading. A signer signs only a complete canonical manifest whose artifact digests resolve under policy. Development bundles may be unsigned only when explicitly marked `untrusted-development`.

## Consequences

### Positive

- Enables offline and tool-independent verification.
- Uses an interoperable envelope suitable for later Sigstore/OCI integration.
- Makes claim scope and omitted material explicit.

### Negative

- Canonicalization, key lifecycle, revocation, and redaction are substantial design work.
- Bundles may be large and contain sensitive metadata even after payload separation.
- Interoperability does not remove the need for a Cauterizer predicate/verifier specification.

### Neutral

- The initial signer may be local; production key custody is deferred to the deployment threat model.
- Public transparency-log publication is not part of the MVP.

## Validation before acceptance

- Draft and review the predicate schema and verification algorithm.
- Choose canonical serialization, digest algorithms, signer model, and revocation behavior.
- Demonstrate tamper detection for every decision-relevant artifact and field.

## Links

- Depends on [ADR-003](ADR-003-use-immutable-snapshots-and-an-append-only-run-lifecycle.md)
- Depends on [ADR-006](ADR-006-make-remediation-verdicts-deterministic-and-evidence-based.md)
- [Evidence context](../ddd/contexts/evidence.md)
- [in-toto specifications](https://in-toto.io/docs/specs/)
- [SLSA v1.2](https://slsa.dev/spec/v1.2/)
