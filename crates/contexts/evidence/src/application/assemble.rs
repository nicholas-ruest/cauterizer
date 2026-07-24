//! Assemble-and-sign bundle handler.
//!
//! The handler never accepts a caller-supplied signature: it always derives
//! one from the injected [`SignerPort`], so nothing that flows through this
//! module can fabricate a signature's `trust_label`. Combine that with the
//! fact that the only [`SignerPort`] implementations anywhere in this
//! workspace (`UntrustedDevelopmentSigner`, `UntrustedDevelopmentKeyLifecycle`
//! in `cauterizer_infrastructure::crypto`) hardcode the label
//! `"untrusted-development"`, and no bundle this handler produces can ever
//! claim to be anything else.

use crate::domain::bundle::{
    ArtifactDigestOracle, EvidenceBundle, EvidenceMaterial, EvidencePredicateBody,
    EvidenceScope, EvidenceStatement, EvidenceSubject, RecordedVerdict, predicate_schema_name,
    predicate_schema_version,
};
use cauterizer_infrastructure::crypto::{KeyLifecycleError, SignerPort};
use cauterizer_syntax::canonical_json::{CanonicalJsonError, canonicalize};
use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
use cauterizer_syntax::schema::SchemaEnvelope;
use std::fmt;

/// Complete, immutable input to one bundle assembly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssembleBundleRequest {
    /// Owning tenant.
    pub organization_id: OrganizationId,
    /// Remediation Runs run this bundle finalizes evidence for.
    pub run_id: ContextQualifiedId,
    /// Immutable reference to the Verification assessment being attested.
    pub assessment_ref: ContextQualifiedId,
    /// Verbatim recorded verdict.
    pub verdict: RecordedVerdict,
    /// Attested subject artifacts. Must be non-empty.
    pub subjects: Vec<EvidenceSubject>,
    /// Supporting material artifacts.
    pub materials: Vec<EvidenceMaterial>,
    /// Signing key identity passed through to the injected [`SignerPort`].
    pub signing_key_id: ContextQualifiedId,
}

/// Stable, fail-closed bundle assembly failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AssembleError {
    /// A bundle must attest to at least one subject artifact.
    NoSubjects,
    /// A subject digest did not resolve through the injected oracle.
    UnresolvedSubjectArtifact,
    /// A material digest did not resolve through the injected oracle.
    UnresolvedMaterialArtifact,
    /// The statement could not be canonicalized.
    Canonicalization,
    /// The injected signer rejected the signing request.
    Signing(KeyLifecycleError),
}

impl fmt::Display for AssembleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSubjects => formatter.write_str("bundle must attest at least one subject"),
            Self::UnresolvedSubjectArtifact => {
                formatter.write_str("referenced subject artifact could not be confirmed")
            }
            Self::UnresolvedMaterialArtifact => {
                formatter.write_str("referenced material artifact could not be confirmed")
            }
            Self::Canonicalization => formatter.write_str("statement could not be canonicalized"),
            Self::Signing(error) => write!(formatter, "signing failed: {error}"),
        }
    }
}
impl std::error::Error for AssembleError {}

impl From<CanonicalJsonError> for AssembleError {
    fn from(_: CanonicalJsonError) -> Self {
        Self::Canonicalization
    }
}

/// Assembles and signs one evidence bundle.
///
/// Every referenced subject and material digest is confirmed through `oracle`
/// before any signature is requested, so a missing or digest-mismatched
/// artifact fails closed without ever invoking the signer or constructing a
/// partial bundle. Calling this twice with an equal `request` (same
/// organization, run, assessment, verdict, subjects, materials, and signing
/// key) against the same `signer` produces bit-identical canonical statement
/// bytes and a bit-identical signature both times, because statement
/// construction and JCS canonicalization are pure functions of `request` and
/// Ed25519 signing is deterministic for a fixed key and message.
///
/// # Errors
///
/// Returns [`AssembleError::NoSubjects`] for an empty subject list,
/// [`AssembleError::UnresolvedSubjectArtifact`] or
/// [`AssembleError::UnresolvedMaterialArtifact`] when `oracle` cannot confirm
/// a referenced digest, and [`AssembleError::Signing`] when the injected
/// [`SignerPort`] rejects the request (unknown, revoked, destroyed, or
/// out-of-window key).
pub fn assemble_bundle(
    request: AssembleBundleRequest,
    oracle: &impl ArtifactDigestOracle,
    signer: &impl SignerPort,
) -> Result<EvidenceBundle, AssembleError> {
    if request.subjects.is_empty() {
        return Err(AssembleError::NoSubjects);
    }
    for subject in &request.subjects {
        if !oracle.exists(subject.digest) {
            return Err(AssembleError::UnresolvedSubjectArtifact);
        }
    }
    for material in &request.materials {
        if !oracle.exists(material.digest) {
            return Err(AssembleError::UnresolvedMaterialArtifact);
        }
    }

    let predicate = SchemaEnvelope::new(
        predicate_schema_name(),
        predicate_schema_version(),
        EvidencePredicateBody {
            verdict: request.verdict,
            assessment_ref: request.assessment_ref,
            scope: EvidenceScope {
                organization_id: request.organization_id,
                run_id: request.run_id,
            },
            materials: request.materials,
        },
    );
    let statement = EvidenceStatement::new(request.subjects, predicate);
    let canonical = canonicalize(&statement)?;
    let signature = signer
        .sign(&request.signing_key_id, &canonical)
        .map_err(AssembleError::Signing)?;
    Ok(EvidenceBundle {
        statement,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cauterizer_infrastructure::crypto::{
        GenerateKeyRequest, KeyLifecycleClock, KeyLifecyclePort, TrustDomain,
        UntrustedDevelopmentKeyLifecycle,
    };
    use cauterizer_syntax::digest::Sha256Digest;
    use cauterizer_syntax::time::UtcInstant;
    use std::collections::HashSet;
    use std::sync::Mutex;

    struct FixedClock(Mutex<UtcInstant>);
    impl FixedClock {
        fn at(instant: &str) -> Self {
            Self(Mutex::new(UtcInstant::parse(instant).unwrap()))
        }
    }
    impl KeyLifecycleClock for FixedClock {
        fn now(&self) -> UtcInstant {
            self.0.lock().unwrap().clone()
        }
    }

    struct SetOracle(HashSet<Sha256Digest>);
    impl ArtifactDigestOracle for SetOracle {
        fn exists(&self, digest: Sha256Digest) -> bool {
            self.0.contains(&digest)
        }
    }

    fn org() -> OrganizationId {
        OrganizationId::new("00000000").unwrap()
    }
    fn id(context: &str, n: u64) -> ContextQualifiedId {
        ContextQualifiedId::new(context, &format!("{n:08}")).unwrap()
    }

    fn signer() -> (UntrustedDevelopmentKeyLifecycle<FixedClock>, ContextQualifiedId) {
        let directory = tempfile::tempdir().unwrap();
        let adapter = UntrustedDevelopmentKeyLifecycle::open_with_clock(
            directory.keep(),
            FixedClock::at("2026-01-01T00:00:00Z"),
        )
        .unwrap();
        let metadata = adapter
            .generate(GenerateKeyRequest {
                trust_domain: TrustDomain::new("evidence-bundle-signer"),
                not_before: UtcInstant::parse("2026-01-01T00:00:00Z").unwrap(),
                expires_at: UtcInstant::parse("2026-06-01T00:00:00Z").unwrap(),
            })
            .unwrap();
        (adapter, metadata.key_id)
    }

    fn subject_digest() -> Sha256Digest {
        Sha256Digest::of_bytes(b"patch-bytes")
    }
    fn material_digest() -> Sha256Digest {
        Sha256Digest::of_bytes(b"baseline-bytes")
    }

    fn oracle() -> SetOracle {
        SetOracle(HashSet::from([subject_digest(), material_digest()]))
    }

    fn request(signing_key_id: ContextQualifiedId) -> AssembleBundleRequest {
        AssembleBundleRequest {
            organization_id: org(),
            run_id: id("run", 1),
            assessment_ref: id("assessment", 1),
            verdict: RecordedVerdict::VerifiedForFixture,
            subjects: vec![EvidenceSubject {
                name: "candidate-patch".into(),
                digest: subject_digest(),
            }],
            materials: vec![EvidenceMaterial {
                name: "baseline-observation".into(),
                digest: material_digest(),
            }],
            signing_key_id,
        }
    }

    #[test]
    fn assembles_a_bundle_labeled_untrusted_development() {
        let (signer, key_id) = signer();
        let bundle = assemble_bundle(request(key_id), &oracle(), &signer).unwrap();
        assert_eq!(bundle.signature.trust_label, "untrusted-development");
        signer
            .verify(&canonicalize(&bundle.statement).unwrap(), &bundle.signature)
            .unwrap();
    }

    #[test]
    fn repeated_assembly_of_the_same_request_is_bit_identical() {
        let (signer, key_id) = signer();
        let first = assemble_bundle(request(key_id.clone()), &oracle(), &signer).unwrap();
        let second = assemble_bundle(request(key_id), &oracle(), &signer).unwrap();
        assert_eq!(
            canonicalize(&first.statement).unwrap(),
            canonicalize(&second.statement).unwrap()
        );
        assert_eq!(first.signature.signature, second.signature.signature);
    }

    #[test]
    fn empty_subjects_fail_closed_without_touching_the_signer() {
        let (signer, key_id) = signer();
        let mut bad = request(key_id);
        bad.subjects.clear();
        assert_eq!(
            assemble_bundle(bad, &oracle(), &signer),
            Err(AssembleError::NoSubjects)
        );
    }

    #[test]
    fn unresolved_subject_digest_fails_closed_without_signing() {
        let (signer, key_id) = signer();
        let mut bad = request(key_id);
        bad.subjects[0].digest = Sha256Digest::of_bytes(b"never-committed");
        assert_eq!(
            assemble_bundle(bad, &oracle(), &signer),
            Err(AssembleError::UnresolvedSubjectArtifact)
        );
    }

    #[test]
    fn unresolved_material_digest_fails_closed_without_signing() {
        let (signer, key_id) = signer();
        let mut bad = request(key_id);
        bad.materials[0].digest = Sha256Digest::of_bytes(b"never-committed");
        assert_eq!(
            assemble_bundle(bad, &oracle(), &signer),
            Err(AssembleError::UnresolvedMaterialArtifact)
        );
    }

    #[test]
    fn unknown_signing_key_fails_closed_with_the_signer_reason() {
        let (signer, _) = signer();
        let unknown_key = ContextQualifiedId::new("signing-key", "unknown0").unwrap();
        assert_eq!(
            assemble_bundle(request(unknown_key), &oracle(), &signer),
            Err(AssembleError::Signing(KeyLifecycleError::UnknownKey))
        );
    }
}
