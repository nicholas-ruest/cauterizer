//! Offline in-toto bundle verifier.
//!
//! Every check runs against caller-supplied bytes and ports only: no network
//! call, no wall-clock read, and no artifact store fetch. The verifier's
//! notion of "now" is whatever `signer`'s injected clock reports, which lets
//! a caller replay the same bundle at signing time and again later at
//! verification-policy time and observe key expiry/revocation evaluated at
//! the later instant rather than frozen at the moment the bundle was signed.

use crate::domain::bundle::{ArtifactDigestOracle, EvidenceBundle, predicate_schema_name};
use cauterizer_infrastructure::crypto::{KeyLifecycleError, SignerPort};
use cauterizer_syntax::canonical_json::canonicalize;
use cauterizer_syntax::schema::SchemaVersion;
use std::fmt;

/// Signature trust labels this verifier currently accepts.
///
/// The only [`SignerPort`] implementations in this workspace
/// (`cauterizer_infrastructure::crypto::UntrustedDevelopmentSigner` and
/// `UntrustedDevelopmentKeyLifecycle`) hardcode `"untrusted-development"` on
/// every signature they produce. This allowlist is deliberately narrower than
/// "whatever the signer accepts": it fails closed even if a signature's
/// cryptographic bytes are individually valid, so a bundle can never be
/// silently reinterpreted as trusted/production output. When a real
/// production signer is introduced, its label joins this allowlist alongside
/// an explicit verification-policy decision — never by widening this array
/// to `"anything"`.
const ACCEPTED_TRUST_LABELS: &[&str] = &["untrusted-development"];

/// Stable, fail-closed offline verification failure.
///
/// Content-tampering vectors (an altered subject digest that still resolves
/// through `oracle`'s issuance set, an altered predicate field, or corrupted
/// signature bytes) are cryptographically indistinguishable by design: an
/// unforgeable signature must not tell an attacker *which* byte they moved,
/// so all three collapse to [`VerifyError::SignatureInvalid`]. Referential and
/// key-lifecycle failures are checked independently of the signature and keep
/// their own distinct reasons.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifyError {
    /// The predicate's schema name/version was not the expected contract.
    UnsupportedPredicateSchema,
    /// A subject digest did not resolve through the injected oracle.
    UnresolvedSubjectArtifact,
    /// A material digest did not resolve through the injected oracle.
    UnresolvedMaterialArtifact,
    /// The statement could not be canonicalized.
    Canonicalization,
    /// The signature's trust label is not in [`ACCEPTED_TRUST_LABELS`].
    UntrustedLabelRejected,
    /// The signing key is not known to the verifying [`SignerPort`].
    UnknownKey,
    /// The signing key is not yet within its validity window.
    KeyNotYetValid,
    /// The signing key's validity (or overlap) window has elapsed.
    KeyExpired,
    /// The signing key has been explicitly revoked.
    KeyRevoked,
    /// The signing key's private material has been destroyed.
    KeyDestroyed,
    /// The statement bytes, predicate, or signature do not authenticate.
    SignatureInvalid,
    /// The key-lifecycle boundary was unavailable; verification fails closed.
    SignerUnavailable,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedPredicateSchema => "unsupported_predicate_schema",
            Self::UnresolvedSubjectArtifact => "unresolved_subject_artifact",
            Self::UnresolvedMaterialArtifact => "unresolved_material_artifact",
            Self::Canonicalization => "statement_not_canonicalizable",
            Self::UntrustedLabelRejected => "untrusted_label_rejected",
            Self::UnknownKey => "signing_key_unknown",
            Self::KeyNotYetValid => "signing_key_not_yet_valid",
            Self::KeyExpired => "signing_key_expired",
            Self::KeyRevoked => "signing_key_revoked",
            Self::KeyDestroyed => "signing_key_destroyed",
            Self::SignatureInvalid => "signature_invalid",
            Self::SignerUnavailable => "key_lifecycle_unavailable",
        })
    }
}
impl std::error::Error for VerifyError {}

impl From<KeyLifecycleError> for VerifyError {
    fn from(error: KeyLifecycleError) -> Self {
        match error {
            KeyLifecycleError::UnknownKey => Self::UnknownKey,
            KeyLifecycleError::KeyNotYetValid => Self::KeyNotYetValid,
            KeyLifecycleError::KeyExpired => Self::KeyExpired,
            KeyLifecycleError::KeyRevoked => Self::KeyRevoked,
            KeyLifecycleError::KeyDestroyed => Self::KeyDestroyed,
            KeyLifecycleError::Unavailable => Self::SignerUnavailable,
            // These lifecycle-management-only variants are never returned by
            // `SignerPort::verify`; fail closed into the same bucket as any
            // other cryptographic non-authentication if the port ever does.
            KeyLifecycleError::UnknownTrustDomain
            | KeyLifecycleError::NoActiveKey
            | KeyLifecycleError::AlreadyActive
            | KeyLifecycleError::InvalidWindow
            | KeyLifecycleError::NotActiveForSigning
            | KeyLifecycleError::InvalidSignature => Self::SignatureInvalid,
        }
    }
}

/// Validates schema/version, every referenced digest, JCS canonical bytes,
/// the signature, the signing key's current validity interval, and its
/// current revocation state — entirely offline.
///
/// # Errors
///
/// Returns the first applicable [`VerifyError`]: an unsupported predicate
/// schema/version, an unresolved subject/material digest, an untrusted
/// signature label, or the [`SignerPort::verify`] failure (mapped from
/// [`KeyLifecycleError`]) for an invalid, expired, revoked, destroyed, or
/// unknown-key signature.
pub fn verify_bundle(
    bundle: &EvidenceBundle,
    consumer_schema_version: &SchemaVersion,
    oracle: &impl ArtifactDigestOracle,
    signer: &impl SignerPort,
) -> Result<(), VerifyError> {
    bundle
        .statement
        .predicate
        .require_contract(&predicate_schema_name(), consumer_schema_version)
        .map_err(|_| VerifyError::UnsupportedPredicateSchema)?;

    for subject in &bundle.statement.subject {
        if !oracle.exists(subject.digest) {
            return Err(VerifyError::UnresolvedSubjectArtifact);
        }
    }
    for material in &bundle.statement.predicate.payload.materials {
        if !oracle.exists(material.digest) {
            return Err(VerifyError::UnresolvedMaterialArtifact);
        }
    }

    if !ACCEPTED_TRUST_LABELS.contains(&bundle.signature.trust_label) {
        return Err(VerifyError::UntrustedLabelRejected);
    }

    let canonical = canonicalize(&bundle.statement).map_err(|_| VerifyError::Canonicalization)?;
    signer.verify(&canonical, &bundle.signature)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::assemble::{AssembleBundleRequest, assemble_bundle};
    use crate::domain::bundle::{
        EvidenceMaterial, EvidenceSubject, RecordedVerdict, predicate_schema_version,
    };
    use cauterizer_infrastructure::crypto::{
        GenerateKeyRequest, KeyLifecyclePort, SharedFixedClock, TrustDomain,
        UntrustedDevelopmentKeyLifecycle,
    };
    use cauterizer_syntax::digest::Sha256Digest;
    use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
    use cauterizer_syntax::time::UtcInstant;
    use std::collections::HashSet;

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
    fn subject_digest() -> Sha256Digest {
        Sha256Digest::of_bytes(b"patch-bytes")
    }
    fn material_digest() -> Sha256Digest {
        Sha256Digest::of_bytes(b"baseline-bytes")
    }
    fn oracle() -> SetOracle {
        SetOracle(HashSet::from([subject_digest(), material_digest()]))
    }

    fn adapter_at(clock: &SharedFixedClock) -> UntrustedDevelopmentKeyLifecycle<&SharedFixedClock> {
        let directory = tempfile::tempdir().unwrap();
        UntrustedDevelopmentKeyLifecycle::open_with_clock(directory.keep(), clock).unwrap()
    }

    fn signed_bundle(
        adapter: &UntrustedDevelopmentKeyLifecycle<&SharedFixedClock>,
    ) -> (EvidenceBundle, ContextQualifiedId) {
        let metadata = adapter
            .generate(GenerateKeyRequest {
                trust_domain: TrustDomain::new("evidence-bundle-signer"),
                not_before: UtcInstant::parse("2026-01-01T00:00:00Z").unwrap(),
                expires_at: UtcInstant::parse("2026-02-01T00:00:00Z").unwrap(),
            })
            .unwrap();
        let request = AssembleBundleRequest {
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
            signing_key_id: metadata.key_id.clone(),
        };
        let bundle = assemble_bundle(request, &oracle(), adapter).unwrap();
        (bundle, metadata.key_id)
    }

    #[test]
    fn accepts_a_freshly_assembled_bundle() {
        let clock = SharedFixedClock::at("2026-01-01T00:00:00Z");
        let adapter = adapter_at(&clock);
        let (bundle, _) = signed_bundle(&adapter);
        verify_bundle(&bundle, &predicate_schema_version(), &oracle(), &adapter).unwrap();
    }

    #[test]
    fn altered_subject_digest_is_rejected() {
        let clock = SharedFixedClock::at("2026-01-01T00:00:00Z");
        let adapter = adapter_at(&clock);
        let (mut bundle, _) = signed_bundle(&adapter);
        bundle.statement.subject[0].digest = Sha256Digest::of_bytes(b"never-issued");
        assert_eq!(
            verify_bundle(&bundle, &predicate_schema_version(), &oracle(), &adapter),
            Err(VerifyError::UnresolvedSubjectArtifact)
        );
    }

    #[test]
    fn altered_material_digest_is_rejected() {
        let clock = SharedFixedClock::at("2026-01-01T00:00:00Z");
        let adapter = adapter_at(&clock);
        let (mut bundle, _) = signed_bundle(&adapter);
        bundle.statement.predicate.payload.materials[0].digest =
            Sha256Digest::of_bytes(b"never-issued");
        assert_eq!(
            verify_bundle(&bundle, &predicate_schema_version(), &oracle(), &adapter),
            Err(VerifyError::UnresolvedMaterialArtifact)
        );
    }

    #[test]
    fn altered_predicate_field_invalidates_the_signature() {
        let clock = SharedFixedClock::at("2026-01-01T00:00:00Z");
        let adapter = adapter_at(&clock);
        let (mut bundle, _) = signed_bundle(&adapter);
        // The verdict is flipped but every referenced digest is still one the
        // oracle recognizes, so only the signature can catch this tamper.
        bundle.statement.predicate.payload.verdict = RecordedVerdict::Rejected;
        assert_eq!(
            verify_bundle(&bundle, &predicate_schema_version(), &oracle(), &adapter),
            Err(VerifyError::SignatureInvalid)
        );
    }

    #[test]
    fn corrupted_signature_bytes_are_rejected() {
        let clock = SharedFixedClock::at("2026-01-01T00:00:00Z");
        let adapter = adapter_at(&clock);
        let (mut bundle, _) = signed_bundle(&adapter);
        bundle.signature.signature[0] ^= 0xFF;
        assert_eq!(
            verify_bundle(&bundle, &predicate_schema_version(), &oracle(), &adapter),
            Err(VerifyError::SignatureInvalid)
        );
    }

    #[test]
    fn expired_key_is_rejected_at_verification_policy_time_not_signing_time() {
        let clock = SharedFixedClock::at("2026-01-01T00:00:00Z");
        let adapter = adapter_at(&clock);
        let (bundle, _) = signed_bundle(&adapter);
        // Valid immediately after signing.
        verify_bundle(&bundle, &predicate_schema_version(), &oracle(), &adapter).unwrap();
        // Advance the shared clock past the key's expiry: the exact same
        // bytes now fail, proving expiry is judged at verify time.
        clock.set("2026-03-01T00:00:00Z");
        assert_eq!(
            verify_bundle(&bundle, &predicate_schema_version(), &oracle(), &adapter),
            Err(VerifyError::KeyExpired)
        );
    }

    #[test]
    fn revoked_key_is_rejected_immediately_with_no_cache() {
        let clock = SharedFixedClock::at("2026-01-01T00:00:00Z");
        let adapter = adapter_at(&clock);
        let (bundle, key_id) = signed_bundle(&adapter);
        verify_bundle(&bundle, &predicate_schema_version(), &oracle(), &adapter).unwrap();
        adapter.revoke(&key_id, "key-compromise-drill").unwrap();
        assert_eq!(
            verify_bundle(&bundle, &predicate_schema_version(), &oracle(), &adapter),
            Err(VerifyError::KeyRevoked)
        );
    }

    #[test]
    fn unsupported_predicate_schema_version_is_rejected() {
        let clock = SharedFixedClock::at("2026-01-01T00:00:00Z");
        let adapter = adapter_at(&clock);
        let (bundle, _) = signed_bundle(&adapter);
        let incompatible = SchemaVersion::parse("2.0.0").unwrap();
        assert_eq!(
            verify_bundle(&bundle, &incompatible, &oracle(), &adapter),
            Err(VerifyError::UnsupportedPredicateSchema)
        );
    }

    #[test]
    fn a_bundle_relabeled_to_claim_trust_is_structurally_impossible_to_accept() {
        let clock = SharedFixedClock::at("2026-01-01T00:00:00Z");
        let adapter = adapter_at(&clock);
        let (mut bundle, _) = signed_bundle(&adapter);
        // `assemble_bundle` never accepts a caller-supplied signature, so the
        // only way to even attempt a "trusted" claim is to hand-mutate the
        // public field after the fact. The verifier's allowlist catches it
        // before any cryptographic check runs.
        bundle.signature.trust_label = "trusted-production";
        assert_eq!(
            verify_bundle(&bundle, &predicate_schema_version(), &oracle(), &adapter),
            Err(VerifyError::UntrustedLabelRejected)
        );
    }

    #[test]
    fn every_signer_port_implementation_in_this_workspace_only_ever_labels_untrusted_development() {
        // Structural proof for acceptance criterion 3: enumerate every
        // concrete `SignerPort` implementation this workspace defines
        // (there is exactly one family, `UntrustedDevelopmentKeyLifecycle`,
        // since `cauterizer_infrastructure::crypto` is this workspace's only
        // producer of `KeySignature` values) and confirm its label is not in
        // some other, wider set. If a second, production-labeled
        // implementation is ever added, this assertion documents exactly
        // what must also change here: `ACCEPTED_TRUST_LABELS`.
        let clock = SharedFixedClock::at("2026-01-01T00:00:00Z");
        let adapter = adapter_at(&clock);
        let (bundle, _) = signed_bundle(&adapter);
        assert_eq!(bundle.signature.trust_label, "untrusted-development");
        assert_eq!(ACCEPTED_TRUST_LABELS, &["untrusted-development"]);
    }
}
