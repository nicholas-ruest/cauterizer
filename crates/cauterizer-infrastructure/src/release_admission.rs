//! Release artifact admission verification.
//!
//! This is the sign/verify/tamper-detection *logic* a hosted release
//! pipeline's admission gate runs before treating a build as releasable. It
//! is deliberately independent of any GitHub Actions runtime: it can be
//! exercised entirely with `cargo test`, using this workspace's existing
//! [`SignerPort`] (the same port `contexts/evidence`'s bundle verifier
//! already uses). `.github/workflows/release.yml` performs the actual
//! artifact signing with GitHub's native, OIDC/Sigstore-backed build
//! provenance attestation (`actions/attest-build-provenance`) and verifies
//! it with `gh attestation verify` — neither of which this sandbox can
//! exercise, since both need a real GitHub Actions run identity. What *can*
//! be proven locally, and is proven by the tests below, is that the
//! admission check correctly rejects a manifest whose signature does not
//! authenticate the exact artifact set, and correctly rejects an artifact
//! whose bytes were swapped after the manifest was signed. A production
//! deployment would swap the local dev [`SignerPort`] used in tests for a
//! KMS/HSM-backed implementation (P12's stubbed hosted placeholder); the
//! admission algorithm itself does not change.

use crate::crypto::{KeyLifecycleError, KeySignature, SignerPort};
use cauterizer_syntax::canonical_json::canonicalize;
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::ContextQualifiedId;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt;

/// One artifact's name and content digest, bound into a release manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReleaseArtifact {
    /// Stable artifact name (for example, a binary or SBOM file name).
    pub name: String,
    /// Content digest of the artifact's exact bytes.
    pub digest: Sha256Digest,
}

/// A signed, fixed, ordered set of release artifact digests. Signing binds
/// every artifact name and digest together: an attacker cannot swap one
/// artifact, add an extra one, or drop one without invalidating the
/// signature or failing the digest comparison in [`verify_release_admission`].
#[derive(Clone, Debug)]
pub struct SignedReleaseManifest {
    /// Human-readable release identifier (for example, a version tag).
    pub release_tag: String,
    /// Every artifact admitted as part of this release.
    pub artifacts: Vec<ReleaseArtifact>,
    /// Signature over the manifest's canonical bytes.
    pub signature: KeySignature,
}

/// Stable, fail-closed release admission failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    /// A manifest with no artifacts can never be releasable.
    EmptyManifest,
    /// The observed artifact set's size does not match the manifest's.
    ArtifactCountMismatch,
    /// A manifest-listed artifact was not found among the observed set.
    ArtifactMissing(String),
    /// An observed artifact's digest does not match the signed manifest.
    ArtifactDigestMismatch(String),
    /// The manifest could not be canonicalized.
    Canonicalization,
    /// The signature does not authenticate the exact manifest bytes, or the
    /// signing key is unknown, expired, revoked, or destroyed.
    Signature(KeyLifecycleError),
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyManifest => formatter.write_str("release_manifest_empty"),
            Self::ArtifactCountMismatch => formatter.write_str("release_artifact_count_mismatch"),
            Self::ArtifactMissing(name) => {
                write!(formatter, "release_artifact_missing:{name}")
            }
            Self::ArtifactDigestMismatch(name) => {
                write!(formatter, "release_artifact_digest_mismatch:{name}")
            }
            Self::Canonicalization => formatter.write_str("release_manifest_not_canonicalizable"),
            Self::Signature(error) => write!(formatter, "release_signature_rejected:{error:?}"),
        }
    }
}
impl std::error::Error for AdmissionError {}

#[derive(Serialize)]
struct ManifestPayload<'a> {
    release_tag: &'a str,
    artifacts: &'a [ReleaseArtifact],
}

fn canonical_manifest_bytes(
    release_tag: &str,
    artifacts: &[ReleaseArtifact],
) -> Result<Vec<u8>, AdmissionError> {
    canonicalize(&ManifestPayload {
        release_tag,
        artifacts,
    })
    .map_err(|_| AdmissionError::Canonicalization)
}

/// Signs a release manifest binding `release_tag` to the exact `artifacts`
/// set. Callers pass artifact digests computed from the real bytes about to
/// be published (binaries, SBOM, checksum file); this function never reads
/// a filesystem or network path itself.
///
/// # Errors
///
/// Fails when the manifest cannot be canonicalized or the signer rejects
/// the requested key (unknown, not active, revoked, destroyed, or outside
/// its validity window).
pub fn sign_release_manifest(
    signer: &impl SignerPort,
    key_id: &ContextQualifiedId,
    release_tag: &str,
    artifacts: Vec<ReleaseArtifact>,
) -> Result<SignedReleaseManifest, AdmissionError> {
    let bytes = canonical_manifest_bytes(release_tag, &artifacts)?;
    let signature = signer
        .sign(key_id, &bytes)
        .map_err(AdmissionError::Signature)?;
    Ok(SignedReleaseManifest {
        release_tag: release_tag.to_string(),
        artifacts,
        signature,
    })
}

/// Verifies a signed release manifest against the artifact digests actually
/// observed on disk (or wherever the release job staged them), keyed by
/// artifact name. This is the admission gate: it must reject before a build
/// is treated as releasable if any artifact's bytes changed after signing,
/// any artifact is missing or unexpected, or the signature does not
/// authenticate the exact manifest.
///
/// Digest/count checks run before the cryptographic check, matching this
/// workspace's existing evidence-bundle verifier: cheap referential checks
/// fail closed first, and a signature check never needs to run against a
/// manifest that already fails structurally.
///
/// # Errors
///
/// Returns the first applicable [`AdmissionError`].
pub fn verify_release_admission(
    signer: &impl SignerPort,
    manifest: &SignedReleaseManifest,
    observed: &BTreeMap<String, Sha256Digest>,
) -> Result<(), AdmissionError> {
    if manifest.artifacts.is_empty() {
        return Err(AdmissionError::EmptyManifest);
    }
    if observed.len() != manifest.artifacts.len() {
        return Err(AdmissionError::ArtifactCountMismatch);
    }
    for artifact in &manifest.artifacts {
        match observed.get(&artifact.name) {
            None => return Err(AdmissionError::ArtifactMissing(artifact.name.clone())),
            Some(actual_digest) if *actual_digest != artifact.digest => {
                return Err(AdmissionError::ArtifactDigestMismatch(
                    artifact.name.clone(),
                ));
            }
            Some(_) => {}
        }
    }

    let bytes = canonical_manifest_bytes(&manifest.release_tag, &manifest.artifacts)?;
    signer
        .verify(&bytes, &manifest.signature)
        .map_err(AdmissionError::Signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        GenerateKeyRequest, KeyLifecyclePort, SharedFixedClock, TrustDomain,
        UntrustedDevelopmentKeyLifecycle,
    };
    use cauterizer_syntax::time::UtcInstant;

    fn adapter_at(clock: &SharedFixedClock) -> UntrustedDevelopmentKeyLifecycle<&SharedFixedClock> {
        let directory = tempfile::tempdir().unwrap();
        UntrustedDevelopmentKeyLifecycle::open_with_clock(directory.keep(), clock).unwrap()
    }

    fn active_key(
        adapter: &UntrustedDevelopmentKeyLifecycle<&SharedFixedClock>,
    ) -> ContextQualifiedId {
        adapter
            .generate(GenerateKeyRequest {
                trust_domain: TrustDomain::new("release-signer"),
                not_before: UtcInstant::parse("2026-01-01T00:00:00Z").unwrap(),
                expires_at: UtcInstant::parse("2026-02-01T00:00:00Z").unwrap(),
            })
            .unwrap()
            .key_id
    }

    fn artifacts() -> Vec<ReleaseArtifact> {
        vec![
            ReleaseArtifact {
                name: "cauterizer-cli".into(),
                digest: Sha256Digest::of_bytes(b"cli-binary-bytes-v1"),
            },
            ReleaseArtifact {
                name: "cauterizer.cdx.json".into(),
                digest: Sha256Digest::of_bytes(b"sbom-bytes-v1"),
            },
        ]
    }

    fn observed_matching(manifest: &SignedReleaseManifest) -> BTreeMap<String, Sha256Digest> {
        manifest
            .artifacts
            .iter()
            .map(|artifact| (artifact.name.clone(), artifact.digest))
            .collect()
    }

    #[test]
    fn a_freshly_signed_manifest_with_matching_artifacts_is_admitted() {
        let clock = SharedFixedClock::at("2026-01-01T00:00:00Z");
        let adapter = adapter_at(&clock);
        let key_id = active_key(&adapter);
        let manifest = sign_release_manifest(&adapter, &key_id, "v1.0.0", artifacts()).unwrap();
        let observed = observed_matching(&manifest);
        verify_release_admission(&adapter, &manifest, &observed).unwrap();
    }

    #[test]
    fn a_tampered_artifact_swapped_after_signing_is_rejected() {
        let clock = SharedFixedClock::at("2026-01-01T00:00:00Z");
        let adapter = adapter_at(&clock);
        let key_id = active_key(&adapter);
        let manifest = sign_release_manifest(&adapter, &key_id, "v1.0.0", artifacts()).unwrap();
        let mut observed = observed_matching(&manifest);
        // A "bad release" artifact: same name, different bytes than what was
        // signed (e.g. a compromised build step substituted a binary).
        observed.insert(
            "cauterizer-cli".into(),
            Sha256Digest::of_bytes(b"malicious-substituted-binary"),
        );
        assert_eq!(
            verify_release_admission(&adapter, &manifest, &observed),
            Err(AdmissionError::ArtifactDigestMismatch(
                "cauterizer-cli".into()
            ))
        );
    }

    #[test]
    fn a_missing_artifact_is_rejected() {
        let clock = SharedFixedClock::at("2026-01-01T00:00:00Z");
        let adapter = adapter_at(&clock);
        let key_id = active_key(&adapter);
        let manifest = sign_release_manifest(&adapter, &key_id, "v1.0.0", artifacts()).unwrap();
        let mut observed = observed_matching(&manifest);
        observed.remove("cauterizer.cdx.json");
        assert_eq!(
            verify_release_admission(&adapter, &manifest, &observed),
            Err(AdmissionError::ArtifactCountMismatch)
        );
    }

    #[test]
    fn an_unexpected_extra_artifact_is_rejected() {
        let clock = SharedFixedClock::at("2026-01-01T00:00:00Z");
        let adapter = adapter_at(&clock);
        let key_id = active_key(&adapter);
        let manifest = sign_release_manifest(&adapter, &key_id, "v1.0.0", artifacts()).unwrap();
        let mut observed = observed_matching(&manifest);
        observed.insert(
            "unexpected-extra-binary".into(),
            Sha256Digest::of_bytes(b"not-part-of-the-signed-release"),
        );
        assert_eq!(
            verify_release_admission(&adapter, &manifest, &observed),
            Err(AdmissionError::ArtifactCountMismatch)
        );
    }

    #[test]
    fn corrupted_signature_bytes_are_rejected() {
        let clock = SharedFixedClock::at("2026-01-01T00:00:00Z");
        let adapter = adapter_at(&clock);
        let key_id = active_key(&adapter);
        let mut manifest = sign_release_manifest(&adapter, &key_id, "v1.0.0", artifacts()).unwrap();
        manifest.signature.signature[0] ^= 0xFF;
        let observed = observed_matching(&manifest);
        assert_eq!(
            verify_release_admission(&adapter, &manifest, &observed),
            Err(AdmissionError::Signature(
                KeyLifecycleError::InvalidSignature
            ))
        );
    }

    #[test]
    fn a_manifest_field_edited_after_signing_invalidates_the_signature() {
        let clock = SharedFixedClock::at("2026-01-01T00:00:00Z");
        let adapter = adapter_at(&clock);
        let key_id = active_key(&adapter);
        let mut manifest = sign_release_manifest(&adapter, &key_id, "v1.0.0", artifacts()).unwrap();
        // Re-tag the release without re-signing: a "was v1.0.0, now claims to
        // be v1.0.1" tamper that never touches an artifact's own digest.
        manifest.release_tag = "v1.0.1".into();
        let observed = observed_matching(&manifest);
        assert_eq!(
            verify_release_admission(&adapter, &manifest, &observed),
            Err(AdmissionError::Signature(
                KeyLifecycleError::InvalidSignature
            ))
        );
    }

    #[test]
    fn a_revoked_signing_key_is_rejected_on_the_next_check() {
        let clock = SharedFixedClock::at("2026-01-01T00:00:00Z");
        let adapter = adapter_at(&clock);
        let key_id = active_key(&adapter);
        let manifest = sign_release_manifest(&adapter, &key_id, "v1.0.0", artifacts()).unwrap();
        let observed = observed_matching(&manifest);
        verify_release_admission(&adapter, &manifest, &observed).unwrap();

        adapter
            .revoke(&key_id, "release-signing-key-compromise-drill")
            .unwrap();
        assert_eq!(
            verify_release_admission(&adapter, &manifest, &observed),
            Err(AdmissionError::Signature(KeyLifecycleError::KeyRevoked))
        );
    }

    #[test]
    fn an_empty_manifest_can_never_be_admitted() {
        let clock = SharedFixedClock::at("2026-01-01T00:00:00Z");
        let adapter = adapter_at(&clock);
        let key_id = active_key(&adapter);
        let manifest = sign_release_manifest(&adapter, &key_id, "v1.0.0", Vec::new()).unwrap();
        let observed = BTreeMap::new();
        assert_eq!(
            verify_release_admission(&adapter, &manifest, &observed),
            Err(AdmissionError::EmptyManifest)
        );
    }
}
