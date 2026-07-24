//! Credential-scoped capability boundary over the CAS artifact store.
//!
//! `crates/contexts/verification/src/application/firewall.rs` already proves the
//! solver/verifier information-flow firewall at the verification context's own
//! `SeparatedArtifactStore`. That reference adapter binds a workload credential to
//! exactly one [`AccessDomain`]-shaped namespace at issuance time (HMAC-tagged, not
//! caller-declared), so a solver workload can never manufacture a verifier-scoped
//! capability. This module is the equivalent boundary at the CAS storage layer
//! (`artifacts.rs`/`s3_artifacts.rs`): [`ArtifactReadAuthorization`] is a plain
//! public struct any caller can construct with any [`AccessDomain`] value, so
//! nothing at that layer previously stopped a caller who only *should* hold
//! solver-scoped authority from simply writing `access_domain: AccessDomain::Verifier`
//! into the authorization it passes to [`ArtifactStore::read_verified`]. The
//! [`ScopedArtifactStore`] wrapper closes that gap by requiring a
//! [`ArtifactCredential`] whose access domain is cryptographically bound at
//! mint time, mirroring `firewall.rs`'s `CredentialIssuer`/`WorkloadCredential`
//! idiom exactly, and adds a `list`/`exists` capability the underlying CAS ports
//! deliberately do not expose (see `s3_artifacts.rs`'s module doc: "the production
//! adapter intentionally exposes no tenant-facing list or existence API") so that
//! capability itself can be domain-scoped and tested rather than absent by accident.
//!
//! `ScopedArtifactStore` is generic over any [`ArtifactStore`] implementation, so it
//! wraps `InMemoryArtifactStore` and `S3ArtifactStore<T>` uniformly.

use std::collections::HashMap;

use crate::artifacts::{
    AccessDomain, ArtifactDescriptor, ArtifactError, ArtifactReadAuthorization, ArtifactStore,
};
use cauterizer_syntax::classification::DataClass;
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};

/// Issuer-owned capability mint binding one credential to exactly one access domain.
///
/// The key must be supplied from a protected runtime secret. Credentials cannot be
/// constructed, nor have their domain changed, outside this module.
pub struct ArtifactCredentialIssuer {
    tenant: OrganizationId,
    key: Sha256Digest,
}

impl ArtifactCredentialIssuer {
    /// Creates the tenant-specific issuer.
    #[must_use]
    pub const fn new(tenant: OrganizationId, key: Sha256Digest) -> Self {
        Self { tenant, key }
    }

    /// Issues an authenticated, domain-bound capability for one workload.
    #[must_use]
    pub fn issue(
        &self,
        access_domain: AccessDomain,
        workload: ContextQualifiedId,
        maximum_classification: DataClass,
    ) -> ArtifactCredential {
        let tag = credential_tag(&self.key, &self.tenant, access_domain, &workload);
        ArtifactCredential {
            tenant: self.tenant.clone(),
            access_domain,
            workload,
            maximum_classification,
            tag,
        }
    }
}

/// Workload-bound, domain-scoped authenticated capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactCredential {
    tenant: OrganizationId,
    access_domain: AccessDomain,
    workload: ContextQualifiedId,
    maximum_classification: DataClass,
    tag: Sha256Digest,
}

fn credential_tag(
    key: &Sha256Digest,
    tenant: &OrganizationId,
    access_domain: AccessDomain,
    workload: &ContextQualifiedId,
) -> Sha256Digest {
    let mut bytes = b"cauterizer.infrastructure.artifact-credential.v1\0".to_vec();
    bytes.extend_from_slice(key.as_bytes());
    append(&mut bytes, tenant.as_str());
    append(&mut bytes, access_domain.as_str());
    append(&mut bytes, workload.as_str());
    Sha256Digest::of_bytes(bytes)
}

fn append(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

/// Registry of committed digests keyed by tenant and access domain.
///
/// Populated only by an authorized commit call (see [`ArtifactCommitIndex::record`]),
/// never by a scoped read credential, so a solver-scoped credential cannot cause the
/// verifier/evidence-domain index to reveal anything about its contents.
#[derive(Default)]
pub struct ArtifactCommitIndex {
    by_domain: HashMap<(OrganizationId, AccessDomain), Vec<Sha256Digest>>,
}

impl ArtifactCommitIndex {
    /// Records one committed descriptor's digest under its own tenant/domain.
    pub fn record(&mut self, descriptor: &ArtifactDescriptor) {
        let key = (
            descriptor.metadata.organization_id.clone(),
            descriptor.metadata.access_domain,
        );
        let digests = self.by_domain.entry(key).or_default();
        if !digests.contains(&descriptor.digest) {
            digests.push(descriptor.digest);
        }
    }
}

/// Credential-authenticated read/list/existence boundary over any [`ArtifactStore`].
///
/// A credential minted for one [`AccessDomain`] cannot list, read, or detect the
/// existence of another domain's objects, including by guessing a real digest from
/// that other domain: `list` only ever returns entries recorded under the
/// credential's own bound domain, and `read`/`exists` build the underlying
/// [`ArtifactReadAuthorization`] exclusively from the credential's bound domain,
/// never from caller input, so the caller has no way to smuggle a different domain
/// through this boundary even if it tried.
pub struct ScopedArtifactStore<'a, S> {
    store: &'a S,
    index: &'a ArtifactCommitIndex,
    credential_key: Sha256Digest,
    tenant: OrganizationId,
}

impl<'a, S: ArtifactStore> ScopedArtifactStore<'a, S> {
    /// Creates a scoped view authenticating against one tenant's credential key.
    #[must_use]
    pub const fn new(
        store: &'a S,
        index: &'a ArtifactCommitIndex,
        credential_key: Sha256Digest,
        tenant: OrganizationId,
    ) -> Self {
        Self {
            store,
            index,
            credential_key,
            tenant,
        }
    }

    /// Reads bytes within the credential's own bound domain.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactError::Unauthorized`] for an invalid credential and
    /// [`ArtifactError::NotFound`] uniformly for an absent digest or one that
    /// belongs to a different access domain.
    pub fn read(
        &self,
        credential: &ArtifactCredential,
        digest: Sha256Digest,
    ) -> Result<Vec<u8>, ArtifactError> {
        self.authenticate(credential)?;
        self.store.read_verified(
            digest,
            &ArtifactReadAuthorization {
                organization_id: credential.tenant.clone(),
                access_domain: credential.access_domain,
                maximum_classification: credential.maximum_classification,
            },
        )
    }

    /// Reports whether a digest is readable within the credential's own bound domain.
    ///
    /// Uses the same uniform not-found path as [`Self::read`], so probing a real
    /// digest from a different domain is indistinguishable from probing a random one.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactError::Unauthorized`] for an invalid credential and
    /// propagates any error other than [`ArtifactError::NotFound`].
    pub fn exists(
        &self,
        credential: &ArtifactCredential,
        digest: Sha256Digest,
    ) -> Result<bool, ArtifactError> {
        match self.read(credential, digest) {
            Ok(_) => Ok(true),
            Err(ArtifactError::NotFound) => Ok(false),
            Err(other) => Err(other),
        }
    }

    /// Lists digests committed under the credential's own bound domain only.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactError::Unauthorized`] for an invalid credential.
    pub fn list(&self, credential: &ArtifactCredential) -> Result<Vec<Sha256Digest>, ArtifactError> {
        self.authenticate(credential)?;
        Ok(self
            .index
            .by_domain
            .get(&(credential.tenant.clone(), credential.access_domain))
            .cloned()
            .unwrap_or_default())
    }

    fn authenticate(&self, credential: &ArtifactCredential) -> Result<(), ArtifactError> {
        let expected = credential_tag(
            &self.credential_key,
            &self.tenant,
            credential.access_domain,
            &credential.workload,
        );
        if credential.tenant == self.tenant && credential.tag == expected {
            Ok(())
        } else {
            Err(ArtifactError::Unauthorized)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::{
        ArtifactMetadata, InMemoryArtifactStore, QuarantineId, QuarantineUpload,
    };
    use cauterizer_syntax::classification::{DataClass, RegionCode, RetentionMetadata};
    use cauterizer_syntax::schema::{SchemaName, SchemaVersion};
    use cauterizer_syntax::time::UtcInstant;

    fn tenant() -> OrganizationId {
        OrganizationId::new("00000000").unwrap()
    }

    fn credential_key() -> Sha256Digest {
        Sha256Digest::of_bytes(b"artifact-credential-key")
    }

    fn metadata(domain: AccessDomain) -> ArtifactMetadata {
        ArtifactMetadata {
            organization_id: tenant(),
            classification: DataClass::RestrictedSecurity,
            retention: RetentionMetadata::new(RegionCode::parse("us-east-1").unwrap(), 30, false)
                .unwrap(),
            access_domain: domain,
            media_type: "application/octet-stream".into(),
            schema_name: SchemaName::parse("dev.cauterizer.artifact.payload").unwrap(),
            schema_version: SchemaVersion::parse("1.0.0").unwrap(),
            encryption_key_ref: ContextQualifiedId::new("key", "00000000").unwrap(),
            producer: "acquisition".into(),
            created_at: UtcInstant::parse("2026-07-24T00:00:00Z").unwrap(),
            created_day: 1,
        }
    }

    fn commit(
        store: &mut InMemoryArtifactStore,
        index: &mut ArtifactCommitIndex,
        domain: AccessDomain,
        quarantine_opaque: &str,
        bytes: &[u8],
    ) -> ArtifactDescriptor {
        let id = QuarantineId::new(quarantine_opaque).unwrap();
        store
            .begin_quarantine(
                id.clone(),
                QuarantineUpload {
                    expected_digest: Sha256Digest::of_bytes(bytes),
                    expected_size: bytes.len() as u64,
                    metadata: metadata(domain),
                },
            )
            .unwrap();
        store.write_quarantine(&id, bytes).unwrap();
        let descriptor = store.validate_and_commit(&id).unwrap();
        index.record(&descriptor);
        descriptor
    }

    #[test]
    fn solver_scoped_credential_cannot_list_read_or_probe_verifier_or_evidence_objects() {
        let mut store = InMemoryArtifactStore::default();
        let mut index = ArtifactCommitIndex::default();
        let verifier_descriptor = commit(
            &mut store,
            &mut index,
            AccessDomain::Verifier,
            "00000001",
            b"gold patch and hidden test",
        );
        let evidence_descriptor = commit(
            &mut store,
            &mut index,
            AccessDomain::Evidence,
            "00000002",
            b"final policy-approved bundle",
        );
        let solver_descriptor = commit(
            &mut store,
            &mut index,
            AccessDomain::Solver,
            "00000003",
            b"approved solver-visible input",
        );

        let issuer = ArtifactCredentialIssuer::new(tenant(), credential_key());
        let solver_workload = ContextQualifiedId::new("worker", "00000001").unwrap();
        let solver_credential = issuer.issue(
            AccessDomain::Solver,
            solver_workload,
            DataClass::RestrictedSecurity,
        );
        let view = ScopedArtifactStore::new(&store, &index, credential_key(), tenant());

        // Enumeration only ever reveals the credential's own domain.
        assert_eq!(view.list(&solver_credential).unwrap(), vec![
            solver_descriptor.digest
        ]);

        // Reading a real verifier/evidence digest is indistinguishable from a
        // random guess: both fail closed with the same uniform NotFound.
        assert_eq!(
            view.read(&solver_credential, verifier_descriptor.digest),
            Err(ArtifactError::NotFound)
        );
        assert_eq!(
            view.read(&solver_credential, evidence_descriptor.digest),
            Err(ArtifactError::NotFound)
        );
        assert_eq!(
            view.read(&solver_credential, Sha256Digest::of_bytes(b"unknown")),
            Err(ArtifactError::NotFound)
        );

        // Existence probing across domains is likewise uniform.
        assert_eq!(
            view.exists(&solver_credential, verifier_descriptor.digest),
            Ok(false)
        );
        assert_eq!(
            view.exists(&solver_credential, evidence_descriptor.digest),
            Ok(false)
        );
        assert_eq!(
            view.exists(&solver_credential, solver_descriptor.digest),
            Ok(true)
        );
    }

    #[test]
    fn tampered_domain_and_cross_tenant_credentials_are_rejected() {
        let mut store = InMemoryArtifactStore::default();
        let mut index = ArtifactCommitIndex::default();
        let descriptor = commit(
            &mut store,
            &mut index,
            AccessDomain::Verifier,
            "00000001",
            b"hidden",
        );
        let issuer = ArtifactCredentialIssuer::new(tenant(), credential_key());
        let workload = ContextQualifiedId::new("worker", "00000001").unwrap();
        let view = ScopedArtifactStore::new(&store, &index, credential_key(), tenant());

        // A credential minted for Solver, then hand-edited to claim Verifier,
        // fails authentication because the tag no longer matches its domain.
        let mut tampered = issuer.issue(
            AccessDomain::Solver,
            workload.clone(),
            DataClass::RestrictedSecurity,
        );
        tampered.access_domain = AccessDomain::Verifier;
        assert_eq!(
            view.list(&tampered),
            Err(ArtifactError::Unauthorized)
        );
        assert_eq!(
            view.read(&tampered, descriptor.digest),
            Err(ArtifactError::Unauthorized)
        );

        // A credential minted with the wrong key entirely also fails.
        let wrong_key_issuer =
            ArtifactCredentialIssuer::new(tenant(), Sha256Digest::of_bytes(b"wrong-key"));
        let wrong_key = wrong_key_issuer.issue(
            AccessDomain::Verifier,
            workload.clone(),
            DataClass::RestrictedSecurity,
        );
        assert_eq!(view.list(&wrong_key), Err(ArtifactError::Unauthorized));

        // A credential minted for a different tenant also fails.
        let other_tenant = OrganizationId::new("11111111").unwrap();
        let cross_tenant = ArtifactCredentialIssuer::new(other_tenant, credential_key())
            .issue(AccessDomain::Verifier, workload, DataClass::RestrictedSecurity);
        assert_eq!(view.list(&cross_tenant), Err(ArtifactError::Unauthorized));
    }

    #[test]
    fn verifier_scoped_credential_still_reads_its_own_domain() {
        let mut store = InMemoryArtifactStore::default();
        let mut index = ArtifactCommitIndex::default();
        let descriptor = commit(
            &mut store,
            &mut index,
            AccessDomain::Verifier,
            "00000001",
            b"hidden test oracle",
        );
        let issuer = ArtifactCredentialIssuer::new(tenant(), credential_key());
        let verifier_credential = issuer.issue(
            AccessDomain::Verifier,
            ContextQualifiedId::new("worker", "00000002").unwrap(),
            DataClass::RestrictedSecurity,
        );
        let view = ScopedArtifactStore::new(&store, &index, credential_key(), tenant());
        assert_eq!(
            view.read(&verifier_credential, descriptor.digest).unwrap(),
            b"hidden test oracle"
        );
        assert_eq!(view.list(&verifier_credential).unwrap(), vec![descriptor.digest]);
    }
}
