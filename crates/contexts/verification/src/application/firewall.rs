//! Solver/verifier information-flow firewall reference adapter.

use crate::domain::qualification::PublicFixtureDescriptor;
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
use std::collections::HashMap;

/// Physically and cryptographically distinct artifact access domains.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AccessDomain {
    /// Approved solver-visible inputs.
    SolverPublic,
    /// Hidden tests, gold patches, and oracle material.
    VerifierHidden,
}

/// Least-privilege workload class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkloadRole {
    /// Trusted acquisition publisher; the only cross-namespace writer.
    Acquisition,
    /// Solver workload restricted to public reads.
    Solver,
    /// Verifier workload restricted to hidden reads and qualification sealing.
    Verifier,
}

/// Issuer-owned capability mint.
///
/// The key must be supplied from a protected runtime secret. Credentials cannot
/// be constructed or have their claims changed outside this module.
pub struct CredentialIssuer {
    tenant: OrganizationId,
    key: Sha256Digest,
}

impl CredentialIssuer {
    /// Creates the tenant-specific issuer.
    #[must_use]
    pub fn new(tenant: OrganizationId, key: Sha256Digest) -> Self {
        Self { tenant, key }
    }

    /// Issues an authenticated, workload-bound capability.
    #[must_use]
    pub fn issue(&self, role: WorkloadRole, workload: ContextQualifiedId) -> WorkloadCredential {
        let tag = credential_tag(&self.key, &self.tenant, role, &workload);
        WorkloadCredential {
            tenant: self.tenant.clone(),
            role,
            workload,
            tag,
        }
    }
}

/// Workload-bound authenticated capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkloadCredential {
    tenant: OrganizationId,
    role: WorkloadRole,
    workload: ContextQualifiedId,
    tag: Sha256Digest,
}

/// Payload-free result intentionally identical for absent and forbidden digests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreError {
    /// No readable object exists in this credential namespace.
    NotFound,
    /// Credential authentication or tenant binding failed.
    Unauthorized,
    /// This workload role cannot perform the requested write.
    WriteDenied,
}

#[derive(Default)]
struct DomainStore {
    objects: HashMap<Sha256Digest, Vec<u8>>,
}

/// Reference adapter using distinct physical maps and domain-specific access.
pub struct SeparatedArtifactStore {
    tenant: OrganizationId,
    credential_key: Sha256Digest,
    solver: DomainStore,
    verifier: DomainStore,
}

impl SeparatedArtifactStore {
    /// Creates empty, tenant-bound namespaces.
    #[must_use]
    pub fn new(tenant: OrganizationId, credential_key: Sha256Digest) -> Self {
        Self {
            tenant,
            credential_key,
            solver: DomainStore::default(),
            verifier: DomainStore::default(),
        }
    }

    /// Commits bytes through acquisition authority.
    ///
    /// Acquisition is the only role allowed to populate either namespace.
    /// # Errors
    /// Rejects unauthenticated, cross-tenant, solver, and verifier writes.
    pub fn commit(
        &mut self,
        credential: &WorkloadCredential,
        domain: AccessDomain,
        bytes: Vec<u8>,
    ) -> Result<Sha256Digest, StoreError> {
        self.authenticate(credential)?;
        if credential.role != WorkloadRole::Acquisition {
            return Err(StoreError::WriteDenied);
        }
        let digest = Sha256Digest::of_bytes(&bytes);
        match domain {
            AccessDomain::SolverPublic => &mut self.solver,
            AccessDomain::VerifierHidden => &mut self.verifier,
        }
        .objects
        .insert(digest, bytes);
        Ok(digest)
    }

    /// Reads only the namespace granted to the workload role.
    ///
    /// Acquisition credentials deliberately have no evaluation read authority.
    /// Unknown and cross-domain digests return the same result.
    /// # Errors
    /// Rejects invalid credentials and returns [`StoreError::NotFound`] for
    /// absent or cross-domain objects.
    pub fn read(
        &self,
        credential: &WorkloadCredential,
        digest: &Sha256Digest,
    ) -> Result<&[u8], StoreError> {
        self.authenticate(credential)?;
        let store = match credential.role {
            WorkloadRole::Solver => &self.solver,
            WorkloadRole::Verifier => &self.verifier,
            WorkloadRole::Acquisition => return Err(StoreError::Unauthorized),
        };
        store
            .objects
            .get(digest)
            .map(Vec::as_slice)
            .ok_or(StoreError::NotFound)
    }

    /// Lists only the role's namespace in stable digest order.
    /// # Errors
    /// Rejects invalid credentials and acquisition read attempts.
    pub fn list(&self, credential: &WorkloadCredential) -> Result<Vec<Sha256Digest>, StoreError> {
        self.authenticate(credential)?;
        let store = match credential.role {
            WorkloadRole::Solver => &self.solver,
            WorkloadRole::Verifier => &self.verifier,
            WorkloadRole::Acquisition => return Err(StoreError::Unauthorized),
        };
        let mut digests: Vec<_> = store.objects.keys().copied().collect();
        digests.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        Ok(digests)
    }

    fn authenticate(&self, credential: &WorkloadCredential) -> Result<(), StoreError> {
        let expected = credential_tag(
            &self.credential_key,
            &credential.tenant,
            credential.role,
            &credential.workload,
        );
        if credential.tenant == self.tenant && credential.tag == expected {
            Ok(())
        } else {
            Err(StoreError::Unauthorized)
        }
    }
}

fn credential_tag(
    key: &Sha256Digest,
    tenant: &OrganizationId,
    role: WorkloadRole,
    workload: &ContextQualifiedId,
) -> Sha256Digest {
    let mut bytes = b"cauterizer.verification.workload-credential.v1\0".to_vec();
    bytes.extend_from_slice(key.as_bytes());
    append(&mut bytes, tenant.as_str());
    append(
        &mut bytes,
        match role {
            WorkloadRole::Acquisition => "acquisition",
            WorkloadRole::Solver => "solver",
            WorkloadRole::Verifier => "verifier",
        },
    );
    append(&mut bytes, workload.as_str());
    Sha256Digest::of_bytes(bytes)
}

fn append(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

/// Stable assessment gate failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssessmentAdmissionError {
    /// Caller lacks a valid tenant-bound verifier capability.
    Unauthorized,
    /// Descriptor has no exact sealed qualification record.
    NotQualified,
}

/// Tenant-scoped registry preventing handcrafted descriptors entering assessment.
pub struct QualificationRegistry {
    tenant: OrganizationId,
    credential_key: Sha256Digest,
    qualified: HashMap<Sha256Digest, PublicFixtureDescriptor>,
}

impl QualificationRegistry {
    /// Creates an empty tenant qualification registry.
    #[must_use]
    pub fn new(tenant: OrganizationId, credential_key: Sha256Digest) -> Self {
        Self {
            tenant,
            credential_key,
            qualified: HashMap::new(),
        }
    }

    /// Seals a descriptor produced by the verifier qualification workflow.
    /// # Errors
    /// Only a valid verifier capability for this tenant may seal a result.
    pub fn seal(
        &mut self,
        credential: &WorkloadCredential,
        descriptor: PublicFixtureDescriptor,
    ) -> Result<(), AssessmentAdmissionError> {
        self.authenticate_verifier(credential)?;
        self.qualified
            .insert(descriptor.qualification_digest, descriptor);
        Ok(())
    }

    /// Admits only the exact tenant-sealed descriptor.
    /// # Errors
    /// Rejects invalid callers and unqualified, substituted, or stale descriptors.
    pub fn admit_assessment(
        &self,
        credential: &WorkloadCredential,
        descriptor: &PublicFixtureDescriptor,
    ) -> Result<(), AssessmentAdmissionError> {
        self.authenticate_verifier(credential)?;
        if self.qualified.get(&descriptor.qualification_digest) == Some(descriptor) {
            Ok(())
        } else {
            Err(AssessmentAdmissionError::NotQualified)
        }
    }

    fn authenticate_verifier(
        &self,
        credential: &WorkloadCredential,
    ) -> Result<(), AssessmentAdmissionError> {
        let expected = credential_tag(
            &self.credential_key,
            &credential.tenant,
            credential.role,
            &credential.workload,
        );
        if credential.tenant == self.tenant
            && credential.role == WorkloadRole::Verifier
            && credential.tag == expected
        {
            Ok(())
        } else {
            Err(AssessmentAdmissionError::Unauthorized)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn org(value: &str) -> OrganizationId {
        OrganizationId::new(value).unwrap()
    }
    fn key(value: &str) -> Sha256Digest {
        Sha256Digest::of_bytes(value)
    }
    fn issuer(tenant: &OrganizationId) -> CredentialIssuer {
        CredentialIssuer::new(tenant.clone(), key("credential-key"))
    }
    fn credential(tenant: &OrganizationId, role: WorkloadRole) -> WorkloadCredential {
        issuer(tenant).issue(role, ContextQualifiedId::new("worker", "00000000").unwrap())
    }
    fn descriptor() -> PublicFixtureDescriptor {
        PublicFixtureDescriptor {
            advisory_id: "CVE-2022-29217".into(),
            source_bundle_digest: key("source"),
            environment_bundle_digest: key("environment"),
            acquisition_manifest_digest: key("acquisition"),
            qualification_policy: "fixture-qualification-v1-10x".into(),
            qualification_digest: key("qualification"),
        }
    }

    #[test]
    fn solver_cannot_enumerate_or_probe_hidden_assets() {
        let tenant = org("00000000");
        let mut store = SeparatedArtifactStore::new(tenant.clone(), key("credential-key"));
        let acquisition = credential(&tenant, WorkloadRole::Acquisition);
        let solver = credential(&tenant, WorkloadRole::Solver);
        let hidden = store
            .commit(
                &acquisition,
                AccessDomain::VerifierHidden,
                b"gold patch and hidden test".to_vec(),
            )
            .unwrap();
        assert!(store.list(&solver).unwrap().is_empty());
        assert_eq!(store.read(&solver, &hidden), Err(StoreError::NotFound));
        assert_eq!(
            store.read(&solver, &key("unknown")),
            Err(StoreError::NotFound)
        );
    }

    #[test]
    fn only_acquisition_can_write_either_namespace() {
        let tenant = org("00000000");
        let mut store = SeparatedArtifactStore::new(tenant.clone(), key("credential-key"));
        for role in [WorkloadRole::Solver, WorkloadRole::Verifier] {
            let capability = credential(&tenant, role);
            for domain in [AccessDomain::SolverPublic, AccessDomain::VerifierHidden] {
                assert_eq!(
                    store.commit(&capability, domain, b"probe".to_vec()),
                    Err(StoreError::WriteDenied)
                );
            }
        }
    }

    #[test]
    fn tampered_wrong_key_and_cross_tenant_credentials_fail() {
        let tenant = org("00000000");
        let other = org("11111111");
        let mut store = SeparatedArtifactStore::new(tenant.clone(), key("credential-key"));
        let mut tampered = credential(&tenant, WorkloadRole::Solver);
        tampered.role = WorkloadRole::Verifier;
        assert_eq!(store.list(&tampered), Err(StoreError::Unauthorized));

        let wrong_key = CredentialIssuer::new(tenant.clone(), key("wrong-key")).issue(
            WorkloadRole::Solver,
            ContextQualifiedId::new("worker", "00000000").unwrap(),
        );
        assert_eq!(store.list(&wrong_key), Err(StoreError::Unauthorized));
        assert_eq!(
            store.commit(
                &credential(&other, WorkloadRole::Acquisition),
                AccessDomain::SolverPublic,
                vec![]
            ),
            Err(StoreError::Unauthorized)
        );
    }

    #[test]
    fn listing_is_deterministic() {
        let tenant = org("00000000");
        let mut store = SeparatedArtifactStore::new(tenant.clone(), key("credential-key"));
        let acquisition = credential(&tenant, WorkloadRole::Acquisition);
        let solver = credential(&tenant, WorkloadRole::Solver);
        for bytes in [b"z".as_slice(), b"a".as_slice(), b"m".as_slice()] {
            store
                .commit(&acquisition, AccessDomain::SolverPublic, bytes.to_vec())
                .unwrap();
        }
        let first = store.list(&solver).unwrap();
        let mut sorted = first.clone();
        sorted.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        assert_eq!(first, sorted);
        assert_eq!(first, store.list(&solver).unwrap());
    }

    #[test]
    fn qualification_is_tenant_scoped_and_verifier_sealed() {
        let tenant = org("00000000");
        let other = org("11111111");
        let verifier = credential(&tenant, WorkloadRole::Verifier);
        let solver = credential(&tenant, WorkloadRole::Solver);
        let mut registry = QualificationRegistry::new(tenant.clone(), key("credential-key"));
        let first = descriptor();

        assert_eq!(
            registry.seal(&solver, first.clone()),
            Err(AssessmentAdmissionError::Unauthorized)
        );
        assert_eq!(
            registry.admit_assessment(&verifier, &first),
            Err(AssessmentAdmissionError::NotQualified)
        );
        registry.seal(&verifier, first.clone()).unwrap();
        assert_eq!(registry.admit_assessment(&verifier, &first), Ok(()));
        assert_eq!(
            registry.admit_assessment(&credential(&other, WorkloadRole::Verifier), &first),
            Err(AssessmentAdmissionError::Unauthorized)
        );

        let mut substituted = first;
        substituted.qualification_policy = "unqualified-policy".into();
        assert_eq!(
            registry.admit_assessment(&verifier, &substituted),
            Err(AssessmentAdmissionError::NotQualified)
        );
    }
}
