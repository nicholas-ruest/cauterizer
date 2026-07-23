//! Content-addressed artifact mechanics with tenant and access-domain isolation.

use std::collections::{HashMap, HashSet};

use cauterizer_syntax::classification::{DataClass, RetentionMetadata};
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
use cauterizer_syntax::schema::{SchemaName, SchemaVersion};
use cauterizer_syntax::time::UtcInstant;

/// Physically and logically separated artifact authority.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AccessDomain {
    /// Ordinary tenant-owned workflow material.
    Tenant,
    /// Network-acquired public or approved source material.
    Acquisition,
    /// Material intentionally visible to candidate solvers.
    Solver,
    /// Hidden grading and verifier material.
    Verifier,
    /// Final evidence manifests and policy-approved attachments.
    Evidence,
}

impl AccessDomain {
    /// Stable storage and contract representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tenant => "tenant",
            Self::Acquisition => "acquisition",
            Self::Solver => "solver",
            Self::Verifier => "verifier",
            Self::Evidence => "evidence",
        }
    }
}

/// Replaceable S3-compatible production object-store boundary.
///
/// Implementations must use create-only quarantine objects, server-side size
/// and digest validation, atomic/conditional commit, immutable committed keys,
/// and exact tenant/access-domain authorization before any existence lookup.
pub trait S3CompatibleObjectStorePort {
    /// Writes a bounded chunk to a non-addressable quarantine object.
    ///
    /// # Errors
    ///
    /// Fails for an unauthorized namespace, absent upload, or size overflow.
    fn put_quarantine_chunk(
        &mut self,
        organization_id: &OrganizationId,
        access_domain: AccessDomain,
        quarantine_id: &QuarantineId,
        chunk: &[u8],
    ) -> Result<(), ArtifactError>;

    /// Conditionally publishes a validated immutable object.
    ///
    /// # Errors
    ///
    /// Fails for absent/corrupt quarantine data or an existing conflicting key.
    fn commit_object(
        &mut self,
        descriptor: &ArtifactDescriptor,
        quarantine_id: &QuarantineId,
    ) -> Result<(), ArtifactError>;

    /// Retrieves exact bytes without providing list/head/existence authority.
    ///
    /// # Errors
    ///
    /// Uses a uniform failure for absent and unauthorized objects and rejects corruption.
    fn get_exact(
        &self,
        digest: Sha256Digest,
        authorization: &ArtifactReadAuthorization,
    ) -> Result<Vec<u8>, ArtifactError>;

    /// Deletes a payload only after policy has persisted its tombstone.
    ///
    /// # Errors
    ///
    /// Fails for unauthorized or unavailable objects.
    fn delete_exact(
        &mut self,
        digest: Sha256Digest,
        authorization: &ArtifactReadAuthorization,
    ) -> Result<(), ArtifactError>;
}

/// Immutable metadata required before an artifact becomes addressable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactMetadata {
    /// Owning tenant.
    pub organization_id: OrganizationId,
    /// Payload disclosure class.
    pub classification: DataClass,
    /// Residency, retention, and legal-hold policy.
    pub retention: RetentionMetadata,
    /// Logical and physical access namespace.
    pub access_domain: AccessDomain,
    /// Bounded IANA-style media type.
    pub media_type: String,
    /// Schema governing the payload.
    pub schema_name: SchemaName,
    /// Immutable semantic schema revision.
    pub schema_version: SchemaVersion,
    /// Opaque envelope-key reference; never raw key material.
    pub encryption_key_ref: ContextQualifiedId,
    /// Provider-neutral producer identifier.
    pub producer: String,
    /// Canonical creation time.
    pub created_at: UtcInstant,
    /// Creation day used by deterministic retention reconciliation.
    pub created_day: u64,
}

/// Client declaration validated server-side before commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantineUpload {
    /// Expected content digest.
    pub expected_digest: Sha256Digest,
    /// Expected exact payload length.
    pub expected_size: u64,
    /// Descriptor metadata.
    pub metadata: ArtifactMetadata,
}

/// Opaque quarantine handle; it is not a committed artifact reference.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct QuarantineId(ContextQualifiedId);

impl QuarantineId {
    /// Creates a caller-generated quarantine identifier.
    ///
    /// # Errors
    ///
    /// Returns an error unless the opaque component is canonical shared ID syntax.
    pub fn new(opaque: &str) -> Result<Self, ArtifactError> {
        ContextQualifiedId::new("quarantine", opaque)
            .map(Self)
            .map_err(|_| ArtifactError::InvalidMetadata)
    }

    /// Returns the canonical quarantine handle spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Committed artifact descriptor safe for aggregate references.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactDescriptor {
    /// Server-computed content digest.
    pub digest: Sha256Digest,
    /// Exact payload size.
    pub size: u64,
    /// Immutable governance metadata.
    pub metadata: ArtifactMetadata,
}

/// Exact authority required for a payload read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactReadAuthorization {
    /// Authenticated tenant.
    pub organization_id: OrganizationId,
    /// Authorized isolated namespace.
    pub access_domain: AccessDomain,
    /// Highest payload classification this request may retrieve.
    pub maximum_classification: DataClass,
}

/// Minimal retained fact after protected payload deletion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactTombstone {
    /// Deleted artifact digest.
    pub digest: Sha256Digest,
    /// Owning tenant.
    pub organization_id: OrganizationId,
    /// Isolated namespace from which it was deleted.
    pub access_domain: AccessDomain,
    /// Attributable policy reason.
    pub reason: String,
    /// Canonical deletion time.
    pub deleted_at: UtcInstant,
}

/// Mark-and-sweep root including the full authorization namespace.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ArtifactRoot {
    /// Owning tenant.
    pub organization_id: OrganizationId,
    /// Isolated artifact namespace.
    pub access_domain: AccessDomain,
    /// Retained content digest.
    pub digest: Sha256Digest,
}

/// Stable artifact service failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactError {
    /// Metadata or bounded media/producer values were invalid.
    InvalidMetadata,
    /// Quarantine handle was absent or already consumed.
    QuarantineNotFound,
    /// Received bytes exceeded or did not equal the declared size.
    SizeMismatch,
    /// Server-computed digest differed from the declaration or committed descriptor.
    DigestMismatch,
    /// Descriptor is absent, tombstoned, or not committed.
    NotFound,
    /// Tenant, access domain, or classification authority did not match.
    Unauthorized,
    /// Legal hold prevents deletion.
    LegalHold,
    /// Existing content under this namespace/digest has conflicting metadata.
    DescriptorConflict,
}

/// Application-facing artifact mechanism port.
pub trait ArtifactStore {
    /// Opens a non-addressable quarantine upload.
    ///
    /// # Errors
    /// Returns an error for invalid metadata or duplicate handles.
    fn begin_quarantine(
        &mut self,
        id: QuarantineId,
        upload: QuarantineUpload,
    ) -> Result<(), ArtifactError>;
    /// Appends one bounded upload chunk.
    ///
    /// # Errors
    /// Returns an error for missing handles or declared-size overflow.
    fn write_quarantine(&mut self, id: &QuarantineId, chunk: &[u8]) -> Result<(), ArtifactError>;
    /// Validates size, digest, media/schema metadata and atomically commits.
    ///
    /// # Errors
    /// Returns an error when validation fails or committed metadata conflicts.
    fn validate_and_commit(
        &mut self,
        id: &QuarantineId,
    ) -> Result<ArtifactDescriptor, ArtifactError>;
    /// Reads exact authorized bytes and re-verifies their content digest.
    ///
    /// # Errors
    /// Returns an error for absent, unauthorized, tombstoned, or corrupt data.
    fn read_verified(
        &self,
        digest: Sha256Digest,
        authorization: &ArtifactReadAuthorization,
    ) -> Result<Vec<u8>, ArtifactError>;
}

#[derive(Clone)]
struct Pending {
    declaration: QuarantineUpload,
    bytes: Vec<u8>,
}

#[derive(Clone)]
struct Committed {
    descriptor: ArtifactDescriptor,
    bytes: Vec<u8>,
}

/// Process-local development adapter modelling separate object-store namespaces.
#[derive(Clone, Default)]
pub struct InMemoryArtifactStore {
    quarantine: HashMap<QuarantineId, Pending>,
    committed: HashMap<String, Committed>,
    tombstones: Vec<ArtifactTombstone>,
}

impl InMemoryArtifactStore {
    /// Returns attributable deletion records without protected payload content.
    #[must_use]
    pub fn tombstones(&self) -> &[ArtifactTombstone] {
        &self.tombstones
    }

    /// Removes an incomplete quarantine upload during reconciliation.
    #[must_use]
    pub fn abandon_quarantine(&mut self, id: &QuarantineId) -> bool {
        self.quarantine.remove(id).is_some()
    }

    #[cfg(test)]
    fn corrupt_payload_for_test(
        &mut self,
        digest: Sha256Digest,
        authorization: &ArtifactReadAuthorization,
    ) {
        let key = storage_key(
            &authorization.organization_id,
            authorization.access_domain,
            digest,
        );
        self.committed.get_mut(&key).unwrap().bytes.push(0);
    }

    /// Deletes one committed payload and records a tombstone.
    ///
    /// # Errors
    /// Returns an error for missing artifacts, mismatched authority, or legal hold.
    pub fn tombstone(
        &mut self,
        digest: Sha256Digest,
        authorization: &ArtifactReadAuthorization,
        reason: String,
        deleted_at: &UtcInstant,
    ) -> Result<(), ArtifactError> {
        let key = storage_key(
            &authorization.organization_id,
            authorization.access_domain,
            digest,
        );
        let artifact = self.committed.get(&key).ok_or(ArtifactError::NotFound)?;
        authorize(&artifact.descriptor, authorization)?;
        if artifact.descriptor.metadata.retention.legal_hold() {
            return Err(ArtifactError::LegalHold);
        }
        self.committed.remove(&key);
        self.tombstones.push(ArtifactTombstone {
            digest,
            organization_id: authorization.organization_id.clone(),
            access_domain: authorization.access_domain,
            reason,
            deleted_at: deleted_at.clone(),
        });
        Ok(())
    }

    /// Sweeps unmarked artifacts whose retention elapsed; legal holds survive.
    pub fn sweep(
        &mut self,
        current_day: u64,
        roots: &HashSet<ArtifactRoot>,
        deleted_at: &UtcInstant,
    ) -> usize {
        let candidates = self
            .committed
            .iter()
            .filter(|(_, item)| {
                let metadata = &item.descriptor.metadata;
                let root = ArtifactRoot {
                    organization_id: metadata.organization_id.clone(),
                    access_domain: metadata.access_domain,
                    digest: item.descriptor.digest,
                };
                !roots.contains(&root)
                    && !metadata.retention.legal_hold()
                    && current_day.saturating_sub(metadata.created_day)
                        >= u64::from(metadata.retention.retention_days())
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in &candidates {
            if let Some(item) = self.committed.remove(key) {
                self.tombstones.push(ArtifactTombstone {
                    digest: item.descriptor.digest,
                    organization_id: item.descriptor.metadata.organization_id,
                    access_domain: item.descriptor.metadata.access_domain,
                    reason: "retention_expired".into(),
                    deleted_at: deleted_at.clone(),
                });
            }
        }
        candidates.len()
    }
}

impl ArtifactStore for InMemoryArtifactStore {
    fn begin_quarantine(
        &mut self,
        id: QuarantineId,
        upload: QuarantineUpload,
    ) -> Result<(), ArtifactError> {
        validate_metadata(&upload.metadata)?;
        if self.quarantine.contains_key(&id) {
            return Err(ArtifactError::DescriptorConflict);
        }
        self.quarantine.insert(
            id,
            Pending {
                declaration: upload,
                bytes: Vec::new(),
            },
        );
        Ok(())
    }

    fn write_quarantine(&mut self, id: &QuarantineId, chunk: &[u8]) -> Result<(), ArtifactError> {
        let pending = self
            .quarantine
            .get_mut(id)
            .ok_or(ArtifactError::QuarantineNotFound)?;
        let next = pending
            .bytes
            .len()
            .checked_add(chunk.len())
            .ok_or(ArtifactError::SizeMismatch)?;
        if u64::try_from(next).map_err(|_| ArtifactError::SizeMismatch)?
            > pending.declaration.expected_size
        {
            return Err(ArtifactError::SizeMismatch);
        }
        pending.bytes.extend_from_slice(chunk);
        Ok(())
    }

    fn validate_and_commit(
        &mut self,
        id: &QuarantineId,
    ) -> Result<ArtifactDescriptor, ArtifactError> {
        let pending = self
            .quarantine
            .get(id)
            .ok_or(ArtifactError::QuarantineNotFound)?;
        if u64::try_from(pending.bytes.len()).map_err(|_| ArtifactError::SizeMismatch)?
            != pending.declaration.expected_size
        {
            return Err(ArtifactError::SizeMismatch);
        }
        let digest = Sha256Digest::of_bytes(&pending.bytes);
        if digest != pending.declaration.expected_digest {
            return Err(ArtifactError::DigestMismatch);
        }
        let descriptor = ArtifactDescriptor {
            digest,
            size: pending.declaration.expected_size,
            metadata: pending.declaration.metadata.clone(),
        };
        let key = storage_key(
            &descriptor.metadata.organization_id,
            descriptor.metadata.access_domain,
            digest,
        );
        if let Some(existing) = self.committed.get(&key) {
            if existing.descriptor == descriptor && existing.bytes == pending.bytes {
                self.quarantine.remove(id);
                return Ok(descriptor);
            }
            return Err(ArtifactError::DescriptorConflict);
        }
        let pending = self
            .quarantine
            .remove(id)
            .ok_or(ArtifactError::QuarantineNotFound)?;
        self.committed.insert(
            key,
            Committed {
                descriptor: descriptor.clone(),
                bytes: pending.bytes,
            },
        );
        Ok(descriptor)
    }

    fn read_verified(
        &self,
        digest: Sha256Digest,
        authorization: &ArtifactReadAuthorization,
    ) -> Result<Vec<u8>, ArtifactError> {
        let key = storage_key(
            &authorization.organization_id,
            authorization.access_domain,
            digest,
        );
        let item = self.committed.get(&key).ok_or(ArtifactError::NotFound)?;
        authorize(&item.descriptor, authorization)?;
        if Sha256Digest::of_bytes(&item.bytes) != item.descriptor.digest {
            return Err(ArtifactError::DigestMismatch);
        }
        Ok(item.bytes.clone())
    }
}

fn validate_metadata(metadata: &ArtifactMetadata) -> Result<(), ArtifactError> {
    let media = metadata.media_type.as_bytes();
    if media.is_empty()
        || media.len() > 128
        || !media.contains(&b'/')
        || !media.iter().all(u8::is_ascii_graphic)
        || metadata.producer.is_empty()
        || metadata.producer.len() > 96
    {
        return Err(ArtifactError::InvalidMetadata);
    }
    Ok(())
}

fn authorize(
    descriptor: &ArtifactDescriptor,
    authorization: &ArtifactReadAuthorization,
) -> Result<(), ArtifactError> {
    let metadata = &descriptor.metadata;
    if metadata.organization_id != authorization.organization_id
        || metadata.access_domain != authorization.access_domain
        || metadata.classification > authorization.maximum_classification
    {
        return Err(ArtifactError::Unauthorized);
    }
    Ok(())
}

fn storage_key(org: &OrganizationId, domain: AccessDomain, digest: Sha256Digest) -> String {
    format!("{}/{domain:?}/{digest}", org.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cauterizer_syntax::classification::RegionCode;

    fn metadata(domain: AccessDomain, legal_hold: bool) -> ArtifactMetadata {
        ArtifactMetadata {
            organization_id: OrganizationId::new("00000000").unwrap(),
            classification: DataClass::RestrictedSecurity,
            retention: RetentionMetadata::new(
                RegionCode::parse("us-east-1").unwrap(),
                1,
                legal_hold,
            )
            .unwrap(),
            access_domain: domain,
            media_type: "application/json".into(),
            schema_name: SchemaName::parse("dev.cauterizer.verification.observation").unwrap(),
            schema_version: SchemaVersion::parse("1.0.0").unwrap(),
            encryption_key_ref: ContextQualifiedId::new("key", "00000000").unwrap(),
            producer: "verification".into(),
            created_at: UtcInstant::parse("2026-07-22T00:00:00Z").unwrap(),
            created_day: 10,
        }
    }

    fn auth(domain: AccessDomain) -> ArtifactReadAuthorization {
        ArtifactReadAuthorization {
            organization_id: OrganizationId::new("00000000").unwrap(),
            access_domain: domain,
            maximum_classification: DataClass::RestrictedSecurity,
        }
    }

    fn commit(
        store: &mut InMemoryArtifactStore,
        domain: AccessDomain,
        hold: bool,
    ) -> ArtifactDescriptor {
        let bytes = b"{\"ok\":true}";
        let id = QuarantineId::new(match domain {
            AccessDomain::Tenant => "00000001",
            AccessDomain::Acquisition => "00000004",
            AccessDomain::Solver => "00000002",
            AccessDomain::Verifier => "00000003",
            AccessDomain::Evidence => "00000005",
        })
        .unwrap();
        store
            .begin_quarantine(
                id.clone(),
                QuarantineUpload {
                    expected_digest: Sha256Digest::of_bytes(bytes),
                    expected_size: bytes.len() as u64,
                    metadata: metadata(domain, hold),
                },
            )
            .unwrap();
        store.write_quarantine(&id, bytes).unwrap();
        store.validate_and_commit(&id).unwrap()
    }

    #[test]
    fn quarantine_is_not_addressable_and_validates_size_and_digest() {
        let mut store = InMemoryArtifactStore::default();
        let bytes = b"partial";
        let id = QuarantineId::new("00000001").unwrap();
        store
            .begin_quarantine(
                id.clone(),
                QuarantineUpload {
                    expected_digest: Sha256Digest::of_bytes(b"complete"),
                    expected_size: 8,
                    metadata: metadata(AccessDomain::Tenant, false),
                },
            )
            .unwrap();
        store.write_quarantine(&id, bytes).unwrap();
        assert_eq!(
            store.read_verified(
                Sha256Digest::of_bytes(b"complete"),
                &auth(AccessDomain::Tenant)
            ),
            Err(ArtifactError::NotFound)
        );
        assert_eq!(
            store.validate_and_commit(&id),
            Err(ArtifactError::SizeMismatch)
        );
        assert!(store.abandon_quarantine(&id));
    }

    #[test]
    fn committed_descriptors_preserve_historical_schema_versions() {
        let mut store = InMemoryArtifactStore::default();
        let old_bytes = b"{\"schema\":1}";
        let old_id = QuarantineId::new("00000006").unwrap();
        let mut old_metadata = metadata(AccessDomain::Evidence, false);
        old_metadata.schema_version = SchemaVersion::parse("1.0.0").unwrap();
        store
            .begin_quarantine(
                old_id.clone(),
                QuarantineUpload {
                    expected_digest: Sha256Digest::of_bytes(old_bytes),
                    expected_size: old_bytes.len() as u64,
                    metadata: old_metadata,
                },
            )
            .unwrap();
        store.write_quarantine(&old_id, old_bytes).unwrap();
        let old = store.validate_and_commit(&old_id).unwrap();

        let new_bytes = b"{\"schema\":2}";
        let new_id = QuarantineId::new("00000007").unwrap();
        let mut new_metadata = metadata(AccessDomain::Evidence, false);
        new_metadata.schema_version = SchemaVersion::parse("2.0.0").unwrap();
        store
            .begin_quarantine(
                new_id.clone(),
                QuarantineUpload {
                    expected_digest: Sha256Digest::of_bytes(new_bytes),
                    expected_size: new_bytes.len() as u64,
                    metadata: new_metadata,
                },
            )
            .unwrap();
        store.write_quarantine(&new_id, new_bytes).unwrap();
        let new = store.validate_and_commit(&new_id).unwrap();

        assert_eq!(old.metadata.schema_version.as_str(), "1.0.0");
        assert_eq!(new.metadata.schema_version.as_str(), "2.0.0");
        assert_eq!(
            store
                .read_verified(old.digest, &auth(AccessDomain::Evidence))
                .unwrap(),
            old_bytes
        );
        assert_eq!(
            store
                .read_verified(new.digest, &auth(AccessDomain::Evidence))
                .unwrap(),
            new_bytes
        );
    }

    #[test]
    fn reads_are_tenant_classification_domain_and_digest_verified() {
        let mut store = InMemoryArtifactStore::default();
        let descriptor = commit(&mut store, AccessDomain::Verifier, false);
        assert_eq!(
            store.read_verified(descriptor.digest, &auth(AccessDomain::Solver)),
            Err(ArtifactError::NotFound)
        );
        let low = ArtifactReadAuthorization {
            maximum_classification: DataClass::Confidential,
            ..auth(AccessDomain::Verifier)
        };
        assert_eq!(
            store.read_verified(descriptor.digest, &low),
            Err(ArtifactError::Unauthorized)
        );
        assert_eq!(
            store
                .read_verified(descriptor.digest, &auth(AccessDomain::Verifier))
                .unwrap(),
            b"{\"ok\":true}"
        );
        store.corrupt_payload_for_test(descriptor.digest, &auth(AccessDomain::Verifier));
        assert_eq!(
            store.read_verified(descriptor.digest, &auth(AccessDomain::Verifier)),
            Err(ArtifactError::DigestMismatch)
        );
    }

    #[test]
    fn mark_sweep_retains_roots_and_holds_and_tombstones_expired_payloads() {
        let mut store = InMemoryArtifactStore::default();
        let swept = commit(&mut store, AccessDomain::Tenant, false);
        let held = commit(&mut store, AccessDomain::Verifier, true);
        let rooted = commit(&mut store, AccessDomain::Solver, false);
        let roots = HashSet::from([ArtifactRoot {
            organization_id: rooted.metadata.organization_id.clone(),
            access_domain: rooted.metadata.access_domain,
            digest: rooted.digest,
        }]);
        assert_eq!(
            store.sweep(
                11,
                &roots,
                &UtcInstant::parse("2026-07-23T00:00:00Z").unwrap()
            ),
            1
        );
        assert_eq!(
            store.read_verified(swept.digest, &auth(AccessDomain::Tenant)),
            Err(ArtifactError::NotFound)
        );
        assert!(
            store
                .read_verified(held.digest, &auth(AccessDomain::Verifier))
                .is_ok()
        );
        assert!(
            store
                .read_verified(rooted.digest, &auth(AccessDomain::Solver))
                .is_ok()
        );
        assert_eq!(store.tombstones().len(), 1);
    }

    #[test]
    fn explicit_tombstone_respects_legal_hold() {
        let mut store = InMemoryArtifactStore::default();
        let held = commit(&mut store, AccessDomain::Verifier, true);
        assert_eq!(
            store.tombstone(
                held.digest,
                &auth(AccessDomain::Verifier),
                "retention".into(),
                &UtcInstant::parse("2026-07-23T00:00:00Z").unwrap()
            ),
            Err(ArtifactError::LegalHold)
        );
    }
}
