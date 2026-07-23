//! S3-compatible immutable artifact storage and exact-key reconciliation.
//!
//! Provider SDK and credential types remain outside the trusted contract. An outer
//! transport adapter must implement conditional create, bounded reads, and exact delete.
//! The production adapter intentionally exposes no tenant-facing list or existence API.

use std::collections::HashMap;

use crate::artifacts::{
    AccessDomain, ArtifactDescriptor, ArtifactError, ArtifactReadAuthorization, ArtifactStore,
    QuarantineId, QuarantineUpload, authorize, storage_key, validate_metadata,
};
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::OrganizationId;

const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;

/// Result of a create-only object write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateOutcome {
    /// The immutable key was created.
    Created,
    /// The exact key already existed and was not overwritten.
    AlreadyExists,
}

/// Stable provider-neutral transport failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectTransportError {
    /// Exact key does not exist.
    NotFound,
    /// Transport, authentication, or provider service failed.
    Unavailable,
    /// Provider returned more bytes than the requested bound.
    ResponseTooLarge,
}

/// Minimal S3-compatible object operations required by the trusted adapter.
pub trait S3ObjectApi {
    /// Appends bytes to a create-only, non-addressable quarantine upload.
    ///
    /// # Errors
    /// Returns a stable transport failure without provider details.
    fn append_quarantine(
        &mut self,
        key: &str,
        chunk: &[u8],
        maximum_size: u64,
    ) -> Result<(), ObjectTransportError>;

    /// Reads an exact key with a hard response-size bound.
    ///
    /// # Errors
    /// Returns a stable transport failure without provider details.
    fn get_bounded(&self, key: &str, maximum_size: u64) -> Result<Vec<u8>, ObjectTransportError>;

    /// Creates an immutable key using `If-None-Match: *` semantics.
    ///
    /// # Errors
    /// Returns a stable transport failure without provider details.
    fn put_if_absent(
        &mut self,
        key: &str,
        bytes: &[u8],
    ) -> Result<CreateOutcome, ObjectTransportError>;

    /// Deletes an exact key. Implementations must not expand prefixes.
    ///
    /// # Errors
    /// Returns a stable transport failure without provider details.
    fn delete_exact(&mut self, key: &str) -> Result<(), ObjectTransportError>;
}

#[derive(Clone)]
struct PendingUpload {
    declaration: QuarantineUpload,
    quarantine_key: String,
}

/// S3-compatible production artifact adapter.
pub struct S3ArtifactStore<T> {
    transport: T,
    pending: HashMap<QuarantineId, PendingUpload>,
    descriptors: HashMap<String, ArtifactDescriptor>,
}

impl<T> S3ArtifactStore<T> {
    /// Creates a production adapter over a least-privilege S3-compatible transport.
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            pending: HashMap::new(),
            descriptors: HashMap::new(),
        }
    }

    /// Restores committed `PostgreSQL` descriptors after process restart.
    ///
    /// # Errors
    ///
    /// Rejects invalid metadata or conflicting descriptors for one immutable key.
    pub fn register_descriptor(
        &mut self,
        descriptor: ArtifactDescriptor,
    ) -> Result<(), ArtifactError> {
        validate_metadata(&descriptor.metadata)?;
        let key = committed_key(&descriptor);
        if self
            .descriptors
            .get(&key)
            .is_some_and(|existing| existing != &descriptor)
        {
            return Err(ArtifactError::DescriptorConflict);
        }
        self.descriptors.insert(key, descriptor);
        Ok(())
    }

    /// Returns the transport for lifecycle wiring after all pending uploads are resolved.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.transport
    }
}

impl<T: S3ObjectApi> ArtifactStore for S3ArtifactStore<T> {
    fn begin_quarantine(
        &mut self,
        id: QuarantineId,
        upload: QuarantineUpload,
    ) -> Result<(), ArtifactError> {
        validate_metadata(&upload.metadata)?;
        if upload.expected_size > MAX_ARTIFACT_BYTES {
            return Err(ArtifactError::SizeMismatch);
        }
        if self.pending.contains_key(&id) {
            return Err(ArtifactError::DescriptorConflict);
        }
        let quarantine_key = format!(
            "quarantine/{}/{}/{}",
            upload.metadata.organization_id.as_str(),
            upload.metadata.access_domain.as_str(),
            id.as_str()
        );
        self.pending.insert(
            id,
            PendingUpload {
                declaration: upload,
                quarantine_key,
            },
        );
        Ok(())
    }

    fn write_quarantine(&mut self, id: &QuarantineId, chunk: &[u8]) -> Result<(), ArtifactError> {
        let pending = self
            .pending
            .get(id)
            .ok_or(ArtifactError::QuarantineNotFound)?;
        self.transport
            .append_quarantine(
                &pending.quarantine_key,
                chunk,
                pending.declaration.expected_size,
            )
            .map_err(map_write_error)
    }

    fn validate_and_commit(
        &mut self,
        id: &QuarantineId,
    ) -> Result<ArtifactDescriptor, ArtifactError> {
        let pending = self
            .pending
            .get(id)
            .ok_or(ArtifactError::QuarantineNotFound)?;
        let bytes = self
            .transport
            .get_bounded(&pending.quarantine_key, pending.declaration.expected_size)
            .map_err(map_quarantine_read_error)?;
        if u64::try_from(bytes.len()).map_err(|_| ArtifactError::SizeMismatch)?
            != pending.declaration.expected_size
        {
            return Err(ArtifactError::SizeMismatch);
        }
        let digest = Sha256Digest::of_bytes(&bytes);
        if digest != pending.declaration.expected_digest {
            return Err(ArtifactError::DigestMismatch);
        }
        let descriptor = ArtifactDescriptor {
            digest,
            size: pending.declaration.expected_size,
            metadata: pending.declaration.metadata.clone(),
        };
        let object_key = committed_key(&descriptor);
        match self
            .transport
            .put_if_absent(&object_key, &bytes)
            .map_err(|_| ArtifactError::NotFound)?
        {
            CreateOutcome::Created => {}
            CreateOutcome::AlreadyExists => {
                let existing = self
                    .transport
                    .get_bounded(&object_key, MAX_ARTIFACT_BYTES)
                    .map_err(|_| ArtifactError::DescriptorConflict)?;
                if existing != bytes || Sha256Digest::of_bytes(&existing) != descriptor.digest {
                    return Err(ArtifactError::DescriptorConflict);
                }
            }
        }
        self.transport
            .delete_exact(&pending.quarantine_key)
            .map_err(|_| ArtifactError::NotFound)?;
        self.pending.remove(id);
        self.descriptors
            .insert(committed_key(&descriptor), descriptor.clone());
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
        let committed_key = format!("committed/{key}");
        let descriptor = self
            .descriptors
            .get(&committed_key)
            .ok_or(ArtifactError::NotFound)?;
        authorize(descriptor, authorization).map_err(|_| ArtifactError::NotFound)?;
        let bytes = self
            .transport
            .get_bounded(&committed_key, descriptor.size)
            .map_err(|_| ArtifactError::NotFound)?;
        if Sha256Digest::of_bytes(&bytes) != digest {
            return Err(ArtifactError::DigestMismatch);
        }
        if u64::try_from(bytes.len()).ok() != Some(descriptor.size) {
            return Err(ArtifactError::SizeMismatch);
        }
        Ok(bytes)
    }
}

fn committed_key(descriptor: &ArtifactDescriptor) -> String {
    format!(
        "committed/{}",
        storage_key(
            &descriptor.metadata.organization_id,
            descriptor.metadata.access_domain,
            descriptor.digest
        )
    )
}

fn map_write_error(error: ObjectTransportError) -> ArtifactError {
    match error {
        ObjectTransportError::ResponseTooLarge => ArtifactError::SizeMismatch,
        ObjectTransportError::NotFound | ObjectTransportError::Unavailable => {
            ArtifactError::QuarantineNotFound
        }
    }
}

fn map_quarantine_read_error(error: ObjectTransportError) -> ArtifactError {
    match error {
        ObjectTransportError::ResponseTooLarge => ArtifactError::SizeMismatch,
        ObjectTransportError::NotFound | ObjectTransportError::Unavailable => {
            ArtifactError::QuarantineNotFound
        }
    }
}

/// Exact metadata/object discrepancy. It contains no payload or provider details.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconciliationIssue {
    /// `PostgreSQL` has a live descriptor but the exact immutable object is absent.
    MissingObject(ArtifactDescriptor),
    /// Object length differs from committed `PostgreSQL` metadata.
    SizeMismatch(ArtifactDescriptor),
    /// Object bytes do not hash to the committed `PostgreSQL` digest.
    DigestMismatch(ArtifactDescriptor),
    /// Storage could not prove object state; reconciliation fails closed.
    StoreUnavailable(ArtifactDescriptor),
}

/// Minimal live `PostgreSQL` metadata needed to reconcile one immutable object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredObjectExpectation {
    /// Owning tenant.
    pub organization_id: OrganizationId,
    /// Physically isolated access namespace.
    pub access_domain: AccessDomain,
    /// Committed content digest.
    pub digest: Sha256Digest,
    /// Committed exact payload length.
    pub size: u64,
}

/// Provider-neutral discrepancy for a `PostgreSQL` object expectation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoredObjectIssue {
    /// Metadata exists but the exact object does not.
    Missing(StoredObjectExpectation),
    /// Object length differs from `PostgreSQL` metadata.
    SizeMismatch(StoredObjectExpectation),
    /// Object digest differs from `PostgreSQL` metadata.
    DigestMismatch(StoredObjectExpectation),
    /// Object state could not be proven.
    StoreUnavailable(StoredObjectExpectation),
}

/// Reconciles live `PostgreSQL` expectations without namespace listing authority.
#[must_use]
pub fn reconcile_expectations<T: S3ObjectApi>(
    transport: &T,
    expectations: &[StoredObjectExpectation],
) -> Vec<StoredObjectIssue> {
    let mut issues = Vec::new();
    for expectation in expectations {
        let key = format!(
            "committed/{}",
            storage_key(
                &expectation.organization_id,
                expectation.access_domain,
                expectation.digest
            )
        );
        match transport.get_bounded(&key, expectation.size) {
            Err(ObjectTransportError::NotFound) => {
                issues.push(StoredObjectIssue::Missing(expectation.clone()));
            }
            Err(ObjectTransportError::ResponseTooLarge) => {
                issues.push(StoredObjectIssue::SizeMismatch(expectation.clone()));
            }
            Err(ObjectTransportError::Unavailable) => {
                issues.push(StoredObjectIssue::StoreUnavailable(expectation.clone()));
            }
            Ok(bytes) if u64::try_from(bytes.len()).ok() != Some(expectation.size) => {
                issues.push(StoredObjectIssue::SizeMismatch(expectation.clone()));
            }
            Ok(bytes) if Sha256Digest::of_bytes(&bytes) != expectation.digest => {
                issues.push(StoredObjectIssue::DigestMismatch(expectation.clone()));
            }
            Ok(_) => {}
        }
    }
    issues
}

/// Reconciles `PostgreSQL` descriptor snapshots against exact S3-compatible keys.
///
/// This deliberately does not list tenant namespaces. Orphan discovery must consume a
/// provider-generated inventory through a separate administrative identity.
#[must_use]
pub fn reconcile_exact<T: S3ObjectApi>(
    transport: &T,
    descriptors: &[ArtifactDescriptor],
) -> Vec<ReconciliationIssue> {
    let mut issues = Vec::new();
    for descriptor in descriptors {
        let result = transport.get_bounded(&committed_key(descriptor), descriptor.size);
        match result {
            Err(ObjectTransportError::NotFound) => {
                issues.push(ReconciliationIssue::MissingObject(descriptor.clone()));
            }
            Err(ObjectTransportError::ResponseTooLarge) => {
                issues.push(ReconciliationIssue::SizeMismatch(descriptor.clone()));
            }
            Err(ObjectTransportError::Unavailable) => {
                issues.push(ReconciliationIssue::StoreUnavailable(descriptor.clone()));
            }
            Ok(bytes) if u64::try_from(bytes.len()).ok() != Some(descriptor.size) => {
                issues.push(ReconciliationIssue::SizeMismatch(descriptor.clone()));
            }
            Ok(bytes) if Sha256Digest::of_bytes(&bytes) != descriptor.digest => {
                issues.push(ReconciliationIssue::DigestMismatch(descriptor.clone()));
            }
            Ok(_) => {}
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::ArtifactMetadata;
    use cauterizer_syntax::classification::{DataClass, RegionCode, RetentionMetadata};
    use cauterizer_syntax::identifiers::ContextQualifiedId;
    use cauterizer_syntax::schema::{SchemaName, SchemaVersion};
    use cauterizer_syntax::time::UtcInstant;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct FakeS3 {
        objects: BTreeMap<String, Vec<u8>>,
        unavailable: bool,
    }

    impl S3ObjectApi for FakeS3 {
        fn append_quarantine(
            &mut self,
            key: &str,
            chunk: &[u8],
            maximum_size: u64,
        ) -> Result<(), ObjectTransportError> {
            let object = self.objects.entry(key.into()).or_default();
            if u64::try_from(object.len().saturating_add(chunk.len()))
                .map_or(true, |length| length > maximum_size)
            {
                return Err(ObjectTransportError::ResponseTooLarge);
            }
            object.extend_from_slice(chunk);
            Ok(())
        }

        fn get_bounded(
            &self,
            key: &str,
            maximum_size: u64,
        ) -> Result<Vec<u8>, ObjectTransportError> {
            if self.unavailable {
                return Err(ObjectTransportError::Unavailable);
            }
            let bytes = self
                .objects
                .get(key)
                .ok_or(ObjectTransportError::NotFound)?;
            if u64::try_from(bytes.len()).map_or(true, |length| length > maximum_size) {
                return Err(ObjectTransportError::ResponseTooLarge);
            }
            Ok(bytes.clone())
        }

        fn put_if_absent(
            &mut self,
            key: &str,
            bytes: &[u8],
        ) -> Result<CreateOutcome, ObjectTransportError> {
            if self.objects.contains_key(key) {
                return Ok(CreateOutcome::AlreadyExists);
            }
            self.objects.insert(key.into(), bytes.into());
            Ok(CreateOutcome::Created)
        }

        fn delete_exact(&mut self, key: &str) -> Result<(), ObjectTransportError> {
            self.objects
                .remove(key)
                .map(|_| ())
                .ok_or(ObjectTransportError::NotFound)
        }
    }

    fn metadata(domain: AccessDomain) -> ArtifactMetadata {
        ArtifactMetadata {
            organization_id: OrganizationId::new("00000000").unwrap(),
            classification: DataClass::RestrictedSecurity,
            retention: RetentionMetadata::new(RegionCode::parse("us-east-1").unwrap(), 30, false)
                .unwrap(),
            access_domain: domain,
            media_type: "application/octet-stream".into(),
            schema_name: SchemaName::parse("dev.cauterizer.artifact.payload").unwrap(),
            schema_version: SchemaVersion::parse("1.0.0").unwrap(),
            encryption_key_ref: ContextQualifiedId::new("key", "00000000").unwrap(),
            producer: "acquisition".into(),
            created_at: UtcInstant::parse("2026-07-23T00:00:00Z").unwrap(),
            created_day: 1,
        }
    }

    fn commit(store: &mut S3ArtifactStore<FakeS3>, bytes: &[u8]) -> ArtifactDescriptor {
        let id = QuarantineId::new("00000000").unwrap();
        store
            .begin_quarantine(
                id.clone(),
                QuarantineUpload {
                    expected_digest: Sha256Digest::of_bytes(bytes),
                    expected_size: bytes.len() as u64,
                    metadata: metadata(AccessDomain::Verifier),
                },
            )
            .unwrap();
        store.write_quarantine(&id, bytes).unwrap();
        store.validate_and_commit(&id).unwrap()
    }

    #[test]
    fn quarantine_commit_is_create_only_and_digest_verified() {
        let mut store = S3ArtifactStore::new(FakeS3::default());
        let descriptor = commit(&mut store, b"immutable");
        let authorization = ArtifactReadAuthorization {
            organization_id: descriptor.metadata.organization_id.clone(),
            access_domain: AccessDomain::Verifier,
            maximum_classification: DataClass::RestrictedSecurity,
        };
        assert_eq!(
            store
                .read_verified(descriptor.digest, &authorization)
                .unwrap(),
            b"immutable"
        );
        assert!(
            store
                .into_inner()
                .objects
                .keys()
                .all(|key| !key.starts_with("quarantine/"))
        );
    }

    #[test]
    fn cross_domain_read_is_uniformly_not_found() {
        let mut store = S3ArtifactStore::new(FakeS3::default());
        let descriptor = commit(&mut store, b"hidden");
        let wrong = ArtifactReadAuthorization {
            organization_id: descriptor.metadata.organization_id,
            access_domain: AccessDomain::Solver,
            maximum_classification: DataClass::RestrictedSecurity,
        };
        assert_eq!(
            store.read_verified(descriptor.digest, &wrong),
            Err(ArtifactError::NotFound)
        );
    }

    #[test]
    fn conflicting_existing_object_never_overwrites() {
        let bytes = b"expected";
        let descriptor = ArtifactDescriptor {
            digest: Sha256Digest::of_bytes(bytes),
            size: bytes.len() as u64,
            metadata: metadata(AccessDomain::Verifier),
        };
        let mut fake = FakeS3::default();
        fake.objects
            .insert(committed_key(&descriptor), b"substitution".to_vec());
        let mut store = S3ArtifactStore::new(fake);
        let id = QuarantineId::new("00000000").unwrap();
        store
            .begin_quarantine(
                id.clone(),
                QuarantineUpload {
                    expected_digest: descriptor.digest,
                    expected_size: descriptor.size,
                    metadata: descriptor.metadata,
                },
            )
            .unwrap();
        store.write_quarantine(&id, bytes).unwrap();
        assert_eq!(
            store.validate_and_commit(&id),
            Err(ArtifactError::DescriptorConflict)
        );
    }

    #[test]
    fn reconciliation_distinguishes_missing_corrupt_size_and_outage() {
        let good_bytes = b"good";
        let descriptor = ArtifactDescriptor {
            digest: Sha256Digest::of_bytes(good_bytes),
            size: good_bytes.len() as u64,
            metadata: metadata(AccessDomain::Acquisition),
        };
        let fake = FakeS3::default();
        assert!(matches!(
            reconcile_exact(&fake, std::slice::from_ref(&descriptor)).as_slice(),
            [ReconciliationIssue::MissingObject(_)]
        ));
        let mut fake = FakeS3::default();
        fake.objects
            .insert(committed_key(&descriptor), b"evil".to_vec());
        assert!(matches!(
            reconcile_exact(&fake, std::slice::from_ref(&descriptor)).as_slice(),
            [ReconciliationIssue::DigestMismatch(_)]
        ));
        fake.objects
            .insert(committed_key(&descriptor), b"oversized".to_vec());
        assert!(matches!(
            reconcile_exact(&fake, std::slice::from_ref(&descriptor)).as_slice(),
            [ReconciliationIssue::SizeMismatch(_)]
        ));
        fake.unavailable = true;
        assert!(matches!(
            reconcile_exact(&fake, &[descriptor]).as_slice(),
            [ReconciliationIssue::StoreUnavailable(_)]
        ));
    }
}
