//! Development filesystem adapter for the governed [`ArtifactStore`] port.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use cauterizer_syntax::digest::Sha256Digest;

use crate::artifacts::{
    AccessDomain, ArtifactDescriptor, ArtifactError, ArtifactReadAuthorization, ArtifactStore,
    QuarantineId, QuarantineUpload,
};

#[derive(Debug)]
struct PendingFile {
    declaration: QuarantineUpload,
    path: PathBuf,
    length: u64,
}

/// Local-development object store backed by an explicitly selected directory.
///
/// Metadata is process-local; payload files use separate tenant, solver, and
/// verifier directory trees. This adapter is not a production object store.
pub struct FilesystemArtifactStore {
    root: PathBuf,
    pending: HashMap<QuarantineId, PendingFile>,
    committed: HashMap<String, ArtifactDescriptor>,
}

impl FilesystemArtifactStore {
    /// Opens an existing, absolute, non-symlink directory as the storage root.
    ///
    /// The adapter creates only its fixed namespace children and applies owner-
    /// only permissions on Unix platforms.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactError::InvalidMetadata`] if the root is relative,
    /// missing, not a directory, a symlink, or cannot be securely initialized.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ArtifactError> {
        let supplied = root.as_ref();
        if !supplied.is_absolute() {
            return Err(ArtifactError::InvalidMetadata);
        }
        let metadata =
            fs::symlink_metadata(supplied).map_err(|_| ArtifactError::InvalidMetadata)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(ArtifactError::InvalidMetadata);
        }
        let root = supplied
            .canonicalize()
            .map_err(|_| ArtifactError::InvalidMetadata)?;
        restrict_directory(&root)?;
        for domain in [
            AccessDomain::Tenant,
            AccessDomain::Acquisition,
            AccessDomain::Solver,
            AccessDomain::Verifier,
            AccessDomain::Evidence,
        ] {
            let directory = root.join(domain_name(domain));
            create_directory_beneath(&root, &directory)?;
            create_directory_beneath(&root, &directory.join("quarantine"))?;
            create_directory_beneath(&root, &directory.join("committed"))?;
        }
        Ok(Self {
            root,
            pending: HashMap::new(),
            committed: HashMap::new(),
        })
    }

    /// Removes an incomplete upload and its quarantine file.
    #[must_use]
    pub fn abandon_quarantine(&mut self, id: &QuarantineId) -> bool {
        self.pending
            .remove(id)
            .is_some_and(|pending| fs::remove_file(pending.path).is_ok())
    }

    /// Removes every known incomplete upload, returning the number removed.
    pub fn cleanup_partial_uploads(&mut self) -> usize {
        let paths = self
            .pending
            .drain()
            .map(|(_, pending)| pending.path)
            .collect::<Vec<_>>();
        paths
            .into_iter()
            .filter(|path| fs::remove_file(path).is_ok())
            .count()
    }

    fn quarantine_path(&self, upload: &QuarantineUpload, id: &QuarantineId) -> PathBuf {
        self.root
            .join(domain_name(upload.metadata.access_domain))
            .join("quarantine")
            .join(upload.metadata.organization_id.as_str())
            .join(id.as_str())
    }

    fn committed_path(&self, descriptor: &ArtifactDescriptor) -> PathBuf {
        self.root
            .join(domain_name(descriptor.metadata.access_domain))
            .join("committed")
            .join(descriptor.metadata.organization_id.as_str())
            .join(descriptor.digest.to_tagged_hex().replace(':', "_"))
    }
}

impl ArtifactStore for FilesystemArtifactStore {
    fn begin_quarantine(
        &mut self,
        id: QuarantineId,
        upload: QuarantineUpload,
    ) -> Result<(), ArtifactError> {
        validate_upload_metadata(&upload)?;
        if self.pending.contains_key(&id) {
            return Err(ArtifactError::DescriptorConflict);
        }
        let path = self.quarantine_path(&upload, &id);
        let parent = path.parent().ok_or(ArtifactError::InvalidMetadata)?;
        create_directory_beneath(&self.root, parent)?;
        let file = secure_create_new(&path)?;
        drop(file);
        self.pending.insert(
            id,
            PendingFile {
                declaration: upload,
                path,
                length: 0,
            },
        );
        Ok(())
    }

    fn write_quarantine(&mut self, id: &QuarantineId, chunk: &[u8]) -> Result<(), ArtifactError> {
        let pending = self
            .pending
            .get_mut(id)
            .ok_or(ArtifactError::QuarantineNotFound)?;
        reject_symlink(&pending.path)?;
        let chunk_len = u64::try_from(chunk.len()).map_err(|_| ArtifactError::SizeMismatch)?;
        let next = pending
            .length
            .checked_add(chunk_len)
            .ok_or(ArtifactError::SizeMismatch)?;
        if next > pending.declaration.expected_size {
            return Err(ArtifactError::SizeMismatch);
        }
        let mut options = OpenOptions::new();
        options.append(true).write(true);
        let mut file = options
            .open(&pending.path)
            .map_err(|_| ArtifactError::QuarantineNotFound)?;
        file.write_all(chunk)
            .and_then(|()| file.sync_data())
            .map_err(|_| ArtifactError::InvalidMetadata)?;
        pending.length = next;
        Ok(())
    }

    fn validate_and_commit(
        &mut self,
        id: &QuarantineId,
    ) -> Result<ArtifactDescriptor, ArtifactError> {
        let pending = self
            .pending
            .get(id)
            .ok_or(ArtifactError::QuarantineNotFound)?;
        if pending.length != pending.declaration.expected_size {
            return Err(ArtifactError::SizeMismatch);
        }
        reject_symlink(&pending.path)?;
        let bytes = read_bounded(&pending.path, pending.declaration.expected_size)?;
        let digest = Sha256Digest::of_bytes(&bytes);
        if digest != pending.declaration.expected_digest {
            return Err(ArtifactError::DigestMismatch);
        }
        let descriptor = ArtifactDescriptor {
            digest,
            size: pending.declaration.expected_size,
            metadata: pending.declaration.metadata.clone(),
        };
        let key = descriptor_key(&descriptor);
        if let Some(existing) = self.committed.get(&key) {
            return if existing == &descriptor {
                let pending = self
                    .pending
                    .remove(id)
                    .ok_or(ArtifactError::QuarantineNotFound)?;
                fs::remove_file(pending.path).map_err(|_| ArtifactError::InvalidMetadata)?;
                Ok(descriptor)
            } else {
                Err(ArtifactError::DescriptorConflict)
            };
        }
        let target = self.committed_path(&descriptor);
        let parent = target.parent().ok_or(ArtifactError::InvalidMetadata)?;
        create_directory_beneath(&self.root, parent)?;
        // Reserve the immutable destination with create-new semantics. Plain
        // rename would replace an artifact created by a racing writer on Unix.
        let reservation = secure_create_new(&target)?;
        drop(reservation);
        if fs::rename(&pending.path, &target).is_err() {
            let _ = fs::remove_file(&target);
            return Err(ArtifactError::InvalidMetadata);
        }
        restrict_file(&target)?;
        self.pending.remove(id);
        self.committed.insert(key, descriptor.clone());
        Ok(descriptor)
    }

    fn read_verified(
        &self,
        digest: Sha256Digest,
        authorization: &ArtifactReadAuthorization,
    ) -> Result<Vec<u8>, ArtifactError> {
        let key = format!(
            "{}/{:?}/{digest}",
            authorization.organization_id.as_str(),
            authorization.access_domain
        );
        let descriptor = self.committed.get(&key).ok_or(ArtifactError::NotFound)?;
        if descriptor.metadata.organization_id != authorization.organization_id
            || descriptor.metadata.access_domain != authorization.access_domain
            || descriptor.metadata.classification > authorization.maximum_classification
        {
            return Err(ArtifactError::Unauthorized);
        }
        let path = self.committed_path(descriptor);
        ensure_beneath(&self.root, path.parent().ok_or(ArtifactError::NotFound)?)?;
        reject_symlink(&path)?;
        let bytes = read_bounded(&path, descriptor.size)?;
        if Sha256Digest::of_bytes(&bytes) != descriptor.digest {
            return Err(ArtifactError::DigestMismatch);
        }
        Ok(bytes)
    }
}

fn descriptor_key(descriptor: &ArtifactDescriptor) -> String {
    format!(
        "{}/{:?}/{}",
        descriptor.metadata.organization_id.as_str(),
        descriptor.metadata.access_domain,
        descriptor.digest
    )
}

const fn domain_name(domain: AccessDomain) -> &'static str {
    match domain {
        AccessDomain::Tenant => "tenant",
        AccessDomain::Acquisition => "acquisition",
        AccessDomain::Solver => "solver",
        AccessDomain::Verifier => "verifier",
        AccessDomain::Evidence => "evidence",
    }
}

fn create_directory_beneath(root: &Path, target: &Path) -> Result<(), ArtifactError> {
    let relative = target
        .strip_prefix(root)
        .map_err(|_| ArtifactError::Unauthorized)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err(ArtifactError::Unauthorized),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|_| ArtifactError::InvalidMetadata)?;
            }
            Err(_) => return Err(ArtifactError::InvalidMetadata),
        }
        restrict_directory(&current)?;
    }
    ensure_beneath(root, target)
}

fn validate_upload_metadata(upload: &QuarantineUpload) -> Result<(), ArtifactError> {
    let media = upload.metadata.media_type.as_bytes();
    if media.is_empty()
        || media.len() > 128
        || !media.contains(&b'/')
        || !media.iter().all(u8::is_ascii_graphic)
        || upload.metadata.producer.is_empty()
        || upload.metadata.producer.len() > 96
    {
        return Err(ArtifactError::InvalidMetadata);
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<(), ArtifactError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ArtifactError::NotFound)?;
    if metadata.file_type().is_symlink() {
        return Err(ArtifactError::Unauthorized);
    }
    Ok(())
}

fn ensure_beneath(root: &Path, directory: &Path) -> Result<(), ArtifactError> {
    let canonical = directory
        .canonicalize()
        .map_err(|_| ArtifactError::InvalidMetadata)?;
    if !canonical.starts_with(root) {
        return Err(ArtifactError::Unauthorized);
    }
    Ok(())
}

fn secure_create_new(path: &Path) -> Result<File, ArtifactError> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    options
        .open(path)
        .map_err(|_| ArtifactError::DescriptorConflict)
}

fn read_bounded(path: &Path, expected_size: u64) -> Result<Vec<u8>, ArtifactError> {
    let file = File::open(path).map_err(|_| ArtifactError::NotFound)?;
    let mut bytes = Vec::new();
    file.take(expected_size.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| ArtifactError::NotFound)?;
    if u64::try_from(bytes.len()).map_err(|_| ArtifactError::SizeMismatch)? != expected_size {
        return Err(ArtifactError::SizeMismatch);
    }
    Ok(bytes)
}

fn restrict_directory(path: &Path) -> Result<(), ArtifactError> {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| ArtifactError::InvalidMetadata)?;
    Ok(())
}

fn restrict_file(path: &Path) -> Result<(), ArtifactError> {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| ArtifactError::InvalidMetadata)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use cauterizer_syntax::classification::{DataClass, RegionCode, RetentionMetadata};
    use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
    use cauterizer_syntax::schema::{SchemaName, SchemaVersion};
    use cauterizer_syntax::time::UtcInstant;
    use tempfile::TempDir;

    use super::*;

    fn upload(domain: AccessDomain, bytes: &[u8]) -> QuarantineUpload {
        QuarantineUpload {
            expected_digest: Sha256Digest::of_bytes(bytes),
            expected_size: bytes.len() as u64,
            metadata: crate::artifacts::ArtifactMetadata {
                organization_id: OrganizationId::new("00000000").unwrap(),
                classification: DataClass::RestrictedSecurity,
                retention: RetentionMetadata::new(
                    RegionCode::parse("us-east-1").unwrap(),
                    1,
                    false,
                )
                .unwrap(),
                access_domain: domain,
                media_type: "application/json".into(),
                schema_name: SchemaName::parse("dev.cauterizer.verification.observation").unwrap(),
                schema_version: SchemaVersion::parse("1.0.0").unwrap(),
                encryption_key_ref: ContextQualifiedId::new("key", "00000000").unwrap(),
                producer: "verification".into(),
                created_at: UtcInstant::parse("2026-07-23T00:00:00Z").unwrap(),
                created_day: 1,
            },
        }
    }

    fn authorization(domain: AccessDomain) -> ArtifactReadAuthorization {
        ArtifactReadAuthorization {
            organization_id: OrganizationId::new("00000000").unwrap(),
            access_domain: domain,
            maximum_classification: DataClass::RestrictedSecurity,
        }
    }

    #[test]
    fn commit_renames_out_of_quarantine_and_reads_verified_bytes() {
        let temporary = TempDir::new().unwrap();
        let mut store = FilesystemArtifactStore::open(temporary.path()).unwrap();
        let bytes = b"{\"verified\":true}";
        let id = QuarantineId::new("00000000").unwrap();
        store
            .begin_quarantine(id.clone(), upload(AccessDomain::Verifier, bytes))
            .unwrap();
        store.write_quarantine(&id, bytes).unwrap();
        let descriptor = store.validate_and_commit(&id).unwrap();
        assert_eq!(
            store
                .read_verified(descriptor.digest, &authorization(AccessDomain::Verifier))
                .unwrap(),
            bytes
        );
        assert_eq!(
            store.read_verified(descriptor.digest, &authorization(AccessDomain::Solver)),
            Err(ArtifactError::NotFound)
        );
    }

    #[test]
    fn partial_upload_cleanup_removes_temp_file() {
        let temporary = TempDir::new().unwrap();
        let mut store = FilesystemArtifactStore::open(temporary.path()).unwrap();
        let id = QuarantineId::new("00000000").unwrap();
        store
            .begin_quarantine(id.clone(), upload(AccessDomain::Tenant, b"complete"))
            .unwrap();
        store.write_quarantine(&id, b"part").unwrap();
        assert_eq!(store.cleanup_partial_uploads(), 1);
        assert_eq!(
            store.validate_and_commit(&id),
            Err(ArtifactError::QuarantineNotFound)
        );
    }

    #[test]
    fn rejects_invalid_descriptor_metadata_before_creating_upload() {
        let temporary = TempDir::new().unwrap();
        let mut store = FilesystemArtifactStore::open(temporary.path()).unwrap();
        let id = QuarantineId::new("00000000").unwrap();
        let mut invalid = upload(AccessDomain::Tenant, b"content");
        invalid.metadata.media_type = "not-a-media-type".into();
        assert_eq!(
            store.begin_quarantine(id.clone(), invalid),
            Err(ArtifactError::InvalidMetadata)
        );
        assert_eq!(
            store.validate_and_commit(&id),
            Err(ArtifactError::QuarantineNotFound)
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_root_and_symlink_payload_substitution() {
        use std::os::unix::fs::symlink;
        let temporary = TempDir::new().unwrap();
        let link = temporary.path().join("root-link");
        symlink(temporary.path(), &link).unwrap();
        assert!(matches!(
            FilesystemArtifactStore::open(&link),
            Err(ArtifactError::InvalidMetadata)
        ));
        let mut store = FilesystemArtifactStore::open(temporary.path()).unwrap();
        let bytes = b"content";
        let id = QuarantineId::new("00000000").unwrap();
        store
            .begin_quarantine(id.clone(), upload(AccessDomain::Verifier, bytes))
            .unwrap();
        store.write_quarantine(&id, bytes).unwrap();
        let descriptor = store.validate_and_commit(&id).unwrap();
        let path = store.committed_path(&descriptor);
        fs::remove_file(&path).unwrap();
        symlink("/dev/null", &path).unwrap();
        assert_eq!(
            store.read_verified(descriptor.digest, &authorization(AccessDomain::Verifier)),
            Err(ArtifactError::Unauthorized)
        );
    }
}
