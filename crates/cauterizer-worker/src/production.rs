//! Truth-preserving production bridge adapters.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::{ArtifactBinding, CandidateTransferSource};
use base64::Engine as _;
use cauterizer_external_actions::application::RemoteError;
use cauterizer_git_workspace_publisher::{PublishedCommit, VisibleCheck as GitVisibleCheck};
use cauterizer_integration_management::contracts::CandidatePatch;
use cauterizer_integration_management::contracts::{
    GitCommitOid, GitCommitTransfer, GitFileObject,
};
use cauterizer_patch_proposals::application::SolverPort;
use cauterizer_patch_proposals::domain::{ProposalAttempt, SolverBrief};
use cauterizer_patch_proposals_coding_agent::{ProcessPort, ProcessRequest};
use cauterizer_remediation_runs::application::agentic::{
    CandidateAttempt, CandidateSolver, ComponentError, HiddenDecision, HiddenVerifier,
    SolverRequest, VisibleCheck as RepairVisibleCheck, VisibleEvaluator, VisibleFeedback,
};
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
use cauterizer_verification::application::assessment::{
    AssessmentAdapterError, AssessmentInputRepository, AssessmentRecorder, HiddenAssessmentAdapter,
};
use cauterizer_verification::domain::assessment::{
    AssessmentVerdict, CandidateAssessment, CandidateAssessmentEngine, CandidateAssessmentInput,
};
use serde::{Deserialize, Serialize};

/// Candidate-bound verifier facts admitted to the external-delivery boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDeliveryEvidence {
    /// Tenant owning the assessment and delivery.
    pub organization_id: OrganizationId,
    /// Remediation run that produced the candidate.
    pub run_id: ContextQualifiedId,
    /// Exact candidate admitted by the verifier.
    pub candidate_digest: Sha256Digest,
    /// Recorded deterministic verifier assessment.
    pub assessment_digest: Sha256Digest,
    /// Digest of the exact verifier policy used for the assessment.
    pub policy_digest: Sha256Digest,
}

impl VerifiedDeliveryEvidence {
    /// Re-evaluates and binds a recorded verified assessment to its tenant, run, candidate, and policy.
    ///
    /// # Errors
    /// Fails closed for candidate substitution, a non-verified verdict, or a tampered assessment.
    pub fn from_recorded(
        organization_id: OrganizationId,
        run_id: ContextQualifiedId,
        candidate_digest: Sha256Digest,
        input: &CandidateAssessmentInput,
        recorded: &CandidateAssessment,
    ) -> Result<Self, AssessmentAdapterError> {
        if input.organization_id != organization_id
            || input.run_id != run_id
            || input.patch.patch_digest != candidate_digest
            || recorded.verdict != AssessmentVerdict::VerifiedForFixture
            || CandidateAssessmentEngine::assess(input) != *recorded
        {
            return Err(AssessmentAdapterError::EvidenceMismatch);
        }
        let policy = serde_jcs::to_vec(&input.policy)
            .map_err(|_| AssessmentAdapterError::EvidenceUnavailable)?;
        Ok(Self {
            organization_id,
            run_id,
            candidate_digest,
            assessment_digest: recorded.assessment_digest,
            policy_digest: Sha256Digest::of_bytes(policy),
        })
    }
}

/// Validated candidate patch retention keyed by its content digest.
pub trait CandidateArtifactRepository: Clone {
    /// Stores normalized bytes and paths, rejecting digest substitution.
    ///
    /// # Errors
    /// Fails closed when storage is unavailable or identity conflicts.
    fn put(&self, patch: CandidatePatch) -> Result<(), ComponentError>;
    /// Loads an exact candidate artifact.
    ///
    /// # Errors
    /// Fails closed when storage is unavailable.
    fn get(&self, digest: Sha256Digest) -> Result<Option<CandidatePatch>, ComponentError>;
}
/// Sanitized solver-visible diagnostic storage, disjoint from verifier evidence.
pub trait VisibleDiagnosticRepository: Send + Sync {
    /// Stores exact bounded public diagnostic bytes.
    ///
    /// # Errors
    /// Rejects oversized, substituted, or unavailable diagnostic state.
    fn put(
        &self,
        id: ContextQualifiedId,
        digest: Sha256Digest,
        bytes: Vec<u8>,
    ) -> Result<(), ComponentError>;
    /// Loads public diagnostic bytes while revalidating their digest.
    ///
    /// # Errors
    /// Rejects substituted or unavailable diagnostic state.
    fn get(
        &self,
        id: &ContextQualifiedId,
        digest: Sha256Digest,
    ) -> Result<Option<Vec<u8>>, ComponentError>;
}
type DiagnosticMap = BTreeMap<String, (Sha256Digest, Vec<u8>)>;
/// In-memory visible diagnostic repository for one repair execution.
#[derive(Clone, Default)]
pub struct InMemoryVisibleDiagnostics(Arc<Mutex<DiagnosticMap>>);
impl VisibleDiagnosticRepository for InMemoryVisibleDiagnostics {
    fn put(
        &self,
        id: ContextQualifiedId,
        digest: Sha256Digest,
        bytes: Vec<u8>,
    ) -> Result<(), ComponentError> {
        if bytes.is_empty() || bytes.len() > 16_384 || Sha256Digest::of_bytes(&bytes) != digest {
            return Err(ComponentError);
        }
        let mut values = self.0.lock().map_err(|_| ComponentError)?;
        if let Some(existing) = values.get(id.as_str()) {
            return if existing == &(digest, bytes) {
                Ok(())
            } else {
                Err(ComponentError)
            };
        }
        values.insert(id.as_str().into(), (digest, bytes));
        Ok(())
    }
    fn get(
        &self,
        id: &ContextQualifiedId,
        digest: Sha256Digest,
    ) -> Result<Option<Vec<u8>>, ComponentError> {
        match self
            .0
            .lock()
            .map_err(|_| ComponentError)?
            .get(id.as_str())
            .cloned()
        {
            Some((stored, bytes))
                if stored == digest && Sha256Digest::of_bytes(&bytes) == digest =>
            {
                Ok(Some(bytes))
            }
            Some(_) => Err(ComponentError),
            None => Ok(None),
        }
    }
}

/// In-memory reference store used by a single worker execution.
#[derive(Clone, Default)]
pub struct InMemoryCandidateArtifacts(Arc<Mutex<BTreeMap<String, CandidatePatch>>>);
impl CandidateArtifactRepository for InMemoryCandidateArtifacts {
    fn put(&self, patch: CandidatePatch) -> Result<(), ComponentError> {
        let mut values = self.0.lock().map_err(|_| ComponentError)?;
        let key = patch.digest().to_tagged_hex();
        if let Some(existing) = values.get(&key) {
            return if existing == &patch {
                Ok(())
            } else {
                Err(ComponentError)
            };
        }
        values.insert(key, patch);
        Ok(())
    }
    fn get(&self, digest: Sha256Digest) -> Result<Option<CandidatePatch>, ComponentError> {
        self.0
            .lock()
            .map(|values| values.get(&digest.to_tagged_hex()).cloned())
            .map_err(|_| ComponentError)
    }
}

/// Restart-safe filesystem store for normalized patches and remote commit material.
#[derive(Clone)]
pub struct FilesystemCandidateArtifacts {
    root: Arc<PathBuf>,
    binding: Arc<ArtifactBinding>,
}
#[derive(Serialize, Deserialize)]
struct StoredPatch {
    organization_id: String,
    run_id: String,
    repository: String,
    installation_id: String,
    digest: Sha256Digest,
    bytes_base64: String,
    paths: Vec<String>,
}
#[derive(Serialize, Deserialize)]
struct StoredTransfer {
    organization_id: String,
    run_id: String,
    repository: String,
    installation_id: String,
    candidate: Sha256Digest,
    commit: String,
    base: String,
    commit_message: String,
    files: Vec<StoredFile>,
}
#[derive(Serialize, Deserialize)]
struct StoredFile {
    path: String,
    content_base64: String,
    executable: bool,
}
impl FilesystemCandidateArtifacts {
    /// Creates or opens an absolute candidate artifact directory.
    ///
    /// # Errors
    /// Rejects relative or unavailable storage roots.
    pub fn new(root: &Path, binding: ArtifactBinding) -> Result<Self, ComponentError> {
        if !root.is_absolute() {
            return Err(ComponentError);
        }
        if binding.run_id.is_empty()
            || binding.repository.is_empty()
            || binding.installation_id.is_empty()
        {
            return Err(ComponentError);
        }
        std::fs::create_dir_all(root).map_err(|_| ComponentError)?;
        let root = root.canonicalize().map_err(|_| ComponentError)?;
        let namespace = Sha256Digest::of_bytes(format!(
            "{}\0{}\0{}\0{}",
            binding.organization_id, binding.run_id, binding.repository, binding.installation_id
        ));
        let root = root.join(namespace.to_tagged_hex().replace(':', "-"));
        std::fs::create_dir(&root)
            .or_else(|error| {
                (error.kind() == std::io::ErrorKind::AlreadyExists)
                    .then_some(())
                    .ok_or(error)
            })
            .map_err(|_| ComponentError)?;
        if !root
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
        {
            return Err(ComponentError);
        }
        Ok(Self {
            root: Arc::new(root),
            binding: Arc::new(binding),
        })
    }
    /// Atomically stores transfer material bound to all three identities.
    ///
    /// # Errors
    /// Rejects unavailable storage and conflicting immutable identity reuse.
    pub fn put_transfer(
        &self,
        candidate: Sha256Digest,
        commit: &GitCommitOid,
        transfer: &GitCommitTransfer,
    ) -> Result<(), ComponentError> {
        let total = transfer.files.iter().try_fold(0usize, |total, file| {
            (file.content.len() <= 1_048_576)
                .then(|| total.checked_add(file.content.len()))
                .flatten()
        });
        if transfer.files.is_empty()
            || transfer.files.len() > 100
            || total.is_none_or(|bytes| bytes > 8 * 1024 * 1024)
            || transfer.commit_message.is_empty()
            || transfer.commit_message.len() > 1024
        {
            return Err(ComponentError);
        }
        let stored = StoredTransfer {
            organization_id: self.binding.organization_id.to_string(),
            run_id: self.binding.run_id.clone(),
            repository: self.binding.repository.clone(),
            installation_id: self.binding.installation_id.clone(),
            candidate,
            commit: commit.as_str().into(),
            base: transfer.base_commit_oid.as_str().into(),
            commit_message: transfer.commit_message.clone(),
            files: transfer
                .files
                .iter()
                .map(|file| StoredFile {
                    path: file.path.clone(),
                    content_base64: base64::engine::general_purpose::STANDARD.encode(&file.content),
                    executable: file.executable,
                })
                .collect(),
        };
        self.atomic(
            &self.path(candidate, "transfer"),
            &serde_json::to_vec(&stored).map_err(|_| ComponentError)?,
        )
    }
    fn path(&self, digest: Sha256Digest, kind: &str) -> PathBuf {
        self.root.join(format!(
            "{}.{kind}.json",
            digest.to_tagged_hex().replace(':', "-")
        ))
    }
    fn atomic(&self, destination: &Path, bytes: &[u8]) -> Result<(), ComponentError> {
        if bytes.len() > 12 * 1024 * 1024 {
            return Err(ComponentError);
        }
        if destination
            .symlink_metadata()
            .is_ok_and(|meta| !meta.is_file())
        {
            return Err(ComponentError);
        }
        let mut temporary =
            tempfile::NamedTempFile::new_in(self.root.as_ref()).map_err(|_| ComponentError)?;
        std::io::Write::write_all(&mut temporary, bytes).map_err(|_| ComponentError)?;
        temporary.as_file().sync_all().map_err(|_| ComponentError)?;
        match temporary.persist_noclobber(destination) {
            Ok(_) => std::fs::File::open(self.root.as_ref())
                .and_then(|directory| directory.sync_all())
                .map_err(|_| ComponentError),
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = destination.symlink_metadata().map_err(|_| ComponentError)?;
                if !metadata.is_file() {
                    return Err(ComponentError);
                }
                (bounded_nofollow_read(destination, 12 * 1024 * 1024)
                    .map_err(|_| ComponentError)?
                    == bytes)
                    .then_some(())
                    .ok_or(ComponentError)
            }
            Err(_) => Err(ComponentError),
        }
    }
}
impl CandidateArtifactRepository for FilesystemCandidateArtifacts {
    fn put(&self, patch: CandidatePatch) -> Result<(), ComponentError> {
        if patch.as_bytes().len() > 8 * 1024 * 1024 || patch.paths().len() > 100 {
            return Err(ComponentError);
        }
        let stored = StoredPatch {
            organization_id: self.binding.organization_id.to_string(),
            run_id: self.binding.run_id.clone(),
            repository: self.binding.repository.clone(),
            installation_id: self.binding.installation_id.clone(),
            digest: patch.digest(),
            bytes_base64: base64::engine::general_purpose::STANDARD.encode(patch.as_bytes()),
            paths: patch.paths().iter().cloned().collect(),
        };
        self.atomic(
            &self.path(patch.digest(), "patch"),
            &serde_json::to_vec(&stored).map_err(|_| ComponentError)?,
        )
    }
    fn get(&self, digest: Sha256Digest) -> Result<Option<CandidatePatch>, ComponentError> {
        let file_path = self.path(digest, "patch");
        let bytes = match bounded_nofollow_read(&file_path, 12 * 1024 * 1024) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ComponentError),
        };
        let stored: StoredPatch = serde_json::from_slice(&bytes).map_err(|_| ComponentError)?;
        if !self.matches_binding(
            &stored.organization_id,
            &stored.run_id,
            &stored.repository,
            &stored.installation_id,
        ) {
            return Err(ComponentError);
        }
        let patch_bytes = base64::engine::general_purpose::STANDARD
            .decode(stored.bytes_base64)
            .map_err(|_| ComponentError)?;
        if patch_bytes.len() > 8 * 1024 * 1024 {
            return Err(ComponentError);
        }
        let candidate_patch =
            CandidatePatch::from_normalized(patch_bytes, stored.paths.into_iter().collect());
        if stored.digest != digest || candidate_patch.digest() != digest {
            return Err(ComponentError);
        }
        Ok(Some(candidate_patch))
    }
}
impl CandidateTransferSource for FilesystemCandidateArtifacts {
    fn find(
        &self,
        binding: &ArtifactBinding,
        candidate: Sha256Digest,
        commit: &GitCommitOid,
        base: &GitCommitOid,
    ) -> Result<Option<GitCommitTransfer>, RemoteError> {
        let path = self.path(candidate, "transfer");
        if binding != self.binding.as_ref() {
            return Err(RemoteError::Rejected);
        }
        let bytes = match bounded_nofollow_read(&path, 12 * 1024 * 1024) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(RemoteError::UnavailableOrAmbiguous),
        };
        let stored: StoredTransfer =
            serde_json::from_slice(&bytes).map_err(|_| RemoteError::UnavailableOrAmbiguous)?;
        if !self.matches_binding(
            &stored.organization_id,
            &stored.run_id,
            &stored.repository,
            &stored.installation_id,
        ) {
            return Err(RemoteError::Rejected);
        }
        if stored.candidate != candidate
            || stored.commit != commit.as_str()
            || stored.base != base.as_str()
        {
            return Err(RemoteError::Rejected);
        }
        let base_commit_oid = GitCommitOid::parse(stored.base).ok_or(RemoteError::Rejected)?;
        let files = stored
            .files
            .into_iter()
            .map(|file| {
                base64::engine::general_purpose::STANDARD
                    .decode(file.content_base64)
                    .map(|content| GitFileObject {
                        path: file.path,
                        content,
                        executable: file.executable,
                    })
                    .map_err(|_| RemoteError::Rejected)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let total = files.iter().try_fold(0usize, |total, file| {
            (file.content.len() <= 1_048_576)
                .then(|| total.checked_add(file.content.len()))
                .flatten()
        });
        if files.is_empty()
            || files.len() > 100
            || total.is_none_or(|bytes| bytes > 8 * 1024 * 1024)
            || stored.commit_message.is_empty()
            || stored.commit_message.len() > 1024
        {
            return Err(RemoteError::Rejected);
        }
        Ok(Some(GitCommitTransfer {
            base_commit_oid,
            commit_message: stored.commit_message,
            files,
        }))
    }
}

impl FilesystemCandidateArtifacts {
    fn matches_binding(
        &self,
        organization: &str,
        run: &str,
        repository: &str,
        installation: &str,
    ) -> bool {
        organization == self.binding.organization_id.as_str()
            && run == self.binding.run_id
            && repository == self.binding.repository
            && installation == self.binding.installation_id
    }
}

fn bounded_nofollow_read(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("nonregular artifact"));
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(std::io::Error::other("oversized artifact"));
    }
    Ok(bytes)
}

/// Maps a provider-neutral Patch Proposals solver into the bounded repair loop.
pub struct RepairCandidateAdapter<S, A> {
    solver: S,
    brief: SolverBrief,
    artifacts: A,
    diagnostics: Option<Arc<dyn VisibleDiagnosticRepository>>,
}
impl<S, A> RepairCandidateAdapter<S, A> {
    /// Binds the solver to an approved public brief and artifact store.
    #[must_use]
    pub const fn new(solver: S, brief: SolverBrief, artifacts: A) -> Self {
        Self {
            solver,
            brief,
            artifacts,
            diagnostics: None,
        }
    }
    /// Adds the shared sanitized visible-feedback repository.
    #[must_use]
    pub fn with_diagnostics(
        mut self,
        diagnostics: impl VisibleDiagnosticRepository + 'static,
    ) -> Self {
        self.diagnostics = Some(Arc::new(diagnostics));
        self
    }
}
impl<S: SolverPort, A: CandidateArtifactRepository> CandidateSolver
    for RepairCandidateAdapter<S, A>
{
    fn propose(&mut self, request: &SolverRequest) -> Result<CandidateAttempt, ComponentError> {
        if self.brief.run_id.as_str() != request.run_id.as_str() {
            return Err(ComponentError);
        }
        let mut attempt_brief = self.brief.clone();
        if let Some(feedback) = &request.visible_feedback {
            let bytes = self
                .diagnostics
                .as_ref()
                .ok_or(ComponentError)?
                .get(&feedback.diagnostic, feedback.digest)?
                .ok_or(ComponentError)?;
            let text = std::str::from_utf8(&bytes).map_err(|_| ComponentError)?;
            attempt_brief.public_test_instructions.push(format!(
                "retry parent={} remaining_units={} diagnostic_digest={} diagnostic={text}",
                request
                    .parent_proposal
                    .as_ref()
                    .map_or("none", |value| value.as_str()),
                request.remaining_solver_units,
                feedback.digest.to_tagged_hex()
            ));
        }
        let output = self
            .solver
            .solve(&attempt_brief)
            .map_err(|_| ComponentError)?;
        let usage = output.usage;
        let mut attempt = ProposalAttempt::open(
            ContextQualifiedId::new("proposal", &format!("{:08}", request.attempt_number))
                .map_err(|_| ComponentError)?,
            attempt_brief,
        )
        .map_err(|_| ComponentError)?;
        let (patch, _) = attempt
            .accept(
                output,
                ContextQualifiedId::new("candidate", &format!("{:08}", request.attempt_number))
                    .map_err(|_| ComponentError)?,
            )
            .map_err(|_| ComponentError)?;
        let artifact =
            CandidatePatch::from_normalized(patch.as_bytes().to_vec(), patch.paths().clone());
        if artifact.digest() != patch.digest() {
            return Err(ComponentError);
        }
        self.artifacts.put(artifact)?;
        Ok(CandidateAttempt {
            number: request.attempt_number,
            proposal: attempt.id,
            patch_digest: patch.digest(),
            parent_proposal: request.parent_proposal.clone(),
            solver_units: usage.tokens,
            patch_bytes: u64::try_from(patch.as_bytes().len()).map_err(|_| ComponentError)?,
            changed_lines: patch.changed_lines(),
            cost_micros: usage.cost_micros,
            time_millis: usage.time_millis,
        })
    }
}

/// Verifier-owned sealed JSON input and append-only result directory.
#[derive(Clone)]
pub struct SealedFileVerificationStore {
    input: PathBuf,
    results: PathBuf,
}

/// Separate verifier command that produces candidate-bound sealed observations on demand.
pub struct CommandVerificationStore {
    runner: Mutex<Box<dyn ProcessPort + Send>>,
    request: ProcessRequest,
    results: PathBuf,
    artifacts: FilesystemCandidateArtifacts,
    immutable_base: GitCommitOid,
}
impl CommandVerificationStore {
    /// Constructs an isolated verifier command and append-only result sink.
    ///
    /// # Errors
    /// Rejects a relative verifier result directory.
    pub fn new(
        runner: impl ProcessPort + Send + 'static,
        request: ProcessRequest,
        results: PathBuf,
        artifacts: FilesystemCandidateArtifacts,
        immutable_base: GitCommitOid,
    ) -> Result<Self, AssessmentAdapterError> {
        if !results.is_absolute() {
            return Err(AssessmentAdapterError::EvidenceUnavailable);
        }
        Ok(Self {
            runner: Mutex::new(Box::new(runner)),
            request,
            results,
            artifacts,
            immutable_base,
        })
    }

    /// Reloads an exact assessment previously persisted by this verifier sink.
    ///
    /// # Errors
    /// Fails closed when the record is absent, malformed, or substituted.
    pub fn recorded(
        &self,
        expected: &CandidateAssessment,
    ) -> Result<CandidateAssessment, AssessmentAdapterError> {
        let path = assessment_path(&self.results, expected.assessment_digest);
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options
            .open(path)
            .map_err(|_| AssessmentAdapterError::EvidenceUnavailable)?;
        let size = file
            .metadata()
            .map_err(|_| AssessmentAdapterError::EvidenceUnavailable)?
            .len();
        if size > 65_536 {
            return Err(AssessmentAdapterError::EvidenceUnavailable);
        }
        let capacity =
            usize::try_from(size).map_err(|_| AssessmentAdapterError::EvidenceUnavailable)?;
        let mut bytes = Vec::with_capacity(capacity);
        std::io::Read::read_to_end(&mut file, &mut bytes)
            .map_err(|_| AssessmentAdapterError::EvidenceUnavailable)?;
        let canonical = serde_json::to_vec(expected)
            .map_err(|_| AssessmentAdapterError::EvidenceUnavailable)?;
        if bytes != canonical {
            return Err(AssessmentAdapterError::EvidenceMismatch);
        }
        Ok(expected.clone())
    }
}
impl AssessmentInputRepository for CommandVerificationStore {
    fn load(
        &self,
        candidate: Sha256Digest,
    ) -> Result<Option<CandidateAssessmentInput>, AssessmentAdapterError> {
        let patch = self
            .artifacts
            .get(candidate)
            .map_err(|_| AssessmentAdapterError::EvidenceUnavailable)?
            .ok_or(AssessmentAdapterError::EvidenceUnavailable)?;
        let mut request = self.request.clone();
        request.stdin = serde_json::to_vec(
            &serde_json::json!({
                "protocol":"cauterizer.verifier.v1",
                "candidate_digest":candidate,
                "candidate_patch_base64":base64::engine::general_purpose::STANDARD.encode(patch.as_bytes()),
                "changed_paths":patch.paths(),
                "immutable_base_revision":self.immutable_base.as_str(),
            }),
        )
        .map_err(|_| AssessmentAdapterError::EvidenceUnavailable)?;
        let result = self
            .runner
            .lock()
            .map_err(|_| AssessmentAdapterError::StorageUnavailable)?
            .execute(&request)
            .map_err(|_| AssessmentAdapterError::EvidenceUnavailable)?;
        if result.exit_code != Some(0) || result.timed_out || result.output_exceeded {
            return Err(AssessmentAdapterError::EvidenceUnavailable);
        }
        let input: CandidateAssessmentInput = serde_json::from_slice(&result.stdout)
            .map_err(|_| AssessmentAdapterError::EvidenceUnavailable)?;
        if input.patch.patch_digest != candidate {
            return Err(AssessmentAdapterError::EvidenceMismatch);
        }
        Ok(Some(input))
    }
}
impl AssessmentRecorder for CommandVerificationStore {
    fn record(&self, assessment: &CandidateAssessment) -> Result<(), AssessmentAdapterError> {
        record_assessment(&self.results, assessment)
    }
}

fn record_assessment(
    results: &Path,
    assessment: &CandidateAssessment,
) -> Result<(), AssessmentAdapterError> {
    std::fs::create_dir_all(results).map_err(|_| AssessmentAdapterError::StorageUnavailable)?;
    let path = assessment_path(results, assessment.assessment_digest);
    let bytes =
        serde_json::to_vec(assessment).map_err(|_| AssessmentAdapterError::StorageUnavailable)?;
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut file) => std::io::Write::write_all(&mut file, &bytes)
            .map_err(|_| AssessmentAdapterError::StorageUnavailable),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(_) => Err(AssessmentAdapterError::StorageUnavailable),
    }
}

fn assessment_path(results: &Path, digest: Sha256Digest) -> PathBuf {
    results.join(format!("{}.json", digest.to_tagged_hex().replace(':', "-")))
}
impl SealedFileVerificationStore {
    /// Requires absolute, distinct verifier-owned paths.
    ///
    /// # Errors
    /// Rejects relative or overlapping verifier paths.
    pub fn new(input: PathBuf, results: PathBuf) -> Result<Self, AssessmentAdapterError> {
        if !input.is_absolute() || !results.is_absolute() || input == results {
            return Err(AssessmentAdapterError::EvidenceUnavailable);
        }
        Ok(Self { input, results })
    }
}
impl AssessmentInputRepository for SealedFileVerificationStore {
    fn load(
        &self,
        _: Sha256Digest,
    ) -> Result<Option<CandidateAssessmentInput>, AssessmentAdapterError> {
        let bytes =
            std::fs::read(&self.input).map_err(|_| AssessmentAdapterError::EvidenceUnavailable)?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| AssessmentAdapterError::EvidenceUnavailable)
    }
}
impl AssessmentRecorder for SealedFileVerificationStore {
    fn record(&self, assessment: &CandidateAssessment) -> Result<(), AssessmentAdapterError> {
        record_assessment(&self.results, assessment)
    }
}

/// Narrow adapter from verifier assessment to repair-loop hidden verdicts.
pub struct RepairHiddenVerifier<R, W>(pub HiddenAssessmentAdapter<R, W>);
impl<R: AssessmentInputRepository, W: AssessmentRecorder> HiddenVerifier
    for RepairHiddenVerifier<R, W>
{
    fn verify(&mut self, candidate: &CandidateAttempt) -> Result<HiddenDecision, ComponentError> {
        self.0
            .verify(candidate.patch_digest)
            .map(|verdict| match verdict {
                AssessmentVerdict::VerifiedForFixture => HiddenDecision::Verified,
                AssessmentVerdict::Rejected => HiddenDecision::Rejected,
                AssessmentVerdict::Inconclusive => HiddenDecision::Inconclusive,
                AssessmentVerdict::NonConformant => HiddenDecision::NonConformant,
            })
            .map_err(|_| ComponentError)
    }
}

/// Applies candidates in isolated Git worktrees, runs visible checks, and retains real commits.
pub struct PublishingVisibleEvaluator<A> {
    artifacts: A,
    checkout: PathBuf,
    base: GitCommitOid,
    checks: Vec<GitVisibleCheck>,
    published: BTreeMap<String, PublishedCommit>,
    diagnostics: Option<Arc<dyn VisibleDiagnosticRepository>>,
    executor: Option<Box<dyn cauterizer_git_workspace_publisher::CandidateCheckExecutor>>,
}
impl<A: CandidateArtifactRepository> PublishingVisibleEvaluator<A> {
    /// Constructs a visible evaluator bound to an immutable checkout and branch.
    #[must_use]
    pub fn new(
        artifacts: A,
        checkout: PathBuf,
        base: GitCommitOid,
        _branch: String,
        checks: Vec<GitVisibleCheck>,
    ) -> Self {
        Self {
            artifacts,
            checkout,
            base,
            checks,
            published: BTreeMap::new(),
            diagnostics: None,
            executor: None,
        }
    }
    /// Requires visible checks to run through the supplied isolation boundary.
    #[must_use]
    pub fn with_check_executor(
        mut self,
        executor: impl cauterizer_git_workspace_publisher::CandidateCheckExecutor + 'static,
    ) -> Self {
        self.executor = Some(Box::new(executor));
        self
    }
    /// Adds the shared sanitized visible-feedback repository.
    #[must_use]
    pub fn with_diagnostics(
        mut self,
        diagnostics: impl VisibleDiagnosticRepository + 'static,
    ) -> Self {
        self.diagnostics = Some(Arc::new(diagnostics));
        self
    }
    /// Takes the exact locally published commit for a candidate.
    pub fn take_published(&mut self, digest: Sha256Digest) -> Option<PublishedCommit> {
        self.published.remove(&digest.to_tagged_hex())
    }
}
impl<A: CandidateArtifactRepository> VisibleEvaluator for PublishingVisibleEvaluator<A> {
    fn evaluate(
        &mut self,
        candidate: &CandidateAttempt,
    ) -> Result<RepairVisibleCheck, ComponentError> {
        let patch = self
            .artifacts
            .get(candidate.patch_digest)?
            .ok_or(ComponentError)?;
        let result = if let Some(executor) = &mut self.executor {
            cauterizer_git_workspace_publisher::evaluate_candidate_with(
                &self.checkout,
                &self.base,
                &patch,
                &self.checks,
                executor.as_mut(),
            )
        } else {
            cauterizer_git_workspace_publisher::evaluate_candidate(
                &self.checkout,
                &self.base,
                &patch,
                &self.checks,
            )
        };
        match result {
            Ok(()) => Ok(RepairVisibleCheck::Passed),
            Err(cauterizer_git_workspace_publisher::PublishError::CheckFailed) => {
                let bytes = b"visible checks failed";
                let diagnostic =
                    ContextQualifiedId::new("diagnostic", &format!("{:08}", candidate.number))
                        .map_err(|_| ComponentError)?;
                let digest = Sha256Digest::of_bytes(bytes);
                self.diagnostics.as_ref().ok_or(ComponentError)?.put(
                    diagnostic.clone(),
                    digest,
                    bytes.to_vec(),
                )?;
                Ok(RepairVisibleCheck::Failed(VisibleFeedback {
                    diagnostic,
                    digest,
                }))
            }
            Err(_) => Err(ComponentError),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cauterizer_patch_proposals::domain::{
        ProposalBudget, ProposalError, SolverOutput, SolverUsage,
    };
    use cauterizer_remediation_runs::domain::RemediationRunId;
    use cauterizer_syntax::identifiers::OrganizationId;
    use std::collections::BTreeSet;

    fn verified_input(candidate: Sha256Digest) -> CandidateAssessmentInput {
        use cauterizer_verification::domain::assessment::{
            AssessmentPolicy, ExecutionObservation, ExecutionOutcome, ObservationRole,
            PatchObservation,
        };
        let mut observations = Vec::new();
        for repetition in 1..=2 {
            for (role, outcome, count) in [
                (
                    ObservationRole::BaselineVulnerable,
                    ExecutionOutcome::Failed,
                    1,
                ),
                (ObservationRole::GoldControl, ExecutionOutcome::Passed, 20),
                (
                    ObservationRole::CandidateHidden,
                    ExecutionOutcome::Passed,
                    4,
                ),
                (
                    ObservationRole::CandidateRegression,
                    ExecutionOutcome::Passed,
                    20,
                ),
            ] {
                observations.push(ExecutionObservation {
                    id: ContextQualifiedId::new(
                        "observation",
                        &format!("{:08}", observations.len() + 1),
                    )
                    .unwrap(),
                    role,
                    repetition,
                    outcome,
                    test_count: count,
                    result_digest: Sha256Digest::of_bytes(format!("{role:?}-{outcome:?}-{count}")),
                    conformant: true,
                });
            }
        }
        CandidateAssessmentInput {
            organization_id: OrganizationId::new("organization1").unwrap(),
            run_id: ContextQualifiedId::new("run", "00000001").unwrap(),
            policy: AssessmentPolicy {
                repetitions: 2,
                max_changed_lines: 10,
                allowed_path_prefixes: vec!["src/".into()],
                forbidden_paths: BTreeSet::new(),
            },
            patch: PatchObservation {
                patch_digest: candidate,
                changed_paths: vec!["src/lib.rs".into()],
                changed_lines: 1,
            },
            observations,
        }
    }

    #[test]
    fn verified_delivery_evidence_rejects_scope_candidate_and_assessment_substitution() {
        let candidate = Sha256Digest::of_bytes(b"candidate");
        let input = verified_input(candidate);
        let assessment = CandidateAssessmentEngine::assess(&input);
        let organization = input.organization_id.clone();
        let run = input.run_id.clone();
        assert!(
            VerifiedDeliveryEvidence::from_recorded(
                organization.clone(),
                run.clone(),
                candidate,
                &input,
                &assessment
            )
            .is_ok()
        );
        assert!(
            VerifiedDeliveryEvidence::from_recorded(
                OrganizationId::new("organization2").unwrap(),
                run.clone(),
                candidate,
                &input,
                &assessment
            )
            .is_err()
        );
        assert!(
            VerifiedDeliveryEvidence::from_recorded(
                organization.clone(),
                ContextQualifiedId::new("run", "00000002").unwrap(),
                candidate,
                &input,
                &assessment
            )
            .is_err()
        );
        assert!(
            VerifiedDeliveryEvidence::from_recorded(
                organization,
                run,
                Sha256Digest::of_bytes(b"substitute"),
                &input,
                &assessment
            )
            .is_err()
        );
        let mut tampered = assessment;
        tampered.assessment_digest = Sha256Digest::of_bytes(b"tampered");
        assert!(
            VerifiedDeliveryEvidence::from_recorded(
                input.organization_id.clone(),
                input.run_id.clone(),
                candidate,
                &input,
                &tampered
            )
            .is_err()
        );
    }

    fn artifact_binding() -> ArtifactBinding {
        ArtifactBinding {
            organization_id: OrganizationId::new("organization1").unwrap(),
            run_id: "run:00000001".into(),
            repository: "acme/widget".into(),
            installation_id: "installation:00000001".into(),
        }
    }

    struct CapturingSolver(Arc<Mutex<Vec<u8>>>);
    impl SolverPort for CapturingSolver {
        fn solve(&mut self, brief: &SolverBrief) -> Result<SolverOutput, ProposalError> {
            *self.0.lock().unwrap() = serde_json::to_vec(brief).unwrap();
            Ok(SolverOutput {
                patch: b"--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-a\n+b\n".to_vec(),
                rationale: Some("public failure repair".into()),
                usage: SolverUsage {
                    tokens: 2,
                    cost_micros: 3,
                    time_millis: 4,
                },
                solver_provenance: Sha256Digest::of_bytes(b"solver"),
            })
        }
    }
    fn brief() -> SolverBrief {
        SolverBrief {
            organization_id: OrganizationId::new("organization1").unwrap(),
            run_id: ContextQualifiedId::new("run", "00000001").unwrap(),
            problem: "public problem".into(),
            source_digest: Sha256Digest::of_bytes(b"source"),
            public_test_instructions: vec!["public test".into()],
            allowed_paths: BTreeSet::from(["src/lib.rs".into()]),
            allowed_tools: BTreeSet::from(["patch".into()]),
            budget: ProposalBudget {
                attempts: 1,
                tokens: 10,
                cost_micros: 10,
                time_millis: 10,
                paths: 1,
                patch_bytes: 1024,
                changed_lines: 10,
            },
            memory_namespace: None,
        }
    }

    #[test]
    fn candidate_artifact_preserves_exact_bytes_paths_and_digest() {
        let bytes = b"--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-a\n+b\n".to_vec();
        let patch =
            CandidatePatch::from_normalized(bytes.clone(), BTreeSet::from(["src/lib.rs".into()]));
        let digest = patch.digest();
        let store = InMemoryCandidateArtifacts::default();
        store.put(patch).unwrap();
        let loaded = store.get(digest).unwrap().unwrap();
        assert_eq!(loaded.digest(), Sha256Digest::of_bytes(&bytes));
        assert_eq!(loaded.as_bytes(), bytes);
        assert_eq!(loaded.paths(), &BTreeSet::from(["src/lib.rs".into()]));
        assert!(
            store
                .get(Sha256Digest::of_bytes(b"other"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn repair_solver_retains_exact_patch_and_receives_no_hidden_input() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let artifacts = InMemoryCandidateArtifacts::default();
        let mut solver = RepairCandidateAdapter::new(
            CapturingSolver(captured.clone()),
            brief(),
            artifacts.clone(),
        );
        let candidate = solver
            .propose(&SolverRequest {
                run_id: RemediationRunId::new("00000001").unwrap(),
                baseline: ContextQualifiedId::new("observation", "00000001").unwrap(),
                parent_proposal: None,
                visible_feedback: None,
                attempt_number: 1,
                remaining_solver_units: 10,
            })
            .unwrap();
        assert_eq!(
            artifacts
                .get(candidate.patch_digest)
                .unwrap()
                .unwrap()
                .digest(),
            candidate.patch_digest
        );
        let public_request = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
        assert!(!public_request.contains("verifier"));
        assert!(!public_request.contains("hidden"));
    }

    #[test]
    fn filesystem_store_survives_restart_and_rejects_identity_substitution() {
        let directory = tempfile::tempdir().unwrap();
        let binding = artifact_binding();
        let store = FilesystemCandidateArtifacts::new(directory.path(), binding.clone()).unwrap();
        let bytes = b"--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-a\n+b\n".to_vec();
        let patch = CandidatePatch::from_normalized(bytes, BTreeSet::from(["src/lib.rs".into()]));
        let candidate = patch.digest();
        store.put(patch).unwrap();
        let commit = GitCommitOid::parse("0123456789abcdef0123456789abcdef01234567").unwrap();
        let base = GitCommitOid::parse("1111111111111111111111111111111111111111").unwrap();
        let transfer = GitCommitTransfer {
            base_commit_oid: base.clone(),
            commit_message: "Automated vulnerability remediation".into(),
            files: vec![GitFileObject {
                path: "src/lib.rs".into(),
                content: b"b\n".to_vec(),
                executable: false,
            }],
        };
        store.put_transfer(candidate, &commit, &transfer).unwrap();
        let restarted =
            FilesystemCandidateArtifacts::new(directory.path(), binding.clone()).unwrap();
        assert_eq!(
            restarted.get(candidate).unwrap().unwrap().digest(),
            candidate
        );
        assert_eq!(
            restarted.find(&binding, candidate, &commit, &base).unwrap(),
            Some(transfer)
        );
        let other = GitCommitOid::parse("2222222222222222222222222222222222222222").unwrap();
        assert_eq!(
            restarted.find(&binding, candidate, &other, &base),
            Err(RemoteError::Rejected)
        );
        let mut foreign = binding.clone();
        foreign.organization_id = OrganizationId::new("organization2").unwrap();
        assert_eq!(
            restarted.find(&foreign, candidate, &commit, &base),
            Err(RemoteError::Rejected)
        );
        assert_eq!(
            restarted
                .find(&binding, Sha256Digest::of_bytes(b"missing"), &commit, &base)
                .unwrap(),
            None
        );
    }

    #[test]
    fn concurrent_conflicting_transfer_writers_never_overwrite() {
        let directory = tempfile::tempdir().unwrap();
        let store =
            FilesystemCandidateArtifacts::new(directory.path(), artifact_binding()).unwrap();
        let candidate = Sha256Digest::of_bytes(b"candidate");
        let commit = GitCommitOid::parse("0123456789abcdef0123456789abcdef01234567").unwrap();
        let base = GitCommitOid::parse("1111111111111111111111111111111111111111").unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = [b"left".to_vec(), b"right".to_vec()]
            .into_iter()
            .map(|content| {
                let store = store.clone();
                let commit = commit.clone();
                let base = base.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    store.put_transfer(
                        candidate,
                        &commit,
                        &GitCommitTransfer {
                            base_commit_oid: base,
                            commit_message: "Automated vulnerability remediation".into(),
                            files: vec![GitFileObject {
                                path: "src/lib.rs".into(),
                                content,
                                executable: false,
                            }],
                        },
                    )
                })
            })
            .collect();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
    }

    #[test]
    fn maximum_transfer_roundtrips_with_bounded_encoding() {
        let directory = tempfile::tempdir().unwrap();
        let binding = artifact_binding();
        let store = FilesystemCandidateArtifacts::new(directory.path(), binding.clone()).unwrap();
        let candidate = Sha256Digest::of_bytes(b"max-candidate");
        let commit = GitCommitOid::parse("0123456789abcdef0123456789abcdef01234567").unwrap();
        let base = GitCommitOid::parse("1111111111111111111111111111111111111111").unwrap();
        let transfer = GitCommitTransfer {
            base_commit_oid: base.clone(),
            commit_message: "bounded maximum".into(),
            files: (0..8)
                .map(|index| GitFileObject {
                    path: format!("src/file-{index}.bin"),
                    content: vec![u8::try_from(index).unwrap(); 1_048_576],
                    executable: false,
                })
                .collect(),
        };
        store.put_transfer(candidate, &commit, &transfer).unwrap();
        assert_eq!(
            store.find(&binding, candidate, &commit, &base).unwrap(),
            Some(transfer)
        );
    }
}
