//! Versioned provider-neutral SCM delivery contracts.

use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{IdempotencyKey, OrganizationId};
use std::collections::BTreeSet;

use crate::domain::ScmCapability;

/// Validated raw Git commit object ID (SHA-1 or SHA-256 repository format).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitCommitOid(String);

impl GitCommitOid {
    /// Parses a raw lowercase hexadecimal Git object ID.
    #[must_use]
    pub fn parse(value: impl Into<String>) -> Option<Self> {
        let value = value.into();
        ((value.len() == 40 || value.len() == 64)
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
        .then_some(Self(value))
    }

    /// Returns the raw untagged object ID accepted by GitHub's Git data API.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One complete changed file uploaded through a provider Git object API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitFileObject {
    /// Validated repository-relative path.
    pub path: String,
    /// Complete non-secret file bytes.
    pub content: Vec<u8>,
    /// Exact Git tree mode for a regular file.
    pub executable: bool,
}

/// Material required to reproduce a candidate commit in a remote object database.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitCommitTransfer {
    /// Existing immutable remote parent commit.
    pub base_commit_oid: GitCommitOid,
    /// Exact bounded message used to reproduce the local commit object.
    pub commit_message: String,
    /// Complete changed files; unchanged entries are inherited from the base tree.
    pub files: Vec<GitFileObject>,
}

/// One safe desired mutation. Provider-specific objects never cross this boundary.
#[allow(missing_docs)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScmMutation {
    /// Create a tracking issue.
    CreateIssue { title: String, body: String },
    /// Update an owned tracking issue.
    UpdateIssue {
        remote_id: String,
        title: String,
        body: String,
    },
    /// Create a remediation branch at an immutable revision.
    CreateBranch {
        branch: String,
        base_revision: String,
    },
    /// Push an immutable candidate tree/commit to an owned branch.
    PushCandidateCommit {
        branch: String,
        /// Cauterizer evidence identity for the candidate patch.
        candidate_digest: Sha256Digest,
        /// Existing Git commit object to which the owned ref will advance.
        commit_oid: GitCommitOid,
        /// Remote object material when the commit is not already present remotely.
        transfer: Option<GitCommitTransfer>,
    },
    /// Create a pull request targeting a human-reviewed base branch.
    CreatePullRequest {
        branch: String,
        base_branch: String,
        title: String,
        body: String,
    },
    /// Update an owned pull request.
    UpdatePullRequest {
        remote_id: String,
        title: String,
        body: String,
    },
    /// Attach a concise evidence summary, never verifier secrets.
    PostEvidenceSummary {
        remote_id: String,
        summary: String,
        evidence_digest: Sha256Digest,
    },
}

impl ScmMutation {
    /// Capability required by this operation.
    #[must_use]
    pub const fn capability(&self) -> ScmCapability {
        match self {
            Self::CreateIssue { .. } => ScmCapability::CreateIssue,
            Self::UpdateIssue { .. } => ScmCapability::UpdateIssue,
            Self::CreateBranch { .. } => ScmCapability::CreateBranch,
            Self::PushCandidateCommit { .. } => ScmCapability::PushCandidateCommit,
            Self::CreatePullRequest { .. } => ScmCapability::CreatePullRequest,
            Self::UpdatePullRequest { .. } => ScmCapability::UpdatePullRequest,
            Self::PostEvidenceSummary { .. } => ScmCapability::PostEvidenceSummary,
        }
    }

    /// Branch affected by branch-scoped authority.
    #[must_use]
    pub fn branch(&self) -> Option<&str> {
        match self {
            Self::CreateBranch { branch, .. }
            | Self::PushCandidateCommit { branch, .. }
            | Self::CreatePullRequest { branch, .. } => Some(branch),
            _ => None,
        }
    }
}

/// Replay-safe desired-state request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryRequest {
    /// Authenticated tenant requesting delivery.
    pub organization_id: OrganizationId,
    /// Exact installation grant to use.
    pub installation_id: String,
    /// Exact repository slug.
    pub repository: String,
    /// Stable logical object identity used to reconcile after ambiguous failures.
    pub correlation_key: String,
    /// Retry identity.
    pub idempotency_key: IdempotencyKey,
    /// Digest of the complete canonical request.
    pub request_digest: Sha256Digest,
    /// Safe desired mutation.
    pub mutation: ScmMutation,
}

/// Provider-neutral remote object receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteObject {
    /// Opaque provider object ID.
    pub remote_id: String,
    /// Stable human-facing URL.
    pub url: String,
    /// Digest of desired state last applied by this connector.
    pub applied_digest: Sha256Digest,
}

/// Whether delivery mutated remote state or recovered a prior mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryDisposition {
    /// A new remote object was created.
    Created,
    /// Existing remote state was updated.
    Updated,
    /// The same idempotency key and digest returned its prior receipt.
    Replayed,
    /// A different retry key found the already-applied desired state.
    Reconciled,
}

/// Successful delivery receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryReceipt {
    /// How the connector satisfied the request.
    pub disposition: DeliveryDisposition,
    /// Stable remote object identity and applied-state digest.
    pub object: RemoteObject,
}
/// Immutable, already-normalized patch handed to the local SCM publisher.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidatePatch {
    bytes: Vec<u8>,
    paths: BTreeSet<String>,
    digest: Sha256Digest,
}

impl CandidatePatch {
    /// Creates the cross-context publication contract.
    ///
    /// The proposal context remains responsible for normalization; the
    /// publisher independently checks the paths against the checkout.
    #[must_use]
    pub fn from_normalized(bytes: Vec<u8>, paths: BTreeSet<String>) -> Self {
        let digest = Sha256Digest::of_bytes(&bytes);
        Self {
            bytes,
            paths,
            digest,
        }
    }

    /// Canonical unified-diff bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Canonical changed paths.
    #[must_use]
    pub fn paths(&self) -> &BTreeSet<String> {
        &self.paths
    }

    /// Candidate content identity.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}
