//! Provider-neutral integration manifests and least-authority installation grants.

use std::collections::BTreeSet;
use std::fmt;

use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
use serde::{Deserialize, Serialize};

/// The complete set of SCM mutations Cauterizer can request.
///
/// Deliberately absent are merge, approval, release, deployment, repository
/// administration, and protected-branch mutation capabilities. Consequently a
/// valid manifest or grant cannot express those authorities.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScmCapability {
    /// Create a remediation tracking issue.
    CreateIssue,
    /// Update an issue previously owned by this installation.
    UpdateIssue,
    /// Create a namespaced remediation branch.
    CreateBranch,
    /// Push a candidate commit to an owned remediation branch.
    PushCandidateCommit,
    /// Open a pull request for human review.
    CreatePullRequest,
    /// Update a pull request previously owned by this installation.
    UpdatePullRequest,
    /// Post a bounded evidence summary to an owned issue or pull request.
    PostEvidenceSummary,
}

/// Capabilities a provider-neutral connector implementation declares.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CapabilityManifest {
    /// Stable connector implementation identifier.
    pub connector_id: String,
    /// Supported, safe operations.
    pub capabilities: BTreeSet<ScmCapability>,
}

impl CapabilityManifest {
    /// Constructs a validated manifest.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InvalidManifest`] for a blank connector identity
    /// or an empty capability set.
    pub fn new(
        connector_id: impl Into<String>,
        capabilities: impl IntoIterator<Item = ScmCapability>,
    ) -> Result<Self, PolicyError> {
        let manifest = Self {
            connector_id: connector_id.into(),
            capabilities: capabilities.into_iter().collect(),
        };
        if manifest.connector_id.trim().is_empty() || manifest.capabilities.is_empty() {
            return Err(PolicyError::InvalidManifest);
        }
        Ok(manifest)
    }
}

/// Installation-time authority, scoped to tenant, repositories, and branch namespace.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InstallationGrant {
    /// Context-owned immutable installation identity.
    pub installation_id: ContextQualifiedId,
    /// Owning tenant.
    pub organization_id: OrganizationId,
    /// Exact provider-neutral repository slugs (`owner/name`).
    pub repositories: BTreeSet<String>,
    /// Branch prefix under which the connector may create and push branches.
    pub branch_prefix: String,
    /// Exact pull-request target branches this installation may select.
    pub allowed_target_branches: BTreeSet<String>,
    /// Provider default branch, which can never be used as a remediation source.
    pub default_branch: String,
    /// Known protected branches which can never be used as remediation sources.
    pub protected_branches: BTreeSet<String>,
    /// Subset of the connector manifest granted by an administrator.
    pub capabilities: BTreeSet<ScmCapability>,
    /// Optional exclusive Unix-second expiry.
    pub expires_at_unix: Option<u64>,
}

impl InstallationGrant {
    /// Validates grant syntax and ensures it cannot exceed connector support.
    ///
    /// # Errors
    ///
    /// Returns a stable policy error for malformed scope or capabilities not
    /// declared by the connector manifest.
    pub fn validate(&self, manifest: &CapabilityManifest) -> Result<(), PolicyError> {
        if self.repositories.is_empty()
            || self
                .repositories
                .iter()
                .any(|repository| !valid_repository(repository))
            || !valid_branch_prefix(&self.branch_prefix)
            || !valid_branch_name(&self.default_branch)
            || self.allowed_target_branches.is_empty()
            || self
                .allowed_target_branches
                .iter()
                .chain(self.protected_branches.iter())
                .any(|branch| !valid_branch_name(branch))
            || self.capabilities.is_empty()
        {
            return Err(PolicyError::InvalidGrant);
        }
        if !self.capabilities.is_subset(&manifest.capabilities) {
            return Err(PolicyError::CapabilityNotSupported);
        }
        Ok(())
    }

    /// Deny-default authorization for one exact operation.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::GrantExpired`] for an expired grant and
    /// [`PolicyError::Denied`] for a repository, branch, or capability mismatch.
    pub fn authorize(
        &self,
        repository: &str,
        branch: Option<&str>,
        capability: ScmCapability,
        now_unix: u64,
    ) -> Result<(), PolicyError> {
        if self
            .expires_at_unix
            .is_some_and(|expiry| now_unix >= expiry)
        {
            return Err(PolicyError::GrantExpired);
        }
        if !self.repositories.contains(repository) || !self.capabilities.contains(&capability) {
            return Err(PolicyError::Denied);
        }
        if matches!(
            capability,
            ScmCapability::CreateBranch
                | ScmCapability::PushCandidateCommit
                | ScmCapability::CreatePullRequest
        ) && branch.is_none_or(|name| {
            !name.starts_with(&self.branch_prefix)
                || name == self.default_branch
                || self.protected_branches.contains(name)
        }) {
            return Err(PolicyError::Denied);
        }
        Ok(())
    }

    /// Authorizes an exact pull-request target independently of its source.
    ///
    /// # Errors
    /// Returns [`PolicyError::Denied`] when the target is outside the grant allowlist.
    pub fn authorize_target_branch(&self, branch: &str) -> Result<(), PolicyError> {
        if self.allowed_target_branches.contains(branch) {
            Ok(())
        } else {
            Err(PolicyError::Denied)
        }
    }
}

fn valid_repository(value: &str) -> bool {
    let mut pieces = value.split('/');
    matches!((pieces.next(), pieces.next(), pieces.next()), (Some(a), Some(b), None) if valid_slug(a) && valid_slug(b))
}

fn valid_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_branch_prefix(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('/')
        && !value.contains("..")
        && !value.contains('~')
        && !value.contains('^')
        && !value.contains(':')
        && !value.contains(' ')
        && value.ends_with('/')
}

fn valid_branch_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains("..")
        && !value.contains('~')
        && !value.contains('^')
        && !value.contains(':')
        && !value.contains(' ')
}

/// Stable policy rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    /// Connector manifest is empty or malformed.
    InvalidManifest,
    /// Installation scope is empty or malformed.
    InvalidGrant,
    /// Grant asks for a capability the connector does not declare.
    CapabilityNotSupported,
    /// Requested mutation is outside the installation grant.
    Denied,
    /// Installation grant is no longer active.
    GrantExpired,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidManifest => "invalid_connector_manifest",
            Self::InvalidGrant => "invalid_installation_grant",
            Self::CapabilityNotSupported => "connector_capability_not_supported",
            Self::Denied => "scm_operation_denied",
            Self::GrantExpired => "installation_grant_expired",
        })
    }
}

impl std::error::Error for PolicyError {}
