//! Explicit-file worker command boundary.

use std::path::{Path, PathBuf};

use crate::production::{
    CandidateArtifactRepository, CommandVerificationStore, FilesystemCandidateArtifacts,
    InMemoryVisibleDiagnostics, PublishingVisibleEvaluator, RepairCandidateAdapter,
    RepairHiddenVerifier, VerifiedDeliveryEvidence,
};
use crate::{InMemoryInstallationGrants, ScmGateway, SystemEpochClock};
use cauterizer_external_actions::application::RemoteActionGateway;
use cauterizer_external_actions::domain::{
    ActionCapability, DeliveryAttestation, DeliveryStatus, ExternalActionDelivery,
    ExternalActionDeliveryId, ExternalActionError, ExternalActionGrantId, ExternalActionRequest,
};
use cauterizer_external_actions_postgres::{
    MIGRATOR, PostgresExternalActionRepository, PostgresExternalActionService,
};
use cauterizer_git_workspace_publisher::{PublishedCommit, VisibleCheck as GitVisibleCheck};
use cauterizer_integration_management::application::ConnectorError;
use cauterizer_integration_management::contracts::GitCommitOid;
use cauterizer_integration_management::domain::{InstallationGrant, ScmCapability};
use cauterizer_integration_management_github::{
    GitHubConnector, ReqwestTransport, Secret, SecretProvider,
};
use cauterizer_patch_proposals::domain::{ProposalBudget, SolverBrief};
#[cfg(test)]
use cauterizer_patch_proposals_coding_agent::LocalCommandRunner;
use cauterizer_patch_proposals_coding_agent::{CodingAgentAdapter, ProcessRequest};
#[cfg(not(test))]
use cauterizer_patch_proposals_coding_agent::{OciIsolation, OciProcessRunner, ProcessPort};
use cauterizer_remediation_runs::application::agentic::{
    CandidateAttempt, RepairBudget, RepairLoop, RepairOutcome, RepairRequest, RepairTranscript,
};
use cauterizer_remediation_runs::application::review_delivery::{
    AsyncReviewDeliveryRepository, GenerationClaim, GenerationLeaseRepository, PlanKind,
    PlannedAction, PlannedSubject, ReviewDelivery, ReviewDeliveryKey, ReviewDeliveryPlan,
    ReviewStage, StageCheckpoint, VersionedDelivery,
};
use cauterizer_remediation_runs::domain::RemediationRunId;
use cauterizer_remediation_runs_postgres::{
    PostgresReviewDeliveryRepository, REVIEW_DELIVERY_MIGRATOR,
};
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::IdempotencyKey;
use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
use cauterizer_verification::application::assessment::HiddenAssessmentAdapter;
use cauterizer_verification::domain::assessment::{CandidateAssessment, CandidateAssessmentInput};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use std::collections::BTreeMap;

/// Exact command without shell interpolation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandSpec {
    /// Executable name or path.
    pub program: String,
    /// Exact argument vector.
    #[serde(default)]
    pub arguments: Vec<String>,
}

/// Hard workflow budgets.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationBudgets {
    /// Candidate attempt limit.
    pub attempts: u32,
    /// Solver usage limit.
    pub solver_units: u64,
    /// Per-process timeout.
    pub command_timeout_seconds: u64,
    /// Per-stream output limit.
    pub output_bytes: usize,
    /// Maximum provider spend in micros.
    pub spend_micros: u64,
    /// Maximum normalized patch bytes.
    pub patch_bytes: u64,
    /// Maximum changed source lines.
    pub changed_lines: u64,
}

/// Mandatory OCI isolation identities for each untrusted execution role.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeIsolationConfig {
    /// Absolute Podman-compatible runtime executable.
    pub runtime: PathBuf,
    /// Pinned solver image digest.
    pub solver_image: String,
    /// Pinned verifier image digest, distinct from the solver image.
    pub verifier_image: String,
    /// Pinned visible-check image digest.
    pub visible_image: String,
    /// Numeric non-root solver UID/GID.
    pub solver_user: String,
    /// Numeric non-root verifier UID/GID.
    pub verifier_user: String,
    /// Numeric non-root visible-check UID/GID.
    pub visible_user: String,
    /// OCI memory cap.
    pub memory: String,
    /// OCI CPU cap.
    pub cpus: String,
    /// OCI process cap.
    pub pids_limit: u32,
}

/// Secret-free worker configuration. Credential values are environment references only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationConfig {
    /// Stable worker identity used for fenced generation leases.
    pub worker_id: String,
    /// Upstream-owned remediation run identifier.
    pub run_id: String,
    /// Upstream-owned immutable baseline observation reference.
    pub baseline_observation: String,
    /// Explicit prior candidate to replace; never inferred from another invocation.
    #[serde(default)]
    pub supersedes_candidate_digest: Option<String>,
    /// Tenant owning the preinstalled grant.
    pub organization_id: String,
    /// Preinstalled External Actions grant identifier.
    pub external_grant_id: String,
    /// Separate verifier workspace root.
    pub verifier_root: PathBuf,
    /// Exact verifier executable and arguments, never exposed to the solver.
    pub verifier: CommandSpec,
    /// Verifier-owned append-only assessment result directory.
    pub verifier_results_path: PathBuf,
    /// Durable normalized candidate and commit-transfer artifact directory.
    pub candidate_artifacts_path: PathBuf,
    /// Public solver problem statement.
    pub solver_problem: String,
    /// Digest of the public source bundle.
    pub source_digest: String,
    /// Exact repository-relative paths the solver may modify.
    pub allowed_paths: Vec<String>,
    /// Exact public tools exposed to the solver.
    pub allowed_tools: Vec<String>,
    /// Existing clean repository checkout.
    pub checkout_path: PathBuf,
    /// Immutable base commit revision.
    pub base_revision: String,
    /// Namespaced remediation branch.
    pub remediation_branch: String,
    /// Exact pull-request target branch.
    pub pull_request_base_branch: String,
    /// Provider-neutral coding-agent process.
    pub solver: CommandSpec,
    /// Ordered public build/lint/test commands.
    pub visible_commands: Vec<CommandSpec>,
    /// Hard workflow limits.
    pub budgets: AutomationBudgets,
    /// Mandatory container isolation policy.
    pub runtime_isolation: RuntimeIsolationConfig,
    /// GitHub installation identifier.
    pub github_installation: String,
    /// Exact `owner/repository` slug.
    pub github_repository: String,
    /// Environment variable containing the `PostgreSQL` URL.
    pub postgres_url_env: String,
    /// Environment variable containing the GitHub token.
    pub github_token_env: String,
    /// When true, validate and describe the workflow without mutations.
    pub dry_run: bool,
}

impl AutomationConfig {
    /// Loads and validates a secret-free JSON file.
    ///
    /// # Errors
    /// Rejects unreadable, malformed, unsafe, or secret-bearing configuration.
    pub fn load(path: &Path) -> Result<Self, CommandError> {
        let bytes = std::fs::read(path).map_err(|_| CommandError::ConfigurationUnavailable)?;
        let config: Self =
            serde_json::from_slice(&bytes).map_err(|_| CommandError::InvalidConfiguration)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), CommandError> {
        if !self.checkout_path.is_absolute()
            || GitCommitOid::parse(&self.base_revision).is_none()
            || !self.remediation_branch.starts_with("cauterizer/")
            || self.remediation_branch.contains("..")
            || self.solver.program.is_empty()
            || self.visible_commands.is_empty()
            || self
                .visible_commands
                .iter()
                .any(|item| item.program.is_empty())
            || self.budgets.attempts == 0
            || self.budgets.solver_units == 0
            || self.budgets.command_timeout_seconds == 0
            || self.budgets.output_bytes == 0
            || self.budgets.spend_micros == 0
            || self.budgets.patch_bytes == 0
            || self.budgets.changed_lines == 0
            || !self.runtime_isolation.runtime.is_absolute()
            || self.runtime_isolation.pids_limit == 0
            || self.runtime_isolation.memory.is_empty()
            || self.runtime_isolation.cpus.is_empty()
            || !pinned_image(&self.runtime_isolation.solver_image)
            || !pinned_image(&self.runtime_isolation.verifier_image)
            || !pinned_image(&self.runtime_isolation.visible_image)
            || self.runtime_isolation.solver_image == self.runtime_isolation.verifier_image
            || !non_root_user(&self.runtime_isolation.solver_user)
            || !non_root_user(&self.runtime_isolation.verifier_user)
            || !non_root_user(&self.runtime_isolation.visible_user)
            || !repository_slug(&self.github_repository)
            || self.organization_id.parse::<OrganizationId>().is_err()
            || self.worker_id.len() < 8
            || self.worker_id.len() > 64
            || !self
                .worker_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || self.run_id.parse::<ContextQualifiedId>().is_err()
            || self
                .baseline_observation
                .parse::<ContextQualifiedId>()
                .is_err()
            || ExternalActionGrantId::new(&self.external_grant_id).is_err()
            || !self.verifier_results_path.is_absolute()
            || !self.verifier_root.is_absolute()
            || self.verifier.program.is_empty()
            || !self.candidate_artifacts_path.is_absolute()
            || self.solver_problem.trim().is_empty()
            || self.source_digest.parse::<Sha256Digest>().is_err()
            || self.allowed_paths.is_empty()
            || self.allowed_tools.is_empty()
            || !safe_branch(&self.pull_request_base_branch)
            || !env_name(&self.postgres_url_env)
            || !env_name(&self.github_token_env)
            || self.postgres_url_env == self.github_token_env
        {
            return Err(CommandError::InvalidConfiguration);
        }
        if self
            .supersedes_candidate_digest
            .as_deref()
            .is_some_and(|value| value.parse::<Sha256Digest>().is_err())
        {
            return Err(CommandError::InvalidConfiguration);
        }
        let serialized =
            serde_json::to_string(self).map_err(|_| CommandError::InvalidConfiguration)?;
        let lower = serialized.to_ascii_lowercase();
        if ["ghp_", "github_pat_", "postgres://", "password="]
            .iter()
            .any(|marker| lower.contains(marker))
        {
            return Err(CommandError::SecretInConfiguration);
        }
        Ok(())
    }
}

fn pinned_image(value: &str) -> bool {
    value.rsplit_once("@sha256:").is_some_and(|(name, digest)| {
        !name.is_empty()
            && digest.len() == 64
            && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn non_root_user(value: &str) -> bool {
    let Some((uid, gid)) = value.split_once(':') else {
        return false;
    };
    uid.parse::<u32>().is_ok_and(|id| id != 0) && gid.parse::<u32>().is_ok_and(|id| id != 0)
}

#[cfg(not(test))]
fn oci_policy(
    config: &AutomationConfig,
    image: &str,
    user: &str,
    source_root: &Path,
    workspace: &Path,
) -> OciIsolation {
    OciIsolation {
        runtime: config.runtime_isolation.runtime.clone(),
        image: image.into(),
        user: user.into(),
        source_root: source_root.into(),
        workspace: workspace.into(),
        memory: config.runtime_isolation.memory.clone(),
        cpus: config.runtime_isolation.cpus.clone(),
        pids_limit: config.runtime_isolation.pids_limit,
    }
}

#[cfg(not(test))]
struct OciVisibleChecks {
    runtime: RuntimeIsolationConfig,
    source_root: PathBuf,
    timeout: std::time::Duration,
    output_limit: usize,
}
#[cfg(not(test))]
impl cauterizer_git_workspace_publisher::CandidateCheckExecutor for OciVisibleChecks {
    fn execute(
        &mut self,
        worktree: &Path,
        checks: &[GitVisibleCheck],
    ) -> Result<(), cauterizer_git_workspace_publisher::PublishError> {
        let mut runner = OciProcessRunner::new(OciIsolation {
            runtime: self.runtime.runtime.clone(),
            image: self.runtime.visible_image.clone(),
            user: self.runtime.visible_user.clone(),
            source_root: self.source_root.clone(),
            workspace: worktree.into(),
            memory: self.runtime.memory.clone(),
            cpus: self.runtime.cpus.clone(),
            pids_limit: self.runtime.pids_limit,
        })
        .map_err(|_| cauterizer_git_workspace_publisher::PublishError::Unavailable)?;
        for check in checks {
            let result = runner
                .execute(&ProcessRequest {
                    program: check.program.clone(),
                    arguments: check.args.clone(),
                    working_directory: worktree.into(),
                    environment: BTreeMap::from([
                        ("PATH".into(), "/usr/bin:/bin".into()),
                        ("LC_ALL".into(), "C".into()),
                    ]),
                    stdin: vec![],
                    timeout: self.timeout,
                    output_limit: self.output_limit,
                })
                .map_err(|_| cauterizer_git_workspace_publisher::PublishError::Unavailable)?;
            if result.timed_out || result.output_exceeded || result.exit_code != Some(0) {
                return Err(cauterizer_git_workspace_publisher::PublishError::CheckFailed);
            }
        }
        Ok(())
    }
}

fn safe_branch(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
}

fn env_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn repository_slug(value: &str) -> bool {
    let mut parts = value.split('/');
    let (Some(owner), Some(repository), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    [owner, repository].into_iter().all(|part| {
        !part.is_empty()
            && part.len() <= 100
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            && part != "."
            && part != ".."
    })
}

/// Dispatches `run --config /absolute/path.json`; secrets in arguments are rejected.
///
/// # Errors
/// Returns a stable error for unsafe arguments, configuration, or unavailable production wiring.
pub fn dispatch(arguments: impl IntoIterator<Item = String>) -> Result<(), CommandError> {
    let arguments: Vec<_> = arguments.into_iter().collect();
    if arguments
        .iter()
        .any(|value| value.contains("token=") || value.contains("postgres://"))
    {
        return Err(CommandError::SecretInArguments);
    }
    let [command, flag, path] = arguments.as_slice() else {
        return Err(CommandError::Usage);
    };
    if command != "run" || flag != "--config" {
        return Err(CommandError::Usage);
    }
    let config = AutomationConfig::load(Path::new(path))?;
    if !config.dry_run {
        let runtime =
            tokio::runtime::Runtime::new().map_err(|_| CommandError::ProductionBootstrapFailed)?;
        return runtime.block_on(production_preflight(&config));
    }
    println!(
        "validated dry-run for {} at {} on {}",
        config.github_repository, config.base_revision, config.remediation_branch
    );
    Ok(())
}

#[derive(Clone)]
struct EnvSecretProvider {
    variable: String,
}
impl std::fmt::Debug for EnvSecretProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EnvSecretProvider([REDACTED])")
    }
}
impl SecretProvider for EnvSecretProvider {
    fn github_token(&self, _: &str) -> Result<Secret, ConnectorError> {
        std::env::var(&self.variable)
            .ok()
            .filter(|value| !value.is_empty())
            .map(|value| Secret::from(value.as_str()))
            .ok_or(ConnectorError::Unavailable)
    }
}

#[allow(clippy::too_many_lines)]
async fn production_preflight(config: &AutomationConfig) -> Result<(), CommandError> {
    let database_url =
        std::env::var(&config.postgres_url_env).map_err(|_| CommandError::CredentialUnavailable)?;
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .map_err(|_| CommandError::ProductionBootstrapFailed)?;
    MIGRATOR
        .run(&pool)
        .await
        .map_err(|_| CommandError::ProductionBootstrapFailed)?;
    let repository = PostgresExternalActionRepository::new(pool.clone());
    let organization: OrganizationId = config
        .organization_id
        .parse()
        .map_err(|_| CommandError::InvalidConfiguration)?;
    let grant_id = ExternalActionGrantId::new(&config.external_grant_id)
        .map_err(|_| CommandError::InvalidConfiguration)?;
    let grant = repository
        .find_grant(&organization, &grant_id)
        .await
        .map_err(|_| CommandError::ProductionBootstrapFailed)?
        .ok_or(CommandError::GrantUnavailable)?;
    if !grant.enabled
        || grant.installation_ref != config.github_installation
        || grant.repository != config.github_repository
        || !config.remediation_branch.starts_with(&grant.branch_prefix)
    {
        return Err(CommandError::GrantUnavailable);
    }
    let capabilities = grant
        .capabilities
        .iter()
        .filter_map(|capability| match capability {
            ActionCapability::CreateIssue => Some(ScmCapability::CreateIssue),
            ActionCapability::UpdateIssue => Some(ScmCapability::UpdateIssue),
            ActionCapability::CreateRemediationBranch => Some(ScmCapability::CreateBranch),
            ActionCapability::PushCandidateCommit => Some(ScmCapability::PushCandidateCommit),
            ActionCapability::OpenPullRequest => Some(ScmCapability::CreatePullRequest),
            ActionCapability::UpdatePullRequest => Some(ScmCapability::UpdatePullRequest),
            ActionCapability::PostVerificationResult => Some(ScmCapability::PostEvidenceSummary),
            _ => None,
        })
        .collect();
    let installation = InstallationGrant {
        installation_id: config
            .github_installation
            .parse::<ContextQualifiedId>()
            .map_err(|_| CommandError::InvalidConfiguration)?,
        organization_id: organization.clone(),
        repositories: std::collections::BTreeSet::from([config.github_repository.clone()]),
        branch_prefix: grant.branch_prefix.clone(),
        allowed_target_branches: std::collections::BTreeSet::from([config
            .pull_request_base_branch
            .clone()]),
        default_branch: config.pull_request_base_branch.clone(),
        protected_branches: std::collections::BTreeSet::from([config
            .pull_request_base_branch
            .clone()]),
        capabilities,
        expires_at_unix: (grant.expires_at_epoch_seconds() != u64::MAX)
            .then_some(grant.expires_at_epoch_seconds()),
    };
    let transport = ReqwestTransport::new().map_err(|_| CommandError::ProductionBootstrapFailed)?;
    let secrets = EnvSecretProvider {
        variable: config.github_token_env.clone(),
    };
    secrets
        .github_token(&config.github_installation)
        .map_err(|_| CommandError::CredentialUnavailable)?;
    let connector = GitHubConnector::new("https://api.github.com", transport, secrets);
    connector
        .preflight_repository_policy(
            &installation,
            &config.github_repository,
            &config.remediation_branch,
            &config.pull_request_base_branch,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| CommandError::ProductionBootstrapFailed)?
                .as_secs(),
        )
        .map_err(|_| CommandError::GrantUnavailable)?;
    let artifact_binding = crate::ArtifactBinding {
        organization_id: organization.clone(),
        run_id: config.run_id.clone(),
        repository: config.github_repository.clone(),
        installation_id: config.github_installation.clone(),
    };
    let artifacts =
        FilesystemCandidateArtifacts::new(&config.candidate_artifacts_path, artifact_binding)
            .map_err(|_| CommandError::ProductionBootstrapFailed)?;
    let gateway = ScmGateway::new(
        connector,
        InMemoryInstallationGrants::new([installation]),
        SystemEpochClock,
    )
    .with_transfer_source(artifacts.clone());
    let service = PostgresExternalActionService::new(repository, gateway);
    REVIEW_DELIVERY_MIGRATOR
        .run(&pool)
        .await
        .map_err(|_| CommandError::ProductionBootstrapFailed)?;
    let reviews = PostgresReviewDeliveryRepository::new(pool);
    execute_production(config, organization, grant_id, service, reviews, artifacts).await
}

struct GenerationResult {
    candidate: CandidateAttempt,
    transcript: RepairTranscript,
    published: Option<PublishedCommit>,
    base: GitCommitOid,
    verified_evidence: Option<VerifiedDeliveryEvidence>,
}

struct ProductionGenerationPipeline<'a> {
    config: &'a AutomationConfig,
    organization: &'a OrganizationId,
    run_ref: ContextQualifiedId,
    run_id: RemediationRunId,
    artifacts: FilesystemCandidateArtifacts,
}

impl ProductionGenerationPipeline<'_> {
    #[allow(clippy::too_many_lines)]
    fn run(self) -> Result<GenerationResult, CommandError> {
        let config = self.config;
        #[cfg(not(test))]
        let solver_workspace = tempfile::tempdir().map_err(|_| CommandError::ExecutionFailed)?;
        #[cfg(not(test))]
        let verifier_workspace =
            tempfile::tempdir().map_err(|_| CommandError::VerificationUnavailable)?;
        let baseline: ContextQualifiedId = config
            .baseline_observation
            .parse()
            .map_err(|_| CommandError::InvalidConfiguration)?;
        let source_digest = config
            .source_digest
            .parse()
            .map_err(|_| CommandError::InvalidConfiguration)?;
        let brief = SolverBrief {
            organization_id: self.organization.clone(),
            run_id: self.run_ref.clone(),
            problem: config.solver_problem.clone(),
            source_digest,
            public_test_instructions: config
                .visible_commands
                .iter()
                .map(|item| format!("{} {:?}", item.program, item.arguments))
                .collect(),
            allowed_paths: config.allowed_paths.iter().cloned().collect(),
            allowed_tools: config.allowed_tools.iter().cloned().collect(),
            budget: ProposalBudget {
                attempts: u16::try_from(config.budgets.attempts)
                    .map_err(|_| CommandError::InvalidConfiguration)?,
                tokens: config.budgets.solver_units,
                cost_micros: config.budgets.spend_micros,
                time_millis: config.budgets.command_timeout_seconds.saturating_mul(1000),
                paths: u32::try_from(config.allowed_paths.len())
                    .map_err(|_| CommandError::InvalidConfiguration)?,
                patch_bytes: config.budgets.patch_bytes,
                changed_lines: config.budgets.changed_lines,
            },
            memory_namespace: None,
        };
        #[cfg(not(test))]
        let runner = OciProcessRunner::new(oci_policy(
            config,
            &config.runtime_isolation.solver_image,
            &config.runtime_isolation.solver_user,
            &config.checkout_path,
            solver_workspace.path(),
        ))
        .map_err(|_| CommandError::ExecutionFailed)?;
        #[cfg(test)]
        let runner = LocalCommandRunner::new(&config.checkout_path)
            .map_err(|_| CommandError::ExecutionFailed)?;
        let process = ProcessRequest {
            program: config.solver.program.clone(),
            arguments: config.solver.arguments.clone(),
            working_directory: config.checkout_path.clone(),
            environment: std::collections::BTreeMap::from([
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("LC_ALL".into(), "C".into()),
            ]),
            stdin: vec![],
            timeout: std::time::Duration::from_secs(config.budgets.command_timeout_seconds),
            output_limit: config.budgets.output_bytes,
        };
        let diagnostics = InMemoryVisibleDiagnostics::default();
        let mut solver = RepairCandidateAdapter::new(
            CodingAgentAdapter::new(runner, process),
            brief,
            self.artifacts.clone(),
        )
        .with_diagnostics(diagnostics.clone());
        let base =
            GitCommitOid::parse(&config.base_revision).ok_or(CommandError::InvalidConfiguration)?;
        let checks = config
            .visible_commands
            .iter()
            .map(|item| GitVisibleCheck {
                program: item.program.clone(),
                args: item.arguments.clone(),
            })
            .collect();
        let visible = PublishingVisibleEvaluator::new(
            self.artifacts.clone(),
            config.checkout_path.clone(),
            base.clone(),
            config.remediation_branch.clone(),
            checks,
        );
        #[cfg(not(test))]
        let visible = visible.with_check_executor(OciVisibleChecks {
            runtime: config.runtime_isolation.clone(),
            source_root: config.checkout_path.clone(),
            timeout: std::time::Duration::from_secs(config.budgets.command_timeout_seconds),
            output_limit: config.budgets.output_bytes,
        });
        let mut visible = visible.with_diagnostics(diagnostics);
        std::fs::create_dir_all(&config.verifier_results_path)
            .map_err(|_| CommandError::VerificationUnavailable)?;
        #[cfg(not(test))]
        let verifier_runner = OciProcessRunner::new(oci_policy(
            config,
            &config.runtime_isolation.verifier_image,
            &config.runtime_isolation.verifier_user,
            &config.verifier_root,
            verifier_workspace.path(),
        ))
        .map_err(|_| CommandError::VerificationUnavailable)?;
        #[cfg(test)]
        let verifier_runner = LocalCommandRunner::new(&config.verifier_root)
            .map_err(|_| CommandError::VerificationUnavailable)?;
        let verifier_process = ProcessRequest {
            program: config.verifier.program.clone(),
            arguments: config.verifier.arguments.clone(),
            working_directory: config.verifier_root.clone(),
            environment: std::collections::BTreeMap::from([
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("LC_ALL".into(), "C".into()),
            ]),
            stdin: vec![],
            timeout: std::time::Duration::from_secs(config.budgets.command_timeout_seconds),
            output_limit: config.budgets.output_bytes,
        };
        let verifier_store = std::sync::Arc::new(
            CommandVerificationStore::new(
                verifier_runner,
                verifier_process,
                config.verifier_results_path.clone(),
                self.artifacts.clone(),
                base.clone(),
            )
            .map_err(|_| CommandError::VerificationUnavailable)?,
        );
        let captured = std::sync::Arc::new(std::sync::Mutex::new(VerifierCapture::default()));
        let mut hidden = RepairHiddenVerifier(HiddenAssessmentAdapter::new(
            SharedVerifier(verifier_store.clone(), captured.clone()),
            SharedVerifier(verifier_store, captured.clone()),
        ));
        let transcript = RepairLoop::execute(
            &RepairRequest {
                run_id: self.run_id,
                baseline,
            },
            RepairBudget {
                max_attempts: config.budgets.attempts,
                max_solver_units: config.budgets.solver_units,
            },
            &mut solver,
            &mut visible,
            &mut hidden,
        )
        .map_err(|_| CommandError::ExecutionFailed)?;
        let candidate = match &transcript.outcome {
            RepairOutcome::Verified { candidate }
            | RepairOutcome::VerificationStopped { candidate, .. } => candidate.clone(),
            RepairOutcome::BudgetExhausted => transcript
                .attempts
                .last()
                .map(|record| record.candidate.clone())
                .ok_or(CommandError::ExecutionFailed)?,
        };
        let verified_evidence = if matches!(transcript.outcome, RepairOutcome::Verified { .. }) {
            let (input, recorded) = captured
                .lock()
                .map_err(|_| CommandError::VerificationUnavailable)?
                .verified(candidate.patch_digest)
                .ok_or(CommandError::VerificationUnavailable)?;
            Some(
                VerifiedDeliveryEvidence::from_recorded(
                    self.organization.clone(),
                    self.run_ref,
                    candidate.patch_digest,
                    &input,
                    &recorded,
                )
                .map_err(|_| CommandError::VerificationUnavailable)?,
            )
        } else {
            None
        };
        let published = if let Some(evidence) = &verified_evidence {
            let patch = self
                .artifacts
                .get(candidate.patch_digest)
                .map_err(|_| CommandError::ExecutionFailed)?
                .ok_or(CommandError::ExecutionFailed)?;
            Some(
                cauterizer_git_workspace_publisher::publish_verified(
                    &self.config.checkout_path,
                    &base,
                    &patch,
                    &self.config.remediation_branch,
                    &cauterizer_git_workspace_publisher::PublicationIdentity {
                        run_id: self.config.run_id.clone(),
                        evidence_digest: evidence.assessment_digest,
                    },
                )
                .map_err(|_| CommandError::ExecutionFailed)?,
            )
        } else {
            None
        };
        Ok(GenerationResult {
            candidate,
            transcript,
            published,
            base,
            verified_evidence,
        })
    }
}

#[derive(Default)]
struct VerifierCapture {
    inputs: BTreeMap<String, CandidateAssessmentInput>,
    assessments: BTreeMap<String, CandidateAssessment>,
}
impl VerifierCapture {
    fn verified(
        &self,
        candidate: Sha256Digest,
    ) -> Option<(CandidateAssessmentInput, CandidateAssessment)> {
        let input = self.inputs.get(&candidate.to_tagged_hex())?;
        let assessment = self.assessments.values().find(|assessment| {
            cauterizer_verification::domain::assessment::CandidateAssessmentEngine::assess(input)
                == **assessment
        })?;
        Some((input.clone(), assessment.clone()))
    }
}
struct SharedVerifier(
    std::sync::Arc<CommandVerificationStore>,
    std::sync::Arc<std::sync::Mutex<VerifierCapture>>,
);
impl cauterizer_verification::application::assessment::AssessmentInputRepository
    for SharedVerifier
{
    fn load(
        &self,
        candidate: Sha256Digest,
    ) -> Result<
        Option<cauterizer_verification::domain::assessment::CandidateAssessmentInput>,
        cauterizer_verification::application::assessment::AssessmentAdapterError,
    > {
        let input =
            cauterizer_verification::application::assessment::AssessmentInputRepository::load(
                self.0.as_ref(),
                candidate,
            )?;
        if let Some(input) = &input {
            self.1.lock().map_err(|_| cauterizer_verification::application::assessment::AssessmentAdapterError::StorageUnavailable)?
                .inputs.insert(candidate.to_tagged_hex(), input.clone());
        }
        Ok(input)
    }
}
impl cauterizer_verification::application::assessment::AssessmentRecorder for SharedVerifier {
    fn record(
        &self,
        assessment: &cauterizer_verification::domain::assessment::CandidateAssessment,
    ) -> Result<(), cauterizer_verification::application::assessment::AssessmentAdapterError> {
        cauterizer_verification::application::assessment::AssessmentRecorder::record(
            self.0.as_ref(),
            assessment,
        )?;
        self.1.lock().map_err(|_| cauterizer_verification::application::assessment::AssessmentAdapterError::StorageUnavailable)?
            .assessments.insert(assessment.assessment_digest.to_tagged_hex(), assessment.clone());
        Ok(())
    }
}

#[allow(clippy::too_many_lines, clippy::items_after_statements)]
async fn execute_production<R: RemoteActionGateway + Clone + Send + Sync + 'static>(
    config: &AutomationConfig,
    organization: OrganizationId,
    grant_id: ExternalActionGrantId,
    actions: PostgresExternalActionService<R>,
    reviews: PostgresReviewDeliveryRepository,
    artifacts: FilesystemCandidateArtifacts,
) -> Result<(), CommandError> {
    let run_ref: ContextQualifiedId = config
        .run_id
        .parse()
        .map_err(|_| CommandError::InvalidConfiguration)?;
    let run_id =
        RemediationRunId::new(run_ref.opaque()).map_err(|_| CommandError::InvalidConfiguration)?;
    let active = reviews
        .load_active(&organization, &run_id)
        .await
        .map_err(|_| CommandError::DeliveryFailed)?;
    let mut superseded = match (active, config.supersedes_candidate_digest.as_deref()) {
        (Some(mut active), None) => {
            resume_delivery(&actions, &reviews, &mut active).await?;
            return Ok(());
        }
        (Some(active), Some(expected)) => {
            let expected: Sha256Digest = expected
                .parse()
                .map_err(|_| CommandError::InvalidConfiguration)?;
            validate_supersession_target(&active, expected)?;
            Some(active)
        }
        (None, Some(_)) => return Err(CommandError::SupersessionRejected),
        (None, None) => None,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CommandError::ExecutionFailed)?
        .as_secs();
    let lease = match reviews
        .claim(
            &organization,
            &run_id,
            &config.worker_id,
            now,
            generation_lease_seconds(config)?,
        )
        .await
        .map_err(|_| CommandError::ExecutionFailed)?
    {
        GenerationClaim::Acquired(lease) => lease,
        GenerationClaim::Held => return Err(CommandError::GenerationAlreadyClaimed),
    };
    let generation = ProductionGenerationPipeline {
        config,
        organization: &organization,
        run_ref,
        run_id: run_id.clone(),
        artifacts: artifacts.clone(),
    }
    .run()?;
    let GenerationResult {
        candidate,
        transcript,
        mut published,
        base,
        verified_evidence,
    } = generation;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CommandError::ExecutionFailed)?
        .as_secs();
    if !reviews
        .is_current(&lease, now)
        .await
        .map_err(|_| CommandError::ExecutionFailed)?
    {
        if let Some(stale) = published.take() {
            cauterizer_git_workspace_publisher::discard_candidate(
                &config.checkout_path,
                &config.remediation_branch,
                &stale.commit_oid,
            )
            .map_err(|_| CommandError::ExecutionFailed)?;
        }
        return Err(CommandError::GenerationAlreadyClaimed);
    }
    if let Some(prior) = superseded.as_mut() {
        prior
            .delivery
            .supersede(candidate.patch_digest)
            .map_err(|_| CommandError::SupersessionRejected)?;
        *prior = reviews
            .save(prior.version, prior.delivery.clone())
            .await
            .map_err(|_| CommandError::SupersessionRejected)?;
    }
    let key = ReviewDeliveryKey {
        organization_id: organization.clone(),
        run_id,
        candidate_digest: candidate.patch_digest,
    };
    let outcome_text = match &transcript.outcome {
        RepairOutcome::Verified { .. } => "VerifiedForFixture: candidate ready for human review",
        RepairOutcome::VerificationStopped { decision, .. } => match decision {
            cauterizer_remediation_runs::application::agentic::HiddenDecision::Rejected => {
                "Rejected: automated candidate withheld"
            }
            cauterizer_remediation_runs::application::agentic::HiddenDecision::Inconclusive => {
                "Inconclusive: automated candidate withheld"
            }
            cauterizer_remediation_runs::application::agentic::HiddenDecision::NonConformant => {
                "NonConformant: automated candidate withheld"
            }
            cauterizer_remediation_runs::application::agentic::HiddenDecision::Verified => {
                return Err(CommandError::ExecutionFailed);
            }
        },
        RepairOutcome::BudgetExhausted => {
            "BudgetExhausted: automated remediation stopped for human review"
        }
    };
    let issue = action_request(
        config,
        &organization,
        &grant_id,
        &candidate,
        &transcript,
        1,
        ActionCapability::CreateIssue,
        "Vulnerability remediation",
        outcome_text,
        None,
    )?;
    if !matches!(transcript.outcome, RepairOutcome::Verified { .. }) {
        if let Some(unverified) = published.take() {
            cauterizer_git_workspace_publisher::discard_candidate(
                &config.checkout_path,
                &config.remediation_branch,
                &unverified.commit_oid,
            )
            .map_err(|_| CommandError::ExecutionFailed)?;
        }
        let plan = delivery_plan(PlanKind::IssueOnly, [(ReviewStage::Issue, issue, None)])?;
        let mut versioned = reviews
            .create(ReviewDelivery::new(key, plan))
            .await
            .map_err(|_| CommandError::DeliveryFailed)?;
        resume_delivery(&actions, &reviews, &mut versioned).await?;
        return Ok(());
    }
    let published = published.ok_or(CommandError::ExecutionFailed)?;
    if published.candidate_digest != candidate.patch_digest
        || published.transfer.base_commit_oid != base
    {
        return Err(CommandError::ExecutionFailed);
    }
    artifacts
        .put_transfer(
            candidate.patch_digest,
            &published.commit_oid,
            &published.transfer,
        )
        .map_err(|_| CommandError::ExecutionFailed)?;
    let verified_evidence = verified_evidence.ok_or(CommandError::VerificationUnavailable)?;
    if verified_evidence.organization_id != organization
        || verified_evidence.run_id.as_str() != config.run_id
        || verified_evidence.candidate_digest != candidate.patch_digest
    {
        return Err(CommandError::VerificationUnavailable);
    }
    let attestation = DeliveryAttestation {
        candidate_digest: verified_evidence.candidate_digest,
        policy_result_digest: verified_evidence.policy_digest,
        policy_approved: true,
        patch_bytes: candidate.patch_bytes,
        changed_lines: candidate.changed_lines,
        attempts: u32::try_from(transcript.attempts.len())
            .map_err(|_| CommandError::ExecutionFailed)?,
        elapsed_millis: transcript.elapsed_millis,
        compute_units: transcript.solver_units,
        spend_micros: transcript.spend_micros,
    };
    let branch = action_request(
        config,
        &organization,
        &grant_id,
        &candidate,
        &transcript,
        2,
        ActionCapability::CreateRemediationBranch,
        &config.remediation_branch,
        &config.base_revision,
        Some(attestation.clone()),
    )?;
    let commit_body = format!(
        "{}|{}|{}|{}",
        candidate.patch_digest.to_tagged_hex(),
        published.commit_oid.as_str(),
        base.as_str(),
        config.run_id
    );
    let commit = action_request(
        config,
        &organization,
        &grant_id,
        &candidate,
        &transcript,
        3,
        ActionCapability::PushCandidateCommit,
        &config.remediation_branch,
        &commit_body,
        Some(attestation.clone()),
    )?;
    let pr_body = format!(
        "base={}\nCandidate passed independent verification; human review required",
        config.pull_request_base_branch
    );
    let pr = action_request(
        config,
        &organization,
        &grant_id,
        &candidate,
        &transcript,
        4,
        ActionCapability::OpenPullRequest,
        &config.remediation_branch,
        &pr_body,
        Some(attestation.clone()),
    )?;
    let summary = format!(
        "evidence={}\nVerified for fixture; recorded assessment retained",
        verified_evidence.assessment_digest.to_tagged_hex()
    );
    let evidence = action_request(
        config,
        &organization,
        &grant_id,
        &candidate,
        &transcript,
        5,
        ActionCapability::PostVerificationResult,
        "owned-pull-request",
        &summary,
        Some(attestation),
    )?;
    let plan = delivery_plan(
        PlanKind::VerifiedReview,
        [
            (ReviewStage::Issue, issue, None),
            (ReviewStage::Branch, branch, None),
            (ReviewStage::Commit, commit, None),
            (ReviewStage::PullRequest, pr, None),
            (
                ReviewStage::Summary,
                evidence,
                Some(ReviewStage::PullRequest),
            ),
        ],
    )?;
    let mut versioned = reviews
        .create(ReviewDelivery::new(key, plan))
        .await
        .map_err(|_| CommandError::DeliveryFailed)?;
    resume_delivery(&actions, &reviews, &mut versioned).await?;
    Ok(())
}

fn validate_supersession_target(
    active: &VersionedDelivery,
    expected: Sha256Digest,
) -> Result<(), CommandError> {
    if active.delivery.key.candidate_digest != expected
        || active.delivery.is_superseded()
        || active.delivery.get(ReviewStage::Summary).is_none()
    {
        return Err(CommandError::SupersessionRejected);
    }
    Ok(())
}

fn generation_lease_seconds(config: &AutomationConfig) -> Result<u64, CommandError> {
    let commands = u64::try_from(config.visible_commands.len())
        .map_err(|_| CommandError::InvalidConfiguration)?
        .checked_add(2)
        .ok_or(CommandError::InvalidConfiguration)?;
    u64::from(config.budgets.attempts)
        .checked_mul(commands)
        .and_then(|value| value.checked_mul(config.budgets.command_timeout_seconds))
        .and_then(|value| value.checked_add(60))
        .filter(|value| *value >= 60)
        .ok_or(CommandError::InvalidConfiguration)
}

fn delivery_plan<const N: usize>(
    kind: PlanKind,
    requests: [(ReviewStage, ExternalActionRequest, Option<ReviewStage>); N],
) -> Result<ReviewDeliveryPlan, CommandError> {
    let mut actions = BTreeMap::new();
    for (stage, mut request, prior) in requests {
        let subject = if let Some(prior) = prior {
            request.subject.clear();
            PlannedSubject::PriorStageRemoteId(prior)
        } else {
            PlannedSubject::Literal(request.subject.as_bytes().to_vec())
        };
        request.subject.clear();
        let template_bytes =
            serde_jcs::to_vec(&request).map_err(|_| CommandError::DeliveryFailed)?;
        actions.insert(
            stage,
            PlannedAction {
                template_digest: Sha256Digest::of_bytes(&template_bytes),
                template_bytes,
                subject,
            },
        );
    }
    ReviewDeliveryPlan::new(kind, actions).map_err(|_| CommandError::DeliveryFailed)
}

trait ActionExecutor {
    async fn execute_action(
        &self,
        id: ExternalActionDeliveryId,
        request: ExternalActionRequest,
    ) -> Result<ExternalActionDelivery, ExternalActionError>;
}
impl<R: RemoteActionGateway + Clone + Send + Sync + 'static> ActionExecutor
    for PostgresExternalActionService<R>
{
    async fn execute_action(
        &self,
        id: ExternalActionDeliveryId,
        request: ExternalActionRequest,
    ) -> Result<ExternalActionDelivery, ExternalActionError> {
        self.execute(id, request).await
    }
}

async fn resume_delivery<A: ActionExecutor, Q: AsyncReviewDeliveryRepository>(
    actions: &A,
    reviews: &Q,
    versioned: &mut VersionedDelivery,
) -> Result<(), CommandError> {
    while let Some((stage, materialized)) = versioned.delivery.next_stage() {
        let mut request: ExternalActionRequest =
            serde_json::from_slice(&materialized.template_bytes)
                .map_err(|_| CommandError::DeliveryFailed)?;
        request.subject =
            String::from_utf8(materialized.subject).map_err(|_| CommandError::DeliveryFailed)?;
        execute_and_checkpoint(
            actions,
            reviews,
            versioned,
            stage,
            request,
            materialized.request_digest,
        )
        .await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn action_request(
    config: &AutomationConfig,
    organization: &OrganizationId,
    grant: &ExternalActionGrantId,
    candidate: &cauterizer_remediation_runs::application::agentic::CandidateAttempt,
    _: &cauterizer_remediation_runs::application::agentic::RepairTranscript,
    sequence: u8,
    capability: ActionCapability,
    subject: &str,
    body: &str,
    policy_attestation: Option<DeliveryAttestation>,
) -> Result<ExternalActionRequest, CommandError> {
    let identity = Sha256Digest::of_bytes(format!(
        "{}|{}|{}|{sequence}",
        organization.as_str(),
        config.run_id,
        candidate.patch_digest.to_tagged_hex()
    ));
    Ok(ExternalActionRequest {
        organization_id: organization.clone(),
        grant_id: grant.clone(),
        repository: config.github_repository.clone(),
        capability,
        idempotency_key: IdempotencyKey::new(format!(
            "action-{}-{sequence}",
            identity.to_tagged_hex().trim_start_matches("sha256:")
        ))
        .map_err(|_| CommandError::InvalidConfiguration)?,
        correlation_key: format!(
            "lineage-{}",
            Sha256Digest::of_bytes(format!("{}|{capability:?}", config.run_id))
                .to_tagged_hex()
                .trim_start_matches("sha256:")
        ),
        subject: subject.into(),
        redacted_body: body.into(),
        policy_attestation,
    })
}

async fn execute_and_checkpoint<A: ActionExecutor, Q: AsyncReviewDeliveryRepository>(
    actions: &A,
    reviews: &Q,
    versioned: &mut cauterizer_remediation_runs::application::review_delivery::VersionedDelivery,
    stage: ReviewStage,
    request: ExternalActionRequest,
    request_digest: Sha256Digest,
) -> Result<String, CommandError> {
    if let Some(existing) = versioned.delivery.get(stage) {
        if existing.request_digest == request_digest {
            return Ok(existing.remote_id.clone());
        }
        return Err(CommandError::DeliveryFailed);
    }
    let delivery = actions
        .execute_action(
            ExternalActionDeliveryId::new(
                &Sha256Digest::of_bytes(request.idempotency_key.as_str())
                    .to_tagged_hex()
                    .trim_start_matches("sha256:")[..32],
            )
            .map_err(|_| CommandError::DeliveryFailed)?,
            request,
        )
        .await
        .map_err(|_| CommandError::DeliveryFailed)?;
    let DeliveryStatus::Succeeded {
        remote_id,
        remote_url,
    } = delivery.status
    else {
        return Err(CommandError::DeliveryFailed);
    };
    loop {
        let mut next = versioned.delivery.clone();
        next.checkpoint(
            stage,
            StageCheckpoint {
                request_digest,
                remote_reference: remote_url.clone(),
                remote_id: remote_id.clone(),
            },
        )
        .map_err(|_| CommandError::DeliveryFailed)?;
        match reviews.save(versioned.version, next).await {
            Ok(saved) => { *versioned = saved; return Ok(remote_id); }
            Err(cauterizer_remediation_runs::application::review_delivery::ReviewDeliveryError::Conflict) => {
                *versioned = reviews.load(&versioned.delivery.key).await.map_err(|_| CommandError::DeliveryFailed)?.ok_or(CommandError::DeliveryFailed)?;
                if let Some(existing) = versioned.delivery.get(stage) {
                    if existing.request_digest == request_digest
                        && existing.remote_reference == remote_url
                        && existing.remote_id == remote_id
                    {
                        return Ok(remote_id);
                    }
                    return Err(CommandError::DeliveryFailed);
                }
            }
            Err(_) => return Err(CommandError::DeliveryFailed),
        }
    }
}

/// Stable command error with no configuration or credential echo.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandError {
    /// Invalid invocation.
    Usage,
    /// Config file could not be read.
    ConfigurationUnavailable,
    /// Config structure or policy was invalid.
    InvalidConfiguration,
    /// Secret material appeared in the config.
    SecretInConfiguration,
    /// Secret material appeared in process arguments.
    SecretInArguments,
    /// Live Postgres/GitHub adapter composition is not installed.
    ProductionBootstrapFailed,
    /// Solver, visible execution, publishing, or orchestration failed.
    ExecutionFailed,
    /// Sealed verifier input or recording was unavailable.
    VerificationUnavailable,
    /// Durable review delivery or remote action failed.
    DeliveryFailed,
    /// Another worker owns the fenced generation lease.
    GenerationAlreadyClaimed,
    /// Explicit supersession did not exactly match a completed owned workflow.
    SupersessionRejected,
    /// Preinstalled authority was absent, disabled, or mismatched.
    GrantUnavailable,
    /// A named credential environment variable was absent.
    CredentialUnavailable,
}
impl std::fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Usage => "usage: cauterizer-worker run --config /absolute/path.json",
            Self::ConfigurationUnavailable => "configuration unavailable",
            Self::InvalidConfiguration => "invalid configuration",
            Self::SecretInConfiguration => "secret in configuration",
            Self::SecretInArguments => "secret in arguments",
            Self::ProductionBootstrapFailed => "production bootstrap failed",
            Self::ExecutionFailed => "production remediation execution failed",
            Self::VerificationUnavailable => "verification unavailable",
            Self::DeliveryFailed => "review delivery failed",
            Self::GenerationAlreadyClaimed => "remediation generation already claimed",
            Self::SupersessionRejected => "remediation supersession rejected",
            Self::GrantUnavailable => "preinstalled grant unavailable",
            Self::CredentialUnavailable => "credential unavailable",
        })
    }
}
impl std::error::Error for CommandError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ArtifactBinding;
    use cauterizer_remediation_runs::application::review_delivery::ReviewDeliveryError;
    use std::process::Command;
    use std::sync::{Arc, Mutex};

    #[test]
    fn environment_secret_provider_is_redacted_and_missing_is_coarse() {
        let provider = EnvSecretProvider {
            variable: "CAUTERIZER_TEST_VARIABLE_THAT_MUST_NOT_EXIST_9F31".into(),
        };
        assert_eq!(format!("{provider:?}"), "EnvSecretProvider([REDACTED])");
        assert!(matches!(
            provider.github_token("installation_00000001"),
            Err(ConnectorError::Unavailable)
        ));
    }

    #[test]
    fn invalid_identity_and_policy_digest_are_rejected() {
        let config: Result<AutomationConfig, _> = serde_json::from_value(serde_json::json!({
            "worker_id":"worker0001", "organization_id":"wrong", "external_grant_id":"wrong", "policy_result_digest":"wrong", "evidence_digest":"wrong",
            "run_id":"wrong", "baseline_observation":"wrong",
            "verifier_results_path":"/verifier/results", "verifier_root":"/verifier", "verifier":{"program":"verify"},
            "candidate_artifacts_path":"/candidates",
            "solver_problem":"repair", "source_digest":"wrong", "allowed_paths":["src/lib.rs"], "allowed_tools":["patch"],
            "checkout_path":"/tmp/repo", "base_revision":"0123456789abcdef", "remediation_branch":"cauterizer/fix", "pull_request_base_branch":"main",
            "solver":{"program":"agent"}, "visible_commands":[{"program":"test"}],
            "budgets":{"attempts":1,"solver_units":1,"command_timeout_seconds":1,"output_bytes":1,"spend_micros":1,"patch_bytes":1,"changed_lines":1},
            "github_installation":"installation_00000001", "github_repository":"owner/repo",
            "postgres_url_env":"DATABASE_URL", "github_token_env":"GITHUB_TOKEN", "dry_run":false
        }));
        assert!(config.is_err() || config.unwrap().validate().is_err());
    }

    #[test]
    fn generation_lease_covers_every_bounded_process_plus_cleanup_margin() {
        let mut config: AutomationConfig = serde_json::from_value(serde_json::json!({
            "worker_id":"worker0001", "organization_id":"organization1", "external_grant_id":"grant0001",
            "run_id":"run:00000001", "baseline_observation":"observation:00000001",
            "verifier_results_path":"/verifier/results", "verifier_root":"/verifier", "verifier":{"program":"verify"},
            "candidate_artifacts_path":"/candidates", "solver_problem":"repair", "source_digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "allowed_paths":["src/lib.rs"], "allowed_tools":["patch"],
            "checkout_path":"/tmp/repo", "base_revision":"0123456789abcdef0123456789abcdef01234567", "remediation_branch":"cauterizer/fix", "pull_request_base_branch":"main",
            "solver":{"program":"agent"}, "visible_commands":[{"program":"test"},{"program":"lint"}],
            "budgets":{"attempts":3,"solver_units":10,"command_timeout_seconds":20,"output_bytes":1024,"spend_micros":10,"patch_bytes":1024,"changed_lines":10},
            "github_installation":"installation_00000001", "github_repository":"owner/repo", "postgres_url_env":"DATABASE_URL", "github_token_env":"GITHUB_TOKEN", "dry_run":false,
            "runtime_isolation":{"runtime":"/usr/bin/podman","solver_image":"solver@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","verifier_image":"verifier@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","visible_image":"visible@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","solver_user":"10001:10001","verifier_user":"10002:10002","visible_user":"10003:10003","memory":"512m","cpus":"1","pids_limit":64}
        })).unwrap();
        assert_eq!(generation_lease_seconds(&config), Ok(300));
        config.budgets.command_timeout_seconds = u64::MAX;
        assert_eq!(
            generation_lease_seconds(&config),
            Err(CommandError::InvalidConfiguration)
        );
    }

    #[derive(Clone, Default)]
    struct FakeActions(Arc<Mutex<Vec<ActionCapability>>>);
    impl ActionExecutor for FakeActions {
        async fn execute_action(
            &self,
            id: ExternalActionDeliveryId,
            request: ExternalActionRequest,
        ) -> Result<ExternalActionDelivery, ExternalActionError> {
            self.0.lock().unwrap().push(request.capability);
            Ok(ExternalActionDelivery {
                id,
                request,
                status: DeliveryStatus::Succeeded {
                    remote_id: format!("remote-{}", self.0.lock().unwrap().len()),
                    remote_url: "https://example.invalid/review".into(),
                },
                attempts: 1,
                reconciliation_attempts: 0,
                next_reconcile_at_epoch_seconds: 0,
                reconciliation_lease_until_epoch_seconds: None,
                reconciliation_claim_token: 0,
            })
        }
    }
    #[derive(Clone)]
    struct FakeReviews(Arc<Mutex<VersionedDelivery>>);
    impl AsyncReviewDeliveryRepository for FakeReviews {
        async fn load(
            &self,
            _: &ReviewDeliveryKey,
        ) -> Result<Option<VersionedDelivery>, ReviewDeliveryError> {
            Ok(Some(self.0.lock().unwrap().clone()))
        }
        async fn create(
            &self,
            _: ReviewDelivery,
        ) -> Result<VersionedDelivery, ReviewDeliveryError> {
            Ok(self.0.lock().unwrap().clone())
        }
        async fn save(
            &self,
            expected: u64,
            delivery: ReviewDelivery,
        ) -> Result<VersionedDelivery, ReviewDeliveryError> {
            let mut state = self.0.lock().unwrap();
            if state.version != expected {
                return Err(ReviewDeliveryError::Conflict);
            }
            *state = VersionedDelivery {
                delivery,
                version: expected + 1,
            };
            Ok(state.clone())
        }
        async fn load_active(
            &self,
            _: &OrganizationId,
            _: &RemediationRunId,
        ) -> Result<Option<VersionedDelivery>, ReviewDeliveryError> {
            Ok(Some(self.0.lock().unwrap().clone()))
        }
    }

    fn planned_request(capability: ActionCapability, sequence: u8) -> ExternalActionRequest {
        ExternalActionRequest {
            organization_id: OrganizationId::new("organization1").unwrap(),
            grant_id: ExternalActionGrantId::new("grant0001").unwrap(),
            repository: "owner/repo".into(),
            capability,
            idempotency_key: IdempotencyKey::new(format!("candidate-stage-{sequence}")).unwrap(),
            correlation_key: format!("logical-review-{sequence}"),
            subject: "subject".into(),
            redacted_body: "safe body".into(),
            policy_attestation: None,
        }
    }

    #[tokio::test]
    async fn persisted_plan_resumes_after_checkpoint_without_replaying_prior_action() {
        let requests = [
            (
                ReviewStage::Issue,
                planned_request(ActionCapability::CreateIssue, 1),
                None,
            ),
            (
                ReviewStage::Branch,
                planned_request(ActionCapability::CreateRemediationBranch, 2),
                None,
            ),
            (
                ReviewStage::Commit,
                planned_request(ActionCapability::PushCandidateCommit, 3),
                None,
            ),
            (
                ReviewStage::PullRequest,
                planned_request(ActionCapability::OpenPullRequest, 4),
                None,
            ),
            (
                ReviewStage::Summary,
                planned_request(ActionCapability::PostVerificationResult, 5),
                Some(ReviewStage::PullRequest),
            ),
        ];
        let plan = delivery_plan(PlanKind::VerifiedReview, requests).unwrap();
        let key = ReviewDeliveryKey {
            organization_id: OrganizationId::new("organization1").unwrap(),
            run_id: RemediationRunId::new("run00001").unwrap(),
            candidate_digest: Sha256Digest::of_bytes(b"candidate"),
        };
        let mut delivery = ReviewDelivery::new(key, plan);
        let issue_digest = delivery
            .materialize(ReviewStage::Issue)
            .unwrap()
            .request_digest;
        delivery
            .checkpoint(
                ReviewStage::Issue,
                StageCheckpoint {
                    request_digest: issue_digest,
                    remote_reference: "https://example.invalid/issue".into(),
                    remote_id: "issue-1".into(),
                },
            )
            .unwrap();
        let mut active = VersionedDelivery {
            delivery,
            version: 1,
        };
        let reviews = FakeReviews(Arc::new(Mutex::new(active.clone())));
        let actions = FakeActions::default();
        resume_delivery(&actions, &reviews, &mut active)
            .await
            .unwrap();
        assert_eq!(
            actions.0.lock().unwrap().as_slice(),
            &[
                ActionCapability::CreateRemediationBranch,
                ActionCapability::PushCandidateCommit,
                ActionCapability::OpenPullRequest,
                ActionCapability::PostVerificationResult,
            ]
        );
        assert!(active.delivery.get(ReviewStage::Summary).is_some());
        resume_delivery(&actions, &reviews, &mut active)
            .await
            .unwrap();
        assert_eq!(actions.0.lock().unwrap().len(), 4);
    }

    #[test]
    fn supersession_requires_exact_completed_unsuperseded_candidate() {
        let requests = [
            (
                ReviewStage::Issue,
                planned_request(ActionCapability::CreateIssue, 1),
                None,
            ),
            (
                ReviewStage::Branch,
                planned_request(ActionCapability::CreateRemediationBranch, 2),
                None,
            ),
            (
                ReviewStage::Commit,
                planned_request(ActionCapability::PushCandidateCommit, 3),
                None,
            ),
            (
                ReviewStage::PullRequest,
                planned_request(ActionCapability::OpenPullRequest, 4),
                None,
            ),
            (
                ReviewStage::Summary,
                planned_request(ActionCapability::PostVerificationResult, 5),
                Some(ReviewStage::PullRequest),
            ),
        ];
        let candidate = Sha256Digest::of_bytes(b"prior");
        let key = ReviewDeliveryKey {
            organization_id: OrganizationId::new("organization1").unwrap(),
            run_id: RemediationRunId::new("run00001").unwrap(),
            candidate_digest: candidate,
        };
        let mut delivery = ReviewDelivery::new(
            key,
            delivery_plan(PlanKind::VerifiedReview, requests).unwrap(),
        );
        let incomplete = VersionedDelivery {
            delivery: delivery.clone(),
            version: 1,
        };
        assert_eq!(
            validate_supersession_target(&incomplete, candidate),
            Err(CommandError::SupersessionRejected)
        );
        for stage in [
            ReviewStage::Issue,
            ReviewStage::Branch,
            ReviewStage::Commit,
            ReviewStage::PullRequest,
            ReviewStage::Summary,
        ] {
            let materialized = delivery.materialize(stage).unwrap();
            delivery
                .checkpoint(
                    stage,
                    StageCheckpoint {
                        request_digest: materialized.request_digest,
                        remote_reference: format!("https://example.invalid/{stage:?}"),
                        remote_id: format!("remote-{stage:?}"),
                    },
                )
                .unwrap();
        }
        let complete = VersionedDelivery {
            delivery,
            version: 6,
        };
        assert_eq!(validate_supersession_target(&complete, candidate), Ok(()));
        assert_eq!(
            validate_supersession_target(&complete, Sha256Digest::of_bytes(b"other")),
            Err(CommandError::SupersessionRejected)
        );
    }

    fn git(repository: &Path, arguments: &[&str]) -> String {
        let output = Command::new("git")
            .args(arguments)
            .current_dir(repository)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().into()
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn production_generation_retries_public_failure_then_verifies_publishes_and_resumes() {
        let temporary = tempfile::tempdir().unwrap();
        let repository = temporary.path().join("repository");
        let verifier_root = temporary.path().join("verifier");
        let artifacts_root = temporary.path().join("artifacts");
        let results_root = verifier_root.join("results");
        std::fs::create_dir_all(&repository).unwrap();
        std::fs::create_dir_all(&verifier_root).unwrap();
        std::fs::create_dir_all(&artifacts_root).unwrap();
        std::fs::write(repository.join("value.txt"), "bad\n").unwrap();
        git(&repository, &["init", "-b", "main"]);
        git(&repository, &["config", "user.name", "Fixture"]);
        git(
            &repository,
            &["config", "user.email", "fixture@example.invalid"],
        );
        git(&repository, &["add", "value.txt"]);
        git(&repository, &["commit", "-m", "base"]);
        let base = git(&repository, &["rev-parse", "HEAD"]);

        let solver = temporary.path().join("solver.py");
        let solver_count = temporary.path().join("solver-count");
        let solver_inputs = temporary.path().join("solver-inputs");
        std::fs::write(
            &solver,
            r#"import json, pathlib, sys
request = sys.stdin.read()
count_path, inputs_path = map(pathlib.Path, sys.argv[1:3])
count = int(count_path.read_text()) + 1 if count_path.exists() else 1
count_path.write_text(str(count))
with inputs_path.open("a") as output: output.write(request + "\n")
if count == 2 and "visible checks failed" not in request: sys.exit(8)
replacement = "still-bad" if count == 1 else "good"
patch = "diff --git a/value.txt b/value.txt\n--- a/value.txt\n+++ b/value.txt\n@@ -1 +1 @@\n-bad\n+" + replacement + "\n"
json.dump({"patch":patch,"tokens":1,"cost_micros":1,"time_millis":1,"provenance":"sha256:7f90d7e3f6d17e625c56b260c6b57629252c3c0e96eea4d9929d8fbbc4e6c6f1","rationale":"fixture"}, sys.stdout)
"#,
        )
        .unwrap();
        let verifier = verifier_root.join("verifier.py");
        std::fs::write(
            &verifier,
            r#"import base64, json, sys
request = json.load(sys.stdin)
candidate = request["candidate_digest"]
if b"+good\n" not in base64.b64decode(request["candidate_patch_base64"]): sys.exit(9)
if request["changed_paths"] != ["value.txt"] or len(request["immutable_base_revision"]) != 40: sys.exit(10)
roles = [("BaselineVulnerable","Failed",1),("GoldControl","Passed",20),("CandidateHidden","Passed",4),("CandidateRegression","Passed",20)]
observations=[]
for repetition in (1,2):
  for index,(role,outcome,count) in enumerate(roles):
    observations.append({"id":"execution_%08d" % (repetition*10+index),"role":role,"repetition":repetition,"outcome":outcome,"test_count":count,"result_digest":"sha256:"+("%064x" % (index+1)),"conformant":True})
json.dump({"organization_id":"org_organization1","run_id":"run_00000001","policy":{"repetitions":2,"max_changed_lines":10,"allowed_path_prefixes":["value.txt"],"forbidden_paths":[]},"patch":{"patch_digest":candidate,"changed_paths":["value.txt"],"changed_lines":2},"observations":observations},sys.stdout)
"#,
        )
        .unwrap();
        let config = AutomationConfig {
            worker_id: "worker0001".into(),
            run_id: "run_00000001".into(),
            baseline_observation: "observation_00000001".into(),
            supersedes_candidate_digest: None,
            organization_id: "organization1".into(),
            external_grant_id: "grant0001".into(),
            verifier_root: verifier_root.clone(),
            verifier: CommandSpec {
                program: "/usr/bin/python3".into(),
                arguments: vec![verifier.to_string_lossy().into()],
            },
            verifier_results_path: results_root,
            candidate_artifacts_path: artifacts_root.clone(),
            solver_problem: "replace the vulnerable value".into(),
            source_digest: Sha256Digest::of_bytes(b"public source").to_tagged_hex(),
            allowed_paths: vec!["value.txt".into()],
            allowed_tools: vec!["patch".into()],
            checkout_path: repository.clone(),
            base_revision: base.clone(),
            remediation_branch: "cauterizer/fixture".into(),
            pull_request_base_branch: "main".into(),
            solver: CommandSpec {
                program: "/usr/bin/python3".into(),
                arguments: vec![
                    solver.to_string_lossy().into(),
                    solver_count.to_string_lossy().into(),
                    solver_inputs.to_string_lossy().into(),
                ],
            },
            visible_commands: vec![CommandSpec {
                program: "/usr/bin/grep".into(),
                arguments: vec!["-qx".into(), "good".into(), "value.txt".into()],
            }],
            budgets: AutomationBudgets {
                attempts: 2,
                solver_units: 10,
                command_timeout_seconds: 10,
                output_bytes: 65_536,
                spend_micros: 10,
                patch_bytes: 4096,
                changed_lines: 10,
            },
            runtime_isolation: RuntimeIsolationConfig {
                runtime: PathBuf::from("/usr/bin/podman"),
                solver_image: format!(
                    "solver@{}",
                    Sha256Digest::of_bytes(b"solver image").to_tagged_hex()
                ),
                verifier_image: format!(
                    "verifier@{}",
                    Sha256Digest::of_bytes(b"verifier image").to_tagged_hex()
                ),
                visible_image: format!(
                    "visible@{}",
                    Sha256Digest::of_bytes(b"visible image").to_tagged_hex()
                ),
                solver_user: "10001:10001".into(),
                verifier_user: "10002:10002".into(),
                visible_user: "10003:10003".into(),
                memory: "256m".into(),
                cpus: "1".into(),
                pids_limit: 64,
            },
            github_installation: "installation_00000001".into(),
            github_repository: "acme/widget".into(),
            postgres_url_env: "DATABASE_URL".into(),
            github_token_env: "GITHUB_TOKEN".into(),
            dry_run: false,
        };
        let organization = OrganizationId::new("organization1").unwrap();
        let binding = ArtifactBinding {
            organization_id: organization.clone(),
            run_id: config.run_id.clone(),
            repository: config.github_repository.clone(),
            installation_id: config.github_installation.clone(),
        };
        let artifacts = FilesystemCandidateArtifacts::new(&artifacts_root, binding).unwrap();
        let generated_result = ProductionGenerationPipeline {
            config: &config,
            organization: &organization,
            run_ref: config.run_id.parse().unwrap(),
            run_id: RemediationRunId::new("00000001").unwrap(),
            artifacts,
        }
        .run();
        assert!(
            generated_result.is_ok(),
            "generation failed; solver count={:?}; inputs={:?}; artifacts={:?}",
            std::fs::read_to_string(&solver_count),
            std::fs::read_to_string(&solver_inputs),
            std::fs::read_dir(&artifacts_root)
                .unwrap()
                .map(|item| item.unwrap().path())
                .collect::<Vec<_>>()
        );
        let generated = generated_result.unwrap();
        assert!(matches!(
            generated.transcript.outcome,
            RepairOutcome::Verified { .. }
        ));
        assert_eq!(generated.transcript.attempts.len(), 2);
        assert_eq!(std::fs::read_to_string(&solver_count).unwrap(), "2");
        assert!(
            std::fs::read_to_string(&solver_inputs)
                .unwrap()
                .contains("visible checks failed")
        );
        let published = generated.published.unwrap();
        assert_eq!(
            git(&repository, &["rev-parse", "cauterizer/fixture"]),
            published.commit_oid.as_str()
        );
        assert_ne!(published.commit_oid.as_str(), base);
        assert!(generated.verified_evidence.is_some());

        let requests = [
            (
                ReviewStage::Issue,
                planned_request(ActionCapability::CreateIssue, 1),
                None,
            ),
            (
                ReviewStage::Branch,
                planned_request(ActionCapability::CreateRemediationBranch, 2),
                None,
            ),
            (
                ReviewStage::Commit,
                planned_request(ActionCapability::PushCandidateCommit, 3),
                None,
            ),
            (
                ReviewStage::PullRequest,
                planned_request(ActionCapability::OpenPullRequest, 4),
                None,
            ),
            (
                ReviewStage::Summary,
                planned_request(ActionCapability::PostVerificationResult, 5),
                Some(ReviewStage::PullRequest),
            ),
        ];
        let plan = delivery_plan(PlanKind::VerifiedReview, requests).unwrap();
        let key = ReviewDeliveryKey {
            organization_id: organization,
            run_id: RemediationRunId::new("00000001").unwrap(),
            candidate_digest: generated.candidate.patch_digest,
        };
        let initial = VersionedDelivery {
            delivery: ReviewDelivery::new(key, plan),
            version: 0,
        };
        let reviews = FakeReviews(Arc::new(Mutex::new(initial.clone())));
        let actions = FakeActions::default();
        let mut active = initial;
        resume_delivery(&actions, &reviews, &mut active)
            .await
            .unwrap();
        assert_eq!(actions.0.lock().unwrap().len(), 5);
        resume_delivery(&actions, &reviews, &mut active)
            .await
            .unwrap();
        assert_eq!(
            actions.0.lock().unwrap().len(),
            5,
            "restart must make zero remote calls"
        );
    }
}
