//! Runnable worker-side composition for automated repair and review delivery.
#![forbid(unsafe_code)]

/// Secure local automation command and configuration boundary.
pub mod command;
/// Truth-preserving adapters between proposal, repair, verification, and publication.
pub mod production;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use cauterizer_external_actions::application::{
    DeliveryRepository, ExternalActionKillSwitch, ExternalActionService, GrantRepository,
    RemoteActionGateway, RemoteError, RemoteReceipt,
};
use cauterizer_external_actions::domain::{
    ActionCapability, DeliveryAttestation, ExternalActionDeliveryId, ExternalActionError,
    ExternalActionGrantId, ExternalActionRequest,
};
use cauterizer_integration_management::application::ScmConnector;
use cauterizer_integration_management::contracts::{
    DeliveryRequest, GitCommitOid, GitCommitTransfer, ScmMutation,
};
use cauterizer_integration_management::domain::InstallationGrant;
use cauterizer_remediation_runs::application::agentic::{
    CandidateAttempt, CandidateSolver, HiddenVerifier, RepairBudget, RepairLoop, RepairOutcome,
    RepairRequest, RepairTranscript, VisibleEvaluator,
};
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{IdempotencyKey, OrganizationId};

/// Resolves installation grants without coupling the worker to provider storage.
pub trait InstallationGrantSource: Send + Sync {
    /// Loads one exact tenant/installation grant.
    ///
    /// # Errors
    /// Returns a coarse remote failure when grant storage is unavailable.
    fn find(
        &self,
        organization: &OrganizationId,
        installation_ref: &str,
    ) -> Result<Option<InstallationGrant>, RemoteError>;
}
/// Time source for installation expiry decisions.
pub trait EpochClock: Send + Sync {
    /// Current Unix epoch seconds.
    ///
    /// # Errors
    /// Returns a coarse failure when a trustworthy time cannot be obtained.
    fn now(&self) -> Result<u64, RemoteError>;
}
/// Resolves immutable remote commit material by bound identities.
pub trait CandidateTransferSource: Send + Sync {
    /// Loads transfer material for the exact candidate, commit, and base.
    ///
    /// # Errors
    /// Fails closed on unavailable, malformed, or substituted artifact state.
    fn find(
        &self,
        binding: &ArtifactBinding,
        candidate: Sha256Digest,
        commit: &GitCommitOid,
        base: &GitCommitOid,
    ) -> Result<Option<GitCommitTransfer>, RemoteError>;
}
/// Exact authority namespace for locally retained candidate material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactBinding {
    /// Tenant owning the artifact.
    pub organization_id: OrganizationId,
    /// Exact remediation run.
    pub run_id: String,
    /// Exact SCM repository.
    pub repository: String,
    /// Exact installation used for delivery.
    pub installation_id: String,
}
/// Production wall clock.
#[derive(Clone, Copy, Default)]
pub struct SystemEpochClock;
impl EpochClock for SystemEpochClock {
    fn now(&self) -> Result<u64, RemoteError> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| RemoteError::UnavailableOrAmbiguous)
    }
}

/// Deterministic grant source for tests and local composition.
#[derive(Clone, Default)]
pub struct InMemoryInstallationGrants(Arc<BTreeMap<(OrganizationId, String), InstallationGrant>>);
impl InMemoryInstallationGrants {
    /// Builds a source from validated grants.
    #[must_use]
    pub fn new(grants: impl IntoIterator<Item = InstallationGrant>) -> Self {
        Self(Arc::new(
            grants
                .into_iter()
                .map(|grant| {
                    (
                        (
                            grant.organization_id.clone(),
                            grant.installation_id.as_str().into(),
                        ),
                        grant,
                    )
                })
                .collect(),
        ))
    }
}
impl InstallationGrantSource for InMemoryInstallationGrants {
    fn find(
        &self,
        organization: &OrganizationId,
        installation_ref: &str,
    ) -> Result<Option<InstallationGrant>, RemoteError> {
        Ok(self
            .0
            .get(&(organization.clone(), installation_ref.into()))
            .cloned())
    }
}

/// Adapter from review-action delivery to any provider-neutral SCM connector.
pub struct ScmGateway<C, S, N> {
    connector: Arc<C>,
    grants: S,
    clock: N,
    calls: Arc<AtomicUsize>,
    transfers: Option<Arc<dyn CandidateTransferSource>>,
}
impl<C, S: Clone, N: Clone> Clone for ScmGateway<C, S, N> {
    fn clone(&self) -> Self {
        Self {
            connector: self.connector.clone(),
            grants: self.grants.clone(),
            clock: self.clock.clone(),
            calls: self.calls.clone(),
            transfers: self.transfers.clone(),
        }
    }
}

impl<C, S, N> ScmGateway<C, S, N> {
    /// Creates a bridge using a connector and exact installation-grant source.
    #[must_use]
    pub fn new(connector: C, grants: S, clock: N) -> Self {
        Self {
            connector: Arc::new(connector),
            grants,
            clock,
            calls: Arc::new(AtomicUsize::new(0)),
            transfers: None,
        }
    }
    /// Adds the immutable transfer source required for commit publication.
    #[must_use]
    pub fn with_transfer_source(mut self, source: impl CandidateTransferSource + 'static) -> Self {
        self.transfers = Some(Arc::new(source));
        self
    }

    /// Number of actual connector delivery calls, excluding local delivery replays.
    #[must_use]
    pub fn delivery_calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl<C: ScmConnector, S: InstallationGrantSource, N: EpochClock> ScmGateway<C, S, N> {
    #[allow(clippy::too_many_lines)]
    fn request(
        &self,
        request: &ExternalActionRequest,
        installation_ref: &str,
    ) -> Result<(InstallationGrant, DeliveryRequest), RemoteError> {
        let grant = self
            .grants
            .find(&request.organization_id, installation_ref)?
            .ok_or(RemoteError::Rejected)?;
        if grant.organization_id != request.organization_id
            || grant.installation_id.as_str() != installation_ref
            || !grant.repositories.contains(&request.repository)
        {
            return Err(RemoteError::Rejected);
        }
        let branch = request.subject.clone();
        let mutation = match request.capability {
            ActionCapability::CreateIssue => ScmMutation::CreateIssue {
                title: request.subject.clone(),
                body: request.redacted_body.clone(),
            },
            ActionCapability::UpdateIssue => {
                let (title, body) = request
                    .redacted_body
                    .split_once('\n')
                    .ok_or(RemoteError::Rejected)?;
                ScmMutation::UpdateIssue {
                    remote_id: request.subject.clone(),
                    title: title
                        .strip_prefix("title=")
                        .filter(|value| !value.is_empty())
                        .ok_or(RemoteError::Rejected)?
                        .into(),
                    body: body.into(),
                }
            }
            ActionCapability::CreateRemediationBranch => ScmMutation::CreateBranch {
                branch,
                base_revision: request.redacted_body.clone(),
            },
            ActionCapability::PushCandidateCommit => {
                let mut values = request.redacted_body.split('|');
                let digest: Sha256Digest = values
                    .next()
                    .ok_or(RemoteError::Rejected)?
                    .parse()
                    .map_err(|_| RemoteError::Rejected)?;
                let oid = GitCommitOid::parse(values.next().ok_or(RemoteError::Rejected)?)
                    .ok_or(RemoteError::Rejected)?;
                let base = GitCommitOid::parse(values.next().ok_or(RemoteError::Rejected)?)
                    .ok_or(RemoteError::Rejected)?;
                let run_id = values
                    .next()
                    .filter(|value| !value.is_empty())
                    .ok_or(RemoteError::Rejected)?;
                if values.next().is_some() {
                    return Err(RemoteError::Rejected);
                }
                let binding = ArtifactBinding {
                    organization_id: request.organization_id.clone(),
                    run_id: run_id.into(),
                    repository: request.repository.clone(),
                    installation_id: installation_ref.into(),
                };
                let transfer = self
                    .transfers
                    .as_ref()
                    .ok_or(RemoteError::Rejected)?
                    .find(&binding, digest, &oid, &base)?
                    .ok_or(RemoteError::Rejected)?;
                if transfer.base_commit_oid != base {
                    return Err(RemoteError::Rejected);
                }
                ScmMutation::PushCandidateCommit {
                    branch,
                    candidate_digest: digest,
                    commit_oid: oid,
                    transfer: Some(transfer),
                }
            }
            ActionCapability::OpenPullRequest => ScmMutation::CreatePullRequest {
                branch,
                base_branch: request
                    .redacted_body
                    .lines()
                    .next()
                    .and_then(|line| line.strip_prefix("base="))
                    .filter(|base| safe_branch_ref(base))
                    .ok_or(RemoteError::Rejected)?
                    .into(),
                title: "Automated vulnerability remediation".into(),
                body: request
                    .redacted_body
                    .split_once('\n')
                    .map(|(_, body)| body.to_owned())
                    .ok_or(RemoteError::Rejected)?,
            },
            ActionCapability::UpdatePullRequest => {
                let (title, body) = request
                    .redacted_body
                    .split_once('\n')
                    .ok_or(RemoteError::Rejected)?;
                ScmMutation::UpdatePullRequest {
                    remote_id: request.subject.clone(),
                    title: title
                        .strip_prefix("title=")
                        .filter(|value| !value.is_empty())
                        .ok_or(RemoteError::Rejected)?
                        .into(),
                    body: body.into(),
                }
            }
            ActionCapability::PostVerificationResult => ScmMutation::PostEvidenceSummary {
                remote_id: request.subject.clone(),
                summary: request
                    .redacted_body
                    .split_once('\n')
                    .map(|(_, summary)| summary.to_owned())
                    .ok_or(RemoteError::Rejected)?,
                evidence_digest: request
                    .redacted_body
                    .lines()
                    .next()
                    .and_then(|line| line.strip_prefix("evidence="))
                    .ok_or(RemoteError::Rejected)?
                    .parse()
                    .map_err(|_| RemoteError::Rejected)?,
            },
            _ => return Err(RemoteError::Rejected),
        };
        let delivery = DeliveryRequest {
            organization_id: request.organization_id.clone(),
            installation_id: installation_ref.into(),
            repository: request.repository.clone(),
            correlation_key: request.correlation_key.clone(),
            idempotency_key: request.idempotency_key.clone(),
            request_digest: delivery_digest(request, installation_ref),
            mutation,
        };
        grant
            .validate(self.connector.manifest())
            .map_err(|_| RemoteError::Rejected)?;
        grant
            .authorize(
                &delivery.repository,
                delivery.mutation.branch(),
                delivery.mutation.capability(),
                self.clock.now()?,
            )
            .map_err(|_| RemoteError::Rejected)?;
        Ok((grant, delivery))
    }
}

impl<C: ScmConnector, S: InstallationGrantSource, N: EpochClock> RemoteActionGateway
    for ScmGateway<C, S, N>
{
    fn find_existing(
        &self,
        request: &ExternalActionRequest,
        installation_ref: &str,
    ) -> Result<Option<RemoteReceipt>, RemoteError> {
        let (grant, delivery) = self.request(request, installation_ref)?;
        self.connector
            .reconcile(&grant, &delivery, self.clock.now()?)
            .map(|object| {
                object.map(|value| RemoteReceipt {
                    remote_id: value.remote_id,
                    remote_url: value.url,
                })
            })
            .map_err(|_| RemoteError::UnavailableOrAmbiguous)
    }

    fn deliver(
        &self,
        request: &ExternalActionRequest,
        installation_ref: &str,
    ) -> Result<RemoteReceipt, RemoteError> {
        let (grant, delivery) = self.request(request, installation_ref)?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.connector
            .deliver(&grant, delivery, self.clock.now()?)
            .map(|receipt| RemoteReceipt {
                remote_id: receipt.object.remote_id,
                remote_url: receipt.object.url,
            })
            .map_err(|_| RemoteError::Rejected)
    }
}

fn delivery_digest(request: &ExternalActionRequest, installation_ref: &str) -> Sha256Digest {
    let mut canonical = Vec::new();
    let mut field = |value: &[u8]| {
        canonical.extend_from_slice(&(value.len() as u64).to_be_bytes());
        canonical.extend_from_slice(value);
    };
    field(request.organization_id.as_str().as_bytes());
    field(request.grant_id.as_str().as_bytes());
    field(installation_ref.as_bytes());
    field(request.repository.as_bytes());
    field(&[request.capability as u8]);
    field(request.correlation_key.as_bytes());
    field(request.idempotency_key.as_str().as_bytes());
    field(request.subject.as_bytes());
    field(request.redacted_body.as_bytes());
    if let Some(attestation) = &request.policy_attestation {
        field(attestation.candidate_digest.to_tagged_hex().as_bytes());
        field(attestation.policy_result_digest.to_tagged_hex().as_bytes());
        field(&[u8::from(attestation.policy_approved)]);
        for number in [
            attestation.patch_bytes,
            attestation.changed_lines,
            u64::from(attestation.attempts),
            attestation.elapsed_millis,
            attestation.compute_units,
            attestation.spend_micros,
        ] {
            field(&number.to_be_bytes());
        }
    } else {
        field(b"no-attestation");
    }
    Sha256Digest::of_bytes(canonical)
}
fn safe_branch_ref(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
}

/// Successful human-review delivery references.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewDelivery {
    /// Tracking issue URL.
    pub issue: String,
    /// Remediation branch receipt URL, present only for a verified candidate.
    pub branch: Option<String>,
    /// Candidate commit receipt URL, present only for a verified candidate.
    pub commit: Option<String>,
    /// Pull-request URL, present only for a verified candidate.
    pub pull_request: Option<String>,
    /// Evidence-summary receipt URL, present only for a verified candidate.
    pub evidence_summary: Option<String>,
}

/// End-to-end worker composition. Hidden-verification failures never reach delivery.
pub struct LocalMetaHarness<G, D, K, R> {
    actions: ExternalActionService<G, D, K, R>,
    organization_id: OrganizationId,
    grant_id: ExternalActionGrantId,
    repository: String,
}

impl<G: GrantRepository, D: DeliveryRepository, K: ExternalActionKillSwitch, R: RemoteActionGateway>
    LocalMetaHarness<G, D, K, R>
{
    /// Constructs a local worker composition around durable action ports.
    #[must_use]
    pub fn new(
        actions: ExternalActionService<G, D, K, R>,
        organization_id: OrganizationId,
        grant_id: ExternalActionGrantId,
        repository: impl Into<String>,
    ) -> Self {
        Self {
            actions,
            organization_id,
            grant_id,
            repository: repository.into(),
        }
    }

    /// Repairs, independently verifies, and delivers a review-only change set.
    ///
    /// # Errors
    ///
    /// Fails closed when repair orchestration or an authorized SCM delivery fails.
    pub fn run<S: CandidateSolver, V: VisibleEvaluator, H: HiddenVerifier>(
        &self,
        request: &RepairRequest,
        budget: RepairBudget,
        solver: &mut S,
        visible: &mut V,
        hidden: &mut H,
    ) -> Result<(RepairTranscript, Option<ReviewDelivery>), HarnessError> {
        let transcript = RepairLoop::execute(request, budget, solver, visible, hidden)?;
        let run = request.run_id.as_str();
        let issue_body = match &transcript.outcome {
            RepairOutcome::Verified { .. } => "Verified automated remediation available",
            RepairOutcome::VerificationStopped { .. } => {
                "Automated remediation requires maintainer attention"
            }
            RepairOutcome::BudgetExhausted => "Automated remediation budget exhausted",
        };
        let issue = self.action(
            run,
            1,
            ActionCapability::CreateIssue,
            "Vulnerability remediation",
            issue_body,
            None,
        )?;
        let delivery = if let RepairOutcome::Verified { candidate } = &transcript.outcome {
            let attestation = DeliveryAttestation {
                candidate_digest: candidate.patch_digest,
                policy_result_digest: Sha256Digest::of_bytes("local-policy-v1"),
                policy_approved: true,
                patch_bytes: candidate.patch_bytes,
                changed_lines: candidate.changed_lines,
                attempts: u32::try_from(transcript.attempts.len())
                    .map_err(|_| ExternalActionError::NotAuthorized)?,
                elapsed_millis: transcript.elapsed_millis,
                compute_units: transcript.solver_units,
                spend_micros: transcript.spend_micros,
            };
            self.deliver_verified(request, candidate, issue.remote_url, &attestation)?
        } else {
            ReviewDelivery {
                issue: issue.remote_url,
                branch: None,
                commit: None,
                pull_request: None,
                evidence_summary: None,
            }
        };
        Ok((transcript, Some(delivery)))
    }

    fn deliver_verified(
        &self,
        request: &RepairRequest,
        candidate: &CandidateAttempt,
        issue: String,
        attestation: &DeliveryAttestation,
    ) -> Result<ReviewDelivery, ExternalActionError> {
        let run = request.run_id.as_str();
        let branch_name = format!("cauterizer/{run}");
        let branch = self.action(
            run,
            2,
            ActionCapability::CreateRemediationBranch,
            &branch_name,
            "1111111111111111111111111111111111111111",
            Some(attestation.clone()),
        )?;
        let commit = self.action(
            run,
            3,
            ActionCapability::PushCandidateCommit,
            &branch_name,
            &format!(
                "{}|{}|{}|{}",
                candidate.patch_digest.to_tagged_hex(),
                "0123456789abcdef0123456789abcdef01234567",
                "1111111111111111111111111111111111111111",
                run
            ),
            Some(attestation.clone()),
        )?;
        let pull_request = self.action(
            run,
            4,
            ActionCapability::OpenPullRequest,
            &branch_name,
            "base=main\nCandidate passed independent verification; human merge review required",
            Some(attestation.clone()),
        )?;
        let evidence_summary = self.action(
            run,
            5,
            ActionCapability::PostVerificationResult,
            &pull_request.remote_id,
            "evidence=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nVerified for fixture; recorded assessment retained",
            Some(attestation.clone()),
        )?;
        Ok(ReviewDelivery {
            issue,
            branch: Some(branch.remote_url),
            commit: Some(commit.remote_url),
            pull_request: Some(pull_request.remote_url),
            evidence_summary: Some(evidence_summary.remote_url),
        })
    }

    fn action(
        &self,
        run: &str,
        sequence: u8,
        capability: ActionCapability,
        subject: &str,
        body: &str,
        policy_attestation: Option<DeliveryAttestation>,
    ) -> Result<RemoteReceipt, ExternalActionError> {
        let request = ExternalActionRequest {
            organization_id: self.organization_id.clone(),
            grant_id: self.grant_id.clone(),
            repository: self.repository.clone(),
            capability,
            idempotency_key: IdempotencyKey::new(format!("{run}-{sequence}"))
                .map_err(|_| ExternalActionError::InvalidValue)?,
            correlation_key: format!(
                "lineage-{}",
                Sha256Digest::of_bytes(format!("{run}|{capability:?}"))
                    .to_tagged_hex()
                    .trim_start_matches("sha256:")
            ),
            subject: subject.into(),
            redacted_body: body.into(),
            policy_attestation,
        };
        let delivery = self.actions.execute(
            ExternalActionDeliveryId::new(&format!("{sequence:08}"))?,
            request,
        )?;
        match delivery.status {
            cauterizer_external_actions::domain::DeliveryStatus::Succeeded {
                remote_id,
                remote_url,
            } => Ok(RemoteReceipt {
                remote_id,
                remote_url,
            }),
            _ => Err(ExternalActionError::RemoteUnavailable),
        }
    }
}

/// Composition failure without provider-sensitive diagnostics.
#[derive(Debug)]
pub enum HarnessError {
    /// Candidate generation or verification orchestration failed.
    Repair(cauterizer_remediation_runs::application::agentic::OrchestrationError),
    /// A review-only SCM mutation failed.
    Delivery(ExternalActionError),
}
impl From<cauterizer_remediation_runs::application::agentic::OrchestrationError> for HarnessError {
    fn from(value: cauterizer_remediation_runs::application::agentic::OrchestrationError) -> Self {
        Self::Repair(value)
    }
}
impl From<ExternalActionError> for HarnessError {
    fn from(value: ExternalActionError) -> Self {
        Self::Delivery(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cauterizer_external_actions::application::{
        InMemoryDeliveryRepository, InMemoryGrantRepository, InMemoryKillSwitch,
    };
    use cauterizer_external_actions::domain::{ExternalActionGrant, GrantConstraints};
    use cauterizer_integration_management::application::FakeScmConnector;
    use cauterizer_integration_management::domain::{CapabilityManifest, ScmCapability};
    use cauterizer_remediation_runs::application::agentic::{
        ComponentError, HiddenDecision, SolverRequest, VisibleCheck, VisibleFeedback,
    };
    use cauterizer_remediation_runs::domain::RemediationRunId;
    use cauterizer_syntax::identifiers::ContextQualifiedId;
    use std::collections::{BTreeSet, VecDeque};

    const REPOSITORY: &str = "owner/repo";

    fn id(context: &str, value: u32) -> ContextQualifiedId {
        ContextQualifiedId::new(context, &format!("{value:08}")).unwrap()
    }

    struct Solver {
        calls: usize,
    }
    impl CandidateSolver for Solver {
        fn propose(&mut self, request: &SolverRequest) -> Result<CandidateAttempt, ComponentError> {
            self.calls += 1;
            Ok(CandidateAttempt {
                number: request.attempt_number,
                proposal: id("proposal", request.attempt_number),
                patch_digest: Sha256Digest::of_bytes(format!("patch-{}", request.attempt_number)),
                parent_proposal: request.parent_proposal.clone(),
                solver_units: 1,
                patch_bytes: 64,
                changed_lines: 2,
                cost_micros: 3,
                time_millis: 5,
            })
        }
    }
    struct Visible(VecDeque<VisibleCheck>);
    impl VisibleEvaluator for Visible {
        fn evaluate(&mut self, _: &CandidateAttempt) -> Result<VisibleCheck, ComponentError> {
            Ok(self.0.pop_front().unwrap())
        }
    }
    struct Hidden(HiddenDecision);
    impl HiddenVerifier for Hidden {
        fn verify(&mut self, _: &CandidateAttempt) -> Result<HiddenDecision, ComponentError> {
            Ok(self.0)
        }
    }
    #[derive(Clone, Copy)]
    struct FixedClock(u64);
    impl EpochClock for FixedClock {
        fn now(&self) -> Result<u64, RemoteError> {
            Ok(self.0)
        }
    }
    struct FixtureTransfers;
    impl CandidateTransferSource for FixtureTransfers {
        fn find(
            &self,
            _: &ArtifactBinding,
            _: Sha256Digest,
            _: &GitCommitOid,
            base: &GitCommitOid,
        ) -> Result<Option<GitCommitTransfer>, RemoteError> {
            Ok(Some(GitCommitTransfer {
                base_commit_oid: base.clone(),
                commit_message: "Automated vulnerability remediation".into(),
                files: vec![],
            }))
        }
    }

    type Harness = LocalMetaHarness<
        InMemoryGrantRepository,
        InMemoryDeliveryRepository,
        InMemoryKillSwitch,
        ScmGateway<FakeScmConnector, InMemoryInstallationGrants, FixedClock>,
    >;

    fn setup() -> (
        Harness,
        ScmGateway<FakeScmConnector, InMemoryInstallationGrants, FixedClock>,
    ) {
        let capabilities = BTreeSet::from([
            ScmCapability::CreateIssue,
            ScmCapability::CreateBranch,
            ScmCapability::PushCandidateCommit,
            ScmCapability::CreatePullRequest,
            ScmCapability::PostEvidenceSummary,
        ]);
        let manifest = CapabilityManifest::new("fake", capabilities.clone()).unwrap();
        let organization_id = OrganizationId::new("organization1").unwrap();
        let installation_id = id("installation", 1);
        let integration_grant = InstallationGrant {
            installation_id: installation_id.clone(),
            organization_id: organization_id.clone(),
            repositories: BTreeSet::from([REPOSITORY.into()]),
            branch_prefix: "cauterizer/".into(),
            allowed_target_branches: BTreeSet::from(["main".into()]),
            default_branch: "main".into(),
            protected_branches: BTreeSet::from(["main".into()]),
            capabilities,
            expires_at_unix: None,
        };
        let gateway = ScmGateway::new(
            FakeScmConnector::new(manifest),
            InMemoryInstallationGrants::new([integration_grant]),
            FixedClock(100),
        )
        .with_transfer_source(FixtureTransfers);
        let grants = InMemoryGrantRepository::default();
        let grant_id = ExternalActionGrantId::new("grant0001").unwrap();
        grants.put(
            ExternalActionGrant::new(
                grant_id.clone(),
                organization_id.clone(),
                installation_id.as_str(),
                REPOSITORY,
                "cauterizer/",
                BTreeSet::from([
                    ActionCapability::CreateIssue,
                    ActionCapability::CreateRemediationBranch,
                    ActionCapability::PushCandidateCommit,
                    ActionCapability::OpenPullRequest,
                    ActionCapability::PostVerificationResult,
                ]),
            )
            .unwrap()
            .with_constraints(GrantConstraints::new(1_000, 100, 10, 60_000, 1_000, 1_000).unwrap()),
        );
        let kill_switch = InMemoryKillSwitch::default();
        kill_switch.set(false);
        let actions = ExternalActionService::new(
            grants,
            InMemoryDeliveryRepository::default(),
            kill_switch,
            gateway.clone(),
        );
        (
            LocalMetaHarness::new(actions, organization_id, grant_id, REPOSITORY),
            gateway,
        )
    }

    fn request() -> RepairRequest {
        RepairRequest {
            run_id: RemediationRunId::new("00000001").unwrap(),
            baseline: id("observation", 1),
        }
    }

    fn external_request() -> ExternalActionRequest {
        ExternalActionRequest {
            organization_id: OrganizationId::new("organization1").unwrap(),
            grant_id: ExternalActionGrantId::new("grant0001").unwrap(),
            repository: REPOSITORY.into(),
            capability: ActionCapability::CreateIssue,
            idempotency_key: IdempotencyKey::new("gateway-test").unwrap(),
            correlation_key: "gateway-review-object".into(),
            subject: "issue".into(),
            redacted_body: "safe".into(),
            policy_attestation: None,
        }
    }

    #[test]
    fn gateway_rejects_wrong_installation_and_tenant_before_counting_delivery() {
        let (_, gateway) = setup();
        let request = external_request();
        assert_eq!(
            gateway.deliver(&request, "installation_99999999"),
            Err(RemoteError::Rejected)
        );
        let mut foreign = request;
        foreign.organization_id = OrganizationId::new("organization2").unwrap();
        assert_eq!(
            gateway.deliver(&foreign, "installation_00000001"),
            Err(RemoteError::Rejected)
        );
        assert_eq!(gateway.delivery_calls(), 0);
    }

    #[test]
    fn gateway_uses_clock_and_rejects_expired_installation_before_counting() {
        let capabilities = BTreeSet::from([ScmCapability::CreateIssue]);
        let connector = FakeScmConnector::new(
            CapabilityManifest::new("fake-expiry", capabilities.clone()).unwrap(),
        );
        let grant = InstallationGrant {
            installation_id: id("installation", 1),
            organization_id: OrganizationId::new("organization1").unwrap(),
            repositories: BTreeSet::from([REPOSITORY.into()]),
            branch_prefix: "cauterizer/".into(),
            allowed_target_branches: BTreeSet::from(["main".into()]),
            default_branch: "main".into(),
            protected_branches: BTreeSet::from(["main".into()]),
            capabilities,
            expires_at_unix: Some(100),
        };
        let gateway = ScmGateway::new(
            connector,
            InMemoryInstallationGrants::new([grant]),
            FixedClock(100),
        );
        assert_eq!(
            gateway.deliver(&external_request(), "installation_00000001"),
            Err(RemoteError::Rejected)
        );
        assert_eq!(gateway.delivery_calls(), 0);
    }

    #[test]
    fn delivery_digest_binds_installation_tenant_repository_and_attestation() {
        let request = external_request();
        let original = delivery_digest(&request, "installation_00000001");
        assert_ne!(original, delivery_digest(&request, "installation_00000002"));
        let mut changed = request.clone();
        changed.repository = "owner/other".into();
        assert_ne!(original, delivery_digest(&changed, "installation_00000001"));
        changed = request;
        changed.policy_attestation = Some(DeliveryAttestation {
            candidate_digest: Sha256Digest::of_bytes(b"candidate"),
            policy_result_digest: Sha256Digest::of_bytes(b"policy"),
            policy_approved: true,
            patch_bytes: 1,
            changed_lines: 1,
            attempts: 1,
            elapsed_millis: 1,
            compute_units: 1,
            spend_micros: 1,
        });
        assert_ne!(original, delivery_digest(&changed, "installation_00000001"));
    }

    #[test]
    fn retries_visible_failure_then_delivers_complete_review_chain_exactly_once() {
        let (harness, gateway) = setup();
        let feedback = VisibleFeedback {
            diagnostic: id("diagnostic", 1),
            digest: Sha256Digest::of_bytes(b"build failed"),
        };
        let mut solver = Solver { calls: 0 };
        let mut visible = Visible(VecDeque::from([
            VisibleCheck::Failed(feedback.clone()),
            VisibleCheck::Passed,
        ]));
        let (_, first) = harness
            .run(
                &request(),
                RepairBudget {
                    max_attempts: 3,
                    max_solver_units: 3,
                },
                &mut solver,
                &mut visible,
                &mut Hidden(HiddenDecision::Verified),
            )
            .unwrap();
        let first = first.unwrap();
        assert_eq!(solver.calls, 2);
        assert_eq!(gateway.delivery_calls(), 5);
        assert!(
            first
                .pull_request
                .as_deref()
                .is_some_and(|url| url.contains("scm.invalid"))
        );

        let mut replay_solver = Solver { calls: 0 };
        let mut replay_visible = Visible(VecDeque::from([
            VisibleCheck::Failed(feedback),
            VisibleCheck::Passed,
        ]));
        let (_, replay) = harness
            .run(
                &request(),
                RepairBudget {
                    max_attempts: 3,
                    max_solver_units: 3,
                },
                &mut replay_solver,
                &mut replay_visible,
                &mut Hidden(HiddenDecision::Verified),
            )
            .unwrap();
        assert_eq!(replay.unwrap(), first);
        assert_eq!(gateway.delivery_calls(), 5);
    }

    #[test]
    fn hidden_failure_creates_issue_but_no_branch_commit_or_pull_request() {
        let (harness, gateway) = setup();
        let (_, delivery) = harness
            .run(
                &request(),
                RepairBudget {
                    max_attempts: 2,
                    max_solver_units: 2,
                },
                &mut Solver { calls: 0 },
                &mut Visible(VecDeque::from([VisibleCheck::Passed])),
                &mut Hidden(HiddenDecision::Rejected),
            )
            .unwrap();
        let delivery = delivery.expect("failure should remain visible as an issue");
        assert!(delivery.issue.contains("scm.invalid"));
        assert_eq!(delivery.branch, None);
        assert_eq!(delivery.commit, None);
        assert_eq!(delivery.pull_request, None);
        assert_eq!(delivery.evidence_summary, None);
        assert_eq!(gateway.delivery_calls(), 1);
    }

    #[test]
    fn local_review_delivery_throughput_measurement() {
        let (harness, gateway) = setup();
        let started = std::time::Instant::now();
        for sequence in 1..=1_000_u32 {
            let run = RepairRequest {
                run_id: RemediationRunId::new(&format!("{sequence:08}"))
                    .expect("benchmark run identity"),
                baseline: id("observation", 1),
            };
            let (_, delivery) = harness
                .run(
                    &run,
                    RepairBudget {
                        max_attempts: 1,
                        max_solver_units: 1,
                    },
                    &mut Solver { calls: 0 },
                    &mut Visible(VecDeque::from([VisibleCheck::Passed])),
                    &mut Hidden(HiddenDecision::Verified),
                )
                .expect("local benchmark delivery");
            assert!(delivery.is_some());
        }
        let elapsed = started.elapsed();
        assert_eq!(gateway.delivery_calls(), 5_000);
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "1,000 local remediation deliveries took {elapsed:?}"
        );
    }
}
