//! Restart-safe delivery of verified candidates to human review.
#![allow(missing_docs, clippy::missing_errors_doc)]

use crate::domain::RemediationRunId;
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::OrganizationId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::{Arc, Mutex};

/// Tenant/run/candidate identity. A different candidate is never an implicit retry.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ReviewDeliveryKey {
    /// Owning tenant.
    pub organization_id: OrganizationId,
    /// Owning remediation run.
    pub run_id: RemediationRunId,
    /// Exact verified candidate.
    pub candidate_digest: Sha256Digest,
}

/// Strict delivery order.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ReviewStage {
    Issue,
    Branch,
    Commit,
    PullRequest,
    Summary,
}
impl ReviewStage {
    const fn prior(self) -> Option<Self> {
        match self {
            Self::Issue => None,
            Self::Branch => Some(Self::Issue),
            Self::Commit => Some(Self::Branch),
            Self::PullRequest => Some(Self::Commit),
            Self::Summary => Some(Self::PullRequest),
        }
    }
}

/// Immutable checkpoint binding desired request to observed remote object.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StageCheckpoint {
    /// Digest of the complete canonical outbound request.
    pub request_digest: Sha256Digest,
    /// Safe provider reference.
    pub remote_reference: String,
    /// Opaque provider object ID retained independently from its display URL.
    #[serde(default)]
    pub remote_id: String,
}

/// Bounded canonical provider-safe request planned before external mutation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PlannedAction {
    /// Canonical serialized request fields other than the subject.
    pub template_bytes: Vec<u8>,
    /// Digest of the exact template bytes.
    pub template_digest: Sha256Digest,
    /// Subject known now or sourced from an earlier checkpoint.
    pub subject: PlannedSubject,
}
/// Immutable subject binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PlannedSubject {
    /// Subject is known when planning.
    Literal(Vec<u8>),
    /// Subject is the opaque provider ID recorded by a prior stage.
    PriorStageRemoteId(ReviewStage),
}
/// Cardinality of the planned workflow.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PlanKind {
    IssueOnly,
    VerifiedReview,
}
/// Fully materialized action ready for exact deserialization/delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedAction {
    pub template_bytes: Vec<u8>,
    pub subject: Vec<u8>,
    pub request_digest: Sha256Digest,
}

/// Immutable complete review-delivery plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReviewDeliveryPlan {
    kind: PlanKind,
    actions: BTreeMap<ReviewStage, PlannedAction>,
}
impl ReviewDeliveryPlan {
    /// Validates stage cardinality, templates, and prior-stage dependencies.
    pub fn new(
        kind: PlanKind,
        actions: BTreeMap<ReviewStage, PlannedAction>,
    ) -> Result<Self, ReviewDeliveryError> {
        let verified = [
            ReviewStage::Issue,
            ReviewStage::Branch,
            ReviewStage::Commit,
            ReviewStage::PullRequest,
            ReviewStage::Summary,
        ];
        let required: &[ReviewStage] = match kind {
            PlanKind::IssueOnly => &verified[..1],
            PlanKind::VerifiedReview => &verified,
        };
        if actions.len() != required.len()
            || required.iter().any(|stage| !actions.contains_key(stage))
        {
            return Err(ReviewDeliveryError::InvalidPlan);
        }
        if actions.values().any(|action| {
            action.template_bytes.is_empty()
                || action.template_bytes.len() > 64 * 1024
                || Sha256Digest::of_bytes(&action.template_bytes) != action.template_digest
        }) {
            return Err(ReviewDeliveryError::InvalidPlan);
        }
        for (stage, action) in &actions {
            if let PlannedSubject::PriorStageRemoteId(prior) = action.subject {
                if prior >= *stage || !actions.contains_key(&prior) {
                    return Err(ReviewDeliveryError::InvalidPlan);
                }
            }
        }
        Ok(Self { kind, actions })
    }
    /// Returns exact planned action for a stage.
    #[must_use]
    pub fn get(&self, stage: ReviewStage) -> Option<&PlannedAction> {
        self.actions.get(&stage)
    }
}

/// Aggregate state persisted after every successful remote stage.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReviewDelivery {
    /// Stable identity.
    pub key: ReviewDeliveryKey,
    /// Immutable complete plan required for restart without solver state.
    plan: ReviewDeliveryPlan,
    /// Ordered completed stages.
    checkpoints: BTreeMap<ReviewStage, StageCheckpoint>,
    /// Candidate that explicitly replaces this delivery, if any.
    superseded_by: Option<Sha256Digest>,
}
impl ReviewDelivery {
    /// Starts an empty delivery.
    #[must_use]
    pub fn new(key: ReviewDeliveryKey, plan: ReviewDeliveryPlan) -> Self {
        Self {
            key,
            plan,
            checkpoints: BTreeMap::new(),
            superseded_by: None,
        }
    }
    /// Records or exactly replays one stage.
    pub fn checkpoint(
        &mut self,
        stage: ReviewStage,
        checkpoint: StageCheckpoint,
    ) -> Result<CheckpointOutcome, ReviewDeliveryError> {
        if self.superseded_by.is_some() {
            return Err(ReviewDeliveryError::Superseded);
        }
        if self.materialize(stage)?.request_digest != checkpoint.request_digest {
            return Err(ReviewDeliveryError::ReplayConflict);
        }
        if !safe_reference(&checkpoint.remote_reference) || !safe_remote_id(&checkpoint.remote_id) {
            return Err(ReviewDeliveryError::InvalidReference);
        }
        if let Some(existing) = self.checkpoints.get(&stage) {
            return if existing == &checkpoint {
                Ok(CheckpointOutcome::Replayed)
            } else {
                Err(ReviewDeliveryError::ReplayConflict)
            };
        }
        if self.plan.get(stage).is_none()
            || stage
                .prior()
                .is_some_and(|prior| !self.checkpoints.contains_key(&prior))
        {
            return Err(ReviewDeliveryError::OutOfOrder);
        }
        self.checkpoints.insert(stage, checkpoint);
        Ok(CheckpointOutcome::Advanced)
    }
    /// Explicitly freezes this candidate in favor of a different candidate digest.
    pub fn supersede(&mut self, replacement: Sha256Digest) -> Result<(), ReviewDeliveryError> {
        if replacement == self.key.candidate_digest {
            return Err(ReviewDeliveryError::ReplayConflict);
        }
        match self.superseded_by {
            None => {
                self.superseded_by = Some(replacement);
                Ok(())
            }
            Some(value) if value == replacement => Ok(()),
            Some(_) => Err(ReviewDeliveryError::ReplayConflict),
        }
    }
    /// Returns one completed checkpoint.
    #[must_use]
    pub fn get(&self, stage: ReviewStage) -> Option<&StageCheckpoint> {
        self.checkpoints.get(&stage)
    }
    /// Whether a newer candidate explicitly replaced this workflow.
    #[must_use]
    pub const fn is_superseded(&self) -> bool {
        self.superseded_by.is_some()
    }
    /// Exact next planned action, or none after completion/supersession.
    #[must_use]
    pub fn next_stage(&self) -> Option<(ReviewStage, MaterializedAction)> {
        if self.is_superseded() {
            return None;
        }
        [
            ReviewStage::Issue,
            ReviewStage::Branch,
            ReviewStage::Commit,
            ReviewStage::PullRequest,
            ReviewStage::Summary,
        ]
        .into_iter()
        .find(|stage| self.plan.get(*stage).is_some() && !self.checkpoints.contains_key(stage))
        .and_then(|stage| self.materialize(stage).ok().map(|action| (stage, action)))
    }
    /// Materializes a stage, binding any prior remote ID into its digest.
    pub fn materialize(
        &self,
        stage: ReviewStage,
    ) -> Result<MaterializedAction, ReviewDeliveryError> {
        let action = self
            .plan
            .get(stage)
            .ok_or(ReviewDeliveryError::OutOfOrder)?;
        let subject = match &action.subject {
            PlannedSubject::Literal(value) => value.clone(),
            PlannedSubject::PriorStageRemoteId(prior) => self
                .checkpoints
                .get(prior)
                .map(|checkpoint| checkpoint.remote_id.as_bytes().to_vec())
                .ok_or(ReviewDeliveryError::OutOfOrder)?,
        };
        let mut canonical = Vec::with_capacity(action.template_bytes.len() + subject.len() + 16);
        canonical.extend_from_slice(&(action.template_bytes.len() as u64).to_be_bytes());
        canonical.extend_from_slice(&action.template_bytes);
        canonical.extend_from_slice(&(subject.len() as u64).to_be_bytes());
        canonical.extend_from_slice(&subject);
        Ok(MaterializedAction {
            template_bytes: action.template_bytes.clone(),
            subject,
            request_digest: Sha256Digest::of_bytes(canonical),
        })
    }
}

/// Domain checkpoint result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointOutcome {
    Advanced,
    Replayed,
}
/// Stable domain/storage error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewDeliveryError {
    Conflict,
    NotFound,
    ReplayConflict,
    OutOfOrder,
    Superseded,
    InvalidReference,
    Unavailable,
    InvalidPlan,
}
impl fmt::Display for ReviewDeliveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ReviewDeliveryError {}

/// Optimistically versioned aggregate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedDelivery {
    pub delivery: ReviewDelivery,
    pub version: u64,
}
/// Atomic durable repository boundary.
pub trait ReviewDeliveryRepository: Send + Sync {
    /// Loads exact tenant/run/candidate state.
    fn load(
        &self,
        key: &ReviewDeliveryKey,
    ) -> Result<Option<VersionedDelivery>, ReviewDeliveryError>;
    /// Creates at version one, or returns exact existing state.
    fn create(&self, delivery: ReviewDelivery) -> Result<VersionedDelivery, ReviewDeliveryError>;
    /// Replaces state only at the caller-observed version.
    fn save(
        &self,
        expected_version: u64,
        delivery: ReviewDelivery,
    ) -> Result<VersionedDelivery, ReviewDeliveryError>;
}

/// Async repository boundary used by durable worker composition.
#[allow(async_fn_in_trait)]
pub trait AsyncReviewDeliveryRepository: Send + Sync {
    /// Loads exact tenant/run/candidate state.
    async fn load(
        &self,
        key: &ReviewDeliveryKey,
    ) -> Result<Option<VersionedDelivery>, ReviewDeliveryError>;
    /// Creates version one or exactly replays creation.
    async fn create(
        &self,
        delivery: ReviewDelivery,
    ) -> Result<VersionedDelivery, ReviewDeliveryError>;
    /// Optimistically replaces state.
    async fn save(
        &self,
        expected_version: u64,
        delivery: ReviewDelivery,
    ) -> Result<VersionedDelivery, ReviewDeliveryError>;
    /// Loads the only non-superseded workflow for a tenant/run.
    async fn load_active(
        &self,
        organization: &OrganizationId,
        run: &RemediationRunId,
    ) -> Result<Option<VersionedDelivery>, ReviewDeliveryError>;
}

/// Fenced right to perform expensive candidate generation for one tenant/run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationLease {
    /// Tenant boundary.
    pub organization_id: OrganizationId,
    /// Run boundary.
    pub run_id: RemediationRunId,
    /// Opaque worker owner identity.
    pub owner: String,
    /// Monotonically increasing fencing token.
    pub fence: u64,
    /// Exclusive Unix-second expiry.
    pub expires_at_unix: u64,
}
/// Lease acquisition result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GenerationClaim {
    Acquired(GenerationLease),
    Held,
}
/// Async generation-lease repository.
#[allow(async_fn_in_trait)]
pub trait GenerationLeaseRepository: Send + Sync {
    /// Acquires an absent/expired lease and increments its fence.
    async fn claim(
        &self,
        organization: &OrganizationId,
        run: &RemediationRunId,
        owner: &str,
        now_unix: u64,
        lease_seconds: u64,
    ) -> Result<GenerationClaim, ReviewDeliveryError>;
    /// Confirms a fence still owns an unexpired lease before publication.
    async fn is_current(
        &self,
        lease: &GenerationLease,
        now_unix: u64,
    ) -> Result<bool, ReviewDeliveryError>;
}

/// Transactional in-memory reference repository.
#[derive(Clone, Default)]
pub struct InMemoryReviewDeliveryRepository(
    Arc<Mutex<HashMap<ReviewDeliveryKey, VersionedDelivery>>>,
);
impl ReviewDeliveryRepository for InMemoryReviewDeliveryRepository {
    fn load(
        &self,
        key: &ReviewDeliveryKey,
    ) -> Result<Option<VersionedDelivery>, ReviewDeliveryError> {
        Ok(self
            .0
            .lock()
            .map_err(|_| ReviewDeliveryError::Unavailable)?
            .get(key)
            .cloned())
    }
    fn create(&self, delivery: ReviewDelivery) -> Result<VersionedDelivery, ReviewDeliveryError> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| ReviewDeliveryError::Unavailable)?;
        if let Some(existing) = state.get(&delivery.key) {
            return if existing.delivery == delivery {
                Ok(existing.clone())
            } else {
                Err(ReviewDeliveryError::Conflict)
            };
        }
        let value = VersionedDelivery {
            delivery: delivery.clone(),
            version: 1,
        };
        state.insert(delivery.key.clone(), value.clone());
        Ok(value)
    }
    fn save(
        &self,
        expected_version: u64,
        delivery: ReviewDelivery,
    ) -> Result<VersionedDelivery, ReviewDeliveryError> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| ReviewDeliveryError::Unavailable)?;
        let current = state
            .get(&delivery.key)
            .ok_or(ReviewDeliveryError::NotFound)?;
        if current.version != expected_version {
            return Err(ReviewDeliveryError::Conflict);
        }
        let version = expected_version
            .checked_add(1)
            .ok_or(ReviewDeliveryError::Conflict)?;
        let value = VersionedDelivery {
            delivery: delivery.clone(),
            version,
        };
        state.insert(delivery.key.clone(), value.clone());
        Ok(value)
    }
}
fn safe_reference(value: &str) -> bool {
    value.starts_with("https://") && !value.contains(['\n', '\r', ' ']) && value.len() <= 2048
}
fn safe_remote_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.bytes().all(|byte| byte.is_ascii_graphic())
        && !value.contains(['\n', '\r'])
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(byte: u8) -> ReviewDeliveryKey {
        ReviewDeliveryKey {
            organization_id: OrganizationId::new("organization1").unwrap(),
            run_id: RemediationRunId::new("00000001").unwrap(),
            candidate_digest: Sha256Digest::of_bytes([byte]),
        }
    }
    fn point(stage: ReviewStage, digest: Sha256Digest) -> StageCheckpoint {
        StageCheckpoint {
            request_digest: digest,
            remote_reference: format!("https://scm.invalid/{stage:?}"),
            remote_id: format!("remote-{stage:?}"),
        }
    }
    fn plan() -> ReviewDeliveryPlan {
        ReviewDeliveryPlan::new(
            PlanKind::VerifiedReview,
            [
                ReviewStage::Issue,
                ReviewStage::Branch,
                ReviewStage::Commit,
                ReviewStage::PullRequest,
                ReviewStage::Summary,
            ]
            .into_iter()
            .map(|stage| {
                (
                    stage,
                    PlannedAction {
                        template_bytes: vec![stage as u8],
                        template_digest: Sha256Digest::of_bytes([stage as u8]),
                        subject: if stage == ReviewStage::Summary {
                            PlannedSubject::PriorStageRemoteId(ReviewStage::PullRequest)
                        } else {
                            PlannedSubject::Literal(vec![])
                        },
                    },
                )
            })
            .collect(),
        )
        .unwrap()
    }
    #[test]
    fn checkpoints_restart_replay_and_supersession() {
        let repository = InMemoryReviewDeliveryRepository::default();
        let mut saved = repository
            .create(ReviewDelivery::new(key(1), plan()))
            .unwrap();
        let stages = [
            ReviewStage::Issue,
            ReviewStage::Branch,
            ReviewStage::Commit,
            ReviewStage::PullRequest,
            ReviewStage::Summary,
        ];
        for (index, stage) in stages.into_iter().enumerate() {
            let digest = saved.delivery.materialize(stage).unwrap().request_digest;
            assert_eq!(
                saved
                    .delivery
                    .checkpoint(stage, point(stage, digest))
                    .unwrap(),
                CheckpointOutcome::Advanced
            );
            repository.save(saved.version, saved.delivery).unwrap();
            saved = repository.load(&key(1)).unwrap().unwrap();
            let expected_next = stages.get(index + 1).copied();
            assert_eq!(
                saved
                    .delivery
                    .next_stage()
                    .map(|(next, action)| (next, action.template_bytes.clone())),
                expected_next.map(|next| (next, vec![next as u8]))
            );
            if expected_next == Some(ReviewStage::Summary) {
                assert_eq!(
                    saved.delivery.next_stage().unwrap().1.subject,
                    b"remote-PullRequest"
                );
            }
            assert_eq!(
                saved
                    .delivery
                    .checkpoint(stage, point(stage, digest))
                    .unwrap(),
                CheckpointOutcome::Replayed
            );
        }
        saved.delivery.supersede(key(2).candidate_digest).unwrap();
        assert_eq!(
            saved.delivery.checkpoint(
                ReviewStage::Summary,
                point(ReviewStage::Summary, Sha256Digest::of_bytes(b"irrelevant"))
            ),
            Err(ReviewDeliveryError::Superseded)
        );
    }
    #[test]
    fn rejects_out_of_order_substitution_and_concurrent_save() {
        let repository = InMemoryReviewDeliveryRepository::default();
        let mut first = repository
            .create(ReviewDelivery::new(key(1), plan()))
            .unwrap();
        let branch_digest = first
            .delivery
            .materialize(ReviewStage::Branch)
            .unwrap()
            .request_digest;
        assert_eq!(
            first.delivery.checkpoint(
                ReviewStage::Branch,
                point(ReviewStage::Branch, branch_digest)
            ),
            Err(ReviewDeliveryError::OutOfOrder)
        );
        let issue_digest = first
            .delivery
            .materialize(ReviewStage::Issue)
            .unwrap()
            .request_digest;
        first
            .delivery
            .checkpoint(ReviewStage::Issue, point(ReviewStage::Issue, issue_digest))
            .unwrap();
        let stale = first.clone();
        repository.save(first.version, first.delivery).unwrap();
        assert_eq!(
            repository.save(stale.version, stale.delivery),
            Err(ReviewDeliveryError::Conflict)
        );
        let mut loaded = repository.load(&key(1)).unwrap().unwrap();
        let mut changed = point(ReviewStage::Issue, issue_digest);
        changed.remote_reference.push_str("-different");
        assert_eq!(
            loaded.delivery.checkpoint(ReviewStage::Issue, changed),
            Err(ReviewDeliveryError::ReplayConflict)
        );
    }
    #[test]
    fn issue_only_plan_has_truthful_cardinality_and_dependency_validation() {
        let issue = PlannedAction {
            template_bytes: b"issue".to_vec(),
            template_digest: Sha256Digest::of_bytes(b"issue"),
            subject: PlannedSubject::Literal(b"title".to_vec()),
        };
        let plan = ReviewDeliveryPlan::new(
            PlanKind::IssueOnly,
            BTreeMap::from([(ReviewStage::Issue, issue)]),
        )
        .unwrap();
        let delivery = ReviewDelivery::new(key(3), plan);
        assert_eq!(delivery.next_stage().unwrap().0, ReviewStage::Issue);
        let bad = PlannedAction {
            template_bytes: b"summary".to_vec(),
            template_digest: Sha256Digest::of_bytes(b"summary"),
            subject: PlannedSubject::PriorStageRemoteId(ReviewStage::PullRequest),
        };
        assert_eq!(
            ReviewDeliveryPlan::new(
                PlanKind::IssueOnly,
                BTreeMap::from([(ReviewStage::Issue, bad)])
            ),
            Err(ReviewDeliveryError::InvalidPlan)
        );
    }
}
