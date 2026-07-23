//! Append-only, replayable remediation process aggregate.

use std::collections::BTreeMap;
use std::fmt;

use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
use cauterizer_syntax::schema::SchemaVersion;
use serde::{Deserialize, Serialize};

/// Context-owned run identifier.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RemediationRunId(ContextQualifiedId);
impl RemediationRunId {
    /// Creates a run ID.
    ///
    /// # Errors
    /// Rejects invalid shared identifier syntax.
    pub fn new(opaque: &str) -> Result<Self, RunError> {
        ContextQualifiedId::new("run", opaque)
            .map(Self)
            .map_err(|_| RunError::InvalidInput)
    }
    /// Returns the context-qualified spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Declared solver/verifier information-flow mode.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ConformanceMode {
    /// Solver and verifier communicate only through permitted artifacts.
    Conformant,
    /// The run records a declared exception to the information-flow policy.
    ExplicitlyNonConformant,
}

/// Exact immutable cross-context inputs bound once per run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunInputs {
    /// Advisory Intake immutable snapshot reference.
    pub advisory_snapshot: ContextQualifiedId,
    /// Authorized Asset Portfolio resolution receipt.
    pub target_revision: ContextQualifiedId,
    /// Digest of the acquisition bundle for the target.
    pub target_artifact: Sha256Digest,
    /// Immutable verification policy revision.
    pub policy_version: SchemaVersion,
    /// Commercial Entitlements reservation contract.
    pub budget_reservation: ContextQualifiedId,
    /// Declared information-flow mode.
    pub conformance_mode: ConformanceMode,
    /// Digest binding the complete canonical run input document.
    pub inputs_digest: Sha256Digest,
}

/// Optional ancestry used for correction/supersession without history mutation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunLineage {
    /// Immediate ancestor run, when this run is a continuation.
    pub parent: Option<RemediationRunId>,
    /// Prior run whose result this run explicitly replaces.
    pub supersedes: Option<RemediationRunId>,
}

/// Deterministic verdict vocabulary owned by Verification, only recorded here.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RecordedVerdict {
    /// Candidate satisfies the policy for the named fixture.
    VerifiedForFixture,
    /// Candidate deterministically fails verification.
    Rejected,
    /// Available observations cannot establish a result.
    Inconclusive,
    /// Verification observed a prohibited information flow.
    NonConformant,
}

/// Authenticated owning bounded context for an inbound fact.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum FactProducer {
    /// Sandboxed execution context.
    IsolatedExecution,
    /// Patch proposal context.
    PatchProposals,
    /// Verification context.
    Verification,
    /// Evidence finalization context.
    Evidence,
}

/// Inbound fact envelope authenticated before aggregate application.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthenticatedFact {
    /// Globally unique event ID used for deduplication.
    pub event_id: ContextQualifiedId,
    /// Tenant asserted by the authenticated producer contract.
    pub organization_id: OrganizationId,
    /// Exact run whose process state may advance.
    pub run_id: RemediationRunId,
    /// Owning bounded context.
    pub producer: FactProducer,
    /// Context fact body containing references only.
    pub payload: InboundFact,
}

/// Facts another context owns; Remediation Runs never fabricates these.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum InboundFact {
    /// Isolated Execution produced an immutable baseline observation.
    BaselineObserved {
        /// Immutable observation reference.
        observation: ContextQualifiedId,
    },
    /// Patch Proposals produced one immutable candidate.
    PatchProposed {
        /// Immutable proposal reference.
        proposal: ContextQualifiedId,
        /// Digest of the exact patch bytes.
        patch_digest: Sha256Digest,
    },
    /// Verification produced a deterministic assessment.
    CandidateAssessed {
        /// Immutable assessment reference.
        assessment: ContextQualifiedId,
        /// Verifier-owned result, recorded verbatim.
        verdict: RecordedVerdict,
    },
    /// Evidence finalized a bundle for this run.
    EvidenceFinalized {
        /// Immutable evidence bundle reference.
        bundle: ContextQualifiedId,
        /// Digest of the complete canonical bundle.
        bundle_digest: Sha256Digest,
    },
}

/// Durable state projection derived solely from [`RunEvent`] history.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RunState {
    /// Identity exists and inputs have not been bound.
    Draft,
    /// Immutable cross-context inputs are bound.
    InputsBound,
    /// Baseline work has been requested.
    BaselineRequested,
    /// Baseline observation has arrived.
    BaselineObserved,
    /// Patch proposal work has been requested.
    ProposalRequested,
    /// A patch proposal has arrived.
    PatchReceived,
    /// Verification has been requested.
    AssessmentRequested,
    /// Verification completed with a result eligible for evidence.
    Assessed(RecordedVerdict),
    /// Verification could not establish a result.
    Inconclusive,
    /// Verification found a conformance violation.
    NonConformant,
    /// Evidence finalization has been requested.
    EvidenceRequested,
    /// Final evidence has arrived and awaits sealing.
    EvidenceReceived,
    /// Reserved execution budget was exhausted.
    BudgetExhausted,
    /// An operator or policy cancelled the run.
    Cancelled,
    /// History is final and immutable.
    Sealed,
}
impl RunState {
    /// Whether no future transition may change this run.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::BudgetExhausted | Self::Cancelled | Self::Sealed)
    }
}

/// Append-only run event used for crash recovery and projection rebuild.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RunEvent {
    /// Establishes immutable run identity and ancestry.
    RemediationRunCreated {
        /// Tenant boundary.
        organization_id: OrganizationId,
        /// Context-owned run identity.
        run_id: RemediationRunId,
        /// Correction and supersession ancestry.
        lineage: RunLineage,
    },
    /// Records a successfully accepted command identity for restart-safe deduplication.
    CommandAccepted {
        /// Caller-provided idempotency key.
        key: String,
        /// Digest of the complete canonical command.
        digest: Sha256Digest,
    },
    /// Records a successfully accepted inbound fact for restart-safe deduplication.
    FactAccepted {
        /// Complete authenticated fact envelope.
        fact: AuthenticatedFact,
    },
    /// Binds the immutable run inputs.
    InputsBound {
        /// Complete input binding.
        inputs: RunInputs,
    },
    /// Requests baseline execution.
    BaselineRequested,
    /// Records the externally owned baseline result.
    BaselineObserved {
        /// Immutable observation reference.
        observation: ContextQualifiedId,
    },
    /// Requests proposal generation.
    ProposalRequested,
    /// Records the externally owned patch proposal.
    PatchReceived {
        /// Immutable proposal reference.
        proposal: ContextQualifiedId,
        /// Digest of exact patch bytes.
        patch_digest: Sha256Digest,
    },
    /// Requests deterministic verification.
    AssessmentRequested,
    /// Records the externally owned verification result.
    AssessmentRecorded {
        /// Immutable assessment reference.
        assessment: ContextQualifiedId,
        /// Verifier-owned verdict.
        verdict: RecordedVerdict,
    },
    /// Requests evidence finalization.
    EvidenceRequested,
    /// Records the externally owned evidence result.
    EvidenceRecorded {
        /// Immutable evidence bundle reference.
        bundle: ContextQualifiedId,
        /// Digest of the canonical bundle.
        bundle_digest: Sha256Digest,
    },
    /// Records exhaustion of the reserved budget.
    BudgetExhausted,
    /// Records explicit cancellation.
    RunCancelled {
        /// Stable human-readable cancellation reason.
        reason: String,
    },
    /// Irreversibly seals the run.
    RunSealed,
}

/// Coarse direct application command; result ownership remains external.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunCommand {
    /// Binds all immutable inputs exactly once.
    BindInputs(RunInputs),
    /// Requests baseline execution.
    RequestBaseline,
    /// Requests patch proposal generation.
    RequestProposal,
    /// Requests verification.
    RequestAssessment,
    /// Requests final evidence generation.
    RequestEvidence,
    /// Ends the run because its reserved budget is exhausted.
    MarkBudgetExhausted,
    /// Cancels the run with an auditable reason.
    Cancel {
        /// Stable human-readable cancellation reason.
        reason: String,
    },
    /// Irreversibly seals a completed outcome.
    Seal,
}

/// Sole append-only process aggregate.
#[derive(Clone, Debug)]
pub struct RemediationRun {
    organization_id: OrganizationId,
    id: RemediationRunId,
    lineage: RunLineage,
    state: RunState,
    inputs: Option<RunInputs>,
    baseline: Option<ContextQualifiedId>,
    proposal: Option<(ContextQualifiedId, Sha256Digest)>,
    assessment: Option<(ContextQualifiedId, RecordedVerdict)>,
    evidence: Option<(ContextQualifiedId, Sha256Digest)>,
    events: Vec<RunEvent>,
    pending: Vec<RunEvent>,
    commands: BTreeMap<String, Sha256Digest>,
    facts: BTreeMap<ContextQualifiedId, AuthenticatedFact>,
}

impl RemediationRun {
    /// Creates a run and first append-only event.
    #[must_use]
    pub fn create(
        organization_id: OrganizationId,
        id: RemediationRunId,
        lineage: RunLineage,
    ) -> Self {
        let event = RunEvent::RemediationRunCreated {
            organization_id: organization_id.clone(),
            run_id: id.clone(),
            lineage: lineage.clone(),
        };
        Self {
            organization_id,
            id,
            lineage,
            state: RunState::Draft,
            inputs: None,
            baseline: None,
            proposal: None,
            assessment: None,
            evidence: None,
            events: vec![event.clone()],
            pending: vec![event],
            commands: BTreeMap::new(),
            facts: BTreeMap::new(),
        }
    }
    /// Current replay-derived state.
    #[must_use]
    pub const fn state(&self) -> RunState {
        self.state
    }
    /// Immutable tenant boundary.
    #[must_use]
    pub const fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }
    /// Immutable run identity.
    #[must_use]
    pub const fn id(&self) -> &RemediationRunId {
        &self.id
    }
    /// Immutable ancestry.
    #[must_use]
    pub const fn lineage(&self) -> &RunLineage {
        &self.lineage
    }
    /// Complete append-only timeline.
    #[must_use]
    pub fn timeline(&self) -> &[RunEvent] {
        &self.events
    }

    /// Applies an idempotent direct command.
    ///
    /// # Errors
    /// Rejects malformed/conflicting keys, invalid transitions, or terminal mutation.
    pub fn command(
        &mut self,
        key: String,
        digest: Sha256Digest,
        command: RunCommand,
    ) -> Result<RunState, RunError> {
        if key.is_empty() || key.len() > 128 {
            return Err(RunError::InvalidInput);
        }
        if let Some(existing) = self.commands.get(&key) {
            return if existing == &digest {
                Ok(self.state)
            } else {
                Err(RunError::IdempotencyConflict)
            };
        }
        let event = self.command_event(command)?;
        self.apply_new(event)?;
        self.commands.insert(key.clone(), digest);
        let accepted = RunEvent::CommandAccepted { key, digest };
        self.events.push(accepted.clone());
        self.pending.push(accepted);
        Ok(self.state)
    }

    /// Applies an authenticated owning-context fact idempotently.
    ///
    /// # Errors
    /// Rejects tenant/producer mismatch, conflicting event identity, out-of-order
    /// delivery, or any attempted terminal mutation.
    pub fn apply_fact(&mut self, fact: AuthenticatedFact) -> Result<RunState, RunError> {
        if fact.organization_id != self.organization_id {
            return Err(RunError::TenantMismatch);
        }
        if fact.run_id != self.id {
            return Err(RunError::RunMismatch);
        }
        if let Some(existing) = self.facts.get(&fact.event_id) {
            return if existing == &fact {
                Ok(self.state)
            } else {
                Err(RunError::FactIdentityConflict)
            };
        }
        let event = match (&fact.producer, &fact.payload) {
            (FactProducer::IsolatedExecution, InboundFact::BaselineObserved { observation }) => {
                RunEvent::BaselineObserved {
                    observation: observation.clone(),
                }
            }
            (
                FactProducer::PatchProposals,
                InboundFact::PatchProposed {
                    proposal,
                    patch_digest,
                },
            ) => RunEvent::PatchReceived {
                proposal: proposal.clone(),
                patch_digest: *patch_digest,
            },
            (
                FactProducer::Verification,
                InboundFact::CandidateAssessed {
                    assessment,
                    verdict,
                },
            ) => RunEvent::AssessmentRecorded {
                assessment: assessment.clone(),
                verdict: *verdict,
            },
            (
                FactProducer::Evidence,
                InboundFact::EvidenceFinalized {
                    bundle,
                    bundle_digest,
                },
            ) => RunEvent::EvidenceRecorded {
                bundle: bundle.clone(),
                bundle_digest: *bundle_digest,
            },
            _ => return Err(RunError::ProducerMismatch),
        };
        self.apply_new(event)?;
        self.facts.insert(fact.event_id.clone(), fact.clone());
        let accepted = RunEvent::FactAccepted { fact };
        self.events.push(accepted.clone());
        self.pending.push(accepted);
        Ok(self.state)
    }

    /// Rebuilds identical state from a complete ordered timeline.
    ///
    /// # Errors
    /// Rejects absent creation, inconsistent identity, or invalid history.
    pub fn rebuild(events: &[RunEvent]) -> Result<Self, RunError> {
        let Some(RunEvent::RemediationRunCreated {
            organization_id,
            run_id,
            lineage,
        }) = events.first()
        else {
            return Err(RunError::InvalidHistory);
        };
        let mut run = Self::create(organization_id.clone(), run_id.clone(), lineage.clone());
        run.events.clear();
        run.pending.clear();
        for event in events {
            run.apply_replay(event.clone())?;
        }
        Ok(run)
    }
    /// Drains new events for atomic state/outbox persistence.
    pub fn take_pending_events(&mut self) -> Vec<RunEvent> {
        std::mem::take(&mut self.pending)
    }
    /// Stable reason a run is waiting; `None` for terminal states.
    #[must_use]
    pub const fn stuck_step(&self) -> Option<&'static str> {
        match self.state {
            RunState::Draft => Some("inputs"),
            RunState::InputsBound => Some("baseline_request"),
            RunState::BaselineRequested => Some("baseline_fact"),
            RunState::BaselineObserved => Some("proposal_request"),
            RunState::ProposalRequested => Some("proposal_fact"),
            RunState::PatchReceived => Some("assessment_request"),
            RunState::AssessmentRequested => Some("assessment_fact"),
            RunState::Assessed(_) => Some("evidence_request"),
            RunState::Inconclusive | RunState::NonConformant | RunState::EvidenceReceived => {
                Some("seal")
            }
            RunState::EvidenceRequested => Some("evidence_fact"),
            RunState::BudgetExhausted | RunState::Cancelled | RunState::Sealed => None,
        }
    }

    fn command_event(&self, command: RunCommand) -> Result<RunEvent, RunError> {
        if self.state.is_terminal() {
            return Err(RunError::Terminal);
        }
        match (self.state, command) {
            (RunState::Draft, RunCommand::BindInputs(inputs)) => {
                Ok(RunEvent::InputsBound { inputs })
            }
            (RunState::InputsBound, RunCommand::RequestBaseline) => Ok(RunEvent::BaselineRequested),
            (RunState::BaselineObserved, RunCommand::RequestProposal) => {
                Ok(RunEvent::ProposalRequested)
            }
            (RunState::PatchReceived, RunCommand::RequestAssessment) => {
                Ok(RunEvent::AssessmentRequested)
            }
            (RunState::Assessed(_), RunCommand::RequestEvidence) => Ok(RunEvent::EvidenceRequested),
            (RunState::Inconclusive | RunState::NonConformant, RunCommand::Seal) => {
                Ok(RunEvent::RunSealed)
            }
            (RunState::EvidenceReceived, RunCommand::Seal) => Ok(RunEvent::RunSealed),
            (_, RunCommand::MarkBudgetExhausted) => Ok(RunEvent::BudgetExhausted),
            (_, RunCommand::Cancel { reason })
                if !reason.trim().is_empty() && reason.len() <= 256 =>
            {
                Ok(RunEvent::RunCancelled { reason })
            }
            _ => Err(RunError::InvalidTransition),
        }
    }
    fn apply_new(&mut self, event: RunEvent) -> Result<(), RunError> {
        self.apply_transition(&event)?;
        self.events.push(event.clone());
        self.pending.push(event);
        Ok(())
    }
    fn apply_replay(&mut self, event: RunEvent) -> Result<(), RunError> {
        if matches!(event, RunEvent::RemediationRunCreated { .. }) {
            if !self.events.is_empty() {
                return Err(RunError::InvalidHistory);
            }
            if let RunEvent::RemediationRunCreated {
                organization_id,
                run_id,
                lineage,
            } = &event
            {
                if organization_id != &self.organization_id
                    || run_id != &self.id
                    || lineage != &self.lineage
                {
                    return Err(RunError::InvalidHistory);
                }
                self.state = RunState::Draft;
            }
        } else if let RunEvent::CommandAccepted { key, digest } = &event {
            if self.commands.insert(key.clone(), *digest).is_some() {
                return Err(RunError::InvalidHistory);
            }
        } else if let RunEvent::FactAccepted { fact } = &event {
            if fact.organization_id != self.organization_id
                || fact.run_id != self.id
                || self
                    .facts
                    .insert(fact.event_id.clone(), fact.clone())
                    .is_some()
            {
                return Err(RunError::InvalidHistory);
            }
        } else {
            self.apply_transition(&event)?;
        }
        self.events.push(event);
        Ok(())
    }
    fn apply_transition(&mut self, event: &RunEvent) -> Result<(), RunError> {
        if self.state.is_terminal() {
            return Err(RunError::Terminal);
        }
        match (self.state, event) {
            (RunState::Draft, RunEvent::InputsBound { inputs }) => {
                self.inputs = Some(inputs.clone());
                self.state = RunState::InputsBound;
            }
            (RunState::InputsBound, RunEvent::BaselineRequested) => {
                self.state = RunState::BaselineRequested;
            }
            (RunState::BaselineRequested, RunEvent::BaselineObserved { observation }) => {
                self.baseline = Some(observation.clone());
                self.state = RunState::BaselineObserved;
            }
            (RunState::BaselineObserved, RunEvent::ProposalRequested) => {
                self.state = RunState::ProposalRequested;
            }
            (
                RunState::ProposalRequested,
                RunEvent::PatchReceived {
                    proposal,
                    patch_digest,
                },
            ) => {
                self.proposal = Some((proposal.clone(), *patch_digest));
                self.state = RunState::PatchReceived;
            }
            (RunState::PatchReceived, RunEvent::AssessmentRequested) => {
                self.state = RunState::AssessmentRequested;
            }
            (
                RunState::AssessmentRequested,
                RunEvent::AssessmentRecorded {
                    assessment,
                    verdict,
                },
            ) => {
                self.assessment = Some((assessment.clone(), *verdict));
                self.state = match verdict {
                    RecordedVerdict::Inconclusive => RunState::Inconclusive,
                    RecordedVerdict::NonConformant => RunState::NonConformant,
                    _ => RunState::Assessed(*verdict),
                }
            }
            (RunState::Assessed(_), RunEvent::EvidenceRequested) => {
                self.state = RunState::EvidenceRequested;
            }
            (
                RunState::EvidenceRequested,
                RunEvent::EvidenceRecorded {
                    bundle,
                    bundle_digest,
                },
            ) => {
                self.evidence = Some((bundle.clone(), *bundle_digest));
                self.state = RunState::EvidenceReceived;
            }
            (
                RunState::EvidenceReceived | RunState::Inconclusive | RunState::NonConformant,
                RunEvent::RunSealed,
            ) => self.state = RunState::Sealed,
            (_, RunEvent::BudgetExhausted) => self.state = RunState::BudgetExhausted,
            (_, RunEvent::RunCancelled { .. }) => self.state = RunState::Cancelled,
            _ => return Err(RunError::InvalidTransition),
        }
        Ok(())
    }
}

/// Stable process invariant errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunError {
    /// Input syntax or bounds are invalid.
    InvalidInput,
    /// An idempotency key was reused for different command content.
    IdempotencyConflict,
    /// An inbound fact belongs to another tenant.
    TenantMismatch,
    /// An inbound fact belongs to another run.
    RunMismatch,
    /// A fact event ID was reused for different content.
    FactIdentityConflict,
    /// The claimed producer does not own the fact type.
    ProducerMismatch,
    /// The requested transition is not valid from the current state.
    InvalidTransition,
    /// The run is terminal and cannot be mutated.
    Terminal,
    /// Persisted event history violates aggregate invariants.
    InvalidHistory,
}
impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for RunError {}

#[cfg(test)]
mod tests {
    use super::*;
    fn org() -> OrganizationId {
        OrganizationId::new("00000000").unwrap()
    }
    fn id(context: &str, n: u64) -> ContextQualifiedId {
        ContextQualifiedId::new(context, &format!("{n:08}")).unwrap()
    }
    fn inputs() -> RunInputs {
        RunInputs {
            advisory_snapshot: id("advisory", 1),
            target_revision: id("target", 1),
            target_artifact: Sha256Digest::of_bytes(b"target"),
            policy_version: SchemaVersion::parse("1.0.0").unwrap(),
            budget_reservation: id("reservation", 1),
            conformance_mode: ConformanceMode::Conformant,
            inputs_digest: Sha256Digest::of_bytes(b"inputs"),
        }
    }
    fn run() -> RemediationRun {
        RemediationRun::create(
            org(),
            RemediationRunId::new("00000000").unwrap(),
            RunLineage {
                parent: None,
                supersedes: None,
            },
        )
    }
    fn command(run: &mut RemediationRun, n: u64, value: RunCommand) {
        run.command(
            format!("key-{n}"),
            Sha256Digest::of_bytes(format!("command-{n}")),
            value,
        )
        .unwrap();
    }
    fn fact(n: u64, producer: FactProducer, payload: InboundFact) -> AuthenticatedFact {
        AuthenticatedFact {
            event_id: id("event", n),
            organization_id: org(),
            run_id: RemediationRunId::new("00000000").unwrap(),
            producer,
            payload,
        }
    }
    #[test]
    fn complete_lifecycle_never_fabricates_external_results_and_replays() {
        let mut r = run();
        command(&mut r, 1, RunCommand::BindInputs(inputs()));
        command(&mut r, 2, RunCommand::RequestBaseline);
        r.apply_fact(fact(
            1,
            FactProducer::IsolatedExecution,
            InboundFact::BaselineObserved {
                observation: id("observation", 1),
            },
        ))
        .unwrap();
        command(&mut r, 3, RunCommand::RequestProposal);
        r.apply_fact(fact(
            2,
            FactProducer::PatchProposals,
            InboundFact::PatchProposed {
                proposal: id("proposal", 1),
                patch_digest: Sha256Digest::of_bytes(b"patch"),
            },
        ))
        .unwrap();
        command(&mut r, 4, RunCommand::RequestAssessment);
        r.apply_fact(fact(
            3,
            FactProducer::Verification,
            InboundFact::CandidateAssessed {
                assessment: id("assessment", 1),
                verdict: RecordedVerdict::VerifiedForFixture,
            },
        ))
        .unwrap();
        command(&mut r, 5, RunCommand::RequestEvidence);
        r.apply_fact(fact(
            4,
            FactProducer::Evidence,
            InboundFact::EvidenceFinalized {
                bundle: id("bundle", 1),
                bundle_digest: Sha256Digest::of_bytes(b"bundle"),
            },
        ))
        .unwrap();
        command(&mut r, 6, RunCommand::Seal);
        assert_eq!(r.state(), RunState::Sealed);
        let rebuilt = RemediationRun::rebuild(r.timeline()).unwrap();
        assert_eq!(
            (rebuilt.state(), rebuilt.timeline()),
            (r.state(), r.timeline())
        );
    }
    #[test]
    fn wrong_producer_tenant_duplicate_and_out_of_order_facts_fail_closed() {
        let mut r = run();
        command(&mut r, 1, RunCommand::BindInputs(inputs()));
        command(&mut r, 2, RunCommand::RequestBaseline);
        let valid = fact(
            1,
            FactProducer::IsolatedExecution,
            InboundFact::BaselineObserved {
                observation: id("observation", 1),
            },
        );
        assert_eq!(
            r.apply_fact(valid.clone()).unwrap(),
            r.apply_fact(valid).unwrap()
        );
        assert_eq!(
            r.apply_fact(fact(
                2,
                FactProducer::Verification,
                InboundFact::PatchProposed {
                    proposal: id("proposal", 1),
                    patch_digest: Sha256Digest::of_bytes(b"p")
                }
            )),
            Err(RunError::ProducerMismatch)
        );
        assert_eq!(
            r.apply_fact(fact(
                3,
                FactProducer::PatchProposals,
                InboundFact::PatchProposed {
                    proposal: id("proposal", 1),
                    patch_digest: Sha256Digest::of_bytes(b"p")
                }
            )),
            Err(RunError::InvalidTransition)
        );
    }
    #[test]
    fn command_and_fact_deduplication_survive_rebuild() {
        let mut r = run();
        let command_digest = Sha256Digest::of_bytes(b"bind-inputs");
        r.command(
            "bind".into(),
            command_digest,
            RunCommand::BindInputs(inputs()),
        )
        .unwrap();
        command(&mut r, 2, RunCommand::RequestBaseline);
        let baseline = fact(
            1,
            FactProducer::IsolatedExecution,
            InboundFact::BaselineObserved {
                observation: id("observation", 1),
            },
        );
        r.apply_fact(baseline.clone()).unwrap();

        let mut rebuilt = RemediationRun::rebuild(r.timeline()).unwrap();
        assert_eq!(
            rebuilt
                .command(
                    "bind".into(),
                    command_digest,
                    RunCommand::Cancel {
                        reason: "retry body is ignored only because its digest matches".into(),
                    },
                )
                .unwrap(),
            RunState::BaselineObserved
        );
        assert_eq!(
            rebuilt.apply_fact(baseline).unwrap(),
            RunState::BaselineObserved
        );
    }
    #[test]
    fn every_verdict_is_recorded_without_recalculation() {
        for verdict in [
            RecordedVerdict::VerifiedForFixture,
            RecordedVerdict::Rejected,
            RecordedVerdict::Inconclusive,
            RecordedVerdict::NonConformant,
        ] {
            let mut r = run();
            command(&mut r, 1, RunCommand::BindInputs(inputs()));
            command(&mut r, 2, RunCommand::RequestBaseline);
            r.apply_fact(fact(
                1,
                FactProducer::IsolatedExecution,
                InboundFact::BaselineObserved {
                    observation: id("o", 1),
                },
            ))
            .unwrap();
            command(&mut r, 3, RunCommand::RequestProposal);
            r.apply_fact(fact(
                2,
                FactProducer::PatchProposals,
                InboundFact::PatchProposed {
                    proposal: id("p", 1),
                    patch_digest: Sha256Digest::of_bytes(b"p"),
                },
            ))
            .unwrap();
            command(&mut r, 4, RunCommand::RequestAssessment);
            r.apply_fact(fact(
                3,
                FactProducer::Verification,
                InboundFact::CandidateAssessed {
                    assessment: id("a", 1),
                    verdict,
                },
            ))
            .unwrap();
            let expected = match verdict {
                RecordedVerdict::Inconclusive => RunState::Inconclusive,
                RecordedVerdict::NonConformant => RunState::NonConformant,
                _ => RunState::Assessed(verdict),
            };
            assert_eq!(r.state(), expected);
        }
    }
    #[test]
    fn cancellation_and_budget_races_have_one_terminal_winner() {
        for cancel_first in [true, false] {
            let mut r = run();
            let first = if cancel_first {
                RunCommand::Cancel {
                    reason: "operator".into(),
                }
            } else {
                RunCommand::MarkBudgetExhausted
            };
            command(&mut r, 1, first);
            let second = if cancel_first {
                RunCommand::MarkBudgetExhausted
            } else {
                RunCommand::Cancel {
                    reason: "operator".into(),
                }
            };
            assert_eq!(
                r.command("key-2".into(), Sha256Digest::of_bytes(b"2"), second),
                Err(RunError::Terminal)
            );
        }
    }
    #[test]
    fn command_replay_and_terminal_property_hold_for_all_states() {
        let mut r = run();
        let digest = Sha256Digest::of_bytes(b"same");
        assert_eq!(
            r.command("key".into(), digest, RunCommand::BindInputs(inputs()))
                .unwrap(),
            r.command(
                "key".into(),
                digest,
                RunCommand::Cancel {
                    reason: "ignored retry payload".into()
                }
            )
            .unwrap()
        );
        command(
            &mut r,
            2,
            RunCommand::Cancel {
                reason: "done".into(),
            },
        );
        for n in 0..32 {
            assert_eq!(
                r.command(
                    format!("later-{n}"),
                    Sha256Digest::of_bytes([n]),
                    RunCommand::MarkBudgetExhausted
                ),
                Err(RunError::Terminal)
            );
        }
    }
}
