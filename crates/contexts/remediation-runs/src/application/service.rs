//! Direct command facade and owning-context anti-corruption handlers.
use super::ports::{
    AuditError, AuditFact, AuditOutcome, AuditSink, AuthorizationDecision, CommandControl, Commit,
    CommitOutcome, InboundEnvelope, RemediationRunRepository, RepositoryError, RunAuthorizer,
    RunKey,
};
use crate::domain::{
    AuthenticatedFact, FactProducer, InboundFact, RemediationRun, RemediationRunId, RunCommand,
    RunError, RunEvent, RunLineage, RunState,
};
use cauterizer_syntax::authorization::AuthorizationRequestContext;
use cauterizer_syntax::identifiers::ContextQualifiedId;
use std::fmt;
/// Authenticated contract envelope plus translated provider-neutral fact.
pub struct OwningContextEvent {
    /// Durable inbox metadata.
    pub envelope: InboundEnvelope,
    /// Anti-corruption translation result.
    pub fact: AuthenticatedFact,
}
/// Durable run application facade.
pub struct RemediationRunService<R, Z, U> {
    repository: R,
    authorizer: Z,
    audit: U,
}
impl<R: RemediationRunRepository<RemediationRun, RunEvent>, Z: RunAuthorizer, U: AuditSink>
    RemediationRunService<R, Z, U>
{
    /// Constructs the facade.
    #[must_use]
    pub const fn new(repository: R, authorizer: Z, audit: U) -> Self {
        Self {
            repository,
            authorizer,
            audit,
        }
    }
    /// Creates one append-only run under exact retry binding.
    /// # Errors
    /// Fails closed on authorization, audit, persistence, or malformed identity.
    pub fn create_run(
        &self,
        a: &AuthorizationRequestContext,
        id: RemediationRunId,
        lineage: RunLineage,
        control: &CommandControl,
    ) -> Result<CommitOutcome, ApplicationError> {
        let key = Self::key(a, id.as_str())?;
        self.guard(a, "runs.create", id.as_str())?;
        let mut run = RemediationRun::create(a.organization_id().clone(), id, lineage);
        let events = run.take_pending_events();
        let result = self.repository.create(
            key,
            control,
            Commit {
                aggregate: run,
                events,
            },
        )?;
        self.audit(
            a,
            "runs.create",
            a.resource().as_str(),
            AuditOutcome::Succeeded,
        )?;
        Ok(result)
    }
    /// Applies a coarse coordination command; request commands never fabricate external results.
    /// # Errors
    /// Rejects unauthorized, stale, conflicting, invalid, or terminal transitions atomically.
    pub fn command(
        &self,
        a: &AuthorizationRequestContext,
        id: &RemediationRunId,
        command: RunCommand,
        control: &CommandControl,
    ) -> Result<RunState, ApplicationError> {
        let action = action_for(&command);
        self.guard(a, action, id.as_str())?;
        let key = Self::key(a, id.as_str())?;
        let mut loaded = self
            .repository
            .load(&key)?
            .ok_or(RepositoryError::NotFound)?;
        let result = match loaded.aggregate.command(
            control.idempotency_key.as_str().into(),
            control.request_digest,
            command,
        ) {
            Ok(state) => state,
            Err(error) => {
                self.audit(a, action, id.as_str(), AuditOutcome::Failed)?;
                return Err(ApplicationError::Domain(error));
            }
        };
        let events = loaded.aggregate.take_pending_events();
        self.repository.commit_command(
            &key,
            control,
            Commit {
                aggregate: loaded.aggregate,
                events,
            },
        )?;
        self.audit(a, action, id.as_str(), AuditOutcome::Succeeded)?;
        Ok(result)
    }
    /// Applies an authenticated translated owning-context fact through the durable inbox.
    /// # Errors
    /// Rejects envelope substitution, wrong producer/tenant, duplicates with changed payload,
    /// gaps, stale versions, invalid lifecycle order, and cancellation races.
    pub fn handle_owning_context_event(
        &self,
        id: &RemediationRunId,
        expected_version: u64,
        event: OwningContextEvent,
    ) -> Result<CommitOutcome, ApplicationError> {
        validate_envelope(&event)?;
        if event.fact.run_id != *id {
            return Err(ApplicationError::InvalidEnvelope);
        }
        let key = RunKey {
            tenant: event.envelope.tenant.clone(),
            run_id: ContextQualifiedId::new(
                "run",
                id.as_str().strip_prefix("run_").unwrap_or(id.as_str()),
            )
            .map_err(|_| ApplicationError::InvalidEnvelope)?,
        };
        let mut loaded = self
            .repository
            .load(&key)?
            .ok_or(RepositoryError::NotFound)?;
        loaded
            .aggregate
            .apply_fact(event.fact)
            .map_err(ApplicationError::Domain)?;
        let events = loaded.aggregate.take_pending_events();
        self.repository
            .commit_inbound(
                &key,
                expected_version,
                &event.envelope,
                Commit {
                    aggregate: loaded.aggregate,
                    events,
                },
            )
            .map_err(Into::into)
    }
    /// Handles only an authenticated Isolated Execution baseline observation.
    /// # Errors
    /// Rejects any other producer or fact before repository access.
    pub fn handle_execution_observed(
        &self,
        id: &RemediationRunId,
        version: u64,
        event: OwningContextEvent,
    ) -> Result<CommitOutcome, ApplicationError> {
        if !matches!(
            (&event.fact.producer, &event.fact.payload),
            (
                FactProducer::IsolatedExecution,
                InboundFact::BaselineObserved { .. }
            )
        ) {
            return Err(ApplicationError::InvalidEnvelope);
        }
        self.handle_owning_context_event(id, version, event)
    }
    /// Handles only an authenticated Patch Proposals candidate fact.
    /// # Errors
    /// Rejects any other producer or fact before repository access.
    pub fn handle_patch_proposed(
        &self,
        id: &RemediationRunId,
        version: u64,
        event: OwningContextEvent,
    ) -> Result<CommitOutcome, ApplicationError> {
        if !matches!(
            (&event.fact.producer, &event.fact.payload),
            (
                FactProducer::PatchProposals,
                InboundFact::PatchProposed { .. }
            )
        ) {
            return Err(ApplicationError::InvalidEnvelope);
        }
        self.handle_owning_context_event(id, version, event)
    }
    /// Handles only an authenticated Verification assessment fact.
    /// # Errors
    /// Rejects any other producer or fact before repository access.
    pub fn handle_candidate_assessed(
        &self,
        id: &RemediationRunId,
        version: u64,
        event: OwningContextEvent,
    ) -> Result<CommitOutcome, ApplicationError> {
        if !matches!(
            (&event.fact.producer, &event.fact.payload),
            (
                FactProducer::Verification,
                InboundFact::CandidateAssessed { .. }
            )
        ) {
            return Err(ApplicationError::InvalidEnvelope);
        }
        self.handle_owning_context_event(id, version, event)
    }
    /// Handles only an authenticated Evidence finalization fact.
    /// # Errors
    /// Rejects any other producer or fact before repository access.
    pub fn handle_evidence_bundle_finalized(
        &self,
        id: &RemediationRunId,
        version: u64,
        event: OwningContextEvent,
    ) -> Result<CommitOutcome, ApplicationError> {
        if !matches!(
            (&event.fact.producer, &event.fact.payload),
            (
                FactProducer::Evidence,
                InboundFact::EvidenceFinalized { .. }
            )
        ) {
            return Err(ApplicationError::InvalidEnvelope);
        }
        self.handle_owning_context_event(id, version, event)
    }
    fn key(a: &AuthorizationRequestContext, id: &str) -> Result<RunKey, ApplicationError> {
        Ok(RunKey {
            tenant: a.organization_id().clone(),
            run_id: ContextQualifiedId::new("run", id.strip_prefix("run_").unwrap_or(id))
                .map_err(|_| ApplicationError::InvalidEnvelope)?,
        })
    }
    fn guard(
        &self,
        a: &AuthorizationRequestContext,
        action: &str,
        resource: &str,
    ) -> Result<(), ApplicationError> {
        if a.action().as_str() != action
            || a.resource().as_str() != resource
            || self.authorizer.authorize(a) != AuthorizationDecision::Allow
        {
            self.audit(a, action, resource, AuditOutcome::Denied)?;
            return Err(ApplicationError::Denied);
        }
        Ok(())
    }
    fn audit(
        &self,
        a: &AuthorizationRequestContext,
        action: &str,
        run: &str,
        outcome: AuditOutcome,
    ) -> Result<(), ApplicationError> {
        self.audit
            .record(AuditFact {
                tenant: a.organization_id().clone(),
                action: action.into(),
                run: run.into(),
                outcome,
            })
            .map_err(Into::into)
    }
}
fn action_for(command: &RunCommand) -> &'static str {
    match command {
        RunCommand::BindInputs(_) => "runs.bind_inputs",
        RunCommand::RequestBaseline => "runs.request_baseline",
        RunCommand::RequestProposal => "runs.request_proposal",
        RunCommand::RequestAssessment => "runs.request_assessment",
        RunCommand::RequestEvidence => "runs.request_evidence",
        RunCommand::MarkBudgetExhausted => "runs.budget_exhausted",
        RunCommand::Cancel { .. } => "runs.cancel",
        RunCommand::Seal => "runs.seal",
    }
}
fn validate_envelope(event: &OwningContextEvent) -> Result<(), ApplicationError> {
    if event.envelope.event_id != event.fact.event_id
        || event.envelope.tenant != event.fact.organization_id
    {
        return Err(ApplicationError::InvalidEnvelope);
    }
    let expected = match (&event.fact.producer, &event.fact.payload) {
        (FactProducer::IsolatedExecution, InboundFact::BaselineObserved { .. }) => {
            "isolated-execution"
        }
        (FactProducer::PatchProposals, InboundFact::PatchProposed { .. }) => "patch-proposals",
        (FactProducer::Verification, InboundFact::CandidateAssessed { .. }) => "verification",
        (FactProducer::Evidence, InboundFact::EvidenceFinalized { .. }) => "evidence",
        _ => return Err(ApplicationError::InvalidEnvelope),
    };
    if event.envelope.producer != expected {
        return Err(ApplicationError::InvalidEnvelope);
    }
    Ok(())
}
/// Stable application failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationError {
    /// Authorization denied.
    Denied,
    /// Audit unavailable.
    AuditUnavailable,
    /// Persistence/inbox failure.
    Repository(RepositoryError),
    /// Aggregate rejection.
    Domain(RunError),
    /// Authenticated envelope inconsistent with translated fact.
    InvalidEnvelope,
}
impl From<RepositoryError> for ApplicationError {
    fn from(value: RepositoryError) -> Self {
        Self::Repository(value)
    }
}
impl From<AuditError> for ApplicationError {
    fn from(_: AuditError) -> Self {
        Self::AuditUnavailable
    }
}
impl fmt::Display for ApplicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Denied => "run_operation_denied",
            Self::AuditUnavailable => "run_audit_unavailable",
            Self::Repository(_) => "run_repository_failure",
            Self::Domain(_) => "run_transition_rejected",
            Self::InvalidEnvelope => "run_inbound_envelope_invalid",
        })
    }
}
impl std::error::Error for ApplicationError {}
