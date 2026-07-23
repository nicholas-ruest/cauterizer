//! Application ports, handlers, and deterministic local adapters.
#![allow(
    clippy::manual_let_else,
    clippy::missing_errors_doc,
    clippy::single_match_else,
    missing_docs
)]

use crate::domain::{
    CandidatePatchRef, ProposalAttempt, ProposalError, SolverBrief, SolverOutput, SolverUsage,
    UnifiedPatch,
};
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
use std::collections::HashMap;

/// Context-owned replaceable solver boundary.
pub trait SolverPort {
    /// Produces only patch text, provenance, and bounded usage.
    fn solve(&mut self, brief: &SolverBrief) -> Result<SolverOutput, ProposalError>;
}

/// Atomic persistence boundary. Implementations persist aggregate, facts, and
/// outbox records in one transaction.
pub trait ProposalAttemptRepository {
    /// Loads within the authenticated tenant partition.
    fn load(
        &self,
        tenant: &OrganizationId,
        id: &ContextQualifiedId,
    ) -> Result<Option<ProposalAttempt>, ProposalError>;
    /// Atomically applies an optimistic change and its public facts.
    fn save_atomic(
        &mut self,
        tenant: &OrganizationId,
        expected_version: Option<u64>,
        attempt: ProposalAttempt,
        facts: Vec<ProposalFact>,
    ) -> Result<(), ProposalError>;
    /// Returns a prior result or rejects conflicting key reuse.
    fn idempotency(
        &self,
        tenant: &OrganizationId,
        key: &str,
        request: Sha256Digest,
    ) -> Result<Option<CommandResult>, ProposalError>;
    /// Commits the stable command result with the aggregate transaction.
    fn record_idempotency(
        &mut self,
        tenant: &OrganizationId,
        key: String,
        request: Sha256Digest,
        result: CommandResult,
    );
}

/// Authenticated, tenant-scoped command authority.
#[derive(Clone)]
pub struct CommandContext {
    /// Authenticated tenant.
    pub organization_id: OrganizationId,
    /// Explicit proposal permission.
    pub may_propose: bool,
}

/// Public event payload queued atomically.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposalFact {
    /// Attempt admitted.
    Opened { attempt_id: ContextQualifiedId },
    /// Candidate became immutable.
    Proposed {
        attempt_id: ContextQualifiedId,
        candidate: CandidatePatchRef,
    },
    /// Provider failed without leaking provider detail.
    ProviderFailed { attempt_id: ContextQualifiedId },
}

/// Stable retry result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandResult {
    /// Opened aggregate.
    Opened { attempt_id: ContextQualifiedId },
    /// Immutable proposal.
    Proposed(CandidatePatchRef),
    /// Stable failure recorded.
    ProviderFailed,
}

/// Tenant-safe read model rebuilt entirely from published facts.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AttemptProjection {
    rows: HashMap<ContextQualifiedId, AttemptSummary>,
}

/// Payload-free status view; patch bytes and solver input are never projected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptSummary {
    /// Stable attempt identity.
    pub attempt_id: ContextQualifiedId,
    /// Stable lifecycle label.
    pub status: &'static str,
    /// Candidate digest when proposed.
    pub candidate_digest: Option<Sha256Digest>,
}

impl AttemptProjection {
    /// Applies replayable facts idempotently.
    pub fn apply(&mut self, fact: &ProposalFact) {
        match fact {
            ProposalFact::Opened { attempt_id } => {
                self.rows
                    .entry(attempt_id.clone())
                    .or_insert_with(|| AttemptSummary {
                        attempt_id: attempt_id.clone(),
                        status: "open",
                        candidate_digest: None,
                    });
            }
            ProposalFact::Proposed {
                attempt_id,
                candidate,
            } => {
                self.rows.insert(
                    attempt_id.clone(),
                    AttemptSummary {
                        attempt_id: attempt_id.clone(),
                        status: "proposed",
                        candidate_digest: Some(candidate.patch_digest),
                    },
                );
            }
            ProposalFact::ProviderFailed { attempt_id } => {
                self.rows.insert(
                    attempt_id.clone(),
                    AttemptSummary {
                        attempt_id: attempt_id.clone(),
                        status: "provider_failed",
                        candidate_digest: None,
                    },
                );
            }
        }
    }

    /// Returns one tenant-partition-local summary.
    #[must_use]
    pub fn get(&self, id: &ContextQualifiedId) -> Option<&AttemptSummary> {
        self.rows.get(id)
    }
}

/// Coarse application facade.
pub struct ProposalService<R> {
    repository: R,
}

impl<R: ProposalAttemptRepository> ProposalService<R> {
    /// Creates the facade around a context-owned repository.
    pub const fn new(repository: R) -> Self {
        Self { repository }
    }

    /// Opens an idempotent tenant-owned attempt.
    pub fn open(
        &mut self,
        context: &CommandContext,
        key: &str,
        id: ContextQualifiedId,
        brief: SolverBrief,
    ) -> Result<CommandResult, ProposalError> {
        authorize(context, &brief.organization_id)?;
        let request = brief.digest();
        if let Some(result) = self
            .repository
            .idempotency(&context.organization_id, key, request)?
        {
            return Ok(result);
        }
        let attempt = ProposalAttempt::open(id.clone(), brief)?;
        let result = CommandResult::Opened {
            attempt_id: id.clone(),
        };
        self.repository.save_atomic(
            &context.organization_id,
            None,
            attempt,
            vec![ProposalFact::Opened { attempt_id: id }],
        )?;
        self.repository.record_idempotency(
            &context.organization_id,
            key.to_owned(),
            request,
            result.clone(),
        );
        Ok(result)
    }

    /// Invokes a solver and atomically publishes at most one candidate.
    pub fn propose(
        &mut self,
        context: &CommandContext,
        key: &str,
        attempt_id: &ContextQualifiedId,
        candidate_id: ContextQualifiedId,
        solver: &mut impl SolverPort,
    ) -> Result<(CommandResult, UnifiedPatch), ProposalError> {
        let mut attempt = self
            .repository
            .load(&context.organization_id, attempt_id)?
            .ok_or(ProposalError::Unauthorized)?;
        authorize(context, &attempt.brief.organization_id)?;
        let mut request_bytes = attempt.brief.digest().as_bytes().to_vec();
        request_bytes.extend_from_slice(candidate_id.as_str().as_bytes());
        let request = Sha256Digest::of_bytes(request_bytes);
        if self
            .repository
            .idempotency(&context.organization_id, key, request)?
            .is_some()
        {
            return Err(ProposalError::AttemptTerminal);
        }
        let expected = attempt.version;
        let output = match solver.solve(&attempt.brief) {
            Ok(output) => output,
            Err(_) => {
                attempt.provider_failed()?;
                self.repository.save_atomic(
                    &context.organization_id,
                    Some(expected),
                    attempt,
                    vec![ProposalFact::ProviderFailed {
                        attempt_id: attempt_id.clone(),
                    }],
                )?;
                return Err(ProposalError::ProviderUnavailable);
            }
        };
        let (patch, candidate) = attempt.accept(output, candidate_id)?;
        let result = CommandResult::Proposed(candidate.clone());
        self.repository.save_atomic(
            &context.organization_id,
            Some(expected),
            attempt,
            vec![ProposalFact::Proposed {
                attempt_id: attempt_id.clone(),
                candidate,
            }],
        )?;
        self.repository.record_idempotency(
            &context.organization_id,
            key.to_owned(),
            request,
            result.clone(),
        );
        Ok((result, patch))
    }

    /// Returns the repository for composition/tests.
    pub fn into_repository(self) -> R {
        self.repository
    }
}

fn authorize(context: &CommandContext, owner: &OrganizationId) -> Result<(), ProposalError> {
    if context.may_propose && &context.organization_id == owner {
        Ok(())
    } else {
        Err(ProposalError::Unauthorized)
    }
}

/// Manual input adapter.
pub struct ManualSolver {
    output: Option<SolverOutput>,
}
impl ManualSolver {
    /// Creates a single-use manual adapter.
    #[must_use]
    pub const fn new(output: SolverOutput) -> Self {
        Self {
            output: Some(output),
        }
    }
}
impl SolverPort for ManualSolver {
    fn solve(&mut self, _brief: &SolverBrief) -> Result<SolverOutput, ProposalError> {
        self.output.take().ok_or(ProposalError::ProviderUnavailable)
    }
}

/// Deterministic offline solver used for reproducible pipelines.
pub struct DeterministicMockSolver {
    patch: Vec<u8>,
    provenance: Sha256Digest,
}
impl DeterministicMockSolver {
    /// Pins exact output and configuration provenance.
    #[must_use]
    pub fn new(patch: impl Into<Vec<u8>>, provenance: Sha256Digest) -> Self {
        Self {
            patch: patch.into(),
            provenance,
        }
    }
}
impl SolverPort for DeterministicMockSolver {
    fn solve(&mut self, _brief: &SolverBrief) -> Result<SolverOutput, ProposalError> {
        Ok(SolverOutput {
            patch: self.patch.clone(),
            rationale: Some("deterministic offline candidate".into()),
            usage: SolverUsage::default(),
            solver_provenance: self.provenance,
        })
    }
}

/// Replay-safe in-memory reference adapter.
#[derive(Default)]
pub struct MemoryProposalRepository {
    attempts: HashMap<(OrganizationId, ContextQualifiedId), ProposalAttempt>,
    idempotency: HashMap<(OrganizationId, String), (Sha256Digest, CommandResult)>,
    /// Transactionally queued facts.
    pub outbox: Vec<ProposalFact>,
}

impl ProposalAttemptRepository for MemoryProposalRepository {
    fn load(
        &self,
        tenant: &OrganizationId,
        id: &ContextQualifiedId,
    ) -> Result<Option<ProposalAttempt>, ProposalError> {
        Ok(self.attempts.get(&(tenant.clone(), id.clone())).cloned())
    }

    fn save_atomic(
        &mut self,
        tenant: &OrganizationId,
        expected_version: Option<u64>,
        attempt: ProposalAttempt,
        facts: Vec<ProposalFact>,
    ) -> Result<(), ProposalError> {
        if &attempt.brief.organization_id != tenant {
            return Err(ProposalError::Unauthorized);
        }
        let key = (tenant.clone(), attempt.id.clone());
        let actual = self.attempts.get(&key).map(|value| value.version);
        if actual != expected_version {
            return Err(ProposalError::ConcurrencyConflict);
        }
        self.attempts.insert(key, attempt);
        self.outbox.extend(facts);
        Ok(())
    }

    fn idempotency(
        &self,
        tenant: &OrganizationId,
        key: &str,
        request: Sha256Digest,
    ) -> Result<Option<CommandResult>, ProposalError> {
        match self.idempotency.get(&(tenant.clone(), key.to_owned())) {
            Some((stored, result)) if *stored == request => Ok(Some(result.clone())),
            Some(_) => Err(ProposalError::IdempotencyConflict),
            None => Ok(None),
        }
    }

    fn record_idempotency(
        &mut self,
        tenant: &OrganizationId,
        key: String,
        request: Sha256Digest,
        result: CommandResult,
    ) {
        self.idempotency
            .insert((tenant.clone(), key), (request, result));
    }
}
