//! Bounded repair-loop orchestration.
//!
//! The types in this module deliberately make the public test loop and the
//! independent verifier different ports. Hidden verification can return only a
//! terminal admission decision; it can never manufacture solver feedback.

use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::ContextQualifiedId;
use std::fmt;

/// Immutable inputs needed to start an automated repair loop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairRequest {
    /// Run whose append-only history owns the orchestration.
    pub run_id: super::super::domain::RemediationRunId,
    /// Immutable vulnerable baseline observation.
    pub baseline: ContextQualifiedId,
}

/// Hard limits applied before invoking any external component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairBudget {
    /// Maximum number of candidates the solver may create.
    pub max_attempts: u32,
    /// Maximum cumulative provider-reported solver units.
    pub max_solver_units: u64,
}

impl RepairBudget {
    /// Validates non-zero, bounded limits.
    ///
    /// # Errors
    ///
    /// Returns [`OrchestrationError::InvalidBudget`] when either limit is zero
    /// or the attempt limit exceeds the hard safety ceiling.
    #[must_use = "validated budgets must be used"]
    pub fn validate(self) -> Result<Self, OrchestrationError> {
        if self.max_attempts == 0 || self.max_attempts > 100 || self.max_solver_units == 0 {
            Err(OrchestrationError::InvalidBudget)
        } else {
            Ok(self)
        }
    }
}

/// Solver-visible result produced only by ordinary build and test execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VisibleFeedback {
    /// Sanitized, immutable diagnostic artifact. The hidden verifier cannot set it.
    pub diagnostic: ContextQualifiedId,
    /// Digest binds the exact sanitized diagnostic bytes.
    pub digest: Sha256Digest,
}

/// Immutable candidate identity and parent relation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateAttempt {
    /// One-based attempt number.
    pub number: u32,
    /// Immutable proposal reference.
    pub proposal: ContextQualifiedId,
    /// Exact candidate patch digest.
    pub patch_digest: Sha256Digest,
    /// Previous candidate, if this candidate repairs a public-test failure.
    pub parent_proposal: Option<ContextQualifiedId>,
    /// Provider-reported units consumed creating this candidate.
    pub solver_units: u64,
    /// Exact normalized patch size in bytes.
    pub patch_bytes: u64,
    /// Exact number of changed source lines.
    pub changed_lines: u64,
    /// Provider-reported spend for this attempt in micros.
    pub cost_micros: u64,
    /// Provider-reported elapsed generation time for this attempt.
    pub time_millis: u64,
}

/// Input exposed to the solver. It contains no verifier assessment or details.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SolverRequest {
    /// Run identity used to derive provider idempotency keys.
    pub run_id: super::super::domain::RemediationRunId,
    /// Immutable vulnerable baseline.
    pub baseline: ContextQualifiedId,
    /// Prior candidate identity for lineage.
    pub parent_proposal: Option<ContextQualifiedId>,
    /// Sanitized feedback from visible checks only.
    pub visible_feedback: Option<VisibleFeedback>,
    /// One-based candidate number.
    pub attempt_number: u32,
    /// Remaining provider budget for this call, enforced by the adapter.
    pub remaining_solver_units: u64,
}

/// Candidate-generation port implemented by a coding agent adapter.
pub trait CandidateSolver {
    /// Produces exactly one immutable candidate.
    ///
    /// # Errors
    ///
    /// Returns a coarse component error without verifier-derived detail.
    fn propose(&mut self, request: &SolverRequest) -> Result<CandidateAttempt, ComponentError>;
}

/// Result of solver-visible build, test, and lint checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VisibleCheck {
    /// Candidate may advance to independent verification.
    Passed,
    /// Candidate may be repaired using this sanitized feedback.
    Failed(VisibleFeedback),
}

/// Public-check port. Its failure diagnostics are safe to return to the solver.
pub trait VisibleEvaluator {
    /// Applies the candidate and runs ordinary visible checks.
    ///
    /// # Errors
    ///
    /// Returns a coarse component error when visible evaluation cannot run.
    fn evaluate(&mut self, candidate: &CandidateAttempt) -> Result<VisibleCheck, ComponentError>;
}

/// Narrow result of hidden verification. No diagnostic channel exists by design.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HiddenDecision {
    /// Candidate satisfies the independent policy.
    Verified,
    /// Candidate fails the independent policy.
    Rejected,
    /// Verification could not establish a result.
    Inconclusive,
    /// Verification detected prohibited information flow.
    NonConformant,
}

/// Independent hidden-verification port.
pub trait HiddenVerifier {
    /// Assesses one publicly passing candidate and reveals only a narrow verdict.
    ///
    /// # Errors
    ///
    /// Returns a coarse component error without hidden observation detail.
    fn verify(&mut self, candidate: &CandidateAttempt) -> Result<HiddenDecision, ComponentError>;
}

/// Append-only record of one solver attempt and its public result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptRecord {
    /// Immutable generated candidate.
    pub candidate: CandidateAttempt,
    /// Public result used to choose the next transition.
    pub visible_result: VisibleCheck,
}

/// Terminal repair-loop outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepairOutcome {
    /// A candidate passed public checks and independent verification.
    Verified {
        /// Final candidate admitted by the independent verifier.
        candidate: CandidateAttempt,
    },
    /// Independent verification ended the loop without leaking feedback.
    VerificationStopped {
        /// Final candidate assessed by the independent verifier.
        candidate: CandidateAttempt,
        /// Coarse terminal decision; no hidden observation is exposed.
        decision: HiddenDecision,
    },
    /// No further solver call was permitted.
    BudgetExhausted,
}

/// Complete immutable transcript suitable for persistence as run events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairTranscript {
    /// Ordered, immutable attempt lineage.
    pub attempts: Vec<AttemptRecord>,
    /// Cumulative provider-reported solver usage.
    pub solver_units: u64,
    /// Cumulative provider-reported spend across all attempts.
    pub spend_micros: u64,
    /// Cumulative provider-reported generation time across all attempts.
    pub elapsed_millis: u64,
    /// Terminal outcome.
    pub outcome: RepairOutcome,
}

/// Stateless coordinator; all retry state is returned in the transcript.
pub struct RepairLoop;

impl RepairLoop {
    /// Runs a bounded visible-feedback loop followed by independent verification.
    ///
    /// # Errors
    ///
    /// Fails closed for invalid budgets, solver contract violations, component
    /// failure, arithmetic overflow, or duplicate proposal identity.
    #[must_use = "the terminal transcript must be persisted"]
    pub fn execute<S: CandidateSolver, V: VisibleEvaluator, H: HiddenVerifier>(
        request: &RepairRequest,
        budget: RepairBudget,
        solver: &mut S,
        visible: &mut V,
        hidden: &mut H,
    ) -> Result<RepairTranscript, OrchestrationError> {
        let budget = budget.validate()?;
        let mut attempts = Vec::new();
        let mut units = 0_u64;
        let mut spend_micros = 0_u64;
        let mut elapsed_millis = 0_u64;
        let mut feedback = None;
        let mut parent = None;
        let mut proposal_ids = std::collections::BTreeSet::new();

        for number in 1..=budget.max_attempts {
            if units >= budget.max_solver_units {
                break;
            }
            let solver_request = SolverRequest {
                run_id: request.run_id.clone(),
                baseline: request.baseline.clone(),
                parent_proposal: parent.clone(),
                visible_feedback: feedback.clone(),
                attempt_number: number,
                remaining_solver_units: budget.max_solver_units - units,
            };
            let candidate = solver.propose(&solver_request)?;
            if candidate.number != number
                || candidate.parent_proposal != parent
                || candidate.solver_units == 0
                || candidate.patch_bytes == 0
                || candidate.changed_lines == 0
                || candidate.solver_units > budget.max_solver_units - units
                || !proposal_ids.insert(candidate.proposal.clone())
            {
                return Err(OrchestrationError::InvalidCandidate);
            }
            units += candidate.solver_units;
            spend_micros = spend_micros
                .checked_add(candidate.cost_micros)
                .ok_or(OrchestrationError::InvalidCandidate)?;
            elapsed_millis = elapsed_millis
                .checked_add(candidate.time_millis)
                .ok_or(OrchestrationError::InvalidCandidate)?;
            let check = visible.evaluate(&candidate)?;
            attempts.push(AttemptRecord {
                candidate: candidate.clone(),
                visible_result: check.clone(),
            });
            match check {
                VisibleCheck::Failed(next_feedback) => {
                    parent = Some(candidate.proposal);
                    feedback = Some(next_feedback);
                }
                VisibleCheck::Passed => {
                    let decision = hidden.verify(&candidate)?;
                    let outcome = if decision == HiddenDecision::Verified {
                        RepairOutcome::Verified { candidate }
                    } else {
                        RepairOutcome::VerificationStopped {
                            candidate,
                            decision,
                        }
                    };
                    return Ok(RepairTranscript {
                        attempts,
                        solver_units: units,
                        spend_micros,
                        elapsed_millis,
                        outcome,
                    });
                }
            }
        }
        Ok(RepairTranscript {
            attempts,
            solver_units: units,
            spend_micros,
            elapsed_millis,
            outcome: RepairOutcome::BudgetExhausted,
        })
    }
}

/// Stable adapter error without provider-sensitive details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentError;

/// Fail-closed orchestration errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrchestrationError {
    /// Limits were empty or outside supported bounds.
    InvalidBudget,
    /// Solver violated attempt lineage or reported usage outside the reservation.
    InvalidCandidate,
    /// An external component failed.
    Component,
}

impl From<ComponentError> for OrchestrationError {
    fn from(_: ComponentError) -> Self {
        Self::Component
    }
}
impl fmt::Display for OrchestrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for OrchestrationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::RemediationRunId;
    use std::collections::VecDeque;

    fn id(context: &str, n: u32) -> ContextQualifiedId {
        ContextQualifiedId::new(context, &format!("{n:08}")).unwrap()
    }
    fn request() -> RepairRequest {
        RepairRequest {
            run_id: RemediationRunId::new("00000001").unwrap(),
            baseline: id("observation", 1),
        }
    }
    #[derive(Default)]
    struct Solver {
        requests: Vec<SolverRequest>,
    }
    impl CandidateSolver for Solver {
        fn propose(&mut self, r: &SolverRequest) -> Result<CandidateAttempt, ComponentError> {
            self.requests.push(r.clone());
            Ok(CandidateAttempt {
                number: r.attempt_number,
                proposal: id("proposal", r.attempt_number),
                patch_digest: Sha256Digest::of_bytes(format!("patch-{}", r.attempt_number)),
                parent_proposal: r.parent_proposal.clone(),
                solver_units: 2,
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
    #[derive(Default)]
    struct Hidden {
        calls: usize,
        decision: Option<HiddenDecision>,
    }
    impl HiddenVerifier for Hidden {
        fn verify(&mut self, _: &CandidateAttempt) -> Result<HiddenDecision, ComponentError> {
            self.calls += 1;
            Ok(self.decision.unwrap())
        }
    }
    fn feedback(n: u32) -> VisibleFeedback {
        VisibleFeedback {
            diagnostic: id("diagnostic", n),
            digest: Sha256Digest::of_bytes(format!("diagnostic-{n}")),
        }
    }

    #[test]
    fn retries_with_only_visible_feedback_and_preserves_lineage() {
        let mut solver = Solver::default();
        let mut visible = Visible(VecDeque::from([
            VisibleCheck::Failed(feedback(1)),
            VisibleCheck::Passed,
        ]));
        let mut hidden = Hidden {
            decision: Some(HiddenDecision::Verified),
            ..Hidden::default()
        };
        let transcript = RepairLoop::execute(
            &request(),
            RepairBudget {
                max_attempts: 3,
                max_solver_units: 10,
            },
            &mut solver,
            &mut visible,
            &mut hidden,
        )
        .unwrap();
        assert_eq!(transcript.attempts.len(), 2);
        assert_eq!(transcript.solver_units, 4);
        assert_eq!(transcript.spend_micros, 6);
        assert_eq!(transcript.elapsed_millis, 10);
        assert_eq!(solver.requests[0].remaining_solver_units, 10);
        assert_eq!(solver.requests[1].remaining_solver_units, 8);
        assert_eq!(solver.requests[1].visible_feedback, Some(feedback(1)));
        assert_eq!(solver.requests[1].parent_proposal, Some(id("proposal", 1)));
        assert!(matches!(transcript.outcome, RepairOutcome::Verified { .. }));
    }

    #[test]
    fn hidden_rejection_is_terminal_and_never_becomes_solver_feedback() {
        let mut solver = Solver::default();
        let mut visible = Visible(VecDeque::from([VisibleCheck::Passed]));
        let mut hidden = Hidden {
            decision: Some(HiddenDecision::Rejected),
            ..Hidden::default()
        };
        let result = RepairLoop::execute(
            &request(),
            RepairBudget {
                max_attempts: 9,
                max_solver_units: 20,
            },
            &mut solver,
            &mut visible,
            &mut hidden,
        )
        .unwrap();
        assert_eq!(solver.requests.len(), 1);
        assert_eq!(solver.requests[0].visible_feedback, None);
        assert!(matches!(
            result.outcome,
            RepairOutcome::VerificationStopped {
                decision: HiddenDecision::Rejected,
                ..
            }
        ));
    }

    #[test]
    fn attempt_and_unit_budgets_stop_before_an_extra_solver_call() {
        let mut solver = Solver::default();
        let mut visible = Visible(VecDeque::from([
            VisibleCheck::Failed(feedback(1)),
            VisibleCheck::Failed(feedback(2)),
        ]));
        let mut hidden = Hidden::default();
        let result = RepairLoop::execute(
            &request(),
            RepairBudget {
                max_attempts: 2,
                max_solver_units: 4,
            },
            &mut solver,
            &mut visible,
            &mut hidden,
        )
        .unwrap();
        assert_eq!(solver.requests.len(), 2);
        assert_eq!(hidden.calls, 0);
        assert_eq!(result.outcome, RepairOutcome::BudgetExhausted);
    }

    #[test]
    fn rejects_solver_lineage_or_usage_contract_violations() {
        struct Bad;
        impl CandidateSolver for Bad {
            fn propose(&mut self, _: &SolverRequest) -> Result<CandidateAttempt, ComponentError> {
                Ok(CandidateAttempt {
                    number: 99,
                    proposal: id("proposal", 1),
                    patch_digest: Sha256Digest::of_bytes(b"p"),
                    parent_proposal: None,
                    solver_units: 1,
                    patch_bytes: 1,
                    changed_lines: 1,
                    cost_micros: 0,
                    time_millis: 0,
                })
            }
        }
        let error = RepairLoop::execute(
            &request(),
            RepairBudget {
                max_attempts: 1,
                max_solver_units: 1,
            },
            &mut Bad,
            &mut Visible(VecDeque::new()),
            &mut Hidden::default(),
        )
        .unwrap_err();
        assert_eq!(error, OrchestrationError::InvalidCandidate);
    }

    #[test]
    fn rejects_empty_or_unbounded_attempt_budgets_before_calling_components() {
        let mut solver = Solver::default();
        let error = RepairLoop::execute(
            &request(),
            RepairBudget {
                max_attempts: 0,
                max_solver_units: 1,
            },
            &mut solver,
            &mut Visible(VecDeque::new()),
            &mut Hidden::default(),
        )
        .unwrap_err();
        assert_eq!(error, OrchestrationError::InvalidBudget);
        assert!(solver.requests.is_empty());
    }
}
