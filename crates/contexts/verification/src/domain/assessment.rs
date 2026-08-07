//! Deterministic, leak-resistant candidate assessment.

use std::collections::{BTreeMap, BTreeSet};

use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
use serde::{Deserialize, Serialize};

/// Immutable execution role known only to verification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ObservationRole {
    /// Unpatched target must reproduce the vulnerability.
    BaselineVulnerable,
    /// Known-good control must pass the hidden fixture.
    GoldControl,
    /// Candidate must pass hidden security tests.
    CandidateHidden,
    /// Candidate must preserve the regression inventory.
    CandidateRegression,
}

/// Coarse execution result. Process output is deliberately absent.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ExecutionOutcome {
    /// All selected tests passed.
    Passed,
    /// At least one selected test failed deterministically.
    Failed,
    /// The immutable execution deadline elapsed.
    TimedOut,
    /// Infrastructure could not produce a trustworthy observation.
    InfrastructureFailure,
}

/// One immutable, content-bound execution observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionObservation {
    /// Immutable isolated-execution reference.
    pub id: ContextQualifiedId,
    /// Verification-only role.
    pub role: ObservationRole,
    /// One-based repetition number.
    pub repetition: u32,
    /// Coarse process outcome.
    pub outcome: ExecutionOutcome,
    /// Discovered test inventory for this execution.
    pub test_count: u32,
    /// Digest of normalized results, excluding timing and random identifiers.
    pub result_digest: Sha256Digest,
    /// Whether execution satisfied the declared information-flow policy.
    pub conformant: bool,
}

/// Immutable candidate patch facts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PatchObservation {
    /// Exact candidate patch digest.
    pub patch_digest: Sha256Digest,
    /// Normalized repository-relative changed paths.
    pub changed_paths: Vec<String>,
    /// Total added and removed lines.
    pub changed_lines: u32,
}

/// Immutable assessment policy revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssessmentPolicy {
    /// Required independent repetitions for every execution role.
    pub repetitions: u32,
    /// Maximum total changed lines.
    pub max_changed_lines: u32,
    /// Repository-relative prefixes the candidate may modify.
    pub allowed_path_prefixes: Vec<String>,
    /// Paths that are forbidden even under an allowed prefix.
    pub forbidden_paths: BTreeSet<String>,
}

/// Complete verifier-held input. This type must never cross into solver APIs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CandidateAssessmentInput {
    /// Tenant that owns this immutable verifier input.
    pub organization_id: OrganizationId,
    /// Remediation run that produced the candidate.
    pub run_id: ContextQualifiedId,
    /// Immutable policy.
    pub policy: AssessmentPolicy,
    /// Candidate patch observation.
    pub patch: PatchObservation,
    /// Unordered immutable execution observations.
    pub observations: Vec<ExecutionObservation>,
}

/// Public deterministic verdict.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AssessmentVerdict {
    /// Candidate satisfies this exact fixture and policy.
    VerifiedForFixture,
    /// Candidate deterministically fails policy or tests.
    Rejected,
    /// Evidence cannot establish a trustworthy result.
    Inconclusive,
    /// A prohibited information flow or malformed trust claim was observed.
    NonConformant,
}

/// Stable coarse reason safe for workflow routing. No hidden test detail is encoded.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ReasonCode {
    /// All gates passed.
    Verified,
    /// Required immutable evidence was absent or duplicated.
    MissingEvidence,
    /// Repeated execution did not produce the same normalized result.
    UnstableObservation,
    /// At least one execution timed out.
    ExecutionTimeout,
    /// At least one execution failed operationally.
    InfrastructureFailure,
    /// The unpatched baseline did not reproduce the vulnerability.
    BaselineNotVulnerable,
    /// The known-good control did not validate the fixture.
    GoldControlFailed,
    /// Candidate failed a hidden security check.
    CandidateHiddenFailed,
    /// Candidate failed ordinary regression tests.
    RegressionFailed,
    /// Candidate reduced the discovered regression inventory.
    RegressionInventoryLoss,
    /// Candidate exceeded the immutable patch-size budget.
    PatchBudgetExceeded,
    /// Candidate modified a path outside its authorized scope.
    PatchScopeViolation,
    /// Execution violated solver/verifier separation.
    InformationFlowViolation,
    /// Policy or observation structure was invalid.
    InvalidEvidence,
}

/// Deterministic assessment record. Detailed observations remain verifier-held.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CandidateAssessment {
    /// Narrow workflow verdict.
    pub verdict: AssessmentVerdict,
    /// Coarse stable reason.
    pub reason: ReasonCode,
    /// Digest of canonical result plus complete immutable input.
    pub assessment_digest: Sha256Digest,
}

/// Pure assessment engine.
pub struct CandidateAssessmentEngine;

impl CandidateAssessmentEngine {
    /// Evaluates every gate in stable fail-closed precedence order.
    #[must_use]
    pub fn assess(input: &CandidateAssessmentInput) -> CandidateAssessment {
        let (verdict, reason) = Self::decide(input);
        let mut canonical_input = input.clone();
        canonical_input.observations.sort_by(|left, right| {
            (left.role, left.repetition, &left.id).cmp(&(right.role, right.repetition, &right.id))
        });
        canonical_input.patch.changed_paths.sort();
        canonical_input.policy.allowed_path_prefixes.sort();
        let canonical = serde_json::to_vec(&(canonical_input, verdict, reason))
            .unwrap_or_else(|_| b"assessment-serialization-failure".to_vec());
        CandidateAssessment {
            verdict,
            reason,
            assessment_digest: Sha256Digest::of_bytes(canonical),
        }
    }

    fn decide(input: &CandidateAssessmentInput) -> (AssessmentVerdict, ReasonCode) {
        if input.observations.iter().any(|item| !item.conformant) {
            return (
                AssessmentVerdict::NonConformant,
                ReasonCode::InformationFlowViolation,
            );
        }
        if !valid_policy(&input.policy) || !valid_paths(&input.patch.changed_paths) {
            return (
                AssessmentVerdict::NonConformant,
                ReasonCode::InvalidEvidence,
            );
        }
        let Some(grouped) = group_complete(&input.observations, input.policy.repetitions) else {
            return (AssessmentVerdict::Inconclusive, ReasonCode::MissingEvidence);
        };
        if grouped
            .values()
            .flatten()
            .any(|item| item.outcome == ExecutionOutcome::TimedOut)
        {
            return (
                AssessmentVerdict::Inconclusive,
                ReasonCode::ExecutionTimeout,
            );
        }
        if grouped
            .values()
            .flatten()
            .any(|item| item.outcome == ExecutionOutcome::InfrastructureFailure)
        {
            return (
                AssessmentVerdict::Inconclusive,
                ReasonCode::InfrastructureFailure,
            );
        }
        if grouped.values().any(|items| !repeatable(items)) {
            return (
                AssessmentVerdict::Inconclusive,
                ReasonCode::UnstableObservation,
            );
        }
        if outcome(&grouped, ObservationRole::BaselineVulnerable) != ExecutionOutcome::Failed {
            return (
                AssessmentVerdict::Inconclusive,
                ReasonCode::BaselineNotVulnerable,
            );
        }
        if outcome(&grouped, ObservationRole::GoldControl) != ExecutionOutcome::Passed {
            return (
                AssessmentVerdict::Inconclusive,
                ReasonCode::GoldControlFailed,
            );
        }
        if input.patch.changed_lines > input.policy.max_changed_lines {
            return (AssessmentVerdict::Rejected, ReasonCode::PatchBudgetExceeded);
        }
        if input.patch.changed_paths.iter().any(|path| {
            input.policy.forbidden_paths.contains(path)
                || !input
                    .policy
                    .allowed_path_prefixes
                    .iter()
                    .any(|prefix| path.starts_with(prefix))
        }) {
            return (AssessmentVerdict::Rejected, ReasonCode::PatchScopeViolation);
        }
        if outcome(&grouped, ObservationRole::CandidateHidden) != ExecutionOutcome::Passed {
            return (
                AssessmentVerdict::Rejected,
                ReasonCode::CandidateHiddenFailed,
            );
        }
        if outcome(&grouped, ObservationRole::CandidateRegression) != ExecutionOutcome::Passed {
            return (AssessmentVerdict::Rejected, ReasonCode::RegressionFailed);
        }
        let gold_count = test_count(&grouped, ObservationRole::GoldControl);
        let regression_count = test_count(&grouped, ObservationRole::CandidateRegression);
        if regression_count < gold_count {
            return (
                AssessmentVerdict::Rejected,
                ReasonCode::RegressionInventoryLoss,
            );
        }
        (AssessmentVerdict::VerifiedForFixture, ReasonCode::Verified)
    }
}

fn valid_policy(policy: &AssessmentPolicy) -> bool {
    policy.repetitions > 0
        && policy.repetitions <= 100
        && !policy.allowed_path_prefixes.is_empty()
        && policy
            .allowed_path_prefixes
            .iter()
            .all(|path| valid_path(path))
        && policy.forbidden_paths.iter().all(|path| valid_path(path))
}
fn valid_paths(paths: &[String]) -> bool {
    !paths.is_empty() && paths.iter().all(|path| valid_path(path))
}
fn valid_path(path: &str) -> bool {
    !path.is_empty() && !path.starts_with('/') && !path.split('/').any(|part| part == "..")
}
fn group_complete(
    observations: &[ExecutionObservation],
    repetitions: u32,
) -> Option<BTreeMap<ObservationRole, Vec<&ExecutionObservation>>> {
    let mut grouped: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for observation in observations {
        grouped
            .entry(observation.role)
            .or_default()
            .push(observation);
    }
    for role in [
        ObservationRole::BaselineVulnerable,
        ObservationRole::GoldControl,
        ObservationRole::CandidateHidden,
        ObservationRole::CandidateRegression,
    ] {
        let items = grouped.get_mut(&role)?;
        items.sort_by_key(|item| item.repetition);
        if items.len() != repetitions as usize
            || (1..=repetitions)
                .zip(items.iter())
                .any(|(expected, item)| item.repetition != expected)
        {
            return None;
        }
    }
    (grouped.len() == 4).then_some(grouped)
}
fn repeatable(items: &[&ExecutionObservation]) -> bool {
    items.windows(2).all(|pair| {
        pair[0].outcome == pair[1].outcome
            && pair[0].test_count == pair[1].test_count
            && pair[0].result_digest == pair[1].result_digest
    })
}
fn outcome(
    grouped: &BTreeMap<ObservationRole, Vec<&ExecutionObservation>>,
    role: ObservationRole,
) -> ExecutionOutcome {
    grouped[&role][0].outcome
}
fn test_count(
    grouped: &BTreeMap<ObservationRole, Vec<&ExecutionObservation>>,
    role: ObservationRole,
) -> u32 {
    grouped[&role][0].test_count
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: u32) -> ContextQualifiedId {
        ContextQualifiedId::new("observation", &format!("{value:08}")).unwrap()
    }
    fn observation(
        role: ObservationRole,
        repetition: u32,
        outcome: ExecutionOutcome,
        test_count: u32,
    ) -> ExecutionObservation {
        ExecutionObservation {
            id: id((role as u32 + 1) * 100 + repetition),
            role,
            repetition,
            outcome,
            test_count,
            result_digest: Sha256Digest::of_bytes(format!("{role:?}-{outcome:?}-{test_count}")),
            conformant: true,
        }
    }
    fn passing() -> CandidateAssessmentInput {
        let mut observations = Vec::new();
        for repetition in 1..=2 {
            observations.push(observation(
                ObservationRole::BaselineVulnerable,
                repetition,
                ExecutionOutcome::Failed,
                1,
            ));
            observations.push(observation(
                ObservationRole::GoldControl,
                repetition,
                ExecutionOutcome::Passed,
                20,
            ));
            observations.push(observation(
                ObservationRole::CandidateHidden,
                repetition,
                ExecutionOutcome::Passed,
                4,
            ));
            observations.push(observation(
                ObservationRole::CandidateRegression,
                repetition,
                ExecutionOutcome::Passed,
                20,
            ));
        }
        CandidateAssessmentInput {
            organization_id: OrganizationId::new("00000000").unwrap(),
            run_id: ContextQualifiedId::new("run", "00000001").unwrap(),
            policy: AssessmentPolicy {
                repetitions: 2,
                max_changed_lines: 100,
                allowed_path_prefixes: vec!["src/".into(), "tests/".into()],
                forbidden_paths: BTreeSet::from(["src/generated.rs".into()]),
            },
            patch: PatchObservation {
                patch_digest: Sha256Digest::of_bytes(b"patch"),
                changed_paths: vec!["src/lib.rs".into()],
                changed_lines: 8,
            },
            observations,
        }
    }
    fn assert_result(
        input: &CandidateAssessmentInput,
        verdict: AssessmentVerdict,
        reason: ReasonCode,
    ) {
        let result = CandidateAssessmentEngine::assess(input);
        assert_eq!((result.verdict, result.reason), (verdict, reason));
    }

    #[test]
    fn golden_candidate_passes_every_independent_gate() {
        assert_result(
            &passing(),
            AssessmentVerdict::VerifiedForFixture,
            ReasonCode::Verified,
        );
    }

    #[test]
    fn missing_timeout_and_unstable_evidence_are_inconclusive() {
        let mut missing = passing();
        missing.observations.pop();
        assert_result(
            &missing,
            AssessmentVerdict::Inconclusive,
            ReasonCode::MissingEvidence,
        );

        let mut timeout = passing();
        timeout.observations[2].outcome = ExecutionOutcome::TimedOut;
        assert_result(
            &timeout,
            AssessmentVerdict::Inconclusive,
            ReasonCode::ExecutionTimeout,
        );

        let mut infrastructure = passing();
        infrastructure.observations[3].outcome = ExecutionOutcome::InfrastructureFailure;
        assert_result(
            &infrastructure,
            AssessmentVerdict::Inconclusive,
            ReasonCode::InfrastructureFailure,
        );

        let mut unstable = passing();
        let item = unstable
            .observations
            .iter_mut()
            .find(|item| item.role == ObservationRole::CandidateHidden && item.repetition == 2)
            .unwrap();
        item.result_digest = Sha256Digest::of_bytes(b"flaky normalized result");
        assert_result(
            &unstable,
            AssessmentVerdict::Inconclusive,
            ReasonCode::UnstableObservation,
        );
    }

    #[test]
    fn controls_must_prove_vulnerable_baseline_and_valid_gold() {
        let mut baseline = passing();
        for item in baseline
            .observations
            .iter_mut()
            .filter(|item| item.role == ObservationRole::BaselineVulnerable)
        {
            item.outcome = ExecutionOutcome::Passed;
            item.result_digest = Sha256Digest::of_bytes(b"baseline-pass");
        }
        assert_result(
            &baseline,
            AssessmentVerdict::Inconclusive,
            ReasonCode::BaselineNotVulnerable,
        );
        let mut gold = passing();
        for item in gold
            .observations
            .iter_mut()
            .filter(|item| item.role == ObservationRole::GoldControl)
        {
            item.outcome = ExecutionOutcome::Failed;
            item.result_digest = Sha256Digest::of_bytes(b"gold-fail");
        }
        assert_result(
            &gold,
            AssessmentVerdict::Inconclusive,
            ReasonCode::GoldControlFailed,
        );
    }

    #[test]
    fn patch_scope_budget_hidden_and_regression_failures_reject() {
        let mut forbidden = passing();
        forbidden.patch.changed_paths = vec!["src/generated.rs".into()];
        assert_result(
            &forbidden,
            AssessmentVerdict::Rejected,
            ReasonCode::PatchScopeViolation,
        );
        let mut outside = passing();
        outside.patch.changed_paths = vec!["Cargo.toml".into()];
        assert_result(
            &outside,
            AssessmentVerdict::Rejected,
            ReasonCode::PatchScopeViolation,
        );
        let mut budget = passing();
        budget.patch.changed_lines = 101;
        assert_result(
            &budget,
            AssessmentVerdict::Rejected,
            ReasonCode::PatchBudgetExceeded,
        );
        let mut hidden = passing();
        for item in hidden
            .observations
            .iter_mut()
            .filter(|item| item.role == ObservationRole::CandidateHidden)
        {
            item.outcome = ExecutionOutcome::Failed;
            item.result_digest = Sha256Digest::of_bytes(b"hidden-fail");
        }
        assert_result(
            &hidden,
            AssessmentVerdict::Rejected,
            ReasonCode::CandidateHiddenFailed,
        );
        let mut regression = passing();
        for item in regression
            .observations
            .iter_mut()
            .filter(|item| item.role == ObservationRole::CandidateRegression)
        {
            item.outcome = ExecutionOutcome::Failed;
            item.result_digest = Sha256Digest::of_bytes(b"regression-fail");
        }
        assert_result(
            &regression,
            AssessmentVerdict::Rejected,
            ReasonCode::RegressionFailed,
        );
    }

    #[test]
    fn test_inventory_loss_rejects_and_nonconformance_dominates() {
        let mut inventory = passing();
        for item in inventory
            .observations
            .iter_mut()
            .filter(|item| item.role == ObservationRole::CandidateRegression)
        {
            item.test_count = 19;
            item.result_digest = Sha256Digest::of_bytes(b"nineteen-tests");
        }
        assert_result(
            &inventory,
            AssessmentVerdict::Rejected,
            ReasonCode::RegressionInventoryLoss,
        );
        inventory.observations[0].conformant = false;
        assert_result(
            &inventory,
            AssessmentVerdict::NonConformant,
            ReasonCode::InformationFlowViolation,
        );
    }

    #[test]
    fn replay_is_deterministic_for_every_observation_order() {
        let original = passing();
        let expected = CandidateAssessmentEngine::assess(&original);
        for rotation in 0..original.observations.len() {
            let mut permuted = original.clone();
            permuted.observations.rotate_left(rotation);
            permuted.patch.changed_paths.reverse();
            permuted.policy.allowed_path_prefixes.reverse();
            assert_eq!(CandidateAssessmentEngine::assess(&permuted), expected);
        }
    }
}
