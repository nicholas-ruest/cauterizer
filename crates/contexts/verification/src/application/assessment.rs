//! Application adapter that keeps verifier evidence and reasons behind the boundary.

use cauterizer_syntax::digest::Sha256Digest;

use crate::domain::assessment::{
    AssessmentVerdict, CandidateAssessment, CandidateAssessmentEngine, CandidateAssessmentInput,
};

/// Verifier-owned immutable input lookup.
pub trait AssessmentInputRepository {
    /// Loads the exact sealed observations for a candidate digest.
    ///
    /// # Errors
    /// Reports verifier storage failure without exposing hidden content.
    fn load(
        &self,
        candidate: Sha256Digest,
    ) -> Result<Option<CandidateAssessmentInput>, AssessmentAdapterError>;
}

/// Append-only assessment persistence.
pub trait AssessmentRecorder {
    /// Records the complete verifier-held result idempotently by assessment digest.
    ///
    /// # Errors
    /// Reports verifier storage failure without exposing hidden content.
    fn record(&self, assessment: &CandidateAssessment) -> Result<(), AssessmentAdapterError>;
}

/// Hidden-verification adapter. Its public return type has no reason or diagnostic field.
pub struct HiddenAssessmentAdapter<R, W> {
    repository: R,
    recorder: W,
}

impl<R: AssessmentInputRepository, W: AssessmentRecorder> HiddenAssessmentAdapter<R, W> {
    /// Constructs the verifier-side adapter.
    #[must_use]
    pub const fn new(repository: R, recorder: W) -> Self {
        Self {
            repository,
            recorder,
        }
    }

    /// Runs deterministic verification and exposes only its narrow verdict.
    ///
    /// # Errors
    /// Fails closed when sealed evidence is unavailable or the assessment cannot be recorded.
    pub fn verify(
        &self,
        candidate: Sha256Digest,
    ) -> Result<AssessmentVerdict, AssessmentAdapterError> {
        let input = self
            .repository
            .load(candidate)?
            .ok_or(AssessmentAdapterError::EvidenceUnavailable)?;
        if input.patch.patch_digest != candidate {
            return Err(AssessmentAdapterError::EvidenceMismatch);
        }
        let assessment = CandidateAssessmentEngine::assess(&input);
        self.recorder.record(&assessment)?;
        Ok(assessment.verdict)
    }
}

/// Stable boundary failure without hidden details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssessmentAdapterError {
    /// Sealed observations are not available.
    EvidenceUnavailable,
    /// Loaded evidence belongs to another candidate.
    EvidenceMismatch,
    /// Verifier storage is unavailable.
    StorageUnavailable,
}

impl std::fmt::Display for AssessmentAdapterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("hidden assessment unavailable")
    }
}
impl std::error::Error for AssessmentAdapterError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeSet;

    use crate::domain::assessment::{
        AssessmentPolicy, ExecutionObservation, ExecutionOutcome, ObservationRole, PatchObservation,
    };
    use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};

    struct Repository(Option<CandidateAssessmentInput>);
    impl AssessmentInputRepository for Repository {
        fn load(
            &self,
            _: Sha256Digest,
        ) -> Result<Option<CandidateAssessmentInput>, AssessmentAdapterError> {
            Ok(self.0.clone())
        }
    }
    #[derive(Default)]
    struct Recorder(RefCell<Vec<CandidateAssessment>>);
    impl AssessmentRecorder for Recorder {
        fn record(&self, assessment: &CandidateAssessment) -> Result<(), AssessmentAdapterError> {
            self.0.borrow_mut().push(assessment.clone());
            Ok(())
        }
    }
    fn input(candidate: Sha256Digest) -> CandidateAssessmentInput {
        let roles = [
            (
                ObservationRole::BaselineVulnerable,
                ExecutionOutcome::Failed,
            ),
            (ObservationRole::GoldControl, ExecutionOutcome::Passed),
            (ObservationRole::CandidateHidden, ExecutionOutcome::Passed),
            (
                ObservationRole::CandidateRegression,
                ExecutionOutcome::Passed,
            ),
        ];
        CandidateAssessmentInput {
            organization_id: OrganizationId::new("00000000").unwrap(),
            run_id: ContextQualifiedId::new("run", "00000001").unwrap(),
            policy: AssessmentPolicy {
                repetitions: 1,
                max_changed_lines: 10,
                allowed_path_prefixes: vec!["src/".into()],
                forbidden_paths: BTreeSet::new(),
            },
            patch: PatchObservation {
                patch_digest: candidate,
                changed_paths: vec!["src/lib.rs".into()],
                changed_lines: 1,
            },
            observations: roles
                .into_iter()
                .enumerate()
                .map(|(index, (role, outcome))| ExecutionObservation {
                    id: ContextQualifiedId::new("observation", &format!("{:08}", index + 1))
                        .unwrap(),
                    role,
                    repetition: 1,
                    outcome,
                    test_count: 1,
                    result_digest: Sha256Digest::of_bytes(format!("{role:?}-{outcome:?}")),
                    conformant: true,
                })
                .collect(),
        }
    }

    #[test]
    fn adapter_returns_only_verdict_and_records_private_assessment() {
        let candidate = Sha256Digest::of_bytes(b"candidate");
        let recorder = Recorder::default();
        let adapter = HiddenAssessmentAdapter::new(Repository(Some(input(candidate))), recorder);
        assert_eq!(
            adapter.verify(candidate),
            Ok(AssessmentVerdict::VerifiedForFixture)
        );
        assert_eq!(adapter.recorder.0.borrow().len(), 1);
    }

    #[test]
    fn candidate_substitution_fails_before_assessment_recording() {
        let candidate = Sha256Digest::of_bytes(b"candidate");
        let adapter = HiddenAssessmentAdapter::new(
            Repository(Some(input(Sha256Digest::of_bytes(b"other")))),
            Recorder::default(),
        );
        assert_eq!(
            adapter.verify(candidate),
            Err(AssessmentAdapterError::EvidenceMismatch)
        );
        assert!(adapter.recorder.0.borrow().is_empty());
    }
}
