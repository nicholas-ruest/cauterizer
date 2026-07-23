//! Patch Proposals owns the deliberately one-way solver boundary.
#![forbid(unsafe_code)]

use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Domain model and policies.
pub mod domain {
    #![allow(clippy::missing_errors_doc, clippy::wildcard_imports)]
    use super::*;

    /// Hard limits applied before invoking an untrusted solver.
    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ProposalBudget {
        /// Maximum solver attempts.
        pub attempts: u16,
        /// Maximum provider tokens.
        pub tokens: u64,
        /// Maximum cost in millionths of the configured currency.
        pub cost_micros: u64,
        /// Maximum elapsed milliseconds.
        pub time_millis: u64,
        /// Maximum changed paths.
        pub paths: u32,
        /// Maximum canonical patch bytes.
        pub patch_bytes: u64,
        /// Maximum changed lines.
        pub changed_lines: u64,
    }

    impl ProposalBudget {
        /// Rejects absent or unreasonable limits.
        pub fn validate(&self) -> Result<(), ProposalError> {
            if self.attempts == 0
                || self.tokens == 0
                || self.time_millis == 0
                || self.paths == 0
                || self.patch_bytes == 0
                || self.changed_lines == 0
            {
                Err(ProposalError::InvalidBudget)
            } else {
                Ok(())
            }
        }
    }

    /// Approved, immutable solver input. No verifier result can be represented.
    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SolverBrief {
        /// Tenant partition.
        pub organization_id: OrganizationId,
        /// Owning remediation run.
        pub run_id: ContextQualifiedId,
        /// Public problem statement.
        pub problem: String,
        /// Public source bundle.
        pub source_digest: Sha256Digest,
        /// Public test instructions.
        pub public_test_instructions: Vec<String>,
        /// Relative paths the solver may modify.
        pub allowed_paths: BTreeSet<String>,
        /// Exact tools the solver may use.
        pub allowed_tools: BTreeSet<String>,
        /// Attempt limits.
        pub budget: ProposalBudget,
        /// Explicitly empty for conformant work.
        pub memory_namespace: Option<String>,
    }

    impl SolverBrief {
        /// Applies public-view, size, path, and memory isolation rules.
        pub fn validate(&self) -> Result<(), ProposalError> {
            self.budget.validate()?;
            if self.problem.trim().is_empty()
                || self.problem.len() > 32 * 1024
                || self.public_test_instructions.len() > 64
                || self.allowed_paths.is_empty()
                || self.allowed_tools.is_empty()
                || self.memory_namespace.is_some()
            {
                return Err(ProposalError::InvalidBrief);
            }
            for value in self
                .public_test_instructions
                .iter()
                .chain(self.allowed_paths.iter())
                .chain(self.allowed_tools.iter())
            {
                if value.is_empty() || value.len() > 1024 || has_control(value) {
                    return Err(ProposalError::InvalidBrief);
                }
            }
            for path in &self.allowed_paths {
                validate_path(path)?;
            }
            Ok(())
        }

        /// Stable digest of the approved solver view.
        #[must_use]
        pub fn digest(&self) -> Sha256Digest {
            let bytes = serde_json::to_vec(self).unwrap_or_default();
            Sha256Digest::of_bytes(bytes)
        }
    }

    /// Metering asserted by the solver adapter and checked independently.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct SolverUsage {
        /// Provider tokens.
        pub tokens: u64,
        /// Cost in millionths.
        pub cost_micros: u64,
        /// Elapsed milliseconds.
        pub time_millis: u64,
    }

    /// Bounded solver output. Rationale is provenance, never hidden reasoning.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct SolverOutput {
        /// Text unified diff.
        pub patch: Vec<u8>,
        /// Short, user-authored provenance note.
        pub rationale: Option<String>,
        /// Metered resource use.
        pub usage: SolverUsage,
        /// Adapter identity/configuration digest.
        pub solver_provenance: Sha256Digest,
    }

    /// Canonical immutable patch.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct UnifiedPatch {
        bytes: Vec<u8>,
        paths: BTreeSet<String>,
        changed_lines: u64,
        digest: Sha256Digest,
    }

    impl UnifiedPatch {
        /// Canonical bytes.
        #[must_use]
        pub fn as_bytes(&self) -> &[u8] {
            &self.bytes
        }
        /// Changed paths.
        #[must_use]
        pub fn paths(&self) -> &BTreeSet<String> {
            &self.paths
        }
        /// Content digest.
        #[must_use]
        pub const fn digest(&self) -> Sha256Digest {
            self.digest
        }
    }

    /// Defensive unified-diff parser and canonicalizer.
    pub struct PatchNormalizationService;

    impl PatchNormalizationService {
        /// Parses a bounded textual patch and validates every target path.
        pub fn normalize(bytes: &[u8], brief: &SolverBrief) -> Result<UnifiedPatch, ProposalError> {
            if bytes.is_empty() || bytes.len() as u64 > brief.budget.patch_bytes {
                return Err(ProposalError::PatchSizeExceeded);
            }
            let text = std::str::from_utf8(bytes).map_err(|_| ProposalError::BinaryPatch)?;
            if has_control(text)
                || text.contains("GIT binary patch")
                || text.contains("Binary files ")
            {
                return Err(ProposalError::BinaryPatch);
            }
            let canonical = text.replace("\r\n", "\n");
            let canonical = canonical.trim_end_matches('\n').to_owned() + "\n";
            let lines: Vec<_> = canonical.lines().collect();
            let mut paths = BTreeSet::new();
            let mut changed = 0_u64;
            let mut saw_hunk = false;
            let mut index = 0;
            while index < lines.len() {
                if let Some(old) = lines[index].strip_prefix("--- ") {
                    let new_line = lines.get(index + 1).ok_or(ProposalError::MalformedPatch)?;
                    let new = new_line
                        .strip_prefix("+++ ")
                        .ok_or(ProposalError::MalformedPatch)?;
                    let old = strip_prefix(old);
                    let new = strip_prefix(new);
                    if old != "/dev/null" {
                        validate_path(old)?;
                    }
                    if new == "/dev/null" {
                        return Err(ProposalError::ForbiddenPath);
                    }
                    validate_path(new)?;
                    if !brief.allowed_paths.contains(new) || !paths.insert(new.to_owned()) {
                        return Err(ProposalError::ForbiddenPath);
                    }
                    index += 2;
                    continue;
                }
                if lines[index].starts_with("@@ ") {
                    saw_hunk = true;
                } else if saw_hunk
                    && (lines[index].starts_with('+') || lines[index].starts_with('-'))
                    && !lines[index].starts_with("+++")
                    && !lines[index].starts_with("---")
                {
                    changed = changed.saturating_add(1);
                } else if !saw_hunk
                    && !lines[index].starts_with("diff --git ")
                    && !lines[index].starts_with("index ")
                {
                    return Err(ProposalError::MalformedPatch);
                }
                index += 1;
            }
            if paths.is_empty() || !saw_hunk {
                return Err(ProposalError::MalformedPatch);
            }
            if paths.len() > brief.budget.paths as usize || changed > brief.budget.changed_lines {
                return Err(ProposalError::PatchBudgetExceeded);
            }
            let digest = Sha256Digest::of_bytes(canonical.as_bytes());
            Ok(UnifiedPatch {
                bytes: canonical.into_bytes(),
                paths,
                changed_lines: changed,
                digest,
            })
        }
    }

    /// Immutable candidate descriptor published one way to verification.
    #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct CandidatePatchRef {
        /// Candidate identifier.
        pub candidate_id: ContextQualifiedId,
        /// Canonical patch digest.
        pub patch_digest: Sha256Digest,
        /// Approved brief digest.
        pub brief_digest: Sha256Digest,
        /// Solver/configuration provenance.
        pub solver_provenance: Sha256Digest,
        /// Bounded rationale provenance.
        pub rationale: Option<String>,
    }

    /// Attempt lifecycle.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum AttemptState {
        /// Solver may be invoked.
        Open,
        /// Exactly one candidate exists.
        Proposed(CandidatePatchRef),
        /// Terminal stable failure.
        Failed(ProposalError),
        /// Explicit abort.
        Aborted,
    }

    /// Aggregate enforcing exactly one terminal result.
    #[derive(Clone, Debug)]
    pub struct ProposalAttempt {
        /// Aggregate ID.
        pub id: ContextQualifiedId,
        /// Immutable brief.
        pub brief: SolverBrief,
        /// Current lifecycle.
        pub state: AttemptState,
        /// Optimistic version.
        pub version: u64,
    }

    impl ProposalAttempt {
        /// Opens an attempt after admission.
        pub fn open(id: ContextQualifiedId, brief: SolverBrief) -> Result<Self, ProposalError> {
            brief.validate()?;
            Ok(Self {
                id,
                brief,
                state: AttemptState::Open,
                version: 0,
            })
        }

        /// Accepts at most one candidate.
        pub fn accept(
            &mut self,
            output: SolverOutput,
            candidate_id: ContextQualifiedId,
        ) -> Result<(UnifiedPatch, CandidatePatchRef), ProposalError> {
            if self.state != AttemptState::Open {
                return Err(ProposalError::AttemptTerminal);
            }
            enforce_usage(output.usage, &self.brief.budget)?;
            let rationale = output.rationale.map(|value| {
                let trimmed: String = value.chars().take(2_048).collect();
                trimmed
            });
            if rationale
                .as_deref()
                .is_some_and(|value| has_control(value) || verdict_claim(value))
            {
                return Err(ProposalError::ForbiddenProvenance);
            }
            let patch = PatchNormalizationService::normalize(&output.patch, &self.brief)?;
            let candidate = CandidatePatchRef {
                candidate_id,
                patch_digest: patch.digest,
                brief_digest: self.brief.digest(),
                solver_provenance: output.solver_provenance,
                rationale,
            };
            self.state = AttemptState::Proposed(candidate.clone());
            self.version += 1;
            Ok((patch, candidate))
        }

        /// Records a stable provider failure.
        pub fn provider_failed(&mut self) -> Result<(), ProposalError> {
            if self.state != AttemptState::Open {
                return Err(ProposalError::AttemptTerminal);
            }
            self.state = AttemptState::Failed(ProposalError::ProviderUnavailable);
            self.version += 1;
            Ok(())
        }
    }

    fn enforce_usage(usage: SolverUsage, budget: &ProposalBudget) -> Result<(), ProposalError> {
        if usage.tokens > budget.tokens
            || usage.cost_micros > budget.cost_micros
            || usage.time_millis > budget.time_millis
        {
            Err(ProposalError::BudgetExceeded)
        } else {
            Ok(())
        }
    }

    fn strip_prefix(value: &str) -> &str {
        value
            .split_whitespace()
            .next()
            .unwrap_or(value)
            .strip_prefix("a/")
            .or_else(|| {
                value
                    .split_whitespace()
                    .next()
                    .unwrap_or(value)
                    .strip_prefix("b/")
            })
            .unwrap_or_else(|| value.split_whitespace().next().unwrap_or(value))
    }

    fn validate_path(path: &str) -> Result<(), ProposalError> {
        if path.is_empty()
            || path.starts_with('/')
            || path.starts_with('\\')
            || path.contains('\\')
            || path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || path.contains(':')
            || has_control(path)
        {
            Err(ProposalError::ForbiddenPath)
        } else {
            Ok(())
        }
    }

    fn has_control(value: &str) -> bool {
        value.chars().any(|character| {
            character.is_control() && character != '\n' && character != '\r' && character != '\t'
        })
    }

    fn verdict_claim(value: &str) -> bool {
        let lower = value.to_ascii_lowercase();
        [
            "verified",
            "safe",
            "fixed",
            "ready to deploy",
            "hidden test",
        ]
        .iter()
        .any(|term| lower.contains(term))
    }

    /// Stable failure language without provider or verifier internals.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
    #[serde(rename_all = "snake_case")]
    pub enum ProposalError {
        /// Invalid limit envelope.
        InvalidBudget,
        /// Public view is malformed or contaminated.
        InvalidBrief,
        /// Patch is malformed.
        MalformedPatch,
        /// Binary/control content is forbidden.
        BinaryPatch,
        /// A path is outside the approved scope.
        ForbiddenPath,
        /// Byte limit exceeded.
        PatchSizeExceeded,
        /// Path or line budget exceeded.
        PatchBudgetExceeded,
        /// Solver metering exceeded.
        BudgetExceeded,
        /// Rationale attempted to claim a verdict or hidden knowledge.
        ForbiddenProvenance,
        /// Attempt already has a terminal result.
        AttemptTerminal,
        /// Replaceable solver could not produce output.
        ProviderUnavailable,
        /// Tenant authorization failed.
        Unauthorized,
        /// Idempotency key was reused with different input.
        IdempotencyConflict,
        /// Optimistic aggregate version changed.
        ConcurrencyConflict,
    }

    impl fmt::Display for ProposalError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "{self:?}")
        }
    }
    impl std::error::Error for ProposalError {}
}

/// Application use cases and owned ports.
pub mod application;

/// Versioned published language.
pub mod contracts;

/// Stable bounded-context name.
pub const CONTEXT_NAME: &str = "patch-proposals";

#[cfg(test)]
mod tests {
    use super::application::*;
    use super::domain::*;
    use super::*;
    use proptest::prelude::*;

    fn brief() -> SolverBrief {
        SolverBrief {
            organization_id: "org_abcdefgh".parse().unwrap(),
            run_id: ContextQualifiedId::new("run", "abcdefgh").unwrap(),
            problem: "repair public behavior".into(),
            source_digest: Sha256Digest::of_bytes("source"),
            public_test_instructions: vec!["cargo test --public".into()],
            allowed_paths: BTreeSet::from(["src/lib.rs".into()]),
            allowed_tools: BTreeSet::from(["apply_patch".into()]),
            budget: ProposalBudget {
                attempts: 1,
                tokens: 100,
                cost_micros: 20,
                time_millis: 1000,
                paths: 1,
                patch_bytes: 1024,
                changed_lines: 4,
            },
            memory_namespace: None,
        }
    }
    fn patch() -> Vec<u8> {
        b"--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-old\n+new\n".to_vec()
    }
    fn output() -> SolverOutput {
        SolverOutput {
            patch: patch(),
            rationale: Some("bounded provenance".into()),
            usage: SolverUsage {
                tokens: 10,
                cost_micros: 2,
                time_millis: 10,
            },
            solver_provenance: Sha256Digest::of_bytes("mock-v1"),
        }
    }

    #[test]
    fn manual_and_mock_are_deterministic() {
        let brief = brief();
        let mut manual = ManualSolver::new(output());
        assert_eq!(manual.solve(&brief).unwrap().patch, patch());
        assert_eq!(
            manual.solve(&brief),
            Err(ProposalError::ProviderUnavailable)
        );
        let mut mock = DeterministicMockSolver::new(patch(), Sha256Digest::of_bytes("mock-v1"));
        assert_eq!(
            mock.solve(&brief).unwrap().patch,
            mock.solve(&brief).unwrap().patch
        );
    }

    #[test]
    fn one_attempt_yields_at_most_one_candidate() {
        let mut attempt = ProposalAttempt::open(
            ContextQualifiedId::new("proposal", "abcdefgh").unwrap(),
            brief(),
        )
        .unwrap();
        attempt
            .accept(
                output(),
                ContextQualifiedId::new("candidate", "abcdefgh").unwrap(),
            )
            .unwrap();
        assert_eq!(
            attempt.accept(
                output(),
                ContextQualifiedId::new("candidate", "ijklmnop").unwrap()
            ),
            Err(ProposalError::AttemptTerminal)
        );
    }

    #[test]
    fn rejects_binary_traversal_forbidden_and_malformed_patches() {
        let brief = brief();
        for (bytes, expected) in [
            (b"GIT binary patch\n".as_slice(), ProposalError::BinaryPatch),
            (
                b"--- a/../secret\n+++ b/../secret\n@@ -1 +1 @@\n-a\n+b\n".as_slice(),
                ProposalError::ForbiddenPath,
            ),
            (
                b"--- a/other\n+++ b/other\n@@ -1 +1 @@\n-a\n+b\n".as_slice(),
                ProposalError::ForbiddenPath,
            ),
            (b"hello\n".as_slice(), ProposalError::MalformedPatch),
        ] {
            assert_eq!(
                PatchNormalizationService::normalize(bytes, &brief),
                Err(expected)
            );
        }
    }

    #[test]
    fn rejects_budget_races_and_provider_failure_is_terminal() {
        let mut attempt = ProposalAttempt::open(
            ContextQualifiedId::new("proposal", "abcdefgh").unwrap(),
            brief(),
        )
        .unwrap();
        let mut oversized = output();
        oversized.usage.tokens = 101;
        assert_eq!(
            attempt.accept(
                oversized,
                ContextQualifiedId::new("candidate", "abcdefgh").unwrap()
            ),
            Err(ProposalError::BudgetExceeded)
        );
        attempt.provider_failed().unwrap();
        assert_eq!(
            attempt.provider_failed(),
            Err(ProposalError::AttemptTerminal)
        );
    }

    #[test]
    fn rejects_memory_contamination_and_verdict_claims() {
        let mut contaminated = brief();
        contaminated.memory_namespace = Some("shared-verifier-memory".into());
        assert_eq!(contaminated.validate(), Err(ProposalError::InvalidBrief));
        let mut attempt = ProposalAttempt::open(
            ContextQualifiedId::new("proposal", "abcdefgh").unwrap(),
            brief(),
        )
        .unwrap();
        let mut claiming = output();
        claiming.rationale = Some("verified safe by hidden tests".into());
        assert_eq!(
            attempt.accept(
                claiming,
                ContextQualifiedId::new("candidate", "abcdefgh").unwrap()
            ),
            Err(ProposalError::ForbiddenProvenance)
        );
    }

    #[test]
    fn facade_is_tenant_scoped_idempotent_and_queues_facts_atomically() {
        let tenant: OrganizationId = "org_abcdefgh".parse().unwrap();
        let context = CommandContext {
            organization_id: tenant.clone(),
            may_propose: true,
        };
        let attempt_id = ContextQualifiedId::new("proposal", "abcdefgh").unwrap();
        let mut service = ProposalService::new(MemoryProposalRepository::default());
        let opened = service
            .open(&context, "open-key", attempt_id.clone(), brief())
            .unwrap();
        assert_eq!(
            service
                .open(&context, "open-key", attempt_id.clone(), brief())
                .unwrap(),
            opened
        );
        let mut changed = brief();
        changed.problem = "different request".into();
        assert_eq!(
            service.open(&context, "open-key", attempt_id.clone(), changed),
            Err(ProposalError::IdempotencyConflict)
        );
        let mut solver = DeterministicMockSolver::new(patch(), Sha256Digest::of_bytes("mock-v1"));
        service
            .propose(
                &context,
                "propose-key",
                &attempt_id,
                ContextQualifiedId::new("candidate", "abcdefgh").unwrap(),
                &mut solver,
            )
            .unwrap();
        let repository = service.into_repository();
        assert_eq!(repository.outbox.len(), 2);
    }

    #[test]
    fn facade_denies_cross_tenant_and_unprivileged_callers() {
        let mut service = ProposalService::new(MemoryProposalRepository::default());
        for context in [
            CommandContext {
                organization_id: "org_ijklmnop".parse().unwrap(),
                may_propose: true,
            },
            CommandContext {
                organization_id: "org_abcdefgh".parse().unwrap(),
                may_propose: false,
            },
        ] {
            assert_eq!(
                service.open(
                    &context,
                    "key",
                    ContextQualifiedId::new("proposal", "abcdefgh").unwrap(),
                    brief()
                ),
                Err(ProposalError::Unauthorized)
            );
        }
    }

    #[test]
    fn projection_rebuild_is_replay_safe_and_payload_free() {
        let attempt = ContextQualifiedId::new("proposal", "abcdefgh").unwrap();
        let candidate = CandidatePatchRef {
            candidate_id: attempt.clone(),
            patch_digest: Sha256Digest::of_bytes("patch"),
            brief_digest: Sha256Digest::of_bytes("brief"),
            solver_provenance: Sha256Digest::of_bytes("solver"),
            rationale: None,
        };
        let facts = [
            ProposalFact::Opened {
                attempt_id: attempt.clone(),
            },
            ProposalFact::Opened {
                attempt_id: attempt.clone(),
            },
            ProposalFact::Proposed {
                attempt_id: attempt.clone(),
                candidate: candidate.clone(),
            },
            ProposalFact::Proposed {
                attempt_id: attempt.clone(),
                candidate,
            },
        ];
        let mut projection = AttemptProjection::default();
        for fact in &facts {
            projection.apply(fact);
        }
        let summary = projection.get(&attempt).unwrap();
        assert_eq!(summary.status, "proposed");
        assert_eq!(
            summary.candidate_digest,
            Some(Sha256Digest::of_bytes("patch"))
        );
    }

    #[test]
    fn manifest_has_no_verifier_or_orchestration_dependency() {
        let manifest = include_str!("../Cargo.toml").to_ascii_lowercase();
        for forbidden in [
            "cauterizer-verification",
            "opentelemetry",
            "tracing-subscriber",
        ] {
            assert!(
                !manifest.contains(forbidden),
                "forbidden dependency/channel: {forbidden}"
            );
        }
    }

    proptest! {
        #[test]
        fn arbitrary_non_diff_never_panics_or_becomes_candidate(data in prop::collection::vec(any::<u8>(), 0..2048)) {
            let result = PatchNormalizationService::normalize(&data, &brief());
            if let Ok(value) = result {
                prop_assert!(value.as_bytes().starts_with(b"--- ") || value.as_bytes().starts_with(b"diff --git "));
                prop_assert!(value.paths().iter().all(|path| path == "src/lib.rs"));
            }
        }
    }
}
