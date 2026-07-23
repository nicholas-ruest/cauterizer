//! Anti-corruption adapter for the one P00-selected CVE-Bench record.

use crate::domain::qualification::{
    Control, PublicFixtureDescriptor, QualificationError, QualificationPlan, QualificationRequest,
};
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
use cauterizer_syntax::time::UtcInstant;

/// Exact public P00 fixture identifier.
pub const ADVISORY_ID: &str = "CVE-2022-29217";
/// Exact CVE-Bench repository commit selected by P00.
pub const BENCHMARK_COMMIT: &str = "47abc2b2b522f4d8afd07296d2a35042d8639f1d";
/// Exact vulnerable `PyJWT` revision selected by P00.
pub const VULNERABLE_REVISION: &str = "24b29adfebcb4f057a3cef5aaf35653bc0c1c8cc";
/// Exact upstream fix revision carried as the hidden gold control.
pub const FIX_REVISION: &str = "9c528670c455b8d948aff95ed50e22940d1ad3fc";
/// Immutable benchmark origin.
pub const BENCHMARK_REPOSITORY: &str = "https://github.com/ruvnet/CVE-bench.git";
/// Immutable target origin.
pub const TARGET_REPOSITORY: &str = "https://github.com/jpadilla/pyjwt.git";
/// SHA-256 of `git archive` for the selected benchmark commit.
pub const BENCHMARK_ARCHIVE_SHA256: &str =
    "sha256:d1c77dd3083b8af9dabb479797f5df27895361e1f0564048589ee8c2dccab00d";
/// SHA-256 of `git archive` for the vulnerable target commit.
pub const TARGET_ARCHIVE_SHA256: &str =
    "sha256:3bd310cc86de449e4b55b861993d69fb815a042107b83addc21194ea1a750b10";
/// SHA-256 of the compact selected dataset record, including its hidden patches.
pub const DATASET_RECORD_SHA256: &str =
    "sha256:970c05dd1ca3a1e317989a1a5ab14acb66515e5c0d6e4c43f7926107856fb816";
/// SHA-256 of the benchmark MIT license notice.
pub const BENCHMARK_LICENSE_SHA256: &str =
    "sha256:631f94984f626818d42ecf717aa6e8e0afd4f9f355ca706bd2effafbd1416d06";
/// SHA-256 of the target MIT license notice at the vulnerable revision.
pub const TARGET_LICENSE_SHA256: &str =
    "sha256:797a7a20231d4c433e9f1911db1731d06b5828b98f499819a034f7c0f56f5ce5";
/// Fixed policy recording the ten-fresh-job rule.
pub const POLICY_VERSION: &str = "fixture-qualification-v1-10x";

/// Independently reproducible upstream evidence, separate from qualification outcomes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedUpstreamProvenance {
    /// Benchmark archive bytes.
    pub benchmark_archive: Sha256Digest,
    /// Vulnerable target archive bytes.
    pub target_archive: Sha256Digest,
    /// Selected compact dataset record.
    pub dataset_record: Sha256Digest,
    /// Benchmark license/notice.
    pub benchmark_license: Sha256Digest,
    /// Target license/notice.
    pub target_license: Sha256Digest,
}

impl VerifiedUpstreamProvenance {
    /// Parses the checked-in, independently measured P00 pins.
    ///
    /// # Panics
    /// Panics only if a developer corrupts a checked-in digest constant.
    #[must_use]
    pub fn pinned() -> Self {
        Self {
            benchmark_archive: BENCHMARK_ARCHIVE_SHA256.parse().expect("checked-in digest"),
            target_archive: TARGET_ARCHIVE_SHA256.parse().expect("checked-in digest"),
            dataset_record: DATASET_RECORD_SHA256.parse().expect("checked-in digest"),
            benchmark_license: BENCHMARK_LICENSE_SHA256.parse().expect("checked-in digest"),
            target_license: TARGET_LICENSE_SHA256.parse().expect("checked-in digest"),
        }
    }

    /// Fails closed if acquired bytes do not match every independently pinned object.
    #[must_use]
    pub fn matches_pins(&self) -> bool {
        self == &Self::pinned()
    }
}

/// Results of executing real controls locally without widening them into qualification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalFixtureExercise {
    /// One fresh authenticated observation for each control.
    pub observations: Vec<(
        Control,
        crate::domain::qualification::QualificationObservation,
    )>,
    /// Immutable source/environment inputs used by all jobs.
    pub public_bundle: SolverPublicBundle,
    /// Always false: rootless local execution is evidence, not conformant qualification.
    pub conformant: bool,
}

/// Solver-public immutable bundle references.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SolverPublicBundle {
    /// Vulnerable source bundle.
    pub source: Sha256Digest,
    /// Build environment bundle.
    pub environment: Sha256Digest,
    /// Acquisition integrity/SBOM/license manifest.
    pub acquisition_manifest: Sha256Digest,
}

/// Verifier-hidden immutable bundle references. This type is never serialized publicly.
#[derive(Clone, Debug)]
pub struct VerifierHiddenBundle {
    /// Hidden security test bundle.
    pub security_test: Sha256Digest,
    /// No-op control patch.
    pub no_op_patch: Sha256Digest,
    /// Bad control patch.
    pub bad_patch: Sha256Digest,
    /// Gold control patch.
    pub gold_patch: Sha256Digest,
    /// Digest of normalized argv and hidden suite policy.
    pub command_manifest: Sha256Digest,
}

/// Pinned fixture plan held exclusively by the verifier adapter.
pub struct PinnedFixturePlan {
    organization_id: OrganizationId,
    public: SolverPublicBundle,
    hidden: VerifierHiddenBundle,
    image_digest: Sha256Digest,
    sandbox_profile: String,
    expires_at: UtcInstant,
    qualification_run_nonce: String,
}

impl PinnedFixturePlan {
    /// Constructs the exact fixture plan from separately loaded stores.
    #[must_use]
    pub fn new(
        organization_id: OrganizationId,
        public: SolverPublicBundle,
        hidden: VerifierHiddenBundle,
        image_digest: Sha256Digest,
        sandbox_profile: impl Into<String>,
        expires_at: UtcInstant,
        qualification_run_nonce: impl Into<String>,
    ) -> Self {
        Self {
            organization_id,
            public,
            hidden,
            image_digest,
            sandbox_profile: sandbox_profile.into(),
            expires_at,
            qualification_run_nonce: qualification_run_nonce.into(),
        }
    }

    fn patch(&self, control: Control) -> Option<Sha256Digest> {
        match control {
            Control::VulnerableBase => None,
            Control::NoOp => Some(self.hidden.no_op_patch),
            Control::Bad => Some(self.hidden.bad_patch),
            Control::Gold => Some(self.hidden.gold_patch),
        }
    }

    /// Exercises the real base/no-op/bad/gold controls through the Rust-owned
    /// qualification execution port. This deliberately cannot publish a qualified
    /// descriptor because the selected local backend is non-conformant.
    ///
    /// # Errors
    /// Fails on a forged receipt, missing cleanup, unexpected outcome, networked
    /// request, reused worker identity, or any local receipt claiming conformance.
    pub fn exercise_nonconformant_local<R>(
        &self,
        runner: &mut R,
    ) -> Result<LocalFixtureExercise, QualificationError>
    where
        R: crate::domain::qualification::QualificationRunner,
    {
        use crate::domain::qualification::TestOutcome;
        let mut observations = Vec::with_capacity(4);
        let mut workers = std::collections::BTreeSet::new();
        for control in [
            Control::VulnerableBase,
            Control::NoOp,
            Control::Bad,
            Control::Gold,
        ] {
            let request = self.request(control, 0)?;
            if !request.egress_denied || !workers.insert(request.worker_identity.clone()) {
                return Err(QualificationError::InvalidExecutionRequest);
            }
            let observation = runner.execute(&request, control)?;
            let expected = if control == Control::Gold {
                TestOutcome::Pass
            } else {
                TestOutcome::Fail
            };
            if observation.outcome != expected
                || observation.request_digest != request.canonical_digest()
                || observation.organization_id != request.organization_id
                || observation.worker_identity != request.worker_identity
                || !observation.authenticated
                || !observation.cleanup_confirmed
                || observation.conformant
            {
                return Err(QualificationError::NonConformant);
            }
            observations.push((control, observation));
        }
        Ok(LocalFixtureExercise {
            observations,
            public_bundle: self.public.clone(),
            conformant: false,
        })
    }
}

impl QualificationPlan for PinnedFixturePlan {
    fn request(
        &self,
        control: Control,
        repetition: u8,
    ) -> Result<QualificationRequest, QualificationError> {
        let control_code = match control {
            Control::VulnerableBase => "base",
            Control::NoOp => "noop",
            Control::Bad => "bad",
            Control::Gold => "gold",
        };
        let suffix = format!(
            "{}{control_code}{repetition:02}job",
            self.qualification_run_nonce
        );
        let mut inputs = vec![
            self.public.source,
            self.public.environment,
            self.hidden.security_test,
            self.hidden.command_manifest,
        ];
        if let Some(patch) = self.patch(control) {
            inputs.push(patch);
        }
        Ok(QualificationRequest {
            organization_id: self.organization_id.clone(),
            lease_id: ContextQualifiedId::new("verification", &suffix)
                .map_err(|_| QualificationError::InvalidExecutionRequest)?,
            worker_identity: ContextQualifiedId::new("worker", &format!("{suffix}fresh"))
                .map_err(|_| QualificationError::InvalidExecutionRequest)?,
            image_digest: self.image_digest,
            environment_digest: self.public.environment,
            sandbox_profile: self.sandbox_profile.clone(),
            argv: vec![
                "/opt/cauterizer/bin/qualified-fixture-runner".into(),
                "--manifest-fd=3".into(),
            ],
            input_artifacts: inputs,
            egress_denied: true,
            cpu_millis: 120_000,
            wall_millis: 180_000,
            memory_bytes: 1_073_741_824,
            disk_bytes: 2_147_483_648,
            process_count: 128,
            output_bytes: 65_536,
            expires_at: self.expires_at.clone(),
        })
    }

    fn publish(&self, qualification_digest: Sha256Digest) -> PublicFixtureDescriptor {
        PublicFixtureDescriptor {
            advisory_id: ADVISORY_ID.into(),
            source_bundle_digest: self.public.source,
            environment_bundle_digest: self.public.environment,
            acquisition_manifest_digest: self.public.acquisition_manifest,
            qualification_policy: POLICY_VERSION.into(),
            qualification_digest,
        }
    }

    fn policy_version(&self) -> &str {
        POLICY_VERSION
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::qualification::*;

    fn digest(value: &str) -> Sha256Digest {
        Sha256Digest::of_bytes(value)
    }
    fn plan() -> PinnedFixturePlan {
        PinnedFixturePlan::new(
            "org_abcdefgh".parse().unwrap(),
            SolverPublicBundle {
                source: digest(VULNERABLE_REVISION),
                environment: digest("locked-env"),
                acquisition_manifest: digest(BENCHMARK_COMMIT),
            },
            VerifierHiddenBundle {
                security_test: digest("secret-test-name"),
                no_op_patch: digest("noop-secret"),
                bad_patch: digest("bad-secret"),
                gold_patch: digest("gold-secret"),
                command_manifest: digest("secret-path-and-command"),
            },
            digest("oci-image"),
            "gvisor-qualified-v1",
            "2026-07-23T01:00:00Z".parse().unwrap(),
            "run00001",
        )
    }

    struct Runner {
        calls: usize,
    }
    impl QualificationRunner for Runner {
        fn execute(
            &mut self,
            request: &QualificationRequest,
            control: Control,
        ) -> Result<QualificationObservation, QualificationError> {
            assert!(request.egress_denied);
            self.calls += 1;
            let request_digest = request.canonical_digest();
            Ok(QualificationObservation {
                outcome: if control == Control::Gold {
                    TestOutcome::Pass
                } else {
                    TestOutcome::Fail
                },
                normalized_digest: digest(match control {
                    Control::VulnerableBase => "base-fail",
                    Control::NoOp => "noop-fail",
                    Control::Bad => "bad-fail",
                    Control::Gold => "gold-pass",
                }),
                request_digest,
                receipt_digest: digest(&format!("receipt-{}", self.calls)),
                organization_id: request.organization_id.clone(),
                worker_identity: request.worker_identity.clone(),
                authenticated: true,
                conformant: true,
                cleanup_confirmed: true,
            })
        }
    }

    #[test]
    fn qualifies_all_controls_in_fresh_network_denied_jobs() {
        let mut runner = Runner { calls: 0 };
        let public = QualificationService::qualify(&plan(), &mut runner).unwrap();
        assert_eq!(runner.calls, 40);
        assert_eq!(public.advisory_id, ADVISORY_ID);
    }

    #[test]
    fn public_descriptor_has_no_hidden_names_paths_timing_logs_or_payloads() {
        let mut runner = Runner { calls: 0 };
        let json =
            serde_json::to_string(&QualificationService::qualify(&plan(), &mut runner).unwrap())
                .unwrap();
        for forbidden in [
            "secret", "gold", "noop", "bad", "test", "path", "command", "timing", "logs", "payload",
        ] {
            assert!(
                !json.to_ascii_lowercase().contains(forbidden),
                "leaked {forbidden}: {json}"
            );
        }
    }

    #[test]
    fn disagreement_fails_closed() {
        struct Flaky(usize);
        impl QualificationRunner for Flaky {
            fn execute(
                &mut self,
                request: &QualificationRequest,
                control: Control,
            ) -> Result<QualificationObservation, QualificationError> {
                self.0 += 1;
                let request_digest = request.canonical_digest();
                Ok(QualificationObservation {
                    outcome: if control == Control::Gold {
                        TestOutcome::Pass
                    } else {
                        TestOutcome::Fail
                    },
                    normalized_digest: digest(if self.0 == 2 { "different" } else { "same" }),
                    request_digest,
                    receipt_digest: digest(&format!("receipt-{}", self.0)),
                    organization_id: request.organization_id.clone(),
                    worker_identity: request.worker_identity.clone(),
                    authenticated: true,
                    conformant: true,
                    cleanup_confirmed: true,
                })
            }
        }
        assert_eq!(
            QualificationService::qualify(&plan(), &mut Flaky(0)),
            Err(QualificationError::Nondeterministic)
        );
    }

    #[test]
    fn forged_or_request_substituted_receipt_fails_closed() {
        struct Forged;
        impl QualificationRunner for Forged {
            fn execute(
                &mut self,
                request: &QualificationRequest,
                control: Control,
            ) -> Result<QualificationObservation, QualificationError> {
                Ok(QualificationObservation {
                    outcome: if control == Control::Gold {
                        TestOutcome::Pass
                    } else {
                        TestOutcome::Fail
                    },
                    normalized_digest: digest("normalized"),
                    request_digest: digest("different-request"),
                    receipt_digest: digest("forged-receipt"),
                    organization_id: request.organization_id.clone(),
                    worker_identity: request.worker_identity.clone(),
                    authenticated: false,
                    conformant: true,
                    cleanup_confirmed: true,
                })
            }
        }
        assert_eq!(
            QualificationService::qualify(&plan(), &mut Forged),
            Err(QualificationError::NonConformant)
        );
    }

    #[test]
    fn run_nonce_changes_request_and_qualification_identity() {
        let first = plan();
        let mut second = plan();
        second.qualification_run_nonce = "run00002".into();
        let first_request = first.request(Control::Gold, 0).unwrap();
        let second_request = second.request(Control::Gold, 0).unwrap();
        assert_ne!(first_request.lease_id, second_request.lease_id);
        assert_ne!(
            first_request.worker_identity,
            second_request.worker_identity
        );
        assert_ne!(
            first_request.canonical_digest(),
            second_request.canonical_digest()
        );
    }

    #[test]
    fn independently_measured_upstream_archives_records_and_notices_are_pinned() {
        let provenance = VerifiedUpstreamProvenance::pinned();
        assert!(provenance.matches_pins());
        assert_eq!(
            BENCHMARK_REPOSITORY,
            "https://github.com/ruvnet/CVE-bench.git"
        );
        assert_eq!(TARGET_REPOSITORY, "https://github.com/jpadilla/pyjwt.git");
        assert_eq!(FIX_REVISION, "9c528670c455b8d948aff95ed50e22940d1ad3fc");
    }

    #[test]
    fn real_local_control_path_records_evidence_but_never_qualifies() {
        struct LocalRunner(usize);
        impl QualificationRunner for LocalRunner {
            fn execute(
                &mut self,
                request: &QualificationRequest,
                control: Control,
            ) -> Result<QualificationObservation, QualificationError> {
                self.0 += 1;
                Ok(QualificationObservation {
                    outcome: if control == Control::Gold {
                        TestOutcome::Pass
                    } else {
                        TestOutcome::Fail
                    },
                    normalized_digest: digest(match control {
                        Control::VulnerableBase => "real-base-fail",
                        Control::NoOp => "real-noop-fail",
                        Control::Bad => "real-bad-fail",
                        Control::Gold => "real-gold-pass",
                    }),
                    request_digest: request.canonical_digest(),
                    receipt_digest: digest(&format!("local-receipt-{}", self.0)),
                    organization_id: request.organization_id.clone(),
                    worker_identity: request.worker_identity.clone(),
                    authenticated: true,
                    conformant: false,
                    cleanup_confirmed: true,
                })
            }
        }
        let exercise = plan()
            .exercise_nonconformant_local(&mut LocalRunner(0))
            .unwrap();
        assert_eq!(exercise.observations.len(), 4);
        assert!(!exercise.conformant);
    }
}
