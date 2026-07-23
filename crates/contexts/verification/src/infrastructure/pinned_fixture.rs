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
/// Fixed policy recording the ten-fresh-job rule.
pub const POLICY_VERSION: &str = "fixture-qualification-v1-10x";

/// Solver-public immutable bundle references.
#[derive(Clone, Debug)]
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
}
