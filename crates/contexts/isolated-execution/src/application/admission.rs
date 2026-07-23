//! Fail-closed admission for declarative isolated execution requests.
use crate::domain::{
    ConformanceLabel, ExecutionRequest, JobClass, NetworkPolicy, OutputLimits, ResourceLimits,
};
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::ContextQualifiedId;

/// Hard platform ceilings enforced outside the guest.
#[derive(Clone, Copy, Debug)]
pub struct AdmissionCeiling {
    /// Resource maxima.
    pub resources: ResourceLimits,
    /// Output maxima.
    pub output: OutputLimits,
}
/// Stable payload-safe denial vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionReason {
    /// Empty, oversized, or ambiguous command.
    InvalidRequest,
    /// Secret-bearing environment key.
    SecretEnvironment,
    /// Evaluation network or malformed acquisition allowlist.
    NetworkDenied,
    /// Host path, traversal, daemon socket, or unsafe mount.
    UnsafeMount,
    /// Capability or privilege request.
    PrivilegeDenied,
    /// Zero or excessive resource/output envelope.
    ResourceLimitExceeded,
    /// Lease identity is malformed.
    IdentityIsolationViolation,
}
/// Validated local execution; label is backend-derived, never caller-selected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedExecution {
    /// Exact lease identity.
    pub lease_id: ContextQualifiedId,
    /// Domain-owned request.
    pub request: ExecutionRequest,
    /// Immutable local backend label.
    pub conformance: ConformanceLabel,
}
/// Local admission policy.
#[derive(Clone, Copy, Debug)]
pub struct AdmissionPolicy {
    /// Hard ceilings.
    pub ceiling: AdmissionCeiling,
}
impl AdmissionPolicy {
    /// Validates every capability before process creation.
    /// # Errors
    /// Returns a stable reason for malformed or forbidden authority.
    pub fn admit(
        &self,
        lease_id: ContextQualifiedId,
        request: ExecutionRequest,
    ) -> Result<AdmittedExecution, AdmissionReason> {
        if !lease_id.as_str().starts_with("execution-lease_") {
            return Err(AdmissionReason::IdentityIsolationViolation);
        }
        if request.request_digest == Sha256Digest::of_bytes([])
            || request.argv.is_empty()
            || request.argv.len() > 128
            || request
                .argv
                .iter()
                .any(|value| value.is_empty() || value.len() > 4096 || value.contains('\0'))
        {
            return Err(AdmissionReason::InvalidRequest);
        }
        if request.environment_variables.len() > 64
            || request.environment_variables.iter().any(|(key, value)| {
                !safe_env_name(key) || value.len() > 4096 || sensitive_name(key)
            })
        {
            return Err(AdmissionReason::SecretEnvironment);
        }
        if request.capabilities.privilege_escalation
            || request.capabilities.runtime_daemon_socket
            || !request.capabilities.linux_capabilities.is_empty()
        {
            return Err(AdmissionReason::PrivilegeDenied);
        }
        for mount in &request.capabilities.mounts {
            if !safe_guest_path(&mount.guest_path)
                || mount.writable == mount.artifact_digest.is_some()
            {
                return Err(AdmissionReason::UnsafeMount);
            }
        }
        match (&request.job_class, &request.capabilities.network) {
            (_, NetworkPolicy::Denied) => {}
            (JobClass::Acquisition, NetworkPolicy::AcquisitionAllowlist(hosts))
                if !hosts.is_empty()
                    && hosts.len() <= 32
                    && hosts.iter().all(|host| safe_host(host)) => {}
            _ => return Err(AdmissionReason::NetworkDenied),
        }
        let resources = request.resources;
        let output = request.output;
        let max = self.ceiling;
        if resources.cpu_millis == 0
            || resources.memory_bytes == 0
            || resources.disk_bytes == 0
            || resources.process_count == 0
            || resources.wall_time_ms == 0
            || output.stdout_bytes == 0
            || output.stderr_bytes == 0
            || resources.cpu_millis > max.resources.cpu_millis
            || resources.memory_bytes > max.resources.memory_bytes
            || resources.disk_bytes > max.resources.disk_bytes
            || resources.process_count > max.resources.process_count
            || resources.wall_time_ms > max.resources.wall_time_ms
            || output.stdout_bytes > max.output.stdout_bytes
            || output.stderr_bytes > max.output.stderr_bytes
        {
            return Err(AdmissionReason::ResourceLimitExceeded);
        }
        Ok(AdmittedExecution {
            lease_id,
            request,
            conformance: ConformanceLabel::NonConformantLocal,
        })
    }
}
fn safe_env_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}
fn sensitive_name(value: &str) -> bool {
    let value = value.to_ascii_uppercase();
    [
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "PASSWD",
        "PRIVATE",
        "CREDENTIAL",
        "AWS_",
        "GITHUB_",
        "SSH_",
        "KUBECONFIG",
        "DOCKER_HOST",
    ]
    .iter()
    .any(|needle| value.contains(needle))
}
fn safe_guest_path(value: &str) -> bool {
    value.starts_with("/workspace/")
        && !value.contains("..")
        && !value.contains('\\')
        && !value.contains("//")
        && !value.ends_with('/')
}
fn safe_host(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value.contains(['/', ':', '@', '\\'])
        && !matches!(value, "localhost" | "metadata.google.internal")
        && !value.to_ascii_lowercase().ends_with(".local")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{CapabilityEnvelope, EnvironmentRef};
    use std::collections::BTreeSet;
    fn resources() -> ResourceLimits {
        ResourceLimits {
            cpu_millis: 500,
            memory_bytes: 64 << 20,
            disk_bytes: 16 << 20,
            process_count: 16,
            wall_time_ms: 1000,
        }
    }
    fn output() -> OutputLimits {
        OutputLimits {
            stdout_bytes: 4096,
            stderr_bytes: 4096,
        }
    }
    fn request(class: JobClass) -> ExecutionRequest {
        ExecutionRequest {
            request_digest: Sha256Digest::of_bytes(b"request"),
            job_class: class,
            environment: EnvironmentRef {
                image_digest: Sha256Digest::of_bytes(b"image"),
                bundle_digest: Sha256Digest::of_bytes(b"bundle"),
            },
            argv: vec!["/bin/test".into()],
            environment_variables: vec![],
            capabilities: CapabilityEnvelope {
                network: NetworkPolicy::Denied,
                mounts: vec![],
                linux_capabilities: BTreeSet::new(),
                privilege_escalation: false,
                runtime_daemon_socket: false,
            },
            resources: resources(),
            output: output(),
        }
    }
    fn policy() -> AdmissionPolicy {
        AdmissionPolicy {
            ceiling: AdmissionCeiling {
                resources: resources(),
                output: output(),
            },
        }
    }
    fn lease() -> ContextQualifiedId {
        ContextQualifiedId::new("execution-lease", "00000000").unwrap()
    }
    #[test]
    fn egress_secrets_privilege_and_daemon_socket_fail() {
        let mut r = request(JobClass::Verifier);
        r.capabilities.network = NetworkPolicy::AcquisitionAllowlist(vec!["example.com".into()]);
        assert_eq!(
            policy().admit(lease(), r),
            Err(AdmissionReason::NetworkDenied)
        );
        let mut r = request(JobClass::Solver);
        r.environment_variables
            .push(("API_TOKEN".into(), "x".into()));
        assert_eq!(
            policy().admit(lease(), r),
            Err(AdmissionReason::SecretEnvironment)
        );
        let mut r = request(JobClass::Solver);
        r.capabilities.runtime_daemon_socket = true;
        assert_eq!(
            policy().admit(lease(), r),
            Err(AdmissionReason::PrivilegeDenied)
        );
    }
    #[test]
    fn traversal_host_mount_and_exhaustion_fail() {
        let mut r = request(JobClass::Solver);
        r.capabilities.mounts.push(crate::domain::DeclaredMount {
            guest_path: "/workspace/../etc".into(),
            artifact_digest: Some(Sha256Digest::of_bytes(b"a")),
            writable: false,
        });
        assert_eq!(
            policy().admit(lease(), r),
            Err(AdmissionReason::UnsafeMount)
        );
        let mut r = request(JobClass::Solver);
        r.resources.process_count = 17;
        assert_eq!(
            policy().admit(lease(), r),
            Err(AdmissionReason::ResourceLimitExceeded)
        );
    }
    #[test]
    fn local_backend_is_always_non_conformant() {
        assert_eq!(
            policy()
                .admit(lease(), request(JobClass::Verifier))
                .unwrap()
                .conformance,
            ConformanceLabel::NonConformantLocal
        );
    }
}
