//! Pure Isolated Execution lease aggregate and admission policy.

use std::collections::BTreeSet;
use std::fmt;

use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};

/// Context-owned execution lease identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExecutionLeaseId(ContextQualifiedId);
impl ExecutionLeaseId {
    /// Creates a lease identity.
    ///
    /// # Errors
    /// Returns [`ExecutionError::InvalidIdentity`] for invalid opaque syntax.
    pub fn new(value: &str) -> Result<Self, ExecutionError> {
        ContextQualifiedId::new("execution-lease", value)
            .map(Self)
            .map_err(|_| ExecutionError::InvalidIdentity)
    }
    /// Returns the qualified spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Security-separated worker pool and workload purpose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobClass {
    /// Allowlisted, networked dependency acquisition only.
    Acquisition,
    /// Hermetic patch-solving work with no verifier authority.
    Solver,
    /// Hermetic verification work with verifier-only identity.
    Verifier,
}

/// Truthful sandbox assurance derived from the backend, never caller-selected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConformanceLabel {
    /// P00-selected rootless Podman development backend.
    NonConformantLocal,
    /// Separately qualified hosted isolation profile.
    ConformantHosted,
}

/// Immutable content-addressed runtime environment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentRef {
    /// OCI image manifest digest.
    pub image_digest: Sha256Digest,
    /// Immutable environment bundle digest.
    pub bundle_digest: Sha256Digest,
}

/// A guest-visible mount backed only by a declared immutable artifact or scratch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclaredMount {
    /// Absolute normalized guest path.
    pub guest_path: String,
    /// Content-addressed source; absent only for bounded scratch.
    pub artifact_digest: Option<Sha256Digest>,
    /// Whether guest writes are permitted.
    pub writable: bool,
}

/// Declarative capabilities, enforced by the supervisor outside the guest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityEnvelope {
    /// Network policy; evaluation jobs must use [`NetworkPolicy::Denied`].
    pub network: NetworkPolicy,
    /// Declared guest mounts.
    pub mounts: Vec<DeclaredMount>,
    /// Linux capabilities. Admission currently requires this to be empty.
    pub linux_capabilities: BTreeSet<String>,
    /// Must remain false.
    pub privilege_escalation: bool,
    /// Must remain false; runtime daemon access is never declarable.
    pub runtime_daemon_socket: bool,
}

/// Network authority for one job.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkPolicy {
    /// No network namespace egress.
    Denied,
    /// Acquisition-only HTTPS proxy allowlist.
    AcquisitionAllowlist(Vec<String>),
}

/// Externally enforced finite resource ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceLimits {
    /// CPU quota in millicores.
    pub cpu_millis: u32,
    /// Memory ceiling in bytes.
    pub memory_bytes: u64,
    /// Writable storage ceiling in bytes.
    pub disk_bytes: u64,
    /// Maximum process count.
    pub process_count: u32,
    /// Wall-clock deadline in milliseconds.
    pub wall_time_ms: u64,
}

/// Externally enforced output ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutputLimits {
    /// Maximum stdout bytes retained after redaction.
    pub stdout_bytes: u64,
    /// Maximum stderr bytes retained after redaction.
    pub stderr_bytes: u64,
}

/// Immutable declarative execution request. Values are references, not secrets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionRequest {
    /// Canonical digest binding this complete request.
    pub request_digest: Sha256Digest,
    /// Security-separated job class.
    pub job_class: JobClass,
    /// Immutable environment.
    pub environment: EnvironmentRef,
    /// Executable and arguments, passed without a shell.
    pub argv: Vec<String>,
    /// Sanitized literal environment variables.
    pub environment_variables: Vec<(String, String)>,
    /// Capability declaration.
    pub capabilities: CapabilityEnvelope,
    /// Resource declaration.
    pub resources: ResourceLimits,
    /// Output declaration.
    pub output: OutputLimits,
}

/// Immutable workload identity bound to one lease and pool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerIdentity {
    /// Opaque workload identity.
    pub id: ContextQualifiedId,
    /// Pool class; must equal the request class.
    pub pool: JobClass,
}

/// Bounded observation facts; this vocabulary deliberately has no verdict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionObservation {
    /// Process exit code, or absent when no exit status exists.
    pub exit_code: Option<i32>,
    /// Digest reference to redacted bounded stdout.
    pub stdout_digest: Option<Sha256Digest>,
    /// Digest reference to redacted bounded stderr.
    pub stderr_digest: Option<Sha256Digest>,
    /// Whether either stream exceeded its declared ceiling.
    pub output_truncated: bool,
    /// Peak externally observed memory usage.
    pub peak_memory_bytes: u64,
    /// Peak externally observed disk usage.
    pub peak_disk_bytes: u64,
    /// Peak externally observed process count.
    pub peak_process_count: u32,
}

/// Reason execution stopped; it does not interpret the observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalKind {
    /// Worker reported process completion.
    Completed,
    /// Supervisor enforced the deadline.
    TimedOut,
    /// Authorized cancellation was enforced.
    Cancelled,
    /// Heartbeats expired or the worker disappeared.
    WorkerLost,
}

/// Authoritative terminal receipt, accepted at most once.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalReceipt {
    /// Exact request digest.
    pub request_digest: Sha256Digest,
    /// Exact image digest.
    pub environment_digest: Sha256Digest,
    /// Worker identity that executed the lease.
    pub worker: WorkerIdentity,
    /// Mechanism-independent stop reason.
    pub kind: TerminalKind,
    /// Bounded observations only.
    pub observation: ExecutionObservation,
    /// Backend-derived assurance label.
    pub conformance: ConformanceLabel,
}

/// Mandatory cleanup result for every terminal path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CleanupReceipt {
    /// Worker resources and job-scoped identity were destroyed.
    Confirmed {
        /// Digest of the supervisor's cleanup evidence.
        cleanup_digest: Sha256Digest,
    },
    /// Cleanup could not be proven; the lease remains failed closed.
    Failed {
        /// Stable non-sensitive cleanup failure code.
        reason_code: String,
    },
}

/// Lease lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseState {
    /// Request admitted, no worker attached.
    Allocated,
    /// Exact worker identity attached and active.
    Running,
    /// Terminal receipt exists and cleanup is mandatory.
    AwaitingCleanup(TerminalKind),
    /// Terminal receipt and cleanup result are both durable.
    Closed(TerminalKind),
}

/// Aggregate events used for replay and audit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionEvent {
    /// Request passed admission and was allocated.
    Allocated,
    /// Worker identity was bound exactly once.
    Started {
        /// Lease-bound worker identity.
        worker: WorkerIdentity,
    },
    /// A monotonic authenticated heartbeat was accepted.
    HeartbeatRecorded {
        /// Strictly increasing worker sequence.
        sequence: u64,
    },
    /// The sole terminal receipt was accepted.
    TerminalRecorded {
        /// Authoritative observation receipt.
        receipt: TerminalReceipt,
    },
    /// The mandatory cleanup outcome was accepted.
    CleanupRecorded {
        /// Mandatory cleanup result.
        receipt: CleanupReceipt,
    },
}

/// Pure aggregate governing one immutable execution attempt.
#[derive(Clone, Debug)]
pub struct ExecutionLease {
    organization_id: OrganizationId,
    id: ExecutionLeaseId,
    request: ExecutionRequest,
    backend_label: ConformanceLabel,
    state: LeaseState,
    worker: Option<WorkerIdentity>,
    heartbeat_sequence: u64,
    terminal: Option<TerminalReceipt>,
    cleanup: Option<CleanupReceipt>,
    events: Vec<ExecutionEvent>,
}

impl ExecutionLease {
    /// Admits and allocates one immutable request.
    ///
    /// # Errors
    /// Rejects forbidden authority, secrets, paths, or unbounded resources.
    pub fn allocate(
        organization_id: OrganizationId,
        id: ExecutionLeaseId,
        request: ExecutionRequest,
        backend_label: ConformanceLabel,
    ) -> Result<Self, ExecutionError> {
        admit(&request)?;
        Ok(Self {
            organization_id,
            id,
            request,
            backend_label,
            state: LeaseState::Allocated,
            worker: None,
            heartbeat_sequence: 0,
            terminal: None,
            cleanup: None,
            events: vec![ExecutionEvent::Allocated],
        })
    }
    /// Tenant owning the lease.
    #[must_use]
    pub const fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }
    /// Lease identity.
    #[must_use]
    pub const fn id(&self) -> &ExecutionLeaseId {
        &self.id
    }
    /// Immutable request.
    #[must_use]
    pub const fn request(&self) -> &ExecutionRequest {
        &self.request
    }
    /// Current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> LeaseState {
        self.state
    }
    /// Authoritative terminal receipt, if present.
    #[must_use]
    pub const fn terminal_receipt(&self) -> Option<&TerminalReceipt> {
        self.terminal.as_ref()
    }
    /// Mandatory cleanup outcome, if present.
    #[must_use]
    pub const fn cleanup_receipt(&self) -> Option<&CleanupReceipt> {
        self.cleanup.as_ref()
    }
    /// Complete replayable event stream.
    #[must_use]
    pub fn events(&self) -> &[ExecutionEvent] {
        &self.events
    }

    /// Binds the lease's sole worker identity.
    ///
    /// # Errors
    /// Rejects wrong state, pool mixing, or identity reuse within this lease.
    pub fn start(&mut self, worker: WorkerIdentity) -> Result<(), ExecutionError> {
        if self.state != LeaseState::Allocated {
            return Err(ExecutionError::InvalidTransition);
        }
        if worker.pool != self.request.job_class {
            return Err(ExecutionError::PoolMismatch);
        }
        self.worker = Some(worker.clone());
        self.state = LeaseState::Running;
        self.events.push(ExecutionEvent::Started { worker });
        Ok(())
    }

    /// Records a strictly increasing heartbeat from the bound worker.
    ///
    /// # Errors
    /// Rejects stale, foreign, or post-terminal heartbeats.
    pub fn heartbeat(
        &mut self,
        worker: &WorkerIdentity,
        sequence: u64,
    ) -> Result<(), ExecutionError> {
        self.require_worker(worker)?;
        if self.state != LeaseState::Running {
            return Err(ExecutionError::InvalidTransition);
        }
        if sequence <= self.heartbeat_sequence {
            return Err(ExecutionError::StaleHeartbeat);
        }
        self.heartbeat_sequence = sequence;
        self.events
            .push(ExecutionEvent::HeartbeatRecorded { sequence });
        Ok(())
    }

    /// Accepts the sole authoritative terminal observation.
    ///
    /// # Errors
    /// Rejects identity/digest/label mismatches, duplicate termination, or exceeded observations.
    pub fn record_terminal(&mut self, receipt: TerminalReceipt) -> Result<(), ExecutionError> {
        self.require_worker(&receipt.worker)?;
        if self.state != LeaseState::Running || self.terminal.is_some() {
            return Err(ExecutionError::TerminalAlreadyRecorded);
        }
        if receipt.request_digest != self.request.request_digest
            || receipt.environment_digest != self.request.environment.image_digest
        {
            return Err(ExecutionError::DigestMismatch);
        }
        if receipt.conformance != self.backend_label {
            return Err(ExecutionError::ConformanceMismatch);
        }
        if receipt.observation.peak_memory_bytes > self.request.resources.memory_bytes
            || receipt.observation.peak_disk_bytes > self.request.resources.disk_bytes
            || receipt.observation.peak_process_count > self.request.resources.process_count
        {
            return Err(ExecutionError::LimitReceiptInvalid);
        }
        let kind = receipt.kind;
        self.terminal = Some(receipt.clone());
        self.state = LeaseState::AwaitingCleanup(kind);
        self.events
            .push(ExecutionEvent::TerminalRecorded { receipt });
        Ok(())
    }

    /// Records cleanup, closing every terminal path even when cleanup failed.
    ///
    /// # Errors
    /// Rejects cleanup before termination or a second cleanup result.
    pub fn confirm_cleanup(&mut self, receipt: CleanupReceipt) -> Result<(), ExecutionError> {
        let LeaseState::AwaitingCleanup(kind) = self.state else {
            return Err(ExecutionError::InvalidTransition);
        };
        if let CleanupReceipt::Failed { reason_code } = &receipt {
            if reason_code.trim().is_empty() || reason_code.len() > 128 {
                return Err(ExecutionError::InvalidCleanup);
            }
        }
        self.cleanup = Some(receipt.clone());
        self.state = LeaseState::Closed(kind);
        self.events
            .push(ExecutionEvent::CleanupRecorded { receipt });
        Ok(())
    }

    fn require_worker(&self, worker: &WorkerIdentity) -> Result<(), ExecutionError> {
        match &self.worker {
            Some(expected) if expected == worker => Ok(()),
            _ => Err(ExecutionError::WorkerMismatch),
        }
    }
}

fn admit(request: &ExecutionRequest) -> Result<(), ExecutionError> {
    if request.argv.is_empty()
        || request.argv.len() > 128
        || request
            .argv
            .iter()
            .any(|v| v.is_empty() || v.len() > 4096 || v.contains('\0'))
    {
        return Err(ExecutionError::InvalidCommand);
    }
    if request.capabilities.privilege_escalation
        || request.capabilities.runtime_daemon_socket
        || !request.capabilities.linux_capabilities.is_empty()
    {
        return Err(ExecutionError::ForbiddenCapability);
    }
    if !matches!(request.job_class, JobClass::Acquisition)
        && !matches!(request.capabilities.network, NetworkPolicy::Denied)
    {
        return Err(ExecutionError::EvaluationEgress);
    }
    if let NetworkPolicy::AcquisitionAllowlist(hosts) = &request.capabilities.network {
        if request.job_class != JobClass::Acquisition
            || hosts.is_empty()
            || hosts
                .iter()
                .any(|h| h.is_empty() || h.contains('/') || h.contains(':'))
        {
            return Err(ExecutionError::InvalidNetworkPolicy);
        }
    }
    for mount in &request.capabilities.mounts {
        if !safe_guest_path(&mount.guest_path)
            || mount.guest_path.contains("docker.sock")
            || mount.guest_path.contains("podman.sock")
            || (mount.writable && mount.artifact_digest.is_some())
        {
            return Err(ExecutionError::ForbiddenMount);
        }
    }
    for (name, value) in &request.environment_variables {
        let upper = name.to_ascii_uppercase();
        if name.is_empty()
            || value.len() > 4096
            || [
                "SECRET",
                "TOKEN",
                "PASSWORD",
                "PRIVATE_KEY",
                "AWS_",
                "AZURE_",
                "GOOGLE_",
            ]
            .iter()
            .any(|needle| upper.contains(needle))
        {
            return Err(ExecutionError::SecretEnvironment);
        }
    }
    let r = request.resources;
    if r.cpu_millis == 0
        || r.memory_bytes == 0
        || r.disk_bytes == 0
        || r.process_count == 0
        || r.wall_time_ms == 0
        || request.output.stdout_bytes == 0
        || request.output.stderr_bytes == 0
    {
        return Err(ExecutionError::UnboundedResources);
    }
    Ok(())
}

fn safe_guest_path(path: &str) -> bool {
    path.starts_with("/workspace/")
        && !path.split('/').any(|part| part == ".." || part == ".")
        && !path.contains("//")
}

/// Stable admission and lifecycle errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionError {
    /// Invalid lease or worker identity syntax.
    InvalidIdentity,
    /// Command declaration is empty, oversized, or contains NUL.
    InvalidCommand,
    /// Privilege, daemon access, or Linux capability was requested.
    ForbiddenCapability,
    /// Evaluation workload requested network access.
    EvaluationEgress,
    /// Acquisition allowlist is malformed.
    InvalidNetworkPolicy,
    /// Guest mount is unsafe or grants undeclared host authority.
    ForbiddenMount,
    /// Environment variable appears secret-bearing.
    SecretEnvironment,
    /// A finite external resource limit is missing.
    UnboundedResources,
    /// Command is not valid from the current state.
    InvalidTransition,
    /// Worker belongs to a different security pool.
    PoolMismatch,
    /// Message does not come from the lease-bound worker.
    WorkerMismatch,
    /// Heartbeat is duplicate or out of order.
    StaleHeartbeat,
    /// A terminal receipt already exists or state is terminal.
    TerminalAlreadyRecorded,
    /// Receipt request or environment digest differs from allocation.
    DigestMismatch,
    /// Receipt attempts to relabel its immutable backend assurance.
    ConformanceMismatch,
    /// Reported external resource peak contradicts the enforced ceiling.
    LimitReceiptInvalid,
    /// Cleanup failure reason is malformed.
    InvalidCleanup,
}
impl fmt::Display for ExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl std::error::Error for ExecutionError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(class: JobClass) -> ExecutionRequest {
        ExecutionRequest {
            request_digest: Sha256Digest::of_bytes(b"request"),
            job_class: class,
            environment: EnvironmentRef {
                image_digest: Sha256Digest::of_bytes(b"image"),
                bundle_digest: Sha256Digest::of_bytes(b"bundle"),
            },
            argv: vec!["/usr/bin/test".into()],
            environment_variables: vec![("LANG".into(), "C.UTF-8".into())],
            capabilities: CapabilityEnvelope {
                network: NetworkPolicy::Denied,
                mounts: vec![DeclaredMount {
                    guest_path: "/workspace/input".into(),
                    artifact_digest: Some(Sha256Digest::of_bytes(b"input")),
                    writable: false,
                }],
                linux_capabilities: BTreeSet::new(),
                privilege_escalation: false,
                runtime_daemon_socket: false,
            },
            resources: ResourceLimits {
                cpu_millis: 1_000,
                memory_bytes: 64 << 20,
                disk_bytes: 128 << 20,
                process_count: 32,
                wall_time_ms: 30_000,
            },
            output: OutputLimits {
                stdout_bytes: 65_536,
                stderr_bytes: 65_536,
            },
        }
    }
    fn worker(class: JobClass, value: &str) -> WorkerIdentity {
        WorkerIdentity {
            id: ContextQualifiedId::new("worker", value).unwrap(),
            pool: class,
        }
    }
    fn lease(request: ExecutionRequest) -> Result<ExecutionLease, ExecutionError> {
        ExecutionLease::allocate(
            OrganizationId::new("00000000").unwrap(),
            ExecutionLeaseId::new("00000000").unwrap(),
            request,
            ConformanceLabel::NonConformantLocal,
        )
    }
    fn terminal(
        request: &ExecutionRequest,
        worker: WorkerIdentity,
        kind: TerminalKind,
    ) -> TerminalReceipt {
        TerminalReceipt {
            request_digest: request.request_digest,
            environment_digest: request.environment.image_digest,
            worker,
            kind,
            observation: ExecutionObservation {
                exit_code: Some(0),
                stdout_digest: None,
                stderr_digest: None,
                output_truncated: false,
                peak_memory_bytes: 1,
                peak_disk_bytes: 1,
                peak_process_count: 1,
            },
            conformance: ConformanceLabel::NonConformantLocal,
        }
    }

    #[test]
    fn rejects_evaluation_egress_secrets_privilege_daemons_and_paths() {
        let mut cases = Vec::new();
        let mut value = request(JobClass::Solver);
        value.capabilities.network =
            NetworkPolicy::AcquisitionAllowlist(vec!["registry.example".into()]);
        cases.push((value, ExecutionError::EvaluationEgress));
        let mut value = request(JobClass::Solver);
        value
            .environment_variables
            .push(("API_TOKEN".into(), "synthetic".into()));
        cases.push((value, ExecutionError::SecretEnvironment));
        let mut value = request(JobClass::Solver);
        value.capabilities.privilege_escalation = true;
        cases.push((value, ExecutionError::ForbiddenCapability));
        let mut value = request(JobClass::Solver);
        value.capabilities.runtime_daemon_socket = true;
        cases.push((value, ExecutionError::ForbiddenCapability));
        for path in [
            "/host/etc",
            "/workspace/../etc",
            "/workspace/docker.sock",
            "/workspace//input",
        ] {
            let mut value = request(JobClass::Solver);
            value.capabilities.mounts[0].guest_path = path.into();
            cases.push((value, ExecutionError::ForbiddenMount));
        }
        for (value, expected) in cases {
            assert_eq!(lease(value).unwrap_err(), expected);
        }
    }

    #[test]
    fn job_pools_and_worker_identity_are_not_interchangeable() {
        let request = request(JobClass::Verifier);
        let mut value = lease(request).unwrap();
        assert_eq!(
            value.start(worker(JobClass::Solver, "00000001")),
            Err(ExecutionError::PoolMismatch)
        );
        let verifier = worker(JobClass::Verifier, "00000002");
        value.start(verifier.clone()).unwrap();
        assert_eq!(
            value.heartbeat(&worker(JobClass::Verifier, "00000003"), 1),
            Err(ExecutionError::WorkerMismatch)
        );
        value.heartbeat(&verifier, 1).unwrap();
        assert_eq!(
            value.heartbeat(&verifier, 1),
            Err(ExecutionError::StaleHeartbeat)
        );
    }

    #[test]
    fn every_terminal_kind_requires_and_records_cleanup() {
        for kind in [
            TerminalKind::Completed,
            TerminalKind::TimedOut,
            TerminalKind::Cancelled,
            TerminalKind::WorkerLost,
        ] {
            let request = request(JobClass::Solver);
            let mut value = lease(request.clone()).unwrap();
            let identity = worker(JobClass::Solver, "00000001");
            value.start(identity.clone()).unwrap();
            value
                .record_terminal(terminal(&request, identity, kind))
                .unwrap();
            assert_eq!(value.state(), LeaseState::AwaitingCleanup(kind));
            assert!(value.cleanup_receipt().is_none());
            value
                .confirm_cleanup(CleanupReceipt::Failed {
                    reason_code: "destroy-not-confirmed".into(),
                })
                .unwrap();
            assert_eq!(value.state(), LeaseState::Closed(kind));
            assert!(value.cleanup_receipt().is_some());
        }
    }

    #[test]
    fn local_backend_cannot_emit_conformant_or_second_terminal_receipt() {
        let request = request(JobClass::Solver);
        let identity = worker(JobClass::Solver, "00000001");
        let mut value = lease(request.clone()).unwrap();
        value.start(identity.clone()).unwrap();
        let mut receipt = terminal(&request, identity.clone(), TerminalKind::Completed);
        receipt.conformance = ConformanceLabel::ConformantHosted;
        assert_eq!(
            value.record_terminal(receipt),
            Err(ExecutionError::ConformanceMismatch)
        );
        value
            .record_terminal(terminal(&request, identity.clone(), TerminalKind::TimedOut))
            .unwrap();
        assert_eq!(
            value.record_terminal(terminal(&request, identity, TerminalKind::Completed)),
            Err(ExecutionError::TerminalAlreadyRecorded)
        );
    }

    #[test]
    fn external_limit_receipt_cannot_claim_enforcement_above_envelope() {
        let request = request(JobClass::Solver);
        let identity = worker(JobClass::Solver, "00000001");
        let mut value = lease(request.clone()).unwrap();
        value.start(identity.clone()).unwrap();
        let mut receipt = terminal(&request, identity, TerminalKind::Completed);
        receipt.observation.peak_process_count = request.resources.process_count + 1;
        assert_eq!(
            value.record_terminal(receipt),
            Err(ExecutionError::LimitReceiptInvalid)
        );
    }
}
