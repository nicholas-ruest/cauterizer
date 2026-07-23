//! Rootless Podman local worker supervisor.
use crate::application::admission::AdmittedExecution;
use crate::domain::JobClass;
use std::fmt;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};
/// Authoritative supervisor termination category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Termination {
    /// Worker exited before deadline.
    Exited(i32),
    /// Supervisor killed it at deadline.
    TimedOut,
    /// Caller cancellation won the race.
    Cancelled,
    /// Worker disappeared without an exit status.
    WorkerLost,
}
/// Mandatory cleanup outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupOutcome {
    /// Container removal confirmed.
    Confirmed,
    /// Backend could not confirm removal.
    Failed,
}
/// Bounded observation; never a verification verdict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisorReceipt {
    /// Terminal category.
    pub termination: Termination,
    /// Mandatory cleanup result.
    pub cleanup: CleanupOutcome,
    /// Bounded stdout prefix.
    pub stdout: Vec<u8>,
    /// Bounded stderr prefix.
    pub stderr: Vec<u8>,
    /// P00-required label.
    pub conformance_label: &'static str,
}
/// Stable backend failure before an authoritative receipt exists.
#[derive(Debug)]
pub struct SupervisorError;
impl fmt::Display for SupervisorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("local_worker_backend_unavailable")
    }
}
impl std::error::Error for SupervisorError {}
/// P00-selected rootless Podman backend. It can never emit a conformant receipt.
#[derive(Clone, Debug)]
pub struct LocalPodmanSupervisor {
    binary: String,
}
impl Default for LocalPodmanSupervisor {
    fn default() -> Self {
        Self {
            binary: "podman".into(),
        }
    }
}
impl LocalPodmanSupervisor {
    /// Creates a supervisor with an explicit binary for qualification tests.
    #[must_use]
    pub fn new(binary: impl Into<String>) -> Self {
        Self {
            binary: binary.into(),
        }
    }
    /// Returns the exact daemonless OCI invocation after admission.
    #[must_use]
    pub fn command_line(&self, execution: &AdmittedExecution) -> Vec<String> {
        let r = &execution.request;
        let name = worker_name(execution.lease_id.as_str(), r.job_class);
        let mut args = vec![
            "run".into(),
            "--name".into(),
            name,
            "--network".into(),
            "none".into(),
            "--read-only".into(),
            "--log-driver".into(),
            "none".into(),
            "--cap-drop".into(),
            "ALL".into(),
            "--security-opt".into(),
            "no-new-privileges".into(),
            "--pids-limit".into(),
            r.resources.process_count.to_string(),
            "--memory".into(),
            r.resources.memory_bytes.to_string(),
            "--cpus".into(),
            format!("{:.3}", f64::from(r.resources.cpu_millis) / 1000.0),
            "--tmpfs".into(),
            format!(
                "/work:rw,noexec,nosuid,nodev,size={}",
                r.resources.disk_bytes
            ),
            "--user".into(),
            "65532:65532".into(),
        ];
        for (key, value) in &r.environment_variables {
            args.push("--env".into());
            args.push(format!("{key}={value}"));
        }
        args.push(format!(
            "localhost/cauterizer-worker@{}",
            r.environment.image_digest.to_tagged_hex()
        ));
        args.extend(r.argv.clone());
        args
    }
    /// Runs with external timeout/cancellation/output caps and unconditional cleanup.
    /// # Errors
    /// Returns only when the backend cannot be spawned; post-spawn paths return a cleanup-bearing receipt.
    pub fn execute(
        &self,
        execution: &AdmittedExecution,
        cancel: &Arc<AtomicBool>,
    ) -> Result<SupervisorReceipt, SupervisorError> {
        let name = worker_name(execution.lease_id.as_str(), execution.request.job_class);
        let args = self.command_line(execution);
        let mut child = Command::new(&self.binary)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| SupervisorError)?;
        let stdout = bounded_reader(
            child.stdout.take(),
            usize::try_from(execution.request.output.stdout_bytes).unwrap_or(usize::MAX),
        );
        let stderr = bounded_reader(
            child.stderr.take(),
            usize::try_from(execution.request.output.stderr_bytes).unwrap_or(usize::MAX),
        );
        let deadline =
            Instant::now() + Duration::from_millis(execution.request.resources.wall_time_ms);
        let termination = loop {
            if cancel.load(Ordering::Acquire) {
                let _ = child.kill();
                let _ = child.wait();
                break Termination::Cancelled;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                break Termination::TimedOut;
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    break status
                        .code()
                        .map_or(Termination::WorkerLost, Termination::Exited);
                }
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(_) => break Termination::WorkerLost,
            }
        };
        let cleanup = Command::new(&self.binary)
            .args(["rm", "--force", &name])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_or(CleanupOutcome::Failed, |status| {
                if status.success() {
                    CleanupOutcome::Confirmed
                } else {
                    CleanupOutcome::Failed
                }
            });
        Ok(SupervisorReceipt {
            termination,
            cleanup,
            stdout: stdout.join().unwrap_or_default(),
            stderr: stderr.join().unwrap_or_default(),
            conformance_label: "non-conformant-local",
        })
    }
}
fn bounded_reader<R: Read + Send + 'static>(
    reader: Option<R>,
    limit: usize,
) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut retained = Vec::with_capacity(limit.min(8192));
        if let Some(mut source) = reader {
            let mut buffer = [0u8; 8192];
            while let Ok(count) = source.read(&mut buffer) {
                if count == 0 {
                    break;
                }
                let remaining = limit.saturating_sub(retained.len());
                retained.extend_from_slice(&buffer[..count.min(remaining)]);
            }
        }
        retained
    })
}
fn worker_name(lease: &str, class: JobClass) -> String {
    let pool = match class {
        JobClass::Acquisition => "acq",
        JobClass::Solver => "solver",
        JobClass::Verifier => "verifier",
    };
    format!("cauterizer-{pool}-{}", lease.replace('_', "-"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::admission::*;
    use crate::domain::{
        CapabilityEnvelope, ConformanceLabel, EnvironmentRef, ExecutionRequest, NetworkPolicy,
        OutputLimits, ResourceLimits,
    };
    use cauterizer_syntax::digest::Sha256Digest;
    use cauterizer_syntax::identifiers::ContextQualifiedId;
    use std::collections::BTreeSet;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    fn admitted(class: JobClass) -> AdmittedExecution {
        AdmittedExecution {
            lease_id: ContextQualifiedId::new("execution-lease", "00000000").unwrap(),
            request: ExecutionRequest {
                request_digest: Sha256Digest::of_bytes(b"request"),
                job_class: class,
                environment: EnvironmentRef {
                    image_digest: Sha256Digest::of_bytes(b"image"),
                    bundle_digest: Sha256Digest::of_bytes(b"bundle"),
                },
                argv: vec!["/bin/true".into()],
                environment_variables: vec![],
                capabilities: CapabilityEnvelope {
                    network: NetworkPolicy::Denied,
                    mounts: vec![],
                    linux_capabilities: BTreeSet::new(),
                    privilege_escalation: false,
                    runtime_daemon_socket: false,
                },
                resources: ResourceLimits {
                    wall_time_ms: 100,
                    memory_bytes: 1024,
                    disk_bytes: 1024,
                    process_count: 2,
                    cpu_millis: 100,
                },
                output: OutputLimits {
                    stdout_bytes: 32,
                    stderr_bytes: 32,
                },
            },
            conformance: ConformanceLabel::NonConformantLocal,
        }
    }
    #[test]
    fn command_denies_network_mounts_privilege_and_capabilities() {
        let args = LocalPodmanSupervisor::default().command_line(&admitted(JobClass::Verifier));
        let text = args.join(" ");
        assert!(text.contains("--network none"));
        assert!(text.contains("--cap-drop ALL"));
        assert!(text.contains("no-new-privileges"));
        assert!(text.contains("--read-only"));
        assert!(!text.contains("docker.sock"));
        assert!(!text.contains("--privileged"));
        assert!(!text.contains("--volume"));
    }
    #[test]
    fn pool_identities_are_distinct_and_local_is_never_conformant() {
        let s = LocalPodmanSupervisor::default();
        assert_ne!(
            s.command_line(&admitted(JobClass::Solver))[2],
            s.command_line(&admitted(JobClass::Verifier))[2]
        );
        assert_eq!(
            admitted(JobClass::Verifier).conformance,
            ConformanceLabel::NonConformantLocal
        );
    }
    #[cfg(unix)]
    fn fake_backend(mode: &str) -> LocalPodmanSupervisor {
        let path =
            std::env::temp_dir().join(format!("cauterizer-podman-{mode}-{}", std::process::id()));
        let run = match mode {
            "timeout" => "sleep 2",
            "lost" => "kill -9 $$",
            _ => "exit 0",
        };
        let cleanup = if mode == "cleanup-fail" {
            "exit 1"
        } else {
            "exit 0"
        };
        std::fs::write(
            &path,
            format!("#!/bin/sh\nif [ \"$1\" = \"run\" ]; then {run}; fi\n{cleanup}\n"),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions).unwrap();
        LocalPodmanSupervisor::new(path.to_string_lossy())
    }
    #[cfg(unix)]
    #[test]
    fn terminal_paths_always_report_cleanup_and_never_conformance() {
        for (mode, expected) in [
            ("success", Termination::Exited(0)),
            ("timeout", Termination::TimedOut),
            ("lost", Termination::WorkerLost),
            ("cleanup-fail", Termination::Exited(0)),
        ] {
            let receipt = fake_backend(mode)
                .execute(
                    &admitted(JobClass::Verifier),
                    &Arc::new(AtomicBool::new(false)),
                )
                .unwrap();
            assert_eq!(receipt.termination, expected);
            assert_eq!(receipt.conformance_label, "non-conformant-local");
            assert_eq!(
                receipt.cleanup,
                if mode == "cleanup-fail" {
                    CleanupOutcome::Failed
                } else {
                    CleanupOutcome::Confirmed
                }
            );
        }
        let cancelled = Arc::new(AtomicBool::new(true));
        let receipt = fake_backend("timeout")
            .execute(&admitted(JobClass::Verifier), &cancelled)
            .unwrap();
        assert_eq!(receipt.termination, Termination::Cancelled);
        assert_eq!(receipt.cleanup, CleanupOutcome::Confirmed);
    }
}
