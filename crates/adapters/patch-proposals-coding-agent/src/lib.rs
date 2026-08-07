//! Hardened provider-neutral coding-agent and visible-command adapters.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use cauterizer_patch_proposals::application::SolverPort;
use cauterizer_patch_proposals::domain::{
    PatchNormalizationService, ProposalError, SolverBrief, SolverOutput, SolverUsage,
};
use cauterizer_syntax::digest::Sha256Digest;
use serde::{Deserialize, Serialize};

/// Exact executable request; no shell command string can be represented.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessRequest {
    /// Executable path or name.
    pub program: String,
    /// Exact argument vector.
    pub arguments: Vec<String>,
    /// Canonical working directory under the configured workspace root.
    pub working_directory: PathBuf,
    /// Complete environment after `env_clear`.
    pub environment: BTreeMap<String, String>,
    /// Exact standard input.
    pub stdin: Vec<u8>,
    /// Hard elapsed-time limit.
    pub timeout: Duration,
    /// Maximum bytes retained for each output stream.
    pub output_limit: usize,
}

/// Bounded process result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessResult {
    /// Exit status code, or `None` when terminated by signal.
    pub exit_code: Option<i32>,
    /// Bounded standard output.
    pub stdout: Vec<u8>,
    /// Bounded standard error.
    pub stderr: Vec<u8>,
    /// Whether the deadline elapsed.
    pub timed_out: bool,
    /// Whether either output stream exceeded its cap.
    pub output_exceeded: bool,
}

/// Replaceable sandbox/process boundary.
pub trait ProcessPort {
    /// Executes one exact request.
    ///
    /// # Errors
    /// Returns a coarse error when execution cannot be securely established.
    fn execute(&mut self, request: &ProcessRequest) -> Result<ProcessResult, AdapterError>;
}

/// Pinned rootless OCI execution policy for untrusted commands.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OciIsolation {
    /// OCI CLI (`podman` in production).
    pub runtime: PathBuf,
    /// Immutable image reference including `@sha256:`.
    pub image: String,
    /// Numeric non-root container UID/GID (`uid:gid`).
    pub user: String,
    /// Read-only source tree mounted at `/source`.
    pub source_root: PathBuf,
    /// Isolated writable workspace mounted at `/workspace`.
    pub workspace: PathBuf,
    /// Memory limit accepted by the OCI runtime.
    pub memory: String,
    /// CPU quota accepted by the OCI runtime.
    pub cpus: String,
    /// Maximum container processes.
    pub pids_limit: u32,
}

/// Process adapter that executes exact argv inside a locked-down OCI container.
pub struct OciProcessRunner {
    policy: OciIsolation,
}
impl OciProcessRunner {
    /// Validates and pins an OCI policy.
    ///
    /// # Errors
    /// Rejects mutable images, root users, missing roots, or invalid resource limits.
    pub fn new(mut policy: OciIsolation) -> Result<Self, AdapterError> {
        policy.source_root = policy
            .source_root
            .canonicalize()
            .map_err(|_| AdapterError::InvalidRequest)?;
        policy.workspace = policy
            .workspace
            .canonicalize()
            .map_err(|_| AdapterError::InvalidRequest)?;
        let pinned = policy
            .image
            .rsplit_once("@sha256:")
            .is_some_and(|(name, digest)| {
                !name.is_empty()
                    && digest.len() == 64
                    && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            });
        if !pinned
            || !policy.runtime.is_absolute()
            || policy.runtime.file_name().and_then(|value| value.to_str()) != Some("podman")
            || policy.user.starts_with("0:")
            || policy.user == "0"
            || policy.pids_limit == 0
            || policy.memory.is_empty()
            || policy.cpus.is_empty()
            || !policy.source_root.is_dir()
            || !policy.workspace.is_dir()
        {
            return Err(AdapterError::InvalidRequest);
        }
        Ok(Self { policy })
    }

    fn argv(&self, request: &ProcessRequest) -> Result<Vec<String>, AdapterError> {
        if request.program.is_empty() || request.timeout.is_zero() || request.output_limit == 0 {
            return Err(AdapterError::InvalidRequest);
        }
        let cwd = request
            .working_directory
            .canonicalize()
            .map_err(|_| AdapterError::InvalidRequest)?;
        let container_cwd = if let Ok(relative) = cwd.strip_prefix(&self.policy.workspace) {
            Path::new("/workspace").join(relative)
        } else if let Ok(relative) = cwd.strip_prefix(&self.policy.source_root) {
            Path::new("/source").join(relative)
        } else {
            return Err(AdapterError::PathEscape);
        };
        let mut argv = vec![
            "run".into(),
            "--rm".into(),
            "--network=none".into(),
            "--read-only".into(),
            "--cap-drop=ALL".into(),
            "--security-opt=no-new-privileges".into(),
            format!("--pids-limit={}", self.policy.pids_limit),
            format!("--memory={}", self.policy.memory),
            format!("--cpus={}", self.policy.cpus),
            format!("--user={}", self.policy.user),
            "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m".into(),
            "--tmpfs=/source/.git:ro,noexec,nosuid,nodev,size=1m".into(),
            format!("--volume={}:/source:ro", self.policy.source_root.display()),
            format!("--volume={}:/workspace:rw", self.policy.workspace.display()),
            format!("--workdir={}", container_cwd.display()),
        ];
        for (name, value) in &request.environment {
            if !matches!(name.as_str(), "PATH" | "LC_ALL" | "LANG" | "TZ") || value.contains('\n') {
                return Err(AdapterError::InvalidRequest);
            }
            argv.push(format!("--env={name}={value}"));
        }
        argv.push(self.policy.image.clone());
        argv.push(request.program.clone());
        argv.extend(request.arguments.clone());
        Ok(argv)
    }
}
impl ProcessPort for OciProcessRunner {
    fn execute(&mut self, request: &ProcessRequest) -> Result<ProcessResult, AdapterError> {
        let argv = self.argv(request)?;
        let mut local = LocalCommandRunner::new("/")?;
        local.execute(&ProcessRequest {
            program: self.policy.runtime.to_string_lossy().into_owned(),
            arguments: argv,
            working_directory: PathBuf::from("/"),
            environment: BTreeMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
            stdin: request.stdin.clone(),
            timeout: request.timeout,
            output_limit: request.output_limit,
        })
    }
}

/// Local command runner with cwd confinement, cleared environment, timeout, and output caps.
pub struct LocalCommandRunner {
    root: PathBuf,
}
impl LocalCommandRunner {
    /// Pins a canonical workspace root.
    ///
    /// # Errors
    /// Rejects a missing or non-directory root.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, AdapterError> {
        let root = root
            .as_ref()
            .canonicalize()
            .map_err(|_| AdapterError::InvalidRequest)?;
        if !root.is_dir() {
            return Err(AdapterError::InvalidRequest);
        }
        Ok(Self { root })
    }
}
impl ProcessPort for LocalCommandRunner {
    fn execute(&mut self, request: &ProcessRequest) -> Result<ProcessResult, AdapterError> {
        if request.program.is_empty() || request.timeout.is_zero() || request.output_limit == 0 {
            return Err(AdapterError::InvalidRequest);
        }
        let cwd = request
            .working_directory
            .canonicalize()
            .map_err(|_| AdapterError::InvalidRequest)?;
        if !cwd.starts_with(&self.root) {
            return Err(AdapterError::PathEscape);
        }
        let mut child = Command::new(&request.program)
            .args(&request.arguments)
            .current_dir(cwd)
            .env_clear()
            .envs(&request.environment)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| AdapterError::ProcessUnavailable)?;
        child
            .stdin
            .take()
            .ok_or(AdapterError::ProcessUnavailable)?
            .write_all(&request.stdin)
            .map_err(|_| AdapterError::ProcessUnavailable)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(AdapterError::ProcessUnavailable)?;
        let stderr = child
            .stderr
            .take()
            .ok_or(AdapterError::ProcessUnavailable)?;
        let limit = request.output_limit;
        let out = thread::spawn(move || bounded_read(stdout, limit));
        let err = thread::spawn(move || bounded_read(stderr, limit));
        let started = Instant::now();
        let (status, timed_out) = loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|_| AdapterError::ProcessUnavailable)?
            {
                break (status, false);
            }
            if started.elapsed() >= request.timeout {
                child.kill().map_err(|_| AdapterError::ProcessUnavailable)?;
                break (
                    child.wait().map_err(|_| AdapterError::ProcessUnavailable)?,
                    true,
                );
            }
            thread::sleep(Duration::from_millis(5));
        };
        let (stdout, stdout_over) = out.join().map_err(|_| AdapterError::ProcessUnavailable)??;
        let (stderr, stderr_over) = err.join().map_err(|_| AdapterError::ProcessUnavailable)??;
        Ok(ProcessResult {
            exit_code: status.code(),
            stdout,
            stderr,
            timed_out,
            output_exceeded: stdout_over || stderr_over,
        })
    }
}

fn bounded_read(reader: impl Read, limit: usize) -> Result<(Vec<u8>, bool), AdapterError> {
    let mut bytes = Vec::new();
    reader
        .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| AdapterError::ProcessUnavailable)?;
    let exceeded = bytes.len() > limit;
    bytes.truncate(limit);
    Ok((bytes, exceeded))
}

#[derive(Serialize)]
struct SolverRequest<'a> {
    protocol: &'static str,
    brief: &'a SolverBrief,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SolverResponse {
    patch: String,
    tokens: u64,
    cost_micros: u64,
    time_millis: u64,
    provenance: Sha256Digest,
    rationale: Option<String>,
}

/// Canonical-JSON coding-agent adapter implementing the Patch Proposals solver port.
pub struct CodingAgentAdapter<P> {
    process: P,
    command: ProcessRequest,
}
impl<P> CodingAgentAdapter<P> {
    /// Constructs an adapter from a fully constrained process template.
    #[must_use]
    pub const fn new(process: P, command: ProcessRequest) -> Self {
        Self { process, command }
    }
}
impl<P: ProcessPort> SolverPort for CodingAgentAdapter<P> {
    fn solve(&mut self, brief: &SolverBrief) -> Result<SolverOutput, ProposalError> {
        brief.validate()?;
        self.command.stdin = serde_json::to_vec(&SolverRequest {
            protocol: "cauterizer.coding-agent.v1",
            brief,
        })
        .map_err(|_| ProposalError::ProviderUnavailable)?;
        let result = self
            .process
            .execute(&self.command)
            .map_err(|_| ProposalError::ProviderUnavailable)?;
        if result.timed_out || result.output_exceeded || result.exit_code != Some(0) {
            return Err(ProposalError::ProviderUnavailable);
        }
        let response: SolverResponse = serde_json::from_slice(&result.stdout)
            .map_err(|_| ProposalError::ProviderUnavailable)?;
        let patch = PatchNormalizationService::normalize(response.patch.as_bytes(), brief)?;
        Ok(SolverOutput {
            patch: patch.as_bytes().to_vec(),
            rationale: response.rationale,
            usage: SolverUsage {
                tokens: response.tokens,
                cost_micros: response.cost_micros,
                time_millis: response.time_millis,
            },
            solver_provenance: response.provenance,
        })
    }
}

/// One exact visible build/lint/test command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VisibleCommand {
    /// Stable non-secret label.
    pub label: String,
    /// Constrained process request.
    pub process: ProcessRequest,
}
/// Sanitized visible evaluation result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VisibleResult {
    /// All configured commands passed.
    Passed,
    /// Safe bounded diagnostics for solver retry.
    Failed(Vec<u8>),
    /// Execution did not produce trustworthy feedback.
    Inconclusive,
}
/// Runs solver-visible checks only; hidden inputs cannot be supplied.
pub struct VisibleCommandEvaluator<P> {
    process: P,
    commands: Vec<VisibleCommand>,
    diagnostic_limit: usize,
}
impl<P: ProcessPort> VisibleCommandEvaluator<P> {
    /// Constructs the visible evaluator.
    #[must_use]
    pub const fn new(process: P, commands: Vec<VisibleCommand>, diagnostic_limit: usize) -> Self {
        Self {
            process,
            commands,
            diagnostic_limit,
        }
    }
    /// Runs configured commands in order and returns redacted bounded diagnostics.
    ///
    /// # Errors
    /// Returns a coarse error if constraints are invalid or execution is unavailable.
    pub fn evaluate(&mut self) -> Result<VisibleResult, AdapterError> {
        if self.commands.is_empty() || self.diagnostic_limit == 0 {
            return Err(AdapterError::InvalidRequest);
        }
        for command in &self.commands {
            let result = self.process.execute(&command.process)?;
            if result.timed_out || result.output_exceeded {
                return Ok(VisibleResult::Inconclusive);
            }
            if result.exit_code != Some(0) {
                let mut diagnostic = format!("{}: command failed\n", command.label).into_bytes();
                diagnostic.extend_from_slice(&sanitize(
                    &result.stderr,
                    self.diagnostic_limit.saturating_sub(diagnostic.len()),
                ));
                diagnostic.truncate(self.diagnostic_limit);
                return Ok(VisibleResult::Failed(diagnostic));
            }
        }
        Ok(VisibleResult::Passed)
    }
}
fn sanitize(bytes: &[u8], limit: usize) -> Vec<u8> {
    let value = String::from_utf8_lossy(bytes);
    let mut output = value
        .lines()
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            if [
                "authorization:",
                "bearer ",
                "api_key",
                "access_token",
                "private_key",
            ]
            .iter()
            .any(|term| lower.contains(term))
            {
                "[REDACTED]"
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    output.truncate(limit);
    output
}

/// Stable adapter error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterError {
    /// Invalid constraints.
    InvalidRequest,
    /// Working directory escaped its root.
    PathEscape,
    /// Process could not be safely executed.
    ProcessUnavailable,
}
impl std::fmt::Display for AdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("coding agent unavailable")
    }
}
impl std::error::Error for AdapterError {}

#[cfg(test)]
mod tests {
    use super::*;
    use cauterizer_patch_proposals::domain::ProposalBudget;
    use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
    use std::collections::{BTreeSet, VecDeque};

    struct Fake(VecDeque<ProcessResult>);
    impl ProcessPort for Fake {
        fn execute(&mut self, _: &ProcessRequest) -> Result<ProcessResult, AdapterError> {
            Ok(self.0.pop_front().unwrap())
        }
    }
    fn brief() -> SolverBrief {
        SolverBrief {
            organization_id: OrganizationId::new("organization1").unwrap(),
            run_id: ContextQualifiedId::new("run", "00000001").unwrap(),
            problem: "fix public failure".into(),
            source_digest: Sha256Digest::of_bytes(b"source"),
            public_test_instructions: vec!["test".into()],
            allowed_paths: BTreeSet::from(["src/lib.rs".into()]),
            allowed_tools: BTreeSet::from(["patch".into()]),
            budget: ProposalBudget {
                attempts: 2,
                tokens: 100,
                cost_micros: 100,
                time_millis: 1000,
                paths: 1,
                patch_bytes: 1024,
                changed_lines: 10,
            },
            memory_namespace: None,
        }
    }
    fn request(root: &Path) -> ProcessRequest {
        ProcessRequest {
            program: "true".into(),
            arguments: vec![],
            working_directory: root.into(),
            environment: BTreeMap::new(),
            stdin: vec![],
            timeout: Duration::from_secs(1),
            output_limit: 4096,
        }
    }
    fn result(stdout: Vec<u8>) -> ProcessResult {
        ProcessResult {
            exit_code: Some(0),
            stdout,
            stderr: vec![],
            timed_out: false,
            output_exceeded: false,
        }
    }

    #[test]
    fn oci_policy_is_pinned_non_root_and_preserves_exact_argv() {
        let source = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let runner = OciProcessRunner::new(OciIsolation {
            runtime: "/usr/bin/podman".into(),
            image: "registry.invalid/solver@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            user: "65532:65532".into(),
            source_root: source.path().into(),
            workspace: workspace.path().into(),
            memory: "512m".into(),
            cpus: "1".into(),
            pids_limit: 64,
        }).unwrap();
        let mut process = request(workspace.path());
        process.program = "/opt/agent".into();
        process.arguments = vec!["literal;not-shell".into(), "$(touch /tmp/pwned)".into()];
        process.environment.insert("PATH".into(), "/usr/bin".into());
        let argv = runner.argv(&process).unwrap();
        for required in [
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user=65532:65532",
        ] {
            assert!(argv.iter().any(|value| value == required));
        }
        assert_eq!(
            &argv[argv.len() - 3..],
            ["/opt/agent", "literal;not-shell", "$(touch /tmp/pwned)"]
        );
        process
            .environment
            .insert("GITHUB_TOKEN".into(), "secret".into());
        assert_eq!(runner.argv(&process), Err(AdapterError::InvalidRequest));
        assert!(
            OciProcessRunner::new(OciIsolation {
                runtime: "podman".into(),
                image: "mutable:latest".into(),
                user: "0:0".into(),
                source_root: source.path().into(),
                workspace: workspace.path().into(),
                memory: "1g".into(),
                cpus: "1".into(),
                pids_limit: 1,
            })
            .is_err()
        );
    }

    #[test]
    fn live_rootless_oci_probe_when_configured() {
        let Ok(image) = std::env::var("CAUTERIZER_TEST_OCI_IMAGE") else {
            return;
        };
        let source = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let runtime = std::env::var("CAUTERIZER_TEST_OCI_RUNTIME")
            .unwrap_or_else(|_| "/usr/bin/podman".into());
        let mut runner = OciProcessRunner::new(OciIsolation {
            runtime: runtime.into(),
            image,
            user: "65532:65532".into(),
            source_root: source.path().into(),
            workspace: workspace.path().into(),
            memory: "128m".into(),
            cpus: "0.5".into(),
            pids_limit: 16,
        })
        .unwrap();
        let mut probe = request(workspace.path());
        probe.program = "/bin/sh".into();
        probe.arguments = vec![
            "-c".into(),
            "test ! -e /run/secrets && test ! -w / && test ! -e /source/.git/config".into(),
        ];
        let result = runner.execute(&probe).unwrap();
        assert_eq!(result.exit_code, Some(0));
        assert!(!result.timed_out && !result.output_exceeded);
    }

    #[test]
    fn canonical_protocol_accepts_only_valid_normalized_patch() {
        let patch = "--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-old\n+new\n";
        let json = serde_json::json!({"patch":patch,"tokens":1,"cost_micros":0,"time_millis":1,"provenance":Sha256Digest::of_bytes(b"agent"),"rationale":"public build repair"});
        let mut adapter = CodingAgentAdapter::new(
            Fake(VecDeque::from([result(serde_json::to_vec(&json).unwrap())])),
            request(Path::new(".")),
        );
        assert!(adapter.solve(&brief()).is_ok());
    }

    #[test]
    fn timeout_output_exit_malformed_and_traversal_fail_closed() {
        let base = result(b"not-json".to_vec());
        for value in [
            ProcessResult {
                timed_out: true,
                ..base.clone()
            },
            ProcessResult {
                output_exceeded: true,
                ..base.clone()
            },
            ProcessResult {
                exit_code: Some(2),
                ..base.clone()
            },
            base,
        ] {
            let mut adapter =
                CodingAgentAdapter::new(Fake(VecDeque::from([value])), request(Path::new(".")));
            assert_eq!(
                adapter.solve(&brief()),
                Err(ProposalError::ProviderUnavailable)
            );
        }
        let json = serde_json::json!({"patch":"--- a/../x\n+++ b/../x\n@@ -1 +1 @@\n-a\n+b\n","tokens":1,"cost_micros":0,"time_millis":1,"provenance":Sha256Digest::of_bytes(b"agent"),"rationale":null});
        let mut adapter = CodingAgentAdapter::new(
            Fake(VecDeque::from([result(serde_json::to_vec(&json).unwrap())])),
            request(Path::new(".")),
        );
        assert_eq!(adapter.solve(&brief()), Err(ProposalError::ForbiddenPath));
    }

    #[test]
    fn visible_diagnostics_are_bounded_and_secret_redacted() {
        let failed = ProcessResult {
            exit_code: Some(1),
            stdout: vec![],
            stderr: b"Authorization: bearer secret\nordinary failure".to_vec(),
            timed_out: false,
            output_exceeded: false,
        };
        let mut evaluator = VisibleCommandEvaluator::new(
            Fake(VecDeque::from([failed])),
            vec![VisibleCommand {
                label: "test".into(),
                process: request(Path::new(".")),
            }],
            100,
        );
        let VisibleResult::Failed(bytes) = evaluator.evaluate().unwrap() else {
            panic!("expected failure")
        };
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("[REDACTED]"));
        assert!(!text.contains("secret"));
        assert!(text.len() <= 100);
    }

    #[test]
    fn local_runner_executes_exact_harmless_command_and_confines_cwd() {
        let root = std::env::current_dir().unwrap();
        let mut runner = LocalCommandRunner::new(&root).unwrap();
        let mut exact = request(&root);
        exact.program = "printf".into();
        exact.arguments = vec!["%s".into(), "hello".into()];
        assert_eq!(runner.execute(&exact).unwrap().stdout, b"hello");
        exact.working_directory = root.parent().unwrap().into();
        assert_eq!(runner.execute(&exact), Err(AdapterError::PathEscape));
    }
}
