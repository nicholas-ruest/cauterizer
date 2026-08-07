//! Safe local Git commit production with no push, merge, or credential authority.
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use cauterizer_integration_management::contracts::{
    CandidatePatch, GitCommitOid, GitCommitTransfer, GitFileObject,
};
use cauterizer_syntax::digest::Sha256Digest;

const OUTPUT_LIMIT: u64 = 256 * 1024;
const TIMEOUT: Duration = Duration::from_secs(120);

/// One visible check executed after patch application and before commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VisibleCheck {
    /// Exact executable, resolved by the parent process.
    pub program: String,
    /// Exact arguments without shell interpretation.
    pub args: Vec<String>,
}

/// Executes visible commands against an already patched disposable worktree.
pub trait CandidateCheckExecutor {
    /// Runs every check without granting SCM or host authority.
    ///
    /// # Errors
    /// Returns a coarse check failure or unavailable result.
    fn execute(&mut self, worktree: &Path, checks: &[VisibleCheck]) -> Result<(), PublishError>;
}

struct HostCheckExecutor;
impl CandidateCheckExecutor for HostCheckExecutor {
    fn execute(&mut self, worktree: &Path, checks: &[VisibleCheck]) -> Result<(), PublishError> {
        for check in checks {
            if check.program.is_empty() || run(&check.program, &check.args, worktree)?.status != 0 {
                return Err(PublishError::CheckFailed);
            }
        }
        Ok(())
    }
}

/// Commit produced locally for a previously validated candidate patch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedCommit {
    /// Real Git commit object ID.
    pub commit_oid: GitCommitOid,
    /// Independent Cauterizer candidate identity.
    pub candidate_digest: Sha256Digest,
    /// Material for reproducing this commit through a remote Git object API.
    pub transfer: GitCommitTransfer,
}

/// Immutable identities embedded in the deterministic machine commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationIdentity {
    /// Context-qualified remediation run identity.
    pub run_id: String,
    /// Digest of the evidence bundle retained for review.
    pub evidence_digest: Sha256Digest,
}

impl PublicationIdentity {
    fn message(&self, candidate: Sha256Digest) -> Result<String, PublishError> {
        if self.run_id.is_empty()
            || self.run_id.len() > 128
            || !self
                .run_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_'))
        {
            return Err(PublishError::InvalidPatch);
        }
        Ok(format!(
            "Automated vulnerability remediation\n\nCauterizer-Run: {}\nCauterizer-Candidate: {}\nCauterizer-Evidence: {}",
            self.run_id,
            candidate.to_tagged_hex(),
            self.evidence_digest.to_tagged_hex()
        ))
    }
}

/// Fail-closed publisher error without command output or credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishError {
    /// Checkout is dirty, malformed, or not at the immutable base.
    InvalidCheckout,
    /// Patch touches a prohibited filesystem object or cannot apply.
    InvalidPatch,
    /// Caller-visible validation failed.
    CheckFailed,
    /// A bounded subprocess timed out or infrastructure failed.
    Unavailable,
    /// Another publisher owns the checkout lease.
    Busy,
}

impl std::fmt::Display for PublishError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl std::error::Error for PublishError {}

/// Produces a local commit from a clean immutable checkout.
///
/// This API cannot push, merge, sign, or access a credential helper.
///
/// # Errors
/// Rejects dirty/wrong-base repositories, unsafe paths, failed patch/checks,
/// timeouts, excessive output, or invalid Git results.
pub fn publish(
    checkout: &Path,
    base: &GitCommitOid,
    patch: &CandidatePatch,
    branch: &str,
    checks: &[VisibleCheck],
) -> Result<PublishedCommit, PublishError> {
    publish_with_identity(checkout, base, patch, branch, checks, None)
}

/// Produces a deterministic commit whose message binds the run, candidate, and evidence.
///
/// # Errors
/// Rejects dirty/wrong-base repositories, unsafe paths, failed patch/checks,
/// timeouts, excessive output, or invalid Git results.
pub fn publish_bound(
    checkout: &Path,
    base: &GitCommitOid,
    patch: &CandidatePatch,
    branch: &str,
    checks: &[VisibleCheck],
    identity: &PublicationIdentity,
) -> Result<PublishedCommit, PublishError> {
    publish_with_identity(checkout, base, patch, branch, checks, Some(identity))
}

/// Applies a candidate in an isolated worktree and runs visible checks without
/// creating a commit or branch.
///
/// # Errors
/// Uses the same fail-closed checkout, patch, timeout, hook, and path policy as
/// [`publish_verified`].
pub fn evaluate_candidate(
    checkout: &Path,
    base: &GitCommitOid,
    patch: &CandidatePatch,
    checks: &[VisibleCheck],
) -> Result<(), PublishError> {
    evaluate_candidate_with(checkout, base, patch, checks, &mut HostCheckExecutor)
}

/// Applies a candidate and delegates checks to an injected isolation boundary.
///
/// # Errors
/// Fails closed for checkout, patch, executor, or cleanup failures.
pub fn evaluate_candidate_with(
    checkout: &Path,
    base: &GitCommitOid,
    patch: &CandidatePatch,
    checks: &[VisibleCheck],
    executor: &mut dyn CandidateCheckExecutor,
) -> Result<(), PublishError> {
    if !checkout.is_dir() || patch_paths(patch.as_bytes())? != *patch.paths() {
        return Err(PublishError::InvalidPatch);
    }
    let root = fs::canonicalize(checkout).map_err(|_| PublishError::InvalidCheckout)?;
    let _lock = CheckoutLock::acquire(&root)?;
    validate_checkout(&root, base, patch)?;
    let temporary = tempfile::Builder::new()
        .prefix("cauterizer-evaluation-")
        .tempdir()
        .map_err(|_| PublishError::Unavailable)?;
    let worktree = temporary.path().join("tree");
    git(
        &root,
        &[
            "worktree",
            "add",
            "--detach",
            path_text(&worktree)?,
            base.as_str(),
        ],
    )?;
    let result = apply_patch(&worktree, patch).and_then(|()| executor.execute(&worktree, checks));
    let _ = git(
        &root,
        &[
            "worktree",
            "remove",
            "--force",
            path_text(&worktree).unwrap_or(""),
        ],
    );
    result
}

/// Publishes a candidate only after the caller supplies verified evidence identity.
///
/// # Errors
/// Rejects invalid identities, unsafe checkout or patch state, failed Git
/// operations, or a conflicting pre-existing remediation branch.
pub fn publish_verified(
    checkout: &Path,
    base: &GitCommitOid,
    patch: &CandidatePatch,
    branch: &str,
    identity: &PublicationIdentity,
) -> Result<PublishedCommit, PublishError> {
    publish_bound(checkout, base, patch, branch, &[], identity)
}

fn publish_with_identity(
    checkout: &Path,
    base: &GitCommitOid,
    patch: &CandidatePatch,
    branch: &str,
    checks: &[VisibleCheck],
    identity: Option<&PublicationIdentity>,
) -> Result<PublishedCommit, PublishError> {
    if !safe_branch(branch) || !checkout.is_dir() {
        return Err(PublishError::InvalidCheckout);
    }
    if patch_paths(patch.as_bytes())? != *patch.paths() {
        return Err(PublishError::InvalidPatch);
    }
    let root = fs::canonicalize(checkout).map_err(|_| PublishError::InvalidCheckout)?;
    let _lock = CheckoutLock::acquire(&root)?;
    if !git(
        &root,
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?
    .stdout
    .is_empty()
        || text(git(&root, &["rev-parse", "HEAD"])?)? != base.as_str()
        || text(git(&root, &["rev-parse", "--show-toplevel"])?)? != root.to_string_lossy()
        || root.join(".gitmodules").exists()
    {
        return Err(PublishError::InvalidCheckout);
    }
    for path in patch.paths() {
        let target = root.join(path);
        if target
            .symlink_metadata()
            .is_ok_and(|meta| meta.file_type().is_symlink())
        {
            return Err(PublishError::InvalidPatch);
        }
        if let Some(parent) = target.parent() {
            let mut cursor = parent;
            while cursor.starts_with(&root) && cursor != root {
                if cursor
                    .symlink_metadata()
                    .is_ok_and(|meta| meta.file_type().is_symlink())
                {
                    return Err(PublishError::InvalidPatch);
                }
                cursor = cursor.parent().ok_or(PublishError::InvalidPatch)?;
            }
        }
    }

    let temporary = tempfile::Builder::new()
        .prefix("cauterizer-worktree-")
        .tempdir()
        .map_err(|_| PublishError::Unavailable)?;
    let worktree = temporary.path().join("tree");
    let branch_ref = format!("refs/heads/{branch}");
    git(
        &root,
        &[
            "worktree",
            "add",
            "--detach",
            path_text(&worktree)?,
            base.as_str(),
        ],
    )?;
    let message = identity.map_or_else(
        || Ok("Automated vulnerability remediation".to_owned()),
        |identity| identity.message(patch.digest()),
    )?;
    let result = publish_in_worktree(&worktree, &branch_ref, base, patch, checks, &message);
    let _ = git(
        &root,
        &[
            "worktree",
            "remove",
            "--force",
            path_text(&worktree).unwrap_or(""),
        ],
    );
    result
}

fn validate_checkout(
    root: &Path,
    base: &GitCommitOid,
    patch: &CandidatePatch,
) -> Result<(), PublishError> {
    if !git(root, &["status", "--porcelain=v1", "--untracked-files=all"])?
        .stdout
        .is_empty()
        || text(git(root, &["rev-parse", "HEAD"])?)? != base.as_str()
        || text(git(root, &["rev-parse", "--show-toplevel"])?)? != root.to_string_lossy()
        || root.join(".gitmodules").exists()
    {
        return Err(PublishError::InvalidCheckout);
    }
    for path in patch.paths() {
        let target = root.join(path);
        if target
            .symlink_metadata()
            .is_ok_and(|meta| meta.file_type().is_symlink())
        {
            return Err(PublishError::InvalidPatch);
        }
        if let Some(parent) = target.parent() {
            let mut cursor = parent;
            while cursor.starts_with(root) && cursor != root {
                if cursor
                    .symlink_metadata()
                    .is_ok_and(|meta| meta.file_type().is_symlink())
                {
                    return Err(PublishError::InvalidPatch);
                }
                cursor = cursor.parent().ok_or(PublishError::InvalidPatch)?;
            }
        }
    }
    Ok(())
}

/// Deletes an unpublished remediation branch only when it still names the exact
/// candidate commit produced by this publisher.
///
/// # Errors
/// Refuses unsafe branches, dirty/invalid checkouts, or a branch that was moved
/// by another actor. A missing branch is an idempotent success.
pub fn discard_candidate(
    checkout: &Path,
    branch: &str,
    expected: &GitCommitOid,
) -> Result<(), PublishError> {
    if !safe_branch(branch) || !checkout.is_dir() {
        return Err(PublishError::InvalidCheckout);
    }
    let root = fs::canonicalize(checkout).map_err(|_| PublishError::InvalidCheckout)?;
    let _lock = CheckoutLock::acquire(&root)?;
    let reference = format!("refs/heads/{branch}");
    let mut arguments = vec![
        "-c".to_owned(),
        "core.hooksPath=/dev/null".to_owned(),
        "-c".to_owned(),
        "credential.helper=".to_owned(),
    ];
    arguments.extend(["rev-parse".to_owned(), "--verify".to_owned(), reference]);
    let observed = run("git", &arguments, &root)?;
    if observed.status != 0 {
        return Ok(());
    }
    if text(observed)? != expected.as_str() {
        return Err(PublishError::InvalidCheckout);
    }
    git(&root, &["branch", "-D", branch])?;
    Ok(())
}

fn publish_in_worktree(
    worktree: &Path,
    branch_ref: &str,
    base: &GitCommitOid,
    patch: &CandidatePatch,
    checks: &[VisibleCheck],
    commit_message: &str,
) -> Result<PublishedCommit, PublishError> {
    apply_and_check(worktree, patch, checks)?;
    git(
        worktree,
        &[
            "-c",
            "user.name=Cauterizer",
            "-c",
            "user.email=cauterizer@invalid",
            "-c",
            "commit.gpgSign=false",
            "commit",
            "--no-gpg-sign",
            "--no-verify",
            "-m",
            commit_message,
        ],
    )?;
    let oid = text(git(worktree, &["rev-parse", "HEAD"])?)?;
    let branch = branch_ref.trim_start_matches("refs/heads/");
    let existing = run(
        "git",
        &[
            "-c".into(),
            "core.hooksPath=/dev/null".into(),
            "-c".into(),
            "credential.helper=".into(),
            "rev-parse".into(),
            "--verify".into(),
            branch_ref.into(),
        ],
        worktree,
    )?;
    if existing.status == 0 {
        if text(existing)? != oid {
            return Err(PublishError::InvalidCheckout);
        }
    } else {
        git(worktree, &["branch", branch, &oid])?;
    }
    let files = patch
        .paths()
        .iter()
        .map(|path| {
            fs::read(worktree.join(path))
                .map(|content| GitFileObject {
                    path: path.clone(),
                    content,
                    executable: is_executable(&worktree.join(path)),
                })
                .map_err(|_| PublishError::InvalidPatch)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PublishedCommit {
        commit_oid: GitCommitOid::parse(oid).ok_or(PublishError::Unavailable)?,
        candidate_digest: patch.digest(),
        transfer: GitCommitTransfer {
            base_commit_oid: base.clone(),
            commit_message: commit_message.to_owned(),
            files,
        },
    })
}

fn apply_and_check(
    worktree: &Path,
    patch: &CandidatePatch,
    checks: &[VisibleCheck],
) -> Result<(), PublishError> {
    apply_patch(worktree, patch)?;
    HostCheckExecutor.execute(worktree, checks)
}

fn apply_patch(worktree: &Path, patch: &CandidatePatch) -> Result<(), PublishError> {
    let patch_file = tempfile::NamedTempFile::new().map_err(|_| PublishError::Unavailable)?;
    fs::write(patch_file.path(), patch.as_bytes()).map_err(|_| PublishError::Unavailable)?;
    let patch_path = path_text(patch_file.path())?;
    git(
        worktree,
        &[
            "apply",
            "--check",
            "--index",
            "--whitespace=error-all",
            patch_path,
        ],
    )?;
    git(
        worktree,
        &["apply", "--index", "--whitespace=error-all", patch_path],
    )?;
    Ok(())
}

struct Outcome {
    status: i32,
    stdout: Vec<u8>,
}
fn git(cwd: &Path, args: &[&str]) -> Result<Outcome, PublishError> {
    let mut complete = vec!["-c", "core.hooksPath=/dev/null", "-c", "credential.helper="];
    complete.extend_from_slice(args);
    run(
        "git",
        &complete
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>(),
        cwd,
    )
    .and_then(|outcome| {
        if outcome.status == 0 {
            Ok(outcome)
        } else {
            Err(PublishError::InvalidPatch)
        }
    })
}
fn run(program: &str, args: &[String], cwd: &Path) -> Result<Outcome, PublishError> {
    let stdout = tempfile::tempfile().map_err(|_| PublishError::Unavailable)?;
    let stderr = tempfile::tempfile().map_err(|_| PublishError::Unavailable)?;
    let mut child = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/nonexistent")
        .env("LC_ALL", "C")
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00Z")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00Z")
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            stdout.try_clone().map_err(|_| PublishError::Unavailable)?,
        ))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|_| PublishError::Unavailable)?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|_| PublishError::Unavailable)? {
            break status;
        }
        if started.elapsed() >= TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(PublishError::Unavailable);
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let size = stdout
        .metadata()
        .map_err(|_| PublishError::Unavailable)?
        .len();
    if size > OUTPUT_LIMIT {
        return Err(PublishError::Unavailable);
    }
    let mut stdout = stdout;
    stdout.rewind().map_err(|_| PublishError::Unavailable)?;
    let mut bytes = Vec::new();
    stdout
        .read_to_end(&mut bytes)
        .map_err(|_| PublishError::Unavailable)?;
    Ok(Outcome {
        status: status.code().unwrap_or(-1),
        stdout: bytes,
    })
}
fn text(outcome: Outcome) -> Result<String, PublishError> {
    String::from_utf8(outcome.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| PublishError::Unavailable)
}
fn path_text(path: &Path) -> Result<&str, PublishError> {
    path.to_str().ok_or(PublishError::InvalidCheckout)
}
fn safe_branch(value: &str) -> bool {
    value.starts_with("cauterizer/")
        && !value.contains("..")
        && !value.contains([' ', '~', '^', ':', '?', '*', '[', '\\'])
}

struct CheckoutLock {
    file: File,
}
impl CheckoutLock {
    fn acquire(root: &Path) -> Result<Self, PublishError> {
        let git_dir = root.join(".git");
        if !git_dir.is_dir()
            || git_dir
                .symlink_metadata()
                .is_ok_and(|meta| meta.file_type().is_symlink())
        {
            return Err(PublishError::InvalidCheckout);
        }
        let path = git_dir.join("cauterizer-publish.lock");
        if path.symlink_metadata().is_ok_and(|metadata| {
            !metadata.file_type().is_file() || metadata.file_type().is_symlink()
        }) {
            return Err(PublishError::InvalidCheckout);
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options.open(&path).map_err(|_| PublishError::Unavailable)?;
        if !file
            .metadata()
            .is_ok_and(|metadata| metadata.file_type().is_file())
        {
            return Err(PublishError::InvalidCheckout);
        }
        let deadline = Instant::now() + Duration::from_millis(100);
        loop {
            match fs2::FileExt::try_lock_exclusive(&file) {
                Ok(()) => return Ok(Self { file }),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(PublishError::Busy);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return Err(PublishError::Unavailable),
            }
        }
    }
}
impl Drop for CheckoutLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    fn command(root: &Path, arguments: &[&str]) {
        assert!(
            Command::new("git")
                .args(arguments)
                .current_dir(root)
                .status()
                .unwrap()
                .success()
        );
    }

    #[test]
    fn discard_deletes_only_the_exact_owned_branch_and_is_idempotent() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        command(root, &["init", "-q"]);
        fs::write(root.join("README"), "base\n").unwrap();
        command(root, &["add", "README"]);
        command(
            root,
            &[
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@invalid",
                "commit",
                "-qm",
                "base",
            ],
        );
        command(root, &["branch", "cauterizer/candidate"]);
        let oid = text(git(root, &["rev-parse", "HEAD"]).unwrap()).unwrap();
        let oid = GitCommitOid::parse(oid).unwrap();
        discard_candidate(root, "cauterizer/candidate", &oid).unwrap();
        discard_candidate(root, "cauterizer/candidate", &oid).unwrap();
        command(root, &["branch", "cauterizer/candidate"]);
        let wrong = GitCommitOid::parse("0123456789abcdef0123456789abcdef01234567").unwrap();
        assert_eq!(
            discard_candidate(root, "cauterizer/candidate", &wrong),
            Err(PublishError::InvalidCheckout)
        );
        assert!(
            git(
                root,
                &["rev-parse", "--verify", "refs/heads/cauterizer/candidate"]
            )
            .is_ok()
        );
    }

    #[test]
    fn publish_reuses_exact_deterministic_candidate_after_preplan_crash() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        command(root, &["init", "-q"]);
        fs::write(root.join("README"), "base\n").unwrap();
        command(root, &["add", "README"]);
        command(
            root,
            &[
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@invalid",
                "commit",
                "-qm",
                "base",
            ],
        );
        let base =
            GitCommitOid::parse(text(git(root, &["rev-parse", "HEAD"]).unwrap()).unwrap()).unwrap();
        let bytes = b"diff --git a/README b/README\nindex df967b9..a7453f0 100644\n--- a/README\n+++ b/README\n@@ -1 +1 @@\n-base\n+fixed\n".to_vec();
        let patch = CandidatePatch::from_normalized(bytes, BTreeSet::from(["README".into()]));
        let first = publish(root, &base, &patch, "cauterizer/candidate", &[]).unwrap();
        let replay = publish(root, &base, &patch, "cauterizer/candidate", &[]).unwrap();
        assert_eq!(first, replay);
    }
}
fn patch_paths(bytes: &[u8]) -> Result<BTreeSet<String>, PublishError> {
    let text = std::str::from_utf8(bytes).map_err(|_| PublishError::InvalidPatch)?;
    let mut paths = BTreeSet::new();
    for line in text.lines().filter(|line| line.starts_with("+++ ")) {
        let raw = line
            .strip_prefix("+++ b/")
            .ok_or(PublishError::InvalidPatch)?;
        let path = raw.split('\t').next().ok_or(PublishError::InvalidPatch)?;
        if path.is_empty()
            || path.starts_with('/')
            || path.split('/').any(|part| {
                part.is_empty() || part == "." || part == ".." || part.eq_ignore_ascii_case(".git")
            })
        {
            return Err(PublishError::InvalidPatch);
        }
        paths.insert(path.to_owned());
    }
    if paths.is_empty() {
        return Err(PublishError::InvalidPatch);
    }
    Ok(paths)
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
}
#[cfg(not(unix))]
fn is_executable(_: &Path) -> bool {
    false
}
