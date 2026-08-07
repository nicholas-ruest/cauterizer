//! End-to-end local Git publisher tests.

use cauterizer_git_workspace_publisher::{
    PublicationIdentity, PublishError, VisibleCheck, evaluate_candidate, publish, publish_verified,
};
use cauterizer_integration_management::contracts::{CandidatePatch, GitCommitOid};
use cauterizer_syntax::digest::Sha256Digest;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}

#[test]
fn evaluation_creates_no_ref_and_verified_commit_binds_exact_identities() {
    let repo = repository();
    let base = head(repo.path());
    evaluate_candidate(repo.path(), &base, &patch(), &[]).unwrap();
    assert!(
        git(
            repo.path(),
            &[
                "for-each-ref",
                "--format=%(refname)",
                "refs/heads/cauterizer/"
            ]
        )
        .is_empty()
    );
    let identity = PublicationIdentity {
        run_id: "run:00000001".into(),
        evidence_digest: Sha256Digest::of_bytes(b"verified-evidence"),
    };
    let published = publish_verified(
        repo.path(),
        &base,
        &patch(),
        "cauterizer/verified",
        &identity,
    )
    .unwrap();
    let message = git(
        repo.path(),
        &["show", "-s", "--format=%B", published.commit_oid.as_str()],
    );
    assert!(message.contains("Cauterizer-Run: run:00000001"));
    assert!(message.contains(&format!(
        "Cauterizer-Candidate: {}",
        patch().digest().to_tagged_hex()
    )));
    assert!(message.contains(&format!(
        "Cauterizer-Evidence: {}",
        identity.evidence_digest.to_tagged_hex()
    )));
    assert_eq!(published.transfer.commit_message, message);
}
fn repository() -> tempfile::TempDir {
    let repo = tempfile::tempdir().unwrap();
    git(repo.path(), &["init", "-q"]);
    fs::create_dir(repo.path().join("src")).unwrap();
    fs::write(repo.path().join("src/lib.rs"), "old\n").unwrap();
    git(repo.path(), &["add", "."]);
    git(
        repo.path(),
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
    repo
}
fn patch() -> CandidatePatch {
    CandidatePatch::from_normalized(
        b"--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-old\n+new\n".to_vec(),
        std::collections::BTreeSet::from(["src/lib.rs".into()]),
    )
}
fn head(repo: &Path) -> GitCommitOid {
    GitCommitOid::parse(git(repo, &["rev-parse", "HEAD"])).unwrap()
}

#[test]
fn creates_real_commit_on_namespaced_branch_without_running_hooks() {
    let repo = repository();
    let hook = repo.path().join(".git/hooks/pre-commit");
    fs::write(&hook, "#!/bin/sh\ntouch hook-ran\nexit 1\n").unwrap();
    let mut permissions = fs::metadata(&hook).unwrap().permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o755);
    }
    fs::set_permissions(&hook, permissions).unwrap();
    let base = head(repo.path());
    let result = publish(
        repo.path(),
        &base,
        &patch(),
        "cauterizer/run-1",
        &[VisibleCheck {
            program: "/usr/bin/test".into(),
            args: vec!["-f".into(), "src/lib.rs".into()],
        }],
    )
    .unwrap();
    assert_eq!(result.candidate_digest, patch().digest());
    assert_eq!(result.transfer.base_commit_oid, base);
    assert_eq!(result.transfer.files.len(), 1);
    assert_eq!(result.transfer.files[0].path, "src/lib.rs");
    assert_eq!(result.transfer.files[0].content, b"new\n");
    assert!(!result.transfer.files[0].executable);
    assert_eq!(
        git(repo.path(), &["rev-parse", "cauterizer/run-1"]),
        result.commit_oid.as_str()
    );
    assert!(!repo.path().join("hook-ran").exists());
    assert!(git(repo.path(), &["status", "--porcelain"]).is_empty());

    let raw = Command::new("git")
        .args(["cat-file", "commit", result.commit_oid.as_str()])
        .current_dir(repo.path())
        .output()
        .unwrap()
        .stdout;
    let tree = git(
        repo.path(),
        &[
            "rev-parse",
            &format!("{}^{{tree}}", result.commit_oid.as_str()),
        ],
    );
    let expected = format!(
        "tree {tree}\nparent {}\nauthor Cauterizer <cauterizer@invalid> 946684800 +0000\ncommitter Cauterizer <cauterizer@invalid> 946684800 +0000\n\nAutomated vulnerability remediation\n",
        base.as_str()
    );
    assert_eq!(raw, expected.as_bytes());
    let mut child = Command::new("git")
        .args(["hash-object", "-t", "commit", "--stdin"])
        .current_dir(repo.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(expected.as_bytes())
        .unwrap();
    let independently_hashed = String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap();
    assert_eq!(independently_hashed.trim(), result.commit_oid.as_str());
}

#[test]
fn rejects_dirty_wrong_base_and_failed_check_without_branch() {
    let repo = repository();
    let base = head(repo.path());
    fs::write(repo.path().join("dirty"), "x").unwrap();
    assert_eq!(
        publish(repo.path(), &base, &patch(), "cauterizer/dirty", &[]),
        Err(PublishError::InvalidCheckout)
    );
    fs::remove_file(repo.path().join("dirty")).unwrap();
    let wrong = GitCommitOid::parse("0123456789abcdef0123456789abcdef01234567").unwrap();
    assert_eq!(
        publish(repo.path(), &wrong, &patch(), "cauterizer/wrong", &[]),
        Err(PublishError::InvalidCheckout)
    );
    assert_eq!(
        publish(
            repo.path(),
            &base,
            &patch(),
            "cauterizer/fail",
            &[VisibleCheck {
                program: "/usr/bin/false".into(),
                args: vec![]
            }]
        ),
        Err(PublishError::CheckFailed)
    );
    assert!(
        !Command::new("git")
            .args(["show-ref", "--verify", "refs/heads/cauterizer/fail"])
            .current_dir(repo.path())
            .output()
            .unwrap()
            .status
            .success()
    );
}

#[cfg(unix)]
#[test]
fn rejects_patch_targeting_a_tracked_symlink() {
    use std::os::unix::fs::symlink;
    let repo = repository();
    fs::remove_file(repo.path().join("src/lib.rs")).unwrap();
    symlink("../outside", repo.path().join("src/lib.rs")).unwrap();
    git(repo.path(), &["add", "src/lib.rs"]);
    git(
        repo.path(),
        &[
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@invalid",
            "commit",
            "-qm",
            "symlink",
        ],
    );
    let base = head(repo.path());
    assert_eq!(
        publish(repo.path(), &base, &patch(), "cauterizer/symlink", &[]),
        Err(PublishError::InvalidPatch)
    );
}

#[cfg(unix)]
#[test]
fn preserves_executable_mode_in_transfer_material() {
    use std::os::unix::fs::PermissionsExt;
    let repo = repository();
    let path = repo.path().join("src/lib.rs");
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions).unwrap();
    git(repo.path(), &["add", "src/lib.rs"]);
    git(
        repo.path(),
        &[
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@invalid",
            "commit",
            "-qm",
            "executable",
        ],
    );
    let base = head(repo.path());
    let result = publish(repo.path(), &base, &patch(), "cauterizer/executable", &[]).unwrap();
    assert!(result.transfer.files[0].executable);
    assert!(
        git(
            repo.path(),
            &["ls-tree", result.commit_oid.as_str(), "src/lib.rs"]
        )
        .starts_with("100755 blob ")
    );
}

#[test]
fn rejects_substituted_declared_paths_before_git_mutation() {
    let repo = repository();
    let base = head(repo.path());
    let substituted = CandidatePatch::from_normalized(
        patch().as_bytes().to_vec(),
        std::collections::BTreeSet::from(["different/file.rs".into()]),
    );
    assert_eq!(
        publish(
            repo.path(),
            &base,
            &substituted,
            "cauterizer/substitution",
            &[]
        ),
        Err(PublishError::InvalidPatch)
    );
    assert!(git(repo.path(), &["status", "--porcelain"]).is_empty());
}

#[test]
fn concurrent_publishers_have_one_winner_and_leave_checkout_clean() {
    let repo = repository();
    let root = repo.path().to_path_buf();
    let base = head(&root);
    let first_root = root.clone();
    let first_base = base.clone();
    let first = std::thread::spawn(move || {
        publish(
            &first_root,
            &first_base,
            &patch(),
            "cauterizer/concurrent-one",
            &[VisibleCheck {
                program: "/bin/sh".into(),
                args: vec!["-c".into(), "sleep 0.3".into()],
            }],
        )
    });
    std::thread::sleep(std::time::Duration::from_millis(40));
    let second = publish(&root, &base, &patch(), "cauterizer/concurrent-two", &[]);
    assert_eq!(second, Err(PublishError::Busy));
    assert!(first.join().unwrap().is_ok());
    assert!(git(&root, &["status", "--porcelain"]).is_empty());
    assert!(root.join(".git/cauterizer-publish.lock").is_file());
    let reacquired = publish(
        &root,
        &base,
        &patch(),
        "cauterizer/concurrent-after-drop",
        &[],
    );
    assert!(reacquired.is_ok());
}
