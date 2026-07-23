//! Executable consistency check for the P00 decision and evidence registry.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::Command;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("architecture-tests is nested below workspace root")
        .to_path_buf()
}

#[test]
fn p00_baseline_is_machine_verifiable_and_keeps_external_gates_open() {
    let root = workspace_root();
    let output = Command::new("bash")
        .arg(root.join("scripts/ci/verify-p00-acceptance.sh"))
        .arg("baseline")
        .current_dir(&root)
        .output()
        .expect("P00 acceptance verifier must execute");

    assert!(
        output.status.success(),
        "P00 verifier failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("external gates remain explicitly required"),
        "baseline verification must never imply external acceptance"
    );
}
