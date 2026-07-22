//! End-to-end architecture gate over the checked-out workspace.

use std::path::PathBuf;

#[test]
fn workspace_obeys_architecture_policy() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("architecture-tests must live below <workspace>/crates")
        .to_path_buf();
    architecture_tests::assert_workspace_architecture(root);
}
