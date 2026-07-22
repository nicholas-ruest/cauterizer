//! Regression fixtures for allowed and forbidden architecture shapes.

use architecture_tests::audit_workspace;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cauterizer-architecture-{}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn package(
        &self,
        name: &str,
        layer: &str,
        context: Option<&str>,
        dependencies: &str,
        source: &str,
    ) {
        let root = self.0.join(name);
        fs::create_dir_all(root.join("src")).unwrap();
        let context = context
            .map(|value| format!("context = \"{value}\"\n"))
            .unwrap_or_default();
        fs::write(
            root.join("Cargo.toml"),
            format!("[package]\nname = \"{name}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[package.metadata.cauterizer]\nlayer = \"{layer}\"\n{context}\n[dependencies]\n{dependencies}"),
        ).unwrap();
        fs::write(root.join("src/lib.rs"), source).unwrap();
    }

    fn root(&self) -> &Path {
        &self.0
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn rules(root: &Path) -> Vec<&'static str> {
    audit_workspace(root)
        .iter()
        .map(|violation| violation.rule)
        .collect()
}

#[test]
fn accepts_domain_with_shared_syntax_only() {
    let fixture = Fixture::new();
    fixture.package(
        "shared-syntax",
        "shared",
        None,
        "",
        "#![forbid(unsafe_code)]\n",
    );
    fixture.package(
        "runs-domain",
        "domain",
        Some("runs"),
        "shared-syntax = { path = \"../shared-syntax\" }\n",
        "#![forbid(unsafe_code)]\n",
    );
    assert!(audit_workspace(fixture.root()).is_empty());
}

#[test]
fn rejects_framework_dependencies_in_domain() {
    let fixture = Fixture::new();
    fixture.package(
        "runs-domain",
        "domain",
        Some("runs"),
        "sqlx = \"0.8\"\n",
        "",
    );
    assert!(rules(fixture.root()).contains(&"ARCH-DOMAIN-PURE"));
}

#[test]
fn rejects_outward_and_cross_context_dependencies() {
    let fixture = Fixture::new();
    fixture.package(
        "evidence-infrastructure",
        "infrastructure",
        Some("evidence"),
        "",
        "",
    );
    fixture.package(
        "runs-domain",
        "domain",
        Some("runs"),
        "evidence-infrastructure = { path = \"../evidence-infrastructure\" }\n",
        "",
    );
    let findings = rules(fixture.root());
    assert!(findings.contains(&"ARCH-DEPENDENCY-DIRECTION"));
    assert!(findings.contains(&"ARCH-CONTEXT-BOUNDARY"));
}

#[test]
fn permits_cross_context_contract_dependency() {
    let fixture = Fixture::new();
    fixture.package("advisory-contracts", "contracts", Some("advisory"), "", "");
    fixture.package(
        "runs-application",
        "application",
        Some("runs"),
        "advisory-contracts = { path = \"../advisory-contracts\" }\n",
        "",
    );
    assert!(audit_workspace(fixture.root()).is_empty());
}

#[test]
fn rejects_cycles() {
    let fixture = Fixture::new();
    fixture.package(
        "a-app",
        "application",
        None,
        "b-app = { path = \"../b-app\" }\n",
        "",
    );
    fixture.package(
        "b-app",
        "application",
        None,
        "a-app = { path = \"../a-app\" }\n",
        "",
    );
    assert!(rules(fixture.root()).contains(&"ARCH-CYCLE"));
}

#[test]
fn rejects_upstream_sdk_markers_and_unsafe_code() {
    let fixture = Fixture::new();
    fixture.package(
        "verification-contracts",
        "contracts",
        Some("verification"),
        "",
        "pub fn leak(_: osv_client::Record) {}\npub unsafe fn bypass() {}\n",
    );
    let findings = rules(fixture.root());
    assert!(findings.contains(&"ARCH-UPSTREAM-TYPE"));
    assert!(findings.contains(&"ARCH-UNSAFE"));
}

#[test]
fn rejects_source_level_internal_import_even_if_manifest_is_malformed() {
    let fixture = Fixture::new();
    fixture.package(
        "verification-domain",
        "domain",
        Some("verification"),
        "",
        "pub struct Verdict;\n",
    );
    fixture.package(
        "runs-application",
        "application",
        Some("runs"),
        "",
        "use verification_domain::Verdict;\n",
    );
    assert!(rules(fixture.root()).contains(&"ARCH-CROSS-CONTEXT-IMPORT"));
}
