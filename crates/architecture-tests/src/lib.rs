//! Workspace architecture policy for Cauterizer.
//!
//! This crate intentionally uses only the standard library. It is a build-time
//! guard, not a source of domain behavior, and must remain usable before the
//! rest of the workspace compiles.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

const INFRASTRUCTURE_DEPENDENCIES: &[&str] = &[
    "actix-web",
    "axum",
    "diesel",
    "hyper",
    "kube",
    "lapin",
    "nats",
    "object_store",
    "rdkafka",
    "redis",
    "reqwest",
    "rocket",
    "rusqlite",
    "sea-orm",
    "sqlx",
    "surrealdb",
    "tokio-postgres",
    "tonic",
    "tower-http",
    "warp",
];

const UPSTREAM_SDK_MARKERS: &[&str] = &[
    "agentic_flow",
    "agentic-flow",
    "aws_sdk",
    "aws-sdk",
    "claude_flow",
    "claude-flow",
    "cve_bench",
    "cve-bench",
    "octocrab",
    "openai_api",
    "osv_client",
    "ruflo",
];

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
/// One architecture-policy failure with a stable rule identifier.
pub struct Violation {
    /// Stable rule identifier suitable for CI annotations.
    pub rule: &'static str,
    /// Manifest or Rust source file that caused the finding.
    pub path: PathBuf,
    /// Human-readable explanation of the forbidden relationship.
    pub detail: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: {}: {}",
            self.rule,
            self.path.display(),
            self.detail
        )
    }
}

#[derive(Clone, Debug, Default)]
struct Package {
    name: String,
    manifest: PathBuf,
    root: PathBuf,
    layer: Layer,
    context: Option<String>,
    dependencies: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Layer {
    Domain,
    Application,
    Infrastructure,
    Contracts,
    Shared,
    Binary,
    #[default]
    Other,
}

impl Layer {
    fn parse(value: &str) -> Self {
        match value {
            "domain" => Self::Domain,
            "application" => Self::Application,
            "infrastructure" => Self::Infrastructure,
            "contracts" => Self::Contracts,
            "shared" => Self::Shared,
            "binary" => Self::Binary,
            _ => Self::Other,
        }
    }
}

/// Audit every package below `workspace_root` and return deterministic findings.
///
/// Package authors should declare `package.metadata.cauterizer.layer` and, for a
/// bounded context, `package.metadata.cauterizer.context`. Conventional package
/// suffixes remain supported so a malformed or omitted metadata block cannot
/// trivially bypass the checks.
pub fn audit_workspace(workspace_root: impl AsRef<Path>) -> Vec<Violation> {
    let workspace_root = workspace_root.as_ref();
    let mut manifests = Vec::new();
    collect_manifests(workspace_root, workspace_root, &mut manifests);
    let packages: Vec<_> = manifests
        .iter()
        .filter_map(|manifest| parse_package(manifest))
        .collect();
    let by_name: BTreeMap<_, _> = packages
        .iter()
        .map(|package| (package.name.clone(), package))
        .collect();
    let mut violations = Vec::new();

    for package in &packages {
        check_manifest_dependencies(package, &by_name, &mut violations);
        check_sources(package, &by_name, &mut violations);
    }
    check_cycles(&packages, &by_name, &mut violations);
    violations.sort();
    violations.dedup();
    violations
}

/// Panics with all findings. Intended for a single integration test and CI.
///
/// # Panics
///
/// Panics when one or more workspace architecture violations are found.
pub fn assert_workspace_architecture(workspace_root: impl AsRef<Path>) {
    let violations = audit_workspace(workspace_root);
    if !violations.is_empty() {
        let report = violations
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        panic!("Cauterizer architecture policy failed:\n{report}");
    }
}

fn collect_manifests(root: &Path, current: &Path, manifests: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(current) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let relative = path.strip_prefix(root).unwrap_or(&path);
            if relative.components().any(|part| {
                matches!(
                    part.as_os_str().to_str(),
                    Some("target" | ".git" | ".agents" | ".claude" | ".claude-flow")
                )
            }) {
                continue;
            }
            collect_manifests(root, &path, manifests);
        } else if path.file_name().and_then(|name| name.to_str()) == Some("Cargo.toml") {
            manifests.push(path);
        }
    }
}

fn parse_package(manifest: &Path) -> Option<Package> {
    let text = fs::read_to_string(manifest).ok()?;
    let mut section = "";
    let mut name = None;
    let mut layer = Layer::Other;
    let mut context = None;
    let mut dependencies = BTreeSet::new();
    for raw_line in text.lines() {
        let line = strip_comment(raw_line).trim();
        if line.starts_with('[') && line.ends_with(']') {
            section = line.trim_matches(&['[', ']'][..]).trim();
            continue;
        }
        let Some((key, value)) = key_value(line) else {
            continue;
        };
        if section == "package" && key == "name" {
            name = quoted(value).map(str::to_owned);
        } else if section == "package.metadata.cauterizer" {
            match key {
                "layer" => layer = quoted(value).map(Layer::parse).unwrap_or_default(),
                "context" => context = quoted(value).map(str::to_owned),
                _ => {}
            }
        } else if is_dependency_section(section) {
            dependencies.insert(key.replace('_', "-"));
        }
    }
    let name = name?;
    if layer == Layer::Other {
        layer = infer_layer(&name, manifest);
    }
    if context.is_none() {
        context = infer_context(&name, layer);
    }
    Some(Package {
        name,
        root: manifest.parent()?.to_path_buf(),
        manifest: manifest.to_path_buf(),
        layer,
        context,
        dependencies,
    })
}

fn check_manifest_dependencies(
    package: &Package,
    by_name: &BTreeMap<String, &Package>,
    violations: &mut Vec<Violation>,
) {
    for dependency in &package.dependencies {
        if package.layer == Layer::Domain
            && INFRASTRUCTURE_DEPENDENCIES.contains(&dependency.as_str())
        {
            violations.push(Violation {
                rule: "ARCH-DOMAIN-PURE",
                path: package.manifest.clone(),
                detail: format!(
                    "domain package `{}` depends on infrastructure/framework crate `{dependency}`",
                    package.name
                ),
            });
        }
        let Some(target) = by_name.get(dependency) else {
            continue;
        };
        if package.layer == Layer::Domain && !matches!(target.layer, Layer::Domain | Layer::Shared)
        {
            violations.push(Violation {
                rule: "ARCH-DEPENDENCY-DIRECTION",
                path: package.manifest.clone(),
                detail: format!(
                    "domain package `{}` depends outward on `{}` ({:?})",
                    package.name, target.name, target.layer
                ),
            });
        }
        if different_context(package, target) && target.layer != Layer::Contracts {
            violations.push(Violation {
                rule: "ARCH-CONTEXT-BOUNDARY",
                path: package.manifest.clone(),
                detail: format!("`{}` depends on internal package `{}` from another bounded context; depend on its contracts or facade", package.name, target.name),
            });
        }
    }
}

fn check_sources(
    package: &Package,
    by_name: &BTreeMap<String, &Package>,
    violations: &mut Vec<Violation>,
) {
    // The policy implementation necessarily contains the forbidden token corpus.
    // It is a test mechanism with no product authority and audits itself through
    // its fixture suite instead of applying lexical product rules to those strings.
    if package.name == "architecture-tests" {
        return;
    }
    let src = package.root.join("src");
    let mut files = Vec::new();
    collect_rust_files(&src, &mut files);
    for path in files {
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let code = without_line_comments(&text);
        if contains_unsafe_syntax(&code) || code.contains("allow(unsafe_code)") {
            violations.push(Violation {
                rule: "ARCH-UNSAFE",
                path: path.clone(),
                detail: "unsafe Rust is forbidden by default; isolate an exception in a dedicated reviewed crate and amend this policy".into(),
            });
        }
        if matches!(package.layer, Layer::Domain | Layer::Contracts) {
            for marker in UPSTREAM_SDK_MARKERS {
                if code.contains(marker) {
                    violations.push(Violation {
                        rule: "ARCH-UPSTREAM-TYPE",
                        path: path.clone(),
                        detail: format!(
                            "{} package `{}` contains forbidden upstream SDK marker `{marker}`",
                            layer_name(package.layer),
                            package.name
                        ),
                    });
                }
            }
        }
        for target in by_name.values() {
            if different_context(package, target)
                && target.layer != Layer::Contracts
                && source_mentions_crate(&code, &target.name)
            {
                violations.push(Violation {
                    rule: "ARCH-CROSS-CONTEXT-IMPORT",
                    path: path.clone(),
                    detail: format!(
                        "source imports internal crate `{}` from another bounded context",
                        target.name
                    ),
                });
            }
        }
    }
}

fn check_cycles(
    packages: &[Package],
    by_name: &BTreeMap<String, &Package>,
    violations: &mut Vec<Violation>,
) {
    fn visit<'a>(
        package: &'a Package,
        by_name: &BTreeMap<String, &'a Package>,
        visiting: &mut Vec<&'a str>,
        done: &mut BTreeSet<&'a str>,
        violations: &mut Vec<Violation>,
    ) {
        if done.contains(package.name.as_str()) {
            return;
        }
        if let Some(position) = visiting.iter().position(|name| *name == package.name) {
            let mut cycle = visiting[position..].to_vec();
            cycle.push(package.name.as_str());
            violations.push(Violation {
                rule: "ARCH-CYCLE",
                path: package.manifest.clone(),
                detail: format!("workspace package cycle: {}", cycle.join(" -> ")),
            });
            return;
        }
        visiting.push(&package.name);
        for dependency in &package.dependencies {
            if let Some(target) = by_name.get(dependency) {
                visit(target, by_name, visiting, done, violations);
            }
        }
        visiting.pop();
        done.insert(&package.name);
    }

    let mut done = BTreeSet::new();
    for package in packages {
        visit(package, by_name, &mut Vec::new(), &mut done, violations);
    }
}

fn collect_rust_files(current: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(current) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, files);
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            files.push(path);
        }
    }
}

fn key_value(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once('=')?;
    Some((key.trim().trim_matches('"'), value.trim()))
}

fn quoted(value: &str) -> Option<&str> {
    value.trim().strip_prefix('"')?.split('"').next()
}

fn strip_comment(line: &str) -> &str {
    line.split('#').next().unwrap_or(line)
}

fn is_dependency_section(section: &str) -> bool {
    section == "dependencies"
        || section == "dev-dependencies"
        || section == "build-dependencies"
        || section.ends_with(".dependencies")
        || section.ends_with(".dev-dependencies")
        || section.ends_with(".build-dependencies")
}

fn infer_layer(name: &str, manifest: &Path) -> Layer {
    let normalized = format!("{} {}", name.replace('_', "-"), manifest.display());
    if normalized.contains("domain") {
        Layer::Domain
    } else if normalized.contains("infrastructure") || normalized.contains("infra") {
        Layer::Infrastructure
    } else if normalized.contains("application") || normalized.contains("-app") {
        Layer::Application
    } else if normalized.contains("contract") {
        Layer::Contracts
    } else if normalized.contains("shared") || normalized.contains("syntax") {
        Layer::Shared
    } else {
        Layer::Other
    }
}

fn infer_context(name: &str, layer: Layer) -> Option<String> {
    // This package owns cross-cutting adapter mechanisms and deliberately has no
    // bounded-context identity. Context-specific adapters live in separately
    // tagged packages and may depend inward on it.
    if name.replace('_', "-") == "cauterizer-infrastructure" {
        return None;
    }
    if matches!(
        layer,
        Layer::Domain | Layer::Application | Layer::Infrastructure | Layer::Contracts
    ) {
        for suffix in [
            "-infrastructure",
            "-application",
            "-contracts",
            "-domain",
            "-infra",
            "-app",
        ] {
            if let Some(context) = name.replace('_', "-").strip_suffix(suffix) {
                return Some(context.to_owned());
            }
        }
    }
    None
}

fn different_context(left: &Package, right: &Package) -> bool {
    matches!((&left.context, &right.context), (Some(left), Some(right)) if left != right)
}

fn without_line_comments(text: &str) -> String {
    text.lines()
        .map(|line| line.split("//").next().unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n")
}

fn contains_unsafe_syntax(code: &str) -> bool {
    [
        "unsafe {",
        "unsafe fn",
        "unsafe trait",
        "unsafe impl",
        "unsafe extern",
    ]
    .iter()
    .any(|needle| code.contains(needle))
}

fn source_mentions_crate(code: &str, crate_name: &str) -> bool {
    let rust_name = crate_name.replace('-', "_");
    code.contains(&format!("use {rust_name}::"))
        || code.contains(&format!("extern crate {rust_name}"))
        || code.contains(&format!("{rust_name}::"))
}

fn layer_name(layer: Layer) -> &'static str {
    match layer {
        Layer::Domain => "domain",
        Layer::Contracts => "contracts",
        Layer::Application => "application",
        Layer::Infrastructure => "infrastructure",
        Layer::Shared => "shared",
        Layer::Binary => "binary",
        Layer::Other => "unclassified",
    }
}
