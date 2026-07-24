//! P17 worked example: proves the evidence predicate's v1 -> v2 schema major
//! evolution is handled by versioned reinterpretation, never by rewriting a
//! signed statement or silently upgrading/downgrading its shape.
//!
//! - A checked-in v1 golden fixture (`tests/golden/evidence-predicate-body.v1.json`)
//!   still decodes correctly under a reader that only declares v1 support.
//! - A v2-shaped payload (bearing the new required `policy_ref` binding) is
//!   rejected by a v1-only reader at the schema-version gate, with a stable
//!   reason, before the payload is ever interpreted as v1 — it is never
//!   silently accepted or misread as if `policy_ref` did not exist.
//! - Symmetrically, a v1 fixture is rejected by a v2-only reader rather than
//!   being "upgraded" with some default `policy_ref`.

use cauterizer_evidence::domain::bundle::{
    EvidenceMaterial, EvidencePredicateBodyV1, EvidenceScope, RecordedVerdict,
    predicate_schema_name, predicate_schema_version,
};
use cauterizer_evidence::domain::predicate_v2::{
    EvidencePredicateBodyV2, PredicateReadError, predicate_schema_version_v2, read_predicate_v1,
    read_predicate_v2,
};
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
use cauterizer_syntax::schema::SchemaEnvelope;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

fn golden_v1_fixture() -> Value {
    let path = workspace_root()
        .join("crates/contexts/evidence/tests/golden/evidence-predicate-body.v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("missing golden fixture {}: {error}", path.display()));
    serde_json::from_str(&raw).expect("golden fixture is valid JSON")
}

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .expect("cauterizer-evidence must live below <workspace>/crates/contexts")
}

fn id(context: &str, n: u64) -> ContextQualifiedId {
    ContextQualifiedId::new(context, &format!("{n:08}")).unwrap()
}

fn v2_shaped_envelope() -> Value {
    let predicate = SchemaEnvelope::new(
        predicate_schema_name(),
        predicate_schema_version_v2(),
        EvidencePredicateBodyV2 {
            verdict: RecordedVerdict::VerifiedForFixture,
            assessment_ref: id("assessment", 1),
            scope: EvidenceScope {
                organization_id: OrganizationId::new("00000000").unwrap(),
                run_id: id("run", 1),
            },
            materials: vec![EvidenceMaterial {
                name: "baseline-observation".into(),
                digest: Sha256Digest::of_bytes(b"baseline"),
            }],
            policy_ref: id("verification-policy", 7),
        },
    );
    serde_json::to_value(predicate).expect("v2 predicate serializes")
}

#[test]
fn v1_golden_fixture_still_decodes_under_a_v1_only_reader() {
    let fixture = golden_v1_fixture();
    let read = read_predicate_v1(&fixture, &predicate_schema_version())
        .expect("checked-in v1 fixture must remain readable by a v1 consumer");
    assert_eq!(read.payload.verdict, RecordedVerdict::VerifiedForFixture);
    assert_eq!(read.payload.assessment_ref, id("assessment", 1));
    assert_eq!(read.payload.scope.run_id, id("run", 1));

    // Byte-for-byte round trip: the reader neither adds nor drops fields, it
    // only reinterprets exactly what the signed bytes already said.
    let expected = EvidencePredicateBodyV1 {
        verdict: RecordedVerdict::VerifiedForFixture,
        assessment_ref: id("assessment", 1),
        scope: EvidenceScope {
            organization_id: OrganizationId::new("00000000").unwrap(),
            run_id: id("run", 1),
        },
        materials: vec![EvidenceMaterial {
            name: "baseline-observation".into(),
            digest: Sha256Digest::of_bytes(b"baseline"),
        }],
    };
    assert_eq!(read.payload, expected);
}

#[test]
fn v1_only_reader_rejects_a_v2_shaped_payload_with_a_stable_reason_instead_of_misreading_it() {
    let outcome = read_predicate_v1(&v2_shaped_envelope(), &predicate_schema_version());
    assert_eq!(outcome, Err(PredicateReadError::UnsupportedContract));
}

#[test]
fn v2_only_reader_rejects_the_v1_golden_fixture_instead_of_silently_upgrading_it() {
    let outcome = read_predicate_v2(&golden_v1_fixture(), &predicate_schema_version_v2());
    assert_eq!(outcome, Err(PredicateReadError::UnsupportedContract));
}

#[test]
fn v2_only_reader_accepts_its_own_major_and_reads_the_new_policy_binding() {
    let read = read_predicate_v2(&v2_shaped_envelope(), &predicate_schema_version_v2())
        .expect("a v2 consumer must accept a v2 envelope");
    assert_eq!(read.payload.policy_ref, id("verification-policy", 7));
}

#[test]
fn golden_fixture_path_is_the_single_source_of_truth_for_this_test() {
    // Guards against accidentally hand-inlining a second "golden" value that
    // could drift from the checked-in file without either test noticing.
    let path: PathBuf = workspace_root()
        .join("crates/contexts/evidence/tests/golden/evidence-predicate-body.v1.json");
    assert!(
        path.is_file(),
        "expected golden fixture at {}",
        path.display()
    );
}
