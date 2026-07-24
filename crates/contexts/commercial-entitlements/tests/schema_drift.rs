//! Checked-in JSON Schema drift gate for Commercial Entitlements' published
//! contracts.
//!
//! See `crates/contexts/organization-access/tests/schema_drift.rs` for the
//! full rationale (ADR-021 enforcement; this test lives in-crate rather than
//! centralized in `cauterizer-contracts` because of the workspace's
//! bounded-context dependency-direction policy in `crates/architecture-tests`).
//!
//! Regenerate intentionally with:
//! `CAUTERIZER_UPDATE_SCHEMA=1 cargo test -p cauterizer-commercial-entitlements --test schema_drift`

use cauterizer_commercial_entitlements::contracts::{
    BudgetReservationV1, CommercialEntitlementsEventV1,
};
use cauterizer_syntax::schema::{SchemaChange, classify_schema_change};
use schemars::JsonSchema;
use serde_json::{Map, Value};
use std::fs;
use std::path::{Path, PathBuf};

const UPDATE_ENV: &str = "CAUTERIZER_UPDATE_SCHEMA";
const CONTEXT: &str = "commercial-entitlements";

fn assert_schema_matches<T: JsonSchema>(name: &str) {
    let actual = generated_schema::<T>();
    let snapshot = snapshot_path(name);

    if std::env::var_os(UPDATE_ENV).is_some() {
        fs::create_dir_all(snapshot.parent().expect("snapshot has parent"))
            .expect("create schema snapshot directory");
        fs::write(&snapshot, &actual).expect("write schema snapshot");
        return;
    }

    let Ok(expected) = fs::read_to_string(&snapshot) else {
        panic!(
            "missing schema snapshot {} for {CONTEXT}/{name}; regenerate with `{UPDATE_ENV}=1 cargo test -p cauterizer-commercial-entitlements --test schema_drift`",
            snapshot.display()
        )
    };
    if expected == actual {
        return;
    }

    let expected_value: Value =
        serde_json::from_str(&expected).expect("checked-in schema is valid JSON");
    let actual_value: Value =
        serde_json::from_str(&actual).expect("generated schema is valid JSON");
    let guidance = match classify_schema_change(&expected_value, &actual_value) {
        SchemaChange::Identical => unreachable!("byte comparison above already proved a diff"),
        SchemaChange::Additive => {
            "classified ADDITIVE: safe to regenerate the checked-in file in place, no major bump required"
        }
        SchemaChange::SecurityCriticalBreaking => {
            "classified SECURITY-CRITICAL BREAKING: this must ship as a new major version with its \
             own checked-in schema file and a golden previous-major fixture, not an in-place update \
             of this file (see crates/contexts/evidence/tests/schema_evolution.rs for the worked example)"
        }
    };
    panic!(
        "checked-in schema for {CONTEXT}/{name} drifted from the live Rust type ({guidance}); \
         review ADR-021 compatibility impact, then regenerate intentionally with \
         `{UPDATE_ENV}=1 cargo test -p cauterizer-commercial-entitlements --test schema_drift`"
    );
}

fn generated_schema<T: JsonSchema>() -> String {
    let schema = schemars::schema_for!(T);
    let mut value = serde_json::to_value(schema).expect("schema is serializable");
    sort_json(&mut value);
    let mut rendered = serde_json::to_string_pretty(&value).expect("schema renders as JSON");
    rendered.push('\n');
    rendered
}

fn sort_json(value: &mut Value) {
    match value {
        Value::Object(object) => {
            let old = std::mem::take(object);
            let mut entries: Vec<_> = old.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut sorted = Map::new();
            for (key, mut child) in entries {
                sort_json(&mut child);
                sorted.insert(key, child);
            }
            *object = sorted;
        }
        Value::Array(items) => items.iter_mut().for_each(sort_json),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn snapshot_path(name: &str) -> PathBuf {
    workspace_root()
        .join("schemas")
        .join(CONTEXT)
        .join(format!("{name}.schema.json"))
}

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .expect("cauterizer-commercial-entitlements must live below <workspace>/crates/contexts")
}

#[test]
fn budget_reservation_schema_has_not_drifted() {
    assert_schema_matches::<BudgetReservationV1>("budget-reservation.v1");
}

#[test]
fn commercial_entitlements_event_schema_has_not_drifted() {
    assert_schema_matches::<CommercialEntitlementsEventV1>("commercial-entitlements-event.v1");
}
