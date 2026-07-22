//! Checked-in JSON Schema drift gate for shared public primitives.

use cauterizer_syntax::authorization::{
    ActionName, AuthorizationRequestContext, Purpose, ResourceRef,
};
use cauterizer_syntax::classification::{DataClass, RegionCode, RetentionMetadata};
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::envelope::{Cursor, Page, ProblemDetails, ResultEnvelope};
use cauterizer_syntax::identifiers::{
    ActorId, AggregateSequence, CausationId, ContextQualifiedId, CorrelationId, IdempotencyKey,
    IdentityRef, OrganizationId, ServicePrincipalId,
};
use cauterizer_syntax::schema::{SchemaEnvelope, SchemaName, SchemaVersion};
use cauterizer_syntax::sensitive::Sensitive;
use cauterizer_syntax::time::{BoundedDuration, UtcInstant};
use schemars::JsonSchema;
use serde_json::{Map, Value};
use std::fs;
use std::path::{Path, PathBuf};

const UPDATE_ENV: &str = "CAUTERIZER_UPDATE_SCHEMA";

/// Aggregate used only to make every public wire primitive reachable from one
/// stable schema document. Optional fields avoid implying domain requirements.
#[derive(JsonSchema)]
#[allow(dead_code)]
struct SharedPrimitiveSchemaSurface {
    action_name: Option<ActionName>,
    resource_ref: Option<ResourceRef>,
    purpose: Option<Purpose>,
    authorization_request_context: Option<AuthorizationRequestContext>,
    data_class: Option<DataClass>,
    region_code: Option<RegionCode>,
    retention_metadata: Option<RetentionMetadata>,
    sha256_digest: Option<Sha256Digest>,
    cursor: Option<Cursor>,
    string_page: Option<Page<String>>,
    string_result: Option<ResultEnvelope<String>>,
    problem_details: Option<ProblemDetails>,
    context_qualified_id: Option<ContextQualifiedId>,
    organization_id: Option<OrganizationId>,
    actor_id: Option<ActorId>,
    service_principal_id: Option<ServicePrincipalId>,
    identity_ref: Option<IdentityRef>,
    correlation_id: Option<CorrelationId>,
    causation_id: Option<CausationId>,
    idempotency_key: Option<IdempotencyKey>,
    aggregate_sequence: Option<AggregateSequence>,
    schema_name: Option<SchemaName>,
    schema_version: Option<SchemaVersion>,
    string_schema_envelope: Option<SchemaEnvelope<String>>,
    sensitive_string: Option<Sensitive<String>>,
    utc_instant: Option<UtcInstant>,
    bounded_duration: Option<BoundedDuration>,
}

#[test]
fn checked_in_shared_schema_has_not_drifted() {
    let actual = generated_schema();
    let snapshot = snapshot_path();

    if std::env::var_os(UPDATE_ENV).is_some() {
        fs::create_dir_all(snapshot.parent().expect("snapshot has parent"))
            .expect("create schema snapshot directory");
        fs::write(&snapshot, &actual).expect("write shared schema snapshot");
        return;
    }

    let expected = fs::read_to_string(&snapshot).unwrap_or_else(|error| {
        panic!(
            "missing schema snapshot {} ({error}); regenerate with `{UPDATE_ENV}=1 cargo test -p cauterizer-syntax --test schema_drift`",
            snapshot.display()
        )
    });
    assert_eq!(
        expected, actual,
        "shared JSON Schema drifted; review compatibility and ADR-021 impact, then regenerate intentionally with `{UPDATE_ENV}=1 cargo test -p cauterizer-syntax --test schema_drift`"
    );
}

fn generated_schema() -> String {
    let schema = schemars::schema_for!(SharedPrimitiveSchemaSurface);
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

fn snapshot_path() -> PathBuf {
    workspace_root().join("schemas/shared/shared-primitives.schema.json")
}

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("cauterizer-syntax must live below <workspace>/crates")
}
