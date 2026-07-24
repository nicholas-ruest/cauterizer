//! Versioned public contract envelopes.
//!
//! This crate is the ADR-021 policy home: [`check_schema_drift`] is the
//! reusable classification wrapper every context's own `schema_drift`
//! integration test mirrors on a checked-in vs. generated schema mismatch,
//! and [`SUPPORTED_MAJOR_VERSION_WINDOW`] is the checked-in
//! migration/deprecation-window policy.
//!
//! Per-context drift tests (for example
//! `crates/contexts/organization-access/tests/schema_drift.rs`,
//! `crates/contexts/evidence/tests/schema_drift.rs`) call
//! `cauterizer_syntax::schema::classify_schema_change` directly rather than
//! depending on this crate: `crates/architecture-tests` enforces that a
//! domain-layer bounded context may depend only on `shared`/`domain`-layer
//! packages (`cauterizer-syntax` is `shared`), and that this `contracts`-layer
//! crate must never reach into a specific context's domain/application
//! internals (ARCH-DEPENDENCY-DIRECTION, ARCH-CONTEXT-BOUNDARY,
//! ARCH-CYCLE). [`check_schema_drift`] and its tests below prove the
//! classification wiring against the exact same function every per-context
//! test uses, without violating that boundary.

#![forbid(unsafe_code)]

use cauterizer_syntax::schema::{SchemaChange, classify_schema_change};
use serde_json::Value;

/// The namespace used by public Cauterizer schemas.
pub const SCHEMA_NAMESPACE: &str = cauterizer_syntax::schema_namespace();

/// Supported-majors compatibility window for every published Cauterizer contract.
///
/// ADR-021 ("Schema and Contract Evolution Governance") requires a published
/// migration/deprecation-window policy, but its own acceptance criteria leave
/// the exact window *length* unratified pending a named architecture decider
/// (`docs/architecture/p12-p20-prompt-plan.md`, P17's flag). Rather than
/// inventing a fake ratified calendar length, this workspace enforces the
/// conservative default below until that ratification happens:
///
/// - A consuming context MUST remain able to decode the *current* published
///   major version of every contract it consumes, and the *immediately
///   previous* major version. That is exactly two majors — this constant.
/// - Every major version still inside the window MUST have at least one
///   checked-in golden fixture proving a versioned offline reader that only
///   declares that major still decodes it correctly, and proving a reader for
///   a different major correctly rejects it rather than misinterpreting it.
///   See `crates/contexts/evidence/tests/golden` and
///   `crates/contexts/evidence/tests/schema_evolution.rs` for the worked
///   example this policy is checked against.
/// - There is deliberately no fixed calendar length (e.g. "supported for N
///   months from release") attached to this window. Attaching one is an
///   architecture decision that requires a named decider's sign-off per
///   ADR-021's own acceptance rule, not something an autonomous coding
///   session may invent; ADR-021 stays `proposed` until that ratification
///   lands.
pub const SUPPORTED_MAJOR_VERSION_WINDOW: u8 = 2;

/// Outcome of comparing a checked-in JSON Schema against a freshly generated one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaDriftOutcome {
    /// The checked-in and generated schemas are identical.
    Unchanged,
    /// The schemas differ, but only in a way
    /// [`classify_schema_change`] treats as backward-compatible.
    Additive,
    /// The schemas differ in a way that changes validation or security
    /// semantics and requires a new major version and a fresh checked-in
    /// schema file, not an in-place update of the existing one.
    SecurityCriticalBreaking,
}

/// Classifies drift between a checked-in schema and a freshly regenerated one.
///
/// This is the load-bearing call the `schema_drift` integration test makes on
/// every mismatch: it is not enough for a drift check to notice the bytes
/// differ, it must say *why* using the same conservative classifier every
/// context's own contract tests already rely on
/// ([`cauterizer_syntax::schema::classify_schema_change`]), so a reviewer (or
/// CI) can immediately tell whether a checked-in-file update alone is safe or
/// whether the change also needs a major version bump.
#[must_use]
pub fn check_schema_drift(checked_in: &Value, generated: &Value) -> SchemaDriftOutcome {
    match classify_schema_change(checked_in, generated) {
        SchemaChange::Identical => SchemaDriftOutcome::Unchanged,
        SchemaChange::Additive => SchemaDriftOutcome::Additive,
        SchemaChange::SecurityCriticalBreaking => SchemaDriftOutcome::SecurityCriticalBreaking,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base_schema() -> Value {
        json!({
            "type": "object", "additionalProperties": false,
            "properties": {"id": {"type": "string"}}, "required": ["id"]
        })
    }

    #[test]
    fn adding_a_required_field_to_a_checked_in_schema_is_flagged_security_critical() {
        // Simulates a bad PR that adds a new required (security-critical
        // capable) field to an already-published v1 contract in place,
        // instead of shipping it as a new major with its own schema file.
        let mut mutated = base_schema();
        mutated["properties"]["policy_ref"] = json!({"type": "string"});
        mutated["required"]
            .as_array_mut()
            .expect("required array")
            .push(json!("policy_ref"));
        assert_eq!(
            check_schema_drift(&base_schema(), &mutated),
            SchemaDriftOutcome::SecurityCriticalBreaking
        );
    }

    #[test]
    fn adding_a_genuinely_optional_field_to_a_checked_in_schema_is_additive() {
        let mut mutated = base_schema();
        mutated["properties"]["label"] = json!({"type": "string"});
        assert_eq!(
            check_schema_drift(&base_schema(), &mutated),
            SchemaDriftOutcome::Additive
        );
    }

    #[test]
    fn identical_schemas_report_no_drift() {
        assert_eq!(
            check_schema_drift(&base_schema(), &base_schema()),
            SchemaDriftOutcome::Unchanged
        );
    }

    #[test]
    fn deprecation_window_covers_exactly_current_plus_previous_major() {
        assert_eq!(SUPPORTED_MAJOR_VERSION_WINDOW, 2);
    }
}
