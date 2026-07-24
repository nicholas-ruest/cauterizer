//! Evidence predicate schema major `2`: the P17 worked schema-evolution example.
//!
//! [`EvidencePredicateBodyV2`] adds one security-critical required field,
//! `policy_ref`, that binds a recorded verdict to the exact verification
//! policy version that produced it — the "verdict-policy binding" P13's own
//! scope names but v1 never actually carried. Adding a required field to an
//! existing major is exactly the change `classify_schema_change` in
//! `cauterizer-syntax` flags `SecurityCriticalBreaking`, which is why this
//! ships as a new major (`2.0.0`, checked in at
//! `schemas/evidence/evidence-predicate-body.v2.schema.json`) rather than a
//! v1 point release.
//!
//! The two reader functions below prove ADR-021's "never rewritten, only
//! versioned reinterpretation" rule end to end: each reader checks the
//! envelope's schema name/version against its own declared consumer major
//! *before* ever attempting to interpret the payload, so a v2-shaped envelope
//! hitting a v1-only reader is rejected at the version gate, not misread.

use crate::domain::bundle::{
    EvidenceMaterial, EvidencePredicateBodyV1, EvidenceScope, RecordedVerdict,
    predicate_schema_name,
};
use cauterizer_syntax::identifiers::ContextQualifiedId;
use cauterizer_syntax::schema::{SchemaEnvelope, SchemaVersion};
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

/// Cauterizer-owned predicate body (schema major `2`).
///
/// Identical to [`EvidencePredicateBodyV1`] with one additional
/// required field, `policy_ref`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidencePredicateBodyV2 {
    /// Verbatim recorded verdict.
    pub verdict: RecordedVerdict,
    /// Immutable reference to the Verification assessment this bundle attests to.
    pub assessment_ref: ContextQualifiedId,
    /// Organization/run binding.
    pub scope: EvidenceScope,
    /// Supporting materials referenced by, but not asserted as, the subject.
    pub materials: Vec<EvidenceMaterial>,
    /// Immutable reference to the exact verification policy version bound to
    /// `verdict`. Absent from schema major `1`; required from `2` onward.
    pub policy_ref: ContextQualifiedId,
}

/// Returns the v2 predicate body schema revision.
///
/// # Panics
///
/// Never panics: the literal is a checked-in canonical semantic version.
#[must_use]
pub fn predicate_schema_version_v2() -> SchemaVersion {
    SchemaVersion::parse("2.0.0").expect("checked-in canonical schema version")
}

/// Stable, fail-closed reason a versioned predicate reader declined an envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PredicateReadError {
    /// The envelope's schema name or version was not one the reader's
    /// declared consumer version accepts. The payload is never inspected
    /// when this is returned: rejection happens at the version gate, not by
    /// attempting and failing a struct decode.
    UnsupportedContract,
    /// The contract was accepted but the payload body did not match the
    /// reader's expected shape.
    MalformedPayload,
}

impl fmt::Display for PredicateReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedContract => "unsupported_predicate_contract",
            Self::MalformedPayload => "malformed_predicate_payload",
        })
    }
}
impl std::error::Error for PredicateReadError {}

/// Reads a JSON predicate envelope as schema major `1` only.
///
/// # Errors
///
/// Returns [`PredicateReadError::UnsupportedContract`] when `consumer_version`
/// does not accept the envelope's declared version (in particular: any major
/// other than `1`), and [`PredicateReadError::MalformedPayload`] if an
/// accepted envelope's payload does not parse as [`EvidencePredicateBodyV1`].
pub fn read_predicate_v1(
    envelope: &Value,
    consumer_version: &SchemaVersion,
) -> Result<SchemaEnvelope<EvidencePredicateBodyV1>, PredicateReadError> {
    read_predicate_at(envelope, consumer_version)
}

/// Reads a JSON predicate envelope as schema major `2` only.
///
/// # Errors
///
/// See [`read_predicate_v1`]; the same fail-closed rule applies with
/// [`EvidencePredicateBodyV2`] as the accepted payload shape.
pub fn read_predicate_v2(
    envelope: &Value,
    consumer_version: &SchemaVersion,
) -> Result<SchemaEnvelope<EvidencePredicateBodyV2>, PredicateReadError> {
    read_predicate_at(envelope, consumer_version)
}

fn read_predicate_at<T: DeserializeOwned>(
    envelope: &Value,
    consumer_version: &SchemaVersion,
) -> Result<SchemaEnvelope<T>, PredicateReadError> {
    let untyped: SchemaEnvelope<Value> = serde_json::from_value(envelope.clone())
        .map_err(|_| PredicateReadError::MalformedPayload)?;
    untyped
        .require_contract(&predicate_schema_name(), consumer_version)
        .map_err(|_| PredicateReadError::UnsupportedContract)?;
    let payload = serde_json::from_value(untyped.payload)
        .map_err(|_| PredicateReadError::MalformedPayload)?;
    Ok(SchemaEnvelope::new(
        untyped.schema,
        untyped.version,
        payload,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::bundle::predicate_schema_version;
    use cauterizer_syntax::identifiers::OrganizationId;

    fn id(context: &str, n: u64) -> ContextQualifiedId {
        ContextQualifiedId::new(context, &format!("{n:08}")).unwrap()
    }

    fn v1_envelope_json() -> Value {
        serde_json::to_value(SchemaEnvelope::new(
            predicate_schema_name(),
            predicate_schema_version(),
            EvidencePredicateBodyV1 {
                verdict: RecordedVerdict::VerifiedForFixture,
                assessment_ref: id("assessment", 1),
                scope: EvidenceScope {
                    organization_id: OrganizationId::new("00000000").unwrap(),
                    run_id: id("run", 1),
                },
                materials: vec![EvidenceMaterial {
                    name: "baseline-observation".into(),
                    digest: cauterizer_syntax::digest::Sha256Digest::of_bytes(b"baseline"),
                }],
            },
        ))
        .unwrap()
    }

    fn v2_envelope_json() -> Value {
        serde_json::to_value(SchemaEnvelope::new(
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
                    digest: cauterizer_syntax::digest::Sha256Digest::of_bytes(b"baseline"),
                }],
                policy_ref: id("verification-policy", 7),
            },
        ))
        .unwrap()
    }

    #[test]
    fn v1_reader_accepts_a_v1_envelope() {
        let read = read_predicate_v1(&v1_envelope_json(), &predicate_schema_version()).unwrap();
        assert_eq!(read.payload.verdict, RecordedVerdict::VerifiedForFixture);
    }

    #[test]
    fn v1_reader_rejects_a_v2_shaped_envelope_at_the_version_gate() {
        assert_eq!(
            read_predicate_v1(&v2_envelope_json(), &predicate_schema_version()),
            Err(PredicateReadError::UnsupportedContract)
        );
    }

    #[test]
    fn v2_reader_accepts_a_v2_envelope_and_reads_the_policy_binding() {
        let read = read_predicate_v2(&v2_envelope_json(), &predicate_schema_version_v2()).unwrap();
        assert_eq!(read.payload.policy_ref, id("verification-policy", 7));
    }

    #[test]
    fn v2_reader_rejects_a_v1_envelope_at_the_version_gate_rather_than_defaulting_a_policy_ref() {
        assert_eq!(
            read_predicate_v2(&v1_envelope_json(), &predicate_schema_version_v2()),
            Err(PredicateReadError::UnsupportedContract)
        );
    }
}
