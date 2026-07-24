//! In-toto Statement v1-shaped evidence bundle: subject, versioned predicate,
//! and the signature that binds them.
//!
//! This module is deliberately signer-agnostic: it holds no opinion about
//! *which* [`SignerPort`] produced a [`crate::domain::bundle::EvidenceBundle`]'s
//! signature. Only the application-layer assemble handler and the
//! infrastructure-layer verifier decide who may sign and what a bundle's
//! trust label is allowed to mean.

use cauterizer_infrastructure::crypto::KeySignature;
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
use cauterizer_syntax::schema::{SchemaEnvelope, SchemaName, SchemaVersion};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The in-toto `Statement` type this bundle's `_type` field always carries.
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
/// The Cauterizer-owned `predicateType` URI for the P13 evidence predicate.
pub const PREDICATE_TYPE_URI: &str = "https://cauterizer.dev/attestation/evidence-bundle/v1";

/// Returns the reverse-DNS schema name identifying the evidence predicate body.
///
/// # Panics
///
/// Never panics: the literal is a checked-in canonical schema name.
#[must_use]
pub fn predicate_schema_name() -> SchemaName {
    SchemaName::parse("dev.cauterizer.evidence.bundle").expect("checked-in canonical schema name")
}

/// Returns the current predicate body schema revision.
///
/// # Panics
///
/// Never panics: the literal is a checked-in canonical semantic version.
#[must_use]
pub fn predicate_schema_version() -> SchemaVersion {
    SchemaVersion::parse("1.0.0").expect("checked-in canonical schema version")
}

/// Local mirror of Remediation Runs' `RecordedVerdict`.
///
/// Evidence never recomputes a verdict; it only records, verbatim, the value
/// Verification produced and Remediation Runs already accepted. This type is
/// intentionally re-declared here (rather than imported across the bounded
/// context boundary) so Evidence's published predicate never depends on
/// another context's internal aggregate.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordedVerdict {
    /// Candidate satisfied the policy for the named fixture.
    VerifiedForFixture,
    /// Candidate deterministically failed verification.
    Rejected,
    /// Available observations could not establish a result.
    Inconclusive,
    /// Verification observed a prohibited information flow.
    NonConformant,
}

/// One in-toto `subject` entry: a named artifact and its content digest.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSubject {
    /// Human-readable role of this subject within the bundle (for example
    /// `"candidate-patch"`).
    pub name: String,
    /// Immutable content digest of the subject artifact.
    pub digest: Sha256Digest,
}

/// One supporting `materials` entry referenced, but not attested to, by the predicate.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceMaterial {
    /// Human-readable role of this material (for example `"baseline-observation"`).
    pub name: String,
    /// Immutable content digest of the material artifact.
    pub digest: Sha256Digest,
}

/// Organization/run binding bound once into the predicate.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceScope {
    /// Owning tenant.
    pub organization_id: OrganizationId,
    /// Remediation Runs run this bundle finalizes evidence for.
    pub run_id: ContextQualifiedId,
}

/// Cauterizer-owned predicate body (schema major `1`) carried inside the
/// versioned [`SchemaEnvelope`].
///
/// This is the checked-in v1 wire shape: `schemas/evidence/evidence-predicate-body.v1.schema.json`.
/// See [`crate::domain::predicate_v2`] for the v2 evolution and the versioned
/// offline readers that prove v1 and v2 are never conflated.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidencePredicateBodyV1 {
    /// Verbatim recorded verdict.
    pub verdict: RecordedVerdict,
    /// Immutable reference to the Verification assessment this bundle attests to.
    pub assessment_ref: ContextQualifiedId,
    /// Organization/run binding.
    pub scope: EvidenceScope,
    /// Supporting materials referenced by, but not asserted as, the subject.
    pub materials: Vec<EvidenceMaterial>,
}

/// Versioned Cauterizer predicate: schema identity plus the v1 predicate body.
pub type EvidencePredicate = SchemaEnvelope<EvidencePredicateBodyV1>;

/// The exact bytes that get canonicalized and signed: an in-toto `Statement`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceStatement {
    /// Always [`STATEMENT_TYPE`].
    #[serde(rename = "_type")]
    pub type_: String,
    /// Attested artifacts.
    pub subject: Vec<EvidenceSubject>,
    /// Always [`PREDICATE_TYPE_URI`].
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    /// Versioned Cauterizer predicate.
    pub predicate: EvidencePredicate,
}

/// A complete signed evidence bundle: the statement plus its signature.
///
/// Deliberately holds no `new`/public constructor beyond field access: the
/// only way to obtain one backed by a real signature is
/// [`crate::application::assemble::assemble_bundle`], which always derives the
/// signature from an injected [`cauterizer_infrastructure::crypto::SignerPort`]
/// rather than accepting a caller-supplied signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceBundle {
    /// The signed statement.
    pub statement: EvidenceStatement,
    /// Signature over the statement's canonical JCS bytes.
    pub signature: KeySignature,
}

impl EvidenceStatement {
    /// Constructs a statement from its subject list and predicate.
    #[must_use]
    pub fn new(subject: Vec<EvidenceSubject>, predicate: EvidencePredicate) -> Self {
        Self {
            type_: STATEMENT_TYPE.to_owned(),
            subject,
            predicate_type: PREDICATE_TYPE_URI.to_owned(),
            predicate,
        }
    }
}

/// Deterministic port every referenced digest must resolve through.
///
/// Both bundle assembly and offline verification fail closed when a
/// referenced digest does not resolve: assembly never partially constructs a
/// bundle over an artifact that cannot be confirmed, and verification never
/// accepts a bundle that references material the oracle cannot confirm.
pub trait ArtifactDigestOracle {
    /// Returns whether a real artifact is known under this exact digest.
    fn exists(&self, digest: Sha256Digest) -> bool;
}

impl<T: ArtifactDigestOracle + ?Sized> ArtifactDigestOracle for &T {
    fn exists(&self, digest: Sha256Digest) -> bool {
        (**self).exists(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cauterizer_syntax::canonical_json::canonicalize;

    fn org() -> OrganizationId {
        OrganizationId::new("00000000").unwrap()
    }
    fn id(context: &str, n: u64) -> ContextQualifiedId {
        ContextQualifiedId::new(context, &format!("{n:08}")).unwrap()
    }

    fn statement() -> EvidenceStatement {
        let predicate = SchemaEnvelope::new(
            predicate_schema_name(),
            predicate_schema_version(),
            EvidencePredicateBodyV1 {
                verdict: RecordedVerdict::VerifiedForFixture,
                assessment_ref: id("assessment", 1),
                scope: EvidenceScope {
                    organization_id: org(),
                    run_id: id("run", 1),
                },
                materials: vec![EvidenceMaterial {
                    name: "baseline-observation".into(),
                    digest: Sha256Digest::of_bytes(b"baseline"),
                }],
            },
        );
        EvidenceStatement::new(
            vec![EvidenceSubject {
                name: "candidate-patch".into(),
                digest: Sha256Digest::of_bytes(b"patch"),
            }],
            predicate,
        )
    }

    #[test]
    fn statement_serializes_as_a_well_formed_in_toto_v1_envelope() {
        let json = serde_json::to_value(statement()).unwrap();
        assert_eq!(json["_type"], STATEMENT_TYPE);
        assert_eq!(json["predicateType"], PREDICATE_TYPE_URI);
        assert_eq!(json["subject"][0]["name"], "candidate-patch");
        assert_eq!(
            json["predicate"]["schema"],
            "dev.cauterizer.evidence.bundle"
        );
        assert_eq!(json["predicate"]["version"], "1.0.0");
        assert_eq!(
            json["predicate"]["payload"]["verdict"],
            "verified_for_fixture"
        );
    }

    #[test]
    fn statement_round_trips_through_json() {
        let original = statement();
        let json = serde_json::to_string(&original).unwrap();
        let reparsed: EvidenceStatement = serde_json::from_str(&json).unwrap();
        assert_eq!(original, reparsed);
    }

    #[test]
    fn canonicalization_is_deterministic_across_repeated_calls() {
        let a = canonicalize(&statement()).unwrap();
        let b = canonicalize(&statement()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn every_recorded_verdict_variant_has_a_stable_snake_case_wire_label() {
        for (verdict, label) in [
            (
                RecordedVerdict::VerifiedForFixture,
                "\"verified_for_fixture\"",
            ),
            (RecordedVerdict::Rejected, "\"rejected\""),
            (RecordedVerdict::Inconclusive, "\"inconclusive\""),
            (RecordedVerdict::NonConformant, "\"non_conformant\""),
        ] {
            assert_eq!(serde_json::to_string(&verdict).unwrap(), label);
        }
    }

    #[test]
    fn statement_rejects_unknown_fields_on_deserialize() {
        let mut json = serde_json::to_value(statement()).unwrap();
        json["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<EvidenceStatement>(json).is_err());
    }

    struct SetOracle(std::collections::HashSet<Sha256Digest>);
    impl ArtifactDigestOracle for SetOracle {
        fn exists(&self, digest: Sha256Digest) -> bool {
            self.0.contains(&digest)
        }
    }

    #[test]
    fn digest_oracle_is_object_safe_and_usable_by_reference() {
        let oracle = SetOracle(std::collections::HashSet::from([Sha256Digest::of_bytes(
            b"known",
        )]));
        let as_ref: &dyn ArtifactDigestOracle = &oracle;
        assert!(as_ref.exists(Sha256Digest::of_bytes(b"known")));
        assert!(!as_ref.exists(Sha256Digest::of_bytes(b"unknown")));
    }
}
