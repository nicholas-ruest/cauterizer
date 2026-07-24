#![no_main]

//! P15 AC-032 fuzz target: exercises the exact deserialization path the P13
//! offline evidence bundle verifier
//! (`cauterizer_evidence::infrastructure::verifier::verify_bundle`) relies on
//! before any digest/signature check runs — `EvidenceStatement`'s
//! `#[serde(deny_unknown_fields)]` JSON deserialization, its
//! `require_contract` schema/version gate, and `canonical_json`
//! canonicalization of the parsed statement. An attacker who can place bytes
//! in front of this parser (an evidence bundle pulled from storage, an
//! export request body) controls this input; it must never panic regardless
//! of well-formedness.
//!
//! `EvidenceBundle` itself is not fuzzed directly here: its `signature`
//! field (`cauterizer_infrastructure::crypto::KeySignature`) intentionally
//! does not implement `Deserialize` (its `trust_label: &'static str` cannot
//! safely borrow from arbitrary input), so a bundle can never be
//! reconstructed from untrusted bytes alone — only its `EvidenceStatement`
//! half can, and that is exactly the surface this target drives.

use cauterizer_evidence::domain::bundle::{EvidenceStatement, predicate_schema_name, predicate_schema_version};
use cauterizer_syntax::canonical_json::canonicalize;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(statement) = serde_json::from_slice::<EvidenceStatement>(data) else {
        return;
    };
    let _ = statement
        .predicate
        .require_contract(&predicate_schema_name(), &predicate_schema_version());
    let _ = canonicalize(&statement);
});
