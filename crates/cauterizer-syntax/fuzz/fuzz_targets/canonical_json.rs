#![no_main]

//! P15 AC-032 fuzz target: `canonical_json`'s parser is the entry point every
//! signed/canonicalized document in this workspace (evidence bundles, schema
//! envelopes, patch proposal briefs) passes through before it is trusted.
//! This target only asserts the same thing the `cauterizer-syntax`
//! `adversarial_proptests` module asserts (no panic, no unbounded resource
//! use) but over libFuzzer's coverage-guided corpus instead of proptest's
//! random generation, so it can find inputs proptest's strategies would not
//! think to construct.

use cauterizer_syntax::canonical_json::{canonicalize_json, is_canonical};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = canonicalize_json(data);
    let _ = is_canonical(data);
});
