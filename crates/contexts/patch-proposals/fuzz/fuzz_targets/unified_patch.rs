#![no_main]

use cauterizer_patch_proposals::domain::{
    PatchNormalizationService, ProposalBudget, SolverBrief,
};
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::ContextQualifiedId;
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;

fuzz_target!(|data: &[u8]| {
    let brief = SolverBrief {
        organization_id: "org_abcdefgh".parse().expect("static tenant"),
        run_id: ContextQualifiedId::new("run", "abcdefgh").expect("static run"),
        problem: "fuzz parser".into(),
        source_digest: Sha256Digest::of_bytes("source"),
        public_test_instructions: vec!["test".into()],
        allowed_paths: BTreeSet::from(["src/lib.rs".into()]),
        allowed_tools: BTreeSet::from(["patch".into()]),
        budget: ProposalBudget {
            attempts: 1,
            tokens: 1,
            cost_micros: 0,
            time_millis: 1,
            paths: 1,
            patch_bytes: 65_536,
            changed_lines: 4_096,
        },
        memory_namespace: None,
    };
    let _ = PatchNormalizationService::normalize(data, &brief);
});
