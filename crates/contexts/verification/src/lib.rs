//! Verification bounded context.
#![forbid(unsafe_code)]
/// Domain model and policies.
pub mod domain {
    /// Qualification policy and leak-safe descriptors.
    pub mod qualification;
}
/// Application use cases and owned ports.
pub mod application {
    /// Solver/verifier artifact firewall and qualification admission.
    pub mod firewall;
}
/// Versioned published language.
pub mod contracts {
    use cauterizer_syntax::digest::Sha256Digest;
    use cauterizer_syntax::identifiers::OrganizationId;
    use serde::Serialize;

    /// Versioned, tenant-bound public fact emitted after fixture qualification.
    #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct FixtureQualifiedV1 {
        /// Owning tenant.
        pub organization_id: OrganizationId,
        /// Public fixture identifier.
        pub advisory_id: String,
        /// Qualification policy version.
        pub policy_version: String,
        /// Digest of the complete verifier-held qualification record.
        pub qualification_digest: Sha256Digest,
        /// Immutable acquisition manifest.
        pub acquisition_manifest_digest: Sha256Digest,
    }
}
/// Replaceable upstream adapters.
pub mod infrastructure {
    /// Pinned public benchmark anti-corruption adapter.
    pub mod pinned_fixture;
}
/// Stable bounded-context name.
pub const CONTEXT_NAME: &str = "verification";
