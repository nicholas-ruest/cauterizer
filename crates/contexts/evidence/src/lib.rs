//! Evidence bounded context.
#![forbid(unsafe_code)]
/// Domain model and policies.
pub mod domain {
    /// In-toto-shaped evidence bundle aggregate and versioned predicate.
    pub mod bundle;
}
/// Application use cases and owned ports.
pub mod application {
    /// Assemble-and-sign bundle handler.
    pub mod assemble;
}
/// Versioned published language.
pub mod contracts {}
/// Replaceable offline verification boundary.
pub mod infrastructure {
    /// Offline in-toto bundle verifier.
    pub mod verifier;
}
/// Stable bounded-context name.
pub const CONTEXT_NAME: &str = "evidence";
