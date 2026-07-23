//! Advisory Intake bounded context.
#![forbid(unsafe_code)]
/// Domain model and policies.
pub mod domain;
/// Application use cases and owned ports.
pub mod application {
    /// Offline recorded-fixture acquisition and normalization adapter.
    pub mod fixture;
    /// Thread-safe reference adapters.
    pub mod memory;
    /// Application-owned persistence and trust boundaries.
    pub mod ports;
    /// Authorized and replay-safe command facade.
    pub mod service;
}
/// Versioned published language.
pub mod contracts;
/// Stable bounded-context name.
pub const CONTEXT_NAME: &str = "advisory-intake";
