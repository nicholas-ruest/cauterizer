//! Asset Portfolio bounded context.
#![forbid(unsafe_code)]
/// Domain model and policies.
pub mod domain;
/// Application use cases and owned ports.
pub mod application {
    /// Thread-safe reference adapters.
    pub mod memory;
    /// Application-owned persistence and security boundaries.
    pub mod ports;
    /// Tenant-filtered read projections derived from published facts.
    pub mod projections;
    /// Hardened acquisition resolver port and fixture adapter.
    pub mod resolver;
    /// Authorized, audited command and run-binding facade.
    pub mod service;
}
/// Versioned published language.
pub mod contracts;
/// Stable bounded-context name.
pub const CONTEXT_NAME: &str = "asset-portfolio";
