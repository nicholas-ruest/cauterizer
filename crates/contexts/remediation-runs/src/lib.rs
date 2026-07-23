//! Remediation Runs bounded context.
#![forbid(unsafe_code)]
/// Domain model and policies.
pub mod domain;
/// Application use cases and owned ports.
pub mod application {
    /// Transactional in-memory reference adapters.
    pub mod memory;
    /// Application-owned persistence, inbox, authorization, and audit ports.
    pub mod ports;
    /// Rebuildable tenant-scoped lifecycle projections.
    pub mod projection;
    /// Authorized direct commands and authenticated owning-context handlers.
    pub mod service;
}
/// Versioned published language.
pub mod contracts;
/// Stable bounded-context name.
pub const CONTEXT_NAME: &str = "remediation-runs";
