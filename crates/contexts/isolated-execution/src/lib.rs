//! Isolated Execution bounded context.
#![forbid(unsafe_code)]
/// Domain model and policies.
pub mod domain;
/// Application use cases and owned ports.
pub mod application {
    /// Fail-closed local execution admission.
    pub mod admission;
    /// Signed worker-protocol authentication boundary.
    pub mod authentication;
    /// Transactional reference repository.
    pub mod memory;
    /// Persistence and trust boundaries.
    pub mod ports;
    /// In-memory authorization and audit reference adapters.
    pub mod security;
    /// Authorized replay-safe lease facade.
    pub mod service;
}
/// Worker protocol and P00-selected local backend.
pub mod infrastructure {
    /// Rootless Podman supervisor; always non-conformant-local.
    pub mod supervisor;
}
/// Versioned published language.
pub mod contracts;
/// Stable bounded-context name.
pub const CONTEXT_NAME: &str = "isolated-execution";
