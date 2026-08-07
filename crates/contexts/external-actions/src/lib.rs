//! External Actions bounded context.
#![forbid(unsafe_code)]
/// Application use cases and owned ports.
pub mod application;
/// Domain model and policies.
pub mod domain;
/// Versioned published language.
pub mod contracts {}
/// Stable bounded-context name.
pub const CONTEXT_NAME: &str = "external-actions";
