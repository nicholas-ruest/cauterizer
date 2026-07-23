//! Commercial Entitlements bounded context.
#![forbid(unsafe_code)]
/// Application use cases and owned ports.
pub mod application;
/// Versioned published language.
pub mod contracts;
/// Domain model and policies.
pub mod domain;
/// Stable bounded-context name.
pub const CONTEXT_NAME: &str = "commercial-entitlements";
