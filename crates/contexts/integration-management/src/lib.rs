//! Integration Management bounded context.
#![forbid(unsafe_code)]

/// Application-owned SCM connector port and reference adapter.
pub mod application;
/// Versioned published language.
pub mod contracts;
/// Provider-neutral integration policy and installation grants.
pub mod domain;

/// Stable bounded-context name.
pub const CONTEXT_NAME: &str = "integration-management";
