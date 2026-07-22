//! Syntax-only primitives shared by bounded contexts.
//!
//! This crate must not acquire domain meaning or infrastructure dependencies.

#![forbid(unsafe_code)]

/// Returns the schema namespace owned by the platform syntax package.
#[must_use]
pub const fn schema_namespace() -> &'static str {
    "dev.cauterizer"
}
