//! Syntax-only primitives shared by bounded contexts.
//!
//! This crate must not acquire domain meaning or infrastructure dependencies.

#![forbid(unsafe_code)]

pub mod authorization;
pub mod canonical_json;
pub mod classification;
pub mod digest;
pub mod envelope;
pub mod identifiers;
pub mod schema;
pub mod sensitive;
pub mod time;

/// Returns the schema namespace owned by the platform syntax package.
#[must_use]
pub const fn schema_namespace() -> &'static str {
    "dev.cauterizer"
}
