//! Versioned, one-way public language.

/// The immutable proposal fact exposed to verification without solver inputs,
/// patch bytes, telemetry, memory identifiers, or verdict claims.
pub use crate::domain::CandidatePatchRef as PatchProposedV1;
