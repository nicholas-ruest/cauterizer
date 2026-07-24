//! Versioned wire contracts for the endpoints this crate wraps.
//!
//! These reuse the same validated identifier newtypes
//! (`cauterizer_syntax::identifiers`) the wrapped facade itself uses, so the
//! generated JSON Schema reflects the exact same validation the facade enforces
//! rather than a looser boundary-only shape.

use cauterizer_syntax::identifiers::{ActorId, CausationId, CorrelationId, OrganizationId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Request body for `POST /v1/organizations:bootstrap-local`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapOrganizationRequestV1 {
    /// Explicit local tenant scope; retries must address the same organization.
    pub organization_id: OrganizationId,
    /// Bounded organization display name.
    pub organization_name: String,
    /// Pre-authenticated human owner reference; no password is created.
    pub owner_actor_id: ActorId,
    /// Logical request trace.
    pub correlation_id: CorrelationId,
    /// Bootstrap command identity.
    pub causation_id: CausationId,
}

/// Response body returned for both first execution and exact idempotent retries.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapOrganizationResponseV1 {
    /// Created organization.
    pub organization_id: OrganizationId,
    /// Initial owner membership.
    pub owner_member_id: String,
    /// Persisted optimistic version; also surfaced as the response `ETag`.
    pub version: u64,
}
