//! Versioned, provider-neutral Asset Portfolio published language.

use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{
    AggregateSequence, CausationId, ContextQualifiedId, CorrelationId, OrganizationId,
};
use cauterizer_syntax::schema::{SchemaName, SchemaVersion};
use cauterizer_syntax::time::UtcInstant;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Current contract revision.
pub const CONTRACT_VERSION: &str = "1.0.0";
/// Stable event schema identity.
pub const EVENT_SCHEMA_NAME: &str = "dev.cauterizer.asset-portfolio.event";

/// Provider-neutral request for restricted acquisition to resolve one target.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetResolutionRequestV1 {
    /// Owning tenant; adapters must not infer it from credentials or locators.
    pub organization_id: OrganizationId,
    /// Active organization-owned asset.
    pub asset_id: ContextQualifiedId,
    /// Unique request used for replay and destination binding.
    pub resolution_id: ContextQualifiedId,
    /// Canonical provider-neutral source locator validated before acquisition.
    pub source_locator: String,
    /// Immutable commit or mutable selector to resolve under acquisition policy.
    pub revision_selector: String,
    /// Trace identity.
    pub correlation_id: CorrelationId,
}

/// Immutable restricted-acquisition result safe for a run to bind.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetResolutionReceiptV1 {
    /// Tenant copied exactly from the authorized request.
    pub organization_id: OrganizationId,
    /// Asset copied exactly from the authorized request.
    pub asset_id: ContextQualifiedId,
    /// Request identity copied exactly from the authorized request.
    pub resolution_id: ContextQualifiedId,
    /// Canonical source locator that was actually acquired.
    pub source_locator: String,
    /// Immutable full commit identifier resolved by acquisition.
    #[serde(deserialize_with = "deserialize_commit_id")]
    pub commit_id: String,
    /// Digest of the committed acquisition artifact/bundle.
    pub acquisition_artifact_digest: Sha256Digest,
    /// Canonical resolution time.
    pub resolved_at: UtcInstant,
}

fn deserialize_commit_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if valid_commit_id(&value) {
        Ok(value)
    } else {
        Err(serde::de::Error::custom(
            "commit_id must be 40..=64 lowercase hexadecimal characters",
        ))
    }
}

fn valid_commit_id(value: &str) -> bool {
    (40..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

impl TargetResolutionReceiptV1 {
    /// Ensures the receipt cannot substitute tenant, asset, request, or source.
    #[must_use]
    pub fn matches_request(&self, request: &TargetResolutionRequestV1) -> bool {
        valid_commit_id(&self.commit_id)
            && self.organization_id == request.organization_id
            && self.asset_id == request.asset_id
            && self.resolution_id == request.resolution_id
            && self.source_locator == request.source_locator
    }
}

/// Explainable scope result; exclusions have their own stable reason.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeReasonV1 {
    /// An explicit inclusion matched and no exclusion matched.
    ExplicitlyIncluded,
    /// An exclusion matched and overrides every inclusion.
    ExplicitlyExcluded,
    /// No inclusion authorized the target.
    NoMatchingInclusion,
    /// Asset or source ownership is inactive/revoked.
    OwnershipInactive,
}

/// Versioned event envelope.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetPortfolioEventV1 {
    /// Immutable schema identity.
    pub schema_name: SchemaName,
    /// Semantic schema revision.
    pub schema_version: SchemaVersion,
    /// Owning tenant.
    pub organization_id: OrganizationId,
    /// Portfolio aggregate identity.
    pub aggregate_id: ContextQualifiedId,
    /// Aggregate event ordering.
    pub aggregate_sequence: AggregateSequence,
    /// Unique event identity.
    pub event_id: ContextQualifiedId,
    /// Canonical occurrence time.
    pub occurred_at: UtcInstant,
    /// End-to-end trace.
    pub correlation_id: CorrelationId,
    /// Command or event which caused this fact.
    pub causation_id: CausationId,
    /// Consumer-required fact.
    pub payload: AssetPortfolioEventPayloadV1,
}

/// Published Asset Portfolio facts.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum AssetPortfolioEventPayloadV1 {
    /// An organization-owned asset was registered.
    AssetRegistered {
        /// Newly registered asset.
        asset_id: ContextQualifiedId,
        /// Canonical provider-neutral source.
        source_locator: String,
    },
    /// Explicit source ownership was verified.
    SourceOwnershipVerified {
        /// Asset whose source ownership was verified.
        asset_id: ContextQualifiedId,
    },
    /// Environment and criticality labels changed.
    AssetClassified {
        /// Classified asset.
        asset_id: ContextQualifiedId,
        /// Stable deployment environment label.
        environment: String,
        /// Stable criticality label.
        criticality: String,
    },
    /// Scope policy revision became active.
    AssetScopeDefined {
        /// Asset governed by the scope policy.
        asset_id: ContextQualifiedId,
        /// Immutable scope-policy revision.
        scope_version: String,
    },
    /// Ownership/target authorization was revoked.
    AssetDeactivated {
        /// Asset whose authorization was revoked.
        asset_id: ContextQualifiedId,
    },
    /// Restricted acquisition produced an immutable target receipt.
    TargetRevisionResolved {
        /// Immutable acquisition receipt.
        receipt: TargetResolutionReceiptV1,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use schemars::schema_for;
    use serde_json::{Value, json};

    fn request(org: &str) -> TargetResolutionRequestV1 {
        TargetResolutionRequestV1 {
            organization_id: OrganizationId::new(org).unwrap(),
            asset_id: "asset_00000000".parse().unwrap(),
            resolution_id: "resolution_00000000".parse().unwrap(),
            source_locator: "https://source.example/acme/widget".into(),
            revision_selector: "refs/heads/main".into(),
            correlation_id: "correlation_00000000".parse().unwrap(),
        }
    }

    fn receipt(org: &str) -> TargetResolutionReceiptV1 {
        TargetResolutionReceiptV1 {
            organization_id: OrganizationId::new(org).unwrap(),
            asset_id: "asset_00000000".parse().unwrap(),
            resolution_id: "resolution_00000000".parse().unwrap(),
            source_locator: "https://source.example/acme/widget".into(),
            commit_id: "0123456789abcdef0123456789abcdef01234567".into(),
            acquisition_artifact_digest: Sha256Digest::of_bytes(b"acquisition"),
            resolved_at: UtcInstant::parse("2026-07-23T00:00:00Z").unwrap(),
        }
    }

    #[test]
    fn receipt_binding_rejects_cross_tenant_and_destination_substitution() {
        let expected = request("00000000");
        assert!(receipt("00000000").matches_request(&expected));
        assert!(!receipt("11111111").matches_request(&expected));
        let mut substituted = receipt("00000000");
        substituted.source_locator = "https://source.example/attacker/fork".into();
        assert!(!substituted.matches_request(&expected));
    }

    #[test]
    fn resolution_schema_is_closed_and_requires_digest_and_commit() {
        let schema = serde_json::to_value(schema_for!(TargetResolutionReceiptV1)).unwrap();
        assert_eq!(schema["additionalProperties"], Value::Bool(false));
        let required = schema["required"].as_array().unwrap();
        assert!(required.contains(&json!("commit_id")));
        assert!(required.contains(&json!("acquisition_artifact_digest")));
        let mut wire = serde_json::to_value(receipt("00000000")).unwrap();
        wire.as_object_mut()
            .unwrap()
            .insert("provider_repository_id".into(), json!(42));
        assert!(serde_json::from_value::<TargetResolutionReceiptV1>(wire).is_err());
    }

    #[test]
    fn receipt_deserialization_rejects_mutable_or_malformed_commits() {
        for invalid in [
            "main",
            "ABCDEF0123456789ABCDEF0123456789ABCDEF01",
            "0123456789abcdef",
        ] {
            let mut wire = serde_json::to_value(receipt("00000000")).unwrap();
            wire["commit_id"] = json!(invalid);
            assert!(
                serde_json::from_value::<TargetResolutionReceiptV1>(wire).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn contracts_do_not_expose_scm_provider_types() {
        let schema = format!(
            "{}{}",
            serde_json::to_string(&schema_for!(TargetResolutionRequestV1)).unwrap(),
            serde_json::to_string(&schema_for!(TargetResolutionReceiptV1)).unwrap()
        )
        .to_ascii_lowercase();
        for forbidden in [
            "github",
            "gitlab",
            "bitbucket",
            "scm_client",
            "provider_token",
        ] {
            assert!(
                !schema.contains(forbidden),
                "provider type leaked: {forbidden}"
            );
        }
    }

    #[test]
    fn exclusion_reason_is_distinct_and_stable() {
        assert_eq!(
            serde_json::to_value(ScopeReasonV1::ExplicitlyExcluded).unwrap(),
            json!("explicitly_excluded")
        );
        assert_ne!(
            ScopeReasonV1::ExplicitlyExcluded,
            ScopeReasonV1::ExplicitlyIncluded
        );
    }
}
