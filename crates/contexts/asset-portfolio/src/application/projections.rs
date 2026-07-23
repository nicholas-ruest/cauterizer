//! Tenant-filtered Asset Portfolio read projection.

use std::collections::BTreeMap;

use crate::contracts::{
    AssetPortfolioEventPayloadV1, AssetPortfolioEventV1, TargetResolutionReceiptV1,
};
use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};

/// Minimal tenant-safe asset view for application queries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetView {
    /// Owning tenant.
    pub organization_id: OrganizationId,
    /// Asset identity.
    pub asset_id: ContextQualifiedId,
    /// Canonical source locator.
    pub source_locator: String,
    /// Whether ownership and target authorization remain active.
    pub active: bool,
    /// Most recently published immutable target resolution.
    pub resolved_target: Option<TargetResolutionReceiptV1>,
}

/// Projection application failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionError {
    /// Event, receipt, asset, or source tenant/destination did not match.
    TenantMismatch,
    /// The tenant-qualified asset was absent.
    MissingAsset,
    /// One resolution identity was reused for different immutable content.
    ImmutableResolutionConflict,
}

/// Deterministic tenant-partitioned projection.
#[derive(Default)]
pub struct AssetProjection {
    assets: BTreeMap<(OrganizationId, ContextQualifiedId), AssetView>,
}

impl AssetProjection {
    /// Applies one already authenticated, ordered event.
    ///
    /// # Errors
    ///
    /// Rejects absent assets, tenant/source substitution, inactive targets, or
    /// conflicting reuse of an immutable resolution identity.
    pub fn apply(&mut self, event: &AssetPortfolioEventV1) -> Result<(), ProjectionError> {
        match &event.payload {
            AssetPortfolioEventPayloadV1::AssetRegistered {
                asset_id,
                source_locator,
            } => {
                self.assets.insert(
                    (event.organization_id.clone(), asset_id.clone()),
                    AssetView {
                        organization_id: event.organization_id.clone(),
                        asset_id: asset_id.clone(),
                        source_locator: source_locator.clone(),
                        active: true,
                        resolved_target: None,
                    },
                );
                Ok(())
            }
            AssetPortfolioEventPayloadV1::AssetDeactivated { asset_id } => {
                self.asset_mut(&event.organization_id, asset_id)?.active = false;
                Ok(())
            }
            AssetPortfolioEventPayloadV1::TargetRevisionResolved { receipt } => {
                if receipt.organization_id != event.organization_id {
                    return Err(ProjectionError::TenantMismatch);
                }
                let view = self.asset_mut(&event.organization_id, &receipt.asset_id)?;
                if !view.active || view.source_locator != receipt.source_locator {
                    return Err(ProjectionError::TenantMismatch);
                }
                if let Some(existing) = &view.resolved_target {
                    if existing.resolution_id == receipt.resolution_id && existing != receipt {
                        return Err(ProjectionError::ImmutableResolutionConflict);
                    }
                }
                view.resolved_target = Some(receipt.clone());
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Gets an asset only within the caller's exact tenant partition.
    #[must_use]
    pub fn get(
        &self,
        organization_id: &OrganizationId,
        asset_id: &ContextQualifiedId,
    ) -> Option<&AssetView> {
        self.assets
            .get(&(organization_id.clone(), asset_id.clone()))
    }

    fn asset_mut(
        &mut self,
        org: &OrganizationId,
        asset: &ContextQualifiedId,
    ) -> Result<&mut AssetView, ProjectionError> {
        self.assets
            .get_mut(&(org.clone(), asset.clone()))
            .ok_or(ProjectionError::MissingAsset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::TargetResolutionReceiptV1;
    use cauterizer_syntax::digest::Sha256Digest;
    use cauterizer_syntax::identifiers::{AggregateSequence, CausationId, CorrelationId};
    use cauterizer_syntax::schema::{SchemaName, SchemaVersion};
    use cauterizer_syntax::time::UtcInstant;

    fn event(org: &str, payload: AssetPortfolioEventPayloadV1) -> AssetPortfolioEventV1 {
        AssetPortfolioEventV1 {
            schema_name: SchemaName::parse(crate::contracts::EVENT_SCHEMA_NAME).unwrap(),
            schema_version: SchemaVersion::parse(crate::contracts::CONTRACT_VERSION).unwrap(),
            organization_id: OrganizationId::new(org).unwrap(),
            aggregate_id: "portfolio_00000000".parse().unwrap(),
            aggregate_sequence: AggregateSequence::new(1).unwrap(),
            event_id: "event_00000000".parse().unwrap(),
            occurred_at: UtcInstant::parse("2026-07-23T00:00:00Z").unwrap(),
            correlation_id: CorrelationId::new("00000000").unwrap(),
            causation_id: CausationId::new("00000000").unwrap(),
            payload,
        }
    }

    fn receipt(org: &str) -> TargetResolutionReceiptV1 {
        TargetResolutionReceiptV1 {
            organization_id: OrganizationId::new(org).unwrap(),
            asset_id: "asset_00000000".parse().unwrap(),
            resolution_id: "resolution_00000000".parse().unwrap(),
            source_locator: "https://source.example/acme/widget".into(),
            commit_id: "0123456789abcdef0123456789abcdef01234567".into(),
            acquisition_artifact_digest: Sha256Digest::of_bytes(b"bundle"),
            resolved_at: UtcInstant::parse("2026-07-23T00:00:00Z").unwrap(),
        }
    }

    fn registered(org: &str) -> AssetPortfolioEventV1 {
        event(
            org,
            AssetPortfolioEventPayloadV1::AssetRegistered {
                asset_id: "asset_00000000".parse().unwrap(),
                source_locator: "https://source.example/acme/widget".into(),
            },
        )
    }

    #[test]
    fn reads_and_resolution_application_are_tenant_scoped() {
        let mut projection = AssetProjection::default();
        projection.apply(&registered("00000000")).unwrap();
        projection
            .apply(&event(
                "00000000",
                AssetPortfolioEventPayloadV1::TargetRevisionResolved {
                    receipt: receipt("00000000"),
                },
            ))
            .unwrap();
        let asset: ContextQualifiedId = "asset_00000000".parse().unwrap();
        assert!(
            projection
                .get(&OrganizationId::new("00000000").unwrap(), &asset)
                .is_some()
        );
        assert!(
            projection
                .get(&OrganizationId::new("11111111").unwrap(), &asset)
                .is_none()
        );
        assert_eq!(
            projection.apply(&event(
                "00000000",
                AssetPortfolioEventPayloadV1::TargetRevisionResolved {
                    receipt: receipt("11111111"),
                }
            )),
            Err(ProjectionError::TenantMismatch)
        );
    }

    #[test]
    fn resolution_identity_is_immutable_and_destination_substitution_fails() {
        let mut projection = AssetProjection::default();
        projection.apply(&registered("00000000")).unwrap();
        let first = receipt("00000000");
        projection
            .apply(&event(
                "00000000",
                AssetPortfolioEventPayloadV1::TargetRevisionResolved {
                    receipt: first.clone(),
                },
            ))
            .unwrap();
        let mut changed_commit = first.clone();
        changed_commit.commit_id = "ffffffffffffffffffffffffffffffffffffffff".into();
        assert_eq!(
            projection.apply(&event(
                "00000000",
                AssetPortfolioEventPayloadV1::TargetRevisionResolved {
                    receipt: changed_commit,
                }
            )),
            Err(ProjectionError::ImmutableResolutionConflict)
        );
        let mut changed_source = first;
        changed_source.resolution_id = "resolution_11111111".parse().unwrap();
        changed_source.source_locator = "https://source.example/attacker/fork".into();
        assert_eq!(
            projection.apply(&event(
                "00000000",
                AssetPortfolioEventPayloadV1::TargetRevisionResolved {
                    receipt: changed_source,
                }
            )),
            Err(ProjectionError::TenantMismatch)
        );
    }
}
