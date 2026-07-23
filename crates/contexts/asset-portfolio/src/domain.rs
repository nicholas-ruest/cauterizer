//! Private Asset Portfolio aggregate and pure target authorization policy.

use std::collections::BTreeMap;
use std::fmt;

use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
use serde::{Deserialize, Serialize};

macro_rules! owned_id {
    ($name:ident, $prefix:literal) => {
        #[doc = concat!("Asset Portfolio identifier with `", $prefix, "` prefix.")]
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        pub struct $name(ContextQualifiedId);
        impl $name {
            /// Creates an ID from a canonical opaque component.
            ///
            /// # Errors
            /// Returns [`AssetError::InvalidValue`] for invalid shared ID syntax.
            pub fn new(opaque: &str) -> Result<Self, AssetError> {
                ContextQualifiedId::new($prefix, opaque)
                    .map(Self)
                    .map_err(|_| AssetError::InvalidValue)
            }
            /// Returns the context-qualified spelling.
            #[must_use]
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }
    };
}
owned_id!(AssetId, "asset");
owned_id!(ResolutionId, "resolution");

/// Provider-neutral owned object kind.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AssetType {
    /// Version-controlled source repository.
    Repository,
    /// Published package coordinate.
    Package,
    /// Customer-defined software component.
    Component,
}

/// Deployment exposure category.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Environment {
    /// Development-only deployment.
    Development,
    /// Pre-production deployment.
    Staging,
    /// Production deployment.
    Production,
}

/// Customer-owned business-impact category.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Criticality {
    /// Low business impact.
    Low,
    /// Moderate business impact.
    Medium,
    /// High business impact.
    High,
    /// Critical business impact.
    Critical,
}

/// Strict, credential-free HTTPS source locator. Resolution remains an adapter concern.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SourceLocator(String);

impl SourceLocator {
    /// Parses a canonical public HTTPS locator without credentials, query, or fragment.
    ///
    /// # Errors
    /// Rejects non-HTTPS, ambiguous authorities, IP literals, local hosts, encoded
    /// separators, dot segments, control characters, and mutable URL parameters.
    pub fn parse(value: impl Into<String>) -> Result<Self, AssetError> {
        let value = value.into();
        if value.len() > 512
            || !value.starts_with("https://")
            || value.bytes().any(|b| b.is_ascii_control())
        {
            return Err(AssetError::InvalidSourceLocator);
        }
        let remainder = &value[8..];
        if remainder.contains(['?', '#', '@', '\\'])
            || remainder.to_ascii_lowercase().contains("%2f")
            || remainder.to_ascii_lowercase().contains("%5c")
        {
            return Err(AssetError::InvalidSourceLocator);
        }
        let (authority, path) = remainder
            .split_once('/')
            .ok_or(AssetError::InvalidSourceLocator)?;
        if authority.is_empty()
            || authority != authority.to_ascii_lowercase()
            || authority.starts_with('.')
            || authority.ends_with('.')
            || authority.contains("..")
            || authority.contains(':')
            || !authority.contains('.')
            || authority == "localhost"
            || authority.ends_with(".localhost")
            || authority.split('.').all(|part| part.parse::<u8>().is_ok())
        {
            return Err(AssetError::InvalidSourceLocator);
        }
        if !authority
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
            || path.is_empty()
            || path
                .split('/')
                .any(|part| part.is_empty() || matches!(part, "." | ".."))
        {
            return Err(AssetError::InvalidSourceLocator);
        }
        if !path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'-' | b'_'))
        {
            return Err(AssetError::InvalidSourceLocator);
        }
        Ok(Self(value))
    }
    /// Canonical locator string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Immutable selector sent to a restricted acquisition adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RevisionSelector {
    /// Exact lowercase hexadecimal commit/object identity.
    Commit(String),
    /// Customer-approved immutable package version.
    PackageVersion(String),
}

impl RevisionSelector {
    /// Validates that a selector is immutable and canonical.
    ///
    /// # Errors
    /// Rejects branch names, ranges, uppercase commits, and unbounded versions.
    pub fn validate(self) -> Result<Self, AssetError> {
        let valid = match &self {
            Self::Commit(value) => {
                (40..=64).contains(&value.len())
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            }
            Self::PackageVersion(value) => {
                !value.is_empty()
                    && value.len() <= 128
                    && !value.contains(['*', '^', '~', '>', '<', '=', ' '])
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
            }
        };
        if valid {
            Ok(self)
        } else {
            Err(AssetError::InvalidRevision)
        }
    }
}

/// Canonical path/component subject evaluated by scope policy.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ScopeSubject(String);
impl ScopeSubject {
    /// Parses a relative canonical subject.
    ///
    /// # Errors
    /// Rejects absolute, empty, dot-segment, repeated-separator, or control syntax.
    pub fn parse(value: impl Into<String>) -> Result<Self, AssetError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 512
            || value.starts_with('/')
            || value.contains("//")
            || value.contains('\\')
            || value
                .split('/')
                .any(|part| part.is_empty() || matches!(part, "." | ".."))
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'-' | b'_'))
        {
            return Err(AssetError::InvalidValue);
        }
        Ok(Self(value))
    }
    /// Returns the canonical relative subject.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Inclusion or exclusion prefix rule; exclusions always win globally.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ScopeRule {
    /// Includes this exact subject and descendants.
    Include(ScopeSubject),
    /// Excludes this exact subject and descendants.
    Exclude(ScopeSubject),
}

/// Stable explainable scope result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeReason {
    /// A matching inclusion authorized the subject.
    Included,
    /// A matching exclusion overrode every inclusion.
    ExplicitlyExcluded,
    /// No inclusion matched the subject.
    NoMatchingInclusion,
}

/// Pure scope decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScopeDecision {
    allowed: bool,
    reason: ScopeReason,
}
impl ScopeDecision {
    /// Whether at least one inclusion and no exclusion matched.
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        self.allowed
    }
    /// Stable policy reason.
    #[must_use]
    pub const fn reason(self) -> ScopeReason {
        self.reason
    }
}

/// Request sent to a networked acquisition port; the domain never resolves it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetResolutionRequest {
    /// Stable request/retry identity.
    pub resolution_id: ResolutionId,
    /// Aggregate-owned target asset.
    pub asset_id: AssetId,
    /// Exact approved source locator.
    pub source: SourceLocator,
    /// Immutable revision selector.
    pub selector: RevisionSelector,
}

/// Adapter receipt binding exact request inputs to immutable acquired material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TargetResolutionReceipt {
    /// Exact originating request identity.
    pub resolution_id: ResolutionId,
    /// Exact originating asset identity.
    pub asset_id: AssetId,
    /// Exact source observed by acquisition.
    pub source: SourceLocator,
    /// Exact selector resolved by acquisition.
    pub selector: RevisionSelector,
    /// Exact canonical commit/package identity observed after redirects.
    pub resolved_revision: String,
    /// Approved immutable acquisition bundle.
    pub acquisition_artifact_digest: Sha256Digest,
}

/// Domain facts emitted for atomic state/outbox persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AssetEvent {
    /// Asset entered the portfolio.
    AssetRegistered {
        /// Registered asset.
        asset_id: AssetId,
    },
    /// Source ownership became active.
    SourceOwnershipVerified {
        /// Verified asset.
        asset_id: AssetId,
    },
    /// Risk classification changed.
    AssetClassified {
        /// Classified asset.
        asset_id: AssetId,
    },
    /// Scope policy changed.
    AssetScopeDefined {
        /// Scoped asset.
        asset_id: AssetId,
    },
    /// Asset stopped accepting new targets.
    AssetDeactivated {
        /// Deactivated asset.
        asset_id: AssetId,
    },
    /// Acquisition resolved an immutable revision.
    TargetRevisionResolved {
        /// Resolved asset.
        asset_id: AssetId,
        /// Immutable resolution receipt.
        resolution_id: ResolutionId,
    },
}

#[derive(Clone, Debug)]
struct Asset {
    kind: AssetType,
    source: SourceLocator,
    environment: Environment,
    criticality: Criticality,
    ownership_active: bool,
    active: bool,
    scope: Vec<ScopeRule>,
    resolutions: BTreeMap<ResolutionId, TargetResolutionReceipt>,
}

/// Persistence-safe state for one asset without pending domain events.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssetSnapshot {
    /// Aggregate-owned asset ID.
    pub id: AssetId,
    /// Provider-neutral object kind.
    pub kind: AssetType,
    /// Authorized canonical source.
    pub source: SourceLocator,
    /// Deployment environment.
    pub environment: Environment,
    /// Customer-owned criticality.
    pub criticality: Criticality,
    /// Whether current ownership authorization is active.
    pub ownership_active: bool,
    /// Whether new target binding is active.
    pub active: bool,
    /// Ordered inclusion/exclusion policy.
    pub scope: Vec<ScopeRule>,
    /// Immutable accepted resolution receipts.
    pub resolutions: Vec<TargetResolutionReceipt>,
}

/// Sole organization-owned asset aggregate.
#[derive(Clone, Debug)]
pub struct AssetPortfolio {
    organization_id: OrganizationId,
    assets: BTreeMap<AssetId, Asset>,
    pending_events: Vec<AssetEvent>,
}

impl AssetPortfolio {
    /// Creates an empty organization portfolio.
    #[must_use]
    pub const fn new(organization_id: OrganizationId) -> Self {
        Self {
            organization_id,
            assets: BTreeMap::new(),
            pending_events: Vec::new(),
        }
    }
    /// Immutable tenant boundary.
    #[must_use]
    pub const fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }
    /// Produces deterministic persistence state without transient pending events.
    #[must_use]
    pub fn snapshot(&self) -> Vec<AssetSnapshot> {
        self.assets
            .iter()
            .map(|(id, asset)| AssetSnapshot {
                id: id.clone(),
                kind: asset.kind,
                source: asset.source.clone(),
                environment: asset.environment,
                criticality: asset.criticality,
                ownership_active: asset.ownership_active,
                active: asset.active,
                scope: asset.scope.clone(),
                resolutions: asset.resolutions.values().cloned().collect(),
            })
            .collect()
    }
    /// Rehydrates repository state while rechecking cross-field invariants.
    ///
    /// # Errors
    /// Rejects duplicate assets/resolutions, receipt-to-asset mismatches, or an
    /// active scope policy without an inclusion.
    pub fn rehydrate(
        organization_id: OrganizationId,
        snapshots: Vec<AssetSnapshot>,
    ) -> Result<Self, AssetError> {
        let mut assets = BTreeMap::new();
        for snapshot in snapshots {
            if assets.contains_key(&snapshot.id)
                || (!snapshot.scope.is_empty()
                    && !snapshot
                        .scope
                        .iter()
                        .any(|rule| matches!(rule, ScopeRule::Include(_))))
            {
                return Err(AssetError::InvalidSnapshot);
            }
            let mut resolutions = BTreeMap::new();
            for receipt in snapshot.resolutions {
                if receipt.asset_id != snapshot.id
                    || resolutions
                        .insert(receipt.resolution_id.clone(), receipt)
                        .is_some()
                {
                    return Err(AssetError::InvalidSnapshot);
                }
            }
            assets.insert(
                snapshot.id,
                Asset {
                    kind: snapshot.kind,
                    source: snapshot.source,
                    environment: snapshot.environment,
                    criticality: snapshot.criticality,
                    ownership_active: snapshot.ownership_active,
                    active: snapshot.active,
                    scope: snapshot.scope,
                    resolutions,
                },
            );
        }
        Ok(Self {
            organization_id,
            assets,
            pending_events: Vec::new(),
        })
    }
    /// Registers an inactive, not-yet-owned source.
    ///
    /// # Errors
    /// Rejects duplicate asset identities.
    pub fn register(
        &mut self,
        id: AssetId,
        kind: AssetType,
        source: SourceLocator,
        environment: Environment,
        criticality: Criticality,
    ) -> Result<(), AssetError> {
        if self.assets.contains_key(&id) {
            return Err(AssetError::AssetAlreadyExists);
        }
        self.assets.insert(
            id.clone(),
            Asset {
                kind,
                source,
                environment,
                criticality,
                ownership_active: false,
                active: true,
                scope: Vec::new(),
                resolutions: BTreeMap::new(),
            },
        );
        self.pending_events
            .push(AssetEvent::AssetRegistered { asset_id: id });
        Ok(())
    }
    /// Marks explicit source ownership verified by an application adapter.
    ///
    /// # Errors
    /// Rejects absent or inactive assets.
    pub fn verify_ownership(&mut self, id: &AssetId) -> Result<(), AssetError> {
        let asset = self.active_mut(id)?;
        if !asset.ownership_active {
            asset.ownership_active = true;
            self.pending_events
                .push(AssetEvent::SourceOwnershipVerified {
                    asset_id: id.clone(),
                });
        }
        Ok(())
    }
    /// Revokes source authority immediately and prevents new target binding.
    ///
    /// # Errors
    /// Rejects absent assets.
    pub fn revoke_ownership(&mut self, id: &AssetId) -> Result<(), AssetError> {
        let asset = self.assets.get_mut(id).ok_or(AssetError::AssetNotFound)?;
        asset.ownership_active = false;
        Ok(())
    }
    /// Reclassifies environment and criticality without changing target identity.
    ///
    /// # Errors
    /// Rejects absent or inactive assets.
    pub fn classify(
        &mut self,
        id: &AssetId,
        environment: Environment,
        criticality: Criticality,
    ) -> Result<(), AssetError> {
        let asset = self.active_mut(id)?;
        asset.environment = environment;
        asset.criticality = criticality;
        self.pending_events.push(AssetEvent::AssetClassified {
            asset_id: id.clone(),
        });
        Ok(())
    }
    /// Replaces scope rules after validating at least one inclusion.
    ///
    /// # Errors
    /// Rejects absent/inactive assets or an exclusion-only policy.
    pub fn define_scope(&mut self, id: &AssetId, rules: Vec<ScopeRule>) -> Result<(), AssetError> {
        if rules.is_empty()
            || !rules
                .iter()
                .any(|rule| matches!(rule, ScopeRule::Include(_)))
        {
            return Err(AssetError::InvalidScope);
        }
        let asset = self.active_mut(id)?;
        asset.scope = rules;
        self.pending_events.push(AssetEvent::AssetScopeDefined {
            asset_id: id.clone(),
        });
        Ok(())
    }
    /// Evaluates exclusion-first prefix matching.
    #[must_use]
    pub fn evaluate_scope(&self, id: &AssetId, subject: &ScopeSubject) -> ScopeDecision {
        let Some(asset) = self
            .assets
            .get(id)
            .filter(|asset| asset.active && asset.ownership_active)
        else {
            return ScopeDecision {
                allowed: false,
                reason: ScopeReason::NoMatchingInclusion,
            };
        };
        if asset.scope.iter().any(
            |rule| matches!(rule, ScopeRule::Exclude(prefix) if prefix_matches(prefix, subject)),
        ) {
            return ScopeDecision {
                allowed: false,
                reason: ScopeReason::ExplicitlyExcluded,
            };
        }
        if asset.scope.iter().any(
            |rule| matches!(rule, ScopeRule::Include(prefix) if prefix_matches(prefix, subject)),
        ) {
            ScopeDecision {
                allowed: true,
                reason: ScopeReason::Included,
            }
        } else {
            ScopeDecision {
                allowed: false,
                reason: ScopeReason::NoMatchingInclusion,
            }
        }
    }
    /// Deactivates asset and ownership for all future admissions.
    ///
    /// # Errors
    /// Rejects absent assets.
    pub fn deactivate(&mut self, id: &AssetId) -> Result<(), AssetError> {
        let asset = self.assets.get_mut(id).ok_or(AssetError::AssetNotFound)?;
        asset.active = false;
        asset.ownership_active = false;
        self.pending_events.push(AssetEvent::AssetDeactivated {
            asset_id: id.clone(),
        });
        Ok(())
    }
    /// Creates an exact network acquisition request for an active owned asset.
    ///
    /// # Errors
    /// Rejects absent, inactive, unowned assets or invalid selectors.
    pub fn request_resolution(
        &self,
        resolution_id: ResolutionId,
        asset_id: &AssetId,
        selector: RevisionSelector,
    ) -> Result<TargetResolutionRequest, AssetError> {
        let asset = self.assets.get(asset_id).ok_or(AssetError::AssetNotFound)?;
        if !asset.active {
            return Err(AssetError::AssetInactive);
        }
        if !asset.ownership_active {
            return Err(AssetError::OwnershipNotVerified);
        }
        Ok(TargetResolutionRequest {
            resolution_id,
            asset_id: asset_id.clone(),
            source: asset.source.clone(),
            selector: selector.validate()?,
        })
    }
    /// Accepts only a receipt matching the exact request and freezes it by ID.
    ///
    /// # Errors
    /// Rejects destination substitution, mutable/invalid resolved identities, and
    /// conflicting attempts to replace an existing immutable receipt.
    pub fn accept_resolution(
        &mut self,
        request: &TargetResolutionRequest,
        receipt: TargetResolutionReceipt,
    ) -> Result<TargetResolutionReceipt, AssetError> {
        if receipt.resolution_id != request.resolution_id
            || receipt.asset_id != request.asset_id
            || receipt.source != request.source
            || receipt.selector != request.selector
        {
            return Err(AssetError::DestinationSubstitution);
        }
        validate_resolved_revision(&receipt.resolved_revision)?;
        let asset = self.active_mut(&request.asset_id)?;
        if !asset.ownership_active {
            return Err(AssetError::OwnershipNotVerified);
        }
        if let Some(existing) = asset.resolutions.get(&receipt.resolution_id) {
            return if existing == &receipt {
                Ok(existing.clone())
            } else {
                Err(AssetError::ImmutableRevisionConflict)
            };
        }
        asset
            .resolutions
            .insert(receipt.resolution_id.clone(), receipt.clone());
        self.pending_events
            .push(AssetEvent::TargetRevisionResolved {
                asset_id: request.asset_id.clone(),
                resolution_id: receipt.resolution_id.clone(),
            });
        Ok(receipt)
    }
    /// Authorizes a run binding only for an active, owned, in-scope immutable receipt.
    ///
    /// # Errors
    /// Returns a stable reason when any required target property is absent.
    pub fn authorize_target(
        &self,
        asset_id: &AssetId,
        resolution_id: &ResolutionId,
        subject: &ScopeSubject,
    ) -> Result<&TargetResolutionReceipt, AssetError> {
        let asset = self.assets.get(asset_id).ok_or(AssetError::AssetNotFound)?;
        if !asset.active {
            return Err(AssetError::AssetInactive);
        }
        if !asset.ownership_active {
            return Err(AssetError::OwnershipNotVerified);
        }
        if !self.evaluate_scope(asset_id, subject).is_allowed() {
            return Err(AssetError::OutOfScope);
        }
        asset
            .resolutions
            .get(resolution_id)
            .ok_or(AssetError::ResolutionNotFound)
    }
    /// Drains aggregate facts.
    pub fn take_pending_events(&mut self) -> Vec<AssetEvent> {
        std::mem::take(&mut self.pending_events)
    }
    fn active_mut(&mut self, id: &AssetId) -> Result<&mut Asset, AssetError> {
        let asset = self.assets.get_mut(id).ok_or(AssetError::AssetNotFound)?;
        if !asset.active {
            return Err(AssetError::AssetInactive);
        }
        Ok(asset)
    }
}

/// Stable asset/scope failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssetError {
    /// A bounded domain value was malformed.
    InvalidValue,
    /// Source locator violated canonical network-boundary syntax.
    InvalidSourceLocator,
    /// Revision selector or receipt was mutable or malformed.
    InvalidRevision,
    /// Scope lacked a valid inclusion policy.
    InvalidScope,
    /// Persisted state failed aggregate invariant validation.
    InvalidSnapshot,
    /// Asset identity was already registered.
    AssetAlreadyExists,
    /// Asset identity was absent.
    AssetNotFound,
    /// Asset was deactivated.
    AssetInactive,
    /// Source ownership is absent or revoked.
    OwnershipNotVerified,
    /// Scope policy denied the subject.
    OutOfScope,
    /// Immutable resolution receipt was absent.
    ResolutionNotFound,
    /// Receipt did not bind the exact requested source and selector.
    DestinationSubstitution,
    /// Existing receipt identity cannot be replaced.
    ImmutableRevisionConflict,
}
impl fmt::Display for AssetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for AssetError {}

fn prefix_matches(prefix: &ScopeSubject, subject: &ScopeSubject) -> bool {
    subject.0 == prefix.0
        || subject
            .0
            .strip_prefix(&prefix.0)
            .is_some_and(|tail| tail.starts_with('/'))
}
fn validate_resolved_revision(value: &str) -> Result<(), AssetError> {
    if (40..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        Ok(())
    } else {
        Err(AssetError::InvalidRevision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id() -> AssetId {
        AssetId::new("00000000").unwrap()
    }
    fn locator() -> SourceLocator {
        SourceLocator::parse("https://code.example.com/acme/widget.git").unwrap()
    }
    fn portfolio() -> AssetPortfolio {
        let mut p = AssetPortfolio::new(OrganizationId::new("00000000").unwrap());
        p.register(
            id(),
            AssetType::Repository,
            locator(),
            Environment::Production,
            Criticality::High,
        )
        .unwrap();
        p.verify_ownership(&id()).unwrap();
        p.define_scope(
            &id(),
            vec![
                ScopeRule::Include(ScopeSubject::parse("src").unwrap()),
                ScopeRule::Exclude(ScopeSubject::parse("src/secrets").unwrap()),
            ],
        )
        .unwrap();
        p
    }
    fn selector() -> RevisionSelector {
        RevisionSelector::Commit("a".repeat(40))
    }
    fn receipt(request: &TargetResolutionRequest) -> TargetResolutionReceipt {
        TargetResolutionReceipt {
            resolution_id: request.resolution_id.clone(),
            asset_id: request.asset_id.clone(),
            source: request.source.clone(),
            selector: request.selector.clone(),
            resolved_revision: "b".repeat(40),
            acquisition_artifact_digest: Sha256Digest::of_bytes(b"bundle"),
        }
    }
    #[test]
    fn source_locator_rejects_ssrf_and_ambiguous_syntax() {
        for invalid in [
            "http://code.example.com/a/b",
            "https://user@code.example.com/a/b",
            "https://127.0.0.1/a/b",
            "https://localhost/a/b",
            "https://code.example.com/a/../b",
            "https://code.example.com/a/b?ref=main",
            "https://code.example.com/a%2fb",
        ] {
            assert!(SourceLocator::parse(invalid).is_err(), "{invalid}");
        }
    }
    #[test]
    fn exclusion_precedence_table_is_stable() {
        let p = portfolio();
        for (path, allowed, reason) in [
            ("src/lib.rs", true, ScopeReason::Included),
            ("src/secrets/key", false, ScopeReason::ExplicitlyExcluded),
            ("docs/readme", false, ScopeReason::NoMatchingInclusion),
        ] {
            let decision = p.evaluate_scope(&id(), &ScopeSubject::parse(path).unwrap());
            assert_eq!(
                (decision.is_allowed(), decision.reason()),
                (allowed, reason)
            );
        }
    }
    #[test]
    fn ownership_revocation_immediately_denies_resolution_and_binding() {
        let mut p = portfolio();
        let rid = ResolutionId::new("00000000").unwrap();
        let request = p
            .request_resolution(rid.clone(), &id(), selector())
            .unwrap();
        p.accept_resolution(&request, receipt(&request)).unwrap();
        p.revoke_ownership(&id()).unwrap();
        assert_eq!(
            p.request_resolution(ResolutionId::new("00000001").unwrap(), &id(), selector()),
            Err(AssetError::OwnershipNotVerified)
        );
        assert_eq!(
            p.authorize_target(&id(), &rid, &ScopeSubject::parse("src/lib.rs").unwrap()),
            Err(AssetError::OwnershipNotVerified)
        );
    }
    #[test]
    fn receipt_is_immutable_and_destination_substitution_fails() {
        let mut p = portfolio();
        let request = p
            .request_resolution(ResolutionId::new("00000000").unwrap(), &id(), selector())
            .unwrap();
        let original = receipt(&request);
        assert_eq!(
            p.accept_resolution(&request, original.clone()).unwrap(),
            p.accept_resolution(&request, original.clone()).unwrap()
        );
        let mut changed = original;
        changed.resolved_revision = "c".repeat(40);
        assert_eq!(
            p.accept_resolution(&request, changed),
            Err(AssetError::ImmutableRevisionConflict)
        );
        let mut substituted = receipt(&request);
        substituted.source =
            SourceLocator::parse("https://evil.example.com/fork/widget.git").unwrap();
        assert_eq!(
            p.accept_resolution(&request, substituted),
            Err(AssetError::DestinationSubstitution)
        );
    }
    #[test]
    fn target_binding_requires_scope_and_existing_receipt() {
        let p = portfolio();
        assert_eq!(
            p.authorize_target(
                &id(),
                &ResolutionId::new("00000000").unwrap(),
                &ScopeSubject::parse("src/lib.rs").unwrap()
            ),
            Err(AssetError::ResolutionNotFound)
        );
    }

    #[test]
    fn persistence_snapshot_round_trips_without_reemitting_events() {
        let mut original = portfolio();
        let request = original
            .request_resolution(ResolutionId::new("00000000").unwrap(), &id(), selector())
            .unwrap();
        original
            .accept_resolution(&request, receipt(&request))
            .unwrap();
        let snapshots = original.snapshot();
        let mut restored =
            AssetPortfolio::rehydrate(OrganizationId::new("00000000").unwrap(), snapshots).unwrap();
        assert!(
            restored
                .authorize_target(
                    &id(),
                    &ResolutionId::new("00000000").unwrap(),
                    &ScopeSubject::parse("src/lib.rs").unwrap()
                )
                .is_ok()
        );
        assert!(restored.take_pending_events().is_empty());
    }
}
