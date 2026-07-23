//! Authorized and audited Asset Portfolio application facade.
use super::ports::{
    AssetAuthorizer, AssetPortfolioRepository, AuditError, AuditFact, AuditOutcome, AuditSink,
    AuthorizationDecision, CommandControl, PortfolioCommit, RepositoryError,
};
use crate::domain::{
    AssetError, AssetId, AssetPortfolio, AssetType, Criticality, Environment, ResolutionId,
    RevisionSelector, ScopeRule, ScopeSubject, SourceLocator, TargetResolutionReceipt,
    TargetResolutionRequest,
};
use cauterizer_syntax::authorization::AuthorizationRequestContext;
use std::fmt;

/// Complete provider-neutral asset registration payload.
pub struct RegisterAssetCommand {
    /// New aggregate-owned identity.
    pub id: AssetId,
    /// Provider-neutral object kind.
    pub kind: AssetType,
    /// Canonical credential-free source.
    pub source: SourceLocator,
    /// Deployment environment.
    pub environment: Environment,
    /// Business impact classification.
    pub criticality: Criticality,
}

/// Asset command/query facade.
pub struct AssetPortfolioService<R, Z, U> {
    repository: R,
    authorizer: Z,
    audit: U,
}
impl<R, Z, U> AssetPortfolioService<R, Z, U>
where
    R: AssetPortfolioRepository,
    Z: AssetAuthorizer,
    U: AuditSink,
{
    /// Constructs the facade.
    #[must_use]
    pub const fn new(repository: R, authorizer: Z, audit: U) -> Self {
        Self {
            repository,
            authorizer,
            audit,
        }
    }
    /// Creates an empty tenant portfolio.
    /// # Errors
    /// Fails closed on authorization, audit, or persistence failure.
    pub fn create(&self, auth: &AuthorizationRequestContext) -> Result<u64, ApplicationError> {
        self.guard(auth, "assets.create", "portfolio")?;
        let tenant = auth.organization_id().clone();
        self.repository
            .create(
                tenant.clone(),
                PortfolioCommit {
                    aggregate: AssetPortfolio::new(tenant),
                    events: vec![],
                },
            )
            .map_err(Into::into)
    }
    /// Applies one invariant-enforcing aggregate command under optimistic locking.
    /// # Errors
    /// Fails closed and never persists a rejected mutation.
    fn command<T, F>(
        &self,
        auth: &AuthorizationRequestContext,
        action: &str,
        resource: &str,
        control: &CommandControl,
        operation: F,
    ) -> Result<T, ApplicationError>
    where
        F: FnOnce(&mut AssetPortfolio) -> Result<T, AssetError>,
    {
        self.guard(auth, action, resource)?;
        let tenant = auth.organization_id();
        let loaded = self
            .repository
            .load(tenant)?
            .ok_or(RepositoryError::NotFound)?;
        let mut aggregate = loaded.aggregate;
        let result = operation(&mut aggregate).map_err(ApplicationError::Domain);
        let result = match result {
            Ok(v) => v,
            Err(e) => {
                self.audit(auth, action, resource, AuditOutcome::Failed)?;
                return Err(e);
            }
        };
        let events = aggregate.take_pending_events();
        self.repository
            .commit_command(tenant, control, PortfolioCommit { aggregate, events })?;
        self.audit(auth, action, resource, AuditOutcome::Succeeded)?;
        Ok(result)
    }
    /// Registers one provider-neutral source as an inactive-ownership asset.
    ///
    /// # Errors
    /// Fails closed on authorization, audit, persistence, or domain rejection.
    pub fn register_asset(
        &self,
        auth: &AuthorizationRequestContext,
        command: RegisterAssetCommand,
        control: &CommandControl,
    ) -> Result<(), ApplicationError> {
        let resource = command.id.as_str().to_owned();
        self.command(
            auth,
            "assets.register",
            &resource,
            control,
            move |portfolio| {
                portfolio.register(
                    command.id,
                    command.kind,
                    command.source,
                    command.environment,
                    command.criticality,
                )
            },
        )
    }
    /// Marks source ownership verified after an external proof adapter succeeds.
    ///
    /// # Errors
    /// Fails closed on authorization, audit, persistence, or domain rejection.
    pub fn verify_source_ownership(
        &self,
        auth: &AuthorizationRequestContext,
        id: &AssetId,
        control: &CommandControl,
    ) -> Result<(), ApplicationError> {
        self.command(
            auth,
            "assets.verify_ownership",
            id.as_str(),
            control,
            |portfolio| portfolio.verify_ownership(id),
        )
    }
    /// Revokes source authority immediately.
    ///
    /// # Errors
    /// Fails closed on authorization, audit, persistence, or domain rejection.
    pub fn revoke_source_ownership(
        &self,
        auth: &AuthorizationRequestContext,
        id: &AssetId,
        control: &CommandControl,
    ) -> Result<(), ApplicationError> {
        self.command(
            auth,
            "assets.revoke_ownership",
            id.as_str(),
            control,
            |portfolio| portfolio.revoke_ownership(id),
        )
    }
    /// Updates environment and criticality without changing target identity.
    ///
    /// # Errors
    /// Fails closed on authorization, audit, persistence, or domain rejection.
    pub fn classify_asset(
        &self,
        auth: &AuthorizationRequestContext,
        id: &AssetId,
        environment: Environment,
        criticality: Criticality,
        control: &CommandControl,
    ) -> Result<(), ApplicationError> {
        self.command(auth, "assets.classify", id.as_str(), control, |portfolio| {
            portfolio.classify(id, environment, criticality)
        })
    }
    /// Replaces the exclusion-first scope policy.
    ///
    /// # Errors
    /// Fails closed on authorization, audit, persistence, or invalid scope.
    pub fn define_scope(
        &self,
        auth: &AuthorizationRequestContext,
        id: &AssetId,
        rules: Vec<ScopeRule>,
        control: &CommandControl,
    ) -> Result<(), ApplicationError> {
        self.command(
            auth,
            "assets.define_scope",
            id.as_str(),
            control,
            move |portfolio| portfolio.define_scope(id, rules),
        )
    }
    /// Deactivates the asset and its source ownership.
    ///
    /// # Errors
    /// Fails closed on authorization, audit, persistence, or domain rejection.
    pub fn deactivate_asset(
        &self,
        auth: &AuthorizationRequestContext,
        id: &AssetId,
        control: &CommandControl,
    ) -> Result<(), ApplicationError> {
        self.command(
            auth,
            "assets.deactivate",
            id.as_str(),
            control,
            |portfolio| portfolio.deactivate(id),
        )
    }
    /// Creates an exact restricted-acquisition request without performing network I/O.
    ///
    /// # Errors
    /// Denies unauthorized, inactive, unowned, or invalid revision input.
    pub fn request_target_resolution(
        &self,
        auth: &AuthorizationRequestContext,
        resolution_id: ResolutionId,
        asset_id: &AssetId,
        selector: RevisionSelector,
    ) -> Result<TargetResolutionRequest, ApplicationError> {
        self.guard(auth, "assets.resolve", asset_id.as_str())?;
        let aggregate = self
            .repository
            .load(auth.organization_id())?
            .ok_or(RepositoryError::NotFound)?
            .aggregate;
        let result = aggregate
            .request_resolution(resolution_id, asset_id, selector)
            .map_err(ApplicationError::Domain);
        self.audit(
            auth,
            "assets.resolve",
            asset_id.as_str(),
            if result.is_ok() {
                AuditOutcome::Succeeded
            } else {
                AuditOutcome::Failed
            },
        )?;
        result
    }
    /// Persists an immutable acquisition receipt only when it exactly matches its request.
    ///
    /// # Errors
    /// Rejects unauthorized input, substitution, conflicts, or persistence failure.
    pub fn accept_target_resolution(
        &self,
        auth: &AuthorizationRequestContext,
        request: &TargetResolutionRequest,
        receipt: TargetResolutionReceipt,
        control: &CommandControl,
    ) -> Result<TargetResolutionReceipt, ApplicationError> {
        self.command(
            auth,
            "assets.accept_resolution",
            request.asset_id.as_str(),
            control,
            move |portfolio| portfolio.accept_resolution(request, receipt),
        )
    }
    /// Returns a receipt only after active ownership, scope, and immutable-resolution checks.
    /// # Errors
    /// Denies cross-tenant, unauthorized, inactive, unowned, out-of-scope, or absent targets.
    pub fn authorize_run_binding(
        &self,
        auth: &AuthorizationRequestContext,
        asset: &AssetId,
        resolution: &ResolutionId,
        subject: &ScopeSubject,
    ) -> Result<TargetResolutionReceipt, ApplicationError> {
        let resource = asset.as_str();
        self.guard(auth, "assets.bind_run", resource)?;
        let aggregate = self
            .repository
            .load(auth.organization_id())?
            .ok_or(RepositoryError::NotFound)?
            .aggregate;
        let receipt = aggregate
            .authorize_target(asset, resolution, subject)
            .cloned()
            .map_err(ApplicationError::Domain);
        match receipt {
            Ok(r) => {
                self.audit(auth, "assets.bind_run", resource, AuditOutcome::Succeeded)?;
                Ok(r)
            }
            Err(e) => {
                self.audit(auth, "assets.bind_run", resource, AuditOutcome::Failed)?;
                Err(e)
            }
        }
    }
    fn guard(
        &self,
        a: &AuthorizationRequestContext,
        action: &str,
        resource: &str,
    ) -> Result<(), ApplicationError> {
        if a.action().as_str() != action
            || a.resource().as_str() != resource
            || self.authorizer.authorize(a) != AuthorizationDecision::Allow
        {
            self.audit(a, action, resource, AuditOutcome::Denied)?;
            return Err(ApplicationError::Denied);
        }
        Ok(())
    }
    fn audit(
        &self,
        a: &AuthorizationRequestContext,
        action: &str,
        resource: &str,
        outcome: AuditOutcome,
    ) -> Result<(), ApplicationError> {
        self.audit
            .record(AuditFact {
                organization_id: a.organization_id().clone(),
                action: action.into(),
                resource: resource.into(),
                outcome,
            })
            .map_err(Into::into)
    }
}
/// Stable application failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationError {
    /// Policy denied the request.
    Denied,
    /// Mandatory audit could not be recorded.
    AuditUnavailable,
    /// Persistence failed.
    Repository(RepositoryError),
    /// Aggregate invariant rejected the operation.
    Domain(AssetError),
}
impl From<RepositoryError> for ApplicationError {
    fn from(e: RepositoryError) -> Self {
        Self::Repository(e)
    }
}
impl From<AuditError> for ApplicationError {
    fn from(_: AuditError) -> Self {
        Self::AuditUnavailable
    }
}
impl fmt::Display for ApplicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Denied => "asset_operation_denied",
            Self::AuditUnavailable => "asset_audit_unavailable",
            Self::Repository(_) => "asset_repository_failure",
            Self::Domain(_) => "asset_domain_rejection",
        })
    }
}
impl std::error::Error for ApplicationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::memory::{
        InMemoryAssetPortfolioRepository, InMemoryAuditSink, InMemoryAuthorizer,
    };
    use crate::application::ports::AssetPortfolioRepository;
    use crate::domain::{
        AssetType, Criticality, Environment, RevisionSelector, ScopeRule, SourceLocator,
        TargetResolutionReceipt,
    };
    use cauterizer_syntax::authorization::{ActionName, Purpose, ResourceRef};
    use cauterizer_syntax::digest::Sha256Digest;
    use cauterizer_syntax::identifiers::{ActorId, IdempotencyKey, IdentityRef, OrganizationId};
    use std::cell::Cell;

    fn auth(org: &str) -> AuthorizationRequestContext {
        AuthorizationRequestContext::new(
            OrganizationId::new(org).unwrap(),
            IdentityRef::Human(ActorId::new("00000000").unwrap()),
            ActionName::parse("assets.bind_run").unwrap(),
            ResourceRef::parse("asset_00000000").unwrap(),
            Purpose::parse("asset administration").unwrap(),
        )
    }
    fn control(version: u64) -> CommandControl {
        CommandControl {
            expected_version: version,
            idempotency_key: IdempotencyKey::new("command-key").unwrap(),
            request_digest: Sha256Digest::of_bytes(b"canonical-command"),
        }
    }

    fn prepared() -> (AssetPortfolio, AssetId, ResolutionId, ScopeSubject) {
        let tenant = OrganizationId::new("00000000").unwrap();
        let asset = AssetId::new("00000000").unwrap();
        let resolution = ResolutionId::new("00000000").unwrap();
        let subject = ScopeSubject::parse("src/lib.rs").unwrap();
        let mut portfolio = AssetPortfolio::new(tenant);
        portfolio
            .register(
                asset.clone(),
                AssetType::Repository,
                SourceLocator::parse("https://code.example.com/acme/widget.git").unwrap(),
                Environment::Production,
                Criticality::High,
            )
            .unwrap();
        portfolio.verify_ownership(&asset).unwrap();
        portfolio
            .define_scope(
                &asset,
                vec![
                    ScopeRule::Include(ScopeSubject::parse("src").unwrap()),
                    ScopeRule::Exclude(ScopeSubject::parse("src/secrets").unwrap()),
                ],
            )
            .unwrap();
        let request = portfolio
            .request_resolution(
                resolution.clone(),
                &asset,
                RevisionSelector::Commit("a".repeat(40)),
            )
            .unwrap();
        portfolio
            .accept_resolution(
                &request,
                TargetResolutionReceipt {
                    resolution_id: resolution.clone(),
                    asset_id: asset.clone(),
                    source: request.source.clone(),
                    selector: request.selector.clone(),
                    resolved_revision: "b".repeat(40),
                    acquisition_artifact_digest: Sha256Digest::of_bytes(b"bundle"),
                },
            )
            .unwrap();
        portfolio.take_pending_events();
        (portfolio, asset, resolution, subject)
    }

    fn service_with(
        portfolio: AssetPortfolio,
    ) -> (
        AssetPortfolioService<
            InMemoryAssetPortfolioRepository,
            InMemoryAuthorizer,
            InMemoryAuditSink,
        >,
        InMemoryAssetPortfolioRepository,
        InMemoryAuthorizer,
        InMemoryAuditSink,
    ) {
        let repository = InMemoryAssetPortfolioRepository::default();
        repository
            .create(
                OrganizationId::new("00000000").unwrap(),
                PortfolioCommit {
                    aggregate: portfolio,
                    events: vec![],
                },
            )
            .unwrap();
        let authorizer = InMemoryAuthorizer::default();
        let audit = InMemoryAuditSink::default();
        (
            AssetPortfolioService::new(repository.clone(), authorizer.clone(), audit.clone()),
            repository,
            authorizer,
            audit,
        )
    }

    #[test]
    fn denial_is_audited_and_never_invokes_or_persists_mutation() {
        let (portfolio, _, _, _) = prepared();
        let (service, repository, _authorizer, audit) = service_with(portfolio);
        let before = repository
            .load(&OrganizationId::new("00000000").unwrap())
            .unwrap()
            .unwrap();
        let invoked = Cell::new(false);
        assert_eq!(
            service.command(
                &auth("00000000"),
                "assets.deactivate",
                "asset_00000000",
                &control(before.version),
                |_| {
                    invoked.set(true);
                    Ok(())
                }
            ),
            Err(ApplicationError::Denied)
        );
        assert!(!invoked.get());
        let after = repository
            .load(&OrganizationId::new("00000000").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(after.version, before.version);
        assert_eq!(after.aggregate.snapshot(), before.aggregate.snapshot());
        assert_eq!(audit.facts().last().unwrap().outcome, AuditOutcome::Denied);
    }

    #[test]
    fn cross_tenant_binding_is_denied_and_audited_without_lookup_leakage() {
        let (portfolio, asset, resolution, subject) = prepared();
        let (service, _, authorizer, audit) = service_with(portfolio);
        authorizer.set_allowed(false);
        assert_eq!(
            service.authorize_run_binding(&auth("11111111"), &asset, &resolution, &subject,),
            Err(ApplicationError::Denied)
        );
        let fact = audit.facts().pop().unwrap();
        assert_eq!(
            fact.organization_id,
            OrganizationId::new("11111111").unwrap()
        );
        assert_eq!(fact.outcome, AuditOutcome::Denied);
    }

    #[test]
    fn run_binding_requires_active_owned_in_scope_exact_receipt() {
        let (portfolio, asset, resolution, subject) = prepared();
        let (service, repository, authorizer, audit) = service_with(portfolio);
        authorizer.set_allowed(true);
        let receipt = service
            .authorize_run_binding(&auth("00000000"), &asset, &resolution, &subject)
            .unwrap();
        assert_eq!(receipt.resolution_id, resolution);
        assert_eq!(
            audit.facts().last().unwrap().outcome,
            AuditOutcome::Succeeded
        );

        assert_eq!(
            service.authorize_run_binding(
                &auth("00000000"),
                &asset,
                &ResolutionId::new("11111111").unwrap(),
                &subject,
            ),
            Err(ApplicationError::Domain(AssetError::ResolutionNotFound))
        );
        assert_eq!(
            service.authorize_run_binding(
                &auth("00000000"),
                &asset,
                &receipt.resolution_id,
                &ScopeSubject::parse("src/secrets/key").unwrap(),
            ),
            Err(ApplicationError::Domain(AssetError::OutOfScope))
        );

        let loaded = repository
            .load(&OrganizationId::new("00000000").unwrap())
            .unwrap()
            .unwrap();
        let version = loaded.version;
        let mut revoked = loaded.aggregate;
        revoked.revoke_ownership(&asset).unwrap();
        let events = revoked.take_pending_events();
        repository
            .commit_command(
                &OrganizationId::new("00000000").unwrap(),
                &control(version),
                PortfolioCommit {
                    aggregate: revoked,
                    events,
                },
            )
            .unwrap();
        assert_eq!(
            service.authorize_run_binding(
                &auth("00000000"),
                &asset,
                &receipt.resolution_id,
                &subject,
            ),
            Err(ApplicationError::Domain(AssetError::OwnershipNotVerified))
        );
    }
}
