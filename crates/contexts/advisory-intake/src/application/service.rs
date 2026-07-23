//! Authorized, audited, replay-safe application facade.
use super::ports::{
    AdvisoryAuthorizer, AdvisoryRecordRepository, AuditError, AuditFact, AuditOutcome, AuditSink,
    AuthorizationDecision, CommandControl, RecordCommit, RepositoryError,
};
use crate::domain::{
    AdvisoryError, AdvisoryRecord, AdvisoryRecordId, AdvisorySnapshot, AdvisorySource,
    NormalizationFailure, SnapshotId,
};
use cauterizer_syntax::authorization::AuthorizationRequestContext;
use std::fmt;
/// Complete append-only withdrawal observation.
pub struct RecordWithdrawalCommand {
    /// Snapshot being withdrawn by the source observation.
    pub snapshot_id: SnapshotId,
    /// Pinned source attribution.
    pub source: AdvisorySource,
    /// Observation time in epoch milliseconds.
    pub observed_at_ms: u64,
}
/// Advisory Intake command facade.
pub struct AdvisoryIntakeService<R, Z, U> {
    repository: R,
    authorizer: Z,
    audit: U,
}
impl<R: AdvisoryRecordRepository, Z: AdvisoryAuthorizer, U: AuditSink>
    AdvisoryIntakeService<R, Z, U>
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
    /// Creates an empty tenant record.
    /// # Errors
    /// Fails closed on authorization, audit, or persistence failure.
    pub fn create(
        &self,
        a: &AuthorizationRequestContext,
        id: AdvisoryRecordId,
        control: &CommandControl,
    ) -> Result<super::ports::CommitOutcome, ApplicationError> {
        let r = id.as_str();
        self.guard(a, "advisories.create", r)?;
        let t = a.organization_id().clone();
        self.repository
            .create_command(
                t.clone(),
                r.into(),
                control,
                RecordCommit {
                    aggregate: AdvisoryRecord::new(t, id),
                    facts: vec![],
                },
            )
            .map_err(Into::into)
    }
    /// Records one immutable normalized snapshot.
    /// # Errors
    /// Rejects unauthorized, stale, conflicting, or invalid input atomically.
    pub fn record_snapshot(
        &self,
        a: &AuthorizationRequestContext,
        id: &AdvisoryRecordId,
        snapshot: AdvisorySnapshot,
        control: &CommandControl,
    ) -> Result<AdvisorySnapshot, ApplicationError> {
        self.command(
            a,
            "advisories.record_snapshot",
            id.as_str(),
            control,
            move |r| r.record_snapshot(snapshot),
        )
    }
    /// Records a stable normalization failure without raw content.
    /// # Errors
    /// Rejects unauthorized, stale, conflicting, or invalid input atomically.
    pub fn record_failure(
        &self,
        a: &AuthorizationRequestContext,
        id: &AdvisoryRecordId,
        failure: NormalizationFailure,
        control: &CommandControl,
    ) -> Result<(), ApplicationError> {
        self.command(
            a,
            "advisories.record_failure",
            id.as_str(),
            control,
            move |r| r.record_failure(failure),
        )
    }
    /// Appends a withdrawal observation without modifying its snapshot.
    /// # Errors
    /// Rejects unauthorized, stale, conflicting, or unknown snapshot input.
    pub fn record_withdrawal(
        &self,
        a: &AuthorizationRequestContext,
        id: &AdvisoryRecordId,
        command: RecordWithdrawalCommand,
        control: &CommandControl,
    ) -> Result<(), ApplicationError> {
        self.command(
            a,
            "advisories.record_withdrawal",
            id.as_str(),
            control,
            move |record| {
                record.record_withdrawal(
                    &command.snapshot_id,
                    command.source,
                    command.observed_at_ms,
                )
            },
        )
    }
    /// Resolves an alias only when its observed mapping is unambiguous.
    /// # Errors
    /// Rejects unauthorized, stale, conflicting, missing, or ambiguous aliases.
    pub fn resolve_alias(
        &self,
        a: &AuthorizationRequestContext,
        id: &AdvisoryRecordId,
        alias: &str,
        control: &CommandControl,
    ) -> Result<AdvisorySource, ApplicationError> {
        self.command(
            a,
            "advisories.resolve_alias",
            id.as_str(),
            control,
            move |record| record.resolve_alias(alias),
        )
    }
    /// Records a reviewed choice from the observed alias candidates.
    /// # Errors
    /// Rejects unauthorized, stale, conflicting, or unobserved selections.
    pub fn resolve_alias_explicitly(
        &self,
        a: &AuthorizationRequestContext,
        id: &AdvisoryRecordId,
        alias: &str,
        selected: &AdvisorySource,
        control: &CommandControl,
    ) -> Result<(), ApplicationError> {
        self.command(
            a,
            "advisories.resolve_alias",
            id.as_str(),
            control,
            move |record| record.resolve_alias_explicitly(alias, selected),
        )
    }
    fn command<T, F>(
        &self,
        a: &AuthorizationRequestContext,
        action: &str,
        id: &str,
        control: &CommandControl,
        f: F,
    ) -> Result<T, ApplicationError>
    where
        F: FnOnce(&mut AdvisoryRecord) -> Result<T, AdvisoryError>,
    {
        self.guard(a, action, id)?;
        let mut loaded = self
            .repository
            .load(a.organization_id(), id)?
            .ok_or(RepositoryError::NotFound)?;
        let result = match f(&mut loaded.aggregate) {
            Ok(v) => v,
            Err(e) => {
                self.audit(a, action, id, AuditOutcome::Failed)?;
                return Err(ApplicationError::Domain(e));
            }
        };
        let facts = loaded.aggregate.take_pending_facts();
        self.repository.commit(
            a.organization_id(),
            id,
            control,
            RecordCommit {
                aggregate: loaded.aggregate,
                facts,
            },
        )?;
        self.audit(a, action, id, AuditOutcome::Succeeded)?;
        Ok(result)
    }
    fn guard(
        &self,
        a: &AuthorizationRequestContext,
        action: &str,
        id: &str,
    ) -> Result<(), ApplicationError> {
        if a.action().as_str() != action
            || a.resource().as_str() != id
            || self.authorizer.authorize(a) != AuthorizationDecision::Allow
        {
            self.audit(a, action, id, AuditOutcome::Denied)?;
            return Err(ApplicationError::Denied);
        }
        Ok(())
    }
    fn audit(
        &self,
        a: &AuthorizationRequestContext,
        action: &str,
        id: &str,
        outcome: AuditOutcome,
    ) -> Result<(), ApplicationError> {
        self.audit
            .record(AuditFact {
                tenant: a.organization_id().clone(),
                action: action.into(),
                record: id.into(),
                outcome,
            })
            .map_err(Into::into)
    }
}
/// Stable facade failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationError {
    /// Denied.
    Denied,
    /// Mandatory audit unavailable.
    AuditUnavailable,
    /// Persistence failure.
    Repository(RepositoryError),
    /// Domain rejection.
    Domain(AdvisoryError),
}
impl From<RepositoryError> for ApplicationError {
    fn from(v: RepositoryError) -> Self {
        Self::Repository(v)
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
            Self::Denied => "advisory_operation_denied",
            Self::AuditUnavailable => "advisory_audit_unavailable",
            Self::Repository(_) => "advisory_repository_failure",
            Self::Domain(_) => "advisory_domain_rejection",
        })
    }
}
impl std::error::Error for ApplicationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::memory::{
        InMemoryAdvisoryRepository, InMemoryAuditSink, InMemoryAuthorizer,
    };
    use crate::application::ports::{
        AdvisoryRecordRepository, AuditOutcome, CommandControl, RecordCommit,
    };
    use crate::domain::{
        AcquisitionId, AdvisoryArtifactRef, AffectedRange, Ecosystem, SeverityVector,
    };
    use cauterizer_syntax::authorization::{ActionName, Purpose, ResourceRef};
    use cauterizer_syntax::classification::DataClass;
    use cauterizer_syntax::digest::Sha256Digest;
    use cauterizer_syntax::identifiers::{ActorId, IdempotencyKey, IdentityRef, OrganizationId};
    use cauterizer_syntax::schema::{SchemaName, SchemaVersion};
    use std::collections::BTreeSet;

    type Service =
        AdvisoryIntakeService<InMemoryAdvisoryRepository, InMemoryAuthorizer, InMemoryAuditSink>;

    fn tenant(value: &str) -> OrganizationId {
        OrganizationId::new(value).unwrap()
    }
    fn id() -> AdvisoryRecordId {
        AdvisoryRecordId::new("00000000").unwrap()
    }
    fn source(external: &str) -> AdvisorySource {
        AdvisorySource::new("fixture".into(), external.into(), "fixture-v1".into()).unwrap()
    }
    fn artifact(bytes: &[u8], class: DataClass) -> AdvisoryArtifactRef {
        AdvisoryArtifactRef {
            digest: Sha256Digest::of_bytes(bytes),
            classification: class,
            schema_name: SchemaName::parse("dev.cauterizer.advisory.snapshot").unwrap(),
            schema_version: SchemaVersion::parse("1.0.0").unwrap(),
            size_bytes: bytes.len() as u64,
        }
    }
    fn snapshot(n: u64) -> AdvisorySnapshot {
        AdvisorySnapshot {
            id: SnapshotId::new(&format!("{n:08}")).unwrap(),
            acquisition_id: AcquisitionId::new(&format!("{n:08}")).unwrap(),
            input_digest: Sha256Digest::of_bytes(format!("input-{n}")),
            source: source(&format!("CVE-{n}")),
            acquired_at_ms: n,
            published_at_ms: Some(n),
            modified_at_ms: Some(n),
            raw: artifact(format!("raw-{n}").as_bytes(), DataClass::Confidential),
            canonical: artifact(format!("canonical-{n}").as_bytes(), DataClass::Public),
            aliases: BTreeSet::from([format!("CVE-{n}")]),
            affected: vec![
                AffectedRange::new(
                    Ecosystem::new("cargo".into()).unwrap(),
                    "crate".into(),
                    "0".into(),
                    Some("1.2.3".into()),
                    None,
                )
                .unwrap(),
            ],
            severity: vec![
                SeverityVector::new(
                    "cvss".into(),
                    "3.1".into(),
                    "CVSS:3.1/AV:N".into(),
                    source("NVD"),
                )
                .unwrap(),
            ],
        }
    }
    fn control(version: u64, key: &str, digest: &[u8]) -> CommandControl {
        CommandControl {
            expected_version: version,
            idempotency_key: IdempotencyKey::new(key).unwrap(),
            request_digest: Sha256Digest::of_bytes(digest),
        }
    }
    fn auth(org: &str, action: &str) -> AuthorizationRequestContext {
        AuthorizationRequestContext::new(
            tenant(org),
            IdentityRef::Human(ActorId::new("00000000").unwrap()),
            ActionName::parse(action).unwrap(),
            ResourceRef::parse(id().as_str()).unwrap(),
            Purpose::parse("advisory intake").unwrap(),
        )
    }
    fn setup(
        record: AdvisoryRecord,
    ) -> (
        Service,
        InMemoryAdvisoryRepository,
        InMemoryAuthorizer,
        InMemoryAuditSink,
    ) {
        let repository = InMemoryAdvisoryRepository::default();
        repository
            .create(
                tenant("00000000"),
                id().as_str().into(),
                RecordCommit {
                    aggregate: record,
                    facts: vec![],
                },
            )
            .unwrap();
        let authorizer = InMemoryAuthorizer::default();
        let audit = InMemoryAuditSink::default();
        (
            AdvisoryIntakeService::new(repository.clone(), authorizer.clone(), audit.clone()),
            repository,
            authorizer,
            audit,
        )
    }

    #[test]
    fn denied_snapshot_is_audited_without_mutation() {
        let record = AdvisoryRecord::new(tenant("00000000"), id());
        let (service, repository, _authorizer, audit) = setup(record);
        assert_eq!(
            service.record_snapshot(
                &auth("00000000", "advisories.record_snapshot"),
                &id(),
                snapshot(1),
                &control(1, "deny-key", b"one"),
            ),
            Err(ApplicationError::Denied)
        );
        let loaded = repository
            .load(&tenant("00000000"), id().as_str())
            .unwrap()
            .unwrap();
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.aggregate.snapshots().count(), 0);
        assert!(repository.outbox().is_empty());
        assert_eq!(audit.facts().last().unwrap().outcome, AuditOutcome::Denied);
    }

    #[test]
    fn snapshot_exact_retry_returns_same_result_and_conflicting_reuse_fails() {
        let record = AdvisoryRecord::new(tenant("00000000"), id());
        let (service, repository, authorizer, _) = setup(record);
        authorizer.set_allowed(true);
        let auth = auth("00000000", "advisories.record_snapshot");
        let command = control(1, "snapshot-key", b"snapshot-one");
        let first = service
            .record_snapshot(&auth, &id(), snapshot(1), &command)
            .unwrap();
        let outbox = repository.outbox();
        let replay = service
            .record_snapshot(&auth, &id(), snapshot(1), &command)
            .unwrap();
        assert_eq!(replay, first);
        assert_eq!(repository.outbox(), outbox);
        let mut changed = snapshot(1);
        changed.input_digest = Sha256Digest::of_bytes(b"changed");
        assert_eq!(
            service.record_snapshot(
                &auth,
                &id(),
                changed,
                &control(2, "snapshot-key", b"changed")
            ),
            Err(ApplicationError::Domain(AdvisoryError::IdempotencyConflict))
        );
        assert_eq!(
            repository
                .load(&tenant("00000000"), id().as_str())
                .unwrap()
                .unwrap()
                .version,
            2
        );
    }

    #[test]
    fn withdrawal_appends_history_without_mutating_snapshot() {
        let mut record = AdvisoryRecord::new(tenant("00000000"), id());
        let original = record.record_snapshot(snapshot(1)).unwrap();
        record.take_pending_facts();
        let (service, repository, authorizer, _) = setup(record);
        authorizer.set_allowed(true);
        service
            .record_withdrawal(
                &auth("00000000", "advisories.record_withdrawal"),
                &id(),
                RecordWithdrawalCommand {
                    snapshot_id: original.id.clone(),
                    source: source("CVE-1"),
                    observed_at_ms: 2,
                },
                &control(1, "withdraw-key", b"withdraw-one"),
            )
            .unwrap();
        let loaded = repository
            .load(&tenant("00000000"), id().as_str())
            .unwrap()
            .unwrap()
            .aggregate;
        assert_eq!(loaded.snapshots().collect::<Vec<_>>(), vec![&original]);
        assert!(matches!(
            loaded.history().last(),
            Some(crate::domain::AdvisoryFact::WithdrawalObserved { .. })
        ));
    }

    #[test]
    fn ambiguous_alias_denies_automatic_resolution_but_reviewed_selection_succeeds() {
        let mut record = AdvisoryRecord::new(tenant("00000000"), id());
        let selected = source("CVE-1");
        record
            .observe_alias("CVE-ALIAS".into(), selected.clone())
            .unwrap();
        record
            .observe_alias("CVE-ALIAS".into(), source("CVE-2"))
            .unwrap();
        record.take_pending_facts();
        let (service, repository, authorizer, audit) = setup(record);
        authorizer.set_allowed(true);
        let auth = auth("00000000", "advisories.resolve_alias");
        assert_eq!(
            service.resolve_alias(&auth, &id(), "CVE-ALIAS", &control(1, "auto", b"auto")),
            Err(ApplicationError::Domain(AdvisoryError::AliasAmbiguous))
        );
        assert_eq!(audit.facts().last().unwrap().outcome, AuditOutcome::Failed);
        service
            .resolve_alias_explicitly(
                &auth,
                &id(),
                "CVE-ALIAS",
                &selected,
                &control(1, "reviewed", b"reviewed"),
            )
            .unwrap();
        assert_eq!(
            repository
                .load(&tenant("00000000"), id().as_str())
                .unwrap()
                .unwrap()
                .version,
            2
        );
        assert_eq!(
            audit.facts().last().unwrap().outcome,
            AuditOutcome::Succeeded
        );
    }

    #[test]
    fn cross_tenant_request_is_denied_before_repository_lookup() {
        let record = AdvisoryRecord::new(tenant("00000000"), id());
        let (service, repository, _authorizer, audit) = setup(record);
        assert_eq!(
            service.record_snapshot(
                &auth("11111111", "advisories.record_snapshot"),
                &id(),
                snapshot(1),
                &control(1, "foreign", b"foreign"),
            ),
            Err(ApplicationError::Denied)
        );
        assert_eq!(
            repository
                .load(&tenant("00000000"), id().as_str())
                .unwrap()
                .unwrap()
                .version,
            1
        );
        assert!(
            repository
                .load(&tenant("11111111"), id().as_str())
                .unwrap()
                .is_none()
        );
        assert_eq!(audit.facts().last().unwrap().tenant, tenant("11111111"));
    }
}
