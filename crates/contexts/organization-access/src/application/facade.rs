//! Direct application facade, including explicit local-only bootstrap.

use super::ports::{
    Clock, IdGenerator, IdempotencyError, IdempotencyStore, IdempotentResult,
    OrganizationRepository, RepositoryError, SaveOrganization,
};
use crate::contracts::{
    CONTRACT_VERSION, ORGANIZATION_AGGREGATE_TYPE, OrganizationAccessEventPayloadV1,
    OrganizationAccessEventV1,
};
use crate::domain::{DomainError, EventContext, EventId, MemberId, Organization};
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{
    ActorId, AggregateSequence, CausationId, ContextQualifiedId, CorrelationId, IdempotencyKey,
    OrganizationId,
};
use cauterizer_syntax::schema::{SchemaName, SchemaVersion};
use std::fmt;

/// Explicit deployment mode accepted by local bootstrap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapMode {
    /// Single-organization offline development mode; never production federation.
    LocalOfflineDevelopment,
}

/// Creates the one explicit organization and human owner for local operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapLocalOrganization {
    /// Must explicitly select non-production local mode.
    pub mode: BootstrapMode,
    /// Explicit local tenant scope; retries must address the same organization.
    pub organization_id: OrganizationId,
    /// Bounded organization display name, validated by the aggregate.
    pub organization_name: String,
    /// Pre-authenticated human owner reference; no password is created.
    pub owner_actor_id: ActorId,
    /// Organization-scoped replay key.
    pub idempotency_key: IdempotencyKey,
    /// SHA-256 digest of canonical command input from the boundary.
    pub request_digest: Sha256Digest,
    /// Logical request trace.
    pub correlation_id: CorrelationId,
    /// Bootstrap command identity.
    pub causation_id: CausationId,
}

/// Stable bootstrap result returned on first execution and exact retries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapResult {
    /// Created organization.
    pub organization_id: OrganizationId,
    /// Initial owner membership.
    pub owner_member_id: String,
    /// Persisted optimistic version.
    pub version: u64,
}

/// Direct application facade independent of HTTP, `IdPs`, and orchestration tools.
pub struct OrganizationAccessFacade<R, I, C, G> {
    repository: R,
    idempotency: I,
    clock: C,
    ids: G,
}

impl<R, I, C, G> OrganizationAccessFacade<R, I, C, G>
where
    R: OrganizationRepository<Aggregate = Organization>,
    I: IdempotencyStore<BootstrapResult>,
    C: Clock,
    G: IdGenerator,
{
    /// Creates a facade from application-owned ports.
    #[must_use]
    pub const fn new(repository: R, idempotency: I, clock: C, ids: G) -> Self {
        Self {
            repository,
            idempotency,
            clock,
            ids,
        }
    }

    /// Performs explicit local development bootstrap exactly once per key.
    ///
    /// # Errors
    ///
    /// Returns a stable error for changed idempotent input, invalid generated
    /// identifiers/domain input, or an optimistic persistence conflict.
    pub fn bootstrap_local(
        &mut self,
        command: BootstrapLocalOrganization,
    ) -> Result<BootstrapResult, ApplicationError> {
        let organization_id = command.organization_id.clone();
        if let Some(previous) = self
            .idempotency
            .get(&organization_id, &command.idempotency_key)
        {
            return if previous.request_digest == command.request_digest {
                Ok(previous.result)
            } else {
                Err(ApplicationError::IdempotencyConflict)
            };
        }

        let member = MemberId::new(&self.ids.next_opaque("member"))
            .map_err(|_| ApplicationError::InvalidGeneratedIdentifier)?;
        let event_id = EventId::new(&self.ids.next_opaque("org-event"))
            .map_err(|_| ApplicationError::InvalidGeneratedIdentifier)?;
        let public_event_id = event_id
            .as_str()
            .parse::<ContextQualifiedId>()
            .map_err(|_| ApplicationError::InvalidGeneratedIdentifier)?;
        let event_context = EventContext {
            event_id,
            occurred_at_ms: self.clock.now_unix_millis(),
            correlation_id: command.correlation_id.clone(),
            causation_id: command.causation_id.clone(),
        };
        let mut aggregate = Organization::create(
            organization_id.clone(),
            command.organization_name,
            member.clone(),
            command.owner_actor_id.clone(),
            event_context,
        )?;
        let domain_events = aggregate.take_pending_events();
        debug_assert_eq!(domain_events.len(), 1);
        let public_event = OrganizationAccessEventV1 {
            schema_name: SchemaName::parse("dev.cauterizer.organization-access.event")
                .map_err(|_| ApplicationError::InvalidGeneratedIdentifier)?,
            schema_version: SchemaVersion::parse(CONTRACT_VERSION)
                .map_err(|_| ApplicationError::InvalidGeneratedIdentifier)?,
            aggregate_type: ORGANIZATION_AGGREGATE_TYPE.to_owned(),
            organization_id: organization_id.clone(),
            aggregate_sequence: AggregateSequence::new(1)
                .map_err(|_| ApplicationError::InvalidGeneratedIdentifier)?,
            event_id: public_event_id,
            occurred_at: self.clock.now(),
            correlation_id: command.correlation_id,
            causation_id: command.causation_id,
            payload: OrganizationAccessEventPayloadV1::OrganizationCreated {
                owner: command.owner_actor_id,
            },
        };
        let version = self.repository.save(
            &organization_id,
            SaveOrganization {
                aggregate,
                expected_version: None,
                events: vec![public_event],
            },
        )?;
        let result = BootstrapResult {
            organization_id: organization_id.clone(),
            owner_member_id: member.as_str().to_owned(),
            version,
        };
        self.idempotency.put(
            organization_id,
            command.idempotency_key,
            IdempotentResult {
                request_digest: command.request_digest,
                result: result.clone(),
            },
        )?;
        Ok(result)
    }

    /// Borrows the repository for local queries/tests.
    #[must_use]
    pub const fn repository(&self) -> &R {
        &self.repository
    }
}

/// Stable application boundary errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApplicationError {
    /// Boundary-provided/generator identifier was invalid.
    InvalidGeneratedIdentifier,
    /// Same replay key was presented with different canonical input.
    IdempotencyConflict,
    /// Domain invariant rejected the command.
    Domain(DomainError),
    /// Optimistic persistence failed.
    Repository(RepositoryError),
}

impl fmt::Display for ApplicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGeneratedIdentifier => formatter.write_str("invalid_generated_identifier"),
            Self::IdempotencyConflict => formatter.write_str("idempotency_conflict"),
            Self::Domain(error) => fmt::Display::fmt(error, formatter),
            Self::Repository(_) => formatter.write_str("repository_error"),
        }
    }
}

impl std::error::Error for ApplicationError {}
impl From<DomainError> for ApplicationError {
    fn from(value: DomainError) -> Self {
        Self::Domain(value)
    }
}
impl From<RepositoryError> for ApplicationError {
    fn from(value: RepositoryError) -> Self {
        Self::Repository(value)
    }
}
impl From<IdempotencyError> for ApplicationError {
    fn from(_: IdempotencyError) -> Self {
        Self::IdempotencyConflict
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::memory::{InMemoryIdempotencyStore, InMemoryOrganizationRepository};
    use crate::application::ports::{Clock, IdGenerator};
    use cauterizer_syntax::time::UtcInstant;

    #[derive(Clone)]
    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> UtcInstant {
            UtcInstant::parse("2026-07-22T00:00:00Z").expect("fixture instant")
        }
        fn now_unix_millis(&self) -> u64 {
            1_753_142_400_000
        }
    }

    struct SequentialIds(u64);
    impl IdGenerator for SequentialIds {
        fn next_opaque(&mut self, _context: &'static str) -> String {
            self.0 += 1;
            format!("00000000{:08}", self.0)
        }
    }

    fn command(digest_input: &str) -> BootstrapLocalOrganization {
        BootstrapLocalOrganization {
            mode: BootstrapMode::LocalOfflineDevelopment,
            organization_id: OrganizationId::new("00000000").expect("organization"),
            organization_name: "Local Cauterizer".to_owned(),
            owner_actor_id: ActorId::new("00000000").expect("actor"),
            idempotency_key: IdempotencyKey::new("bootstrap-0001").expect("key"),
            request_digest: Sha256Digest::of_bytes(digest_input),
            correlation_id: CorrelationId::new("00000000").expect("correlation"),
            causation_id: CausationId::new("00000000").expect("causation"),
        }
    }

    #[test]
    fn bootstrap_is_exactly_idempotent_and_emits_one_versioned_fact() {
        let mut facade = OrganizationAccessFacade::new(
            InMemoryOrganizationRepository::default(),
            InMemoryIdempotencyStore::default(),
            FixedClock,
            SequentialIds(0),
        );
        let first = facade.bootstrap_local(command("one")).expect("first");
        let retry = facade.bootstrap_local(command("one")).expect("retry");
        assert_eq!(first, retry);
        assert_eq!(facade.repository().outbox().len(), 1);
        assert_eq!(
            facade.repository().outbox()[0].schema_version.as_str(),
            CONTRACT_VERSION
        );
    }

    #[test]
    fn bootstrap_rejects_changed_input_for_the_same_tenant_key() {
        let mut facade = OrganizationAccessFacade::new(
            InMemoryOrganizationRepository::default(),
            InMemoryIdempotencyStore::default(),
            FixedClock,
            SequentialIds(0),
        );
        facade.bootstrap_local(command("one")).expect("first");
        assert_eq!(
            facade.bootstrap_local(command("changed")),
            Err(ApplicationError::IdempotencyConflict)
        );
    }
}
