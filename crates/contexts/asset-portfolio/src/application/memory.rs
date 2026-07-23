//! Thread-safe reference adapters.
use super::ports::{
    AssetAuthorizer, AssetPortfolioRepository, AuditError, AuditFact, AuditSink,
    AuthorizationDecision, CommandCommitOutcome, CommandControl, PortfolioCommit, RepositoryError,
    VersionedPortfolio,
};
use crate::domain::AssetEvent;
use cauterizer_syntax::authorization::AuthorizationRequestContext;
use cauterizer_syntax::identifiers::OrganizationId;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct State {
    portfolios: BTreeMap<OrganizationId, VersionedPortfolio>,
    outbox: Vec<(OrganizationId, AssetEvent)>,
    commands: BTreeMap<
        (
            OrganizationId,
            cauterizer_syntax::identifiers::IdempotencyKey,
        ),
        (cauterizer_syntax::digest::Sha256Digest, u64),
    >,
}
/// In-memory repository with transaction-equivalent locking.
#[derive(Clone, Default)]
pub struct InMemoryAssetPortfolioRepository {
    state: Arc<Mutex<State>>,
}
impl InMemoryAssetPortfolioRepository {
    /// Returns relay-visible facts in commit order.
    /// # Panics
    /// Panics only after another thread poisons the reference-adapter lock.
    #[must_use]
    pub fn outbox(&self) -> Vec<(OrganizationId, AssetEvent)> {
        self.state
            .lock()
            .expect("repository lock poisoned")
            .outbox
            .clone()
    }
}
impl AssetPortfolioRepository for InMemoryAssetPortfolioRepository {
    fn load(&self, t: &OrganizationId) -> Result<Option<VersionedPortfolio>, RepositoryError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?
            .portfolios
            .get(t)
            .cloned())
    }
    fn create(&self, t: OrganizationId, c: PortfolioCommit) -> Result<u64, RepositoryError> {
        let mut s = self
            .state
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;
        if s.portfolios.contains_key(&t) {
            return Err(RepositoryError::Conflict);
        }
        s.portfolios.insert(
            t.clone(),
            VersionedPortfolio {
                aggregate: c.aggregate,
                version: 1,
            },
        );
        s.outbox
            .extend(c.events.into_iter().map(|e| (t.clone(), e)));
        Ok(1)
    }
    fn commit_command(
        &self,
        t: &OrganizationId,
        control: &CommandControl,
        c: PortfolioCommit,
    ) -> Result<CommandCommitOutcome, RepositoryError> {
        let mut s = self
            .state
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;
        let command_key = (t.clone(), control.idempotency_key.clone());
        if let Some((digest, version)) = s.commands.get(&command_key) {
            return if digest == &control.request_digest {
                Ok(CommandCommitOutcome::Replayed(*version))
            } else {
                Err(RepositoryError::IdempotencyConflict)
            };
        }
        let current = s.portfolios.get(t).ok_or(RepositoryError::NotFound)?;
        if current.version != control.expected_version {
            return Err(RepositoryError::Conflict);
        }
        let next = control
            .expected_version
            .checked_add(1)
            .ok_or(RepositoryError::VersionExhausted)?;
        s.portfolios.insert(
            t.clone(),
            VersionedPortfolio {
                aggregate: c.aggregate,
                version: next,
            },
        );
        s.outbox
            .extend(c.events.into_iter().map(|e| (t.clone(), e)));
        s.commands
            .insert(command_key, (control.request_digest, next));
        Ok(CommandCommitOutcome::Committed(next))
    }
}
/// Configurable policy reference adapter; defaults to deny.
#[derive(Clone, Default)]
pub struct InMemoryAuthorizer {
    allowed: Arc<Mutex<bool>>,
}
impl InMemoryAuthorizer {
    /// Sets the test policy result.
    /// # Panics
    /// Panics only after another thread poisons the reference-adapter lock.
    pub fn set_allowed(&self, allowed: bool) {
        *self.allowed.lock().expect("authorizer lock poisoned") = allowed;
    }
}
impl AssetAuthorizer for InMemoryAuthorizer {
    fn authorize(&self, _: &AuthorizationRequestContext) -> AuthorizationDecision {
        if *self.allowed.lock().expect("authorizer lock poisoned") {
            AuthorizationDecision::Allow
        } else {
            AuthorizationDecision::Deny
        }
    }
}
/// Append-only audit reference adapter.
#[derive(Clone, Default)]
pub struct InMemoryAuditSink {
    facts: Arc<Mutex<Vec<AuditFact>>>,
}
impl InMemoryAuditSink {
    /// Returns recorded facts.
    /// # Panics
    /// Panics only after another thread poisons the reference-adapter lock.
    #[must_use]
    pub fn facts(&self) -> Vec<AuditFact> {
        self.facts.lock().expect("audit lock poisoned").clone()
    }
}
impl AuditSink for InMemoryAuditSink {
    fn record(&self, f: AuditFact) -> Result<(), AuditError> {
        self.facts.lock().map_err(|_| AuditError)?.push(f);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{AssetPortfolio, AssetType, Criticality, Environment, SourceLocator};

    fn tenant() -> OrganizationId {
        OrganizationId::new("00000000").unwrap()
    }
    fn control(version: u64, key: &str, input: &[u8]) -> CommandControl {
        CommandControl {
            expected_version: version,
            idempotency_key: cauterizer_syntax::identifiers::IdempotencyKey::new(key).unwrap(),
            request_digest: cauterizer_syntax::digest::Sha256Digest::of_bytes(input),
        }
    }

    #[test]
    fn stale_save_rolls_back_state_and_outbox_atomically() {
        let repository = InMemoryAssetPortfolioRepository::default();
        let mut initial = AssetPortfolio::new(tenant());
        initial
            .register(
                crate::domain::AssetId::new("00000000").unwrap(),
                AssetType::Repository,
                SourceLocator::parse("https://code.example.com/acme/widget.git").unwrap(),
                Environment::Production,
                Criticality::High,
            )
            .unwrap();
        let events = initial.take_pending_events();
        repository
            .create(
                tenant(),
                PortfolioCommit {
                    aggregate: initial,
                    events,
                },
            )
            .unwrap();
        let before = repository.load(&tenant()).unwrap().unwrap();
        let outbox_before = repository.outbox();
        let mut stale = before.aggregate.clone();
        stale
            .deactivate(&crate::domain::AssetId::new("00000000").unwrap())
            .unwrap();
        let stale_events = stale.take_pending_events();

        assert_eq!(
            repository.commit_command(
                &tenant(),
                &control(0, "stale", b"deactivate"),
                PortfolioCommit {
                    aggregate: stale,
                    events: stale_events,
                }
            ),
            Err(RepositoryError::Conflict)
        );
        let after = repository.load(&tenant()).unwrap().unwrap();
        assert_eq!(after.version, before.version);
        assert_eq!(after.aggregate.snapshot(), before.aggregate.snapshot());
        assert_eq!(repository.outbox(), outbox_before);
    }

    #[test]
    fn exact_retry_replays_without_advancing_state_or_outbox_and_key_reuse_conflicts() {
        let repository = InMemoryAssetPortfolioRepository::default();
        repository
            .create(
                tenant(),
                PortfolioCommit {
                    aggregate: AssetPortfolio::new(tenant()),
                    events: vec![],
                },
            )
            .unwrap();
        let first = PortfolioCommit {
            aggregate: AssetPortfolio::new(tenant()),
            events: vec![],
        };
        let first_control = control(1, "register-one", b"canonical-register-input");
        assert_eq!(
            repository
                .commit_command(&tenant(), &first_control, first)
                .unwrap(),
            CommandCommitOutcome::Committed(2)
        );
        let outbox = repository.outbox();
        assert_eq!(
            repository
                .commit_command(
                    &tenant(),
                    &first_control,
                    PortfolioCommit {
                        aggregate: AssetPortfolio::new(tenant()),
                        events: vec![],
                    },
                )
                .unwrap(),
            CommandCommitOutcome::Replayed(2)
        );
        assert_eq!(repository.load(&tenant()).unwrap().unwrap().version, 2);
        assert_eq!(repository.outbox(), outbox);
        assert_eq!(
            repository.commit_command(
                &tenant(),
                &control(2, "register-one", b"different-input"),
                PortfolioCommit {
                    aggregate: AssetPortfolio::new(tenant()),
                    events: vec![]
                },
            ),
            Err(RepositoryError::IdempotencyConflict)
        );
    }
}
