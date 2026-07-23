//! Thread-safe in-memory application adapters.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use cauterizer_syntax::authorization::{ActionName, AuthorizationRequestContext};
use cauterizer_syntax::identifiers::{IdempotencyKey, OrganizationId};

use super::ports::{
    AccountKey, AuditError, AuditFact, AuditSink, AuthorizationDecision, CommercialAuthorizer,
    EntitlementAccountRepository, IdempotencyError, IdempotencyRecord, IdempotencyStore,
    RepositoryCommit, RepositoryError, Versioned,
};

#[derive(Clone, Debug)]
struct RepositoryState<A, E> {
    accounts: BTreeMap<AccountKey, Versioned<A>>,
    outbox: Vec<(AccountKey, E)>,
}

impl<A, E> Default for RepositoryState<A, E> {
    fn default() -> Self {
        Self {
            accounts: BTreeMap::new(),
            outbox: Vec::new(),
        }
    }
}

/// Thread-safe reference repository whose lock models one row transaction.
#[derive(Clone, Debug)]
pub struct InMemoryEntitlementRepository<A, E> {
    state: Arc<Mutex<RepositoryState<A, E>>>,
}

impl<A, E> Default for InMemoryEntitlementRepository<A, E> {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(RepositoryState::default())),
        }
    }
}

impl<A: Clone, E: Clone> InMemoryEntitlementRepository<A, E> {
    /// Returns relay-visible events in commit order for contract tests.
    ///
    /// # Panics
    ///
    /// Panics only after another test thread has poisoned the in-memory lock.
    #[must_use]
    pub fn outbox(&self) -> Vec<(AccountKey, E)> {
        self.state
            .lock()
            .expect("repository lock poisoned")
            .outbox
            .clone()
    }
}

impl<A: Clone, E: Clone> EntitlementAccountRepository<A, E>
    for InMemoryEntitlementRepository<A, E>
{
    fn load(&self, key: &AccountKey) -> Result<Option<Versioned<A>>, RepositoryError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?
            .accounts
            .get(key)
            .cloned())
    }

    fn transact<T, F>(
        &self,
        key: &AccountKey,
        expected_version: u64,
        operation: F,
    ) -> Result<T, RepositoryError>
    where
        F: FnOnce(&A) -> Result<(RepositoryCommit<A, E>, T), RepositoryError>,
    {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;
        let current = state.accounts.get(key).ok_or(RepositoryError::NotFound)?;
        if current.version != expected_version {
            return Err(RepositoryError::Conflict);
        }
        let next = current
            .version
            .checked_add(1)
            .ok_or(RepositoryError::VersionExhausted)?;
        let (commit, result) = operation(&current.aggregate)?;
        let staged_events = commit.events;
        state.accounts.insert(
            key.clone(),
            Versioned {
                aggregate: commit.aggregate,
                version: next,
            },
        );
        state
            .outbox
            .extend(staged_events.into_iter().map(|event| (key.clone(), event)));
        Ok(result)
    }

    fn create(
        &self,
        key: AccountKey,
        commit: RepositoryCommit<A, E>,
    ) -> Result<u64, RepositoryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;
        if state.accounts.contains_key(&key) {
            return Err(RepositoryError::Conflict);
        }
        state.accounts.insert(
            key.clone(),
            Versioned {
                aggregate: commit.aggregate,
                version: 1,
            },
        );
        state
            .outbox
            .extend(commit.events.into_iter().map(|event| (key.clone(), event)));
        Ok(1)
    }
}

type IdempotencyKeyTuple = (OrganizationId, ActionName, IdempotencyKey);

/// Thread-safe tenant/scope/key replay store.
#[derive(Clone, Debug)]
pub struct InMemoryIdempotencyStore<R> {
    records: Arc<Mutex<BTreeMap<IdempotencyKeyTuple, IdempotencyRecord<R>>>>,
}

impl<R> Default for InMemoryIdempotencyStore<R> {
    fn default() -> Self {
        Self {
            records: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl<R: Clone + Eq> IdempotencyStore<R> for InMemoryIdempotencyStore<R> {
    fn get(
        &self,
        organization_id: &OrganizationId,
        scope: &ActionName,
        key: &IdempotencyKey,
    ) -> Option<IdempotencyRecord<R>> {
        self.records
            .lock()
            .expect("idempotency lock poisoned")
            .get(&(organization_id.clone(), scope.clone(), key.clone()))
            .cloned()
    }

    fn put(
        &self,
        organization_id: OrganizationId,
        scope: ActionName,
        key: IdempotencyKey,
        record: IdempotencyRecord<R>,
    ) -> Result<(), IdempotencyError> {
        let mut records = self.records.lock().map_err(|_| IdempotencyError)?;
        let compound = (organization_id, scope, key);
        match records.get(&compound) {
            Some(existing) if existing != &record => Err(IdempotencyError),
            Some(_) => Ok(()),
            None => {
                records.insert(compound, record);
                Ok(())
            }
        }
    }
}

/// Deterministic deny-by-default authorizer for application tests/local wiring.
#[derive(Clone, Debug, Default)]
pub struct StaticAuthorizer {
    allowed: Arc<Mutex<Vec<AuthorizationRequestContext>>>,
}

impl StaticAuthorizer {
    /// Adds one exact request shape to the allowlist.
    ///
    /// # Panics
    ///
    /// Panics only after another test thread has poisoned the in-memory lock.
    pub fn allow(&self, request: AuthorizationRequestContext) {
        self.allowed
            .lock()
            .expect("authorization lock poisoned")
            .push(request);
    }
}

impl CommercialAuthorizer for StaticAuthorizer {
    fn authorize(&self, request: &AuthorizationRequestContext) -> AuthorizationDecision {
        if self
            .allowed
            .lock()
            .is_ok_and(|allowed| allowed.iter().any(|candidate| candidate == request))
        {
            AuthorizationDecision::Allow
        } else {
            AuthorizationDecision::Deny
        }
    }
}

/// Append-only in-memory audit adapter with failure injection.
#[derive(Clone, Debug)]
pub struct InMemoryAuditSink {
    state: Arc<Mutex<(bool, Vec<AuditFact>)>>,
}

impl Default for InMemoryAuditSink {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new((true, Vec::new()))),
        }
    }
}

impl InMemoryAuditSink {
    /// Enables/disables deterministic write failure.
    pub fn set_available(&self, available: bool) {
        if let Ok(mut state) = self.state.lock() {
            state.0 = available;
        }
    }

    /// Returns recorded facts without exposing a mutable sink.
    ///
    /// # Panics
    ///
    /// Panics only after another test thread has poisoned the in-memory lock.
    #[must_use]
    pub fn facts(&self) -> Vec<AuditFact> {
        self.state.lock().expect("audit lock poisoned").1.clone()
    }
}

impl AuditSink for InMemoryAuditSink {
    fn record(&self, fact: AuditFact) -> Result<(), AuditError> {
        let mut state = self.state.lock().map_err(|_| AuditError)?;
        if !state.0 {
            return Err(AuditError);
        }
        state.1.push(fact);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use cauterizer_syntax::digest::Sha256Digest;

    use super::*;

    fn key(tenant: &str) -> AccountKey {
        AccountKey {
            organization_id: OrganizationId::new(tenant).unwrap(),
            account_id: cauterizer_syntax::identifiers::ContextQualifiedId::new(
                "entitlement-account",
                "00000000",
            )
            .unwrap(),
        }
    }

    #[test]
    fn optimistic_race_has_exactly_one_winner_and_no_lost_events() {
        let repository = InMemoryEntitlementRepository::<u64, String>::default();
        repository
            .create(
                key("00000000"),
                RepositoryCommit {
                    aggregate: 100,
                    events: vec!["created".into()],
                },
            )
            .unwrap();
        let threads = 16;
        let barrier = Arc::new(Barrier::new(threads));
        let successes = (0..threads)
            .map(|_| {
                let repository = repository.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    repository.transact(&key("00000000"), 1, |balance| {
                        Ok((
                            RepositoryCommit {
                                aggregate: balance - 60,
                                events: vec!["reserved-60".into()],
                            },
                            (),
                        ))
                    })
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .filter_map(|handle| handle.join().unwrap().ok())
            .count();
        assert_eq!(successes, 1);
        assert_eq!(
            repository
                .load(&key("00000000"))
                .unwrap()
                .unwrap()
                .aggregate,
            40
        );
        assert_eq!(
            repository.outbox(),
            [
                (key("00000000"), "created".into()),
                (key("00000000"), "reserved-60".into())
            ]
        );
    }

    #[test]
    fn callback_failure_rolls_back_state_and_outbox() {
        let repository = InMemoryEntitlementRepository::<u64, String>::default();
        repository
            .create(
                key("00000000"),
                RepositoryCommit {
                    aggregate: 10,
                    events: vec![],
                },
            )
            .unwrap();
        assert_eq!(
            repository.transact::<(), _>(&key("00000000"), 1, |_| {
                Err(RepositoryError::MutationRejected)
            }),
            Err(RepositoryError::MutationRejected)
        );
        assert_eq!(
            repository.load(&key("00000000")).unwrap().unwrap().version,
            1
        );
        assert!(repository.outbox().is_empty());
    }

    #[test]
    fn idempotency_is_tenant_and_command_scoped_and_conflicts_exactly() {
        let store = InMemoryIdempotencyStore::default();
        let scope = ActionName::parse("entitlements.reserve").unwrap();
        let replay = IdempotencyRecord {
            request_digest: Sha256Digest::of_bytes("same"),
            result: 7_u64,
        };
        store
            .put(
                OrganizationId::new("00000000").unwrap(),
                scope.clone(),
                IdempotencyKey::new("request-0001").unwrap(),
                replay.clone(),
            )
            .unwrap();
        assert_eq!(
            store.get(
                &OrganizationId::new("00000000").unwrap(),
                &scope,
                &IdempotencyKey::new("request-0001").unwrap()
            ),
            Some(replay.clone())
        );
        assert!(
            store
                .put(
                    OrganizationId::new("11111111").unwrap(),
                    scope.clone(),
                    IdempotencyKey::new("request-0001").unwrap(),
                    replay.clone(),
                )
                .is_ok()
        );
        assert_eq!(
            store.put(
                OrganizationId::new("00000000").unwrap(),
                scope,
                IdempotencyKey::new("request-0001").unwrap(),
                IdempotencyRecord {
                    request_digest: Sha256Digest::of_bytes("changed"),
                    result: 7
                }
            ),
            Err(IdempotencyError)
        );
    }
}
