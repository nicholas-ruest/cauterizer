//! Transactional in-memory reference adapters.
use super::ports::{
    AuditError, AuditFact, AuditSink, AuthorizationDecision, CommandControl, Commit, CommitOutcome,
    InboundEnvelope, RemediationRunRepository, RepositoryError, RunAuthorizer, RunKey, Versioned,
};
use cauterizer_syntax::authorization::AuthorizationRequestContext;
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{ContextQualifiedId, IdempotencyKey};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
type CommandKey = (RunKey, IdempotencyKey);
type InboxKey = (String, String, ContextQualifiedId);
struct State<A, E> {
    runs: BTreeMap<RunKey, Versioned<A>>,
    outbox: Vec<(RunKey, E)>,
    commands: BTreeMap<CommandKey, (Sha256Digest, u64)>,
    inbox: BTreeMap<InboxKey, (Sha256Digest, u64)>,
    sequences: BTreeMap<(String, String), u64>,
}
impl<A, E> Default for State<A, E> {
    fn default() -> Self {
        Self {
            runs: BTreeMap::new(),
            outbox: vec![],
            commands: BTreeMap::new(),
            inbox: BTreeMap::new(),
            sequences: BTreeMap::new(),
        }
    }
}
/// Lock-backed repository modelling one database transaction.
pub struct InMemoryRunRepository<A, E> {
    state: Arc<Mutex<State<A, E>>>,
}
impl<A, E> Clone for InMemoryRunRepository<A, E> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}
impl<A, E> Default for InMemoryRunRepository<A, E> {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(State::default())),
        }
    }
}
impl<A: Clone, E: Clone> InMemoryRunRepository<A, E> {
    /// Returns relay-visible events.
    /// # Panics
    /// Panics only after another thread poisoned the reference lock.
    #[must_use]
    pub fn outbox(&self) -> Vec<(RunKey, E)> {
        self.state
            .lock()
            .expect("repository lock poisoned")
            .outbox
            .clone()
    }
}
impl<A: Clone, E: Clone> RemediationRunRepository<A, E> for InMemoryRunRepository<A, E> {
    fn load(&self, key: &RunKey) -> Result<Option<Versioned<A>>, RepositoryError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?
            .runs
            .get(key)
            .cloned())
    }
    fn create(
        &self,
        key: RunKey,
        control: &CommandControl,
        commit: Commit<A, E>,
    ) -> Result<CommitOutcome, RepositoryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;
        let command_key = (key.clone(), control.idempotency_key.clone());
        if let Some((digest, version)) = state.commands.get(&command_key) {
            return if digest == &control.request_digest {
                Ok(CommitOutcome::Replayed(*version))
            } else {
                Err(RepositoryError::IdempotencyConflict)
            };
        }
        if control.expected_version != 0 || state.runs.contains_key(&key) {
            return Err(RepositoryError::Conflict);
        }
        state.runs.insert(
            key.clone(),
            Versioned {
                aggregate: commit.aggregate,
                version: 1,
            },
        );
        state
            .outbox
            .extend(commit.events.into_iter().map(|event| (key.clone(), event)));
        state
            .commands
            .insert(command_key, (control.request_digest, 1));
        Ok(CommitOutcome::Committed(1))
    }
    fn commit_command(
        &self,
        key: &RunKey,
        control: &CommandControl,
        commit: Commit<A, E>,
    ) -> Result<CommitOutcome, RepositoryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;
        let command_key = (key.clone(), control.idempotency_key.clone());
        if let Some((digest, version)) = state.commands.get(&command_key) {
            return if digest == &control.request_digest {
                Ok(CommitOutcome::Replayed(*version))
            } else {
                Err(RepositoryError::IdempotencyConflict)
            };
        }
        let current = state.runs.get(key).ok_or(RepositoryError::NotFound)?;
        if current.version != control.expected_version {
            return Err(RepositoryError::Conflict);
        }
        let next = control
            .expected_version
            .checked_add(1)
            .ok_or(RepositoryError::VersionExhausted)?;
        state.runs.insert(
            key.clone(),
            Versioned {
                aggregate: commit.aggregate,
                version: next,
            },
        );
        state
            .outbox
            .extend(commit.events.into_iter().map(|event| (key.clone(), event)));
        state
            .commands
            .insert(command_key, (control.request_digest, next));
        Ok(CommitOutcome::Committed(next))
    }
    fn commit_inbound(
        &self,
        key: &RunKey,
        expected_version: u64,
        envelope: &InboundEnvelope,
        commit: Commit<A, E>,
    ) -> Result<CommitOutcome, RepositoryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;
        if envelope.tenant != key.tenant {
            return Err(RepositoryError::TenantMismatch);
        }
        let inbox_key = (
            envelope.producer.clone(),
            envelope.stream.clone(),
            envelope.event_id.clone(),
        );
        if let Some((digest, version)) = state.inbox.get(&inbox_key) {
            return if digest == &envelope.payload_digest {
                Ok(CommitOutcome::DuplicateInbound(*version))
            } else {
                Err(RepositoryError::IdempotencyConflict)
            };
        }
        let sequence_key = (envelope.producer.clone(), envelope.stream.clone());
        let prior = state.sequences.get(&sequence_key).copied().unwrap_or(0);
        if envelope.sequence != prior.saturating_add(1) {
            return Err(RepositoryError::OutOfOrder);
        }
        let current = state.runs.get(key).ok_or(RepositoryError::NotFound)?;
        if current.version != expected_version {
            return Err(RepositoryError::Conflict);
        }
        let next = expected_version
            .checked_add(1)
            .ok_or(RepositoryError::VersionExhausted)?;
        state.runs.insert(
            key.clone(),
            Versioned {
                aggregate: commit.aggregate,
                version: next,
            },
        );
        state
            .outbox
            .extend(commit.events.into_iter().map(|event| (key.clone(), event)));
        state
            .inbox
            .insert(inbox_key, (envelope.payload_digest, next));
        state.sequences.insert(sequence_key, envelope.sequence);
        Ok(CommitOutcome::Committed(next))
    }
}
/// Deny-default configurable authorizer.
#[derive(Clone, Default)]
pub struct InMemoryAuthorizer {
    allowed: Arc<Mutex<bool>>,
}
impl InMemoryAuthorizer {
    /// Sets policy result.
    /// # Panics
    /// Panics only after another thread poisoned the reference lock.
    pub fn set_allowed(&self, value: bool) {
        *self.allowed.lock().expect("authorizer lock poisoned") = value;
    }
}
impl RunAuthorizer for InMemoryAuthorizer {
    fn authorize(&self, _: &AuthorizationRequestContext) -> AuthorizationDecision {
        if *self.allowed.lock().expect("authorizer lock poisoned") {
            AuthorizationDecision::Allow
        } else {
            AuthorizationDecision::Deny
        }
    }
}
/// Append-only audit adapter.
#[derive(Clone, Default)]
pub struct InMemoryAuditSink {
    facts: Arc<Mutex<Vec<AuditFact>>>,
}
impl InMemoryAuditSink {
    /// Returns recorded facts.
    /// # Panics
    /// Panics only after another thread poisoned the reference lock.
    #[must_use]
    pub fn facts(&self) -> Vec<AuditFact> {
        self.facts.lock().expect("audit lock poisoned").clone()
    }
}
impl AuditSink for InMemoryAuditSink {
    fn record(&self, fact: AuditFact) -> Result<(), AuditError> {
        self.facts.lock().map_err(|_| AuditError)?.push(fact);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cauterizer_syntax::identifiers::OrganizationId;
    fn key() -> RunKey {
        RunKey {
            tenant: OrganizationId::new("00000000").unwrap(),
            run_id: ContextQualifiedId::new("run", "00000000").unwrap(),
        }
    }
    fn control(version: u64, key: &str, input: &[u8]) -> CommandControl {
        CommandControl {
            expected_version: version,
            idempotency_key: IdempotencyKey::new(key).unwrap(),
            request_digest: Sha256Digest::of_bytes(input),
        }
    }
    #[test]
    fn crash_replay_and_conflicting_retry_are_stable() {
        let repo = InMemoryRunRepository::<u8, &str>::default();
        let k = key();
        let c = control(0, "create", b"one");
        assert_eq!(
            repo.create(
                k.clone(),
                &c,
                Commit {
                    aggregate: 1,
                    events: vec!["created"]
                }
            )
            .unwrap(),
            CommitOutcome::Committed(1)
        );
        let before = repo.outbox();
        assert_eq!(
            repo.create(
                k.clone(),
                &c,
                Commit {
                    aggregate: 9,
                    events: vec!["bad"]
                }
            )
            .unwrap(),
            CommitOutcome::Replayed(1)
        );
        assert_eq!(repo.outbox(), before);
        assert_eq!(
            repo.create(
                k,
                &control(0, "create", b"other"),
                Commit {
                    aggregate: 2,
                    events: vec![]
                }
            ),
            Err(RepositoryError::IdempotencyConflict)
        );
    }
    #[test]
    fn inbound_duplicate_gap_and_payload_substitution_fail_closed() {
        let repo = InMemoryRunRepository::<u8, &str>::default();
        let k = key();
        repo.create(
            k.clone(),
            &control(0, "create", b"one"),
            Commit {
                aggregate: 1,
                events: vec![],
            },
        )
        .unwrap();
        let envelope = InboundEnvelope {
            tenant: k.tenant.clone(),
            producer: "isolated-execution".into(),
            stream: "lease_1".into(),
            sequence: 1,
            event_id: ContextQualifiedId::new("event", "00000000").unwrap(),
            payload_digest: Sha256Digest::of_bytes(b"receipt"),
        };
        assert_eq!(
            repo.commit_inbound(
                &k,
                1,
                &envelope,
                Commit {
                    aggregate: 2,
                    events: vec!["observed"]
                }
            )
            .unwrap(),
            CommitOutcome::Committed(2)
        );
        let before = repo.outbox();
        assert_eq!(
            repo.commit_inbound(
                &k,
                1,
                &envelope,
                Commit {
                    aggregate: 9,
                    events: vec![]
                }
            )
            .unwrap(),
            CommitOutcome::DuplicateInbound(2)
        );
        assert_eq!(repo.outbox(), before);
        let mut gap = envelope.clone();
        gap.event_id = ContextQualifiedId::new("event", "11111111").unwrap();
        gap.sequence = 3;
        assert_eq!(
            repo.commit_inbound(
                &k,
                2,
                &gap,
                Commit {
                    aggregate: 3,
                    events: vec![]
                }
            ),
            Err(RepositoryError::OutOfOrder)
        );
        let mut changed = envelope;
        changed.payload_digest = Sha256Digest::of_bytes(b"substitution");
        assert_eq!(
            repo.commit_inbound(
                &k,
                2,
                &changed,
                Commit {
                    aggregate: 3,
                    events: vec![]
                }
            ),
            Err(RepositoryError::IdempotencyConflict)
        );
    }
    #[test]
    fn cancellation_race_has_one_atomic_winner() {
        let repo = InMemoryRunRepository::<&str, &str>::default();
        let run = key();
        repo.create(
            run.clone(),
            &control(0, "create", b"create"),
            Commit {
                aggregate: "active",
                events: vec![],
            },
        )
        .unwrap();
        assert_eq!(
            repo.commit_command(
                &run,
                &control(1, "cancel-a", b"operator-a"),
                Commit {
                    aggregate: "cancelled",
                    events: vec!["cancelled"]
                }
            )
            .unwrap(),
            CommitOutcome::Committed(2)
        );
        let outbox = repo.outbox();
        assert_eq!(
            repo.commit_command(
                &run,
                &control(1, "cancel-b", b"operator-b"),
                Commit {
                    aggregate: "cancelled-other",
                    events: vec!["cancelled-other"]
                }
            ),
            Err(RepositoryError::Conflict)
        );
        assert_eq!(repo.load(&run).unwrap().unwrap().aggregate, "cancelled");
        assert_eq!(repo.outbox(), outbox);
    }
}
