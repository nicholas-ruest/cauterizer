//! Thread-safe offline reference adapters.
use super::ports::{
    AdvisoryAuthorizer, AdvisoryRecordRepository, AuditError, AuditFact, AuditSink,
    AuthorizationDecision, CommandControl, CommitOutcome, RecordCommit, RepositoryError,
    VersionedRecord,
};
use crate::domain::AdvisoryFact;
use cauterizer_syntax::authorization::AuthorizationRequestContext;
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{IdempotencyKey, OrganizationId};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
type RecordKey = (OrganizationId, String);
type CommandKey = (OrganizationId, String, IdempotencyKey);
#[derive(Default)]
struct State {
    records: BTreeMap<RecordKey, VersionedRecord>,
    outbox: Vec<(RecordKey, AdvisoryFact)>,
    commands: BTreeMap<CommandKey, (Sha256Digest, u64)>,
}
/// Lock-backed repository modelling one relational transaction.
#[derive(Clone, Default)]
pub struct InMemoryAdvisoryRepository {
    state: Arc<Mutex<State>>,
}
impl InMemoryAdvisoryRepository {
    /// Returns relay-visible facts.
    /// # Panics
    /// Panics only when another thread poisoned the reference lock.
    #[must_use]
    pub fn outbox(&self) -> Vec<(RecordKey, AdvisoryFact)> {
        self.state
            .lock()
            .expect("repository lock poisoned")
            .outbox
            .clone()
    }
}
impl AdvisoryRecordRepository for InMemoryAdvisoryRepository {
    fn load(
        &self,
        tenant: &OrganizationId,
        record: &str,
    ) -> Result<Option<VersionedRecord>, RepositoryError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?
            .records
            .get(&(tenant.clone(), record.into()))
            .cloned())
    }
    fn create(
        &self,
        tenant: OrganizationId,
        record: String,
        commit: RecordCommit,
    ) -> Result<u64, RepositoryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;
        let record_key = (tenant, record);
        if state.records.contains_key(&record_key) {
            return Err(RepositoryError::Conflict);
        }
        state.records.insert(
            record_key.clone(),
            VersionedRecord {
                aggregate: commit.aggregate,
                version: 1,
            },
        );
        state.outbox.extend(
            commit
                .facts
                .into_iter()
                .map(|fact| (record_key.clone(), fact)),
        );
        Ok(1)
    }
    fn create_command(
        &self,
        tenant: OrganizationId,
        record: String,
        control: &CommandControl,
        commit: RecordCommit,
    ) -> Result<CommitOutcome, RepositoryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;
        let command_key = (
            tenant.clone(),
            record.clone(),
            control.idempotency_key.clone(),
        );
        if let Some((digest, version)) = state.commands.get(&command_key) {
            return if digest == &control.request_digest {
                Ok(CommitOutcome::Replayed(*version))
            } else {
                Err(RepositoryError::IdempotencyConflict)
            };
        }
        if control.expected_version != 0 {
            return Err(RepositoryError::Conflict);
        }
        let record_key = (tenant, record);
        if state.records.contains_key(&record_key) {
            return Err(RepositoryError::Conflict);
        }
        state.records.insert(
            record_key.clone(),
            VersionedRecord {
                aggregate: commit.aggregate,
                version: 1,
            },
        );
        state.outbox.extend(
            commit
                .facts
                .into_iter()
                .map(|fact| (record_key.clone(), fact)),
        );
        state
            .commands
            .insert(command_key, (control.request_digest, 1));
        Ok(CommitOutcome::Committed(1))
    }
    fn commit(
        &self,
        t: &OrganizationId,
        r: &str,
        cntl: &CommandControl,
        c: RecordCommit,
    ) -> Result<CommitOutcome, RepositoryError> {
        let mut s = self
            .state
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;
        let ck = (t.clone(), r.into(), cntl.idempotency_key.clone());
        if let Some((d, v)) = s.commands.get(&ck) {
            return if d == &cntl.request_digest {
                Ok(CommitOutcome::Replayed(*v))
            } else {
                Err(RepositoryError::IdempotencyConflict)
            };
        }
        let rk = (t.clone(), r.into());
        let current = s.records.get(&rk).ok_or(RepositoryError::NotFound)?;
        if current.version != cntl.expected_version {
            return Err(RepositoryError::Conflict);
        }
        let next = cntl
            .expected_version
            .checked_add(1)
            .ok_or(RepositoryError::VersionExhausted)?;
        s.records.insert(
            rk.clone(),
            VersionedRecord {
                aggregate: c.aggregate,
                version: next,
            },
        );
        s.outbox
            .extend(c.facts.into_iter().map(|f| (rk.clone(), f)));
        s.commands.insert(ck, (cntl.request_digest, next));
        Ok(CommitOutcome::Committed(next))
    }
}
/// Deny-default configurable test policy.
#[derive(Clone, Default)]
pub struct InMemoryAuthorizer {
    allow: Arc<Mutex<bool>>,
}
impl InMemoryAuthorizer {
    /// Sets policy result.
    /// # Panics
    /// Panics only when another thread poisoned the reference lock.
    pub fn set_allowed(&self, v: bool) {
        *self.allow.lock().expect("authorizer lock poisoned") = v;
    }
}
impl AdvisoryAuthorizer for InMemoryAuthorizer {
    fn authorize(&self, _: &AuthorizationRequestContext) -> AuthorizationDecision {
        if *self.allow.lock().expect("authorizer lock poisoned") {
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
    /// Returns audit facts.
    /// # Panics
    /// Panics only when another thread poisoned the reference lock.
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
    use crate::domain::{AdvisoryRecord, AdvisoryRecordId};

    fn tenant() -> OrganizationId {
        OrganizationId::new("00000000").unwrap()
    }
    fn aggregate() -> AdvisoryRecord {
        AdvisoryRecord::new(tenant(), AdvisoryRecordId::new("00000000").unwrap())
    }
    fn control(version: u64, key: &str, input: &[u8]) -> CommandControl {
        CommandControl {
            expected_version: version,
            idempotency_key: IdempotencyKey::new(key).unwrap(),
            request_digest: Sha256Digest::of_bytes(input),
        }
    }

    #[test]
    fn exact_replay_is_atomic_and_conflicting_reuse_fails() {
        let repository = InMemoryAdvisoryRepository::default();
        repository
            .create(
                tenant(),
                "advisory_00000000".into(),
                RecordCommit {
                    aggregate: aggregate(),
                    facts: vec![],
                },
            )
            .unwrap();
        let command = control(1, "fixture-one", b"canonical fixture command");
        assert_eq!(
            repository
                .commit(
                    &tenant(),
                    "advisory_00000000",
                    &command,
                    RecordCommit {
                        aggregate: aggregate(),
                        facts: vec![]
                    }
                )
                .unwrap(),
            CommitOutcome::Committed(2)
        );
        let outbox = repository.outbox();
        assert_eq!(
            repository
                .commit(
                    &tenant(),
                    "advisory_00000000",
                    &command,
                    RecordCommit {
                        aggregate: aggregate(),
                        facts: vec![]
                    }
                )
                .unwrap(),
            CommitOutcome::Replayed(2)
        );
        assert_eq!(
            repository
                .load(&tenant(), "advisory_00000000")
                .unwrap()
                .unwrap()
                .version,
            2
        );
        assert_eq!(repository.outbox(), outbox);
        assert_eq!(
            repository.commit(
                &tenant(),
                "advisory_00000000",
                &control(2, "fixture-one", b"different"),
                RecordCommit {
                    aggregate: aggregate(),
                    facts: vec![]
                }
            ),
            Err(RepositoryError::IdempotencyConflict)
        );
    }

    #[test]
    fn stale_version_changes_neither_state_nor_outbox() {
        let repository = InMemoryAdvisoryRepository::default();
        repository
            .create(
                tenant(),
                "advisory_00000000".into(),
                RecordCommit {
                    aggregate: aggregate(),
                    facts: vec![],
                },
            )
            .unwrap();
        let before = repository.outbox();
        assert_eq!(
            repository.commit(
                &tenant(),
                "advisory_00000000",
                &control(0, "stale", b"input"),
                RecordCommit {
                    aggregate: aggregate(),
                    facts: vec![]
                }
            ),
            Err(RepositoryError::Conflict)
        );
        assert_eq!(
            repository
                .load(&tenant(), "advisory_00000000")
                .unwrap()
                .unwrap()
                .version,
            1
        );
        assert_eq!(repository.outbox(), before);
    }
}
