//! Transactional in-memory lease repository.
use super::ports::{
    CommandControl, CommitOutcome, ExecutionLeaseRepository, LeaseCommit, LeaseKey,
    RepositoryError, VersionedLease,
};
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::IdempotencyKey;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
type CommandKey = (LeaseKey, IdempotencyKey);
#[derive(Default)]
struct State {
    leases: BTreeMap<LeaseKey, VersionedLease>,
    outbox: Vec<(LeaseKey, crate::domain::ExecutionEvent)>,
    commands: BTreeMap<CommandKey, (Sha256Digest, u64)>,
}
/// Lock-backed transaction reference adapter.
#[derive(Clone, Default)]
pub struct InMemoryLeaseRepository {
    state: Arc<Mutex<State>>,
}
impl InMemoryLeaseRepository {
    /// Returns relay-visible events.
    /// # Panics
    /// Panics only after another thread poisons the reference lock.
    #[must_use]
    pub fn outbox(&self) -> Vec<(LeaseKey, crate::domain::ExecutionEvent)> {
        self.state
            .lock()
            .expect("repository lock poisoned")
            .outbox
            .clone()
    }
}
impl ExecutionLeaseRepository for InMemoryLeaseRepository {
    fn load(&self, key: &LeaseKey) -> Result<Option<VersionedLease>, RepositoryError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?
            .leases
            .get(key)
            .cloned())
    }
    fn create(
        &self,
        key: LeaseKey,
        control: &CommandControl,
        commit: LeaseCommit,
    ) -> Result<CommitOutcome, RepositoryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;
        let command = (key.clone(), control.idempotency_key.clone());
        if let Some((digest, version)) = state.commands.get(&command) {
            return if digest == &control.request_digest {
                Ok(CommitOutcome::Replayed(*version))
            } else {
                Err(RepositoryError::IdempotencyConflict)
            };
        }
        if control.expected_version != 0 || state.leases.contains_key(&key) {
            return Err(RepositoryError::Conflict);
        }
        state.leases.insert(
            key.clone(),
            VersionedLease {
                aggregate: commit.aggregate,
                version: 1,
            },
        );
        state
            .outbox
            .extend(commit.events.into_iter().map(|event| (key.clone(), event)));
        state.commands.insert(command, (control.request_digest, 1));
        Ok(CommitOutcome::Committed(1))
    }
    fn commit(
        &self,
        key: &LeaseKey,
        control: &CommandControl,
        commit: LeaseCommit,
    ) -> Result<CommitOutcome, RepositoryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;
        let command = (key.clone(), control.idempotency_key.clone());
        if let Some((digest, version)) = state.commands.get(&command) {
            return if digest == &control.request_digest {
                Ok(CommitOutcome::Replayed(*version))
            } else {
                Err(RepositoryError::IdempotencyConflict)
            };
        }
        let current = state.leases.get(key).ok_or(RepositoryError::NotFound)?;
        if current.version != control.expected_version {
            return Err(RepositoryError::Conflict);
        }
        let next = control
            .expected_version
            .checked_add(1)
            .ok_or(RepositoryError::VersionExhausted)?;
        state.leases.insert(
            key.clone(),
            VersionedLease {
                aggregate: commit.aggregate,
                version: next,
            },
        );
        state
            .outbox
            .extend(commit.events.into_iter().map(|event| (key.clone(), event)));
        state
            .commands
            .insert(command, (control.request_digest, next));
        Ok(CommitOutcome::Committed(next))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::*;
    use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
    use std::collections::BTreeSet;

    fn request() -> ExecutionRequest {
        ExecutionRequest {
            request_digest: Sha256Digest::of_bytes(b"request"),
            job_class: JobClass::Solver,
            environment: EnvironmentRef {
                image_digest: Sha256Digest::of_bytes(b"image"),
                bundle_digest: Sha256Digest::of_bytes(b"bundle"),
            },
            argv: vec!["/usr/bin/test".into()],
            environment_variables: vec![("LANG".into(), "C.UTF-8".into())],
            capabilities: CapabilityEnvelope {
                network: NetworkPolicy::Denied,
                mounts: vec![],
                linux_capabilities: BTreeSet::new(),
                privilege_escalation: false,
                runtime_daemon_socket: false,
            },
            resources: ResourceLimits {
                cpu_millis: 1,
                memory_bytes: 1,
                disk_bytes: 1,
                process_count: 1,
                wall_time_ms: 1,
            },
            output: OutputLimits {
                stdout_bytes: 1,
                stderr_bytes: 1,
            },
        }
    }
    fn lease() -> ExecutionLease {
        ExecutionLease::allocate(
            OrganizationId::new("00000000").unwrap(),
            ExecutionLeaseId::new("00000000").unwrap(),
            request(),
            ConformanceLabel::NonConformantLocal,
        )
        .unwrap()
    }
    fn key() -> LeaseKey {
        LeaseKey {
            tenant: OrganizationId::new("00000000").unwrap(),
            lease: "execution-lease_00000000".into(),
        }
    }
    fn control(version: u64, replay: &str, digest: &[u8]) -> CommandControl {
        CommandControl {
            expected_version: version,
            idempotency_key: IdempotencyKey::new(replay).unwrap(),
            request_digest: Sha256Digest::of_bytes(digest),
        }
    }

    #[test]
    fn exact_retry_conflict_and_stale_save_are_atomic() {
        let repository = InMemoryLeaseRepository::default();
        let aggregate = lease();
        let events = aggregate.events().to_vec();
        let create = control(0, "allocate-key", b"allocate");
        assert_eq!(
            repository
                .create(key(), &create, LeaseCommit { aggregate, events })
                .unwrap(),
            CommitOutcome::Committed(1)
        );
        let outbox = repository.outbox();
        assert_eq!(
            repository
                .create(
                    key(),
                    &create,
                    LeaseCommit {
                        aggregate: lease(),
                        events: vec![]
                    }
                )
                .unwrap(),
            CommitOutcome::Replayed(1)
        );
        assert_eq!(repository.outbox(), outbox);
        assert_eq!(
            repository.create(
                key(),
                &control(0, "allocate-key", b"different"),
                LeaseCommit {
                    aggregate: lease(),
                    events: vec![]
                }
            ),
            Err(RepositoryError::IdempotencyConflict)
        );

        let before = repository.load(&key()).unwrap().unwrap();
        let mut changed = before.aggregate.clone();
        changed
            .start(WorkerIdentity {
                id: ContextQualifiedId::new("worker", "00000000").unwrap(),
                pool: JobClass::Solver,
            })
            .unwrap();
        assert_eq!(
            repository.commit(
                &key(),
                &control(0, "stale-key", b"stale"),
                LeaseCommit {
                    aggregate: changed,
                    events: vec![]
                }
            ),
            Err(RepositoryError::Conflict)
        );
        let after = repository.load(&key()).unwrap().unwrap();
        assert_eq!(after.version, before.version);
        assert_eq!(after.aggregate.state(), before.aggregate.state());
        assert_eq!(repository.outbox(), outbox);
    }
}
