//! Transactional in-memory metadata persistence for tests and local operation.
//!
//! The adapter is deliberately ignorant of aggregate and event semantics. It
//! models the atomicity contract shared by context-owned repositories: one
//! optimistic aggregate write, append-only domain events, transactional outbox
//! records, and an idempotency result become visible together or not at all.

use cauterizer_syntax::authorization::ActionName;
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{ContextQualifiedId, IdempotencyKey, OrganizationId};
use std::collections::BTreeMap;
use std::fmt;

/// Tenant-qualified aggregate storage key.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AggregateKey {
    /// Immutable tenant partition.
    pub tenant: OrganizationId,
    /// Context-owned aggregate identifier.
    pub aggregate: ContextQualifiedId,
}

/// Tenant- and command-scope-qualified replay key.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReplayKey {
    /// Immutable tenant partition.
    pub tenant: OrganizationId,
    /// Application-defined command scope.
    pub scope: ActionName,
    /// Idempotency-key spelling validated by the application boundary.
    pub key: IdempotencyKey,
}

/// Persisted optimistic aggregate snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Versioned<S> {
    /// Opaque context-owned state.
    pub state: S,
    /// Monotonically increasing repository version.
    pub version: u64,
}

/// Persisted idempotent result and the canonical request digest that owns it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredResult<R> {
    /// Canonical digest of the complete command input.
    pub request_digest: Sha256Digest,
    /// Stable result returned by exact retries.
    pub result: R,
}

/// One atomic metadata mutation.
pub struct Transaction<S, E, O, R> {
    /// Aggregate partition and identity.
    pub aggregate_key: AggregateKey,
    /// `None` creates only; `Some(n)` updates only version `n`.
    pub expected_version: Option<u64>,
    /// Replacement aggregate state after domain invariants passed.
    pub state: S,
    /// Immutable domain events appended to this aggregate's history.
    pub events: Vec<E>,
    /// Outgoing records made relay-visible with the aggregate change.
    pub outbox: Vec<O>,
    /// Replay key atomically bound to the command result.
    pub replay_key: ReplayKey,
    /// Canonical complete-command digest.
    pub request_digest: Sha256Digest,
    /// Stable command result.
    pub result: R,
}

/// Successful first execution or exact replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransactionOutcome<R> {
    /// A new transaction committed at this aggregate version.
    Committed {
        /// Newly persisted aggregate version.
        version: u64,
        /// Stable command result atomically bound to the replay key.
        result: R,
    },
    /// No write occurred; the prior exact result was returned.
    Replayed(R),
}

/// Failures which always leave every collection unchanged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransactionError {
    /// Aggregate optimistic version did not match.
    VersionConflict {
        /// Version requested by the caller.
        expected: Option<u64>,
        /// Current stored version, or `None` when absent.
        actual: Option<u64>,
    },
    /// A replay key already owns different canonical input.
    IdempotencyConflict,
    /// Replay and aggregate tenant partitions differed.
    TenantMismatch,
    /// Aggregate version could not advance.
    VersionExhausted,
}

impl fmt::Display for TransactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::VersionConflict { .. } => "optimistic version conflict",
            Self::IdempotencyConflict => "idempotency key conflicts with prior input",
            Self::TenantMismatch => "transaction tenant mismatch",
            Self::VersionExhausted => "aggregate version exhausted",
        })
    }
}

impl std::error::Error for TransactionError {}

/// Deterministic transactional metadata store.
#[derive(Clone, Debug)]
pub struct InMemoryTransactionalStore<S, E, O, R> {
    aggregates: BTreeMap<AggregateKey, Versioned<S>>,
    events: BTreeMap<AggregateKey, Vec<E>>,
    outbox: Vec<O>,
    results: BTreeMap<ReplayKey, StoredResult<R>>,
}

impl<S, E, O, R> Default for InMemoryTransactionalStore<S, E, O, R> {
    fn default() -> Self {
        Self {
            aggregates: BTreeMap::new(),
            events: BTreeMap::new(),
            outbox: Vec::new(),
            results: BTreeMap::new(),
        }
    }
}

impl<S: Clone, E: Clone, O: Clone, R: Clone + Eq> InMemoryTransactionalStore<S, E, O, R> {
    /// Executes a transaction or returns the result of an exact prior command.
    ///
    /// Validation occurs before mutation. A staged clone is swapped into place
    /// only after every write succeeds, providing deterministic rollback for
    /// this local adapter.
    ///
    /// # Errors
    ///
    /// Returns a tenant mismatch, optimistic-version conflict, replay-key
    /// conflict, or version-exhaustion error without changing any collection.
    pub fn execute(
        &mut self,
        transaction: Transaction<S, E, O, R>,
    ) -> Result<TransactionOutcome<R>, TransactionError> {
        if transaction.aggregate_key.tenant != transaction.replay_key.tenant {
            return Err(TransactionError::TenantMismatch);
        }
        if let Some(stored) = self.results.get(&transaction.replay_key) {
            return if stored.request_digest == transaction.request_digest {
                Ok(TransactionOutcome::Replayed(stored.result.clone()))
            } else {
                Err(TransactionError::IdempotencyConflict)
            };
        }

        let actual = self
            .aggregates
            .get(&transaction.aggregate_key)
            .map(|stored| stored.version);
        if actual != transaction.expected_version {
            return Err(TransactionError::VersionConflict {
                expected: transaction.expected_version,
                actual,
            });
        }
        let version = actual
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(TransactionError::VersionExhausted)?;

        let mut staged = self.clone();
        staged.aggregates.insert(
            transaction.aggregate_key.clone(),
            Versioned {
                state: transaction.state,
                version,
            },
        );
        staged
            .events
            .entry(transaction.aggregate_key)
            .or_default()
            .extend(transaction.events);
        staged.outbox.extend(transaction.outbox);
        staged.results.insert(
            transaction.replay_key,
            StoredResult {
                request_digest: transaction.request_digest,
                result: transaction.result.clone(),
            },
        );
        *self = staged;
        Ok(TransactionOutcome::Committed {
            version,
            result: transaction.result,
        })
    }

    /// Loads one tenant-qualified aggregate snapshot.
    #[must_use]
    pub fn aggregate(&self, key: &AggregateKey) -> Option<&Versioned<S>> {
        self.aggregates.get(key)
    }

    /// Returns the immutable event history for one aggregate.
    #[must_use]
    pub fn events(&self, key: &AggregateKey) -> &[E] {
        self.events.get(key).map_or(&[], Vec::as_slice)
    }

    /// Returns relay-visible outbox records in commit order.
    #[must_use]
    pub fn outbox(&self) -> &[O] {
        &self.outbox
    }

    /// Loads a tenant- and scope-qualified replay result.
    #[must_use]
    pub fn result(&self, key: &ReplayKey) -> Option<&StoredResult<R>> {
        self.results.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aggregate(tenant: &str) -> AggregateKey {
        AggregateKey {
            tenant: OrganizationId::new(tenant).unwrap(),
            aggregate: ContextQualifiedId::new("run", "00000001").unwrap(),
        }
    }
    fn replay(tenant: &str, key: &str) -> ReplayKey {
        ReplayKey {
            tenant: OrganizationId::new(tenant).unwrap(),
            scope: ActionName::parse("runs.create").unwrap(),
            key: IdempotencyKey::new(key).unwrap(),
        }
    }
    fn transaction(
        expected_version: Option<u64>,
        digest: &str,
    ) -> Transaction<String, String, String, u64> {
        Transaction {
            aggregate_key: aggregate("aaaaaaaa"),
            expected_version,
            state: digest.into(),
            events: vec![format!("event-{digest}")],
            outbox: vec![format!("outbox-{digest}")],
            replay_key: replay("aaaaaaaa", digest),
            request_digest: Sha256Digest::of_bytes(digest),
            result: 7,
        }
    }

    #[test]
    fn commits_state_events_outbox_and_result_atomically() {
        let mut store = InMemoryTransactionalStore::default();
        assert_eq!(
            store.execute(transaction(None, "a")).unwrap(),
            TransactionOutcome::Committed {
                version: 1,
                result: 7
            }
        );
        assert_eq!(
            store.aggregate(&aggregate("aaaaaaaa")).unwrap(),
            &Versioned {
                state: "a".into(),
                version: 1
            }
        );
        assert_eq!(store.events(&aggregate("aaaaaaaa")), ["event-a"]);
        assert_eq!(store.outbox(), ["outbox-a"]);
        assert_eq!(store.result(&replay("aaaaaaaa", "a")).unwrap().result, 7);
    }

    #[test]
    fn version_conflict_rolls_back_every_collection() {
        let mut store = InMemoryTransactionalStore::default();
        store.execute(transaction(None, "a")).unwrap();
        let before = store.clone();
        let error = store.execute(transaction(None, "b")).unwrap_err();
        assert_eq!(
            error,
            TransactionError::VersionConflict {
                expected: None,
                actual: Some(1)
            }
        );
        assert_eq!(store.aggregates, before.aggregates);
        assert_eq!(store.events, before.events);
        assert_eq!(store.outbox, before.outbox);
        assert_eq!(store.results, before.results);
    }

    #[test]
    fn exact_retry_replays_and_conflicting_key_rolls_back() {
        let mut store = InMemoryTransactionalStore::default();
        let mut first = transaction(None, "same");
        first.replay_key = replay("aaaaaaaa", "key");
        store.execute(first).unwrap();
        let mut retry = transaction(Some(99), "same");
        retry.replay_key = replay("aaaaaaaa", "key");
        assert_eq!(
            store.execute(retry).unwrap(),
            TransactionOutcome::Replayed(7)
        );
        let before = store.clone();
        let mut conflict = transaction(Some(1), "different");
        conflict.replay_key = replay("aaaaaaaa", "key");
        assert_eq!(
            store.execute(conflict),
            Err(TransactionError::IdempotencyConflict)
        );
        assert_eq!(store.aggregates, before.aggregates);
        assert_eq!(store.events, before.events);
        assert_eq!(store.outbox, before.outbox);
    }

    #[test]
    fn tenant_mismatch_and_cross_tenant_keys_fail_closed() {
        let mut store = InMemoryTransactionalStore::default();
        let mut invalid = transaction(None, "a");
        invalid.replay_key = replay("bbbbbbbb", "key");
        assert_eq!(
            store.execute(invalid),
            Err(TransactionError::TenantMismatch)
        );
        assert!(store.aggregate(&aggregate("aaaaaaaa")).is_none());

        store.execute(transaction(None, "a")).unwrap();
        let mut other = transaction(None, "b");
        other.aggregate_key = aggregate("bbbbbbbb");
        other.replay_key = replay("bbbbbbbb", "a");
        assert!(matches!(
            store.execute(other),
            Ok(TransactionOutcome::Committed { version: 1, .. })
        ));
        assert_eq!(store.events(&aggregate("aaaaaaaa")), ["event-a"]);
        assert_eq!(store.events(&aggregate("bbbbbbbb")), ["event-b"]);
    }

    #[test]
    fn successful_updates_append_history_and_outbox_without_overwrite() {
        let mut store = InMemoryTransactionalStore::default();
        store.execute(transaction(None, "a")).unwrap();
        store.execute(transaction(Some(1), "b")).unwrap();
        assert_eq!(store.aggregate(&aggregate("aaaaaaaa")).unwrap().version, 2);
        assert_eq!(store.events(&aggregate("aaaaaaaa")), ["event-a", "event-b"]);
        assert_eq!(store.outbox(), ["outbox-a", "outbox-b"]);
    }
}
