//! Deterministic in-memory application adapters for tests and local mode.

use super::ports::{
    AuditError, AuditSink, AuthorizationPolicyRepository, IdempotencyError, IdempotencyStore,
    IdempotentResult, OrganizationRepository, RepositoryError, SaveOrganization, Versioned,
};
use crate::contracts::AuthorizationAuditFactV1;
use crate::domain::AuthorizationPolicy;
use cauterizer_syntax::identifiers::{IdempotencyKey, OrganizationId};
use std::collections::BTreeMap;

/// In-memory policy adapter with exact tenant-key lookup and no default policy.
#[derive(Clone, Debug, Default)]
pub struct InMemoryPolicyRepository {
    policies: BTreeMap<OrganizationId, AuthorizationPolicy>,
}

impl InMemoryPolicyRepository {
    /// Installs or replaces one organization's immutable policy snapshot.
    pub fn insert(&mut self, policy: AuthorizationPolicy) {
        self.policies
            .insert(policy.organization_id().clone(), policy);
    }
}

impl AuthorizationPolicyRepository for InMemoryPolicyRepository {
    fn load_policy(&self, organization_id: &OrganizationId) -> Option<AuthorizationPolicy> {
        self.policies.get(organization_id).cloned()
    }
}

/// Append-only in-memory authorization audit adapter.
#[derive(Clone, Debug, Default)]
pub struct InMemoryAuditSink {
    facts: Vec<AuthorizationAuditFactV1>,
}

impl InMemoryAuditSink {
    /// Returns facts in decision order.
    #[must_use]
    pub fn facts(&self) -> &[AuthorizationAuditFactV1] {
        &self.facts
    }
}

impl AuditSink for InMemoryAuditSink {
    fn record(&mut self, fact: AuthorizationAuditFactV1) -> Result<(), AuditError> {
        self.facts.push(fact);
        Ok(())
    }
}

/// In-memory optimistic repository with a durable-style event outbox view.
#[derive(Clone, Debug)]
pub struct InMemoryOrganizationRepository<T: Clone> {
    states: BTreeMap<OrganizationId, Versioned<T>>,
    outbox: Vec<crate::contracts::OrganizationAccessEventV1>,
}

impl<T: Clone> Default for InMemoryOrganizationRepository<T> {
    fn default() -> Self {
        Self {
            states: BTreeMap::new(),
            outbox: Vec::new(),
        }
    }
}

impl<T: Clone> InMemoryOrganizationRepository<T> {
    /// Returns public facts in atomic save order.
    #[must_use]
    pub fn outbox(&self) -> &[crate::contracts::OrganizationAccessEventV1] {
        &self.outbox
    }
}

impl<T: Clone> OrganizationRepository for InMemoryOrganizationRepository<T> {
    type Aggregate = T;

    fn load(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Option<Versioned<T>>, RepositoryError> {
        Ok(self.states.get(organization_id).cloned())
    }

    fn save(
        &mut self,
        organization_id: &OrganizationId,
        request: SaveOrganization<T>,
    ) -> Result<u64, RepositoryError> {
        let actual = self.states.get(organization_id).map(|value| value.version);
        if actual != request.expected_version {
            return Err(RepositoryError::Conflict {
                expected: request.expected_version,
                actual,
            });
        }
        let version = actual
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(RepositoryError::CorruptState)?;
        self.states.insert(
            organization_id.clone(),
            Versioned {
                aggregate: request.aggregate,
                version,
            },
        );
        self.outbox.extend(request.events);
        Ok(version)
    }
}

/// In-memory organization-scoped idempotency store.
#[derive(Clone, Debug)]
pub struct InMemoryIdempotencyStore<T: Clone> {
    entries: BTreeMap<(OrganizationId, IdempotencyKey), IdempotentResult<T>>,
}
impl<T: Clone> Default for InMemoryIdempotencyStore<T> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }
}

impl<T: Clone + Eq> IdempotencyStore<T> for InMemoryIdempotencyStore<T> {
    fn get(
        &self,
        organization_id: &OrganizationId,
        key: &IdempotencyKey,
    ) -> Option<IdempotentResult<T>> {
        self.entries
            .get(&(organization_id.clone(), key.clone()))
            .cloned()
    }
    fn put(
        &mut self,
        organization_id: OrganizationId,
        key: IdempotencyKey,
        value: IdempotentResult<T>,
    ) -> Result<(), IdempotencyError> {
        match self.entries.get(&(organization_id.clone(), key.clone())) {
            Some(existing) if existing != &value => Err(IdempotencyError::ConflictingRequest),
            Some(_) => Ok(()),
            None => {
                self.entries.insert((organization_id, key), value);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::ports::SaveOrganization;
    use cauterizer_syntax::digest::Sha256Digest;

    fn organization() -> OrganizationId {
        OrganizationId::new("00000000").unwrap()
    }

    #[test]
    fn repository_enforces_create_and_update_versions() {
        let id = organization();
        let mut repository = InMemoryOrganizationRepository::<String>::default();
        assert_eq!(
            repository
                .save(
                    &id,
                    SaveOrganization {
                        aggregate: "one".into(),
                        expected_version: None,
                        events: vec![]
                    }
                )
                .unwrap(),
            1
        );
        assert_eq!(
            repository
                .save(
                    &id,
                    SaveOrganization {
                        aggregate: "two".into(),
                        expected_version: Some(1),
                        events: vec![]
                    }
                )
                .unwrap(),
            2
        );
        assert!(matches!(
            repository.save(
                &id,
                SaveOrganization {
                    aggregate: "stale".into(),
                    expected_version: Some(1),
                    events: vec![]
                }
            ),
            Err(RepositoryError::Conflict {
                actual: Some(2),
                ..
            })
        ));
        assert_eq!(repository.load(&id).unwrap().unwrap().aggregate, "two");
    }

    #[test]
    fn idempotency_is_tenant_scoped_and_conflicts_on_changed_input() {
        let id = organization();
        let key = IdempotencyKey::new("request-0001").unwrap();
        let mut store = InMemoryIdempotencyStore::default();
        store
            .put(
                id.clone(),
                key.clone(),
                IdempotentResult {
                    request_digest: Sha256Digest::of_bytes("a"),
                    result: 1_u8,
                },
            )
            .unwrap();
        assert_eq!(store.get(&id, &key).unwrap().result, 1);
        assert_eq!(
            store.put(
                id,
                key,
                IdempotentResult {
                    request_digest: Sha256Digest::of_bytes("b"),
                    result: 2
                }
            ),
            Err(IdempotencyError::ConflictingRequest)
        );
    }
}
