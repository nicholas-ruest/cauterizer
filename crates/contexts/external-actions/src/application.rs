//! Delivery orchestration and replaceable persistence/provider ports.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::domain::{
    DeliveryStatus, ExternalActionDelivery, ExternalActionDeliveryId, ExternalActionError,
    ExternalActionGrant, ExternalActionGrantId, ExternalActionRequest, is_safe_external_reference,
};
use cauterizer_syntax::identifiers::{IdempotencyKey, OrganizationId};

/// Durable grant lookup.
pub trait GrantRepository {
    /// Finds an organization-bound grant by identity.
    ///
    /// # Errors
    /// Returns a sanitized persistence failure.
    fn find(
        &self,
        organization_id: &OrganizationId,
        id: &ExternalActionGrantId,
    ) -> Result<Option<ExternalActionGrant>, ExternalActionError>;
}

/// Durable delivery store. Implementations must enforce uniqueness of
/// `(organization, idempotency key)` and compare the complete request on replay.
pub trait DeliveryRepository {
    /// Finds a delivery by its organization-scoped replay identity.
    ///
    /// # Errors
    /// Returns a sanitized persistence failure.
    fn get_by_key(
        &self,
        organization_id: &OrganizationId,
        key: &IdempotencyKey,
    ) -> Result<Option<ExternalActionDelivery>, ExternalActionError>;
    /// Inserts a new delivery while enforcing idempotency uniqueness.
    ///
    /// # Errors
    /// Returns a persistence or idempotency-conflict error.
    fn insert(&self, delivery: ExternalActionDelivery) -> Result<(), ExternalActionError>;
    /// Persists a delivery lifecycle transition.
    ///
    /// # Errors
    /// Returns a sanitized persistence failure.
    fn update(&self, delivery: ExternalActionDelivery) -> Result<(), ExternalActionError>;
}

/// Global emergency stop, evaluated immediately before every remote mutation.
pub trait ExternalActionKillSwitch {
    /// Returns whether all remote mutations must stop.
    ///
    /// # Errors
    /// Returns a sanitized state-provider failure.
    fn engaged(&self) -> Result<bool, ExternalActionError>;
}

/// Sanitized provider receipt.
#[derive(Clone, Eq, PartialEq)]
pub struct RemoteReceipt {
    /// Opaque provider identity used for follow-up updates and comments.
    pub remote_id: String,
    /// Sanitized human-facing provider URL.
    pub remote_url: String,
}

impl std::fmt::Debug for RemoteReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RemoteReceipt { remote_id: [REDACTED], remote_url: [REDACTED] }")
    }
}

impl RemoteReceipt {
    fn is_safe(&self) -> bool {
        is_safe_external_reference(&self.remote_id) && is_safe_external_reference(&self.remote_url)
    }
}

/// Provider result deliberately excludes raw response text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteError {
    /// The mutation may or may not have succeeded.
    UnavailableOrAmbiguous,
    /// The provider conclusively rejected the mutation.
    Rejected,
}

/// SCM port supporting lookup by the same idempotency identity used to mutate.
pub trait RemoteActionGateway {
    /// Reconciles an ambiguous delivery using its stable replay identity.
    ///
    /// # Errors
    /// Returns a sanitized provider failure.
    fn find_existing(
        &self,
        request: &ExternalActionRequest,
        installation_ref: &str,
    ) -> Result<Option<RemoteReceipt>, RemoteError>;
    /// Attempts the requested provider mutation.
    ///
    /// # Errors
    /// Returns a sanitized rejected or ambiguous provider result.
    fn deliver(
        &self,
        request: &ExternalActionRequest,
        installation_ref: &str,
    ) -> Result<RemoteReceipt, RemoteError>;
}

/// Fail-closed application service.
pub struct ExternalActionService<G, D, K, R> {
    grants: G,
    deliveries: D,
    kill_switch: K,
    remote: R,
}

impl<G: GrantRepository, D: DeliveryRepository, K: ExternalActionKillSwitch, R: RemoteActionGateway>
    ExternalActionService<G, D, K, R>
{
    #[must_use]
    /// Creates a fail-closed service from its ports.
    pub const fn new(grants: G, deliveries: D, kill_switch: K, remote: R) -> Self {
        Self {
            grants,
            deliveries,
            kill_switch,
            remote,
        }
    }

    /// Delivers once. Replays return the recorded receipt; ambiguous attempts are
    /// reconciled remotely before any second mutation.
    ///
    /// # Errors
    /// Returns a validation, authorization, persistence, kill-switch, or sanitized provider error.
    pub fn execute(
        &self,
        id: ExternalActionDeliveryId,
        request: ExternalActionRequest,
    ) -> Result<ExternalActionDelivery, ExternalActionError> {
        request.validate()?;
        if !request.capability.is_permitted() {
            return Err(ExternalActionError::ProhibitedCapability);
        }
        if let Some(existing) = self
            .deliveries
            .get_by_key(&request.organization_id, &request.idempotency_key)?
        {
            if existing.request != request {
                return Err(ExternalActionError::IdempotencyConflict);
            }
            return match existing.status {
                DeliveryStatus::Pending | DeliveryStatus::Unknown => self.resume(existing),
                DeliveryStatus::ReconciliationExhausted => {
                    Err(ExternalActionError::RemoteUnavailable)
                }
                _ => Ok(existing),
            };
        }
        let organization_id = request.organization_id.clone();
        let idempotency_key = request.idempotency_key.clone();
        let delivery = ExternalActionDelivery::pending(id, request)?;
        self.deliveries.insert(delivery)?;
        let canonical = self
            .deliveries
            .get_by_key(&organization_id, &idempotency_key)?
            .ok_or(ExternalActionError::NotFound)?;
        self.resume(canonical)
    }

    fn resume(
        &self,
        mut delivery: ExternalActionDelivery,
    ) -> Result<ExternalActionDelivery, ExternalActionError> {
        if self.kill_switch.engaged()? {
            return Err(ExternalActionError::KillSwitchEngaged);
        }
        let grant = self
            .grants
            .find(
                &delivery.request.organization_id,
                &delivery.request.grant_id,
            )?
            .ok_or(ExternalActionError::NotAuthorized)?;
        grant.authorizes_request(&delivery.request)?;
        if matches!(delivery.status, DeliveryStatus::Unknown) {
            match self
                .remote
                .find_existing(&delivery.request, &grant.installation_ref)
            {
                Ok(Some(receipt)) => {
                    if !receipt.is_safe() {
                        return Err(ExternalActionError::RemoteUnavailable);
                    }
                    delivery.status = DeliveryStatus::Succeeded {
                        remote_id: receipt.remote_id,
                        remote_url: receipt.remote_url,
                    };
                    self.deliveries.update(delivery.clone())?;
                    return Ok(delivery);
                }
                Err(_) | Ok(None) => return Err(ExternalActionError::RemoteUnavailable),
            }
        }
        if self.kill_switch.engaged()? {
            return Err(ExternalActionError::KillSwitchEngaged);
        }
        delivery.attempts = delivery.attempts.saturating_add(1);
        match self
            .remote
            .deliver(&delivery.request, &grant.installation_ref)
        {
            Ok(receipt) => {
                if !receipt.is_safe() {
                    delivery.status = DeliveryStatus::Unknown;
                    self.deliveries.update(delivery)?;
                    return Err(ExternalActionError::RemoteUnavailable);
                }
                delivery.status = DeliveryStatus::Succeeded {
                    remote_id: receipt.remote_id,
                    remote_url: receipt.remote_url,
                }
            }
            Err(RemoteError::Rejected) => {
                delivery.status = DeliveryStatus::Rejected {
                    reason_code: "provider_rejected".into(),
                }
            }
            Err(RemoteError::UnavailableOrAmbiguous) => delivery.status = DeliveryStatus::Unknown,
        }
        self.deliveries.update(delivery.clone())?;
        match delivery.status {
            DeliveryStatus::Unknown | DeliveryStatus::ReconciliationExhausted => {
                Err(ExternalActionError::RemoteUnavailable)
            }
            DeliveryStatus::Rejected { .. } => Err(ExternalActionError::RemoteRejected),
            _ => Ok(delivery),
        }
    }
}

#[derive(Clone, Default)]
/// Thread-safe in-memory grant repository for tests and local development.
pub struct InMemoryGrantRepository(
    Arc<Mutex<BTreeMap<(OrganizationId, ExternalActionGrantId), ExternalActionGrant>>>,
);
impl InMemoryGrantRepository {
    /// Adds or replaces a grant by organization and identity.
    ///
    /// # Panics
    /// Panics if another thread poisoned the in-memory lock.
    pub fn put(&self, grant: ExternalActionGrant) {
        self.0
            .lock()
            .expect("grant lock")
            .insert((grant.organization_id.clone(), grant.id.clone()), grant);
    }
}
impl GrantRepository for InMemoryGrantRepository {
    fn find(
        &self,
        organization_id: &OrganizationId,
        id: &ExternalActionGrantId,
    ) -> Result<Option<ExternalActionGrant>, ExternalActionError> {
        Ok(self
            .0
            .lock()
            .map_err(|_| ExternalActionError::RemoteUnavailable)?
            .get(&(organization_id.clone(), id.clone()))
            .cloned())
    }
}

#[derive(Clone, Default)]
/// Thread-safe in-memory delivery repository.
pub struct InMemoryDeliveryRepository(
    Arc<Mutex<BTreeMap<(OrganizationId, String), ExternalActionDelivery>>>,
);
impl DeliveryRepository for InMemoryDeliveryRepository {
    fn get_by_key(
        &self,
        organization_id: &OrganizationId,
        key: &IdempotencyKey,
    ) -> Result<Option<ExternalActionDelivery>, ExternalActionError> {
        Ok(self
            .0
            .lock()
            .map_err(|_| ExternalActionError::RemoteUnavailable)?
            .get(&(organization_id.clone(), key.as_str().to_owned()))
            .cloned())
    }
    fn insert(&self, delivery: ExternalActionDelivery) -> Result<(), ExternalActionError> {
        let key = (
            delivery.request.organization_id.clone(),
            delivery.request.idempotency_key.as_str().to_owned(),
        );
        let mut records = self
            .0
            .lock()
            .map_err(|_| ExternalActionError::RemoteUnavailable)?;
        if let Some(existing) = records.get(&key) {
            return if existing.request == delivery.request {
                Ok(())
            } else {
                Err(ExternalActionError::IdempotencyConflict)
            };
        }
        records.insert(key, delivery);
        Ok(())
    }
    fn update(&self, delivery: ExternalActionDelivery) -> Result<(), ExternalActionError> {
        let key = (
            delivery.request.organization_id.clone(),
            delivery.request.idempotency_key.as_str().to_owned(),
        );
        let mut records = self
            .0
            .lock()
            .map_err(|_| ExternalActionError::RemoteUnavailable)?;
        let current = records.get(&key).ok_or(ExternalActionError::NotFound)?;
        let terminal = matches!(
            current.status,
            DeliveryStatus::Succeeded { .. }
                | DeliveryStatus::Rejected { .. }
                | DeliveryStatus::ReconciliationExhausted
        );
        if current.id != delivery.id
            || current.request != delivery.request
            || delivery.attempts < current.attempts
            || (terminal && current.status != delivery.status)
        {
            return Err(ExternalActionError::IdempotencyConflict);
        }
        records.insert(key, delivery);
        Ok(())
    }
}

#[derive(Clone)]
/// Thread-safe mutable emergency stop for tests and local development.
pub struct InMemoryKillSwitch(Arc<Mutex<bool>>);
impl Default for InMemoryKillSwitch {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(true)))
    }
}
impl InMemoryKillSwitch {
    /// Changes the emergency-stop state.
    ///
    /// # Panics
    /// Panics if another thread poisoned the in-memory lock.
    pub fn set(&self, engaged: bool) {
        *self.0.lock().expect("kill switch lock") = engaged;
    }
}
impl ExternalActionKillSwitch for InMemoryKillSwitch {
    fn engaged(&self) -> Result<bool, ExternalActionError> {
        self.0
            .lock()
            .map(|value| *value)
            .map_err(|_| ExternalActionError::KillSwitchEngaged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{ActionCapability, ExternalActionGrantId};
    use crate::domain::{DeliveryAttestation, GrantConstraints};
    use cauterizer_syntax::digest::Sha256Digest;
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone, Default)]
    struct Remote {
        calls: Arc<AtomicUsize>,
        existing: Arc<Mutex<Option<RemoteReceipt>>>,
        ambiguous: Arc<Mutex<bool>>,
    }
    impl RemoteActionGateway for Remote {
        fn find_existing(
            &self,
            _: &ExternalActionRequest,
            _: &str,
        ) -> Result<Option<RemoteReceipt>, RemoteError> {
            Ok(self.existing.lock().unwrap().clone())
        }
        fn deliver(
            &self,
            _: &ExternalActionRequest,
            _: &str,
        ) -> Result<RemoteReceipt, RemoteError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if *self.ambiguous.lock().unwrap() {
                Err(RemoteError::UnavailableOrAmbiguous)
            } else {
                Ok(RemoteReceipt {
                    remote_id: "42".into(),
                    remote_url: "https://scm.invalid/pr/42".into(),
                })
            }
        }
    }
    fn org() -> OrganizationId {
        OrganizationId::new("organization1").unwrap()
    }
    fn setup() -> (
        InMemoryGrantRepository,
        InMemoryDeliveryRepository,
        InMemoryKillSwitch,
        Remote,
        ExternalActionRequest,
    ) {
        let grants = InMemoryGrantRepository::default();
        let grant_id = ExternalActionGrantId::new("grant0001").unwrap();
        grants.put(
            ExternalActionGrant::new(
                grant_id.clone(),
                org(),
                "installation-1",
                "owner/repo",
                "cauterizer/",
                BTreeSet::from([ActionCapability::OpenPullRequest]),
            )
            .unwrap()
            .with_constraints(GrantConstraints::new(100, 10, 2, 1_000, 10, 100).unwrap()),
        );
        let request = ExternalActionRequest {
            organization_id: org(),
            grant_id,
            repository: "owner/repo".into(),
            capability: ActionCapability::OpenPullRequest,
            idempotency_key: IdempotencyKey::new("run-1-pr").unwrap(),
            correlation_key: "run-1-pr".into(),
            subject: "Security fix".into(),
            redacted_body: "Verified remediation evidence sha256:abc".into(),
            policy_attestation: Some(DeliveryAttestation {
                candidate_digest: Sha256Digest::of_bytes("candidate"),
                policy_result_digest: Sha256Digest::of_bytes("policy"),
                policy_approved: true,
                patch_bytes: 1,
                changed_lines: 1,
                attempts: 1,
                elapsed_millis: 1,
                compute_units: 1,
                spend_micros: 1,
            }),
        };
        let kill_switch = InMemoryKillSwitch::default();
        kill_switch.set(false);
        (
            grants,
            InMemoryDeliveryRepository::default(),
            kill_switch,
            Remote::default(),
            request,
        )
    }
    #[test]
    fn replay_does_not_repeat_remote_mutation() {
        let (grants, deliveries, kill_switch, remote, request) = setup();
        let service = ExternalActionService::new(grants, deliveries, kill_switch, remote.clone());
        let first = service
            .execute(
                ExternalActionDeliveryId::new("delivery01").unwrap(),
                request.clone(),
            )
            .unwrap();
        let second = service
            .execute(
                ExternalActionDeliveryId::new("delivery02").unwrap(),
                request,
            )
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(remote.calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn kill_switch_prevents_remote_call() {
        let (grants, deliveries, kill_switch, remote, request) = setup();
        kill_switch.set(true);
        let service = ExternalActionService::new(grants, deliveries, kill_switch, remote.clone());
        assert_eq!(
            service.execute(
                ExternalActionDeliveryId::new("delivery01").unwrap(),
                request
            ),
            Err(ExternalActionError::KillSwitchEngaged)
        );
        assert_eq!(remote.calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn ambiguous_delivery_is_reconciled_before_retry() {
        let (grants, deliveries, kill_switch, remote, request) = setup();
        *remote.ambiguous.lock().unwrap() = true;
        let service = ExternalActionService::new(grants, deliveries, kill_switch, remote.clone());
        assert_eq!(
            service.execute(
                ExternalActionDeliveryId::new("delivery01").unwrap(),
                request.clone()
            ),
            Err(ExternalActionError::RemoteUnavailable)
        );
        *remote.ambiguous.lock().unwrap() = false;
        *remote.existing.lock().unwrap() = Some(RemoteReceipt {
            remote_id: "42".into(),
            remote_url: "https://scm.invalid/pr/42".into(),
        });
        assert!(matches!(
            service
                .execute(
                    ExternalActionDeliveryId::new("delivery02").unwrap(),
                    request
                )
                .unwrap()
                .status,
            DeliveryStatus::Succeeded { .. }
        ));
        assert_eq!(remote.calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn unknown_with_no_remote_match_never_redelivers_immediately() {
        let (grants, deliveries, kill_switch, remote, request) = setup();
        *remote.ambiguous.lock().unwrap() = true;
        let service = ExternalActionService::new(grants, deliveries, kill_switch, remote.clone());
        assert_eq!(
            service.execute(
                ExternalActionDeliveryId::new("delivery03").unwrap(),
                request.clone()
            ),
            Err(ExternalActionError::RemoteUnavailable)
        );
        *remote.ambiguous.lock().unwrap() = false;
        assert_eq!(
            service.execute(
                ExternalActionDeliveryId::new("delivery04").unwrap(),
                request
            ),
            Err(ExternalActionError::RemoteUnavailable)
        );
        assert_eq!(remote.calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn same_key_with_different_request_conflicts() {
        let (grants, deliveries, kill_switch, remote, request) = setup();
        let service = ExternalActionService::new(grants, deliveries, kill_switch, remote);
        service
            .execute(
                ExternalActionDeliveryId::new("delivery01").unwrap(),
                request.clone(),
            )
            .unwrap();
        let mut changed = request;
        changed.subject = "different".into();
        assert_eq!(
            service.execute(
                ExternalActionDeliveryId::new("delivery02").unwrap(),
                changed
            ),
            Err(ExternalActionError::IdempotencyConflict)
        );
    }

    #[test]
    fn concurrent_exact_inserts_converge_on_one_identity() {
        let (_, deliveries, _, _, request) = setup();
        let mut workers = Vec::new();
        for index in 0..16 {
            let repository = deliveries.clone();
            let candidate = ExternalActionDelivery::pending(
                ExternalActionDeliveryId::new(&format!("concurrent{index:02}")).unwrap(),
                request.clone(),
            )
            .unwrap();
            workers.push(std::thread::spawn(move || repository.insert(candidate)));
        }
        for worker in workers {
            worker.join().unwrap().unwrap();
        }
        let canonical = deliveries
            .get_by_key(&request.organization_id, &request.idempotency_key)
            .unwrap()
            .unwrap();
        assert_eq!(canonical.request, request);
    }

    #[test]
    fn terminal_delivery_cannot_be_regressed_or_substituted() {
        let (_, deliveries, _, _, request) = setup();
        let mut terminal = ExternalActionDelivery::pending(
            ExternalActionDeliveryId::new("terminal01").unwrap(),
            request,
        )
        .unwrap();
        deliveries.insert(terminal.clone()).unwrap();
        terminal.status = DeliveryStatus::Succeeded {
            remote_id: "42".into(),
            remote_url: "https://scm.invalid/pr/42".into(),
        };
        terminal.attempts = 1;
        deliveries.update(terminal.clone()).unwrap();
        let mut regression = terminal;
        regression.status = DeliveryStatus::Unknown;
        assert_eq!(
            deliveries.update(regression),
            Err(ExternalActionError::IdempotencyConflict)
        );
    }

    #[test]
    fn typed_receipt_equality_and_debug_are_safe() {
        let receipt = RemoteReceipt {
            remote_id: "provider-42".into(),
            remote_url: "https://scm.invalid/pr/42".into(),
        };
        assert_eq!(receipt, receipt.clone());
        let debug = format!("{receipt:?}");
        assert!(!debug.contains("provider-42"));
        assert!(!debug.contains("scm.invalid"));
        assert!(receipt.is_safe());
    }
}
