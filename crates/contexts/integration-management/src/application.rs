//! Application-owned SCM connector port and deterministic fake adapter.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::IdempotencyKey;

use crate::contracts::{
    DeliveryDisposition, DeliveryReceipt, DeliveryRequest, RemoteObject, ScmMutation,
};
use crate::domain::{CapabilityManifest, InstallationGrant, PolicyError};

/// Provider-neutral SCM connector. It exposes no merge/release/deploy methods.
pub trait ScmConnector {
    /// Returns the connector's immutable safe-capability declaration.
    fn manifest(&self) -> &CapabilityManifest;
    /// Applies desired state exactly once, reconciling ambiguous prior delivery.
    ///
    /// # Errors
    /// Rejects invalid or unauthorized requests, replay substitution and
    /// conflicting remote state; also reports provider unavailability.
    fn deliver(
        &self,
        grant: &InstallationGrant,
        request: DeliveryRequest,
        now_unix: u64,
    ) -> Result<DeliveryReceipt, ConnectorError>;
    /// Finds a previously created object by stable logical identity.
    ///
    /// # Errors
    /// Reports provider unavailability.
    fn reconcile(
        &self,
        grant: &InstallationGrant,
        request: &DeliveryRequest,
        now_unix: u64,
    ) -> Result<Option<RemoteObject>, ConnectorError>;
}

#[derive(Clone)]
struct Recorded {
    request_digest: Sha256Digest,
    object: RemoteObject,
}

#[derive(Default)]
struct FakeState {
    next_id: u64,
    attempts: BTreeMap<(String, IdempotencyKey), Recorded>,
    objects: BTreeMap<(String, String, String), RemoteObject>,
}

/// Lock-backed reference connector used by contract and orchestration tests.
#[derive(Clone)]
pub struct FakeScmConnector {
    manifest: CapabilityManifest,
    state: Arc<Mutex<FakeState>>,
}

impl FakeScmConnector {
    /// Creates an empty deterministic connector for the supplied manifest.
    #[must_use]
    pub fn new(manifest: CapabilityManifest) -> Self {
        Self {
            manifest,
            state: Arc::new(Mutex::new(FakeState::default())),
        }
    }
}

impl ScmConnector for FakeScmConnector {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn deliver(
        &self,
        grant: &InstallationGrant,
        request: DeliveryRequest,
        now_unix: u64,
    ) -> Result<DeliveryReceipt, ConnectorError> {
        if request.installation_id != grant.installation_id.as_str() {
            return Err(ConnectorError::Denied);
        }
        if request.organization_id != grant.organization_id {
            return Err(ConnectorError::Denied);
        }
        grant.validate(&self.manifest)?;
        grant.authorize(
            &request.repository,
            request.mutation.branch(),
            request.mutation.capability(),
            now_unix,
        )?;
        if let ScmMutation::CreatePullRequest { base_branch, .. } = &request.mutation {
            grant.authorize_target_branch(base_branch)?;
        }
        if request.correlation_key.trim().is_empty() {
            return Err(ConnectorError::InvalidRequest);
        }
        let mut state = self.state.lock().map_err(|_| ConnectorError::Unavailable)?;
        let attempt_key = (
            request.installation_id.clone(),
            request.idempotency_key.clone(),
        );
        if let Some(recorded) = state.attempts.get(&attempt_key) {
            return if recorded.request_digest == request.request_digest {
                Ok(DeliveryReceipt {
                    disposition: DeliveryDisposition::Replayed,
                    object: recorded.object.clone(),
                })
            } else {
                Err(ConnectorError::IdempotencyConflict)
            };
        }
        let object_key = (
            request.installation_id.clone(),
            request.repository.clone(),
            request.correlation_key.clone(),
        );
        if let Some(object) = state.objects.get(&object_key).cloned() {
            if object.applied_digest != request.request_digest {
                return Err(ConnectorError::ReconciliationConflict);
            }
            state.attempts.insert(
                attempt_key,
                Recorded {
                    request_digest: request.request_digest,
                    object: object.clone(),
                },
            );
            return Ok(DeliveryReceipt {
                disposition: DeliveryDisposition::Reconciled,
                object,
            });
        }
        state.next_id = state
            .next_id
            .checked_add(1)
            .ok_or(ConnectorError::Unavailable)?;
        let remote_id = format!("fake-{}", state.next_id);
        let object = RemoteObject {
            url: format!(
                "https://scm.invalid/{}/objects/{remote_id}",
                request.repository
            ),
            remote_id,
            applied_digest: request.request_digest,
        };
        let disposition = if matches!(
            request.mutation,
            ScmMutation::UpdateIssue { .. }
                | ScmMutation::UpdatePullRequest { .. }
                | ScmMutation::PostEvidenceSummary { .. }
        ) {
            DeliveryDisposition::Updated
        } else {
            DeliveryDisposition::Created
        };
        state.objects.insert(object_key, object.clone());
        state.attempts.insert(
            attempt_key,
            Recorded {
                request_digest: request.request_digest,
                object: object.clone(),
            },
        );
        Ok(DeliveryReceipt {
            disposition,
            object,
        })
    }

    fn reconcile(
        &self,
        grant: &InstallationGrant,
        request: &DeliveryRequest,
        now_unix: u64,
    ) -> Result<Option<RemoteObject>, ConnectorError> {
        if request.installation_id != grant.installation_id.as_str()
            || request.organization_id != grant.organization_id
        {
            return Err(ConnectorError::Denied);
        }
        grant.authorize(
            &request.repository,
            request.mutation.branch(),
            request.mutation.capability(),
            now_unix,
        )?;
        if let ScmMutation::CreatePullRequest { base_branch, .. } = &request.mutation {
            grant.authorize_target_branch(base_branch)?;
        }
        Ok(self
            .state
            .lock()
            .map_err(|_| ConnectorError::Unavailable)?
            .objects
            .get(&(
                request.installation_id.clone(),
                request.repository.clone(),
                request.correlation_key.clone(),
            ))
            .cloned())
    }
}

/// Stable connector failure vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorError {
    /// Installation scope or capability did not authorize the operation.
    Denied,
    /// Request or grant failed structural validation.
    InvalidRequest,
    /// One retry identity was reused with a different request digest.
    IdempotencyConflict,
    /// Logical object identity exists with different desired state.
    ReconciliationConflict,
    /// Connector storage or provider is unavailable.
    Unavailable,
}

impl From<PolicyError> for ConnectorError {
    fn from(error: PolicyError) -> Self {
        match error {
            PolicyError::Denied | PolicyError::GrantExpired => Self::Denied,
            _ => Self::InvalidRequest,
        }
    }
}
impl fmt::Display for ConnectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Denied => "scm_delivery_denied",
            Self::InvalidRequest => "invalid_scm_delivery_request",
            Self::IdempotencyConflict => "scm_idempotency_conflict",
            Self::ReconciliationConflict => "scm_reconciliation_conflict",
            Self::Unavailable => "scm_connector_unavailable",
        })
    }
}
impl std::error::Error for ConnectorError {}
