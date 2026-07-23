//! Authorized, audited, replay-safe lease facade.
use super::ports::{
    AuditError, AuditFact, AuditOutcome, AuditSink, AuthorizationDecision, CommandControl,
    CommitOutcome, ExecutionAuthorizer, ExecutionLeaseRepository, LeaseCommit, LeaseKey,
    RepositoryError,
};
use crate::domain::{
    CleanupReceipt, ConformanceLabel, ExecutionError, ExecutionLease, ExecutionLeaseId,
    ExecutionRequest, LeaseState, TerminalReceipt, WorkerIdentity,
};
use cauterizer_syntax::authorization::AuthorizationRequestContext;
use std::fmt;
/// Application service for authoritative lease lifecycle transitions.
pub struct ExecutionService<R, Z, U> {
    repository: R,
    authorizer: Z,
    audit: U,
}
impl<R: ExecutionLeaseRepository, Z: ExecutionAuthorizer, U: AuditSink> ExecutionService<R, Z, U> {
    /// Constructs facade.
    #[must_use]
    pub const fn new(repository: R, authorizer: Z, audit: U) -> Self {
        Self {
            repository,
            authorizer,
            audit,
        }
    }
    /// Allocates an admitted immutable request.
    /// # Errors
    /// Rejects authorization, stale/reused commands, or domain admission failure.
    pub fn allocate(
        &self,
        a: &AuthorizationRequestContext,
        id: ExecutionLeaseId,
        request: ExecutionRequest,
        label: ConformanceLabel,
        control: &CommandControl,
    ) -> Result<CommitOutcome, ApplicationError> {
        self.guard(a, "executions.allocate", id.as_str())?;
        let lease = ExecutionLease::allocate(a.organization_id().clone(), id, request, label)
            .map_err(ApplicationError::Domain)?;
        let events = lease.events().to_vec();
        let result = self.repository.create(
            LeaseKey {
                tenant: a.organization_id().clone(),
                lease: a.resource().as_str().into(),
            },
            control,
            LeaseCommit {
                aggregate: lease,
                events,
            },
        )?;
        self.audit(a, "executions.allocate", AuditOutcome::Succeeded)?;
        Ok(result)
    }
    /// Starts the exact pool-bound worker.
    /// # Errors
    /// Rejects authorization, stale/reused commands, pool mixing, or invalid state.
    pub fn start(
        &self,
        a: &AuthorizationRequestContext,
        id: &ExecutionLeaseId,
        worker: WorkerIdentity,
        control: &CommandControl,
    ) -> Result<LeaseState, ApplicationError> {
        self.mutate(a, id, "executions.start", control, move |lease| {
            lease.start(worker)
        })
    }
    /// Records a monotonic worker heartbeat.
    /// # Errors
    /// Rejects authorization, stale/reused commands, foreign workers, or stale sequence.
    pub fn heartbeat(
        &self,
        a: &AuthorizationRequestContext,
        id: &ExecutionLeaseId,
        worker: &WorkerIdentity,
        sequence: u64,
        control: &CommandControl,
    ) -> Result<LeaseState, ApplicationError> {
        self.mutate(a, id, "executions.heartbeat", control, |lease| {
            lease.heartbeat(worker, sequence)
        })
    }
    /// Records an authoritative completed/timeout/cancel/worker-loss receipt.
    /// # Errors
    /// Rejects authorization, stale/reused commands, identity/digest/label mismatch, or duplicate terminal result.
    pub fn terminal(
        &self,
        a: &AuthorizationRequestContext,
        id: &ExecutionLeaseId,
        receipt: TerminalReceipt,
        control: &CommandControl,
    ) -> Result<LeaseState, ApplicationError> {
        self.mutate(a, id, "executions.terminal", control, move |lease| {
            lease.record_terminal(receipt)
        })
    }
    /// Records mandatory cleanup success or failure.
    /// # Errors
    /// Rejects authorization, stale/reused commands, missing terminal receipt, or duplicate cleanup.
    pub fn cleanup(
        &self,
        a: &AuthorizationRequestContext,
        id: &ExecutionLeaseId,
        receipt: CleanupReceipt,
        control: &CommandControl,
    ) -> Result<LeaseState, ApplicationError> {
        self.mutate(a, id, "executions.cleanup", control, move |lease| {
            lease.confirm_cleanup(receipt)
        })
    }
    fn mutate<F>(
        &self,
        a: &AuthorizationRequestContext,
        id: &ExecutionLeaseId,
        action: &str,
        control: &CommandControl,
        operation: F,
    ) -> Result<LeaseState, ApplicationError>
    where
        F: FnOnce(&mut ExecutionLease) -> Result<(), ExecutionError>,
    {
        self.guard(a, action, id.as_str())?;
        let key = LeaseKey {
            tenant: a.organization_id().clone(),
            lease: id.as_str().into(),
        };
        let mut loaded = self
            .repository
            .load(&key)?
            .ok_or(RepositoryError::NotFound)?;
        let prior = loaded.aggregate.events().len();
        if let Err(error) = operation(&mut loaded.aggregate) {
            self.audit(a, action, AuditOutcome::Failed)?;
            return Err(ApplicationError::Domain(error));
        }
        let state = loaded.aggregate.state();
        let events = loaded.aggregate.events()[prior..].to_vec();
        self.repository.commit(
            &key,
            control,
            LeaseCommit {
                aggregate: loaded.aggregate,
                events,
            },
        )?;
        self.audit(a, action, AuditOutcome::Succeeded)?;
        Ok(state)
    }
    fn guard(
        &self,
        a: &AuthorizationRequestContext,
        action: &str,
        lease: &str,
    ) -> Result<(), ApplicationError> {
        if a.action().as_str() != action
            || a.resource().as_str() != lease
            || self.authorizer.authorize(a) != AuthorizationDecision::Allow
        {
            self.audit(a, action, AuditOutcome::Denied)?;
            return Err(ApplicationError::Denied);
        }
        Ok(())
    }
    fn audit(
        &self,
        a: &AuthorizationRequestContext,
        action: &str,
        outcome: AuditOutcome,
    ) -> Result<(), ApplicationError> {
        self.audit
            .record(AuditFact {
                tenant: a.organization_id().clone(),
                action: action.into(),
                lease: a.resource().as_str().into(),
                outcome,
            })
            .map_err(Into::into)
    }
}
/// Stable application failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationError {
    /// Denied.
    Denied,
    /// Audit unavailable.
    AuditUnavailable,
    /// Persistence failure.
    Repository(RepositoryError),
    /// Domain rejection.
    Domain(ExecutionError),
}
impl From<RepositoryError> for ApplicationError {
    fn from(v: RepositoryError) -> Self {
        Self::Repository(v)
    }
}
impl From<AuditError> for ApplicationError {
    fn from(_: AuditError) -> Self {
        Self::AuditUnavailable
    }
}
impl fmt::Display for ApplicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ApplicationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::memory::InMemoryLeaseRepository;
    use crate::application::ports::ExecutionLeaseRepository;
    use crate::application::security::{InMemoryAuditSink, InMemoryAuthorizer};
    use crate::domain::*;
    use cauterizer_syntax::authorization::{ActionName, Purpose, ResourceRef};
    use cauterizer_syntax::digest::Sha256Digest;
    use cauterizer_syntax::identifiers::{
        ActorId, ContextQualifiedId, IdempotencyKey, IdentityRef, OrganizationId,
    };
    use std::collections::BTreeSet;

    fn id() -> ExecutionLeaseId {
        ExecutionLeaseId::new("00000000").unwrap()
    }
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
    fn auth(action: &str) -> AuthorizationRequestContext {
        AuthorizationRequestContext::new(
            OrganizationId::new("00000000").unwrap(),
            IdentityRef::Human(ActorId::new("00000000").unwrap()),
            ActionName::parse(action).unwrap(),
            ResourceRef::parse(id().as_str()).unwrap(),
            Purpose::parse("execution supervision").unwrap(),
        )
    }
    fn control(version: u64, key: &str) -> CommandControl {
        CommandControl {
            expected_version: version,
            idempotency_key: IdempotencyKey::new(key).unwrap(),
            request_digest: Sha256Digest::of_bytes(key),
        }
    }
    fn terminal(
        request: &ExecutionRequest,
        worker: WorkerIdentity,
        kind: TerminalKind,
    ) -> TerminalReceipt {
        TerminalReceipt {
            request_digest: request.request_digest,
            environment_digest: request.environment.image_digest,
            worker,
            kind,
            observation: ExecutionObservation {
                exit_code: Some(0),
                stdout_digest: None,
                stderr_digest: None,
                output_truncated: false,
                peak_memory_bytes: 1,
                peak_disk_bytes: 1,
                peak_process_count: 1,
            },
            conformance: ConformanceLabel::NonConformantLocal,
        }
    }

    #[test]
    fn denied_allocate_is_audited_without_state_or_outbox() {
        let repository = InMemoryLeaseRepository::default();
        let authorizer = InMemoryAuthorizer::default();
        let audit = InMemoryAuditSink::default();
        let service = ExecutionService::new(repository.clone(), authorizer, audit.clone());
        assert_eq!(
            service.allocate(
                &auth("executions.allocate"),
                id(),
                request(),
                ConformanceLabel::NonConformantLocal,
                &control(0, "deny")
            ),
            Err(ApplicationError::Denied)
        );
        let key = LeaseKey {
            tenant: OrganizationId::new("00000000").unwrap(),
            lease: id().as_str().into(),
        };
        assert!(repository.load(&key).unwrap().is_none());
        assert!(repository.outbox().is_empty());
        assert_eq!(audit.len(), 1);
    }

    #[test]
    fn typed_lifecycle_all_terminal_kinds_require_cleanup_before_closed() {
        for (index, kind) in [
            TerminalKind::Completed,
            TerminalKind::TimedOut,
            TerminalKind::Cancelled,
            TerminalKind::WorkerLost,
        ]
        .into_iter()
        .enumerate()
        {
            let repository = InMemoryLeaseRepository::default();
            let authorizer = InMemoryAuthorizer::default();
            authorizer.set_allowed(true);
            let audit = InMemoryAuditSink::default();
            let service = ExecutionService::new(repository.clone(), authorizer, audit.clone());
            let request = request();
            service
                .allocate(
                    &auth("executions.allocate"),
                    id(),
                    request.clone(),
                    ConformanceLabel::NonConformantLocal,
                    &control(0, &format!("allocate-{index}")),
                )
                .unwrap();
            let worker = WorkerIdentity {
                id: ContextQualifiedId::new("worker", "00000000").unwrap(),
                pool: JobClass::Solver,
            };
            assert_eq!(
                service
                    .start(
                        &auth("executions.start"),
                        &id(),
                        worker.clone(),
                        &control(1, &format!("start-{index}"))
                    )
                    .unwrap(),
                LeaseState::Running
            );
            assert_eq!(
                service
                    .terminal(
                        &auth("executions.terminal"),
                        &id(),
                        terminal(&request, worker, kind),
                        &control(2, &format!("terminal-{index}"))
                    )
                    .unwrap(),
                LeaseState::AwaitingCleanup(kind)
            );
            let key = LeaseKey {
                tenant: OrganizationId::new("00000000").unwrap(),
                lease: id().as_str().into(),
            };
            assert!(
                repository
                    .load(&key)
                    .unwrap()
                    .unwrap()
                    .aggregate
                    .cleanup_receipt()
                    .is_none()
            );
            assert_eq!(
                service
                    .cleanup(
                        &auth("executions.cleanup"),
                        &id(),
                        CleanupReceipt::Confirmed {
                            cleanup_digest: Sha256Digest::of_bytes(b"cleanup")
                        },
                        &control(3, &format!("cleanup-{index}"))
                    )
                    .unwrap(),
                LeaseState::Closed(kind)
            );
            assert!(
                repository
                    .load(&key)
                    .unwrap()
                    .unwrap()
                    .aggregate
                    .cleanup_receipt()
                    .is_some()
            );
            assert_eq!(audit.len(), 4);
        }
    }
}
