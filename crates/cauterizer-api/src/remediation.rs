//! Versioned, transport-neutral remediation control handlers.

use cauterizer_remediation_runs::application::ports::{
    AuditSink, CommandControl, CommitOutcome, RemediationRunRepository, RunAuthorizer,
};
use cauterizer_remediation_runs::application::service::{ApplicationError, RemediationRunService};
use cauterizer_remediation_runs::domain::{
    RemediationRun, RemediationRunId, RunCommand, RunEvent, RunLineage, RunState,
};
use cauterizer_syntax::authorization::{
    ActionName, AuthorizationRequestContext, Purpose, ResourceRef,
};
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::envelope::ProblemDetails;
use cauterizer_syntax::identifiers::{IdempotencyKey, IdentityRef, OrganizationId};
use serde::{Deserialize, Serialize};

use crate::http::HttpResponse;

/// Version 1 request to start one remediation run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriggerRemediationRequestV1 {
    /// Authenticated tenant.
    pub organization_id: OrganizationId,
    /// Authenticated human or service identity.
    pub actor: IdentityRef,
    /// Context-owned run opaque component.
    pub run_opaque: String,
}

/// Version 1 cancellation request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelRemediationRequestV1 {
    /// Authenticated tenant.
    pub organization_id: OrganizationId,
    /// Authenticated human or service identity.
    pub actor: IdentityRef,
    /// Context-owned run opaque component.
    pub run_opaque: String,
    /// Caller-observed optimistic version.
    pub expected_version: u64,
    /// Bounded cancellation reason.
    pub reason: String,
}

/// Version 1 run control result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationStatusV1 {
    /// Canonical run identifier.
    pub run_id: String,
    /// Current state.
    pub state: RunState,
    /// Optimistic aggregate version.
    pub version: u64,
}

/// Handles an idempotent remediation trigger.
#[must_use]
pub fn handle_trigger<R, Z, U>(
    service: &RemediationRunService<R, Z, U>,
    idempotency_key: &str,
    request: &TriggerRemediationRequestV1,
) -> HttpResponse
where
    R: RemediationRunRepository<RemediationRun, RunEvent>,
    Z: RunAuthorizer,
    U: AuditSink,
{
    let Ok((run, authorization, control)) = control_parts(
        "runs.create",
        idempotency_key,
        request.organization_id.clone(),
        request.actor.clone(),
        &request.run_opaque,
        0,
        request,
    ) else {
        return problem(400, "remediation.invalid_request");
    };
    match service.create_run(
        &authorization,
        run.clone(),
        RunLineage {
            parent: None,
            supersedes: None,
        },
        &control,
    ) {
        Ok(CommitOutcome::Committed(version) | CommitOutcome::Replayed(version)) => {
            HttpResponse::ok(
                202,
                Some(format!("\"{version}\"")),
                RemediationStatusV1 {
                    run_id: run.as_str().into(),
                    state: RunState::Draft,
                    version,
                },
            )
        }
        Ok(CommitOutcome::DuplicateInbound(_)) => problem(500, "remediation.invalid_outcome"),
        Err(error) => application_problem(error),
    }
}

/// Handles exact tenant-scoped run status lookup.
#[must_use]
pub fn handle_status<R, Z, U>(
    service: &RemediationRunService<R, Z, U>,
    organization_id: OrganizationId,
    actor: IdentityRef,
    run_opaque: &str,
) -> HttpResponse
where
    R: RemediationRunRepository<RemediationRun, RunEvent>,
    Z: RunAuthorizer,
    U: AuditSink,
{
    read_like(
        service,
        "runs.read",
        organization_id,
        actor,
        run_opaque,
        false,
    )
}

/// Handles an idempotent terminal cancellation command.
#[must_use]
pub fn handle_cancel<R, Z, U>(
    service: &RemediationRunService<R, Z, U>,
    idempotency_key: &str,
    request: &CancelRemediationRequestV1,
) -> HttpResponse
where
    R: RemediationRunRepository<RemediationRun, RunEvent>,
    Z: RunAuthorizer,
    U: AuditSink,
{
    let Ok((run, authorization, control)) = control_parts(
        "runs.cancel",
        idempotency_key,
        request.organization_id.clone(),
        request.actor.clone(),
        &request.run_opaque,
        request.expected_version,
        request,
    ) else {
        return problem(400, "remediation.invalid_request");
    };
    match service.command(
        &authorization,
        &run,
        RunCommand::Cancel {
            reason: request.reason.clone(),
        },
        &control,
    ) {
        Ok(state) => HttpResponse::ok(
            200,
            None,
            RemediationStatusV1 {
                run_id: run.as_str().into(),
                state,
                version: request.expected_version.saturating_add(1),
            },
        ),
        Err(error) => application_problem(error),
    }
}

/// Authorizes a coarse reconciliation request without exposing connector authority.
#[must_use]
pub fn handle_reconcile<R, Z, U>(
    service: &RemediationRunService<R, Z, U>,
    organization_id: OrganizationId,
    actor: IdentityRef,
    run_opaque: &str,
) -> HttpResponse
where
    R: RemediationRunRepository<RemediationRun, RunEvent>,
    Z: RunAuthorizer,
    U: AuditSink,
{
    read_like(
        service,
        "runs.reconcile",
        organization_id,
        actor,
        run_opaque,
        true,
    )
}

fn read_like<R, Z, U>(
    service: &RemediationRunService<R, Z, U>,
    action: &str,
    organization_id: OrganizationId,
    actor: IdentityRef,
    run_opaque: &str,
    reconcile: bool,
) -> HttpResponse
where
    R: RemediationRunRepository<RemediationRun, RunEvent>,
    Z: RunAuthorizer,
    U: AuditSink,
{
    let Ok(run) = RemediationRunId::new(run_opaque) else {
        return problem(400, "remediation.invalid_request");
    };
    let Ok(authorization) = authorization(action, organization_id, actor, run.as_str()) else {
        return problem(400, "remediation.invalid_request");
    };
    let result = if reconcile {
        service.authorize_reconciliation(&authorization, &run)
    } else {
        service.status(&authorization, &run)
    };
    match result {
        Ok((state, version)) => HttpResponse::ok(
            if reconcile { 202 } else { 200 },
            Some(format!("\"{version}\"")),
            RemediationStatusV1 {
                run_id: run.as_str().into(),
                state,
                version,
            },
        ),
        Err(error) => application_problem(error),
    }
}

fn control_parts<T: Serialize>(
    action: &str,
    key: &str,
    organization_id: OrganizationId,
    actor: IdentityRef,
    run_opaque: &str,
    expected_version: u64,
    request: &T,
) -> Result<
    (
        RemediationRunId,
        AuthorizationRequestContext,
        CommandControl,
    ),
    (),
> {
    let run = RemediationRunId::new(run_opaque).map_err(|_| ())?;
    let authorization = authorization(action, organization_id, actor, run.as_str())?;
    let canonical = serde_jcs::to_vec(request).map_err(|_| ())?;
    Ok((
        run,
        authorization,
        CommandControl {
            expected_version,
            idempotency_key: IdempotencyKey::new(key).map_err(|_| ())?,
            request_digest: Sha256Digest::of_bytes(canonical),
        },
    ))
}

fn authorization(
    action: &str,
    organization_id: OrganizationId,
    actor: IdentityRef,
    run: &str,
) -> Result<AuthorizationRequestContext, ()> {
    Ok(AuthorizationRequestContext::new(
        organization_id,
        actor,
        ActionName::parse(action).map_err(|_| ())?,
        ResourceRef::parse(run).map_err(|_| ())?,
        Purpose::parse("remediation control").map_err(|_| ())?,
    ))
}

fn application_problem(error: ApplicationError) -> HttpResponse {
    match error {
        ApplicationError::Denied => problem(403, "remediation.denied"),
        ApplicationError::Repository(
            cauterizer_remediation_runs::application::ports::RepositoryError::NotFound,
        ) => problem(404, "remediation.not_found"),
        ApplicationError::Repository(
            cauterizer_remediation_runs::application::ports::RepositoryError::IdempotencyConflict,
        ) => problem(409, "remediation.idempotency_conflict"),
        ApplicationError::Repository(_) => problem(409, "remediation.conflict"),
        ApplicationError::Domain(_) => problem(422, "remediation.invalid_transition"),
        ApplicationError::AuditUnavailable | ApplicationError::InvalidEnvelope => {
            problem(500, "remediation.unavailable")
        }
    }
}

fn problem(status: u16, reason: &str) -> HttpResponse {
    HttpResponse::problem(
        &ProblemDetails::new(
            format!("urn:cauterizer:problem:{reason}"),
            "Remediation request failed",
            status,
            reason,
            None,
        )
        .expect("stable remediation problem"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cauterizer_remediation_runs::application::memory::{
        InMemoryAuditSink, InMemoryAuthorizer, InMemoryRunRepository,
    };
    use cauterizer_syntax::identifiers::{ActorId, ServicePrincipalId};

    type Service = RemediationRunService<
        InMemoryRunRepository<RemediationRun, RunEvent>,
        InMemoryAuthorizer,
        InMemoryAuditSink,
    >;

    fn service(allowed: bool) -> Service {
        let authorizer = InMemoryAuthorizer::default();
        authorizer.set_allowed(allowed);
        RemediationRunService::new(
            InMemoryRunRepository::default(),
            authorizer,
            InMemoryAuditSink::default(),
        )
    }

    fn trigger() -> TriggerRemediationRequestV1 {
        TriggerRemediationRequestV1 {
            organization_id: OrganizationId::new("controlorg").unwrap(),
            actor: IdentityRef::Human(ActorId::new("operator1").unwrap()),
            run_opaque: "controlrun1".into(),
        }
    }

    #[test]
    fn trigger_exact_retry_replays_and_substitution_conflicts() {
        let service = service(true);
        let first = handle_trigger(&service, "trigger-key", &trigger());
        assert_eq!(first.status, 202);
        assert_eq!(handle_trigger(&service, "trigger-key", &trigger()), first);
        let mut changed = trigger();
        changed.actor = IdentityRef::Service(ServicePrincipalId::new("service01").unwrap());
        let conflict = handle_trigger(&service, "trigger-key", &changed);
        assert_eq!(conflict.status, 409);
        assert_eq!(conflict.body["reason"], "remediation.idempotency_conflict");
    }

    #[test]
    fn status_is_tenant_scoped_and_cancel_replays_exactly() {
        let service = service(true);
        let request = trigger();
        assert_eq!(
            handle_trigger(&service, "trigger-key", &request).status,
            202
        );
        let status = handle_status(
            &service,
            request.organization_id.clone(),
            request.actor.clone(),
            &request.run_opaque,
        );
        assert_eq!(status.status, 200);
        assert_eq!(status.body["data"]["state"], "Draft");
        assert_eq!(
            handle_status(
                &service,
                OrganizationId::new("otherorg1").unwrap(),
                request.actor.clone(),
                &request.run_opaque,
            )
            .status,
            404
        );
        let cancel = CancelRemediationRequestV1 {
            organization_id: request.organization_id,
            actor: request.actor,
            run_opaque: request.run_opaque,
            expected_version: 1,
            reason: "operator requested cancellation".into(),
        };
        let first = handle_cancel(&service, "cancel-key", &cancel);
        assert_eq!(first.status, 200);
        assert_eq!(handle_cancel(&service, "cancel-key", &cancel), first);
    }

    #[test]
    fn reconcile_requires_explicit_permission_and_exposes_no_connector_action() {
        let denied = service(false);
        let request = trigger();
        let response = handle_reconcile(
            &denied,
            request.organization_id,
            request.actor,
            &request.run_opaque,
        );
        assert_eq!(response.status, 403);
        assert_eq!(response.body["reason"], "remediation.denied");
    }
}
