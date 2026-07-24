//! HTTP-shaped wrapper over the Organization & Access facade.
//!
//! `cauterizer_organization_access::application::facade::OrganizationAccessFacade::bootstrap_local`
//! (P04) already enforces exact-retry idempotency through its `IdempotencyStore`
//! port. This module's only job is translation: map an HTTP-shaped
//! `Idempotency-Key` header and a parsed request body onto the facade's own
//! command, and map its result back onto an [`HttpResponse`].

use crate::contracts::{BootstrapOrganizationRequestV1, BootstrapOrganizationResponseV1};
use crate::http::HttpResponse;
use cauterizer_organization_access::application::facade::{
    ApplicationError, BootstrapLocalOrganization, BootstrapMode, BootstrapResult,
    OrganizationAccessFacade,
};
use cauterizer_organization_access::application::ports::{
    Clock, IdGenerator, IdempotencyStore, OrganizationRepository,
};
use cauterizer_organization_access::domain::Organization;
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::envelope::ProblemDetails;
use cauterizer_syntax::identifiers::IdempotencyKey;

/// Handles one `POST /v1/organizations:bootstrap-local` request against the facade.
///
/// The request digest bound to the idempotency key is the SHA-256 of the
/// request body's canonical (RFC 8785 JCS) bytes, so two requests are "the exact
/// same request" for replay purposes if and only if they are canonically
/// identical — not merely byte-identical (whitespace/key-order differences do
/// not count as a different request; a changed field value does).
#[must_use]
pub fn handle_bootstrap_local<R, I, C, G>(
    facade: &mut OrganizationAccessFacade<R, I, C, G>,
    idempotency_key_header: &str,
    request: &BootstrapOrganizationRequestV1,
) -> HttpResponse
where
    R: OrganizationRepository<Aggregate = Organization>,
    I: IdempotencyStore<BootstrapResult>,
    C: Clock,
    G: IdGenerator,
{
    let Ok(idempotency_key) = IdempotencyKey::new(idempotency_key_header) else {
        return invalid_idempotency_key_problem();
    };
    let Ok(canonical_bytes) = serde_jcs::to_vec(request) else {
        return non_canonical_request_problem();
    };
    let request_digest = Sha256Digest::of_bytes(canonical_bytes);
    let command = BootstrapLocalOrganization {
        mode: BootstrapMode::LocalOfflineDevelopment,
        organization_id: request.organization_id.clone(),
        organization_name: request.organization_name.clone(),
        owner_actor_id: request.owner_actor_id.clone(),
        idempotency_key,
        request_digest,
        correlation_id: request.correlation_id.clone(),
        causation_id: request.causation_id.clone(),
    };
    match facade.bootstrap_local(command) {
        Ok(result) => HttpResponse::ok(
            201,
            Some(etag(result.version)),
            BootstrapOrganizationResponseV1 {
                organization_id: result.organization_id.clone(),
                owner_member_id: result.owner_member_id.clone(),
                version: result.version,
            },
        ),
        Err(error) => HttpResponse::problem(&application_error_problem(&error)),
    }
}

/// Aggregate-sequence/ETag-shaped concurrency token for a persisted version.
fn etag(version: u64) -> String {
    format!("\"{version}\"")
}

fn invalid_idempotency_key_problem() -> HttpResponse {
    HttpResponse::problem(
        &ProblemDetails::new(
            "urn:cauterizer:problem:invalid-idempotency-key",
            "Invalid Idempotency-Key",
            400,
            "idempotency.invalid_key",
            None,
        )
        .expect("stable problem literal is valid"),
    )
}

fn non_canonical_request_problem() -> HttpResponse {
    HttpResponse::problem(
        &ProblemDetails::new(
            "urn:cauterizer:problem:non-canonical-request",
            "Request Body Not Canonicalizable",
            400,
            "request.not_canonical",
            None,
        )
        .expect("stable problem literal is valid"),
    )
}

fn application_error_problem(error: &ApplicationError) -> ProblemDetails {
    let (status, type_suffix, title, reason) = match error {
        ApplicationError::IdempotencyConflict => (
            409,
            "idempotency-conflict",
            "Idempotency Key Reused With A Different Request",
            "idempotency.conflict",
        ),
        ApplicationError::InvalidGeneratedIdentifier => (
            500,
            "invalid-generated-identifier",
            "Invalid Generated Identifier",
            "internal.invalid_generated_identifier",
        ),
        ApplicationError::Domain(_) => (
            422,
            "domain-rejected",
            "Request Rejected By Domain Invariant",
            "domain.rejected",
        ),
        ApplicationError::Repository(_) => (
            409,
            "aggregate-conflict",
            "Aggregate Persistence Conflict",
            "aggregate.conflict",
        ),
    };
    ProblemDetails::new(
        format!("urn:cauterizer:problem:{type_suffix}"),
        title,
        status,
        reason,
        None,
    )
    .expect("stable problem literal is valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use cauterizer_organization_access::application::memory::{
        InMemoryIdempotencyStore, InMemoryOrganizationRepository,
    };
    use cauterizer_organization_access::application::ports::{Clock, IdGenerator};
    use cauterizer_syntax::identifiers::{ActorId, CausationId, CorrelationId, OrganizationId};
    use cauterizer_syntax::time::UtcInstant;

    #[derive(Clone)]
    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> UtcInstant {
            UtcInstant::parse("2026-07-24T00:00:00Z").expect("fixture instant")
        }
        fn now_unix_millis(&self) -> u64 {
            1_753_315_200_000
        }
    }

    struct SequentialIds(u64);
    impl IdGenerator for SequentialIds {
        fn next_opaque(&mut self, _context: &'static str) -> String {
            self.0 += 1;
            format!("00000000{:08}", self.0)
        }
    }

    type Facade = OrganizationAccessFacade<
        InMemoryOrganizationRepository<Organization>,
        InMemoryIdempotencyStore<BootstrapResult>,
        FixedClock,
        SequentialIds,
    >;

    fn facade() -> Facade {
        OrganizationAccessFacade::new(
            InMemoryOrganizationRepository::default(),
            InMemoryIdempotencyStore::default(),
            FixedClock,
            SequentialIds(0),
        )
    }

    fn request() -> BootstrapOrganizationRequestV1 {
        BootstrapOrganizationRequestV1 {
            organization_id: OrganizationId::new("00000000").unwrap(),
            organization_name: "Local Cauterizer".to_owned(),
            owner_actor_id: ActorId::new("00000000").unwrap(),
            correlation_id: CorrelationId::new("00000000").unwrap(),
            causation_id: CausationId::new("00000000").unwrap(),
        }
    }

    #[test]
    fn exact_retry_with_the_same_idempotency_key_returns_the_identical_prior_result() {
        let mut facade = facade();
        let first = handle_bootstrap_local(&mut facade, "bootstrap-0001", &request());
        assert_eq!(first.status, 201);
        assert_eq!(first.etag.as_deref(), Some("\"1\""));

        let retry = handle_bootstrap_local(&mut facade, "bootstrap-0001", &request());
        assert_eq!(retry, first);
    }

    #[test]
    fn same_key_with_a_different_request_returns_a_stable_conflict_not_either_version() {
        let mut facade = facade();
        let first = handle_bootstrap_local(&mut facade, "bootstrap-0001", &request());
        assert_eq!(first.status, 201);

        let mut changed = request();
        changed.organization_name = "Renamed Before Commit".to_owned();
        let conflict = handle_bootstrap_local(&mut facade, "bootstrap-0001", &changed);
        assert_eq!(conflict.status, 409);
        assert_eq!(conflict.body["reason"], "idempotency.conflict");

        // Neither the original nor the changed version was silently applied a
        // second time: the facade's own repository still shows exactly one commit.
        assert_eq!(facade.repository().outbox().len(), 1);
    }

    #[test]
    fn a_different_idempotency_key_is_an_independent_request() {
        let mut facade = facade();
        let _ = handle_bootstrap_local(&mut facade, "bootstrap-0001", &request());
        let mut other = request();
        other.organization_id = OrganizationId::new("11111111").unwrap();
        let second = handle_bootstrap_local(&mut facade, "bootstrap-0002", &other);
        assert_eq!(second.status, 201);
        assert_eq!(facade.repository().outbox().len(), 2);
    }

    #[test]
    fn an_invalid_idempotency_key_header_is_rejected_before_touching_the_facade() {
        let mut facade = facade();
        let response = handle_bootstrap_local(&mut facade, "", &request());
        assert_eq!(response.status, 400);
        assert_eq!(response.body["reason"], "idempotency.invalid_key");
        assert!(facade.repository().outbox().is_empty());
    }
}
