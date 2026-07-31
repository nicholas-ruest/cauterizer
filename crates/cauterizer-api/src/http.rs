//! Minimal transport-neutral HTTP-shaped response envelope.
//!
//! See the crate root docs for why this crate exposes a plain, provably
//! HTTP-envelope-compatible response type instead of binding a live server.

use cauterizer_syntax::envelope::{ProblemDetails, ResultEnvelope};
use serde::Serialize;
use serde_json::Value;

/// One HTTP-shaped response: numeric status, an optional concurrency-token
/// (`ETag`) header value, and a JSON body.
///
/// The body is always either a [`ResultEnvelope`] or a [`ProblemDetails`]
/// serialized to [`Value`], exactly what a real transport adapter would render
/// as the wire body — this type carries no behavior a socket-bound server
/// couldn't reuse unchanged.
#[derive(Clone, Debug, PartialEq)]
pub struct HttpResponse {
    /// HTTP-compatible numeric status.
    pub status: u16,
    /// Aggregate-sequence/ETag-shaped concurrency token, when the resource has one.
    pub etag: Option<String>,
    /// JSON-serialized [`ResultEnvelope`] or [`ProblemDetails`] body.
    pub body: Value,
}

impl HttpResponse {
    /// Builds a successful, envelope-wrapped response.
    ///
    /// # Panics
    ///
    /// Panics only if `data` cannot be represented as JSON, which does not
    /// happen for this crate's contract DTOs (they are plain, non-cyclic structs).
    #[must_use]
    pub fn ok<T: Serialize>(status: u16, etag: Option<String>, data: T) -> Self {
        Self {
            status,
            etag,
            body: serde_json::to_value(ResultEnvelope::new(data))
                .expect("contract DTOs are always JSON-serializable"),
        }
    }

    /// Builds an RFC 9457-compatible problem response; the status mirrors the problem.
    ///
    /// # Panics
    ///
    /// Panics only if `problem` cannot be represented as JSON, which does not
    /// happen for [`ProblemDetails`] (it is a plain, bounded, non-cyclic struct).
    #[must_use]
    pub fn problem(problem: &ProblemDetails) -> Self {
        Self {
            status: problem.status,
            etag: None,
            body: serde_json::to_value(problem)
                .expect("ProblemDetails is always JSON-serializable"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_wraps_data_in_a_result_envelope_with_the_given_status_and_etag() {
        let response = HttpResponse::ok(201, Some("\"3\"".to_owned()), "payload");
        assert_eq!(response.status, 201);
        assert_eq!(response.etag.as_deref(), Some("\"3\""));
        assert_eq!(response.body, serde_json::json!({ "data": "payload" }));
    }

    #[test]
    fn problem_carries_the_problems_own_status_and_no_etag() {
        let problem = ProblemDetails::new(
            "urn:cauterizer:problem:example",
            "Example",
            409,
            "example.conflict",
            None,
        )
        .unwrap();
        let response = HttpResponse::problem(&problem);
        assert_eq!(response.status, 409);
        assert_eq!(response.etag, None);
        assert_eq!(response.body["reason"], "example.conflict");
    }
}
