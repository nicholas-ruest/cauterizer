//! Contract-first, idempotent HTTP-shaped surface over Cauterizer application facades.
//!
//! # Why not a bound `axum` server
//!
//! P19's scope allows either a real bound HTTP server or "a `tower::Service`-shaped
//! or even a plain function-based request/response pipeline that's provably
//! HTTP-envelope-compatible", explicitly preferring the latter over shipping a
//! half-wired server with untested routes. This crate takes the function-based
//! path: [`http::HttpResponse`] carries exactly what a real transport adapter needs
//! (numeric status, an optional `ETag` header value, and a JSON body), and every
//! handler in [`organization`] is a plain, fully unit-tested function from a typed
//! request to that response. No `axum`/`actix-web`/`warp`/`tower` dependency is
//! introduced (`crates/architecture-tests` already forbids those inside a
//! domain-layer package, and none is added here either), which keeps this crate
//! honestly scoped: every byte of behavior it claims is exercised by a test, and a
//! future real transport adapter is additive (it calls these same functions) rather
//! than a redesign.
//!
//! # What is wrapped
//!
//! [`organization::handle_bootstrap_local`] wraps
//! `cauterizer_organization_access::application::facade::OrganizationAccessFacade::bootstrap_local`
//! end-to-end: an HTTP-shaped `Idempotency-Key` header maps directly onto the
//! facade's own `IdempotencyKey`, and the request-digest binding that decides
//! exact-retry-replay vs. conflict reuses the facade's already-tested
//! `IdempotencyStore` semantics (P04) rather than reinventing them. This crate adds
//! only the translation layer: canonical (JCS) request digesting, RFC
//! 9457-compatible [`cauterizer_syntax::envelope::ProblemDetails`] error mapping,
//! and an aggregate-sequence/ETag-shaped concurrency token derived from the
//! facade's returned version.
//!
//! `cauterizer-cli` is unaffected: it still calls application facades directly, not
//! through this crate.

#![forbid(unsafe_code)]

/// Versioned wire contracts for the endpoints this crate wraps.
pub mod contracts;
/// Minimal transport-neutral HTTP-shaped response envelope.
pub mod http;
/// HTTP-shaped wrapper over the Organization & Access facade.
pub mod organization;
/// Opaque, offset-based pagination cursor codec reusing `cauterizer_syntax::envelope::Cursor`.
pub mod pagination;
