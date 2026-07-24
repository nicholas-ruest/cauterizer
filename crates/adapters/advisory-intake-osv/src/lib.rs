//! Live OSV.dev advisory acquisition adapter for Advisory Intake.
//!
//! This crate implements the *advisory* half of ADR-020's networked-
//! acquisition governance (P16): a hardened, allowlist-enforcing HTTP
//! acquisition path for the real OSV.dev API, alongside — not replacing —
//! `advisory-intake`'s existing offline fixture path
//! (`cauterizer_advisory_intake::application::fixture::LocalFixtureAdapter`).
//!
//! # Never real network I/O in tests
//! [`transport::HttpFetchPort`] is the only way this crate performs network
//! I/O. Every test in this crate injects [`fake::ScriptedHttpFetchPort`], a
//! deterministic in-memory double, instead. This crate currently ships no
//! `reqwest`-backed (or otherwise real) implementation of `HttpFetchPort`:
//! wiring one is an explicit, documented follow-up (see the crate's
//! implementation notes), not something silently deferred. Until that
//! follow-up lands, live acquisition cannot run at all — there is no code
//! path here that reaches the network, so there is nothing to feature-gate
//! today. When a real implementation is added it MUST be behind a Cargo
//! feature that is off by default and not enabled by this workspace's
//! default test/build profile.
//!
//! # Provenance
//! No new "source class" field was added anywhere: `AdvisorySource::source`
//! (`cauterizer_advisory_intake::domain::AdvisorySource`) is already a
//! free-form, policy-neutral provenance string used by the existing fixture
//! path (as `"fixture"`); callers of this crate should pass `"live-osv"` for
//! advisories acquired here. See the crate implementation notes for why a
//! contract change was judged unnecessary.

#![forbid(unsafe_code)]

/// Hardened acquisition orchestration: destination allowlisting, redirect
/// and DNS-rebinding defense, byte limits, and the fixed retry policy.
pub mod acquire;
/// Deterministic, network-free `HttpFetchPort` test double.
pub mod fake;
/// OSV.dev advisory schema mapping into `NormalizedFixture`.
pub mod osv;
/// The narrow HTTP transport port real and fake implementations satisfy.
pub mod transport;
