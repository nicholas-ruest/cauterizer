//! Replaceable implementations of application-owned ports.
//!
//! Domain meaning does not belong in this crate.

#![forbid(unsafe_code)]

/// Reliable, tenant-scoped event delivery mechanisms.
pub mod delivery;
/// Generic transactional-outbox dispatch loop (claim, handle, ack/retry/dead-letter).
pub mod dispatcher;
/// Filesystem content-addressed artifact adapter for local development.
pub mod filesystem_artifacts;
/// PostgreSQL 17 transactional metadata adapter and migrations.
pub mod postgres;
/// S3-compatible, immutable content-addressed artifact adapter.
pub mod s3_artifacts;

/// Credential-scoped capability boundary over the CAS artifact store (solver/verifier
/// negative-permission enforcement).
pub mod artifact_access;
/// Content-addressed artifact ports and local adapters.
pub mod artifacts;
/// Cryptographic operation ports and untrusted local adapters.
pub mod crypto;

/// Release artifact admission verification (P20): sign/verify/tamper
/// detection logic for a release manifest, independent of any hosted
/// signing identity or CI runtime.
pub mod release_admission;

/// Reusable transactional metadata persistence mechanisms.
pub mod transactional;

/// Audit-safe structured telemetry: event/metric allowlist, RED metrics,
/// threat-model alerts, and local file sinks.
pub mod telemetry;

/// Wires Isolated Execution's worker-protocol signer through the P12
/// key-lifecycle port.
pub mod worker_signing;

/// Identifies this adapter package in diagnostics.
pub const ADAPTER_PACKAGE: &str = "cauterizer-infrastructure";
