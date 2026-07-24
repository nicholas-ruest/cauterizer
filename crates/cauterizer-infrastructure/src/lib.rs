//! Replaceable implementations of application-owned ports.
//!
//! Domain meaning does not belong in this crate.

#![forbid(unsafe_code)]

/// Reliable, tenant-scoped event delivery mechanisms.
pub mod delivery;
/// Filesystem content-addressed artifact adapter for local development.
pub mod filesystem_artifacts;
/// PostgreSQL 17 transactional metadata adapter and migrations.
pub mod postgres;
/// S3-compatible, immutable content-addressed artifact adapter.
pub mod s3_artifacts;

/// Content-addressed artifact ports and local adapters.
pub mod artifacts;
/// Cryptographic operation ports and untrusted local adapters.
pub mod crypto;

/// Reusable transactional metadata persistence mechanisms.
pub mod transactional;

/// Wires Isolated Execution's worker-protocol signer through the P12
/// key-lifecycle port.
pub mod worker_signing;

/// Identifies this adapter package in diagnostics.
pub const ADAPTER_PACKAGE: &str = "cauterizer-infrastructure";
