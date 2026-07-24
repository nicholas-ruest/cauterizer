//! Audit-safe structured telemetry: a closed event/metric allowlist, bounded
//! RED metrics, ten threat-model alert checks, and local file sinks.
//!
//! ## P18 scope and triage
//!
//! This module replaces no existing per-context `AuditSink` port
//! (`crates/contexts/*/src/application/ports.rs`); those remain each
//! context's own authorization-audit trail. This is the additional,
//! shared, cross-context telemetry/alerting layer named by
//! `docs/architecture/p12-p20-prompt-plan.md`'s P18 section.
//!
//! The ten alert identifiers implemented in [`alerts`] are taken verbatim
//! from `docs/architecture/abuse-case-test-matrix.md`'s "Alert and audit
//! linkage" paragraph (repeated cross-organization denials, capability
//! misuse, sandbox egress attempts, cleanup failures, verifier-store access
//! by a solver identity, signer-policy denial spikes, secret-redaction
//! detections, break-glass use, event authentication failures, export
//! authorization failures) -- not the shorter five-item paraphrase in the
//! P12-P20 prompt-plan doc's own P18 section, which the assigning prompt
//! flagged as inaccurate.
//!
//! Only the local sink and alert suite are exercised here. No hosted
//! OpenTelemetry collector, hosted audit stream, or named
//! operations/product reviewer exists for this session to exercise; a real
//! hosted exporter needs a distinct future adapter behind
//! [`sink::TelemetrySink`]/[`sink::AuditStream`], not a fake "connected"
//! claim.

/// The ten executable alert checks.
pub mod alerts;
/// The closed event schema and redaction guard.
pub mod event;
/// Bounded-dimension RED metrics.
pub mod metrics;
/// Local file sinks and in-memory test doubles.
pub mod sink;

#[cfg(test)]
mod redaction_corpus_tests;

pub use event::{
    BoundedContext, DetailReference, Outcome, ReasonCode, TelemetryEvent, TelemetryEventKind,
    classified_detail,
};
pub use metrics::RedMetrics;
pub use sink::{
    AuditStream, InMemoryAuditStream, InMemoryTelemetrySink, LocalAppendOnlyAuditSink,
    LocalFileTelemetrySink, TelemetryError, TelemetrySink,
};
