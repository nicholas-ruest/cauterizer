//! Local telemetry sinks.
//!
//! Two distinct sinks, matching the plan doc's "local sink: bounded
//! structured files + separate append-only audit":
//! - [`LocalFileTelemetrySink`] writes bounded, size-rotated JSON-lines
//!   structured events. Once a file reaches its bound, the oldest content is
//!   rotated out to a single `.1` sibling and a fresh file starts: this sink
//!   is allowed to lose old lines under sustained load.
//! - [`LocalAppendOnlyAuditSink`] writes to a *different* file that never
//!   rotates or truncates: every security-relevant event stays for as long
//!   as the file exists.
//!
//! Both are separate from the six existing per-context `AuditSink` ports
//! ([`crate::telemetry`] module docs); they are the shared cross-context
//! telemetry/alerting layer P18 owns, not a replacement for those ports.
//!
//! In-memory doubles ([`InMemoryTelemetrySink`], [`InMemoryAuditStream`])
//! follow the same shape used throughout this workspace (see
//! `crates/contexts/organization-access/src/application/memory.rs`).

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use super::event::TelemetryEvent;

/// Stable local-sink failure.
#[derive(Debug)]
pub enum TelemetryError {
    /// The underlying file could not be opened, read, or written.
    Io(std::io::Error),
    /// The event could not be encoded as JSON.
    Encoding(serde_json::Error),
}

impl fmt::Display for TelemetryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => f.write_str("telemetry sink I/O failed"),
            Self::Encoding(_) => f.write_str("telemetry event could not be encoded"),
        }
    }
}

impl std::error::Error for TelemetryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Encoding(error) => Some(error),
        }
    }
}

impl From<std::io::Error> for TelemetryError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for TelemetryError {
    fn from(value: serde_json::Error) -> Self {
        Self::Encoding(value)
    }
}

/// Structured telemetry event sink: bounded, may rotate away old content.
pub trait TelemetrySink {
    /// Records one event.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError`] when the event cannot be durably recorded.
    fn record_event(&mut self, event: &TelemetryEvent) -> Result<(), TelemetryError>;
}

/// Append-only security audit stream: a distinct sink/file from
/// [`TelemetrySink`], never rotated, so audit content cannot be silently
/// dropped alongside ordinary structured logs.
pub trait AuditStream {
    /// Appends one event.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError`] when the event cannot be durably appended.
    fn append(&mut self, event: &TelemetryEvent) -> Result<(), TelemetryError>;
}

fn rotated_sibling(path: &Path) -> PathBuf {
    let mut rotated = path.as_os_str().to_owned();
    rotated.push(".1");
    PathBuf::from(rotated)
}

/// Bounded, size-rotated JSON-lines structured event file.
pub struct LocalFileTelemetrySink {
    path: PathBuf,
    max_bytes: u64,
    file: File,
}

impl LocalFileTelemetrySink {
    /// Opens (creating if absent) a bounded structured-event file.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError`] when the file cannot be opened.
    pub fn open(path: impl Into<PathBuf>, max_bytes: u64) -> Result<Self, TelemetryError> {
        let path = path.into();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            max_bytes: max_bytes.max(1),
            file,
        })
    }

    /// The exact path this sink is currently writing.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn rotate_if_needed(&mut self) -> Result<(), TelemetryError> {
        if self.file.metadata()?.len() < self.max_bytes {
            return Ok(());
        }
        let rotated = rotated_sibling(&self.path);
        fs::rename(&self.path, &rotated)?;
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        Ok(())
    }
}

impl TelemetrySink for LocalFileTelemetrySink {
    fn record_event(&mut self, event: &TelemetryEvent) -> Result<(), TelemetryError> {
        self.rotate_if_needed()?;
        let line = serde_json::to_string(event)?;
        writeln!(self.file, "{line}")?;
        self.file.flush()?;
        Ok(())
    }
}

/// Append-only, never-rotated audit file.
pub struct LocalAppendOnlyAuditSink {
    path: PathBuf,
    file: File,
}

impl LocalAppendOnlyAuditSink {
    /// Opens (creating if absent) an append-only audit file.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError`] when the file cannot be opened.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, TelemetryError> {
        let path = path.into();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self { path, file })
    }

    /// The exact append-only audit file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AuditStream for LocalAppendOnlyAuditSink {
    fn append(&mut self, event: &TelemetryEvent) -> Result<(), TelemetryError> {
        let line = serde_json::to_string(event)?;
        writeln!(self.file, "{line}")?;
        self.file.flush()?;
        Ok(())
    }
}

/// Deterministic in-memory structured-event sink for tests.
#[derive(Clone, Debug, Default)]
pub struct InMemoryTelemetrySink {
    events: Vec<TelemetryEvent>,
}

impl InMemoryTelemetrySink {
    /// Returns recorded events in record order.
    #[must_use]
    pub fn events(&self) -> &[TelemetryEvent] {
        &self.events
    }
}

impl TelemetrySink for InMemoryTelemetrySink {
    fn record_event(&mut self, event: &TelemetryEvent) -> Result<(), TelemetryError> {
        self.events.push(event.clone());
        Ok(())
    }
}

/// Deterministic in-memory append-only audit stream for tests.
#[derive(Clone, Debug, Default)]
pub struct InMemoryAuditStream {
    events: Vec<TelemetryEvent>,
}

impl InMemoryAuditStream {
    /// Returns appended events in append order.
    #[must_use]
    pub fn events(&self) -> &[TelemetryEvent] {
        &self.events
    }
}

impl AuditStream for InMemoryAuditStream {
    fn append(&mut self, event: &TelemetryEvent) -> Result<(), TelemetryError> {
        self.events.push(event.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::event::{BoundedContext, Outcome, ReasonCode, TelemetryEventKind};

    fn sample(at: u64) -> TelemetryEvent {
        TelemetryEvent::new(
            TelemetryEventKind::RequestObserved,
            BoundedContext::Evidence,
            Outcome::Success,
            ReasonCode::RequestSucceeded,
            at,
        )
    }

    #[test]
    fn in_memory_sink_and_audit_stream_record_in_order() {
        let mut sink = InMemoryTelemetrySink::default();
        let mut audit = InMemoryAuditStream::default();
        for at in 0..3 {
            sink.record_event(&sample(at)).unwrap();
            audit.append(&sample(at)).unwrap();
        }
        assert_eq!(sink.events().len(), 3);
        assert_eq!(audit.events().len(), 3);
        assert_eq!(sink.events()[0].observed_at_unix_millis, 0);
        assert_eq!(audit.events()[2].observed_at_unix_millis, 2);
    }

    #[test]
    fn local_file_sink_and_audit_sink_are_separate_files_and_both_persist() {
        let dir = tempfile::tempdir().unwrap();
        let telemetry_path = dir.path().join("telemetry.jsonl");
        let audit_path = dir.path().join("audit.jsonl");
        assert_ne!(telemetry_path, audit_path);

        let mut telemetry = LocalFileTelemetrySink::open(&telemetry_path, 1_000_000).unwrap();
        let mut audit = LocalAppendOnlyAuditSink::open(&audit_path).unwrap();
        telemetry.record_event(&sample(1)).unwrap();
        audit.append(&sample(1)).unwrap();

        let telemetry_contents = fs::read_to_string(&telemetry_path).unwrap();
        let audit_contents = fs::read_to_string(&audit_path).unwrap();
        assert_eq!(telemetry_contents.lines().count(), 1);
        assert_eq!(audit_contents.lines().count(), 1);
        assert!(telemetry_contents.contains("request_observed"));
        assert!(audit_contents.contains("request_observed"));
    }

    #[test]
    fn local_file_sink_rotates_once_it_exceeds_its_byte_bound() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("telemetry.jsonl");
        // A tiny bound guarantees the very first line already triggers
        // rotation on the second write.
        let mut sink = LocalFileTelemetrySink::open(&path, 16).unwrap();
        sink.record_event(&sample(1)).unwrap();
        sink.record_event(&sample(2)).unwrap();

        let rotated = rotated_sibling(&path);
        assert!(
            rotated.exists(),
            "rotation should have produced a .1 sibling"
        );
        let rotated_contents = fs::read_to_string(&rotated).unwrap();
        assert!(rotated_contents.contains("\"observed_at_unix_millis\":1"));
        let current_contents = fs::read_to_string(&path).unwrap();
        assert!(current_contents.contains("\"observed_at_unix_millis\":2"));
    }

    /// Not a load test: a small, honest, this-sandbox-only local timing
    /// sample of structured-event write throughput, quoted (with that
    /// caveat) in the P18 provisional SLI table
    /// (`docs/architecture/p18-provisional-sli-table.md`). The bound is a
    /// generous sanity check, not a performance assertion.
    #[test]
    fn local_file_sink_write_throughput_measurement() {
        const SAMPLES: u32 = 5_000;
        let dir = tempfile::tempdir().unwrap();
        let mut sink =
            LocalFileTelemetrySink::open(dir.path().join("throughput.jsonl"), 64 * 1024 * 1024)
                .unwrap();

        let started = std::time::Instant::now();
        for at in 0..u64::from(SAMPLES) {
            sink.record_event(&sample(at)).unwrap();
        }
        let elapsed = started.elapsed();

        #[allow(clippy::cast_precision_loss)]
        let events_per_second = f64::from(SAMPLES) / elapsed.as_secs_f64().max(f64::EPSILON);
        eprintln!(
            "local_file_sink_write_throughput_measurement: {SAMPLES} events in {elapsed:?} ({events_per_second:.0} events/sec, this sandbox only)"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "sanity bound only, not a performance contract: took {elapsed:?}"
        );
    }

    #[test]
    fn append_only_audit_sink_never_shrinks_across_many_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut audit = LocalAppendOnlyAuditSink::open(&path).unwrap();
        let mut previous_len = 0_u64;
        for at in 0..50 {
            audit.append(&sample(at)).unwrap();
            let len = fs::metadata(&path).unwrap().len();
            assert!(len > previous_len, "audit file must only grow");
            previous_len = len;
        }
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 50);
    }
}
