//! Reference inbox, ordering, dead-letter, and reconciliation mechanisms.
//!
//! The adapter deliberately assigns no meaning to event payloads. A production
//! store persists the same keys and transitions in the relational transaction
//! that applies the consumer effect.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use cauterizer_syntax::classification::DataClass;
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{
    ActorId, AggregateSequence, ContextQualifiedId, OrganizationId,
};
use cauterizer_syntax::schema::{SchemaName, SchemaVersion};

const MAX_NAME_BYTES: usize = 96;
const MAX_REASON_BYTES: usize = 64;
const MAX_REPLAY_JUSTIFICATION_BYTES: usize = 512;

/// Validated consumer or producer name used in durable keys.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EndpointName(String);

impl EndpointName {
    /// Parses a bounded lowercase service name.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, padded, or non-canonical names.
    pub fn parse(value: impl Into<String>) -> Result<Self, DeliveryConfigurationError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_NAME_BYTES
            || value.starts_with('-')
            || value.ends_with('-')
            || value.contains("--")
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(DeliveryConfigurationError::InvalidEndpointName);
        }
        Ok(Self(value))
    }

    /// Returns the canonical endpoint name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable, payload-safe handler failure reason.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailureCode(String);

impl FailureCode {
    /// Parses a bounded `snake_case` reason code.
    ///
    /// # Errors
    ///
    /// Rejects text that could be an unbounded provider error or payload.
    pub fn parse(value: impl Into<String>) -> Result<Self, DeliveryConfigurationError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_REASON_BYTES
            || value.starts_with('_')
            || value.ends_with('_')
            || value.contains("__")
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(DeliveryConfigurationError::InvalidFailureCode);
        }
        Ok(Self(value))
    }

    /// Returns the audit-safe reason code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Complete metadata needed for deduplication, ordering, and safe diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryEnvelope<P> {
    /// Immutable tenant boundary.
    pub organization_id: OrganizationId,
    /// Authenticated producer identity.
    pub producer: EndpointName,
    /// Globally unique event reference.
    pub event_id: ContextQualifiedId,
    /// Aggregate stream identity.
    pub aggregate_id: ContextQualifiedId,
    /// Monotonic position within the aggregate stream.
    pub aggregate_sequence: AggregateSequence,
    /// Published event schema.
    pub schema_name: SchemaName,
    /// Published event schema version.
    pub schema_version: SchemaVersion,
    /// Classification inherited by stored payload and dead-letter copies.
    pub classification: DataClass,
    /// Digest of the canonical event envelope, used to reject identity conflicts.
    pub envelope_digest: Sha256Digest,
    /// Context-owned payload, opaque to this mechanism.
    pub payload: P,
}

/// Consumer compatibility and poison policy.
#[derive(Clone, Debug)]
pub struct DeliveryPolicy {
    consumer: EndpointName,
    handler_version: SchemaVersion,
    allowed_producers: BTreeSet<EndpointName>,
    supported_schemas: BTreeMap<SchemaName, SchemaVersion>,
    max_attempts: u16,
}

impl DeliveryPolicy {
    /// Creates a fail-closed delivery policy.
    ///
    /// # Errors
    ///
    /// At least one producer/schema and one retry attempt are required.
    pub fn new(
        consumer: EndpointName,
        handler_version: SchemaVersion,
        allowed_producers: impl IntoIterator<Item = EndpointName>,
        supported_schemas: impl IntoIterator<Item = (SchemaName, SchemaVersion)>,
        max_attempts: u16,
    ) -> Result<Self, DeliveryConfigurationError> {
        let allowed_producers = allowed_producers.into_iter().collect::<BTreeSet<_>>();
        let supported_schemas = supported_schemas.into_iter().collect::<BTreeMap<_, _>>();
        if allowed_producers.is_empty() || supported_schemas.is_empty() || max_attempts == 0 {
            return Err(DeliveryConfigurationError::EmptyPolicy);
        }
        Ok(Self {
            consumer,
            handler_version,
            allowed_producers,
            supported_schemas,
            max_attempts,
        })
    }
}

/// Handler outcome. Details are intentionally stable codes rather than errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandlerFailure {
    /// A bounded retry may succeed without changing the event.
    Retryable(FailureCode),
    /// The event cannot be handled without operator intervention.
    Poison(FailureCode),
}

/// Outcome of one delivery attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeliveryOutcome {
    /// The event and any newly contiguous held events were applied in order.
    Applied {
        /// Number of events applied by this call.
        count: usize,
    },
    /// The exact event was already applied by this handler version.
    Duplicate,
    /// A predecessor is missing; this event is retained, not acknowledged away.
    HeldForGap {
        /// Next required sequence.
        expected: u64,
    },
    /// Retryable failure remains below the poison threshold.
    RetryScheduled {
        /// Attempt count including this failure.
        attempts: u16,
    },
    /// The event is retained in governed dead-letter state.
    DeadLettered {
        /// Stable local dead-letter reference.
        id: DeadLetterId,
    },
}

/// Monotonic local dead-letter reference.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DeadLetterId(u64);

impl DeadLetterId {
    /// Returns the numeric identifier for persistence/operations tooling.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct EventKey {
    consumer: EndpointName,
    handler_version: SchemaVersion,
    producer: EndpointName,
    organization_id: OrganizationId,
    event_id: ContextQualifiedId,
    schema_major: u64,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct StreamKey {
    consumer: EndpointName,
    handler_version: SchemaVersion,
    producer: EndpointName,
    organization_id: OrganizationId,
    aggregate_id: ContextQualifiedId,
}

#[derive(Clone, Debug)]
struct ProcessedRecord {
    digest: Sha256Digest,
}

/// Why a retained delivery entered the dead-letter workflow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeadLetterReason {
    /// Handler declared a permanent schema/business poison condition.
    HandlerPoison(FailureCode),
    /// Bounded retry attempts were exhausted.
    AttemptsExhausted(FailureCode),
    /// Event identity was reused with different canonical content.
    ConflictingIdentity,
    /// Sequence is behind the committed stream checkpoint without a dedup record.
    SequenceRegression,
    /// A different event already occupies this held sequence.
    ConflictingSequence,
}

/// Current dead-letter disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeadLetterStatus {
    /// Awaiting governed intervention.
    Open,
    /// Successfully replayed through the normal handler and ordering path.
    Replayed,
}

/// Operator-visible dead-letter metadata. Payload access remains separately authorized.
#[derive(Clone, Debug)]
pub struct DeadLetter<P> {
    /// Stable reference.
    pub id: DeadLetterId,
    /// Tenant that owns the event and retained payload.
    pub organization_id: OrganizationId,
    /// Safe reason for intervention.
    pub reason: DeadLetterReason,
    /// Number of handler attempts before dead-lettering.
    pub attempts: u16,
    /// Current workflow status.
    pub status: DeadLetterStatus,
    envelope: DeliveryEnvelope<P>,
}

/// Explicit authority required for tenant-safe replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayAuthorization {
    /// Tenant scope approved for replay.
    pub organization_id: OrganizationId,
    /// Human operator authorizing replay.
    pub actor_id: ActorId,
    /// Bounded justification retained in the replay audit.
    justification: String,
}

impl ReplayAuthorization {
    /// Creates a bounded replay authorization record.
    ///
    /// # Errors
    ///
    /// Empty, padded, or oversized justifications are rejected.
    pub fn new(
        organization_id: OrganizationId,
        actor_id: ActorId,
        justification: impl Into<String>,
    ) -> Result<Self, DeliveryConfigurationError> {
        let justification = justification.into();
        if justification.is_empty()
            || justification.trim() != justification
            || justification.len() > MAX_REPLAY_JUSTIFICATION_BYTES
        {
            return Err(DeliveryConfigurationError::InvalidReplayJustification);
        }
        Ok(Self {
            organization_id,
            actor_id,
            justification,
        })
    }
}

/// Append-only record of a governed replay attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayAudit {
    /// Dead-letter subject.
    pub dead_letter_id: DeadLetterId,
    /// Tenant scope.
    pub organization_id: OrganizationId,
    /// Human operator.
    pub actor_id: ActorId,
    /// Whether the replay applied successfully.
    pub succeeded: bool,
    /// Bounded justification.
    pub justification: String,
}

/// Per-stream reconciliation finding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamFinding {
    /// Tenant owning the stream.
    pub organization_id: OrganizationId,
    /// Aggregate stream.
    pub aggregate_id: ContextQualifiedId,
    /// Next required sequence.
    pub expected_sequence: u64,
    /// Held future sequences.
    pub held_sequences: Vec<u64>,
    /// Open dead letters blocking or affecting the stream.
    pub open_dead_letters: Vec<DeadLetterId>,
}

/// Reconciliation snapshot suitable for queue-age/gap operations tooling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationReport {
    /// Streams with a gap or open poison event.
    pub findings: Vec<StreamFinding>,
    /// Total applied deduplication records.
    pub processed_events: usize,
}

/// In-memory reference implementation of durable inbox semantics.
#[derive(Clone, Debug)]
pub struct ReliableInbox<P> {
    policy: DeliveryPolicy,
    processed: BTreeMap<EventKey, ProcessedRecord>,
    checkpoints: BTreeMap<StreamKey, u64>,
    held: BTreeMap<(StreamKey, u64), DeliveryEnvelope<P>>,
    attempts: BTreeMap<EventKey, u16>,
    dead_letters: BTreeMap<DeadLetterId, DeadLetter<P>>,
    event_dead_letters: BTreeMap<EventKey, DeadLetterId>,
    replay_audit: Vec<ReplayAudit>,
    next_dead_letter_id: u64,
}

impl<P: Clone> ReliableInbox<P> {
    /// Creates an empty inbox. Durable deployments restore these maps from storage.
    #[must_use]
    pub fn new(policy: DeliveryPolicy) -> Self {
        Self {
            policy,
            processed: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            held: BTreeMap::new(),
            attempts: BTreeMap::new(),
            dead_letters: BTreeMap::new(),
            event_dead_letters: BTreeMap::new(),
            replay_audit: Vec::new(),
            next_dead_letter_id: 1,
        }
    }

    /// Receives one at-least-once delivery.
    ///
    /// The handler and successful inbox transition must be enclosed in one
    /// relational transaction by a production adapter.
    ///
    /// # Errors
    ///
    /// Authentication/schema policy failures and sequence overflow fail closed.
    pub fn receive<F>(
        &mut self,
        envelope: DeliveryEnvelope<P>,
        handler: &mut F,
    ) -> Result<DeliveryOutcome, DeliveryError>
    where
        F: FnMut(&DeliveryEnvelope<P>) -> Result<(), HandlerFailure>,
    {
        self.validate(&envelope)?;
        let event_key = self.event_key(&envelope)?;
        if let Some(record) = self.processed.get(&event_key) {
            return if record.digest == envelope.envelope_digest {
                Ok(DeliveryOutcome::Duplicate)
            } else {
                self.dead_letter(
                    envelope,
                    event_key,
                    0,
                    DeadLetterReason::ConflictingIdentity,
                )
            };
        }
        if let Some(id) = self.event_dead_letters.get(&event_key) {
            return Ok(DeliveryOutcome::DeadLettered { id: *id });
        }
        self.receive_unchecked(envelope, event_key, handler)
    }

    fn receive_unchecked<F>(
        &mut self,
        envelope: DeliveryEnvelope<P>,
        event_key: EventKey,
        handler: &mut F,
    ) -> Result<DeliveryOutcome, DeliveryError>
    where
        F: FnMut(&DeliveryEnvelope<P>) -> Result<(), HandlerFailure>,
    {
        let stream = self.stream_key(&envelope);
        let expected = self.checkpoints.get(&stream).copied().unwrap_or(1);
        let sequence = envelope.aggregate_sequence.get();
        if sequence < expected {
            return self.dead_letter(envelope, event_key, 0, DeadLetterReason::SequenceRegression);
        }
        if sequence > expected {
            let held_key = (stream, sequence);
            if let Some(existing) = self.held.get(&held_key) {
                if existing.event_id == envelope.event_id
                    && existing.envelope_digest == envelope.envelope_digest
                {
                    return Ok(DeliveryOutcome::HeldForGap { expected });
                }
                return self.dead_letter(
                    envelope,
                    event_key,
                    0,
                    DeadLetterReason::ConflictingSequence,
                );
            }
            self.held.insert(held_key, envelope);
            return Ok(DeliveryOutcome::HeldForGap { expected });
        }
        match self.apply_one(envelope, event_key, handler)? {
            ApplyOne::Applied => {
                let mut count = 1;
                loop {
                    let expected = self.checkpoints.get(&stream).copied().unwrap_or(1);
                    let Some(next) = self.held.remove(&(stream.clone(), expected)) else {
                        break;
                    };
                    let key = self.event_key(&next)?;
                    match self.apply_one(next, key, handler)? {
                        ApplyOne::Applied => count += 1,
                        ApplyOne::RetryScheduled(attempts) => {
                            return Ok(DeliveryOutcome::RetryScheduled { attempts });
                        }
                        ApplyOne::DeadLettered(id) => {
                            return Ok(DeliveryOutcome::DeadLettered { id });
                        }
                    }
                }
                Ok(DeliveryOutcome::Applied { count })
            }
            ApplyOne::RetryScheduled(attempts) => Ok(DeliveryOutcome::RetryScheduled { attempts }),
            ApplyOne::DeadLettered(id) => Ok(DeliveryOutcome::DeadLettered { id }),
        }
    }

    fn apply_one<F>(
        &mut self,
        envelope: DeliveryEnvelope<P>,
        event_key: EventKey,
        handler: &mut F,
    ) -> Result<ApplyOne, DeliveryError>
    where
        F: FnMut(&DeliveryEnvelope<P>) -> Result<(), HandlerFailure>,
    {
        match handler(&envelope) {
            Ok(()) => {
                let stream = self.stream_key(&envelope);
                let next = envelope
                    .aggregate_sequence
                    .get()
                    .checked_add(1)
                    .ok_or(DeliveryError::SequenceExhausted)?;
                self.checkpoints.insert(stream, next);
                self.attempts.remove(&event_key);
                self.processed.insert(
                    event_key,
                    ProcessedRecord {
                        digest: envelope.envelope_digest,
                    },
                );
                Ok(ApplyOne::Applied)
            }
            Err(HandlerFailure::Retryable(code)) => {
                let attempts = self.attempts.entry(event_key.clone()).or_default();
                *attempts = attempts.saturating_add(1);
                if *attempts < self.policy.max_attempts {
                    Ok(ApplyOne::RetryScheduled(*attempts))
                } else {
                    let attempts = *attempts;
                    self.attempts.remove(&event_key);
                    let outcome = self.dead_letter(
                        envelope,
                        event_key,
                        attempts,
                        DeadLetterReason::AttemptsExhausted(code),
                    )?;
                    let DeliveryOutcome::DeadLettered { id } = outcome else {
                        unreachable!("dead_letter always returns DeadLettered")
                    };
                    Ok(ApplyOne::DeadLettered(id))
                }
            }
            Err(HandlerFailure::Poison(code)) => {
                let attempts = self
                    .attempts
                    .remove(&event_key)
                    .unwrap_or(0)
                    .saturating_add(1);
                let outcome = self.dead_letter(
                    envelope,
                    event_key,
                    attempts,
                    DeadLetterReason::HandlerPoison(code),
                )?;
                let DeliveryOutcome::DeadLettered { id } = outcome else {
                    unreachable!("dead_letter always returns DeadLettered")
                };
                Ok(ApplyOne::DeadLettered(id))
            }
        }
    }

    fn dead_letter(
        &mut self,
        envelope: DeliveryEnvelope<P>,
        event_key: EventKey,
        attempts: u16,
        reason: DeadLetterReason,
    ) -> Result<DeliveryOutcome, DeliveryError> {
        let id = DeadLetterId(self.next_dead_letter_id);
        self.next_dead_letter_id = self
            .next_dead_letter_id
            .checked_add(1)
            .ok_or(DeliveryError::DeadLetterIdExhausted)?;
        self.event_dead_letters.insert(event_key, id);
        self.dead_letters.insert(
            id,
            DeadLetter {
                id,
                organization_id: envelope.organization_id.clone(),
                reason,
                attempts,
                status: DeadLetterStatus::Open,
                envelope,
            },
        );
        Ok(DeliveryOutcome::DeadLettered { id })
    }

    /// Replays one open dead letter through normal validation and ordering.
    ///
    /// # Errors
    ///
    /// Missing/resolved records or cross-tenant authorization fail closed.
    pub fn replay<F>(
        &mut self,
        id: DeadLetterId,
        authorization: ReplayAuthorization,
        handler: &mut F,
    ) -> Result<DeliveryOutcome, DeliveryError>
    where
        F: FnMut(&DeliveryEnvelope<P>) -> Result<(), HandlerFailure>,
    {
        let envelope = {
            let record = self
                .dead_letters
                .get(&id)
                .ok_or(DeliveryError::DeadLetterNotFound)?;
            if record.status != DeadLetterStatus::Open {
                return Err(DeliveryError::DeadLetterAlreadyResolved);
            }
            if record.organization_id != authorization.organization_id {
                return Err(DeliveryError::ReplayOrganizationMismatch);
            }
            record.envelope.clone()
        };
        self.validate(&envelope)?;
        let event_key = self.event_key(&envelope)?;
        self.event_dead_letters.remove(&event_key);
        let outcome = self.receive_unchecked(envelope, event_key.clone(), handler)?;
        let succeeded = matches!(outcome, DeliveryOutcome::Applied { .. });
        if succeeded {
            if let Some(record) = self.dead_letters.get_mut(&id) {
                record.status = DeadLetterStatus::Replayed;
            }
        } else {
            self.event_dead_letters.entry(event_key).or_insert(id);
        }
        self.replay_audit.push(ReplayAudit {
            dead_letter_id: id,
            organization_id: authorization.organization_id,
            actor_id: authorization.actor_id,
            succeeded,
            justification: authorization.justification,
        });
        Ok(outcome)
    }

    /// Returns an operator-safe dead-letter record.
    #[must_use]
    pub fn dead_letter_record(&self, id: DeadLetterId) -> Option<&DeadLetter<P>> {
        self.dead_letters.get(&id)
    }

    /// Returns append-only replay audit facts.
    #[must_use]
    pub fn replay_audit(&self) -> &[ReplayAudit] {
        &self.replay_audit
    }

    /// Finds missing predecessors and poison records without exposing payloads.
    #[must_use]
    pub fn reconcile(&self) -> ReconciliationReport {
        let mut streams = BTreeSet::new();
        streams.extend(self.checkpoints.keys().cloned());
        streams.extend(self.held.keys().map(|(stream, _)| stream.clone()));
        for record in self
            .dead_letters
            .values()
            .filter(|record| record.status == DeadLetterStatus::Open)
        {
            streams.insert(self.stream_key(&record.envelope));
        }
        let findings = streams
            .into_iter()
            .filter_map(|stream| {
                let expected_sequence = self.checkpoints.get(&stream).copied().unwrap_or(1);
                let held_sequences = self
                    .held
                    .keys()
                    .filter_map(|(candidate, sequence)| (candidate == &stream).then_some(*sequence))
                    .collect::<Vec<_>>();
                let open_dead_letters = self
                    .dead_letters
                    .iter()
                    .filter_map(|(id, record)| {
                        (record.status == DeadLetterStatus::Open
                            && self.stream_key(&record.envelope) == stream)
                            .then_some(*id)
                    })
                    .collect::<Vec<_>>();
                (!held_sequences.is_empty() || !open_dead_letters.is_empty()).then_some(
                    StreamFinding {
                        organization_id: stream.organization_id,
                        aggregate_id: stream.aggregate_id,
                        expected_sequence,
                        held_sequences,
                        open_dead_letters,
                    },
                )
            })
            .collect();
        ReconciliationReport {
            findings,
            processed_events: self.processed.len(),
        }
    }

    fn validate(&self, envelope: &DeliveryEnvelope<P>) -> Result<(), DeliveryError> {
        if !self.policy.allowed_producers.contains(&envelope.producer) {
            return Err(DeliveryError::ProducerDenied);
        }
        let supported = self
            .policy
            .supported_schemas
            .get(&envelope.schema_name)
            .ok_or(DeliveryError::UnsupportedSchema)?;
        if !supported.accepts(&envelope.schema_version) {
            return Err(DeliveryError::UnsupportedSchemaVersion);
        }
        Ok(())
    }

    fn event_key(&self, envelope: &DeliveryEnvelope<P>) -> Result<EventKey, DeliveryError> {
        let major = envelope
            .schema_version
            .semver()
            .map_err(|_| DeliveryError::UnsupportedSchemaVersion)?
            .major;
        Ok(EventKey {
            consumer: self.policy.consumer.clone(),
            handler_version: self.policy.handler_version.clone(),
            producer: envelope.producer.clone(),
            organization_id: envelope.organization_id.clone(),
            event_id: envelope.event_id.clone(),
            schema_major: major,
        })
    }

    fn stream_key(&self, envelope: &DeliveryEnvelope<P>) -> StreamKey {
        StreamKey {
            consumer: self.policy.consumer.clone(),
            handler_version: self.policy.handler_version.clone(),
            producer: envelope.producer.clone(),
            organization_id: envelope.organization_id.clone(),
            aggregate_id: envelope.aggregate_id.clone(),
        }
    }
}

enum ApplyOne {
    Applied,
    RetryScheduled(u16),
    DeadLettered(DeadLetterId),
}

/// Invalid static delivery configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryConfigurationError {
    /// Consumer/producer name is not canonical.
    InvalidEndpointName,
    /// Failure reason is not a bounded machine code.
    InvalidFailureCode,
    /// Producer/schema allowlist or retry policy was empty.
    EmptyPolicy,
    /// Replay justification is absent, padded, or oversized.
    InvalidReplayJustification,
}

impl fmt::Display for DeliveryConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEndpointName => "invalid delivery endpoint name",
            Self::InvalidFailureCode => "invalid delivery failure code",
            Self::EmptyPolicy => "delivery policy must declare producers, schemas, and attempts",
            Self::InvalidReplayJustification => "invalid replay justification",
        })
    }
}
impl std::error::Error for DeliveryConfigurationError {}

/// Fail-closed delivery/replay error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryError {
    /// Producer is not authenticated/allowlisted for this consumer.
    ProducerDenied,
    /// Event schema name is unknown.
    UnsupportedSchema,
    /// Event schema version is incompatible with the handler.
    UnsupportedSchemaVersion,
    /// Aggregate sequence cannot advance.
    SequenceExhausted,
    /// Local dead-letter identity space exhausted.
    DeadLetterIdExhausted,
    /// Requested dead letter does not exist.
    DeadLetterNotFound,
    /// Requested dead letter was already successfully replayed.
    DeadLetterAlreadyResolved,
    /// Replay authority is for another organization.
    ReplayOrganizationMismatch,
}

impl fmt::Display for DeliveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ProducerDenied => "delivery_producer_denied",
            Self::UnsupportedSchema => "delivery_schema_unsupported",
            Self::UnsupportedSchemaVersion => "delivery_schema_version_unsupported",
            Self::SequenceExhausted => "delivery_sequence_exhausted",
            Self::DeadLetterIdExhausted => "dead_letter_id_exhausted",
            Self::DeadLetterNotFound => "dead_letter_not_found",
            Self::DeadLetterAlreadyResolved => "dead_letter_already_resolved",
            Self::ReplayOrganizationMismatch => "replay_organization_mismatch",
        })
    }
}
impl std::error::Error for DeliveryError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(max_attempts: u16) -> DeliveryPolicy {
        DeliveryPolicy::new(
            EndpointName::parse("remediation-runs").unwrap(),
            SchemaVersion::parse("1.0.0").unwrap(),
            [EndpointName::parse("advisory-intake").unwrap()],
            [(
                SchemaName::parse("dev.cauterizer.advisory-intake.snapshotted").unwrap(),
                SchemaVersion::parse("1.2.0").unwrap(),
            )],
            max_attempts,
        )
        .unwrap()
    }

    fn envelope(sequence: u64, event: u64, org: &str) -> DeliveryEnvelope<String> {
        DeliveryEnvelope {
            organization_id: OrganizationId::new(org).unwrap(),
            producer: EndpointName::parse("advisory-intake").unwrap(),
            event_id: ContextQualifiedId::new("event", &format!("00000000{event:08}")).unwrap(),
            aggregate_id: ContextQualifiedId::new("advisory", "0000000000000001").unwrap(),
            aggregate_sequence: AggregateSequence::new(sequence).unwrap(),
            schema_name: SchemaName::parse("dev.cauterizer.advisory-intake.snapshotted").unwrap(),
            schema_version: SchemaVersion::parse("1.1.0").unwrap(),
            classification: DataClass::Internal,
            envelope_digest: Sha256Digest::of_bytes(format!("{org}:{sequence}:{event}")),
            payload: format!("payload-{sequence}"),
        }
    }

    #[test]
    fn exact_duplicate_is_not_applied_twice() {
        let mut inbox = ReliableInbox::new(policy(3));
        let mut applied = Vec::new();
        let mut handler = |event: &DeliveryEnvelope<String>| {
            applied.push(event.aggregate_sequence.get());
            Ok(())
        };
        let event = envelope(1, 1, "00000000");
        assert_eq!(
            inbox.receive(event.clone(), &mut handler).unwrap(),
            DeliveryOutcome::Applied { count: 1 }
        );
        assert_eq!(
            inbox.receive(event, &mut handler).unwrap(),
            DeliveryOutcome::Duplicate
        );
        let _ = handler;
        assert_eq!(applied, vec![1]);
    }

    #[test]
    fn compatible_historical_schema_revisions_remain_deliverable() {
        let mut inbox = ReliableInbox::new(policy(3));
        let mut applied = Vec::new();
        let mut handler = |event: &DeliveryEnvelope<String>| {
            applied.push(event.schema_version.as_str().to_owned());
            Ok(())
        };

        let mut historical = envelope(1, 41, "00000000");
        historical.schema_version = SchemaVersion::parse("1.0.0").unwrap();
        let mut current = envelope(2, 42, "00000000");
        current.schema_version = SchemaVersion::parse("1.2.0").unwrap();

        assert_eq!(
            inbox.receive(historical, &mut handler).unwrap(),
            DeliveryOutcome::Applied { count: 1 }
        );
        assert_eq!(
            inbox.receive(current, &mut handler).unwrap(),
            DeliveryOutcome::Applied { count: 1 }
        );
        let _ = handler;
        assert_eq!(applied, ["1.0.0", "1.2.0"]);
    }

    #[test]
    fn out_of_order_events_are_held_then_drained_in_sequence() {
        let mut inbox = ReliableInbox::new(policy(3));
        let mut applied = Vec::new();
        let mut handler = |event: &DeliveryEnvelope<String>| {
            applied.push(event.aggregate_sequence.get());
            Ok(())
        };
        assert_eq!(
            inbox
                .receive(envelope(3, 3, "00000000"), &mut handler)
                .unwrap(),
            DeliveryOutcome::HeldForGap { expected: 1 }
        );
        assert_eq!(
            inbox
                .receive(envelope(2, 2, "00000000"), &mut handler)
                .unwrap(),
            DeliveryOutcome::HeldForGap { expected: 1 }
        );
        assert_eq!(
            inbox
                .receive(envelope(1, 1, "00000000"), &mut handler)
                .unwrap(),
            DeliveryOutcome::Applied { count: 3 }
        );
        let _ = handler;
        assert_eq!(applied, vec![1, 2, 3]);
        assert!(inbox.reconcile().findings.is_empty());
    }

    #[test]
    fn ordering_and_deduplication_are_tenant_scoped() {
        let mut inbox = ReliableInbox::new(policy(3));
        let mut applied = Vec::new();
        let mut handler = |event: &DeliveryEnvelope<String>| {
            applied.push(event.organization_id.clone());
            Ok(())
        };
        inbox
            .receive(envelope(1, 1, "00000000"), &mut handler)
            .unwrap();
        inbox
            .receive(envelope(1, 1, "11111111"), &mut handler)
            .unwrap();
        let _ = handler;
        assert_eq!(applied.len(), 2);
    }

    #[test]
    fn retry_exhaustion_dead_letters_without_advancing_checkpoint() {
        let mut inbox = ReliableInbox::new(policy(2));
        let code = FailureCode::parse("dependency_unavailable").unwrap();
        let mut handler =
            |_event: &DeliveryEnvelope<String>| Err(HandlerFailure::Retryable(code.clone()));
        assert_eq!(
            inbox
                .receive(envelope(1, 1, "00000000"), &mut handler)
                .unwrap(),
            DeliveryOutcome::RetryScheduled { attempts: 1 }
        );
        let DeliveryOutcome::DeadLettered { id } = inbox
            .receive(envelope(1, 1, "00000000"), &mut handler)
            .unwrap()
        else {
            panic!("expected dead letter");
        };
        assert_eq!(
            inbox.dead_letter_record(id).unwrap().reason,
            DeadLetterReason::AttemptsExhausted(code)
        );
        assert_eq!(inbox.reconcile().findings[0].expected_sequence, 1);
    }

    #[test]
    fn poison_replay_is_tenant_authorized_audited_and_drains_held_work() {
        use std::cell::Cell;

        let mut inbox = ReliableInbox::new(policy(3));
        let poison = Cell::new(true);
        let code = FailureCode::parse("unsupported_required_semantics").unwrap();
        let mut handler = |event: &DeliveryEnvelope<String>| {
            if poison.get() && event.aggregate_sequence.get() == 1 {
                Err(HandlerFailure::Poison(code.clone()))
            } else {
                Ok(())
            }
        };
        let DeliveryOutcome::DeadLettered { id } = inbox
            .receive(envelope(1, 1, "00000000"), &mut handler)
            .unwrap()
        else {
            panic!("expected dead letter");
        };
        assert_eq!(
            inbox
                .receive(envelope(2, 2, "00000000"), &mut handler)
                .unwrap(),
            DeliveryOutcome::HeldForGap { expected: 1 }
        );
        let wrong = ReplayAuthorization::new(
            OrganizationId::new("11111111").unwrap(),
            ActorId::new("00000000").unwrap(),
            "reviewed schema correction",
        )
        .unwrap();
        assert_eq!(
            inbox.replay(id, wrong, &mut handler),
            Err(DeliveryError::ReplayOrganizationMismatch)
        );
        poison.set(false);
        let authorized = ReplayAuthorization::new(
            OrganizationId::new("00000000").unwrap(),
            ActorId::new("00000000").unwrap(),
            "reviewed schema correction",
        )
        .unwrap();
        assert_eq!(
            inbox.replay(id, authorized, &mut handler).unwrap(),
            DeliveryOutcome::Applied { count: 2 }
        );
        assert_eq!(
            inbox.dead_letter_record(id).unwrap().status,
            DeadLetterStatus::Replayed
        );
        assert!(inbox.replay_audit()[0].succeeded);
    }

    #[test]
    fn unsupported_producer_and_schema_fail_before_handler() {
        let mut inbox = ReliableInbox::new(policy(3));
        let mut calls = 0;
        let mut handler = |_event: &DeliveryEnvelope<String>| {
            calls += 1;
            Ok(())
        };
        let mut denied = envelope(1, 1, "00000000");
        denied.producer = EndpointName::parse("patch-proposals").unwrap();
        assert_eq!(
            inbox.receive(denied, &mut handler),
            Err(DeliveryError::ProducerDenied)
        );
        let mut incompatible = envelope(1, 2, "00000000");
        incompatible.schema_version = SchemaVersion::parse("2.0.0").unwrap();
        assert_eq!(
            inbox.receive(incompatible, &mut handler),
            Err(DeliveryError::UnsupportedSchemaVersion)
        );
        let _ = handler;
        assert_eq!(calls, 0);
    }

    #[test]
    fn conflicting_event_identity_and_sequence_are_governed_poison() {
        let mut inbox = ReliableInbox::new(policy(3));
        let mut handler = |_event: &DeliveryEnvelope<String>| Ok(());
        let held = envelope(2, 2, "00000000");
        inbox.receive(held, &mut handler).unwrap();
        let conflict = envelope(2, 3, "00000000");
        let DeliveryOutcome::DeadLettered { id } = inbox.receive(conflict, &mut handler).unwrap()
        else {
            panic!("expected conflict dead letter");
        };
        assert_eq!(
            inbox.dead_letter_record(id).unwrap().reason,
            DeadLetterReason::ConflictingSequence
        );
    }
}
