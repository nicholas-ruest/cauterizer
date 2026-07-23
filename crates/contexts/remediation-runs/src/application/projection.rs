//! Deterministic tenant-scoped run projection rebuilt from ordered run facts.
use crate::contracts::{
    RemediationRunEventPayloadV1 as Payload, RemediationRunEventV1, RunInputsV1,
};
use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
use std::collections::BTreeMap;

/// Run-owned lifecycle phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectedPhase {
    /// Run identity exists but inputs are not bound.
    Created,
    /// Immutable inputs are bound and baseline may be requested.
    InputsBound,
    /// Baseline work has been requested and is pending.
    BaselinePending,
    /// Candidate generation has been requested and is pending.
    ProposalPending,
    /// Independent assessment has been requested and is pending.
    AssessmentPending,
    /// Evidence construction has been requested and is pending.
    EvidencePending,
    /// Run was terminally cancelled.
    Cancelled,
    /// Run-owned history was terminally sealed.
    Sealed,
}
/// Timeline item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimelineEntry {
    /// Aggregate sequence.
    pub sequence: u64,
    /// Stable fact name.
    pub fact: &'static str,
    /// Delivery-clock observation.
    pub observed_at_ms: u64,
}
/// Tenant run view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunView {
    /// Tenant.
    pub organization_id: OrganizationId,
    /// Run.
    pub run_id: ContextQualifiedId,
    /// Current phase.
    pub phase: ProjectedPhase,
    /// Immutable inputs.
    pub inputs: Option<RunInputsV1>,
    /// Append-only timeline.
    pub timeline: Vec<TimelineEntry>,
}
/// Projection failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionError {
    /// Run absent.
    MissingRun,
    /// Sequence not contiguous.
    SequenceGap,
    /// Same sequence has different content.
    ConflictingReplay,
    /// Terminal state cannot advance.
    TerminalRun,
    /// Transition invalid.
    InvalidTransition,
}
/// Stuck pending step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StuckStep {
    /// Tenant.
    pub organization_id: OrganizationId,
    /// Run.
    pub run_id: ContextQualifiedId,
    /// Pending phase.
    pub phase: ProjectedPhase,
    /// Age.
    pub age_ms: u64,
}

/// Rebuildable projection.
#[derive(Default)]
pub struct RunProjection {
    runs: BTreeMap<(OrganizationId, ContextQualifiedId), RunView>,
    applied: BTreeMap<(OrganizationId, ContextQualifiedId, u64), RemediationRunEventV1>,
}
impl RunProjection {
    /// Applies one authenticated ordered run event.
    ///
    /// # Errors
    ///
    /// Rejects missing runs, gaps, conflicting replays, terminal advancement,
    /// and transitions which are not valid for the projected phase.
    pub fn apply(
        &mut self,
        event: RemediationRunEventV1,
        observed_at_ms: u64,
    ) -> Result<(), ProjectionError> {
        let ek = (
            event.organization_id.clone(),
            event.run_id.clone(),
            event.aggregate_sequence.get(),
        );
        if let Some(old) = self.applied.get(&ek) {
            return if old == &event {
                Ok(())
            } else {
                Err(ProjectionError::ConflictingReplay)
            };
        }
        let key = (event.organization_id.clone(), event.run_id.clone());
        let seq = event.aggregate_sequence.get();
        if matches!(event.payload, Payload::RemediationRunCreated) {
            if seq != 1 || self.runs.contains_key(&key) {
                return Err(ProjectionError::InvalidTransition);
            }
            self.runs.insert(
                key,
                RunView {
                    organization_id: event.organization_id.clone(),
                    run_id: event.run_id.clone(),
                    phase: ProjectedPhase::Created,
                    inputs: None,
                    timeline: vec![TimelineEntry {
                        sequence: 1,
                        fact: "remediation_run_created",
                        observed_at_ms,
                    }],
                },
            );
            self.applied.insert(ek, event);
            return Ok(());
        }
        let view = self.runs.get_mut(&key).ok_or(ProjectionError::MissingRun)?;
        let prior_sequence = view
            .timeline
            .last()
            .ok_or(ProjectionError::InvalidTransition)?
            .sequence;
        if seq != prior_sequence + 1 {
            return Err(ProjectionError::SequenceGap);
        }
        if matches!(
            view.phase,
            ProjectedPhase::Cancelled | ProjectedPhase::Sealed
        ) {
            return Err(ProjectionError::TerminalRun);
        }
        let (phase, fact, inputs) = match &event.payload {
            Payload::RunInputsBound { inputs } if view.phase == ProjectedPhase::Created => (
                ProjectedPhase::InputsBound,
                "run_inputs_bound",
                Some(inputs.clone()),
            ),
            Payload::BaselineRequested { .. } if view.phase == ProjectedPhase::InputsBound => {
                (ProjectedPhase::BaselinePending, "baseline_requested", None)
            }
            Payload::ProposalRequested { .. } if view.phase == ProjectedPhase::BaselinePending => {
                (ProjectedPhase::ProposalPending, "proposal_requested", None)
            }
            Payload::AssessmentRequested { .. }
                if view.phase == ProjectedPhase::ProposalPending =>
            {
                (
                    ProjectedPhase::AssessmentPending,
                    "assessment_requested",
                    None,
                )
            }
            Payload::EvidenceRequested { .. }
                if view.phase == ProjectedPhase::AssessmentPending =>
            {
                (ProjectedPhase::EvidencePending, "evidence_requested", None)
            }
            Payload::RunCancelled { .. } => (ProjectedPhase::Cancelled, "run_cancelled", None),
            Payload::RunRecordSealed { .. } if view.phase == ProjectedPhase::EvidencePending => {
                (ProjectedPhase::Sealed, "run_record_sealed", None)
            }
            _ => return Err(ProjectionError::InvalidTransition),
        };
        if let Some(i) = inputs {
            view.inputs = Some(i);
        }
        view.phase = phase;
        view.timeline.push(TimelineEntry {
            sequence: seq,
            fact,
            observed_at_ms,
        });
        self.applied.insert(ek, event);
        Ok(())
    }
    /// Exact-tenant lookup.
    #[must_use]
    pub fn get(&self, org: &OrganizationId, run: &ContextQualifiedId) -> Option<&RunView> {
        self.runs.get(&(org.clone(), run.clone()))
    }
    /// Pending steps older than threshold for one tenant.
    #[must_use]
    pub fn stuck_steps(
        &self,
        org: &OrganizationId,
        now_ms: u64,
        threshold_ms: u64,
    ) -> Vec<StuckStep> {
        self.runs
            .values()
            .filter(|v| {
                &v.organization_id == org
                    && matches!(
                        v.phase,
                        ProjectedPhase::BaselinePending
                            | ProjectedPhase::ProposalPending
                            | ProjectedPhase::AssessmentPending
                            | ProjectedPhase::EvidencePending
                    )
            })
            .filter_map(|v| {
                let age_ms = now_ms.saturating_sub(v.timeline.last()?.observed_at_ms);
                (age_ms >= threshold_ms).then(|| StuckStep {
                    organization_id: v.organization_id.clone(),
                    run_id: v.run_id.clone(),
                    phase: v.phase,
                    age_ms,
                })
            })
            .collect()
    }
    /// Replays an ordered durable stream into a fresh projection.
    ///
    /// # Errors
    ///
    /// Returns the first ordering, replay, terminal, or transition error in
    /// the supplied stream without returning a partially rebuilt projection.
    pub fn rebuild(
        events: impl IntoIterator<Item = (RemediationRunEventV1, u64)>,
    ) -> Result<Self, ProjectionError> {
        let mut p = Self::default();
        for (e, t) in events {
            p.apply(e, t)?;
        }
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::{CONTRACT_VERSION, ConformanceModeV1, EVENT_SCHEMA_NAME};
    use cauterizer_syntax::digest::Sha256Digest;
    use cauterizer_syntax::identifiers::{AggregateSequence, CausationId, CorrelationId};
    use cauterizer_syntax::schema::{SchemaName, SchemaVersion};
    use cauterizer_syntax::time::UtcInstant;

    fn event(org: &str, sequence: u64, payload: Payload) -> RemediationRunEventV1 {
        RemediationRunEventV1 {
            schema_name: SchemaName::parse(EVENT_SCHEMA_NAME).unwrap(),
            schema_version: SchemaVersion::parse(CONTRACT_VERSION).unwrap(),
            organization_id: OrganizationId::new(org).unwrap(),
            run_id: "run_00000000".parse().unwrap(),
            aggregate_sequence: AggregateSequence::new(sequence).unwrap(),
            event_id: format!("event_{sequence:08}").parse().unwrap(),
            occurred_at: UtcInstant::parse("2026-07-23T00:00:00Z").unwrap(),
            correlation_id: CorrelationId::new("00000000").unwrap(),
            causation_id: CausationId::new("00000000").unwrap(),
            payload,
        }
    }
    fn inputs() -> RunInputsV1 {
        RunInputsV1 {
            advisory_snapshot_id: "advisory-snapshot_00000000".parse().unwrap(),
            advisory_snapshot_digest: Sha256Digest::of_bytes(b"advisory"),
            target_resolution_id: "resolution_00000000".parse().unwrap(),
            acquisition_artifact_digest: Sha256Digest::of_bytes(b"target"),
            policy_version: SchemaVersion::parse("1.0.0").unwrap(),
            conformance_mode: ConformanceModeV1::Conformant,
            budget_reservation_id: "reservation_00000000".parse().unwrap(),
        }
    }
    fn pending_stream(org: &str) -> Vec<(RemediationRunEventV1, u64)> {
        vec![
            (event(org, 1, Payload::RemediationRunCreated), 10),
            (
                event(org, 2, Payload::RunInputsBound { inputs: inputs() }),
                20,
            ),
            (
                event(
                    org,
                    3,
                    Payload::BaselineRequested {
                        request_id: "baseline-request_00000000".parse().unwrap(),
                    },
                ),
                30,
            ),
        ]
    }

    #[test]
    fn rebuild_is_deterministic_tenant_scoped_and_timeline_complete() {
        let stream = pending_stream("00000000");
        let first = RunProjection::rebuild(stream.clone()).unwrap();
        let second = RunProjection::rebuild(stream).unwrap();
        let run: ContextQualifiedId = "run_00000000".parse().unwrap();
        assert_eq!(
            first.get(&OrganizationId::new("00000000").unwrap(), &run),
            second.get(&OrganizationId::new("00000000").unwrap(), &run)
        );
        let view = first
            .get(&OrganizationId::new("00000000").unwrap(), &run)
            .unwrap();
        assert_eq!(view.phase, ProjectedPhase::BaselinePending);
        assert_eq!(
            view.timeline.iter().map(|e| e.sequence).collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert!(
            first
                .get(&OrganizationId::new("11111111").unwrap(), &run)
                .is_none()
        );
    }

    #[test]
    fn stuck_queries_are_tenant_safe_and_replays_do_not_duplicate_timeline() {
        let stream = pending_stream("00000000");
        let mut projection = RunProjection::rebuild(stream.clone()).unwrap();
        projection.apply(stream[2].0.clone(), stream[2].1).unwrap();
        let run: ContextQualifiedId = "run_00000000".parse().unwrap();
        assert_eq!(
            projection
                .get(&OrganizationId::new("00000000").unwrap(), &run)
                .unwrap()
                .timeline
                .len(),
            3
        );
        let stuck = projection.stuck_steps(&OrganizationId::new("00000000").unwrap(), 130, 100);
        assert_eq!(stuck.len(), 1);
        assert_eq!(stuck[0].phase, ProjectedPhase::BaselinePending);
        assert!(
            projection
                .stuck_steps(&OrganizationId::new("11111111").unwrap(), 130, 100)
                .is_empty()
        );
    }

    #[test]
    fn gaps_conflicts_and_terminal_advancement_fail_closed() {
        let mut projection = RunProjection::default();
        projection
            .apply(event("00000000", 1, Payload::RemediationRunCreated), 1)
            .unwrap();
        assert_eq!(
            projection.apply(
                event("00000000", 3, Payload::RunInputsBound { inputs: inputs() }),
                2
            ),
            Err(ProjectionError::SequenceGap)
        );
        projection
            .apply(
                event(
                    "00000000",
                    2,
                    Payload::RunCancelled {
                        reason_code: "operator_cancelled".into(),
                    },
                ),
                2,
            )
            .unwrap();
        assert_eq!(
            projection.apply(
                event(
                    "00000000",
                    3,
                    Payload::BaselineRequested {
                        request_id: "baseline-request_00000000".parse().unwrap()
                    }
                ),
                3
            ),
            Err(ProjectionError::TerminalRun)
        );
    }
}
