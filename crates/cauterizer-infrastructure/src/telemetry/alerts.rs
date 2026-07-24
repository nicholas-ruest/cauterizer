//! The ten production alerts named by
//! `docs/architecture/abuse-case-test-matrix.md`'s "Alert and audit linkage"
//! paragraph, implemented as pure, executable checks against a slice of
//! [`TelemetryEvent`].
//!
//! Each alert is either:
//! - **any-occurrence**: a single matching event is itself the security
//!   signal (capability misuse, sandbox egress, cleanup failure,
//!   verifier-store access by a solver, a secret-redaction detection,
//!   break-glass use, an event authentication failure, an export
//!   authorization failure); or
//! - **threshold-based**: only a *repeated* or *spiking* volume is the
//!   signal, matching the paragraph's own wording ("repeated
//!   cross-organization denials", "signer-policy denial spikes"), so a
//!   single denial does not fire and does not page anyone.
//!
//! Every function is deliberately pure (`&[TelemetryEvent] -> bool`) so a
//! caller can evaluate it against any window: the in-memory sink's buffer, a
//! batch read back from the local file sink, or a synthetic test fixture.

use std::collections::BTreeMap;

use cauterizer_syntax::identifiers::{IdentityRef, OrganizationId};

use super::event::{TelemetryEvent, TelemetryEventKind};

/// A repeated cross-organization denial alert fires once the same
/// actor/organization pair accumulates at least this many denials.
pub const CROSS_ORGANIZATION_DENIAL_REPEAT_THRESHOLD: usize = 3;

/// A signer-policy denial spike alert fires once total denials in the
/// evaluated window reach this count.
pub const SIGNER_POLICY_DENIAL_SPIKE_THRESHOLD: usize = 5;

/// Stable identifiers for the ten alerts, for reporting/attachment to audit
/// records (mirrors the plan doc's "attach alert identifiers").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlertId {
    /// Repeated cross-organization denials.
    RepeatedCrossOrganizationDenials,
    /// Capability misuse.
    CapabilityMisuse,
    /// Sandbox egress attempts.
    SandboxEgressAttempts,
    /// Cleanup failures.
    CleanupFailures,
    /// Verifier-store access by a solver identity.
    VerifierStoreSolverAccess,
    /// Signer-policy denial spikes.
    SignerPolicyDenialSpikes,
    /// Secret-redaction detections.
    SecretRedactionDetections,
    /// Break-glass use.
    BreakGlassUse,
    /// Event authentication failures.
    EventAuthenticationFailures,
    /// Export authorization failures.
    ExportAuthorizationFailures,
}

fn any_kind(events: &[TelemetryEvent], kind: TelemetryEventKind) -> bool {
    events.iter().any(|event| event.kind == kind)
}

fn count_kind(events: &[TelemetryEvent], kind: TelemetryEventKind) -> usize {
    events.iter().filter(|event| event.kind == kind).count()
}

/// Largest per-(organization, actor) occurrence count of `kind` in `events`.
fn max_group_count(events: &[TelemetryEvent], kind: TelemetryEventKind) -> usize {
    let mut counts: BTreeMap<(Option<OrganizationId>, Option<IdentityRef>), usize> =
        BTreeMap::new();
    for event in events.iter().filter(|event| event.kind == kind) {
        *counts
            .entry((event.organization_id.clone(), event.actor.clone()))
            .or_insert(0) += 1;
    }
    counts.values().copied().max().unwrap_or(0)
}

/// Repeated cross-organization denials: the same actor/organization pair
/// was denied at least [`CROSS_ORGANIZATION_DENIAL_REPEAT_THRESHOLD`] times.
#[must_use]
pub fn repeated_cross_organization_denials(events: &[TelemetryEvent]) -> bool {
    max_group_count(events, TelemetryEventKind::CrossOrganizationDenial)
        >= CROSS_ORGANIZATION_DENIAL_REPEAT_THRESHOLD
}

/// Capability misuse: any occurrence fires.
#[must_use]
pub fn capability_misuse(events: &[TelemetryEvent]) -> bool {
    any_kind(events, TelemetryEventKind::CapabilityMisuse)
}

/// Sandbox egress attempts: any occurrence fires.
#[must_use]
pub fn sandbox_egress_attempts(events: &[TelemetryEvent]) -> bool {
    any_kind(events, TelemetryEventKind::SandboxEgressAttempt)
}

/// Cleanup failures: any occurrence fires.
#[must_use]
pub fn cleanup_failures(events: &[TelemetryEvent]) -> bool {
    any_kind(events, TelemetryEventKind::CleanupFailure)
}

/// Verifier-store access by a solver identity: any occurrence fires.
#[must_use]
pub fn verifier_store_solver_access(events: &[TelemetryEvent]) -> bool {
    any_kind(events, TelemetryEventKind::VerifierStoreSolverAccess)
}

/// Signer-policy denial spikes: total denials reach
/// [`SIGNER_POLICY_DENIAL_SPIKE_THRESHOLD`] within the evaluated window.
#[must_use]
pub fn signer_policy_denial_spikes(events: &[TelemetryEvent]) -> bool {
    count_kind(events, TelemetryEventKind::SignerPolicyDenial)
        >= SIGNER_POLICY_DENIAL_SPIKE_THRESHOLD
}

/// Secret-redaction detections: any occurrence fires.
#[must_use]
pub fn secret_redaction_detections(events: &[TelemetryEvent]) -> bool {
    any_kind(events, TelemetryEventKind::SecretRedactionDetected)
}

/// Break-glass use: any occurrence fires.
#[must_use]
pub fn break_glass_use(events: &[TelemetryEvent]) -> bool {
    any_kind(events, TelemetryEventKind::BreakGlassUse)
}

/// Event authentication failures: any occurrence fires.
#[must_use]
pub fn event_authentication_failures(events: &[TelemetryEvent]) -> bool {
    any_kind(events, TelemetryEventKind::EventAuthenticationFailure)
}

/// Export authorization failures: any occurrence fires.
#[must_use]
pub fn export_authorization_failures(events: &[TelemetryEvent]) -> bool {
    any_kind(events, TelemetryEventKind::ExportAuthorizationFailure)
}

/// One alert's pure check function paired with its stable identifier.
type AlertCheck = (fn(&[TelemetryEvent]) -> bool, AlertId);

/// Evaluates all ten alerts and returns the identifiers of the ones that
/// fire, in the fixed order documented on [`AlertId`].
#[must_use]
pub fn evaluate_all(events: &[TelemetryEvent]) -> Vec<AlertId> {
    let checks: [AlertCheck; 10] = [
        (
            repeated_cross_organization_denials,
            AlertId::RepeatedCrossOrganizationDenials,
        ),
        (capability_misuse, AlertId::CapabilityMisuse),
        (sandbox_egress_attempts, AlertId::SandboxEgressAttempts),
        (cleanup_failures, AlertId::CleanupFailures),
        (
            verifier_store_solver_access,
            AlertId::VerifierStoreSolverAccess,
        ),
        (
            signer_policy_denial_spikes,
            AlertId::SignerPolicyDenialSpikes,
        ),
        (
            secret_redaction_detections,
            AlertId::SecretRedactionDetections,
        ),
        (break_glass_use, AlertId::BreakGlassUse),
        (
            event_authentication_failures,
            AlertId::EventAuthenticationFailures,
        ),
        (
            export_authorization_failures,
            AlertId::ExportAuthorizationFailures,
        ),
    ];
    checks
        .into_iter()
        .filter_map(|(check, id)| check(events).then_some(id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::event::{BoundedContext, Outcome, ReasonCode};
    use cauterizer_syntax::identifiers::ActorId;

    fn organization(opaque: &str) -> OrganizationId {
        OrganizationId::new(opaque).unwrap()
    }

    fn actor(opaque: &str) -> IdentityRef {
        IdentityRef::Human(ActorId::new(opaque).unwrap())
    }

    fn event(kind: TelemetryEventKind, context: BoundedContext, at: u64) -> TelemetryEvent {
        TelemetryEvent::new(
            kind,
            context,
            Outcome::Denied,
            ReasonCode::TenantMismatch,
            at,
        )
    }

    /// A handful of ordinary, successful requests: the baseline every alert
    /// test's "quiet traffic" sample is built from.
    fn quiet_traffic() -> Vec<TelemetryEvent> {
        (0..5_u64)
            .map(|index| {
                TelemetryEvent::new(
                    TelemetryEventKind::RequestObserved,
                    BoundedContext::RemediationRuns,
                    Outcome::Success,
                    ReasonCode::RequestSucceeded,
                    index * 1_000,
                )
                .with_organization(organization("quietorg1"))
                .with_actor(actor("quietuser"))
                .with_duration_millis(20)
            })
            .collect()
    }

    #[test]
    fn repeated_cross_organization_denials_fires_on_repeat_and_not_on_quiet_traffic() {
        let mut quiet = quiet_traffic();
        // One isolated denial is not a repeat.
        quiet.push(
            event(
                TelemetryEventKind::CrossOrganizationDenial,
                BoundedContext::OrganizationAccess,
                6_000,
            )
            .with_organization(organization("victimorg1"))
            .with_actor(actor("attacker1")),
        );
        assert!(!repeated_cross_organization_denials(&quiet));

        let mut trigger = quiet_traffic();
        for at in 0..CROSS_ORGANIZATION_DENIAL_REPEAT_THRESHOLD {
            trigger.push(
                event(
                    TelemetryEventKind::CrossOrganizationDenial,
                    BoundedContext::OrganizationAccess,
                    7_000 + at as u64,
                )
                .with_organization(organization("victimorg1"))
                .with_actor(actor("attacker1")),
            );
        }
        assert!(repeated_cross_organization_denials(&trigger));
    }

    #[test]
    fn capability_misuse_fires_on_any_occurrence_and_not_on_quiet_traffic() {
        let quiet = quiet_traffic();
        assert!(!capability_misuse(&quiet));

        let mut trigger = quiet_traffic();
        trigger.push(event(
            TelemetryEventKind::CapabilityMisuse,
            BoundedContext::IsolatedExecution,
            9_000,
        ));
        assert!(capability_misuse(&trigger));
    }

    #[test]
    fn sandbox_egress_attempts_fires_on_any_occurrence_and_not_on_quiet_traffic() {
        let quiet = quiet_traffic();
        assert!(!sandbox_egress_attempts(&quiet));

        let mut trigger = quiet_traffic();
        trigger.push(event(
            TelemetryEventKind::SandboxEgressAttempt,
            BoundedContext::IsolatedExecution,
            9_000,
        ));
        assert!(sandbox_egress_attempts(&trigger));
    }

    #[test]
    fn cleanup_failures_fires_on_any_occurrence_and_not_on_quiet_traffic() {
        let quiet = quiet_traffic();
        assert!(!cleanup_failures(&quiet));

        let mut trigger = quiet_traffic();
        trigger.push(event(
            TelemetryEventKind::CleanupFailure,
            BoundedContext::IsolatedExecution,
            9_000,
        ));
        assert!(cleanup_failures(&trigger));
    }

    #[test]
    fn verifier_store_solver_access_fires_on_any_occurrence_and_not_on_quiet_traffic() {
        let quiet = quiet_traffic();
        assert!(!verifier_store_solver_access(&quiet));

        let mut trigger = quiet_traffic();
        trigger.push(event(
            TelemetryEventKind::VerifierStoreSolverAccess,
            BoundedContext::Verification,
            9_000,
        ));
        assert!(verifier_store_solver_access(&trigger));
    }

    #[test]
    fn signer_policy_denial_spikes_fires_on_spike_and_not_on_a_lone_denial() {
        let mut quiet = quiet_traffic();
        quiet.push(event(
            TelemetryEventKind::SignerPolicyDenial,
            BoundedContext::Evidence,
            9_000,
        ));
        assert!(!signer_policy_denial_spikes(&quiet));

        let mut trigger = quiet_traffic();
        for at in 0..SIGNER_POLICY_DENIAL_SPIKE_THRESHOLD {
            trigger.push(event(
                TelemetryEventKind::SignerPolicyDenial,
                BoundedContext::Evidence,
                9_000 + at as u64,
            ));
        }
        assert!(signer_policy_denial_spikes(&trigger));
    }

    #[test]
    fn secret_redaction_detections_fires_on_any_occurrence_and_not_on_quiet_traffic() {
        let quiet = quiet_traffic();
        assert!(!secret_redaction_detections(&quiet));

        let mut trigger = quiet_traffic();
        trigger.push(event(
            TelemetryEventKind::SecretRedactionDetected,
            BoundedContext::IntegrationManagement,
            9_000,
        ));
        assert!(secret_redaction_detections(&trigger));
    }

    #[test]
    fn break_glass_use_fires_on_any_occurrence_and_not_on_quiet_traffic() {
        let quiet = quiet_traffic();
        assert!(!break_glass_use(&quiet));

        let mut trigger = quiet_traffic();
        trigger.push(event(
            TelemetryEventKind::BreakGlassUse,
            BoundedContext::OrganizationAccess,
            9_000,
        ));
        assert!(break_glass_use(&trigger));
    }

    #[test]
    fn event_authentication_failures_fires_on_any_occurrence_and_not_on_quiet_traffic() {
        let quiet = quiet_traffic();
        assert!(!event_authentication_failures(&quiet));

        let mut trigger = quiet_traffic();
        trigger.push(event(
            TelemetryEventKind::EventAuthenticationFailure,
            BoundedContext::RemediationRuns,
            9_000,
        ));
        assert!(event_authentication_failures(&trigger));
    }

    #[test]
    fn export_authorization_failures_fires_on_any_occurrence_and_not_on_quiet_traffic() {
        let quiet = quiet_traffic();
        assert!(!export_authorization_failures(&quiet));

        let mut trigger = quiet_traffic();
        trigger.push(event(
            TelemetryEventKind::ExportAuthorizationFailure,
            BoundedContext::ExternalActions,
            9_000,
        ));
        assert!(export_authorization_failures(&trigger));
    }

    #[test]
    fn evaluate_all_reports_every_fired_alert_and_nothing_on_quiet_traffic() {
        assert!(evaluate_all(&quiet_traffic()).is_empty());

        let mut trigger = quiet_traffic();
        trigger.push(event(
            TelemetryEventKind::BreakGlassUse,
            BoundedContext::OrganizationAccess,
            9_000,
        ));
        trigger.push(event(
            TelemetryEventKind::ExportAuthorizationFailure,
            BoundedContext::ExternalActions,
            9_500,
        ));
        let fired = evaluate_all(&trigger);
        assert_eq!(fired.len(), 2);
        assert!(fired.contains(&AlertId::BreakGlassUse));
        assert!(fired.contains(&AlertId::ExportAuthorizationFailures));
    }
}
