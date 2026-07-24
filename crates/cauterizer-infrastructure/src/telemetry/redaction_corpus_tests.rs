//! Redaction corpus: adversarial proof that attempted leaks of
//! confidential/restricted-security content can never reach a constructed
//! [`TelemetryEvent`] -- or its serialized form -- as raw text.
//!
//! Each corpus entry mimics a real leak vector named across the platform's
//! abuse-case matrix: raw key material (AC-021), a raw local source path
//! (AC-024's "absolute paths"), and a raw tenant prompt (AC-024's
//! "prompts"). Every entry is run through both [`classified_detail`] and the
//! full [`TelemetryEvent`] builder, and the assertions check the actual
//! serialized JSON, not just the typed value, so a future change to
//! `Serialize` cannot quietly reopen the leak.
//!
//! This module also documents, in its own history, that the guard is load
//! bearing: during development the `Confidential`/`RestrictedSecurity` arm
//! of [`classified_detail`] was temporarily changed to keep raw text (the
//! same behavior as the `Public`/`Internal` arm), and
//! `confidential_and_restricted_values_never_reach_event_output_as_text`
//! failed immediately and unambiguously (`assertion failed: DetailReference
//! ... leaked as text-shaped output`) before the guard was restored.

use crate::telemetry::event::{
    BoundedContext, DetailReference, Outcome, ReasonCode, TelemetryEvent, TelemetryEventKind,
    classified_detail,
};
use cauterizer_syntax::classification::DataClass;
use cauterizer_syntax::sensitive::Sensitive;

struct LeakAttempt {
    label: &'static str,
    class: DataClass,
    raw: &'static str,
}

fn corpus() -> Vec<LeakAttempt> {
    vec![
        LeakAttempt {
            label: "raw_api_secret_bytes",
            class: DataClass::RestrictedSecurity,
            raw: "sk_live_do-not-leak-9f8e7d6c5b4a3210",
        },
        LeakAttempt {
            label: "raw_signing_key_material",
            class: DataClass::RestrictedSecurity,
            raw: "-----BEGIN PRIVATE KEY----- do-not-leak-either -----END PRIVATE KEY-----",
        },
        LeakAttempt {
            label: "raw_local_source_path",
            class: DataClass::Confidential,
            raw: "/home/tenant-acme/src/internal/payment_engine.rs",
        },
        LeakAttempt {
            label: "raw_tenant_prompt_text",
            class: DataClass::Confidential,
            raw: "customer's private remediation prompt: patch CVE-2024-1234, db creds=hunter2",
        },
        LeakAttempt {
            label: "raw_verifier_restricted_log_line",
            class: DataClass::Confidential,
            raw: "verifier oracle: candidate failed hidden test case #17 with input 'admin:admin'",
        },
    ]
}

#[test]
fn confidential_and_restricted_values_never_reach_event_output_as_text() {
    for attempt in corpus() {
        let raw = Sensitive::new(attempt.raw.to_owned());

        let detail = classified_detail(attempt.class, &raw);
        assert!(
            matches!(detail, DetailReference::Digest(_)),
            "{}: DetailReference {detail:?} leaked as text-shaped output",
            attempt.label,
        );

        let event = TelemetryEvent::new(
            TelemetryEventKind::SecretRedactionDetected,
            BoundedContext::IntegrationManagement,
            Outcome::Denied,
            ReasonCode::SecretPatternMatched,
            0,
        )
        .with_classified_detail(attempt.class, &raw);

        let serialized = serde_json::to_string(&event).unwrap();
        assert!(
            !serialized.contains(attempt.raw),
            "{}: raw plaintext appeared in serialized telemetry event: {serialized}",
            attempt.label,
        );
        // Also guard against trivial substring leaks (e.g. only part of a
        // multi-word secret was hashed away).
        for word in attempt.raw.split_whitespace().filter(|w| w.len() > 4) {
            assert!(
                !serialized.contains(word),
                "{}: fragment {word:?} of the raw value appeared in serialized output",
                attempt.label,
            );
        }
    }
}

#[test]
fn public_and_internal_values_pass_through_as_bounded_text_by_contrast() {
    // Not every classification is refused -- only Confidential/
    // RestrictedSecurity. This contrast case keeps the corpus test from
    // being vacuously true (e.g. if `classified_detail` always returned a
    // digest regardless of class, the corpus test above would still pass
    // for the wrong reason).
    let raw = Sensitive::new("dispatcher_lag_within_bound".to_owned());
    assert_eq!(
        classified_detail(DataClass::Public, &raw),
        DetailReference::Text("dispatcher_lag_within_bound".to_owned())
    );
    let event = TelemetryEvent::new(
        TelemetryEventKind::RequestObserved,
        BoundedContext::RemediationRuns,
        Outcome::Success,
        ReasonCode::RequestSucceeded,
        0,
    )
    .with_classified_detail(DataClass::Internal, &raw);
    let serialized = serde_json::to_string(&event).unwrap();
    assert!(serialized.contains("dispatcher_lag_within_bound"));
}
