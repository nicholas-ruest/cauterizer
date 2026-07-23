//! In-memory security reference adapters.
use super::ports::{AuditError, AuditFact, AuditSink, AuthorizationDecision, ExecutionAuthorizer};
use cauterizer_syntax::authorization::AuthorizationRequestContext;
use std::sync::{Arc, Mutex};
/// Deny-default configurable authorizer.
#[derive(Clone, Default)]
pub struct InMemoryAuthorizer {
    allowed: Arc<Mutex<bool>>,
}
impl InMemoryAuthorizer {
    /// Sets policy result.
    /// # Panics
    /// Panics only after another thread poisons the lock.
    pub fn set_allowed(&self, value: bool) {
        *self.allowed.lock().expect("authorizer lock poisoned") = value;
    }
}
impl ExecutionAuthorizer for InMemoryAuthorizer {
    fn authorize(&self, _: &AuthorizationRequestContext) -> AuthorizationDecision {
        if *self.allowed.lock().expect("authorizer lock poisoned") {
            AuthorizationDecision::Allow
        } else {
            AuthorizationDecision::Deny
        }
    }
}
/// Append-only audit sink.
#[derive(Clone, Default)]
pub struct InMemoryAuditSink {
    facts: Arc<Mutex<Vec<AuditFact>>>,
}
impl InMemoryAuditSink {
    /// Number of recorded facts.
    /// # Panics
    /// Panics only after another thread poisons the lock.
    #[must_use]
    pub fn len(&self) -> usize {
        self.facts.lock().expect("audit lock poisoned").len()
    }
    /// Whether no facts exist.
    /// # Panics
    /// Panics only after another thread poisons the lock.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl AuditSink for InMemoryAuditSink {
    fn record(&self, fact: AuditFact) -> Result<(), AuditError> {
        self.facts.lock().map_err(|_| AuditError)?.push(fact);
        Ok(())
    }
}
