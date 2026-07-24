//! Deterministic, network-free test double for [`crate::transport::HttpFetchPort`].
//!
//! No test in this crate (or any consumer) performs real network I/O: every
//! test injects [`ScriptedHttpFetchPort`] in place of a `reqwest`-backed
//! transport.

use crate::transport::{FetchOutcome, HttpFetchPort, TransportError};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

type Script = Result<FetchOutcome, TransportError>;

#[derive(Default)]
struct State {
    scripts: BTreeMap<String, VecDeque<Script>>,
    calls: Vec<String>,
}

/// A scripted transport: each call to [`HttpFetchPort::get`] pops the next
/// queued response for that exact URL, in the order it was queued.
#[derive(Clone, Default)]
pub struct ScriptedHttpFetchPort {
    state: Arc<Mutex<State>>,
}
impl ScriptedHttpFetchPort {
    /// Creates an empty scripted transport.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Queues one scripted response or transport error for `url`.
    ///
    /// # Panics
    /// Panics only when another thread poisoned the reference lock.
    pub fn queue(&self, url: impl Into<String>, outcome: Script) {
        self.state
            .lock()
            .expect("scripted transport lock poisoned")
            .scripts
            .entry(url.into())
            .or_default()
            .push_back(outcome);
    }
    /// Returns every URL requested, in call order.
    ///
    /// # Panics
    /// Panics only when another thread poisoned the reference lock.
    #[must_use]
    pub fn calls(&self) -> Vec<String> {
        self.state
            .lock()
            .expect("scripted transport lock poisoned")
            .calls
            .clone()
    }
}
impl HttpFetchPort for ScriptedHttpFetchPort {
    fn get(&self, url: &str) -> Result<FetchOutcome, TransportError> {
        let mut state = self.state.lock().expect("scripted transport lock poisoned");
        state.calls.push(url.to_owned());
        state
            .scripts
            .get_mut(url)
            .and_then(VecDeque::pop_front)
            .unwrap_or(Err(TransportError::Unavailable))
    }
}
