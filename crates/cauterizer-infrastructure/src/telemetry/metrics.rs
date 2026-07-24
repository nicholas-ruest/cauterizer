//! Bounded-dimension RED (rate, errors, duration) metrics.
//!
//! Dimensions are exactly [`BoundedContext`] x [`Outcome`]: a fixed,
//! enumerable set with no tenant-supplied labels, so cardinality cannot grow
//! with tenant volume the way an arbitrary tenant-ID or free-text label
//! would.

use std::collections::BTreeMap;

use super::event::{BoundedContext, Outcome};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct RedKey {
    context: BoundedContext,
    outcome: Outcome,
}

#[derive(Clone, Copy, Debug, Default)]
struct RedCounter {
    count: u64,
    total_duration_millis: u128,
    max_duration_millis: u32,
}

/// Accumulates request-outcome-duration samples over a bounded, closed
/// dimension set.
#[derive(Clone, Debug, Default)]
pub struct RedMetrics {
    counters: BTreeMap<RedKey, RedCounter>,
}

impl RedMetrics {
    /// Creates an empty accumulator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one RED sample for a bounded context/outcome pair.
    pub fn record(&mut self, context: BoundedContext, outcome: Outcome, duration_millis: u32) {
        let counter = self
            .counters
            .entry(RedKey { context, outcome })
            .or_default();
        counter.count += 1;
        counter.total_duration_millis += u128::from(duration_millis);
        counter.max_duration_millis = counter.max_duration_millis.max(duration_millis);
    }

    /// Total sample count (the "rate" numerator) for a context, across all
    /// outcomes.
    #[must_use]
    pub fn rate(&self, context: BoundedContext) -> u64 {
        self.counters
            .iter()
            .filter(|(key, _)| key.context == context)
            .map(|(_, counter)| counter.count)
            .sum()
    }

    /// Count of `Denied` + `Error` samples (the "errors" numerator) for a
    /// context.
    #[must_use]
    pub fn errors(&self, context: BoundedContext) -> u64 {
        [Outcome::Denied, Outcome::Error]
            .into_iter()
            .filter_map(|outcome| self.counters.get(&RedKey { context, outcome }))
            .map(|counter| counter.count)
            .sum()
    }

    /// Mean duration in milliseconds for a context across all outcomes, or
    /// `None` when no samples exist.
    #[must_use]
    pub fn mean_duration_millis(&self, context: BoundedContext) -> Option<f64> {
        let (count, total) = self
            .counters
            .iter()
            .filter(|(key, _)| key.context == context)
            .fold((0_u64, 0_u128), |(count, total), (_, counter)| {
                (count + counter.count, total + counter.total_duration_millis)
            });
        if count == 0 {
            return None;
        }
        #[allow(clippy::cast_precision_loss)]
        Some(total as f64 / count as f64)
    }

    /// Maximum observed duration in milliseconds for a context, or `None`
    /// when no samples exist.
    #[must_use]
    pub fn max_duration_millis(&self, context: BoundedContext) -> Option<u32> {
        self.counters
            .iter()
            .filter(|(key, _)| key.context == context)
            .map(|(_, counter)| counter.max_duration_millis)
            .max()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_and_errors_are_scoped_per_context() {
        let mut metrics = RedMetrics::new();
        metrics.record(BoundedContext::IsolatedExecution, Outcome::Success, 10);
        metrics.record(BoundedContext::IsolatedExecution, Outcome::Error, 20);
        metrics.record(BoundedContext::IsolatedExecution, Outcome::Denied, 5);
        metrics.record(BoundedContext::Evidence, Outcome::Success, 100);

        assert_eq!(metrics.rate(BoundedContext::IsolatedExecution), 3);
        assert_eq!(metrics.errors(BoundedContext::IsolatedExecution), 2);
        assert_eq!(metrics.rate(BoundedContext::Evidence), 1);
        assert_eq!(metrics.errors(BoundedContext::Evidence), 0);
    }

    #[test]
    fn duration_aggregates_are_correct_and_unpopulated_contexts_are_none() {
        let mut metrics = RedMetrics::new();
        metrics.record(BoundedContext::Verification, Outcome::Success, 10);
        metrics.record(BoundedContext::Verification, Outcome::Success, 30);

        assert_eq!(
            metrics.mean_duration_millis(BoundedContext::Verification),
            Some(20.0)
        );
        assert_eq!(
            metrics.max_duration_millis(BoundedContext::Verification),
            Some(30)
        );
        assert_eq!(
            metrics.mean_duration_millis(BoundedContext::ExternalActions),
            None
        );
        assert_eq!(
            metrics.max_duration_millis(BoundedContext::ExternalActions),
            None
        );
    }
}
