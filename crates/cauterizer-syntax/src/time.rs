//! Canonical, timezone-independent time syntax.

use core::fmt;
use core::str::FromStr;
use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// Maximum duration accepted at a platform contract boundary: seven days.
pub const MAX_DURATION_MILLIS: u64 = 7 * 24 * 60 * 60 * 1_000;

/// A canonical RFC 3339 UTC instant.
///
/// Only `YYYY-MM-DDTHH:MM:SS[.fraction]Z` is accepted. Offsets, spaces, leap
/// seconds, lowercase separators, and fractional trailing zeroes are rejected so
/// equal instants have one wire representation. Fractional precision is limited
/// to nanoseconds.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, JsonSchema)]
#[schemars(transparent)]
pub struct UtcInstant(String);

impl UtcInstant {
    /// Parses and validates a canonical UTC instant.
    ///
    /// # Errors
    ///
    /// Returns [`TimeSyntaxError::InvalidInstant`] unless the value has the one
    /// canonical representation documented on [`UtcInstant`].
    pub fn parse(value: impl Into<String>) -> Result<Self, TimeSyntaxError> {
        let value = value.into();
        validate_instant(&value)?;
        Ok(Self(value))
    }

    /// Returns the canonical wire representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the instant and returns its canonical wire representation.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for UtcInstant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for UtcInstant {
    type Err = TimeSyntaxError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for UtcInstant {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for UtcInstant {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

/// A non-zero, millisecond-precision duration bounded for platform contracts.
///
/// The JSON representation is an integer number of milliseconds. Domain code
/// may impose a tighter limit, but no shared contract can exceed seven days.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct BoundedDuration(u64);

impl BoundedDuration {
    /// Creates a duration when it is in `1..=MAX_DURATION_MILLIS`.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or a value above [`MAX_DURATION_MILLIS`].
    pub const fn from_millis(milliseconds: u64) -> Result<Self, TimeSyntaxError> {
        if milliseconds == 0 {
            return Err(TimeSyntaxError::ZeroDuration);
        }
        if milliseconds > MAX_DURATION_MILLIS {
            return Err(TimeSyntaxError::DurationTooLarge {
                actual: milliseconds,
                maximum: MAX_DURATION_MILLIS,
            });
        }
        Ok(Self(milliseconds))
    }

    /// Returns the exact number of milliseconds.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Converts to the standard library duration type without loss.
    #[must_use]
    pub const fn as_std(self) -> Duration {
        Duration::from_millis(self.0)
    }
}

impl TryFrom<Duration> for BoundedDuration {
    type Error = TimeSyntaxError;

    fn try_from(value: Duration) -> Result<Self, Self::Error> {
        let milliseconds =
            u64::try_from(value.as_millis()).map_err(|_| TimeSyntaxError::DurationTooLarge {
                actual: u64::MAX,
                maximum: MAX_DURATION_MILLIS,
            })?;
        if Duration::from_millis(milliseconds) != value {
            return Err(TimeSyntaxError::SubMillisecondDuration);
        }
        Self::from_millis(milliseconds)
    }
}

impl<'de> Deserialize<'de> for BoundedDuration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::from_millis(value).map_err(de::Error::custom)
    }
}

/// Validation failure for canonical time syntax.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TimeSyntaxError {
    /// The instant is not in canonical UTC RFC 3339 form.
    InvalidInstant,
    /// Zero is not a useful deadline or resource budget.
    ZeroDuration,
    /// The duration includes precision that the wire format cannot preserve.
    SubMillisecondDuration,
    /// The duration exceeds the platform-wide contract maximum.
    DurationTooLarge {
        /// Rejected duration in milliseconds.
        actual: u64,
        /// Largest permitted duration in milliseconds.
        maximum: u64,
    },
}

impl fmt::Display for TimeSyntaxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInstant => formatter.write_str("instant is not canonical RFC 3339 UTC"),
            Self::ZeroDuration => formatter.write_str("duration must be non-zero"),
            Self::SubMillisecondDuration => {
                formatter.write_str("duration must have exact millisecond precision")
            }
            Self::DurationTooLarge { actual, maximum } => {
                write!(formatter, "duration {actual}ms exceeds maximum {maximum}ms")
            }
        }
    }
}

impl std::error::Error for TimeSyntaxError {}

fn validate_instant(value: &str) -> Result<(), TimeSyntaxError> {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
        || bytes.last() != Some(&b'Z')
    {
        return Err(TimeSyntaxError::InvalidInstant);
    }

    for index in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18] {
        if !bytes[index].is_ascii_digit() {
            return Err(TimeSyntaxError::InvalidInstant);
        }
    }

    let year = decimal(bytes, 0, 4);
    let month = decimal(bytes, 5, 7);
    let day = decimal(bytes, 8, 10);
    let hour = decimal(bytes, 11, 13);
    let minute = decimal(bytes, 14, 16);
    let second = decimal(bytes, 17, 19);

    if year == 0
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(TimeSyntaxError::InvalidInstant);
    }

    match bytes.get(19) {
        Some(b'Z') if bytes.len() == 20 => Ok(()),
        Some(b'.') => {
            let fraction = &bytes[20..bytes.len() - 1];
            if fraction.is_empty()
                || fraction.len() > 9
                || !fraction.iter().all(u8::is_ascii_digit)
                || fraction.last() == Some(&b'0')
            {
                Err(TimeSyntaxError::InvalidInstant)
            } else {
                Ok(())
            }
        }
        _ => Err(TimeSyntaxError::InvalidInstant),
    }
}

fn decimal(bytes: &[u8], start: usize, end: usize) -> u32 {
    bytes[start..end]
        .iter()
        .fold(0, |value, digit| value * 10 + u32::from(digit - b'0'))
}

const fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

const fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_canonical_instants() {
        for value in [
            "2024-02-29T00:00:00Z",
            "2026-07-22T23:59:59.123456789Z",
            "2000-02-29T12:30:45.1Z",
        ] {
            assert_eq!(UtcInstant::parse(value).expect("valid").as_str(), value);
        }
    }

    #[test]
    fn rejects_noncanonical_or_invalid_instants() {
        for value in [
            "2023-02-29T00:00:00Z",
            "2024-01-01t00:00:00z",
            "2024-01-01T00:00:00+00:00",
            "2024-01-01 00:00:00Z",
            "2024-01-01T00:00:60Z",
            "2024-01-01T00:00:00.120Z",
            "0000-01-01T00:00:00Z",
        ] {
            assert_eq!(
                UtcInstant::parse(value),
                Err(TimeSyntaxError::InvalidInstant)
            );
        }
    }

    #[test]
    fn duration_bounds_and_precision_are_enforced() {
        assert_eq!(
            BoundedDuration::from_millis(1).expect("valid").as_millis(),
            1
        );
        assert_eq!(
            BoundedDuration::from_millis(0),
            Err(TimeSyntaxError::ZeroDuration)
        );
        assert!(BoundedDuration::from_millis(MAX_DURATION_MILLIS + 1).is_err());
        assert_eq!(
            BoundedDuration::try_from(Duration::from_nanos(1)),
            Err(TimeSyntaxError::SubMillisecondDuration)
        );
    }

    #[test]
    fn serde_uses_canonical_string_and_integer_forms() {
        let instant = UtcInstant::parse("2026-07-22T01:02:03.4Z").expect("valid");
        assert_eq!(
            serde_json::to_string(&instant).expect("serialize"),
            "\"2026-07-22T01:02:03.4Z\""
        );
        let duration = BoundedDuration::from_millis(250).expect("valid");
        assert_eq!(serde_json::to_string(&duration).expect("serialize"), "250");
    }
}
