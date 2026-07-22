//! Version-neutral cursor, result, and problem envelope primitives.

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

/// Maximum opaque cursor size.
pub const MAX_CURSOR_LENGTH: usize = 512;

/// An opaque URL-safe pagination cursor.
#[derive(Clone, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Cursor(String);

impl Cursor {
    /// Validates a non-empty base64url-compatible opaque cursor.
    ///
    /// # Errors
    ///
    /// Returns an error when the cursor is empty, oversized, or not canonical
    /// base64url-compatible syntax.
    pub fn parse(value: impl Into<String>) -> Result<Self, EnvelopeError> {
        let value = value.into();
        if value.is_empty() {
            return Err(EnvelopeError("cursor must not be empty"));
        }
        if value.len() > MAX_CURSOR_LENGTH {
            return Err(EnvelopeError("cursor exceeds maximum length"));
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'='))
        {
            return Err(EnvelopeError("cursor is not base64url-compatible"));
        }
        if value
            .as_bytes()
            .iter()
            .position(|byte| *byte == b'=')
            .is_some_and(|position| !value[position..].bytes().all(|byte| byte == b'='))
        {
            return Err(EnvelopeError("cursor padding must appear only at the end"));
        }
        if value.bytes().filter(|byte| *byte == b'=').count() > 2 {
            return Err(EnvelopeError("cursor has excessive padding"));
        }
        Ok(Self(value))
    }

    /// Returns the opaque representation without interpreting it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Cursor {
    type Error = EnvelopeError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}
impl From<Cursor> for String {
    fn from(value: Cursor) -> Self {
        value.0
    }
}
impl fmt::Debug for Cursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Cursor([opaque])")
    }
}

/// A cursor-paginated collection response.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page<T> {
    /// Items in deterministic server-selected order.
    pub items: Vec<T>,
    /// Cursor for the next page, absent at the end.
    pub next_cursor: Option<Cursor>,
}

/// A success envelope with optional non-sensitive metadata.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultEnvelope<T> {
    /// Successful response value.
    pub data: T,
}

impl<T> ResultEnvelope<T> {
    /// Wraps successful data.
    #[must_use]
    pub const fn new(data: T) -> Self {
        Self { data }
    }
}

/// Stable, bounded RFC 9457-style problem information.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProblemDetails {
    /// Stable URI identifying the problem class.
    #[serde(rename = "type")]
    pub type_uri: String,
    /// Short human-readable title.
    pub title: String,
    /// HTTP-compatible numeric status.
    pub status: u16,
    /// Stable machine-readable reason code.
    pub reason: String,
    /// Optional bounded safe detail; never a stack trace or sensitive payload.
    pub detail: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProblemDetailsWire {
    #[serde(rename = "type")]
    type_uri: String,
    title: String,
    status: u16,
    reason: String,
    detail: Option<String>,
}

impl<'de> Deserialize<'de> for ProblemDetails {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = ProblemDetailsWire::deserialize(deserializer)?;
        Self::new(
            wire.type_uri,
            wire.title,
            wire.status,
            wire.reason,
            wire.detail,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl ProblemDetails {
    /// Constructs bounded problem details.
    ///
    /// # Errors
    ///
    /// Returns an error when any string is empty, oversized, contains forbidden
    /// control characters, or the status/reason/type syntax is invalid.
    pub fn new(
        type_uri: impl Into<String>,
        title: impl Into<String>,
        status: u16,
        reason: impl Into<String>,
        detail: Option<String>,
    ) -> Result<Self, EnvelopeError> {
        let type_uri = type_uri.into();
        let title = title.into();
        let reason = reason.into();
        bounded(&type_uri, 256, "problem type URI")?;
        bounded(&title, 128, "problem title")?;
        bounded(&reason, 96, "problem reason")?;
        if type_uri.chars().any(char::is_control) || !type_uri.contains(':') {
            return Err(EnvelopeError(
                "problem type must be an absolute URI without control characters",
            ));
        }
        if title.chars().any(char::is_control) {
            return Err(EnvelopeError("problem title contains control characters"));
        }
        if !(100..=599).contains(&status) {
            return Err(EnvelopeError("problem status must be between 100 and 599"));
        }
        if !reason.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        }) {
            return Err(EnvelopeError("problem reason has forbidden characters"));
        }
        if let Some(value) = &detail {
            bounded(value, 1024, "problem detail")?;
            if value.chars().any(char::is_control) {
                return Err(EnvelopeError("problem detail contains control characters"));
            }
        }
        Ok(Self {
            type_uri,
            title,
            status,
            reason,
            detail,
        })
    }
}

/// Envelope syntax validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnvelopeError(&'static str);
impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for EnvelopeError {}

fn bounded(value: &str, max: usize, label: &'static str) -> Result<(), EnvelopeError> {
    if value.is_empty() || value.len() > max || value.trim() != value {
        return Err(EnvelopeError(label));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cursor_is_bounded_opaque_and_redacted_in_debug() {
        let cursor = Cursor::parse("c2VjcmV0").unwrap();
        assert_eq!(format!("{cursor:?}"), "Cursor([opaque])");
        assert!(Cursor::parse("bad+/cursor").is_err());
        assert!(Cursor::parse("x".repeat(MAX_CURSOR_LENGTH + 1)).is_err());
    }
    #[test]
    fn problem_rejects_invalid_status_reason_and_controls() {
        assert!(
            ProblemDetails::new(
                "urn:cauterizer:error",
                "Denied",
                403,
                "authorization.denied",
                None
            )
            .is_ok()
        );
        assert!(ProblemDetails::new("urn:x", "Bad", 999, "bad", None).is_err());
        assert!(ProblemDetails::new("urn:x", "Bad", 400, "Bad Reason", None).is_err());
        assert!(
            ProblemDetails::new("urn:x", "Bad", 400, "bad", Some("stack\ntrace".into())).is_err()
        );
        assert!(
            serde_json::from_str::<ProblemDetails>(
                r#"{"type":"urn:x","title":"Bad","status":999,"reason":"bad","detail":null}"#
            )
            .is_err()
        );
    }
}
