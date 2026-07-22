//! Explicit redaction wrapper for sensitive values.

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Serialize, Serializer};
use std::fmt;

const REDACTED: &str = "[REDACTED]";

/// A value that cannot leak through `Debug`, `Display`, or Serde serialization.
///
/// Access is deliberately explicit. This wrapper reduces accidental disclosure;
/// it is not secret memory and does not promise zeroization.
#[derive(Clone, Eq, PartialEq)]
pub struct Sensitive<T>(T);

impl<T> Sensitive<T> {
    /// Wraps a sensitive value.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Explicitly borrows the underlying value at a reviewed use site.
    #[must_use]
    pub const fn expose_sensitive(&self) -> &T {
        &self.0
    }

    /// Explicitly consumes the wrapper and returns the value.
    #[must_use]
    pub fn into_sensitive(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sensitive([REDACTED])")
    }
}
impl<T> fmt::Display for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}
impl<T> Serialize for Sensitive<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(REDACTED)
    }
}

impl<T> JsonSchema for Sensitive<T> {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "SensitiveRedacted".into()
    }
    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        <String>::json_schema(generator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_common_formatters_redact() {
        let value = Sensitive::new("do-not-leak".to_owned());
        assert_eq!(format!("{value}"), REDACTED);
        assert_eq!(format!("{value:?}"), "Sensitive([REDACTED])");
        assert_eq!(serde_json::to_string(&value).unwrap(), "\"[REDACTED]\"");
        assert!(!format!("{value:?}").contains(value.expose_sensitive()));
    }
}
