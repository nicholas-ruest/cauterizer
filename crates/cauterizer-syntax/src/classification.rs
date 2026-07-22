//! Data classification, residency, and retention syntax.

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::num::NonZeroU32;

/// Platform-wide data sensitivity labels ordered from least to most sensitive.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    /// Information approved for public disclosure.
    Public,
    /// Non-public operational metadata with low disclosure impact.
    Internal,
    /// Organization-private business or source information.
    Confidential,
    /// Security-sensitive data requiring the strongest payload controls.
    RestrictedSecurity,
}

/// An opaque deployment region code with strict portable syntax.
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(try_from = "String", into = "String")]
pub struct RegionCode(String);

impl RegionCode {
    /// Parses a lowercase ASCII region code such as `us-east-1`.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-canonical length, separator, case, or alphabet.
    pub fn parse(value: impl Into<String>) -> Result<Self, ClassificationError> {
        let value = value.into();
        if !(2..=32).contains(&value.len()) {
            return Err(ClassificationError(
                "region length must be between 2 and 32 bytes",
            ));
        }
        if value.starts_with('-') || value.ends_with('-') || value.contains("--") {
            return Err(ClassificationError(
                "region separators must be internal and singular",
            ));
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(ClassificationError(
                "region must contain lowercase ASCII letters, digits, and hyphens only",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the region code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RegionCode {
    type Error = ClassificationError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<RegionCode> for String {
    fn from(value: RegionCode) -> Self {
        value.0
    }
}
impl fmt::Display for RegionCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Retention and residency metadata carried with classified descriptors.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct RetentionMetadata {
    region: RegionCode,
    retention_days: NonZeroU32,
    legal_hold: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetentionMetadataWire {
    region: RegionCode,
    retention_days: u32,
    legal_hold: bool,
}

impl<'de> Deserialize<'de> for RetentionMetadata {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = RetentionMetadataWire::deserialize(deserializer)?;
        Self::new(wire.region, wire.retention_days, wire.legal_hold)
            .map_err(serde::de::Error::custom)
    }
}

impl RetentionMetadata {
    /// Maximum supported retention interval (100 years).
    pub const MAX_RETENTION_DAYS: u32 = 36_525;

    /// Creates bounded retention metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when retention is zero or exceeds 100 years.
    pub fn new(
        region: RegionCode,
        retention_days: u32,
        legal_hold: bool,
    ) -> Result<Self, ClassificationError> {
        let retention_days = NonZeroU32::new(retention_days)
            .ok_or(ClassificationError("retention must be at least one day"))?;
        if retention_days.get() > Self::MAX_RETENTION_DAYS {
            return Err(ClassificationError(
                "retention exceeds the supported maximum",
            ));
        }
        Ok(Self {
            region,
            retention_days,
            legal_hold,
        })
    }

    /// Storage residency region.
    #[must_use]
    pub const fn region(&self) -> &RegionCode {
        &self.region
    }
    /// Retention interval in whole days.
    #[must_use]
    pub const fn retention_days(&self) -> u32 {
        self.retention_days.get()
    }
    /// Whether policy currently prevents ordinary expiry/deletion.
    #[must_use]
    pub const fn legal_hold(&self) -> bool {
        self.legal_hold
    }
}

/// Classification syntax validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClassificationError(&'static str);
impl fmt::Display for ClassificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ClassificationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_order_is_sensitivity_order() {
        assert!(DataClass::RestrictedSecurity > DataClass::Confidential);
    }

    #[test]
    fn region_has_one_canonical_form() {
        assert_eq!(
            RegionCode::parse("us-east-1").unwrap().as_str(),
            "us-east-1"
        );
        for invalid in ["US-east-1", "-east", "east-", "east--one", "e"] {
            assert!(RegionCode::parse(invalid).is_err());
        }
    }

    #[test]
    fn retention_is_nonzero_and_bounded() {
        let region = RegionCode::parse("local-1").unwrap();
        assert!(RetentionMetadata::new(region.clone(), 0, false).is_err());
        assert!(
            RetentionMetadata::new(
                region.clone(),
                RetentionMetadata::MAX_RETENTION_DAYS + 1,
                false
            )
            .is_err()
        );
        assert_eq!(
            RetentionMetadata::new(region, 30, true)
                .unwrap()
                .retention_days(),
            30
        );
        assert!(
            serde_json::from_str::<RetentionMetadata>(
                r#"{"region":"local-1","retention_days":0,"legal_hold":false}"#
            )
            .is_err()
        );
    }
}
