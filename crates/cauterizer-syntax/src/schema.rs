//! Versioned published-contract envelope syntax.

use core::fmt;
use core::str::FromStr;

use schemars::JsonSchema;
use semver::Version;
use serde::{Deserialize, Deserializer, Serialize, de};

const NAMESPACE_PREFIX: &str = "dev.cauterizer.";

/// A reverse-DNS schema name owned by a Cauterizer bounded context.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct SchemaName(String);

impl SchemaName {
    /// Parses a canonical schema name such as `dev.cauterizer.verification.candidate-assessed`.
    ///
    /// # Errors
    ///
    /// Returns [`SchemaSyntaxError::InvalidName`] for a foreign namespace or a
    /// non-canonical segment.
    pub fn parse(value: impl Into<String>) -> Result<Self, SchemaSyntaxError> {
        let value = value.into();
        let suffix = value
            .strip_prefix(NAMESPACE_PREFIX)
            .ok_or(SchemaSyntaxError::InvalidName)?;
        if suffix.is_empty()
            || suffix.len() > 180
            || suffix.split('.').any(|segment| {
                segment.is_empty()
                    || segment.len() > 63
                    || segment.starts_with('-')
                    || segment.ends_with('-')
                    || !segment.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
        {
            return Err(SchemaSyntaxError::InvalidName);
        }
        Ok(Self(value))
    }

    /// Returns the canonical schema name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SchemaName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for SchemaName {
    type Err = SchemaSyntaxError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl<'de> Deserialize<'de> for SchemaName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// A canonical semantic schema version.
///
/// Build metadata is forbidden because it is ignored by semantic-version
/// precedence and would allow distinct envelope identifiers for the same version.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct SchemaVersion(String);

impl SchemaVersion {
    /// Parses a strict semantic version in canonical textual form.
    ///
    /// # Errors
    ///
    /// Returns [`SchemaSyntaxError::InvalidVersion`] for invalid, non-canonical,
    /// or build-qualified semantic versions.
    pub fn parse(value: impl Into<String>) -> Result<Self, SchemaSyntaxError> {
        let value = value.into();
        let parsed = Version::parse(&value).map_err(|_| SchemaSyntaxError::InvalidVersion)?;
        if !parsed.build.is_empty() || parsed.to_string() != value {
            return Err(SchemaSyntaxError::InvalidVersion);
        }
        Ok(Self(value))
    }

    /// Returns the canonical version string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Parses the already validated value for semantic comparisons.
    ///
    /// # Errors
    ///
    /// Returns [`SchemaSyntaxError::InvalidVersion`] if the stored invariant was
    /// violated by a future incompatible representation change.
    pub fn semver(&self) -> Result<Version, SchemaSyntaxError> {
        Version::parse(&self.0).map_err(|_| SchemaSyntaxError::InvalidVersion)
    }

    /// Returns whether this consumer version accepts a producer version.
    ///
    /// Published contracts are compatible within a major version when the
    /// producer's minor version is not newer than the consumer's. Pre-release
    /// versions require exact equality and major zero is deliberately exact.
    #[must_use]
    pub fn accepts(&self, producer: &Self) -> bool {
        let (Ok(consumer), Ok(producer)) = (self.semver(), producer.semver()) else {
            return false;
        };
        if !consumer.pre.is_empty() || !producer.pre.is_empty() || consumer.major == 0 {
            return consumer == producer;
        }
        consumer.major == producer.major && consumer.minor >= producer.minor
    }
}

impl fmt::Display for SchemaVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for SchemaVersion {
    type Err = SchemaSyntaxError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// The syntax-level envelope for every published command, event, and document.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SchemaEnvelope<T> {
    /// Reverse-DNS contract name.
    pub schema: SchemaName,
    /// Semantic contract version.
    pub version: SchemaVersion,
    /// Context-owned content. The shared kernel assigns it no domain meaning.
    pub payload: T,
}

impl<T> SchemaEnvelope<T> {
    /// Constructs an envelope from validated syntax primitives.
    #[must_use]
    pub const fn new(schema: SchemaName, version: SchemaVersion, payload: T) -> Self {
        Self {
            schema,
            version,
            payload,
        }
    }

    /// Validates the envelope identity against an expected consumer contract.
    ///
    /// # Errors
    ///
    /// Returns [`SchemaSyntaxError::UnexpectedName`] for the wrong contract or
    /// [`SchemaSyntaxError::IncompatibleVersion`] for a version outside the
    /// conservative compatibility rule.
    pub fn require_contract(
        &self,
        expected_schema: &SchemaName,
        consumer_version: &SchemaVersion,
    ) -> Result<(), SchemaSyntaxError> {
        if &self.schema != expected_schema {
            return Err(SchemaSyntaxError::UnexpectedName);
        }
        if !consumer_version.accepts(&self.version) {
            return Err(SchemaSyntaxError::IncompatibleVersion);
        }
        Ok(())
    }
}

/// Validation failure for schema identifiers or compatibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaSyntaxError {
    /// The schema is outside the platform namespace or has an invalid segment.
    InvalidName,
    /// The version is not canonical `SemVer` or contains build metadata.
    InvalidVersion,
    /// The envelope names a different contract than the consumer expects.
    UnexpectedName,
    /// The producer version is not accepted by the consumer version.
    IncompatibleVersion,
}

impl fmt::Display for SchemaSyntaxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidName => "invalid Cauterizer schema name",
            Self::InvalidVersion => "invalid canonical semantic schema version",
            Self::UnexpectedName => "unexpected schema name",
            Self::IncompatibleVersion => "incompatible schema version",
        })
    }
}

impl std::error::Error for SchemaSyntaxError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_names_and_versions() {
        assert!(SchemaName::parse("dev.cauterizer.verification.candidate-assessed").is_ok());
        for invalid in [
            "verification.event",
            "dev.cauterizer.Verification.event",
            "dev.cauterizer.verification.-event",
            "dev.cauterizer.verification..event",
        ] {
            assert_eq!(
                SchemaName::parse(invalid),
                Err(SchemaSyntaxError::InvalidName)
            );
        }

        assert!(SchemaVersion::parse("1.2.3").is_ok());
        assert!(SchemaVersion::parse("1.2.3-rc.1").is_ok());
        for invalid in ["1", "v1.2.3", "01.2.3", "1.2.3+build"] {
            assert_eq!(
                SchemaVersion::parse(invalid),
                Err(SchemaSyntaxError::InvalidVersion)
            );
        }
    }

    #[test]
    fn compatibility_is_conservative_and_explicit() {
        let consumer = SchemaVersion::parse("1.3.0").expect("valid");
        assert!(consumer.accepts(&SchemaVersion::parse("1.2.9").expect("valid")));
        assert!(!consumer.accepts(&SchemaVersion::parse("1.4.0").expect("valid")));
        assert!(!consumer.accepts(&SchemaVersion::parse("2.0.0").expect("valid")));
        assert!(
            !SchemaVersion::parse("0.2.1")
                .expect("valid")
                .accepts(&SchemaVersion::parse("0.2.0").expect("valid"))
        );
    }

    #[test]
    fn envelope_denies_unknown_fields_and_wrong_contract() {
        let json = r#"{
          "schema":"dev.cauterizer.verification.candidate-assessed",
          "version":"1.0.0",
          "payload":{"ok":true},
          "authority":"solver"
        }"#;
        assert!(serde_json::from_str::<SchemaEnvelope<serde_json::Value>>(json).is_err());

        let envelope = SchemaEnvelope::new(
            SchemaName::parse("dev.cauterizer.verification.candidate-assessed").expect("valid"),
            SchemaVersion::parse("1.0.0").expect("valid"),
            (),
        );
        assert_eq!(
            envelope.require_contract(
                &SchemaName::parse("dev.cauterizer.evidence.bundle").expect("valid"),
                &SchemaVersion::parse("1.0.0").expect("valid")
            ),
            Err(SchemaSyntaxError::UnexpectedName)
        );
    }
}
