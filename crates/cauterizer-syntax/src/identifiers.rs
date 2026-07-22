//! Bounded, context-qualified identifiers and request-coordination syntax.
//!
//! These types deliberately carry no aggregate behavior. They validate the
//! public spelling of references shared across bounded contexts.

use core::fmt;
use core::num::NonZeroU64;
use core::str::FromStr;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

const MIN_OPAQUE_LENGTH: usize = 8;
const MAX_OPAQUE_LENGTH: usize = 64;
const MAX_ID_LENGTH: usize = 96;
const MAX_IDEMPOTENCY_KEY_LENGTH: usize = 128;

/// A failure to construct or parse a shared identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentifierError {
    /// The value was empty.
    Empty,
    /// The complete value exceeded its public contract limit.
    TooLong {
        /// Maximum accepted byte length.
        max: usize,
        /// Received byte length.
        actual: usize,
    },
    /// A context/prefix was not the expected canonical value.
    WrongContext {
        /// Required canonical context.
        expected: &'static str,
        /// Context found in the input.
        actual: String,
    },
    /// A context component was not a lowercase ASCII slug.
    InvalidContext,
    /// The opaque component had an invalid length or alphabet.
    InvalidOpaque,
    /// The required context/opaque separator was absent.
    MissingSeparator,
    /// An aggregate sequence was zero.
    ZeroSequence,
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("identifier must not be empty"),
            Self::TooLong { max, actual } => {
                write!(
                    formatter,
                    "identifier length {actual} exceeds maximum {max}"
                )
            }
            Self::WrongContext { expected, actual } => write!(
                formatter,
                "identifier context must be `{expected}`, received `{actual}`"
            ),
            Self::InvalidContext => formatter.write_str(
                "identifier context must be a lowercase ASCII slug beginning with a letter",
            ),
            Self::InvalidOpaque => formatter.write_str(
                "opaque identifier component must be 8-64 lowercase ASCII letters or digits",
            ),
            Self::MissingSeparator => {
                formatter.write_str("identifier must contain one context separator (`_`)")
            }
            Self::ZeroSequence => formatter.write_str("aggregate sequence must be non-zero"),
        }
    }
}

impl std::error::Error for IdentifierError {}

/// A canonical `<context>_<opaque>` reference.
///
/// Context names are lowercase ASCII slugs. Opaque components are deliberately
/// restricted to lowercase base36-compatible text so comparison is stable
/// across databases, filesystems, and URL encoders.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct ContextQualifiedId(String);

impl ContextQualifiedId {
    /// Constructs a reference from separately validated components.
    ///
    /// # Errors
    ///
    /// Returns an error when the context is not a canonical lowercase slug,
    /// when the opaque component is not bounded lowercase base36 text, or when
    /// their combined representation exceeds the contract limit.
    pub fn new(context: &str, opaque: &str) -> Result<Self, IdentifierError> {
        validate_context(context)?;
        validate_opaque(opaque)?;
        let actual = context.len() + 1 + opaque.len();
        if actual > MAX_ID_LENGTH {
            return Err(IdentifierError::TooLong {
                max: MAX_ID_LENGTH,
                actual,
            });
        }
        Ok(Self(format!("{context}_{opaque}")))
    }

    /// Returns the canonical context component.
    #[must_use]
    pub fn context(&self) -> &str {
        match self.0.split_once('_') {
            Some((context, _)) => context,
            None => "",
        }
    }

    /// Returns the opaque component without interpreting it.
    #[must_use]
    pub fn opaque(&self) -> &str {
        match self.0.split_once('_') {
            Some((_, opaque)) => opaque,
            None => "",
        }
    }

    /// Returns the canonical wire representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ContextQualifiedId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ContextQualifiedId")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for ContextQualifiedId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for ContextQualifiedId {
    type Err = IdentifierError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() {
            return Err(IdentifierError::Empty);
        }
        if value.len() > MAX_ID_LENGTH {
            return Err(IdentifierError::TooLong {
                max: MAX_ID_LENGTH,
                actual: value.len(),
            });
        }
        let (context, opaque) = value
            .split_once('_')
            .ok_or(IdentifierError::MissingSeparator)?;
        if opaque.contains('_') {
            return Err(IdentifierError::InvalidOpaque);
        }
        Self::new(context, opaque)
    }
}

impl<'de> Deserialize<'de> for ContextQualifiedId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

macro_rules! tagged_identifier {
    ($(#[$meta:meta])* $name:ident, $context:literal) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
        #[serde(transparent)]
        pub struct $name(ContextQualifiedId);

        impl $name {
            /// Constructs the identifier from its opaque component.
            ///
            /// # Errors
            ///
            /// Returns an error when the component is not 8-64 lowercase
            /// ASCII letters or digits.
            pub fn new(opaque: &str) -> Result<Self, IdentifierError> {
                ContextQualifiedId::new($context, opaque).map(Self)
            }

            /// Returns the canonical tagged representation.
            #[must_use]
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }

            /// Returns the uninterpreted opaque component.
            #[must_use]
            pub fn opaque(&self) -> &str {
                self.0.opaque()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, formatter)
            }
        }

        impl FromStr for $name {
            type Err = IdentifierError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let parsed = ContextQualifiedId::from_str(value)?;
                if parsed.context() != $context {
                    return Err(IdentifierError::WrongContext {
                        expected: $context,
                        actual: parsed.context().to_owned(),
                    });
                }
                Ok(Self(parsed))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                value.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

tagged_identifier!(
    /// Organization-scoped syntax reference.
    OrganizationId,
    "org"
);
tagged_identifier!(
    /// Authenticated human actor syntax reference.
    ActorId,
    "actor"
);
tagged_identifier!(
    /// Authenticated workload/service-principal syntax reference.
    ServicePrincipalId,
    "service"
);
tagged_identifier!(
    /// Trace-safe correlation reference spanning one logical request.
    CorrelationId,
    "correlation"
);
tagged_identifier!(
    /// Reference to the command or event that caused another fact.
    CausationId,
    "causation"
);

/// A syntax-level authenticated principal reference.
#[derive(
    Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum IdentityRef {
    /// A human identity reference.
    Human(ActorId),
    /// A non-human workload identity reference.
    Service(ServicePrincipalId),
}

/// Backward-compatible descriptive alias for [`IdentityRef`].
pub type PrincipalRef = IdentityRef;

/// A bounded client-supplied key used to make one command replay-safe.
///
/// Keys are opaque and case-sensitive. The allowed URL-safe alphabet avoids
/// accidental control characters, whitespace normalization, and log injection.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// Parses a non-empty URL-safe key of at most 128 bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, oversized, or non-URL-safe key.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        let value = value.into();
        if value.is_empty() {
            return Err(IdentifierError::Empty);
        }
        if value.len() > MAX_IDEMPOTENCY_KEY_LENGTH {
            return Err(IdentifierError::TooLong {
                max: MAX_IDEMPOTENCY_KEY_LENGTH,
                actual: value.len(),
            });
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
        {
            return Err(IdentifierError::InvalidOpaque);
        }
        Ok(Self(value))
    }

    /// Returns the exact key supplied by the client.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for IdempotencyKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdempotencyKey([REDACTED])")
    }
}

impl<'de> Deserialize<'de> for IdempotencyKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Monotonically increasing one-based sequence of an aggregate event.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct AggregateSequence(NonZeroU64);

impl AggregateSequence {
    /// Creates a non-zero sequence.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError::ZeroSequence`] when `value` is zero.
    pub const fn new(value: u64) -> Result<Self, IdentifierError> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(IdentifierError::ZeroSequence),
        }
    }

    /// Returns the numeric sequence.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the checked next sequence, or `None` at `u64::MAX`.
    #[must_use]
    pub fn checked_next(self) -> Option<Self> {
        self.get()
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .map(Self)
    }
}

impl<'de> Deserialize<'de> for AggregateSequence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(u64::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

fn validate_context(value: &str) -> Result<(), IdentifierError> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(IdentifierError::InvalidContext);
    };
    if !first.is_ascii_lowercase()
        || value.len() > 31
        || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || value.ends_with('-')
        || value.contains("--")
    {
        return Err(IdentifierError::InvalidContext);
    }
    Ok(())
}

fn validate_opaque(value: &str) -> Result<(), IdentifierError> {
    if !(MIN_OPAQUE_LENGTH..=MAX_OPAQUE_LENGTH).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err(IdentifierError::InvalidOpaque);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const OPAQUE: &str = "01j4z3y6ab8cdef0";

    #[test]
    fn parses_and_splits_canonical_id() {
        let id: ContextQualifiedId = "remediation-runs_01j4z3y6ab8cdef0".parse().unwrap();
        assert_eq!(id.context(), "remediation-runs");
        assert_eq!(id.opaque(), OPAQUE);
    }

    #[test]
    fn typed_ids_reject_context_substitution() {
        let error = "actor_01j4z3y6ab8cdef0"
            .parse::<OrganizationId>()
            .unwrap_err();
        assert!(matches!(error, IdentifierError::WrongContext { .. }));
    }

    #[test]
    fn invalid_spellings_are_rejected() {
        for value in [
            "",
            "ORG_01j4z3y6ab8cdef0",
            "org-short",
            "org_01J4Z3Y6AB8CDEF0",
            "org_01j4z3y6ab8cdef0_extra",
            "-org_01j4z3y6ab8cdef0",
            "org--child_01j4z3y6ab8cdef0",
        ] {
            assert!(
                value.parse::<ContextQualifiedId>().is_err(),
                "accepted {value}"
            );
        }
    }

    #[test]
    fn opaque_alphabet_property_is_exhaustive_for_ascii() {
        for byte in 0_u8..=127 {
            let mut value = OPAQUE.as_bytes().to_vec();
            value[0] = byte;
            let value = String::from_utf8(value).unwrap();
            let accepted = byte.is_ascii_lowercase() || byte.is_ascii_digit();
            assert_eq!(ContextQualifiedId::new("test", &value).is_ok(), accepted);
        }
    }

    #[test]
    fn idempotency_key_is_bounded_and_redacted() {
        let key = IdempotencyKey::new("Client_key.01~retry").unwrap();
        assert_eq!(key.as_str(), "Client_key.01~retry");
        assert_eq!(format!("{key:?}"), "IdempotencyKey([REDACTED])");
        assert!(IdempotencyKey::new("has whitespace").is_err());
        assert!(IdempotencyKey::new("x".repeat(129)).is_err());
    }

    #[test]
    fn aggregate_sequence_is_one_based_and_overflow_safe() {
        assert_eq!(
            AggregateSequence::new(1)
                .unwrap()
                .checked_next()
                .unwrap()
                .get(),
            2
        );
        assert!(AggregateSequence::new(0).is_err());
        assert!(
            AggregateSequence::new(u64::MAX)
                .unwrap()
                .checked_next()
                .is_none()
        );
    }

    proptest! {
        #[test]
        fn arbitrary_oversized_identifiers_are_rejected(extra in ".{97,512}") {
            prop_assert!(extra.parse::<ContextQualifiedId>().is_err());
        }

        #[test]
        fn arbitrary_valid_opaque_values_round_trip(opaque in "[a-z0-9]{8,64}") {
            let id = ContextQualifiedId::new("property", &opaque).expect("generated valid ID");
            let reparsed: ContextQualifiedId = id.as_str().parse().expect("round trip");
            prop_assert_eq!(reparsed, id);
        }
    }
}
