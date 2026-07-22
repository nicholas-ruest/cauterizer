//! Organization-scoped authorization request syntax.

use crate::identifiers::{IdentityRef, OrganizationId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;

const MAX_ACTION_LEN: usize = 96;
const MAX_RESOURCE_LEN: usize = 256;
const MAX_PURPOSE_LEN: usize = 256;

/// A syntactically valid action name such as `runs.read`.
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(try_from = "String", into = "String")]
pub struct ActionName(String);

/// An opaque, bounded resource reference interpreted by an owning context.
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(try_from = "String", into = "String")]
pub struct ResourceRef(String);

/// A bounded, audit-safe statement of why access is requested.
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(try_from = "String", into = "String")]
pub struct Purpose(String);

/// Syntax-only input to an authorization policy.
///
/// Possessing this value does not imply that access was granted.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRequestContext {
    organization_id: OrganizationId,
    actor: IdentityRef,
    action: ActionName,
    resource: ResourceRef,
    purpose: Purpose,
}

impl AuthorizationRequestContext {
    /// Creates an organization-bound authorization request.
    #[must_use]
    pub const fn new(
        organization_id: OrganizationId,
        actor: IdentityRef,
        action: ActionName,
        resource: ResourceRef,
        purpose: Purpose,
    ) -> Self {
        Self {
            organization_id,
            actor,
            action,
            resource,
            purpose,
        }
    }

    /// Organization whose policy must decide the request.
    #[must_use]
    pub const fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// Authenticated actor or service identity reference.
    #[must_use]
    pub const fn actor(&self) -> &IdentityRef {
        &self.actor
    }

    /// Requested action syntax.
    #[must_use]
    pub const fn action(&self) -> &ActionName {
        &self.action
    }

    /// Opaque resource reference.
    #[must_use]
    pub const fn resource(&self) -> &ResourceRef {
        &self.resource
    }

    /// Declared purpose.
    #[must_use]
    pub const fn purpose(&self) -> &Purpose {
        &self.purpose
    }
}

macro_rules! bounded_value {
    ($type:ident, $max:expr, $label:literal, $validator:expr) => {
        impl $type {
            /// Parses and validates the bounded value.
            ///
            /// # Errors
            ///
            /// Returns an error when the value is empty, oversized, padded with
            /// whitespace, or contains a character outside its canonical alphabet.
            pub fn parse(value: impl Into<String>) -> Result<Self, AuthorizationSyntaxError> {
                let value = value.into();
                validate_bounded(&value, $max, $label, $validator)?;
                Ok(Self(value))
            }

            /// Returns the canonical string representation.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $type {
            type Error = AuthorizationSyntaxError;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::parse(value)
            }
        }

        impl From<$type> for String {
            fn from(value: $type) -> Self {
                value.0
            }
        }

        impl fmt::Display for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

bounded_value!(
    ActionName,
    MAX_ACTION_LEN,
    "action",
    |character: char| character.is_ascii_lowercase()
        || character.is_ascii_digit()
        || matches!(character, '.' | ':' | '-' | '_')
);
bounded_value!(
    ResourceRef,
    MAX_RESOURCE_LEN,
    "resource",
    |character: char| character.is_ascii_alphanumeric()
        || matches!(character, '/' | ':' | '-' | '_' | '.')
);
bounded_value!(
    Purpose,
    MAX_PURPOSE_LEN,
    "purpose",
    |character: char| character.is_ascii_graphic() || character == ' '
);

/// Failure to parse an authorization syntax value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationSyntaxError {
    field: &'static str,
    reason: &'static str,
}

impl fmt::Display for AuthorizationSyntaxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid {}: {}", self.field, self.reason)
    }
}

impl std::error::Error for AuthorizationSyntaxError {}

fn validate_bounded(
    value: &str,
    max: usize,
    field: &'static str,
    allowed: impl Fn(char) -> bool,
) -> Result<(), AuthorizationSyntaxError> {
    if value.is_empty() {
        return Err(AuthorizationSyntaxError {
            field,
            reason: "must not be empty",
        });
    }
    if value.len() > max {
        return Err(AuthorizationSyntaxError {
            field,
            reason: "exceeds maximum encoded length",
        });
    }
    if value.trim() != value {
        return Err(AuthorizationSyntaxError {
            field,
            reason: "must not have surrounding whitespace",
        });
    }
    if !value.chars().all(allowed) {
        return Err(AuthorizationSyntaxError {
            field,
            reason: "contains a forbidden character",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_is_canonical_and_bounded() {
        assert_eq!(
            ActionName::parse("runs.read").unwrap().as_str(),
            "runs.read"
        );
        assert!(ActionName::parse("Runs.Read").is_err());
        assert!(ActionName::parse("x".repeat(MAX_ACTION_LEN + 1)).is_err());
    }

    #[test]
    fn resource_rejects_query_and_control_characters() {
        assert!(ResourceRef::parse("run:01/revision-2").is_ok());
        assert!(ResourceRef::parse("run:01?secret=true").is_err());
        assert!(ResourceRef::parse("run:01\nforged").is_err());
    }

    #[test]
    fn purpose_is_trimmed_bounded_printable_text() {
        assert!(Purpose::parse("incident response investigation").is_ok());
        assert!(Purpose::parse(" padded ").is_err());
        assert!(Purpose::parse("line\nbreak").is_err());
    }
}
