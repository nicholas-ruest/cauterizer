//! RFC 8785 JSON Canonicalization Scheme (JCS) support.

use core::fmt;
use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::Value;

/// Serializes a value using RFC 8785 JCS.
///
/// Callers signing external JSON should prefer [`canonicalize_json`] so duplicate
/// object members are rejected before the value model can discard them.
///
/// # Errors
///
/// Returns [`CanonicalJsonError::Canonicalization`] when the value contains a
/// representation outside the JCS data model.
pub fn canonicalize<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, CanonicalJsonError> {
    serde_jcs::to_vec(value)
        .map_err(|error| CanonicalJsonError::Canonicalization(error.to_string()))
}

/// Parses one JSON document, rejects duplicate object members, and emits RFC 8785 JCS bytes.
///
/// # Errors
///
/// Returns an error for invalid UTF-8 or JSON, duplicate members, trailing data,
/// non-finite/overflowing numbers, or a value that JCS cannot serialize.
pub fn canonicalize_json(input: &[u8]) -> Result<Vec<u8>, CanonicalJsonError> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = UniqueValue::deserialize(&mut deserializer)
        .map_err(|error| CanonicalJsonError::InvalidJson(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| CanonicalJsonError::InvalidJson(error.to_string()))?;
    canonicalize(&value.0)
}

/// Returns whether input is already exactly one canonical RFC 8785 JSON document.
///
/// # Errors
///
/// Returns the same validation failures as [`canonicalize_json`].
pub fn is_canonical(input: &[u8]) -> Result<bool, CanonicalJsonError> {
    Ok(canonicalize_json(input)? == input)
}

/// Failure to parse or canonicalize JSON without ambiguity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalJsonError {
    /// The input is not one complete, valid JSON document.
    InvalidJson(String),
    /// An object repeats a member name.
    DuplicateKey(String),
    /// A valid value cannot be represented by RFC 8785 JCS.
    Canonicalization(String),
}

impl fmt::Display for CanonicalJsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson(reason) => write!(formatter, "invalid JSON: {reason}"),
            Self::DuplicateKey(key) => write!(formatter, "duplicate JSON object member: {key}"),
            Self::Canonicalization(reason) => {
                write!(formatter, "JSON cannot be canonicalized: {reason}")
            }
        }
    }
}

impl std::error::Error for CanonicalJsonError {}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> de::Visitor<'de> for UniqueValueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value with unique object member names")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.unsigned_abs() > 9_007_199_254_740_991 {
            return Err(E::custom("integer exceeds the interoperable JSON range"));
        }
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value > 9_007_199_254_740_991 {
            return Err(E::custom("integer exceeds the interoperable JSON range"));
        }
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
        while let Some(value) = sequence.next_element::<UniqueValue>()? {
            values.push(value.0);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(CanonicalJsonError::DuplicateKey(key)));
            }
            let value = map.next_value::<UniqueValue>()?;
            values.insert(key, value.0);
        }
        Ok(UniqueValue(Value::Object(values.into_iter().collect())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rfc_8785_golden_vector() {
        // RFC 8785 section 3.2.2 example, including UTF-16 property sorting.
        let input = r#"{
          "numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],
          "string":"€$\u000f\nA'B\"\\\"/",
          "literals":[null,true,false]
        }"#
        .as_bytes();
        let expected = concat!(
            r#"{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\"/"}"#,
        );
        assert_eq!(
            canonicalize_json(input).expect("canonicalize"),
            expected.as_bytes()
        );
    }

    #[test]
    fn sorts_object_members_and_is_idempotent() {
        let canonical =
            canonicalize_json(br#"{ "z": 1, "a": { "b": 2, "a": 1 } }"#).expect("canonicalize");
        assert_eq!(canonical, br#"{"a":{"a":1,"b":2},"z":1}"#);
        assert_eq!(canonicalize_json(&canonical).expect("again"), canonical);
        assert!(is_canonical(&canonical).expect("check"));
    }

    #[test]
    fn rejects_duplicate_members_at_any_depth() {
        for input in [
            br#"{"a":1,"a":2}"#.as_slice(),
            br#"{"outer":{"x":1,"x":2}}"#.as_slice(),
        ] {
            let error = canonicalize_json(input).expect_err("duplicate must fail");
            assert!(error.to_string().contains("duplicate JSON object member"));
        }
    }

    #[test]
    fn rejects_invalid_utf8_trailing_data_and_non_json_numbers() {
        for input in [
            b"\xff".as_slice(),
            br"{} {}".as_slice(),
            b"NaN".as_slice(),
            b"1e9999".as_slice(),
            b"9007199254740992".as_slice(),
        ] {
            assert!(canonicalize_json(input).is_err());
        }
    }

    /// P15 AC-032 adversarial coverage: malformed/oversized/deeply-nested/
    /// non-UTF-8 input must never panic or hang the parser, and every
    /// rejection must land on one of [`CanonicalJsonError`]'s three stable
    /// variants rather than an unwind. This is the actually-runnable
    /// counterpart to the `patch-proposals`/`evidence` libfuzzer targets,
    /// which need `cargo-fuzz` and are not guaranteed to be executable in
    /// every environment.
    mod adversarial_proptests {
        use super::*;
        use proptest::prelude::*;

        /// Confirms a deep-nesting input never panics and, if rejected,
        /// fails with [`CanonicalJsonError::InvalidJson`] — the variant
        /// `serde_json`'s built-in recursion-depth bound reports. A crash
        /// or a different error variant here would mean the depth bound
        /// stopped applying.
        fn assert_never_panics_and_fails_closed_if_rejected(input: &[u8]) {
            match canonicalize_json(input) {
                Ok(_) | Err(CanonicalJsonError::InvalidJson(_)) => {}
                Err(other) => {
                    panic!("deeply nested input was rejected for an unexpected reason: {other:?}")
                }
            }
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// Fully arbitrary bytes, including invalid UTF-8, must never
            /// panic `canonicalize_json`/`is_canonical` — only ever return
            /// `Ok` or one of the three stable [`CanonicalJsonError`] variants.
            #[test]
            fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
                let _ = canonicalize_json(&bytes);
                let _ = is_canonical(&bytes);
            }

            /// Arbitrary bytes appended after a valid JSON opener, biasing
            /// generation toward inputs that look enough like JSON to reach
            /// deeper into the parser before failing.
            #[test]
            fn near_valid_malformed_documents_never_panic(
                opener in prop::sample::select(vec!["{", "[", "\"", "{\"a\":", "[1,"]),
                tail in prop::collection::vec(any::<u8>(), 0..256),
            ) {
                let mut input = opener.as_bytes().to_vec();
                input.extend(tail);
                let _ = canonicalize_json(&input);
            }

            /// A right-nested array `depth` levels deep. `serde_json`'s
            /// default recursion limit (128) must reject anything beyond it
            /// with a stable error rather than overflowing the stack.
            #[test]
            fn deeply_nested_arrays_never_panic_and_fail_closed(depth in 0_usize..20_000) {
                let mut input = String::with_capacity(depth * 2);
                input.extend(std::iter::repeat_n('[', depth));
                input.extend(std::iter::repeat_n(']', depth));
                assert_never_panics_and_fails_closed_if_rejected(input.as_bytes());
            }

            /// A right-nested object `depth` levels deep, same guard as the
            /// array case but exercising the map-visitor recursion path.
            #[test]
            fn deeply_nested_objects_never_panic_and_fail_closed(depth in 0_usize..20_000) {
                let mut input = String::new();
                input.extend(std::iter::repeat_n(r#"{"a":"#, depth));
                input.push_str("null");
                input.extend(std::iter::repeat_n('}', depth));
                assert_never_panics_and_fails_closed_if_rejected(input.as_bytes());
            }

            /// A wide (not deep) flat array with many siblings — oversized
            /// rather than recursive — must also complete without panicking.
            #[test]
            fn oversized_flat_array_never_panics(count in 0_usize..20_000) {
                let mut input = String::from("[");
                for index in 0..count {
                    if index > 0 {
                        input.push(',');
                    }
                    input.push('1');
                }
                input.push(']');
                let _ = canonicalize_json(input.as_bytes());
            }

            /// A single oversized string member must also complete without
            /// panicking, exercising the string/escape scanner on a large
            /// buffer instead of the structural nesting path.
            #[test]
            fn oversized_string_member_never_panics(length in 0_usize..20_000) {
                let input = format!(r#"{{"a":"{}"}}"#, "x".repeat(length));
                let _ = canonicalize_json(input.as_bytes());
            }
        }
    }
}
