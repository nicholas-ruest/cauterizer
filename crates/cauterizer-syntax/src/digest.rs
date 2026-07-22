//! Canonical SHA-256 digest syntax.

use core::fmt;
use core::hash::{Hash, Hasher};
use core::str::FromStr;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

/// The only digest algorithm accepted by the initial contract profile.
pub const SHA256_ALGORITHM: &str = "sha256";
const DIGEST_BYTES: usize = 32;
const HEX_LENGTH: usize = DIGEST_BYTES * 2;
const TAGGED_LENGTH: usize = SHA256_ALGORITHM.len() + 1 + HEX_LENGTH;

/// A failure to parse a canonical digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DigestError {
    /// The algorithm tag was absent or was not `sha256`.
    UnsupportedAlgorithm,
    /// The hexadecimal payload did not contain exactly 64 characters.
    InvalidLength {
        /// Received hexadecimal payload length.
        actual: usize,
    },
    /// The payload was not lowercase hexadecimal.
    InvalidHex {
        /// Zero-based position of the invalid payload byte.
        index: usize,
    },
}

impl fmt::Display for DigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAlgorithm => {
                formatter.write_str("digest must use the `sha256:` algorithm tag")
            }
            Self::InvalidLength { actual } => {
                write!(
                    formatter,
                    "SHA-256 payload length must be 64, received {actual}"
                )
            }
            Self::InvalidHex { index } => write!(
                formatter,
                "SHA-256 payload contains non-lowercase-hex byte at index {index}"
            ),
        }
    }
}

impl std::error::Error for DigestError {}

/// A canonical `sha256:<lowercase-hex>` content digest.
#[derive(Clone, Copy, JsonSchema)]
#[schemars(transparent)]
pub struct Sha256Digest(#[schemars(with = "String")] [u8; DIGEST_BYTES]);

impl Sha256Digest {
    /// Hashes an exact byte sequence.
    #[must_use]
    pub fn of_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(Sha256::digest(bytes.as_ref()).into())
    }

    /// Constructs a digest from an already computed byte array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; DIGEST_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the exact 32 digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }

    /// Returns the canonical tagged lowercase representation.
    #[must_use]
    pub fn to_tagged_hex(self) -> String {
        let mut output = String::with_capacity(TAGGED_LENGTH);
        output.push_str(SHA256_ALGORITHM);
        output.push(':');
        for byte in self.0 {
            use fmt::Write as _;
            write!(output, "{byte:02x}").expect("writing to String is infallible");
        }
        output
    }
}

impl PartialEq for Sha256Digest {
    fn eq(&self, other: &Self) -> bool {
        // Accumulating every byte avoids data-dependent early return. This is
        // useful defense in depth for authorization checks involving known
        // digests, although callers must not treat digests as secret values.
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
    }
}

impl Eq for Sha256Digest {}

impl Hash for Sha256Digest {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_tagged_hex())
    }
}

impl FromStr for Sha256Digest {
    type Err = DigestError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let payload = value
            .strip_prefix("sha256:")
            .ok_or(DigestError::UnsupportedAlgorithm)?;
        if payload.len() != HEX_LENGTH {
            return Err(DigestError::InvalidLength {
                actual: payload.len(),
            });
        }
        let mut bytes = [0_u8; DIGEST_BYTES];
        for (index, pair) in payload.as_bytes().chunks_exact(2).enumerate() {
            let high = decode_hex(pair[0]).ok_or(DigestError::InvalidHex { index: index * 2 })?;
            let low = decode_hex(pair[1]).ok_or(DigestError::InvalidHex {
                index: index * 2 + 1,
            })?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_tagged_hex())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

const fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_SHA256: &str =
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn hashes_known_vector_and_round_trips() {
        let digest = Sha256Digest::of_bytes([]);
        assert_eq!(digest.to_string(), EMPTY_SHA256);
        assert_eq!(EMPTY_SHA256.parse::<Sha256Digest>().unwrap(), digest);
    }

    #[test]
    fn rejects_untagged_uppercase_and_wrong_algorithm_values() {
        assert!(EMPTY_SHA256[7..].parse::<Sha256Digest>().is_err());
        assert!(EMPTY_SHA256.to_uppercase().parse::<Sha256Digest>().is_err());
        assert!(
            EMPTY_SHA256
                .replace("sha256", "sha512")
                .parse::<Sha256Digest>()
                .is_err()
        );
    }

    #[test]
    fn lowercase_hex_alphabet_property_is_exhaustive_for_ascii() {
        let mut canonical = EMPTY_SHA256.as_bytes().to_vec();
        for byte in 0_u8..=127 {
            canonical[7] = byte;
            let value = String::from_utf8(canonical.clone()).unwrap();
            let accepted = byte.is_ascii_digit() || matches!(byte, b'a'..=b'f');
            assert_eq!(value.parse::<Sha256Digest>().is_ok(), accepted);
        }
    }

    #[test]
    fn equality_distinguishes_every_byte_position() {
        let baseline = Sha256Digest::from_bytes([0; DIGEST_BYTES]);
        for index in 0..DIGEST_BYTES {
            let mut changed = [0; DIGEST_BYTES];
            changed[index] = 1;
            assert_ne!(baseline, Sha256Digest::from_bytes(changed));
        }
    }
}
