//! Cryptographic operation ports and explicitly untrusted development adapters.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use std::fmt;

/// Fixed AES-256-GCM nonce length.
pub const NONCE_LENGTH: usize = 12;

/// Authenticated envelope ciphertext owned by a referenced key operation.
#[derive(Clone, Eq, PartialEq)]
pub struct EnvelopeCiphertext {
    /// Non-secret key reference; raw key bytes are never returned.
    pub key_ref: ContextQualifiedId,
    /// Unique nonce supplied by the trusted caller/random source.
    pub nonce: [u8; NONCE_LENGTH],
    /// Ciphertext including the authentication tag.
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for EnvelopeCiphertext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvelopeCiphertext")
            .field("key_ref", &self.key_ref)
            .field("nonce", &"[REDACTED]")
            .field(
                "ciphertext",
                &format_args!("[{} bytes]", self.ciphertext.len()),
            )
            .finish()
    }
}

/// Stable cryptographic operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    /// Tenant/key reference did not match this adapter.
    UnauthorizedKey,
    /// Authentication failed or ciphertext was corrupted.
    AuthenticationFailed,
    /// Signature did not verify.
    InvalidSignature,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnauthorizedKey => "unauthorized_key_reference",
            Self::AuthenticationFailed => "ciphertext_authentication_failed",
            Self::InvalidSignature => "signature_invalid",
        })
    }
}
impl std::error::Error for CryptoError {}

/// Operation-only envelope encryption boundary suitable for a production KMS.
pub trait EnvelopeEncryptionPort {
    /// Encrypts exact bytes with tenant/key-bound associated data.
    ///
    /// # Errors
    ///
    /// Fails closed for an unauthorized key or encryption failure.
    fn encrypt(
        &self,
        organization_id: &OrganizationId,
        key_ref: &ContextQualifiedId,
        nonce: [u8; NONCE_LENGTH],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<EnvelopeCiphertext, CryptoError>;

    /// Authenticates and decrypts exact bytes.
    ///
    /// # Errors
    ///
    /// Fails closed for tenant/key mismatch, tampering, or wrong associated data.
    fn decrypt(
        &self,
        organization_id: &OrganizationId,
        value: &EnvelopeCiphertext,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}

/// Signature metadata returned without exposing private key material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevelopmentSignature {
    /// Non-secret signing-key reference.
    pub key_ref: ContextQualifiedId,
    /// Ed25519 signature bytes.
    pub signature: [u8; 64],
    /// Trust label that prevents production-authentication claims.
    pub trust_label: &'static str,
}

/// Operation-only signing boundary suitable for a production HSM/KMS.
pub trait SigningPort {
    /// Signs exact caller-canonicalized bytes.
    ///
    /// # Errors
    ///
    /// Fails when the key reference is not authorized for this signer.
    fn sign(
        &self,
        key_ref: &ContextQualifiedId,
        message: &[u8],
    ) -> Result<DevelopmentSignature, CryptoError>;

    /// Verifies an exact message and signature.
    ///
    /// # Errors
    ///
    /// Fails for a key mismatch or invalid signature.
    fn verify(&self, message: &[u8], signature: &DevelopmentSignature) -> Result<(), CryptoError>;
}

/// Local AES-256-GCM adapter. It is never a production KMS or key store.
pub struct UntrustedDevelopmentEnvelopeEncryption {
    organization_id: OrganizationId,
    key_ref: ContextQualifiedId,
    cipher: Aes256Gcm,
}

impl UntrustedDevelopmentEnvelopeEncryption {
    /// Creates the explicitly local adapter from test/development key bytes.
    #[must_use]
    pub fn new(
        organization_id: OrganizationId,
        key_ref: ContextQualifiedId,
        key: [u8; 32],
    ) -> Self {
        Self {
            organization_id,
            key_ref,
            cipher: Aes256Gcm::new(&key.into()),
        }
    }
}

impl EnvelopeEncryptionPort for UntrustedDevelopmentEnvelopeEncryption {
    fn encrypt(
        &self,
        organization_id: &OrganizationId,
        key_ref: &ContextQualifiedId,
        nonce: [u8; NONCE_LENGTH],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<EnvelopeCiphertext, CryptoError> {
        if organization_id != &self.organization_id || key_ref != &self.key_ref {
            return Err(CryptoError::UnauthorizedKey);
        }
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        Ok(EnvelopeCiphertext {
            key_ref: key_ref.clone(),
            nonce,
            ciphertext,
        })
    }

    fn decrypt(
        &self,
        organization_id: &OrganizationId,
        value: &EnvelopeCiphertext,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if organization_id != &self.organization_id || value.key_ref != self.key_ref {
            return Err(CryptoError::UnauthorizedKey);
        }
        self.cipher
            .decrypt(
                Nonce::from_slice(&value.nonce),
                Payload {
                    msg: &value.ciphertext,
                    aad: associated_data,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)
    }
}

/// Local Ed25519 adapter labeled `untrusted-development` on every signature.
pub struct UntrustedDevelopmentSigner {
    key_ref: ContextQualifiedId,
    signing_key: SigningKey,
}

impl UntrustedDevelopmentSigner {
    /// Creates a development signer from local key bytes.
    #[must_use]
    pub fn new(key_ref: ContextQualifiedId, secret: [u8; 32]) -> Self {
        Self {
            key_ref,
            signing_key: SigningKey::from_bytes(&secret),
        }
    }

    /// Returns the non-secret verification key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl SigningPort for UntrustedDevelopmentSigner {
    fn sign(
        &self,
        key_ref: &ContextQualifiedId,
        message: &[u8],
    ) -> Result<DevelopmentSignature, CryptoError> {
        if key_ref != &self.key_ref {
            return Err(CryptoError::UnauthorizedKey);
        }
        Ok(DevelopmentSignature {
            key_ref: key_ref.clone(),
            signature: self.signing_key.sign(message).to_bytes(),
            trust_label: "untrusted-development",
        })
    }

    fn verify(&self, message: &[u8], signature: &DevelopmentSignature) -> Result<(), CryptoError> {
        if signature.key_ref != self.key_ref || signature.trust_label != "untrusted-development" {
            return Err(CryptoError::UnauthorizedKey);
        }
        self.signing_key
            .verifying_key()
            .verify(message, &Signature::from_bytes(&signature.signature))
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn org() -> OrganizationId {
        OrganizationId::new("00000000").unwrap()
    }
    fn key() -> ContextQualifiedId {
        ContextQualifiedId::new("key", "00000000").unwrap()
    }

    #[test]
    fn envelope_encryption_binds_tenant_key_nonce_and_associated_data() {
        let adapter = UntrustedDevelopmentEnvelopeEncryption::new(org(), key(), [7; 32]);
        let encrypted = adapter
            .encrypt(&org(), &key(), [9; 12], b"secret", b"descriptor")
            .unwrap();
        assert_eq!(
            adapter.decrypt(&org(), &encrypted, b"descriptor").unwrap(),
            b"secret"
        );
        assert_eq!(
            adapter.decrypt(&org(), &encrypted, b"other"),
            Err(CryptoError::AuthenticationFailed)
        );
        let mut corrupted = encrypted.clone();
        corrupted.ciphertext[0] ^= 1;
        assert_eq!(
            adapter.decrypt(&org(), &corrupted, b"descriptor"),
            Err(CryptoError::AuthenticationFailed)
        );
        assert_eq!(
            adapter.encrypt(
                &OrganizationId::new("00000001").unwrap(),
                &key(),
                [8; 12],
                b"secret",
                b"descriptor"
            ),
            Err(CryptoError::UnauthorizedKey)
        );
        assert!(!format!("{encrypted:?}").contains("secret"));
    }

    #[test]
    fn development_signatures_are_labeled_and_detect_tampering() {
        let signer = UntrustedDevelopmentSigner::new(key(), [3; 32]);
        let signature = signer.sign(&key(), b"canonical").unwrap();
        assert_eq!(signature.trust_label, "untrusted-development");
        signer.verify(b"canonical", &signature).unwrap();
        assert_eq!(
            signer.verify(b"changed", &signature),
            Err(CryptoError::InvalidSignature)
        );
    }
}
